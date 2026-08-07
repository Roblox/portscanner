"""Generation-safe PostgreSQL state transitions for ACT."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .contracts import ContractValidationError, validate_finding
from .models import (
    MAX_PORT,
    CoverageDeclaration,
    Observation,
    ScanEnvelope,
    TargetEvent,
    parse_address,
)


class DataInvariantError(RuntimeError):
    """Incoming evidence conflicts with an established stable identity."""


class UnknownTargetError(DataInvariantError):
    """A scan arrived before its target event."""


class AttemptConflictError(DataInvariantError):
    """An existing attempt ID was reused for different evidence."""


class RuleConfigurationError(DataInvariantError):
    """An editable detection rule contains an unsupported predicate."""


def stable_hash(*parts: Any) -> str:
    canonical = json.dumps(
        parts,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def finding_fingerprint(
    rule_key: str,
    target_id: str,
    protocol: str,
    port: int,
) -> str:
    return stable_hash("act-finding-v1", rule_key, target_id, protocol, port)


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _target_addresses(event: TargetEvent) -> list[str]:
    try:
        addresses = [parse_address(address) for address in event.addresses]
    except ValueError as error:
        raise DataInvariantError("target event contains an invalid address binding") from error
    if event.event_type == "remove" and addresses:
        raise DataInvariantError("target removal cannot retain an address binding")
    if event.event_type == "upsert" and not addresses:
        raise DataInvariantError("active target event requires an address binding")
    return addresses


@dataclass(frozen=True, slots=True)
class IngestResult:
    duplicate: bool
    stale_generation: bool
    state_eligible: bool
    handoff_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    duplicate: bool
    findings_examined: int
    handoff_keys: tuple[str, ...]


class Repository:
    """Owns all state transitions; callers publish queued objects after commit."""

    def __init__(self, connection: psycopg.Connection[Any]) -> None:
        self.connection = connection
        self.connection.row_factory = dict_row
        self.connection.autocommit = True

    def apply_target_event(
        self,
        event: TargetEvent,
        *,
        finding_bucket: str | None = None,
    ) -> bool:
        """Apply one inventory event; return False for an already-seen event."""
        addresses = _target_addresses(event)
        source_event_time = event.source_event_time or event.source_observed_at
        source_collected_at = event.source_collected_at or event.source_observed_at
        dispatched_at = event.dispatched_at or source_collected_at
        removal_time = event.removed_at or event.source_observed_at
        with self.connection.transaction():
            duplicate = self.connection.execute(
                "SELECT 1 FROM act.target_events WHERE event_id = %s",
                (event.event_id,),
            ).fetchone()
            if duplicate is not None:
                return False

            target = self.connection.execute(
                "SELECT * FROM act.targets WHERE target_id = %s FOR UPDATE",
                (event.target_id,),
            ).fetchone()
            accepted = False
            stale = False
            address_binding_changed = False
            generation_gap_reactivation = False
            if target is None:
                accepted = True
                status = "removed" if event.event_type == "remove" else "active"
                removed_at = removal_time if status == "removed" else None
                self.connection.execute(
                    """
                    INSERT INTO act.targets (
                        target_id,
                        provider,
                        provider_scope_id,
                        provider_target_id,
                        location,
                        current_generation,
                        status,
                        current_addresses,
                        context,
                        source_observed_at,
                        removed_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s::INET[],
                        %s, %s, %s
                    )
                    """,
                    (
                        event.target_id,
                        event.provider,
                        event.provider_scope_id,
                        event.provider_target_id,
                        event.location,
                        event.generation,
                        status,
                        addresses,
                        Jsonb(dict(event.context)),
                        event.source_observed_at,
                        removed_at,
                    ),
                )
            else:
                identity = (
                    target["provider"],
                    target["provider_scope_id"],
                    target["provider_target_id"],
                )
                incoming_identity = (
                    event.provider,
                    event.provider_scope_id,
                    event.provider_target_id,
                )
                if identity != incoming_identity:
                    raise DataInvariantError(
                        "target_id cannot be reassigned to another provider identity"
                    )
                accepted = event.generation > target["current_generation"] or (
                    event.generation == target["current_generation"]
                    and event.source_observed_at >= target["source_observed_at"]
                )
                stale = not accepted
                if accepted:
                    previous_addresses = {str(address) for address in target["current_addresses"]}
                    generation_gap_reactivation = (
                        event.event_type == "upsert"
                        and event.scan_reason == "new_target"
                        and target["status"] == "active"
                        and event.generation > target["current_generation"] + 1
                    )
                    address_binding_changed = (
                        event.event_type == "upsert" and previous_addresses != set(addresses)
                    )
                    status = "removed" if event.event_type == "remove" else "active"
                    removed_at = removal_time if status == "removed" else None
                    self.connection.execute(
                        """
                        UPDATE act.targets
                        SET location = %s,
                            current_generation = %s,
                            status = %s,
                            current_addresses = %s::INET[],
                            context = %s,
                            source_observed_at = %s,
                            updated_at = clock_timestamp(),
                            removed_at = %s
                        WHERE target_id = %s
                        """,
                        (
                            event.location,
                            event.generation,
                            status,
                            addresses,
                            Jsonb(dict(event.context)),
                            event.source_observed_at,
                            removed_at,
                            event.target_id,
                        ),
                    )

            self.connection.execute(
                """
                INSERT INTO act.target_events (
                    event_id,
                    target_id,
                    generation,
                    event_type,
                    provider,
                    provider_scope_id,
                    provider_target_id,
                    location,
                    addresses,
                    context,
                    source_event_time,
                    source_observed_at,
                    source_collected_at,
                    dispatched_at,
                    removed_at,
                    accepted,
                    stale
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::INET[], %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    event.event_id,
                    event.target_id,
                    event.generation,
                    event.event_type,
                    event.provider,
                    event.provider_scope_id,
                    event.provider_target_id,
                    event.location,
                    addresses,
                    Jsonb(dict(event.context)),
                    source_event_time,
                    event.source_observed_at,
                    source_collected_at,
                    dispatched_at,
                    removal_time if event.event_type == "remove" else None,
                    accepted,
                    stale,
                ),
            )

            if accepted and event.event_type == "remove":
                count_row = self.connection.execute(
                    """
                    SELECT count(*) AS count
                    FROM act.findings
                    WHERE target_id = %s AND status = 'open'
                    """,
                    (event.target_id,),
                ).fetchone()
                if not isinstance(count_row, Mapping):
                    raise DataInvariantError("open finding count query returned no row")
                open_findings = count_row.get("count")
                if (
                    isinstance(open_findings, bool)
                    or not isinstance(open_findings, int)
                    or open_findings < 0
                ):
                    raise DataInvariantError("open finding count query returned an invalid count")
                if open_findings and not finding_bucket:
                    raise DataInvariantError(
                        "finding bucket is required to publish removal transitions"
                    )
                self._close_for_ownership_removal(
                    event,
                    finding_bucket=finding_bucket,
                )
            elif accepted and generation_gap_reactivation:
                self._close_for_generation_gap_reactivation(
                    event,
                    finding_bucket=finding_bucket,
                )
            elif accepted and address_binding_changed:
                self._close_for_address_binding_change(
                    event,
                    finding_bucket=finding_bucket,
                )
        return True

    def ingest_scan(
        self,
        envelope: ScanEnvelope,
        observations: Sequence[Observation],
        *,
        envelope_bucket: str,
        envelope_key: str,
        envelope_version: str | None,
        envelope_sha256: str,
        raw_result_version: str | None,
        enrichment_result_version: str | None,
        finding_bucket: str,
        xml_completion_validated: bool,
    ) -> IngestResult:
        handoff_keys: list[str] = []
        with self.connection.transaction():
            target = self.connection.execute(
                "SELECT * FROM act.targets WHERE target_id = %s FOR UPDATE",
                (envelope.target_id,),
            ).fetchone()
            if target is None:
                raise UnknownTargetError("scan target is not present")
            if target["provider"] != envelope.provider:
                raise DataInvariantError("scan provider does not match target provider")
            source_event = self.connection.execute(
                """
                SELECT *
                FROM act.target_events
                WHERE event_id = %s
                FOR SHARE
                """,
                (envelope.target_event_id,),
            ).fetchone()
            if source_event is None:
                raise UnknownTargetError("scan target event is not present")
            if (
                source_event["target_id"] != envelope.target_id
                or source_event["generation"] != envelope.generation
                or source_event["provider"] != envelope.provider
            ):
                raise DataInvariantError("scan does not match its target event")
            result_owner = self.connection.execute(
                "SELECT attempt_id FROM act.scan_attempts WHERE result_id = %s",
                (envelope.result_id,),
            ).fetchone()
            if result_owner is not None and result_owner["attempt_id"] != envelope.attempt_id:
                raise AttemptConflictError("result_id was already used by another attempt")

            existing = self.connection.execute(
                """
                SELECT
                    result_id,
                    source_envelope_sha256,
                    raw_result_sha256,
                    enrichment_result_sha256,
                    stale_generation,
                    state_eligible
                FROM act.scan_attempts
                WHERE attempt_id = %s
                """,
                (envelope.attempt_id,),
            ).fetchone()
            expected_raw_hash = None if envelope.raw_result is None else envelope.raw_result.sha256
            expected_enrichment_hash = (
                None if envelope.enrichment_result is None else envelope.enrichment_result.sha256
            )
            if existing is not None:
                if (
                    existing["result_id"].strip() != envelope.result_id
                    or existing["source_envelope_sha256"].strip() != envelope_sha256
                    or (
                        None
                        if existing["raw_result_sha256"] is None
                        else existing["raw_result_sha256"].strip()
                    )
                    != expected_raw_hash
                    or (
                        None
                        if existing["enrichment_result_sha256"] is None
                        else existing["enrichment_result_sha256"].strip()
                    )
                    != expected_enrichment_hash
                ):
                    raise AttemptConflictError("attempt_id was already used by different evidence")
                pending = self._pending_handoff_keys(source_attempt_id=envelope.attempt_id)
                return IngestResult(
                    duplicate=True,
                    stale_generation=existing["stale_generation"],
                    state_eligible=existing["state_eligible"],
                    handoff_keys=tuple(pending),
                )

            current_addresses = {str(address) for address in target["current_addresses"]}
            stale_generation = envelope.generation != target["current_generation"]
            address_current = envelope.address in current_addresses
            state_eligible = (
                not stale_generation
                and target["status"] == "active"
                and address_current
                and envelope.outcome == "complete"
                and xml_completion_validated
            )
            raw = envelope.raw_result
            enrichment = envelope.enrichment_result
            self.connection.execute(
                """
                INSERT INTO act.scan_attempts (
                    attempt_id,
                    result_id,
                    run_id,
                    directive_id,
                    target_id,
                    target_event_id,
                    trace_id,
                    generation,
                    provider,
                    observed_address,
                    profile,
                    scanner_version,
                    outcome,
                    exit_code,
                    error_type,
                    error_retryable,
                    source_event_time,
                    source_observed_at,
                    source_collected_at,
                    dispatched_at,
                    scan_started_at,
                    scan_completed_at,
                    result_uploaded_at,
                    source_envelope_bucket,
                    source_envelope_key,
                    source_envelope_version,
                    source_envelope_sha256,
                    raw_result_bucket,
                    raw_result_key,
                    raw_result_version,
                    raw_result_sha256,
                    enrichment_result_bucket,
                    enrichment_result_key,
                    enrichment_result_version,
                    enrichment_result_sha256,
                    xml_completion_validated,
                    stale_generation,
                    state_eligible
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::INET,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    envelope.attempt_id,
                    envelope.result_id,
                    envelope.run_id,
                    envelope.directive_id,
                    envelope.target_id,
                    envelope.target_event_id,
                    envelope.trace_id,
                    envelope.generation,
                    envelope.provider,
                    envelope.address,
                    envelope.profile,
                    envelope.scanner_version,
                    envelope.outcome,
                    envelope.exit_code,
                    envelope.error_type,
                    envelope.error_retryable,
                    source_event["source_event_time"],
                    source_event["source_observed_at"],
                    source_event["source_collected_at"],
                    source_event["dispatched_at"],
                    envelope.scan_started_at,
                    envelope.scan_completed_at,
                    envelope.result_uploaded_at,
                    envelope_bucket,
                    envelope_key,
                    envelope_version,
                    envelope_sha256,
                    None if raw is None else raw.bucket,
                    None if raw is None else raw.key,
                    raw_result_version,
                    None if raw is None else raw.sha256,
                    None if enrichment is None else enrichment.bucket,
                    None if enrichment is None else enrichment.key,
                    enrichment_result_version,
                    None if enrichment is None else enrichment.sha256,
                    xml_completion_validated,
                    stale_generation,
                    state_eligible,
                ),
            )

            for coverage in envelope.coverage:
                self.connection.execute(
                    """
                    INSERT INTO act.scan_attempt_coverage (
                        attempt_id,
                        protocol,
                        port_spec,
                        port_from,
                        port_to,
                        complete
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        envelope.attempt_id,
                        coverage.protocol,
                        coverage.port_spec,
                        coverage.port_from,
                        coverage.port_to,
                        coverage.complete,
                    ),
                )

            for observation in observations:
                if observation.observed_address != envelope.address:
                    raise DataInvariantError("observation address does not match ScanResult target")
                self.connection.execute(
                    """
                    INSERT INTO act.observations (
                        attempt_id,
                        target_id,
                        generation,
                        protocol,
                        port,
                        observed_address,
                        state,
                        service_name,
                        service_product,
                        service_version,
                        certificate_sha256,
                        ssh_host_key_sha256,
                        banner_sha256,
                        service_identity_sha256,
                        observed_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s::INET, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        envelope.attempt_id,
                        envelope.target_id,
                        envelope.generation,
                        observation.protocol,
                        observation.port,
                        observation.observed_address,
                        observation.state,
                        observation.service_name,
                        observation.service_product,
                        observation.service_version,
                        observation.certificate_sha256,
                        observation.ssh_host_key_sha256,
                        observation.banner_sha256,
                        observation.service_identity_sha256,
                        observation.observed_at,
                    ),
                )

            current_attempt = (
                not stale_generation and target["status"] == "active" and address_current
            )
            if current_attempt:
                self.connection.execute(
                    """
                    UPDATE act.targets
                    SET last_attempt_at = GREATEST(
                            COALESCE(last_attempt_at, %s),
                            %s
                        ),
                        last_confirmed_at = CASE
                            WHEN %s THEN GREATEST(
                                COALESCE(last_confirmed_at, %s),
                                %s
                            )
                            ELSE last_confirmed_at
                        END
                    WHERE target_id = %s
                    """,
                    (
                        envelope.scan_completed_at,
                        envelope.scan_completed_at,
                        state_eligible,
                        envelope.scan_completed_at,
                        envelope.scan_completed_at,
                        envelope.target_id,
                    ),
                )

            if state_eligible:
                affected, transition_types = self._apply_exposure_evidence(
                    envelope,
                    observations,
                )
                handoff_keys.extend(
                    self._reconcile_finding_keys(
                        affected,
                        target_id=envelope.target_id,
                        source_kind="scan_attempt",
                        source_key=envelope.attempt_id,
                        source_attempt_id=envelope.attempt_id,
                        occurred_at=envelope.scan_completed_at,
                        finding_bucket=finding_bucket,
                        transition_types=transition_types,
                    )
                )

        return IngestResult(
            duplicate=False,
            stale_generation=stale_generation,
            state_eligible=state_eligible,
            handoff_keys=tuple(handoff_keys),
        )

    def _apply_exposure_evidence(
        self,
        envelope: ScanEnvelope,
        observations: Sequence[Observation],
    ) -> tuple[set[tuple[str, int]], dict[tuple[str, int], str]]:
        observed = {
            (observation.protocol, observation.port): observation for observation in observations
        }
        affected: set[tuple[str, int]] = set()
        transitions: dict[tuple[str, int], str] = {}

        for key in sorted(observed):
            if not self._attempt_controls_port(envelope, *key):
                continue
            observation = observed[key]
            if observation.state == "open":
                applied, transition = self._open_exposure(envelope, observation)
            elif observation.state in {"closed", "filtered"} and self._covered(
                envelope.coverage, *key
            ):
                applied, transition = self._close_exposure(
                    target_id=envelope.target_id,
                    generation=envelope.generation,
                    protocol=observation.protocol,
                    port=observation.port,
                    source_attempt_id=envelope.attempt_id,
                    occurred_at=envelope.scan_completed_at,
                    reason=(
                        "explicit_closed" if observation.state == "closed" else "explicit_filtered"
                    ),
                )
            else:
                applied = False
                transition = None
            if applied:
                affected.add(key)
            if transition is not None:
                transitions[key] = transition

        state_rows = self.connection.execute(
            """
            SELECT protocol, port
            FROM act.exposure_state
            WHERE target_id = %s
            FOR UPDATE
            """,
            (envelope.target_id,),
        ).fetchall()
        for row in state_rows:
            key = (row["protocol"], row["port"])
            if (
                key in observed
                or not self._covered(envelope.coverage, *key)
                or not self._attempt_controls_port(envelope, *key)
            ):
                continue
            applied, transition = self._close_exposure(
                target_id=envelope.target_id,
                generation=envelope.generation,
                protocol=key[0],
                port=key[1],
                source_attempt_id=envelope.attempt_id,
                occurred_at=envelope.scan_completed_at,
                reason="coverage_absence",
            )
            if applied:
                affected.add(key)
            if transition is not None:
                transitions[key] = transition
        return affected, transitions

    @staticmethod
    def _covered(
        coverage: Sequence[CoverageDeclaration],
        protocol: str,
        port: int,
    ) -> bool:
        return any(item.contains(protocol, port) for item in coverage)

    def _attempt_controls_port(
        self,
        envelope: ScanEnvelope,
        protocol: str,
        port: int,
    ) -> bool:
        winner = self.connection.execute(
            """
            SELECT attempt.attempt_id
            FROM act.scan_attempts AS attempt
            JOIN act.scan_attempt_coverage AS coverage
              ON coverage.attempt_id = attempt.attempt_id
            WHERE attempt.target_id = %s
              AND attempt.generation = %s
              AND attempt.state_eligible
              AND coverage.complete
              AND coverage.protocol = %s
              AND coverage.port_from IS NOT NULL
              AND %s BETWEEN coverage.port_from AND coverage.port_to
            ORDER BY
                attempt.scan_completed_at DESC,
                attempt.attempt_id COLLATE "C" DESC
            LIMIT 1
            """,
            (envelope.target_id, envelope.generation, protocol, port),
        ).fetchone()
        return winner is not None and winner["attempt_id"] == envelope.attempt_id

    @staticmethod
    def _scan_evidence_is_newer(
        row: Mapping[str, Any],
        *,
        generation: int,
        occurred_at: datetime,
        attempt_id: str,
    ) -> bool:
        last_generation = int(row["last_generation"])
        if generation != last_generation:
            return generation > last_generation
        return (occurred_at, attempt_id) > (
            row["last_confirmed_at"],
            row["last_attempt_id"],
        )

    def _open_exposure(
        self,
        envelope: ScanEnvelope,
        observation: Observation,
    ) -> tuple[bool, str | None]:
        row = self.connection.execute(
            """
            SELECT *
            FROM act.exposure_state
            WHERE target_id = %s AND protocol = %s AND port = %s
            FOR UPDATE
            """,
            (envelope.target_id, observation.protocol, observation.port),
        ).fetchone()
        if row is not None and not self._scan_evidence_is_newer(
            row,
            generation=envelope.generation,
            occurred_at=envelope.scan_completed_at,
            attempt_id=envelope.attempt_id,
        ):
            return False, None
        occurred_at = (
            envelope.scan_completed_at
            if row is None
            else max(
                envelope.scan_completed_at,
                row["last_confirmed_at"],
                row["last_changed_at"],
            )
        )
        event_type: str | None
        if row is None:
            event_type = "opened"
            reason = "open_observation"
            previous_state = None
            previous_hash = None
            self.connection.execute(
                """
                INSERT INTO act.exposure_state (
                    target_id,
                    protocol,
                    port,
                    state,
                    observed_address,
                    service_name,
                    service_product,
                    service_version,
                    certificate_sha256,
                    ssh_host_key_sha256,
                    banner_sha256,
                    service_identity_sha256,
                    first_opened_at,
                    last_confirmed_at,
                    last_changed_at,
                    last_attempt_id,
                    last_generation
                )
                VALUES (
                    %s, %s, %s, 'open', %s::INET, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    envelope.target_id,
                    observation.protocol,
                    observation.port,
                    observation.observed_address,
                    observation.service_name,
                    observation.service_product,
                    observation.service_version,
                    observation.certificate_sha256,
                    observation.ssh_host_key_sha256,
                    observation.banner_sha256,
                    observation.service_identity_sha256,
                    occurred_at,
                    occurred_at,
                    occurred_at,
                    envelope.attempt_id,
                    envelope.generation,
                ),
            )
        elif row["state"] == "closed":
            event_type = "reopened"
            reason = "open_observation"
            previous_state = "closed"
            previous_hash = row["service_identity_sha256"].strip()
            self.connection.execute(
                """
                UPDATE act.exposure_state
                SET state = 'open',
                    observed_address = %s::INET,
                    service_name = %s,
                    service_product = %s,
                    service_version = %s,
                    certificate_sha256 = %s,
                    ssh_host_key_sha256 = %s,
                    banner_sha256 = %s,
                    service_identity_sha256 = %s,
                    last_confirmed_at = %s,
                    last_changed_at = %s,
                    closed_at = NULL,
                    closure_reason = NULL,
                    last_attempt_id = %s,
                    last_generation = %s,
                    state_version = state_version + 1
                WHERE target_id = %s AND protocol = %s AND port = %s
                """,
                (
                    observation.observed_address,
                    observation.service_name,
                    observation.service_product,
                    observation.service_version,
                    observation.certificate_sha256,
                    observation.ssh_host_key_sha256,
                    observation.banner_sha256,
                    observation.service_identity_sha256,
                    occurred_at,
                    occurred_at,
                    envelope.attempt_id,
                    envelope.generation,
                    envelope.target_id,
                    observation.protocol,
                    observation.port,
                ),
            )
        else:
            previous_state = "open"
            previous_hash = row["service_identity_sha256"].strip()
            identity_changed = previous_hash != observation.service_identity_sha256
            address_changed = str(row["observed_address"]) != observation.observed_address
            event_type = "updated" if identity_changed or address_changed else None
            reason = "service_changed" if identity_changed else "address_changed"
            self.connection.execute(
                """
                UPDATE act.exposure_state
                SET observed_address = %s::INET,
                    service_name = %s,
                    service_product = %s,
                    service_version = %s,
                    certificate_sha256 = %s,
                    ssh_host_key_sha256 = %s,
                    banner_sha256 = %s,
                    service_identity_sha256 = %s,
                    last_confirmed_at = GREATEST(last_confirmed_at, %s),
                    last_changed_at = CASE
                        WHEN %s THEN %s
                        ELSE last_changed_at
                    END,
                    last_attempt_id = %s,
                    last_generation = %s,
                    state_version = state_version + CASE WHEN %s THEN 1 ELSE 0 END
                WHERE target_id = %s AND protocol = %s AND port = %s
                """,
                (
                    observation.observed_address,
                    observation.service_name,
                    observation.service_product,
                    observation.service_version,
                    observation.certificate_sha256,
                    observation.ssh_host_key_sha256,
                    observation.banner_sha256,
                    observation.service_identity_sha256,
                    occurred_at,
                    event_type is not None,
                    occurred_at,
                    envelope.attempt_id,
                    envelope.generation,
                    event_type is not None,
                    envelope.target_id,
                    observation.protocol,
                    observation.port,
                ),
            )
            if event_type is None:
                return True, None

        event_key = stable_hash(
            "act-exposure-event-v1",
            envelope.attempt_id,
            envelope.target_id,
            observation.protocol,
            observation.port,
            event_type,
            observation.service_identity_sha256,
            observation.observed_address,
        )
        self.connection.execute(
            """
            INSERT INTO act.exposure_events (
                event_key,
                target_id,
                generation,
                protocol,
                port,
                source_attempt_id,
                event_type,
                previous_state,
                new_state,
                reason,
                previous_service_identity_sha256,
                service_identity_sha256,
                occurred_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, 'open',
                %s, %s, %s, %s
            )
            """,
            (
                event_key,
                envelope.target_id,
                envelope.generation,
                observation.protocol,
                observation.port,
                envelope.attempt_id,
                event_type,
                previous_state,
                reason,
                previous_hash,
                observation.service_identity_sha256,
                occurred_at,
            ),
        )
        return True, event_type

    def _close_exposure(
        self,
        *,
        target_id: str,
        generation: int,
        protocol: str,
        port: int,
        source_attempt_id: str | None,
        occurred_at: datetime,
        reason: str,
        source_key: str | None = None,
    ) -> tuple[bool, str | None]:
        row = self.connection.execute(
            """
            SELECT *
            FROM act.exposure_state
            WHERE target_id = %s AND protocol = %s AND port = %s
            FOR UPDATE
            """,
            (target_id, protocol, port),
        ).fetchone()
        if row is None:
            return False, None
        if source_attempt_id is not None and not self._scan_evidence_is_newer(
            row,
            generation=generation,
            occurred_at=occurred_at,
            attempt_id=source_attempt_id,
        ):
            return False, None
        if row["state"] != "open":
            if source_attempt_id is None:
                return False, None
            self.connection.execute(
                """
                UPDATE act.exposure_state
                SET last_confirmed_at = GREATEST(last_confirmed_at, %s),
                    last_attempt_id = %s,
                    last_generation = %s
                WHERE target_id = %s AND protocol = %s AND port = %s
                """,
                (
                    occurred_at,
                    source_attempt_id,
                    generation,
                    target_id,
                    protocol,
                    port,
                ),
            )
            return True, None

        transition_at = max(
            occurred_at,
            row["last_confirmed_at"],
            row["last_changed_at"],
        )

        if source_attempt_id is None:
            self.connection.execute(
                """
                UPDATE act.exposure_state
                SET state = 'closed',
                    last_confirmed_at = %s,
                    last_changed_at = %s,
                    closed_at = %s,
                    closure_reason = %s,
                    last_generation = GREATEST(last_generation, %s),
                    state_version = state_version + 1
                WHERE target_id = %s AND protocol = %s AND port = %s
                """,
                (
                    transition_at,
                    transition_at,
                    transition_at,
                    reason,
                    generation,
                    target_id,
                    protocol,
                    port,
                ),
            )
        else:
            self.connection.execute(
                """
                UPDATE act.exposure_state
                SET state = 'closed',
                    last_confirmed_at = %s,
                    last_changed_at = %s,
                    closed_at = %s,
                    closure_reason = %s,
                    last_attempt_id = %s,
                    last_generation = %s,
                    state_version = state_version + 1
                WHERE target_id = %s AND protocol = %s AND port = %s
                """,
                (
                    transition_at,
                    transition_at,
                    transition_at,
                    reason,
                    source_attempt_id,
                    generation,
                    target_id,
                    protocol,
                    port,
                ),
            )

        identity = row["service_identity_sha256"].strip()
        event_source = source_attempt_id or source_key
        event_key = stable_hash(
            "act-exposure-event-v1",
            event_source,
            target_id,
            protocol,
            port,
            "closed",
            reason,
            identity,
        )
        self.connection.execute(
            """
            INSERT INTO act.exposure_events (
                event_key,
                target_id,
                generation,
                protocol,
                port,
                source_attempt_id,
                event_type,
                previous_state,
                new_state,
                reason,
                previous_service_identity_sha256,
                service_identity_sha256,
                occurred_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, 'closed', 'open', 'closed',
                %s, %s, %s, %s
            )
            """,
            (
                event_key,
                target_id,
                generation,
                protocol,
                port,
                source_attempt_id,
                reason,
                identity,
                identity,
                transition_at,
            ),
        )
        return True, "closed"

    def _reconcile_finding_keys(
        self,
        keys: Iterable[tuple[str, int]],
        *,
        target_id: str,
        source_kind: str,
        source_key: str,
        source_attempt_id: str | None,
        occurred_at: datetime,
        finding_bucket: str,
        transition_types: Mapping[tuple[str, int], str] | None = None,
        queue_event_handoffs: bool = True,
    ) -> list[str]:
        rules = self.connection.execute(
            "SELECT * FROM act.detection_rules ORDER BY rule_key"
        ).fetchall()
        queued: list[str] = []
        for protocol, port in sorted(set(keys)):
            exposure = self.connection.execute(
                """
                SELECT exposure.*, target.status AS target_status,
                       target.current_generation, target.provider
                FROM act.exposure_state AS exposure
                JOIN act.targets AS target USING (target_id)
                WHERE exposure.target_id = %s
                  AND exposure.protocol = %s
                  AND exposure.port = %s
                """,
                (target_id, protocol, port),
            ).fetchone()
            target = self.connection.execute(
                """
                SELECT target_id, status, current_generation, provider
                FROM act.targets
                WHERE target_id = %s
                """,
                (target_id,),
            ).fetchone()
            if target is None:
                raise UnknownTargetError("finding target is not present")
            existing_rows = self.connection.execute(
                """
                SELECT *
                FROM act.findings
                WHERE target_id = %s AND protocol = %s AND port = %s
                FOR UPDATE
                """,
                (target_id, protocol, port),
            ).fetchall()
            existing = {row["rule_key"]: row for row in existing_rows}
            matched: set[str] = set()
            if (
                exposure is not None
                and exposure["state"] == "open"
                and target["status"] == "active"
            ):
                for rule in rules:
                    if not self._rule_matches(rule, exposure):
                        continue
                    matched.add(rule["rule_key"])
                    handoff = self._ensure_finding(
                        target=target,
                        exposure=exposure,
                        rule=rule,
                        existing=existing.get(rule["rule_key"]),
                        source_kind=source_kind,
                        source_key=source_key,
                        source_attempt_id=source_attempt_id,
                        occurred_at=occurred_at,
                        finding_bucket=finding_bucket,
                        exposure_transition=(
                            None
                            if transition_types is None
                            else transition_types.get((protocol, port))
                        ),
                        queue_event_handoff=queue_event_handoffs,
                    )
                    if handoff is not None:
                        queued.append(handoff)

            for rule_key, finding in existing.items():
                if finding["status"] != "open" or rule_key in matched:
                    continue
                rule = next(
                    (item for item in rules if item["rule_key"] == rule_key),
                    None,
                )
                reason = self._finding_resolution_reason(
                    target["status"],
                    exposure,
                    rule,
                )
                handoff = self._resolve_finding(
                    finding=finding,
                    target_generation=target["current_generation"],
                    reason=reason,
                    source_kind=source_kind,
                    source_key=source_key,
                    source_attempt_id=source_attempt_id,
                    occurred_at=occurred_at,
                    finding_bucket=finding_bucket,
                    queue_event_handoff=queue_event_handoffs,
                )
                if handoff is not None:
                    queued.append(handoff)
        return queued

    @staticmethod
    def _finding_resolution_reason(
        target_status: str,
        exposure: Mapping[str, Any] | None,
        rule: Mapping[str, Any] | None,
    ) -> str:
        if target_status == "removed":
            return "ownership_removed"
        if exposure is None or exposure["state"] == "closed":
            return "exposure_closed"
        if rule is not None and not rule["enabled"]:
            return "rule_disabled"
        return "rule_no_longer_matches"

    @staticmethod
    def _rule_matches(rule: Mapping[str, Any], exposure: Mapping[str, Any]) -> bool:
        if not rule["enabled"]:
            return False
        criteria = rule["match_criteria"]
        if not isinstance(criteria, dict):
            raise RuleConfigurationError("rule match_criteria must be an object")
        allowed = (
            {"protocols"}
            if rule["rule_type"] == "exposure"
            else {
                "protocols",
                "ports",
            }
        )
        if set(criteria) != allowed:
            raise RuleConfigurationError(f"rule {rule['rule_key']} has unsupported match fields")
        protocols = criteria.get("protocols")
        if (
            not isinstance(protocols, list)
            or not protocols
            or not all(isinstance(item, str) for item in protocols)
        ):
            raise RuleConfigurationError(
                f"rule {rule['rule_key']} protocols must be a nonempty string list"
            )
        if exposure["protocol"] not in protocols:
            return False
        if rule["rule_type"] == "exposure":
            return True
        ports = criteria.get("ports")
        if (
            not isinstance(ports, list)
            or not ports
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and 1 <= item <= MAX_PORT
                for item in ports
            )
        ):
            raise RuleConfigurationError(f"rule {rule['rule_key']} ports must be valid integers")
        return exposure["port"] in ports

    def _ensure_finding(
        self,
        *,
        target: Mapping[str, Any],
        exposure: Mapping[str, Any],
        rule: Mapping[str, Any],
        existing: Mapping[str, Any] | None,
        source_kind: str,
        source_key: str,
        source_attempt_id: str | None,
        occurred_at: datetime,
        finding_bucket: str,
        exposure_transition: str | None,
        queue_event_handoff: bool,
    ) -> str | None:
        fingerprint = finding_fingerprint(
            rule["rule_key"],
            exposure["target_id"],
            exposure["protocol"],
            exposure["port"],
        )
        identity = exposure["service_identity_sha256"].strip()
        transition_at = max(
            occurred_at,
            exposure["first_opened_at"],
            exposure["last_confirmed_at"],
            exposure["last_changed_at"],
            *(
                ()
                if existing is None
                else (
                    existing["first_opened_at"],
                    existing["last_seen_at"],
                    existing["last_changed_at"],
                )
            ),
        )
        if existing is None:
            event_type = "opened"
            previous_status = None
            version = 1
            reason = (
                "reconciliation_repair"
                if source_kind == "reconciliation"
                else ("exposure_reopened" if exposure_transition == "reopened" else "exposure_open")
            )
        elif existing["status"] == "resolved":
            event_type = "reopened"
            previous_status = "resolved"
            version = existing["finding_version"] + 1
            reason = (
                "reconciliation_repair" if source_kind == "reconciliation" else "exposure_reopened"
            )
        else:
            identity_changed = existing["service_identity_sha256"].strip() != identity
            address_changed = str(existing["observed_address"]) != str(exposure["observed_address"])
            rule_changed = (
                existing["severity"] != rule["severity"]
                or existing["title"] != rule["name"]
                or existing["description"] != rule["description"]
            )
            if not (identity_changed or address_changed or rule_changed):
                self.connection.execute(
                    """
                    UPDATE act.findings
                    SET last_seen_at = GREATEST(last_seen_at, %s)
                    WHERE fingerprint = %s
                    """,
                    (exposure["last_confirmed_at"], fingerprint),
                )
                return None
            event_type = "updated"
            previous_status = "open"
            version = existing["finding_version"] + 1
            if identity_changed:
                reason = "service_changed"
            elif address_changed:
                reason = "address_changed"
            else:
                reason = "rule_changed"

        event_key = stable_hash(
            "act-finding-event-v1",
            fingerprint,
            source_kind,
            source_key,
            event_type,
            version,
        )
        values = (
            rule["severity"],
            rule["name"],
            rule["description"],
            exposure["observed_address"],
            exposure["service_name"],
            exposure["service_product"],
            exposure["service_version"],
            exposure["certificate_sha256"],
            exposure["ssh_host_key_sha256"],
            exposure["banner_sha256"],
            identity,
            exposure["last_confirmed_at"],
            transition_at,
            version,
            event_key,
        )
        if existing is None:
            self.connection.execute(
                """
                INSERT INTO act.findings (
                    fingerprint,
                    target_id,
                    protocol,
                    port,
                    rule_key,
                    status,
                    severity,
                    title,
                    description,
                    observed_address,
                    service_name,
                    service_product,
                    service_version,
                    certificate_sha256,
                    ssh_host_key_sha256,
                    banner_sha256,
                    service_identity_sha256,
                    first_opened_at,
                    last_seen_at,
                    last_changed_at,
                    finding_version,
                    last_event_key
                )
                VALUES (
                    %s, %s, %s, %s, %s, 'open',
                    %s, %s, %s, %s::INET, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    fingerprint,
                    exposure["target_id"],
                    exposure["protocol"],
                    exposure["port"],
                    rule["rule_key"],
                    rule["severity"],
                    rule["name"],
                    rule["description"],
                    exposure["observed_address"],
                    exposure["service_name"],
                    exposure["service_product"],
                    exposure["service_version"],
                    exposure["certificate_sha256"],
                    exposure["ssh_host_key_sha256"],
                    exposure["banner_sha256"],
                    identity,
                    exposure["first_opened_at"],
                    exposure["last_confirmed_at"],
                    transition_at,
                    version,
                    event_key,
                ),
            )
        else:
            self.connection.execute(
                """
                UPDATE act.findings
                SET status = 'open',
                    severity = %s,
                    title = %s,
                    description = %s,
                    observed_address = %s::INET,
                    service_name = %s,
                    service_product = %s,
                    service_version = %s,
                    certificate_sha256 = %s,
                    ssh_host_key_sha256 = %s,
                    banner_sha256 = %s,
                    service_identity_sha256 = %s,
                    last_seen_at = GREATEST(last_seen_at, %s),
                    last_changed_at = %s,
                    resolved_at = NULL,
                    resolution_reason = NULL,
                    finding_version = %s,
                    last_event_key = %s
                WHERE fingerprint = %s
                """,
                (*values, fingerprint),
            )

        self._insert_finding_event(
            event_key=event_key,
            fingerprint=fingerprint,
            target_id=exposure["target_id"],
            target_generation=target["current_generation"],
            protocol=exposure["protocol"],
            port=exposure["port"],
            rule_key=rule["rule_key"],
            event_type=event_type,
            previous_status=previous_status,
            new_status="open",
            severity=rule["severity"],
            reason=reason,
            finding_version=version,
            source_kind=source_kind,
            source_key=source_key,
            source_attempt_id=source_attempt_id,
            service_identity_sha256=identity,
            occurred_at=transition_at,
        )
        if not queue_event_handoff:
            return None
        return self._queue_finding_event(
            event_key=event_key,
            fingerprint=fingerprint,
            source_attempt_id=source_attempt_id,
            finding_bucket=finding_bucket,
        )

    def _resolve_finding(
        self,
        *,
        finding: Mapping[str, Any],
        target_generation: int,
        reason: str,
        source_kind: str,
        source_key: str,
        source_attempt_id: str | None,
        occurred_at: datetime,
        finding_bucket: str,
        queue_event_handoff: bool,
    ) -> str | None:
        if finding["status"] != "open":
            return None
        fingerprint = finding["fingerprint"].strip()
        identity = finding["service_identity_sha256"].strip()
        version = finding["finding_version"] + 1
        transition_at = max(
            occurred_at,
            finding["first_opened_at"],
            finding["last_seen_at"],
            finding["last_changed_at"],
        )
        event_key = stable_hash(
            "act-finding-event-v1",
            fingerprint,
            source_kind,
            source_key,
            "resolved",
            version,
        )
        self.connection.execute(
            """
            UPDATE act.findings
            SET status = 'resolved',
                last_changed_at = %s,
                resolved_at = %s,
                resolution_reason = %s,
                finding_version = %s,
                last_event_key = %s
            WHERE fingerprint = %s
            """,
            (
                transition_at,
                transition_at,
                reason,
                version,
                event_key,
                fingerprint,
            ),
        )
        self._insert_finding_event(
            event_key=event_key,
            fingerprint=fingerprint,
            target_id=finding["target_id"],
            target_generation=target_generation,
            protocol=finding["protocol"],
            port=finding["port"],
            rule_key=finding["rule_key"],
            event_type="resolved",
            previous_status="open",
            new_status="resolved",
            severity=finding["severity"],
            reason=reason,
            finding_version=version,
            source_kind=source_kind,
            source_key=source_key,
            source_attempt_id=source_attempt_id,
            service_identity_sha256=identity,
            occurred_at=transition_at,
        )
        if not queue_event_handoff:
            return None
        return self._queue_finding_event(
            event_key=event_key,
            fingerprint=fingerprint,
            source_attempt_id=source_attempt_id,
            finding_bucket=finding_bucket,
        )

    def _insert_finding_event(
        self,
        *,
        event_key: str,
        fingerprint: str,
        target_id: str,
        target_generation: int,
        protocol: str,
        port: int,
        rule_key: str,
        event_type: str,
        previous_status: str | None,
        new_status: str,
        severity: str,
        reason: str,
        finding_version: int,
        source_kind: str,
        source_key: str,
        source_attempt_id: str | None,
        service_identity_sha256: str,
        occurred_at: datetime,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO act.finding_events (
                event_key,
                fingerprint,
                target_id,
                target_generation,
                protocol,
                port,
                rule_key,
                event_type,
                previous_status,
                new_status,
                severity,
                reason,
                finding_version,
                source_kind,
                source_key,
                source_attempt_id,
                service_identity_sha256,
                occurred_at
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                event_key,
                fingerprint,
                target_id,
                target_generation,
                protocol,
                port,
                rule_key,
                event_type,
                previous_status,
                new_status,
                severity,
                reason,
                finding_version,
                source_kind,
                source_key,
                source_attempt_id,
                service_identity_sha256,
                occurred_at,
            ),
        )

    def _finding_payload(
        self,
        fingerprint: str,
        *,
        kind: str,
        event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        finding = self.connection.execute(
            """
            SELECT finding.*, target.provider, target.current_generation
            FROM act.findings AS finding
            JOIN act.targets AS target USING (target_id)
            WHERE finding.fingerprint = %s
            """,
            (fingerprint,),
        ).fetchone()
        if finding is None:
            raise DataInvariantError("finding disappeared while queuing handoff")
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "kind": kind,
            "finding": {
                "fingerprint": finding["fingerprint"].strip(),
                "target_id": finding["target_id"],
                "provider": finding["provider"],
                "generation": finding["current_generation"],
                "protocol": finding["protocol"],
                "port": finding["port"],
                "rule_key": finding["rule_key"],
                "status": finding["status"],
                "severity": finding["severity"],
                "title": finding["title"],
                "description": finding["description"],
                "observed_address": str(finding["observed_address"]),
                "service": {
                    "name": finding["service_name"],
                    "product": finding["service_product"],
                    "version": finding["service_version"],
                    "certificate_sha256": (
                        None
                        if finding["certificate_sha256"] is None
                        else finding["certificate_sha256"].strip()
                    ),
                    "ssh_host_key_sha256": (
                        None
                        if finding["ssh_host_key_sha256"] is None
                        else finding["ssh_host_key_sha256"].strip()
                    ),
                    "banner_sha256": (
                        None
                        if finding["banner_sha256"] is None
                        else finding["banner_sha256"].strip()
                    ),
                    "identity_sha256": finding["service_identity_sha256"].strip(),
                },
                "first_opened_at": _timestamp(finding["first_opened_at"]),
                "last_seen_at": _timestamp(finding["last_seen_at"]),
                "last_changed_at": _timestamp(finding["last_changed_at"]),
                "resolved_at": (
                    None if finding["resolved_at"] is None else _timestamp(finding["resolved_at"])
                ),
                "resolution_reason": finding["resolution_reason"],
                "version": finding["finding_version"],
            },
        }
        if event is not None:
            payload["event"] = {
                "event_key": event["event_key"].strip(),
                "event_type": event["event_type"],
                "previous_status": event["previous_status"],
                "new_status": event["new_status"],
                "reason": event["reason"],
                "occurred_at": _timestamp(event["occurred_at"]),
                "source": {
                    "kind": event["source_kind"],
                    "key": event["source_key"],
                },
            }
        try:
            return dict(validate_finding(payload))
        except ContractValidationError as error:
            raise RuleConfigurationError(
                "finding payload produced by editable detection policy failed the shared contract"
            ) from error

    def _queue_finding_event(
        self,
        *,
        event_key: str,
        fingerprint: str,
        source_attempt_id: str | None,
        finding_bucket: str,
    ) -> str:
        if not finding_bucket:
            raise DataInvariantError("finding bucket must not be empty")
        event = self.connection.execute(
            "SELECT * FROM act.finding_events WHERE event_key = %s",
            (event_key,),
        ).fetchone()
        payload = self._finding_payload(
            fingerprint,
            kind="finding_event",
            event=event,
        )
        encoded = canonical_payload_bytes(payload)
        payload_sha256 = hashlib.sha256(encoded).hexdigest()
        handoff_key = stable_hash("act-handoff-v1", "finding_event", event_key, finding_bucket)
        object_key = f"findings/events/{fingerprint}/{event_key}.json"
        self.connection.execute(
            """
            INSERT INTO act.finding_handoffs (
                handoff_key,
                fingerprint,
                finding_event_key,
                source_attempt_id,
                handoff_kind,
                object_bucket,
                object_key,
                payload,
                payload_sha256
            )
            VALUES (%s, %s, %s, %s, 'finding_event', %s, %s, %s, %s)
            ON CONFLICT (handoff_key) DO NOTHING
            """,
            (
                handoff_key,
                fingerprint,
                event_key,
                source_attempt_id,
                finding_bucket,
                object_key,
                Jsonb(payload),
                payload_sha256,
            ),
        )
        return handoff_key

    def _close_for_generation_gap_reactivation(
        self,
        event: TargetEvent,
        *,
        finding_bucket: str | None,
    ) -> None:
        keys = {
            (row["protocol"], row["port"])
            for row in self.connection.execute(
                """
                SELECT protocol, port
                FROM act.exposure_state
                WHERE target_id = %s AND state = 'open'
                FOR UPDATE
                """,
                (event.target_id,),
            ).fetchall()
        }
        keys.update(
            (row["protocol"], row["port"])
            for row in self.connection.execute(
                """
                SELECT protocol, port
                FROM act.findings
                WHERE target_id = %s AND status = 'open'
                FOR UPDATE
                """,
                (event.target_id,),
            ).fetchall()
        )
        if not keys:
            return
        if not finding_bucket:
            raise DataInvariantError(
                "finding bucket is required to publish generation-gap transitions"
            )

        for protocol, port in sorted(keys):
            self._close_exposure(
                target_id=event.target_id,
                generation=event.generation,
                protocol=protocol,
                port=port,
                source_attempt_id=None,
                source_key=event.event_id,
                occurred_at=event.source_observed_at,
                reason="generation_gap_reactivation",
            )
        self._reconcile_finding_keys(
            keys,
            target_id=event.target_id,
            source_kind="target_event",
            source_key=event.event_id,
            source_attempt_id=None,
            occurred_at=event.source_observed_at,
            finding_bucket=finding_bucket,
            transition_types=dict.fromkeys(keys, "closed"),
        )

    def _close_for_address_binding_change(
        self,
        event: TargetEvent,
        *,
        finding_bucket: str | None,
    ) -> None:
        current_addresses = {parse_address(address) for address in event.addresses}
        keys = {
            (row["protocol"], row["port"])
            for row in self.connection.execute(
                """
                SELECT protocol, port, observed_address
                FROM act.exposure_state
                WHERE target_id = %s AND state = 'open'
                FOR UPDATE
                """,
                (event.target_id,),
            ).fetchall()
            if str(row["observed_address"]) not in current_addresses
        }
        keys.update(
            (row["protocol"], row["port"])
            for row in self.connection.execute(
                """
                SELECT protocol, port, observed_address
                FROM act.findings
                WHERE target_id = %s AND status = 'open'
                FOR UPDATE
                """,
                (event.target_id,),
            ).fetchall()
            if str(row["observed_address"]) not in current_addresses
        )
        if not keys:
            return
        if not finding_bucket:
            raise DataInvariantError(
                "finding bucket is required to publish address-binding transitions"
            )

        transitions: dict[tuple[str, int], str] = {}
        for protocol, port in sorted(keys):
            _applied, transition = self._close_exposure(
                target_id=event.target_id,
                generation=event.generation,
                protocol=protocol,
                port=port,
                source_attempt_id=None,
                source_key=event.event_id,
                occurred_at=event.source_observed_at,
                reason="address_binding_changed",
            )
            if transition is not None:
                transitions[(protocol, port)] = transition
        self._reconcile_finding_keys(
            keys,
            target_id=event.target_id,
            source_kind="target_event",
            source_key=event.event_id,
            source_attempt_id=None,
            occurred_at=event.source_observed_at,
            finding_bucket=finding_bucket,
            transition_types=transitions,
        )

    def _close_for_ownership_removal(
        self,
        event: TargetEvent,
        *,
        finding_bucket: str | None,
    ) -> None:
        keys = {
            (row["protocol"], row["port"])
            for row in self.connection.execute(
                """
                SELECT protocol, port
                FROM act.exposure_state
                WHERE target_id = %s AND state = 'open'
                FOR UPDATE
                """,
                (event.target_id,),
            ).fetchall()
        }
        keys.update(
            (row["protocol"], row["port"])
            for row in self.connection.execute(
                """
                SELECT protocol, port
                FROM act.findings
                WHERE target_id = %s AND status = 'open'
                FOR UPDATE
                """,
                (event.target_id,),
            ).fetchall()
        )
        for protocol, port in sorted(keys):
            self._close_exposure(
                target_id=event.target_id,
                generation=event.generation,
                protocol=protocol,
                port=port,
                source_attempt_id=None,
                source_key=event.event_id,
                occurred_at=event.removed_at or event.source_observed_at,
                reason="ownership_removed",
            )
        if keys:
            self._reconcile_finding_keys(
                keys,
                target_id=event.target_id,
                source_kind="target_event",
                source_key=event.event_id,
                source_attempt_id=None,
                occurred_at=event.removed_at or event.source_observed_at,
                finding_bucket=finding_bucket or "",
                transition_types=dict.fromkeys(keys, "closed"),
            )

    def reconcile_all(
        self,
        invocation_key: str,
        *,
        finding_bucket: str,
    ) -> ReconciliationResult:
        run_key = stable_hash("act-reconciliation-v1", invocation_key)
        with self.connection.transaction():
            run = self.connection.execute(
                """
                SELECT *
                FROM act.reconciliation_runs
                WHERE run_key = %s
                FOR UPDATE
                """,
                (run_key,),
            ).fetchone()
            if run is not None and run["completed_at"] is not None:
                return ReconciliationResult(
                    duplicate=True,
                    findings_examined=run["findings_examined"],
                    handoff_keys=tuple(self._pending_handoff_keys(run_key=run_key)),
                )
            if run is None:
                self.connection.execute(
                    """
                    INSERT INTO act.reconciliation_runs (run_key, invocation_key)
                    VALUES (%s, %s)
                    """,
                    (run_key, invocation_key),
                )

            key_rows = self.connection.execute(
                """
                SELECT target_id, protocol, port FROM act.exposure_state
                UNION
                SELECT target_id, protocol, port FROM act.findings
                ORDER BY target_id, protocol, port
                """
            ).fetchall()
            grouped: dict[str, set[tuple[str, int]]] = {}
            for row in key_rows:
                grouped.setdefault(row["target_id"], set()).add((row["protocol"], row["port"]))

            queued: list[str] = []
            now = _utcnow()
            for target_id, keys in sorted(grouped.items()):
                queued.extend(
                    self._reconcile_finding_keys(
                        keys,
                        target_id=target_id,
                        source_kind="reconciliation",
                        source_key=invocation_key,
                        source_attempt_id=None,
                        occurred_at=now,
                        finding_bucket=finding_bucket,
                    )
                )

            current = self.connection.execute(
                "SELECT * FROM act.current_findings ORDER BY fingerprint"
            ).fetchall()
            queued.extend(
                self._queue_current_snapshot(
                    finding["fingerprint"].strip(),
                    run_key=run_key,
                    finding_bucket=finding_bucket,
                )
                for finding in current
            )
            self.connection.execute(
                """
                UPDATE act.reconciliation_runs
                SET completed_at = %s,
                    findings_examined = %s,
                    handoffs_queued = %s
                WHERE run_key = %s
                """,
                (now, len(key_rows), len(set(queued)), run_key),
            )
        return ReconciliationResult(
            duplicate=False,
            findings_examined=len(key_rows),
            handoff_keys=tuple(dict.fromkeys(queued)),
        )

    def _queue_current_snapshot(
        self,
        fingerprint: str,
        *,
        run_key: str,
        finding_bucket: str,
    ) -> str:
        if not finding_bucket:
            raise DataInvariantError("finding bucket must not be empty")
        payload = self._finding_payload(fingerprint, kind="current_finding")
        encoded = canonical_payload_bytes(payload)
        payload_sha256 = hashlib.sha256(encoded).hexdigest()
        handoff_key = stable_hash(
            "act-handoff-v1",
            "current_snapshot",
            run_key,
            fingerprint,
            finding_bucket,
        )
        object_key = f"findings/current/{run_key}/{fingerprint}.json"
        self.connection.execute(
            """
            INSERT INTO act.finding_handoffs (
                handoff_key,
                fingerprint,
                run_key,
                handoff_kind,
                object_bucket,
                object_key,
                payload,
                payload_sha256
            )
            VALUES (%s, %s, %s, 'current_snapshot', %s, %s, %s, %s)
            ON CONFLICT (handoff_key) DO NOTHING
            """,
            (
                handoff_key,
                fingerprint,
                run_key,
                finding_bucket,
                object_key,
                Jsonb(payload),
                payload_sha256,
            ),
        )
        return handoff_key

    def _pending_handoff_keys(
        self,
        *,
        source_attempt_id: str | None = None,
        run_key: str | None = None,
    ) -> list[str]:
        rows = self.connection.execute(
            """
            SELECT handoff_key
            FROM act.finding_handoffs
            WHERE published_at IS NULL
              AND (%s::TEXT IS NULL OR source_attempt_id = %s)
              AND (%s::TEXT IS NULL OR run_key = %s)
            ORDER BY created_at, handoff_key
            """,
            (source_attempt_id, source_attempt_id, run_key, run_key),
        ).fetchall()
        return [row["handoff_key"].strip() for row in rows]

    def pending_target_event_handoff_keys(self, event_id: str) -> tuple[str, ...]:
        rows = self.connection.execute(
            """
            SELECT handoff.handoff_key
            FROM act.finding_handoffs AS handoff
            JOIN act.finding_events AS event
              ON event.event_key = handoff.finding_event_key
            WHERE handoff.published_at IS NULL
              AND event.source_kind = 'target_event'
              AND event.source_key = %s
            ORDER BY handoff.created_at, handoff.handoff_key
            """,
            (event_id,),
        ).fetchall()
        return tuple(row["handoff_key"].strip() for row in rows)

    def pending_handoffs(
        self,
        *,
        keys: Sequence[str] | None = None,
        limit: int = 1000,
    ) -> list[Mapping[str, Any]]:
        if keys is not None and not keys:
            return []
        if keys is None:
            return self.connection.execute(
                """
                SELECT *
                FROM act.finding_handoffs
                WHERE published_at IS NULL
                ORDER BY created_at, handoff_key
                LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return self.connection.execute(
            """
            SELECT *
            FROM act.finding_handoffs
            WHERE published_at IS NULL
              AND handoff_key = ANY(%s)
            ORDER BY created_at, handoff_key
            LIMIT %s
            """,
            (list(keys), limit),
        ).fetchall()

    def record_handoff_attempt(self, handoff_key: str) -> None:
        with self.connection.transaction():
            self.connection.execute(
                """
                UPDATE act.finding_handoffs
                SET publish_attempts = publish_attempts + 1,
                    first_attempted_at = COALESCE(
                        first_attempted_at,
                        clock_timestamp()
                    ),
                    last_attempted_at = clock_timestamp()
                WHERE handoff_key = %s AND published_at IS NULL
                """,
                (handoff_key,),
            )

    def record_handoff_error(self, handoff_key: str, error_code: str) -> None:
        with self.connection.transaction():
            self.connection.execute(
                """
                UPDATE act.finding_handoffs
                SET last_error_code = %s
                WHERE handoff_key = %s AND published_at IS NULL
                """,
                (error_code[:128], handoff_key),
            )

    def mark_handoff_published(self, handoff_key: str) -> None:
        with self.connection.transaction():
            self.connection.execute(
                """
                UPDATE act.finding_handoffs
                SET published_at = COALESCE(published_at, clock_timestamp()),
                    last_error_code = NULL
                WHERE handoff_key = %s
                """,
                (handoff_key,),
            )
