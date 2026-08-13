from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from botocore.exceptions import ClientError

from portscanner_contracts import Finding

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "db" / "migrator" / "src"))

from act_migrator import Migrator, discover_migrations  # noqa: E402
from act_parser.database import Repository, finding_fingerprint  # noqa: E402
from act_parser.handoff import HandoffPublisher  # noqa: E402
from act_parser.models import (  # noqa: E402
    CoverageDeclaration,
    Observation,
    RawResultReference,
    ScanEnvelope,
    TargetEvent,
)
from act_parser.xml_parser import service_identity_sha256  # noqa: E402

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="TEST_DATABASE_URL is required for PostgreSQL integration tests",
    ),
]
BASE_TIME = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
FINDING_BUCKET = "finding-test-bucket"
TARGET_ID = hashlib.sha256(b"target-example-1").hexdigest()


@pytest.fixture(scope="module")
def connection() -> Any:
    migrations = discover_migrations(REPOSITORY_ROOT / "db" / "migrations")
    with psycopg.connect(DATABASE_URL) as database:
        migrator = Migrator(database, migrations)
        migrator.down(target="000000", steps=None)
        migrator.up()
        yield database
        migrator.down(target="000000", steps=None)


@pytest.fixture
def repository(connection: Any) -> Repository:
    connection.execute(
        """
        TRUNCATE TABLE
            act.finding_handoffs,
            act.reconciliation_runs,
            act.finding_events,
            act.findings,
            act.exposure_events,
            act.exposure_state,
            act.observations,
            act.scan_attempt_coverage,
            act.scan_attempts,
            act.target_events,
            act.targets
        RESTART IDENTITY CASCADE
        """
    )
    return Repository(connection)


def _target_event(
    event_id: str,
    *,
    generation: int = 1,
    address: str = "192.0.2.10",
    event_type: str = "upsert",
    minute: int = 0,
    scan_reason: str | None = "target_change",
) -> TargetEvent:
    return TargetEvent(
        event_id=event_id,
        target_id=TARGET_ID,
        generation=generation,
        event_type=event_type,
        provider="aws",
        provider_scope_id="scope-example-1",
        provider_target_id="resource-example-1",
        location="region-example-1",
        addresses=() if event_type == "remove" else (address,),
        context={"environment": "test"},
        source_observed_at=BASE_TIME + timedelta(minutes=minute),
        scan_reason=None if event_type == "remove" else scan_reason,
    )


def _coverage(
    ports: str,
    *,
    protocol: str = "tcp",
    complete: bool = True,
) -> tuple[CoverageDeclaration, ...]:
    return tuple(
        CoverageDeclaration.from_mapping(
            {"protocol": protocol, "ports": [ports], "complete": complete}
        )
    )


def _envelope(
    attempt_id: str,
    *,
    generation: int = 1,
    address: str = "192.0.2.10",
    outcome: str = "complete",
    coverage: tuple[CoverageDeclaration, ...] | None = None,
    minute: int = 1,
) -> ScanEnvelope:
    started = BASE_TIME + timedelta(minutes=minute)
    completed = started + timedelta(seconds=10)
    return ScanEnvelope(
        attempt_id=attempt_id,
        result_id=hashlib.sha256(f"result:{attempt_id}".encode()).hexdigest(),
        run_id=f"run-{attempt_id}",
        directive_id=hashlib.sha256(f"directive:{attempt_id}".encode()).hexdigest(),
        target_event_id=f"event-for-{attempt_id}",
        trace_id=f"trace-for-{attempt_id}",
        provider="aws",
        target_id=TARGET_ID,
        generation=generation,
        address=address,
        profile="test-profile",
        scanner_version="sha256:test-scanner",
        outcome=outcome,
        exit_code=0 if outcome == "complete" else None,
        error_type=None if outcome == "complete" else outcome,
        error_retryable=None if outcome == "complete" else True,
        scan_started_at=started,
        scan_completed_at=completed,
        result_uploaded_at=completed + timedelta(seconds=1),
        coverage=coverage or _coverage("1-65535"),
        declared_open_tcp_ports=(),
        raw_result=RawResultReference(
            bucket="raw-test-bucket",
            key=f"raw/{attempt_id}.xml",
            sha256=hashlib.sha256(attempt_id.encode("utf-8")).hexdigest(),
        ),
        enrichment_result=None,
    )


def _observation(
    port: int,
    *,
    address: str = "192.0.2.10",
    state: str = "open",
    product: str = "Example Service",
    version: str = "1.0",
    protocol: str = "tcp",
    minute: int = 1,
) -> Observation:
    identity = service_identity_sha256(
        service_name="example",
        service_product=product,
        service_version=version,
        certificate_sha256=None,
        ssh_host_key_sha256=None,
        banner_sha256=None,
    )
    return Observation(
        protocol=protocol,
        port=port,
        observed_address=address,
        state=state,
        service_name="example",
        service_product=product,
        service_version=version,
        certificate_sha256=None,
        ssh_host_key_sha256=None,
        banner_sha256=None,
        service_identity_sha256=identity,
        observed_at=BASE_TIME + timedelta(minutes=minute),
    )


def _ingest(
    repository: Repository,
    envelope: ScanEnvelope,
    observations: list[Observation],
    *,
    finding_bucket: str | None = FINDING_BUCKET,
    queue_finding_handoffs: bool = True,
) -> Any:
    target_event = repository.connection.execute(
        """
        SELECT event_id
        FROM act.target_events
        WHERE target_id = %s AND generation = %s
        ORDER BY received_at DESC
        LIMIT 1
        """,
        (envelope.target_id, envelope.generation),
    ).fetchone()
    envelope = replace(envelope, target_event_id=target_event["event_id"])
    return repository.ingest_scan(
        envelope,
        observations,
        envelope_bucket="envelope-test-bucket",
        envelope_key=f"results/{envelope.attempt_id}.json",
        envelope_version=None,
        envelope_sha256=hashlib.sha256(f"envelope:{envelope.attempt_id}".encode()).hexdigest(),
        raw_result_version=None,
        enrichment_result_version=None,
        finding_bucket=finding_bucket,
        xml_completion_validated=envelope.outcome == "complete",
        queue_finding_handoffs=queue_finding_handoffs,
    )


def _state(connection: Any, port: int) -> str | None:
    row = connection.execute(
        """
        SELECT state
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = %s
        """,
        (TARGET_ID, port),
    ).fetchone()
    return None if row is None else row["state"]


def _scalar(
    connection: Any,
    statement: str,
    parameters: tuple[Any, ...] = (),
) -> Any:
    row = connection.execute(statement, parameters).fetchone()
    return next(iter(row.values()))


def test_duplicate_stale_generation_and_reassigned_address(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-1"))
    first = _envelope("attempt-1")
    assert not _ingest(repository, first, [_observation(22)]).duplicate
    assert _ingest(repository, first, [_observation(22)]).duplicate
    assert _scalar(connection, "SELECT count(*) FROM act.scan_attempts") == 1
    assert _scalar(connection, "SELECT count(*) FROM act.observations") == 1

    repository.apply_target_event(
        _target_event(
            "target-upsert-2",
            generation=2,
            address="192.0.2.20",
            minute=2,
        ),
        finding_bucket=FINDING_BUCKET,
    )
    stale = _ingest(
        repository,
        _envelope("attempt-stale", generation=1, minute=3),
        [_observation(80, minute=3)],
    )
    assert stale.stale_generation
    assert not stale.state_eligible
    assert _state(connection, 80) is None
    assert (
        _scalar(
            connection,
            "SELECT count(*) FROM act.observations WHERE attempt_id = 'attempt-stale'",
        )
        == 1
    )

    current = _ingest(
        repository,
        _envelope(
            "attempt-current",
            generation=2,
            address="192.0.2.20",
            minute=4,
        ),
        [_observation(22, address="192.0.2.20", minute=4)],
    )
    assert current.state_eligible
    row = connection.execute(
        """
        SELECT host(observed_address) AS observed_address, count(*) OVER () AS row_count
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = 22
        """,
        (TARGET_ID,),
    ).fetchone()
    assert row == {"observed_address": "192.0.2.20", "row_count": 1}


def test_targeted_full_partial_timeout_and_explicit_closure(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-closure"))
    _ingest(
        repository,
        _envelope("attempt-open"),
        [_observation(22), _observation(80), _observation(443)],
    )

    _ingest(
        repository,
        _envelope("attempt-targeted", coverage=_coverage("80"), minute=2),
        [],
    )
    assert _state(connection, 80) == "closed"
    assert _state(connection, 22) == "open"
    assert _state(connection, 443) == "open"

    _ingest(
        repository,
        _envelope(
            "attempt-partial",
            outcome="partial",
            coverage=_coverage("1-65535", complete=False),
            minute=3,
        ),
        [],
    )
    partial_attempt = connection.execute(
        """
        SELECT
            attempt.outcome,
            attempt.xml_completion_validated,
            attempt.raw_result_key,
            attempt.raw_result_sha256,
            count(observation.observation_id) AS observation_count
        FROM act.scan_attempts AS attempt
        LEFT JOIN act.observations AS observation
          ON observation.attempt_id = attempt.attempt_id
        WHERE attempt.attempt_id = 'attempt-partial'
        GROUP BY
            attempt.outcome,
            attempt.xml_completion_validated,
            attempt.raw_result_key,
            attempt.raw_result_sha256
        """
    ).fetchone()
    assert partial_attempt == {
        "outcome": "partial",
        "xml_completion_validated": False,
        "raw_result_key": "raw/attempt-partial.xml",
        "raw_result_sha256": hashlib.sha256(b"attempt-partial").hexdigest(),
        "observation_count": 0,
    }
    _ingest(
        repository,
        _envelope(
            "attempt-timeout",
            outcome="timeout",
            coverage=_coverage("1-65535"),
            minute=4,
        ),
        [],
    )
    assert _state(connection, 22) == "open"
    assert _state(connection, 443) == "open"

    _ingest(
        repository,
        _envelope("attempt-filtered", coverage=_coverage("443"), minute=5),
        [_observation(443, state="filtered", minute=5)],
    )
    assert _state(connection, 443) == "closed"
    assert (
        _scalar(
            connection,
            """
        SELECT closure_reason
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = 443
        """,
            (TARGET_ID,),
        )
        == "explicit_filtered"
    )

    _ingest(repository, _envelope("attempt-full", minute=6), [])
    assert _state(connection, 22) == "closed"
    assert (
        _scalar(
            connection,
            """
        SELECT closure_reason
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = 22
        """,
            (TARGET_ID,),
        )
        == "coverage_absence"
    )


def test_scan_attempt_reordering_uses_timestamp_and_attempt_id_watermarks(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-reordering"))
    _ingest(
        repository,
        _envelope("baseline-open"),
        [_observation(100), _observation(101)],
    )

    _ingest(
        repository,
        _envelope("z-equal-winner-100", coverage=_coverage("100"), minute=5),
        [_observation(100, state="closed", minute=5)],
    )
    _ingest(
        repository,
        _envelope("a-equal-loser-100", coverage=_coverage("100"), minute=5),
        [_observation(100, minute=5)],
    )

    _ingest(
        repository,
        _envelope("a-equal-loser-101", coverage=_coverage("101"), minute=5),
        [_observation(101, minute=5)],
    )
    _ingest(
        repository,
        _envelope("z-equal-winner-101", coverage=_coverage("101"), minute=5),
        [_observation(101, state="closed", minute=5)],
    )

    rows = connection.execute(
        """
        SELECT port, state, last_attempt_id
        FROM act.exposure_state
        WHERE target_id = %s AND port IN (100, 101)
        ORDER BY port
        """,
        (TARGET_ID,),
    ).fetchall()
    assert rows == [
        {"port": 100, "state": "closed", "last_attempt_id": "z-equal-winner-100"},
        {"port": 101, "state": "closed", "last_attempt_id": "z-equal-winner-101"},
    ]
    assert _scalar(connection, "SELECT count(*) FROM act.scan_attempts") == 5


def test_address_binding_change_closes_old_address_and_publishes_history(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-old-address"))
    _ingest(
        repository,
        _envelope("attempt-old-address", minute=5),
        [_observation(22, minute=5)],
    )

    repository.apply_target_event(
        _target_event(
            "target-address-changed",
            generation=2,
            address="192.0.2.20",
            minute=2,
        ),
        finding_bucket=FINDING_BUCKET,
    )

    exposure = connection.execute(
        """
        SELECT state, closure_reason, last_changed_at, last_confirmed_at
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = 22
        """,
        (TARGET_ID,),
    ).fetchone()
    assert exposure["state"] == "closed"
    assert exposure["closure_reason"] == "address_binding_changed"
    assert exposure["last_changed_at"] >= BASE_TIME + timedelta(minutes=5, seconds=10)
    assert exposure["last_confirmed_at"] == exposure["last_changed_at"]
    assert _scalar(
        connection,
        "SELECT array_agg(DISTINCT resolution_reason) FROM act.findings",
    ) == ["exposure_closed"]
    assert (
        _scalar(
            connection,
            """
            SELECT count(*)
            FROM act.finding_handoffs AS handoff
            JOIN act.finding_events AS event
              ON event.event_key = handoff.finding_event_key
            WHERE event.source_kind = 'target_event'
              AND event.source_key = 'target-address-changed'
              AND event.event_type = 'resolved'
            """,
        )
        == 2
    )

    _ingest(
        repository,
        _envelope(
            "attempt-new-address",
            generation=2,
            address="192.0.2.20",
            minute=6,
        ),
        [_observation(22, address="192.0.2.20", minute=6)],
    )
    assert _state(connection, 22) == "open"
    assert _scalar(connection, "SELECT count(*) FROM act.exposure_events") >= 3


def test_generation_gap_reactivation_closes_prior_state_at_unchanged_address(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-before-generation-gap"))
    _ingest(
        repository,
        _envelope("attempt-before-generation-gap"),
        [_observation(22)],
    )

    repository.apply_target_event(
        _target_event(
            "target-after-generation-gap",
            generation=3,
            minute=3,
            scan_reason="new_target",
        ),
        finding_bucket=FINDING_BUCKET,
    )

    assert connection.execute(
        """
        SELECT state, closure_reason, last_generation
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = 22
        """,
        (TARGET_ID,),
    ).fetchone() == {
        "state": "closed",
        "closure_reason": "generation_gap_reactivation",
        "last_generation": 3,
    }
    assert _scalar(
        connection,
        "SELECT array_agg(DISTINCT status) FROM act.findings",
    ) == ["resolved"]

    repository.apply_target_event(
        _target_event(
            "missed-removal-arrived-late",
            generation=2,
            event_type="remove",
            minute=2,
        ),
        finding_bucket=FINDING_BUCKET,
    )
    assert connection.execute(
        """
        SELECT status, current_generation, host(current_addresses[1]) AS current_address
        FROM act.targets
        WHERE target_id = %s
        """,
        (TARGET_ID,),
    ).fetchone() == {
        "status": "active",
        "current_generation": 3,
        "current_address": "192.0.2.10",
    }


@pytest.mark.parametrize("scan_reason", ["target_change", "policy_change"])
def test_non_reactivation_generation_gap_preserves_current_state(
    repository: Repository,
    connection: Any,
    scan_reason: str,
) -> None:
    repository.apply_target_event(_target_event("target-before-nonreactivation-gap"))
    _ingest(
        repository,
        _envelope("attempt-before-nonreactivation-gap"),
        [_observation(22)],
    )

    repository.apply_target_event(
        _target_event(
            f"target-after-{scan_reason}-gap",
            generation=3,
            minute=3,
            scan_reason=scan_reason,
        ),
        finding_bucket=FINDING_BUCKET,
    )

    assert _state(connection, 22) == "open"
    assert _scalar(
        connection,
        "SELECT array_agg(DISTINCT status) FROM act.findings",
    ) == ["open"]
    assert (
        _scalar(
            connection,
            "SELECT current_generation FROM act.targets WHERE target_id = %s",
            (TARGET_ID,),
        )
        == 3
    )


def test_late_removal_preserves_source_time_but_uses_monotonic_transitions(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-late-removal"))
    _ingest(
        repository,
        _envelope("attempt-before-late-removal", minute=10),
        [_observation(22, minute=10)],
    )

    repository.apply_target_event(
        _target_event(
            "target-late-removal",
            generation=2,
            event_type="remove",
            minute=2,
        ),
        finding_bucket=FINDING_BUCKET,
    )

    source_removed_at = BASE_TIME + timedelta(minutes=2)
    assert (
        _scalar(
            connection,
            "SELECT removed_at FROM act.target_events WHERE event_id = 'target-late-removal'",
        )
        == source_removed_at
    )
    finding = connection.execute(
        """
        SELECT last_seen_at, last_changed_at, resolved_at, resolution_reason
        FROM act.findings
        WHERE target_id = %s
        ORDER BY fingerprint
        LIMIT 1
        """,
        (TARGET_ID,),
    ).fetchone()
    assert finding["resolution_reason"] == "ownership_removed"
    assert finding["last_changed_at"] >= finding["last_seen_at"]
    assert finding["resolved_at"] == finding["last_changed_at"]
    assert finding["resolved_at"] > source_removed_at


def test_reopen_service_change_and_deterministic_findings(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-findings"))
    _ingest(
        repository,
        _envelope("attempt-db-open"),
        [_observation(5432, version="1.0")],
    )
    expected = {
        finding_fingerprint("new-or-reopened-exposure", TARGET_ID, "tcp", 5432),
        finding_fingerprint("common-public-database-port", TARGET_ID, "tcp", 5432),
    }
    rows = connection.execute(
        "SELECT fingerprint, status FROM act.findings ORDER BY fingerprint"
    ).fetchall()
    assert {row["fingerprint"].strip() for row in rows} == expected
    assert {row["status"] for row in rows} == {"open"}

    _ingest(
        repository,
        _envelope("attempt-db-close", coverage=_coverage("5432"), minute=2),
        [],
    )
    assert _scalar(connection, "SELECT array_agg(DISTINCT status) FROM act.findings") == [
        "resolved"
    ]

    _ingest(
        repository,
        _envelope("attempt-db-reopen", minute=3),
        [_observation(5432, version="2.0", minute=3)],
    )
    _ingest(
        repository,
        _envelope("attempt-db-update", minute=4),
        [_observation(5432, version="3.0", minute=4)],
    )
    final_rows = connection.execute(
        """
        SELECT fingerprint, status, service_version, finding_version
        FROM act.findings
        ORDER BY fingerprint
        """
    ).fetchall()
    assert {row["fingerprint"].strip() for row in final_rows} == expected
    assert all(row["status"] == "open" and row["service_version"] == "3.0" for row in final_rows)
    assert all(row["finding_version"] >= 4 for row in final_rows)
    assert _scalar(connection, "SELECT count(*) FROM act.findings") == 2


def test_target_removal_resolves_current_state_and_preserves_history(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-removal"))
    _ingest(repository, _envelope("attempt-management"), [_observation(22)])

    repository.apply_target_event(
        _target_event(
            "target-remove",
            generation=2,
            event_type="remove",
            minute=2,
        ),
        finding_bucket=FINDING_BUCKET,
    )

    target = connection.execute(
        """
        SELECT status, current_generation
        FROM act.targets
        WHERE target_id = %s
        """,
        (TARGET_ID,),
    ).fetchone()
    assert target == {"status": "removed", "current_generation": 2}
    assert connection.execute(
        """
        SELECT state, closure_reason
        FROM act.exposure_state
        WHERE target_id = %s AND protocol = 'tcp' AND port = 22
        """,
        (TARGET_ID,),
    ).fetchone() == {
        "state": "closed",
        "closure_reason": "ownership_removed",
    }
    assert _scalar(
        connection,
        "SELECT array_agg(DISTINCT resolution_reason) FROM act.findings",
    ) == ["ownership_removed"]
    assert _scalar(connection, "SELECT count(*) FROM act.finding_events") > 2
    assert _scalar(connection, "SELECT count(*) FROM act.current_findings") == 0


class _ExistingObjectS3:
    def __init__(self, payload_sha256: str) -> None:
        self.payload_sha256 = payload_sha256

    def put_object(self, **_kwargs: Any) -> None:
        raise ClientError(
            {
                "Error": {"Code": "PreconditionFailed"},
                "ResponseMetadata": {"HTTPStatusCode": 412},
            },
            "PutObject",
        )

    def head_object(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Metadata": {"payload-sha256": self.payload_sha256}}


def test_handoff_retry_and_processor_current_only_export(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(_target_event("target-upsert-handoff"))
    result = _ingest(
        repository,
        _envelope("attempt-handoff"),
        [_observation(5432)],
    )
    handoff = repository.pending_handoffs(keys=result.handoff_keys, limit=1)[0]
    assert Finding.model_validate(handoff["payload"]).kind.value == "finding_event"
    assert str(handoff["object_key"]).startswith("findings/events/")
    publisher = HandoffPublisher(
        _ExistingObjectS3(handoff["payload_sha256"].strip()),
        repository,
    )
    assert publisher.publish_pending(keys=[handoff["handoff_key"].strip()]) == 1
    assert publisher.publish_pending(keys=[handoff["handoff_key"].strip()]) == 0
    assert connection.execute(
        """
        SELECT published_at IS NOT NULL AS published, publish_attempts
        FROM act.finding_handoffs
        WHERE handoff_key = %s
        """,
        (handoff["handoff_key"],),
    ).fetchone() == {"published": True, "publish_attempts": 1}

    connection.execute(
        """
        UPDATE act.detection_rules
        SET severity = 'critical', updated_at = clock_timestamp()
        WHERE rule_key = 'common-public-database-port'
        """
    )
    reconciliation = repository.reconcile_all(
        "scheduled-repair-1",
        finding_bucket=FINDING_BUCKET,
    )
    assert not reconciliation.duplicate
    assert repository.reconcile_all(
        "scheduled-repair-1",
        finding_bucket=FINDING_BUCKET,
    ).duplicate
    reconciliation_events = connection.execute(
        """
        SELECT payload
        FROM act.finding_handoffs AS handoff
        JOIN act.finding_events AS event
          ON event.event_key = handoff.finding_event_key
        WHERE handoff.handoff_kind = 'finding_event'
          AND event.source_kind = 'reconciliation'
          AND event.source_key = 'scheduled-repair-1'
        ORDER BY handoff.handoff_key
        """
    ).fetchall()
    assert len(reconciliation_events) == 1
    assert reconciliation_events[0]["payload"]["event"]["event_type"] == "updated"
    assert reconciliation_events[0]["payload"]["event"]["reason"] == "rule_changed"
    snapshots = connection.execute(
        """
        SELECT payload, object_key
        FROM act.finding_handoffs
        WHERE handoff_kind = 'current_snapshot'
        ORDER BY handoff_key
        """
    ).fetchall()
    assert len(snapshots) == 2
    assert all(row["payload"]["finding"]["status"] == "open" for row in snapshots)
    assert all(
        Finding.model_validate(row["payload"]).kind.value == "current_finding" for row in snapshots
    )
    assert all(str(row["object_key"]).startswith("findings/current/") for row in snapshots)
    assert all("reconciliation_run_key" not in row["payload"] for row in snapshots)
    serialized = str(snapshots)
    assert "raw_result" not in serialized
    assert "credentials" not in serialized


def test_database_findings_commit_without_export_handoffs(
    repository: Repository,
    connection: Any,
) -> None:
    repository.apply_target_event(
        _target_event("target-upsert-database-only", scan_reason="new_target"),
        finding_bucket=None,
        queue_finding_handoffs=False,
    )
    result = _ingest(
        repository,
        _envelope("attempt-database-only", coverage=_coverage("18080")),
        [_observation(18080)],
        finding_bucket=None,
        queue_finding_handoffs=False,
    )

    assert result.state_eligible
    assert result.handoff_keys == ()
    assert (
        _scalar(
            connection,
            """
            SELECT count(*)
            FROM act.findings
            WHERE target_id = %s
              AND protocol = 'tcp'
              AND port = 18080
              AND status = 'open'
              AND severity = 'low'
            """,
            (TARGET_ID,),
        )
        == 1
    )
    assert _scalar(connection, "SELECT count(*) FROM act.finding_handoffs") == 0

    repository.apply_target_event(
        _target_event(
            "target-remove-database-only",
            generation=2,
            event_type="remove",
            minute=2,
        ),
        finding_bucket=None,
        queue_finding_handoffs=False,
    )
    assert (
        _scalar(
            connection,
            "SELECT count(*) FROM act.findings WHERE status = 'resolved'",
        )
        == 1
    )
    assert _scalar(connection, "SELECT count(*) FROM act.finding_handoffs") == 0
