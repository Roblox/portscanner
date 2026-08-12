"""AWS Lambda partial-batch handler for prioritized Scanner dispatch."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .cancellation import (
    CancellationResult,
    cancel_event_scanner,
    cancel_older_scanners,
    cancel_scanners_through_generation,
)
from .config import GeneratorConfig
from .event_reader import RecordRejection, parse_shared_contract, read_target_event
from .idempotency import (
    ClaimDisposition,
    ClaimState,
    DynamoClaimStore,
    EventClaim,
)
from .kubernetes import CreateResult, KubernetesScannerClient, ScannerClient
from .revalidation import (
    OwnershipCheck,
    OwnershipDecision,
    OwnershipService,
    ownership_service_from_environment,
    revalidate_event,
)
from .scanner_resource import (
    build_scanner_resource,
    identifier_hash,
    scanner_name,
    trace_id_for_event,
)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

_LOG_FIELDS = {
    "message_hash",
    "event_hash",
    "trace_hash",
    "target_hash",
    "generation",
    "verdict",
    "decision",
    "outcome",
    "error_code",
    "cancelled",
}


def _log(level: int, action: str, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "component": "portscanner-generator",
        "action": action,
    }
    payload.update(
        {key: value for key, value in fields.items() if key in _LOG_FIELDS and value is not None}
    )
    LOGGER.log(
        level,
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _event_time(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{field_name} is not an RFC3339 timestamp") from error
    else:
        raise ValueError(f"{field_name} is not an RFC3339 timestamp")
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} has no timezone")
    return parsed.astimezone(UTC)


class RetryableRecordError(RuntimeError):
    """A retryable per-message failure safe to expose by code only."""

    def __init__(
        self,
        code: str,
        *,
        event_hash: str | None = None,
        trace_hash: str | None = None,
        verdict: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.event_hash = event_hash
        self.trace_hash = trace_hash
        self.verdict = verdict


@dataclass(frozen=True)
class RecordOutcome:
    outcome: str
    event_hash: str
    trace_hash: str
    verdict: str | None = None
    cancelled: int = 0


@dataclass
class GeneratorServices:
    config: GeneratorConfig
    s3_client: Any
    claim_store: DynamoClaimStore
    ownership_service: OwnershipService
    scanner_client_factory: Callable[[], ScannerClient]
    event_parser: Callable[[Mapping[str, Any]], Any] = parse_shared_contract
    clock: Callable[[], datetime] = _now
    _scanner_client: ScannerClient | None = field(default=None, init=False)

    def scanner_client(self) -> ScannerClient:
        if self._scanner_client is None:
            self._scanner_client = self.scanner_client_factory()
        return self._scanner_client


def _hashes(event: Any) -> tuple[str, str, str]:
    return (
        identifier_hash(event.event_id, length=16),
        identifier_hash(trace_id_for_event(event), length=16),
        identifier_hash(event.target.target_id, length=16),
    )


def _enum_text(value: Any) -> str:
    enum_value = getattr(value, "value", value)
    if not isinstance(enum_value, str) or not enum_value:
        raise ValueError("contract enum value must be a non-empty string")
    return enum_value


def _event_type(event: Any) -> str:
    return _enum_text(event.event_type)


def _provider(event: Any) -> str:
    value = getattr(event, "provider", None)
    if value is None:
        value = event.target.provider
    return _enum_text(value)


def _reason(event: Any) -> str:
    if _event_type(event) == "target.removed":
        return "removed"
    return _enum_text(event.scan.reason)


def _retry_claim(
    services: GeneratorServices,
    claim: EventClaim,
    *,
    error_code: str,
) -> None:
    try:
        services.claim_store.mark_retryable(
            claim,
            now=services.clock(),
            error_code=error_code,
        )
    except Exception:
        # The original SQS record remains retryable. An intact CLAIMED lease can
        # be recovered after expiry if this best-effort transition also failed.
        return


def _complete_claim(
    services: GeneratorServices,
    claim: EventClaim,
    *,
    state: ClaimState,
    check: OwnershipCheck,
    scanner_resource_name: str | None = None,
    cancelled_count: int = 0,
) -> None:
    services.claim_store.complete(
        claim,
        state=state,
        now=services.clock(),
        verdict=check.verdict,
        scanner_name=scanner_resource_name,
        cancelled_count=cancelled_count,
    )


def _cancel(
    services: GeneratorServices,
    event: Any,
    *,
    accepted_generation: int | None = None,
    exclude_names: tuple[str, ...] = (),
) -> CancellationResult:
    return cancel_older_scanners(
        services.scanner_client(),
        target_id=event.target.target_id,
        accepted_generation=accepted_generation or event.target.generation,
        exclude_names=exclude_names,
    )


def _cancel_terminal(
    services: GeneratorServices,
    event: Any,
    *,
    check: OwnershipCheck | None = None,
) -> CancellationResult:
    exact_name = scanner_name(event.event_id)
    exact_deleted = cancel_event_scanner(
        services.scanner_client(),
        event_id=event.event_id,
    )
    if check is not None and (
        check.decision is OwnershipDecision.CANCEL
        or (check.decision is OwnershipDecision.STALE and check.reason == "policy-or-lifecycle")
    ):
        result = cancel_scanners_through_generation(
            services.scanner_client(),
            target_id=event.target.target_id,
            unsafe_generation=event.target.generation,
            exclude_names=(exact_name,),
        )
    else:
        accepted_generation = event.target.generation
        if (
            check is not None
            and check.decision is OwnershipDecision.STALE
            and check.current_generation is not None
            and check.current_generation > accepted_generation
        ):
            accepted_generation = check.current_generation
        result = _cancel(
            services,
            event,
            accepted_generation=accepted_generation,
            exclude_names=(exact_name,),
        )
    return CancellationResult(
        matched=result.matched,
        deleted=result.deleted + int(exact_deleted),
    )


def process_sqs_record(
    record: Mapping[str, Any],
    services: GeneratorServices,
) -> RecordOutcome:
    """Process one SQS record without leaking its raw contents to logs."""

    _, event = read_target_event(
        record,
        services.s3_client,
        services.config,
        parser=services.event_parser,
    )
    event_hash, trace_hash, opaque_target_hash = _hashes(event)
    current = _event_time(services.clock(), "clock")
    is_removal = _event_type(event) == "target.removed"
    deadline_at = None if is_removal else _event_time(event.scan.deadline_at, "scan.deadline_at")
    not_after = None if is_removal else _event_time(event.scan.not_after, "scan.not_after")

    try:
        claim_result = services.claim_store.acquire(
            event_id=event.event_id,
            trace_id=trace_id_for_event(event),
            target_id=event.target.target_id,
            generation=event.target.generation,
            event_type=_event_type(event),
            provider=_provider(event),
            reason=_reason(event),
            now=current,
        )
    except Exception as error:
        raise RetryableRecordError(
            "claim_acquire_failed",
            event_hash=event_hash,
            trace_hash=trace_hash,
        ) from error

    if claim_result.disposition is ClaimDisposition.DUPLICATE:
        _log(
            logging.INFO,
            "event_deduplicated",
            event_hash=event_hash,
            trace_hash=trace_hash,
            target_hash=opaque_target_hash,
            generation=event.target.generation,
            outcome="duplicate",
        )
        return RecordOutcome("duplicate", event_hash, trace_hash)
    if claim_result.disposition is ClaimDisposition.BUSY:
        raise RetryableRecordError(
            "claim_busy",
            event_hash=event_hash,
            trace_hash=trace_hash,
        )
    claim = claim_result.claim
    if claim is None:
        raise RetryableRecordError(
            "claim_missing",
            event_hash=event_hash,
            trace_hash=trace_hash,
        )

    if not is_removal and not services.config.target_allowed(str(event.target.public_address)):
        try:
            exact_deleted = cancel_event_scanner(
                services.scanner_client(),
                event_id=event.event_id,
            )
            services.claim_store.complete(
                claim,
                state=ClaimState.CANCELLED,
                now=services.clock(),
                verdict="scope-denied",
                scanner_name=scanner_name(event.event_id),
                cancelled_count=int(exact_deleted),
            )
        except Exception as error:
            _retry_claim(services, claim, error_code="scope_denial_failed")
            raise RetryableRecordError(
                "scope_denial_failed",
                event_hash=event_hash,
                trace_hash=trace_hash,
                verdict="scope-denied",
            ) from error
        _log(
            logging.WARNING,
            "event_rejected",
            event_hash=event_hash,
            trace_hash=trace_hash,
            target_hash=opaque_target_hash,
            generation=event.target.generation,
            verdict="scope-denied",
            outcome="scope_denied",
            cancelled=int(exact_deleted),
        )
        return RecordOutcome(
            "scope_denied",
            event_hash,
            trace_hash,
            "scope-denied",
            int(exact_deleted),
        )

    try:
        check = revalidate_event(services.ownership_service, event)
    except Exception as error:
        _retry_claim(services, claim, error_code="ownership_check_failed")
        raise RetryableRecordError(
            "ownership_check_failed",
            event_hash=event_hash,
            trace_hash=trace_hash,
        ) from error

    _log(
        logging.INFO,
        "ownership_revalidated",
        event_hash=event_hash,
        trace_hash=trace_hash,
        target_hash=opaque_target_hash,
        generation=event.target.generation,
        verdict=check.verdict,
        decision=check.decision.value,
    )
    if check.decision is OwnershipDecision.RETRY:
        _retry_claim(services, claim, error_code="ownership_unknown")
        raise RetryableRecordError(
            "ownership_unknown",
            event_hash=event_hash,
            trace_hash=trace_hash,
            verdict=check.verdict,
        )

    if is_removal:
        try:
            cancellation = _cancel_terminal(services, event, check=check)
            _complete_claim(
                services,
                claim,
                state=ClaimState.REMOVED,
                check=check,
                cancelled_count=cancellation.deleted,
            )
        except Exception as error:
            _retry_claim(services, claim, error_code="removal_failed")
            raise RetryableRecordError(
                "removal_failed",
                event_hash=event_hash,
                trace_hash=trace_hash,
                verdict=check.verdict,
            ) from error
        return RecordOutcome(
            "removed",
            event_hash,
            trace_hash,
            check.verdict,
            cancellation.deleted,
        )

    if check.decision is OwnershipDecision.STALE:
        try:
            cancellation = _cancel_terminal(services, event, check=check)
            _complete_claim(
                services,
                claim,
                state=ClaimState.STALE,
                check=check,
                cancelled_count=cancellation.deleted,
            )
        except Exception as error:
            _retry_claim(services, claim, error_code="audit_finalize_failed")
            raise RetryableRecordError(
                "audit_finalize_failed",
                event_hash=event_hash,
                trace_hash=trace_hash,
                verdict=check.verdict,
            ) from error
        return RecordOutcome(
            "stale",
            event_hash,
            trace_hash,
            check.verdict,
            cancellation.deleted,
        )

    if check.decision is OwnershipDecision.CANCEL:
        try:
            cancellation = _cancel_terminal(services, event, check=check)
            _complete_claim(
                services,
                claim,
                state=ClaimState.CANCELLED,
                check=check,
                cancelled_count=cancellation.deleted,
            )
        except Exception as error:
            _retry_claim(services, claim, error_code="cancellation_failed")
            raise RetryableRecordError(
                "cancellation_failed",
                event_hash=event_hash,
                trace_hash=trace_hash,
                verdict=check.verdict,
            ) from error
        return RecordOutcome(
            "cancelled",
            event_hash,
            trace_hash,
            check.verdict,
            cancellation.deleted,
        )

    try:
        cancellation = _cancel(services, event)
        resource = build_scanner_resource(
            event,
            namespace=services.config.namespace,
            api_group=services.config.api_group,
            api_version=services.config.api_version,
        )
    except Exception as error:
        _retry_claim(services, claim, error_code="dispatch_failed")
        raise RetryableRecordError(
            "dispatch_failed",
            event_hash=event_hash,
            trace_hash=trace_hash,
            verdict=check.verdict,
        ) from error

    # Cancellation can involve multiple API calls. Revalidate again after that
    # work so the ownership/generation gate is immediately adjacent to create.
    try:
        final_check = revalidate_event(services.ownership_service, event)
    except Exception as error:
        _retry_claim(services, claim, error_code="ownership_recheck_failed")
        raise RetryableRecordError(
            "ownership_recheck_failed",
            event_hash=event_hash,
            trace_hash=trace_hash,
        ) from error
    _log(
        logging.INFO,
        "ownership_rechecked",
        event_hash=event_hash,
        trace_hash=trace_hash,
        target_hash=opaque_target_hash,
        generation=event.target.generation,
        verdict=final_check.verdict,
        decision=final_check.decision.value,
    )
    if final_check.decision is OwnershipDecision.RETRY:
        _retry_claim(services, claim, error_code="ownership_unknown")
        raise RetryableRecordError(
            "ownership_unknown",
            event_hash=event_hash,
            trace_hash=trace_hash,
            verdict=final_check.verdict,
        )
    if final_check.decision is not OwnershipDecision.DISPATCH:
        terminal_state = (
            ClaimState.STALE
            if final_check.decision is OwnershipDecision.STALE
            else ClaimState.CANCELLED
        )
        try:
            terminal_cancellation = _cancel_terminal(
                services,
                event,
                check=final_check,
            )
            cancellation = CancellationResult(
                matched=max(cancellation.matched, terminal_cancellation.matched),
                deleted=cancellation.deleted + terminal_cancellation.deleted,
            )
            _complete_claim(
                services,
                claim,
                state=terminal_state,
                check=final_check,
                cancelled_count=cancellation.deleted,
            )
        except Exception as error:
            _retry_claim(services, claim, error_code="audit_finalize_failed")
            raise RetryableRecordError(
                "audit_finalize_failed",
                event_hash=event_hash,
                trace_hash=trace_hash,
                verdict=final_check.verdict,
            ) from error
        return RecordOutcome(
            ("stale" if final_check.decision is OwnershipDecision.STALE else "cancelled"),
            event_hash,
            trace_hash,
            final_check.verdict,
            cancellation.deleted,
        )

    check = final_check
    create_time = _event_time(services.clock(), "clock")
    if (deadline_at is not None and create_time >= deadline_at) or (
        not_after is not None and create_time >= not_after
    ):
        try:
            exact_deleted = cancel_event_scanner(
                services.scanner_client(),
                event_id=event.event_id,
            )
            cancellation = CancellationResult(
                matched=cancellation.matched,
                deleted=cancellation.deleted + int(exact_deleted),
            )
            _complete_claim(
                services,
                claim,
                state=ClaimState.EXPIRED,
                check=check,
                cancelled_count=cancellation.deleted,
            )
        except Exception as error:
            _retry_claim(services, claim, error_code="audit_finalize_failed")
            raise RetryableRecordError(
                "audit_finalize_failed",
                event_hash=event_hash,
                trace_hash=trace_hash,
                verdict=check.verdict,
            ) from error
        return RecordOutcome(
            "expired",
            event_hash,
            trace_hash,
            check.verdict,
            cancellation.deleted,
        )

    try:
        create_result = services.scanner_client().create(resource)
        _complete_claim(
            services,
            claim,
            state=ClaimState.DISPATCHED,
            check=check,
            scanner_resource_name=scanner_name(event.event_id),
            cancelled_count=cancellation.deleted,
        )
    except Exception as error:
        _retry_claim(services, claim, error_code="dispatch_failed")
        raise RetryableRecordError(
            "dispatch_failed",
            event_hash=event_hash,
            trace_hash=trace_hash,
            verdict=check.verdict,
        ) from error

    outcome = "dispatched" if create_result is CreateResult.CREATED else "already_dispatched"
    return RecordOutcome(
        outcome,
        event_hash,
        trace_hash,
        check.verdict,
        cancellation.deleted,
    )


def build_services(config: GeneratorConfig | None = None) -> GeneratorServices:
    """Construct production AWS, inventory, and lazy Kubernetes dependencies."""

    active_config = config or GeneratorConfig.from_environment()
    import boto3

    session = boto3.session.Session(region_name=active_config.aws_region)
    s3_client = session.client("s3", region_name=active_config.aws_region)
    table = session.resource(
        "dynamodb",
        region_name=active_config.aws_region,
    ).Table(active_config.table_name)
    claim_store = DynamoClaimStore(
        table,
        partition_key=active_config.partition_key,
        lease_seconds=active_config.claim_lease_seconds,
        audit_ttl_days=active_config.audit_ttl_days,
    )
    ownership_service = ownership_service_from_environment(
        session=session,
        state_table=active_config.inventory_table_name,
    )

    def scanner_client_factory() -> ScannerClient:
        from .eks_auth import build_custom_objects_api

        return KubernetesScannerClient(
            build_custom_objects_api(active_config, session=session),
            active_config,
        )

    return GeneratorServices(
        config=active_config,
        s3_client=s3_client,
        claim_store=claim_store,
        ownership_service=ownership_service,
        scanner_client_factory=scanner_client_factory,
    )


_CACHED_SERVICES: GeneratorServices | None = None


def _default_services() -> GeneratorServices:
    global _CACHED_SERVICES
    if _CACHED_SERVICES is None:
        _CACHED_SERVICES = build_services()
    return _CACHED_SERVICES


def lambda_handler(
    event: Mapping[str, Any],
    context: Any,
    *,
    services: GeneratorServices | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Return Lambda's SQS partial batch response."""

    del context
    active_services = services or _default_services()
    records = event.get("Records") if isinstance(event, Mapping) else None
    if not isinstance(records, list):
        raise ValueError("Lambda event must contain an SQS Records list")

    failures: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("SQS Records entries must be objects")
        message_id = record.get("messageId")
        if not isinstance(message_id, str) or not message_id:
            raise ValueError("SQS record has no messageId")
        message_hash = identifier_hash(message_id, length=16)
        try:
            outcome = process_sqs_record(record, active_services)
            _log(
                logging.INFO,
                "record_completed",
                message_hash=message_hash,
                event_hash=outcome.event_hash,
                trace_hash=outcome.trace_hash,
                verdict=outcome.verdict,
                outcome=outcome.outcome,
                cancelled=outcome.cancelled,
            )
        except RecordRejection as error:
            _log(
                logging.WARNING,
                "record_rejected",
                message_hash=message_hash,
                error_code=error.code,
                outcome="quarantine",
            )
            failures.append({"itemIdentifier": message_id})
        except RetryableRecordError as error:
            _log(
                logging.WARNING,
                "record_retryable",
                message_hash=message_hash,
                event_hash=error.event_hash,
                trace_hash=error.trace_hash,
                verdict=error.verdict,
                error_code=error.code,
                outcome="retry",
            )
            failures.append({"itemIdentifier": message_id})
        except Exception:
            _log(
                logging.ERROR,
                "record_retryable",
                message_hash=message_hash,
                error_code="unexpected_processing_failure",
                outcome="retry",
            )
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}


handler = lambda_handler
