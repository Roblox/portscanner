"""Build bounded shared contracts from normalized AWS observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from portscanner_contracts import (
    FULL_TCP_PORT_RANGE,
    SCHEMA_VERSION,
    AddressFamily,
    AwsContext,
    AwsTags,
    CloudProvider,
    PolicyChange,
    ScanDirective,
    ScanProfile,
    ScanReason,
    SourceObservation,
    Target,
    TargetEvent,
    TargetEventType,
    TargetRemoval,
    TcpPortRange,
    TransportProtocol,
    canonical_json,
    deterministic_sha256,
)

from portscanner_inventory.aws.normalize import NormalizedTarget
from portscanner_inventory.base import CandidatePorts, SnapshotScope

PRIORITY_DISPATCH_WINDOW = timedelta(minutes=5)
PRIORITY_EXECUTION_WINDOW = timedelta(minutes=30)
MANUAL_DISPATCH_WINDOW = timedelta(minutes=10)
COVERAGE_DISPATCH_WINDOW = timedelta(hours=2)
COVERAGE_EXECUTION_WINDOW = timedelta(hours=6)


@dataclass(frozen=True, slots=True)
class EventSource:
    name: str
    event_id: str
    request_id: str
    event_time: datetime
    observed_at: datetime


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("event timestamp must be timezone aware")
    return value.astimezone(UTC)


def snapshot_source(
    scope: SnapshotScope,
    collected_at: datetime,
    *,
    observed_at: datetime | None = None,
) -> EventSource:
    collected_at = _utc(collected_at)
    observation = _utc(observed_at or collected_at)
    if observation > collected_at:
        raise ValueError("snapshot observation cannot be later than collection")
    identity = {
        "scope": scope.key,
        "observed_at": observation,
        "collected_at": collected_at,
    }
    event_id = deterministic_sha256("portscanner.inventory.snapshot.v1", identity)
    return EventSource(
        name=scope.source,
        event_id=event_id,
        request_id=deterministic_sha256(
            "portscanner.inventory.snapshot-request.v1",
            identity,
        ),
        event_time=observation,
        observed_at=observation,
    )


def signal_source(target: NormalizedTarget, collected_at: datetime) -> EventSource:
    collected_at = _utc(collected_at)
    observed_at = _utc(target.observed_at or collected_at)
    if observed_at > collected_at:
        raise ValueError("signal observation cannot be later than collection")
    event_id = target.source_event_id
    if not target.source_event_name or not event_id:
        raise ValueError("signal target has no source identifiers")
    request_id = target.source_request_id or deterministic_sha256(
        "portscanner.inventory.signal-request.v1",
        {"event_id": event_id},
    )
    event_time = _utc(target.source_event_time or observed_at)
    if event_time > observed_at:
        event_time = observed_at
    return EventSource(
        name=target.source_event_name,
        event_id=event_id,
        request_id=request_id,
        event_time=event_time,
        observed_at=observed_at,
    )


def _ranges(candidate: CandidatePorts) -> tuple[TcpPortRange, ...]:
    if candidate.full_tcp:
        return (FULL_TCP_PORT_RANGE,)
    return tuple(TcpPortRange(start=start, end=end) for start, end in candidate.ranges)


def _target(value: NormalizedTarget, generation: int) -> Target:
    return Target.create(
        provider=CloudProvider.AWS,
        scope_id=value.account_id,
        location=value.region,
        resource_id=value.network_interface_id,
        private_address=value.private_ip,
        public_address=value.public_ip,
        address_family=AddressFamily.IPV4,
        transport=TransportProtocol.TCP,
        generation=generation,
    )


def _source(value: EventSource, collected_at: datetime) -> SourceObservation:
    return SourceObservation.create(
        source_event_name=value.name,
        source_event_id=value.event_id,
        source_request_id=value.request_id,
        event_time=value.event_time,
        observed_at=value.observed_at,
        collected_at=_utc(collected_at),
    )


def _context(
    value: NormalizedTarget,
    source: EventSource,
    candidate: CandidatePorts,
) -> AwsContext:
    allowed_tags = {
        key: item
        for key, item in value.tags
        if key in {"application", "environment", "name", "service"} and item.strip()
    }
    return AwsContext(
        account_id=value.account_id,
        region=value.region,
        network_interface_id=value.network_interface_id,
        private_ip=value.private_ip,
        public_ip=value.public_ip,
        instance_id=value.instance_id,
        security_group_ids=value.security_group_ids,
        policy_fingerprint=value.policy_fingerprint,
        candidate_tcp_port_ranges=_ranges(candidate),
        source_event_name=source.name,
        source_event_id=source.event_id,
        source_request_id=source.request_id,
        tags=AwsTags(**allowed_tags),
    )


def build_target_event(
    current: NormalizedTarget,
    generation: int,
    *,
    source: EventSource,
    collected_at: datetime,
    previous: NormalizedTarget | None = None,
    reason: ScanReason | None = None,
) -> TargetEvent:
    """Build a new-target, target-change, policy-change, or coverage contract."""

    collected_at = _utc(collected_at)
    target = _target(current, generation)
    policy_changed = previous is not None and (
        previous.security_group_ids != current.security_group_ids
        or previous.policy_fingerprint != current.policy_fingerprint
    )
    state_changed = previous is not None and previous.state_signature != current.state_signature
    if reason is None:
        if previous is None:
            reason = ScanReason.NEW_TARGET
        elif policy_changed:
            reason = ScanReason.POLICY_CHANGE
        else:
            reason = ScanReason.TARGET_CHANGE

    if reason is ScanReason.NEW_TARGET and previous is not None:
        raise ValueError("new targets must not have active previous target state")
    if reason is ScanReason.TARGET_CHANGE:
        if previous is None:
            raise ValueError("target changes require previous target state")
        if policy_changed:
            raise ValueError("target changes cannot include security-group policy changes")
        if not state_changed:
            raise ValueError("target changes require changed target state")
    if reason is ScanReason.POLICY_CHANGE and not policy_changed:
        raise ValueError("policy changes require changed security-group policy state")

    if reason is ScanReason.POLICY_CHANGE:
        candidate = current.candidate_ports
        ranges = _ranges(candidate)
        profile = ScanProfile.FAST_FULL_TCP if candidate.full_tcp else ScanProfile.TARGETED_TCP
        priority = 200
        deadline = collected_at + PRIORITY_DISPATCH_WINDOW
        not_after = collected_at + PRIORITY_EXECUTION_WINDOW
        event_type = TargetEventType.POLICY_CHANGED
    elif reason is ScanReason.TARGET_CHANGE:
        candidate = CandidatePorts.full()
        ranges = (FULL_TCP_PORT_RANGE,)
        profile = ScanProfile.FAST_FULL_TCP
        priority = 200
        deadline = collected_at + PRIORITY_DISPATCH_WINDOW
        not_after = collected_at + PRIORITY_EXECUTION_WINDOW
        event_type = TargetEventType.TARGET_UPSERT
    elif reason is ScanReason.COVERAGE:
        candidate = CandidatePorts.full()
        ranges = (FULL_TCP_PORT_RANGE,)
        profile = ScanProfile.DEEP
        priority = 10
        deadline = collected_at + COVERAGE_DISPATCH_WINDOW
        not_after = collected_at + COVERAGE_EXECUTION_WINDOW
        event_type = TargetEventType.RESCAN_REQUESTED
    elif reason in {ScanReason.NEW_TARGET, ScanReason.MANUAL}:
        managed_targeted = (
            reason is ScanReason.NEW_TARGET
            and current.managed_canary
            and not current.candidate_ports.full_tcp
        )
        candidate = current.candidate_ports if managed_targeted else CandidatePorts.full()
        ranges = _ranges(candidate)
        profile = ScanProfile.TARGETED_TCP if managed_targeted else ScanProfile.FAST_FULL_TCP
        priority = 500 if reason is ScanReason.MANUAL else 100
        deadline = collected_at + (
            MANUAL_DISPATCH_WINDOW if reason is ScanReason.MANUAL else PRIORITY_DISPATCH_WINDOW
        )
        not_after = collected_at + PRIORITY_EXECUTION_WINDOW
        event_type = (
            TargetEventType.RESCAN_REQUESTED
            if reason is ScanReason.MANUAL
            else TargetEventType.TARGET_UPSERT
        )
    else:
        raise ValueError(f"unsupported scan reason: {reason}")

    observation = _source(source, collected_at)
    directive = ScanDirective.create(
        target_id=target.target_id,
        target_generation=generation,
        reason=reason,
        profile=profile,
        priority=priority,
        requested_at=collected_at,
        deadline_at=deadline,
        not_after=not_after,
        tcp_port_ranges=ranges,
    )
    policy_change = None
    if reason is ScanReason.POLICY_CHANGE:
        if previous is None:
            raise ValueError("policy changes require previous target state")
        previous_fingerprint = (
            previous.policy_fingerprint
            if previous.policy_fingerprint != current.policy_fingerprint
            else None
        )
        policy_change = PolicyChange.create(
            target_id=target.target_id,
            previous_fingerprint=previous_fingerprint,
            current_fingerprint=current.policy_fingerprint,
            changed_at=collected_at,
            candidate_tcp_port_ranges=ranges,
        )
    return TargetEvent.create(
        schema_version=SCHEMA_VERSION,
        event_type=event_type,
        target=target,
        source=observation,
        policy_change=policy_change,
        scan=directive,
        aws_context=_context(current, source, candidate),
    )


def build_removal_event(
    current: NormalizedTarget,
    generation: int,
    *,
    source: EventSource,
    collected_at: datetime,
) -> TargetRemoval:
    """Build a deterministic bounded tombstone for downstream cancellation."""

    target = _target(current, generation)
    observation = _source(source, collected_at)
    context = _context(current, source, CandidatePorts.full())
    return TargetRemoval.create(
        schema_version=SCHEMA_VERSION,
        event_type=TargetEventType.TARGET_REMOVED,
        target=target,
        source=observation,
        aws_context=context,
        removed_at=_utc(collected_at),
    )


def event_json(event: TargetEvent | TargetRemoval) -> str:
    return canonical_json(event)
