from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from portscanner_contracts import (
    FULL_TCP_PORT_RANGE,
    ScanProfile,
    ScanReason,
    TargetEventType,
    TargetRemoval,
    parse_target_event,
)

from portscanner_inventory.base import CandidatePorts, SnapshotScope
from portscanner_inventory.events import (
    build_target_event,
    event_json,
    signal_source,
    snapshot_source,
)
from portscanner_inventory.state import DynamoStateStore, ReconcileAction

from .helpers import FakeDynamo, normalized_target, permission

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _source():
    return snapshot_source(
        SnapshotScope(source="aws-config", name="example-aggregator"),
        NOW,
    )


def test_add_duplicate_and_relevant_change_use_monotonic_generations() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    initial = normalized_target()

    added = store.reconcile(initial, source=_source(), now=NOW)
    duplicate = store.reconcile(initial, source=_source(), now=NOW)
    changed = store.reconcile(
        normalized_target(public_ip="203.0.113.20"),
        source=_source(),
        now=NOW + timedelta(minutes=1),
    )

    assert added.action is ReconcileAction.ADDED
    assert added.state is not None and added.state.generation == 1
    assert added.event is not None
    assert added.event.scan.reason is ScanReason.NEW_TARGET
    assert duplicate.action is ReconcileAction.NOOP
    assert changed.action is ReconcileAction.CHANGED
    assert changed.state is not None and changed.state.generation == 2
    assert changed.event is not None
    assert changed.event.scan.reason is ScanReason.TARGET_CHANGE
    assert changed.event.event_type is TargetEventType.TARGET_UPSERT
    assert changed.event.scan.profile is ScanProfile.FAST_FULL_TCP
    assert changed.event.scan.priority == 200
    assert changed.event.scan.deadline_at == NOW + timedelta(minutes=6)
    assert changed.event.scan.not_after == NOW + timedelta(minutes=11)
    assert changed.event.scan.tcp_port_ranges == (FULL_TCP_PORT_RANGE,)
    assert changed.event.aws_context.candidate_tcp_port_ranges == (FULL_TCP_PORT_RANGE,)
    assert changed.event.policy_change is None
    assert client.transactions == 2
    assert len([key for key in client.items if key[0].startswith("OUTBOX#")]) == 2


def test_allowlisted_tag_change_is_a_noop_and_does_not_advance_generation() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    first = normalized_target(tags=[{"Key": "name", "Value": "one"}])
    second = normalized_target(tags=[{"Key": "name", "Value": "two"}])

    store.reconcile(first, source=_source(), now=NOW)
    result = store.reconcile(second, source=_source(), now=NOW + timedelta(minutes=1))

    assert result.action is ReconcileAction.NOOP
    assert result.state is not None and result.state.generation == 1


def test_known_instance_lifecycle_advances_and_survives_unknown_snapshots() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    unknown = normalized_target()
    lifecycle = json.loads(unknown.lifecycle)
    lifecycle["instance"] = "running"
    running = replace(
        unknown,
        lifecycle=json.dumps(lifecycle, separators=(",", ":"), sort_keys=True),
    )
    lifecycle["instance"] = "stopped"
    stopped = replace(
        unknown,
        lifecycle=json.dumps(lifecycle, separators=(",", ":"), sort_keys=True),
    )

    first = store.reconcile(running, source=_source(), now=NOW)
    snapshot = store.reconcile(
        unknown,
        source=_source(),
        now=NOW + timedelta(minutes=1),
    )
    changed = store.reconcile(
        stopped,
        source=_source(),
        now=NOW + timedelta(minutes=2),
    )

    assert first.state.generation == 1
    assert snapshot.action is ReconcileAction.NOOP
    assert json.loads(snapshot.state.target.lifecycle)["instance"] == "running"
    assert changed.state.generation == 2
    assert changed.event is not None
    assert changed.event.scan.reason is ScanReason.TARGET_CHANGE
    assert changed.event.event_type is TargetEventType.TARGET_UPSERT
    assert changed.event.scan.profile is ScanProfile.FAST_FULL_TCP
    assert changed.event.scan.tcp_port_ranges == (FULL_TCP_PORT_RANGE,)
    assert changed.event.policy_change is None


def test_target_change_requires_existing_changed_non_policy_state() -> None:
    current = normalized_target()

    with pytest.raises(ValueError, match="require previous"):
        build_target_event(
            current,
            1,
            source=_source(),
            collected_at=NOW,
            reason=ScanReason.TARGET_CHANGE,
        )
    with pytest.raises(ValueError, match="require changed target state"):
        build_target_event(
            current,
            2,
            source=_source(),
            collected_at=NOW,
            previous=current,
            reason=ScanReason.TARGET_CHANGE,
        )
    with pytest.raises(ValueError, match="must not have active previous"):
        build_target_event(
            current,
            2,
            source=_source(),
            collected_at=NOW,
            previous=current,
            reason=ScanReason.NEW_TARGET,
        )


def test_policy_change_uses_bounded_targeted_tcp_delta() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    first = normalized_target()
    changed = normalized_target(permissions={"sg-11111111": [permission(80, 80)]}).with_signal(
        event_name="AuthorizeSecurityGroupIngress",
        event_id="event-id",
        request_id="request-id",
        event_time=NOW,
        candidate_ports=CandidatePorts(ranges=((80, 80),)),
    )
    store.reconcile(first, source=_source(), now=NOW)

    result = store.reconcile(
        changed,
        source=signal_source(changed, NOW + timedelta(minutes=1)),
        now=NOW + timedelta(minutes=1),
    )

    assert result.event.event_type.value == "policy.changed"
    assert result.event.scan.reason is ScanReason.POLICY_CHANGE
    assert result.event.scan.profile.value == "targeted-tcp"
    assert result.event.scan.tcp_port_ranges[0].start == 80
    assert result.state.generation == 2


def test_security_group_attachment_change_advances_even_when_policy_is_equivalent() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    first = normalized_target()
    second = normalized_target(
        group_ids=("sg-22222222",),
        permissions={"sg-22222222": [permission()]},
    ).with_signal(
        event_name="ModifyNetworkInterfaceAttribute",
        event_id="event-id",
        request_id="request-id",
        event_time=NOW,
        candidate_ports=CandidatePorts.full(),
    )
    assert first.policy_fingerprint == second.policy_fingerprint
    store.reconcile(first, source=_source(), now=NOW)

    result = store.reconcile(
        second,
        source=signal_source(second, NOW + timedelta(minutes=1)),
        now=NOW + timedelta(minutes=1),
    )

    assert result.action is ReconcileAction.CHANGED
    assert result.state.generation == 2
    assert result.event.event_type.value == "policy.changed"
    assert result.event.scan.reason is ScanReason.POLICY_CHANGE
    assert result.event.policy_change.previous_fingerprint is None


def test_removal_advances_generation_and_writes_tombstone_outbox() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    added = store.reconcile(normalized_target(), source=_source(), now=NOW)
    assert added.state is not None

    removed = store.remove(
        added.state,
        source=_source(),
        now=NOW + timedelta(minutes=1),
    )

    assert removed.action is ReconcileAction.REMOVED
    assert removed.state is not None
    assert removed.state.status == "removed"
    assert removed.state.generation == 2
    assert isinstance(removed.event, TargetRemoval)
    assert removed.event.event_type.value == "target.removed"
    assert parse_target_event(event_json(removed.event)) == removed.event

    outbox = client.items[(f"OUTBOX#{removed.event.event_id}", "EVENT")]
    persisted = parse_target_event(outbox["event_json"]["S"])
    assert persisted == removed.event


def test_stale_removal_cannot_delete_a_newer_generation() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    first = store.reconcile(normalized_target(), source=_source(), now=NOW)
    assert first.state is not None
    newer = store.reconcile(
        normalized_target(public_ip="203.0.113.20"),
        source=_source(),
        now=NOW + timedelta(minutes=1),
    )

    result = store.remove(
        first.state,
        source=_source(),
        now=NOW + timedelta(minutes=2),
    )

    assert result.action is ReconcileAction.RACE
    assert result.state.generation == 2
    assert result.state.status == "active"
    assert result.state.target.public_ip == newer.state.target.public_ip


def test_reactivation_after_removal_is_a_new_target() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    added = store.reconcile(normalized_target(), source=_source(), now=NOW)
    assert added.state is not None
    removed = store.remove(
        added.state,
        source=_source(),
        now=NOW + timedelta(minutes=1),
    )
    assert removed.state is not None

    reactivated = store.reconcile(
        normalized_target(),
        source=_source(),
        now=NOW + timedelta(minutes=2),
    )

    assert reactivated.action is ReconcileAction.ADDED
    assert reactivated.state is not None and reactivated.state.generation == 3
    assert reactivated.event is not None
    assert reactivated.event.scan.reason is ScanReason.NEW_TARGET


def test_transaction_generation_race_retries_without_skipping_generation() -> None:
    client = FakeDynamo()
    client.fail_transactions = 1
    store = DynamoStateStore(client, "inventory")

    result = store.reconcile(normalized_target(), source=_source(), now=NOW)

    assert result.action is ReconcileAction.ADDED
    assert result.state is not None and result.state.generation == 1
    assert client.transactions == 2


def test_persistent_generation_race_is_reported() -> None:
    client = FakeDynamo()
    client.fail_transactions = 10
    store = DynamoStateStore(client, "inventory", max_retries=2)

    result = store.reconcile(normalized_target(), source=_source(), now=NOW)

    assert result.action is ReconcileAction.RACE
    assert result.state is None


def test_signal_dedupe_uses_ttl_and_can_be_released() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")

    assert store.claim_signal("event-id", now=NOW, ttl_seconds=60)
    assert not store.claim_signal("event-id", now=NOW, ttl_seconds=60)
    assert store.claim_signal(
        "event-id",
        now=NOW + timedelta(seconds=61),
        ttl_seconds=60,
    )
    store.release_signal("event-id")
    assert store.claim_signal("event-id", now=NOW, ttl_seconds=60)


def test_coverage_outbox_is_deterministic_within_schedule_bucket() -> None:
    client = FakeDynamo()
    store = DynamoStateStore(client, "inventory")
    added = store.reconcile(normalized_target(), source=_source(), now=NOW)
    assert added.state is not None

    first = store.enqueue_coverage(added.state, source=_source(), now=NOW)
    duplicate = store.enqueue_coverage(added.state, source=_source(), now=NOW)

    assert first.event is not None
    assert first.event.scan.reason is ScanReason.COVERAGE
    assert duplicate.action is ReconcileAction.NOOP
    assert duplicate.event is None
