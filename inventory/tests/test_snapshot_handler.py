from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from portscanner_inventory.base import (
    OwnershipCheck,
    OwnershipVerdict,
    ScopeCompletion,
    SnapshotBatch,
    SnapshotScope,
)
from portscanner_inventory.events import snapshot_source
from portscanner_inventory.handlers.snapshot import reconcile_snapshot
from portscanner_inventory.state import DynamoStateStore

from .helpers import FakeDynamo, normalized_target, permission

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
SCOPE = SnapshotScope(source="ec2", account_id="123456789012", region="us-east-1")
CONFIG_SCOPE = SnapshotScope(source="aws-config", name="example-aggregator")


class Backend:
    def __init__(self, batch: SnapshotBatch) -> None:
        self.batch = batch

    def collect(self) -> SnapshotBatch:
        return self.batch


class Ownership:
    def __init__(self, verdict: OwnershipVerdict) -> None:
        self.verdict = verdict
        self.calls = 0

    def validate(self, _target_id: str, _generation: int) -> OwnershipCheck:
        self.calls += 1
        return OwnershipCheck(self.verdict)


def _seed(store: DynamoStateStore):
    return store.reconcile(
        normalized_target(),
        source=snapshot_source(SCOPE, NOW),
        now=NOW,
    ).state


def test_complete_snapshot_adds_and_revalidates_missing_target_before_removal() -> None:
    store = DynamoStateStore(FakeDynamo(), "inventory")
    old = _seed(store)
    assert old is not None
    new = replace(
        normalized_target(public_ip="203.0.113.20"),
        network_interface_id="eni-bbbbbbbb",
        private_ip="10.0.1.10",
    )
    batch = SnapshotBatch(
        scope=SCOPE,
        targets=(new,),
        completion=ScopeCompletion.COMPLETE,
        pages=1,
    )
    ownership = Ownership(OwnershipVerdict.INACTIVE)

    summary = reconcile_snapshot(
        Backend(batch),
        store,
        ownership,
        now=NOW + timedelta(minutes=1),
    )

    assert summary["added"] == 1
    assert summary["removed"] == 1
    assert summary["revalidated"] == 1
    assert store.get(old.target_id).status == "removed"


def test_incomplete_snapshot_never_revalidates_or_removes_missing_targets() -> None:
    store = DynamoStateStore(FakeDynamo(), "inventory")
    old = _seed(store)
    assert old is not None
    batch = SnapshotBatch(
        scope=SCOPE,
        targets=(),
        completion=ScopeCompletion.PARTIAL,
        pages=1,
        failure_code="ThrottlingException",
    )

    class MustNotRun:
        def validate(self, *_args):
            raise AssertionError("partial snapshot attempted a removal")

    summary = reconcile_snapshot(
        Backend(batch),
        store,
        MustNotRun(),
        now=NOW + timedelta(minutes=1),
    )

    assert summary["removed"] == 0
    assert summary["revalidated"] == 0
    assert store.get(old.target_id).status == "active"


def test_complete_snapshot_does_not_remove_a_still_active_direct_read() -> None:
    store = DynamoStateStore(FakeDynamo(), "inventory")
    old = _seed(store)
    assert old is not None
    batch = SnapshotBatch(
        scope=SCOPE,
        targets=(),
        completion=ScopeCompletion.COMPLETE,
        pages=1,
    )
    ownership = Ownership(OwnershipVerdict.ACTIVE)

    summary = reconcile_snapshot(
        Backend(batch),
        store,
        ownership,
        now=NOW + timedelta(minutes=1),
    )

    assert summary["removed"] == 0
    assert ownership.calls == 1
    assert store.get(old.target_id).status == "active"


def test_generation_race_does_not_reconcile_an_older_direct_read() -> None:
    store = DynamoStateStore(FakeDynamo(), "inventory")
    old = _seed(store)
    assert old is not None
    stale_live_read = normalized_target(public_ip="203.0.113.20")

    class GenerationRaceOwnership:
        def validate(self, _target_id: str, generation: int) -> OwnershipCheck:
            return OwnershipCheck(
                OwnershipVerdict.STALE,
                current=stale_live_read,
                reason="generation-race",
                current_generation=generation + 1,
            )

    summary = reconcile_snapshot(
        Backend(
            SnapshotBatch(
                scope=SCOPE,
                targets=(),
                completion=ScopeCompletion.COMPLETE,
                pages=1,
            )
        ),
        store,
        GenerationRaceOwnership(),
        now=NOW + timedelta(minutes=1),
    )

    current = store.get(old.target_id)
    assert current is not None
    assert summary["changed"] == 0
    assert current.generation == old.generation
    assert current.target.public_ip == old.target.public_ip


def test_mixed_config_snapshot_directly_revalidates_missed_security_group_change() -> None:
    store = DynamoStateStore(FakeDynamo(), "inventory")
    group_id = normalized_target().security_group_ids[0]
    initial = replace(
        normalized_target(),
        observed_at=NOW,
        eni_observed_at=NOW,
        security_group_observed_at=((group_id, NOW),),
    )
    added = store.reconcile(
        initial,
        source=snapshot_source(CONFIG_SCOPE, NOW),
        now=NOW,
    )
    assert added.state is not None

    direct_time = NOW + timedelta(minutes=2)
    direct = normalized_target(public_ip="203.0.113.20").with_observation(direct_time)
    signaled = store.reconcile(
        direct,
        source=snapshot_source(SCOPE, direct_time),
        now=direct_time,
    )
    assert signaled.state is not None
    assert signaled.state.target.eni_observed_at is None
    assert signaled.state.target.security_group_observed_at == ((group_id, NOW),)

    eni_capture = NOW + timedelta(minutes=1)
    group_capture = NOW + timedelta(minutes=3)
    permissions = {group_id: [permission(80, 80)]}
    config_target = replace(
        normalized_target(
            public_ip="203.0.113.20",
            permissions=permissions,
        ),
        observed_at=group_capture,
        eni_observed_at=eni_capture,
        security_group_observed_at=((group_id, group_capture),),
    )
    live_target = normalized_target(
        public_ip="203.0.113.20",
        permissions=permissions,
    )

    class PolicyDriftOwnership:
        def __init__(self) -> None:
            self.calls = 0

        def validate(self, _target_id: str, generation: int) -> OwnershipCheck:
            self.calls += 1
            return OwnershipCheck(
                OwnershipVerdict.STALE,
                current=live_target,
                reason="policy-or-lifecycle",
                current_generation=generation,
            )

    ownership = PolicyDriftOwnership()
    summary = reconcile_snapshot(
        Backend(
            SnapshotBatch(
                scope=CONFIG_SCOPE,
                targets=(config_target,),
                completion=ScopeCompletion.COMPLETE,
                pages=2,
            )
        ),
        store,
        ownership,
        now=group_capture + timedelta(minutes=1),
    )

    current = store.get(initial.target_id)
    assert current is not None
    assert summary["changed"] == 1
    assert summary["revalidated"] == 1
    assert ownership.calls == 1
    assert current.generation == 3
    assert current.target.policy_fingerprint == config_target.policy_fingerprint
    assert current.target.eni_observed_at == eni_capture
    assert current.target.security_group_observed_at == ((group_id, group_capture),)
