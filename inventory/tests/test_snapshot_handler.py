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

from .helpers import FakeDynamo, normalized_target

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
SCOPE = SnapshotScope(source="ec2", account_id="123456789012", region="us-east-1")


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
