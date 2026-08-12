from __future__ import annotations

import unittest
from datetime import timedelta
from decimal import Decimal

from portscanner_generator.idempotency import (
    ClaimDisposition,
    ClaimState,
    DynamoClaimStore,
)

from .fakes import NOW, FakeDynamoTable

EVENT_ID = "event-example-0001"
TRACE_ID = "trace-example-0001"
TARGET_ID = "provider:scope:resource:address-example"


def acquire(
    store: DynamoClaimStore,
    *,
    now=NOW,
    owner: str,
):
    return store.acquire(
        event_id=EVENT_ID,
        trace_id=TRACE_ID,
        target_id=TARGET_ID,
        generation=3,
        event_type="target.upsert",
        provider="aws",
        reason="new_target",
        now=now,
        owner=owner,
    )


class IdempotencyTests(unittest.TestCase):
    def test_failed_creation_transitions_to_retryable_and_reclaims(self) -> None:
        table = FakeDynamoTable()
        store = DynamoClaimStore(table, lease_seconds=120)
        first = acquire(store, owner="owner-one")
        self.assertIs(first.disposition, ClaimDisposition.ACQUIRED)

        changed = store.mark_retryable(
            first.claim,  # type: ignore[arg-type]
            now=NOW,
            error_code="dispatch_failed",
        )
        second = acquire(
            store,
            now=NOW + timedelta(seconds=1),
            owner="owner-two",
        )

        self.assertTrue(changed)
        self.assertIs(second.disposition, ClaimDisposition.ACQUIRED)
        self.assertEqual(second.claim.attempt, 2)  # type: ignore[union-attr]
        item = next(iter(table.items.values()))
        self.assertEqual(item["state"], ClaimState.CLAIMED.value)
        self.assertEqual(item["claimOwner"], "owner-two")
        self.assertEqual(item["attempts"], 2)

    def test_terminal_dispatch_is_a_duplicate_on_redelivery(self) -> None:
        table = FakeDynamoTable()
        store = DynamoClaimStore(table)
        first = acquire(store, owner="owner-one")
        store.complete(
            first.claim,  # type: ignore[arg-type]
            state=ClaimState.DISPATCHED,
            now=NOW,
            verdict="ACTIVE",
            scanner_name="scan-event-hash",
        )

        duplicate = acquire(
            store,
            now=NOW + timedelta(minutes=1),
            owner="owner-two",
        )

        self.assertIs(duplicate.disposition, ClaimDisposition.DUPLICATE)
        self.assertIs(duplicate.state, ClaimState.DISPATCHED)

    def test_live_claim_is_busy_but_expired_claim_is_recoverable(self) -> None:
        table = FakeDynamoTable()
        store = DynamoClaimStore(table, lease_seconds=120)
        acquire(store, owner="owner-one")
        item = next(iter(table.items.values()))
        item["leaseExpiresAt"] = Decimal(item["leaseExpiresAt"])
        item["attempts"] = Decimal(item["attempts"])

        busy = acquire(
            store,
            now=NOW + timedelta(seconds=119),
            owner="owner-two",
        )
        recovered = acquire(
            store,
            now=NOW + timedelta(seconds=120),
            owner="owner-three",
        )

        self.assertIs(busy.disposition, ClaimDisposition.BUSY)
        self.assertIs(recovered.disposition, ClaimDisposition.ACQUIRED)
        self.assertEqual(recovered.claim.attempt, 2)  # type: ignore[union-attr]
        self.assertEqual(
            recovered.claim.owner,  # type: ignore[union-attr]
            "owner-three",
        )

    def test_audit_item_contains_hashes_not_raw_identifiers(self) -> None:
        table = FakeDynamoTable()
        store = DynamoClaimStore(table)
        acquire(store, owner="owner-one")
        item = next(iter(table.items.values()))
        serialized = repr(item)

        self.assertNotIn(EVENT_ID, serialized)
        self.assertNotIn(TRACE_ID, serialized)
        self.assertNotIn(TARGET_ID, serialized)
        self.assertEqual(len(item["eventHash"]), 64)
        self.assertEqual(len(item["traceHash"]), 64)
        self.assertEqual(len(item["targetHash"]), 64)


if __name__ == "__main__":
    unittest.main()
