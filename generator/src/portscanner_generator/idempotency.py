"""Retry-safe DynamoDB event claims and terminal audit states."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any


class ClaimState(StrEnum):
    CLAIMED = "CLAIMED"
    RETRYABLE = "RETRYABLE"
    DISPATCHED = "DISPATCHED"
    STALE = "STALE"
    CANCELLED = "CANCELLED"
    REMOVED = "REMOVED"
    EXPIRED = "EXPIRED"


TERMINAL_STATES = {
    ClaimState.DISPATCHED,
    ClaimState.STALE,
    ClaimState.CANCELLED,
    ClaimState.REMOVED,
    ClaimState.EXPIRED,
}


class ClaimDisposition(StrEnum):
    ACQUIRED = "acquired"
    DUPLICATE = "duplicate"
    BUSY = "busy"


class ClaimStoreError(RuntimeError):
    """Base error for claim state that cannot be advanced safely."""


class ClaimCollision(ClaimStoreError):
    """A cryptographic key collision or corrupted item was observed."""


class ClaimLost(ClaimStoreError):
    """The caller no longer owns the conditional claim lease."""


@dataclass(frozen=True)
class EventClaim:
    key: str
    event_hash: str
    owner: str
    attempt: int


@dataclass(frozen=True)
class ClaimResult:
    disposition: ClaimDisposition
    claim: EventClaim | None = None
    state: ClaimState | None = None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("claim timestamps must include a timezone")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _conditional_failure(error: Exception) -> bool:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return False
    error_data = response.get("Error")
    return (
        isinstance(error_data, Mapping)
        and error_data.get("Code") == "ConditionalCheckFailedException"
    )


def _dynamodb_integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
        return int(value)
    return None


class DynamoClaimStore:
    """Lease first, create second, then conditionally finalize.

    A crash after Kubernetes creation leaves a recoverable CLAIMED item. Once the
    lease expires, a retry acquires the item, receives Kubernetes 409 for the
    deterministic resource name, and finalizes DISPATCHED.
    """

    def __init__(
        self,
        table: Any,
        *,
        partition_key: str = "dispatch_id",
        lease_seconds: int = 120,
        audit_ttl_days: int = 30,
    ) -> None:
        self._table = table
        self._partition_key = partition_key
        self._lease_seconds = lease_seconds
        self._audit_ttl_days = audit_ttl_days

    def acquire(
        self,
        *,
        event_id: str,
        trace_id: str,
        target_id: str,
        generation: int,
        event_type: str,
        provider: str,
        reason: str,
        now: datetime,
        owner: str | None = None,
    ) -> ClaimResult:
        current = _utc(now)
        event_hash = _sha256(event_id)
        key = f"event#{event_hash}"
        claim_owner = owner or uuid.uuid4().hex
        lease_expires = int(current.timestamp()) + self._lease_seconds
        expires_at = int((current + timedelta(days=self._audit_ttl_days)).timestamp())
        item = {
            self._partition_key: key,
            "eventHash": event_hash,
            "traceHash": _sha256(trace_id),
            "targetHash": _sha256(target_id),
            "generation": generation,
            "eventType": event_type,
            "provider": provider,
            "reason": reason,
            "state": ClaimState.CLAIMED.value,
            "claimOwner": claim_owner,
            "leaseExpiresAt": lease_expires,
            "attempts": 1,
            "createdAt": _timestamp(current),
            "updatedAt": _timestamp(current),
            "expires_at": expires_at,
        }
        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(#pk)",
                ExpressionAttributeNames={"#pk": self._partition_key},
            )
            return ClaimResult(
                disposition=ClaimDisposition.ACQUIRED,
                claim=EventClaim(
                    key=key,
                    event_hash=event_hash,
                    owner=claim_owner,
                    attempt=1,
                ),
                state=ClaimState.CLAIMED,
            )
        except Exception as error:
            if not _conditional_failure(error):
                raise

        existing = self._get(key)
        if existing.get("eventHash") != event_hash:
            raise ClaimCollision("claim key does not match the event hash")
        state = self._state(existing)
        if state in TERMINAL_STATES:
            return ClaimResult(
                disposition=ClaimDisposition.DUPLICATE,
                state=state,
            )
        existing_lease = _dynamodb_integer(existing.get("leaseExpiresAt"))
        lease_is_expired = existing_lease is not None and existing_lease <= int(current.timestamp())
        if state is ClaimState.CLAIMED and not lease_is_expired:
            return ClaimResult(
                disposition=ClaimDisposition.BUSY,
                state=state,
            )
        if state is not ClaimState.RETRYABLE and not lease_is_expired:
            raise ClaimStoreError("claim item is in an unsupported state")

        try:
            self._table.update_item(
                Key={self._partition_key: key},
                UpdateExpression=(
                    "SET #state = :claimed, #owner = :owner, #lease = :lease, "
                    "#updated = :updated, #expires = :expires "
                    "ADD #attempts :one"
                ),
                ConditionExpression=(
                    "#eventHash = :eventHash AND "
                    "(#state = :retryable OR "
                    "(#state = :claimed AND #lease <= :now))"
                ),
                ExpressionAttributeNames={
                    "#state": "state",
                    "#owner": "claimOwner",
                    "#lease": "leaseExpiresAt",
                    "#updated": "updatedAt",
                    "#expires": "expires_at",
                    "#attempts": "attempts",
                    "#eventHash": "eventHash",
                },
                ExpressionAttributeValues={
                    ":claimed": ClaimState.CLAIMED.value,
                    ":retryable": ClaimState.RETRYABLE.value,
                    ":owner": claim_owner,
                    ":lease": lease_expires,
                    ":updated": _timestamp(current),
                    ":expires": expires_at,
                    ":one": 1,
                    ":eventHash": event_hash,
                    ":now": int(current.timestamp()),
                },
            )
        except Exception as error:
            if not _conditional_failure(error):
                raise
            return self._classify_after_race(key, event_hash, current)

        previous_attempts = _dynamodb_integer(existing.get("attempts"))
        attempt = previous_attempts + 1 if previous_attempts is not None else 2
        return ClaimResult(
            disposition=ClaimDisposition.ACQUIRED,
            claim=EventClaim(
                key=key,
                event_hash=event_hash,
                owner=claim_owner,
                attempt=attempt,
            ),
            state=ClaimState.CLAIMED,
        )

    def complete(
        self,
        claim: EventClaim,
        *,
        state: ClaimState,
        now: datetime,
        verdict: str,
        scanner_name: str | None = None,
        cancelled_count: int = 0,
    ) -> bool:
        if state not in TERMINAL_STATES:
            raise ValueError("complete requires a terminal claim state")
        current = _utc(now)
        names = {
            "#state": "state",
            "#owner": "claimOwner",
            "#lease": "leaseExpiresAt",
            "#updated": "updatedAt",
            "#verdict": "ownershipVerdict",
            "#cancelled": "cancelledCount",
            "#eventHash": "eventHash",
        }
        values: dict[str, Any] = {
            ":terminal": state.value,
            ":claimed": ClaimState.CLAIMED.value,
            ":owner": claim.owner,
            ":updated": _timestamp(current),
            ":verdict": verdict,
            ":cancelled": cancelled_count,
            ":eventHash": claim.event_hash,
        }
        assignments = [
            "#state = :terminal",
            "#updated = :updated",
            "#verdict = :verdict",
            "#cancelled = :cancelled",
        ]
        if scanner_name is not None:
            names["#scanner"] = "scannerName"
            values[":scanner"] = scanner_name
            assignments.append("#scanner = :scanner")

        try:
            self._table.update_item(
                Key={self._partition_key: claim.key},
                UpdateExpression=(f"SET {', '.join(assignments)} REMOVE #owner, #lease"),
                ConditionExpression=(
                    "#eventHash = :eventHash AND #state = :claimed AND #owner = :owner"
                ),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
            return True
        except Exception as error:
            if not _conditional_failure(error):
                raise
        existing = self._get(claim.key)
        if existing.get("eventHash") == claim.event_hash and existing.get("state") == state.value:
            return False
        raise ClaimLost("claim could not be finalized by its owner")

    def mark_retryable(
        self,
        claim: EventClaim,
        *,
        now: datetime,
        error_code: str,
    ) -> bool:
        current = _utc(now)
        try:
            self._table.update_item(
                Key={self._partition_key: claim.key},
                UpdateExpression=(
                    "SET #state = :retryable, #updated = :updated, "
                    "#error = :error REMOVE #owner, #lease"
                ),
                ConditionExpression=(
                    "#eventHash = :eventHash AND #state = :claimed AND #owner = :owner"
                ),
                ExpressionAttributeNames={
                    "#state": "state",
                    "#updated": "updatedAt",
                    "#error": "lastErrorCode",
                    "#owner": "claimOwner",
                    "#lease": "leaseExpiresAt",
                    "#eventHash": "eventHash",
                },
                ExpressionAttributeValues={
                    ":retryable": ClaimState.RETRYABLE.value,
                    ":claimed": ClaimState.CLAIMED.value,
                    ":updated": _timestamp(current),
                    ":error": error_code,
                    ":eventHash": claim.event_hash,
                    ":owner": claim.owner,
                },
            )
            return True
        except Exception as error:
            if _conditional_failure(error):
                return False
            raise

    def _get(self, key: str) -> Mapping[str, Any]:
        response = self._table.get_item(
            Key={self._partition_key: key},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, Mapping):
            raise ClaimStoreError("claim item disappeared during a conditional race")
        return item

    @staticmethod
    def _state(item: Mapping[str, Any]) -> ClaimState:
        raw_state = item.get("state")
        if not isinstance(raw_state, str):
            raise ClaimStoreError("claim item has an unknown state")
        try:
            return ClaimState(raw_state)
        except ValueError as error:
            raise ClaimStoreError("claim item has an unknown state") from error

    def _classify_after_race(
        self,
        key: str,
        event_hash: str,
        now: datetime,
    ) -> ClaimResult:
        item = self._get(key)
        if item.get("eventHash") != event_hash:
            raise ClaimCollision("claim key does not match the event hash")
        state = self._state(item)
        if state in TERMINAL_STATES:
            return ClaimResult(ClaimDisposition.DUPLICATE, state=state)
        lease = _dynamodb_integer(item.get("leaseExpiresAt"))
        if state is ClaimState.CLAIMED and lease is not None and lease > int(now.timestamp()):
            return ClaimResult(ClaimDisposition.BUSY, state=state)
        raise ClaimStoreError("claim changed during reacquisition")
