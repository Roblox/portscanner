"""DynamoDB target state, generation fencing, dedupe, and transactional outbox."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from portscanner_contracts import ScanReason, TargetEvent, TargetRemoval, deterministic_sha256

from portscanner_inventory.aws.normalize import NormalizedTarget
from portscanner_inventory.base import SignalHint, SnapshotScope, aws_error_code
from portscanner_inventory.events import (
    EventSource,
    build_removal_event,
    build_target_event,
    event_json,
)


class ReconcileAction(StrEnum):
    ADDED = "added"
    CHANGED = "changed"
    NOOP = "noop"
    REMOVED = "removed"
    RACE = "race"


@dataclass(frozen=True, slots=True)
class TargetState:
    target_id: str
    generation: int
    status: str
    target: NormalizedTarget
    signature: str
    contract_target_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    action: ReconcileAction
    state: TargetState | None
    event: TargetEvent | TargetRemoval | None = None


def _s(value: str) -> dict[str, str]:
    return {"S": value}


def _n(value: int) -> dict[str, str]:
    return {"N": str(value)}


def _attribute(item: Mapping[str, Any], name: str) -> str | None:
    value = item.get(name)
    if not isinstance(value, Mapping):
        return None
    if "S" in value:
        return str(value["S"])
    if "N" in value:
        return str(value["N"])
    return None


def _conditional_failure(error: BaseException) -> bool:
    return aws_error_code(error) in {
        "ConditionalCheckFailedException",
        "TransactionCanceledException",
    }


class DynamoStateStore:
    def __init__(
        self,
        client: Any,
        table_name: str,
        *,
        outbox_ttl_seconds: int = 604_800,
        max_retries: int = 4,
    ) -> None:
        if not table_name:
            raise ValueError("table_name is required")
        self._client = client
        self._table_name = table_name
        self._outbox_ttl_seconds = outbox_ttl_seconds
        self._max_retries = max_retries

    @staticmethod
    def _target_key(target_id: str) -> dict[str, dict[str, str]]:
        return {"pk": _s(f"TARGET#{target_id}"), "sk": _s("STATE")}

    @staticmethod
    def _outbox_key(event_id: str) -> dict[str, dict[str, str]]:
        return {"pk": _s(f"OUTBOX#{event_id}"), "sk": _s("EVENT")}

    def _state_item(
        self,
        state: TargetState,
        *,
        updated_at: datetime,
    ) -> dict[str, Any]:
        return {
            **self._target_key(state.target_id),
            "entity": _s("target"),
            "status": _s(state.status),
            "generation": _n(state.generation),
            "signature": _s(state.signature),
            "target_json": _s(
                json.dumps(
                    state.target.to_state_dict(),
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            ),
            "account_id": _s(state.target.account_id),
            "region": _s(state.target.region),
            "network_interface_id": _s(state.target.network_interface_id),
            "private_ip": _s(state.target.private_ip),
            "public_ip": _s(state.target.public_ip),
            "contract_target_id": _s(state.contract_target_id or ""),
            "updated_at": _s(updated_at.astimezone(UTC).isoformat().replace("+00:00", "Z")),
        }

    def _outbox_item(
        self,
        event: TargetEvent | TargetRemoval,
        target: NormalizedTarget,
        *,
        now: datetime,
    ) -> dict[str, Any]:
        event_id = str(event.event_id)
        return {
            **self._outbox_key(event_id),
            "entity": _s("outbox"),
            "event_id": _s(event_id),
            "event_json": _s(event_json(event)),
            "account_id": _s(target.account_id),
            "region": _s(target.region),
            "expires_at": _n(int(now.timestamp()) + self._outbox_ttl_seconds),
        }

    def _decode_state(self, item: Mapping[str, Any]) -> TargetState:
        target_json = _attribute(item, "target_json")
        generation = _attribute(item, "generation")
        status = _attribute(item, "status")
        pk = _attribute(item, "pk")
        if (
            not target_json
            or not generation
            or not status
            or not pk
            or not pk.startswith("TARGET#")
        ):
            raise ValueError("invalid target state item")
        target = NormalizedTarget.from_state_dict(json.loads(target_json))
        return TargetState(
            target_id=pk.removeprefix("TARGET#"),
            generation=int(generation),
            status=status,
            target=target,
            signature=_attribute(item, "signature") or target.state_signature,
            contract_target_id=_attribute(item, "contract_target_id") or None,
        )

    def get(self, target_id: str) -> TargetState | None:
        response = self._client.get_item(
            TableName=self._table_name,
            Key=self._target_key(target_id),
            ConsistentRead=True,
        )
        item = response.get("Item")
        return self._decode_state(item) if isinstance(item, Mapping) else None

    def list_current(self, scope: SnapshotScope | None = None) -> tuple[TargetState, ...]:
        values: list[TargetState] = []
        key: Mapping[str, Any] | None = None
        while True:
            request: dict[str, Any] = {
                "TableName": self._table_name,
                "ConsistentRead": True,
            }
            if key:
                request["ExclusiveStartKey"] = key
            response = self._client.scan(**request)
            for item in response.get("Items", ()):
                if not isinstance(item, Mapping) or _attribute(item, "entity") != "target":
                    continue
                state = self._decode_state(item)
                if state.status != "active":
                    continue
                if scope and not scope.includes(state.target.account_id, state.target.region):
                    continue
                values.append(state)
            key = response.get("LastEvaluatedKey")
            if not key:
                return tuple(sorted(values, key=lambda item: item.target_id))

    def find_signal_candidates(self, hint: SignalHint) -> tuple[TargetState, ...]:
        matches: list[TargetState] = []
        for state in self.list_current():
            target = state.target
            if target.account_id != hint.account_id or target.region != hint.region:
                continue
            identifiers_match = any(
                (
                    bool(
                        hint.network_interface_ids
                        and target.network_interface_id in hint.network_interface_ids
                    ),
                    bool(
                        hint.network_interface_attachment_ids
                        and target.attachment_id in hint.network_interface_attachment_ids
                    ),
                    bool(hint.instance_ids and target.instance_id in hint.instance_ids),
                    bool(
                        hint.security_group_ids
                        and set(target.security_group_ids).intersection(hint.security_group_ids)
                    ),
                    bool(hint.public_ips and target.public_ip in hint.public_ips),
                    bool(hint.allocation_ids and target.allocation_id in hint.allocation_ids),
                    bool(hint.association_ids and target.association_id in hint.association_ids),
                )
            )
            if identifiers_match:
                matches.append(state)
        unique = {item.target_id: item for item in matches}
        return tuple(sorted(unique.values(), key=lambda item: item.target_id))

    def _write_state_and_outbox(
        self,
        state: TargetState,
        event: TargetEvent | TargetRemoval,
        *,
        now: datetime,
        previous: TargetState | None,
    ) -> None:
        if previous is None:
            condition = "attribute_not_exists(pk)"
            names = None
            values = None
        else:
            condition = "#generation = :expected AND #status = :status"
            names = {"#generation": "generation", "#status": "status"}
            values = {
                ":expected": _n(previous.generation),
                ":status": _s(previous.status),
            }
        put_state: dict[str, Any] = {
            "TableName": self._table_name,
            "Item": self._state_item(state, updated_at=now),
            "ConditionExpression": condition,
        }
        if names:
            put_state["ExpressionAttributeNames"] = names
        if values:
            put_state["ExpressionAttributeValues"] = values
        put_outbox = {
            "TableName": self._table_name,
            "Item": self._outbox_item(event, state.target, now=now),
            "ConditionExpression": "attribute_not_exists(pk)",
        }
        self._client.transact_write_items(
            TransactItems=[{"Put": put_state}, {"Put": put_outbox}],
            ClientRequestToken=str(event.event_id)[:36],
        )

    def reconcile(
        self,
        target: NormalizedTarget,
        *,
        source: EventSource,
        now: datetime,
    ) -> ReconcileResult:
        for _attempt in range(self._max_retries):
            previous = self.get(target.target_id)
            if previous is not None and previous.status == "active":
                target = target.preserving_known_lifecycle(previous.target)
            if (
                previous is not None
                and previous.status == "active"
                and previous.signature == target.state_signature
            ):
                return ReconcileResult(ReconcileAction.NOOP, previous)

            generation = 1 if previous is None else previous.generation + 1
            event = build_target_event(
                target,
                generation,
                source=source,
                collected_at=now,
                previous=previous.target if previous and previous.status == "active" else None,
            )
            state = TargetState(
                target_id=target.target_id,
                generation=generation,
                status="active",
                target=target,
                signature=target.state_signature,
                contract_target_id=event.target.target_id,
            )
            try:
                self._write_state_and_outbox(
                    state,
                    event,
                    now=now,
                    previous=previous,
                )
            except Exception as error:
                if _conditional_failure(error):
                    continue
                raise
            action = (
                ReconcileAction.ADDED
                if previous is None or previous.status != "active"
                else ReconcileAction.CHANGED
            )
            return ReconcileResult(action, state, event)
        return ReconcileResult(ReconcileAction.RACE, self.get(target.target_id))

    def remove(
        self,
        expected: TargetState,
        *,
        source: EventSource,
        now: datetime,
    ) -> ReconcileResult:
        current = self.get(expected.target_id)
        if (
            current is None
            or current.status != "active"
            or current.generation != expected.generation
        ):
            return ReconcileResult(ReconcileAction.RACE, current)
        generation = current.generation + 1
        event = build_removal_event(
            current.target,
            generation,
            source=source,
            collected_at=now,
        )
        removed = TargetState(
            target_id=current.target_id,
            generation=generation,
            status="removed",
            target=current.target,
            signature=current.signature,
            contract_target_id=current.contract_target_id,
        )
        try:
            self._write_state_and_outbox(
                removed,
                event,
                now=now,
                previous=current,
            )
        except Exception as error:
            if _conditional_failure(error):
                return ReconcileResult(ReconcileAction.RACE, self.get(expected.target_id))
            raise
        return ReconcileResult(ReconcileAction.REMOVED, removed, event)

    def enqueue_coverage(
        self,
        state: TargetState,
        *,
        source: EventSource,
        now: datetime,
    ) -> ReconcileResult:
        current = self.get(state.target_id)
        if current is None or current.status != "active" or current.generation != state.generation:
            return ReconcileResult(ReconcileAction.RACE, current)
        event = build_target_event(
            current.target,
            current.generation,
            source=source,
            collected_at=now,
            reason=ScanReason.COVERAGE,
        )
        try:
            self._client.transact_write_items(
                TransactItems=[
                    {
                        "ConditionCheck": {
                            "TableName": self._table_name,
                            "Key": self._target_key(current.target_id),
                            "ConditionExpression": (
                                "#generation = :expected AND #status = :active"
                            ),
                            "ExpressionAttributeNames": {
                                "#generation": "generation",
                                "#status": "status",
                            },
                            "ExpressionAttributeValues": {
                                ":expected": _n(current.generation),
                                ":active": _s("active"),
                            },
                        }
                    },
                    {
                        "Put": {
                            "TableName": self._table_name,
                            "Item": self._outbox_item(event, current.target, now=now),
                            "ConditionExpression": "attribute_not_exists(pk)",
                        }
                    },
                ],
                ClientRequestToken=str(event.event_id)[:36],
            )
        except Exception as error:
            if _conditional_failure(error):
                latest = self.get(state.target_id)
                if (
                    latest is not None
                    and latest.status == "active"
                    and latest.generation == state.generation
                ):
                    return ReconcileResult(ReconcileAction.NOOP, latest)
                return ReconcileResult(ReconcileAction.RACE, latest)
            raise
        return ReconcileResult(ReconcileAction.CHANGED, current, event)

    def claim_signal(self, signal_id: str, *, now: datetime, ttl_seconds: int) -> bool:
        digest = deterministic_sha256(
            "portscanner.inventory.signal-dedupe.v1",
            {"signal_id": signal_id},
        )
        item = {
            "pk": _s(f"SIGNAL#{digest}"),
            "sk": _s("DEDUPE"),
            "entity": _s("signal-dedupe"),
            "expires_at": _n(int(now.timestamp()) + ttl_seconds),
        }
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=item,
                ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
                ExpressionAttributeValues={":now": _n(int(now.timestamp()))},
            )
        except Exception as error:
            if _conditional_failure(error):
                return False
            raise
        return True

    def release_signal(self, signal_id: str) -> None:
        digest = deterministic_sha256(
            "portscanner.inventory.signal-dedupe.v1",
            {"signal_id": signal_id},
        )
        self._client.delete_item(
            TableName=self._table_name,
            Key={"pk": _s(f"SIGNAL#{digest}"), "sk": _s("DEDUPE")},
        )
