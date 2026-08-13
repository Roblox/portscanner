"""Normalize inventory ownership verdicts into dispatch decisions."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class OwnershipDecision(StrEnum):
    DISPATCH = "dispatch"
    STALE = "stale"
    CANCEL = "cancel"
    RETRY = "retry"


@dataclass(frozen=True)
class OwnershipCheck:
    verdict: str
    requested_generation: int
    current_generation: int | None
    decision: OwnershipDecision
    reason: str | None = None


class OwnershipService(Protocol):
    def validate_event(self, event: Any) -> Any:
        """Return a verdict for a complete shared event."""


def _field(verdict: Any, name: str, default: Any = None) -> Any:
    if isinstance(verdict, Mapping):
        return verdict.get(name, default)
    return getattr(verdict, name, default)


def _state_name(value: Any) -> str:
    enum_value = getattr(value, "value", value)
    if not isinstance(enum_value, str):
        return "UNKNOWN"
    return enum_value.strip().upper()


def classify_verdict(verdict: Any, requested_generation: int) -> OwnershipCheck:
    """Apply the fail-closed ownership/generation gate."""

    state_value = _field(verdict, "verdict")
    if state_value is None:
        state_value = _field(verdict, "state")
    state = _state_name(state_value)
    current = _field(verdict, "current_generation")
    if current is None:
        current_object = _field(verdict, "current")
        candidate_generation = _field(current_object, "generation")
        if isinstance(candidate_generation, int) and not isinstance(candidate_generation, bool):
            current = candidate_generation
    reported_request = _field(verdict, "requested_generation")
    if reported_request is not None and reported_request != requested_generation:
        state = "UNKNOWN"
        current = None
    if current is not None and (
        isinstance(current, bool) or not isinstance(current, int) or current < 1
    ):
        state = "UNKNOWN"
        current = None

    if state == "ACTIVE":
        if current is None or current == requested_generation:
            decision = OwnershipDecision.DISPATCH
        elif current is not None and current > requested_generation:
            decision = OwnershipDecision.STALE
        else:
            # Inventory behind the event is not proof of current ownership.
            decision = OwnershipDecision.RETRY
    elif state == "STALE":
        decision = OwnershipDecision.STALE
    elif state in {"MOVED", "INACTIVE"}:
        decision = OwnershipDecision.CANCEL
    else:
        state = "UNKNOWN"
        decision = OwnershipDecision.RETRY

    return OwnershipCheck(
        verdict=state,
        requested_generation=requested_generation,
        current_generation=current,
        decision=decision,
        reason=(str(reason) if (reason := _field(verdict, "reason")) is not None else None),
    )


def revalidate_event(
    service: OwnershipService,
    event: Any,
) -> OwnershipCheck:
    generation = event.target.generation
    raw_verdict = service.validate_event(event)
    return classify_verdict(raw_verdict, generation)


def ownership_service_from_environment(
    *,
    session: Any | None = None,
    state_table: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> OwnershipService:
    """Build the inventory package's AWS ownership validator."""

    env = environment if environment is not None else os.environ
    from portscanner_inventory.aws.ownership import OwnershipValidator
    from portscanner_inventory.aws.session import AwsClientFactory
    from portscanner_inventory.state import DynamoStateStore

    table_name = state_table or env.get("INVENTORY_TABLE")
    if not table_name:
        raise RuntimeError("inventory ownership state table is not configured")
    if session is None:
        import boto3

        session = boto3.Session()
    state = DynamoStateStore(session.client("dynamodb"), table_name)
    factory = AwsClientFactory(
        session,
        role_arn_template=env.get("DISCOVERY_ROLE_ARN_TEMPLATE"),
        external_id=env.get("DISCOVERY_EXTERNAL_ID"),
        local_account_id=env.get("AWS_ACCOUNT_ID"),
    )
    allowed_tags = tuple(
        sorted(
            {value.strip() for value in env.get("ALLOWED_TAG_KEYS", "").split(",") if value.strip()}
        )
    )
    allowed_interface_types = tuple(
        sorted(
            {
                value.strip()
                for value in env.get("ALLOWED_ENI_INTERFACE_TYPES", "").split(",")
                if value.strip()
            }
        )
    )
    return OwnershipValidator(
        state,
        factory,
        allowed_tag_keys=allowed_tags,
        allowed_interface_types=allowed_interface_types,
        required_tag_key=env.get("REQUIRED_TARGET_TAG_KEY") or None,
        required_tag_value=env.get("REQUIRED_TARGET_TAG_VALUE") or None,
    )
