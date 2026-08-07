from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from portscanner_inventory.aws.ownership import OwnershipValidator
from portscanner_inventory.base import OwnershipVerdict, SnapshotScope
from portscanner_inventory.events import build_target_event, snapshot_source
from portscanner_inventory.state import TargetState

from .helpers import AwsError, eni, normalized_target, permission, security_group

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _state(generation: int = 1) -> TargetState:
    target = normalized_target()
    return TargetState(
        target_id=target.target_id,
        generation=generation,
        status="active",
        target=target,
        signature=target.state_signature,
    )


class StaticState:
    def __init__(self, value: TargetState | None) -> None:
        self.value = value

    def get(self, _target_id: str) -> TargetState | None:
        return self.value


class Client:
    def __init__(
        self,
        interface: dict[str, Any] | None = None,
        *,
        error: Exception | None = None,
        permissions: list[dict[str, Any]] | None = None,
        instance_state: str = "running",
    ) -> None:
        self.interface = interface or eni()
        self.error = error
        self.permissions = permissions
        self.instance_state = instance_state

    def describe_network_interfaces(self, **_request: Any) -> dict[str, Any]:
        if self.error:
            raise self.error
        return {"NetworkInterfaces": [self.interface]}

    def describe_security_groups(self, **_request: Any) -> dict[str, Any]:
        return {"SecurityGroups": [security_group(permissions=self.permissions)]}

    def describe_instances(self, **_request: Any) -> dict[str, Any]:
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-bbbbbbbb",
                            "State": {"Name": self.instance_state},
                        }
                    ]
                }
            ]
        }


def _validator(state: Any, client: Any) -> OwnershipValidator:
    return OwnershipValidator(state, lambda _account, _region: client)


def test_active_ownership_verifies_state_before_and_after_ec2_read() -> None:
    state = _state()

    result = _validator(StaticState(state), Client()).validate(state.target_id, 1)

    assert result.verdict is OwnershipVerdict.ACTIVE


def test_stale_generation_short_circuits_without_ec2() -> None:
    state = _state(generation=2)

    result = _validator(StaticState(state), object()).validate(state.target_id, 1)

    assert result.verdict is OwnershipVerdict.STALE
    assert result.current_generation == 2


def test_removed_state_still_reports_superseding_generation() -> None:
    state = _state(generation=2)
    removed = TargetState(
        target_id=state.target_id,
        generation=state.generation,
        status="removed",
        target=state.target,
        signature=state.signature,
    )

    result = _validator(StaticState(removed), object()).validate(state.target_id, 1)

    assert result.verdict is OwnershipVerdict.STALE
    assert result.current_generation == 2


def test_moved_public_association_is_not_active() -> None:
    state = _state()
    live = eni(public_ip="203.0.113.99")

    result = _validator(StaticState(state), Client(live)).validate(state.target_id, 1)

    assert result.verdict is OwnershipVerdict.MOVED


def test_missing_public_association_is_inactive() -> None:
    state = _state()

    result = _validator(StaticState(state), Client(eni(public_ip=None))).validate(
        state.target_id,
        1,
    )

    assert result.verdict is OwnershipVerdict.INACTIVE


def test_stopped_instance_lifecycle_is_inactive() -> None:
    state = _state()

    result = _validator(
        StaticState(state),
        Client(instance_state="stopped"),
    ).validate(state.target_id, 1)

    assert result.verdict is OwnershipVerdict.INACTIVE
    assert result.reason == "lifecycle"


def test_permission_and_throttle_errors_are_unknown() -> None:
    state = _state()

    denied = _validator(
        StaticState(state),
        Client(error=AwsError("UnauthorizedOperation")),
    ).validate(state.target_id, 1)
    throttled = _validator(
        StaticState(state),
        Client(error=AwsError("ThrottlingException")),
    ).validate(state.target_id, 1)

    assert denied.verdict is OwnershipVerdict.UNKNOWN
    assert throttled.verdict is OwnershipVerdict.UNKNOWN


def test_live_policy_drift_is_stale() -> None:
    state = _state()

    result = _validator(
        StaticState(state),
        Client(permissions=[permission(80, 80)]),
    ).validate(state.target_id, 1)

    assert result.verdict is OwnershipVerdict.STALE


def test_generation_change_during_validation_is_stale() -> None:
    initial = _state(1)
    newer = _state(2)

    class RacingState:
        def __init__(self) -> None:
            self.values = [initial, newer]

        def get(self, _target_id: str) -> TargetState:
            return self.values.pop(0)

    result = _validator(RacingState(), Client()).validate(initial.target_id, 1)

    assert result.verdict is OwnershipVerdict.STALE
    assert result.reason == "generation-race"
    assert result.current_generation == 2


def test_validate_event_compares_contract_context_to_final_live_target() -> None:
    event_target = normalized_target()
    source = snapshot_source(
        SnapshotScope(source="aws-config", name="example-aggregator"),
        NOW,
    )
    event = build_target_event(
        event_target,
        1,
        source=source,
        collected_at=NOW,
    )
    live_target = normalized_target(public_ip="203.0.113.99")
    live_state = TargetState(
        target_id=live_target.target_id,
        generation=1,
        status="active",
        target=live_target,
        signature=live_target.state_signature,
    )

    result = _validator(
        StaticState(live_state),
        Client(eni(public_ip=live_target.public_ip)),
    ).validate_event(event)

    assert result.verdict is OwnershipVerdict.STALE
    assert result.reason == "event-context"
    assert result.current is not None
    assert result.current.public_ip == live_target.public_ip


def test_validate_event_ignores_descriptive_tag_only_changes() -> None:
    event_target = normalized_target(tags=[{"Key": "name", "Value": "before"}])
    source = snapshot_source(
        SnapshotScope(source="aws-config", name="example-aggregator"),
        NOW,
    )
    event = build_target_event(
        event_target,
        1,
        source=source,
        collected_at=NOW,
    )
    live_target = normalized_target(tags=[{"Key": "name", "Value": "after"}])
    live_state = TargetState(
        target_id=live_target.target_id,
        generation=1,
        status="active",
        target=live_target,
        signature=live_target.state_signature,
    )

    result = _validator(
        StaticState(live_state),
        Client(eni(tags=[{"Key": "name", "Value": "after"}])),
    ).validate_event(event)

    assert result.verdict is OwnershipVerdict.ACTIVE
