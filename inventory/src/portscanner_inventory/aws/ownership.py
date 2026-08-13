"""Fresh ownership and generation validation immediately before dispatch."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from portscanner_inventory.aws.normalize import (
    NormalizedTarget,
    extract_security_group,
    lifecycle_is_active,
    lifecycle_matches,
    normalize_network_interface,
)
from portscanner_inventory.base import (
    OwnershipCheck,
    OwnershipVerdict,
    aws_error_code,
    is_not_found,
)


class OwnershipValidator:
    def __init__(
        self,
        state: Any,
        client_factory: Any,
        *,
        allowed_tag_keys: Sequence[str] = (),
        allowed_interface_types: Sequence[str] = (),
        required_tag_key: str | None = None,
        required_tag_value: str | None = None,
    ) -> None:
        self._state = state
        self._factory = client_factory
        self._allowed_tag_keys = tuple(allowed_tag_keys)
        self._allowed_interface_types = tuple(allowed_interface_types)
        self._required_tag_key = required_tag_key
        self._required_tag_value = required_tag_value

    def _client(self, target: NormalizedTarget) -> Any:
        if hasattr(self._factory, "client"):
            return self._factory.client(
                "ec2",
                account_id=target.account_id,
                region=target.region,
            )
        return self._factory(target.account_id, target.region)

    @staticmethod
    def _current_state_matches(state: Any, generation: int) -> bool:
        return (
            state is not None
            and getattr(state, "status", None) == "active"
            and getattr(state, "generation", None) == generation
        )

    @staticmethod
    def _live_association(
        eni: Mapping[str, Any],
        private_ip: str,
    ) -> tuple[bool, str | None]:
        for value in eni.get("PrivateIpAddresses", ()):
            if not isinstance(value, Mapping) or value.get("PrivateIpAddress") != private_ip:
                continue
            association = value.get("Association")
            if isinstance(association, Mapping) and association.get("PublicIp"):
                return True, str(association["PublicIp"])
            return True, None
        if eni.get("PrivateIpAddress") == private_ip:
            association = eni.get("Association")
            if isinstance(association, Mapping) and association.get("PublicIp"):
                return True, str(association["PublicIp"])
            return True, None
        return False, None

    @staticmethod
    def _groups(
        client: Any,
        eni: Mapping[str, Any],
    ) -> dict[str, tuple[Mapping[str, Any], ...]]:
        group_ids = tuple(
            sorted(
                {
                    str(value["GroupId"])
                    for value in eni.get("Groups", ())
                    if isinstance(value, Mapping) and value.get("GroupId")
                }
            )
        )
        if not group_ids:
            return {}
        response = client.describe_security_groups(GroupIds=list(group_ids))
        groups: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for value in response.get("SecurityGroups", ()):
            if isinstance(value, Mapping):
                group_id, permissions = extract_security_group(value)
                groups[group_id] = permissions
        if set(groups) != set(group_ids):
            raise ValueError("security group view is incomplete")
        return groups

    @staticmethod
    def _event_matches_live_target(event: Any, current: NormalizedTarget) -> bool:
        target = event.target
        context = event.aws_context
        return (
            str(target.provider) == "aws"
            and str(target.scope_id) == current.account_id
            and str(target.location) == current.region
            and str(target.resource_id) == current.network_interface_id
            and str(target.private_address) == current.private_ip
            and str(target.public_address) == current.public_ip
            and str(context.account_id) == current.account_id
            and str(context.region) == current.region
            and str(context.network_interface_id) == current.network_interface_id
            and str(context.private_ip) == current.private_ip
            and str(context.public_ip) == current.public_ip
            and context.instance_id == current.instance_id
            and tuple(context.security_group_ids) == current.security_group_ids
            and str(context.policy_fingerprint) == current.policy_fingerprint
        )

    def validate(self, target_id: str, generation: int) -> OwnershipCheck:
        initial = self._state.get(target_id)
        if not self._current_state_matches(initial, generation):
            return OwnershipCheck(
                OwnershipVerdict.STALE,
                reason="generation",
                current_generation=(initial.generation if initial is not None else None),
            )
        expected: NormalizedTarget = initial.target

        try:
            client = self._client(expected)
            response = client.describe_network_interfaces(
                NetworkInterfaceIds=[expected.network_interface_id]
            )
        except Exception as error:
            if is_not_found(error):
                return OwnershipCheck(OwnershipVerdict.INACTIVE, reason="eni-not-found")
            return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason=aws_error_code(error))

        values = [
            value for value in response.get("NetworkInterfaces", ()) if isinstance(value, Mapping)
        ]
        if len(values) != 1:
            return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason="ambiguous-eni")
        eni = values[0]
        private_present, live_public_ip = self._live_association(eni, expected.private_ip)
        if not private_present:
            return OwnershipCheck(OwnershipVerdict.MOVED, reason="private-ip-moved")
        if live_public_ip is None:
            return OwnershipCheck(OwnershipVerdict.INACTIVE, reason="association-removed")
        if live_public_ip != expected.public_ip:
            return OwnershipCheck(OwnershipVerdict.MOVED, reason="public-ip-moved")
        if str(eni.get("Status", "")).lower() != "in-use":
            return OwnershipCheck(OwnershipVerdict.INACTIVE, reason="eni-inactive")

        instance_state: str | None = None
        if expected.instance_id:
            try:
                response = client.describe_instances(InstanceIds=[expected.instance_id])
            except Exception as error:
                if is_not_found(error):
                    return OwnershipCheck(
                        OwnershipVerdict.INACTIVE,
                        reason="instance-not-found",
                    )
                return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason=aws_error_code(error))
            instances = [
                instance
                for reservation in response.get("Reservations", ())
                if isinstance(reservation, Mapping)
                for instance in reservation.get("Instances", ())
                if isinstance(instance, Mapping)
                and instance.get("InstanceId") == expected.instance_id
            ]
            if len(instances) != 1 or not isinstance(instances[0].get("State"), Mapping):
                return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason="ambiguous-instance")
            instance_state = str(instances[0]["State"].get("Name") or "unknown").lower()

        try:
            groups = self._groups(client, eni)
            current_values = normalize_network_interface(
                eni,
                account_id=expected.account_id,
                region=expected.region,
                security_groups=groups,
                allowed_tag_keys=self._allowed_tag_keys,
                instance_state=instance_state,
                allowed_interface_types=self._allowed_interface_types,
                required_tag_key=self._required_tag_key,
                required_tag_value=self._required_tag_value,
            )
        except Exception as error:
            return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason=aws_error_code(error))
        current = next((item for item in current_values if item.target_id == target_id), None)
        if current is None:
            return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason="normalization-race")
        if not lifecycle_is_active(current.lifecycle):
            return OwnershipCheck(OwnershipVerdict.INACTIVE, current, "lifecycle")
        if (
            not lifecycle_matches(expected.lifecycle, current.lifecycle)
            or current.security_group_ids != expected.security_group_ids
            or current.policy_fingerprint != expected.policy_fingerprint
        ):
            return OwnershipCheck(
                OwnershipVerdict.STALE,
                current,
                "policy-or-lifecycle",
                initial.generation,
            )

        final = self._state.get(target_id)
        if not self._current_state_matches(final, generation):
            return OwnershipCheck(
                OwnershipVerdict.STALE,
                current,
                "generation-race",
                (final.generation if final is not None else None),
            )
        return OwnershipCheck(
            OwnershipVerdict.ACTIVE,
            current,
            current_generation=generation,
        )

    def validate_event(self, event: Any) -> OwnershipCheck:
        """Validate a shared TargetEvent and its complete live AWS context."""

        context = event.aws_context
        stable_id = (
            f"aws:{context.account_id}:{context.region}:eni:{context.network_interface_id}:"
            f"private-ip:{context.private_ip}"
        )
        result = self.validate(stable_id, event.target.generation)
        if result.verdict is not OwnershipVerdict.ACTIVE:
            return result
        if result.current is None:
            return OwnershipCheck(OwnershipVerdict.UNKNOWN, reason="missing-live-target")
        if not self._event_matches_live_target(event, result.current):
            return OwnershipCheck(
                OwnershipVerdict.STALE,
                result.current,
                "event-context",
            )
        return result
