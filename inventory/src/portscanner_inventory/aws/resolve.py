"""Resolve sanitized signals by re-reading current EC2 state."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from portscanner_inventory.aws.normalize import (
    NormalizedTarget,
    extract_security_group,
    normalize_network_interface,
)
from portscanner_inventory.base import (
    Resolution,
    ResolutionStatus,
    SignalHint,
    aws_error_code,
    is_not_found,
)


def _chunks(values: Sequence[str], size: int) -> Iterable[tuple[str, ...]]:
    for offset in range(0, len(values), size):
        yield tuple(values[offset : offset + size])


class Ec2Resolver:
    def __init__(
        self,
        client_factory: Any,
        *,
        allowed_tag_keys: Sequence[str] = (),
        page_size: int = 500,
    ) -> None:
        self._factory = client_factory
        self._allowed_tag_keys = tuple(allowed_tag_keys)
        self._page_size = page_size

    def _client(self, hint: SignalHint) -> Any:
        if hasattr(self._factory, "client"):
            return self._factory.client(
                "ec2",
                account_id=hint.account_id,
                region=hint.region,
            )
        return self._factory(hint.account_id, hint.region)

    def _paginate_enis(
        self,
        client: Any,
        *,
        filters: Sequence[Mapping[str, Any]],
    ) -> tuple[Mapping[str, Any], ...]:
        values: list[Mapping[str, Any]] = []
        token: str | None = None
        while True:
            request: dict[str, Any] = {
                "Filters": list(filters),
                "MaxResults": self._page_size,
            }
            if token:
                request["NextToken"] = token
            response = client.describe_network_interfaces(**request)
            values.extend(
                item for item in response.get("NetworkInterfaces", ()) if isinstance(item, Mapping)
            )
            next_token = response.get("NextToken")
            if not next_token:
                return tuple(values)
            token = str(next_token)

    def _read_eni_ids(
        self,
        client: Any,
        eni_ids: Sequence[str],
    ) -> tuple[tuple[Mapping[str, Any], ...], tuple[str, ...]]:
        values: list[Mapping[str, Any]] = []
        missing: set[str] = set()
        for chunk in _chunks(tuple(sorted(set(eni_ids))), 100):
            try:
                response = client.describe_network_interfaces(NetworkInterfaceIds=list(chunk))
            except Exception as error:
                if is_not_found(error):
                    for eni_id in chunk:
                        try:
                            response = client.describe_network_interfaces(
                                NetworkInterfaceIds=[eni_id]
                            )
                        except Exception as single_error:
                            if is_not_found(single_error):
                                missing.add(eni_id)
                                continue
                            raise
                        values.extend(
                            item
                            for item in response.get("NetworkInterfaces", ())
                            if isinstance(item, Mapping)
                        )
                    continue
                raise
            values.extend(
                item for item in response.get("NetworkInterfaces", ()) if isinstance(item, Mapping)
            )
        found = {
            str(item.get("NetworkInterfaceId")) for item in values if item.get("NetworkInterfaceId")
        }
        missing.update(set(eni_ids) - found)
        return tuple(values), tuple(sorted(missing))

    @staticmethod
    def _address_eni_ids(client: Any, hint: SignalHint) -> tuple[str, ...]:
        values: list[Mapping[str, Any]] = []
        requests: list[dict[str, Any]] = []
        if hint.allocation_ids:
            requests.append({"AllocationIds": list(hint.allocation_ids)})
        if hint.association_ids:
            requests.append(
                {"Filters": [{"Name": "association-id", "Values": list(hint.association_ids)}]}
            )
        if hint.public_ips:
            requests.append({"PublicIps": list(hint.public_ips)})
        for request in requests:
            try:
                response = client.describe_addresses(**request)
            except Exception as error:
                if is_not_found(error):
                    continue
                raise
            values.extend(
                item for item in response.get("Addresses", ()) if isinstance(item, Mapping)
            )
        return tuple(
            sorted(
                {
                    str(item["NetworkInterfaceId"])
                    for item in values
                    if item.get("NetworkInterfaceId")
                }
            )
        )

    @staticmethod
    def _security_groups(
        client: Any,
        group_ids: Sequence[str],
    ) -> dict[str, tuple[Mapping[str, Any], ...]]:
        groups: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for chunk in _chunks(tuple(sorted(set(group_ids))), 100):
            response = client.describe_security_groups(GroupIds=list(chunk))
            for value in response.get("SecurityGroups", ()):
                if not isinstance(value, Mapping):
                    continue
                group_id, permissions = extract_security_group(value)
                groups[group_id] = permissions
        missing = set(group_ids) - groups.keys()
        if missing:
            raise ValueError("attached security group was not returned")
        return groups

    @staticmethod
    def _instance_states(
        client: Any,
        instance_ids: Sequence[str],
    ) -> dict[str, str]:
        states: dict[str, str] = {}
        for chunk in _chunks(tuple(sorted(set(instance_ids))), 100):
            try:
                response = client.describe_instances(InstanceIds=list(chunk))
            except Exception as error:
                if is_not_found(error):
                    continue
                raise
            for reservation in response.get("Reservations", ()):
                if not isinstance(reservation, Mapping):
                    continue
                for instance in reservation.get("Instances", ()):
                    if not isinstance(instance, Mapping) or not instance.get("InstanceId"):
                        continue
                    state = instance.get("State")
                    if isinstance(state, Mapping) and state.get("Name"):
                        states[str(instance["InstanceId"])] = str(state["Name"]).lower()
        return states

    def resolve(self, hint: SignalHint) -> Resolution:
        try:
            client = self._client(hint)
            eni_by_id: dict[str, Mapping[str, Any]] = {}

            requested_ids = set(hint.network_interface_ids)
            requested_ids.update(self._address_eni_ids(client, hint))
            direct_enis, missing = self._read_eni_ids(client, tuple(sorted(requested_ids)))
            for value in direct_enis:
                if value.get("NetworkInterfaceId"):
                    eni_by_id[str(value["NetworkInterfaceId"])] = value

            if hint.instance_ids:
                values = self._paginate_enis(
                    client,
                    filters=[
                        {
                            "Name": "attachment.instance-id",
                            "Values": list(hint.instance_ids),
                        }
                    ],
                )
                for value in values:
                    if value.get("NetworkInterfaceId"):
                        eni_by_id[str(value["NetworkInterfaceId"])] = value

            if hint.network_interface_attachment_ids:
                values = self._paginate_enis(
                    client,
                    filters=[
                        {
                            "Name": "attachment.attachment-id",
                            "Values": list(hint.network_interface_attachment_ids),
                        }
                    ],
                )
                for value in values:
                    if value.get("NetworkInterfaceId"):
                        eni_by_id[str(value["NetworkInterfaceId"])] = value

            if hint.security_group_ids:
                values = self._paginate_enis(
                    client,
                    filters=[
                        {
                            "Name": "group-id",
                            "Values": list(hint.security_group_ids),
                        }
                    ],
                )
                for value in values:
                    if value.get("NetworkInterfaceId"):
                        eni_by_id[str(value["NetworkInterfaceId"])] = value

            attached_ids = {
                str(group.get("GroupId"))
                for eni in eni_by_id.values()
                for group in eni.get("Groups", ())
                if isinstance(group, Mapping) and group.get("GroupId")
            }
            groups = (
                self._security_groups(client, tuple(sorted(attached_ids))) if attached_ids else {}
            )
            instance_ids = {
                str(attachment["InstanceId"])
                for eni in eni_by_id.values()
                if isinstance((attachment := eni.get("Attachment")), Mapping)
                and attachment.get("InstanceId")
            }
            instance_states = self._instance_states(client, tuple(sorted(instance_ids)))

            targets: dict[str, NormalizedTarget] = {}
            for eni in eni_by_id.values():
                attachment = eni.get("Attachment")
                instance_id = (
                    str(attachment["InstanceId"])
                    if isinstance(attachment, Mapping) and attachment.get("InstanceId")
                    else None
                )
                for target in normalize_network_interface(
                    eni,
                    account_id=hint.account_id,
                    region=hint.region,
                    security_groups=groups,
                    allowed_tag_keys=self._allowed_tag_keys,
                    instance_state=instance_states.get(instance_id or ""),
                ):
                    signaled = target.with_signal(
                        event_name=hint.event_name,
                        event_id=hint.event_id,
                        request_id=hint.request_id,
                        event_time=hint.event_time,
                        candidate_ports=hint.candidate_ports,
                    )
                    targets[signaled.target_id] = signaled
            return Resolution(
                targets=tuple(targets[key] for key in sorted(targets)),
                missing_network_interface_ids=missing,
            )
        except Exception as error:
            return Resolution(
                targets=(),
                status=ResolutionStatus.UNKNOWN,
                failure_code=aws_error_code(error),
            )
