"""Allowlist and sanitize EC2 EventBridge/CloudTrail change signals."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from portscanner_inventory.base import CandidatePorts, SignalHint

_ENI_RE = re.compile(r"^eni-[0-9a-fA-F]+$")
_ENI_ATTACHMENT_RE = re.compile(r"^eni-attach-[0-9a-fA-F]+$")
_INSTANCE_RE = re.compile(r"^i-[0-9a-fA-F]+$")
_SG_RE = re.compile(r"^sg-[0-9a-fA-F]+$")
_ALLOCATION_RE = re.compile(r"^eipalloc-[0-9a-fA-F]+$")
_ASSOCIATION_RE = re.compile(r"^eipassoc-[0-9a-fA-F]+$")

_EIP_EVENTS = {
    "AssociateAddress",
    "DisassociateAddress",
    "ReleaseAddress",
}
_ENI_EVENTS = {
    "AssignPrivateIpAddresses",
    "AttachNetworkInterface",
    "CreateNetworkInterface",
    "DeleteNetworkInterface",
    "DetachNetworkInterface",
    "ModifyNetworkInterfaceAttribute",
    "UnassignPrivateIpAddresses",
}
_INSTANCE_EVENTS = {
    "RebootInstances",
    "RunInstances",
    "StartInstances",
    "StopInstances",
    "TerminateInstances",
}
_SG_INGRESS_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "ModifySecurityGroupRules",
    "RevokeSecurityGroupIngress",
}
_SG_ATTACHMENT_EVENTS = {"ModifyInstanceAttribute"}
ALLOWED_CLOUDTRAIL_EVENTS = frozenset(
    _EIP_EVENTS | _ENI_EVENTS | _INSTANCE_EVENTS | _SG_INGRESS_EVENTS | _SG_ATTACHMENT_EVENTS
)


def _event_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _items(value: Any) -> tuple[Any, ...]:
    if isinstance(value, Mapping):
        nested = value.get("items") or value.get("Items") or ()
        return tuple(nested) if isinstance(nested, Sequence) and not isinstance(nested, str) else ()
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(value)
    return ()


def _collect(
    values: Iterable[Any],
    pattern: re.Pattern[str],
) -> tuple[str, ...]:
    return tuple(sorted({str(value) for value in values if pattern.fullmatch(str(value))}))


def _field_values(
    containers: Sequence[Mapping[str, Any]],
    singular: Sequence[str],
    sets: Sequence[tuple[str, Sequence[str]]],
) -> tuple[Any, ...]:
    values: list[Any] = []
    for container in containers:
        for name in singular:
            if container.get(name) is not None:
                values.append(container[name])
        for set_name, item_names in sets:
            for item in _items(container.get(set_name)):
                if isinstance(item, Mapping):
                    for item_name in item_names:
                        if item.get(item_name) is not None:
                            values.append(item[item_name])
                            break
                elif isinstance(item, str):
                    values.append(item)
    return tuple(values)


def _permission_items(request: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...] | None:
    raw = request.get("ipPermissions") or request.get("IpPermissions")
    if raw is None:
        return None
    if isinstance(raw, Mapping):
        raw = raw.get("items") or raw.get("Items")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return None
    values = tuple(item for item in raw if isinstance(item, Mapping))
    return values if len(values) == len(raw) else None


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(set(ranges)):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return tuple(merged)


def candidate_tcp_ports(
    request: Mapping[str, Any],
    *,
    max_ranges: int = 32,
    max_ports: int = 8_192,
) -> CandidatePorts:
    """Derive bounded TCP ranges; fall back to full TCP on ambiguity."""

    permissions = _permission_items(request)
    if not permissions:
        return CandidatePorts.full()
    ranges: list[tuple[int, int]] = []
    for permission in permissions:
        protocol = str(permission.get("ipProtocol", permission.get("IpProtocol", "-1"))).lower()
        if protocol in {"-1", "all"}:
            return CandidatePorts.full()
        if protocol not in {"6", "tcp"}:
            continue
        start = permission.get("fromPort", permission.get("FromPort"))
        end = permission.get("toPort", permission.get("ToPort"))
        if not isinstance(start, int) or not isinstance(end, int) or not 1 <= start <= end <= 65535:
            return CandidatePorts.full()
        ranges.append((start, end))
    if not ranges:
        return CandidatePorts.full()
    merged = _merge_ranges(ranges)
    cardinality = sum(end - start + 1 for start, end in merged)
    if len(merged) > max_ranges or cardinality > max_ports:
        return CandidatePorts.full()
    return CandidatePorts(ranges=merged)


def _public_ips(values: Iterable[Any]) -> tuple[str, ...]:
    result: set[str] = set()
    for value in values:
        try:
            address = ipaddress.IPv4Address(str(value))
        except ipaddress.AddressValueError:
            continue
        if not (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            result.add(str(address))
    return tuple(sorted(result))


def parse_signal(
    event: Mapping[str, Any],
    *,
    max_port_ranges: int = 32,
    max_ports: int = 8_192,
) -> SignalHint | None:
    """Return a safe hint, ignore unsupported events, and reject malformed allowed ones."""

    if event.get("source") != "aws.ec2":
        return None
    detail_type = event.get("detail-type")
    detail = _mapping(event.get("detail"))
    account_id = str(event.get("account") or "")
    region = str(event.get("region") or "")

    if detail_type == "EC2 Instance State-change Notification":
        instance_ids = _collect((detail.get("instance-id"),), _INSTANCE_RE)
        if not instance_ids:
            raise ValueError("instance state signal has no valid instance identifier")
        event_id = str(event.get("id") or "")
        return SignalHint(
            account_id=account_id,
            region=region,
            event_name="InstanceStateChange",
            event_id=event_id,
            event_time=_event_time(event.get("time")),
            instance_ids=instance_ids,
        )

    if detail_type != "AWS API Call via CloudTrail":
        return None
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return None
    event_name = str(detail.get("eventName") or "")
    if event_name not in ALLOWED_CLOUDTRAIL_EVENTS:
        return None
    event_id = str(detail.get("eventID") or event.get("id") or "")
    request_id = detail.get("requestID")
    request = _mapping(detail.get("requestParameters"))
    response = _mapping(detail.get("responseElements"))
    if event_name in {
        "ModifyInstanceAttribute",
        "ModifyNetworkInterfaceAttribute",
    } and not (request.get("groupSet") or request.get("groups") or request.get("groupId")):
        return None
    response_network_interface = _mapping(response.get("networkInterface"))
    containers = (request, response, response_network_interface)

    eni_values = _field_values(
        containers,
        ("networkInterfaceId",),
        (("networkInterfaceSet", ("networkInterfaceId",)),),
    )
    attachment_values = _field_values(containers, ("attachmentId",), ())
    instance_values = _field_values(
        containers,
        ("instanceId",),
        (
            ("instancesSet", ("instanceId",)),
            ("instances", ("instanceId",)),
        ),
    )
    group_values = _field_values(
        containers,
        ("groupId",),
        (
            ("groupSet", ("groupId",)),
            ("groups", ("groupId",)),
        ),
    )
    allocation_values = _field_values(containers, ("allocationId",), ())
    association_values = _field_values(containers, ("associationId",), ())
    public_values = _field_values(containers, ("publicIp",), ())

    network_interface_ids = _collect(eni_values, _ENI_RE)
    network_interface_attachment_ids = _collect(
        attachment_values,
        _ENI_ATTACHMENT_RE,
    )
    instance_ids = _collect(instance_values, _INSTANCE_RE)
    security_group_ids = _collect(group_values, _SG_RE)
    allocation_ids = _collect(allocation_values, _ALLOCATION_RE)
    association_ids = _collect(association_values, _ASSOCIATION_RE)
    public_ips = _public_ips(public_values)

    if event_name in _SG_INGRESS_EVENTS:
        ports = candidate_tcp_ports(
            request,
            max_ranges=max_port_ranges,
            max_ports=max_ports,
        )
    else:
        ports = CandidatePorts.full()

    return SignalHint(
        account_id=account_id,
        region=region,
        event_name=event_name,
        event_id=event_id,
        request_id=str(request_id) if request_id else None,
        event_time=_event_time(event.get("time")),
        network_interface_ids=network_interface_ids,
        network_interface_attachment_ids=network_interface_attachment_ids,
        instance_ids=instance_ids,
        security_group_ids=security_group_ids,
        allocation_ids=allocation_ids,
        association_ids=association_ids,
        public_ips=public_ips,
        candidate_ports=ports,
    )
