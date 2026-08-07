"""Deterministic normalization for EC2 ENIs and security-group ingress."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, cast

from portscanner_inventory.base import CandidatePorts

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_ENI_RE = re.compile(r"^eni-[0-9a-fA-F]+$")
_SG_RE = re.compile(r"^sg-[0-9a-fA-F]+$")
_RFC1918 = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _get(value: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in value:
            return value[name]
    return default


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, Mapping):
            return parsed
    return {}


def _canonical_ip_network(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value.strip().lower()


def _canonical_source(kind: str, value: Mapping[str, Any] | str) -> tuple[str, str]:
    if isinstance(value, str):
        raw = value
    elif kind == "ipv4":
        raw = str(_get(value, "CidrIp", "cidrIp", default=""))
    elif kind == "ipv6":
        raw = str(_get(value, "CidrIpv6", "cidrIpv6", default=""))
    elif kind == "prefix":
        raw = str(_get(value, "PrefixListId", "prefixListId", default=""))
    else:
        parts = (
            _get(value, "GroupId", "groupId", default=""),
            _get(value, "UserId", "userId", default=""),
            _get(value, "VpcId", "vpcId", default=""),
            _get(
                value,
                "VpcPeeringConnectionId",
                "vpcPeeringConnectionId",
                default="",
            ),
        )
        raw = "|".join(str(part) for part in parts)
    if kind in {"ipv4", "ipv6"}:
        raw = _canonical_ip_network(raw)
    return kind, raw


def canonicalize_ingress_rules(
    permissions: Sequence[Mapping[str, Any]] | None,
) -> tuple[dict[str, Any], ...]:
    """Return effective ingress semantics, ignoring descriptions and input order."""

    canonical: dict[str, dict[str, Any]] = {}
    for permission in permissions or ():
        protocol = str(_get(permission, "IpProtocol", "ipProtocol", default="-1")).lower()
        if protocol == "6":
            protocol = "tcp"
        elif protocol == "17":
            protocol = "udp"

        sources: set[tuple[str, str]] = set()
        source_fields = (
            ("ipv4", ("IpRanges", "ipRanges")),
            ("ipv6", ("Ipv6Ranges", "ipv6Ranges")),
            ("prefix", ("PrefixListIds", "prefixListIds")),
            ("security-group", ("UserIdGroupPairs", "userIdGroupPairs")),
        )
        for kind, names in source_fields:
            raw_values = _get(permission, *names, default=()) or ()
            if isinstance(raw_values, Mapping):
                raw_values = _get(raw_values, "items", "Items", default=()) or ()
            if isinstance(raw_values, str):
                raw_values = (raw_values,)
            for raw in raw_values:
                if isinstance(raw, (str, Mapping)):
                    source = _canonical_source(kind, raw)
                    if source[1]:
                        sources.add(source)

        from_port = _get(permission, "FromPort", "fromPort")
        to_port = _get(permission, "ToPort", "toPort")
        rule = {
            "protocol": protocol,
            "from_port": int(from_port) if from_port is not None else None,
            "to_port": int(to_port) if to_port is not None else None,
            "sources": [{"kind": kind, "value": value} for kind, value in sorted(sources)],
        }
        encoded = json.dumps(rule, separators=(",", ":"), sort_keys=True)
        canonical[encoded] = rule
    return tuple(canonical[key] for key in sorted(canonical))


def policy_fingerprint(
    security_groups: Mapping[str, Sequence[Mapping[str, Any]]],
    attached_group_ids: Sequence[str],
) -> str:
    """Fingerprint the union of attached ingress rules."""

    effective: dict[str, dict[str, Any]] = {}
    for group_id in sorted(set(attached_group_ids)):
        if group_id not in security_groups:
            raise KeyError(f"missing attached security group: {group_id}")
        for rule in canonicalize_ingress_rules(security_groups[group_id]):
            encoded = json.dumps(rule, separators=(",", ":"), sort_keys=True)
            effective[encoded] = rule
    payload = json.dumps(
        [effective[key] for key in sorted(effective)],
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def extract_security_group(
    value: Mapping[str, Any],
) -> tuple[str, tuple[Mapping[str, Any], ...]]:
    configuration = _as_mapping(_get(value, "configuration", "Configuration", default=value))
    group_id = str(
        _get(
            configuration,
            "groupId",
            "GroupId",
            default=_get(value, "resourceId", "ResourceId", default=""),
        )
    )
    if not _SG_RE.fullmatch(group_id):
        raise ValueError("invalid security group identifier")
    permissions = _get(configuration, "ipPermissions", "IpPermissions", default=()) or ()
    if isinstance(permissions, Mapping):
        permissions = _get(permissions, "items", "Items", default=()) or ()
    if not isinstance(permissions, Sequence) or isinstance(permissions, (str, bytes)):
        raise ValueError("invalid security group ingress")
    return group_id, tuple(item for item in permissions if isinstance(item, Mapping))


def _validate_public_association(value: Any) -> str:
    address = ipaddress.IPv4Address(str(value))
    if (
        any(address in network for network in _RFC1918)
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError("association is not a public IPv4 address")
    return str(address)


def _validate_private_ip(value: Any) -> str:
    return str(ipaddress.IPv4Address(str(value)))


def _tags(value: Mapping[str, Any], allowlist: frozenset[str]) -> tuple[tuple[str, str], ...]:
    raw = _get(value, "TagSet", "tagSet", "Tags", "tags", default=()) or ()
    if isinstance(raw, Mapping) and isinstance(
        _get(raw, "items", "Items"),
        Sequence,
    ):
        raw = _get(raw, "items", "Items", default=()) or ()
    pairs: Iterable[tuple[Any, Any]]
    if isinstance(raw, Mapping):
        pairs = raw.items()
    else:
        pairs = (
            (
                _get(item, "Key", "key"),
                _get(item, "Value", "value"),
            )
            for item in raw
            if isinstance(item, Mapping)
        )
    sanitized: dict[str, str] = {}
    for key, item_value in pairs:
        if not isinstance(key, str) or key not in allowlist or not isinstance(item_value, str):
            continue
        if len(item_value) > 256 or any(ord(character) < 32 for character in item_value):
            continue
        sanitized[key] = item_value
    return tuple(sorted(sanitized.items()))


def _group_ids(value: Mapping[str, Any]) -> tuple[str, ...]:
    raw_groups = _get(value, "Groups", "groups", "groupSet", default=()) or ()
    if isinstance(raw_groups, Mapping):
        raw_groups = _get(raw_groups, "items", "Items", default=()) or ()
    result = {
        str(_get(group, "GroupId", "groupId", default=""))
        for group in raw_groups
        if isinstance(group, Mapping)
    }
    if any(not _SG_RE.fullmatch(group_id) for group_id in result):
        raise ValueError("invalid attached security group identifier")
    return tuple(sorted(result))


def _associations(
    value: Mapping[str, Any],
) -> tuple[tuple[str, str, str | None, str | None], ...]:
    result: set[tuple[str, str, str | None, str | None]] = set()
    raw_private = _get(value, "PrivateIpAddresses", "privateIpAddresses", default=()) or ()
    if isinstance(raw_private, Mapping):
        raw_private = _get(raw_private, "items", "Items", default=()) or ()
    for item in raw_private:
        if not isinstance(item, Mapping):
            continue
        association = _as_mapping(_get(item, "Association", "association", default={}))
        public_ip = _get(association, "PublicIp", "publicIp")
        private_ip = _get(item, "PrivateIpAddress", "privateIpAddress")
        if public_ip and private_ip:
            result.add(
                (
                    _validate_private_ip(private_ip),
                    _validate_public_association(public_ip),
                    str(_get(association, "AllocationId", "allocationId"))
                    if _get(association, "AllocationId", "allocationId")
                    else None,
                    str(_get(association, "AssociationId", "associationId"))
                    if _get(association, "AssociationId", "associationId")
                    else None,
                )
            )

    top_association = _as_mapping(_get(value, "Association", "association", default={}))
    top_public = _get(top_association, "PublicIp", "publicIp")
    top_private = _get(value, "PrivateIpAddress", "privateIpAddress")
    if top_public and top_private:
        result.add(
            (
                _validate_private_ip(top_private),
                _validate_public_association(top_public),
                str(_get(top_association, "AllocationId", "allocationId"))
                if _get(top_association, "AllocationId", "allocationId")
                else None,
                str(_get(top_association, "AssociationId", "associationId"))
                if _get(top_association, "AssociationId", "associationId")
                else None,
            )
        )
    return tuple(sorted(result, key=lambda item: (item[0], item[1])))


def _lifecycle(
    value: Mapping[str, Any],
    *,
    instance_state: str | None,
) -> str:
    attachment = _as_mapping(_get(value, "Attachment", "attachment", default={}))
    lifecycle = {
        "eni": str(_get(value, "Status", "status", default="unknown")).lower(),
        "attachment": str(_get(attachment, "Status", "status", default="none")).lower(),
        "instance_id": str(_get(attachment, "InstanceId", "instanceId", default="")) or None,
        "instance": (instance_state or "unknown").lower(),
    }
    return json.dumps(lifecycle, separators=(",", ":"), sort_keys=True)


def _lifecycle_object(lifecycle: str) -> Mapping[str, object] | None:
    try:
        value = json.loads(lifecycle)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def lifecycle_is_active(lifecycle: str) -> bool:
    value = _lifecycle_object(lifecycle)
    if value is None:
        return False
    if value.get("eni") != "in-use":
        return False
    if value.get("attachment") in {"detached", "detaching"}:
        return False
    return value.get("instance") not in {"shutting-down", "stopped", "stopping", "terminated"}


def lifecycle_matches(expected: str, current: str) -> bool:
    expected_value = _lifecycle_object(expected)
    current_value = _lifecycle_object(current)
    if expected_value is None or current_value is None:
        return False
    if expected_value.get("eni") != current_value.get("eni"):
        return False
    if expected_value.get("attachment") != current_value.get("attachment"):
        return False
    if expected_value.get("instance_id") != current_value.get("instance_id"):
        return False
    expected_instance = expected_value.get("instance")
    return expected_instance == "unknown" or expected_instance == current_value.get("instance")


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    account_id: str
    region: str
    network_interface_id: str
    private_ip: str
    public_ip: str
    instance_id: str | None
    lifecycle: str
    security_group_ids: tuple[str, ...]
    policy_fingerprint: str
    attachment_id: str | None = None
    allocation_id: str | None = None
    association_id: str | None = None
    tags: tuple[tuple[str, str], ...] = ()
    candidate_ports: CandidatePorts = field(default_factory=CandidatePorts.full)
    source_event_name: str | None = None
    source_event_id: str | None = None
    source_request_id: str | None = None
    source_event_time: datetime | None = None

    def __post_init__(self) -> None:
        if not _ACCOUNT_RE.fullmatch(self.account_id):
            raise ValueError("invalid account identifier")
        if not _ENI_RE.fullmatch(self.network_interface_id):
            raise ValueError("invalid network-interface identifier")
        _validate_private_ip(self.private_ip)
        _validate_public_association(self.public_ip)
        if tuple(sorted(set(self.security_group_ids))) != self.security_group_ids:
            raise ValueError("security_group_ids must be sorted and unique")
        if tuple(sorted(self.tags)) != self.tags:
            raise ValueError("tags must be sorted")
        if not re.fullmatch(r"[0-9a-f]{64}", self.policy_fingerprint):
            raise ValueError("invalid policy fingerprint")

    @property
    def target_id(self) -> str:
        return (
            f"aws:{self.account_id}:{self.region}:eni:{self.network_interface_id}:"
            f"private-ip:{self.private_ip}"
        )

    @property
    def state_signature(self) -> str:
        value = (
            self.public_ip,
            self.lifecycle,
            self.security_group_ids,
            self.policy_fingerprint,
        )
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    @property
    def tags_dict(self) -> dict[str, str]:
        return dict(self.tags)

    def with_signal(
        self,
        *,
        event_name: str,
        event_id: str,
        request_id: str | None,
        event_time: datetime | None,
        candidate_ports: CandidatePorts,
    ) -> NormalizedTarget:
        return replace(
            self,
            source_event_name=event_name,
            source_event_id=event_id,
            source_request_id=request_id,
            source_event_time=event_time,
            candidate_ports=candidate_ports,
        )

    def preserving_known_lifecycle(self, previous: NormalizedTarget) -> NormalizedTarget:
        """Keep a known instance state when a snapshot cannot observe it."""

        try:
            current_lifecycle = json.loads(self.lifecycle)
            previous_lifecycle = json.loads(previous.lifecycle)
        except (TypeError, ValueError):
            return self
        if (
            current_lifecycle.get("instance") == "unknown"
            and previous_lifecycle.get("instance") != "unknown"
        ):
            current_lifecycle["instance"] = previous_lifecycle["instance"]
            return replace(
                self,
                lifecycle=json.dumps(
                    current_lifecycle,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        return self

    def to_state_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "network_interface_id": self.network_interface_id,
            "private_ip": self.private_ip,
            "public_ip": self.public_ip,
            "instance_id": self.instance_id,
            "lifecycle": self.lifecycle,
            "security_group_ids": list(self.security_group_ids),
            "policy_fingerprint": self.policy_fingerprint,
            "attachment_id": self.attachment_id,
            "allocation_id": self.allocation_id,
            "association_id": self.association_id,
            "tags": dict(self.tags),
        }

    @classmethod
    def from_state_dict(cls, value: Mapping[str, Any]) -> NormalizedTarget:
        tags = value.get("tags") or {}
        return cls(
            account_id=str(value["account_id"]),
            region=str(value["region"]),
            network_interface_id=str(value["network_interface_id"]),
            private_ip=str(value["private_ip"]),
            public_ip=str(value["public_ip"]),
            instance_id=str(value["instance_id"]) if value.get("instance_id") else None,
            lifecycle=str(value["lifecycle"]),
            security_group_ids=tuple(str(item) for item in value["security_group_ids"]),
            policy_fingerprint=str(value["policy_fingerprint"]),
            attachment_id=str(value["attachment_id"]) if value.get("attachment_id") else None,
            allocation_id=str(value["allocation_id"]) if value.get("allocation_id") else None,
            association_id=str(value["association_id"]) if value.get("association_id") else None,
            tags=tuple(sorted((str(key), str(item)) for key, item in tags.items())),
        )


def normalize_network_interface(
    value: Mapping[str, Any],
    *,
    account_id: str,
    region: str,
    security_groups: Mapping[str, Sequence[Mapping[str, Any]]],
    allowed_tag_keys: Sequence[str] = (),
    instance_state: str | None = None,
) -> tuple[NormalizedTarget, ...]:
    configuration = _as_mapping(_get(value, "configuration", "Configuration", default=value))
    eni_id = str(
        _get(
            configuration,
            "NetworkInterfaceId",
            "networkInterfaceId",
            default=_get(value, "resourceId", "ResourceId", default=""),
        )
    )
    if not _ENI_RE.fullmatch(eni_id):
        raise ValueError("invalid network-interface identifier")
    groups = _group_ids(configuration)
    fingerprint = policy_fingerprint(security_groups, groups)
    attachment = _as_mapping(_get(configuration, "Attachment", "attachment", default={}))
    instance_id = _get(attachment, "InstanceId", "instanceId")
    attachment_id = _get(attachment, "AttachmentId", "attachmentId")
    lifecycle = _lifecycle(configuration, instance_state=instance_state)
    tags = _tags(configuration, frozenset(allowed_tag_keys))
    return tuple(
        NormalizedTarget(
            account_id=account_id,
            region=region,
            network_interface_id=eni_id,
            private_ip=private_ip,
            public_ip=public_ip,
            instance_id=str(instance_id) if instance_id else None,
            lifecycle=lifecycle,
            security_group_ids=groups,
            policy_fingerprint=fingerprint,
            attachment_id=str(attachment_id) if attachment_id else None,
            allocation_id=allocation_id,
            association_id=association_id,
            tags=tags,
        )
        for private_ip, public_ip, allocation_id, association_id in _associations(configuration)
    )
