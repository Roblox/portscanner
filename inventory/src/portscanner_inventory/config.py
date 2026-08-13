"""Validated environment configuration for Lambda entry points."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Any

from portscanner_contracts import AWS_TAG_KEYS

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_ENI_RE = re.compile(r"^eni-[0-9a-fA-F]+$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_.:/=+\-@]{1,128}$")


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(sorted({part.strip() for part in (value or "").split(",") if part.strip()}))


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _boolean(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    if raw.lower() not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return raw.lower() == "true"


def _cidrs(env: Mapping[str, str], name: str) -> tuple[IPv4Network, ...]:
    networks: set[IPv4Network] = set()
    for raw in env.get(name, "").split(","):
        value = raw.strip()
        if not value:
            continue
        try:
            network = IPv4Network(value, strict=True)
        except ValueError as error:
            raise ValueError(f"{name} must contain canonical IPv4 networks") from error
        if str(network) != value:
            raise ValueError(f"{name} must contain canonical IPv4 networks")
        networks.add(network)
    return tuple(sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)))


@dataclass(frozen=True, slots=True)
class ManagedCanary:
    account_id: str
    region: str
    network_interface_id: str
    private_ip: str
    public_ip: str
    tag_key: str
    tag_value: str
    tcp_port: int

    def __post_init__(self) -> None:
        if not _ACCOUNT_RE.fullmatch(self.account_id):
            raise ValueError("managed canary account must contain 12 digits")
        if not _REGION_RE.fullmatch(self.region):
            raise ValueError("managed canary region is invalid")
        if not _ENI_RE.fullmatch(self.network_interface_id):
            raise ValueError("managed canary ENI is invalid")
        try:
            private = IPv4Address(self.private_ip)
            public = IPv4Address(self.public_ip)
        except AddressValueError as error:
            raise ValueError("managed canary addresses must be canonical IPv4") from error
        if str(private) != self.private_ip or str(public) != self.public_ip or not public.is_global:
            raise ValueError("managed canary addresses must be canonical public/private IPv4")
        if not _TAG_RE.fullmatch(self.tag_key) or not self.tag_value.strip():
            raise ValueError("managed canary tag is invalid")
        if not 1 <= self.tcp_port <= 65535:
            raise ValueError("managed canary TCP port must be within 1..65535")

    def matches(self, target: Any) -> bool:
        return bool(
            target.account_id == self.account_id
            and target.region == self.region
            and target.network_interface_id == self.network_interface_id
            and target.private_ip == self.private_ip
            and target.public_ip == self.public_ip
            and target.tags_dict.get(self.tag_key) == self.tag_value
        )


def _managed_canary(env: Mapping[str, str]) -> ManagedCanary | None:
    names = (
        "MANAGED_CANARY_ACCOUNT_ID",
        "MANAGED_CANARY_REGION",
        "MANAGED_CANARY_ENI_ID",
        "MANAGED_CANARY_PRIVATE_IP",
        "MANAGED_CANARY_PUBLIC_IP",
        "MANAGED_CANARY_TAG_KEY",
        "MANAGED_CANARY_TAG_VALUE",
        "MANAGED_CANARY_TCP_PORT",
    )
    values = {name: env.get(name, "").strip() for name in names}
    configured = {name for name, value in values.items() if value}
    if not configured:
        return None
    if configured != set(names):
        raise ValueError("managed canary runtime configuration must be complete")
    try:
        port = int(values["MANAGED_CANARY_TCP_PORT"])
    except ValueError as error:
        raise ValueError("MANAGED_CANARY_TCP_PORT must be an integer") from error
    return ManagedCanary(
        account_id=values["MANAGED_CANARY_ACCOUNT_ID"],
        region=values["MANAGED_CANARY_REGION"],
        network_interface_id=values["MANAGED_CANARY_ENI_ID"],
        private_ip=values["MANAGED_CANARY_PRIVATE_IP"],
        public_ip=values["MANAGED_CANARY_PUBLIC_IP"],
        tag_key=values["MANAGED_CANARY_TAG_KEY"],
        tag_value=values["MANAGED_CANARY_TAG_VALUE"],
        tcp_port=port,
    )


@dataclass(frozen=True, slots=True)
class Settings:
    state_table: str
    event_bucket: str
    event_prefix: str = "target-events/aws"
    priority_queue_url: str = ""
    coverage_queue_url: str = ""
    target_event_queue_url: str = ""
    snapshot_backend: str = "config"
    config_aggregator_name: str | None = None
    account_id: str | None = None
    authorized_account_ids: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    canary_mode: bool = False
    managed_canary: ManagedCanary | None = None
    discovery_role_arn_template: str | None = None
    external_id: str | None = None
    allowed_tag_keys: tuple[str, ...] = ()
    allowed_target_cidrs: tuple[IPv4Network, ...] = ()
    denied_target_cidrs: tuple[IPv4Network, ...] = ()
    allowed_eni_interface_types: tuple[str, ...] = ()
    required_target_tag_key: str | None = None
    required_target_tag_value: str | None = None
    snapshot_max_pages: int = 1000
    signal_dedupe_seconds: int = 86_400
    outbox_ttl_seconds: int = 604_800
    outbox_replay_batch_size: int = 100
    rescan_bucket_seconds: int = 21_600
    max_signal_port_ranges: int = 32
    max_signal_ports: int = 8_192

    def __post_init__(self) -> None:
        if self.snapshot_backend not in {"config", "ec2"}:
            raise ValueError("snapshot_backend must be config or ec2")
        if self.account_id and not _ACCOUNT_RE.fullmatch(self.account_id):
            raise ValueError("account_id must contain 12 digits")
        if any(not _ACCOUNT_RE.fullmatch(value) for value in self.authorized_account_ids):
            raise ValueError("authorized_account_ids must contain 12-digit account IDs")
        if any(not _REGION_RE.fullmatch(value) for value in self.regions):
            raise ValueError("regions must contain valid AWS regions")
        if self.discovery_role_arn_template:
            if "{account_id}" not in self.discovery_role_arn_template:
                raise ValueError("role ARN template must include {account_id}")
            if not self.discovery_role_arn_template.startswith("arn:aws"):
                raise ValueError("invalid role ARN template")
        if any(not _TAG_RE.fullmatch(key) for key in self.allowed_tag_keys):
            raise ValueError("invalid tag allowlist entry")
        if not set(self.allowed_tag_keys).issubset(AWS_TAG_KEYS):
            raise ValueError("tag allowlist contains a field outside the shared AWS context")
        if any(
            not re.fullmatch(r"[a-z0-9-]+", value) for value in self.allowed_eni_interface_types
        ):
            raise ValueError("allowed ENI interface types are invalid")
        if (self.required_target_tag_key is None) != (self.required_target_tag_value is None):
            raise ValueError("required target tag key and value must be configured together")
        if self.required_target_tag_key is not None and (
            not _TAG_RE.fullmatch(self.required_target_tag_key)
            or not self.required_target_tag_value
            or not self.required_target_tag_value.strip()
        ):
            raise ValueError("required target tag is invalid")
        if not 1 <= self.snapshot_max_pages <= 10_000:
            raise ValueError("snapshot_max_pages must be between 1 and 10000")
        if not 86_400 <= self.outbox_ttl_seconds <= 31_536_000:
            raise ValueError("outbox_ttl_seconds must be between one day and one year")
        if not 1 <= self.outbox_replay_batch_size <= 1000:
            raise ValueError("outbox_replay_batch_size must be between 1 and 1000")
        prefix = self.event_prefix.strip("/")
        if not prefix or ".." in prefix.split("/"):
            raise ValueError("invalid event prefix")
        object.__setattr__(self, "event_prefix", prefix)

    def validate_snapshot(self) -> None:
        self.validate_state()
        if self.snapshot_backend == "config" and not self.config_aggregator_name:
            raise ValueError("config_aggregator_name is required for Config snapshots")
        if self.snapshot_backend == "ec2" and (not self.account_id or not self.regions):
            raise ValueError("account_id and regions are required for direct EC2 snapshots")
        if not self.authorized_account_ids:
            raise ValueError("authorized_account_ids is required for snapshots")
        if self.canary_mode and self.managed_canary is not None:
            if self.managed_canary.account_id not in self.authorized_account_ids:
                raise ValueError("managed canary account is outside authorized account scope")
            if self.managed_canary.region not in self.regions:
                raise ValueError("managed canary region is outside snapshot Region scope")
            if not self.target_allowed(self.managed_canary.public_ip):
                raise ValueError("managed canary address is outside configured CIDR scope")

    def validate_state(self) -> None:
        if not self.state_table:
            raise ValueError("state_table is required")

    def validate_signals(self) -> None:
        self.validate_state()
        if not self.authorized_account_ids:
            raise ValueError("authorized_account_ids is required for signals")

    def validate_outbox(self) -> None:
        self.validate_state()
        if not self.event_bucket:
            raise ValueError("event_bucket is required")
        required_queues = {
            "PRIORITY_QUEUE_URL": self.priority_queue_url,
            "COVERAGE_QUEUE_URL": self.coverage_queue_url,
            "TARGET_EVENT_QUEUE_URL": self.target_event_queue_url,
        }
        missing = [name for name, value in required_queues.items() if not value.strip()]
        if missing:
            raise ValueError(f"{', '.join(missing)} required for outbox")

    def account_authorized(self, account_id: str) -> bool:
        return account_id in self.authorized_account_ids

    def target_allowed(self, address: str) -> bool:
        try:
            parsed = IPv4Address(address)
        except AddressValueError:
            return False
        if any(parsed in network for network in self.denied_target_cidrs):
            return False
        return not self.allowed_target_cidrs or any(
            parsed in network for network in self.allowed_target_cidrs
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        return cls(
            state_table=env.get("INVENTORY_TABLE", ""),
            event_bucket=env.get("TARGET_EVENT_BUCKET", ""),
            event_prefix=env.get("TARGET_EVENT_PREFIX", "target-events/aws"),
            priority_queue_url=env.get("PRIORITY_QUEUE_URL", ""),
            coverage_queue_url=env.get("COVERAGE_QUEUE_URL", ""),
            target_event_queue_url=env.get("TARGET_EVENT_QUEUE_URL", ""),
            snapshot_backend=env.get("SNAPSHOT_BACKEND", "config").lower(),
            config_aggregator_name=env.get("CONFIG_AGGREGATOR_NAME"),
            account_id=env.get("AWS_ACCOUNT_ID"),
            authorized_account_ids=_csv(env.get("AUTHORIZED_ACCOUNT_IDS")),
            regions=_csv(env.get("AWS_REGIONS")),
            canary_mode=_boolean(env, "CANARY_MODE"),
            managed_canary=_managed_canary(env),
            discovery_role_arn_template=env.get("DISCOVERY_ROLE_ARN_TEMPLATE"),
            external_id=env.get("DISCOVERY_EXTERNAL_ID"),
            allowed_tag_keys=_csv(env.get("ALLOWED_TAG_KEYS")),
            allowed_target_cidrs=_cidrs(env, "ALLOWED_TARGET_CIDRS"),
            denied_target_cidrs=_cidrs(env, "DENIED_TARGET_CIDRS"),
            allowed_eni_interface_types=_csv(env.get("ALLOWED_ENI_INTERFACE_TYPES")),
            required_target_tag_key=env.get("REQUIRED_TARGET_TAG_KEY") or None,
            required_target_tag_value=env.get("REQUIRED_TARGET_TAG_VALUE") or None,
            snapshot_max_pages=_positive_int(env, "SNAPSHOT_MAX_PAGES", 1000),
            signal_dedupe_seconds=_positive_int(env, "SIGNAL_DEDUPE_SECONDS", 86_400),
            outbox_ttl_seconds=_positive_int(env, "OUTBOX_TTL_SECONDS", 604_800),
            outbox_replay_batch_size=_positive_int(env, "OUTBOX_REPLAY_BATCH_SIZE", 100),
            rescan_bucket_seconds=_positive_int(env, "RESCAN_BUCKET_SECONDS", 21_600),
            max_signal_port_ranges=_positive_int(env, "MAX_SIGNAL_PORT_RANGES", 32),
            max_signal_ports=_positive_int(env, "MAX_SIGNAL_PORTS", 8_192),
        )
