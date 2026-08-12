"""Validated environment configuration for Lambda entry points."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from portscanner_contracts import AWS_TAG_KEYS

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
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
    discovery_role_arn_template: str | None = None
    external_id: str | None = None
    allowed_tag_keys: tuple[str, ...] = ()
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
        if self.discovery_role_arn_template:
            if "{account_id}" not in self.discovery_role_arn_template:
                raise ValueError("role ARN template must include {account_id}")
            if not self.discovery_role_arn_template.startswith("arn:aws"):
                raise ValueError("invalid role ARN template")
        if any(not _TAG_RE.fullmatch(key) for key in self.allowed_tag_keys):
            raise ValueError("invalid tag allowlist entry")
        if not set(self.allowed_tag_keys).issubset(AWS_TAG_KEYS):
            raise ValueError("tag allowlist contains a field outside the shared AWS context")
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

    def validate_state(self) -> None:
        if not self.state_table:
            raise ValueError("state_table is required")

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
            discovery_role_arn_template=env.get("DISCOVERY_ROLE_ARN_TEMPLATE"),
            external_id=env.get("DISCOVERY_EXTERNAL_ID"),
            allowed_tag_keys=_csv(env.get("ALLOWED_TAG_KEYS")),
            signal_dedupe_seconds=_positive_int(env, "SIGNAL_DEDUPE_SECONDS", 86_400),
            outbox_ttl_seconds=_positive_int(env, "OUTBOX_TTL_SECONDS", 604_800),
            outbox_replay_batch_size=_positive_int(env, "OUTBOX_REPLAY_BATCH_SIZE", 100),
            rescan_bucket_seconds=_positive_int(env, "RESCAN_BUCKET_SECONDS", 21_600),
            max_signal_port_ranges=_positive_int(env, "MAX_SIGNAL_PORT_RANGES", 32),
            max_signal_ports=_positive_int(env, "MAX_SIGNAL_PORTS", 8_192),
        )
