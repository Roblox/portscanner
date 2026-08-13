"""Validated environment configuration for the generator Lambda."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv4Network

SCANNER_API_GROUP = "scanning.portscanner.io"
SCANNER_API_VERSION = "v1alpha1"
SCANNER_PLURAL = "scanners"

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_GROUP_RE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)+$"
)
_TABLE_RE = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_CLUSTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
_ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,254}$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-\d+$")


class ConfigurationError(ValueError):
    """Raised when deployment configuration is absent or unsafe."""


def _aliased(
    environment: Mapping[str, str],
    *names: str,
    required: bool = True,
) -> str | None:
    configured = {
        name: environment[name].strip() for name in names if environment.get(name, "").strip()
    }
    values = set(configured.values())
    if len(values) > 1:
        raise ConfigurationError(f"conflicting values configured for {'/'.join(names)}")
    if values:
        return values.pop()
    if required:
        raise ConfigurationError(f"{names[0]} environment variable is required")
    return None


def _positive_int(
    environment: Mapping[str, str],
    name: str,
    default: int,
) -> int:
    raw = environment.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"{name} must be an integer") from error
    if value <= 0:
        raise ConfigurationError(f"{name} must be greater than zero")
    return value


def _cidrs(environment: Mapping[str, str], name: str) -> tuple[IPv4Network, ...]:
    networks: set[IPv4Network] = set()
    for raw in environment.get(name, "").split(","):
        value = raw.strip()
        if not value:
            continue
        try:
            network = IPv4Network(value, strict=True)
        except ValueError as error:
            raise ConfigurationError(f"{name} must contain canonical IPv4 networks") from error
        if str(network) != value:
            raise ConfigurationError(f"{name} must contain canonical IPv4 networks")
        networks.add(network)
    return tuple(sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)))


def _accounts(environment: Mapping[str, str]) -> tuple[str, ...]:
    values = {
        value.strip()
        for value in environment.get("AUTHORIZED_ACCOUNT_IDS", "").split(",")
        if value.strip()
    }
    if any(not _ACCOUNT_RE.fullmatch(value) for value in values):
        raise ConfigurationError("AUTHORIZED_ACCOUNT_IDS must contain 12-digit account IDs")
    return tuple(sorted(values))


@dataclass(frozen=True)
class GeneratorConfig:
    """Complete, validated deployment configuration."""

    event_bucket: str
    event_prefix: str
    table_name: str
    cluster_name: str
    namespace: str
    aws_region: str
    api_group: str = SCANNER_API_GROUP
    api_version: str = SCANNER_API_VERSION
    plural: str = SCANNER_PLURAL
    inventory_table_name: str | None = None
    partition_key: str = "dispatch_id"
    claim_lease_seconds: int = 120
    audit_ttl_days: int = 30
    max_event_bytes: int = 65_536
    allowed_target_cidrs: tuple[IPv4Network, ...] = ()
    denied_target_cidrs: tuple[IPv4Network, ...] = ()
    authorized_account_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        bucket = self.event_bucket.strip()
        if (
            not _BUCKET_RE.fullmatch(bucket)
            or ".." in bucket
            or ".-" in bucket
            or "-." in bucket
            or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", bucket)
        ):
            raise ConfigurationError("TARGET_EVENT_BUCKET is not a valid S3 bucket")
        object.__setattr__(self, "event_bucket", bucket)

        prefix = self.event_prefix.strip()
        if (
            not prefix
            or len(prefix.encode("utf-8")) > 1023
            or prefix.startswith("/")
            or ".." in prefix.split("/")
            or any(ord(character) < 32 for character in prefix)
        ):
            raise ConfigurationError("TARGET_EVENT_PREFIX must be a non-empty relative S3 prefix")
        object.__setattr__(self, "event_prefix", prefix.rstrip("/") + "/")

        if not _TABLE_RE.fullmatch(self.table_name):
            raise ConfigurationError("IDEMPOTENCY_TABLE is not a valid table name")
        if self.inventory_table_name is not None and not _TABLE_RE.fullmatch(
            self.inventory_table_name
        ):
            raise ConfigurationError("INVENTORY_TABLE is not a valid table name")
        if not _CLUSTER_RE.fullmatch(self.cluster_name):
            raise ConfigurationError("EKS_CLUSTER_NAME is not a valid cluster name")
        if len(self.namespace) > 63 or not _DNS_LABEL_RE.fullmatch(self.namespace):
            raise ConfigurationError("K8S_NAMESPACE is not a valid namespace")
        if len(self.api_group) > 253 or not _GROUP_RE.fullmatch(self.api_group):
            raise ConfigurationError("K8S_API_GROUP is not a valid API group")
        if self.api_group != SCANNER_API_GROUP:
            raise ConfigurationError(f"K8S_API_GROUP must be {SCANNER_API_GROUP}")
        if self.api_version != SCANNER_API_VERSION:
            raise ConfigurationError(f"K8S_API_VERSION must be {SCANNER_API_VERSION}")
        if self.plural != SCANNER_PLURAL:
            raise ConfigurationError(f"K8S_CRD_PLURAL must be {SCANNER_PLURAL}")
        if not _ATTRIBUTE_RE.fullmatch(self.partition_key):
            raise ConfigurationError("DYNAMODB_PARTITION_KEY is not a valid attribute name")
        if not _REGION_RE.fullmatch(self.aws_region):
            raise ConfigurationError("AWS_REGION is not a valid AWS region")
        if self.claim_lease_seconds <= 0:
            raise ConfigurationError("CLAIM_LEASE_SECONDS must be greater than zero")
        if self.audit_ttl_days <= 0:
            raise ConfigurationError("AUDIT_TTL_DAYS must be greater than zero")
        if not 1 <= self.max_event_bytes <= 65_536:
            raise ConfigurationError("MAX_EVENT_BYTES must be between 1 and 65536")
        for name, networks in (
            ("ALLOWED_TARGET_CIDRS", self.allowed_target_cidrs),
            ("DENIED_TARGET_CIDRS", self.denied_target_cidrs),
        ):
            if any(
                network.version != 4 or network != IPv4Network(str(network), strict=True)
                for network in networks
            ):
                raise ConfigurationError(f"{name} must contain canonical IPv4 networks")
        if any(not _ACCOUNT_RE.fullmatch(value) for value in self.authorized_account_ids):
            raise ConfigurationError("AUTHORIZED_ACCOUNT_IDS must contain 12-digit account IDs")

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

    def account_allowed(self, account_id: str) -> bool:
        return account_id in self.authorized_account_ids

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> GeneratorConfig:
        env = environment if environment is not None else os.environ
        return cls(
            event_bucket=_aliased(env, "TARGET_EVENT_BUCKET") or "",
            event_prefix=_aliased(env, "TARGET_EVENT_PREFIX") or "",
            table_name=_aliased(env, "IDEMPOTENCY_TABLE") or "",
            cluster_name=_aliased(env, "EKS_CLUSTER_NAME") or "",
            namespace=_aliased(env, "K8S_NAMESPACE") or "",
            aws_region=_aliased(
                env,
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
            )
            or "",
            api_group=_aliased(
                env,
                "K8S_API_GROUP",
                required=False,
            )
            or SCANNER_API_GROUP,
            api_version=env.get("K8S_API_VERSION", SCANNER_API_VERSION).strip(),
            plural=env.get("K8S_CRD_PLURAL", SCANNER_PLURAL).strip(),
            inventory_table_name=_aliased(
                env,
                "INVENTORY_TABLE",
                required=False,
            ),
            partition_key=env.get(
                "DYNAMODB_PARTITION_KEY",
                "dispatch_id",
            ).strip(),
            claim_lease_seconds=_positive_int(
                env,
                "CLAIM_LEASE_SECONDS",
                120,
            ),
            audit_ttl_days=_positive_int(env, "AUDIT_TTL_DAYS", 30),
            max_event_bytes=_positive_int(env, "MAX_EVENT_BYTES", 65_536),
            allowed_target_cidrs=_cidrs(env, "ALLOWED_TARGET_CIDRS"),
            denied_target_cidrs=_cidrs(env, "DENIED_TARGET_CIDRS"),
            authorized_account_ids=_accounts(env),
        )
