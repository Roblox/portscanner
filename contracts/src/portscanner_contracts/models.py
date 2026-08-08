# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

"""Immutable, provider-aware contracts shared by Portscanner components."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    TypeAdapter,
    ValidationInfo,
    WithJsonSchema,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = "1.0"
MAX_CONTRACT_JSON_BYTES = 64 * 1024
MAX_AWS_SECURITY_GROUPS = 64
MAX_AWS_PORT_RANGES = 256
MAX_AWS_TAG_VALUE_LENGTH = 256
MAX_TCP_PORT = 65535
ASCII_CONTROL_LIMIT = 32
AWS_TAG_KEYS = frozenset({"application", "environment", "name", "service"})

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_AWS_ACCOUNT_PATTERN = r"^[0-9]{12}$"
_AWS_REGION_PATTERN = r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$"
_ENI_PATTERN = r"^eni-[0-9a-f]{8,32}$"
_INSTANCE_PATTERN = r"^i-[0-9a-f]{8,32}$"
_SECURITY_GROUP_PATTERN = r"^sg-[0-9a-f]{8,32}$"
_SOURCE_NAME_PATTERN = r"^[A-Za-z0-9_.:/-]+$"
_SAFE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$"
_RULE_KEY_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_IMAGE_VERSION_PATTERN = r"^(?:(?:[^@\s]+@)?sha256:[0-9a-f]{64}|git:[0-9a-f]{40,64})$"
_COVERAGE_TERM_PATTERN = re.compile(r"^(?P<start>[0-9]{1,5})(?:-(?P<end>[0-9]{1,5}))?$")
_UTC_RFC3339_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_UTC_RFC3339_RE = re.compile(_UTC_RFC3339_PATTERN)
_DOCUMENTATION_IPV4_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)


class CloudProvider(StrEnum):
    """Cloud provider represented by a target."""

    AWS = "aws"


class AddressFamily(StrEnum):
    """Network address family."""

    IPV4 = "ipv4"


class TransportProtocol(StrEnum):
    """Transport protocol scanned by the current runtime."""

    TCP = "tcp"


class ScanReason(StrEnum):
    """Reason a scan entered the work queue."""

    NEW_TARGET = "new_target"
    TARGET_CHANGE = "target_change"
    POLICY_CHANGE = "policy_change"
    COVERAGE = "coverage"
    MANUAL = "manual"


class ScanProfile(StrEnum):
    """Scanner behavior requested by a directive."""

    FAST_FULL_TCP = "fast-full-tcp"
    TARGETED_TCP = "targeted-tcp"
    DEEP = "deep"


class ScanOutcome(StrEnum):
    """Terminal outcome for a scan attempt."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    FRESHNESS_REJECTED = "freshness_rejected"


class TargetEventType(StrEnum):
    """Kind of target event emitted by inventory or orchestration."""

    TARGET_UPSERT = "target.upsert"
    TARGET_REMOVED = "target.removed"
    POLICY_CHANGED = "policy.changed"
    RESCAN_REQUESTED = "rescan.requested"


class ScannerEngine(StrEnum):
    """Scanner engine that produced a result."""

    NMAP = "nmap"


class FindingKind(StrEnum):
    """Published finding document kind."""

    FINDING_EVENT = "finding_event"
    CURRENT_FINDING = "current_finding"


class FindingStatus(StrEnum):
    """Current lifecycle state of a finding."""

    OPEN = "open"
    RESOLVED = "resolved"


FindingState = FindingStatus


class FindingSeverity(StrEnum):
    """Detection-rule severity copied into a finding."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingEventType(StrEnum):
    """State transition represented by a finding event."""

    OPENED = "opened"
    REOPENED = "reopened"
    UPDATED = "updated"
    RESOLVED = "resolved"


class FindingResolutionReason(StrEnum):
    """Known reasons that a finding is no longer open."""

    OWNERSHIP_REMOVED = "ownership_removed"
    EXPOSURE_CLOSED = "exposure_closed"
    RULE_DISABLED = "rule_disabled"
    RULE_NO_LONGER_MATCHES = "rule_no_longer_matches"


class FindingReason(StrEnum):
    """Known reasons for publishing a finding transition."""

    EXPOSURE_OPEN = "exposure_open"
    EXPOSURE_REOPENED = "exposure_reopened"
    RECONCILIATION_REPAIR = "reconciliation_repair"
    SERVICE_CHANGED = "service_changed"
    ADDRESS_CHANGED = "address_changed"
    RULE_CHANGED = "rule_changed"
    OWNERSHIP_REMOVED = "ownership_removed"
    EXPOSURE_CLOSED = "exposure_closed"
    RULE_DISABLED = "rule_disabled"
    RULE_NO_LONGER_MATCHES = "rule_no_longer_matches"


class FindingSourceKind(StrEnum):
    """Repository source that caused a finding transition."""

    SCAN_ATTEMPT = "scan_attempt"
    TARGET_EVENT = "target_event"
    RECONCILIATION = "reconciliation"


def _validate_ipv4(value: str) -> str:
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("must be a valid IPv4 address") from error
    if str(parsed) != value:
        raise ValueError("must use canonical IPv4 notation")
    return value


def _validate_public_ipv4(value: str) -> str:
    address = ipaddress.IPv4Address(_validate_ipv4(value))
    if not address.is_global and not any(
        address in network for network in _DOCUMENTATION_IPV4_NETWORKS
    ):
        raise ValueError("must be a public IPv4 or RFC 5737 documentation address")
    return value


def _validate_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("must be an RFC3339 timestamp in UTC")
    return value.astimezone(UTC)


def _validate_utc_input(value: Any) -> Any:
    if isinstance(value, str) and _UTC_RFC3339_RE.fullmatch(value) is None:
        raise ValueError("must use UTC RFC3339 notation with a Z suffix")
    return value


def format_utc_rfc3339(value: datetime) -> str:
    """Serialize an aware UTC datetime using the RFC3339 ``Z`` suffix."""

    return _validate_utc(value).isoformat().replace("+00:00", "Z")


IPv4Address = Annotated[
    str,
    StringConstraints(strict=True, min_length=7, max_length=15),
    AfterValidator(_validate_ipv4),
    WithJsonSchema(
        {
            "type": "string",
            "format": "ipv4",
            "minLength": 7,
            "maxLength": 15,
        }
    ),
]
PublicIPv4Address = Annotated[
    str,
    StringConstraints(strict=True, min_length=7, max_length=15),
    AfterValidator(_validate_public_ipv4),
    WithJsonSchema(
        {
            "type": "string",
            "format": "ipv4",
            "minLength": 7,
            "maxLength": 15,
            "description": "Public IPv4; RFC 5737 ranges are accepted for examples.",
        }
    ),
]
UtcDateTime = Annotated[
    datetime,
    BeforeValidator(_validate_utc_input),
    AfterValidator(_validate_utc),
    PlainSerializer(format_utc_rfc3339, return_type=str, when_used="json"),
    WithJsonSchema(
        {
            "type": "string",
            "format": "date-time",
            "pattern": _UTC_RFC3339_PATTERN,
        }
    ),
]
Sha256Id = Annotated[
    str,
    StringConstraints(strict=True, pattern=_SHA256_PATTERN),
]
AwsAccountId = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_ACCOUNT_PATTERN),
]
AwsRegion = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=9,
        max_length=32,
        pattern=_AWS_REGION_PATTERN,
    ),
]
NetworkInterfaceId = Annotated[
    str,
    StringConstraints(strict=True, pattern=_ENI_PATTERN),
]
InstanceId = Annotated[
    str,
    StringConstraints(strict=True, pattern=_INSTANCE_PATTERN),
]
SecurityGroupId = Annotated[
    str,
    StringConstraints(strict=True, pattern=_SECURITY_GROUP_PATTERN),
]
SourceName = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_SOURCE_NAME_PATTERN,
    ),
]
BoundedText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=256),
]
LongBoundedText = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=4096),
]
SafeIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_SAFE_IDENTIFIER_PATTERN,
    ),
]
RuleKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_RULE_KEY_PATTERN,
    ),
]
ImmutableImageVersion = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=44,
        max_length=256,
        pattern=_IMAGE_VERSION_PATTERN,
    ),
]
TagValue = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=MAX_AWS_TAG_VALUE_LENGTH,
    ),
]
PortNumber = Annotated[int, Field(strict=True, ge=1, le=65535)]
Generation = Annotated[int, Field(strict=True, ge=1)]
Priority = Annotated[int, Field(strict=True, ge=0, le=1000)]
ExitCode = Annotated[int, Field(strict=True, ge=0, le=255)]
FindingVersion = Annotated[int, Field(strict=True, ge=1)]

_SHA256_ID_ADAPTER: TypeAdapter[str] = TypeAdapter(Sha256Id)
_SAFE_IDENTIFIER_ADAPTER: TypeAdapter[str] = TypeAdapter(SafeIdentifier)
_IMAGE_VERSION_ADAPTER: TypeAdapter[str] = TypeAdapter(ImmutableImageVersion)


def validate_sha256_id(value: Any) -> str:
    """Validate a lowercase SHA-256 identifier."""

    return _SHA256_ID_ADAPTER.validate_python(value)


def validate_safe_identifier(value: Any) -> str:
    """Validate a bounded correlation identifier."""

    return _SAFE_IDENTIFIER_ADAPTER.validate_python(value)


def validate_image_version(value: Any) -> str:
    """Validate an immutable OCI digest or Git revision."""

    return _IMAGE_VERSION_ADAPTER.validate_python(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=False)
    if isinstance(value, datetime):
        return format_utc_rfc3339(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used by contract identifiers."""

    return json.dumps(
        _jsonable(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def deterministic_sha256(namespace: str, payload: Any) -> str:
    """Hash a namespaced canonical JSON payload as lowercase SHA-256."""

    if not namespace or namespace.strip() != namespace:
        raise ValueError("namespace must be a non-empty, trimmed string")
    material = f"{namespace}\0{canonical_json(payload)}".encode()
    return hashlib.sha256(material).hexdigest()


class ContractModel(BaseModel):
    """Base for closed, frozen contracts with bounded JSON parsing."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=False,
        validate_default=True,
    )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible data with no provider aliases hidden."""

        return self.model_dump(mode="json", by_alias=True, exclude_none=False)

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the contract to JSON."""

        return self.model_dump_json(by_alias=True, exclude_none=False, indent=indent)

    @classmethod
    def from_json(cls, value: str | bytes | bytearray) -> Self:
        """Validate and parse one bounded JSON contract document."""

        encoded = value.encode() if isinstance(value, str) else bytes(value)
        if len(encoded) > MAX_CONTRACT_JSON_BYTES:
            raise ValueError(f"contract JSON exceeds {MAX_CONTRACT_JSON_BYTES} bytes")
        return cls.model_validate_json(encoded)


class DeterministicModel(ContractModel):
    """Base for contracts whose primary IDs are canonical SHA-256 hashes."""

    _id_field: ClassVar[str]
    _id_namespace: ClassVar[str]

    def _identity_payload(self) -> Mapping[str, Any]:
        raise NotImplementedError

    def expected_id(self) -> str:
        """Return the identifier implied by this model's identity fields."""

        return deterministic_sha256(self._id_namespace, self._identity_payload())

    @model_validator(mode="after")
    def _validate_deterministic_id(self, info: ValidationInfo) -> Self:
        if info.context and info.context.get("skip_deterministic_id"):
            return self
        actual = getattr(self, self._id_field)
        expected = self.expected_id()
        if actual != expected:
            raise ValueError(f"{self._id_field} must equal deterministic SHA-256 {expected}")
        return self

    @classmethod
    def create(cls, **values: Any) -> Self:
        """Validate values and fill the model's deterministic identifier."""

        provisional_values = dict(values)
        provisional_values[cls._id_field] = "0" * 64
        provisional = cls.model_validate(
            provisional_values,
            context={"skip_deterministic_id": True},
        )
        complete_values = provisional.model_dump(mode="python")
        complete_values[cls._id_field] = provisional.expected_id()
        return cls.model_validate(complete_values)


class TcpPortRange(ContractModel):
    """Inclusive TCP port range."""

    start: PortNumber
    end: PortNumber

    @model_validator(mode="after")
    def _validate_order(self) -> Self:
        if self.start > self.end:
            raise ValueError("port range start must not exceed end")
        return self


FULL_TCP_PORT_RANGE = TcpPortRange(start=1, end=65535)


def _validate_port_ranges(
    ranges: tuple[TcpPortRange, ...],
    *,
    allow_empty: bool,
) -> tuple[TcpPortRange, ...]:
    if not allow_empty and not ranges:
        raise ValueError("at least one TCP port range is required")
    previous: TcpPortRange | None = None
    for current in ranges:
        if previous is not None:
            if (current.start, current.end) <= (previous.start, previous.end):
                raise ValueError("TCP port ranges must be sorted")
            if current.start <= previous.end + 1:
                raise ValueError("TCP port ranges must not overlap or be adjacent")
        previous = current
    return ranges


class AwsTags(ContractModel):
    """Closed set of low-risk AWS tags permitted in shared events."""

    application: TagValue | None = None
    environment: TagValue | None = None
    name: TagValue | None = None
    service: TagValue | None = None

    @field_validator("application", "environment", "name", "service")
    @classmethod
    def _reject_blank_tag(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("tag values must not be blank")
        return value


class AwsContext(ContractModel):
    """Closed, bounded AWS evidence needed to explain a scan decision."""

    account_id: AwsAccountId
    region: AwsRegion
    network_interface_id: NetworkInterfaceId
    private_ip: IPv4Address
    public_ip: PublicIPv4Address
    instance_id: InstanceId | None = None
    security_group_ids: Annotated[
        tuple[SecurityGroupId, ...],
        Field(
            max_length=MAX_AWS_SECURITY_GROUPS,
            json_schema_extra={"uniqueItems": True},
        ),
    ]
    policy_fingerprint: Sha256Id
    candidate_tcp_port_ranges: Annotated[
        tuple[TcpPortRange, ...],
        Field(
            max_length=MAX_AWS_PORT_RANGES,
            json_schema_extra={"uniqueItems": True},
        ),
    ]
    source_event_name: SourceName
    source_event_id: BoundedText
    source_request_id: BoundedText
    tags: AwsTags

    @field_validator("security_group_ids")
    @classmethod
    def _validate_security_groups(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("security_group_ids must be sorted and unique")
        return value

    @field_validator("candidate_tcp_port_ranges")
    @classmethod
    def _validate_candidate_ranges(
        cls,
        value: tuple[TcpPortRange, ...],
    ) -> tuple[TcpPortRange, ...]:
        return _validate_port_ranges(value, allow_empty=True)

    @field_validator("source_event_id", "source_request_id")
    @classmethod
    def _reject_blank_source_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source identifiers must not be blank")
        return value


class Target(DeterministicModel):
    """Stable resource/private-address identity plus mutable public state."""

    _id_field = "target_id"
    _id_namespace = "portscanner.target.v1"

    target_id: Sha256Id
    provider: CloudProvider
    scope_id: AwsAccountId
    location: AwsRegion
    resource_id: NetworkInterfaceId
    private_address: IPv4Address
    public_address: PublicIPv4Address
    address_family: AddressFamily
    transport: TransportProtocol
    generation: Generation

    @property
    def address(self) -> str:
        """Compatibility alias for the current public scan address."""

        return self.public_address

    def _identity_payload(self) -> Mapping[str, Any]:
        return {
            "provider": self.provider,
            "scope_id": self.scope_id,
            "location": self.location,
            "resource_id": self.resource_id,
            "private_address": self.private_address,
            "address_family": self.address_family,
        }


class SourceObservation(DeterministicModel):
    """Timestamps and source identifiers for one inventory observation."""

    _id_field = "observation_id"
    _id_namespace = "portscanner.source-observation.v1"

    observation_id: Sha256Id
    source_event_name: SourceName
    source_event_id: BoundedText
    source_request_id: BoundedText
    event_time: UtcDateTime
    observed_at: UtcDateTime
    collected_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_timeline(self) -> Self:
        if self.event_time > self.observed_at:
            raise ValueError("event_time must not be later than observed_at")
        if self.observed_at > self.collected_at:
            raise ValueError("observed_at must not be later than collected_at")
        return self

    @field_validator("source_event_id", "source_request_id")
    @classmethod
    def _reject_blank_source_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source identifiers must not be blank")
        return value

    def _identity_payload(self) -> Mapping[str, Any]:
        return {
            "source_event_name": self.source_event_name,
            "source_event_id": self.source_event_id,
            "source_request_id": self.source_request_id,
            "event_time": self.event_time,
            "observed_at": self.observed_at,
            "collected_at": self.collected_at,
        }


class PolicyChange(DeterministicModel):
    """Relevant policy transition for one stable target identity."""

    _id_field = "policy_change_id"
    _id_namespace = "portscanner.policy-change.v1"

    policy_change_id: Sha256Id
    target_id: Sha256Id
    previous_fingerprint: Sha256Id | None = None
    current_fingerprint: Sha256Id
    changed_at: UtcDateTime
    candidate_tcp_port_ranges: Annotated[
        tuple[TcpPortRange, ...],
        Field(
            max_length=MAX_AWS_PORT_RANGES,
            json_schema_extra={"uniqueItems": True},
        ),
    ]

    @field_validator("candidate_tcp_port_ranges")
    @classmethod
    def _validate_candidate_ranges(
        cls,
        value: tuple[TcpPortRange, ...],
    ) -> tuple[TcpPortRange, ...]:
        return _validate_port_ranges(value, allow_empty=True)

    @model_validator(mode="after")
    def _validate_fingerprint_change(self) -> Self:
        if self.previous_fingerprint == self.current_fingerprint:
            raise ValueError("policy fingerprints must differ")
        return self

    def _identity_payload(self) -> Mapping[str, Any]:
        return {
            "target_id": self.target_id,
            "previous_fingerprint": self.previous_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "changed_at": self.changed_at,
            "candidate_tcp_port_ranges": self.candidate_tcp_port_ranges,
        }


class ScanDirective(DeterministicModel):
    """Bounded request to scan a specific target generation."""

    _id_field = "directive_id"
    _id_namespace = "portscanner.scan-directive.v1"

    directive_id: Sha256Id
    target_id: Sha256Id
    target_generation: Generation
    reason: ScanReason
    profile: ScanProfile
    priority: Priority
    requested_at: UtcDateTime
    deadline_at: UtcDateTime
    not_after: UtcDateTime
    tcp_port_ranges: Annotated[
        tuple[TcpPortRange, ...],
        Field(
            min_length=1,
            max_length=MAX_AWS_PORT_RANGES,
            json_schema_extra={"uniqueItems": True},
        ),
    ]

    @field_validator("tcp_port_ranges")
    @classmethod
    def _validate_scan_ranges(
        cls,
        value: tuple[TcpPortRange, ...],
    ) -> tuple[TcpPortRange, ...]:
        return _validate_port_ranges(value, allow_empty=False)

    @model_validator(mode="after")
    def _validate_directive(self) -> Self:
        if not self.requested_at <= self.deadline_at <= self.not_after:
            raise ValueError("requested_at, deadline_at, and not_after must be ordered")
        if self.profile in {
            ScanProfile.FAST_FULL_TCP,
            ScanProfile.DEEP,
        } and self.tcp_port_ranges != (FULL_TCP_PORT_RANGE,):
            raise ValueError(f"{self.profile.value} requires the complete TCP port range")
        return self

    def _identity_payload(self) -> Mapping[str, Any]:
        return {
            "target_id": self.target_id,
            "target_generation": self.target_generation,
            "reason": self.reason,
            "profile": self.profile,
            "priority": self.priority,
            "requested_at": self.requested_at,
            "deadline_at": self.deadline_at,
            "not_after": self.not_after,
            "tcp_port_ranges": self.tcp_port_ranges,
        }


TargetWorkEventType = Literal[
    TargetEventType.TARGET_UPSERT,
    TargetEventType.POLICY_CHANGED,
    TargetEventType.RESCAN_REQUESTED,
]


def _validate_aws_event_context(
    target: Target,
    source: SourceObservation,
    context: AwsContext,
) -> None:
    if target.provider is not CloudProvider.AWS:
        raise ValueError("the current runtime supports AWS targets only")
    if (
        target.scope_id != context.account_id
        or target.location != context.region
        or target.resource_id != context.network_interface_id
        or target.private_address != context.private_ip
        or target.public_address != context.public_ip
    ):
        raise ValueError("target identity and addresses must match aws_context")
    if (
        source.source_event_name != context.source_event_name
        or source.source_event_id != context.source_event_id
        or source.source_request_id != context.source_request_id
    ):
        raise ValueError("source observation must match aws_context source identifiers")


class TargetEvent(DeterministicModel):
    """Inventory event and its complete, bounded scan decision context."""

    _id_field = "event_id"
    _id_namespace = "portscanner.target-event.v1"

    schema_version: Literal["1.0"]
    event_id: Sha256Id
    event_type: TargetWorkEventType
    target: Target
    source: SourceObservation
    policy_change: PolicyChange | None = None
    scan: ScanDirective
    aws_context: AwsContext

    @property
    def trace_id(self) -> str:
        """Use the deterministic event ID as the root correlation ID."""

        return self.event_id

    @property
    def provider(self) -> CloudProvider:
        """Expose the target provider for dispatch adapters."""

        return self.target.provider

    @model_validator(mode="after")
    def _validate_consistency(self) -> Self:
        target = self.target
        context = self.aws_context
        _validate_aws_event_context(target, self.source, context)
        if (
            self.scan.target_id != target.target_id
            or self.scan.target_generation != target.generation
        ):
            raise ValueError("scan directive must reference this target generation")

        expected_type = {
            ScanReason.NEW_TARGET: TargetEventType.TARGET_UPSERT,
            ScanReason.TARGET_CHANGE: TargetEventType.TARGET_UPSERT,
            ScanReason.POLICY_CHANGE: TargetEventType.POLICY_CHANGED,
            ScanReason.COVERAGE: TargetEventType.RESCAN_REQUESTED,
            ScanReason.MANUAL: TargetEventType.RESCAN_REQUESTED,
        }[self.scan.reason]
        if self.event_type is not expected_type:
            raise ValueError("event_type must match the scan reason")

        if (
            self.scan.reason is ScanReason.TARGET_CHANGE
            and self.scan.profile is not ScanProfile.FAST_FULL_TCP
        ):
            raise ValueError("target_change scans require the fast-full-tcp profile")
        if self.scan.reason is ScanReason.TARGET_CHANGE and context.candidate_tcp_port_ranges != (
            FULL_TCP_PORT_RANGE,
        ):
            raise ValueError("target_change scans require full TCP coverage")

        if self.scan.reason is ScanReason.POLICY_CHANGE:
            if self.policy_change is None:
                raise ValueError("policy_change is required for policy_change scans")
            if (
                self.policy_change.target_id != target.target_id
                or self.policy_change.current_fingerprint != context.policy_fingerprint
                or self.policy_change.candidate_tcp_port_ranges != context.candidate_tcp_port_ranges
            ):
                raise ValueError("policy_change must match target and aws_context")
        elif self.policy_change is not None:
            raise ValueError("policy_change is only valid for policy_change scans")

        if (
            self.scan.profile is ScanProfile.TARGETED_TCP
            and self.scan.tcp_port_ranges != context.candidate_tcp_port_ranges
        ):
            raise ValueError("targeted-tcp ranges must match AWS policy candidates")
        return self

    def _identity_payload(self) -> Mapping[str, Any]:
        dispatch_context = self.aws_context.to_dict()
        dispatch_context.pop("tags", None)
        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "target": self.target,
            "source": self.source,
            "policy_change": self.policy_change,
            "scan": self.scan,
            "aws_context": dispatch_context,
        }


class TargetRemoval(DeterministicModel):
    """Immutable target tombstone used for downstream cancellation and projection."""

    _id_field = "event_id"
    _id_namespace = "portscanner.target-removal.v1"

    schema_version: Literal["1.0"]
    event_id: Sha256Id
    event_type: Literal[TargetEventType.TARGET_REMOVED]
    target: Target
    source: SourceObservation
    aws_context: AwsContext
    removed_at: UtcDateTime

    @property
    def trace_id(self) -> str:
        """Use the deterministic event ID as the root correlation ID."""

        return self.event_id

    @model_validator(mode="after")
    def _validate_consistency(self) -> Self:
        _validate_aws_event_context(self.target, self.source, self.aws_context)
        if self.removed_at < self.source.collected_at:
            raise ValueError("removed_at must not be earlier than source.collected_at")
        return self

    def _identity_payload(self) -> Mapping[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "target": self.target,
            "source": self.source,
            "aws_context": self.aws_context,
            "removed_at": self.removed_at,
        }


type TargetEventPayload = Annotated[
    TargetEvent | TargetRemoval,
    Field(discriminator="event_type"),
]

_TARGET_EVENT_ADAPTER: TypeAdapter[TargetEvent | TargetRemoval] = TypeAdapter(TargetEventPayload)


def parse_target_event(
    value: TargetEvent | TargetRemoval | Mapping[str, Any] | str | bytes | bytearray,
) -> TargetEvent | TargetRemoval:
    """Parse one bounded work or removal event from a mapping or JSON document."""

    if isinstance(value, (TargetEvent, TargetRemoval)):
        return value
    if isinstance(value, Mapping):
        return _TARGET_EVENT_ADAPTER.validate_python(value)
    if not isinstance(value, (str, bytes, bytearray)):
        raise TypeError("target event must be a mapping or JSON document")
    encoded = value.encode() if isinstance(value, str) else bytes(value)
    if len(encoded) > MAX_CONTRACT_JSON_BYTES:
        raise ValueError(f"contract JSON exceeds {MAX_CONTRACT_JSON_BYTES} bytes")
    return _TARGET_EVENT_ADAPTER.validate_json(encoded)


class ScanResult(DeterministicModel):
    """Normalized evidence record nested inside a published ScanResultEnvelope."""

    _id_field = "result_id"
    _id_namespace = "portscanner.scan-result.v1"

    schema_version: Literal["1.0"]
    result_id: Sha256Id
    event_id: Sha256Id
    directive_id: Sha256Id
    target: Target
    profile: ScanProfile
    scanner: ScannerEngine
    scanner_version: BoundedText
    started_at: UtcDateTime
    completed_at: UtcDateTime
    outcome: ScanOutcome
    requested_tcp_port_ranges: Annotated[
        tuple[TcpPortRange, ...],
        Field(
            min_length=1,
            max_length=MAX_AWS_PORT_RANGES,
            json_schema_extra={"uniqueItems": True},
        ),
    ]
    scanned_tcp_port_ranges: Annotated[
        tuple[TcpPortRange, ...],
        Field(
            max_length=MAX_AWS_PORT_RANGES,
            json_schema_extra={"uniqueItems": True},
        ),
    ]
    open_tcp_ports: Annotated[
        tuple[PortNumber, ...],
        Field(max_length=65535, json_schema_extra={"uniqueItems": True}),
    ]
    exit_code: ExitCode | None
    raw_result_sha256: Sha256Id | None
    error_code: BoundedText | None
    error_message: BoundedText | None

    @field_validator("scanner_version", "error_code", "error_message")
    @classmethod
    def _reject_blank_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("text fields must not be blank")
        return value

    @field_validator("requested_tcp_port_ranges")
    @classmethod
    def _validate_requested_ranges(
        cls,
        value: tuple[TcpPortRange, ...],
    ) -> tuple[TcpPortRange, ...]:
        return _validate_port_ranges(value, allow_empty=False)

    @field_validator("scanned_tcp_port_ranges")
    @classmethod
    def _validate_scanned_ranges(
        cls,
        value: tuple[TcpPortRange, ...],
    ) -> tuple[TcpPortRange, ...]:
        return _validate_port_ranges(value, allow_empty=True)

    @field_validator("open_tcp_ports")
    @classmethod
    def _validate_open_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("open_tcp_ports must be sorted and unique")
        return value

    @model_validator(mode="after")
    def _validate_result(self) -> Self:
        if self.started_at > self.completed_at:
            raise ValueError("started_at must not be later than completed_at")
        if (self.error_code is None) != (self.error_message is None):
            raise ValueError("error_code and error_message must be supplied together")

        for port in self.open_tcp_ports:
            if not any(
                port_range.start <= port <= port_range.end
                for port_range in self.scanned_tcp_port_ranges
            ):
                raise ValueError("open_tcp_ports must be covered by scanned ranges")

        if self.outcome is ScanOutcome.COMPLETE:
            if self.scanned_tcp_port_ranges != self.requested_tcp_port_ranges:
                raise ValueError("complete results must cover every requested TCP port")
            if self.exit_code != 0:
                raise ValueError("complete results require exit_code 0")
            if self.error_code is not None:
                raise ValueError("complete results cannot contain an error")
        if self.outcome is ScanOutcome.FRESHNESS_REJECTED and (
            self.scanned_tcp_port_ranges
            or self.open_tcp_ports
            or self.raw_result_sha256 is not None
        ):
            raise ValueError("freshness-rejected work cannot contain scan observations")
        return self

    def _identity_payload(self) -> Mapping[str, Any]:
        return {
            "event_id": self.event_id,
            "directive_id": self.directive_id,
            "target_id": self.target.target_id,
            "target_generation": self.target.generation,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
            "raw_result_sha256": self.raw_result_sha256,
            "open_tcp_ports": self.open_tcp_ports,
        }


class ScanResultTarget(ContractModel):
    """Short target identity repeated on the scanner envelope."""

    target_id: Sha256Id
    address: PublicIPv4Address
    generation: Generation


class ScanCoverage(ContractModel):
    """Canonical TCP port coverage declared by the scanner."""

    protocol: Literal["tcp"]
    ports: Annotated[
        tuple[
            Annotated[
                str,
                StringConstraints(
                    strict=True,
                    min_length=1,
                    max_length=11,
                    pattern=r"^[0-9]{1,5}(?:-[0-9]{1,5})?$",
                ),
            ],
            ...,
        ],
        Field(min_length=1, max_length=MAX_AWS_PORT_RANGES),
    ]
    complete: Annotated[bool, Field(strict=True)]

    @field_validator("ports")
    @classmethod
    def _validate_canonical_ports(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        previous_end = 0
        for term in value:
            match = _COVERAGE_TERM_PATTERN.fullmatch(term)
            if match is None:
                raise ValueError("coverage ports must be TCP ports or ranges")
            start = int(match.group("start"))
            end = int(match.group("end") or start)
            if not 1 <= start <= end <= MAX_TCP_PORT:
                raise ValueError(f"coverage ports must be between 1 and {MAX_TCP_PORT}")
            canonical = str(start) if start == end else f"{start}-{end}"
            if term != canonical or start <= previous_end + (1 if previous_end else 0):
                raise ValueError("coverage ports must be sorted and normalized")
            previous_end = end
        return value

    def as_ranges(self) -> tuple[tuple[int, int], ...]:
        """Return the declared coverage as inclusive numeric ranges."""

        ranges: list[tuple[int, int]] = []
        for term in self.ports:
            match = _COVERAGE_TERM_PATTERN.fullmatch(term)
            if match is None:  # pragma: no cover - guarded by field validation
                raise AssertionError("validated coverage term did not parse")
            start = int(match.group("start"))
            ranges.append((start, int(match.group("end") or start)))
        return tuple(ranges)


class ScanTimestamps(ContractModel):
    """Ordered scanner execution and publication timestamps."""

    scan_started_at: UtcDateTime
    scan_completed_at: UtcDateTime
    result_uploaded_at: UtcDateTime

    @model_validator(mode="after")
    def _validate_timeline(self) -> Self:
        if not (self.scan_started_at <= self.scan_completed_at <= self.result_uploaded_at):
            raise ValueError("scan result timestamps must be ordered")
        return self


class ScanCommand(ContractModel):
    """Bounded, redacted metadata for one Nmap invocation."""

    argv: Annotated[
        tuple[
            Annotated[
                str,
                StringConstraints(strict=True, min_length=1, max_length=2048),
            ],
            ...,
        ],
        Field(min_length=1, max_length=256),
    ]
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=86400)]
    exit_code: ExitCode | None


class ScanCommands(ContractModel):
    """Discovery and optional enrichment command metadata."""

    discovery: ScanCommand
    enrichment: ScanCommand | None


class RawArtifactReference(ContractModel):
    """Immutable S3 reference and digest for one raw scanner artifact."""

    bucket: Annotated[
        str,
        StringConstraints(strict=True, min_length=3, max_length=255),
    ]
    key: Annotated[
        str,
        StringConstraints(strict=True, min_length=1, max_length=1024),
    ]
    sha256: Sha256Id

    @field_validator("bucket")
    @classmethod
    def _validate_bucket(cls, value: str) -> str:
        if any(character.isspace() or ord(character) < ASCII_CONTROL_LIMIT for character in value):
            raise ValueError("S3 bucket must not contain whitespace or control characters")
        return value

    @field_validator("key")
    @classmethod
    def _validate_key(cls, value: str) -> str:
        if any(ord(character) < ASCII_CONTROL_LIMIT for character in value):
            raise ValueError("S3 object key must not contain control characters")
        return value


class NmapRawResult(RawArtifactReference):
    """Raw Nmap discovery XML plus optional enrichment XML."""

    format: Literal["nmap-xml"]
    enrichment: RawArtifactReference | None


class ScanError(ContractModel):
    """Bounded scanner failure safe to publish with an envelope."""

    type: SafeIdentifier
    message: BoundedText
    retryable: Annotated[bool, Field(strict=True)]

    @field_validator("message")
    @classmethod
    def _reject_blank_message(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scanner error message must not be blank")
        return value


class ScanResultEnvelope(ContractModel):
    """Authoritative S3 object published by the Nmap scanner."""

    schema_version: Literal["1.0"]
    event_id: Sha256Id
    directive_id: Sha256Id
    trace_id: SafeIdentifier
    run_id: SafeIdentifier
    attempt_id: SafeIdentifier
    target: ScanResultTarget
    profile: ScanProfile
    image_version: ImmutableImageVersion
    coverage: ScanCoverage
    timestamps: ScanTimestamps
    commands: ScanCommands
    outcome: Literal["complete", "partial", "failed"]
    exit_code: ExitCode | None
    raw_result: NmapRawResult | None
    error: ScanError | None
    scan_result: ScanResult

    def _validate_command_metadata(self) -> None:
        for command in (self.commands.discovery, self.commands.enrichment):
            if command is None:
                continue
            argv = command.argv
            if (
                argv[0] != "nmap"
                or argv.count("<authorized-target>") != 1
                or argv.count("<raw-xml>") != 1
                or any(self.target.address in argument for argument in argv)
                or "-iL" in argv
                or any(argument.startswith("--script-args") for argument in argv)
            ):
                raise ValueError("scanner command metadata must be redacted and bounded")

    def _validate_outcome(self) -> None:
        is_complete = self.outcome == "complete"
        if self.coverage.complete is not is_complete:
            raise ValueError("coverage completeness must match outcome")
        if is_complete:
            if self.error is not None:
                raise ValueError("complete results cannot contain an error")
            if self.exit_code != 0:
                raise ValueError("complete results require exit_code 0")
            if self.raw_result is None:
                raise ValueError("complete results require raw discovery evidence")
        elif self.error is None:
            raise ValueError("partial and failed results require an error")

        if (
            self.raw_result is not None
            and self.raw_result.enrichment is not None
            and self.commands.enrichment is None
        ):
            raise ValueError("raw enrichment evidence requires enrichment command metadata")

    def _validate_nested_result(self) -> None:
        shared = self.scan_result
        raw_hash = self.raw_result.sha256 if self.raw_result is not None else None
        expected = (
            (shared.event_id, self.event_id),
            (shared.directive_id, self.directive_id),
            (shared.target.target_id, self.target.target_id),
            (shared.target.public_address, self.target.address),
            (shared.target.generation, self.target.generation),
            (shared.profile, self.profile),
            (shared.scanner, ScannerEngine.NMAP),
            (shared.scanner_version, self.image_version),
            (shared.started_at, self.timestamps.scan_started_at),
            (shared.completed_at, self.timestamps.scan_completed_at),
            (shared.outcome.value, self.outcome),
            (shared.exit_code, self.exit_code),
            (shared.raw_result_sha256, raw_hash),
            (
                tuple((item.start, item.end) for item in shared.requested_tcp_port_ranges),
                self.coverage.as_ranges(),
            ),
        )
        if any(left != right for left, right in expected):
            raise ValueError("nested ScanResult conflicts with its scanner envelope")
        if self.error is None:
            if shared.error_code is not None or shared.error_message is not None:
                raise ValueError("nested ScanResult error conflicts with its scanner envelope")
        elif shared.error_code != self.error.type or shared.error_message != self.error.message:
            raise ValueError("nested ScanResult error conflicts with its scanner envelope")

    @model_validator(mode="after")
    def _validate_envelope(self) -> Self:
        self._validate_command_metadata()
        self._validate_outcome()
        self._validate_nested_result()
        return self


class FindingService(ContractModel):
    """Normalized service identity attached to a finding."""

    name: BoundedText | None
    product: BoundedText | None
    version: BoundedText | None
    certificate_sha256: Sha256Id | None
    ssh_host_key_sha256: Sha256Id | None
    banner_sha256: Sha256Id | None
    identity_sha256: Sha256Id

    @field_validator("name", "product", "version")
    @classmethod
    def _reject_blank_service_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("service fields must not be blank")
        return value


class FindingRecord(ContractModel):
    """Current state and history for one rule/target/service finding."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"status": {"const": "open"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "resolved_at": {"type": "null"},
                            "resolution_reason": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"status": {"const": "resolved"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "resolved_at": {"not": {"type": "null"}},
                            "resolution_reason": {"not": {"type": "null"}},
                        }
                    },
                },
            ]
        }
    )

    fingerprint: Sha256Id
    target_id: Sha256Id
    provider: CloudProvider
    generation: Generation
    protocol: TransportProtocol
    port: PortNumber
    rule_key: RuleKey
    status: FindingStatus
    severity: FindingSeverity
    title: BoundedText
    description: LongBoundedText
    observed_address: PublicIPv4Address
    service: FindingService
    first_opened_at: UtcDateTime
    last_seen_at: UtcDateTime
    last_changed_at: UtcDateTime
    resolved_at: UtcDateTime | None
    resolution_reason: FindingResolutionReason | None
    version: FindingVersion

    @field_validator("title", "description")
    @classmethod
    def _reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("finding text fields must not be blank")
        return value

    @model_validator(mode="after")
    def _validate_state_and_timeline(self) -> Self:
        if self.first_opened_at > self.last_seen_at:
            raise ValueError("first_opened_at must not be later than last_seen_at")
        if self.first_opened_at > self.last_changed_at:
            raise ValueError("first_opened_at must not be later than last_changed_at")
        if self.status is FindingStatus.OPEN:
            if self.resolved_at is not None or self.resolution_reason is not None:
                raise ValueError("open findings cannot contain resolution fields")
        else:
            if self.resolved_at is None or self.resolution_reason is None:
                raise ValueError("resolved findings require resolution fields")
            if self.last_seen_at > self.resolved_at:
                raise ValueError("last_seen_at must not be later than resolved_at")
            if self.last_changed_at != self.resolved_at:
                raise ValueError("resolved_at must equal last_changed_at")
        return self


class FindingEventSource(ContractModel):
    """Repository source that caused a finding event."""

    kind: FindingSourceKind
    key: BoundedText

    @field_validator("key")
    @classmethod
    def _reject_blank_key(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("finding event source key must not be blank")
        return value


def _finding_event_schema_rule(
    event_type: str,
    previous_status: str | None,
    new_status: str,
    reasons: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "if": {
            "properties": {"event_type": {"const": event_type}},
            "required": ["event_type"],
        },
        "then": {
            "properties": {
                "previous_status": {"const": previous_status},
                "new_status": {"const": new_status},
                "reason": {"enum": list(reasons)},
            }
        },
    }


class FindingEvent(ContractModel):
    """One finding lifecycle transition."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                _finding_event_schema_rule(
                    "opened",
                    None,
                    "open",
                    (
                        "exposure_open",
                        "exposure_reopened",
                        "reconciliation_repair",
                    ),
                ),
                _finding_event_schema_rule(
                    "reopened",
                    "resolved",
                    "open",
                    (
                        "exposure_reopened",
                        "reconciliation_repair",
                    ),
                ),
                _finding_event_schema_rule(
                    "updated",
                    "open",
                    "open",
                    (
                        "service_changed",
                        "address_changed",
                        "rule_changed",
                    ),
                ),
                _finding_event_schema_rule(
                    "resolved",
                    "open",
                    "resolved",
                    (
                        "ownership_removed",
                        "exposure_closed",
                        "rule_disabled",
                        "rule_no_longer_matches",
                    ),
                ),
            ]
        }
    )

    event_key: Sha256Id
    event_type: FindingEventType
    previous_status: FindingStatus | None
    new_status: FindingStatus
    reason: FindingReason
    occurred_at: UtcDateTime
    source: FindingEventSource

    @model_validator(mode="after")
    def _validate_transition(self) -> Self:
        expected = {
            FindingEventType.OPENED: (None, FindingStatus.OPEN),
            FindingEventType.REOPENED: (FindingStatus.RESOLVED, FindingStatus.OPEN),
            FindingEventType.UPDATED: (FindingStatus.OPEN, FindingStatus.OPEN),
            FindingEventType.RESOLVED: (FindingStatus.OPEN, FindingStatus.RESOLVED),
        }[self.event_type]
        if (self.previous_status, self.new_status) != expected:
            raise ValueError("finding event statuses must match event_type")

        allowed_reasons = {
            FindingEventType.OPENED: {
                FindingReason.EXPOSURE_OPEN,
                FindingReason.EXPOSURE_REOPENED,
                FindingReason.RECONCILIATION_REPAIR,
            },
            FindingEventType.REOPENED: {
                FindingReason.EXPOSURE_REOPENED,
                FindingReason.RECONCILIATION_REPAIR,
            },
            FindingEventType.UPDATED: {
                FindingReason.SERVICE_CHANGED,
                FindingReason.ADDRESS_CHANGED,
                FindingReason.RULE_CHANGED,
            },
            FindingEventType.RESOLVED: {
                FindingReason.OWNERSHIP_REMOVED,
                FindingReason.EXPOSURE_CLOSED,
                FindingReason.RULE_DISABLED,
                FindingReason.RULE_NO_LONGER_MATCHES,
            },
        }[self.event_type]
        if self.reason not in allowed_reasons:
            raise ValueError("finding event reason must match event_type")
        return self


class Finding(ContractModel):
    """Exact parser finding object published through the S3 handoff outbox."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"kind": {"const": "finding_event"}},
                        "required": ["kind"],
                    },
                    "then": {
                        "required": ["event"],
                        "properties": {"event": {"not": {"type": "null"}}},
                    },
                },
                {
                    "if": {
                        "properties": {"kind": {"const": "current_finding"}},
                        "required": ["kind"],
                    },
                    "then": {"not": {"required": ["event"]}},
                },
            ]
        }
    )

    schema_version: Literal["1.0"]
    kind: FindingKind
    finding: FindingRecord
    event: FindingEvent | None = None

    @model_validator(mode="after")
    def _validate_document_kind(self) -> Self:
        event_was_supplied = "event" in self.model_fields_set
        if self.kind is FindingKind.FINDING_EVENT:
            if self.event is None:
                raise ValueError("finding_event documents require event")
        elif event_was_supplied:
            raise ValueError("current_finding documents must omit event")

        if self.event is not None:
            if self.event.new_status is not self.finding.status:
                raise ValueError("finding event new_status must match finding status")
            if self.event.occurred_at != self.finding.last_changed_at:
                raise ValueError("finding event occurred_at must match last_changed_at")
            if self.event.event_type is FindingEventType.RESOLVED and (
                self.finding.resolution_reason is None
                or self.event.reason.value != self.finding.resolution_reason.value
            ):
                raise ValueError("resolved event reason must match resolution_reason")
        return self

    def to_dict(self) -> dict[str, Any]:
        """Return the exact JSON-compatible parser payload."""

        exclude = {"event"} if self.event is None else None
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=False,
            exclude=exclude,
        )

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the exact parser payload."""

        exclude = {"event"} if self.event is None else None
        return self.model_dump_json(
            by_alias=True,
            exclude_none=False,
            exclude=exclude,
            indent=indent,
        )


def _validate_contract_mapping_size(value: Mapping[str, Any]) -> None:
    encoded = canonical_json(value).encode("utf-8")
    if len(encoded) > MAX_CONTRACT_JSON_BYTES:
        raise ValueError(f"contract JSON exceeds {MAX_CONTRACT_JSON_BYTES} bytes")


def validate_scan_result(
    value: ScanResultEnvelope | Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and canonicalize one public scanner S3 envelope."""

    if isinstance(value, ScanResultEnvelope):
        return value.to_dict()
    _validate_contract_mapping_size(value)
    return ScanResultEnvelope.model_validate(value).to_dict()


def validate_finding(value: Finding | Mapping[str, Any]) -> dict[str, Any]:
    """Validate and canonicalize one parser finding handoff payload."""

    if isinstance(value, Finding):
        return value.to_dict()
    _validate_contract_mapping_size(value)
    return Finding.model_validate(value).to_dict()
