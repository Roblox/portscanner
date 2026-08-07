"""Small provider-neutral primitives used by the inventory adapters."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")


class ScopeCompletion(StrEnum):
    """Whether a snapshot is authoritative for absence."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SnapshotScope:
    """The exact state domain covered by one snapshot."""

    source: str
    account_id: str | None = None
    region: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.source not in {"aws-config", "ec2"}:
            raise ValueError("unsupported snapshot source")
        if self.account_id is not None and not _ACCOUNT_RE.fullmatch(self.account_id):
            raise ValueError("account_id must contain 12 digits")
        if self.region is not None and not _REGION_RE.fullmatch(self.region):
            raise ValueError("invalid AWS region")
        if self.source == "ec2" and (self.account_id is None or self.region is None):
            raise ValueError("direct EC2 scope requires account_id and region")
        if self.source == "aws-config" and not self.name:
            raise ValueError("AWS Config scope requires an aggregator name")

    @property
    def key(self) -> str:
        parts = [self.source, self.name or "*", self.account_id or "*", self.region or "*"]
        return ":".join(parts)

    def includes(self, account_id: str, region: str) -> bool:
        return (self.account_id in {None, account_id}) and (self.region in {None, region})


@dataclass(frozen=True, slots=True)
class SnapshotBatch:
    """Normalized observations plus an explicit completeness decision."""

    scope: SnapshotScope
    targets: tuple[Any, ...]
    completion: ScopeCompletion
    pages: int = 0
    malformed_records: int = 0
    failure_code: str | None = None

    @property
    def complete(self) -> bool:
        return self.completion is ScopeCompletion.COMPLETE

    def __post_init__(self) -> None:
        if self.pages < 0 or self.malformed_records < 0:
            raise ValueError("snapshot counters cannot be negative")
        if self.completion is ScopeCompletion.COMPLETE:
            if self.failure_code is not None or self.malformed_records:
                raise ValueError("complete snapshots cannot contain failures")
        elif not self.failure_code and not self.malformed_records:
            raise ValueError("incomplete snapshots require a bounded failure reason")


@dataclass(frozen=True, slots=True)
class CandidatePorts:
    """A normalized, bounded TCP port selection."""

    ranges: tuple[tuple[int, int], ...] = ()
    full_tcp: bool = False

    def __post_init__(self) -> None:
        if self.full_tcp and self.ranges not in {(), ((1, 65535),)}:
            raise ValueError("full TCP cannot be combined with partial ranges")
        previous_end = 0
        for start, end in self.ranges:
            if not 1 <= start <= end <= 65535:
                raise ValueError("TCP range must be within 1..65535")
            if start <= previous_end:
                raise ValueError("TCP ranges must be sorted and non-overlapping")
            previous_end = end

    @classmethod
    def full(cls) -> CandidatePorts:
        return cls(ranges=((1, 65535),), full_tcp=True)

    @property
    def contract_ranges(self) -> tuple[str, ...]:
        if self.full_tcp:
            return ("1-65535",)
        return tuple(str(start) if start == end else f"{start}-{end}" for start, end in self.ranges)


@dataclass(frozen=True, slots=True)
class SignalHint:
    """Sanitized identifiers extracted from one allowlisted control-plane event."""

    account_id: str
    region: str
    event_name: str
    event_id: str
    request_id: str | None = None
    event_time: datetime | None = None
    network_interface_ids: tuple[str, ...] = ()
    network_interface_attachment_ids: tuple[str, ...] = ()
    instance_ids: tuple[str, ...] = ()
    security_group_ids: tuple[str, ...] = ()
    allocation_ids: tuple[str, ...] = ()
    association_ids: tuple[str, ...] = ()
    public_ips: tuple[str, ...] = ()
    candidate_ports: CandidatePorts = field(default_factory=CandidatePorts.full)

    def __post_init__(self) -> None:
        if not _ACCOUNT_RE.fullmatch(self.account_id):
            raise ValueError("invalid signal account")
        if not _REGION_RE.fullmatch(self.region):
            raise ValueError("invalid signal region")
        if not self.event_name or not self.event_id:
            raise ValueError("signal event_name and event_id are required")
        if self.event_time is not None and self.event_time.tzinfo is None:
            raise ValueError("signal event_time must be timezone aware")
        identifier_groups = (
            self.network_interface_ids,
            self.network_interface_attachment_ids,
            self.instance_ids,
            self.security_group_ids,
            self.allocation_ids,
            self.association_ids,
            self.public_ips,
        )
        if not any(identifier_groups):
            raise ValueError("signal contains no safe resource identifier")


class ResolutionStatus(StrEnum):
    COMPLETE = "complete"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Resolution:
    targets: tuple[Any, ...]
    status: ResolutionStatus = ResolutionStatus.COMPLETE
    missing_network_interface_ids: tuple[str, ...] = ()
    failure_code: str | None = None


class OwnershipVerdict(StrEnum):
    ACTIVE = "active"
    STALE = "stale"
    MOVED = "moved"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class OwnershipCheck:
    verdict: OwnershipVerdict
    current: Any | None = None
    reason: str | None = None


class SnapshotBackend(Protocol):
    def collect(self) -> SnapshotBatch: ...


class StateReader(Protocol):
    def get(self, target_id: str) -> Any | None: ...


class Clock(Protocol):
    def __call__(self) -> datetime: ...


def utc_now() -> datetime:
    return datetime.now(UTC)


def aws_error_code(error: BaseException) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        details = response.get("Error")
        if isinstance(details, Mapping):
            return str(details.get("Code") or error.__class__.__name__)
    return error.__class__.__name__


_NOT_FOUND_CODES = {
    "InvalidAddress.NotFound",
    "InvalidAssociationID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidInstanceID.NotFound",
    "InvalidNetworkInterfaceID.NotFound",
}
_UNKNOWN_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "AuthFailure",
    "ClientError",
    "DependencyTimeout",
    "EC2ThrottledException",
    "InternalError",
    "InternalFailure",
    "RequestLimitExceeded",
    "ServiceUnavailable",
    "ThrottledException",
    "Throttling",
    "ThrottlingException",
    "UnauthorizedOperation",
}


def is_not_found(error: BaseException) -> bool:
    return aws_error_code(error) in _NOT_FOUND_CODES


def is_unknown_aws_error(error: BaseException) -> bool:
    code = aws_error_code(error)
    return (
        code in _UNKNOWN_CODES
        or "throttl" in code.lower()
        or "timeout" in code.lower()
        or "temporar" in code.lower()
    )


_SAFE_LOG_FIELDS = {
    "operation",
    "status",
    "records",
    "targets",
    "events",
    "failures",
    "pages",
    "completion",
    "verdict",
    "reason",
}


def structured_log(
    logger: logging.Logger,
    operation: str,
    *,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Log only an intentionally small set of non-secret aggregate fields."""

    safe = {"operation": operation}
    safe.update({key: value for key, value in fields.items() if key in _SAFE_LOG_FIELDS})
    logger.log(level, json.dumps(safe, separators=(",", ":"), sort_keys=True, default=str))


def partial_batch(
    records: Sequence[Mapping[str, Any]],
    process: Callable[[Mapping[str, Any]], None],
) -> dict[str, list[dict[str, str]]]:
    failures: list[dict[str, str]] = []
    for record in records:
        identifier = str(record.get("messageId") or record.get("eventID") or "")
        try:
            process(record)
        except Exception:
            if not identifier:
                raise
            failures.append({"itemIdentifier": identifier})
    return {"batchItemFailures": failures}
