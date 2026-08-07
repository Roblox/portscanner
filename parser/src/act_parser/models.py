"""Validated in-memory shapes used by the parser and data-plane repository."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_PORT_SPEC = re.compile(r"^(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")
MAX_PORT = 65535


def parse_timestamp(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError(f"{field} must be an RFC 3339 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def parse_address(value: Any, field: str = "address") -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as error:
        raise ValueError(f"{field} must be an IP address") from error


def port_spec_bounds(spec: str) -> tuple[int | None, int | None]:
    """Return inclusive numeric bounds; symbolic declarations remain non-closing."""
    match = _PORT_SPEC.fullmatch(spec)
    if match is None:
        if spec == "nmap-default":
            return None, None
        raise ValueError("coverage port spec is invalid")
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    if not (1 <= start <= end <= MAX_PORT):
        raise ValueError("coverage port bounds must be between 1 and 65535")
    return start, end


@dataclass(frozen=True, slots=True)
class CoverageDeclaration:
    protocol: str
    port_spec: str
    port_from: int | None
    port_to: int | None
    complete: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> list[CoverageDeclaration]:
        protocol = str(value["protocol"]).lower()
        complete = bool(value["complete"])
        declarations = []
        for raw_spec in value["ports"]:
            spec = str(raw_spec)
            start, end = port_spec_bounds(spec)
            declarations.append(cls(protocol, spec, start, end, complete))
        if not declarations:
            raise ValueError("coverage must declare at least one port spec")
        return declarations

    def contains(self, protocol: str, port: int) -> bool:
        return (
            self.complete
            and self.port_from is not None
            and self.port_to is not None
            and self.protocol == protocol
            and self.port_from <= port <= self.port_to
        )


@dataclass(frozen=True, slots=True)
class RawResultReference:
    bucket: str
    key: str
    sha256: str
    version_id: str | None = None


def _raw_reference(value: Mapping[str, Any], field: str) -> RawResultReference:
    digest = value.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError(f"{field}.sha256 is required and must be SHA-256")
    return RawResultReference(
        bucket=str(value["bucket"]),
        key=str(value["key"]),
        sha256=digest.lower(),
        version_id=value.get("version_id"),
    )


@dataclass(frozen=True, slots=True)
class ScanEnvelope:
    attempt_id: str
    result_id: str
    run_id: str
    directive_id: str
    target_event_id: str
    trace_id: str
    provider: str
    target_id: str
    generation: int
    address: str
    profile: str
    scanner_version: str
    outcome: str
    exit_code: int | None
    error_type: str | None
    error_retryable: bool | None
    scan_started_at: datetime
    scan_completed_at: datetime
    result_uploaded_at: datetime | None
    coverage: tuple[CoverageDeclaration, ...]
    declared_open_tcp_ports: tuple[int, ...]
    raw_result: RawResultReference | None
    enrichment_result: RawResultReference | None

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> ScanEnvelope:
        target = payload["target"]
        timestamps = payload["timestamps"]
        shared = payload.get("scan_result")
        if not isinstance(shared, Mapping):
            raise ValueError("shared scan_result is required")
        shared_target = shared.get("target")
        if not isinstance(shared_target, Mapping):
            raise ValueError("shared scan_result.target is required")
        raw_result = payload.get("raw_result")
        if raw_result is None:
            raw_reference = None
            enrichment_reference = None
        else:
            raw_reference = _raw_reference(raw_result, "raw_result")
            enrichment = raw_result.get("enrichment")
            enrichment_reference = (
                None if enrichment is None else _raw_reference(enrichment, "raw_result.enrichment")
            )

        raw_coverage = payload["coverage"]
        coverage_items: Sequence[Mapping[str, Any]]
        coverage_items = [raw_coverage] if isinstance(raw_coverage, Mapping) else raw_coverage
        coverage = tuple(
            declaration
            for item in coverage_items
            for declaration in CoverageDeclaration.from_mapping(item)
        )

        error = payload.get("error")
        result_uploaded = timestamps.get("result_uploaded_at")
        return cls(
            attempt_id=str(payload["attempt_id"]),
            result_id=str(shared["result_id"]),
            run_id=str(payload["run_id"]),
            directive_id=str(payload["directive_id"]),
            target_event_id=str(payload["event_id"]),
            trace_id=str(payload["trace_id"]),
            provider=str(shared_target["provider"]),
            target_id=str(target["target_id"]),
            generation=int(target["generation"]),
            address=parse_address(target["address"], "target.address"),
            profile=str(payload["profile"]),
            scanner_version=str(payload["image_version"]),
            outcome=str(payload["outcome"]),
            exit_code=payload.get("exit_code"),
            error_type=None if error is None else str(error["type"]),
            error_retryable=None if error is None else bool(error["retryable"]),
            scan_started_at=parse_timestamp(
                timestamps["scan_started_at"], "timestamps.scan_started_at"
            ),
            scan_completed_at=parse_timestamp(
                timestamps["scan_completed_at"], "timestamps.scan_completed_at"
            ),
            result_uploaded_at=(
                None
                if result_uploaded is None
                else parse_timestamp(result_uploaded, "timestamps.result_uploaded_at")
            ),
            coverage=coverage,
            declared_open_tcp_ports=tuple(int(port) for port in shared["open_tcp_ports"]),
            raw_result=raw_reference,
            enrichment_result=enrichment_reference,
        )


@dataclass(frozen=True, slots=True)
class Observation:
    protocol: str
    port: int
    observed_address: str
    state: str
    service_name: str | None
    service_product: str | None
    service_version: str | None
    certificate_sha256: str | None
    ssh_host_key_sha256: str | None
    banner_sha256: str | None
    service_identity_sha256: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class TargetEvent:
    event_id: str
    target_id: str
    generation: int
    event_type: str
    provider: str
    provider_scope_id: str
    provider_target_id: str
    location: str | None
    addresses: tuple[str, ...]
    context: Mapping[str, Any]
    source_observed_at: datetime
    source_event_time: datetime | None = None
    source_collected_at: datetime | None = None
    dispatched_at: datetime | None = None
    removed_at: datetime | None = None
