# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Shared-contract ScanResult construction and canonical envelope serialization."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from portscanner_contracts import (
    AddressFamily,
    CloudProvider,
    ScannerEngine,
    ScanOutcome,
    ScanProfile,
    ScanResult,
    Target,
    TcpPortRange,
    TransportProtocol,
    validate_safe_identifier,
)
from portscanner_contracts import (
    validate_image_version as validate_contract_image_version,
)
from portscanner_contracts import (
    validate_scan_result as validate_contract_scan_result,
)
from portscanner_contracts import (
    validate_sha256_id as validate_contract_sha256_id,
)

from .coverage import PortCoverage


class ScanResultError(ValueError):
    """Raised when a ScanResult cannot satisfy the shared contract."""


@dataclass(frozen=True)
class RawArtifact:
    bucket: str
    key: str
    sha256: str

    def as_payload(self) -> dict[str, str]:
        validate_sha256_id(self.sha256, name="raw artifact SHA-256")
        return {
            "bucket": self.bucket,
            "key": self.key,
            "sha256": self.sha256,
        }


def validate_identifier(value: str, *, name: str) -> str:
    try:
        return validate_safe_identifier(value)
    except (TypeError, ValueError) as error:
        raise ScanResultError(f"{name} must be a bounded safe identifier") from error


def validate_sha256_id(value: str, *, name: str) -> str:
    try:
        return validate_contract_sha256_id(value)
    except (TypeError, ValueError) as error:
        raise ScanResultError(f"{name} must be a lowercase SHA-256 identifier") from error


def validate_image_version(value: str) -> str:
    """Require an OCI digest or immutable source revision, never a mutable tag."""

    try:
        return validate_contract_image_version(value)
    except (TypeError, ValueError) as error:
        raise ScanResultError(
            "image_version must be an immutable OCI sha256 digest or git revision"
        ) from error


def utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ScanResultError("ScanResult timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def command_metadata(
    argv: Sequence[str] | None,
    *,
    timeout_seconds: int,
    exit_code: int | None,
) -> dict[str, Any] | None:
    if argv is None:
        return None
    return {
        "argv": list(argv),
        "timeout_seconds": timeout_seconds,
        "exit_code": exit_code,
    }


def build_contract_target(
    *,
    target_id: str,
    provider: str,
    scope_id: str,
    location: str,
    resource_id: str,
    private_address: str,
    public_address: str,
    generation: int,
) -> Any:
    """Validate the complete target identity required by the shared contract."""

    try:
        return Target(
            target_id=validate_sha256_id(target_id, name="target_id"),
            provider=CloudProvider(provider),
            scope_id=scope_id,
            location=location,
            resource_id=resource_id,
            private_address=private_address,
            public_address=public_address,
            address_family=AddressFamily.IPV4,
            transport=TransportProtocol.TCP,
            generation=generation,
        )
    except (TypeError, ValueError) as error:
        raise ScanResultError("target identity failed the shared contract") from error


def _mapping_from_contract(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        return dict(value.model_dump(mode="json", exclude_none=False))
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    raise ScanResultError("portscanner_contracts returned an unsupported ScanResult")


def _shared_scan_result(
    *,
    event_id: str,
    directive_id: str,
    contract_target: Any,
    profile: str,
    image_version: str,
    coverage: PortCoverage,
    scanned_coverage_complete: bool,
    open_ports: Sequence[int],
    started_at: datetime,
    completed_at: datetime,
    outcome: str,
    exit_code: int | None,
    raw_discovery: RawArtifact | None,
    error: Mapping[str, Any] | None,
) -> dict[str, Any]:
    requested_ranges = tuple(
        TcpPortRange(start=item.start, end=item.end) for item in coverage.ranges
    )
    scanned_ranges = requested_ranges if scanned_coverage_complete else ()
    error_code = str(error["type"]) if error is not None else None
    error_message = str(error["message"]) if error is not None else None
    try:
        shared = ScanResult.create(
            schema_version="1.0",
            event_id=validate_sha256_id(event_id, name="event_id"),
            directive_id=validate_sha256_id(directive_id, name="directive_id"),
            target=contract_target,
            profile=ScanProfile(profile),
            scanner=ScannerEngine.NMAP,
            scanner_version=validate_image_version(image_version),
            started_at=started_at.astimezone(UTC),
            completed_at=completed_at.astimezone(UTC),
            outcome=ScanOutcome(outcome),
            requested_tcp_port_ranges=requested_ranges,
            scanned_tcp_port_ranges=scanned_ranges,
            open_tcp_ports=tuple(sorted(set(open_ports))),
            exit_code=exit_code,
            raw_result_sha256=(raw_discovery.sha256 if raw_discovery is not None else None),
            error_code=error_code,
            error_message=error_message,
        )
    except (TypeError, ValueError) as contract_error:
        raise ScanResultError("ScanResult failed the shared contract") from contract_error
    return _mapping_from_contract(shared)


def build_scan_result_payload(
    *,
    event_id: str,
    directive_id: str,
    trace_id: str,
    run_id: str,
    attempt_id: str,
    contract_target: Any,
    target: str,
    target_id: str,
    target_generation: int,
    profile: str,
    image_version: str,
    coverage: PortCoverage,
    complete: bool,
    scanned_coverage_complete: bool,
    open_ports: Sequence[int],
    started_at: datetime,
    completed_at: datetime,
    result_uploaded_at: datetime,
    discovery_command: Mapping[str, Any],
    enrichment_command: Mapping[str, Any] | None,
    outcome: str,
    exit_code: int | None,
    raw_discovery: RawArtifact | None,
    raw_enrichment: RawArtifact | None,
    error: Mapping[str, Any] | None,
) -> dict[str, Any]:
    raw_result: dict[str, Any] | None = None
    if raw_discovery is not None:
        raw_result = {
            "format": "nmap-xml",
            **raw_discovery.as_payload(),
            "enrichment": (raw_enrichment.as_payload() if raw_enrichment is not None else None),
        }

    shared_result = _shared_scan_result(
        event_id=event_id,
        directive_id=directive_id,
        contract_target=contract_target,
        profile=profile,
        image_version=image_version,
        coverage=coverage,
        scanned_coverage_complete=scanned_coverage_complete,
        open_ports=open_ports,
        started_at=started_at,
        completed_at=completed_at,
        outcome=outcome,
        exit_code=exit_code,
        raw_discovery=raw_discovery,
        error=error,
    )
    payload = {
        "schema_version": "1.0",
        "event_id": event_id,
        "directive_id": directive_id,
        "trace_id": trace_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "target": {
            "target_id": target_id,
            "address": target,
            "generation": target_generation,
        },
        "profile": profile,
        "image_version": image_version,
        "coverage": {
            "protocol": "tcp",
            "ports": list(coverage.as_strings()),
            "complete": complete,
        },
        "timestamps": {
            "scan_started_at": utc_timestamp(started_at),
            "scan_completed_at": utc_timestamp(completed_at),
            "result_uploaded_at": utc_timestamp(result_uploaded_at),
        },
        "commands": {
            "discovery": dict(discovery_command),
            "enrichment": (dict(enrichment_command) if enrichment_command is not None else None),
        },
        "outcome": outcome,
        "exit_code": exit_code,
        "raw_result": raw_result,
        "error": dict(error) if error is not None else None,
        "scan_result": shared_result,
    }
    try:
        return validate_contract_scan_result(payload)
    except (TypeError, ValueError) as contract_error:
        raise ScanResultError("ScanResultEnvelope failed the shared contract") from contract_error


def validate_scan_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate through the authoritative public ScanResultEnvelope contract."""

    try:
        return validate_contract_scan_result(payload)
    except (TypeError, ValueError) as error:
        raise ScanResultError("ScanResultEnvelope failed the shared contract") from error


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
