# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Single-target VERIFY scan orchestration."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .coverage import CoverageError, PortCoverage
from .nmap import (
    NmapTuning,
    Runner,
    build_discovery_command,
    build_enrichment_command,
    redact_command,
    resolve_deep_scripts,
)
from .result import (
    RawArtifact,
    build_contract_target,
    build_scan_result_payload,
    canonical_json_bytes,
    command_metadata,
    validate_identifier,
    validate_image_version,
    validate_scan_result,
    validate_sha256_id,
)
from .storage import (
    ConditionalWriter,
    ObjectAlreadyExistsError,
    ObjectKeys,
    build_object_keys,
    normalize_prefix,
    validate_bucket,
)
from .targets import authorize_target
from .xml import NmapXmlError, validate_complete_scan


class ScanProfile(StrEnum):
    FAST_FULL_TCP = "fast-full-tcp"
    TARGETED_TCP = "targeted-tcp"
    DEEP = "deep"


@dataclass(frozen=True)
class ScanRequest:
    target: str
    profile: str
    event_id: str
    directive_id: str
    trace_id: str
    run_id: str
    attempt_id: str
    target_id: str
    target_provider: str
    target_scope_id: str
    target_location: str
    target_resource_id: str
    target_private_address: str
    target_generation: int
    image_version: str
    bucket: str
    prefix: str
    ports: str | None = None
    deep_scripts: tuple[str, ...] = ()
    configured_script_allowlist: tuple[str, ...] | None = None
    allowed_cidrs: tuple[str, ...] = ()
    denied_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedScan:
    target: str
    contract_target: Any
    profile: ScanProfile
    coverage: PortCoverage
    deep_scripts: tuple[str, ...]
    keys: ObjectKeys


class ScanExecutionError(RuntimeError):
    """A scan or publication failed and the CLI must exit nonzero."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str,
        payload: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.payload = dict(payload) if payload is not None else None


@dataclass(frozen=True)
class _PhaseFailureError(Exception):
    error_type: str
    message: str
    retryable: bool
    exit_code: int | None
    scanned_coverage_complete: bool = False
    open_ports: tuple[int, ...] = ()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def prepare_scan(request: ScanRequest) -> PreparedScan:
    """Validate all event, target, profile, and storage fields before execution."""

    target = str(
        authorize_target(
            request.target,
            allowed_cidrs=request.allowed_cidrs,
            denied_cidrs=request.denied_cidrs,
        )
    )
    try:
        profile = ScanProfile(request.profile)
    except ValueError as error:
        raise ValueError("unsupported scan profile") from error
    for name, value in (
        ("event_id", request.event_id),
        ("directive_id", request.directive_id),
        ("target_id", request.target_id),
    ):
        validate_sha256_id(value, name=name)
    for name, value in (
        ("trace_id", request.trace_id),
        ("run_id", request.run_id),
        ("attempt_id", request.attempt_id),
    ):
        validate_identifier(value, name=name)
    if request.target_generation < 1:
        raise ValueError("target_generation must be positive")
    validate_image_version(request.image_version)
    validate_bucket(request.bucket)
    normalize_prefix(request.prefix)
    contract_target = build_contract_target(
        target_id=request.target_id,
        provider=request.target_provider,
        scope_id=request.target_scope_id,
        location=request.target_location,
        resource_id=request.target_resource_id,
        private_address=request.target_private_address,
        public_address=target,
        generation=request.target_generation,
    )

    if profile is ScanProfile.FAST_FULL_TCP:
        coverage = PortCoverage.full_tcp()
        if request.ports is not None and PortCoverage.parse(request.ports) != coverage:
            raise CoverageError("fast-full-tcp only accepts declared ports 1-65535")
        if request.deep_scripts:
            raise ValueError("deep scripts are only valid for the deep profile")
        scripts: tuple[str, ...] = ()
    else:
        if request.ports is None:
            raise CoverageError(f"{profile.value} requires explicit TCP port coverage")
        coverage = PortCoverage.parse(request.ports)
        if profile is ScanProfile.TARGETED_TCP:
            if request.deep_scripts:
                raise ValueError("deep scripts are only valid for the deep profile")
            scripts = ()
        else:
            scripts = resolve_deep_scripts(
                request.deep_scripts,
                configured_allowlist=request.configured_script_allowlist,
            )

    return PreparedScan(
        target=target,
        contract_target=contract_target,
        profile=profile,
        coverage=coverage,
        deep_scripts=scripts,
        keys=build_object_keys(
            request.prefix,
            request.event_id,
            request.attempt_id,
        ),
    )


def _run_phase(
    runner: Runner,
    command: Sequence[str],
    *,
    timeout_seconds: int,
    phase: str,
    scanned_coverage_complete: bool = False,
    open_ports: tuple[int, ...] = (),
) -> int:
    try:
        result = runner.run(command, timeout_seconds=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise _PhaseFailureError(
            error_type=f"{phase}_timeout",
            message=f"Nmap {phase} exceeded its configured timeout",
            retryable=True,
            exit_code=None,
            scanned_coverage_complete=scanned_coverage_complete,
            open_ports=open_ports,
        ) from error
    except OSError as error:
        raise _PhaseFailureError(
            error_type=f"{phase}_execution_failed",
            message=f"Nmap {phase} could not be executed",
            retryable=True,
            exit_code=None,
            scanned_coverage_complete=scanned_coverage_complete,
            open_ports=open_ports,
        ) from error
    if result.returncode != 0:
        raise _PhaseFailureError(
            error_type=f"{phase}_failed",
            message=f"Nmap {phase} exited unsuccessfully",
            retryable=True,
            exit_code=result.returncode,
            scanned_coverage_complete=scanned_coverage_complete,
            open_ports=open_ports,
        )
    return result.returncode


def _existing_nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _put_raw_if_present(
    writer: ConditionalWriter,
    *,
    request: ScanRequest,
    path: Path,
    key: str,
) -> RawArtifact | None:
    if not _existing_nonempty(path):
        return None
    digest = writer.put_file(
        bucket=request.bucket,
        key=key,
        path=path,
        content_type="application/xml",
    )
    return RawArtifact(bucket=request.bucket, key=key, sha256=digest)


def _error_payload(failure: _PhaseFailureError) -> dict[str, object]:
    return {
        "type": failure.error_type,
        "message": failure.message,
        "retryable": failure.retryable,
    }


def _validated_result(
    *,
    request: ScanRequest,
    prepared: PreparedScan,
    started_at: datetime,
    completed_at: datetime,
    result_uploaded_at: datetime,
    complete: bool,
    scanned_coverage_complete: bool,
    open_ports: Sequence[int],
    outcome: str,
    exit_code: int | None,
    discovery_metadata: Mapping[str, object],
    enrichment_metadata: Mapping[str, object] | None,
    raw_discovery: RawArtifact | None,
    raw_enrichment: RawArtifact | None,
    error: Mapping[str, object] | None,
) -> dict[str, object]:
    payload = build_scan_result_payload(
        event_id=request.event_id,
        directive_id=request.directive_id,
        trace_id=request.trace_id,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        contract_target=prepared.contract_target,
        target=prepared.target,
        target_id=request.target_id,
        target_generation=request.target_generation,
        profile=prepared.profile.value,
        image_version=request.image_version,
        coverage=prepared.coverage,
        complete=complete,
        scanned_coverage_complete=scanned_coverage_complete,
        open_ports=open_ports,
        started_at=started_at,
        completed_at=completed_at,
        result_uploaded_at=result_uploaded_at,
        discovery_command=discovery_metadata,
        enrichment_command=enrichment_metadata,
        outcome=outcome,
        exit_code=exit_code,
        raw_discovery=raw_discovery,
        raw_enrichment=raw_enrichment,
        error=error,
    )
    return validate_scan_result(payload)


def _publish_failed_scan(
    *,
    request: ScanRequest,
    prepared: PreparedScan,
    tuning: NmapTuning,
    writer: ConditionalWriter,
    started_at: datetime,
    completed_at: datetime,
    discovery_path: Path,
    enrichment_path: Path,
    discovery_argv: Sequence[str],
    discovery_exit_code: int | None,
    enrichment_argv: Sequence[str] | None,
    enrichment_exit_code: int | None,
    failure: _PhaseFailureError,
    clock: Callable[[], datetime],
) -> dict[str, object] | None:
    """Best-effort raw-first failed-envelope publication."""

    raw_discovery: RawArtifact | None = None
    raw_enrichment: RawArtifact | None = None
    try:
        raw_discovery = _put_raw_if_present(
            writer,
            request=request,
            path=discovery_path,
            key=prepared.keys.discovery_xml,
        )
    except Exception:
        raw_discovery = None
    try:
        raw_enrichment = _put_raw_if_present(
            writer,
            request=request,
            path=enrichment_path,
            key=prepared.keys.enrichment_xml,
        )
    except Exception:
        raw_enrichment = None

    discovery_meta = command_metadata(
        redact_command(
            discovery_argv,
            target=prepared.target,
            output_path=discovery_path,
        ),
        timeout_seconds=tuning.discovery_process_timeout_seconds,
        exit_code=discovery_exit_code,
    )
    if discovery_meta is None:
        raise RuntimeError("discovery command metadata is missing")
    enrichment_meta = command_metadata(
        (
            redact_command(
                enrichment_argv,
                target=prepared.target,
                output_path=enrichment_path,
            )
            if enrichment_argv is not None
            else None
        ),
        timeout_seconds=tuning.enrichment_process_timeout_seconds,
        exit_code=enrichment_exit_code,
    )
    outcome = (
        "partial"
        if _existing_nonempty(discovery_path) or _existing_nonempty(enrichment_path)
        else "failed"
    )
    try:
        payload = _validated_result(
            request=request,
            prepared=prepared,
            started_at=started_at,
            completed_at=completed_at,
            result_uploaded_at=clock(),
            complete=False,
            scanned_coverage_complete=failure.scanned_coverage_complete,
            open_ports=failure.open_ports,
            outcome=outcome,
            exit_code=failure.exit_code,
            discovery_metadata=discovery_meta,
            enrichment_metadata=enrichment_meta,
            raw_discovery=raw_discovery,
            raw_enrichment=raw_enrichment,
            error=_error_payload(failure),
        )
        writer.put_bytes(
            bucket=request.bucket,
            key=prepared.keys.envelope_json,
            value=canonical_json_bytes(payload),
            content_type="application/json",
        )
        return payload
    except Exception:
        return None


def execute_scan(
    request: ScanRequest,
    *,
    tuning: NmapTuning,
    runner: Runner,
    writer: ConditionalWriter,
    working_directory: str | Path,
    clock: Callable[[], datetime] = _utc_now,
) -> dict[str, object]:
    """Run discovery, enrich only opens, then publish immutable artifacts."""

    prepared = prepare_scan(request)
    workdir = Path(working_directory)
    if not workdir.is_dir():
        raise ValueError("scanner working directory does not exist")
    discovery_path = workdir / "nmap-discovery.xml"
    enrichment_path = workdir / "nmap-enrichment.xml"
    if discovery_path.exists() or enrichment_path.exists():
        raise ValueError("scanner working directory must be dedicated and empty")

    discovery_argv = build_discovery_command(
        target=prepared.target,
        coverage=prepared.coverage,
        output_path=discovery_path,
        tuning=tuning,
    )
    enrichment_argv: list[str] | None = None
    discovery_exit_code: int | None = None
    enrichment_exit_code: int | None = None
    started_at = clock()

    try:
        discovery_exit_code = _run_phase(
            runner,
            discovery_argv,
            timeout_seconds=tuning.discovery_process_timeout_seconds,
            phase="discovery",
        )
        try:
            discovery_report = validate_complete_scan(
                discovery_path,
                target=prepared.target,
                coverage=prepared.coverage,
            )
        except NmapXmlError as error:
            raise _PhaseFailureError(
                error_type="discovery_incomplete",
                message="Nmap discovery XML did not prove complete coverage",
                retryable=True,
                exit_code=discovery_exit_code,
            ) from error

        if discovery_report.open_ports:
            enrichment_coverage = PortCoverage.from_ports(discovery_report.open_ports)
            enrichment_argv = build_enrichment_command(
                target=prepared.target,
                open_ports=discovery_report.open_ports,
                output_path=enrichment_path,
                tuning=tuning,
                scripts=prepared.deep_scripts,
            )
            enrichment_exit_code = _run_phase(
                runner,
                enrichment_argv,
                timeout_seconds=tuning.enrichment_process_timeout_seconds,
                phase="enrichment",
                scanned_coverage_complete=True,
                open_ports=tuple(sorted(discovery_report.open_ports)),
            )
            try:
                validate_complete_scan(
                    enrichment_path,
                    target=prepared.target,
                    coverage=enrichment_coverage,
                )
            except NmapXmlError as error:
                raise _PhaseFailureError(
                    error_type="enrichment_incomplete",
                    message="Nmap enrichment XML was incomplete",
                    retryable=True,
                    exit_code=enrichment_exit_code,
                    scanned_coverage_complete=True,
                    open_ports=tuple(sorted(discovery_report.open_ports)),
                ) from error
    except _PhaseFailureError as failure:
        completed_at = clock()
        failed_payload = _publish_failed_scan(
            request=request,
            prepared=prepared,
            tuning=tuning,
            writer=writer,
            started_at=started_at,
            completed_at=completed_at,
            discovery_path=discovery_path,
            enrichment_path=enrichment_path,
            discovery_argv=discovery_argv,
            discovery_exit_code=discovery_exit_code,
            enrichment_argv=enrichment_argv,
            enrichment_exit_code=enrichment_exit_code,
            failure=failure,
            clock=clock,
        )
        raise ScanExecutionError(
            failure.message,
            error_type=failure.error_type,
            payload=failed_payload,
        ) from failure

    completed_at = clock()
    discovery_meta = command_metadata(
        redact_command(
            discovery_argv,
            target=prepared.target,
            output_path=discovery_path,
        ),
        timeout_seconds=tuning.discovery_process_timeout_seconds,
        exit_code=discovery_exit_code,
    )
    if discovery_meta is None:
        raise RuntimeError("discovery command metadata is missing")
    enrichment_meta = command_metadata(
        (
            redact_command(
                enrichment_argv,
                target=prepared.target,
                output_path=enrichment_path,
            )
            if enrichment_argv is not None
            else None
        ),
        timeout_seconds=tuning.enrichment_process_timeout_seconds,
        exit_code=enrichment_exit_code,
    )

    try:
        raw_discovery = _put_raw_if_present(
            writer,
            request=request,
            path=discovery_path,
            key=prepared.keys.discovery_xml,
        )
        if raw_discovery is None:
            raise RuntimeError("completed scan has no discovery artifact")
        raw_enrichment = _put_raw_if_present(
            writer,
            request=request,
            path=enrichment_path,
            key=prepared.keys.enrichment_xml,
        )
        payload = _validated_result(
            request=request,
            prepared=prepared,
            started_at=started_at,
            completed_at=completed_at,
            result_uploaded_at=clock(),
            complete=True,
            scanned_coverage_complete=True,
            open_ports=tuple(sorted(discovery_report.open_ports)),
            outcome="complete",
            exit_code=0,
            discovery_metadata=discovery_meta,
            enrichment_metadata=enrichment_meta,
            raw_discovery=raw_discovery,
            raw_enrichment=raw_enrichment,
            error=None,
        )
        writer.put_bytes(
            bucket=request.bucket,
            key=prepared.keys.envelope_json,
            value=canonical_json_bytes(payload),
            content_type="application/json",
        )
    except ObjectAlreadyExistsError as error:
        raise ScanExecutionError(
            "immutable result key already exists",
            error_type="duplicate_result",
        ) from error
    except Exception as error:
        raise ScanExecutionError(
            "scan result upload failed",
            error_type="result_upload_failed",
        ) from error
    return payload
