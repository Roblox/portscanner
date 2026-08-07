# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Single-target VERIFY scan orchestration."""

from __future__ import annotations

import math
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .coverage import CoverageError, PortCoverage
from .nmap import (
    NmapTerminationError,
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
from .xml import NmapXmlError, extract_open_tcp_ports, validate_complete_scan

MIN_PHASE_EXECUTION_SECONDS = 2


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
    deadline_at: datetime
    not_after: datetime
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
    deadline_at: datetime
    not_after: datetime


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
    publish_enrichment_artifact: bool = True


@dataclass(frozen=True)
class _PhaseBudget:
    process_timeout_seconds: int
    host_timeout_seconds: int


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_datetime(value: datetime, *, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware timestamp")
    return value.astimezone(UTC)


def _phase_budget(
    *,
    not_after: datetime,
    now: datetime,
    upload_reserve_seconds: int,
    configured_process_timeout_seconds: int,
    configured_host_timeout_seconds: int,
) -> _PhaseBudget | None:
    current = _utc_datetime(now, name="scanner clock")
    remaining_seconds = math.floor((not_after - current).total_seconds())
    execution_seconds = remaining_seconds - upload_reserve_seconds
    if execution_seconds < MIN_PHASE_EXECUTION_SECONDS:
        return None
    process_timeout = min(configured_process_timeout_seconds, execution_seconds)
    host_timeout = min(configured_host_timeout_seconds, process_timeout - 1)
    if host_timeout < 1:
        return None
    return _PhaseBudget(
        process_timeout_seconds=process_timeout,
        host_timeout_seconds=host_timeout,
    )


def _insufficient_budget_failure(
    phase: str,
    *,
    scanned_coverage_complete: bool = False,
    open_ports: tuple[int, ...] = (),
) -> _PhaseFailureError:
    return _PhaseFailureError(
        error_type="insufficient_execution_budget",
        message=f"insufficient time remains before notAfter to start Nmap {phase}",
        retryable=False,
        exit_code=None,
        scanned_coverage_complete=scanned_coverage_complete,
        open_ports=open_ports,
    )


def _termination_failure(
    *,
    scanned_coverage_complete: bool = False,
    open_ports: tuple[int, ...] = (),
) -> _PhaseFailureError:
    return _PhaseFailureError(
        error_type="terminated",
        message="scan termination was requested",
        retryable=True,
        exit_code=None,
        scanned_coverage_complete=scanned_coverage_complete,
        open_ports=open_ports,
    )


def _never_terminated() -> bool:
    return False


def _request_deadlines(request: ScanRequest) -> tuple[datetime, datetime]:
    deadline_at = _utc_datetime(request.deadline_at, name="deadline_at")
    not_after = _utc_datetime(request.not_after, name="not_after")
    if deadline_at > not_after:
        raise ValueError("deadline_at must not be later than not_after")
    return deadline_at, not_after


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
    deadline_at, not_after = _request_deadlines(request)
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
        deadline_at=deadline_at,
        not_after=not_after,
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
    except NmapTerminationError as error:
        raise _PhaseFailureError(
            error_type="terminated",
            message="scan termination was requested",
            retryable=True,
            exit_code=None,
            scanned_coverage_complete=scanned_coverage_complete,
            open_ports=open_ports,
        ) from error
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
    writer: ConditionalWriter,
    started_at: datetime,
    completed_at: datetime,
    discovery_path: Path,
    enrichment_path: Path,
    discovery_argv: Sequence[str],
    discovery_timeout_seconds: int,
    discovery_exit_code: int | None,
    enrichment_argv: Sequence[str] | None,
    enrichment_timeout_seconds: int | None,
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
    if failure.publish_enrichment_artifact:
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
        timeout_seconds=discovery_timeout_seconds,
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
        timeout_seconds=enrichment_timeout_seconds or 1,
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


def execute_scan(  # noqa: PLR0912, PLR0915 - phase state must remain publishable.
    request: ScanRequest,
    *,
    tuning: NmapTuning,
    runner: Runner,
    writer: ConditionalWriter,
    working_directory: str | Path,
    clock: Callable[[], datetime] = _utc_now,
    termination_requested: Callable[[], bool] = _never_terminated,
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

    started_at = _utc_datetime(clock(), name="scanner clock")
    discovery_budget = _phase_budget(
        not_after=prepared.not_after,
        now=started_at,
        upload_reserve_seconds=tuning.upload_reserve_seconds,
        configured_process_timeout_seconds=tuning.discovery_process_timeout_seconds,
        configured_host_timeout_seconds=tuning.discovery_host_timeout_seconds,
    )
    discovery_can_start = discovery_budget is not None
    if discovery_budget is None:
        discovery_budget = _PhaseBudget(process_timeout_seconds=1, host_timeout_seconds=1)
    discovery_argv = build_discovery_command(
        target=prepared.target,
        coverage=prepared.coverage,
        output_path=discovery_path,
        tuning=tuning,
        host_timeout_seconds=discovery_budget.host_timeout_seconds,
    )
    enrichment_argv: list[str] | None = None
    enrichment_budget: _PhaseBudget | None = None
    discovery_exit_code: int | None = None
    enrichment_exit_code: int | None = None

    try:
        if not discovery_can_start:
            raise _insufficient_budget_failure("discovery")
        if termination_requested():
            raise _termination_failure()
        discovery_exit_code = _run_phase(
            runner,
            discovery_argv,
            timeout_seconds=discovery_budget.process_timeout_seconds,
            phase="discovery",
        )
        if termination_requested():
            raise _termination_failure()
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
            enrichment_budget = _phase_budget(
                not_after=prepared.not_after,
                now=clock(),
                upload_reserve_seconds=tuning.upload_reserve_seconds,
                configured_process_timeout_seconds=tuning.enrichment_process_timeout_seconds,
                configured_host_timeout_seconds=tuning.enrichment_host_timeout_seconds,
            )
            enrichment_can_start = enrichment_budget is not None
            if enrichment_budget is None:
                enrichment_budget = _PhaseBudget(
                    process_timeout_seconds=1,
                    host_timeout_seconds=1,
                )
            enrichment_argv = build_enrichment_command(
                target=prepared.target,
                open_ports=discovery_report.open_ports,
                output_path=enrichment_path,
                tuning=tuning,
                scripts=prepared.deep_scripts,
                host_timeout_seconds=enrichment_budget.host_timeout_seconds,
            )
            discovered_open_ports = tuple(sorted(discovery_report.open_ports))
            if not enrichment_can_start:
                raise _insufficient_budget_failure(
                    "enrichment",
                    scanned_coverage_complete=True,
                    open_ports=discovered_open_ports,
                )
            if termination_requested():
                raise _termination_failure(
                    scanned_coverage_complete=True,
                    open_ports=discovered_open_ports,
                )
            enrichment_exit_code = _run_phase(
                runner,
                enrichment_argv,
                timeout_seconds=enrichment_budget.process_timeout_seconds,
                phase="enrichment",
                scanned_coverage_complete=True,
                open_ports=discovered_open_ports,
            )
            try:
                enrichment_open_ports = extract_open_tcp_ports(enrichment_path)
            except NmapXmlError as error:
                raise _PhaseFailureError(
                    error_type="enrichment_incomplete",
                    message="Nmap enrichment XML was incomplete",
                    retryable=True,
                    exit_code=enrichment_exit_code,
                    scanned_coverage_complete=True,
                    open_ports=discovered_open_ports,
                ) from error
            if enrichment_open_ports != discovery_report.open_ports:
                raise _PhaseFailureError(
                    error_type="enrichment_port_set_changed",
                    message="open TCP port set changed between discovery and enrichment",
                    retryable=True,
                    exit_code=enrichment_exit_code,
                    scanned_coverage_complete=False,
                    open_ports=(),
                    publish_enrichment_artifact=False,
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
                    open_ports=discovered_open_ports,
                ) from error
        if termination_requested():
            raise _termination_failure(
                scanned_coverage_complete=True,
                open_ports=tuple(sorted(discovery_report.open_ports)),
            )
    except _PhaseFailureError as failure:
        completed_at = _utc_datetime(clock(), name="scanner clock")
        failed_payload = _publish_failed_scan(
            request=request,
            prepared=prepared,
            writer=writer,
            started_at=started_at,
            completed_at=completed_at,
            discovery_path=discovery_path,
            enrichment_path=enrichment_path,
            discovery_argv=discovery_argv,
            discovery_timeout_seconds=discovery_budget.process_timeout_seconds,
            discovery_exit_code=discovery_exit_code,
            enrichment_argv=enrichment_argv,
            enrichment_timeout_seconds=(
                enrichment_budget.process_timeout_seconds if enrichment_budget is not None else None
            ),
            enrichment_exit_code=enrichment_exit_code,
            failure=failure,
            clock=clock,
        )
        raise ScanExecutionError(
            failure.message,
            error_type=failure.error_type,
            payload=failed_payload,
        ) from failure

    completed_at = _utc_datetime(clock(), name="scanner clock")
    discovery_meta = command_metadata(
        redact_command(
            discovery_argv,
            target=prepared.target,
            output_path=discovery_path,
        ),
        timeout_seconds=discovery_budget.process_timeout_seconds,
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
        timeout_seconds=(
            enrichment_budget.process_timeout_seconds if enrichment_budget is not None else 1
        ),
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
