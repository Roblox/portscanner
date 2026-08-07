# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Console entrypoint for the hardened VERIFY worker."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from . import __version__
from .nmap import (
    NmapTuning,
    Runner,
    SubprocessRunner,
    configured_script_allowlist,
)
from .storage import ConditionalWriter, S3ConditionalWriter
from .worker import ScanExecutionError, ScanProfile, ScanRequest, execute_scan


class _StoreOnce(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        if not isinstance(values, str):
            parser.error(f"{option_string or self.dest} requires exactly one value")
        marker = f"_{self.dest}_was_explicit"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} may be supplied only once")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, values)


def _environment_list(name: str) -> list[str]:
    value = os.environ.get(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _first_environment(names: Sequence[str]) -> str | None:
    return next((os.environ[name] for name in names if name in os.environ), None)


def _required_or_environment(
    parser: argparse.ArgumentParser,
    flag: str,
    *,
    environment: str | Sequence[str],
    help_text: str,
    **kwargs: Any,
) -> None:
    environments = (environment,) if isinstance(environment, str) else tuple(environment)
    default = _first_environment(environments)
    parser.add_argument(
        flag,
        default=default,
        required=default is None,
        help=f"{help_text} (or {', '.join(environments)})",
        **kwargs,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner-verify",
        description="Run one authorized, bounded Nmap VERIFY scan",
    )
    parser.add_argument("--version", action="version", version=__version__)
    _required_or_environment(
        parser,
        "--target",
        environment=("TARGET_ADDRESS", "PORTSCANNER_TARGET_ADDRESS"),
        help_text="one literal public IPv4 target",
        action=_StoreOnce,
    )
    _required_or_environment(
        parser,
        "--profile",
        environment=("SCAN_PROFILE", "PORTSCANNER_PROFILE"),
        help_text="scan profile",
        choices=[profile.value for profile in ScanProfile],
    )
    parser.add_argument(
        "--ports",
        "--tcp-ports",
        dest="ports",
        action=_StoreOnce,
        default=_first_environment(("SCAN_PORTS", "PORTSCANNER_TCP_PORTS")),
        help="explicit TCP ports/ranges for targeted-tcp or deep",
    )
    parser.add_argument(
        "--scan-mode",
        choices=("fast", "targeted", "deep"),
        help="operator compatibility field; must agree with --profile",
    )
    parser.add_argument(
        "--service-detection",
        action="store_true",
        help="operator compatibility field valid only for deep",
    )
    parser.add_argument(
        "--deep-script",
        action="append",
        default=_environment_list("NMAP_DEEP_SCRIPTS"),
        help="safe allowlisted script name; repeat for more",
    )

    for flag, environment, help_text in (
        (
            "--event-id",
            ("TARGET_EVENT_ID", "PORTSCANNER_EVENT_ID"),
            "shared event SHA-256 identifier",
        ),
        (
            "--directive-id",
            ("SCAN_DIRECTIVE_ID", "PORTSCANNER_DIRECTIVE_ID"),
            "shared directive SHA-256 identifier",
        ),
        ("--trace-id", ("TRACE_ID", "PORTSCANNER_TRACE_ID"), "distributed trace identifier"),
        ("--run-id", ("RUN_ID", "PORTSCANNER_RUN_ID"), "scanner run identifier"),
        (
            "--attempt-id",
            ("ATTEMPT_ID", "PORTSCANNER_ATTEMPT_ID"),
            "immutable attempt identifier",
        ),
        ("--target-id", ("TARGET_ID", "PORTSCANNER_TARGET_ID"), "shared target SHA-256 identifier"),
        (
            "--target-provider",
            ("TARGET_PROVIDER", "PORTSCANNER_TARGET_PROVIDER"),
            "shared target provider",
        ),
        (
            "--target-scope-id",
            ("TARGET_SCOPE_ID", "PORTSCANNER_TARGET_SCOPE_ID"),
            "shared target scope identifier",
        ),
        (
            "--target-location",
            ("TARGET_LOCATION", "PORTSCANNER_TARGET_LOCATION"),
            "shared target location",
        ),
        (
            "--target-resource-id",
            ("TARGET_RESOURCE_ID", "PORTSCANNER_TARGET_RESOURCE_ID"),
            "shared target resource identifier",
        ),
        (
            "--target-private-address",
            ("TARGET_PRIVATE_ADDRESS", "PORTSCANNER_TARGET_PRIVATE_ADDRESS"),
            "shared target private IPv4 address",
        ),
        (
            "--image-version",
            ("SCANNER_IMAGE_VERSION", "PORTSCANNER_IMAGE_VERSION"),
            "immutable image digest",
        ),
        ("--s3-bucket", ("RESULTS_BUCKET", "PORTSCANNER_RESULT_BUCKET"), "result bucket"),
        ("--s3-prefix", ("RESULTS_PREFIX", "PORTSCANNER_RESULT_PREFIX"), "object-key prefix"),
    ):
        _required_or_environment(
            parser,
            flag,
            environment=environment,
            help_text=help_text,
        )
    _required_or_environment(
        parser,
        "--target-generation",
        environment=("TARGET_GENERATION", "PORTSCANNER_TARGET_GENERATION"),
        help_text="positive inventory generation",
        type=int,
    )

    parser.add_argument(
        "--allowed-cidr",
        action="append",
        default=_environment_list("SCANNER_ALLOWED_CIDRS"),
        help="operator-authorized IPv4 CIDR; repeat for more",
    )
    parser.add_argument(
        "--denied-cidr",
        action="append",
        default=_environment_list("SCANNER_DENIED_CIDRS"),
        help="operator-denied IPv4 CIDR; repeat for more",
    )

    parser.add_argument(
        "--min-rate",
        type=int,
        default=os.environ.get("NMAP_MIN_RATE", "100"),
    )
    parser.add_argument(
        "--max-rate",
        type=int,
        default=os.environ.get("NMAP_MAX_RATE", "500"),
    )
    parser.add_argument(
        "--discovery-retries",
        type=int,
        default=os.environ.get("NMAP_DISCOVERY_RETRIES", "2"),
    )
    parser.add_argument(
        "--enrichment-retries",
        type=int,
        default=os.environ.get("NMAP_ENRICHMENT_RETRIES", "1"),
    )
    parser.add_argument(
        "--max-rtt-timeout-ms",
        type=int,
        default=os.environ.get("NMAP_MAX_RTT_TIMEOUT_MS", "1000"),
    )
    parser.add_argument(
        "--discovery-host-timeout",
        type=int,
        default=os.environ.get("NMAP_DISCOVERY_HOST_TIMEOUT_SECONDS", "1200"),
    )
    parser.add_argument(
        "--enrichment-host-timeout",
        type=int,
        default=os.environ.get("NMAP_ENRICHMENT_HOST_TIMEOUT_SECONDS", "600"),
    )
    parser.add_argument(
        "--discovery-timeout",
        type=int,
        default=os.environ.get("NMAP_DISCOVERY_TIMEOUT_SECONDS", "1260"),
    )
    parser.add_argument(
        "--enrichment-timeout",
        type=int,
        default=os.environ.get("NMAP_ENRICHMENT_TIMEOUT_SECONDS", "660"),
    )
    parser.add_argument(
        "--script-timeout",
        type=int,
        default=os.environ.get("NMAP_SCRIPT_TIMEOUT_SECONDS", "60"),
    )
    parser.add_argument(
        "--version-intensity",
        type=int,
        default=os.environ.get("NMAP_VERSION_INTENSITY", "5"),
    )
    return parser


def _request_from_args(args: argparse.Namespace) -> ScanRequest:
    expected_mode = {
        ScanProfile.FAST_FULL_TCP.value: "fast",
        ScanProfile.TARGETED_TCP.value: "targeted",
        ScanProfile.DEEP.value: "deep",
    }[args.profile]
    if args.scan_mode is not None and args.scan_mode != expected_mode:
        raise ValueError("--scan-mode conflicts with --profile")
    if args.service_detection and args.profile != ScanProfile.DEEP.value:
        raise ValueError("--service-detection is only valid for deep")
    return ScanRequest(
        target=args.target,
        profile=args.profile,
        event_id=args.event_id,
        directive_id=args.directive_id,
        trace_id=args.trace_id,
        run_id=args.run_id,
        attempt_id=args.attempt_id,
        target_id=args.target_id,
        target_provider=args.target_provider,
        target_scope_id=args.target_scope_id,
        target_location=args.target_location,
        target_resource_id=args.target_resource_id,
        target_private_address=args.target_private_address,
        target_generation=args.target_generation,
        image_version=args.image_version,
        bucket=args.s3_bucket,
        prefix=args.s3_prefix,
        ports=args.ports,
        deep_scripts=tuple(args.deep_script),
        configured_script_allowlist=configured_script_allowlist(
            os.environ.get("NMAP_SAFE_SCRIPT_ALLOWLIST")
        ),
        allowed_cidrs=tuple(args.allowed_cidr),
        denied_cidrs=tuple(args.denied_cidr),
    )


def _tuning_from_args(args: argparse.Namespace) -> NmapTuning:
    return NmapTuning(
        min_rate=args.min_rate,
        max_rate=args.max_rate,
        discovery_retries=args.discovery_retries,
        enrichment_retries=args.enrichment_retries,
        max_rtt_timeout_ms=args.max_rtt_timeout_ms,
        discovery_host_timeout_seconds=args.discovery_host_timeout,
        enrichment_host_timeout_seconds=args.enrichment_host_timeout,
        discovery_process_timeout_seconds=args.discovery_timeout,
        enrichment_process_timeout_seconds=args.enrichment_timeout,
        script_timeout_seconds=args.script_timeout,
        version_intensity=args.version_intensity,
    )


def _default_writer() -> S3ConditionalWriter:
    import boto3  # noqa: PLC0415
    from botocore.config import Config  # noqa: PLC0415

    client = boto3.client(
        "s3",
        config=Config(retries={"mode": "standard", "max_attempts": 4}),
    )
    return S3ConditionalWriter(client)


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    writer: ConditionalWriter | None = None,
    executor: Callable[..., Mapping[str, object]] = execute_scan,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        request = _request_from_args(args)
        tuning = _tuning_from_args(args)
        selected_runner = runner if runner is not None else SubprocessRunner()
        selected_writer = writer if writer is not None else _default_writer()
        temporary_root = os.environ.get("SCANNER_TMPDIR", "/tmp")  # noqa: S108
        with tempfile.TemporaryDirectory(
            prefix="portscanner-verify-",
            dir=temporary_root,
        ) as working_directory:
            executor(
                request,
                tuning=tuning,
                runner=selected_runner,
                writer=selected_writer,
                working_directory=working_directory,
            )
    except ScanExecutionError as error:
        sys.stderr.write(f"scan failed: {error.error_type}\n")
        return 1
    except (ValueError, OSError) as error:
        parser.error(str(error))
    return 0


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
