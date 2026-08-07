# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Bounded Nmap command construction and process execution."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .coverage import PortCoverage

NMAP_BINARY = "nmap"
MAX_MIN_RATE = 2_000
MAX_RATE = 5_000
MAX_RETRIES = 3
MIN_RTT_TIMEOUT_MS = 100
MAX_RTT_TIMEOUT_MS = 5_000
MIN_HOST_TIMEOUT_SECONDS = 30
MAX_HOST_TIMEOUT_SECONDS = 7_200
MAX_PROCESS_TIMEOUT_SECONDS = 7_500
MAX_SCRIPT_TIMEOUT_SECONDS = 300
MAX_VERSION_INTENSITY = 7

KNOWN_SAFE_DEEP_SCRIPTS = frozenset(
    {
        "banner",
        "http-title",
        "ssh-hostkey",
        "ssh2-enum-algos",
        "ssl-cert",
        "ssl-enum-ciphers",
        "tls-alpn",
    }
)
DEFAULT_SAFE_DEEP_SCRIPTS = frozenset(
    {
        "banner",
        "http-title",
        "ssh2-enum-algos",
        "ssl-cert",
        "tls-alpn",
    }
)
_SCRIPT_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class NmapConfigurationError(ValueError):
    """Raised when Nmap tuning or script configuration is unsafe."""


@dataclass(frozen=True)
class NmapTuning:
    """Conservative, operator-controlled bounds for both Nmap phases."""

    min_rate: int = 100
    max_rate: int = 500
    discovery_retries: int = 2
    enrichment_retries: int = 1
    max_rtt_timeout_ms: int = 1_000
    discovery_host_timeout_seconds: int = 1_200
    enrichment_host_timeout_seconds: int = 600
    discovery_process_timeout_seconds: int = 1_260
    enrichment_process_timeout_seconds: int = 660
    script_timeout_seconds: int = 60
    version_intensity: int = 5

    def __post_init__(self) -> None:
        if not 1 <= self.min_rate <= MAX_MIN_RATE:
            raise NmapConfigurationError("min_rate must be between 1 and 2000")
        if not self.min_rate <= self.max_rate <= MAX_RATE:
            raise NmapConfigurationError("max_rate must be between min_rate and 5000")
        for name, value in (
            ("discovery_retries", self.discovery_retries),
            ("enrichment_retries", self.enrichment_retries),
        ):
            if not 0 <= value <= MAX_RETRIES:
                raise NmapConfigurationError(f"{name} must be between 0 and 3")
        if not MIN_RTT_TIMEOUT_MS <= self.max_rtt_timeout_ms <= MAX_RTT_TIMEOUT_MS:
            raise NmapConfigurationError("max_rtt_timeout_ms must be between 100 and 5000")
        for name, value in (
            ("discovery_host_timeout_seconds", self.discovery_host_timeout_seconds),
            ("enrichment_host_timeout_seconds", self.enrichment_host_timeout_seconds),
        ):
            if not MIN_HOST_TIMEOUT_SECONDS <= value <= MAX_HOST_TIMEOUT_SECONDS:
                raise NmapConfigurationError(f"{name} must be between 30 and 7200")
        if not (
            self.discovery_host_timeout_seconds
            < self.discovery_process_timeout_seconds
            <= MAX_PROCESS_TIMEOUT_SECONDS
        ):
            raise NmapConfigurationError(
                "discovery process timeout must exceed and bound host timeout"
            )
        if not (
            self.enrichment_host_timeout_seconds
            < self.enrichment_process_timeout_seconds
            <= MAX_PROCESS_TIMEOUT_SECONDS
        ):
            raise NmapConfigurationError(
                "enrichment process timeout must exceed and bound host timeout"
            )
        if not 1 <= self.script_timeout_seconds <= MAX_SCRIPT_TIMEOUT_SECONDS:
            raise NmapConfigurationError("script_timeout_seconds must be between 1 and 300")
        if not 0 <= self.version_intensity <= MAX_VERSION_INTENSITY:
            raise NmapConfigurationError("version_intensity must be between 0 and 7")


def _split_script_names(values: Iterable[str]) -> set[str]:
    names: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise NmapConfigurationError("Nmap script names must be strings")
        for raw_name in value.split(","):
            name = raw_name.strip()
            if not name or _SCRIPT_NAME.fullmatch(name) is None:
                raise NmapConfigurationError("invalid Nmap script name")
            names.add(name)
    return names


def resolve_deep_scripts(
    requested: Iterable[str],
    *,
    configured_allowlist: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Resolve requested deep scripts against a bounded operator allowlist."""

    if configured_allowlist is None:
        allowed = set(DEFAULT_SAFE_DEEP_SCRIPTS)
    else:
        allowed = _split_script_names(configured_allowlist)
    unknown_allowed = allowed - KNOWN_SAFE_DEEP_SCRIPTS
    if unknown_allowed:
        raise NmapConfigurationError(
            "configured deep-script allowlist contains unsupported scripts"
        )

    selected = _split_script_names(requested)
    if selected - allowed:
        raise NmapConfigurationError(
            "requested deep script is not in the configured safe allowlist"
        )
    return tuple(sorted(selected))


def configured_script_allowlist(environment_value: str | None) -> tuple[str, ...] | None:
    """Convert the trusted deployment setting into resolver input."""

    if environment_value is None:
        return None
    if not environment_value.strip():
        return ()
    return tuple(part.strip() for part in environment_value.split(","))


def _base_scan_command(
    *,
    target: str,
    coverage: PortCoverage,
    output_path: os.PathLike[str] | str,
    retries: int,
    host_timeout_seconds: int,
    tuning: NmapTuning,
) -> list[str]:
    return [
        NMAP_BINARY,
        "-n",
        "-Pn",
        "-sS",
        "--reason",
        "--max-retries",
        str(retries),
        "--min-rate",
        str(tuning.min_rate),
        "--max-rate",
        str(tuning.max_rate),
        "--max-rtt-timeout",
        f"{tuning.max_rtt_timeout_ms}ms",
        "--host-timeout",
        f"{host_timeout_seconds}s",
        "-p",
        coverage.nmap_spec,
        "-oX",
        os.fspath(output_path),
        target,
    ]


def build_discovery_command(
    *,
    target: str,
    coverage: PortCoverage,
    output_path: os.PathLike[str] | str,
    tuning: NmapTuning,
) -> list[str]:
    """Build the exact-coverage SYN discovery phase."""

    return _base_scan_command(
        target=target,
        coverage=coverage,
        output_path=output_path,
        retries=tuning.discovery_retries,
        host_timeout_seconds=tuning.discovery_host_timeout_seconds,
        tuning=tuning,
    )


def build_enrichment_command(
    *,
    target: str,
    open_ports: Iterable[int],
    output_path: os.PathLike[str] | str,
    tuning: NmapTuning,
    scripts: Iterable[str] = (),
) -> list[str]:
    """Build service enrichment limited to discovered-open TCP ports."""

    coverage = PortCoverage.from_ports(open_ports)
    command = _base_scan_command(
        target=target,
        coverage=coverage,
        output_path=output_path,
        retries=tuning.enrichment_retries,
        host_timeout_seconds=tuning.enrichment_host_timeout_seconds,
        tuning=tuning,
    )
    target_argument = command.pop()
    command.extend(
        [
            "-sV",
            "--version-intensity",
            str(tuning.version_intensity),
        ]
    )
    selected_scripts = tuple(sorted(set(scripts)))
    if selected_scripts:
        if set(selected_scripts) - KNOWN_SAFE_DEEP_SCRIPTS:
            raise NmapConfigurationError("unsafe Nmap script reached command builder")
        command.extend(
            [
                "--script-timeout",
                f"{tuning.script_timeout_seconds}s",
                "--script",
                ",".join(selected_scripts),
            ]
        )
    command.append(target_argument)
    return command


def redact_command(
    command: Sequence[str],
    *,
    target: str,
    output_path: os.PathLike[str] | str,
) -> list[str]:
    """Remove target and local artifact path from persisted command metadata."""

    output = os.fspath(output_path)
    redacted: list[str] = []
    for index, argument in enumerate(command):
        if index == 0:
            redacted.append(Path(argument).name)
        elif argument == target:
            redacted.append("<authorized-target>")
        elif argument == output:
            redacted.append("<raw-xml>")
        else:
            redacted.append(argument)
    return redacted


@dataclass(frozen=True)
class ProcessResult:
    returncode: int


class Runner(Protocol):
    def run(self, command: Sequence[str], *, timeout_seconds: int) -> ProcessResult:
        """Execute one already-validated argv sequence."""


class SubprocessRunner:
    """Execute Nmap without a shell or inherited input/output streams."""

    def run(self, command: Sequence[str], *, timeout_seconds: int) -> ProcessResult:
        completed = subprocess.run(  # noqa: S603 - argv is fully constructed above.
            list(command),
            check=False,
            shell=False,
            timeout=timeout_seconds,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ProcessResult(returncode=completed.returncode)
