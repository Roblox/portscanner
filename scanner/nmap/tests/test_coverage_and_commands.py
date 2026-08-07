# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest
from portscanner_scanner.coverage import (
    CoverageError,
    PortCoverage,
    normalize_port_coverage,
)
from portscanner_scanner.nmap import (
    NmapConfigurationError,
    NmapTuning,
    build_discovery_command,
    build_enrichment_command,
    redact_command,
    resolve_deep_scripts,
)


def test_coverage_normalization_is_deterministic():
    assert normalize_port_coverage("443,80-82,81-90,443,22,23") == (
        "22-23",
        "80-90",
        "443",
    )
    assert PortCoverage.parse(("90-100", "80-89")).nmap_spec == "80-100"


@pytest.mark.parametrize(
    "coverage",
    ["", "0", "65536", "90-80", "1,,2", "http", "+80", "1-2-3"],
)
def test_invalid_coverage_is_rejected(coverage):
    with pytest.raises(CoverageError):
        PortCoverage.parse(coverage)


def test_discovery_command_is_bounded_single_target_argv(tmp_path):
    output = tmp_path / "discovery.xml"
    tuning = NmapTuning()
    command = build_discovery_command(
        target="target-input",
        coverage=PortCoverage.full_tcp(),
        output_path=output,
        tuning=tuning,
    )

    assert command[0] == "nmap"
    assert command.count("target-input") == 1
    assert command[-1] == "target-input"
    assert command[command.index("-p") + 1] == "1-65535"
    assert command[command.index("--max-rate") + 1] == "500"
    assert command[command.index("--max-retries") + 1] == "2"
    assert command[command.index("-oX") + 1] == str(output)
    assert "-iL" not in command
    assert all("masscan" not in argument for argument in command)

    persisted = redact_command(
        command,
        target="target-input",
        output_path=output,
    )
    assert "target-input" not in persisted
    assert str(output) not in persisted
    assert persisted[-1] == "<authorized-target>"
    assert persisted[persisted.index("-oX") + 1] == "<raw-xml>"


def test_enrichment_is_limited_to_sorted_discovered_ports_and_safe_scripts(tmp_path):
    command = build_enrichment_command(
        target="<authorized-target>",
        open_ports=(8443, 443, 443),
        output_path=tmp_path / "enrichment.xml",
        tuning=NmapTuning(),
        scripts=("ssl-cert", "banner"),
    )

    assert command[command.index("-p") + 1] == "443,8443"
    assert command[command.index("--script") + 1] == "banner,ssl-cert"
    assert "--script-args" not in command
    assert "-sV" in command


def test_deep_scripts_must_be_in_configured_compiled_allowlist():
    assert resolve_deep_scripts(
        ("ssl-cert", "banner"),
        configured_allowlist=("banner", "ssl-cert"),
    ) == ("banner", "ssl-cert")
    with pytest.raises(NmapConfigurationError):
        resolve_deep_scripts(
            ("ssl-enum-ciphers",),
            configured_allowlist=("ssl-cert",),
        )
    with pytest.raises(NmapConfigurationError):
        resolve_deep_scripts(
            (),
            configured_allowlist=("arbitrary-script",),
        )


def test_tuning_rejects_unbounded_values():
    with pytest.raises(NmapConfigurationError):
        NmapTuning(max_rate=50_000)
    with pytest.raises(NmapConfigurationError):
        NmapTuning(discovery_retries=10)
    with pytest.raises(NmapConfigurationError):
        NmapTuning(
            discovery_host_timeout_seconds=1_200,
            discovery_process_timeout_seconds=1_200,
        )
