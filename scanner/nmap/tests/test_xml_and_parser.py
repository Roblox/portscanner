# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from conftest import DOCUMENTATION_TARGET, contract_target, nmap_xml
from portscanner_scanner.coverage import PortCoverage
from portscanner_scanner.parser import ResultIntegrityError, parse_authoritative_result
from portscanner_scanner.result import RawArtifact, build_scan_result_payload
from portscanner_scanner.xml import (
    NmapXmlError,
    discovery_is_complete,
    extract_open_tcp_ports,
    parse_xml_bytes,
    validate_complete_scan,
)


def test_discovery_completeness_and_open_port_extraction(tmp_path):
    path = tmp_path / "raw.xml"
    path.write_bytes(
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 2),),
        )
    )
    coverage = PortCoverage.parse("80-82")

    report = validate_complete_scan(
        path,
        target=DOCUMENTATION_TARGET,
        coverage=coverage,
    )
    assert report.open_ports == frozenset({80})
    assert report.represented_port_count == 3
    assert extract_open_tcp_ports(path) == frozenset({80})
    assert discovery_is_complete(
        path,
        target=DOCUMENTATION_TARGET,
        coverage=coverage,
    )


@pytest.mark.parametrize(
    "raw",
    [
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 1),),
        ),
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 2),),
            finished=False,
        ),
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 2),),
            total_hosts=2,
        ),
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("open", 2),),
        ),
    ],
)
def test_incomplete_or_ambiguous_discovery_is_rejected(tmp_path, raw):
    path = tmp_path / "raw.xml"
    path.write_bytes(raw)
    with pytest.raises(NmapXmlError):
        validate_complete_scan(
            path,
            target=DOCUMENTATION_TARGET,
            coverage=PortCoverage.parse("80-82"),
        )


def test_host_timeout_is_incomplete(tmp_path):
    path = tmp_path / "raw.xml"
    raw = nmap_xml(
        explicit_states={80: "closed"},
    ).replace(b"<host>", b'<host timedout="true">', 1)
    path.write_bytes(raw)

    assert not discovery_is_complete(
        path,
        target=DOCUMENTATION_TARGET,
        coverage=PortCoverage.parse("80"),
    )


def test_defused_parser_rejects_entity_expansion():
    raw = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><nmaprun>&e;</nmaprun>'
    with pytest.raises(NmapXmlError):
        parse_xml_bytes(raw)


def _envelope(raw: bytes, *, complete: bool) -> dict:
    shared_target = contract_target()
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    artifact = RawArtifact(
        bucket="configured-results",
        key="prefix/raw.xml",
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    error = (
        None
        if complete
        else {
            "type": "discovery_incomplete",
            "message": "Nmap discovery XML did not prove complete coverage",
            "retryable": True,
        }
    )
    return build_scan_result_payload(
        event_id="1" * 64,
        directive_id="2" * 64,
        trace_id="trace-001",
        run_id="run-001",
        attempt_id="attempt-001",
        contract_target=shared_target,
        target=DOCUMENTATION_TARGET,
        target_id=shared_target.target_id,
        target_generation=3,
        profile="targeted-tcp",
        image_version=f"sha256:{'a' * 64}",
        coverage=PortCoverage.parse("80-82"),
        complete=complete,
        scanned_coverage_complete=complete,
        open_ports=(80,) if complete else (),
        started_at=timestamp,
        completed_at=timestamp,
        result_uploaded_at=timestamp,
        discovery_command={
            "argv": ["nmap", "-oX", "<raw-xml>", "<authorized-target>"],
            "timeout_seconds": 60,
            "exit_code": 0 if complete else None,
        },
        enrichment_command=None,
        outcome="complete" if complete else "partial",
        exit_code=0 if complete else None,
        raw_discovery=artifact,
        raw_enrichment=None,
        error=error,
    )


def test_parser_uses_envelope_correlation_and_hash_checks_xml():
    raw = nmap_xml(
        explicit_states={80: "open"},
        collapsed_states=(("closed", 2),),
        root_attributes='event_id="forged" trace_id="forged"',
    )
    parsed = parse_authoritative_result(_envelope(raw, complete=True), raw)

    assert parsed["event_id"] == "1" * 64
    assert parsed["trace_id"] == "trace-001"
    assert parsed["observations"] == [
        {
            "protocol": "tcp",
            "port": 80,
            "state": "OPEN",
            "nmap_state": "open",
        }
    ]
    assert parsed["collapsed_observations"][0]["state"] == "CLOSED"

    with pytest.raises(ResultIntegrityError, match="SHA-256"):
        parse_authoritative_result(_envelope(raw, complete=True), raw + b" ")


def test_partial_xml_never_proves_closure():
    raw = nmap_xml(
        explicit_states={80: "closed", 81: "open"},
        finished=False,
    )
    parsed = parse_authoritative_result(_envelope(raw, complete=False), raw)
    states = {item["port"]: item["state"] for item in parsed["observations"]}

    assert states == {80: "UNKNOWN", 81: "OPEN"}
    assert parsed["collapsed_observations"] == []
