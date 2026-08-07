from __future__ import annotations

import pytest
from act_parser.models import CoverageDeclaration, ScanEnvelope, port_spec_bounds


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("22", (22, 22)),
        ("1-65535", (1, 65535)),
        ("nmap-default", (None, None)),
    ],
)
def test_port_spec_bounds(spec: str, expected: tuple[int | None, int | None]) -> None:
    assert port_spec_bounds(spec) == expected


@pytest.mark.parametrize("spec", ["0", "2-1", "65536", "all", "22,80"])
def test_invalid_port_specs_are_rejected(spec: str) -> None:
    with pytest.raises(ValueError):
        port_spec_bounds(spec)


def test_symbolic_coverage_cannot_close_by_absence() -> None:
    declaration = CoverageDeclaration.from_mapping(
        {"protocol": "tcp", "ports": ["nmap-default"], "complete": True}
    )[0]
    assert not declaration.contains("tcp", 22)


def test_incomplete_numeric_coverage_cannot_close_by_absence() -> None:
    declaration = CoverageDeclaration("tcp", "22", 22, None, True)

    assert not declaration.contains("tcp", 22)


def test_scan_envelope_uses_authoritative_nested_scan_result() -> None:
    digest = "a" * 64
    payload = {
        "attempt_id": "attempt-1",
        "run_id": "run-1",
        "event_id": digest,
        "directive_id": "b" * 64,
        "trace_id": "trace-1",
        "target": {
            "target_id": "c" * 64,
            "generation": 2,
            "address": "192.0.2.10",
        },
        "profile": "targeted-tcp",
        "image_version": f"sha256:{'d' * 64}",
        "outcome": "complete",
        "exit_code": 0,
        "error": None,
        "coverage": {"protocol": "tcp", "ports": ["22"], "complete": True},
        "timestamps": {
            "scan_started_at": "2026-01-02T03:04:00Z",
            "scan_completed_at": "2026-01-02T03:04:10Z",
            "result_uploaded_at": "2026-01-02T03:04:11Z",
        },
        "raw_result": {
            "bucket": "raw-test-bucket",
            "key": "events/example/raw/discovery.xml",
            "sha256": "e" * 64,
            "enrichment": {
                "bucket": "raw-test-bucket",
                "key": "events/example/raw/enrichment.xml",
                "sha256": "f" * 64,
            },
        },
        "scan_result": {
            "result_id": digest,
            "target": {"provider": "example-cloud"},
            "open_tcp_ports": [22],
        },
    }

    envelope = ScanEnvelope.from_mapping(payload)

    assert envelope.attempt_id == "attempt-1"
    assert envelope.result_id == digest
    assert envelope.provider == "example-cloud"
    assert envelope.declared_open_tcp_ports == (22,)
    assert envelope.enrichment_result is not None
    assert envelope.enrichment_result.sha256 == "f" * 64
