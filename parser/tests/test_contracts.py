from __future__ import annotations

import json
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from act_parser.contracts import (
    ContractValidationError,
    parse_target_event,
    validate_finding,
    validate_scan_result,
)
from act_parser.database import Repository
from act_parser.models import ScanEnvelope


def test_uses_shared_validator_without_local_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[dict[str, object]] = []
    module = types.ModuleType("portscanner_contracts")

    def validator(payload: dict[str, object]) -> dict[str, object]:
        called.append(payload)
        return {**payload, "validated": True}

    module.validate_scan_result = validator  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "portscanner_contracts", module)

    payload = {"schema_version": "1.0"}
    assert validate_scan_result(payload)["validated"] is True
    assert called == [payload]


def test_rejects_non_mapping_model_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("portscanner_contracts")

    class InvalidModel:
        def model_dump(self, *, mode: str) -> list[str]:
            assert mode == "json"
            return []

    def validator(_payload: dict[str, object]) -> InvalidModel:
        return InvalidModel()

    module.validate_scan_result = validator  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "portscanner_contracts", module)

    with pytest.raises(ContractValidationError, match="unsupported value"):
        validate_scan_result({})


def test_wraps_shared_contract_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("portscanner_contracts")

    def validator(_payload: dict[str, object]) -> None:
        raise ValueError("invalid")

    module.validate_scan_result = validator  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "portscanner_contracts", module)

    with pytest.raises(ContractValidationError):
        validate_scan_result({})


def test_finding_adapter_uses_public_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[dict[str, object]] = []
    module = types.ModuleType("portscanner_contracts")

    def validator(payload: dict[str, object]) -> dict[str, object]:
        called.append(payload)
        return {**payload, "validated": True}

    module.validate_finding = validator  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "portscanner_contracts", module)

    payload = {"schema_version": "1.0"}
    assert validate_finding(payload)["validated"] is True
    assert called == [payload]


def test_target_event_uses_shared_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("portscanner_contracts")
    parsed = object()
    calls: list[dict[str, object]] = []

    def parser(payload: dict[str, object]) -> object:
        calls.append(payload)
        return parsed

    module.parse_target_event = parser  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "portscanner_contracts", module)
    payload = {"event_type": "target.upsert"}

    assert parse_target_event(payload) is parsed
    assert calls == [payload]


def test_accepts_authoritative_typed_scanner_envelope() -> None:
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
    )

    started_at = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
    completed_at = started_at + timedelta(seconds=10)
    target = Target.create(
        provider=CloudProvider.AWS,
        scope_id="000000000000",
        location="us-east-1",
        resource_id="eni-00000000",
        private_address="192.0.2.1",
        public_address="192.0.2.10",
        address_family=AddressFamily.IPV4,
        transport=TransportProtocol.TCP,
        generation=1,
    )
    scan_result = ScanResult.create(
        schema_version="1.0",
        event_id="a" * 64,
        directive_id="b" * 64,
        target=target,
        profile=ScanProfile.TARGETED_TCP,
        scanner=ScannerEngine.NMAP,
        scanner_version=f"sha256:{'c' * 64}",
        started_at=started_at,
        completed_at=completed_at,
        outcome=ScanOutcome.COMPLETE,
        requested_tcp_port_ranges=(TcpPortRange(start=22, end=22),),
        scanned_tcp_port_ranges=(TcpPortRange(start=22, end=22),),
        open_tcp_ports=(22,),
        exit_code=0,
        raw_result_sha256="d" * 64,
        error_code=None,
        error_message=None,
    )
    command = {
        "argv": ["nmap", "<authorized-target>", "-oX", "<raw-xml>"],
        "timeout_seconds": 60,
        "exit_code": 0,
    }
    envelope_payload = {
        "schema_version": "1.0",
        "event_id": "a" * 64,
        "directive_id": "b" * 64,
        "trace_id": "trace-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "target": {
            "target_id": target.target_id,
            "generation": 1,
            "address": "192.0.2.10",
        },
        "profile": "targeted-tcp",
        "image_version": f"sha256:{'c' * 64}",
        "coverage": {"protocol": "tcp", "ports": ["22"], "complete": True},
        "timestamps": {
            "scan_started_at": "2026-01-02T03:04:00Z",
            "scan_completed_at": "2026-01-02T03:04:10Z",
            "result_uploaded_at": "2026-01-02T03:04:11Z",
        },
        "commands": {"discovery": command, "enrichment": command},
        "outcome": "complete",
        "exit_code": 0,
        "raw_result": {
            "format": "nmap-xml",
            "bucket": "raw-test-bucket",
            "key": "events/example/raw/discovery.xml",
            "sha256": "d" * 64,
            "enrichment": {
                "bucket": "raw-test-bucket",
                "key": "events/example/raw/enrichment.xml",
                "sha256": "e" * 64,
            },
        },
        "error": None,
        "scan_result": scan_result.to_dict(),
    }

    envelope = ScanEnvelope.from_mapping(validate_scan_result(envelope_payload))

    assert envelope.result_id == scan_result.result_id
    assert envelope.attempt_id == "attempt-1"
    assert envelope.provider == "aws"
    assert envelope.declared_open_tcp_ports == (22,)


def test_repository_finding_payload_matches_committed_wire_example() -> None:
    example_path = Path(__file__).resolve().parents[2] / "examples" / "finding.json"
    expected = json.loads(example_path.read_text(encoding="utf-8"))
    finding = expected["finding"]
    event = expected["event"]
    service = finding["service"]

    def timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    row = {
        "fingerprint": finding["fingerprint"],
        "target_id": finding["target_id"],
        "provider": finding["provider"],
        "current_generation": finding["generation"],
        "protocol": finding["protocol"],
        "port": finding["port"],
        "rule_key": finding["rule_key"],
        "status": finding["status"],
        "severity": finding["severity"],
        "title": finding["title"],
        "description": finding["description"],
        "observed_address": finding["observed_address"],
        "service_name": service["name"],
        "service_product": service["product"],
        "service_version": service["version"],
        "certificate_sha256": service["certificate_sha256"],
        "ssh_host_key_sha256": service["ssh_host_key_sha256"],
        "banner_sha256": service["banner_sha256"],
        "service_identity_sha256": service["identity_sha256"],
        "first_opened_at": timestamp(finding["first_opened_at"]),
        "last_seen_at": timestamp(finding["last_seen_at"]),
        "last_changed_at": timestamp(finding["last_changed_at"]),
        "resolved_at": finding["resolved_at"],
        "resolution_reason": finding["resolution_reason"],
        "finding_version": finding["version"],
    }

    class Result:
        def fetchone(self) -> dict[str, Any]:
            return row

    class Connection:
        row_factory: Any = None
        autocommit = False

        def execute(self, *_args: Any, **_kwargs: Any) -> Result:
            return Result()

    repository = Repository(Connection())  # type: ignore[arg-type]
    event_row = {
        "event_key": event["event_key"],
        "event_type": event["event_type"],
        "previous_status": event["previous_status"],
        "new_status": event["new_status"],
        "reason": event["reason"],
        "occurred_at": timestamp(event["occurred_at"]),
        "source_kind": event["source"]["kind"],
        "source_key": event["source"]["key"],
    }

    assert (
        repository._finding_payload(
            finding["fingerprint"],
            kind="finding_event",
            event=event_row,
        )
        == expected
    )
