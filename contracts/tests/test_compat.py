# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from portscanner_contracts import ScanResultEnvelope, TargetEvent, validate_scan_result

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def test_target_event_accepts_a_decoded_json_mapping() -> None:
    payload = cast(
        dict[str, Any],
        json.loads((EXAMPLES / "target-event.json").read_text(encoding="utf-8")),
    )

    event = TargetEvent.model_validate(payload)

    assert event.target.address == "192.0.2.44"
    assert event.trace_id == event.event_id
    assert event.provider == event.target.provider


def _scanner_envelope() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((EXAMPLES / "scan-result.json").read_text(encoding="utf-8")),
    )


def test_scanner_envelope_adapter_is_closed_and_round_trips() -> None:
    payload = _scanner_envelope()

    assert validate_scan_result(payload) == payload
    assert ScanResultEnvelope.model_validate(payload).to_dict() == payload

    payload["unbounded"] = {}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        validate_scan_result(payload)


def test_scanner_envelope_checks_nested_typed_result() -> None:
    payload = _scanner_envelope()

    assert validate_scan_result(payload) == payload

    payload["event_id"] = "0" * 64
    with pytest.raises(ValidationError, match="nested ScanResult conflicts"):
        validate_scan_result(payload)

    payload = _scanner_envelope()
    coverage = cast(dict[str, Any], payload["coverage"])
    coverage["ports"] = ["22", "443", "8444"]
    with pytest.raises(ValidationError, match="nested ScanResult conflicts"):
        validate_scan_result(payload)


def test_scanner_envelope_rejects_raw_target_in_command_metadata() -> None:
    payload = _scanner_envelope()
    target = cast(dict[str, Any], payload["target"])
    commands = cast(dict[str, Any], payload["commands"])
    discovery = cast(dict[str, Any], commands["discovery"])
    argv = cast(list[str], discovery["argv"])
    argv.append(f"--target={target['address']}")

    with pytest.raises(ValidationError, match="redacted"):
        validate_scan_result(payload)


def test_scanner_envelope_rejects_unknown_nested_fields() -> None:
    payload = _scanner_envelope()
    nested = cast(dict[str, Any], payload["scan_result"])
    nested["provider_metadata"] = {}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        validate_scan_result(payload)
