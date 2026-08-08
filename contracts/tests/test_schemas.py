# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from portscanner_contracts import (
    Finding,
    ScanResultEnvelope,
    TargetEvent,
    TargetRemoval,
    parse_target_event,
    schema_document,
    target_event_schema_document,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
SCHEMAS = ROOT / "schemas"
CONTRACTS = [
    (TargetEvent, "target-event"),
    (ScanResultEnvelope, "scan-result"),
    (Finding, "finding"),
]
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _walk_dicts(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


@pytest.mark.parametrize(("model", "stem"), CONTRACTS)
def test_checked_in_schema_matches_model(
    model: type[TargetEvent] | type[ScanResultEnvelope] | type[Finding],
    stem: str,
) -> None:
    filename = f"{stem}.schema.json"
    checked_in = _read_json(SCHEMAS / filename)

    generated = (
        target_event_schema_document(filename)
        if model is TargetEvent
        else schema_document(model, filename)
    )
    assert checked_in == generated
    Draft202012Validator.check_schema(checked_in)


@pytest.mark.parametrize(("model", "stem"), CONTRACTS)
def test_synthetic_example_validates_with_schema_and_model(
    model: type[TargetEvent] | type[ScanResultEnvelope] | type[Finding],
    stem: str,
) -> None:
    schema = _read_json(SCHEMAS / f"{stem}.schema.json")
    example_path = EXAMPLES / f"{stem}.json"
    example = _read_json(example_path)

    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(example)
    assert model.from_json(example_path.read_text(encoding="utf-8")).to_dict() == example


@pytest.mark.parametrize(("model", "stem"), CONTRACTS)
def test_every_schema_object_is_closed(
    model: type[TargetEvent] | type[ScanResultEnvelope] | type[Finding],
    stem: str,
) -> None:
    del model
    schema = _read_json(SCHEMAS / f"{stem}.schema.json")
    object_schemas = [node for node in _walk_dicts(schema) if node.get("type") == "object"]

    assert object_schemas
    assert all(node.get("additionalProperties") is False for node in object_schemas)


@pytest.mark.parametrize(("_model", "stem"), CONTRACTS)
def test_schemas_reject_unknown_top_level_fields(
    _model: type[TargetEvent] | type[ScanResultEnvelope] | type[Finding],
    stem: str,
) -> None:
    schema = _read_json(SCHEMAS / f"{stem}.schema.json")
    example = _read_json(EXAMPLES / f"{stem}.json")
    example["provider_metadata"] = {"raw": "not-allowed"}

    assert not Draft202012Validator(schema).is_valid(example)


def test_target_event_schema_rejects_unknown_aws_context_fields() -> None:
    schema = _read_json(SCHEMAS / "target-event.schema.json")
    example = _read_json(EXAMPLES / "target-event.json")
    context = example["aws_context"]
    assert isinstance(context, dict)
    context["raw_provider_metadata"] = {"not": "allowed"}

    assert not Draft202012Validator(schema).is_valid(example)


def test_target_event_schema_is_one_of_work_or_removal() -> None:
    schema = _read_json(SCHEMAS / "target-event.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    work = _read_json(EXAMPLES / "target-event.json")
    removal = _read_json(EXAMPLES / "target-removal.json")

    assert {branch["$ref"] for branch in schema["oneOf"]} == {
        "#/$defs/TargetEvent",
        "#/$defs/TargetRemoval",
    }
    validator.validate(work)
    validator.validate(removal)
    assert isinstance(parse_target_event(removal), TargetRemoval)

    work.pop("scan")
    assert not validator.is_valid(work)
    removal["scan"] = _read_json(EXAMPLES / "target-event.json")["scan"]
    assert not validator.is_valid(removal)


def test_target_removal_example_round_trips_through_shared_parser() -> None:
    example_path = EXAMPLES / "target-removal.json"
    example = _read_json(example_path)

    parsed = parse_target_event(example_path.read_text(encoding="utf-8"))

    assert isinstance(parsed, TargetRemoval)
    assert parsed.to_dict() == example


def test_schema_requires_utc_rfc3339() -> None:
    schema = _read_json(SCHEMAS / "finding.schema.json")
    example = _read_json(EXAMPLES / "finding.json")
    finding = example["finding"]
    assert isinstance(finding, dict)
    finding["first_opened_at"] = "2026-01-15T02:02:18-08:00"

    assert not Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).is_valid(example)


def test_examples_use_only_documentation_public_addresses() -> None:
    for path in EXAMPLES.glob("*.json"):
        for node in _walk_dicts(_read_json(path)):
            for field in ("address", "observed_address", "public_address", "public_ip"):
                if field not in node:
                    continue
                address = ipaddress.ip_address(node[field])
                assert any(address in network for network in DOCUMENTATION_NETWORKS)


def test_finding_schema_enforces_kind_event_and_resolution_shape() -> None:
    schema = _read_json(SCHEMAS / "finding.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    missing_event = _read_json(EXAMPLES / "finding.json")
    missing_event.pop("event")
    assert not validator.is_valid(missing_event)

    invalid_reason = _read_json(EXAMPLES / "finding.json")
    event = invalid_reason["event"]
    assert isinstance(event, dict)
    event["reason"] = "service_changed"
    assert not validator.is_valid(invalid_reason)

    current = _read_json(EXAMPLES / "finding.json")
    current["kind"] = "current_finding"
    current.pop("event")
    validator.validate(current)

    finding = current["finding"]
    assert isinstance(finding, dict)
    finding["status"] = "resolved"
    assert not validator.is_valid(current)
