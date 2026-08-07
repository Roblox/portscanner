# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import runpy
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from portscanner_contracts import (
    AWS_TAG_KEYS,
    FULL_TCP_PORT_RANGE,
    AddressFamily,
    AwsContext,
    CloudProvider,
    ContractModel,
    Finding,
    FindingEventType,
    FindingKind,
    FindingSeverity,
    FindingStatus,
    ScanDirective,
    ScanOutcome,
    ScanProfile,
    ScanReason,
    ScanResultEnvelope,
    Target,
    TargetEvent,
    TargetEventType,
    TargetRemoval,
    TransportProtocol,
    parse_target_event,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def test_checked_in_examples_match_generator() -> None:
    filenames = (
        "target-event.json",
        "target-removal.json",
        "scan-result.json",
        "finding.json",
    )

    generator = runpy.run_path(str(EXAMPLES / "generate.py"))
    build_examples = cast(
        Callable[[], tuple[ContractModel, ...]],
        generator["build_examples"],
    )

    for filename, document in zip(filenames, build_examples(), strict=True):
        assert json.loads(document.to_json()) == _load(EXAMPLES / filename)


@pytest.mark.parametrize(
    ("model", "filename"),
    [
        (TargetEvent, "target-event.json"),
        (TargetRemoval, "target-removal.json"),
        (ScanResultEnvelope, "scan-result.json"),
        (Finding, "finding.json"),
    ],
)
def test_json_round_trip(
    model: type[TargetEvent] | type[TargetRemoval] | type[ScanResultEnvelope] | type[Finding],
    filename: str,
) -> None:
    raw = (EXAMPLES / filename).read_text(encoding="utf-8")
    parsed = model.from_json(raw)

    assert model.from_json(parsed.to_json()) == parsed
    assert json.loads(parsed.to_json()) == json.loads(raw)


def test_target_identity_ignores_mutable_public_state() -> None:
    event = TargetEvent.from_json((EXAMPLES / "target-event.json").read_text(encoding="utf-8"))
    target = event.target
    replacement = Target.create(
        provider=target.provider,
        scope_id=target.scope_id,
        location=target.location,
        resource_id=target.resource_id,
        private_address=target.private_address,
        public_address="198.51.100.61",
        address_family=target.address_family,
        transport=target.transport,
        generation=target.generation + 1,
    )

    assert replacement.target_id == target.target_id
    assert replacement.public_address != target.public_address
    assert replacement.generation != target.generation


def test_tampered_deterministic_id_is_rejected() -> None:
    payload = _load(EXAMPLES / "target-event.json")
    target = payload["target"]
    assert isinstance(target, dict)
    target["target_id"] = "0" * 64

    with pytest.raises(ValidationError, match="deterministic SHA-256"):
        TargetEvent.from_json(json.dumps(payload))


def test_target_event_union_round_trips_work_and_removal_documents() -> None:
    work_payload = _load(EXAMPLES / "target-event.json")
    removal_payload = _load(EXAMPLES / "target-removal.json")

    work = parse_target_event(work_payload)
    removal = parse_target_event(json.dumps(removal_payload))

    assert isinstance(work, TargetEvent)
    assert isinstance(removal, TargetRemoval)
    assert parse_target_event(work.to_json()) == work
    assert parse_target_event(removal.to_dict()) == removal
    assert removal.trace_id == removal.event_id
    assert set(TargetRemoval.model_fields) == {
        "schema_version",
        "event_id",
        "event_type",
        "target",
        "source",
        "aws_context",
        "removed_at",
    }
    assert "scan" not in removal.to_dict()
    with pytest.raises(ValidationError, match="frozen"):
        removal.removed_at = removal.source.collected_at  # type: ignore[misc]


def test_target_removal_rejects_tampering_and_extra_scan() -> None:
    payload = _load(EXAMPLES / "target-removal.json")
    payload["event_id"] = "0" * 64
    with pytest.raises(ValidationError, match="deterministic SHA-256"):
        parse_target_event(payload)

    payload = _load(EXAMPLES / "target-removal.json")
    payload["scan"] = _load(EXAMPLES / "target-event.json")["scan"]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_target_event(payload)


def test_target_removal_validates_context_and_timeline() -> None:
    payload = _load(EXAMPLES / "target-removal.json")
    payload.pop("event_id")
    context = cast(dict[str, Any], payload["aws_context"])
    context["public_ip"] = "198.51.100.61"
    with pytest.raises(ValidationError, match="must match aws_context"):
        TargetRemoval.create(**payload)

    payload = _load(EXAMPLES / "target-removal.json")
    payload.pop("event_id")
    context = cast(dict[str, Any], payload["aws_context"])
    context["source_event_id"] = "different-source-event"
    with pytest.raises(ValidationError, match="source observation must match"):
        TargetRemoval.create(**payload)

    payload = _load(EXAMPLES / "target-removal.json")
    payload.pop("event_id")
    payload["removed_at"] = "2026-01-15T10:59:59Z"
    with pytest.raises(ValidationError, match=r"source\.collected_at"):
        TargetRemoval.create(**payload)


def test_work_target_event_requires_scan() -> None:
    payload = _load(EXAMPLES / "target-event.json")
    payload.pop("scan")

    with pytest.raises(ValidationError, match="Field required"):
        parse_target_event(payload)


def test_target_change_is_a_full_tcp_target_upsert_without_policy_change() -> None:
    policy_event = TargetEvent.from_json(
        (EXAMPLES / "target-event.json").read_text(encoding="utf-8")
    )
    context = AwsContext.model_validate(
        {
            **policy_event.aws_context.to_dict(),
            "candidate_tcp_port_ranges": (FULL_TCP_PORT_RANGE,),
        }
    )
    directive = ScanDirective.create(
        target_id=policy_event.target.target_id,
        target_generation=policy_event.target.generation,
        reason=ScanReason.TARGET_CHANGE,
        profile=ScanProfile.FAST_FULL_TCP,
        priority=200,
        requested_at=policy_event.scan.requested_at,
        deadline_at=policy_event.scan.deadline_at,
        not_after=policy_event.scan.not_after,
        tcp_port_ranges=(FULL_TCP_PORT_RANGE,),
    )

    event = TargetEvent.create(
        schema_version="1.0",
        event_type=TargetEventType.TARGET_UPSERT,
        target=policy_event.target,
        source=policy_event.source,
        policy_change=None,
        scan=directive,
        aws_context=context,
    )

    assert event.scan.reason is ScanReason.TARGET_CHANGE
    assert event.event_type is TargetEventType.TARGET_UPSERT
    assert event.scan.profile is ScanProfile.FAST_FULL_TCP
    assert event.scan.tcp_port_ranges == (FULL_TCP_PORT_RANGE,)
    assert event.policy_change is None


def test_target_change_rejects_wrong_event_profile_and_policy_context() -> None:
    policy_event = TargetEvent.from_json(
        (EXAMPLES / "target-event.json").read_text(encoding="utf-8")
    )
    context = AwsContext.model_validate(
        {
            **policy_event.aws_context.to_dict(),
            "candidate_tcp_port_ranges": (FULL_TCP_PORT_RANGE,),
        }
    )
    full_scan = ScanDirective.create(
        target_id=policy_event.target.target_id,
        target_generation=policy_event.target.generation,
        reason=ScanReason.TARGET_CHANGE,
        profile=ScanProfile.FAST_FULL_TCP,
        priority=200,
        requested_at=policy_event.scan.requested_at,
        deadline_at=policy_event.scan.deadline_at,
        not_after=policy_event.scan.not_after,
        tcp_port_ranges=(FULL_TCP_PORT_RANGE,),
    )
    targeted_scan = ScanDirective.create(
        target_id=policy_event.target.target_id,
        target_generation=policy_event.target.generation,
        reason=ScanReason.TARGET_CHANGE,
        profile=ScanProfile.TARGETED_TCP,
        priority=200,
        requested_at=policy_event.scan.requested_at,
        deadline_at=policy_event.scan.deadline_at,
        not_after=policy_event.scan.not_after,
        tcp_port_ranges=policy_event.scan.tcp_port_ranges,
    )
    shared = {
        "schema_version": "1.0",
        "target": policy_event.target,
        "source": policy_event.source,
        "aws_context": context,
    }

    with pytest.raises(ValidationError, match="event_type must match"):
        TargetEvent.create(
            **shared,
            event_type=TargetEventType.POLICY_CHANGED,
            policy_change=None,
            scan=full_scan,
        )
    with pytest.raises(ValidationError, match="fast-full-tcp"):
        TargetEvent.create(
            **shared,
            event_type=TargetEventType.TARGET_UPSERT,
            policy_change=None,
            scan=targeted_scan,
        )
    with pytest.raises(ValidationError, match="full TCP coverage"):
        TargetEvent.create(
            **{**shared, "aws_context": policy_event.aws_context},
            event_type=TargetEventType.TARGET_UPSERT,
            policy_change=None,
            scan=full_scan,
        )
    with pytest.raises(ValidationError, match="only valid for policy_change"):
        TargetEvent.create(
            **shared,
            event_type=TargetEventType.TARGET_UPSERT,
            policy_change=policy_event.policy_change,
            scan=full_scan,
        )


def test_models_are_frozen() -> None:
    event = TargetEvent.from_json((EXAMPLES / "target-event.json").read_text(encoding="utf-8"))

    with pytest.raises(ValidationError, match="frozen"):
        event.target.generation = 4  # type: ignore[misc]


def test_extra_fields_and_coercion_are_rejected() -> None:
    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    finding["provider_metadata"] = {"unbounded": True}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Finding.from_json(json.dumps(payload))

    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    finding["port"] = "443"
    with pytest.raises(ValidationError, match="valid integer"):
        Finding.from_json(json.dumps(payload))


def test_non_ipv4_and_non_utc_values_are_rejected() -> None:
    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    finding["observed_address"] = "2001:db8::44"
    with pytest.raises(ValidationError, match="valid IPv4"):
        Finding.from_json(json.dumps(payload))

    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    finding["observed_address"] = "10.24.8.17"
    with pytest.raises(ValidationError, match="public IPv4"):
        Finding.from_json(json.dumps(payload))

    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    finding["first_opened_at"] = "2026-01-15T02:02:18-08:00"
    with pytest.raises(ValidationError, match="UTC RFC3339"):
        Finding.from_json(json.dumps(payload))


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-01-15T10:02:18+00:00",
        "2026-01-15T10:02:18",
        "2026-01-15T10:02:18.1234567Z",
    ],
)
def test_timestamps_require_canonical_utc_rfc3339(timestamp: str) -> None:
    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    finding["first_opened_at"] = timestamp

    with pytest.raises(ValidationError, match="UTC RFC3339"):
        Finding.from_json(json.dumps(payload))


def test_finding_kind_event_and_resolution_consistency() -> None:
    payload = _load(EXAMPLES / "finding.json")
    payload.pop("event")
    with pytest.raises(ValidationError, match="require event"):
        Finding.model_validate(payload)

    current = _load(EXAMPLES / "finding.json")
    current["kind"] = "current_finding"
    current.pop("event")
    assert "event" not in Finding.model_validate(current).to_dict()

    current["event"] = None
    with pytest.raises(ValidationError, match="must omit event"):
        Finding.model_validate(current)

    invalid_transition = _load(EXAMPLES / "finding.json")
    event = cast(dict[str, Any], invalid_transition["event"])
    event["new_status"] = "resolved"
    with pytest.raises(ValidationError, match="statuses must match"):
        Finding.model_validate(invalid_transition)

    invalid_reason = _load(EXAMPLES / "finding.json")
    event = cast(dict[str, Any], invalid_reason["event"])
    event["reason"] = "service_changed"
    with pytest.raises(ValidationError, match="reason must match"):
        Finding.model_validate(invalid_reason)

    invalid_resolution = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], invalid_resolution["finding"])
    finding["status"] = "resolved"
    with pytest.raises(ValidationError, match="require resolution fields"):
        Finding.model_validate(invalid_resolution)


def test_finding_rejects_invalid_service_digest() -> None:
    payload = _load(EXAMPLES / "finding.json")
    finding = cast(dict[str, Any], payload["finding"])
    service = cast(dict[str, Any], finding["service"])
    service["identity_sha256"] = "not-a-sha256"

    with pytest.raises(ValidationError, match="String should match pattern"):
        Finding.model_validate(payload)


def test_aws_context_is_closed_and_bounded() -> None:
    assert set(AwsContext.model_fields) == {
        "account_id",
        "region",
        "network_interface_id",
        "private_ip",
        "public_ip",
        "instance_id",
        "security_group_ids",
        "policy_fingerprint",
        "candidate_tcp_port_ranges",
        "source_event_name",
        "source_event_id",
        "source_request_id",
        "tags",
    }
    assert {"application", "environment", "name", "service"} == AWS_TAG_KEYS

    payload = _load(EXAMPLES / "target-event.json")
    context = payload["aws_context"]
    assert isinstance(context, dict)
    context["security_group_ids"] = list(reversed(context["security_group_ids"]))
    with pytest.raises(ValidationError, match="sorted and unique"):
        TargetEvent.from_json(json.dumps(payload))


def test_contract_vocabulary_is_exact() -> None:
    assert {item.value for item in ScanReason} == {
        "new_target",
        "target_change",
        "policy_change",
        "coverage",
        "manual",
    }
    assert {item.value for item in ScanProfile} == {
        "fast-full-tcp",
        "targeted-tcp",
        "deep",
    }
    assert {item.value for item in ScanOutcome} == {
        "complete",
        "partial",
        "failed",
        "cancelled",
        "freshness_rejected",
    }
    assert list(CloudProvider) == [CloudProvider.AWS]
    assert list(AddressFamily) == [AddressFamily.IPV4]
    assert list(TransportProtocol) == [TransportProtocol.TCP]
    assert {item.value for item in TargetEventType} == {
        "target.upsert",
        "target.removed",
        "policy.changed",
        "rescan.requested",
    }
    assert {item.value for item in FindingKind} == {
        "finding_event",
        "current_finding",
    }
    assert {item.value for item in FindingStatus} == {"open", "resolved"}
    assert {item.value for item in FindingSeverity} == {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }
    assert {item.value for item in FindingEventType} == {
        "opened",
        "reopened",
        "updated",
        "resolved",
    }


def test_contract_json_size_is_bounded() -> None:
    oversized = b"{" + (b" " * (64 * 1024)) + b"}"

    with pytest.raises(ValueError, match="exceeds"):
        TargetEvent.from_json(oversized)
