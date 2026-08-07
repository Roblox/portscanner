"""Build authoritative one-target Scanner custom resources."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .config import SCANNER_API_GROUP, SCANNER_API_VERSION

TARGET_HASH_LABEL = "scanning.portscanner.io/target-hash"
EVENT_HASH_LABEL = "scanning.portscanner.io/event-hash"
MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
READABLE_STATUS_ANNOTATION = "scanning.portscanner.io/readable-status"

REASON_STATUS: Mapping[str, str] = {
    "new_target": "New door",
    "target_change": "Changed door",
    "policy_change": "Changed door",
    "coverage": "Known door",
    "manual": "Manual verification",
}


def identifier_hash(value: str, *, length: int = 52) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("identifier must be a non-empty string")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def scanner_name(event_id: str) -> str:
    """Return a stable DNS-label-safe name derived only from the event ID."""

    return f"scan-{identifier_hash(event_id)}"


def target_hash(target_id: str) -> str:
    """Return the opaque label value shared by all generations of one target."""

    return identifier_hash(target_id)


def trace_id_for_event(event: Any) -> str:
    """Use an explicit trace ID when present, otherwise the opaque event ID."""

    trace_id = getattr(event, "trace_id", None)
    if isinstance(trace_id, str) and trace_id:
        return trace_id
    return _required_text(event.event_id, "event_id")


def _rfc3339(value: Any, field_name: str) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{field_name} must be an RFC3339 timestamp") from error
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise ValueError(f"{field_name} must be an RFC3339 timestamp")
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _port_range(value: Any) -> tuple[int, int]:
    if isinstance(value, Mapping):
        start = value.get("start")
        end = value.get("end")
    else:
        start = getattr(value, "start", None)
        end = getattr(value, "end", None)
    if (
        isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or not 1 <= start <= end <= 65535
    ):
        raise ValueError("scan TCP port range is invalid")
    return start, end


def _port_selection(
    event: Any,
    fallback_ports: Sequence[int] | None,
) -> tuple[list[int], list[dict[str, int]]]:
    contract_ranges = getattr(event.scan, "tcp_port_ranges", None)
    if contract_ranges is None:
        if fallback_ports is None:
            raise ValueError("scan directive has no explicit TCP ports")
        fallback_selection = sorted(set(fallback_ports))
        if any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in fallback_selection
        ):
            raise ValueError("ports must contain TCP port numbers")
        return fallback_selection, []

    ports: list[int] = []
    ranges: list[dict[str, int]] = []
    for value in contract_ranges:
        start, end = _port_range(value)
        if start == end:
            ports.append(start)
        else:
            ranges.append({"start": start, "end": end})
    if not ports and not ranges:
        raise ValueError("scan directive has no explicit TCP ports")
    return sorted(set(ports)), ranges


def build_scanner_resource(
    event: Any,
    *,
    namespace: str,
    ports: Sequence[int] | None = None,
    api_group: str = SCANNER_API_GROUP,
    api_version: str = SCANNER_API_VERSION,
) -> dict[str, Any]:
    """Build one v1alpha1 Scanner with authoritative correlation in ``spec``."""

    target = event.target
    if isinstance(target, (list, tuple, set, frozenset)):
        raise ValueError("a TargetEvent must contain exactly one target")
    target_id = _required_text(target.target_id, "target.target_id")
    address_value = getattr(target, "public_address", None)
    if address_value is None:
        address_value = getattr(target, "address", None)
    address = _required_text(address_value, "target.public_address")
    provider_value = getattr(target, "provider", None)
    provider = _required_text(
        getattr(provider_value, "value", provider_value),
        "target.provider",
    )
    scope_id = _required_text(getattr(target, "scope_id", None), "target.scope_id")
    location = _required_text(getattr(target, "location", None), "target.location")
    resource_id = _required_text(getattr(target, "resource_id", None), "target.resource_id")
    private_address = _required_text(
        getattr(target, "private_address", None),
        "target.private_address",
    )
    generation = target.generation
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ValueError("target.generation must be a positive integer")

    event_id = _required_text(event.event_id, "event_id")
    trace_id = trace_id_for_event(event)
    directive_id = _required_text(
        getattr(event.scan, "directive_id", None),
        "scan.directive_id",
    )
    reason = _required_text(event.scan.reason, "scan.reason")
    profile = _required_text(event.scan.profile, "scan.profile")
    if reason not in REASON_STATUS:
        raise ValueError("scan.reason has no readable status mapping")
    explicit_ports, explicit_ranges = _port_selection(event, ports)
    priority = event.scan.priority
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise ValueError("scan.priority must be an integer")

    source_timestamps = {
        "eventAt": _rfc3339(event.source.event_time, "source.event_time"),
        "observedAt": _rfc3339(event.source.observed_at, "source.observed_at"),
    }
    return {
        "apiVersion": f"{api_group}/{api_version}",
        "kind": "Scanner",
        "metadata": {
            "name": scanner_name(event_id),
            "namespace": namespace,
            "labels": {
                MANAGED_BY_LABEL: "portscanner-generator",
                TARGET_HASH_LABEL: target_hash(target_id),
                EVENT_HASH_LABEL: identifier_hash(event_id),
            },
            "annotations": {
                READABLE_STATUS_ANNOTATION: REASON_STATUS[reason],
            },
        },
        "spec": {
            "target": {
                "address": address,
                "targetId": target_id,
                "provider": provider,
                "scopeId": scope_id,
                "location": location,
                "resourceId": resource_id,
                "privateAddress": private_address,
                "generation": generation,
            },
            "eventId": event_id,
            "directiveId": directive_id,
            "traceId": trace_id,
            "reason": reason,
            "profile": profile,
            "ports": explicit_ports,
            "ranges": explicit_ranges,
            "priority": priority,
            "deadline": _rfc3339(event.scan.deadline_at, "scan.deadline_at"),
            "notAfter": _rfc3339(event.scan.not_after, "scan.not_after"),
            "sourceTimestamps": source_timestamps,
        },
    }
