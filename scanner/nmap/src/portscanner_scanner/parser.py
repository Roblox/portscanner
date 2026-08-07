# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Parse raw Nmap facts using ScanResult as authoritative correlation."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from .coverage import PortCoverage
from .result import validate_scan_result
from .xml import (
    NmapXmlError,
    nmap_state_to_observation,
    parse_xml_bytes,
    validate_complete_scan_bytes,
)


class ResultIntegrityError(ValueError):
    """Raised when an envelope and its raw XML do not form one trusted result."""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: Any, name: str) -> list[Any]:
    return [child for child in element if _local_name(child.tag) == name]


def _partial_explicit_states(
    xml_bytes: bytes,
    *,
    target: str,
    coverage: PortCoverage,
) -> dict[int, str]:
    root = parse_xml_bytes(xml_bytes)
    hosts = _children(root, "host")
    if len(hosts) != 1:
        raise ResultIntegrityError("raw XML does not describe the envelope target")
    addresses = [
        item.get("addr")
        for item in _children(hosts[0], "address")
        if item.get("addrtype") == "ipv4"
    ]
    if addresses != [target]:
        raise ResultIntegrityError("raw XML target does not match ScanResult")

    states: dict[int, str] = {}
    for ports_element in _children(hosts[0], "ports"):
        for port_element in _children(ports_element, "port"):
            if port_element.get("protocol") != "tcp":
                continue
            try:
                port = int(port_element.get("portid", ""))
            except ValueError as error:
                raise ResultIntegrityError("raw XML contains an invalid TCP port") from error
            if port in states or not coverage.contains(port):
                raise ResultIntegrityError("raw XML port conflicts with declared coverage")
            state_elements = _children(port_element, "state")
            if len(state_elements) != 1 or not state_elements[0].get("state"):
                raise ResultIntegrityError("raw XML port state is invalid")
            states[port] = state_elements[0].get("state")
    return states


def _observation_state(
    nmap_state: str,
    *,
    complete: bool,
    enrichment_set_changed: bool,
) -> str:
    if complete:
        return nmap_state_to_observation(nmap_state)
    if enrichment_set_changed:
        # Discovery and enrichment observed different open sets. Neither phase
        # is authoritative for a state transition in this attempt.
        return "UNKNOWN"
    # A partial run can retain positive OPEN evidence. It can never prove
    # closure for any port because Nmap did not finish the declared work.
    return "OPEN" if nmap_state == "open" else "UNKNOWN"


def parse_authoritative_result(
    envelope: Mapping[str, Any],
    raw_xml: bytes,
) -> dict[str, Any]:
    """Hash-check XML and correlate it only from the shared ScanResult envelope."""

    canonical = validate_scan_result(envelope)
    raw_result = canonical.get("raw_result")
    if not isinstance(raw_result, Mapping) or raw_result.get("format") != "nmap-xml":
        raise ResultIntegrityError("ScanResult has no Nmap XML artifact")
    expected_hash = raw_result.get("sha256")
    actual_hash = hashlib.sha256(raw_xml).hexdigest()
    if not isinstance(expected_hash, str) or not hmac.compare_digest(expected_hash, actual_hash):
        raise ResultIntegrityError("raw Nmap XML SHA-256 does not match ScanResult")

    target = canonical.get("target")
    coverage_payload = canonical.get("coverage")
    if not isinstance(target, Mapping) or not isinstance(coverage_payload, Mapping):
        raise ResultIntegrityError("ScanResult target or coverage is invalid")
    target_address = target.get("address")
    declared_ports = coverage_payload.get("ports")
    if not isinstance(target_address, str) or not isinstance(declared_ports, list):
        raise ResultIntegrityError("ScanResult target or coverage is invalid")
    try:
        coverage = PortCoverage.parse(declared_ports)
    except ValueError as error:
        raise ResultIntegrityError("ScanResult coverage is invalid") from error
    if list(coverage.as_strings()) != declared_ports:
        raise ResultIntegrityError("ScanResult coverage is not canonical")

    complete = coverage_payload.get("complete") is True
    error_payload = canonical.get("error")
    enrichment_set_changed = (
        isinstance(error_payload, Mapping)
        and error_payload.get("type") == "enrichment_port_set_changed"
    )
    try:
        if complete:
            report = validate_complete_scan_bytes(
                raw_xml,
                target=target_address,
                coverage=coverage,
            )
            explicit_states = dict(report.explicit_states)
            collapsed = [
                {
                    "state": nmap_state_to_observation(item.nmap_state),
                    "nmap_state": item.nmap_state,
                    "count": item.count,
                }
                for item in report.collapsed_states
            ]
        else:
            explicit_states = _partial_explicit_states(
                raw_xml,
                target=target_address,
                coverage=coverage,
            )
            collapsed = []
    except NmapXmlError as error:
        raise ResultIntegrityError("raw Nmap XML failed completeness checks") from error

    observations = []
    for port, nmap_state in sorted(explicit_states.items()):
        observations.append(
            {
                "protocol": "tcp",
                "port": port,
                "state": _observation_state(
                    nmap_state,
                    complete=complete,
                    enrichment_set_changed=enrichment_set_changed,
                ),
                "nmap_state": nmap_state,
            }
        )

    return {
        "event_id": canonical["event_id"],
        "directive_id": canonical["directive_id"],
        "trace_id": canonical["trace_id"],
        "run_id": canonical["run_id"],
        "attempt_id": canonical["attempt_id"],
        "target": dict(target),
        "profile": canonical["profile"],
        "coverage": dict(coverage_payload),
        "observations": observations,
        "collapsed_observations": collapsed,
    }
