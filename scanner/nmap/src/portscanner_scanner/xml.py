# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Safe, non-reserializing Nmap XML validation and extraction."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from xml.etree import ElementTree

from defusedxml import ElementTree as DefusedElementTree
from defusedxml.common import DefusedXmlException

from .coverage import PortCoverage

MAX_XML_BYTES = 64 * 1024 * 1024


class NmapXmlError(ValueError):
    """Raised when Nmap XML cannot prove exact completed coverage."""


@dataclass(frozen=True)
class CollapsedState:
    nmap_state: str
    count: int


@dataclass(frozen=True)
class XmlScanReport:
    open_ports: frozenset[int]
    explicit_states: Mapping[int, str]
    collapsed_states: tuple[CollapsedState, ...]
    represented_port_count: int


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in element if _local_name(child.tag) == name]


def _one_child(
    element: ElementTree.Element,
    name: str,
) -> ElementTree.Element:
    children = _children(element, name)
    if len(children) != 1:
        raise NmapXmlError(f"Nmap XML must contain exactly one {name} element")
    return children[0]


def parse_xml_bytes(xml_bytes: bytes) -> ElementTree.Element:
    if not xml_bytes:
        raise NmapXmlError("Nmap XML is empty")
    if len(xml_bytes) > MAX_XML_BYTES:
        raise NmapXmlError("Nmap XML exceeds the configured safety limit")
    try:
        root = cast(ElementTree.Element, DefusedElementTree.fromstring(xml_bytes))
    except (DefusedXmlException, ElementTree.ParseError) as error:
        raise NmapXmlError("Nmap XML is incomplete or unsafe") from error
    if _local_name(root.tag) != "nmaprun":
        raise NmapXmlError("raw result does not have an nmaprun root")
    return root


def read_xml_bytes(path: str | Path) -> bytes:
    xml_path = Path(path)
    try:
        size = xml_path.stat().st_size
    except OSError as error:
        raise NmapXmlError("Nmap did not produce raw XML") from error
    if size <= 0 or size > MAX_XML_BYTES:
        raise NmapXmlError("Nmap XML has an invalid size")
    try:
        return xml_path.read_bytes()
    except OSError as error:
        raise NmapXmlError("Nmap XML could not be read") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _target_host(
    root: ElementTree.Element,
    expected_target: str,
) -> ElementTree.Element:
    hosts = _children(root, "host")
    if len(hosts) != 1:
        raise NmapXmlError("Nmap XML must describe exactly one target host")
    host = hosts[0]
    if host.get("timedout", "").lower() == "true":
        raise NmapXmlError("Nmap reported a host timeout")
    addresses = [
        item.get("addr") for item in _children(host, "address") if item.get("addrtype") == "ipv4"
    ]
    if addresses != [expected_target]:
        raise NmapXmlError("Nmap XML target does not match the envelope target")
    return host


def _validate_run_completion(root: ElementTree.Element) -> None:
    runstats = _one_child(root, "runstats")
    finished = _one_child(runstats, "finished")
    if finished.get("exit") != "success" or finished.get("errormsg"):
        raise NmapXmlError("Nmap did not report a successful finished run")
    hosts = _one_child(runstats, "hosts")
    try:
        total_hosts = int(hosts.get("total", ""))
    except ValueError as error:
        raise NmapXmlError("Nmap host totals are invalid") from error
    if total_hosts != 1:
        raise NmapXmlError("Nmap did not account for exactly one target host")


def validate_complete_scan_bytes(
    xml_bytes: bytes,
    *,
    target: str,
    coverage: PortCoverage,
) -> XmlScanReport:
    """Prove Nmap finished and represented every declared TCP port."""

    root = parse_xml_bytes(xml_bytes)
    _validate_run_completion(root)
    host = _target_host(root, target)
    ports_container = _one_child(host, "ports")

    explicit_states: dict[int, str] = {}
    for port_element in _children(ports_container, "port"):
        if port_element.get("protocol") != "tcp":
            raise NmapXmlError("Nmap XML contains an undeclared protocol")
        try:
            port = int(port_element.get("portid", ""))
        except ValueError as error:
            raise NmapXmlError("Nmap XML contains an invalid port") from error
        if not coverage.contains(port):
            raise NmapXmlError("Nmap XML contains a port outside declared coverage")
        if port in explicit_states:
            raise NmapXmlError("Nmap XML contains a duplicate port")
        state_element = _one_child(port_element, "state")
        state = state_element.get("state")
        if not state:
            raise NmapXmlError("Nmap XML contains a port without state")
        explicit_states[port] = state

    collapsed_states: list[CollapsedState] = []
    for collapsed in _children(ports_container, "extraports"):
        state = collapsed.get("state")
        try:
            count = int(collapsed.get("count", ""))
        except ValueError as error:
            raise NmapXmlError("Nmap collapsed-port count is invalid") from error
        if not state or count < 1:
            raise NmapXmlError("Nmap collapsed-port summary is invalid")
        if state == "open":
            raise NmapXmlError("Nmap collapsed open ports cannot be enriched safely")
        collapsed_states.append(CollapsedState(state, count))

    represented = len(explicit_states) + sum(item.count for item in collapsed_states)
    if represented != coverage.count:
        raise NmapXmlError("Nmap XML does not represent every declared TCP port")

    return XmlScanReport(
        open_ports=frozenset(port for port, state in explicit_states.items() if state == "open"),
        explicit_states=dict(sorted(explicit_states.items())),
        collapsed_states=tuple(collapsed_states),
        represented_port_count=represented,
    )


def validate_complete_scan(
    path: str | Path,
    *,
    target: str,
    coverage: PortCoverage,
) -> XmlScanReport:
    return validate_complete_scan_bytes(
        read_xml_bytes(path),
        target=target,
        coverage=coverage,
    )


def discovery_is_complete(
    path: str | Path,
    *,
    target: str,
    coverage: PortCoverage,
) -> bool:
    try:
        validate_complete_scan(path, target=target, coverage=coverage)
    except NmapXmlError:
        return False
    return True


def extract_open_tcp_ports(path: str | Path) -> frozenset[int]:
    """Extract explicit open TCP ports without treating omissions as closed."""

    root = parse_xml_bytes(read_xml_bytes(path))
    open_ports: set[int] = set()
    for host in _children(root, "host"):
        for ports_container in _children(host, "ports"):
            for port_element in _children(ports_container, "port"):
                if port_element.get("protocol") != "tcp":
                    continue
                state_elements = _children(port_element, "state")
                if len(state_elements) != 1 or state_elements[0].get("state") != "open":
                    continue
                try:
                    open_ports.add(int(port_element.get("portid", "")))
                except ValueError as error:
                    raise NmapXmlError("Nmap XML contains an invalid port") from error
    return frozenset(open_ports)


def nmap_state_to_observation(state: str) -> str:
    if state == "open":
        return "OPEN"
    if state == "closed":
        return "CLOSED"
    return "UNKNOWN"
