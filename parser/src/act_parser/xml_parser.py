"""Minimal, entity-safe Nmap XML normalization."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from defusedxml import ElementTree

from .models import MAX_PORT, CoverageDeclaration, Observation, parse_address

_SPACE = re.compile(r"\s+")
_SCRIPT_IDENTITIES = {
    "ssl-cert": "certificate_sha256",
    "ssh-hostkey": "ssh_host_key_sha256",
    "banner": "banner_sha256",
}


class NmapXmlValidationError(ValueError):
    """Nmap XML cannot prove the completion claimed by its envelope."""


def _local_name(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _children(element: Any, name: str) -> list[Any]:
    return [child for child in element if _local_name(child.tag) == name]


def _one_child(element: Any, name: str) -> Any:
    children = _children(element, name)
    if len(children) != 1:
        raise NmapXmlValidationError(f"Nmap XML must contain exactly one {name} element")
    return children[0]


def _coverage_ranges(
    coverage: Sequence[CoverageDeclaration],
) -> tuple[dict[str, tuple[tuple[int, int], ...]], int]:
    if not coverage:
        raise NmapXmlValidationError("complete Nmap XML requires declared coverage")

    grouped: dict[str, list[tuple[int, int]]] = {}
    for declaration in coverage:
        if not declaration.complete or declaration.port_from is None or declaration.port_to is None:
            raise NmapXmlValidationError(
                "complete Nmap XML requires exact numeric complete coverage"
            )
        grouped.setdefault(declaration.protocol, []).append(
            (declaration.port_from, declaration.port_to)
        )

    merged: dict[str, tuple[tuple[int, int], ...]] = {}
    represented = 0
    for protocol, ranges in grouped.items():
        normalized: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if normalized and start <= normalized[-1][1] + 1:
                previous_start, previous_end = normalized[-1]
                normalized[-1] = (previous_start, max(previous_end, end))
            else:
                normalized.append((start, end))
        merged[protocol] = tuple(normalized)
        represented += sum(end - start + 1 for start, end in normalized)
    return merged, represented


def _in_coverage(
    coverage: dict[str, tuple[tuple[int, int], ...]],
    protocol: str,
    port: int,
) -> bool:
    return any(start <= port <= end for start, end in coverage.get(protocol, ()))


def _authorized_target_host(root: Any, target_address: str) -> Any:
    hosts = _children(root, "host")
    if len(hosts) != 1:
        raise NmapXmlValidationError("Nmap XML must describe exactly one target host")
    host = hosts[0]
    if str(host.get("timedout", "")).lower() in {"1", "true", "yes"}:
        raise NmapXmlValidationError("Nmap reported a host timeout")

    addresses: list[str] = []
    for address in _children(host, "address"):
        try:
            addresses.append(parse_address(address.get("addr")))
        except ValueError:
            continue
    if addresses != [target_address]:
        raise NmapXmlValidationError("Nmap XML target does not match the authorized target")
    return host


def _validate_complete_xml(  # noqa: PLR0912
    root: Any,
    *,
    target_address: str,
    coverage: Sequence[CoverageDeclaration],
) -> Any:
    runstats = _one_child(root, "runstats")
    finished = _one_child(runstats, "finished")
    if finished.get("exit") != "success" or finished.get("errormsg"):
        raise NmapXmlValidationError("Nmap did not report a successful finished run")
    host_totals = _one_child(runstats, "hosts")
    try:
        total_hosts = int(host_totals.get("total", ""))
    except ValueError as error:
        raise NmapXmlValidationError("Nmap host totals are invalid") from error
    if total_hosts != 1:
        raise NmapXmlValidationError("Nmap did not account for exactly one target host")

    host = _authorized_target_host(root, target_address)
    ports = _one_child(host, "ports")
    numeric_coverage, declared_count = _coverage_ranges(coverage)

    explicit: set[tuple[str, int]] = set()
    for port_node in _children(ports, "port"):
        protocol = str(port_node.get("protocol", "")).lower()
        try:
            port = int(port_node.get("portid", ""))
        except ValueError as error:
            raise NmapXmlValidationError("Nmap XML contains an invalid explicit port") from error
        key = (protocol, port)
        if not _in_coverage(numeric_coverage, protocol, port):
            raise NmapXmlValidationError(
                "Nmap XML contains an explicit port outside declared coverage"
            )
        if key in explicit:
            raise NmapXmlValidationError("Nmap XML contains a duplicate explicit port")
        state = _one_child(port_node, "state").get("state")
        if not state:
            raise NmapXmlValidationError("Nmap XML contains an explicit port without state")
        explicit.add(key)

    collapsed_count = 0
    for extraports in _children(ports, "extraports"):
        state = extraports.get("state")
        try:
            count = int(extraports.get("count", ""))
        except ValueError as error:
            raise NmapXmlValidationError("Nmap extraports count is invalid") from error
        if not state or count < 1 or state == "open":
            raise NmapXmlValidationError("Nmap extraports accounting is invalid")
        collapsed_count += count

    if collapsed_count and len(numeric_coverage) != 1:
        raise NmapXmlValidationError(
            "Nmap extraports cannot prove coverage across multiple protocols"
        )
    if len(explicit) + collapsed_count != declared_count:
        raise NmapXmlValidationError(
            "Nmap explicit and extraports accounting does not match declared coverage"
        )
    return host


def _minimized(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = _SPACE.sub(" ", value).strip()
    return normalized[:255] or None


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _script_identity(script: Any) -> str:
    """Canonicalize only long enough to hash; the source text is never returned."""
    output = _SPACE.sub(" ", script.get("output", "")).strip()
    nested = []
    for element in script.iter():
        if element is script:
            continue
        nested.append(
            {
                "tag": element.tag,
                "attributes": sorted(element.attrib.items()),
                "text": _SPACE.sub(" ", element.text or "").strip(),
            }
        )
    return json.dumps(
        {"output": output, "nested": nested},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def service_identity_sha256(
    *,
    service_name: str | None,
    service_product: str | None,
    service_version: str | None,
    certificate_sha256: str | None,
    ssh_host_key_sha256: str | None,
    banner_sha256: str | None,
) -> str:
    canonical = json.dumps(
        {
            "banner_sha256": banner_sha256,
            "certificate_sha256": certificate_sha256,
            "service_name": service_name,
            "service_product": service_product,
            "service_version": service_version,
            "ssh_host_key_sha256": ssh_host_key_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return _digest(canonical)


def _normalize_state(value: str | None) -> str:
    if value == "open":
        return "open"
    if value == "closed":
        return "closed"
    if value == "filtered":
        return "filtered"
    return "unknown"


def parse_nmap_xml(  # noqa: PLR0912
    xml: bytes,
    *,
    target_address: str,
    observed_at: datetime,
    coverage: Sequence[CoverageDeclaration] | None = None,
    require_complete: bool = False,
) -> list[Observation]:
    """Extract one deterministic observation per target/protocol/port."""
    normalized_target = parse_address(target_address, "target_address")
    if not xml:
        raise NmapXmlValidationError("Nmap XML is empty")
    root = ElementTree.fromstring(xml)
    if _local_name(root.tag) != "nmaprun":
        raise ValueError("scan result root must be nmaprun")

    if require_complete:
        if coverage is None:
            raise NmapXmlValidationError("complete Nmap XML requires declared coverage")
        hosts = [
            _validate_complete_xml(
                root,
                target_address=normalized_target,
                coverage=coverage,
            )
        ]
    else:
        hosts = _children(root, "host")

    observations: dict[tuple[str, int], Observation] = {}
    for host in hosts:
        host_addresses = []
        for address in _children(host, "address"):
            try:
                host_addresses.append(parse_address(address.get("addr")))
            except ValueError:
                continue
        if normalized_target not in host_addresses:
            continue

        for ports_node in _children(host, "ports"):
            for port_node in _children(ports_node, "port"):
                protocol = (port_node.get("protocol") or "").lower()
                try:
                    port = int(port_node.get("portid", ""))
                except ValueError as error:
                    raise ValueError("Nmap portid must be an integer") from error
                if not protocol or not 1 <= port <= MAX_PORT:
                    raise ValueError("Nmap protocol or port is invalid")

                state_nodes = _children(port_node, "state")
                state_node = state_nodes[0] if state_nodes else None
                state = _normalize_state(None if state_node is None else state_node.get("state"))
                service_nodes = _children(port_node, "service")
                service_node = service_nodes[0] if service_nodes else None
                service_name = _minimized(
                    None if service_node is None else service_node.get("name")
                )
                service_product = _minimized(
                    None if service_node is None else service_node.get("product")
                )
                service_version = _minimized(
                    None if service_node is None else service_node.get("version")
                )

                hashes: dict[str, str | None] = {
                    "certificate_sha256": None,
                    "ssh_host_key_sha256": None,
                    "banner_sha256": None,
                }
                for script in _children(port_node, "script"):
                    destination = _SCRIPT_IDENTITIES.get(script.get("id", ""))
                    if destination is not None:
                        hashes[destination] = _digest(_script_identity(script))

                identity = service_identity_sha256(
                    service_name=service_name,
                    service_product=service_product,
                    service_version=service_version,
                    certificate_sha256=hashes["certificate_sha256"],
                    ssh_host_key_sha256=hashes["ssh_host_key_sha256"],
                    banner_sha256=hashes["banner_sha256"],
                )
                observation = Observation(
                    protocol=protocol,
                    port=port,
                    observed_address=normalized_target,
                    state=state,
                    service_name=service_name,
                    service_product=service_product,
                    service_version=service_version,
                    certificate_sha256=hashes["certificate_sha256"],
                    ssh_host_key_sha256=hashes["ssh_host_key_sha256"],
                    banner_sha256=hashes["banner_sha256"],
                    service_identity_sha256=identity,
                    observed_at=observed_at,
                )
                key = (protocol, port)
                previous = observations.get(key)
                if previous is not None and previous != observation:
                    raise ValueError("scan contains conflicting observations for one service")
                observations[key] = observation

    return [observations[key] for key in sorted(observations)]


def merge_enrichment_observations(
    discovery: list[Observation],
    enrichment: list[Observation],
    *,
    require_complete: bool,
) -> list[Observation]:
    """Overlay minimized enrichment attributes without changing discovery state."""
    merged = {(item.protocol, item.port): item for item in discovery}
    expected_open = {key for key, item in merged.items() if item.state == "open"}
    enriched: set[tuple[str, int]] = set()
    for item in enrichment:
        key = (item.protocol, item.port)
        baseline = merged.get(key)
        if (
            baseline is None
            or baseline.state != "open"
            or item.state != "open"
            or baseline.observed_address != item.observed_address
        ):
            raise ValueError("enrichment XML conflicts with discovery evidence")
        merged[key] = item
        enriched.add(key)
    if require_complete and enriched != expected_open:
        raise ValueError("enrichment XML does not cover every discovered open port")
    return [merged[key] for key in sorted(merged)]
