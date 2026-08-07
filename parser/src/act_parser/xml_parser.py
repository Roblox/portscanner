"""Minimal, entity-safe Nmap XML normalization."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from defusedxml import ElementTree

from .models import MAX_PORT, Observation, parse_address

_SPACE = re.compile(r"\s+")
_SCRIPT_IDENTITIES = {
    "ssl-cert": "certificate_sha256",
    "ssh-hostkey": "ssh_host_key_sha256",
    "banner": "banner_sha256",
}


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


def parse_nmap_xml(
    xml: bytes,
    *,
    target_address: str,
    observed_at: datetime,
) -> list[Observation]:
    """Extract one deterministic observation per target/protocol/port."""
    normalized_target = parse_address(target_address, "target_address")
    root = ElementTree.fromstring(xml)
    if root.tag != "nmaprun":
        raise ValueError("scan result root must be nmaprun")

    observations: dict[tuple[str, int], Observation] = {}
    for host in root.findall("host"):
        host_addresses = []
        for address in host.findall("address"):
            try:
                host_addresses.append(parse_address(address.get("addr")))
            except ValueError:
                continue
        if normalized_target not in host_addresses:
            continue

        for port_node in host.findall("./ports/port"):
            protocol = (port_node.get("protocol") or "").lower()
            try:
                port = int(port_node.get("portid", ""))
            except ValueError as error:
                raise ValueError("Nmap portid must be an integer") from error
            if not protocol or not 1 <= port <= MAX_PORT:
                raise ValueError("Nmap protocol or port is invalid")

            state_node = port_node.find("state")
            state = _normalize_state(None if state_node is None else state_node.get("state"))
            service_node = port_node.find("service")
            service_name = _minimized(None if service_node is None else service_node.get("name"))
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
            for script in port_node.findall("script"):
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
