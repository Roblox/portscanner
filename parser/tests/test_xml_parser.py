from __future__ import annotations

from datetime import UTC, datetime

import pytest
from act_parser.xml_parser import merge_enrichment_observations, parse_nmap_xml
from defusedxml.common import EntitiesForbidden

OBSERVED_AT = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)


def test_normalizes_only_minimized_service_identity() -> None:
    xml = b"""<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="192.0.2.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="Example Server" version="1.2"/>
            <script id="ssl-cert" output="certificate identity material"/>
            <script id="banner" output="example service banner"/>
            <script id="unrelated" output="must never be normalized"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    observations = parse_nmap_xml(xml, target_address="192.0.2.10", observed_at=OBSERVED_AT)

    assert len(observations) == 1
    observation = observations[0]
    assert observation.state == "open"
    assert observation.service_name == "https"
    assert observation.service_product == "Example Server"
    assert observation.service_version == "1.2"
    assert len(observation.certificate_sha256 or "") == 64
    assert len(observation.banner_sha256 or "") == 64
    assert observation.ssh_host_key_sha256 is None
    assert len(observation.service_identity_sha256) == 64
    assert not hasattr(observation, "scripts")
    assert "identity material" not in repr(observation)


def test_selects_only_the_authoritative_target_address_and_maps_states() -> None:
    xml = b"""<nmaprun>
      <host>
        <address addr="192.0.2.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22"><state state="closed"/></port>
          <port protocol="tcp" portid="23"><state state="filtered"/></port>
          <port protocol="udp" portid="53"><state state="open|filtered"/></port>
        </ports>
      </host>
      <host>
        <address addr="192.0.2.11" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443"><state state="open"/></port>
        </ports>
      </host>
    </nmaprun>"""

    observations = parse_nmap_xml(xml, target_address="192.0.2.10", observed_at=OBSERVED_AT)
    assert [(item.protocol, item.port, item.state) for item in observations] == [
        ("tcp", 22, "closed"),
        ("tcp", 23, "filtered"),
        ("udp", 53, "unknown"),
    ]


def test_rejects_entity_expansion() -> None:
    xml = b"""<?xml version="1.0"?>
    <!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "https://example.invalid/entity">]>
    <nmaprun><host><address addr="192.0.2.10"/><ports>&xxe;</ports></host></nmaprun>
    """
    with pytest.raises(EntitiesForbidden):
        parse_nmap_xml(xml, target_address="192.0.2.10", observed_at=OBSERVED_AT)


def test_enrichment_overlays_identity_without_changing_discovery_scope() -> None:
    discovery = parse_nmap_xml(
        b"""<nmaprun><host><address addr="192.0.2.10"/><ports>
        <port protocol="tcp" portid="443"><state state="open"/></port>
        </ports></host></nmaprun>""",
        target_address="192.0.2.10",
        observed_at=OBSERVED_AT,
    )
    enrichment = parse_nmap_xml(
        b"""<nmaprun><host><address addr="192.0.2.10"/><ports>
        <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="Example Server" version="2.0"/>
        </port></ports></host></nmaprun>""",
        target_address="192.0.2.10",
        observed_at=OBSERVED_AT,
    )

    merged = merge_enrichment_observations(discovery, enrichment, require_complete=True)

    assert len(merged) == 1
    assert merged[0].service_product == "Example Server"
