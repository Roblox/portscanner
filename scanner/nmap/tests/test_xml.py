# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest
from conftest import DOCUMENTATION_TARGET, nmap_xml
from portscanner_scanner.coverage import PortCoverage
from portscanner_scanner.xml import (
    NmapXmlError,
    discovery_is_complete,
    extract_open_tcp_ports,
    parse_xml_bytes,
    validate_complete_scan,
)


def test_discovery_completeness_and_open_port_extraction(tmp_path):
    path = tmp_path / "raw.xml"
    path.write_bytes(
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 2),),
        )
    )
    coverage = PortCoverage.parse("80-82")

    report = validate_complete_scan(
        path,
        target=DOCUMENTATION_TARGET,
        coverage=coverage,
    )
    assert report.open_ports == frozenset({80})
    assert report.represented_port_count == 3
    assert extract_open_tcp_ports(path) == frozenset({80})
    assert discovery_is_complete(
        path,
        target=DOCUMENTATION_TARGET,
        coverage=coverage,
    )


@pytest.mark.parametrize(
    "raw",
    [
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 1),),
        ),
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 2),),
            finished=False,
        ),
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("closed", 2),),
            total_hosts=2,
        ),
        nmap_xml(
            explicit_states={80: "open"},
            collapsed_states=(("open", 2),),
        ),
    ],
)
def test_incomplete_or_ambiguous_discovery_is_rejected(tmp_path, raw):
    path = tmp_path / "raw.xml"
    path.write_bytes(raw)
    with pytest.raises(NmapXmlError):
        validate_complete_scan(
            path,
            target=DOCUMENTATION_TARGET,
            coverage=PortCoverage.parse("80-82"),
        )


def test_host_timeout_is_incomplete(tmp_path):
    path = tmp_path / "raw.xml"
    raw = nmap_xml(
        explicit_states={80: "closed"},
    ).replace(b"<host>", b'<host timedout="true">', 1)
    path.write_bytes(raw)

    assert not discovery_is_complete(
        path,
        target=DOCUMENTATION_TARGET,
        coverage=PortCoverage.parse("80"),
    )


def test_defused_parser_rejects_entity_expansion():
    raw = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><nmaprun>&e;</nmaprun>'
    with pytest.raises(NmapXmlError):
        parse_xml_bytes(raw)
