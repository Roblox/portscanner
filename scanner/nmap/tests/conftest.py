# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

from xml.sax.saxutils import quoteattr

DOCUMENTATION_TARGET = "198.51.100.25"


def contract_target(*, generation: int = 3):
    from portscanner_contracts import (
        AddressFamily,
        CloudProvider,
        Target,
        TransportProtocol,
    )

    return Target.create(
        provider=CloudProvider.AWS,
        scope_id="000000000000",
        location="zz-test-1",
        resource_id="eni-00000000",
        private_address="10.0.0.1",
        public_address=DOCUMENTATION_TARGET,
        address_family=AddressFamily.IPV4,
        transport=TransportProtocol.TCP,
        generation=generation,
    )


def nmap_xml(
    *,
    target: str = DOCUMENTATION_TARGET,
    explicit_states: dict[int, str] | None = None,
    collapsed_states: tuple[tuple[str, int], ...] = (),
    finished: bool = True,
    total_hosts: int = 1,
    root_attributes: str = "",
) -> bytes:
    ports = "".join(
        (f'<port protocol="tcp" portid="{port}"><state state={quoteattr(state)}/></port>')
        for port, state in sorted((explicit_states or {}).items())
    )
    collapsed = "".join(
        f'<extraports state={quoteattr(state)} count="{count}"/>'
        for state, count in collapsed_states
    )
    runstats = (
        (
            "<runstats>"
            '<finished exit="success"/>'
            f'<hosts up="1" down="0" total="{total_hosts}"/>'
            "</runstats>"
        )
        if finished
        else ""
    )
    attributes = f" {root_attributes.strip()}" if root_attributes.strip() else ""
    return (
        f'<nmaprun scanner="nmap"{attributes}>'
        "<host>"
        '<status state="up"/>'
        f'<address addr={quoteattr(target)} addrtype="ipv4"/>'
        f"<ports>{collapsed}{ports}</ports>"
        "</host>"
        f"{runstats}"
        "</nmaprun>"
    ).encode()
