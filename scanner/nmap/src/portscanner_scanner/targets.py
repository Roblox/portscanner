# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Single-target IPv4 safety and CIDR authorization."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


class TargetSafetyError(ValueError):
    """Raised when a target is unsafe or outside operator authorization."""


def _network(octets: tuple[int, int, int, int], prefix_length: int) -> ipaddress.IPv4Network:
    address = ".".join(str(octet) for octet in octets)
    return ipaddress.IPv4Network(f"{address}/{prefix_length}")


# Link-local metadata endpoints are rejected by the generic address checks. These
# non-link-local service addresses need an explicit deny because some Python
# versions classify them as globally reachable.
_METADATA_NETWORKS = (
    _network((100, 100, 100, 200), 32),
    _network((168, 63, 129, 16), 32),
)

# IPv4 protocol-assignment space includes globally classified anycast addresses,
# but it is not an appropriate VERIFY target supplied by an inventory event.
_SPECIAL_SERVICE_NETWORKS = (_network((192, 0, 0, 0), 24),)


def parse_ipv4_cidrs(values: Iterable[str] | None) -> tuple[ipaddress.IPv4Network, ...]:
    """Parse trusted operator CIDR configuration into a stable tuple."""

    parsed: dict[str, ipaddress.IPv4Network] = {}
    for configured_value in values or ():
        if not isinstance(configured_value, str):
            raise TargetSafetyError("configured CIDRs must be strings")
        for raw_cidr in configured_value.split(","):
            cidr = raw_cidr.strip()
            if not cidr:
                raise TargetSafetyError("configured CIDR cannot be empty")
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError as error:
                raise TargetSafetyError(f"invalid configured CIDR: {cidr!r}") from error
            if not isinstance(network, ipaddress.IPv4Network):
                raise TargetSafetyError("only IPv4 authorization CIDRs are supported")
            parsed[network.with_prefixlen] = network
    return tuple(
        sorted(
            parsed.values(),
            key=lambda network: (int(network.network_address), network.prefixlen),
        )
    )


def enforce_cidr_authorization(
    address: ipaddress.IPv4Address,
    *,
    allowed_cidrs: Iterable[ipaddress.IPv4Network] = (),
    denied_cidrs: Iterable[ipaddress.IPv4Network] = (),
) -> None:
    """Apply deny-first operator authorization to an already-safe address."""

    denied = tuple(denied_cidrs)
    allowed = tuple(allowed_cidrs)
    if any(address in network for network in denied):
        raise TargetSafetyError("target is in a denied CIDR")
    if allowed and not any(address in network for network in allowed):
        raise TargetSafetyError("target is outside the configured allowed CIDRs")


def authorize_target(
    target: str,
    *,
    allowed_cidrs: Iterable[str] | None = None,
    denied_cidrs: Iterable[str] | None = None,
) -> ipaddress.IPv4Address:
    """Validate and authorize exactly one canonical, public IPv4 address."""

    if not isinstance(target, str) or not target or target != target.strip():
        raise TargetSafetyError("target must be one canonical IPv4 address")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise TargetSafetyError("target must be a literal IPv4 address") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise TargetSafetyError("IPv6 targets are not supported")

    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or not address.is_global
    ):
        raise TargetSafetyError("target must be a globally reachable public IPv4 address")
    if any(address in network for network in _METADATA_NETWORKS):
        raise TargetSafetyError("metadata service addresses are not valid targets")
    if any(address in network for network in _SPECIAL_SERVICE_NETWORKS):
        raise TargetSafetyError("special service addresses are not valid targets")
    if str(address) != target:
        raise TargetSafetyError("target must use canonical dotted-decimal notation")

    enforce_cidr_authorization(
        address,
        allowed_cidrs=parse_ipv4_cidrs(allowed_cidrs),
        denied_cidrs=parse_ipv4_cidrs(denied_cidrs),
    )
    return address
