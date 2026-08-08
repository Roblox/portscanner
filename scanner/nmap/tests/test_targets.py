# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import ipaddress

import pytest
from conftest import DOCUMENTATION_TARGET
from portscanner_scanner import targets
from portscanner_scanner.targets import (
    TargetSafetyError,
    authorize_target,
    enforce_cidr_authorization,
    parse_ipv4_cidrs,
)


@pytest.mark.parametrize(
    "target",
    [
        "0.0.0.0",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "198.51.100.10",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "2001:db8::1",
        "example.invalid",
        "198.51.100.0/24",
    ],
)
def test_rejects_non_public_or_non_single_ipv4_targets(target):
    with pytest.raises(TargetSafetyError):
        authorize_target(target)


@pytest.mark.parametrize(
    "target",
    [
        ".".join(str(octet) for octet in (100, 100, 100, 200)),
        ".".join(str(octet) for octet in (168, 63, 129, 16)),
    ],
)
def test_rejects_known_non_link_local_metadata_targets(monkeypatch, target):
    class ApparentlyPublicIPv4(ipaddress.IPv4Address):
        @property
        def is_global(self):
            return True

        @property
        def is_private(self):
            return False

    address = ApparentlyPublicIPv4(target)
    monkeypatch.setattr(targets.ipaddress, "ip_address", lambda value: address)
    with pytest.raises(TargetSafetyError, match="metadata"):
        authorize_target(target)


def test_accepts_authorized_public_classification(monkeypatch):
    class PublicIPv4(ipaddress.IPv4Address):
        @property
        def is_unspecified(self):
            return False

        @property
        def is_loopback(self):
            return False

        @property
        def is_private(self):
            return False

        @property
        def is_link_local(self):
            return False

        @property
        def is_multicast(self):
            return False

        @property
        def is_reserved(self):
            return False

        @property
        def is_global(self):
            return True

    address = PublicIPv4(DOCUMENTATION_TARGET)
    monkeypatch.setattr(targets.ipaddress, "ip_address", lambda value: address)

    assert (
        str(
            authorize_target(
                DOCUMENTATION_TARGET,
                allowed_cidrs=("198.51.100.0/24",),
                denied_cidrs=("198.51.100.128/25",),
            )
        )
        == DOCUMENTATION_TARGET
    )


def test_cidr_denies_take_precedence():
    address = ipaddress.IPv4Address(DOCUMENTATION_TARGET)
    allowed = parse_ipv4_cidrs(["198.51.100.0/24"])
    denied = parse_ipv4_cidrs(["198.51.100.0/28", "198.51.100.16/28"])

    with pytest.raises(TargetSafetyError, match="denied"):
        enforce_cidr_authorization(
            address,
            allowed_cidrs=allowed,
            denied_cidrs=denied,
        )


def test_cidr_allowlist_is_required_when_configured():
    address = ipaddress.IPv4Address(DOCUMENTATION_TARGET)
    with pytest.raises(TargetSafetyError, match="outside"):
        enforce_cidr_authorization(
            address,
            allowed_cidrs=parse_ipv4_cidrs(["203.0.113.0/24"]),
        )


def test_cidr_configuration_is_ipv4_and_canonical():
    with pytest.raises(TargetSafetyError):
        parse_ipv4_cidrs(["198.51.100.1/24"])
    with pytest.raises(TargetSafetyError):
        parse_ipv4_cidrs(["2001:db8::/32"])
