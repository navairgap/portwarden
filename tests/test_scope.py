"""Scope semantics: exact targets and authorized subnets."""

from __future__ import annotations

from typing import Any

import pytest

from portwarden.errors import InventoryError
from portwarden.hosts import is_host_in_scope
from portwarden.models import Inventory


def inventory(scope: list[str], services: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "complete",
        "scope": scope,
        "services": services,
    }


def service(host: str, port: int = 443) -> dict[str, Any]:
    return {"host": host, "port": port, "protocol": "tcp"}


class CidrScopeTests:
    def test_service_inside_authorized_subnet_is_accepted(self):
        parsed = Inventory.parse(inventory(["203.0.113.0/24"], [service("203.0.113.7")]))
        assert parsed.services[0].host == "203.0.113.7"

    def test_service_outside_the_subnet_is_rejected(self):
        with pytest.raises(InventoryError, match="outside"):
            Inventory.parse(inventory(["203.0.113.0/24"], [service("203.0.114.7")]))

    def test_ipv6_subnets_accept_member_addresses(self):
        parsed = Inventory.parse(inventory(["2001:db8:aa::/48"], [service("2001:db8:aa::5")]))
        assert len(parsed.services) == 1

    def test_hostnames_never_match_a_subnet_implicitly(self):
        with pytest.raises(InventoryError, match="outside"):
            Inventory.parse(inventory(["203.0.113.0/24"], [service("web.example.org")]))

    def test_mixed_exact_and_cidr_scope_accepts_both_kinds(self):
        parsed = Inventory.parse(
            inventory(
                ["192.0.2.10", "203.0.113.0/24"],
                [service("192.0.2.10"), service("203.0.113.9", port=22)],
            )
        )
        assert len(parsed.services) == 2

    def test_cidr_with_host_bits_set_is_rejected(self):
        with pytest.raises(InventoryError, match="scope"):
            Inventory.parse(inventory(["203.0.113.1/24"], []))

    def test_single_address_prefixes_behave_like_exact_targets(self):
        parsed = Inventory.parse(inventory(["192.0.2.10/32"], [service("192.0.2.10")]))
        assert len(parsed.services) == 1


class MembershipTests:
    def test_exact_string_match_wins_before_parsing(self):
        assert is_host_in_scope("host.example.org", ["host.example.org"])

    def test_non_ip_host_is_never_in_a_network_scope(self):
        assert not is_host_in_scope("host.example.org", ["203.0.113.0/24"])

    def test_address_version_mismatch_is_not_a_membership(self):
        assert not is_host_in_scope("192.0.2.10", ["2001:db8::/32"])
