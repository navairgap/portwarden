"""Scope fingerprint algorithm and compatibility gating."""

from __future__ import annotations

from typing import Any

import pytest

from portwarden.diff import compare
from portwarden.errors import InventoryError, ScopeMismatchError
from portwarden.fingerprint import (
    FINGERPRINT_PREFIX,
    compute_fingerprint,
    is_valid_fingerprint,
    normalize_ports,
)
from portwarden.models import Inventory

SCAN_PARAMETERS = {"protocols": ["tcp"], "ports": [22, 80, "443"]}
FINGERPRINT_DOC = {
    "schema_version": 1,
    "status": "complete",
    "scope": ["192.0.2.10"],
    "services": [],
    "scan_parameters": SCAN_PARAMETERS,
    "scope_fingerprint": compute_fingerprint(
        ["192.0.2.10"], SCAN_PARAMETERS, schema_version=1
    ),
}


class NormalizePortsTests:
    def test_ranges_expand_and_sort_numerically(self):
        assert normalize_ports(["443", 22, "1-3"]) == (1, 2, 3, 22, 443)

    def test_duplicates_are_removed(self):
        assert normalize_ports([80, "80", 81]) == (80, 81)

    @pytest.mark.parametrize("bad", [0, 65536, True, "80-", "a", None, "65536"])
    def test_invalid_entries_are_rejected(self, bad):
        with pytest.raises(InventoryError):
            normalize_ports([bad])

    def test_reversed_ranges_are_rejected(self):
        with pytest.raises(InventoryError, match="range"):
            normalize_ports(["100-1"])

    def test_empty_selection_is_rejected(self):
        with pytest.raises(InventoryError, match="empty"):
            normalize_ports([])


class ComputeTests:
    def test_known_algorithm_sha256_prefix(self):
        value = compute_fingerprint(["192.0.2.10"], None, schema_version=1)
        assert value.startswith(FINGERPRINT_PREFIX)
        assert len(value) == len(FINGERPRINT_PREFIX) + 64
        assert is_valid_fingerprint(value)

    def test_port_and_scope_order_do_not_matter(self):
        a = compute_fingerprint(
            ["b.example.org", "192.0.2.10"], {"ports": [443, 22]}, schema_version=1
        )
        b = compute_fingerprint(
            ["192.0.2.10", "b.example.org"], {"ports": [22, 443]}, schema_version=1
        )
        assert a == b

    def test_protocols_are_case_insensitive(self):
        a = compute_fingerprint(
            ["192.0.2.10"], {"protocols": ["TCP", "udp"]}, schema_version=1
        )
        b = compute_fingerprint(
            ["192.0.2.10"], {"protocols": ["udp", "tcp"]}, schema_version=1
        )
        assert a == b

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"scope": ["192.0.2.11"]},  # different target
            {"scan_parameters": {"ports": [22]}},  # different port set
            {"scan_parameters": {"protocols": ["udp"]}},  # different protocol
            {"scan_parameters": {"options": {"timeout_seconds": 5}}},
            {"schema_version": 2},
        ],
    )
    def test_changed_requested_work_changes_the_fingerprint(self, kwargs):
        base = compute_fingerprint(
            ["192.0.2.10"], {"ports": [22, 443], "protocols": ["tcp"]}, schema_version=1
        )
        changed = compute_fingerprint(
            kwargs.get("scope", ["192.0.2.10"]),
            kwargs.get("scan_parameters"),
            schema_version=kwargs.get("schema_version", 1),
        )
        assert base != changed

    def test_resolved_addresses_are_not_part_of_the_fingerprint(self):
        # The API only accepts scope/scan parameters, so observations such
        # as resolved addresses cannot leak into the fingerprint.
        assert compute_fingerprint(["192.0.2.10"], None, schema_version=1) == (
            compute_fingerprint(["192.0.2.10"], None, schema_version=1)
        )


class InventoryIntegrationTests:
    def test_declared_fingerprint_must_match_contents(self):
        parsed = Inventory.parse(dict(FINGERPRINT_DOC))
        assert parsed.scope_fingerprint == FINGERPRINT_DOC["scope_fingerprint"]

    def test_tampered_fingerprint_is_rejected(self):
        document = dict(FINGERPRINT_DOC)
        document["scope_fingerprint"] = FINGERPRINT_PREFIX + "0" * 64
        with pytest.raises(InventoryError, match="does not match"):
            Inventory.parse(document)

    def test_malformed_fingerprint_is_rejected(self):
        document = dict(FINGERPRINT_DOC)
        document["scope_fingerprint"] = "md5:deadbeef"
        with pytest.raises(InventoryError, match="sha256"):
            Inventory.parse(document)

    def test_fingerprint_without_scan_parameters_covers_scope_only(self):
        document = {
            "schema_version": 1,
            "status": "complete",
            "scope": ["192.0.2.10"],
            "services": [],
            "scope_fingerprint": compute_fingerprint(["192.0.2.10"], None, schema_version=1),
        }
        assert Inventory.parse(document).scope_fingerprint is not None


class ComparisonGateTests:
    @staticmethod
    def with_scan_parameters(params: dict[str, Any]) -> Inventory:
        document = {
            "schema_version": 1,
            "status": "complete",
            "scope": ["192.0.2.10"],
            "services": [],
            "scan_parameters": params,
            "scope_fingerprint": compute_fingerprint(
                ["192.0.2.10"], params, schema_version=1
            ),
        }
        return Inventory.parse(document)

    def test_fingerprint_mismatch_withholds_comparison(self):
        baseline = self.with_scan_parameters({"ports": [22, 443]})
        current = self.with_scan_parameters({"ports": [22, 443, 8080]})
        assert baseline.scope == current.scope
        with pytest.raises(ScopeMismatchError, match="fingerprints differ"):
            compare(baseline, current)

    def test_override_applies_to_fingerprint_mismatch_only(self):
        baseline = self.with_scan_parameters({"ports": [22, 443]})
        current = self.with_scan_parameters({"ports": [22, 443, 8080]})
        result = compare(baseline, current, allow_fingerprint_mismatch=True)
        assert result["added"] == []

        # A genuine scope mismatch must never be overridden.
        other_scope = Inventory.parse(
            {
                "schema_version": 1,
                "status": "complete",
                "scope": ["192.0.2.11"],
                "services": [],
            }
        )
        with pytest.raises(ScopeMismatchError, match="scopes do not match"):
            compare(baseline, other_scope, allow_fingerprint_mismatch=True)

    def test_missing_fingerprint_on_one_side_is_not_withheld(self):
        baseline = Inventory.parse(
            {
                "schema_version": 1,
                "status": "complete",
                "scope": ["192.0.2.10"],
                "services": [],
            }
        )
        current = self.with_scan_parameters({"ports": [22]})
        result: dict[str, Any] = compare(baseline, current)
        assert result["added"] == []
