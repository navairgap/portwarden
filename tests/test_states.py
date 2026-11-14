"""Per-port observation state semantics (docs/scan-result-semantics.md)."""

from __future__ import annotations

from typing import Any

import pytest

from portwarden.diff import compare
from portwarden.errors import IncompleteInventoryError, InventoryError
from portwarden.models import Inventory

SCOPE = ["192.0.2.10"]


def inventory(services: list[dict[str, Any]], status: str = "complete") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": status,
        "scope": SCOPE,
        "services": services,
    }


def service(port: int, state: str = "open", name: str = "") -> dict[str, Any]:
    return {"host": "192.0.2.10", "port": port, "protocol": "tcp", "state": state, "name": name}


class ServiceStateTests:
    def test_state_defaults_to_open(self):
        parsed = Inventory.parse(inventory([service(22)]))
        assert parsed.services[0].state == "open"

    @pytest.mark.parametrize(
        "state", ["open", "closed", "filtered", "unreachable", "not_scanned", "error"]
    )
    def test_all_documented_states_are_accepted(self, state):
        parsed = Inventory.parse(inventory([service(22, state=state)]))
        assert parsed.services[0].state == state

    def test_unknown_state_is_rejected_not_coerced(self):
        with pytest.raises(InventoryError, match="state"):
            Inventory.parse(inventory([service(22, state="stealth")]))

    def test_non_string_state_is_rejected(self):
        with pytest.raises(InventoryError, match="state"):
            Inventory.parse(inventory([service(22, state=True)]))


class CompletionTests:
    def test_partial_inventories_are_rejected_for_baselines(self):
        with pytest.raises(IncompleteInventoryError, match="completed scans"):
            Inventory.parse(inventory([], status="partial"))

    def test_partial_inventories_can_be_inspected_without_a_baseline(self):
        parsed = Inventory.parse(inventory([service(22)], status="partial"))
        assert parsed.status == "partial"
        assert len(parsed.services) == 1

    def test_unknown_status_is_invalid(self):
        with pytest.raises(InventoryError, match="status"):
            Inventory.parse(inventory([], status="failed"))


class ComparisonStateTests:
    def test_open_to_closed_reports_removed(self):
        baseline = Inventory.parse(inventory([service(22)]))
        current = Inventory.parse(inventory([service(22, state="closed")]))
        result = compare(baseline, current)
        assert [entry["port"] for entry in result["removed"]] == [22]
        assert result["unverified"] == []

    def test_filtered_observation_never_erases_a_baseline_service(self):
        baseline = Inventory.parse(inventory([service(22)]))
        current = Inventory.parse(inventory([service(22, state="filtered")]))
        result = compare(baseline, current)
        assert result["removed"] == []
        assert [entry["port"] for entry in result["unverified"]] == [22]
        assert result["unverified"][0]["reason"] == "filtered"

    @pytest.mark.parametrize("state", ["unreachable", "not_scanned", "error"])
    def test_other_unknown_states_also_stay_unverified(self, state):
        baseline = Inventory.parse(inventory([service(22)]))
        current = Inventory.parse(inventory([service(22, state=state)]))
        result = compare(baseline, current)
        assert result["removed"] == []
        assert [entry["reason"] for entry in result["unverified"]] == [state]

    def test_missing_observation_is_unverified_not_removed(self):
        baseline = Inventory.parse(inventory([service(22)]))
        current = Inventory.parse(inventory([]))
        result = compare(baseline, current)
        assert result["removed"] == []
        assert result["unverified"][0]["reason"] == "missing_from_current"

    def test_service_appearing_again_is_not_added(self):
        baseline = Inventory.parse(inventory([service(22)]))
        current = Inventory.parse(inventory([service(22)]))
        result = compare(baseline, current)
        assert result["added"] == []
        assert result["removed"] == []
        assert result["unverified"] == []
        assert result["changed"] == []

    def test_previously_closed_port_coming_open_is_added(self):
        baseline = Inventory.parse(inventory([service(22, state="closed")]))
        current = Inventory.parse(inventory([service(22, state="open")]))
        result = compare(baseline, current)
        assert [entry["port"] for entry in result["added"]] == [22]

    def test_new_open_service_is_added(self):
        baseline = Inventory.parse(inventory([]))
        current = Inventory.parse(inventory([service(443)]))
        result = compare(baseline, current)
        assert [entry["port"] for entry in result["added"]] == [443]

    def test_closed_observation_without_baseline_service_is_not_added(self):
        baseline = Inventory.parse(inventory([]))
        current = Inventory.parse(inventory([service(22, state="closed")]))
        result = compare(baseline, current)
        assert result["added"] == []

    def test_name_change_is_reported_as_changed(self):
        baseline = Inventory.parse(inventory([service(22, name="ssh")]))
        current = Inventory.parse(inventory([service(22, name="dropbear")]))
        result = compare(baseline, current)
        assert result["removed"] == []
        change = result["changed"][0]
        assert change["baseline_name"] == "ssh"
        assert change["current_name"] == "dropbear"
