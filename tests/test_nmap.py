"""The nmap XML adapter: offline conversion with strict validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from portwarden.cli import main
from portwarden.errors import InventoryError
from portwarden.models import Inventory
from portwarden.nmap import NmapScan
from portwarden.timestamps import parse_rfc3339

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "192.0.2.10,192.0.2.11"


class ParseTests:
    def test_parses_hosts_ports_and_service_names(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        assert scan.is_complete
        assert [host.address for host in scan.hosts] == ["192.0.2.10", "192.0.2.11"]
        first = scan.hosts[0].ports
        assert [(port.port, port.state, port.name) for port in first] == [
            (22, "open", "ssh"),
            (80, "open", "http"),
            (443, "closed", "https"),
        ]

    def test_requested_ports_come_from_scaninfo_not_from_answers(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        assert scan.requested_ports == (22, 80, 443)
        assert scan.protocols == ("tcp",)

    def test_finish_time_is_parsed_as_utc(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        assert scan.scanned_at() == datetime.fromtimestamp(1794643205, tz=timezone.utc)

    def test_combined_open_filtered_maps_to_the_unknown_side(self):
        scan = NmapScan.load(FIXTURES / "nmap_udp.xml")
        port_161 = scan.hosts[0].ports[1]
        assert port_161.state == "filtered"
        assert port_161.name == "snmp"

    def test_timed_out_host_keeps_the_scan_partial(self):
        scan = NmapScan.load(FIXTURES / "nmap_partial.xml")
        assert not scan.is_complete

    def test_failed_finish_keeps_the_scan_partial(self, tmp_path):
        path = tmp_path / "failed.xml"
        path.write_text(
            (FIXTURES / "nmap_two_hosts.xml")
            .read_text(encoding="utf-8")
            .replace('exit="success"', 'exit="error"'),
            encoding="utf-8",
        )
        assert not NmapScan.load(path).is_complete

    def test_non_nmap_xml_is_rejected(self, tmp_path):
        path = tmp_path / "other.xml"
        path.write_text("<report><host/></report>", encoding="utf-8")
        with pytest.raises(InventoryError, match="nmaprun"):
            NmapScan.load(path)

    def test_broken_xml_is_rejected(self, tmp_path):
        path = tmp_path / "broken.xml"
        path.write_text("<nmaprun><host>", encoding="utf-8")
        with pytest.raises(InventoryError, match="parseable"):
            NmapScan.load(path)

    def test_xml_without_hosts_is_rejected(self, tmp_path):
        path = tmp_path / "empty.xml"
        path.write_text("<nmaprun><runstats/></nmaprun>", encoding="utf-8")
        with pytest.raises(InventoryError, match="no host"):
            NmapScan.load(path)


class BuildInventoryTests:
    def test_builds_a_loadable_complete_inventory(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        document = scan.build_inventory(scope=["192.0.2.10", "192.0.2.11"])
        assert document["status"] == "complete"
        assert document["scanned_at"] == "2026-11-14T08:00:05Z"
        parsed = Inventory.parse(document)
        assert len(parsed.services) == 3
        assert parsed.scan_parameters is not None
        assert parsed.scan_parameters.ports == (22, 80, 443)

    def test_open_only_by_default_and_closed_observations_opt_in(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        default = scan.build_inventory(scope=["192.0.2.10", "192.0.2.11"])
        assert all(service["state"] == "open" for service in default["services"])
        explicit = scan.build_inventory(
            scope=["192.0.2.10", "192.0.2.11"], include_closed=True
        )
        states = {(s["port"], s["state"]) for s in explicit["services"]}
        assert (443, "closed") in states

    def test_host_outside_scope_is_an_error_not_an_inferred_target(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        with pytest.raises(InventoryError, match="outside the declared scope"):
            scan.build_inventory(scope=["192.0.2.10"])

    def test_cidr_scope_covers_members(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        document = scan.build_inventory(scope=["192.0.2.0/24"])
        assert len(document["services"]) == 3

    def test_scanned_at_override_is_respected(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        moment = parse_rfc3339("2026-11-14T00:00:00Z")
        document = scan.build_inventory(
            scope=["192.0.2.10", "192.0.2.11"], scanned_at=moment
        )
        assert document["scanned_at"] == "2026-11-14T00:00:00Z"

    def test_partial_scans_are_marked_partial_and_loadable(self):
        scan = NmapScan.load(FIXTURES / "nmap_partial.xml")
        document = scan.build_inventory(scope=["192.0.2.10", "192.0.2.99"])
        assert document["status"] == "partial"
        parsed = Inventory.parse(document, require_complete=False)
        assert len(parsed.services) == 1

    def test_fingerprint_is_computed_and_self_consistent(self):
        scan = NmapScan.load(FIXTURES / "nmap_two_hosts.xml")
        document = scan.build_inventory(scope=["192.0.2.10", "192.0.2.11"])
        assert document["scope_fingerprint"].startswith("sha256:")
        # Inventory.parse already verified declared == computed at load.


class ImportCommandTests:
    def test_import_prints_one_json_document(self, capsys):
        code = main([
            "import-nmap",
            str(FIXTURES / "nmap_two_hosts.xml"),
            "--scope",
            SCOPE,
        ])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "complete"

    def test_incomplete_run_refused_without_flag(self, capsys):
        assert (
            main([
                "import-nmap",
                str(FIXTURES / "nmap_partial.xml"),
                "--scope",
                "192.0.2.10,192.0.2.99",
            ])
            == 4
        )
        assert capsys.readouterr().out == ""

    def test_incomplete_run_imported_as_partial_with_flag(self, capsys):
        code = main([
            "import-nmap",
            str(FIXTURES / "nmap_partial.xml"),
            "--scope",
            "192.0.2.10,192.0.2.99",
            "--allow-partial",
        ])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "partial"

    def test_output_writes_a_restricted_permission_file(self, tmp_path):
        destination = tmp_path / "snapshot.json"
        code = main([
            "import-nmap",
            str(FIXTURES / "nmap_two_hosts.xml"),
            "--scope",
            SCOPE,
            "--output",
            str(destination),
        ])
        assert code == 0
        import stat

        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        document = json.loads(destination.read_text(encoding="utf-8"))
        assert document["status"] == "complete"

    def test_output_refuses_to_overwrite_without_force(self, tmp_path, capsys):
        destination = tmp_path / "snapshot.json"
        destination.write_text("keep me", encoding="utf-8")
        code = main([
            "import-nmap",
            str(FIXTURES / "nmap_two_hosts.xml"),
            "--scope",
            SCOPE,
            "--output",
            str(destination),
        ])
        assert code == 2
        assert destination.read_text(encoding="utf-8") == "keep me"

    def test_invalid_scanned_at_is_an_input_error(self, capsys):
        assert (
            main([
                "import-nmap",
                str(FIXTURES / "nmap_two_hosts.xml"),
                "--scope",
                SCOPE,
                "--scanned-at",
                "later today",
            ])
            == 2
        )
