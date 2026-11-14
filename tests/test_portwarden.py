import unittest

from portwarden import Inventory, InventoryError, compare


class InventoryLoadTests(unittest.TestCase):
    def test_non_utf8_file_is_an_input_error_not_a_crash(self):
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            handle.write(b"\xff\xfe{\x00}")
            path = Path(handle.name)
        try:
            with self.assertRaisesRegex(InventoryError, "UTF-8"):
                Inventory.load(path)
        finally:
            path.unlink(missing_ok=True)

    def test_missing_file_raises_inventory_error(self):
        with self.assertRaises(OSError):
            Inventory.load("/nonexistent/portwarden-fixture.json")


def inventory(scope=None, services=None, status="complete"):
    return {
        "schema_version": 1,
        "status": status,
        "scope": scope or ["192.0.2.10"],
        "services": services or [],
    }


class InventoryValidationTests(unittest.TestCase):
    def test_partial_inventory_cannot_replace_a_baseline(self):
        with self.assertRaisesRegex(InventoryError, "completed scans"):
            Inventory.parse(inventory(status="partial"))

    def test_rejects_services_outside_declared_scope(self):
        item = inventory(services=[{
            "host": "192.0.2.99", "port": 443, "protocol": "tcp"
        }])
        with self.assertRaisesRegex(InventoryError, "outside"):
            Inventory.parse(item)

    def test_rejects_duplicate_service_keys(self):
        service = {"host": "192.0.2.10", "port": 22, "protocol": "tcp"}
        with self.assertRaisesRegex(InventoryError, "duplicate"):
            Inventory.parse(inventory(services=[service, service]))

    def test_rejects_boolean_as_port(self):
        item = inventory(services=[{
            "host": "192.0.2.10", "port": True, "protocol": "tcp"
        }])
        with self.assertRaisesRegex(InventoryError, "port"):
            Inventory.parse(item)


class ScopeValidationTests(unittest.TestCase):
    def test_scope_targets_must_be_valid_hosts(self):
        for bad in ["a b", "..", "exa mple", '"quoted"', "$HOME"]:
            with self.assertRaisesRegex(InventoryError, "scope"):
                Inventory.parse(inventory(scope=[bad]))

    def test_blank_scope_targets_are_rejected(self):
        for bad in ["", "   "]:
            with self.assertRaisesRegex(InventoryError, "blank"):
                Inventory.parse(inventory(scope=[bad]))

    def test_scope_whitespace_is_normalized(self):
        parsed = Inventory.parse(inventory(scope=["  192.0.2.10  "]))
        self.assertEqual(parsed.scope, ("192.0.2.10",))

    def test_overlong_hostname_label_is_rejected(self):
        bad = "a" * 64 + ".example.org"
        with self.assertRaisesRegex(InventoryError, "scope"):
            Inventory.parse(inventory(scope=[bad]))

    def test_valid_hostname_and_ipv6_targets_are_accepted(self):
        parsed = Inventory.parse(inventory(scope=[
            "host.example.org", "2001:db8::1",
        ]))
        self.assertEqual(
            parsed.scope, ("2001:db8::1", "host.example.org")
        )


class InventoryDiffTests(unittest.TestCase):
    def test_reports_new_and_removed_services_deterministically(self):
        old = Inventory.parse(inventory(services=[
            {"host": "192.0.2.10", "port": 22, "protocol": "tcp"},
            {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
        ]))
        new = Inventory.parse(inventory(services=[
            {"host": "192.0.2.10", "port": 22, "protocol": "tcp"},
            {"host": "192.0.2.10", "port": 80, "protocol": "tcp", "state": "closed"},
            {"host": "192.0.2.10", "port": 443, "protocol": "tcp"},
        ]))
        result = compare(old, new)
        self.assertEqual([x["port"] for x in result["added"]], [443])
        self.assertEqual([x["port"] for x in result["removed"]], [80])

    def test_missing_observation_is_not_evidence_of_removal(self):
        old = Inventory.parse(inventory(services=[
            {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
        ]))
        new = Inventory.parse(inventory(services=[]))
        result = compare(old, new)
        self.assertEqual(result["removed"], [])
        self.assertEqual(result["unverified"][0]["reason"], "missing_from_current")

    def test_refuses_scope_mismatch(self):
        old = Inventory.parse(inventory(scope=["192.0.2.10"]))
        new = Inventory.parse(inventory(scope=["192.0.2.11"]))
        with self.assertRaisesRegex(InventoryError, "scopes"):
            compare(old, new)


if __name__ == "__main__":
    unittest.main()
