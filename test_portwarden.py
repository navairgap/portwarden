import unittest

from portwarden import Inventory, InventoryError, compare


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


class InventoryDiffTests(unittest.TestCase):
    def test_reports_new_and_removed_services_deterministically(self):
        old = Inventory.parse(inventory(services=[
            {"host": "192.0.2.10", "port": 22, "protocol": "tcp"},
            {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
        ]))
        new = Inventory.parse(inventory(services=[
            {"host": "192.0.2.10", "port": 22, "protocol": "tcp"},
            {"host": "192.0.2.10", "port": 443, "protocol": "tcp"},
        ]))
        result = compare(old, new)
        self.assertEqual([x["port"] for x in result["added"]], [443])
        self.assertEqual([x["port"] for x in result["removed"]], [80])

    def test_refuses_scope_mismatch(self):
        old = Inventory.parse(inventory(scope=["192.0.2.10"]))
        new = Inventory.parse(inventory(scope=["192.0.2.11"]))
        with self.assertRaisesRegex(InventoryError, "scopes"):
            compare(old, new)


if __name__ == "__main__":
    unittest.main()
