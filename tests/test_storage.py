"""Safe file handling: size limits, atomic writes, baseline promotion."""

from __future__ import annotations

import json
import os
import stat
from typing import Any

import pytest

from portwarden.cli import main
from portwarden.errors import InventoryError
from portwarden.models import Inventory
from portwarden.storage import (
    atomic_write_bytes,
    load_json_document,
    serialize_document,
    write_baseline,
)


def document(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema_version": 1,
        "status": "complete",
        "scope": ["192.0.2.10"],
        "services": [],
    }
    base.update(overrides)
    return base


class LoadDocumentTests:
    def test_reads_a_valid_document(self, tmp_path):
        path = tmp_path / "ok.json"
        path.write_text('{"schema_version": 1}', encoding="utf-8")
        assert load_json_document(path) == {"schema_version": 1}

    def test_rejects_oversized_files_before_parsing(self, tmp_path):
        path = tmp_path / "big.json"
        path.write_text("x" * 64, encoding="utf-8")
        with pytest.raises(InventoryError, match="limit"):
            load_json_document(path, max_bytes=32)

    def test_rejects_invalid_utf8(self, tmp_path):
        path = tmp_path / "binary.json"
        path.write_bytes(b"\xff\xfe{}")
        with pytest.raises(InventoryError, match="UTF-8"):
            load_json_document(path)

    def test_rejects_broken_json(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{nope", encoding="utf-8")
        with pytest.raises(InventoryError, match="invalid JSON"):
            load_json_document(path)

    def test_missing_file_is_an_oserror_for_callers_to_classify(self, tmp_path):
        with pytest.raises(OSError):
            load_json_document(tmp_path / "absent.json")

    def test_load_enforces_the_size_limit_end_to_end(self, tmp_path):
        path = tmp_path / "inventory.json"
        path.write_text(json.dumps(document()), encoding="utf-8")
        with pytest.raises(InventoryError, match="limit"):
            Inventory.load(path, max_bytes=32)
        assert Inventory.load(path, max_bytes=4096).status == "complete"


class AtomicWriteTests:
    def test_written_files_get_restrictive_permissions(self, tmp_path):
        path = tmp_path / "baseline.json"
        atomic_write_bytes(path, b"{}")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_readers_never_see_partial_writes(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text("previous", encoding="utf-8")
        atomic_write_bytes(path, b"replacement")
        assert path.read_text(encoding="utf-8") == "replacement"

    def test_failures_leave_no_temporary_files(self, tmp_path, monkeypatch):
        path = tmp_path / "baseline.json"
        monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError()))
        with pytest.raises(OSError):
            atomic_write_bytes(path, b"{}")
        assert list(tmp_path.glob(".portwarden-*")) == []

    def test_missing_destination_directory_is_rejected(self, tmp_path):
        with pytest.raises(InventoryError, match="destination directory"):
            atomic_write_bytes(tmp_path / "nope" / "baseline.json", b"{}")

    def test_serialization_is_deterministic(self):
        first = serialize_document({"b": 1, "a": [2, 1]})
        second = serialize_document({"a": [2, 1], "b": 1})
        assert first == second
        assert first.endswith(b"\n")


class WriteBaselineTests:
    def test_refuses_to_replace_without_force(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text("keep me", encoding="utf-8")
        with pytest.raises(InventoryError, match="--force"):
            write_baseline(path, document(), overwrite=False)
        assert path.read_text(encoding="utf-8") == "keep me"

    def test_force_replaces_and_keeps_unknown_fields(self, tmp_path):
        path = tmp_path / "baseline.json"
        write_baseline(path, document(note="operator context"), overwrite=True)
        stored = json.loads(path.read_text(encoding="utf-8"))
        assert stored["note"] == "operator context"
        assert stored["schema_version"] == 1


class AcceptCommandTests:
    def write_inventory(self, tmp_path, name, **overrides):  # type: ignore[no-untyped-def]
        path = tmp_path / name
        path.write_text(json.dumps(document(**overrides)), encoding="utf-8")
        return path

    def test_promotes_a_completed_inventory(self, tmp_path):
        current = self.write_inventory(tmp_path, "current.json")
        destination = tmp_path / "baseline.json"
        assert main(["accept", str(current), "--to", str(destination)]) == 0
        stored = json.loads(destination.read_text(encoding="utf-8"))
        assert stored["status"] == "complete"
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600

    def test_never_promotes_partial_scans(self, tmp_path):
        current = self.write_inventory(tmp_path, "partial.json", status="partial")
        destination = tmp_path / "baseline.json"
        assert main(["accept", str(current), "--to", str(destination)]) == 4
        assert not destination.exists()

    def test_existing_baseline_needs_force(self, tmp_path):
        current = self.write_inventory(tmp_path, "current.json")
        destination = self.write_inventory(tmp_path, "baseline.json")
        before = destination.read_text(encoding="utf-8")
        assert main(["accept", str(current), "--to", str(destination)]) == 2
        assert destination.read_text(encoding="utf-8") == before
        assert main(["accept", str(current), "--to", str(destination), "--force"]) == 0
