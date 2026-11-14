"""CLI-level tests: exit codes and stream discipline."""

from __future__ import annotations

import json
from typing import Any

import pytest

from portwarden.cli import main


def inventory(scope: list[str], services: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "complete",
        "scope": scope,
        "services": services,
    }


@pytest.fixture()
def inventory_files(tmp_path):  # type: ignore[no-untyped-def]
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    return baseline, current


def write_inventory(path, document):  # type: ignore[no-untyped-def]
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_scope_mismatch_withholds_comparison_with_exit_5(
    tmp_path, capsys  # type: ignore[no-untyped-def]
):
    baseline = write_inventory(
        tmp_path / "baseline.json", inventory(["192.0.2.10"], [])
    )
    current = write_inventory(tmp_path / "current.json", inventory(["192.0.2.11"], []))
    assert main([str(baseline), str(current)]) == 5
    err = capsys.readouterr().err
    assert "comparison withheld" in err
    # Nothing is written to stdout: a withheld comparison has no result.
    assert capsys.readouterr().out == ""


def test_invalid_input_exits_2_with_diagnostic_on_stderr(
    tmp_path, capsys  # type: ignore[no-untyped-def]
):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    good = write_inventory(tmp_path / "good.json", inventory(["192.0.2.10"], []))
    assert main([str(bad), str(good)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "portwarden:" in captured.err


def test_clean_comparison_exits_0_and_prints_result(
    tmp_path, capsys  # type: ignore[no-untyped-def]
):
    baseline = write_inventory(
        tmp_path / "baseline.json",
        inventory(["192.0.2.10"], [{"host": "192.0.2.10", "port": 22, "protocol": "tcp"}]),
    )
    current = write_inventory(
        tmp_path / "current.json",
        inventory(["192.0.2.10"], [{"host": "192.0.2.10", "port": 22, "protocol": "tcp"}]),
    )
    assert main([str(baseline), str(current)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["added"] == []
    assert payload["removed"] == []
