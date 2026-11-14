"""The full operator workflow: import, accept, compare, re-accept."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from portwarden.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "192.0.2.10,192.0.2.11"


def run(capsys, *argv: str) -> dict | str | int:
    """Run one command and capture its stdout payload."""
    code = main(list(argv))
    assert code in (0, 1), f"unexpected exit {code}: {capsys.readouterr().err}"
    out = capsys.readouterr().out
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def test_full_operator_workflow(tmp_path, capsys):  # type: ignore[no-untyped-def]
    workdir = tmp_path / "state"
    workdir.mkdir()

    # 1. Import the first scan and inspect it.
    snapshot = workdir / "snapshot-2026-11-14.json"
    payload = run(
        capsys,
        "import-nmap",
        str(FIXTURES / "nmap_two_hosts.xml"),
        "--scope",
        SCOPE,
    )
    assert payload["status"] == "complete"
    assert payload["scope_fingerprint"].startswith("sha256:")

    # 2. Validate it, then accept it as the baseline.
    snapshot.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    assert main(["validate", str(snapshot)]) == 0
    capsys.readouterr()
    summary = run(capsys, "accept", str(snapshot), "--to", str(workdir / "baseline.json"))
    assert "Baseline written" in summary
    baseline = workdir / "baseline.json"
    assert stat.S_IMODE(baseline.stat().st_mode) == 0o600

    # 3. Compare the later scan, recording closed observations so a
    #    verified removal can be distinguished from a missing one.
    #    It observed: ssh renamed to dropbear, http closed, https
    #    newly open on .10.
    current = workdir / "snapshot-2026-11-15.json"
    later = run(
        capsys,
        "import-nmap",
        str(FIXTURES / "nmap_two_hosts_later.xml"),
        "--scope",
        SCOPE,
        "--include-closed",
    )
    current.write_text(json.dumps(later, indent=2, sort_keys=True) + "\n")
    report = run(
        capsys,
        "compare",
        str(baseline),
        str(current),
        "--json",
        "--max-age",
        "90000",
    )
    assert report["status"] == "changes_detected"
    assert report["stale"] is False
    assert report["counts"] == {
        "added": 1,
        "changed": 1,
        "removed": 1,
        "unverified": 0,
    }
    assert report["added"][0]["port"] == 443
    assert report["removed"][0]["port"] == 80
    assert report["changed"][0]["current_name"] == "dropbear"

    # 4. Promote the reviewed snapshot over the old baseline, then verify
    #    the system is quiescent.
    assert main(["accept", str(current), "--to", str(baseline), "--force"]) == 0
    capsys.readouterr()
    settled = run(capsys, "compare", str(baseline), str(current), "--json")
    assert settled["status"] == "no_changes"

    # 5. Scans outside the declared scope are refused outright — targets
    #    are never inferred from scan output.
    capsys.readouterr()
    assert (
        main([
            "import-nmap",
            str(FIXTURES / "nmap_two_hosts.xml"),
            "--scope",
            "192.0.2.10",
        ])
        == 2
    )
    assert capsys.readouterr().out == ""

    # 6. A compatible scan of a different scope text is imported, but the
    #    comparison is withheld rather than guessed at.
    narrowed = run(
        capsys,
        "import-nmap",
        str(FIXTURES / "nmap_two_hosts.xml"),
        "--scope",
        "192.0.2.0/24",
    )
    narrowed_path = workdir / "snapshot-narrow.json"
    narrowed_path.write_text(json.dumps(narrowed, indent=2, sort_keys=True) + "\n")
    capsys.readouterr()
    code = main(["compare", str(baseline), str(narrowed_path), "--json"])
    assert code == 5
    assert capsys.readouterr().out == ""


def test_repeated_commands_are_deterministic(tmp_path, capsys):  # type: ignore[no-untyped-def]
    baseline = tmp_path / "baseline.json"
    args = [
        "import-nmap",
        str(FIXTURES / "nmap_two_hosts.xml"),
        "--scope",
        SCOPE,
        "--output",
        str(baseline),
    ]
    assert main(args) == 0
    first = baseline.read_text(encoding="utf-8")
    assert main([*args, "--force"]) == 0
    assert baseline.read_text(encoding="utf-8") == first
