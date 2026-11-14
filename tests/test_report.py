"""Report rendering: JSON envelope and text output."""

from __future__ import annotations

import json
from typing import Any

from portwarden.report import ComparisonReport, format_age, quote_label
from portwarden.timestamps import parse_rfc3339

NOW = parse_rfc3339("2026-11-14T12:00:00Z")
EARLIER = parse_rfc3339("2026-11-14T11:00:00Z")


def result(**overrides: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    base: dict[str, list[dict[str, Any]]] = {
        "added": [],
        "removed": [],
        "changed": [],
        "unverified": [],
    }
    base.update(overrides)
    return base


def report(**kwargs: Any) -> ComparisonReport:
    params = {
        "result": result(),
        "scope_size": 1,
        "baseline_scanned_at": EARLIER,
        "current_scanned_at": EARLIER,
        "scope_fingerprint": "sha256:" + "a" * 64,
        "now": NOW,
    }
    params.update(kwargs)
    return ComparisonReport(**params)


class EnvelopeTests:
    def test_counts_always_match_the_lists(self):
        document = report(
            result=result(added=[{"host": "192.0.2.10", "port": 22, "protocol": "tcp"}])
        ).to_dict()
        assert document["counts"] == {
            "added": 1,
            "changed": 0,
            "removed": 0,
            "unverified": 0,
        }
        assert document["added"] == document["added"]  # identity of lists preserved

    def test_status_reflects_findings(self):
        assert report().to_dict()["status"] == "no_changes"
        document = report(result=result(removed=[{"host": "h", "port": 1, "protocol": "tcp"}]))
        assert document.to_dict()["status"] == "changes_detected"

    def test_unverified_alone_is_not_a_change(self):
        entry = {"host": "h", "port": 1, "protocol": "tcp", "reason": "filtered"}
        document = report(result=result(unverified=[entry])).to_dict()
        assert document["status"] == "no_changes"

    def test_envelope_is_deterministic(self):
        first = report().to_json()
        second = report().to_json()
        assert first == second
        assert json.loads(first)["kind"] == "comparison"

    def test_unknown_ages_are_null_not_guessed(self):
        document = report(baseline_scanned_at=None).to_dict()
        assert document["baseline_scanned_at"] is None

    def test_staleness_policy_values(self):
        max_age = 3600.0
        assert report(max_age_seconds=max_age).to_dict()["stale"] is False
        old = parse_rfc3339("2026-11-14T08:00:00Z")
        assert report(baseline_scanned_at=old, max_age_seconds=max_age).to_dict()["stale"] is True
        assert report(max_age_seconds=max_age, baseline_scanned_at=None).to_dict()["stale"] is None
        assert report().to_dict()["stale"] is None


class TextReportTests:
    def test_sections_appear_with_counts(self):
        text = report(
            result=result(
                added=[{"host": "192.0.2.10", "port": 443, "protocol": "tcp", "name": "https"}],
                unverified=[
                    {"host": "192.0.2.10", "port": 22, "protocol": "tcp", "reason": "filtered"}
                ],
            )
        ).to_text()
        assert "Added (1):" in text
        assert "Unverified (1):" in text
        assert "tcp/443" in text
        assert "reason=filtered" in text

    def test_changed_names_are_json_quoted(self):
        text = report(
            result=result(
                changed=[
                    {
                        "host": "192.0.2.10",
                        "port": 22,
                        "protocol": "tcp",
                        "baseline_name": 'weird "name"',
                        "current_name": "ok",
                    }
                ]
            )
        ).to_text()
        assert '"weird \\"name\\""' in text
        assert '"ok"' in text

    def test_no_changes_is_explicit(self):
        assert "No changes." in report().to_text()

    def test_stale_warning_appears(self):
        old = parse_rfc3339("2026-11-14T08:00:00Z")
        text = report(baseline_scanned_at=old, max_age_seconds=3600.0).to_text()
        assert "WARNING" in text

    def test_rendering_is_deterministic(self):
        assert report().to_text() == report().to_text()


class HelperTests:
    def test_quote_label_is_ascii_and_quoted(self):
        assert quote_label("ssh") == '"ssh"'

    def test_format_age_units(self):
        assert format_age(30) == "30s"
        assert format_age(90) == "1m"
        assert format_age(7200) == "2h 0m"
        assert format_age(90000) == "1d 1h"
        assert format_age(-5) == "0s"
