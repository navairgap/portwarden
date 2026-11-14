"""Strict RFC 3339 timestamp parsing for snapshot metadata."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from portwarden.errors import InventoryError
from portwarden.models import Inventory
from portwarden.timestamps import age_seconds, format_utc, parse_rfc3339


def parse(text: str) -> datetime:
    return parse_rfc3339(text, field_name="scanned_at")


class ParseTests:
    def test_accepts_utc_z_suffix(self):
        parsed = parse("2026-11-14T09:30:00Z")
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timezone.utc.utcoffset(None)

    def test_accepts_fractional_seconds(self):
        assert parse("2026-11-14T09:30:00.123456Z").microsecond == 123456

    @pytest.mark.parametrize("offset", ["+05:30", "-08:00", "+00:00"])
    def test_accepts_explicit_offsets_and_normalizes_to_utc(self, offset):
        parsed = parse(f"2026-11-14T09:30:00{offset}")
        assert parsed.utcoffset() == timezone.utc.utcoffset(None)

    def test_accepts_lowercase_rfc3339_separators(self):
        assert parse("2026-11-14t09:30:00z") == parse("2026-11-14T09:30:00Z")

    @pytest.mark.parametrize(
        "bad",
        [
            "2026-11-14T09:30:00",  # timezone-naive
            "2026-11-14",  # date only
            "2026-11-14 09:30:00Z",  # space separator is not RFC 3339
            "2026-13-01T00:00:00Z",  # impossible month
            "not a timestamp",
            "",
        ],
    )
    def test_rejects_malformed_and_naive_values(self, bad):
        with pytest.raises(InventoryError):
            parse(bad)

    def test_rejects_non_strings(self):
        with pytest.raises(InventoryError, match="timestamp string"):
            parse(1700000000)  # type: ignore[arg-type]


class HelperTests:
    def test_format_utc_round_trips(self):
        moment = parse("2026-11-14T09:30:00+05:30")
        assert format_utc(moment) == "2026-11-14T04:00:00Z"

    def test_age_is_computed_in_seconds(self):
        moment = parse("2026-11-14T09:00:00Z")
        now = parse("2026-11-14T09:01:30Z")
        assert age_seconds(moment, now=now) == 90.0


class InventoryScannedAtTests:
    def document(self, scanned_at):  # type: ignore[no-untyped-def]
        return {
            "schema_version": 1,
            "status": "complete",
            "scope": ["192.0.2.10"],
            "services": [],
            "scanned_at": scanned_at,
        }

    def test_scanned_at_is_parsed_and_normalized(self):
        parsed = Inventory.parse(self.document("2026-11-14T09:30:00+05:30"))
        assert parsed.scanned_at is not None
        assert format_utc(parsed.scanned_at) == "2026-11-14T04:00:00Z"

    def test_missing_scanned_at_stays_none(self):
        document = {
            "schema_version": 1,
            "status": "complete",
            "scope": ["192.0.2.10"],
            "services": [],
        }
        assert Inventory.parse(document).scanned_at is None

    def test_explicit_null_scanned_at_is_accepted_as_unavailable(self):
        parsed = Inventory.parse(self.document(None))
        assert parsed.scanned_at is None

    def test_invalid_scanned_at_rejects_the_inventory(self):
        with pytest.raises(InventoryError, match="scanned_at"):
            Inventory.parse(self.document("yesterday"))
