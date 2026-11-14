"""Strict RFC 3339 timestamp handling for inventory snapshots.

Timestamps describe when a snapshot was taken; they are observation
metadata, never proof that data is current. Parsing accepts only fully
qualified RFC 3339 values with an explicit UTC offset — timezone-naive
timestamps are rejected because their meaning depends on the reader's
environment.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .errors import InventoryError

# RFC 3339 date-time with a mandatory offset (Z or ±HH:MM). Lowercase
# 't'/'z' separators are permitted by the RFC and accepted here.
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def parse_rfc3339(value: object, *, field_name: str = "timestamp") -> datetime:
    """Parse an RFC 3339 timestamp into an aware UTC ``datetime``.

    Raises:
        InventoryError: if the value is not a string, is not RFC 3339, or
            lacks an explicit UTC offset.
    """
    if not isinstance(value, str):
        raise InventoryError(f"{field_name} must be an RFC 3339 timestamp string")
    if not _RFC3339_RE.fullmatch(value):
        raise InventoryError(
            f"{field_name} must be an RFC 3339 timestamp with an explicit UTC offset"
        )
    normalized = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise InventoryError(f"{field_name} is not a valid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:  # defensive: the regex already requires an offset
        raise InventoryError(f"{field_name} must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def format_utc(moment: datetime) -> str:
    """Format an aware datetime as an RFC 3339 UTC string with a Z suffix."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def age_seconds(moment: datetime, *, now: datetime) -> float:
    """Age of ``moment`` relative to ``now``; both must be timezone-aware."""
    if moment.tzinfo is None or now.tzinfo is None:
        raise InventoryError("snapshot ages require timezone-aware timestamps")
    return (now - moment).total_seconds()
