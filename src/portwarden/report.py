"""Presentation of comparison results: JSON envelope and text report.

The JSON envelope is the machine-readable contract: exactly one object,
sorted deterministically, with counts that always match the lists. The
text report is for operators: bounded, escaped labels, and honest
handling of unknown ages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from . import __version__
from .timestamps import age_seconds, format_utc


def quote_label(value: str) -> str:
    """Render a remote-influenced label safely for terminal output.

    Service names are bounded and control-character-free by validation,
    but they originate off-host; JSON quoting keeps them inert even so.
    """
    return json.dumps(value, ensure_ascii=True)


def format_age(seconds: float) -> str:
    """Render an age in coarse human units, deterministically."""
    total = int(seconds)
    if total < 0:
        total = 0
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{total}s"


@dataclass(frozen=True)
class ComparisonReport:
    """A rendered-ready comparison with snapshot metadata and staleness."""

    result: dict[str, list[dict[str, Any]]]
    scope_size: int
    baseline_scanned_at: datetime | None
    current_scanned_at: datetime | None
    scope_fingerprint: str | None
    now: datetime | None = None
    max_age_seconds: float | None = None

    @property
    def has_changes(self) -> bool:
        """True when any diff category is non-empty."""
        return bool(self.result["added"] or self.result["removed"] or self.result["changed"])

    def staleness(self) -> bool | None:
        """Apply the maximum-age policy.

        Returns True/False when the policy is applied and ages are known,
        or None when either the policy was not requested or an age is
        unknown (the report says so instead of guessing).
        """
        if self.max_age_seconds is None:
            return None
        moments = (self.baseline_scanned_at, self.current_scanned_at)
        if any(moment is None for moment in moments):
            return None
        if self.now is None:
            return None
        return any(
            age_seconds(moment, now=self.now) > self.max_age_seconds  # type: ignore[arg-type]
            for moment in moments
        )

    def to_dict(self) -> dict[str, Any]:
        """The stable JSON envelope for scripts and CI jobs."""
        stale = self.staleness()
        counts = {category: len(entries) for category, entries in self.result.items()}
        return {
            "schema_version": 1,
            "kind": "comparison",
            "tool": "portwarden",
            "tool_version": __version__,
            "status": "changes_detected" if self.has_changes else "no_changes",
            "scope_fingerprint": self.scope_fingerprint,
            "baseline_scanned_at": (
                format_utc(self.baseline_scanned_at) if self.baseline_scanned_at else None
            ),
            "current_scanned_at": (
                format_utc(self.current_scanned_at) if self.current_scanned_at else None
            ),
            "stale": stale,
            "counts": counts,
            **self.result,
        }

    def to_json(self) -> str:
        """Serialize the envelope with a trailing newline."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    def to_text(self) -> str:
        """Render the human-readable report."""
        lines: list[str] = ["PortWarden comparison", ""]
        lines.append(f"  Scope: {self.scope_size} target(s)")
        if self.scope_fingerprint:
            lines.append(f"  Scope fingerprint: {self.scope_fingerprint}")
        for label, moment in (
            ("Baseline snapshot", self.baseline_scanned_at),
            ("Current snapshot", self.current_scanned_at),
        ):
            if moment is None or self.now is None:
                lines.append(f"  {label}: (not recorded)")
            else:
                age = format_age(age_seconds(moment, now=self.now))
                lines.append(f"  {label}: {format_utc(moment)} (age {age})")
        stale = self.staleness()
        if stale:
            limit = self.max_age_seconds
            lines.append(
                "  WARNING: snapshot age exceeds the maximum age policy"
                + (f" ({int(limit)}s)" if limit is not None else "")
            )
        lines.append("")
        if not self.has_changes and not self.result["unverified"]:
            lines.append("No changes.")
            return "\n".join(lines) + "\n"

        for title, entries in (
            ("Added", self.result["added"]),
            ("Removed", self.result["removed"]),
            ("Changed", self.result["changed"]),
            ("Unverified", self.result["unverified"]),
        ):
            if not entries:
                continue
            lines.append(f"{title} ({len(entries)}):")
            for entry in entries:
                endpoint = f"{entry['host']} {entry['protocol']}/{entry['port']}"
                if "baseline_name" in entry:
                    lines.append(
                        f"  {endpoint} {quote_label(entry['baseline_name'])} -> "
                        f"{quote_label(entry['current_name'])}"
                    )
                elif "reason" in entry:
                    lines.append(f"  {endpoint} reason={entry['reason']}")
                else:
                    name = quote_label(entry.get("name", ""))
                    lines.append(f"  {endpoint} name={name}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
