"""Command-line interface for PortWarden.

Exit status contract (see docs/cli-output-contract.md):

- 0: success; findings may be present in the structured output
- 1: comparison found changes
- 2: invalid command line, unreadable file, or invalid inventory
- 4: inventory is partial where a completed one was required
- 5: comparison withheld (scope or baseline incompatibility)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from . import __version__
from .diff import compare
from .errors import IncompleteInventoryError, InventoryError, ScopeMismatchError
from .fingerprint import compute_fingerprint
from .models import SCHEMA_VERSION, Inventory
from .report import ComparisonReport

EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_INPUT_ERROR = 2
EXIT_PARTIAL = 4
EXIT_WITHHELD = 5


def build_parser() -> argparse.ArgumentParser:
    """Build the PortWarden argument parser."""
    parser = argparse.ArgumentParser(
        prog="portwarden",
        description=(
            "Local-first baseline monitoring for exposed services. PortWarden "
            "does not scan networks; it compares completed inventory files."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"portwarden {__version__}"
    )
    subcommands = parser.add_subparsers(
        dest="command", required=True, metavar="COMMAND"
    )

    compare_parser = subcommands.add_parser(
        "compare",
        help="compare a current inventory against an accepted baseline",
        description="Compare two completed inventories with identical scope.",
    )
    compare_parser.add_argument("baseline", help="accepted baseline inventory JSON")
    compare_parser.add_argument("current", help="new completed inventory JSON")
    compare_parser.add_argument(
        "--allow-scope-change",
        action="store_true",
        help="explicit operator decision to compare across differing scope "
        "fingerprints (a genuine scope mismatch is still refused)",
    )
    compare_parser.add_argument(
        "--json",
        action="store_true",
        help="emit exactly one JSON report object on stdout",
    )
    compare_parser.add_argument(
        "--max-age",
        type=float,
        default=None,
        metavar="SECONDS",
        help="label the report stale when either snapshot is older than this",
    )
    compare_parser.set_defaults(func=_run_compare)

    validate_parser = subcommands.add_parser(
        "validate",
        help="validate an inventory file without comparing",
        description="Strictly validate one inventory file and summarize it.",
    )
    validate_parser.add_argument("inventory", help="inventory JSON to validate")
    validate_parser.set_defaults(func=_run_validate)

    fingerprint_parser = subcommands.add_parser(
        "fingerprint",
        help="print the scope fingerprint of an inventory",
        description="Compute and print the scope fingerprint of one inventory file.",
    )
    fingerprint_parser.add_argument("inventory", help="inventory JSON to fingerprint")
    fingerprint_parser.set_defaults(func=_run_fingerprint)

    return parser


def _load_pair(args: argparse.Namespace) -> tuple[Inventory, Inventory] | int:
    """Load both compare inputs, mapping failures to documented exits."""
    for path in (args.baseline, args.current):
        if not isinstance(path, str) or not path:
            return EXIT_INPUT_ERROR
    try:
        baseline = Inventory.load(args.baseline)
        current = Inventory.load(args.current)
    except IncompleteInventoryError as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_PARTIAL
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if baseline.scope_fingerprint is None or current.scope_fingerprint is None:
        print(
            "portwarden: warning: at least one inventory has no scope fingerprint; "
            "scope compatibility could not be verified",
            file=sys.stderr,
        )
    return baseline, current


def _run_compare(args: argparse.Namespace) -> int:
    loaded = _load_pair(args)
    if isinstance(loaded, int):
        return loaded
    baseline, current = loaded
    try:
        result = compare(baseline, current)
    except ScopeMismatchError as exc:
        if not args.allow_scope_change:
            print(f"portwarden: comparison withheld: {exc}", file=sys.stderr)
            return EXIT_WITHHELD
        try:
            result = compare(baseline, current, allow_fingerprint_mismatch=True)
        except ScopeMismatchError:
            print(f"portwarden: comparison withheld: {exc}", file=sys.stderr)
            return EXIT_WITHHELD
        print(
            "portwarden: warning: scope fingerprints differ; comparison forced "
            "by explicit operator decision",
            file=sys.stderr,
        )
    matching_fingerprint = (
        baseline.scope_fingerprint
        if baseline.scope_fingerprint == current.scope_fingerprint
        else None
    )
    report = ComparisonReport(
        result=result,
        scope_size=len(baseline.scope),
        baseline_scanned_at=baseline.scanned_at,
        current_scanned_at=current.scanned_at,
        scope_fingerprint=matching_fingerprint,
        now=datetime.now(timezone.utc),
        max_age_seconds=args.max_age,
    )
    print(report.to_json() if args.json else report.to_text())
    return EXIT_CHANGES if report.has_changes else EXIT_OK


def _run_validate(args: argparse.Namespace) -> int:
    try:
        inventory = Inventory.load(args.inventory, require_complete=False)
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(
        f"OK: {inventory.status} inventory: {len(inventory.services)} service(s) "
        f"across {len(inventory.scope)} scope target(s)"
    )
    return EXIT_OK


def _run_fingerprint(args: argparse.Namespace) -> int:
    try:
        inventory = Inventory.load(args.inventory, require_complete=False)
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(
        compute_fingerprint(
            inventory.scope,
            inventory.scan_parameters.as_dict() if inventory.scan_parameters else None,
            schema_version=SCHEMA_VERSION,
        )
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Run one PortWarden command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
