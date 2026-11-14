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
import json
import sys
from datetime import datetime, timezone

from . import __version__
from .diff import compare
from .errors import IncompleteInventoryError, InventoryError, ScopeMismatchError
from .fingerprint import compute_fingerprint
from .models import SCHEMA_VERSION, Inventory
from .nmap import NmapScan
from .report import ComparisonReport
from .storage import write_baseline
from .timestamps import parse_rfc3339

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

    accept_parser = subcommands.add_parser(
        "accept",
        help="promote a completed inventory to the accepted baseline",
        description=(
            "Promote a completed inventory to be the accepted baseline. "
            "Partial scans are never promoted, and an existing baseline is "
            "only replaced with --force."
        ),
    )
    accept_parser.add_argument("current", help="completed inventory JSON to promote")
    accept_parser.add_argument(
        "--to",
        required=True,
        dest="baseline",
        help="destination path for the accepted baseline",
    )
    accept_parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing baseline at the destination",
    )
    accept_parser.set_defaults(func=_run_accept)

    import_parser = subcommands.add_parser(
        "import-nmap",
        help="convert nmap XML output into an inventory",
        description=(
            "Convert the XML output of an nmap run (nmap -oX) into an "
            "inventory document. The declared scope is authoritative; "
            "hosts outside it are refused."
        ),
    )
    import_parser.add_argument("nmap_xml", help="nmap XML file (-oX output)")
    import_parser.add_argument(
        "--scope",
        required=True,
        help="comma-separated authorized targets (hosts or CIDR subnets)",
    )
    import_parser.add_argument(
        "--output",
        help="write the inventory to this path instead of stdout",
    )
    import_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="emit status=partial for incomplete runs instead of refusing",
    )
    import_parser.add_argument(
        "--include-closed",
        action="store_true",
        help="record closed/filtered/unreachable observations explicitly",
    )
    import_parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing file at --output",
    )
    import_parser.add_argument(
        "--scanned-at",
        default=None,
        help="RFC 3339 UTC snapshot time overriding the XML finish time",
    )
    import_parser.set_defaults(func=_run_import_nmap)

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


def _run_import_nmap(args: argparse.Namespace) -> int:
    try:
        scan = NmapScan.load(args.nmap_xml)
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if not scan.is_complete and not args.allow_partial:
        print(
            "portwarden: nmap run is incomplete (down or timed-out hosts, or a "
            "failed finish); use --allow-partial to emit status=partial",
            file=sys.stderr,
        )
        return EXIT_PARTIAL
    scope = [target for target in args.scope.split(",") if target.strip()]
    scanned_at: datetime | None = None
    if args.scanned_at is not None:
        try:
            scanned_at = parse_rfc3339(args.scanned_at, field_name="--scanned-at")
        except InventoryError as exc:
            print(f"portwarden: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
    try:
        document = scan.build_inventory(
            scope=scope,
            scanned_at=scanned_at,
            include_closed=args.include_closed,
        )
    except InventoryError as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if args.output:
        try:
            write_baseline(args.output, document, overwrite=args.force)
        except (OSError, InventoryError) as exc:
            print(f"portwarden: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        print(f"Inventory written to {args.output} ({document['status']})")
    else:
        print(json.dumps(document, indent=2, sort_keys=True))
    return EXIT_OK


def _run_accept(args: argparse.Namespace) -> int:
    try:
        candidate = Inventory.load(args.current, require_complete=False)
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if candidate.status != "complete":
        print(
            "portwarden: an incomplete scan must never be promoted to a baseline",
            file=sys.stderr,
        )
        return EXIT_PARTIAL
    try:
        write_baseline(args.baseline, candidate.document, overwrite=args.force)
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(
        f"Baseline written to {args.baseline} "
        f"({len(candidate.services)} service(s), {len(candidate.scope)} scope target(s))"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Run one PortWarden command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
