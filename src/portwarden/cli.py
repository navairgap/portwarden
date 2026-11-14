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

from . import __version__
from .diff import compare
from .errors import InventoryError, ScopeMismatchError
from .models import Inventory

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
    compare_parser.set_defaults(func=_run_compare)

    validate_parser = subcommands.add_parser(
        "validate",
        help="validate an inventory file without comparing",
        description="Strictly validate one inventory file and summarize it.",
    )
    validate_parser.add_argument("inventory", help="inventory JSON to validate")
    validate_parser.set_defaults(func=_run_validate)

    return parser


def _run_compare(args: argparse.Namespace) -> int:
    try:
        result = compare(Inventory.load(args.baseline), Inventory.load(args.current))
    except ScopeMismatchError as exc:
        print(f"portwarden: comparison withheld: {exc}", file=sys.stderr)
        return EXIT_WITHHELD
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_CHANGES if result["added"] or result["removed"] else EXIT_OK


def _run_validate(args: argparse.Namespace) -> int:
    try:
        inventory = Inventory.load(args.inventory)
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(
        f"OK: complete inventory: {len(inventory.services)} service(s) "
        f"across {len(inventory.scope)} scope target(s)"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Run one PortWarden command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
