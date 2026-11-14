"""Command-line interface for PortWarden."""

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
            "Compare completed service inventories against an accepted baseline. "
            "PortWarden does not scan networks."
        ),
    )
    parser.add_argument("--version", action="version", version=f"portwarden {__version__}")
    parser.add_argument("baseline", help="previous completed inventory JSON")
    parser.add_argument("current", help="new completed inventory JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one comparison; see docs/cli-output-contract.md for the contract."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = compare(Inventory.load(args.baseline), Inventory.load(args.current))
    except ScopeMismatchError as exc:
        print(f"portwarden: comparison withheld: {exc}", file=sys.stderr)
        return EXIT_WITHHELD
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["added"] or result["removed"] else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
