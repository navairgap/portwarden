#!/usr/bin/env python3
"""Offline baseline validation and comparison for authorized service inventories.

PortWarden deliberately does not scan networks. It only compares completed
inventory files produced by an operator-approved scanner.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


class InventoryError(ValueError):
    """Raised when an inventory is unsafe or unsuitable for comparison."""


def _validate_host(host: str) -> None:
    """Validate one target identifier: an IP literal or a hostname label path."""
    if not isinstance(host, str) or not _HOST_RE.fullmatch(host):
        raise InventoryError("host is missing or invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (
            host.startswith(".")
            or host.endswith(".")
            or ".." in host
            or any(len(label) > 63 for label in host.split("."))
        ):
            raise InventoryError(f"invalid host: {host!r}") from None


@dataclass(frozen=True, order=True)
class Service:
    host: str
    port: int
    protocol: str
    name: str = ""

    @classmethod
    def parse(cls, value: object) -> "Service":
        if not isinstance(value, dict):
            raise InventoryError("each service must be an object")
        host = value.get("host")
        port = value.get("port")
        protocol = value.get("protocol", "tcp")
        name = value.get("name", "")
        if not isinstance(host, str):
            raise InventoryError("service host is missing or invalid")
        try:
            _validate_host(host)
        except InventoryError as exc:
            raise InventoryError(f"service {exc}") from exc
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise InventoryError("service port must be an integer from 1 to 65535")
        if protocol not in ("tcp", "udp"):
            raise InventoryError("service protocol must be tcp or udp")
        if not isinstance(name, str) or len(name) > 80 or any(ord(c) < 32 for c in name):
            raise InventoryError("service name must be a short printable string")
        return cls(host, port, protocol, name)

    def as_dict(self) -> dict[str, object]:
        return {"host": self.host, "port": self.port,
                "protocol": self.protocol, "name": self.name}


@dataclass(frozen=True)
class Inventory:
    scope: tuple[str, ...]
    services: tuple[Service, ...]

    @classmethod
    def parse(cls, value: object) -> "Inventory":
        if not isinstance(value, dict):
            raise InventoryError("inventory root must be an object")
        if value.get("schema_version") != 1:
            raise InventoryError("unsupported inventory schema_version")
        if value.get("status") != "complete":
            raise InventoryError("only completed scans can be used as a baseline")
        scope = value.get("scope")
        services = value.get("services")
        if not isinstance(scope, list) or not scope or not all(
            isinstance(item, str) for item in scope
        ):
            raise InventoryError("scope must be a non-empty list of target identifiers")
        # Whitespace normalization is the only identity change applied to
        # targets; everything else must survive validation unchanged.
        normalized: list[str] = []
        for item in scope:
            target = item.strip()
            if not target:
                raise InventoryError("scope targets must not be blank")
            try:
                _validate_host(target)
            except InventoryError as exc:
                raise InventoryError(f"invalid scope target: {exc}") from exc
            normalized.append(target)
        if len(set(normalized)) != len(normalized):
            raise InventoryError("scope contains duplicate targets")
        if not isinstance(services, list):
            raise InventoryError("services must be a list")
        parsed = tuple(Service.parse(item) for item in services)
        keys = [(s.host, s.port, s.protocol) for s in parsed]
        if len(set(keys)) != len(keys):
            raise InventoryError("services contains duplicate host/port/protocol entries")
        allowed = set(normalized)
        if any(s.host not in allowed for s in parsed):
            raise InventoryError("service host is outside the declared inventory scope")
        return cls(tuple(sorted(normalized)), tuple(sorted(parsed)))

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        try:
            with Path(path).open(encoding="utf-8") as stream:
                return cls.parse(json.load(stream))
        except json.JSONDecodeError as exc:
            raise InventoryError(f"invalid JSON: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise InventoryError(f"inventory is not valid UTF-8: {exc}") from exc


def compare(baseline: Inventory, current: Inventory) -> dict[str, list[dict[str, object]]]:
    """Return deterministic additions/removals; reject incompatible scopes."""
    if baseline.scope != current.scope:
        raise InventoryError("baseline and current inventory scopes do not match")
    old = {(s.host, s.port, s.protocol): s for s in baseline.services}
    new = {(s.host, s.port, s.protocol): s for s in current.services}
    added = [new[k].as_dict() for k in sorted(new.keys() - old.keys())]
    removed = [old[k].as_dict() for k in sorted(old.keys() - new.keys())]
    return {"added": added, "removed": removed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="previous completed inventory JSON")
    parser.add_argument("current", help="new completed inventory JSON")
    args = parser.parse_args(argv)
    try:
        result = compare(Inventory.load(args.baseline), Inventory.load(args.current))
    except (OSError, InventoryError) as exc:
        print(f"portwarden: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["added"] or result["removed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
