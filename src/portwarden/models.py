"""Data model and strict parsing for PortWarden inventory files.

An inventory is a completed snapshot of the services exposed by an
explicitly authorized set of targets. Parsing is strict on purpose:
ambiguity in a baseline can hide real changes, so anything that cannot
be interpreted exactly is rejected instead of coerced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import InventoryError
from .hosts import validate_host

SCHEMA_VERSION = 1
MAX_NAME_LENGTH = 80
PROTOCOLS = ("tcp", "udp")


@dataclass(frozen=True, order=True)
class Service:
    """One observed service endpoint, keyed by ``(host, port, protocol)``."""

    host: str
    port: int
    protocol: str
    name: str = ""

    @classmethod
    def parse(cls, value: object) -> Service:
        """Parse and validate one service object from decoded JSON."""
        if not isinstance(value, dict):
            raise InventoryError("each service must be an object")
        host = value.get("host")
        port = value.get("port")
        protocol = value.get("protocol", "tcp")
        name = value.get("name", "")
        if not isinstance(host, str):
            raise InventoryError("service host is missing or invalid")
        try:
            validate_host(host)
        except InventoryError as exc:
            raise InventoryError(f"service {exc}") from exc
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise InventoryError("service port must be an integer from 1 to 65535")
        if protocol not in PROTOCOLS:
            raise InventoryError("service protocol must be tcp or udp")
        if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH or any(
            ord(c) < 32 for c in name
        ):
            raise InventoryError("service name must be a short printable string")
        return cls(host, port, protocol, name)

    @property
    def key(self) -> tuple[str, int, str]:
        """The identity of this observation, ignoring changeable metadata."""
        return (self.host, self.port, self.protocol)

    def as_dict(self) -> dict[str, Any]:
        """Return the canonical JSON mapping for this service."""
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "name": self.name,
        }


@dataclass(frozen=True)
class Inventory:
    """A completed inventory of services for an explicit scope."""

    scope: tuple[str, ...]
    services: tuple[Service, ...]

    @classmethod
    def parse(cls, value: object) -> Inventory:
        """Parse and validate a full inventory document."""
        if not isinstance(value, dict):
            raise InventoryError("inventory root must be an object")
        if value.get("schema_version") != SCHEMA_VERSION:
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
                validate_host(target)
            except InventoryError as exc:
                raise InventoryError(f"invalid scope target: {exc}") from exc
            normalized.append(target)
        if len(set(normalized)) != len(normalized):
            raise InventoryError("scope contains duplicate targets")
        if not isinstance(services, list):
            raise InventoryError("services must be a list")
        parsed = tuple(Service.parse(item) for item in services)
        keys = [service.key for service in parsed]
        if len(set(keys)) != len(keys):
            raise InventoryError(
                "services contains duplicate host/port/protocol entries"
            )
        allowed = set(normalized)
        if any(service.host not in allowed for service in parsed):
            raise InventoryError("service host is outside the declared inventory scope")
        return cls(tuple(sorted(normalized)), tuple(sorted(parsed)))

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        """Load and validate an inventory from a JSON file."""
        try:
            with Path(path).open(encoding="utf-8") as stream:
                return cls.parse(json.load(stream))
        except json.JSONDecodeError as exc:
            raise InventoryError(f"invalid JSON: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise InventoryError(f"inventory is not valid UTF-8: {exc}") from exc
