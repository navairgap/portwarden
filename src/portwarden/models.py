"""Data model and strict parsing for PortWarden inventory files.

An inventory is a snapshot of the services exposed by an explicitly
authorized set of targets. Parsing is strict on purpose: ambiguity in a
baseline can hide real changes, so anything that cannot be interpreted
exactly is rejected instead of coerced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .errors import IncompleteInventoryError, InventoryError
from .hosts import validate_host

SCHEMA_VERSION = 1
MAX_NAME_LENGTH = 80
PROTOCOLS = ("tcp", "udp")

#: Explicit per-port observation states (docs/scan-result-semantics.md).
PortState = Literal["open", "closed", "filtered", "unreachable", "not_scanned", "error"]
STATES: frozenset[str] = frozenset(
    {"open", "closed", "filtered", "unreachable", "not_scanned", "error"}
)

#: Observation states that cannot confirm or deny a service's presence.
UNKNOWN_STATES: frozenset[str] = frozenset(
    {"filtered", "unreachable", "not_scanned", "error"}
)

#: Scan completion markers allowed in inventory files. Failed and cancelled
#: runs must not produce inventory files at all.
STATUSES: frozenset[str] = frozenset({"complete", "partial"})


@dataclass(frozen=True, order=True)
class Service:
    """One observed service endpoint, keyed by ``(host, port, protocol)``."""

    host: str
    port: int
    protocol: str
    name: str = ""
    state: PortState = "open"

    @classmethod
    def parse(cls, value: object) -> Service:
        """Parse and validate one service object from decoded JSON."""
        if not isinstance(value, dict):
            raise InventoryError("each service must be an object")
        host = value.get("host")
        port = value.get("port")
        protocol = value.get("protocol", "tcp")
        name = value.get("name", "")
        state = value.get("state", "open")
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
        if not isinstance(state, str) or state not in STATES:
            raise InventoryError("service state must be a documented observation state")
        return cls(host, port, protocol, name, state)  # type: ignore[arg-type]

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
            "state": self.state,
        }


@dataclass(frozen=True)
class Inventory:
    """An inventory of services for an explicit, authorized scope."""

    scope: tuple[str, ...]
    services: tuple[Service, ...]
    status: str = "complete"
    #: The original parsed document, preserved so rewriting a baseline can
    #: keep unknown fields for forward compatibility.
    document: dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def parse(cls, value: object, *, require_complete: bool = True) -> Inventory:
        """Parse and validate a full inventory document.

        Args:
            value: The decoded JSON document.
            require_complete: Reject partial inventories when True; callers
                that only inspect a file (for example ``validate``) may pass
                False, but a partial inventory must never become a baseline.
        """
        if not isinstance(value, dict):
            raise InventoryError("inventory root must be an object")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise InventoryError("unsupported inventory schema_version")
        status = value.get("status")
        if status not in STATUSES:
            raise InventoryError("inventory status must be complete or partial")
        if require_complete and status != "complete":
            raise IncompleteInventoryError(
                "only completed scans can be used as a baseline"
            )
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
        return cls(
            scope=tuple(sorted(normalized)),
            services=tuple(sorted(parsed)),
            status=status,
            document=value,
        )

    @classmethod
    def load(
        cls, path: str | Path, *, require_complete: bool = True
    ) -> Inventory:
        """Load and validate an inventory from a JSON file."""
        try:
            with Path(path).open(encoding="utf-8") as stream:
                return cls.parse(json.load(stream), require_complete=require_complete)
        except json.JSONDecodeError as exc:
            raise InventoryError(f"invalid JSON: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise InventoryError(f"inventory is not valid UTF-8: {exc}") from exc
