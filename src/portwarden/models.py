"""Data model and strict parsing for PortWarden inventory files.

An inventory is a snapshot of the services exposed by an explicitly
authorized set of targets. Parsing is strict on purpose: ambiguity in a
baseline can hide real changes, so anything that cannot be interpreted
exactly is rejected instead of coerced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from .errors import IncompleteInventoryError, InventoryError
from .fingerprint import (
    compute_fingerprint,
    is_valid_fingerprint,
    normalize_scan_parameters,
)
from .hosts import is_host_in_scope, validate_host, validate_scope_target
from .storage import load_json_document
from .timestamps import parse_rfc3339

SCHEMA_VERSION = 1
MAX_NAME_LENGTH = 80
PROTOCOLS = ("tcp", "udp")

#: Explicit per-port observation states (docs/scan-result-semantics.md).
PortState = Literal["open", "closed", "filtered", "unreachable", "not_scanned", "error"]
STATES: frozenset[str] = frozenset(
    {"open", "closed", "filtered", "unreachable", "not_scanned", "error"}
)

#: Observation states that cannot confirm or deny a service's presence.
UNKNOWN_STATES: frozenset[str] = frozenset({"filtered", "unreachable", "not_scanned", "error"})

#: Scan completion markers allowed in inventory files. Failed and cancelled
#: runs must not produce inventory files at all.
STATUSES: frozenset[str] = frozenset({"complete", "partial"})


@dataclass(frozen=True)
class ScanParameters:
    """The requested work behind a scan, as far as the format records it.

    These fields participate in the scope fingerprint: two inventories
    that disagree about requested protocols, port selection, or
    coverage-affecting options describe different work.
    """

    protocols: tuple[str, ...] | None = None
    ports: tuple[int, ...] | None = None
    options: dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def parse(cls, value: object) -> ScanParameters:
        """Parse and validate the ``scan_parameters`` object.

        Canonicalization is delegated to the fingerprint module so that
        validation and hashing can never disagree about normalization.
        """
        if not isinstance(value, dict):
            raise InventoryError("scan_parameters must be an object")
        unknown = set(value) - {"protocols", "ports", "options"}
        if unknown:
            raise InventoryError(f"unknown scan_parameters field(s): {', '.join(sorted(unknown))}")
        canonical = normalize_scan_parameters(value)
        assert canonical is not None  # normalize raises on empty input
        return cls(
            protocols=tuple(canonical["protocols"]) if "protocols" in canonical else None,
            ports=tuple(canonical["ports"]) if "ports" in canonical else None,
            options=canonical.get("options", {}),
        )

    def as_dict(self) -> dict[str, Any]:
        """The canonical mapping this object contributes to the fingerprint."""
        result: dict[str, Any] = {}
        if self.protocols is not None:
            result["protocols"] = list(self.protocols)
        if self.ports is not None:
            result["ports"] = list(self.ports)
        if self.options:
            result["options"] = dict(self.options)
        return result


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
        if (
            not isinstance(name, str)
            or len(name) > MAX_NAME_LENGTH
            or any(ord(c) < 32 for c in name)
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
    #: When the snapshot was taken, if the scanner recorded it. Observation
    #: metadata only: it is displayed and policy-checked, never trusted as
    #: proof of currency.
    scanned_at: datetime | None = None
    #: The requested work behind the snapshot, when the scanner recorded it.
    scan_parameters: ScanParameters | None = None
    #: Declared (and load-time verified) scope fingerprint, when present.
    scope_fingerprint: str | None = None
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
            raise IncompleteInventoryError("only completed scans can be used as a baseline")
        scope = value.get("scope")
        services = value.get("services")
        if (
            not isinstance(scope, list)
            or not scope
            or not all(isinstance(item, str) for item in scope)
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
                validate_scope_target(target)
            except InventoryError as exc:
                raise InventoryError(f"invalid scope target: {exc}") from exc
            normalized.append(target)
        if len(set(normalized)) != len(normalized):
            raise InventoryError("scope contains duplicate targets")
        if not isinstance(services, list):
            raise InventoryError("services must be a list")
        scanned_at: datetime | None = None
        if value.get("scanned_at") is not None:
            scanned_at = parse_rfc3339(value.get("scanned_at"), field_name="scanned_at")
        scan_parameters: ScanParameters | None = None
        if value.get("scan_parameters") is not None:
            scan_parameters = ScanParameters.parse(value.get("scan_parameters"))
        declared_fingerprint = value.get("scope_fingerprint")
        if declared_fingerprint is not None:
            if not is_valid_fingerprint(declared_fingerprint):
                raise InventoryError("scope_fingerprint must be a sha256-prefixed hex digest")
            computed = compute_fingerprint(
                normalized,
                scan_parameters.as_dict() if scan_parameters else None,
                schema_version=SCHEMA_VERSION,
            )
            if declared_fingerprint != computed:
                raise InventoryError("declared scope_fingerprint does not match inventory contents")
        parsed = tuple(Service.parse(item) for item in services)
        keys = [service.key for service in parsed]
        if len(set(keys)) != len(keys):
            raise InventoryError("services contains duplicate host/port/protocol entries")
        if any(not is_host_in_scope(service.host, normalized) for service in parsed):
            raise InventoryError("service host is outside the declared inventory scope")
        return cls(
            scope=tuple(sorted(normalized)),
            services=tuple(sorted(parsed)),
            status=status,
            scanned_at=scanned_at,
            scan_parameters=scan_parameters,
            scope_fingerprint=declared_fingerprint,
            document=value,
        )

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        require_complete: bool = True,
        max_bytes: int | None = None,
    ) -> Inventory:
        """Load and validate an inventory from a JSON file.

        Files are size-limited and strictly UTF-8 decoded before parsing;
        see docs/baseline-import-export.md.
        """
        if max_bytes is None:
            document = load_json_document(path)
        else:
            document = load_json_document(path, max_bytes=max_bytes)
        return cls.parse(document, require_complete=require_complete)
