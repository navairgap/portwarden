"""Deterministic scope fingerprinting (docs/scan-scope-fingerprint.md).

The fingerprint identifies the *requested work* behind an inventory —
targets, transport protocols, port selection, and coverage-affecting
options — never the observations that happened to come back. Resolved
addresses, elapsed time, and answered ports are deliberately excluded.

The algorithm is part of the stable contract:

1. Build the canonical document: ``schema_version`` as-is; the scope as
   the deduplicated, codepoint-sorted set of whitespace-trimmed targets
   (identity is preserved exactly apart from trimming); and, when scan
   parameters are present, ``protocols`` lowercased/sorted/deduplicated,
   ``ports`` expanded, validated, sorted, deduplicated, and ``options``
   as provided (scalar values only).
2. Serialize with ``json.dumps(canonical, sort_keys=True,
   separators=(",", ":"), ensure_ascii=True)`` and encode as UTF-8.
3. Hash with SHA-256 and prefix the lowercase hex digest with
   ``sha256:``.

The fingerprint is a compatibility aid, not a security signature: it
does not prove that a scan was authorized or that a file was not
modified.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from .errors import InventoryError

FINGERPRINT_PREFIX = "sha256:"

#: Transports an inventory can represent. Shared with the data model so
#: canonicalization and validation always agree.
PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp"})

_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PORT_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")

_MAX_OPTION_ITEMS = 1024
_MAX_OPTION_TEXT = 256


def normalize_ports(selection: Iterable[object]) -> tuple[int, ...]:
    """Expand port numbers and ``a-b`` ranges into a sorted, unique tuple.

    Raises:
        InventoryError: for booleans, non-integer non-range values, empty
            selections, or ports outside 1-65535.
    """
    ports: set[int] = set()
    for item in selection:
        port: int | None = None
        if isinstance(item, bool):
            raise InventoryError("scan ports must be integers or a-b ranges")
        if isinstance(item, int):
            port = item
        elif isinstance(item, str):
            text = item.strip()
            range_match = _PORT_RANGE_RE.fullmatch(text)
            if range_match:
                low, high = int(range_match.group(1)), int(range_match.group(2))
                if low > high:
                    raise InventoryError(f"invalid port range: {text!r}")
                if low < 1 or high > 65535:
                    raise InventoryError(f"port range outside 1-65535: {text!r}")
                ports.update(range(low, high + 1))
                continue
            if text.isdigit():
                port = int(text)
        if port is None:
            raise InventoryError("scan ports must be integers or a-b ranges")
        if not 1 <= port <= 65535:
            raise InventoryError("scan ports must be integers from 1 to 65535")
        ports.add(port)
    if not ports:
        raise InventoryError("scan ports must not be empty")
    return tuple(sorted(ports))


def validate_options(options: dict[str, Any]) -> None:
    """Reject options that cannot take part in a deterministic hash."""

    def check_value(value: object) -> None:
        if isinstance(value, (bool, int)):
            return
        if isinstance(value, str):
            if len(value) > _MAX_OPTION_TEXT or any(ord(c) < 32 for c in value):
                raise InventoryError(
                    "scan options must be short printable strings, numbers, or booleans"
                )
            return
        if isinstance(value, list):
            if len(value) > _MAX_OPTION_ITEMS:
                raise InventoryError("scan option lists are limited to 1024 items")
            for item in value:
                check_value(item)
            return
        raise InventoryError(
            "scan options must be short printable strings, numbers, booleans, "
            "or flat lists of those"
        )

    if not options:
        raise InventoryError("scan options must not be empty when present")
    for key, value in options.items():
        if not isinstance(key, str) or not key:
            raise InventoryError("scan option names must be non-empty strings")
        check_value(value)


def normalize_scan_parameters(params: dict[str, Any] | None) -> dict[str, Any] | None:
    """Canonicalize a raw ``scan_parameters`` mapping for fingerprinting.

    The output contains only normalized values: lowercased, sorted,
    deduplicated protocols; expanded, sorted, unique ports; and options
    validated for deterministic serialization. This is the single source
    of truth for how scan parameters enter the fingerprint.

    Raises:
        InventoryError: for malformed or unsupported values.
    """
    if params is None:
        return None
    if not isinstance(params, dict):
        raise InventoryError("scan_parameters must be an object")
    canonical: dict[str, Any] = {}
    if params.get("protocols") is not None:
        requested = params["protocols"]
        if (
            not isinstance(requested, list)
            or not requested
            or not all(isinstance(item, str) for item in requested)
        ):
            raise InventoryError("scan_parameters protocols must be a non-empty list of strings")
        lowered = {item.strip().lower() for item in requested}
        if not lowered or not lowered <= PROTOCOLS:
            raise InventoryError("scan_parameters protocols must be tcp or udp")
        canonical["protocols"] = sorted(lowered)
    if params.get("ports") is not None:
        requested_ports = params["ports"]
        if not isinstance(requested_ports, list):
            raise InventoryError("scan_parameters ports must be a list of ports or a-b ranges")
        canonical["ports"] = list(normalize_ports(requested_ports))
    if params.get("options") is not None:
        options = params["options"]
        if not isinstance(options, dict):
            raise InventoryError("scan_parameters options must be an object")
        validate_options(options)
        canonical["options"] = options
    if not canonical:
        raise InventoryError("scan_parameters must not be empty")
    return canonical


def canonical_scope_document(
    scope: Iterable[str],
    scan_parameters: dict[str, Any] | None,
    *,
    schema_version: int,
) -> dict[str, Any]:
    """Build the canonical document that a fingerprint is computed over."""
    document: dict[str, Any] = {
        "schema_version": schema_version,
        "scope": sorted({target.strip() for target in scope}),
    }
    if scan_parameters is not None:
        document["scan_parameters"] = scan_parameters
    return document


def fingerprint_from_document(canonical: dict[str, Any]) -> str:
    """Hash one canonical document with the documented algorithm."""
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return FINGERPRINT_PREFIX + hashlib.sha256(encoded).hexdigest()


def compute_fingerprint(
    scope: Iterable[str],
    scan_parameters: dict[str, Any] | None,
    *,
    schema_version: int,
) -> str:
    """Compute the scope fingerprint for the given requested work.

    ``scan_parameters`` may be raw or already canonical; it is normalized
    here before hashing so both forms produce the same digest.
    """
    canonical = canonical_scope_document(
        scope,
        normalize_scan_parameters(scan_parameters),
        schema_version=schema_version,
    )
    return fingerprint_from_document(canonical)


def is_valid_fingerprint(value: object) -> bool:
    """True when the value is a well-formed ``sha256:`` fingerprint."""
    return isinstance(value, str) and _FINGERPRINT_RE.fullmatch(value) is not None
