"""Deterministic comparison of completed inventories.

Semantics follow docs/scan-result-semantics.md: a baseline service may be
reported removed only when the current scan actually observed the port
``closed``. Missing observations, filtered ports, and errored probes stay
``unverified`` — they never erase an accepted service.
"""

from __future__ import annotations

from typing import Any

from .errors import ScopeMismatchError
from .models import UNKNOWN_STATES, Inventory, Service


def _service_dict(service: Service) -> dict[str, Any]:
    return service.as_dict()


def compare(baseline: Inventory, current: Inventory) -> dict[str, list[dict[str, Any]]]:
    """Return deterministic additions, removals, and unverified services.

    Both inventories must describe the same scope. Results are sorted by
    host, then numerically by port, so identical inputs always produce
    identical output.

    Raises:
        ScopeMismatchError: if the two inventories do not describe the
            same scope; the comparison is withheld, not guessed.
    """
    if baseline.scope != current.scope:
        raise ScopeMismatchError("baseline and current inventory scopes do not match")
    old = {service.key: service for service in baseline.services}
    new = {service.key: service for service in current.services}

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []

    for key in sorted(set(old) | set(new)):
        previous = old.get(key)
        observed = new.get(key)
        if observed is not None and observed.state == "open" and (
            previous is None or previous.state != "open"
        ):
            added.append(_service_dict(observed))
            continue
        if previous is not None and previous.state == "open":
            if observed is None:
                unverified.append(
                    {
                        "host": previous.host,
                        "port": previous.port,
                        "protocol": previous.protocol,
                        "name": previous.name,
                        "reason": "missing_from_current",
                    }
                )
            elif observed.state == "closed":
                removed.append(_service_dict(previous))
            elif observed.state in UNKNOWN_STATES:
                unverified.append(
                    {
                        "host": previous.host,
                        "port": previous.port,
                        "protocol": previous.protocol,
                        "name": previous.name,
                        "reason": observed.state,
                    }
                )
            elif observed.name != previous.name:
                changed.append(
                    {
                        "host": previous.host,
                        "port": previous.port,
                        "protocol": previous.protocol,
                        "baseline_name": previous.name,
                        "current_name": observed.name,
                    }
                )
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unverified": unverified,
    }
