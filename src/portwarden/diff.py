"""Deterministic comparison of completed inventories."""

from __future__ import annotations

from typing import Any

from .errors import ScopeMismatchError
from .models import Inventory


def compare(baseline: Inventory, current: Inventory) -> dict[str, list[dict[str, Any]]]:
    """Return deterministic additions and removals between two inventories.

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
    added = [new[key].as_dict() for key in sorted(new.keys() - old.keys())]
    removed = [old[key].as_dict() for key in sorted(old.keys() - new.keys())]
    return {"added": added, "removed": removed}
