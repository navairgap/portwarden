"""Exception types shared across PortWarden."""

from __future__ import annotations


class InventoryError(ValueError):
    """Raised when an inventory is unsafe or unsuitable for comparison."""


class IncompleteInventoryError(InventoryError):
    """Raised when a partial inventory is used where a complete one is required.

    Partial scans must never be promoted to baselines or silently compared,
    because missing observations are not evidence that a service vanished.
    """


class ScopeMismatchError(InventoryError):
    """Raised when a comparison is withheld because scopes are incompatible.

    This is distinct from a parsing error: both inputs may be valid
    inventories that simply describe different authorized work. Callers
    should surface it as a withheld comparison, not as corrupt input.
    """
