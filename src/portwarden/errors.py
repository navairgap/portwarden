"""Exception types shared across PortWarden."""

from __future__ import annotations


class InventoryError(ValueError):
    """Raised when an inventory is unsafe or unsuitable for comparison."""
