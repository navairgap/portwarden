"""PortWarden: local-first baseline monitoring for exposed services.

PortWarden deliberately does not scan networks. It validates and compares
completed inventory files produced by an operator-approved scanner.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["Inventory", "InventoryError", "Service", "__version__", "compare"]

from .diff import compare
from .errors import InventoryError
from .models import Inventory, Service
