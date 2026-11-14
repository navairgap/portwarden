"""Validation for target identifiers: IP literals and hostnames.

Target identity is security-relevant in PortWarden: scope entries decide
which hosts a comparison is allowed to talk about, and service hosts must
belong to that scope. Validation is therefore deliberately strict and
shared by every code path that accepts a host string.
"""

from __future__ import annotations

import ipaddress
import re

from .errors import InventoryError

# IP literals, IPv4 and IPv6 (including zone-free compressed forms), and
# hostnames made of dot-separated labels of letters, digits, and hyphens.
# The single ':' class also admits bare IPv6 addresses without a port.
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")

_MAX_LABEL_LENGTH = 63
_MAX_NAME_LENGTH = 253


def validate_host(host: str) -> None:
    """Validate one target identifier.

    Raises:
        InventoryError: if the value is not an IP literal or a hostname
            composed of well-formed labels.
    """
    if not isinstance(host, str) or not _HOST_RE.fullmatch(host):
        raise InventoryError("host is missing or invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (
            host.startswith(".")
            or host.endswith(".")
            or ".." in host
            or len(host) > _MAX_NAME_LENGTH
            or any(len(label) > _MAX_LABEL_LENGTH for label in host.split("."))
        ):
            raise InventoryError(f"invalid host: {host!r}") from None
