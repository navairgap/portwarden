"""Validation for target identifiers: IP literals and hostnames.

Target identity is security-relevant in PortWarden: scope entries decide
which hosts a comparison is allowed to talk about, and service hosts must
belong to that scope. Validation is therefore deliberately strict and
shared by every code path that accepts a host string.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

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


def validate_scope_target(target: str) -> None:
    """Validate one scope target: a host identifier or a CIDR subnet.

    Raises:
        InventoryError: if the value is neither a valid host nor a CIDR
            network with every host bit zero.
    """
    try:
        validate_host(target)
        return
    except InventoryError:
        pass  # fall through to CIDR parsing
    try:
        ipaddress.ip_network(target, strict=True)
    except ValueError:
        raise InventoryError(f"invalid scope target: {target!r}") from None


def is_host_in_scope(host: str, scope: Iterable[str]) -> bool:
    """Return True when ``host`` belongs to the declared scope.

    A host belongs to the scope when it matches a target exactly, or when
    it is an IP literal inside a CIDR target (an authorized subnet).
    Hostnames never match subnets implicitly: name-to-address resolution
    is an observation, not an identity.
    """
    targets = tuple(scope)
    if host in targets:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=True)
        except ValueError:
            continue  # plain hostnames and host targets are not networks
        if address.version == network.version and address in network:
            return True
    return False
