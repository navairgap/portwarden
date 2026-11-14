"""Offline adapter: nmap XML output to PortWarden inventory format.

PortWarden does not scan networks. This adapter converts the XML
output of a scan the operator already ran (``nmap -oX scan.xml``)
into the inventory format, applying the same strict validation as
hand-written files. The declared scope is authoritative: a host in
the XML that is not covered by the scope is an error, never an
inferred target.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import InventoryError
from .fingerprint import compute_fingerprint
from .hosts import is_host_in_scope, validate_scope_target
from .models import MAX_NAME_LENGTH, PROTOCOLS, SCHEMA_VERSION, Inventory
from .timestamps import format_utc

#: nmap per-port states that map cleanly onto inventory states. Combined
#: states such as open|filtered map to the unknown side (filtered) rather
#: than the optimistic side.
_NMAP_PORT_STATES: dict[str, str] = {
    "open": "open",
    "closed": "closed",
    "filtered": "filtered",
    "unreachable": "unreachable",
    "open|filtered": "filtered",
    "closed|filtered": "filtered",
}

_MAX_SCAN_ARGS = 2000


def _clean_label(value: object) -> str:
    """Bound and strip control characters from scanner-provided text."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(char for char in value if ord(char) >= 32)
    return cleaned.strip()[:MAX_NAME_LENGTH]


@dataclass(frozen=True)
class ImportedPort:
    """One per-port observation from the XML."""

    protocol: str
    port: int
    state: str
    name: str


@dataclass(frozen=True)
class ImportedHost:
    """One host entry from the XML."""

    address: str
    status: str
    timed_out: bool
    ports: tuple[ImportedPort, ...]


@dataclass(frozen=True)
class NmapScan:
    """A parsed nmap XML run, ready to be converted to an inventory."""

    hosts: tuple[ImportedHost, ...]
    protocols: tuple[str, ...]
    requested_ports: tuple[int, ...] | None
    scanner_version: str | None
    args: str | None
    finished_exit: str | None
    finished_epoch: float | None
    source_name: str = "nmap"

    @classmethod
    def parse(cls, data: bytes) -> NmapScan:
        """Parse nmap XML text.

        Raises:
            InventoryError: if the document is not XML, is not an nmap
                run, or contains unusable port or protocol data.
        """
        try:
            root = ET.fromstring(data)
        except ET.ParseError as exc:
            raise InventoryError(f"nmap XML is not parseable: {exc}") from exc
        if root.tag != "nmaprun":
            raise InventoryError("XML root element is not <nmaprun>")

        protocols: set[str] = set()
        requested: set[int] = set()
        for info in root.findall("scaninfo"):
            protocol = (info.get("protocol") or "").strip().lower()
            if not protocol:
                continue
            if protocol not in PROTOCOLS:
                raise InventoryError(
                    f"nmap protocol {protocol!r} cannot be represented; "
                    "only tcp and udp are supported"
                )
            protocols.add(protocol)
            services = info.get("services") or ""
            for token in services.split(","):
                token = token.strip()
                if token:
                    requested.update(
                        _parse_ports_token(token, protocol=protocol)
                    )

        hosts: list[ImportedHost] = []
        for element in root.findall("host"):
            hosts.append(_parse_host(element))
        if not hosts:
            raise InventoryError("nmap XML contains no host entries")

        finished = root.find("runstats/finished")
        finished_exit = finished.get("exit") if finished is not None else None
        finished_epoch: float | None = None
        if finished is not None and finished.get("time"):
            try:
                finished_epoch = float(finished.get("time"))  # type: ignore[arg-type]
            except ValueError:
                finished_epoch = None

        return cls(
            hosts=tuple(hosts),
            protocols=tuple(sorted(protocols)),
            requested_ports=tuple(sorted(requested)) if requested else None,
            scanner_version=root.get("version"),
            args=_clean_label(root.get("args"))[:_MAX_SCAN_ARGS] or None,
            finished_exit=finished_exit,
            finished_epoch=finished_epoch,
        )

    @classmethod
    def load(cls, path: str) -> NmapScan:
        """Load and parse an nmap XML file."""
        with Path(path).open("rb") as stream:
            return cls.parse(stream.read())

    @property
    def is_complete(self) -> bool:
        """True only when every probed host answered and the run succeeded.

        A timed-out host or a down host leaves parts of the requested
        work unobserved, so the scan stays partial: unreachable targets
        are unknown, not empty.
        """
        return (
            self.finished_exit == "success"
            and all(
                host.status == "up" and not host.timed_out for host in self.hosts
            )
        )

    def scanned_at(self) -> datetime | None:
        """The run's finish time as UTC, when the XML recorded one."""
        if self.finished_epoch is None:
            return None
        return datetime.fromtimestamp(self.finished_epoch, tz=timezone.utc)

    def build_inventory(
        self,
        *,
        scope: list[str],
        scanned_at: datetime | None = None,
        include_closed: bool = False,
    ) -> dict[str, Any]:
        """Convert this scan into an inventory document for ``scope``.

        Raises:
            InventoryError: if the scope is empty or invalid, or a host
                in the XML lies outside the declared scope.
        """
        if not scope:
            raise InventoryError("a scope is required; targets are never inferred")
        normalized: list[str] = []
        for target in scope:
            target = target.strip()
            if not target:
                raise InventoryError("scope targets must not be blank")
            validate_scope_target(target)
            if target not in normalized:
                normalized.append(target)
        for host in self.hosts:
            if not is_host_in_scope(host.address, normalized):
                raise InventoryError(
                    f"nmap host {host.address} is outside the declared scope; "
                    "targets are never inferred from scan output"
                )

        services: list[dict[str, Any]] = []
        for host in self.hosts:
            for port in host.ports:
                if port.state == "open" or (
                    include_closed
                    and port.state in {"closed", "filtered", "unreachable"}
                ):
                    services.append(
                        {
                            "host": host.address,
                            "port": port.port,
                            "protocol": port.protocol,
                            "name": port.name,
                            "state": port.state,
                        }
                    )
        services.sort(
            key=lambda item: (item["host"], item["port"], item["protocol"])
        )

        moment = scanned_at if scanned_at is not None else self.scanned_at()
        scan_parameters: dict[str, Any] = {
            "options": {
                "scanner": self.source_name,
                "scanner_version": self.scanner_version or "unknown",
                "scan_args": self.args or "",
            }
        }
        if self.protocols:
            scan_parameters["protocols"] = list(self.protocols)
        if self.requested_ports is not None:
            scan_parameters["ports"] = list(self.requested_ports)

        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "status": "complete" if self.is_complete else "partial",
            "scope": sorted(normalized),
            "services": services,
            "scanned_at": format_utc(moment) if moment else None,
            "scan_parameters": scan_parameters,
        }
        if document["scanned_at"] is None:
            del document["scanned_at"]
        document["scope_fingerprint"] = compute_fingerprint(
            document["scope"], scan_parameters, schema_version=SCHEMA_VERSION
        )
        # Validate our own output through the same strict pipeline every
        # consumer will use; a partial snapshot is still parseable data.
        Inventory.parse(document, require_complete=document["status"] == "complete")
        return document


def _parse_ports_token(token: str, *, protocol: str) -> list[int]:
    """Parse one comma-separated token of an nmap ``services`` attribute."""
    if "-" in token:
        low_text, _, high_text = token.partition("-")
        try:
            low, high = int(low_text), int(high_text)
        except ValueError as exc:
            raise InventoryError(
                f"nmap {protocol} service range is not numeric: {token!r}"
            ) from exc
        if not (1 <= low <= high <= 65535):
            raise InventoryError(f"nmap {protocol} service range is invalid: {token!r}")
        return list(range(low, high + 1))
    try:
        port = int(token)
    except ValueError as exc:
        raise InventoryError(
            f"nmap {protocol} service list is not numeric: {token!r}"
        ) from exc
    if not 1 <= port <= 65535:
        raise InventoryError(f"nmap {protocol} service port is invalid: {token!r}")
    return [port]


def _parse_host(element: ET.Element) -> ImportedHost:
    """Parse one ``<host>`` element."""
    status_element = element.find("status")
    status = (status_element.get("state") if status_element is not None else "") or ""
    timed_out = (element.get("timedout") or "").lower() == "true"

    address = ""
    for address_element in element.findall("address"):
        kind = address_element.get("addrtype")
        if kind in {"ipv4", "ipv6"}:
            address = address_element.get("addr") or ""
            break
    if not address:
        raise InventoryError("nmap host entry has no IPv4/IPv6 address")

    ports: list[ImportedPort] = []
    for port_element in element.findall("ports/port"):
        protocol = (port_element.get("protocol") or "").strip().lower()
        port_text = port_element.get("portid") or ""
        state_element = port_element.find("state")
        raw_state = (state_element.get("state") if state_element is not None else "") or ""
        service_element = port_element.find("service")
        name = _clean_label(service_element.get("name") if service_element is not None else "")
        try:
            port_id = int(port_text)
        except ValueError as exc:
            raise InventoryError(
                f"nmap port id is not numeric: {port_text!r}"
            ) from exc
        if protocol not in PROTOCOLS:
            raise InventoryError(
                f"nmap protocol {protocol!r} cannot be represented; "
                "only tcp and udp are supported"
            )
        if not 1 <= port_id <= 65535:
            raise InventoryError(f"nmap port id is out of range: {port_id}")
        state = _NMAP_PORT_STATES.get(raw_state)
        if state is None:
            raise InventoryError(
                f"nmap port state {raw_state!r} cannot be represented"
            )
        ports.append(
            ImportedPort(
                protocol=protocol, port=port_id, state=state, name=name
            )
        )
    return ImportedHost(
        address=address, status=status, timed_out=timed_out, ports=tuple(ports)
    )
