"""Deterministic comparison of two parsed NetRecon scans."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from models import Port, Scan


@dataclass(frozen=True)
class ExposureChange:
    change: str
    host: str
    port: int | None
    protocol: str | None
    before_service: str | None = None
    after_service: str | None = None
    before_product: str | None = None
    after_product: str | None = None
    before_version: str | None = None
    after_version: str | None = None


def _host_identity(address: str) -> str:
    """Normalize IP address text for comparison while preserving raw evidence elsewhere."""
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return address


def _open_ports(scan: Scan) -> dict[tuple[str, int, str], Port]:
    return {
        (_host_identity(host.address), port.port, port.protocol.strip().lower()): port
        for host in scan.hosts
        for port in host.ports
        if port.state.strip().lower() == "open"
    }


def _port_was_scanned(scan: Scan, port_number: int, protocol: str) -> bool:
    for scope in scan.scan_scopes:
        if scope.protocol.strip().lower() != protocol.strip().lower():
            continue
        for part in scope.services.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                try:
                    if int(start_text) <= port_number <= int(end_text):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(part) == port_number:
                        return True
                except ValueError:
                    continue
    return False


def compare_scans(before: Scan, after: Scan) -> tuple[ExposureChange, ...]:
    """Compare open-port exposure without assigning risk or severity."""
    old = _open_ports(before)
    new = _open_ports(after)
    old_hosts = {_host_identity(host.address) for host in before.hosts}
    new_hosts = {_host_identity(host.address) for host in after.hosts}
    comparable_hosts = (
        {_host_identity(host.address) for host in before.hosts if host.status.lower() == "up"}
        & {_host_identity(host.address) for host in after.hosts if host.status.lower() == "up"}
    )
    changes: list[ExposureChange] = []

    for host in sorted(old_hosts - new_hosts):
        changes.append(ExposureChange("host_not_observed", host, None, None))

    for host in sorted(new_hosts - old_hosts):
        changes.append(ExposureChange("host_newly_observed", host, None, None))

    old_status = {_host_identity(host.address): host.status.lower() for host in before.hosts}
    new_status = {_host_identity(host.address): host.status.lower() for host in after.hosts}
    for host in sorted(old_hosts & new_hosts):
        before_status = old_status[host]
        after_status = new_status[host]
        if before_status == after_status:
            continue
        if before_status == "up" and after_status == "down":
            changes.append(ExposureChange("host_down", host, None, None))
        elif before_status == "down" and after_status == "up":
            changes.append(ExposureChange("host_up", host, None, None))

    for key in sorted(old.keys() | new.keys()):
        host, port_number, protocol = key
        old_port = old.get(key)
        new_port = new.get(key)

        if host not in comparable_hosts:
            continue

        if old_port is None and new_port is not None:
            changes.append(ExposureChange(
                "new", host, port_number, protocol,
                after_service=new_port.service,
                after_product=new_port.product,
                after_version=new_port.version,
            ))
            continue

        if new_port is None and old_port is not None:
            if not _port_was_scanned(after, port_number, protocol):
                continue
            changes.append(ExposureChange(
                "no_longer_open", host, port_number, protocol,
                before_service=old_port.service,
                before_product=old_port.product,
                before_version=old_port.version,
            ))
            continue

        assert old_port is not None and new_port is not None
        before_identity = (
            old_port.service.strip().lower() if old_port.service and old_port.service.strip() else None,
            old_port.product.strip() if old_port.product and old_port.product.strip() else None,
            old_port.version.strip() if old_port.version and old_port.version.strip() else None,
        )
        after_identity = (
            new_port.service.strip().lower() if new_port.service and new_port.service.strip() else None,
            new_port.product.strip() if new_port.product and new_port.product.strip() else None,
            new_port.version.strip() if new_port.version and new_port.version.strip() else None,
        )
        if before_identity != after_identity:
            changes.append(ExposureChange(
                "changed", host, port_number, protocol,
                before_service=old_port.service,
                after_service=new_port.service,
                before_product=old_port.product,
                after_product=new_port.product,
                before_version=old_port.version,
                after_version=new_port.version,
            ))

    return tuple(changes)
