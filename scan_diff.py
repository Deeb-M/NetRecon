"""Deterministic comparison of two parsed NetRecon scans."""

from __future__ import annotations

from dataclasses import dataclass

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


def _open_ports(scan: Scan) -> dict[tuple[str, int, str], Port]:
    return {
        (host.address, port.port, port.protocol): port
        for host in scan.hosts
        for port in host.ports
        if port.state.lower() == "open"
    }


def compare_scans(before: Scan, after: Scan) -> tuple[ExposureChange, ...]:
    """Compare open-port exposure without assigning risk or severity."""
    old = _open_ports(before)
    new = _open_ports(after)
    old_hosts = {host.address for host in before.hosts}
    new_hosts = {host.address for host in after.hosts}
    changes: list[ExposureChange] = []

    for host in sorted(old_hosts - new_hosts):
        changes.append(ExposureChange("host_not_observed", host, None, None))

    for key in sorted(old.keys() | new.keys()):
        host, port_number, protocol = key
        old_port = old.get(key)
        new_port = new.get(key)

        if host not in old_hosts or host not in new_hosts:
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
            changes.append(ExposureChange(
                "closed", host, port_number, protocol,
                before_service=old_port.service,
                before_product=old_port.product,
                before_version=old_port.version,
            ))
            continue

        assert old_port is not None and new_port is not None
        before_identity = (old_port.service, old_port.product, old_port.version)
        after_identity = (new_port.service, new_port.product, new_port.version)
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
