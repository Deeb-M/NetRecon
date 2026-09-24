"""Network-level summaries derived from normalized scan data."""

from __future__ import annotations

from dataclasses import dataclass

from models import Scan


@dataclass(frozen=True)
class NetworkSummary:
    parsed_hosts: int
    up_hosts: int
    open_ports: int
    unique_services: tuple[str, ...]
    service_counts: tuple[tuple[str, int], ...]


def summarize_network(scan: Scan) -> NetworkSummary:
    """Summarize host and open-service observations across the scan."""
    up_hosts = sum(1 for host in scan.hosts if host.status == "up")
    open_ports = 0
    counts: dict[str, int] = {}

    for host in scan.hosts:
        for port in host.ports:
            if port.state != "open":
                continue
            open_ports += 1
            service = (port.service or "unknown").lower()
            counts[service] = counts.get(service, 0) + 1

    service_counts = tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    return NetworkSummary(
        parsed_hosts=len(scan.hosts),
        up_hosts=up_hosts,
        open_ports=open_ports,
        unique_services=tuple(sorted(counts)),
        service_counts=service_counts,
    )
