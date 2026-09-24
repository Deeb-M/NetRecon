"""Network-level summaries derived from normalized scan data."""

from __future__ import annotations

from dataclasses import dataclass

from models import Scan
from scan_diff import _host_identity


@dataclass(frozen=True)
class SharedServiceEndpoint:
    host: str
    port: int
    protocol: str
    product: str | None
    version: str | None
    extra_info: str | None


@dataclass(frozen=True)
class SharedService:
    service: str
    host_count: int
    endpoints: tuple[SharedServiceEndpoint, ...]


@dataclass(frozen=True)
class NetworkSummary:
    parsed_hosts: int
    up_hosts: int
    open_ports: int
    unique_services: tuple[str, ...]
    service_counts: tuple[tuple[str, int], ...]


def summarize_network(scan: Scan) -> NetworkSummary:
    """Summarize host and open-service observations across the scan."""
    up_hosts = sum(1 for host in scan.hosts if host.status.strip().lower() == "up")
    open_ports = 0
    counts: dict[str, int] = {}

    for host in scan.hosts:
        for port in host.ports:
            if port.state.strip().lower() != "open":
                continue
            open_ports += 1
            service = port.service.strip().lower() if port.service and port.service.strip() else "unknown"
            counts[service] = counts.get(service, 0) + 1

    service_counts = tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    return NetworkSummary(
        parsed_hosts=len(scan.hosts),
        up_hosts=up_hosts,
        open_ports=open_ports,
        unique_services=tuple(sorted(counts)),
        service_counts=service_counts,
    )


def summarize_shared_services(scan: Scan) -> tuple[SharedService, ...]:
    """Return services observed on open ports across more than one unique host."""
    by_service: dict[str, list[SharedServiceEndpoint]] = {}

    for host in scan.hosts:
        for port in host.ports:
            if port.state.strip().lower() != "open":
                continue
            service = port.service.strip().lower() if port.service and port.service.strip() else "unknown"
            by_service.setdefault(service, []).append(
                SharedServiceEndpoint(
                    host=host.address,
                    port=port.port,
                    protocol=port.protocol,
                    product=port.product,
                    version=port.version,
                    extra_info=port.extra_info,
                )
            )

    shared: list[SharedService] = []
    for service, endpoints in by_service.items():
        hosts = {_host_identity(endpoint.host) for endpoint in endpoints}
        if len(hosts) < 2:
            continue
        shared.append(
            SharedService(
                service=service,
                host_count=len(hosts),
                endpoints=tuple(
                    sorted(endpoints, key=lambda endpoint: (endpoint.host, endpoint.port, endpoint.protocol))
                ),
            )
        )

    return tuple(sorted(shared, key=lambda item: (-item.host_count, item.service)))
