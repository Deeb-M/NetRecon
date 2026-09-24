"""Per-host summaries derived from scan observations and findings."""

from __future__ import annotations

from dataclasses import dataclass

from findings import Finding
from models import Scan


@dataclass(frozen=True)
class HostSummary:
    host: str
    status: str
    open_ports: int
    services: tuple[str, ...]
    findings: int


def summarize_hosts(
    scan: Scan,
    findings: tuple[Finding, ...],
) -> tuple[HostSummary, ...]:
    """Build descriptive per-host summaries without assigning risk scores."""
    finding_counts: dict[str, int] = {}
    for finding in findings:
        finding_counts[finding.host] = finding_counts.get(finding.host, 0) + 1

    summaries: list[HostSummary] = []
    for host in scan.hosts:
        open_ports = tuple(port for port in host.ports if port.state.lower() == "open")
        services = tuple(
            sorted({
                port.service.strip().lower()
                if port.service and port.service.strip()
                else "unknown"
                for port in open_ports
            })
        )
        summaries.append(
            HostSummary(
                host=host.address,
                status=host.status,
                open_ports=len(open_ports),
                services=services,
                findings=finding_counts.get(host.address, 0),
            )
        )

    return tuple(summaries)
