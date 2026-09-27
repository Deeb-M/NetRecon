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
    severity_counts: tuple[tuple[str, int], ...]


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _ordered_severity_counts(counts: dict[str, int]) -> tuple[tuple[str, int], ...]:
    ordered = tuple(
        (severity, counts[severity])
        for severity in _SEVERITY_ORDER
        if severity in counts
    )
    remaining = tuple(
        sorted(
            (severity, count)
            for severity, count in counts.items()
            if severity not in _SEVERITY_ORDER
        )
    )
    return ordered + remaining


def summarize_hosts(
    scan: Scan,
    findings: tuple[Finding, ...],
) -> tuple[HostSummary, ...]:
    """Build descriptive per-host summaries without assigning risk scores."""
    finding_counts: dict[str, int] = {}
    severity_counts: dict[str, dict[str, int]] = {}
    for finding in findings:
        finding_counts[finding.host] = finding_counts.get(finding.host, 0) + 1
        severity = finding.severity.strip().lower()
        host_counts = severity_counts.setdefault(finding.host, {})
        host_counts[severity] = host_counts.get(severity, 0) + 1

    summaries: list[HostSummary] = []
    for host in scan.hosts:
        open_ports = tuple(
            port for port in host.ports if port.state.strip().lower() == "open"
        )
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
                status=host.status.strip().lower(),
                open_ports=len(open_ports),
                services=services,
                findings=finding_counts.get(host.address, 0),
                severity_counts=_ordered_severity_counts(
                    severity_counts.get(host.address, {})
                ),
            )
        )

    severity_priority = {
        severity: priority for priority, severity in enumerate(_SEVERITY_ORDER)
    }

    def attention_key(summary: HostSummary) -> tuple[int, str]:
        highest_severity = (
            summary.severity_counts[0][0] if summary.severity_counts else None
        )
        priority = (
            severity_priority.get(highest_severity, len(_SEVERITY_ORDER))
            if highest_severity is not None
            else len(_SEVERITY_ORDER) + 1
        )
        return priority, summary.host

    return tuple(sorted(summaries, key=attention_key))
