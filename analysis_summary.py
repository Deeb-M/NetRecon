"""Analysis-level summaries derived from NetRecon findings."""

from __future__ import annotations

from dataclasses import dataclass

from findings import Finding


@dataclass(frozen=True)
class AnalysisSummary:
    total_findings: int
    affected_hosts: int
    severity_counts: tuple[tuple[str, int], ...]


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def summarize_analysis(findings: tuple[Finding, ...]) -> AnalysisSummary:
    """Summarize findings without assigning an arbitrary risk score."""
    counts: dict[str, int] = {}
    hosts: set[str] = set()

    for finding in findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1
        hosts.add(finding.host)

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

    return AnalysisSummary(
        total_findings=len(findings),
        affected_hosts=len(hosts),
        severity_counts=ordered + remaining,
    )
