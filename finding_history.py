"""Evidence-aware history of NetRecon findings across timestamped scans."""

from __future__ import annotations

from dataclasses import dataclass

from analysis_diff import _evidence_source_observed, _identity
from findings import Finding
from models import Scan


@dataclass(frozen=True)
class FindingHistory:
    finding_id: str
    host: str
    port: int | None
    protocol: str | None
    first_seen: int
    last_seen: int
    observations: int
    opportunities: int


def _scan_timestamp(scan: Scan) -> int:
    if scan.started_at is not None:
        return scan.started_at
    if scan.finished_at is not None:
        return scan.finished_at
    raise ValueError(f"scan timestamp unavailable: {scan.source}")


def summarize_finding_history(
    scans: tuple[Scan, ...],
    findings_by_scan: tuple[tuple[Finding, ...], ...],
) -> tuple[FindingHistory, ...]:
    """Summarize repeated findings only when their supporting evidence was observable."""
    if len(scans) != len(findings_by_scan):
        raise ValueError("scan and finding history lengths differ")

    timestamps = tuple(_scan_timestamp(scan) for scan in scans)
    observed: dict[tuple[str, str, int | None, str | None], list[int]] = {}
    examples: dict[tuple[str, str, int | None, str | None], Finding] = {}

    for timestamp, findings in zip(timestamps, findings_by_scan):
        seen_in_scan: set[tuple[str, str, int | None, str | None]] = set()
        for finding in findings:
            key = _identity(finding)
            examples.setdefault(key, finding)
            seen_in_scan.add(key)
        for key in seen_in_scan:
            observed.setdefault(key, []).append(timestamp)

    opportunities = {key: 0 for key in observed}
    for scan in scans:
        for key, finding in examples.items():
            if key in opportunities and _evidence_source_observed(scan, finding):
                opportunities[key] += 1

    return tuple(
        FindingHistory(
            finding_id=key[0],
            host=key[1],
            port=key[2],
            protocol=key[3],
            first_seen=min(times),
            last_seen=max(times),
            observations=len(times),
            opportunities=opportunities[key],
        )
        for key, times in sorted(
            observed.items(),
            key=lambda item: (
                item[0][1],
                item[0][2] if item[0][2] is not None else -1,
                item[0][3] or "",
                item[0][0],
            ),
        )
    )
