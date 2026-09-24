"""Deterministic comparison of evidence-based NetRecon findings."""

from __future__ import annotations

from dataclasses import dataclass

from findings import Finding
from models import Scan
from scan_diff import _port_was_scanned


@dataclass(frozen=True)
class FindingChange:
    change: str
    finding: Finding


def _identity(finding: Finding) -> tuple[str, str, int | None, str | None]:
    return (
        finding.finding_id,
        finding.host,
        finding.port,
        finding.protocol,
    )


def _evidence_source_observed(scan: Scan, finding: Finding) -> bool:
    source = finding.evidence_source
    if not source or not source.startswith("nse:"):
        return True

    script_id = source.removeprefix("nse:").lower()
    host = next((host for host in scan.hosts if host.address == finding.host), None)
    if host is None:
        return False

    if finding.port is None:
        return any(script.script_id.lower() == script_id for script in host.scripts)

    return any(
        port.port == finding.port
        and (finding.protocol is None or port.protocol.lower() == finding.protocol.lower())
        and any(script.script_id.lower() == script_id for script in port.scripts)
        for port in host.ports
    )


def compare_findings(
    before: tuple[Finding, ...],
    after: tuple[Finding, ...],
    before_scan: Scan,
    after_scan: Scan,
) -> tuple[FindingChange, ...]:
    """Compare findings only for hosts observed in both scans."""
    observed_hosts = ({host.address for host in before_scan.hosts} & {host.address for host in after_scan.hosts})
    old = {_identity(finding): finding for finding in before if finding.host in observed_hosts}
    new = {_identity(finding): finding for finding in after if finding.host in observed_hosts}
    changes: list[FindingChange] = []

    for key in sorted(old.keys() | new.keys(), key=lambda item: (
        item[1],
        item[2] if item[2] is not None else -1,
        item[3] or "",
        item[0],
    )):
        old_finding = old.get(key)
        new_finding = new.get(key)

        if old_finding is None and new_finding is not None:
            changes.append(FindingChange("new", new_finding))
        elif new_finding is None and old_finding is not None:
            if old_finding.port is not None:
                if old_finding.protocol is None or not _port_was_scanned(
                    after_scan, old_finding.port, old_finding.protocol
                ):
                    continue
            if not _evidence_source_observed(after_scan, old_finding):
                continue
            changes.append(FindingChange("no_longer_observed", old_finding))

    return tuple(changes)
