"""Deterministic comparison of evidence-based NetRecon findings."""

from __future__ import annotations

from dataclasses import dataclass

from findings import Finding
from models import Scan
from scan_diff import _host_identity, _port_was_scanned


# For these findings, the rendered evidence represents semantic state rather than
# incidental descriptive text. A change in evidence is therefore meaningful.
_SEMANTIC_EVIDENCE_FINDING_IDS = frozenset({
    "host.platform.context",
    "service.application.context",
    "service.product.unknown",
    "ssh.algorithms.inventory",
})


@dataclass(frozen=True)
class FindingChange:
    change: str
    finding: Finding
    before_evidence: str | None = None


def _identity(finding: Finding) -> tuple[str, str, int | None, str | None]:
    return (
        finding.finding_id,
        _host_identity(finding.host),
        finding.port,
        finding.protocol.lower() if finding.protocol is not None else None,
    )


def _detected_service(scan: Scan, finding: Finding) -> str | None:
    """Return the service identity observed for a finding's endpoint."""
    finding_host = _host_identity(finding.host)
    for host in scan.hosts:
        if _host_identity(host.address) != finding_host:
            continue
        for port in host.ports:
            if port.port != finding.port:
                continue
            if finding.protocol is not None and port.protocol.lower() != finding.protocol.lower():
                continue
            return port.service.lower() if port.service else None
    return None


def _evidence_source_observed(scan: Scan, finding: Finding) -> bool:
    source = finding.evidence_source
    if not source:
        return True

    finding_host = _host_identity(finding.host)
    host = next((host for host in scan.hosts if _host_identity(host.address) == finding_host), None)
    if host is None:
        return False

    if source == "service:platform":
        return any(
            port.os_type
            or any(cpe.startswith("cpe:/o:") for cpe in port.cpes)
            for port in host.ports
        )

    if source == "service:application":
        return any(
            port.port == finding.port
            and (finding.protocol is None or port.protocol.lower() == finding.protocol.lower())
            and any(cpe.startswith("cpe:/a:") for cpe in port.cpes)
            for port in host.ports
        )

    if source == "service:detection":
        return any(
            port.port == finding.port
            and (finding.protocol is None or port.protocol.lower() == finding.protocol.lower())
            and bool(port.service)
            for port in host.ports
        )

    if not source.startswith("nse:"):
        return False

    script_id = source.removeprefix("nse:").lower()
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
    observed_hosts = (
        {_host_identity(host.address) for host in before_scan.hosts if host.status.lower() == "up"}
        & {_host_identity(host.address) for host in after_scan.hosts if host.status.lower() == "up"}
    )
    old = {_identity(finding): finding for finding in before if _host_identity(finding.host) in observed_hosts}
    new = {_identity(finding): finding for finding in after if _host_identity(finding.host) in observed_hosts}
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
            change = (
                "new"
                if _evidence_source_observed(before_scan, new_finding)
                else "newly_observed"
            )
            changes.append(FindingChange(change, new_finding))
        elif old_finding is not None and new_finding is not None:
            if old_finding.finding_id == "service.product.unknown":
                semantic_changed = (
                    _detected_service(before_scan, old_finding)
                    != _detected_service(after_scan, new_finding)
                )
            else:
                semantic_changed = (
                    old_finding.finding_id in _SEMANTIC_EVIDENCE_FINDING_IDS
                    and old_finding.evidence != new_finding.evidence
                )
            if semantic_changed:
                changes.append(FindingChange("changed", new_finding, old_finding.evidence))
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
