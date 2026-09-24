"""Human-readable reporting for NetRecon."""

from __future__ import annotations

from dataclasses import asdict
import json

from analysis_diff import FindingChange
from analysis_summary import summarize_analysis
from findings import Finding
from host_summary import summarize_hosts
from models import Host, Port, Scan, ScanScope
from network_summary import summarize_network, summarize_shared_services
from scan_diff import ExposureChange


_SEVERITY_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def prioritize_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Return findings in deterministic analyst-attention order."""
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                _SEVERITY_PRIORITY.get(finding.severity.lower(), 5),
                finding.host,
                finding.port if finding.port is not None else -1,
                finding.finding_id,
            ),
        )
    )


def _service_label(port: Port) -> str:
    parts = [value for value in (port.product, port.version, port.extra_info) if value]
    detected = " ".join(parts)
    service = port.service or "unknown"
    return f"{service} - {detected}" if detected else service


def _host_lines(host: Host) -> list[str]:
    label = host.hostname or host.address
    lines = [f"{label} [{host.address}] ({host.status})"]

    if len(host.addresses) > 1:
        secondary = [
            f"{kind}:{address}"
            for address, kind in host.addresses
            if address != host.address
        ]
        if secondary:
            lines.append(f"  Addresses: {', '.join(secondary)}")

    if len(host.hostnames) > 1:
        lines.append(f"  Names: {', '.join(host.hostnames)}")

    if not host.ports:
        lines.append("  No ports reported")
    else:
        for port in host.ports:
            line = (
                f"  {port.port}/{port.protocol:<3} "
                f"{port.state:<12} {_service_label(port)}"
            )
            if port.tunnel:
                line += f" [tunnel:{port.tunnel}]"
            if port.confidence is not None:
                line += f" [confidence:{port.confidence}]"
            lines.append(line)

            for script in port.scripts:
                output = " ".join(script.output.split())
                lines.append(f"    script {script.script_id}: {output}")

    for script in host.scripts:
        output = " ".join(script.output.split())
        lines.append(f"  host-script {script.script_id}: {output}")

    return lines


def render_text(scan: Scan) -> str:
    """Render a deterministic analyst-friendly text summary."""
    lines = ["NetRecon", "=" * 8, f"Source: {scan.source}"]

    scanner = scan.scanner or "unknown"
    if scan.scanner_version:
        scanner += f" {scan.scanner_version}"
    lines.append(f"Scanner: {scanner}")

    if scan.arguments:
        lines.append(f"Arguments: {scan.arguments}")
    if scan.elapsed is not None:
        lines.append(f"Elapsed: {scan.elapsed:.2f}s")

    reported = len(scan.hosts)
    if scan.hosts_total is not None:
        lines.append(
            f"Hosts: {reported} parsed / {scan.hosts_total} total "
            f"({scan.hosts_up or 0} up, {scan.hosts_down or 0} down)"
        )
    else:
        lines.append(f"Hosts: {reported}")

    summary = summarize_network(scan)
    lines.append(
        f"Network Summary: {summary.up_hosts} up, "
        f"{summary.open_ports} open ports, "
        f"{len(summary.unique_services)} unique services"
    )
    if summary.service_counts:
        services = ", ".join(
            f"{service} ({count})" for service, count in summary.service_counts
        )
        lines.append(f"Open Services: {services}")

    shared_services = summarize_shared_services(scan)
    if shared_services:
        lines.extend(["", "Shared Services", "---------------"])
        for shared in shared_services:
            lines.append(f"{shared.service}: {shared.host_count} hosts")
            for endpoint in shared.endpoints:
                details = " ".join(
                    value
                    for value in (endpoint.product, endpoint.version, endpoint.extra_info)
                    if value
                )
                suffix = f"  {details}" if details else ""
                lines.append(
                    f"  {endpoint.host}:{endpoint.port}/{endpoint.protocol}{suffix}"
                )

    for host in scan.hosts:
        lines.append("")
        lines.extend(_host_lines(host))

    return "\n".join(lines)


def render_json(scan: Scan) -> str:
    """Render the complete parsed scan as stable, machine-readable JSON."""
    return json.dumps(asdict(scan), indent=2, ensure_ascii=False)


def render_analysis_json(scan: Scan, findings: tuple[Finding, ...]) -> str:
    """Render parsed scan data and findings in one machine-readable envelope."""
    payload = {
        "scan": asdict(scan),
        "summary": asdict(summarize_network(scan)),
        "analysis_summary": asdict(summarize_analysis(findings)),
        "shared_services": [asdict(service) for service in summarize_shared_services(scan)],
        "host_summaries": [asdict(summary) for summary in summarize_hosts(scan, findings)],
        "findings": [asdict(finding) for finding in prioritize_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)



def _change_summary(changes: tuple[ExposureChange | FindingChange, ...]) -> dict[str, int]:
    """Count changes by semantic change label in deterministic order."""
    counts: dict[str, int] = {}
    for change in changes:
        counts[change.change] = counts.get(change.change, 0) + 1
    return dict(sorted(counts.items()))


def _coverage_payload(scan: Scan) -> list[dict[str, str]]:
    """Return Nmap-reported scan coverage without inferring unreported scope."""
    return [asdict(scope) for scope in scan.scan_scopes]


def _coverage_text(scan: Scan) -> str:
    if not scan.scan_scopes:
        return "unknown"
    return "; ".join(
        f"{scope.protocol}:{scope.services}" for scope in scan.scan_scopes
    )


def _coverage_changed(before_scan: Scan, after_scan: Scan) -> bool:
    """Return whether Nmap reported different scan scopes."""
    before = {(scope.protocol.lower(), scope.services) for scope in before_scan.scan_scopes}
    after = {(scope.protocol.lower(), scope.services) for scope in after_scan.scan_scopes}
    return before != after


def _expanded_coverage(scan: Scan) -> set[tuple[str, int]]:
    """Expand numeric Nmap scan scopes into protocol/port pairs."""
    covered: set[tuple[str, int]] = set()
    for scope in scan.scan_scopes:
        protocol = scope.protocol.lower()
        for part in scope.services.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    start_text, end_text = part.split("-", 1)
                    start, end = int(start_text), int(end_text)
                    covered.update((protocol, port) for port in range(start, end + 1))
                else:
                    covered.add((protocol, int(part)))
            except ValueError:
                continue
    return covered


def _coverage_difference(before_scan: Scan, after_scan: Scan) -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    """Return newly scanned and no-longer-scanned protocol/port pairs."""
    before = _expanded_coverage(before_scan)
    after = _expanded_coverage(after_scan)
    return tuple(sorted(after - before)), tuple(sorted(before - after))


def _coverage_ports_text(items: tuple[tuple[str, int], ...]) -> str:
    return ", ".join(f"{protocol}/{port}" for protocol, port in items) or "none"


def render_diff_json(changes: tuple[ExposureChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render exposure changes as stable, machine-readable JSON."""
    payload = {
        "change_type": "exposure",
        "summary": _change_summary(changes),
        "changes": [asdict(change) for change in changes],
    }
    if before_scan is not None and after_scan is not None:
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        payload["coverage"] = {
            "changed": _coverage_changed(before_scan, after_scan),
            "before": _coverage_payload(before_scan),
            "after": _coverage_payload(after_scan),
            "newly_scanned": [f"{protocol}/{port}" for protocol, port in newly_scanned],
            "no_longer_scanned": [f"{protocol}/{port}" for protocol, port in no_longer_scanned],
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_analysis_diff_json(changes: tuple[FindingChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render finding changes as stable, machine-readable JSON."""
    payload = {
        "change_type": "analysis",
        "summary": _change_summary(changes),
        "changes": [asdict(change) for change in changes],
    }
    if before_scan is not None and after_scan is not None:
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        payload["coverage"] = {
            "changed": _coverage_changed(before_scan, after_scan),
            "before": _coverage_payload(before_scan),
            "after": _coverage_payload(after_scan),
            "newly_scanned": [f"{protocol}/{port}" for protocol, port in newly_scanned],
            "no_longer_scanned": [f"{protocol}/{port}" for protocol, port in no_longer_scanned],
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_findings(findings: tuple[Finding, ...]) -> str:
    """Render analysis findings separately from raw scan observations."""
    if not findings:
        return "Findings: none"

    ordered_findings = prioritize_findings(findings)
    lines = [f"Findings: {len(ordered_findings)}"]
    for finding in ordered_findings:
        location = finding.host
        if finding.port is not None:
            location += f":{finding.port}/{finding.protocol or 'unknown'}"
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.title}",
                f"  Location: {location}",
                f"  Evidence: {finding.evidence}",
                f"  Recommendation: {finding.recommendation}",
            ]
        )
    return "\n".join(lines)


def render_diff(changes: tuple[ExposureChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render scan-to-scan exposure changes for analyst review."""
    if not changes:
        if before_scan is None or after_scan is None:
            return "Exposure Changes: none"
        return "\n".join([
            "Exposure Changes",
            "----------------",
            "Summary: none",
            f"Before Coverage: {_coverage_text(before_scan)}",
            f"After Coverage:  {_coverage_text(after_scan)}",
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}",
            f"Newly Scanned: {_coverage_ports_text(_coverage_difference(before_scan, after_scan)[0])}",
            f"No Longer Scanned: {_coverage_ports_text(_coverage_difference(before_scan, after_scan)[1])}",
            "Changes: none",
        ])

    summary = _change_summary(changes)
    summary_text = ", ".join(f"{key.upper()}={value}" for key, value in summary.items())
    lines = ["Exposure Changes", "----------------", f"Summary: {summary_text}"]
    if before_scan is not None and after_scan is not None:
        lines.append(f"Before Coverage: {_coverage_text(before_scan)}")
        lines.append(f"After Coverage:  {_coverage_text(after_scan)}")
        lines.append(
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}"
        )
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        lines.append(f"Newly Scanned: {_coverage_ports_text(newly_scanned)}")
        lines.append(f"No Longer Scanned: {_coverage_ports_text(no_longer_scanned)}")
    for change in changes:
        if change.change == "host_not_observed":
            lines.append(f"HOST_NOT_OBSERVED {change.host}")
            continue

        location = f"{change.host}:{change.port}/{change.protocol}"
        if change.change == "new":
            details = " ".join(
                value
                for value in (
                    change.after_service,
                    change.after_product,
                    change.after_version,
                )
                if value
            )
            lines.append(f"NEW     {location}  {details}".rstrip())
        elif change.change == "no_longer_open":
            details = " ".join(
                value
                for value in (
                    change.before_service,
                    change.before_product,
                    change.before_version,
                )
                if value
            )
            lines.append(f"NO_LONGER_OPEN {location}  {details}".rstrip())
        else:
            before = " ".join(
                value
                for value in (
                    change.before_service,
                    change.before_product,
                    change.before_version,
                )
                if value
            ) or "unknown"
            after = " ".join(
                value
                for value in (
                    change.after_service,
                    change.after_product,
                    change.after_version,
                )
                if value
            ) or "unknown"
            lines.append(f"CHANGED {location}  {before} -> {after}")
    return "\n".join(lines)


def render_analysis_diff(changes: tuple[FindingChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render finding changes between two analyzed scans."""
    if not changes:
        if before_scan is None or after_scan is None:
            return "Analysis Changes: none"
        return "\n".join([
            "Analysis Changes",
            "----------------",
            "Summary: none",
            f"Before Coverage: {_coverage_text(before_scan)}",
            f"After Coverage:  {_coverage_text(after_scan)}",
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}",
            f"Newly Scanned: {_coverage_ports_text(_coverage_difference(before_scan, after_scan)[0])}",
            f"No Longer Scanned: {_coverage_ports_text(_coverage_difference(before_scan, after_scan)[1])}",
            "Changes: none",
        ])

    summary = _change_summary(changes)
    summary_text = ", ".join(f"{key.upper()}={value}" for key, value in summary.items())
    lines = ["Analysis Changes", "----------------", f"Summary: {summary_text}"]
    if before_scan is not None and after_scan is not None:
        lines.append(f"Before Coverage: {_coverage_text(before_scan)}")
        lines.append(f"After Coverage:  {_coverage_text(after_scan)}")
        lines.append(
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}"
        )
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        lines.append(f"Newly Scanned: {_coverage_ports_text(newly_scanned)}")
        lines.append(f"No Longer Scanned: {_coverage_ports_text(no_longer_scanned)}")
    for change in changes:
        finding = change.finding
        location = finding.host
        if finding.port is not None:
            location += f":{finding.port}/{finding.protocol or 'unknown'}"
        lines.append(
            f"{change.change.upper():8} [{finding.severity.upper()}] "
            f"{location}  {finding.title}"
        )
        lines.append(f"  Evidence: {finding.evidence}")

    return "\n".join(lines)
