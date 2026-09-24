"""Human-readable reporting for NetRecon."""

from __future__ import annotations

from dataclasses import asdict
import json

from findings import Finding
from models import Host, Port, Scan
from network_summary import summarize_network


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
        "findings": [asdict(finding) for finding in prioritize_findings(findings)],
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
