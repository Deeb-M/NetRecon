"""Human-readable reporting for NetRecon."""

from __future__ import annotations

from models import Host, Port, Scan


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

    for host in scan.hosts:
        lines.append("")
        lines.extend(_host_lines(host))

    return "\n".join(lines)
