"""Evidence-based analysis of normalized Nmap scan data."""

from __future__ import annotations

from dataclasses import dataclass

from models import Scan


@dataclass(frozen=True)
class Finding:
    host: str
    port: int | None
    protocol: str | None
    severity: str
    title: str
    evidence: str
    recommendation: str


def analyze_scan(scan: Scan) -> tuple[Finding, ...]:
    """Return conservative findings that are directly supported by scan evidence."""
    findings: list[Finding] = []

    for host in scan.hosts:
        for port in host.ports:
            if port.state != "open":
                continue

            service = (port.service or "").lower()
            specific_context = False

            if port.port == 445 or service in {"microsoft-ds", "smb"}:
                specific_context = True
                findings.append(
                    Finding(
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        severity="info",
                        title="SMB service exposed",
                        evidence=f"{port.port}/{port.protocol} is open and identified as {port.service or 'SMB-compatible service'}.",
                        recommendation="Review SMB exposure and authorization. In an authorized assessment, verify protocol configuration, signing, accessible shares, and whether guest or anonymous access is permitted.",
                    )
                )

            if port.port == 139 or service == "netbios-ssn":
                specific_context = True
                findings.append(
                    Finding(
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        severity="info",
                        title="NetBIOS session service exposed",
                        evidence=f"{port.port}/{port.protocol} is open and identified as {port.service or 'NetBIOS session service'}.",
                        recommendation="Confirm whether legacy NetBIOS connectivity is required and review its exposure together with SMB.",
                    )
                )

            if port.port == 135 or service == "msrpc":
                specific_context = True
                findings.append(
                    Finding(
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        severity="info",
                        title="Windows RPC endpoint mapper exposed",
                        evidence=f"{port.port}/{port.protocol} is open and identified as {port.service or 'Microsoft RPC'}.",
                        recommendation="Confirm that RPC exposure matches the host's intended role and network boundary; investigate exposed RPC services only within authorized scope.",
                    )
                )

            if service == "telnet" or port.port == 23:
                findings.append(
                    Finding(
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        severity="medium",
                        title="Telnet service exposed",
                        evidence=f"{port.port}/{port.protocol} is open and identified as {port.service or 'Telnet-compatible service'}.",
                        recommendation="Verify whether Telnet is required. Prefer an encrypted administrative protocol such as SSH where possible.",
                    )
                )

            if service == "ftp" or port.port == 21:
                findings.append(
                    Finding(
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        severity="info",
                        title="FTP service exposed",
                        evidence=f"{port.port}/{port.protocol} is open and identified as {port.service or 'FTP-compatible service'}.",
                        recommendation="Review whether FTP is required and whether credentials or transferred data need encrypted transport.",
                    )
                )

            if port.service and not port.product and not specific_context:
                findings.append(
                    Finding(
                        host=host.address,
                        port=port.port,
                        protocol=port.protocol,
                        severity="info",
                        title="Service lacks product identification",
                        evidence=f"Nmap identified service '{port.service}' on {port.port}/{port.protocol} but did not identify a product.",
                        recommendation="Validate the service manually or with authorized service detection before making version-specific security conclusions.",
                    )
                )

    return tuple(findings)
