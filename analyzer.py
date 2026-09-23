"""Evidence-based analysis of normalized Nmap scan data."""

from __future__ import annotations

from dataclasses import dataclass

from models import Scan


@dataclass(frozen=True)
class Finding:
    finding_id: str
    category: str
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
        os_types = sorted({
            port.os_type
            for port in host.ports
            if port.os_type
        })
        cpes = sorted({
            cpe
            for port in host.ports
            for cpe in port.cpes
        })
        os_cpes = [cpe for cpe in cpes if cpe.startswith("cpe:/o:")]
        application_contexts = sorted({
            (port.port, port.protocol, cpe)
            for port in host.ports
            for cpe in port.cpes
            if cpe.startswith("cpe:/a:")
        })

        if os_types or os_cpes:
            evidence_parts = []
            if os_types:
                evidence_parts.append(f"service detection reported OS type(s): {', '.join(os_types)}")
            if os_cpes:
                evidence_parts.append(f"OS CPE(s): {', '.join(os_cpes)}")
            findings.append(
                Finding(
                    finding_id="host.platform.context",
                    category="context",
                    host=host.address,
                    port=None,
                    protocol=None,
                    severity="info",
                    title="Host platform context identified",
                    evidence="; ".join(evidence_parts) + ".",
                    recommendation="Use this platform context to guide authorized follow-up checks; do not treat service-derived OS identification as definitive host fingerprinting.",
                )
            )

        for application_port, application_protocol, application_cpe in application_contexts:
            findings.append(
                Finding(
                    finding_id="service.application.context",
                    category="context",
                    host=host.address,
                    port=application_port,
                    protocol=application_protocol,
                    severity="info",
                    title="Application context identified",
                    evidence=f"Application CPE: {application_cpe}.",
                    recommendation="Use this application identification as service context and validate it before making version-specific security conclusions.",
                )
            )

        script_contexts = [
            (script, None, None)
            for script in host.scripts
        ]
        script_contexts.extend(
            (script, port.port, port.protocol)
            for port in host.ports
            for script in port.scripts
        )

        for script, script_port, script_protocol in script_contexts:
            script_id = script.script_id.lower()
            output = " ".join(script.output.split())
            normalized_output = output.lower()

            if (
                script_id == "http-title"
                and normalized_output.startswith("directory listing for ")
            ):
                findings.append(
                    Finding(
                        finding_id="http.directory_listing.exposed",
                        category="exposure",
                        host=host.address,
                        port=script_port,
                        protocol=script_protocol,
                        severity="info",
                        title="HTTP directory listing exposed",
                        evidence=f"Nmap http-title reported: {output}",
                        recommendation="Review whether directory browsing is intended and ensure exposed files are appropriate for the service's audience.",
                    )
                )

            if script_id == "http-methods" and "supported methods:" in normalized_output:
                methods_text = output.split(":", 1)[1].strip()
                methods = tuple(method.upper() for method in methods_text.split())
                review_methods = tuple(
                    method
                    for method in methods
                    if method in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
                )
                if review_methods:
                    findings.append(
                        Finding(
                            finding_id="http.methods.review",
                            category="configuration",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="medium",
                            title="HTTP methods require review",
                            evidence=(
                                "Nmap http-methods reported supported methods: "
                                f"{' '.join(methods)}; review methods: {' '.join(review_methods)}"
                            ),
                            recommendation="Confirm that the reported methods are intentionally enabled and appropriately restricted for this service.",
                        )
                    )
                elif methods and set(methods).issubset({"GET", "HEAD"}):
                    findings.append(
                        Finding(
                            finding_id="http.methods.standard_read_only",
                            category="protocol",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="info",
                            title="Standard read-only HTTP methods reported",
                            evidence=f"Nmap http-methods reported supported methods: {' '.join(methods)}",
                            recommendation="Retain the supported-method evidence as HTTP service context; no unusual method is indicated by this result.",
                        )
                    )

            if script_id == "smb-protocols":
                smb1_markers = ("nt lm 0.12", "smbv1", "smb 1")
                smb1_reported = any(marker in normalized_output for marker in smb1_markers)
                findings.append(
                    Finding(
                        finding_id=(
                            "smb.protocol.smb1.reported"
                            if smb1_reported
                            else "smb.protocol.modern_only"
                        ),
                        category="protocol",
                        host=host.address,
                        port=445,
                        protocol="tcp",
                        severity="medium" if smb1_reported else "info",
                        title=(
                            "SMBv1 protocol reported"
                            if smb1_reported
                            else "Modern SMB dialects reported"
                        ),
                        evidence=f"Nmap smb-protocols reported: {output}",
                        recommendation=(
                            "Review whether SMBv1 is required and disable it where possible."
                            if smb1_reported
                            else "Retain this protocol evidence as context and continue reviewing SMB configuration."
                        ),
                    )
                )

            if (
                script_id == "smb2-security-mode"
                and "message signing enabled but not required" in normalized_output
            ):
                findings.append(
                    Finding(
                        finding_id="smb.signing.review",
                        category="configuration",
                        host=host.address,
                        port=445,
                        protocol="tcp",
                        severity="medium",
                        title="SMB signing configuration requires review",
                        evidence=f"Nmap smb2-security-mode reported: {output}",
                        recommendation="Review the SMB signing policy and require signing where appropriate for the environment.",
                    )
                )

        for port in host.ports:
            if port.state != "open":
                continue

            service = (port.service or "").lower()
            specific_context = False

            if port.port == 445 or service in {"microsoft-ds", "smb"}:
                specific_context = True
                findings.append(
                    Finding(
                        finding_id="service.smb.exposed",
                        category="exposure",
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
                        finding_id="service.netbios.exposed",
                        category="exposure",
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
                        finding_id="service.rpc.exposed",
                        category="exposure",
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
                        finding_id="service.telnet.exposed",
                        category="transport",
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
                        finding_id="service.ftp.exposed",
                        category="transport",
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
                        finding_id="service.product.unknown",
                        category="visibility",
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
