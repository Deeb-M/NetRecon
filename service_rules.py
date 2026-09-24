"""General service and context rules for NetRecon."""

from __future__ import annotations

from findings import Finding


def analyze_service_context(host) -> tuple[Finding, ...]:
    findings: list[Finding] = []

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
    application_contexts: dict[tuple[int, str], set[str]] = {}
    for port in host.ports:
        for cpe in port.cpes:
            if cpe.startswith("cpe:/a:"):
                application_contexts.setdefault((port.port, port.protocol), set()).add(cpe)

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
                evidence_source="service:platform",
            )
        )

    for (application_port, application_protocol), application_cpes in sorted(application_contexts.items()):
        findings.append(
            Finding(
                finding_id="service.application.context",
                category="context",
                host=host.address,
                port=application_port,
                protocol=application_protocol,
                severity="info",
                title="Application context identified",
                evidence=f"Application CPE(s): {', '.join(sorted(application_cpes))}.",
                recommendation="Use this application identification as service context and validate it before making version-specific security conclusions.",
                evidence_source="service:application",
            )
        )


    for port in host.ports:
        if port.state.lower() != "open":
            continue

        service = (port.service or "").lower()
        specific_context = False

        if service in {"microsoft-ds", "smb"} or (port.port == 445 and not service):
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

        if service == "netbios-ssn" or (port.port == 139 and not service):
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

        if service == "msrpc" or (port.port == 135 and not service):
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

        if service == "telnet" or (port.port == 23 and not service):
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

        if service == "ftp" or (port.port == 21 and not service):
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
                    evidence_source="service:detection",
                )
            )


    return tuple(findings)
