"""Evidence-based analysis of normalized Nmap scan data."""

from __future__ import annotations

from datetime import datetime, timezone
import re

from findings import Finding
from models import Scan



def _parse_ssl_cert_time(output: str, label: str) -> datetime | None:
    """Parse an Nmap ssl-cert ISO timestamp as UTC."""
    match = re.search(
        rf"{re.escape(label)}\s*(\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}})",
        output,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    try:
        return datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_ssl_cert_dns_sans(output: str) -> tuple[str, ...]:
    """Extract DNS SAN values from Nmap ssl-cert output."""
    match = re.search(
        r"Subject Alternative Name:\s*(.*?)(?=\s+Issuer:|\s+Public Key type:|\s+Not valid before:|$)",
        output,
        flags=re.IGNORECASE,
    )
    if not match:
        return ()
    return tuple(
        san.strip().rstrip(".").lower()
        for san in re.findall(r"DNS:([^,\s]+)", match.group(1), flags=re.IGNORECASE)
        if san.strip()
    )


def _dns_name_matches(hostname: str, pattern: str) -> bool:
    """Conservative DNS SAN match with support for one-label wildcards."""
    hostname = hostname.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return hostname == pattern


def analyze_scan(scan: Scan, *, now: datetime | None = None) -> tuple[Finding, ...]:
    """Return conservative findings that are directly supported by scan evidence."""
    findings: list[Finding] = []
    reference_time = now or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    for host in scan.hosts:
        user_hostnames = tuple(
            name.rstrip(".").lower()
            for name, hostname_type in host.hostname_records
            if hostname_type.lower() == "user"
        )
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
                supported_marker = "supported methods:"
                supported_start = normalized_output.index(supported_marker) + len(supported_marker)
                methods_text = output[supported_start:].strip()
                risky_marker = " potentially risky methods:"
                methods_text_lower = methods_text.lower()
                if risky_marker in methods_text_lower:
                    methods_text = methods_text[:methods_text_lower.index(risky_marker)].strip()
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

            if script_id == "ssh2-enum-algos":
                sections = tuple(
                    section
                    for section in (
                        "kex_algorithms",
                        "server_host_key_algorithms",
                        "encryption_algorithms",
                        "mac_algorithms",
                        "compression_algorithms",
                    )
                    if f"{section}:" in normalized_output
                )
                if sections:
                    findings.append(
                        Finding(
                            finding_id="ssh.algorithms.inventory",
                            category="protocol",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="info",
                            title="SSH algorithm inventory collected",
                            evidence=(
                                "Nmap ssh2-enum-algos reported: "
                                f"{', '.join(sections)}."
                            ),
                            recommendation=(
                                "Use the reported SSH algorithm inventory as configuration context "
                                "and review individual algorithms against the system's security policy."
                            ),
                        )
                    )

            if script_id == "ssl-cert":
                dns_sans = _parse_ssl_cert_dns_sans(output)
                if user_hostnames and dns_sans:
                    unmatched = tuple(
                        hostname
                        for hostname in user_hostnames
                        if not any(_dns_name_matches(hostname, san) for san in dns_sans)
                    )
                    if unmatched:
                        findings.append(
                            Finding(
                                finding_id="tls.certificate.identity_mismatch",
                                category="certificate",
                                host=host.address,
                                port=script_port,
                                protocol=script_protocol,
                                severity="medium",
                                title="TLS certificate identity mismatch",
                                evidence=(
                                    "Nmap target hostname(s): "
                                    f"{', '.join(user_hostnames)}; certificate DNS SAN(s): "
                                    f"{', '.join(dns_sans)}."
                                ),
                                recommendation=(
                                    "Review the certificate deployment and confirm the service presents "
                                    "a certificate whose DNS SAN covers the hostname used to access it."
                                ),
                            )
                        )

                valid_from = _parse_ssl_cert_time(output, "Not valid before:")
                valid_until = _parse_ssl_cert_time(output, "Not valid after:")
                if valid_until is not None and valid_until < reference_time:
                    findings.append(
                        Finding(
                            finding_id="tls.certificate.expired",
                            category="certificate",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="medium",
                            title="TLS certificate expired",
                            evidence=f"Nmap ssl-cert reported certificate expiry: {valid_until.strftime('%Y-%m-%dT%H:%M:%S')} UTC.",
                            recommendation="Review the certificate deployment and replace or renew the expired certificate where the service is expected to present a valid certificate.",
                        )
                    )
                if valid_from is not None and valid_from > reference_time:
                    findings.append(
                        Finding(
                            finding_id="tls.certificate.not_yet_valid",
                            category="certificate",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="medium",
                            title="TLS certificate not yet valid",
                            evidence=f"Nmap ssl-cert reported certificate validity begins: {valid_from.strftime('%Y-%m-%dT%H:%M:%S')} UTC.",
                            recommendation="Review certificate deployment and system time; confirm the certificate is not being served before its intended validity period.",
                        )
                    )

            if script_id == "ssl-enum-ciphers":
                legacy_versions = tuple(
                    version
                    for version in ("TLSv1.0", "TLSv1.1")
                    if f"{version.lower()}:" in normalized_output
                )
                if legacy_versions:
                    findings.append(
                        Finding(
                            finding_id="tls.protocol.legacy_enabled",
                            category="protocol",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="medium",
                            title="Legacy TLS protocol versions enabled",
                            evidence=(
                                "Nmap ssl-enum-ciphers reported: "
                                f"{', '.join(legacy_versions)}"
                            ),
                            recommendation="Review whether TLS 1.0 or TLS 1.1 compatibility is still required and disable legacy protocol versions where appropriate.",
                        )
                    )

                if "anonymous key exchange" in normalized_output:
                    findings.append(
                        Finding(
                            finding_id="tls.key_exchange.anonymous",
                            category="configuration",
                            host=host.address,
                            port=script_port,
                            protocol=script_protocol,
                            severity="medium",
                            title="Anonymous TLS key exchange reported",
                            evidence="Nmap ssl-enum-ciphers reported anonymous key exchange support.",
                            recommendation="Review the TLS cipher configuration and disable anonymous key-exchange suites unless they are explicitly required.",
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
