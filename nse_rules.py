"""NSE-driven intelligence rules for NetRecon."""

from __future__ import annotations

from datetime import datetime
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



from findings import Finding


def analyze_nse_scripts(host, user_hostnames: tuple[str, ...], reference_time: datetime) -> tuple[Finding, ...]:
    findings: list[Finding] = []
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


    return tuple(findings)
