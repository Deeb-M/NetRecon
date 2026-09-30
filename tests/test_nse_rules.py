import unittest
from datetime import datetime, timezone

from models import Host, Port, ScriptResult
from nse_rules import analyze_nse_scripts


class NseRulesTests(unittest.TestCase):
    def test_http_directory_listing_produces_exposure_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="http-title", output="Directory listing for /"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "http.directory_listing.exposed")
        self.assertEqual(finding.category, "exposure")
        self.assertEqual(finding.port, 80)
        self.assertEqual(finding.protocol, "tcp")
        self.assertEqual(finding.evidence_source, "nse:http-title")

    def test_http_risky_methods_produce_review_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="http-methods", output="Supported Methods: GET HEAD PUT DELETE"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "http.methods.review")
        self.assertEqual(finding.category, "configuration")
        self.assertEqual(finding.severity, "medium")
        self.assertIn("PUT DELETE", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:http-methods")

    def test_http_standard_methods_produce_read_only_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="http-methods", output="Supported Methods: GET HEAD"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "http.methods.standard_read_only")
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "info")
        self.assertEqual(finding.evidence_source, "nse:http-methods")

    def test_rpc_service_mapping_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=111,
                    protocol="tcp",
                    state="open",
                    service="rpcbind",
                    scripts=(
                        ScriptResult(
                            script_id="rpcinfo",
                            output=(
                                "program version port/proto service "
                                "100000 2 111/tcp rpcbind "
                                "100000 2 111/udp rpcbind "
                                "100003 2,3,4 2049/tcp nfs "
                                "100003 2,3,4 2049/udp nfs "
                                "100005 1,2,3 33508/tcp mountd "
                                "100021 1,3,4 39532/tcp nlockmgr "
                                "100024 1 49509/tcp status"
                            ),
                        ),
                    ),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 30, tzinfo=timezone.utc),
        )

        rpc_findings = [
            finding
            for finding in findings
            if finding.finding_id == "rpc.service.mapping"
        ]

        self.assertEqual(len(rpc_findings), 1)
        finding = rpc_findings[0]
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "info")
        self.assertIn("100003", finding.evidence)
        self.assertIn("2049/tcp", finding.evidence)
        self.assertIn("nfs", finding.evidence)
        self.assertIn("mountd", finding.evidence)
        self.assertIn("nlockmgr", finding.evidence)
        self.assertIn("status", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:rpcinfo")

    def test_smtp_capability_inventory_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=25,
                    protocol="tcp",
                    state="open",
                    scripts=(
                        ScriptResult(
                            script_id="smtp-commands",
                            output=(
                                "mail.example.test, PIPELINING, SIZE 10240000, "
                                "VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, "
                                "8BITMIME, DSN"
                            ),
                        ),
                    ),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "smtp.capabilities.inventory")
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "info")
        self.assertIn("PIPELINING", finding.evidence)
        self.assertIn("VRFY", finding.evidence)
        self.assertIn("STARTTLS", finding.evidence)
        self.assertIn("DSN", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:smtp-commands")

    def test_smtp_starttls_is_advertised_capability_not_tls_validation(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=25,
                    protocol="tcp",
                    state="open",
                    scripts=(
                        ScriptResult(
                            script_id="smtp-commands",
                            output="mail.example.test, PIPELINING, STARTTLS, DSN",
                        ),
                    ),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        finding = next(
            finding
            for finding in findings
            if finding.finding_id == "smtp.capabilities.inventory"
        )

        self.assertIn("STARTTLS", finding.evidence)
        self.assertIn("advertised SMTP capabilities", finding.evidence)
        self.assertIn("does not establish", finding.recommendation)
        self.assertIn("TLS was negotiated", finding.recommendation)
        self.assertIn("security properties were validated", finding.recommendation)

    def test_ssh_algorithm_inventory_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssh2-enum-algos", output="kex_algorithms: curve25519-sha256 encryption_algorithms: aes256-gcm@openssh.com"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "ssh.algorithms.inventory")
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "info")
        self.assertIn("kex_algorithms", finding.evidence)
        self.assertIn("encryption_algorithms", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:ssh2-enum-algos")

    def test_ssh_legacy_kex_requires_review(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol="tcp",
                    state="open",
                    scripts=(
                        ScriptResult(
                            script_id="ssh2-enum-algos",
                            output=(
                                "kex_algorithms:\n"
                                "  curve25519-sha256\n"
                                "  diffie-hellman-group1-sha1\n"
                                "  diffie-hellman-group-exchange-sha1\n"
                                "encryption_algorithms:\n"
                                "  aes256-gcm@openssh.com"
                            ),
                        ),
                    ),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        finding = next(
            finding
            for finding in findings
            if finding.finding_id == "ssh.kex.legacy_review"
        )
        self.assertEqual(finding.category, "configuration")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.port, 22)
        self.assertIn("diffie-hellman-group1-sha1", finding.evidence)
        self.assertIn("diffie-hellman-group-exchange-sha1", finding.evidence)
        self.assertNotIn("curve25519-sha256", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:ssh2-enum-algos")

    def test_expired_tls_certificate_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-cert", output="Not valid before: 2025-01-01T00:00:00 Not valid after: 2026-01-01T00:00:00"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "tls.certificate.expired")
        self.assertEqual(finding.category, "certificate")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.port, 443)
        self.assertEqual(finding.evidence_source, "nse:ssl-cert")

    def test_not_yet_valid_tls_certificate_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-cert", output="Not valid before: 2027-01-01T00:00:00 Not valid after: 2028-01-01T00:00:00"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "tls.certificate.not_yet_valid")
        self.assertEqual(finding.category, "certificate")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.evidence_source, "nse:ssl-cert")

    def test_tls_certificate_identity_mismatch_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-cert", output="Subject Alternative Name: DNS:www.example.com Issuer: Example CA"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=("api.example.com",),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "tls.certificate.identity_mismatch")
        self.assertEqual(finding.category, "certificate")
        self.assertEqual(finding.severity, "medium")
        self.assertIn("api.example.com", finding.evidence)
        self.assertIn("www.example.com", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:ssl-cert")

    def test_tls_certificate_matching_san_has_no_identity_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-cert", output="Subject Alternative Name: DNS:api.example.com Issuer: Example CA"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=("api.example.com",),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(findings, ())

    def test_tls_certificate_wildcard_san_matches_one_label(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-cert", output="Subject Alternative Name: DNS:*.example.com Issuer: Example CA"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=("api.example.com",),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(findings, ())

    def test_tls_certificate_wildcard_san_does_not_match_multiple_labels(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-cert", output="Subject Alternative Name: DNS:*.example.com Issuer: Example CA"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=("deep.api.example.com",),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "tls.certificate.identity_mismatch")

    def test_legacy_tls_protocol_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-enum-ciphers", output="TLSv1.0: ciphers TLSv1.2: ciphers"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "tls.protocol.legacy_enabled")
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "medium")
        self.assertIn("TLSv1.0", finding.evidence)
        self.assertEqual(finding.evidence_source, "nse:ssl-enum-ciphers")

    def test_anonymous_tls_key_exchange_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="ssl-enum-ciphers", output="TLSv1.2: anonymous key exchange"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "tls.key_exchange.anonymous")
        self.assertEqual(finding.category, "configuration")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.evidence_source, "nse:ssl-enum-ciphers")

    def test_smb1_protocol_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="smb-protocols", output="dialects: NT LM 0.12 SMB 2.02 SMB 3.11"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "smb.protocol.smb1.reported")
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.port, 445)
        self.assertEqual(finding.protocol, "tcp")
        self.assertEqual(finding.evidence_source, "nse:smb-protocols")

    def test_modern_smb_protocol_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="smb-protocols", output="dialects: SMB 2.02 SMB 3.11"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "smb.protocol.modern_only")
        self.assertEqual(finding.category, "protocol")
        self.assertEqual(finding.severity, "info")
        self.assertEqual(finding.evidence_source, "nse:smb-protocols")

    def test_smb_signing_review_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(script_id="smb2-security-mode", output="Message signing enabled but not required"),),
                ),
            ),
        )

        findings = analyze_nse_scripts(
            host,
            user_hostnames=(),
            reference_time=datetime(2026, 9, 25, tzinfo=timezone.utc),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "smb.signing.review")
        self.assertEqual(finding.category, "configuration")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.port, 445)
        self.assertEqual(finding.protocol, "tcp")
        self.assertEqual(finding.evidence_source, "nse:smb2-security-mode")


if __name__ == "__main__":
    unittest.main()
