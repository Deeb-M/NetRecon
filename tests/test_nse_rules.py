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


if __name__ == "__main__":
    unittest.main()
