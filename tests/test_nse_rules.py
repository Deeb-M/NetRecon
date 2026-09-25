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


if __name__ == "__main__":
    unittest.main()
