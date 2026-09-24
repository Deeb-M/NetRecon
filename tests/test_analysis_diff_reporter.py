"""Tests for analysis-diff text reporting."""

import json
import unittest

from analysis_diff import FindingChange
from findings import Finding
from reporter import render_analysis_diff, render_analysis_diff_json


class AnalysisDiffReporterTests(unittest.TestCase):
    def test_renders_new_and_no_longer_observed_findings(self) -> None:
        new = Finding(
            "service.telnet.exposed", "transport", "192.0.2.10", 23, "tcp",
            "medium", "Telnet service exposed", "23/tcp open telnet", "Review exposure",
        )
        resolved = Finding(
            "service.product.unknown", "visibility", "192.0.2.20", 80, "tcp",
            "info", "Service product not identified", "80/tcp open http", "Review service",
        )

        output = render_analysis_diff((
            FindingChange("newly_observed", new),
            FindingChange("no_longer_observed", resolved),
        ))

        self.assertIn("NEWLY_OBSERVED", output)
        self.assertIn("NO_LONGER_OBSERVED", output)
        self.assertIn("192.0.2.10:23/tcp", output)
        self.assertIn("192.0.2.20:80/tcp", output)

    def test_renders_no_analysis_changes(self) -> None:
        self.assertEqual(render_analysis_diff(()), "Analysis Changes: none")

    def test_renders_analysis_diff_json_with_evidence_provenance(self) -> None:
        finding = Finding(
            "http.default_page.detected", "context", "192.0.2.10", 80, "tcp",
            "info", "Default HTTP page detected", "Nmap http-title reported a default page.",
            "Review deployment", evidence_source="nse:http-title",
        )

        payload = json.loads(render_analysis_diff_json((FindingChange("newly_observed", finding),)))

        self.assertEqual(payload["change_type"], "analysis")
        self.assertEqual(payload["changes"][0]["change"], "newly_observed")
        self.assertEqual(payload["changes"][0]["finding"]["finding_id"], "http.default_page.detected")
        self.assertEqual(payload["changes"][0]["finding"]["evidence_source"], "nse:http-title")


if __name__ == "__main__":
    unittest.main()
