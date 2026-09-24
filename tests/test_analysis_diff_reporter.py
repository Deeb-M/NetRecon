"""Tests for analysis-diff text reporting."""

import json
import unittest

from analysis_diff import FindingChange
from findings import Finding
from models import Scan, ScanScope
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

        self.assertIn("Summary: NEWLY_OBSERVED=1, NO_LONGER_OBSERVED=1", output)
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
        self.assertEqual(payload["summary"], {"newly_observed": 1})
        self.assertEqual(payload["changes"][0]["change"], "newly_observed")
        self.assertEqual(payload["changes"][0]["finding"]["finding_id"], "http.default_page.detected")
        self.assertEqual(payload["changes"][0]["finding"]["evidence_source"], "nse:http-title")

    def test_renders_scan_coverage_in_analysis_diff(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80,443"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "443"),))
        finding = Finding(
            "http.default_page.detected", "context", "192.0.2.10", 80, "tcp",
            "info", "Default HTTP page detected", "Observed default page.",
            "Review deployment", evidence_source="nse:http-title",
        )
        changes = (FindingChange("newly_observed", finding),)

        output = render_analysis_diff(changes, before, after)
        payload = json.loads(render_analysis_diff_json(changes, before, after))

        self.assertIn("Before Coverage: tcp:80,443", output)
        self.assertIn("After Coverage:  tcp:443", output)
        self.assertIn("Coverage Changed: YES", output)
        self.assertIn("No Longer Scanned: tcp/80", output)
        self.assertTrue(payload["coverage"]["changed"])
        self.assertEqual(payload["coverage"]["newly_scanned"], [])
        self.assertEqual(payload["coverage"]["no_longer_scanned"], ["tcp/80"])

    def test_renders_analysis_coverage_when_there_are_no_changes(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80,443"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "443"),))

        output = render_analysis_diff((), before, after)

        self.assertIn("Summary: none", output)
        self.assertIn("Before Coverage: tcp:80,443", output)
        self.assertIn("After Coverage:  tcp:443", output)
        self.assertIn("Coverage Changed: YES", output)
        self.assertIn("Newly Scanned: none", output)
        self.assertIn("No Longer Scanned: tcp/80", output)
        self.assertIn("Changes: none", output)


if __name__ == "__main__":
    unittest.main()
