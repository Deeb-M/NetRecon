"""Tests for analysis-diff text reporting."""

import unittest

from analysis_diff import FindingChange
from findings import Finding
from reporter import render_analysis_diff


class AnalysisDiffReporterTests(unittest.TestCase):
    def test_renders_new_and_resolved_findings(self) -> None:
        new = Finding(
            "service.telnet.exposed", "transport", "192.0.2.10", 23, "tcp",
            "medium", "Telnet service exposed", "23/tcp open telnet", "Review exposure",
        )
        resolved = Finding(
            "service.product.unknown", "visibility", "192.0.2.20", 80, "tcp",
            "info", "Service product not identified", "80/tcp open http", "Review service",
        )

        output = render_analysis_diff((
            FindingChange("new", new),
            FindingChange("resolved", resolved),
        ))

        self.assertIn("NEW", output)
        self.assertIn("RESOLVED", output)
        self.assertIn("192.0.2.10:23/tcp", output)
        self.assertIn("192.0.2.20:80/tcp", output)

    def test_renders_no_analysis_changes(self) -> None:
        self.assertEqual(render_analysis_diff(()), "Analysis Changes: none")


if __name__ == "__main__":
    unittest.main()
