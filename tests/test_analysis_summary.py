import unittest

from analysis_summary import summarize_analysis
from findings import Finding


class AnalysisSummaryTests(unittest.TestCase):
    def test_summarizes_findings_hosts_and_severities(self) -> None:
        findings = (
            Finding("f1", "configuration", "192.0.2.10", 443, "tcp", "medium", "One", "e1", "r1"),
            Finding("f2", "exposure", "192.0.2.10", 80, "tcp", "info", "Two", "e2", "r2"),
            Finding("f3", "transport", "192.0.2.20", 23, "tcp", "medium", "Three", "e3", "r3"),
        )

        summary = summarize_analysis(findings)

        self.assertEqual(summary.total_findings, 3)
        self.assertEqual(summary.affected_hosts, 2)
        self.assertEqual(summary.severity_counts, (("medium", 2), ("info", 1)))


if __name__ == "__main__":
    unittest.main()
