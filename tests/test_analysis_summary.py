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

    def test_severity_counts_follow_canonical_order(self) -> None:
        findings = (
            Finding("f1", "x", "h1", None, None, "info", "One", "e", "r"),
            Finding("f2", "x", "h2", None, None, "critical", "Two", "e", "r"),
            Finding("f3", "x", "h3", None, None, "low", "Three", "e", "r"),
            Finding("f4", "x", "h4", None, None, "high", "Four", "e", "r"),
            Finding("f5", "x", "h5", None, None, "medium", "Five", "e", "r"),
        )

        summary = summarize_analysis(findings)

        self.assertEqual(
            summary.severity_counts,
            (("critical", 1), ("high", 1), ("medium", 1), ("low", 1), ("info", 1)),
        )

    def test_unknown_severities_are_sorted_after_canonical_severities(self) -> None:
        findings = (
            Finding("f1", "x", "h1", None, None, "warning", "One", "e", "r"),
            Finding("f2", "x", "h2", None, None, "medium", "Two", "e", "r"),
            Finding("f3", "x", "h3", None, None, "advisory", "Three", "e", "r"),
            Finding("f4", "x", "h4", None, None, "WARNING", "Four", "e", "r"),
        )

        summary = summarize_analysis(findings)

        self.assertEqual(
            summary.severity_counts,
            (("medium", 1), ("advisory", 1), ("warning", 2)),
        )


if __name__ == "__main__":
    unittest.main()
