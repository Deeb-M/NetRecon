"""Tests for NetRecon finding-to-finding comparison."""

import unittest

from analysis_diff import compare_findings
from findings import Finding


def _finding(finding_id: str, *, evidence: str = "evidence") -> Finding:
    return Finding(
        finding_id=finding_id,
        category="test",
        host="192.0.2.10",
        port=80,
        protocol="tcp",
        severity="info",
        title=finding_id,
        evidence=evidence,
        recommendation="review",
    )


class AnalysisDiffTests(unittest.TestCase):
    def test_detects_new_and_no_longer_observed_findings(self) -> None:
        before = (_finding("finding.old"), _finding("finding.same"))
        after = (_finding("finding.same"), _finding("finding.new"))

        changes = compare_findings(before, after)

        self.assertEqual(
            [(change.change, change.finding.finding_id) for change in changes],
            [("new", "finding.new"), ("no_longer_observed", "finding.old")],
        )

    def test_evidence_change_does_not_change_finding_identity(self) -> None:
        before = (_finding("finding.same", evidence="before"),)
        after = (_finding("finding.same", evidence="after"),)

        self.assertEqual(compare_findings(before, after), ())


if __name__ == "__main__":
    unittest.main()
