"""Tests for NetRecon finding-to-finding comparison."""

import unittest

from analysis_diff import compare_findings
from findings import Finding
from models import Host, Scan


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


def _scan(source: str, *addresses: str) -> Scan:
    return Scan(
        source=source,
        hosts=tuple(Host(address=address, status="up") for address in addresses),
    )


class AnalysisDiffTests(unittest.TestCase):
    def test_detects_new_and_no_longer_observed_findings(self) -> None:
        before = (_finding("finding.old"), _finding("finding.same"))
        after = (_finding("finding.same"), _finding("finding.new"))
        before_scan = _scan("before.xml", "192.0.2.10")
        after_scan = _scan("after.xml", "192.0.2.10")

        changes = compare_findings(before, after, before_scan, after_scan)

        self.assertEqual(
            [(change.change, change.finding.finding_id) for change in changes],
            [("new", "finding.new"), ("no_longer_observed", "finding.old")],
        )

    def test_evidence_change_does_not_change_finding_identity(self) -> None:
        before = (_finding("finding.same", evidence="before"),)
        after = (_finding("finding.same", evidence="after"),)
        before_scan = _scan("before.xml", "192.0.2.10")
        after_scan = _scan("after.xml", "192.0.2.10")

        self.assertEqual(
            compare_findings(before, after, before_scan, after_scan),
            (),
        )

    def test_missing_host_does_not_create_no_longer_observed_findings(self) -> None:
        before = (_finding("finding.old"),)
        before_scan = _scan("before.xml", "192.0.2.10")
        after_scan = _scan("after.xml")

        self.assertEqual(
            compare_findings(before, (), before_scan, after_scan),
            (),
        )


if __name__ == "__main__":
    unittest.main()
