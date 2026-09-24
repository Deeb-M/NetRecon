"""Tests for NetRecon finding-to-finding comparison."""

import unittest

from analysis_diff import compare_findings
from findings import Finding
from models import Host, Port, Scan, ScanScope, ScriptResult


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


def _scan(source: str, *addresses: str, services: str = "1-65535") -> Scan:
    return Scan(
        source=source,
        scan_scopes=(ScanScope("tcp", services),),
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

    def test_equivalent_ipv6_text_does_not_change_finding_identity(self) -> None:
        before_finding = Finding(
            finding_id="finding.same", category="test",
            host="2001:0db8:0000:0000:0000:0000:0000:0001",
            port=80, protocol="tcp", severity="info", title="same",
            evidence="evidence", recommendation="review",
        )
        after_finding = Finding(
            finding_id="finding.same", category="test", host="2001:db8::1",
            port=80, protocol="tcp", severity="info", title="same",
            evidence="evidence", recommendation="review",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(
            Host(address=before_finding.host, status="up"),
        ))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(
            Host(address=after_finding.host, status="up"),
        ))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

    def test_protocol_case_does_not_change_finding_identity(self) -> None:
        before_finding = _finding("finding.same")
        after_finding = Finding(
            finding_id=before_finding.finding_id,
            category=before_finding.category,
            host=before_finding.host,
            port=before_finding.port,
            protocol="TCP",
            severity=before_finding.severity,
            title=before_finding.title,
            evidence=before_finding.evidence,
            recommendation=before_finding.recommendation,
        )
        before_scan = _scan("before.xml", "192.0.2.10")
        after_scan = _scan("after.xml", "192.0.2.10")

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
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

    def test_host_down_afterward_does_not_resolve_finding(self) -> None:
        finding = _finding("finding.old")
        before_scan = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up"),),
        )
        after_scan = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="down"),),
        )

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_unknown_host_status_does_not_resolve_finding(self) -> None:
        finding = _finding("finding.old")
        before_scan = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up"),),
        )
        after_scan = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="unknown"),),
        )

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_unscanned_port_does_not_create_no_longer_observed_finding(self) -> None:
        before = (_finding("finding.old"),)
        before_scan = _scan("before.xml", "192.0.2.10", services="80")
        after_scan = _scan("after.xml", "192.0.2.10", services="443")

        self.assertEqual(
            compare_findings(before, (), before_scan, after_scan),
            (),
        )

    def test_missing_nse_collection_does_not_create_no_longer_observed(self) -> None:
        finding = Finding(
            finding_id="http.methods.review",
            category="configuration",
            host="192.0.2.10",
            port=80,
            protocol="tcp",
            severity="medium",
            title="HTTP methods require review",
            evidence="Nmap http-methods reported PUT.",
            recommendation="review",
            evidence_source="nse:http-methods",
        )
        before_scan = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", scripts=(ScriptResult("http-methods", "Supported Methods: GET PUT"),)
            ),)),),
        )
        after_scan = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http"
            ),)),),
        )

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_collected_nse_source_can_confirm_no_longer_observed(self) -> None:
        finding = Finding(
            finding_id="http.methods.review",
            category="configuration",
            host="192.0.2.10",
            port=80,
            protocol="tcp",
            severity="medium",
            title="HTTP methods require review",
            evidence="Nmap http-methods reported PUT.",
            recommendation="review",
            evidence_source="nse:http-methods",
        )
        before_scan = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", scripts=(ScriptResult("http-methods", "Supported Methods: GET PUT"),)
            ),)),),
        )
        after_scan = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", scripts=(ScriptResult("http-methods", "Supported Methods: GET HEAD"),)
            ),)),),
        )

        changes = compare_findings((finding,), (), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "no_longer_observed")

    def test_new_nse_finding_is_newly_observed_when_source_was_not_collected_before(self) -> None:
        finding = Finding(
            finding_id="http.default_page.detected",
            category="context",
            host="192.0.2.10",
            port=80,
            protocol="tcp",
            severity="info",
            title="Default HTTP page detected",
            evidence="Nmap http-title reported a default page.",
            recommendation="review",
            evidence_source="nse:http-title",
        )
        before_scan = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http"),)),),
        )
        after_scan = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", scripts=(ScriptResult("http-title", "Apache2 Debian Default Page: It works"),)
            ),)),),
        )

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "newly_observed")

    def test_new_nse_finding_is_new_when_source_was_collected_before(self) -> None:
        finding = Finding(
            finding_id="http.default_page.detected",
            category="context",
            host="192.0.2.10",
            port=80,
            protocol="tcp",
            severity="info",
            title="Default HTTP page detected",
            evidence="Nmap http-title reported a default page.",
            recommendation="review",
            evidence_source="nse:http-title",
        )
        before_scan = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", scripts=(ScriptResult("http-title", "NetRecon Lab"),)
            ),)),),
        )
        after_scan = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", scripts=(ScriptResult("http-title", "Apache2 Debian Default Page: It works"),)
            ),)),),
        )

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")


if __name__ == "__main__":
    unittest.main()
