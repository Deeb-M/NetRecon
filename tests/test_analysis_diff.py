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

    def test_explicit_service_finding_is_not_resolved_without_service_detection_evidence(self) -> None:
        finding = Finding(
            finding_id="service.telnet.exposed", category="transport", host="192.0.2.10",
            port=23, protocol="tcp", severity="medium", title="Telnet service exposed",
            evidence="23/tcp is open and identified as telnet.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "23"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open", "telnet"),),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "23"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open"),),
        ),))

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_unknown_evidence_source_fails_closed(self) -> None:
        finding = Finding(
            finding_id="future.context", category="context", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Future evidence",
            evidence="Collected by a future evidence source.", recommendation="review",
            evidence_source="future:collector",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http"),),
        ),))

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_unknown_product_is_not_resolved_without_service_detection_evidence(self) -> None:
        finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service lacks product identification",
            evidence="Nmap identified service 'http' but did not identify a product.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "8080"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "8080"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open"),),
        ),))

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_unknown_product_can_resolve_when_service_detection_finds_product(self) -> None:
        finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service lacks product identification",
            evidence="Nmap identified service 'http' but did not identify a product.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "8080"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "8080"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http", "Apache httpd"),),
        ),))

        changes = compare_findings((finding,), (), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "no_longer_observed")

    def test_application_context_is_not_resolved_when_application_evidence_not_recollected(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE: cpe:/a:apache:http_server:2.4.68.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", cpes=("cpe:/a:apache:http_server:2.4.68",)),
            ),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http"),),
        ),))

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_application_context_can_resolve_when_application_evidence_is_recollected(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE: cpe:/a:apache:http_server:2.4.68.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", cpes=("cpe:/a:apache:http_server:2.4.68",)),
            ),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", cpes=("cpe:/a:nginx:nginx:1.26",)),
            ),
        ),))

        changes = compare_findings((finding,), (), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "no_longer_observed")

    def test_application_context_change_is_reported_with_previous_evidence(self) -> None:
        before_finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): cpe:/a:apache:http_server:2.4.68.", recommendation="review",
            evidence_source="service:application",
        )
        after_finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): cpe:/a:nginx:nginx:1.26.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", cpes=("cpe:/a:apache:http_server:2.4.68",)),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", cpes=("cpe:/a:nginx:nginx:1.26",)),),
        ),))

        changes = compare_findings((before_finding,), (after_finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].finding, after_finding)
        self.assertEqual(changes[0].before_evidence, before_finding.evidence)

    def test_platform_context_is_not_resolved_when_platform_evidence_not_recollected(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="service detection reported OS type(s): Linux.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", os_type="Linux"),
            ),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http"),
            ),
        ),))

        self.assertEqual(compare_findings((finding,), (), before_scan, after_scan), ())

    def test_platform_context_can_resolve_when_platform_evidence_is_recollected(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="service detection reported OS type(s): Linux.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", os_type="Linux"),
            ),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(443, "tcp", "open", "https", os_type="Windows"),
            ),
        ),))

        changes = compare_findings((finding,), (), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "no_longer_observed")

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

    def test_new_service_detection_finding_is_newly_observed_when_detection_was_not_collected_before(self) -> None:
        finding = Finding(
            finding_id="service.telnet.exposed", category="transport", host="192.0.2.10",
            port=23, protocol="tcp", severity="medium", title="Telnet service exposed",
            evidence="23/tcp is open and identified as telnet.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open", "telnet"),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "newly_observed")

    def test_new_application_context_is_newly_observed_when_application_evidence_was_not_collected_before(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): cpe:/a:apache:http_server:2.4.68.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", cpes=("cpe:/a:apache:http_server:2.4.68",)),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "newly_observed")

    def test_new_platform_context_is_newly_observed_when_platform_evidence_was_not_collected_before(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="service detection reported OS type(s): Linux.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", os_type="Linux"),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "newly_observed")

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
