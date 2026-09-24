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

    def test_unknown_product_evidence_wording_change_does_not_create_semantic_change(self) -> None:
        before_finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service lacks product identification",
            evidence="Nmap identified service 'http' on 8080/tcp but did not identify a product.",
            recommendation="review", evidence_source="service:detection",
        )
        after_finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service lacks product identification",
            evidence="Service detection identified http on 8080/tcp; product remains unknown.",
            recommendation="review", evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http"),),
        ),))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

    def test_unknown_product_service_change_is_reported_with_previous_evidence(self) -> None:
        before_finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service lacks product identification",
            evidence="Nmap identified service 'http' on 8080/tcp but did not identify a product.",
            recommendation="review", evidence_source="service:detection",
        )
        after_finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service lacks product identification",
            evidence="Nmap identified service 'http-proxy' on 8080/tcp but did not identify a product.",
            recommendation="review", evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(8080, "tcp", "open", "http-proxy"),),
        ),))

        changes = compare_findings((before_finding,), (after_finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].finding, after_finding)
        self.assertEqual(changes[0].before_evidence, before_finding.evidence)

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

    def test_application_cpe_case_change_does_not_create_semantic_change(self) -> None:
        before_finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): cpe:/a:example:web:1.0.", recommendation="review",
            evidence_source="service:application",
        )
        after_finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): CPE:/A:EXAMPLE:WEB:1.0.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("cpe:/a:example:web:1.0",)
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("CPE:/A:EXAMPLE:WEB:1.0",)
            ),),
        ),))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

    def test_application_context_evidence_wording_change_does_not_create_semantic_change(self) -> None:
        before_finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): cpe:/a:example:web:1.0.", recommendation="review",
            evidence_source="service:application",
        )
        after_finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Detected application context: cpe:/a:example:web:1.0.", recommendation="review",
            evidence_source="service:application",
        )
        cpes = ("cpe:/a:example:web:1.0",)
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(443, "tcp", "open", "https", cpes=cpes),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(443, "tcp", "open", "https", cpes=cpes),),
        ),))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

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

    def test_ssh_algorithm_section_order_change_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms, encryption_algorithms.",
            recommendation="review", evidence_source="nse:ssh2-enum-algos",
        )
        before_output = (
            "kex_algorithms:\\n  curve25519-sha256\\n"
            "encryption_algorithms:\\n  aes128-ctr"
        )
        after_output = (
            "encryption_algorithms:\\n  aes128-ctr\\n"
            "kex_algorithms:\\n  curve25519-sha256"
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", before_output),
            )),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", after_output),
            )),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_ssh_algorithm_inventory_formatting_change_does_not_create_semantic_change(self) -> None:
        before_finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms.", recommendation="review",
            evidence_source="nse:ssh2-enum-algos",
        )
        after_finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="SSH inventory includes the key-exchange section.", recommendation="review",
            evidence_source="nse:ssh2-enum-algos",
        )
        before_output = "kex_algorithms:\\n  curve25519-sha256\\n  diffie-hellman-group14-sha256"
        after_output = "kex_algorithms:\\n    curve25519-sha256\\n    diffie-hellman-group14-sha256\\n"
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", before_output),
            )),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", after_output),
            )),),
        ),))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

    def test_ssh_algorithm_count_only_change_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms.", recommendation="review",
            evidence_source="nse:ssh2-enum-algos",
        )
        before_output = "kex_algorithms: (1)\n  curve25519-sha256"
        after_output = "kex_algorithms: (99)\n  curve25519-sha256"
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", before_output),
            )),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", after_output),
            )),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_ssh_algorithm_inventory_count_header_detects_real_change(self) -> None:
        before_finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms.", recommendation="review",
            evidence_source="nse:ssh2-enum-algos",
        )
        after_finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms.", recommendation="review",
            evidence_source="nse:ssh2-enum-algos",
        )
        before_output = "kex_algorithms: (1)\n  curve25519-sha256"
        after_output = "kex_algorithms: (1)\n  diffie-hellman-group14-sha256"
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", before_output),
            )),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", after_output),
            )),),
        ),))

        changes = compare_findings((before_finding,), (after_finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].before_evidence, before_finding.evidence)

    def test_ssh_algorithm_inventory_change_is_reported_with_previous_evidence(self) -> None:
        before_finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms: curve25519-sha256.",
            recommendation="review", evidence_source="nse:ssh2-enum-algos",
        )
        after_finding = Finding(
            finding_id="ssh.algorithms.inventory", category="protocol", host="192.0.2.10",
            port=22, protocol="tcp", severity="info", title="SSH algorithm inventory collected",
            evidence="Nmap ssh2-enum-algos reported: kex_algorithms: curve25519-sha256, diffie-hellman-group14-sha256.",
            recommendation="review", evidence_source="nse:ssh2-enum-algos",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", "kex_algorithms:\n  curve25519-sha256"),
            )),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(22, "tcp", "open", "ssh", scripts=(
                ScriptResult("ssh2-enum-algos", "kex_algorithms:\n  curve25519-sha256\n  diffie-hellman-group14-sha256"),
            )),),
        ),))

        changes = compare_findings((before_finding,), (after_finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].finding, after_finding)
        self.assertEqual(changes[0].before_evidence, before_finding.evidence)

    def test_platform_os_type_outer_whitespace_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type=" general purpose ",
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="general purpose",
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_platform_os_type_case_change_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="General Purpose",
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="general purpose",
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_platform_os_type_change_is_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="general purpose",
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="router",
            ),),
        ),))

        changes = compare_findings((finding,), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].before_evidence, finding.evidence)

    def test_duplicate_platform_os_type_across_ports_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", os_type="general purpose"),
                Port(443, "tcp", "open", "https", os_type="general purpose"),
            ),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", os_type="general purpose"),
            ),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_platform_cpe_whitespace_counts_as_observed_provenance(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=(" cpe:/o:example:os:1.0 ",),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("cpe:/o:example:os:1.0",),
            ),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_platform_cpe_outer_whitespace_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=(" cpe:/o:example:os:1.0 ",),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("cpe:/o:example:os:1.0",),
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_duplicate_platform_cpe_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=(
                    "cpe:/o:example:os:1.0", "cpe:/o:example:os:1.0",
                ),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("cpe:/o:example:os:1.0",),
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_detected_service_outer_whitespace_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service product not identified",
            evidence="Service detected without product metadata.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                8080, "tcp", "open", " http ",
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                8080, "tcp", "open", "http",
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_whitespace_only_service_does_not_count_as_detection_provenance(self) -> None:
        finding = Finding(
            finding_id="service.product.unknown", category="visibility", host="192.0.2.10",
            port=8080, protocol="tcp", severity="info", title="Service product not identified",
            evidence="Service detected without product metadata.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                8080, "tcp", "open", "   ",
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                8080, "tcp", "open", "http",
            ),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "newly_observed")

    def test_application_cpe_whitespace_counts_as_observed_provenance(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPEs reported by Nmap.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=(" cpe:/a:example:web:1.0 ",),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("cpe:/a:example:web:1.0",),
            ),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_application_cpe_outer_whitespace_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPEs reported by Nmap.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=(" cpe:/a:example:web:1.0 ",),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("cpe:/a:example:web:1.0",),
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_duplicate_application_cpe_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPEs reported by Nmap.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=(
                    "cpe:/a:example:web:1.0", "cpe:/a:example:web:1.0",
                ),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("cpe:/a:example:web:1.0",),
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_application_cpe_order_change_does_not_create_semantic_change(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPEs reported by Nmap.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=(
                    "cpe:/a:example:web:1.0", "cpe:/a:example:module:2.0",
                ),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=(
                    "cpe:/a:example:module:2.0", "cpe:/a:example:web:1.0",
                ),
            ),),
        ),))

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_host_platform_reverse_evidence_type_change_is_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("cpe:/o:example:os:1.0",),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="general purpose",
            ),),
        ),))

        changes = compare_findings((finding,), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].before_evidence, finding.evidence)

    def test_host_platform_evidence_type_change_is_semantic_change(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", os_type="general purpose",
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("cpe:/o:example:os:1.0",),
            ),),
        ),))

        changes = compare_findings((finding,), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "changed")
        self.assertEqual(changes[0].before_evidence, finding.evidence)

    def test_host_platform_uppercase_os_cpe_prefix_counts_as_observed(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Platform context observed",
            evidence="Platform evidence reported by Nmap.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("CPE:/O:Example:OS:1.0",),
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                80, "tcp", "open", "http", cpes=("cpe:/o:example:os:1.0",),
            ),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_platform_cpe_case_change_does_not_create_semantic_change(self) -> None:
        before_finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="OS CPE(s): cpe:/o:linux:linux_kernel.", recommendation="review",
            evidence_source="service:platform",
        )
        after_finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="OS CPE(s): CPE:/O:LINUX:LINUX_KERNEL.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                22, "tcp", "open", "ssh", cpes=("cpe:/o:linux:linux_kernel",)
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                22, "tcp", "open", "ssh", cpes=("CPE:/O:LINUX:LINUX_KERNEL",)
            ),),
        ),))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

    def test_platform_context_evidence_wording_change_does_not_create_semantic_change(self) -> None:
        before_finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="Platform evidence: Linux; cpe:/o:linux:linux_kernel.", recommendation="review",
            evidence_source="service:platform",
        )
        after_finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="Detected platform context: Linux, cpe:/o:linux:linux_kernel.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                22, "tcp", "open", "ssh", os_type="Linux", cpes=("cpe:/o:linux:linux_kernel",)
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                22, "tcp", "open", "ssh", os_type="Linux", cpes=("cpe:/o:linux:linux_kernel",)
            ),),
        ),))

        self.assertEqual(
            compare_findings((before_finding,), (after_finding,), before_scan, after_scan),
            (),
        )

    def test_platform_context_change_is_reported_with_previous_evidence(self) -> None:
        before_finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="service detection reported OS type(s): Linux.", recommendation="review",
            evidence_source="service:platform",
        )
        after_finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="service detection reported OS type(s): Windows.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", os_type="Linux"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", os_type="Windows"),),
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

    def test_protocol_outer_whitespace_does_not_change_finding_identity(self) -> None:
        before_finding = _finding("finding.same")
        after_finding = Finding(
            finding_id=before_finding.finding_id,
            category=before_finding.category,
            host=before_finding.host,
            port=before_finding.port,
            protocol=" TCP ",
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

    def test_protocol_outer_whitespace_matches_service_detection_evidence(self) -> None:
        finding = Finding(
            finding_id="service.telnet.exposed",
            category="transport",
            host="192.0.2.10",
            port=23,
            protocol=" TCP ",
            severity="medium",
            title="Telnet service exposed",
            evidence="23/tcp is open and identified as telnet.",
            recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10",
            status="up",
            ports=(Port(23, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10",
            status="up",
            ports=(Port(23, "tcp", "open", "telnet"),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_host_status_outer_whitespace_does_not_hide_finding_comparison(self) -> None:
        finding = _finding("finding.same")
        before_scan = Scan(
            source="before.xml",
            hosts=(Host(address="192.0.2.10", status=" UP "),),
        )
        after_scan = Scan(
            source="after.xml",
            hosts=(Host(address="192.0.2.10", status="up"),),
        )

        self.assertEqual(
            compare_findings((finding,), (finding,), before_scan, after_scan),
            (),
        )

    def test_host_status_outer_whitespace_keeps_new_finding_comparison_active(self) -> None:
        new_finding = _finding("finding.new")
        before_scan = Scan(
            source="before.xml",
            hosts=(Host(address="192.0.2.10", status=" UP "),),
        )
        after_scan = Scan(
            source="after.xml",
            hosts=(Host(address="192.0.2.10", status="up"),),
        )

        changes = compare_findings((), (new_finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

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

    def test_http_method_state_transition_reports_old_removed_and_new_added(self) -> None:
        before_finding = Finding(
            finding_id="http.methods.standard_read_only", category="protocol", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="Standard read-only HTTP methods reported",
            evidence="Nmap http-methods reported supported methods: GET HEAD", recommendation="review",
            evidence_source="nse:http-methods",
        )
        after_finding = Finding(
            finding_id="http.methods.review", category="configuration", host="192.0.2.10",
            port=80, protocol="tcp", severity="medium", title="HTTP methods require review",
            evidence="Nmap http-methods reported supported methods: GET HEAD PUT; review methods: PUT",
            recommendation="review", evidence_source="nse:http-methods",
        )
        before_scan = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", scripts=(
                ScriptResult("http-methods", "Supported Methods: GET HEAD"),
            )),),
        ),))
        after_scan = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "80"),), hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", scripts=(
                ScriptResult("http-methods", "Supported Methods: GET HEAD PUT"),
            )),),
        ),))

        changes = compare_findings((before_finding,), (after_finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 2)
        self.assertEqual(
            {(change.change, change.finding.finding_id) for change in changes},
            {
                ("no_longer_observed", "http.methods.standard_read_only"),
                ("new", "http.methods.review"),
            },
        )

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

    def test_new_service_detection_finding_is_new_when_detection_was_collected_before(self) -> None:
        finding = Finding(
            finding_id="service.telnet.exposed", category="transport", host="192.0.2.10",
            port=23, protocol="tcp", severity="medium", title="Telnet service exposed",
            evidence="23/tcp is open and identified as telnet.", recommendation="review",
            evidence_source="service:detection",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open", "http"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open", "telnet"),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_application_cpe_prefix_case_counts_as_collected_evidence(self) -> None:
        finding = Finding(
            finding_id="service.application.context", category="context", host="192.0.2.10",
            port=443, protocol="tcp", severity="info", title="Application context identified",
            evidence="Application CPE(s): CPE:/A:Example:Web:1.0.", recommendation="review",
            evidence_source="service:application",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("CPE:/A:Example:Old:1.0",)
            ),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(
                443, "tcp", "open", "https", cpes=("CPE:/A:Example:Web:1.0",)
            ),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_new_application_context_is_new_when_application_evidence_was_collected_before(self) -> None:
        finding = Finding(
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

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

    def test_new_platform_context_is_new_when_platform_evidence_was_collected_before(self) -> None:
        finding = Finding(
            finding_id="host.platform.context", category="context", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="Host platform context identified",
            evidence="service detection reported OS type(s): Windows.", recommendation="review",
            evidence_source="service:platform",
        )
        before_scan = Scan(source="before.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", os_type="Linux"),),
        ),))
        after_scan = Scan(source="after.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(80, "tcp", "open", "http", os_type="Windows"),),
        ),))

        changes = compare_findings((), (finding,), before_scan, after_scan)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "new")

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
