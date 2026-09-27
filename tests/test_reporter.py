"""Tests for NetRecon text reporting."""

import json
import unittest

from analyzer import Finding
from evidence_collector import (
    CollectionResult,
    CorrelatedEvidenceResult,
    NmapCommand,
    ParsedCollectionResult,
)
from models import Host, Port, Scan, ScriptResult
from reporter import render_evidence_collection, render_evidence_collection_json, render_evidence_collections_json, render_findings, render_host_summaries, render_text


class ReporterTests(unittest.TestCase):
    def test_renders_scan_host_service_and_script_context(self) -> None:
        scan = Scan(
            source="scan.xml",
            scanner="nmap",
            scanner_version="7.95",
            arguments="nmap -sV -oX scan.xml 192.0.2.10",
            elapsed=12.34,
            hosts_up=1,
            hosts_down=0,
            hosts_total=1,
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    hostname="lab.example",
                    addresses=(
                        ("192.0.2.10", "ipv4"),
                        ("00:11:22:33:44:55", "mac"),
                    ),
                    hostnames=("lab.example", "alias.example"),
                    ports=(
                        Port(
                            port=22,
                            protocol="tcp",
                            state="open",
                            service="ssh",
                            product="OpenSSH",
                            version="9.6",
                            confidence=10,
                            scripts=(
                                ScriptResult("ssh-hostkey", "2048 SHA256:example RSA"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        report = render_text(scan)

        self.assertIn("Scanner: nmap 7.95", report)
        self.assertIn("Hosts: 1 parsed / 1 total (1 up, 0 down)", report)
        self.assertIn("Network Summary: 1 up, 1 open ports, 1 unique services", report)
        self.assertIn("Open Services: ssh (1)", report)
        self.assertIn("lab.example [192.0.2.10] (up)", report)
        self.assertIn("mac:00:11:22:33:44:55", report)
        self.assertIn("22/tcp", report)
        self.assertIn("ssh - OpenSSH 9.6", report)
        self.assertIn("[confidence:10]", report)
        self.assertIn("script ssh-hostkey:", report)


    def test_text_report_shows_cross_host_shared_services(self) -> None:
        scan = Scan(
            source="multi.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service="http", product="Apache httpd", version="2.4.68"),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=5357, protocol="tcp", state="open", service="http", product="Microsoft HTTPAPI httpd", version="2.0"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("Shared Services", report)
        self.assertIn("http: 2 hosts", report)
        self.assertIn("192.0.2.10:80/tcp  Apache httpd 2.4.68", report)
        self.assertIn("192.0.2.20:5357/tcp  Microsoft HTTPAPI httpd 2.0", report)

    def test_text_report_normalizes_service_names_in_summaries(self) -> None:
        scan = Scan(
            source="normalized-services.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service=" HTTP "),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
                Host(address="192.0.2.30", status="up", ports=(
                    Port(port=9999, protocol="tcp", state="open", service="   "),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("Network Summary: 3 up, 3 open ports, 2 unique services", report)
        self.assertIn("Open Services: http (2), unknown (1)", report)
        self.assertIn("http: 2 hosts", report)
        self.assertNotIn(" HTTP : 2 hosts", report)

    def test_text_report_normalizes_service_name_in_host_detail(self) -> None:
        scan = Scan(
            source="host-service-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service=" HTTP "),
                    Port(port=9999, protocol="tcp", state="open", service="   "),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("80/tcp open         http", report)
        self.assertIn("9999/tcp open         unknown", report)
        self.assertNotIn(" HTTP ", report)

    def test_text_report_strips_service_metadata_in_host_detail(self) -> None:
        scan = Scan(
            source="host-metadata-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product=" OpenSSH ",
                        version=" 9.6 ",
                        extra_info=" Ubuntu ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("ssh - OpenSSH 9.6 Ubuntu", report)
        self.assertNotIn("  OpenSSH ", report)
        self.assertNotIn(" 9.6  ", report)

    def test_text_report_ignores_whitespace_only_service_metadata(self) -> None:
        scan = Scan(
            source="blank-service-metadata.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product="   ",
                        version=" \t ",
                        extra_info="  ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("22/tcp open         ssh", report)
        self.assertNotIn("ssh -", report)

    def test_text_report_handles_partial_service_metadata(self) -> None:
        scan = Scan(
            source="partial-service-metadata.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product=" OpenSSH ",
                        version=None,
                        extra_info=" Ubuntu ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("ssh - OpenSSH Ubuntu", report)
        self.assertNotIn("OpenSSH  Ubuntu", report)

    def test_text_report_normalizes_protocol_in_host_detail(self) -> None:
        scan = Scan(
            source="host-protocol-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=53, protocol=" UDP ", state="open", service="domain"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("53/udp open", report)
        self.assertNotIn("53/ UDP ", report)

    def test_text_report_normalizes_state_in_host_detail(self) -> None:
        scan = Scan(
            source="host-state-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state=" OPEN ", service="http"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("80/tcp open         http", report)
        self.assertNotIn(" OPEN ", report)

    def test_text_report_normalizes_host_status(self) -> None:
        scan = Scan(
            source="host-status-normalization.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status=" UP ",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service="http"),
                    ),
                ),
            ),
        )

        report = render_text(scan)

        self.assertIn("Network Summary: 1 up, 1 open ports, 1 unique services", report)
        self.assertIn("192.0.2.10 [192.0.2.10] (up)", report)
        self.assertNotIn("( UP )", report)

    def test_text_report_normalizes_protocol_in_shared_service_endpoint(self) -> None:
        scan = Scan(
            source="shared-protocol-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol=" TCP ", state="open", service="http"),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("192.0.2.10:80/tcp", report)
        self.assertNotIn("192.0.2.10:80/ TCP ", report)

    def test_text_report_strips_metadata_in_shared_service_endpoint(self) -> None:
        scan = Scan(
            source="shared-metadata-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product=" Apache httpd ",
                        version=" 2.4.68 ",
                        extra_info="   ",
                    ),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("192.0.2.10:80/tcp  Apache httpd 2.4.68", report)
        self.assertNotIn("  Apache httpd  ", report)
        self.assertNotIn(" 2.4.68  ", report)

    def test_text_report_normalizes_tunnel_in_host_detail(self) -> None:
        scan = Scan(
            source="host-tunnel-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=443,
                        protocol="tcp",
                        state="open",
                        service="https",
                        tunnel=" SSL ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("[tunnel:ssl]", report)
        self.assertNotIn("[tunnel: SSL ]", report)

    def test_text_report_ignores_whitespace_only_tunnel(self) -> None:
        scan = Scan(
            source="blank-tunnel.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=443,
                        protocol="tcp",
                        state="open",
                        service="https",
                        tunnel="   ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("443/tcp open         https", report)
        self.assertNotIn("[tunnel:", report)

    def test_findings_are_prioritized_by_severity(self) -> None:
        findings = (
            Finding("info.context", "context", "192.0.2.10", None, None, "info", "Context", "info evidence", "Review."),
            Finding("medium.config", "configuration", "192.0.2.10", 445, "tcp", "medium", "Configuration review", "medium evidence", "Review."),
            Finding("low.review", "configuration", "192.0.2.10", 80, "tcp", "low", "Low review", "low evidence", "Review."),
        )

        report = render_findings(findings)

        self.assertLess(report.index("[MEDIUM]"), report.index("[LOW]"))
        self.assertLess(report.index("[LOW]"), report.index("[INFO]"))


    def test_equivalent_ipv6_addresses_do_not_create_false_shared_service(self) -> None:
        scan = Scan(source="ipv6.xml", hosts=(
            Host(address="2001:0db8:0000:0000:0000:0000:0000:0001", status="up", ports=(
                Port(port=80, protocol="tcp", state="open", service="http"),
            )),
            Host(address="2001:db8::1", status="up", ports=(
                Port(port=443, protocol="tcp", state="open", service="http"),
            )),
        ))

        report = render_text(scan)
        self.assertNotIn("Shared Services Across Hosts", report)

    def test_summary_status_and_open_state_are_case_insensitive(self) -> None:
        scan = Scan(source="case.xml", hosts=(Host(
            address="192.0.2.10", status="UP", ports=(
                Port(port=80, protocol="tcp", state="OPEN", service="http"),
            ),
        ),))

        report = render_text(scan)
        self.assertIn("Network Summary: 1 up, 1 open ports, 1 unique services", report)
        self.assertIn("80/tcp open", report)


    def test_renders_partial_evidence_collection_failure(self) -> None:
        command = NmapCommand(("nmap",))
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "permission denied"),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(failed,),
            host=Host(address="192.0.2.134", status="up"),
            findings=(),
        )

        report = render_evidence_collection(result)

        self.assertIn("Host: 192.0.2.134", report)
        self.assertIn("Status: partial", report)
        self.assertIn("Failure: permission denied", report)


    def test_renders_timeout_as_partial_evidence_collection_failure(self) -> None:
        command = NmapCommand(("nmap", "-p", "445", "192.0.2.143"))
        timed_out = ParsedCollectionResult(
            result=CollectionResult(
                command,
                124,
                "",
                "Nmap evidence collection timed out",
            ),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(timed_out,),
            host=Host(address="192.0.2.143", status="up"),
            findings=(),
        )

        report = render_evidence_collection(result)

        self.assertIn("Status: partial", report)
        self.assertIn("Failure: Nmap evidence collection timed out", report)

    def test_renders_complete_evidence_collection_without_failure(self) -> None:
        command = NmapCommand(("nmap",))
        successful = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", "warning text"),
            scan=Scan(source="nmap stdout"),
        )
        result = CorrelatedEvidenceResult(
            outcomes=(successful,),
            host=Host(address="192.0.2.135", status="up"),
            findings=(),
        )

        report = render_evidence_collection(result)

        self.assertIn("Host: 192.0.2.135", report)
        self.assertIn("Status: complete", report)
        self.assertNotIn("Failure:", report)


    def test_renders_partial_evidence_collection_as_json(self) -> None:
        command = NmapCommand(("nmap",))
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "permission denied"),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(failed,),
            host=Host(address="192.0.2.136", status="up"),
            findings=(),
        )

        payload = json.loads(render_evidence_collection_json(result))

        self.assertEqual(payload["host"], "192.0.2.136")
        self.assertEqual(payload["status"], "partial")
        self.assertEqual(payload["failures"], ["permission denied"])


    def test_renders_timeout_as_partial_evidence_collection_json(self) -> None:
        command = NmapCommand(("nmap", "-p", "445", "192.0.2.144"))
        timed_out = ParsedCollectionResult(
            result=CollectionResult(
                command,
                124,
                "",
                "Nmap evidence collection timed out",
            ),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(timed_out,),
            host=Host(address="192.0.2.144", status="up"),
            findings=(),
        )

        payload = json.loads(render_evidence_collection_json(result))

        self.assertEqual(payload["status"], "partial")
        self.assertEqual(
            payload["failures"],
            ["Nmap evidence collection timed out"],
        )

    def test_renders_multiple_evidence_collections_as_one_json_document(self) -> None:
        first = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.137", status="up"),
            findings=(),
        )
        second = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.138", status="up"),
            findings=(),
        )

        payload = json.loads(render_evidence_collections_json((first, second)))

        self.assertEqual(
            [item["host"] for item in payload],
            ["192.0.2.137", "192.0.2.138"],
        )
        self.assertEqual([item["status"] for item in payload], ["complete", "complete"])


    def test_evidence_collection_text_report_includes_correlated_findings(self) -> None:
        finding = Finding(
            finding_id="test-evidence",
            category="evidence",
            host="192.0.2.139",
            port=443,
            protocol="tcp",
            severity="info",
            title="Collected TLS evidence",
            evidence="TLS evidence was collected",
            recommendation="Review the collected evidence",
        )
        result = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.139", status="up"),
            findings=(finding,),
        )

        report = render_evidence_collection(result)

        self.assertIn("Findings", report)
        self.assertIn("Collected TLS evidence", report)
        self.assertIn("TLS evidence was collected", report)
        self.assertIn("Host Summary", report)
        self.assertIn(
            "192.0.2.139 — 0 open ports — no open services — 1 findings",
            report,
        )
        self.assertIn("  Severity: info=1", report)


    def test_evidence_collection_json_includes_correlated_findings(self) -> None:
        finding = Finding(
            finding_id="json-evidence",
            category="evidence",
            host="192.0.2.140",
            port=22,
            protocol="tcp",
            severity="info",
            title="Collected SSH evidence",
            evidence="SSH algorithms were collected",
            recommendation="Review the collected algorithms",
        )
        result = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.140", status="up"),
            findings=(finding,),
        )

        payload = json.loads(render_evidence_collection_json(result))

        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["finding_id"], "json-evidence")
        self.assertEqual(payload["findings"][0]["title"], "Collected SSH evidence")


    def test_renders_host_summaries_with_finding_severity_breakdown(self) -> None:
        scan = Scan(
            source="analysis.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service="http"),
                        Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
                    ),
                ),
                Host(address="192.0.2.20", status="up"),
            ),
        )
        findings = (
            Finding("high.one", "test", "192.0.2.10", 445, "tcp", "high", "High", "evidence", "Review."),
            Finding("medium.one", "test", "192.0.2.10", 80, "tcp", "medium", "Medium", "evidence", "Review."),
            Finding("info.one", "test", "192.0.2.10", None, None, "info", "Info", "evidence", "Review."),
        )

        report = render_host_summaries(scan, findings)

        self.assertIn("Host Summary", report)
        self.assertIn("192.0.2.10 — 2 open ports — http, microsoft-ds — 3 findings", report)
        self.assertIn("  Severity: high=1, medium=1, info=1", report)
        self.assertIn("192.0.2.20 — 0 open ports — no open services — 0 findings", report)
        self.assertIn("  Severity: none", report)


if __name__ == "__main__":
    unittest.main()
