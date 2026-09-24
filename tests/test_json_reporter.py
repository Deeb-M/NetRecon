"""Tests for NetRecon JSON reporting."""

import json
import unittest

from analyzer import Finding
from models import Host, Port, Scan
from reporter import render_analysis_json, render_json


class JsonReporterTests(unittest.TestCase):
    def test_json_output_is_valid_and_preserves_nested_scan_data(self) -> None:
        scan = Scan(
            source="scan.xml",
            scanner="nmap",
            scanner_version="7.95",
            hosts_total=1,
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(
                            port=443,
                            protocol="tcp",
                            state="open",
                            service="https",
                            product="nginx",
                        ),
                    ),
                ),
            ),
        )

        data = json.loads(render_json(scan))

        self.assertEqual(data["scanner"], "nmap")
        self.assertEqual(data["hosts_total"], 1)
        self.assertEqual(data["hosts"][0]["address"], "192.0.2.10")
        self.assertEqual(data["hosts"][0]["ports"][0]["port"], 443)
        self.assertEqual(data["hosts"][0]["ports"][0]["product"], "nginx")

    def test_analysis_json_reports_services_shared_across_hosts(self) -> None:
        scan = Scan(
            source="multi.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service="http", product="Apache httpd", version="2.4.68"),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=5357, protocol="tcp", state="open", service="http", product="Microsoft HTTPAPI httpd", version="2.0"),
                    Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
                )),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(len(data["shared_services"]), 1)
        shared = data["shared_services"][0]
        self.assertEqual(shared["service"], "http")
        self.assertEqual(shared["host_count"], 2)
        self.assertEqual(
            [(endpoint["host"], endpoint["port"]) for endpoint in shared["endpoints"]],
            [("192.0.2.10", 80), ("192.0.2.20", 5357)],
        )
        self.assertEqual(shared["endpoints"][0]["product"], "Apache httpd")
        self.assertEqual(shared["endpoints"][1]["product"], "Microsoft HTTPAPI httpd")

    def test_analysis_json_contains_scan_and_findings(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(Host(address="192.0.2.10", status="up"),),
        )
        findings = (
            Finding(
                finding_id="example.finding",
                category="test",
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                severity="info",
                title="Example finding",
                evidence="Direct scan evidence",
                recommendation="Review the service configuration.",
            ),
        )

        data = json.loads(render_analysis_json(scan, findings))

        self.assertEqual(data["scan"]["source"], "scan.xml")
        self.assertEqual(data["summary"]["parsed_hosts"], 1)
        self.assertEqual(data["summary"]["up_hosts"], 1)
        self.assertEqual(data["summary"]["open_ports"], 0)
        self.assertEqual(data["summary"]["unique_services"], [])
        self.assertEqual(data["summary"]["service_counts"], [])
        self.assertEqual(data["analysis_summary"]["total_findings"], 1)
        self.assertEqual(data["analysis_summary"]["affected_hosts"], 1)
        self.assertEqual(data["analysis_summary"]["severity_counts"], [["info", 1]])
        self.assertEqual(data["host_summaries"][0]["host"], "192.0.2.10")
        self.assertEqual(data["host_summaries"][0]["status"], "up")
        self.assertEqual(data["host_summaries"][0]["open_ports"], 0)
        self.assertEqual(data["host_summaries"][0]["services"], [])
        self.assertEqual(data["host_summaries"][0]["findings"], 1)
        self.assertEqual(data["findings"][0]["finding_id"], "example.finding")
        self.assertEqual(data["findings"][0]["category"], "test")
        self.assertEqual(data["findings"][0]["port"], 445)
        self.assertEqual(data["findings"][0]["severity"], "info")
        self.assertEqual(data["findings"][0]["title"], "Example finding")


    def test_analysis_json_normalizes_service_names_in_summaries(self) -> None:
        scan = Scan(
            source="services.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service=" HTTP "),
                        Port(port=8080, protocol="tcp", state="open", service="http"),
                        Port(port=9000, protocol="tcp", state="open", service="   "),
                    ),
                ),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(data["summary"]["unique_services"], ["http", "unknown"])
        self.assertEqual(
            data["summary"]["service_counts"],
            [["http", 2], ["unknown", 1]],
        )
        self.assertEqual(
            data["host_summaries"][0]["services"],
            ["http", "unknown"],
        )


    def test_analysis_json_host_summary_normalizes_open_state_whitespace(self) -> None:
        scan = Scan(
            source="host-summary-state.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=80, protocol="tcp", state=" OPEN ", service="http"),
                    ),
                ),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(data["summary"]["open_ports"], 1)
        self.assertEqual(data["host_summaries"][0]["open_ports"], 1)
        self.assertEqual(data["host_summaries"][0]["services"], ["http"])


    def test_analysis_json_host_summary_normalizes_status_whitespace_and_case(self) -> None:
        scan = Scan(
            source="host-summary-status.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status=" UP ",
                ),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(data["summary"]["up_hosts"], 1)
        self.assertEqual(data["host_summaries"][0]["status"], "up")


    def test_analysis_json_normalizes_protocol_in_shared_service_endpoint(self) -> None:
        scan = Scan(
            source="shared-protocol-json.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol=" TCP ", state="open", service="http"),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(data["shared_services"][0]["endpoints"][0]["protocol"], "tcp")


    def test_analysis_json_strips_metadata_in_shared_service_endpoint(self) -> None:
        scan = Scan(
            source="shared-metadata-json.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product=" Apache httpd ",
                        version=" 2.4.68 ",
                        extra_info=" Ubuntu ",
                    ),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))
        endpoint = data["shared_services"][0]["endpoints"][0]

        self.assertEqual(endpoint["product"], "Apache httpd")
        self.assertEqual(endpoint["version"], "2.4.68")
        self.assertEqual(endpoint["extra_info"], "Ubuntu")


    def test_shared_services_normalize_service_name_whitespace_and_case(self) -> None:
        scan = Scan(
            source="multi.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service=" HTTP "),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(len(data["shared_services"]), 1)
        self.assertEqual(data["shared_services"][0]["service"], "http")
        self.assertEqual(data["shared_services"][0]["host_count"], 2)


    def test_shared_services_group_blank_and_missing_service_as_unknown(self) -> None:
        scan = Scan(
            source="multi.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=9000, protocol="tcp", state="open", service=None),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=9001, protocol="tcp", state="open", service="   "),
                )),
            ),
        )

        data = json.loads(render_analysis_json(scan, ()))

        self.assertEqual(len(data["shared_services"]), 1)
        self.assertEqual(data["shared_services"][0]["service"], "unknown")
        self.assertEqual(data["shared_services"][0]["host_count"], 2)


if __name__ == "__main__":
    unittest.main()
