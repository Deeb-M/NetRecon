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
        self.assertEqual(data["findings"][0]["finding_id"], "example.finding")
        self.assertEqual(data["findings"][0]["category"], "test")
        self.assertEqual(data["findings"][0]["port"], 445)
        self.assertEqual(data["findings"][0]["severity"], "info")
        self.assertEqual(data["findings"][0]["title"], "Example finding")


if __name__ == "__main__":
    unittest.main()
