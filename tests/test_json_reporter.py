"""Tests for NetRecon JSON reporting."""

import json
import unittest

from models import Host, Port, Scan
from reporter import render_json


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


if __name__ == "__main__":
    unittest.main()
