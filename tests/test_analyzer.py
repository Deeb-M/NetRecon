"""Tests for NetRecon analysis findings."""

import unittest

from analyzer import analyze_scan
from models import Host, Port, Scan


class AnalyzerTests(unittest.TestCase):
    def test_flags_telnet_with_direct_evidence(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(port=23, protocol="tcp", state="open", service="telnet"),
            )),),
        )

        findings = analyze_scan(scan)

        self.assertTrue(any(f.title == "Telnet service exposed" for f in findings))
        telnet = next(f for f in findings if f.title == "Telnet service exposed")
        self.assertEqual(telnet.severity, "medium")
        self.assertEqual(telnet.host, "192.0.2.10")
        self.assertIn("23/tcp", telnet.evidence)

    def test_does_not_flag_closed_telnet(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(port=23, protocol="tcp", state="closed", service="telnet"),
            )),),
        )

        self.assertEqual(analyze_scan(scan), ())

    def test_unknown_product_is_informational_not_vulnerability(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(port=80, protocol="tcp", state="open", service="http"),
            )),),
        )

        findings = analyze_scan(scan)

        self.assertTrue(any(f.title == "Service lacks product identification" for f in findings))
        self.assertFalse(any(f.severity in {"high", "critical"} for f in findings))


if __name__ == "__main__":
    unittest.main()
