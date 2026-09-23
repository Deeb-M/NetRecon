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

    def test_windows_services_get_specific_investigation_context(self) -> None:
        scan = Scan(
            source="windows.xml",
            hosts=(Host(address="192.0.2.20", status="up", ports=(
                Port(port=135, protocol="tcp", state="open", service="msrpc", product="Microsoft Windows RPC"),
                Port(port=139, protocol="tcp", state="open", service="netbios-ssn", product="Microsoft Windows netbios-ssn"),
                Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
            )),),
        )

        findings = analyze_scan(scan)
        titles = {finding.title for finding in findings}

        self.assertIn("Windows RPC endpoint mapper exposed", titles)
        self.assertIn("NetBIOS session service exposed", titles)
        self.assertIn("SMB service exposed", titles)
        self.assertFalse(
            any(
                f.title == "Service lacks product identification" and f.port == 445
                for f in findings
            )
        )
        self.assertTrue(all(f.severity == "info" for f in findings))

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
