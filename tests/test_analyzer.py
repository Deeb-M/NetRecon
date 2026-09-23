"""Tests for NetRecon analysis findings."""

import unittest

from analyzer import analyze_scan
from models import Host, Port, Scan, ScriptResult


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

    def test_service_metadata_creates_deduplicated_host_platform_context(self) -> None:
        scan = Scan(
            source="context.xml",
            hosts=(Host(address="192.0.2.20", status="up", ports=(
                Port(
                    port=135,
                    protocol="tcp",
                    state="open",
                    service="msrpc",
                    os_type="Windows",
                    cpes=("cpe:/o:microsoft:windows",),
                ),
                Port(
                    port=5357,
                    protocol="tcp",
                    state="open",
                    service="http",
                    os_type="Windows",
                    cpes=("cpe:/o:microsoft:windows",),
                ),
            )),),
        )

        findings = analyze_scan(scan)
        contexts = [
            finding for finding in findings
            if finding.finding_id == "host.platform.context"
        ]

        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0].category, "context")
        self.assertIsNone(contexts[0].port)
        self.assertIn("Windows", contexts[0].evidence)
        self.assertEqual(contexts[0].evidence.count("cpe:/o:microsoft:windows"), 1)

    def test_modern_smb_protocol_evidence_is_informational(self) -> None:
        scan = Scan(
            source="smb.xml",
            hosts=(Host(
                address="192.0.2.20",
                status="up",
                scripts=(
                    ScriptResult(
                        script_id="smb-protocols",
                        output="dialects: 2.0.2 2.1 3.0 3.0.2 3.1.1",
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        protocol = next(
            finding for finding in findings
            if finding.finding_id == "smb.protocol.modern_only"
        )

        self.assertEqual(protocol.severity, "info")
        self.assertEqual(protocol.category, "protocol")
        self.assertIn("3.1.1", protocol.evidence)

    def test_explicit_smb1_protocol_evidence_is_medium(self) -> None:
        scan = Scan(
            source="smb.xml",
            hosts=(Host(
                address="192.0.2.20",
                status="up",
                scripts=(
                    ScriptResult(
                        script_id="smb-protocols",
                        output="dialects: NT LM 0.12 (SMBv1) 2.0.2 3.1.1",
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        protocol = next(
            finding for finding in findings
            if finding.finding_id == "smb.protocol.smb1.reported"
        )

        self.assertEqual(protocol.severity, "medium")
        self.assertIn("SMBv1", protocol.title)

    def test_smb_signing_nse_evidence_creates_medium_finding(self) -> None:
        scan = Scan(
            source="smb.xml",
            hosts=(Host(
                address="192.0.2.20",
                status="up",
                scripts=(
                    ScriptResult(
                        script_id="smb2-security-mode",
                        output="3.1.1: Message signing enabled but not required",
                    ),
                ),
                ports=(
                    Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        signing = next(
            finding
            for finding in findings
            if finding.title == "SMB signing configuration requires review"
        )

        self.assertEqual(signing.finding_id, "smb.signing.review")
        self.assertEqual(signing.category, "configuration")
        self.assertEqual(signing.severity, "medium")
        self.assertEqual(signing.port, 445)
        self.assertIn("smb2-security-mode", signing.evidence)
        self.assertIn("enabled but not required", signing.evidence)

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
