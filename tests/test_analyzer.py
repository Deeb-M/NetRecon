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

    def test_application_cpe_is_not_reported_as_host_platform(self) -> None:
        scan = Scan(
            source="http.xml",
            hosts=(Host(address="127.0.0.1", status="up", ports=(
                Port(
                    port=8080,
                    protocol="tcp",
                    state="open",
                    service="http",
                    product="SimpleHTTPServer",
                    cpes=("cpe:/a:python:simplehttpserver:0.6",),
                ),
            )),),
        )

        findings = analyze_scan(scan)
        ids = {finding.finding_id for finding in findings}

        self.assertIn("service.application.context", ids)
        self.assertNotIn("host.platform.context", ids)
        application = next(
            finding for finding in findings
            if finding.finding_id == "service.application.context"
        )
        self.assertEqual(application.port, 8080)
        self.assertEqual(application.protocol, "tcp")
        self.assertIn("cpe:/a:python:simplehttpserver:0.6", application.evidence)

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

    def test_http_directory_listing_title_creates_exposure_finding(self) -> None:
        scan = Scan(
            source="http.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8080,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product="SimpleHTTPServer",
                        scripts=(
                            ScriptResult(
                                script_id="http-title",
                                output="Directory listing for /",
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        directory = next(
            finding for finding in findings
            if finding.finding_id == "http.directory_listing.exposed"
        )

        self.assertEqual(directory.category, "exposure")
        self.assertEqual(directory.severity, "info")
        self.assertEqual(directory.port, 8080)
        self.assertEqual(directory.protocol, "tcp")
        self.assertIn("Directory listing for /", directory.evidence)

    def test_standard_http_methods_are_informational_with_port_context(self) -> None:
        scan = Scan(
            source="http-methods.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8080,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product="SimpleHTTPServer",
                        scripts=(
                            ScriptResult(
                                script_id="http-methods",
                                output="Supported Methods: GET HEAD",
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        methods = next(
            finding for finding in findings
            if finding.finding_id == "http.methods.standard_read_only"
        )

        self.assertEqual(methods.category, "protocol")
        self.assertEqual(methods.severity, "info")
        self.assertEqual(methods.port, 8080)
        self.assertEqual(methods.protocol, "tcp")
        self.assertIn("GET HEAD", methods.evidence)

    def test_http_methods_requiring_review_create_medium_finding(self) -> None:
        scan = Scan(
            source="http-methods-review.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8081,
                        protocol="tcp",
                        state="open",
                        service="http",
                        scripts=(
                            ScriptResult(
                                script_id="http-methods",
                                output="Supported Methods: GET HEAD PUT DELETE OPTIONS Potentially risky methods: PUT DELETE",
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        review = next(
            finding for finding in findings
            if finding.finding_id == "http.methods.review"
        )

        self.assertEqual(review.category, "configuration")
        self.assertEqual(review.severity, "medium")
        self.assertEqual(review.port, 8081)
        self.assertEqual(review.protocol, "tcp")
        self.assertIn("GET HEAD PUT DELETE OPTIONS", review.evidence)
        self.assertIn("review methods: PUT DELETE", review.evidence)
        self.assertNotIn("PUT DELETE PUT DELETE", review.evidence)

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
