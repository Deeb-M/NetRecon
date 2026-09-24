"""Tests for NetRecon analysis findings."""

import unittest
from datetime import datetime, timezone

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

    def test_explicit_service_findings_record_detection_provenance_but_port_fallback_does_not(self) -> None:
        explicit = Scan(source="explicit.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open", "telnet"),),
        ),))
        fallback = Scan(source="fallback.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(Port(23, "tcp", "open"),),
        ),))

        explicit_finding = next(
            finding for finding in analyze_scan(explicit)
            if finding.finding_id == "service.telnet.exposed"
        )
        fallback_finding = next(
            finding for finding in analyze_scan(fallback)
            if finding.finding_id == "service.telnet.exposed"
        )

        self.assertEqual(explicit_finding.evidence_source, "service:detection")
        self.assertIsNone(fallback_finding.evidence_source)

    def test_does_not_infer_well_known_service_when_nmap_identifies_conflicting_service(self) -> None:
        scan = Scan(source="conflict.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(port=21, protocol="tcp", state="open", service="ssh"),
                Port(port=23, protocol="tcp", state="open", service="http"),
                Port(port=135, protocol="tcp", state="open", service="http"),
                Port(port=139, protocol="tcp", state="open", service="http"),
                Port(port=445, protocol="tcp", state="open", service="https"),
            ),
        ),))

        finding_ids = {finding.finding_id for finding in analyze_scan(scan)}
        self.assertNotIn("service.ftp.exposed", finding_ids)
        self.assertNotIn("service.telnet.exposed", finding_ids)
        self.assertNotIn("service.rpc.exposed", finding_ids)
        self.assertNotIn("service.netbios.exposed", finding_ids)
        self.assertNotIn("service.smb.exposed", finding_ids)

    def test_well_known_port_is_fallback_when_service_is_unknown(self) -> None:
        scan = Scan(source="unknown.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(port=21, protocol="tcp", state="open"),
                Port(port=23, protocol="tcp", state="open"),
                Port(port=135, protocol="tcp", state="open"),
                Port(port=139, protocol="tcp", state="open"),
                Port(port=445, protocol="tcp", state="open"),
            ),
        ),))

        finding_ids = {finding.finding_id for finding in analyze_scan(scan)}
        self.assertTrue({
            "service.ftp.exposed",
            "service.telnet.exposed",
            "service.rpc.exposed",
            "service.netbios.exposed",
            "service.smb.exposed",
        }.issubset(finding_ids))

    def test_open_state_is_case_insensitive_in_service_analysis(self) -> None:
        scan = Scan(source="uppercase.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(port=23, protocol="tcp", state="OPEN", service="telnet"),
            ),
        ),))

        finding_ids = {finding.finding_id for finding in analyze_scan(scan)}
        self.assertIn("service.telnet.exposed", finding_ids)

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

    def test_application_cpe_prefix_is_case_insensitive(self) -> None:
        original_cpe = "CPE:/A:Example:Web:1.0"
        scan = Scan(source="test.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(443, "tcp", "open", "https", cpes=(original_cpe,)),
            ),
        ),))

        findings = tuple(
            finding
            for finding in analyze_scan(scan)
            if finding.finding_id == "service.application.context"
        )

        self.assertEqual(len(findings), 1)
        self.assertIn(original_cpe, findings[0].evidence)

    def test_application_context_protocol_case_is_aggregated_as_one_endpoint(self) -> None:
        scan = Scan(source="test.xml", hosts=(Host(
            address="192.0.2.10", status="up", ports=(
                Port(443, "TCP", "open", "https", cpes=("cpe:/a:example:web:1.0",)),
                Port(443, "tcp", "open", "https", cpes=("cpe:/a:example:web:2.0",)),
            ),
        ),))

        findings = tuple(
            finding
            for finding in analyze_scan(scan)
            if finding.finding_id == "service.application.context"
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].port, 443)
        self.assertEqual(findings[0].protocol, "tcp")
        self.assertIn("cpe:/a:example:web:1.0", findings[0].evidence)
        self.assertIn("cpe:/a:example:web:2.0", findings[0].evidence)

    def test_multiple_application_cpes_on_same_endpoint_are_aggregated(self) -> None:
        scan = Scan(
            source="multi-app.xml",
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(
                    port=8080,
                    protocol="tcp",
                    state="open",
                    service="http",
                    product="Example",
                    cpes=(
                        "cpe:/a:vendor:first:1.0",
                        "cpe:/a:vendor:second:2.0",
                    ),
                ),
            )),),
        )

        application_findings = tuple(
            finding for finding in analyze_scan(scan)
            if finding.finding_id == "service.application.context"
        )
        self.assertEqual(len(application_findings), 1)
        self.assertIn("cpe:/a:vendor:first:1.0", application_findings[0].evidence)
        self.assertIn("cpe:/a:vendor:second:2.0", application_findings[0].evidence)

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

    def test_apache_debian_default_page_is_informational_context(self) -> None:
        scan = Scan(
            source="http-default.xml",
            hosts=(Host(
                address="192.0.2.30",
                status="up",
                ports=(
                    Port(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product="Apache httpd",
                        scripts=(
                            ScriptResult(
                                script_id="http-title",
                                output="Apache2 Debian Default Page: It works",
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        default_page = next(
            finding for finding in findings
            if finding.finding_id == "http.default_page.detected"
        )

        self.assertEqual(default_page.category, "context")
        self.assertEqual(default_page.severity, "info")
        self.assertEqual(default_page.port, 80)
        self.assertEqual(default_page.protocol, "tcp")
        self.assertIn("Apache2 Debian Default Page: It works", default_page.evidence)

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

    def test_tls_legacy_versions_and_anonymous_key_exchange_are_reviewed(self) -> None:
        scan = Scan(
            source="tls.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8443,
                        protocol="tcp",
                        state="open",
                        service="https-alt",
                        tunnel="ssl",
                        scripts=(
                            ScriptResult(
                                script_id="ssl-enum-ciphers",
                                output=(
                                    "TLSv1.0: ciphers: TLS_ECDH_anon_WITH_AES_256_CBC_SHA - F "
                                    "warnings: Anonymous key exchange, score capped at F "
                                    "TLSv1.1: ciphers: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA - A "
                                    "TLSv1.2: ciphers: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - A "
                                    "least strength: F"
                                ),
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(scan)
        legacy = next(
            finding for finding in findings
            if finding.finding_id == "tls.protocol.legacy_enabled"
        )
        anonymous = next(
            finding for finding in findings
            if finding.finding_id == "tls.key_exchange.anonymous"
        )

        self.assertEqual(legacy.category, "protocol")
        self.assertEqual(legacy.severity, "medium")
        self.assertEqual(legacy.port, 8443)
        self.assertEqual(legacy.protocol, "tcp")
        self.assertIn("TLSv1.0", legacy.evidence)
        self.assertIn("TLSv1.1", legacy.evidence)

        self.assertEqual(anonymous.category, "configuration")
        self.assertEqual(anonymous.severity, "medium")
        self.assertEqual(anonymous.port, 8443)
        self.assertEqual(anonymous.protocol, "tcp")
        self.assertIn("anonymous key exchange", anonymous.evidence.lower())

    def test_expired_tls_certificate_uses_explicit_reference_time(self) -> None:
        scan = Scan(
            source="tls-cert.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8443,
                        protocol="tcp",
                        state="open",
                        service="https-alt",
                        tunnel="ssl",
                        scripts=(
                            ScriptResult(
                                script_id="ssl-cert",
                                output=(
                                    "Subject: commonName=localhost Issuer: commonName=localhost "
                                    "Not valid before: 2026-09-20T00:00:00 "
                                    "Not valid after: 2026-09-22T00:00:00"
                                ),
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(
            scan,
            now=datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc),
        )
        expired = next(
            finding for finding in findings
            if finding.finding_id == "tls.certificate.expired"
        )

        self.assertEqual(expired.category, "certificate")
        self.assertEqual(expired.severity, "medium")
        self.assertEqual(expired.port, 8443)
        self.assertEqual(expired.protocol, "tcp")
        self.assertIn("2026-09-22T00:00:00", expired.evidence)

    def test_valid_tls_certificate_is_not_flagged_as_expired(self) -> None:
        scan = Scan(
            source="tls-cert.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8443,
                        protocol="tcp",
                        state="open",
                        service="https-alt",
                        tunnel="ssl",
                        scripts=(
                            ScriptResult(
                                script_id="ssl-cert",
                                output="Not valid after: 2026-09-24T19:35:21",
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(
            scan,
            now=datetime(2026, 9, 23, 19, 45, tzinfo=timezone.utc),
        )

        self.assertFalse(
            any(
                finding.finding_id == "tls.certificate.expired"
                for finding in findings
            )
        )

    def test_tls_certificate_not_yet_valid_uses_explicit_reference_time(self) -> None:
        scan = Scan(
            source="tls-cert-future.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(
                    Port(
                        port=8443,
                        protocol="tcp",
                        state="open",
                        service="https-alt",
                        tunnel="ssl",
                        scripts=(
                            ScriptResult(
                                script_id="ssl-cert",
                                output=(
                                    "Not valid before: 2026-09-25T00:00:00 "
                                    "Not valid after: 2026-09-26T00:00:00"
                                ),
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(
            scan,
            now=datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc),
        )
        future = next(
            finding for finding in findings
            if finding.finding_id == "tls.certificate.not_yet_valid"
        )

        self.assertEqual(future.category, "certificate")
        self.assertEqual(future.severity, "medium")
        self.assertEqual(future.port, 8443)
        self.assertEqual(future.protocol, "tcp")
        self.assertIn("2026-09-25T00:00:00", future.evidence)

    def test_tls_certificate_identity_match_is_not_flagged(self) -> None:
        scan = Scan(
            source="tls-cert-match.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                hostname="localhost",
                hostnames=("localhost",),
                hostname_records=(("localhost", "user"),),
                ports=(
                    Port(
                        port=8446,
                        protocol="tcp",
                        state="open",
                        service="unknown",
                        tunnel="ssl",
                        scripts=(
                            ScriptResult(
                                script_id="ssl-cert",
                                output=(
                                    "Subject: commonName=localhost "
                                    "Subject Alternative Name: DNS:localhost "
                                    "Issuer: commonName=localhost "
                                    "Not valid before: 2026-09-23T20:09:30 "
                                    "Not valid after: 2026-09-24T20:09:30"
                                ),
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(
            scan,
            now=datetime(2026, 9, 23, 21, 0, tzinfo=timezone.utc),
        )

        self.assertFalse(
            any(
                finding.finding_id == "tls.certificate.identity_mismatch"
                for finding in findings
            )
        )

    def test_tls_certificate_identity_mismatch_uses_user_hostname_and_dns_san(self) -> None:
        scan = Scan(
            source="tls-cert-mismatch.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                hostname="localhost",
                hostnames=("localhost", "localhost"),
                hostname_records=(("localhost", "user"), ("localhost", "PTR")),
                ports=(
                    Port(
                        port=8447,
                        protocol="tcp",
                        state="open",
                        service="unknown",
                        tunnel="ssl",
                        scripts=(
                            ScriptResult(
                                script_id="ssl-cert",
                                output=(
                                    "Subject: commonName=wrong.localhost "
                                    "Subject Alternative Name: DNS:wrong.localhost "
                                    "Issuer: commonName=wrong.localhost "
                                    "Not valid before: 2026-09-23T20:16:44 "
                                    "Not valid after: 2026-09-24T20:16:44"
                                ),
                            ),
                        ),
                    ),
                ),
            ),),
        )

        findings = analyze_scan(
            scan,
            now=datetime(2026, 9, 23, 21, 0, tzinfo=timezone.utc),
        )
        mismatch = next(
            finding for finding in findings
            if finding.finding_id == "tls.certificate.identity_mismatch"
        )

        self.assertEqual(mismatch.category, "certificate")
        self.assertEqual(mismatch.severity, "medium")
        self.assertEqual(mismatch.port, 8447)
        self.assertEqual(mismatch.protocol, "tcp")
        self.assertIn("localhost", mismatch.evidence)
        self.assertIn("wrong.localhost", mismatch.evidence)

    def test_tls_certificate_wildcard_matches_one_dns_label_only(self) -> None:
        matching_scan = Scan(
            source="tls-wildcard-match.xml",
            hosts=(Host(
                address="192.0.2.20",
                status="up",
                hostname="api.example.com",
                hostnames=("api.example.com",),
                hostname_records=(("api.example.com", "user"),),
                ports=(Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                    scripts=(ScriptResult(
                        script_id="ssl-cert",
                        output=(
                            "Subject: commonName=*.example.com "
                            "Subject Alternative Name: DNS:*.example.com "
                            "Issuer: commonName=Example CA"
                        ),
                    ),),
                ),),
            ),),
        )
        nested_scan = Scan(
            source="tls-wildcard-nested.xml",
            hosts=(Host(
                address="192.0.2.21",
                status="up",
                hostname="a.b.example.com",
                hostnames=("a.b.example.com",),
                hostname_records=(("a.b.example.com", "user"),),
                ports=(Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                    scripts=(ScriptResult(
                        script_id="ssl-cert",
                        output=(
                            "Subject: commonName=*.example.com "
                            "Subject Alternative Name: DNS:*.example.com "
                            "Issuer: commonName=Example CA"
                        ),
                    ),),
                ),),
            ),),
        )

        matching_findings = analyze_scan(matching_scan)
        nested_findings = analyze_scan(nested_scan)

        self.assertFalse(any(
            finding.finding_id == "tls.certificate.identity_mismatch"
            for finding in matching_findings
        ))
        self.assertTrue(any(
            finding.finding_id == "tls.certificate.identity_mismatch"
            for finding in nested_findings
        ))

    def test_ssh_algorithm_inventory_is_informational_with_port_context(self) -> None:
        scan = Scan(
            source="ssh-algos.xml",
            hosts=(Host(
                address="127.0.0.1",
                status="up",
                ports=(Port(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    scripts=(ScriptResult(
                        script_id="ssh2-enum-algos",
                        output=(
                            "kex_algorithms: (2) curve25519-sha256 ecdh-sha2-nistp256 "
                            "server_host_key_algorithms: (2) rsa-sha2-512 ssh-ed25519 "
                            "encryption_algorithms: (2) chacha20-poly1305@openssh.com aes256-gcm@openssh.com "
                            "mac_algorithms: (2) hmac-sha2-256-etm@openssh.com hmac-sha1 "
                            "compression_algorithms: (2) none zlib@openssh.com"
                        ),
                    ),),
                ),),
            ),),
        )

        findings = analyze_scan(scan)
        inventory = next(
            finding for finding in findings
            if finding.finding_id == "ssh.algorithms.inventory"
        )

        self.assertEqual(inventory.severity, "info")
        self.assertEqual(inventory.category, "protocol")
        self.assertEqual(inventory.port, 22)
        self.assertEqual(inventory.protocol, "tcp")
        self.assertIn("kex_algorithms", inventory.evidence)
        self.assertIn("mac_algorithms", inventory.evidence)

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
