"""Tests for NetRecon text reporting."""

import unittest

from analyzer import Finding
from models import Host, Port, Scan, ScriptResult
from reporter import render_findings, render_text


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
        self.assertIn("80/tcp OPEN", report)


if __name__ == "__main__":
    unittest.main()
