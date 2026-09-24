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
