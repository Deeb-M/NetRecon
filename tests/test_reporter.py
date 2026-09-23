"""Tests for NetRecon text reporting."""

import unittest

from models import Host, Port, Scan, ScriptResult
from reporter import render_text


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
        self.assertIn("lab.example [192.0.2.10] (up)", report)
        self.assertIn("mac:00:11:22:33:44:55", report)
        self.assertIn("22/tcp", report)
        self.assertIn("ssh - OpenSSH 9.6", report)
        self.assertIn("[confidence:10]", report)
        self.assertIn("script ssh-hostkey:", report)


if __name__ == "__main__":
    unittest.main()
