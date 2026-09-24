"""Tests for NetRecon scan-to-scan exposure comparison."""

import unittest

from models import Host, Port, Scan
from scan_diff import compare_scans


class ScanDiffTests(unittest.TestCase):
    def test_detects_new_closed_and_changed_open_port_exposure(self) -> None:
        before = Scan(source="before.xml", hosts=(
            Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", "Apache httpd", "2.4.67"),
                Port(139, "tcp", "open", "netbios-ssn"),
            )),
        ))
        after = Scan(source="after.xml", hosts=(
            Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", "Apache httpd", "2.4.68"),
                Port(445, "tcp", "open", "microsoft-ds"),
            )),
        ))

        changes = compare_scans(before, after)

        self.assertEqual([change.change for change in changes], ["changed", "closed", "new"])
        self.assertEqual(changes[0].before_version, "2.4.67")
        self.assertEqual(changes[0].after_version, "2.4.68")
        self.assertEqual(changes[1].port, 139)
        self.assertEqual(changes[2].port, 445)

    def test_missing_host_is_not_reported_as_closed_ports(self) -> None:
        before = Scan(source="before.xml", hosts=(
            Host(address="192.0.2.20", status="up", ports=(
                Port(445, "tcp", "open", "microsoft-ds"),
                Port(5357, "tcp", "open", "http"),
            )),
        ))
        after = Scan(source="after.xml", hosts=())

        changes = compare_scans(before, after)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "host_not_observed")
        self.assertEqual(changes[0].host, "192.0.2.20")
        self.assertIsNone(changes[0].port)

    def test_ignores_unchanged_open_port_exposure(self) -> None:
        port = Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6")
        before = Scan(source="before.xml", hosts=(Host(address="192.0.2.10", status="up", ports=(port,)),))
        after = Scan(source="after.xml", hosts=(Host(address="192.0.2.10", status="up", ports=(port,)),))

        self.assertEqual(compare_scans(before, after), ())


if __name__ == "__main__":
    unittest.main()
