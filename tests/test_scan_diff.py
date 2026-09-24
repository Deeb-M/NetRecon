"""Tests for NetRecon scan-to-scan exposure comparison."""

import unittest

from models import Host, Port, Scan, ScanScope
from scan_diff import compare_scans


class ScanDiffTests(unittest.TestCase):
    def test_detects_new_no_longer_open_and_changed_exposure(self) -> None:
        before = Scan(source="before.xml", scan_scopes=(ScanScope("tcp", "80,139,445"),), hosts=(
            Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", "Apache httpd", "2.4.67"),
                Port(139, "tcp", "open", "netbios-ssn"),
            )),
        ))
        after = Scan(source="after.xml", scan_scopes=(ScanScope("tcp", "80,139,445"),), hosts=(
            Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", "Apache httpd", "2.4.68"),
                Port(445, "tcp", "open", "microsoft-ds"),
            )),
        ))

        changes = compare_scans(before, after)

        self.assertEqual([change.change for change in changes], ["changed", "no_longer_open", "new"])
        self.assertEqual(changes[0].before_version, "2.4.67")
        self.assertEqual(changes[0].after_version, "2.4.68")
        self.assertEqual(changes[1].port, 139)
        self.assertEqual(changes[2].port, 445)

    def test_missing_host_is_not_reported_as_no_longer_open_ports(self) -> None:
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

    def test_host_down_afterward_does_not_imply_open_port_closed(self) -> None:
        before = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http"),
            )),),
        )
        after = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="down"),),
        )

        changes = compare_scans(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "host_down")
        self.assertEqual(changes[0].host, "192.0.2.10")
        self.assertIsNone(changes[0].port)

    def test_host_up_afterward_is_reported_without_port_inference(self) -> None:
        before = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="down"),),
        )
        after = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http"),
            )),),
        )

        changes = compare_scans(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "host_up")
        self.assertEqual(changes[0].host, "192.0.2.10")
        self.assertIsNone(changes[0].port)

    def test_unknown_host_status_does_not_create_status_or_port_change(self) -> None:
        before = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http"),
            )),),
        )
        after = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="unknown"),),
        )

        self.assertEqual(compare_scans(before, after), ())

    def test_unknown_to_up_does_not_create_host_up_or_new_port_change(self) -> None:
        before = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="unknown"),),
        )
        after = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "80"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http"),
            )),),
        )

        self.assertEqual(compare_scans(before, after), ())

    def test_open_port_not_scanned_afterward_is_not_reported_closed(self) -> None:
        before = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "1-1000"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(8080, "tcp", "open", "http"),
            )),),
        )
        after = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "22,80,443"),),
            hosts=(Host(address="192.0.2.10", status="up"),),
        )

        self.assertEqual(compare_scans(before, after), ())

    def test_scanned_port_range_can_confirm_no_longer_open(self) -> None:
        before = Scan(
            source="before.xml",
            scan_scopes=(ScanScope("tcp", "1-1000"),),
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(139, "tcp", "open", "netbios-ssn"),
            )),),
        )
        after = Scan(
            source="after.xml",
            scan_scopes=(ScanScope("tcp", "100-200"),),
            hosts=(Host(address="192.0.2.10", status="up"),),
        )

        changes = compare_scans(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "no_longer_open")
        self.assertEqual(changes[0].port, 139)

    def test_protocol_case_does_not_create_false_exposure_change(self) -> None:
        before = Scan(
            source="before.xml",
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(80, "TCP", "open", "http", "Apache httpd", "2.4.68"),
            )),),
        )
        after = Scan(
            source="after.xml",
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(80, "tcp", "open", "http", "Apache httpd", "2.4.68"),
            )),),
        )

        self.assertEqual(compare_scans(before, after), ())

    def test_ignores_unchanged_open_port_exposure(self) -> None:
        port = Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6")
        before = Scan(source="before.xml", hosts=(Host(address="192.0.2.10", status="up", ports=(port,)),))
        after = Scan(source="after.xml", hosts=(Host(address="192.0.2.10", status="up", ports=(port,)),))

        self.assertEqual(compare_scans(before, after), ())

    def test_new_host_is_reported_once_without_port_level_new_changes(self) -> None:
        before = Scan(source="before.xml", hosts=())
        after = Scan(source="after.xml", hosts=(
            Host(address="192.0.2.30", status="up", ports=(
                Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"),
                Port(80, "tcp", "open", "http", "Apache httpd", "2.4.68"),
            )),
        ))

        changes = compare_scans(before, after)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change, "host_newly_observed")
        self.assertEqual(changes[0].host, "192.0.2.30")
        self.assertIsNone(changes[0].port)


if __name__ == "__main__":
    unittest.main()
