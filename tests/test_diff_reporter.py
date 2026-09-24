"""Tests for NetRecon diff text rendering."""

import json
import unittest

from reporter import render_diff, render_diff_json
from models import Scan, ScanScope
from scan_diff import ExposureChange


class DiffReporterTests(unittest.TestCase):
    def test_renders_new_no_longer_open_and_changed_exposure(self) -> None:
        changes = (
            ExposureChange(
                "changed", "192.0.2.10", 80, "tcp",
                before_service="http", after_service="http",
                before_product="Apache httpd", after_product="Apache httpd",
                before_version="2.4.67", after_version="2.4.68",
            ),
            ExposureChange(
                "no_longer_open", "192.0.2.10", 139, "tcp",
                before_service="netbios-ssn",
            ),
            ExposureChange(
                "new", "192.0.2.10", 445, "tcp",
                after_service="microsoft-ds",
            ),
        )

        report = render_diff(changes)

        self.assertIn("Summary: CHANGED=1, NEW=1, NO_LONGER_OPEN=1", report)
        self.assertIn("CHANGED 192.0.2.10:80/tcp  http Apache httpd 2.4.67 -> http Apache httpd 2.4.68", report)
        self.assertIn("NO_LONGER_OPEN 192.0.2.10:139/tcp  netbios-ssn", report)
        self.assertIn("NEW     192.0.2.10:445/tcp  microsoft-ds", report)

    def test_renders_no_changes(self) -> None:
        self.assertEqual(render_diff(()), "Exposure Changes: none")

    def test_renders_diff_json(self) -> None:
        changes = (ExposureChange(
            "new", "192.0.2.10", 443, "tcp",
            after_service="https", after_product="Apache httpd", after_version="2.4.68",
        ),)

        payload = json.loads(render_diff_json(changes))

        self.assertEqual(payload["change_type"], "exposure")
        self.assertEqual(payload["summary"], {"new": 1})
        self.assertEqual(payload["changes"][0]["change"], "new")
        self.assertEqual(payload["changes"][0]["port"], 443)
        self.assertEqual(payload["changes"][0]["after_product"], "Apache httpd")

    def test_renders_scan_coverage_when_scans_are_available(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80,443"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "443"),))
        changes = (ExposureChange("new", "192.0.2.10", 443, "tcp", after_service="https"),)

        report = render_diff(changes, before, after)
        payload = json.loads(render_diff_json(changes, before, after))

        self.assertIn("Before Coverage: tcp:80,443", report)
        self.assertIn("After Coverage:  tcp:443", report)
        self.assertIn("Coverage Changed: YES", report)
        self.assertIn("No Longer Scanned: tcp/80", report)
        self.assertTrue(payload["coverage"]["changed"])
        self.assertEqual(payload["coverage"]["newly_scanned"], [])
        self.assertEqual(payload["coverage"]["no_longer_scanned"], ["tcp/80"])
        self.assertEqual(payload["coverage"]["before"], [{"protocol": "tcp", "services": "80,443"}])
        self.assertEqual(payload["coverage"]["after"], [{"protocol": "tcp", "services": "443"}])

    def test_renders_scan_coverage_when_there_are_no_changes(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80,443"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "443"),))

        report = render_diff((), before, after)

        self.assertIn("Summary: none", report)
        self.assertIn("Before Coverage: tcp:80,443", report)
        self.assertIn("After Coverage:  tcp:443", report)
        self.assertIn("Coverage Changed: YES", report)
        self.assertIn("Newly Scanned: none", report)
        self.assertIn("No Longer Scanned: tcp/80", report)
        self.assertIn("Changes: none", report)

    def test_reports_unchanged_scan_coverage(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80,443"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "80,443"),))
        changes = (ExposureChange("new", "192.0.2.10", 443, "tcp", after_service="https"),)

        report = render_diff(changes, before, after)
        payload = json.loads(render_diff_json(changes, before, after))

        self.assertIn("Coverage Changed: NO", report)
        self.assertIn("Newly Scanned: none", report)
        self.assertIn("No Longer Scanned: none", report)
        self.assertFalse(payload["coverage"]["changed"])
        self.assertEqual(payload["coverage"]["newly_scanned"], [])
        self.assertEqual(payload["coverage"]["no_longer_scanned"], [])

    def test_compacts_consecutive_coverage_ports_in_text_report(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "80,100-105,443"),))

        report = render_diff((), before, after)

        self.assertIn("Newly Scanned: tcp/100-105, tcp/443", report)
        self.assertNotIn("tcp/100, tcp/101", report)

    def test_summarizes_large_coverage_difference_in_text_but_keeps_json_detail(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "80,100-160"),))

        report = render_diff((), before, after)
        payload = json.loads(render_diff_json((), before, after))

        self.assertIn("Newly Scanned: 61 ports (details: --format json)", report)
        self.assertNotIn("tcp/100-160", report)
        self.assertEqual(len(payload["coverage"]["newly_scanned"]), 61)
        self.assertEqual(payload["coverage"]["newly_scanned"][0], "tcp/100")
        self.assertEqual(payload["coverage"]["newly_scanned"][-1], "tcp/160")

    def test_reports_newly_scanned_ports(self) -> None:
        before = Scan("before.xml", scan_scopes=(ScanScope("tcp", "80"),))
        after = Scan("after.xml", scan_scopes=(ScanScope("tcp", "80,443"),))

        report = render_diff((), before, after)
        payload = json.loads(render_diff_json((), before, after))

        self.assertIn("Newly Scanned: tcp/443", report)
        self.assertIn("No Longer Scanned: none", report)
        self.assertEqual(payload["coverage"]["newly_scanned"], ["tcp/443"])
        self.assertEqual(payload["coverage"]["no_longer_scanned"], [])

    def test_renders_newly_observed_host(self) -> None:
        changes = (ExposureChange("host_newly_observed", "192.0.2.30", None, None),)

        report = render_diff(changes)
        payload = json.loads(render_diff_json(changes))

        self.assertIn("Summary: HOST_NEWLY_OBSERVED=1", report)
        self.assertIn("HOST_NEWLY_OBSERVED 192.0.2.30", report)
        self.assertEqual(payload["summary"], {"host_newly_observed": 1})
        self.assertEqual(payload["changes"][0]["host"], "192.0.2.30")


if __name__ == "__main__":
    unittest.main()
