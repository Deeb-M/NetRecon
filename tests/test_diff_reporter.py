"""Tests for NetRecon diff text rendering."""

import json
import unittest

from reporter import render_diff, render_diff_json
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


if __name__ == "__main__":
    unittest.main()
