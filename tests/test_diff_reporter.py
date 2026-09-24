"""Tests for NetRecon diff text rendering."""

import unittest

from reporter import render_diff
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

        self.assertIn("CHANGED 192.0.2.10:80/tcp  http Apache httpd 2.4.67 -> http Apache httpd 2.4.68", report)
        self.assertIn("NO_LONGER_OPEN 192.0.2.10:139/tcp  netbios-ssn", report)
        self.assertIn("NEW     192.0.2.10:445/tcp  microsoft-ds", report)

    def test_renders_no_changes(self) -> None:
        self.assertEqual(render_diff(()), "Exposure Changes: none")


if __name__ == "__main__":
    unittest.main()
