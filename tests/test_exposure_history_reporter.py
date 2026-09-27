"""Tests for NetRecon exposure history reporting."""

import json
import unittest

from exposure_history import ExposureHistory
from reporter import render_exposure_history, render_exposure_history_json


class ExposureHistoryReporterTests(unittest.TestCase):
    def test_text_report_renders_utc_times_and_observation_counts(self) -> None:
        history = (
            ExposureHistory(
                host="192.0.2.10",
                port=22,
                protocol="tcp",
                first_seen=1790180000,
                last_seen=1790183600,
                observations=3,
                opportunities=4,
            ),
        )

        report = render_exposure_history(history)

        self.assertIn("Exposure History", report)
        self.assertIn("192.0.2.10:22/tcp", report)
        self.assertIn("first_observed=", report)
        self.assertIn("last_observed=", report)
        self.assertNotIn("first_seen=", report)
        self.assertNotIn("last_seen=", report)
        self.assertIn("observations=3", report)
        self.assertIn("opportunities=4", report)
        self.assertIn("2026-", report)
        self.assertIn("UTC", report)

    def test_json_report_preserves_numeric_timestamps(self) -> None:
        history = (
            ExposureHistory(
                host="192.0.2.10",
                port=443,
                protocol="tcp",
                first_seen=100,
                last_seen=300,
                observations=2,
                opportunities=3,
            ),
        )

        payload = json.loads(render_exposure_history_json(history))

        self.assertEqual(payload["report_type"], "exposure_history")
        self.assertEqual(payload["summary"]["endpoints"], 1)
        self.assertEqual(payload["history"], [{
            "host": "192.0.2.10",
            "port": 443,
            "protocol": "tcp",
            "first_seen": 100,
            "last_seen": 300,
            "observations": 2,
            "opportunities": 3,
        }])

    def test_empty_history_is_reported_without_inventing_observations(self) -> None:
        self.assertIn("Endpoints: 0", render_exposure_history(()))
        payload = json.loads(render_exposure_history_json(()))
        self.assertEqual(payload["summary"]["endpoints"], 0)
        self.assertEqual(payload["history"], [])


if __name__ == "__main__":
    unittest.main()
