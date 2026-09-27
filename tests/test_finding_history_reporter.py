"""Tests for NetRecon finding history reporting."""

import json
import unittest

from finding_history import FindingHistory
from reporter import render_finding_history, render_finding_history_json


class FindingHistoryReporterTests(unittest.TestCase):
    def test_text_report_uses_observation_language_and_counts(self) -> None:
        history = (
            FindingHistory(
                finding_id="smb.signing.review",
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                first_seen=1790180000,
                last_seen=1790183600,
                observations=2,
                opportunities=3,
            ),
        )

        report = render_finding_history(history)

        self.assertIn("Finding History", report)
        self.assertIn("smb.signing.review", report)
        self.assertIn("192.0.2.10:445/tcp", report)
        self.assertIn("first_observed=", report)
        self.assertIn("last_observed=", report)
        self.assertNotIn("first_seen=", report)
        self.assertNotIn("last_seen=", report)
        self.assertIn("observations=2", report)
        self.assertIn("opportunities=3", report)
        self.assertIn("UTC", report)

    def test_json_report_preserves_numeric_timestamps(self) -> None:
        history = (
            FindingHistory(
                finding_id="smb.signing.review",
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                first_seen=100,
                last_seen=300,
                observations=2,
                opportunities=3,
            ),
        )

        payload = json.loads(render_finding_history_json(history))

        self.assertEqual(payload["report_type"], "finding_history")
        self.assertEqual(payload["summary"]["findings"], 1)
        self.assertEqual(payload["history"], [{
            "finding_id": "smb.signing.review",
            "host": "192.0.2.10",
            "port": 445,
            "protocol": "tcp",
            "first_seen": 100,
            "last_seen": 300,
            "observations": 2,
            "opportunities": 3,
        }])

    def test_empty_history_does_not_invent_findings(self) -> None:
        self.assertIn("Findings: 0", render_finding_history(()))
        payload = json.loads(render_finding_history_json(()))
        self.assertEqual(payload["summary"]["findings"], 0)
        self.assertEqual(payload["history"], [])


if __name__ == "__main__":
    unittest.main()
