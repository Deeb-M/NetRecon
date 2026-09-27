"""Tests for evidence-aware finding history across timestamped scans."""

import unittest

from analyzer import analyze_scan
from finding_history import summarize_finding_history
from models import Host, Port, Scan, ScanScope, ScriptResult


class FindingHistoryTests(unittest.TestCase):
    def test_tracks_repeated_finding_observations_and_valid_evidence_opportunities(self) -> None:
        scans = (
            Scan(
                source="one.xml",
                started_at=100,
                scan_scopes=(ScanScope("tcp", "445"),),
                hosts=(Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(
                        445, "tcp", "open", "microsoft-ds",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),),
                    ),),
                ),),
            ),
            Scan(
                source="two.xml",
                started_at=200,
                scan_scopes=(ScanScope("tcp", "445"),),
                hosts=(Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(445, "tcp", "open", "microsoft-ds"),),
                ),),
            ),
            Scan(
                source="three.xml",
                started_at=300,
                scan_scopes=(ScanScope("tcp", "445"),),
                hosts=(Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(
                        445, "tcp", "open", "microsoft-ds",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),),
                    ),),
                ),),
            ),
        )
        findings = tuple(analyze_scan(scan) for scan in scans)

        history = summarize_finding_history(scans, findings)

        item = next(entry for entry in history if entry.finding_id == "smb.signing.review")
        self.assertEqual((item.host, item.port, item.protocol), ("192.0.2.10", 445, "tcp"))
        self.assertEqual(item.first_seen, 100)
        self.assertEqual(item.last_seen, 300)
        self.assertEqual(item.observations, 2)
        self.assertEqual(item.opportunities, 2)

    def test_valid_evidence_opportunity_without_finding_increases_only_opportunities(self) -> None:
        scans = (
            Scan(
                source="one.xml",
                started_at=100,
                scan_scopes=(ScanScope("tcp", "445"),),
                hosts=(Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(
                        445, "tcp", "open", "microsoft-ds",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),),
                    ),),
                ),),
            ),
            Scan(
                source="two.xml",
                started_at=200,
                scan_scopes=(ScanScope("tcp", "445"),),
                hosts=(Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(
                        445, "tcp", "open", "microsoft-ds",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled and required",
                        ),),
                    ),),
                ),),
            ),
        )
        findings = tuple(analyze_scan(scan) for scan in scans)

        history = summarize_finding_history(scans, findings)

        item = next(entry for entry in history if entry.finding_id == "smb.signing.review")
        self.assertEqual(item.observations, 1)
        self.assertEqual(item.opportunities, 2)
        self.assertEqual(item.first_seen, 100)
        self.assertEqual(item.last_seen, 100)

    def test_host_level_nse_evidence_counts_as_opportunity_for_port_scoped_finding(self) -> None:
        scans = tuple(
            Scan(
                source=f"{timestamp}.xml",
                started_at=timestamp,
                scan_scopes=(ScanScope("tcp", "445"),),
                hosts=(Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(445, "tcp", "open", "microsoft-ds"),),
                    scripts=(ScriptResult(
                        "smb2-security-mode",
                        "Message signing enabled but not required",
                    ),),
                ),),
            )
            for timestamp in (100, 200)
        )
        findings = tuple(analyze_scan(scan) for scan in scans)

        history = summarize_finding_history(scans, findings)

        item = next(entry for entry in history if entry.finding_id == "smb.signing.review")
        self.assertEqual(item.observations, 2)
        self.assertEqual(item.opportunities, 2)

    def test_missing_timestamp_fails_closed(self) -> None:
        scan = Scan(source="missing.xml")
        with self.assertRaisesRegex(ValueError, "timestamp"):
            summarize_finding_history((scan,), ((),))


    def test_duplicate_finding_in_one_scan_counts_once(self) -> None:
        scan = Scan(source="one.xml", started_at=100)
        from findings import Finding
        finding = Finding(
            finding_id="test.finding", category="test", host="192.0.2.10",
            port=80, protocol="tcp", severity="info", title="test",
            evidence="evidence", recommendation="review",
        )

        history = summarize_finding_history((scan,), ((finding, finding),))

        self.assertEqual(history[0].observations, 1)

    def test_first_and_last_seen_use_timestamps_not_input_order(self) -> None:
        from findings import Finding
        finding = Finding(
            finding_id="test.finding", category="test", host="192.0.2.10",
            port=None, protocol=None, severity="info", title="test",
            evidence="evidence", recommendation="review",
        )
        scans = (
            Scan(source="late.xml", started_at=300),
            Scan(source="early.xml", started_at=100),
        )

        history = summarize_finding_history(scans, ((finding,), (finding,)))

        self.assertEqual(history[0].first_seen, 100)
        self.assertEqual(history[0].last_seen, 300)

    def test_scan_and_finding_sequence_lengths_must_match(self) -> None:
        scans = (Scan(source="one.xml", started_at=100),)

        with self.assertRaisesRegex(ValueError, "length"):
            summarize_finding_history(scans, ())



if __name__ == "__main__":
    unittest.main()
