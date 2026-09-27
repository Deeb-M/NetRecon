"""Tests for analyst-facing evidence gaps derived from the evidence planner."""

import unittest

from evidence_gaps import EvidenceGap, summarize_evidence_gaps
from models import Host, Port, Scan, ScriptResult


class EvidenceGapTests(unittest.TestCase):
    def test_missing_smb_evidence_becomes_explained_gaps(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(445, "tcp", "open", "microsoft-ds"),
                    ),
                ),
            ),
        )

        self.assertEqual(
            summarize_evidence_gaps(scan),
            (
                EvidenceGap(
                    host="192.0.2.10",
                    port=445,
                    protocol="tcp",
                    script_id="smb-protocols",
                    purpose="review SMB protocol dialect support",
                ),
                EvidenceGap(
                    host="192.0.2.10",
                    port=445,
                    protocol="tcp",
                    script_id="smb2-security-mode",
                    purpose="review SMB signing configuration",
                ),
            ),
        )

    def test_existing_evidence_is_not_reported_as_gap(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(
                            22,
                            "tcp",
                            "open",
                            "ssh",
                            scripts=(ScriptResult("ssh2-enum-algos", "kex_algorithms:"),),
                        ),
                    ),
                ),
            ),
        )

        self.assertEqual(summarize_evidence_gaps(scan), ())

    def test_unsupported_service_does_not_create_gap(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(Port(5432, "tcp", "open", "postgresql"),),
                ),
            ),
        )

        self.assertEqual(summarize_evidence_gaps(scan), ())


    def test_partial_https_evidence_reports_only_missing_sources(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.20",
                    status="up",
                    ports=(
                        Port(
                            443,
                            "tcp",
                            "open",
                            "https",
                            scripts=(
                                ScriptResult("http-title", "Example"),
                                ScriptResult("ssl-cert", "certificate"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        gaps = summarize_evidence_gaps(scan)

        self.assertEqual(
            tuple(gap.script_id for gap in gaps),
            ("http-methods", "ssl-enum-ciphers"),
        )

    def test_host_level_smb_evidence_does_not_create_false_gap(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.30",
                    status="up",
                    ports=(
                        Port(445, "tcp", "open", "microsoft-ds"),
                    ),
                    scripts=(
                        ScriptResult("smb-protocols", "3.1.1"),
                        ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),
                    ),
                ),
            ),
        )

        self.assertEqual(summarize_evidence_gaps(scan), ())

    def test_multi_host_gaps_remain_bound_to_their_hosts(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.40",
                    status="up",
                    ports=(Port(22, "tcp", "open", "ssh"),),
                ),
                Host(
                    address="192.0.2.41",
                    status="up",
                    ports=(
                        Port(
                            80,
                            "tcp",
                            "open",
                            "http",
                            scripts=(ScriptResult("http-title", "Example"),),
                        ),
                    ),
                ),
            ),
        )

        gaps = summarize_evidence_gaps(scan)

        self.assertEqual(
            tuple((gap.host, gap.port, gap.script_id) for gap in gaps),
            (
                ("192.0.2.40", 22, "ssh2-enum-algos"),
                ("192.0.2.41", 80, "http-methods"),
            ),
        )


if __name__ == "__main__":
    unittest.main()
