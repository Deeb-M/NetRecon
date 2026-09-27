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


if __name__ == "__main__":
    unittest.main()
