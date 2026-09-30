"""Tests for bounded FTP protocol evidence collection."""

import unittest

from ftp_evidence_collector import (
    FtpProtocolEvidence,
    parse_ftp_protocol_evidence,
)


class FtpEvidenceCollectorTests(unittest.TestCase):
    def test_parses_banner_syst_stat_and_anonymous_success_without_overclaiming(self) -> None:
        evidence = parse_ftp_protocol_evidence(
            banner_code=220,
            banner="ProFTPD 1.3.1 Server",
            syst_code=215,
            syst="UNIX Type: L8",
            stat_code=211,
            stat="FTP server status",
            anonymous_code=230,
            anonymous_message="Anonymous access granted",
        )

        self.assertEqual(
            evidence,
            FtpProtocolEvidence(
                banner="ProFTPD 1.3.1 Server",
                syst="UNIX Type: L8",
                stat="FTP server status",
                anonymous_login="allowed",
            ),
        )

    def test_anonymous_denial_is_observed_evidence_not_collection_failure(self) -> None:
        evidence = parse_ftp_protocol_evidence(
            banner_code=220,
            banner="FTP ready",
            syst_code=215,
            syst="UNIX Type: L8",
            stat_code=None,
            stat="",
            anonymous_code=530,
            anonymous_message="Login incorrect",
        )

        self.assertEqual(evidence.anonymous_login, "denied")
        self.assertEqual(evidence.syst, "UNIX Type: L8")
        self.assertIsNone(evidence.stat)

    def test_missing_anonymous_reply_remains_unknown(self) -> None:
        evidence = parse_ftp_protocol_evidence(
            banner_code=220,
            banner="FTP ready",
            syst_code=None,
            syst="",
            stat_code=None,
            stat="",
            anonymous_code=None,
            anonymous_message="",
        )

        self.assertEqual(evidence.anonymous_login, "unknown")
        self.assertIsNone(evidence.syst)
        self.assertIsNone(evidence.stat)


if __name__ == "__main__":
    unittest.main()
