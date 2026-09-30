"""Tests for bounded FTP protocol evidence collection."""

import unittest
from unittest.mock import patch

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

    def test_builds_bounded_read_only_collection_plan(self) -> None:
        from ftp_evidence_collector import build_ftp_protocol_collection_plan

        plan = build_ftp_protocol_collection_plan("192.0.2.10", 2121, timeout=5)

        self.assertEqual(plan.host, "192.0.2.10")
        self.assertEqual(plan.port, 2121)
        self.assertEqual(plan.timeout, 5)
        self.assertEqual(plan.commands, ("SYST", "STAT"))
        self.assertTrue(plan.check_anonymous)
        self.assertFalse(hasattr(plan, "password_candidates"))

    @patch("ftp_evidence_collector.ftplib.FTP")
    def test_executes_only_bounded_read_only_ftp_operations(self, ftp_cls) -> None:
        from ftp_evidence_collector import (
            build_ftp_protocol_collection_plan,
            collect_ftp_protocol_evidence,
        )

        ftp = ftp_cls.return_value
        ftp.getwelcome.return_value = "220 ProFTPD 1.3.1 Server"
        ftp.sendcmd.side_effect = ["215 UNIX Type: L8", "211 FTP server status"]
        ftp.login.return_value = "230 Anonymous access granted"

        plan = build_ftp_protocol_collection_plan("192.0.2.10", 2121, timeout=5)
        evidence = collect_ftp_protocol_evidence(plan)

        ftp.connect.assert_called_once_with("192.0.2.10", 2121, timeout=5)
        self.assertEqual(
            [call.args[0] for call in ftp.sendcmd.call_args_list],
            ["SYST", "STAT"],
        )
        ftp.login.assert_called_once_with("anonymous", "netrecon@")
        self.assertEqual(evidence.syst, "UNIX Type: L8")
        self.assertEqual(evidence.stat, "FTP server status")
        self.assertEqual(evidence.anonymous_login, "allowed")


if __name__ == "__main__":
    unittest.main()
