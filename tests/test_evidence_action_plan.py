"""Tests for analyst-facing evidence action plans."""

import unittest

from evidence_action_plan import EvidenceAction, build_evidence_action_plan
from models import Host, Port, Scan, ScriptResult


class EvidenceActionPlanTests(unittest.TestCase):
    def test_groups_missing_smb_evidence_into_one_transparent_action(self) -> None:
        scan = Scan(
            source="discovery.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
                    ),
                ),
            ),
        )

        actions = build_evidence_action_plan(scan)

        self.assertEqual(
            actions,
            (
                EvidenceAction(
                    host="192.0.2.10",
                    port=445,
                    protocol="tcp",
                    script_ids=("smb-protocols", "smb2-security-mode"),
                    purposes=(
                        "review SMB protocol dialect support",
                        "review SMB signing configuration",
                    ),
                    command=(
                        "nmap",
                        "-p",
                        "445",
                        "--script",
                        "smb-protocols,smb2-security-mode",
                        "-oX",
                        "-",
                        "192.0.2.10",
                    ),
                ),
            ),
        )

    def test_partial_https_evidence_plans_only_missing_collection(self) -> None:
        scan = Scan(
            source="partial.xml",
            hosts=(
                Host(
                    address="192.0.2.20",
                    status="up",
                    ports=(
                        Port(
                            port=443,
                            protocol="tcp",
                            state="open",
                            service="https",
                            scripts=(
                                ScriptResult("http-title", "Example"),
                                ScriptResult("ssl-cert", "certificate"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        action = build_evidence_action_plan(scan)[0]

        self.assertEqual(action.script_ids, ("http-methods", "ssl-enum-ciphers"))
        self.assertEqual(
            action.command,
            (
                "nmap",
                "-p",
                "443",
                "--script",
                "http-methods,ssl-enum-ciphers",
                "-oX",
                "-",
                "192.0.2.20",
            ),
        )

    def test_complete_supported_evidence_creates_no_action(self) -> None:
        scan = Scan(
            source="complete.xml",
            hosts=(
                Host(
                    address="192.0.2.30",
                    status="up",
                    ports=(
                        Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
                    ),
                    scripts=(
                        ScriptResult("smb-protocols", "dialects"),
                        ScriptResult("smb2-security-mode", "signing"),
                    ),
                ),
            ),
        )

        self.assertEqual(build_evidence_action_plan(scan), ())

    def test_ftp_smtp_nfs_rules_create_bounded_actions(self) -> None:
        scan = Scan(
            source="lab.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=2121, protocol="tcp", state="open", service="ftp"),
                        Port(port=2525, protocol="tcp", state="open", service="smtp"),
                        Port(port=2049, protocol="tcp", state="open", service="nfs"),
                    ),
                ),
            ),
        )

        actions = build_evidence_action_plan(scan)

        self.assertEqual(
            tuple((a.port, a.script_ids) for a in actions),
            (
                (2121, ("ftp-syst", "ftp-anon")),
                (2525, ("smtp-commands",)),
                (2049, ("nfs-showmount",)),
            ),
        )
        self.assertTrue(all(a.command[-1] == "192.0.2.10" for a in actions))

    def test_ftp_action_uses_service_detection_before_ftp_evidence_scripts(self) -> None:
        scan = Scan(
            source="ftp-lab.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=2121, protocol="tcp", state="open", service="ftp"),
                    ),
                ),
            ),
        )

        ftp_action = next(
            action
            for action in build_evidence_action_plan(scan)
            if action.port == 2121 and "ftp-syst" in action.script_ids
        )

        self.assertEqual(ftp_action.script_ids, ("ftp-syst", "ftp-anon"))
        self.assertIn("-sV", ftp_action.command)
        self.assertEqual(
            ftp_action.command,
            (
                "nmap", "-sV", "-p", "2121",
                "--script", "ftp-syst,ftp-anon",
                "-oX", "-", "192.0.2.10",
            ),
        )

    def test_nfs_action_includes_rpcbind_context_for_showmount(self) -> None:
        scan = Scan(
            source="nfs-lab.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=111, protocol="tcp", state="open", service="rpcbind"),
                        Port(port=2049, protocol="tcp", state="open", service="nfs"),
                    ),
                ),
            ),
        )

        nfs_action = next(
            action
            for action in build_evidence_action_plan(scan)
            if "nfs-showmount" in action.script_ids
        )

        self.assertEqual(nfs_action.port, 2049)
        self.assertIn("-sV", nfs_action.command)
        self.assertIn("111,2049", nfs_action.command)

    def test_mysql_vnc_rpcbind_rules_create_bounded_actions(self) -> None:
        scan = Scan(
            source="lab.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=33060, protocol="tcp", state="open", service="mysql"),
                        Port(port=5901, protocol="tcp", state="open", service="vnc"),
                        Port(port=1111, protocol="tcp", state="open", service="rpcbind"),
                    ),
                ),
            ),
        )

        actions = build_evidence_action_plan(scan)

        self.assertEqual(
            tuple((a.port, a.script_ids) for a in actions),
            (
                (33060, ("mysql-info",)),
                (5901, ("vnc-info",)),
                (1111, ("rpcinfo",)),
            ),
        )
        self.assertTrue(all(a.command[-1] == "192.0.2.10" for a in actions))

    def test_unsupported_service_creates_no_action(self) -> None:
        scan = Scan(
            source="unsupported.xml",
            hosts=(
                Host(
                    address="192.0.2.40",
                    status="up",
                    ports=(
                        Port(port=5432, protocol="tcp", state="open", service="postgresql"),
                    ),
                ),
            ),
        )

        self.assertEqual(build_evidence_action_plan(scan), ())


    def test_multi_host_actions_remain_bound_to_correct_targets(self) -> None:
        scan = Scan(
            source="multi.xml",
            hosts=(
                Host(
                    address="192.0.2.50",
                    status="up",
                    ports=(Port(port=22, protocol="tcp", state="open", service="ssh"),),
                ),
                Host(
                    address="192.0.2.51",
                    status="up",
                    ports=(Port(port=80, protocol="tcp", state="open", service="http"),),
                ),
            ),
        )

        actions = build_evidence_action_plan(scan)

        self.assertEqual(
            [(a.host, a.port, a.script_ids) for a in actions],
            [
                ("192.0.2.50", 22, ("ssh2-enum-algos",)),
                ("192.0.2.51", 80, ("http-title", "http-methods")),
            ],
        )
        self.assertEqual(actions[0].command[-1], "192.0.2.50")
        self.assertEqual(actions[1].command[-1], "192.0.2.51")


if __name__ == "__main__":
    unittest.main()
