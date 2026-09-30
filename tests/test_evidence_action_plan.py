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
