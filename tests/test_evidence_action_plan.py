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


if __name__ == "__main__":
    unittest.main()
