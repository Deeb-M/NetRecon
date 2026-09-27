"""Contract tests for composing verified discovery into an investigation snapshot."""

import unittest
from unittest.mock import patch

from evidence_action_plan import EvidenceAction
from evidence_gaps import EvidenceGap
from scan_orchestration import (
    DiscoveryExecutionResult,
    DiscoveryResult,
    build_baseline_discovery_plan,
)

from investigation_orchestration import build_investigation_snapshot


class InvestigationOrchestrationTests(unittest.TestCase):
    @patch("investigation_orchestration.summarize_investigation_state")
    @patch("investigation_orchestration.build_evidence_action_plan")
    @patch("investigation_orchestration.summarize_evidence_gaps")
    def test_verified_discovery_composes_existing_intelligence_layers(
        self, gaps_mock, actions_mock, states_mock
    ) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
            timed_out=False,
        )
        scan = object()
        discovery = DiscoveryResult(
            execution=execution,
            success=True,
            scan=scan,
            error=None,
        )
        gap = EvidenceGap(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_id="smb-protocols",
            purpose="review SMB protocol dialect support",
        )
        action = EvidenceAction(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_ids=("smb-protocols",),
            purposes=("review SMB protocol dialect support",),
            command=(
                "nmap",
                "-p",
                "445",
                "--script",
                "smb-protocols",
                "-oX",
                "-",
                "192.0.2.10",
            ),
        )
        gaps_mock.return_value = (gap,)
        actions_mock.return_value = (action,)
        state = object()
        states_mock.return_value = (state,)

        snapshot = build_investigation_snapshot(discovery)

        self.assertTrue(snapshot.ready)
        self.assertIs(snapshot.scan, scan)
        self.assertEqual(snapshot.gaps, (gap,))
        self.assertEqual(snapshot.actions, (action,))
        self.assertEqual(snapshot.states, (state,))
        self.assertIsNone(snapshot.error)
        gaps_mock.assert_called_once_with(scan)
        actions_mock.assert_called_once_with(scan)
        states_mock.assert_called_once_with(scan)

    @patch("investigation_orchestration.summarize_investigation_state")
    @patch("investigation_orchestration.build_evidence_action_plan")
    @patch("investigation_orchestration.summarize_evidence_gaps")
    def test_failed_discovery_stops_without_planning_evidence(
        self, gaps_mock, actions_mock, states_mock
    ) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=2,
            stdout="",
            stderr="nmap failed",
            timed_out=False,
        )
        discovery = DiscoveryResult(
            execution=execution,
            success=False,
            scan=None,
            error="nmap failed",
        )

        snapshot = build_investigation_snapshot(discovery)

        self.assertFalse(snapshot.ready)
        self.assertIsNone(snapshot.scan)
        self.assertEqual(snapshot.gaps, ())
        self.assertEqual(snapshot.actions, ())
        self.assertEqual(snapshot.states, ())
        self.assertEqual(snapshot.error, "nmap failed")
        gaps_mock.assert_not_called()
        actions_mock.assert_not_called()
        states_mock.assert_not_called()

    def test_inconsistent_success_without_verified_scan_fails_closed(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=0,
            stdout="",
            stderr="",
            timed_out=False,
        )
        discovery = DiscoveryResult(
            execution=execution,
            success=True,
            scan=None,
            error=None,
        )

        with self.assertRaisesRegex(
            ValueError,
            "Successful discovery must include a verified scan",
        ):
            build_investigation_snapshot(discovery)


class InvestigationStateContractTests(unittest.TestCase):
    def test_state_separates_observed_endpoint_facts_from_planner_unknowns(self) -> None:
        from investigation_state import EndpointInvestigationState, summarize_investigation_state
        from models import Host, Port, Scan

        scan = Scan(source="scan.xml", hosts=(Host(address="192.0.2.10", status="up", ports=(Port(445, "tcp", "open", "microsoft-ds", product="Windows SMB", version="10"),)),))
        state = summarize_investigation_state(scan)[0]

        self.assertIsInstance(state, EndpointInvestigationState)
        self.assertEqual((state.host, state.port, state.protocol), ("192.0.2.10", 445, "tcp"))
        self.assertEqual(state.known, ("state=open", "service=microsoft-ds", "product=Windows SMB", "version=10"))
        self.assertEqual(tuple(gap.script_id for gap in state.unknown), ("smb-protocols", "smb2-security-mode"))

    def test_state_omits_unobserved_optional_metadata_from_known_facts(self) -> None:
        from investigation_state import summarize_investigation_state
        from models import Host, Port, Scan

        scan = Scan(source="scan.xml", hosts=(Host(address="192.0.2.20", status="up", ports=(Port(22, "tcp", "open", "ssh"),)),))
        state = summarize_investigation_state(scan)[0]

        self.assertEqual(state.known, ("state=open", "service=ssh"))
        self.assertEqual(tuple(gap.script_id for gap in state.unknown), ("ssh2-enum-algos",))

    def test_unsupported_open_service_keeps_observed_facts_without_inventing_unknowns(self) -> None:
        from investigation_state import summarize_investigation_state
        from models import Host, Port, Scan

        scan = Scan(source="scan.xml", hosts=(Host(address="192.0.2.30", status="up", ports=(Port(5432, "tcp", "open", "postgresql"),)),))
        state = summarize_investigation_state(scan)[0]

        self.assertEqual(state.known, ("state=open", "service=postgresql"))
        self.assertEqual(state.unknown, ())


    def test_state_normalizes_endpoint_identity_without_cross_host_gap_leakage(self) -> None:
        from investigation_state import summarize_investigation_state
        from models import Host, Port, Scan, ScriptResult

        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address=" 192.0.2.40 ",
                    status="up",
                    ports=(Port(445, " TCP ", "open", "microsoft-ds"),),
                ),
                Host(
                    address="192.0.2.41",
                    status="up",
                    ports=(
                        Port(
                            445,
                            "tcp",
                            "open",
                            "microsoft-ds",
                            scripts=(
                                ScriptResult("smb-protocols", "3.1.1"),
                                ScriptResult("smb2-security-mode", "enabled"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        states = summarize_investigation_state(scan)

        self.assertEqual(
            tuple((state.host, state.port, state.protocol) for state in states),
            (
                ("192.0.2.40", 445, "tcp"),
                ("192.0.2.41", 445, "tcp"),
            ),
        )
        self.assertEqual(
            tuple(gap.script_id for gap in states[0].unknown),
            ("smb-protocols", "smb2-security-mode"),
        )
        self.assertEqual(states[1].unknown, ())

    def test_closed_endpoint_is_not_present_in_investigation_state(self) -> None:
        from investigation_state import summarize_investigation_state
        from models import Host, Port, Scan

        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.50",
                    status="up",
                    ports=(
                        Port(22, "tcp", "closed", "ssh"),
                        Port(80, "tcp", "open", "http"),
                    ),
                ),
            ),
        )

        states = summarize_investigation_state(scan)

        self.assertEqual(
            tuple((state.port, state.known[0]) for state in states),
            ((80, "state=open"),),
        )


    def test_new_matching_evidence_reduces_only_the_supported_unknown(self) -> None:
        from investigation_state import summarize_investigation_state
        from models import Host, Port, Scan, ScriptResult

        before = Scan(
            source="before.xml",
            hosts=(
                Host(
                    address="192.0.2.60",
                    status="up",
                    ports=(Port(445, "tcp", "open", "microsoft-ds"),),
                ),
            ),
        )
        after = Scan(
            source="after.xml",
            hosts=(
                Host(
                    address="192.0.2.60",
                    status="up",
                    ports=(
                        Port(
                            445,
                            "tcp",
                            "open",
                            "microsoft-ds",
                            scripts=(ScriptResult("smb-protocols", "3.1.1"),),
                        ),
                    ),
                ),
            ),
        )

        before_state = summarize_investigation_state(before)[0]
        after_state = summarize_investigation_state(after)[0]

        self.assertEqual(
            tuple(gap.script_id for gap in before_state.unknown),
            ("smb-protocols", "smb2-security-mode"),
        )
        self.assertEqual(
            tuple(gap.script_id for gap in after_state.unknown),
            ("smb2-security-mode",),
        )
        self.assertEqual(after_state.known, before_state.known)


    def test_failed_collection_does_not_reduce_unknowns(self) -> None:
        from evidence_collector import (
            CollectionResult,
            NmapCommand,
            ParsedCollectionResult,
            merge_collection_outcomes_into_host,
        )
        from investigation_state import summarize_investigation_state
        from models import Host, Port, Scan

        discovered = Host(
            address="192.0.2.70",
            status="up",
            ports=(Port(445, "tcp", "open", "microsoft-ds"),),
        )
        failed = ParsedCollectionResult(
            result=CollectionResult(
                command=NmapCommand(
                    arguments=(
                        "nmap",
                        "-p",
                        "445",
                        "--script",
                        "smb-protocols,smb2-security-mode",
                        "-oX",
                        "-",
                        "192.0.2.70",
                    )
                ),
                returncode=124,
                stdout="",
                stderr="Nmap evidence collection timed out",
            ),
            scan=None,
        )

        merged = merge_collection_outcomes_into_host(discovered, (failed,))
        state = summarize_investigation_state(
            Scan(source="after-timeout", hosts=(merged,))
        )[0]

        self.assertEqual(
            tuple(gap.script_id for gap in state.unknown),
            ("smb-protocols", "smb2-security-mode"),
        )
        self.assertEqual(
            state.known,
            ("state=open", "service=microsoft-ds"),
        )
        self.assertEqual(failed.failure_message, "Nmap evidence collection timed out")


if __name__ == "__main__":
    unittest.main()
