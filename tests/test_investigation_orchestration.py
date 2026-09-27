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


class InvestigationContinuationContractTests(unittest.TestCase):
    def test_re_evaluation_merges_valid_evidence_and_rebuilds_snapshot(self) -> None:
        from evidence_collector import (
            CollectionResult,
            NmapCommand,
            ParsedCollectionResult,
        )
        from investigation_orchestration import re_evaluate_investigation
        from models import Host, Port, Scan, ScriptResult

        discovery_scan = Scan(
            source="discovery.xml",
            hosts=(
                Host(
                    address="192.0.2.80",
                    status="up",
                    ports=(Port(445, "tcp", "open", "microsoft-ds"),),
                ),
            ),
        )
        evidence_scan = Scan(
            source="evidence.xml",
            hosts=(
                Host(
                    address="192.0.2.80",
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
        outcome = ParsedCollectionResult(
            result=CollectionResult(
                command=NmapCommand(arguments=("nmap",)),
                returncode=0,
                stdout="<nmaprun />",
                stderr="",
            ),
            scan=evidence_scan,
        )

        snapshot = re_evaluate_investigation(discovery_scan, (outcome,))

        self.assertTrue(snapshot.ready)
        self.assertIsNone(snapshot.error)
        self.assertEqual(
            tuple(gap.script_id for gap in snapshot.gaps),
            ("smb2-security-mode",),
        )
        self.assertEqual(
            tuple(gap.script_id for gap in snapshot.states[0].unknown),
            ("smb2-security-mode",),
        )
        self.assertEqual(snapshot.actions[0].script_ids, ("smb2-security-mode",))
        self.assertEqual(
            tuple(script.script_id for script in snapshot.scan.hosts[0].ports[0].scripts),
            ("smb-protocols",),
        )


    def test_re_evaluation_keeps_unknown_for_failed_outcome_beside_valid_evidence(self) -> None:
        from evidence_collector import (
            CollectionResult,
            NmapCommand,
            ParsedCollectionResult,
        )
        from investigation_orchestration import re_evaluate_investigation
        from models import Host, Port, Scan, ScriptResult

        discovery_scan = Scan(
            source="discovery.xml",
            hosts=(
                Host(
                    address="192.0.2.90",
                    status="up",
                    ports=(
                        Port(22, "tcp", "open", "ssh"),
                        Port(445, "tcp", "open", "microsoft-ds"),
                    ),
                ),
            ),
        )
        ssh_evidence = ParsedCollectionResult(
            result=CollectionResult(
                command=NmapCommand(arguments=("nmap", "-p", "22")),
                returncode=0,
                stdout="<nmaprun />",
                stderr="",
            ),
            scan=Scan(
                source="ssh-evidence.xml",
                hosts=(
                    Host(
                        address="192.0.2.90",
                        status="up",
                        ports=(
                            Port(
                                22,
                                "tcp",
                                "open",
                                "ssh",
                                scripts=(ScriptResult("ssh2-enum-algos", "algorithms"),),
                            ),
                        ),
                    ),
                ),
            ),
        )
        smb_timeout = ParsedCollectionResult(
            result=CollectionResult(
                command=NmapCommand(arguments=("nmap", "-p", "445")),
                returncode=124,
                stdout="",
                stderr="Nmap evidence collection timed out",
            ),
            scan=None,
        )

        snapshot = re_evaluate_investigation(
            discovery_scan,
            (ssh_evidence, smb_timeout),
        )

        self.assertEqual(
            tuple((gap.port, gap.script_id) for gap in snapshot.gaps),
            ((445, "smb-protocols"), (445, "smb2-security-mode")),
        )
        self.assertEqual(
            tuple((action.port, action.script_ids) for action in snapshot.actions),
            ((445, ("smb-protocols", "smb2-security-mode")),),
        )
        ssh_state = next(state for state in snapshot.states if state.port == 22)
        smb_state = next(state for state in snapshot.states if state.port == 445)
        self.assertEqual(ssh_state.unknown, ())
        self.assertEqual(
            tuple(gap.script_id for gap in smb_state.unknown),
            ("smb-protocols", "smb2-security-mode"),
        )


    @patch("investigation_orchestration.execute_nmap_command")
    def test_execute_approved_actions_runs_exact_displayed_argv_and_re_evaluates(
        self, execute_mock
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_collector import CollectionResult, NmapCommand
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_approved_evidence_actions,
        )
        from models import Host, Port, Scan

        scan = Scan(
            source="discovery.xml",
            hosts=(
                Host(
                    address="192.0.2.100",
                    status="up",
                    ports=(Port(445, "tcp", "open", "microsoft-ds"),),
                ),
            ),
        )
        command = (
            "nmap",
            "-p",
            "445",
            "--script",
            "smb-protocols,smb2-security-mode",
            "-oX",
            "-",
            "192.0.2.100",
        )
        action = EvidenceAction(
            host="192.0.2.100",
            port=445,
            protocol="tcp",
            script_ids=("smb-protocols", "smb2-security-mode"),
            purposes=(
                "review SMB protocol dialect support",
                "review SMB signing configuration",
            ),
            command=command,
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(),
            actions=(action,),
            states=(),
            error=None,
        )
        execute_mock.return_value = CollectionResult(
            command=NmapCommand(arguments=command),
            returncode=124,
            stdout="",
            stderr="Nmap evidence collection timed out",
        )

        result = execute_approved_evidence_actions(snapshot, timeout=7)

        execute_mock.assert_called_once_with(
            NmapCommand(arguments=command),
            timeout=7,
        )
        self.assertEqual(len(result.outcomes), 1)
        self.assertEqual(result.outcomes[0].result.returncode, 124)
        self.assertEqual(
            tuple(gap.script_id for gap in result.snapshot.gaps),
            ("smb-protocols", "smb2-security-mode"),
        )


    @patch("investigation_orchestration.execute_nmap_command")
    def test_approved_execution_rejects_blocked_snapshot_without_running_nmap(
        self, execute_mock
    ) -> None:
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_approved_evidence_actions,
        )

        snapshot = InvestigationSnapshot(
            ready=False,
            scan=None,
            gaps=(),
            actions=(),
            states=(),
            error="discovery failed",
        )

        with self.assertRaisesRegex(
            ValueError,
            "Approved evidence execution requires a ready investigation",
        ):
            execute_approved_evidence_actions(snapshot)

        execute_mock.assert_not_called()

    @patch("investigation_orchestration.execute_nmap_command")
    def test_approved_execution_with_no_actions_runs_nothing_and_re_evaluates(
        self, execute_mock
    ) -> None:
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_approved_evidence_actions,
        )
        from models import Host, Port, Scan

        scan = Scan(
            source="discovery.xml",
            hosts=(
                Host(
                    address="192.0.2.110",
                    status="up",
                    ports=(Port(5432, "tcp", "open", "postgresql"),),
                ),
            ),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )

        result = execute_approved_evidence_actions(snapshot)

        execute_mock.assert_not_called()
        self.assertEqual(result.outcomes, ())
        self.assertTrue(result.snapshot.ready)
        self.assertEqual(result.snapshot.gaps, ())
        self.assertEqual(result.snapshot.actions, ())
        self.assertEqual(len(result.snapshot.states), 1)


class InvestigationContinuationDecisionTests(unittest.TestCase):
    def _snapshot(self, gaps, actions=()):
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        return InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=gaps,
            actions=actions,
            states=(),
            error=None,
        )

    @patch("investigation_orchestration.execute_nmap_command")
    def test_selected_evidence_actions_execute_only_supplied_actions_once(self, execute_mock) -> None:
        from evidence_collector import CollectionResult, NmapCommand
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_selected_evidence_actions,
        )
        from models import Scan

        selected = EvidenceAction(
            host="192.0.2.70",
            port=5357,
            protocol="tcp",
            script_ids=("http-headers",),
            purposes=("purpose",),
            command=("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.70"),
        )
        ignored = EvidenceAction(
            host="192.0.2.70",
            port=5357,
            protocol="tcp",
            script_ids=("http-title",),
            purposes=("purpose",),
            command=("nmap", "-p", "5357", "--script", "http-title"),
        )
        scan = Scan(source="discovery.xml")
        snapshot = InvestigationSnapshot(True, scan, (), (ignored,), (), None)
        execute_mock.return_value = CollectionResult(
            NmapCommand(selected.command),
            0,
            "<nmaprun></nmaprun>",
            "",
        )

        result = execute_selected_evidence_actions(snapshot, (selected,), timeout=7)

        execute_mock.assert_called_once_with(NmapCommand(arguments=selected.command), timeout=7)
        self.assertEqual(len(result.outcomes), 1)
        self.assertTrue(result.snapshot.ready)

    def test_alternative_verification_requires_non_empty_script_output_on_exact_endpoint(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import verify_alternative_evidence
        from models import Host, Port, Scan, ScriptResult

        action = EvidenceAction(
            host="192.0.2.80",
            port=5357,
            protocol="tcp",
            script_ids=("http-headers",),
            purposes=("purpose",),
            command=("nmap",),
        )
        scan = Scan(
            source="alternative.xml",
            hosts=(
                Host(
                    address="192.0.2.80",
                    status="up",
                    ports=(
                        Port(
                            port=5357,
                            protocol="tcp",
                            state="open",
                            service="http",
                            scripts=(ScriptResult("http-headers", "Server: Microsoft-HTTPAPI/2.0"),),
                        ),
                    ),
                ),
            ),
        )
        outcome = ParsedCollectionResult(CollectionResult(NmapCommand(("nmap",)), 0, "<xml/>", ""), scan)

        verification = verify_alternative_evidence(action, outcome)

        self.assertEqual(verification.status, "observed")
        self.assertEqual(verification.observed_script_ids, ("http-headers",))

    def test_alternative_verification_rejects_empty_script_output(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import verify_alternative_evidence
        from models import Host, Port, Scan, ScriptResult

        action = EvidenceAction("192.0.2.81", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        scan = Scan(
            source="alternative.xml",
            hosts=(Host("192.0.2.81", "up", ports=(Port(5357, "tcp", "open", "http", scripts=(ScriptResult("http-headers", "   "),)),)),),
        )
        outcome = ParsedCollectionResult(CollectionResult(NmapCommand(("nmap",)), 0, "<xml/>", ""), scan)

        verification = verify_alternative_evidence(action, outcome)

        self.assertEqual(verification.status, "incomplete")
        self.assertEqual(verification.observed_script_ids, ())

    def test_alternative_verification_rejects_evidence_from_other_endpoint(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import verify_alternative_evidence
        from models import Host, Port, Scan, ScriptResult

        action = EvidenceAction("192.0.2.82", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        scan = Scan(
            source="alternative.xml",
            hosts=(Host("192.0.2.82", "up", ports=(Port(80, "tcp", "open", "http", scripts=(ScriptResult("http-headers", "Server: example"),)),)),),
        )
        outcome = ParsedCollectionResult(CollectionResult(NmapCommand(("nmap",)), 0, "<xml/>", ""), scan)

        self.assertEqual(verify_alternative_evidence(action, outcome).status, "incomplete")

    def test_alternative_verification_distinguishes_collection_failure(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import verify_alternative_evidence

        action = EvidenceAction("192.0.2.83", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        outcome = ParsedCollectionResult(CollectionResult(NmapCommand(("nmap",)), 1, "", "failed"), None)

        verification = verify_alternative_evidence(action, outcome)

        self.assertEqual(verification.status, "collection_failed")
        self.assertEqual(verification.observed_script_ids, ())

    @patch("investigation_orchestration.execute_selected_evidence_actions")
    def test_alternative_round_verifies_each_selected_action_once(self, execute_selected_mock) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import (
            InvestigationContinuationResult,
            InvestigationSnapshot,
            execute_alternative_evidence_round,
        )
        from models import Host, Port, Scan, ScriptResult

        action = EvidenceAction(
            "192.0.2.90", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",)
        )
        scan = Scan(
            source="alternative.xml",
            hosts=(
                Host(
                    "192.0.2.90",
                    "up",
                    ports=(
                        Port(
                            5357,
                            "tcp",
                            "open",
                            "http",
                            scripts=(ScriptResult("http-headers", "Server: example"),),
                        ),
                    ),
                ),
            ),
        )
        outcome = ParsedCollectionResult(
            CollectionResult(NmapCommand(("nmap",)), 0, "<xml/>", ""),
            scan,
        )
        updated = InvestigationSnapshot(True, scan, (), (), (), None)
        execute_selected_mock.return_value = InvestigationContinuationResult((outcome,), updated)

        result = execute_alternative_evidence_round(
            InvestigationSnapshot(True, Scan("discovery.xml"), (), (), (), None),
            (action,),
            timeout=9,
        )

        execute_selected_mock.assert_called_once()
        self.assertEqual(result.snapshot, updated)
        self.assertEqual(len(result.outcomes), 1)
        self.assertEqual(len(result.verifications), 1)
        self.assertEqual(result.verifications[0].status, "observed")

    @patch("investigation_orchestration.execute_selected_evidence_actions")
    def test_alternative_round_preserves_incomplete_verification(self, execute_selected_mock) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import (
            InvestigationContinuationResult,
            InvestigationSnapshot,
            execute_alternative_evidence_round,
        )
        from models import Host, Port, Scan, ScriptResult

        action = EvidenceAction(
            "192.0.2.91", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",)
        )
        scan = Scan(
            source="alternative.xml",
            hosts=(
                Host(
                    "192.0.2.91",
                    "up",
                    ports=(
                        Port(
                            5357,
                            "tcp",
                            "open",
                            "http",
                            scripts=(ScriptResult("http-headers", ""),),
                        ),
                    ),
                ),
            ),
        )
        outcome = ParsedCollectionResult(
            CollectionResult(NmapCommand(("nmap",)), 0, "<xml/>", ""),
            scan,
        )
        updated = InvestigationSnapshot(True, scan, (), (), (), None)
        execute_selected_mock.return_value = InvestigationContinuationResult((outcome,), updated)

        result = execute_alternative_evidence_round(
            InvestigationSnapshot(True, Scan("discovery.xml"), (), (), (), None),
            (action,),
        )

        self.assertEqual(result.verifications[0].status, "incomplete")

    def test_observed_alternative_does_not_satisfy_requirement_on_different_endpoint(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.97", 8080, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gap = EvidenceGap("192.0.2.97", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        round_result = AlternativeEvidenceRoundResult(
            (),
            (AlternativeEvidenceVerification("observed", action, ("http-headers",)),),
            snapshot,
        )

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(
            tuple(r.requirement.requirement_id for r in decision.remaining_requirements),
            ("http_identity_context",),
        )

    def test_verified_alternative_can_complete_semantic_investigation_with_raw_gap_remaining(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.96", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gap = EvidenceGap("192.0.2.96", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        decision = assess_final_investigation_decision(
            AlternativeEvidenceRoundResult(
                (),
                (AlternativeEvidenceVerification("observed", action, ("http-headers",)),),
                snapshot,
            )
        )

        self.assertEqual(decision.status, "complete")
        self.assertEqual(decision.reason, "all_semantic_requirements_satisfied")
        self.assertEqual(decision.remaining_gaps, (gap,))
        self.assertEqual(decision.remaining_requirements, ())

    def test_observed_alternative_records_satisfied_endpoint_requirement(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.95", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gap = EvidenceGap("192.0.2.95", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        decision = assess_final_investigation_decision(
            AlternativeEvidenceRoundResult(
                (),
                (AlternativeEvidenceVerification("observed", action, ("http-headers",)),),
                snapshot,
            )
        )

        self.assertEqual(
            [(state.host, state.port, state.protocol, state.requirement.requirement_id)
             for state in decision.satisfied_requirements],
            [("192.0.2.95", 5357, "tcp", "http_identity_context")],
        )
        self.assertEqual(decision.remaining_requirements, ())

    def test_observed_http_headers_satisfies_only_http_identity_requirement(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.98", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gaps = (
            EvidenceGap("192.0.2.98", 5357, "tcp", "http-title", "purpose"),
            EvidenceGap("192.0.2.98", 5357, "tcp", "http-methods", "purpose"),
        )
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), gaps, (), (), None)
        round_result = AlternativeEvidenceRoundResult(
            (),
            (AlternativeEvidenceVerification("observed", action, ("http-headers",)),),
            snapshot,
        )

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(
            tuple(r.requirement.requirement_id for r in decision.remaining_requirements),
            ("http_supported_methods",),
        )
        self.assertEqual(decision.remaining_gaps, gaps)
        self.assertEqual(
            decision.reason,
            "alternative_evidence_partially_satisfied_requirements",
        )

    def test_final_decision_exposes_distinct_remaining_semantic_requirements(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.99", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gaps = (
            EvidenceGap("192.0.2.99", 5357, "tcp", "http-title", "purpose"),
            EvidenceGap("192.0.2.99", 5357, "tcp", "http-methods", "purpose"),
        )
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), gaps, (), (), None)
        round_result = AlternativeEvidenceRoundResult(
            (),
            (AlternativeEvidenceVerification("incomplete", action, ()),),
            snapshot,
        )

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(
            tuple(r.requirement.requirement_id for r in decision.remaining_requirements),
            ("http_identity_context", "http_supported_methods"),
        )

    def test_remaining_semantic_requirements_preserve_endpoint_identity(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from models import Scan

        gaps = (
            EvidenceGap("192.0.2.70", 80, "tcp", "http-title", "purpose"),
            EvidenceGap("192.0.2.70", 8080, "tcp", "http-title", "purpose"),
        )
        snapshot = InvestigationSnapshot(True, Scan("after.xml"), gaps, (), (), None)
        decision = assess_final_investigation_decision(
            AlternativeEvidenceRoundResult((), (), snapshot)
        )

        self.assertEqual(
            [(state.host, state.port, state.protocol, state.requirement.requirement_id)
             for state in decision.remaining_requirements],
            [
                ("192.0.2.70", 80, "tcp", "http_identity_context"),
                ("192.0.2.70", 8080, "tcp", "http_identity_context"),
            ],
        )

    def test_final_decision_stops_when_alternative_evidence_is_incomplete(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.100", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gap = EvidenceGap("192.0.2.100", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        round_result = AlternativeEvidenceRoundResult(
            (),
            (AlternativeEvidenceVerification("incomplete", action, ()),),
            snapshot,
        )

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "alternative_evidence_incomplete")
        self.assertEqual(decision.remaining_gaps, (gap,))
        self.assertEqual(decision.further_actions, ())

    def test_final_decision_distinguishes_alternative_collection_failure(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.101", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gap = EvidenceGap("192.0.2.101", 5357, "tcp", "http-methods", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        round_result = AlternativeEvidenceRoundResult(
            (),
            (AlternativeEvidenceVerification("collection_failed", action, ()),),
            snapshot,
        )

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "alternative_collection_failed")
        self.assertEqual(decision.further_actions, ())

    def test_final_decision_preserves_observed_alternative_without_falsely_closing_gaps(self) -> None:
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            AlternativeEvidenceVerification,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan

        action = EvidenceAction("192.0.2.102", 5357, "tcp", ("http-headers",), ("purpose",), ("nmap",))
        gap = EvidenceGap("192.0.2.102", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        round_result = AlternativeEvidenceRoundResult(
            (),
            (AlternativeEvidenceVerification("observed", action, ("http-headers",)),),
            snapshot,
        )

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(decision.status, "complete")
        self.assertEqual(decision.reason, "all_semantic_requirements_satisfied")
        self.assertEqual(decision.remaining_gaps, (gap,))
        self.assertEqual(decision.further_actions, ())

    def test_continuation_is_complete_when_no_gaps_remain(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        gap = EvidenceGap("192.0.2.10", 445, "tcp", "smb-protocols", "purpose")
        decision = assess_investigation_continuation(
            self._snapshot((gap,)),
            self._snapshot(()),
        )

        self.assertEqual(decision.status, "complete")
        self.assertEqual(decision.resolved_gaps, (gap,))
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.next_actions, ())

    def test_continuation_is_progressed_when_some_gaps_resolve_and_actions_remain(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        resolved = EvidenceGap("192.0.2.20", 445, "tcp", "smb-protocols", "purpose")
        remaining = EvidenceGap("192.0.2.20", 445, "tcp", "smb2-security-mode", "purpose")
        action = EvidenceAction(
            host="192.0.2.20",
            port=445,
            protocol="tcp",
            script_ids=("smb2-security-mode",),
            purposes=("purpose",),
            command=("nmap",),
        )

        decision = assess_investigation_continuation(
            self._snapshot((resolved, remaining)),
            self._snapshot((remaining,), (action,)),
        )

        self.assertEqual(decision.status, "progressed")
        self.assertEqual(decision.resolved_gaps, (resolved,))
        self.assertEqual(decision.remaining_gaps, (remaining,))
        self.assertEqual(decision.next_actions, (action,))

    def test_continuation_stalls_when_same_unknowns_remain(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        gap = EvidenceGap("192.0.2.30", 5357, "tcp", "http-title", "purpose")
        action = EvidenceAction(
            host="192.0.2.30",
            port=5357,
            protocol="tcp",
            script_ids=("http-title",),
            purposes=("purpose",),
            command=("nmap",),
        )

        decision = assess_investigation_continuation(
            self._snapshot((gap,), (action,)),
            self._snapshot((gap,), (action,)),
        )

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "no_progress")
        self.assertEqual(decision.resolved_gaps, ())
        self.assertEqual(decision.remaining_gaps, (gap,))
        self.assertEqual(decision.next_actions, (action,))

    def test_continuation_stalls_when_only_remaining_action_was_already_attempted(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        resolved = EvidenceGap("192.0.2.40", 445, "tcp", "smb-protocols", "purpose")
        remaining = EvidenceGap("192.0.2.40", 5357, "tcp", "http-title", "purpose")
        attempted_http = EvidenceAction(
            host="192.0.2.40",
            port=5357,
            protocol="tcp",
            script_ids=("http-title",),
            purposes=("purpose",),
            command=("nmap", "-p", "5357", "--script", "http-title"),
        )

        decision = assess_investigation_continuation(
            self._snapshot((resolved, remaining), (attempted_http,)),
            self._snapshot((remaining,), (attempted_http,)),
            attempted_actions=(attempted_http,),
        )

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.resolved_gaps, (resolved,))
        self.assertEqual(decision.next_actions, ())
        self.assertEqual(decision.repeat_blocked_actions, (attempted_http,))
        self.assertEqual(decision.stall_reason, "repeated_actions_exhausted")

    def test_continuation_keeps_new_action_when_another_action_is_repeat_blocked(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        resolved = EvidenceGap("192.0.2.50", 445, "tcp", "smb-protocols", "purpose")
        remaining = EvidenceGap("192.0.2.50", 5357, "tcp", "http-title", "purpose")
        repeated = EvidenceAction(
            host="192.0.2.50",
            port=5357,
            protocol="tcp",
            script_ids=("http-title",),
            purposes=("purpose",),
            command=("nmap", "-p", "5357", "--script", "http-title"),
        )
        new_action = EvidenceAction(
            host="192.0.2.50",
            port=443,
            protocol="tcp",
            script_ids=("ssl-cert",),
            purposes=("purpose",),
            command=("nmap", "-p", "443", "--script", "ssl-cert"),
        )

        decision = assess_investigation_continuation(
            self._snapshot((resolved, remaining), (repeated,)),
            self._snapshot((remaining,), (repeated, new_action)),
            attempted_actions=(repeated,),
        )

        self.assertEqual(decision.status, "progressed")
        self.assertEqual(decision.next_actions, (new_action,))
        self.assertEqual(decision.repeat_blocked_actions, (repeated,))

    def test_resolved_requirement_states_tracks_primary_semantic_progress(self) -> None:
        from evidence_gaps import resolved_requirement_states

        before = (
            EvidenceGap("192.0.2.61", 445, "tcp", "smb-protocols", "purpose"),
            EvidenceGap("192.0.2.61", 445, "tcp", "smb2-security-mode", "purpose"),
            EvidenceGap("192.0.2.61", 5357, "tcp", "http-title", "purpose"),
        )
        after = (
            EvidenceGap("192.0.2.61", 5357, "tcp", "http-title", "purpose"),
        )

        resolved = resolved_requirement_states(before, after)

        self.assertEqual(
            [state.requirement.requirement_id for state in resolved],
            ["smb_protocol_support", "smb_signing_configuration"],
        )

    def test_requirement_states_for_gaps_deduplicates_per_endpoint_and_requirement(self) -> None:
        from evidence_gaps import requirement_states_for_gaps

        states = requirement_states_for_gaps(
            (
                EvidenceGap("192.0.2.60", 443, "tcp", "http-title", "purpose"),
                EvidenceGap("192.0.2.60", 443, "tcp", "http-title", "purpose"),
                EvidenceGap("192.0.2.60", 443, "tcp", "http-methods", "purpose"),
                EvidenceGap("192.0.2.60", 8443, "tcp", "http-title", "purpose"),
            )
        )

        self.assertEqual(
            [(state.port, state.requirement.requirement_id) for state in states],
            [
                (443, "http_identity_context"),
                (443, "http_supported_methods"),
                (8443, "http_identity_context"),
            ],
        )

    def test_requirement_state_normalizes_endpoint_identity(self) -> None:
        from evidence_gaps import requirement_state_for_gap

        state = requirement_state_for_gap(
            EvidenceGap(" 192.0.2.61 ", 8080, " TCP ", "http-title", "purpose")
        )

        self.assertIsNotNone(state)
        self.assertEqual((state.host, state.port, state.protocol), ("192.0.2.61", 8080, "tcp"))
        self.assertEqual(state.requirement.requirement_id, "http_identity_context")

    def test_http_methods_gap_alone_does_not_offer_identity_alternative(self) -> None:
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        gap = EvidenceGap("192.0.2.60", 5357, "tcp", "http-methods", "review supported HTTP methods")
        repeated = EvidenceAction(
            "192.0.2.60", 5357, "tcp", ("http-methods",),
            ("review supported HTTP methods",),
            ("nmap", "-p", "5357", "--script", "http-methods", "-oX", "-", "192.0.2.60"),
        )
        before = InvestigationSnapshot(True, Scan("before.xml"), (gap,), (repeated,), (), None)
        after = InvestigationSnapshot(True, Scan("after.xml"), (gap,), (repeated,), (), None)

        decision = assess_investigation_continuation(before, after, (repeated,))

        self.assertEqual(decision.stall_reason, "repeated_actions_exhausted")
        self.assertEqual(decision.alternative_actions, ())

    def test_exhausted_http_action_offers_http_headers_alternative(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        gap = EvidenceGap("192.0.2.60", 5357, "tcp", "http-title", "purpose")
        attempted = EvidenceAction(
            host="192.0.2.60",
            port=5357,
            protocol="tcp",
            script_ids=("http-title", "http-methods"),
            purposes=("purpose",),
            command=("nmap", "-p", "5357", "--script", "http-title,http-methods", "-oX", "-", "192.0.2.60"),
        )

        decision = assess_investigation_continuation(
            self._snapshot((gap,), (attempted,)),
            self._snapshot((gap,), (attempted,)),
            attempted_actions=(attempted,),
        )

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "repeated_actions_exhausted")
        self.assertEqual(len(decision.alternative_actions), 1)
        alternative = decision.alternative_actions[0]
        self.assertEqual(alternative.script_ids, ("http-headers",))
        self.assertEqual(
            alternative.command,
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.60"),
        )

    def test_exhausted_non_http_action_offers_no_unrelated_alternative(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        gap = EvidenceGap("192.0.2.61", 445, "tcp", "smb-protocols", "purpose")
        attempted = EvidenceAction(
            host="192.0.2.61",
            port=445,
            protocol="tcp",
            script_ids=("smb-protocols",),
            purposes=("purpose",),
            command=("nmap", "-p", "445", "--script", "smb-protocols"),
        )

        decision = assess_investigation_continuation(
            self._snapshot((gap,), (attempted,)),
            self._snapshot((gap,), (attempted,)),
            attempted_actions=(attempted,),
        )

        self.assertEqual(decision.stall_reason, "repeated_actions_exhausted")
        self.assertEqual(decision.alternative_actions, ())

    def test_continuation_assessment_rejects_unready_snapshot(self) -> None:
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )

        blocked = InvestigationSnapshot(
            ready=False,
            scan=None,
            gaps=(),
            actions=(),
            states=(),
            error="discovery failed",
        )

        with self.assertRaisesRegex(
            ValueError,
            "Continuation assessment requires ready investigations",
        ):
            assess_investigation_continuation(blocked, self._snapshot(()))



    def test_continuation_decision_reports_resolved_semantic_requirements(self) -> None:
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        before_gap = EvidenceGap(
            "192.0.2.62", 445, "tcp", "smb-protocols", "review SMB protocol dialect support"
        )
        after_gap = EvidenceGap(
            "192.0.2.62", 5357, "tcp", "http-title", "review HTTP service identity"
        )
        before = InvestigationSnapshot(True, Scan("before.xml"), (before_gap, after_gap), (), (), None)
        after = InvestigationSnapshot(True, Scan("after.xml"), (after_gap,), (), (), None)

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(
            [
                (state.host, state.port, state.protocol, state.requirement.requirement_id)
                for state in decision.resolved_requirements
            ],
            [("192.0.2.62", 445, "tcp", "smb_protocol_support")],
        )



    def test_investigation_attention_uses_merged_nse_evidence(self) -> None:
        from investigation_orchestration import InvestigationSnapshot, build_investigation_attention
        from models import Host, Port, Scan, ScriptResult

        scan = Scan(
            source="merged investigation",
            hosts=(
                Host(
                    address="192.0.2.50",
                    status="up",
                    ports=(
                        Port(
                            445,
                            "tcp",
                            "open",
                            "microsoft-ds",
                            scripts=(
                                ScriptResult("smb-protocols", "2:1:0, 3:0:2, 3:1:1"),
                                ScriptResult(
                                    "smb2-security-mode",
                                    "Message signing enabled but not required",
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )

        attention = build_investigation_attention(snapshot)

        self.assertEqual(
            [item.finding_id for item in attention],
            ["service.smb.exposed", "smb.signing.review"],
        )
        self.assertEqual(attention[1].evidence_source, "nse:smb2-security-mode")
        self.assertNotIn("smb.protocol.modern_only", [item.finding_id for item in attention])


    def test_investigation_synthesis_reflects_existing_outputs_without_new_conclusions(self) -> None:
        from analyst_attention import AnalystAttentionCorrelation, AnalystAttentionItem
        from evidence_gaps import requirement_state_for_gap
        from investigation_orchestration import FinalInvestigationDecision
        from investigation_synthesis import build_investigation_synthesis

        remaining = requirement_state_for_gap(
            EvidenceGap(
                "192.0.2.70",
                5357,
                "tcp",
                "http-title",
                "review HTTP service identity and exposed content context",
            )
        )
        self.assertIsNotNone(remaining)
        final_decision = FinalInvestigationDecision(
            status="stalled",
            reason="alternative_evidence_incomplete",
            remaining_gaps=(),
            remaining_requirements=(remaining,),
        )
        attention = (
            AnalystAttentionItem(
                "service.smb.exposed",
                "exposure",
                "192.0.2.70",
                445,
                "tcp",
                "SMB service exposed",
                "445/tcp is open.",
                "Review SMB exposure.",
                "service:detection",
            ),
            AnalystAttentionItem(
                "smb.signing.review",
                "configuration",
                "192.0.2.70",
                445,
                "tcp",
                "SMB signing configuration requires review",
                "Message signing enabled but not required",
                "Review the SMB signing policy.",
                "nse:smb2-security-mode",
            ),
        )
        correlations = (
            AnalystAttentionCorrelation(
                "smb.exposure_and_signing_review",
                "192.0.2.70",
                "SMB exposure and signing configuration require joint review",
                ("service.smb.exposed", "smb.signing.review"),
                ("service:detection", "nse:smb2-security-mode"),
                "Review the observations together.",
            ),
        )

        synthesis = build_investigation_synthesis(
            final_decision,
            attention,
            correlations,
        )

        self.assertEqual(synthesis.status, "stalled")
        self.assertEqual(synthesis.reason, "alternative_evidence_incomplete")
        self.assertEqual(synthesis.attention_items, 2)
        self.assertEqual(synthesis.correlated_review_groups, 1)
        self.assertEqual(synthesis.remaining_requirements, (remaining,))


if __name__ == "__main__":
    unittest.main()
