"""Contract tests for composing verified discovery into an investigation snapshot."""

import unittest
from unittest.mock import patch

from evidence_action_plan import EvidenceAction
from finding_collection_planner import FindingCollectionPlan, verify_finding_collection_plan
from finding_requirements import FindingDerivedRequirement
from requirement_collection import CollectionAuthorizationDecision, RequirementCollectionStrategy
from models import Host, Port, Scan, ScriptResult
from evidence_gaps import EvidenceGap
from scan_orchestration import (
    DiscoveryExecutionResult,
    DiscoveryResult,
    build_baseline_discovery_plan,
)

from investigation_orchestration import InvestigationContinuationDecision, build_investigation_snapshot, finalize_continuation_decision, re_evaluate_investigation


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


    def test_re_evaluation_tracks_approval_blocked_finding_requirement(self) -> None:
        scan = Scan(
            source="smb.xml",
            hosts=(Host(
                address="192.0.2.96",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(ScriptResult(
                        "smb2-security-mode",
                        "3.1.1: Message signing enabled but not required",
                    ),),
                ),),
            ),),
        )

        snapshot = re_evaluate_investigation(scan, ())

        self.assertEqual(len(snapshot.finding_collection_plans), 1)
        plan = snapshot.finding_collection_plans[0]
        self.assertEqual(
            plan.requirement.requirement_id,
            "smb_access_control_context",
        )
        self.assertFalse(plan.authorization.allowed)
        self.assertEqual(
            plan.authorization.reason,
            "explicit_approval_required",
        )
        self.assertFalse(
            any(
                action.script_ids == ("smb-enum-shares",)
                for action in snapshot.actions
            )
        )


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
    def _snapshot(self, gaps, actions=(), finding_collection_plans=()):
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
    finalize_continuation_decision,
        )
        from models import Scan

        return InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=gaps,
            actions=actions,
            states=(),
            error=None,
            finding_collection_plans=finding_collection_plans,
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

    def test_final_decision_does_not_complete_with_attempted_unsatisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.135",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="attempted_unsatisfied",
            authorization_reason="explicitly_approved",
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(state,),
        )
        round_result = AlternativeEvidenceRoundResult((), (), snapshot)

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "finding_requirement_unsatisfied")
        self.assertEqual(decision.remaining_finding_requirements, (state,))

    def test_final_decision_preserves_all_unresolved_finding_requirements_with_approval_precedence(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from models import Scan

        pending_requirement = FindingDerivedRequirement(
            "pending_context", "192.0.2.207", 445, "tcp",
            "review pending context", "finding.pending", "source",
        )
        unsatisfied_requirement = FindingDerivedRequirement(
            "unsatisfied_context", "192.0.2.207", 445, "tcp",
            "review unsatisfied context", "finding.unsatisfied", "source",
        )
        pending = FindingRequirementState(
            pending_requirement, "pending_approval", "explicit_approval_required", ()
        )
        unsatisfied = FindingRequirementState(
            unsatisfied_requirement, "attempted_unsatisfied", "explicitly_approved", ()
        )
        snapshot = InvestigationSnapshot(
            True, Scan("mixed-final.xml"), (), (), (), None,
            finding_requirement_states=(pending, unsatisfied),
        )

        decision = assess_final_investigation_decision(
            AlternativeEvidenceRoundResult((), (), snapshot)
        )

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "explicit_approval_required")
        self.assertEqual(decision.remaining_finding_requirements, (pending, unsatisfied))

    def test_final_decision_does_not_complete_with_pending_approval_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.136",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="pending_approval",
            authorization_reason="explicit_approval_required",
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(state,),
        )
        round_result = AlternativeEvidenceRoundResult((), (), snapshot)

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "explicit_approval_required")
        self.assertEqual(decision.remaining_finding_requirements, (state,))

    def test_final_decision_can_complete_with_satisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationSnapshot,
            assess_final_investigation_decision,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.137",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="satisfied",
            authorization_reason="explicitly_approved",
            observed_script_ids=("smb-enum-shares",),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(state,),
        )
        round_result = AlternativeEvidenceRoundResult((), (), snapshot)

        decision = assess_final_investigation_decision(round_result)

        self.assertEqual(decision.status, "complete")
        self.assertEqual(decision.reason, "all_gaps_resolved")

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

    def test_continuation_waits_for_explicit_approval_instead_of_completing(self) -> None:
        from investigation_orchestration import assess_investigation_continuation

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        plan = FindingCollectionPlan(
            requirement=requirement,
            strategy=RequirementCollectionStrategy(
                requirement_id="smb_access_control_context",
                status="supported",
                script_ids=("smb-enum-shares",),
                risk_class="intrusive",
                authorization="requires_approval",
            ),
            authorization=CollectionAuthorizationDecision(
                allowed=False,
                reason="explicit_approval_required",
            ),
        )

        decision = assess_investigation_continuation(
            self._snapshot(()),
            self._snapshot((), finding_collection_plans=(plan,)),
        )

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "explicit_approval_required")
        self.assertEqual(decision.next_actions, ())

    def test_continuation_uses_pending_approval_lifecycle_state(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.11",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            requirement=requirement,
            status="pending_approval",
            authorization_reason="explicit_approval_required",
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )
        after = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(pending,),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "explicit_approval_required")
        self.assertEqual(decision.next_actions, ())

    def test_continuation_preserves_pending_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.254",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            requirement=requirement,
            status="pending_approval",
            authorization_reason="explicit_approval_required",
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )
        after = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(pending,),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.remaining_finding_requirements, (pending,))

    def test_continuation_preserves_attempted_unsatisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.255",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        attempted = FindingRequirementState(
            requirement=requirement,
            status="attempted_unsatisfied",
            authorization_reason="explicitly_approved",
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )
        after = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(attempted,),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "finding_requirement_unsatisfied")
        self.assertEqual(decision.remaining_finding_requirements, (attempted,))

    def test_pending_approval_takes_precedence_over_unsatisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        pending_requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.201",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        unsatisfied_requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.202",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            pending_requirement, "pending_approval", "explicit_approval_required", ()
        )
        unsatisfied = FindingRequirementState(
            unsatisfied_requirement, "attempted_unsatisfied", "explicitly_approved", ()
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )
        after = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(pending, unsatisfied),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "explicit_approval_required")
        self.assertEqual(
            decision.remaining_finding_requirements,
            (pending, unsatisfied),
        )

    def test_unsatisfied_finding_requirement_takes_precedence_when_no_gaps_remain(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.200",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        attempted = FindingRequirementState(
            requirement=requirement,
            status="attempted_unsatisfied",
            authorization_reason="explicitly_approved",
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(EvidenceGap("192.0.2.200", 445, "tcp", "smb2-security-mode", "purpose"),),
            actions=(),
            states=(),
            error=None,
        )
        after = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(attempted,),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "finding_requirement_unsatisfied")
        self.assertEqual(decision.remaining_finding_requirements, (attempted,))

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



    def test_investigation_memory_compares_factual_synthesis_changes(self) -> None:
        from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
        from investigation_memory import compare_investigation_syntheses
        from investigation_synthesis import InvestigationSynthesis

        resolved = EvidenceRequirementState(
            "192.0.2.130",
            5357,
            "tcp",
            EvidenceRequirement(
                "http_identity_context",
                "review HTTP service identity and exposed content context",
                ("http-title",),
                ("http-headers",),
            ),
        )
        added = EvidenceRequirementState(
            "192.0.2.130",
            443,
            "tcp",
            EvidenceRequirement(
                "tls_certificate_identity",
                "review TLS certificate identity",
                ("ssl-cert",),
            ),
        )
        previous = InvestigationSynthesis(
            "stalled",
            "alternative_evidence_incomplete",
            4,
            1,
            (resolved,),
        )
        current = InvestigationSynthesis(
            "stalled",
            "no_supported_actions",
            5,
            2,
            (added,),
        )

        memory = compare_investigation_syntheses(previous, current)

        self.assertFalse(memory.status_changed)
        self.assertEqual(memory.previous_status, "stalled")
        self.assertEqual(memory.current_status, "stalled")
        self.assertTrue(memory.reason_changed)
        self.assertEqual(memory.previous_reason, "alternative_evidence_incomplete")
        self.assertEqual(memory.current_reason, "no_supported_actions")
        self.assertEqual(memory.attention_item_change, 1)
        self.assertEqual(memory.correlated_review_group_change, 1)
        self.assertEqual(memory.resolved_requirements, (resolved,))
        self.assertEqual(memory.added_requirements, (added,))



    def test_investigation_history_record_json_round_trip_preserves_state(self) -> None:
        from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
        from investigation_history import (
            InvestigationHistoryRecord,
            parse_investigation_history_record_json,
            render_investigation_history_record_json,
        )
        from investigation_synthesis import InvestigationSynthesis

        remaining = EvidenceRequirementState(
            "192.0.2.140",
            5357,
            "tcp",
            EvidenceRequirement(
                "http_identity_context",
                "review HTTP service identity and exposed content context",
                ("http-title",),
                ("http-headers",),
            ),
        )
        record = InvestigationHistoryRecord(
            observed_at=1770000000,
            target="192.0.2.140",
            synthesis=InvestigationSynthesis(
                status="stalled",
                reason="alternative_evidence_incomplete",
                attention_items=4,
                correlated_review_groups=1,
                remaining_requirements=(remaining,),
            ),
        )

        payload = render_investigation_history_record_json(record)
        restored = parse_investigation_history_record_json(payload)

        self.assertEqual(restored, record)



    def test_investigation_history_store_appends_and_loads_in_order(self) -> None:
        import tempfile
        from pathlib import Path

        from investigation_history import (
            InvestigationHistoryRecord,
            append_investigation_history_record,
            load_investigation_history,
        )
        from investigation_synthesis import InvestigationSynthesis

        first = InvestigationHistoryRecord(
            observed_at=1770000000,
            target="192.0.2.150",
            synthesis=InvestigationSynthesis(
                "stalled",
                "alternative_evidence_incomplete",
                4,
                1,
                (),
            ),
        )
        second = InvestigationHistoryRecord(
            observed_at=1770003600,
            target="192.0.2.150",
            synthesis=InvestigationSynthesis(
                "complete",
                "all_semantic_requirements_satisfied",
                5,
                1,
                (),
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "history.jsonl")
            append_investigation_history_record(path, first)
            append_investigation_history_record(path, second)

            self.assertEqual(load_investigation_history(path), (first, second))



    def test_latest_investigation_for_target_uses_target_and_timestamp(self) -> None:
        from investigation_history import (
            InvestigationHistoryRecord,
            latest_investigation_for_target,
        )
        from investigation_synthesis import InvestigationSynthesis

        def record(observed_at: int, target: str) -> InvestigationHistoryRecord:
            return InvestigationHistoryRecord(
                observed_at=observed_at,
                target=target,
                synthesis=InvestigationSynthesis(
                    "stalled",
                    "no_supported_actions",
                    0,
                    0,
                    (),
                ),
            )

        older_a = record(100, "192.0.2.160")
        other_target = record(300, "192.0.2.161")
        newer_a = record(200, "192.0.2.160")

        selected = latest_investigation_for_target(
            (newer_a, other_target, older_a),
            " 192.0.2.160 ",
        )

        self.assertEqual(selected, newer_a)
        self.assertIsNone(
            latest_investigation_for_target(
                (newer_a, other_target, older_a),
                "192.0.2.162",
            )
        )


    def test_adaptive_plan_chooses_only_supported_next_step(self) -> None:
        from adaptive_investigation import build_adaptive_investigation_plan
        from investigation_orchestration import InvestigationContinuationDecision

        new_action = EvidenceAction(
            "192.0.2.200", 443, "tcp", ("ssl-cert",), ("review certificate",),
            ("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.200"),
        )
        alternative = EvidenceAction(
            "192.0.2.200", 5357, "tcp", ("http-headers",), ("review HTTP identity",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.200"),
        )

        complete = build_adaptive_investigation_plan(
            InvestigationContinuationDecision("complete", (), (), (), ())
        )
        continuing = build_adaptive_investigation_plan(
            InvestigationContinuationDecision(
                "progressed", (), (), (new_action,), ()
            )
        )
        alternative_plan = build_adaptive_investigation_plan(
            InvestigationContinuationDecision(
                "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
            )
        )
        stalled = build_adaptive_investigation_plan(
            InvestigationContinuationDecision(
                "stalled", (), (), (), (), "no_supported_actions"
            )
        )

        self.assertEqual(
            (complete.decision, complete.reason, complete.actions),
            ("stop", "investigation_complete", ()),
        )
        self.assertEqual(
            (continuing.decision, continuing.reason, continuing.actions),
            ("continue", "new_supported_actions_available", (new_action,)),
        )
        self.assertEqual(
            (alternative_plan.decision, alternative_plan.reason, alternative_plan.actions),
            ("alternative", "supported_alternative_actions_available", (alternative,)),
        )
        self.assertEqual(
            (stalled.decision, stalled.reason, stalled.actions),
            ("stop", "no_supported_actions", ()),
        )


    def test_adaptive_controller_selects_only_non_terminal_plan_actions(self) -> None:
        from adaptive_investigation import AdaptiveInvestigationPlan, select_adaptive_actions

        action = EvidenceAction(
            "192.0.2.201", 5357, "tcp", ("http-headers",), ("review HTTP identity",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.201"),
        )

        self.assertEqual(
            select_adaptive_actions(
                AdaptiveInvestigationPlan("continue", "new_supported_actions_available", (action,))
            ),
            (action,),
        )
        self.assertEqual(
            select_adaptive_actions(
                AdaptiveInvestigationPlan("alternative", "supported_alternative_actions_available", (action,))
            ),
            (action,),
        )
        self.assertEqual(
            select_adaptive_actions(
                AdaptiveInvestigationPlan("stop", "no_supported_next_step", (action,))
            ),
            (),
        )


    def test_adaptive_continue_authorizes_only_repeat_guard_safe_next_actions(self) -> None:
        from adaptive_investigation import (
            build_adaptive_investigation_plan,
            select_adaptive_actions,
        )
        from investigation_orchestration import assess_investigation_continuation

        attempted = EvidenceAction(
            "192.0.2.220", 445, "tcp", ("smb-protocols",), ("review SMB dialects",),
            ("nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.220"),
        )
        next_action = EvidenceAction(
            "192.0.2.220", 443, "tcp", ("ssl-cert",), ("review TLS certificate",),
            ("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.220"),
        )
        resolved_gap = EvidenceGap(
            "192.0.2.220", 445, "tcp", "smb-protocols", "review SMB dialects"
        )
        remaining_gap = EvidenceGap(
            "192.0.2.220", 443, "tcp", "ssl-cert", "review TLS certificate"
        )

        before = self._snapshot(
            (resolved_gap, remaining_gap),
            (attempted, next_action),
        )
        after = self._snapshot(
            (remaining_gap,),
            (attempted, next_action),
        )

        decision = assess_investigation_continuation(
            before,
            after,
            attempted_actions=(attempted,),
        )
        plan = build_adaptive_investigation_plan(decision)
        selected = select_adaptive_actions(plan)

        self.assertEqual(decision.status, "progressed")
        self.assertEqual(decision.repeat_blocked_actions, (attempted,))
        self.assertEqual(decision.next_actions, (next_action,))
        self.assertEqual(plan.decision, "continue")
        self.assertEqual(selected, (next_action,))
        self.assertNotIn(attempted, selected)


class EvidenceDerivedKnowledgeTests(unittest.TestCase):
    def test_derives_nonempty_nse_observation_with_explicit_provenance(self) -> None:
        from evidence_knowledge import EvidenceDerivedKnowledge, derive_evidence_knowledge
        from models import Host, Port, Scan, ScriptResult

        scan = Scan(
            source="collected evidence",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(
                            port=445,
                            protocol="TCP",
                            state="open",
                            service="microsoft-ds",
                            scripts=(
                                ScriptResult(
                                    " SMB2-SECURITY-MODE ",
                                    "3.1.1: Message signing enabled but not required",
                                ),
                                ScriptResult("empty-script", "   "),
                            ),
                        ),
                    ),
                ),
            ),
        )

        self.assertEqual(
            derive_evidence_knowledge(scan),
            (
                EvidenceDerivedKnowledge(
                    host="192.0.2.10",
                    port=445,
                    protocol="tcp",
                    fact_type="nse_observation",
                    value="3.1.1: Message signing enabled but not required",
                    evidence_source="nse:smb2-security-mode",
                ),
            ),
        )

    def test_evidence_knowledge_does_not_promote_collected_service_metadata(self) -> None:
        from evidence_knowledge import derive_evidence_knowledge
        from models import Host, Port, Scan

        scan = Scan(
            source="collected evidence",
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
                            product="Example TLS Service",
                            version="1.0",
                        ),
                    ),
                ),
            ),
        )

        self.assertEqual(derive_evidence_knowledge(scan), ())


class FindingDerivedRequirementTests(unittest.TestCase):
    def test_known_finding_derives_requirement_with_provenance(self) -> None:
        from finding_requirements import FindingDerivedRequirement, derive_finding_requirements
        from findings import Finding

        finding = Finding(
            finding_id="smb.signing.review",
            category="configuration",
            host="192.0.2.30",
            port=445,
            protocol="TCP",
            severity="medium",
            title="SMB signing configuration requires review",
            evidence="Observed signing configuration",
            recommendation="Review SMB signing policy",
            evidence_source="nse:smb2-security-mode",
        )

        self.assertEqual(
            derive_finding_requirements((finding,)),
            (
                FindingDerivedRequirement(
                    requirement_id="smb_access_control_context",
                    host="192.0.2.30",
                    port=445,
                    protocol="tcp",
                    purpose="review SMB access controls in the context of the observed signing configuration",
                    finding_id="smb.signing.review",
                    evidence_source="nse:smb2-security-mode",
                ),
            ),
        )

    def test_unmapped_finding_does_not_invent_requirement(self) -> None:
        from finding_requirements import derive_finding_requirements
        from findings import Finding

        finding = Finding(
            finding_id="example.unmapped",
            category="context",
            host="192.0.2.40",
            port=80,
            protocol="tcp",
            severity="info",
            title="Unmapped observation",
            evidence="Observed",
            recommendation="Review",
            evidence_source="nse:example",
        )

        self.assertEqual(derive_finding_requirements((finding,)), ())


class RequirementCollectionStrategyTests(unittest.TestCase):
    def test_smb_access_control_strategy_requires_explicit_approval(self) -> None:
        from finding_requirements import FindingDerivedRequirement
        from requirement_collection import RequirementCollectionStrategy, collection_strategy_for_requirement

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.50",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls in the context of the observed signing configuration",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )

        self.assertEqual(
            collection_strategy_for_requirement(requirement),
            RequirementCollectionStrategy(
                requirement_id="smb_access_control_context",
                status="supported",
                script_ids=("smb-enum-shares",),
                risk_class="intrusive",
                authorization="requires_approval",
            ),
        )

    def test_unmapped_requirement_is_explicitly_unsupported(self) -> None:
        from finding_requirements import FindingDerivedRequirement
        from requirement_collection import RequirementCollectionStrategy, collection_strategy_for_requirement

        requirement = FindingDerivedRequirement(
            requirement_id="unknown_requirement",
            host="192.0.2.50",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls in the context of the observed signing configuration",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )

        self.assertEqual(
            collection_strategy_for_requirement(requirement),
            RequirementCollectionStrategy(
                requirement_id="unknown_requirement",
                status="unsupported",
                reason="no_approved_collection_strategy",
            ),
        )


class CollectionAuthorizationGateTests(unittest.TestCase):
    def test_intrusive_strategy_is_blocked_without_explicit_approval(self) -> None:
        from requirement_collection import (
            CollectionAuthorizationDecision,
            RequirementCollectionStrategy,
            authorize_collection_strategy,
        )

        strategy = RequirementCollectionStrategy(
            requirement_id="smb_access_control_context",
            status="supported",
            script_ids=("smb-enum-shares",),
            risk_class="intrusive",
            authorization="requires_approval",
        )

        self.assertEqual(
            authorize_collection_strategy(strategy),
            CollectionAuthorizationDecision(False, "explicit_approval_required"),
        )

    def test_intrusive_strategy_is_allowed_only_after_explicit_approval(self) -> None:
        from requirement_collection import (
            CollectionAuthorizationDecision,
            RequirementCollectionStrategy,
            authorize_collection_strategy,
        )

        strategy = RequirementCollectionStrategy(
            requirement_id="smb_access_control_context",
            status="supported",
            script_ids=("smb-enum-shares",),
            risk_class="intrusive",
            authorization="requires_approval",
        )

        self.assertEqual(
            authorize_collection_strategy(strategy, explicitly_approved=True),
            CollectionAuthorizationDecision(True, "explicitly_approved"),
        )

    def test_unsupported_strategy_cannot_be_overridden_by_approval(self) -> None:
        from requirement_collection import (
            CollectionAuthorizationDecision,
            RequirementCollectionStrategy,
            authorize_collection_strategy,
        )

        strategy = RequirementCollectionStrategy(
            requirement_id="unknown_requirement",
            status="unsupported",
            reason="no_approved_collection_strategy",
        )

        self.assertEqual(
            authorize_collection_strategy(strategy, explicitly_approved=True),
            CollectionAuthorizationDecision(False, "unsupported_strategy"),
        )


class FindingCollectionPlannerTests(unittest.TestCase):
    def test_finding_pipeline_preserves_requirement_strategy_and_approval_boundary(self) -> None:
        from finding_collection_planner import build_finding_collection_plans
        from findings import Finding

        finding = Finding(
            finding_id="smb.signing.review",
            category="configuration",
            host="192.0.2.60",
            port=445,
            protocol="tcp",
            severity="medium",
            title="SMB signing configuration requires review",
            evidence="Message signing enabled but not required",
            recommendation="Review SMB signing configuration",
            evidence_source="nse:smb2-security-mode",
        )

        plans = build_finding_collection_plans((finding,))

        self.assertEqual(len(plans), 1)
        plan = plans[0]
        self.assertEqual(plan.requirement.requirement_id, "smb_access_control_context")
        self.assertEqual(plan.requirement.finding_id, "smb.signing.review")
        self.assertEqual(plan.requirement.evidence_source, "nse:smb2-security-mode")
        self.assertEqual(plan.strategy.script_ids, ("smb-enum-shares",))
        self.assertEqual(plan.strategy.risk_class, "intrusive")
        self.assertEqual(plan.strategy.authorization, "requires_approval")
        self.assertFalse(plan.authorization.allowed)
        self.assertEqual(plan.authorization.reason, "explicit_approval_required")

    def test_finding_pipeline_can_record_explicit_requirement_approval(self) -> None:
        from finding_collection_planner import build_finding_collection_plans
        from findings import Finding

        finding = Finding(
            finding_id="smb.signing.review",
            category="configuration",
            host="192.0.2.61",
            port=445,
            protocol="tcp",
            severity="medium",
            title="SMB signing configuration requires review",
            evidence="Message signing enabled but not required",
            recommendation="Review SMB signing configuration",
            evidence_source="nse:smb2-security-mode",
        )

        plans = build_finding_collection_plans(
            (finding,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

        self.assertTrue(plans[0].authorization.allowed)
        self.assertEqual(plans[0].authorization.reason, "explicitly_approved")


class FindingCollectionEvidenceActionTests(unittest.TestCase):
    def test_blocked_finding_collection_plan_cannot_become_evidence_action(self) -> None:
        from finding_collection_planner import (
            build_finding_collection_plans,
            evidence_action_for_finding_collection_plan,
        )
        from findings import Finding

        finding = Finding(
            finding_id="smb.signing.review",
            category="configuration",
            host="192.0.2.70",
            port=445,
            protocol="tcp",
            severity="medium",
            title="SMB signing configuration requires review",
            evidence="Message signing enabled but not required",
            recommendation="Review SMB signing configuration",
            evidence_source="nse:smb2-security-mode",
        )

        plan = build_finding_collection_plans((finding,))[0]
        self.assertIsNone(evidence_action_for_finding_collection_plan(plan))

    def test_explicitly_approved_finding_plan_uses_standard_evidence_action_builder(self) -> None:
        from finding_collection_planner import (
            build_finding_collection_plans,
            evidence_action_for_finding_collection_plan,
        )
        from findings import Finding

        finding = Finding(
            finding_id="smb.signing.review",
            category="configuration",
            host="192.0.2.71",
            port=445,
            protocol="tcp",
            severity="medium",
            title="SMB signing configuration requires review",
            evidence="Message signing enabled but not required",
            recommendation="Review SMB signing configuration",
            evidence_source="nse:smb2-security-mode",
        )

        plan = build_finding_collection_plans(
            (finding,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )[0]
        action = evidence_action_for_finding_collection_plan(plan)

        self.assertIsNotNone(action)
        self.assertEqual(action.host, "192.0.2.71")
        self.assertEqual(action.port, 445)
        self.assertEqual(action.protocol, "tcp")
        self.assertEqual(action.script_ids, ("smb-enum-shares",))
        self.assertEqual(
            action.purposes,
            ("review SMB access controls in the context of the observed signing configuration",),
        )
        self.assertEqual(
            action.command,
            (
                "nmap",
                "-p",
                "445",
                "--script",
                "smb-enum-shares",
                "-oX",
                "-",
                "192.0.2.71",
            ),
        )


class DynamicEvidenceActionDerivationTests(unittest.TestCase):
    def test_dynamic_actions_remain_blocked_without_required_approval(self) -> None:
        from investigation_orchestration import build_dynamic_evidence_actions
        from models import Host, Port, Scan, ScriptResult

        scan = Scan(
            source="merged evidence",
            hosts=(
                Host(
                    address="192.0.2.80",
                    status="up",
                    ports=(
                        Port(
                            port=445,
                            protocol="tcp",
                            state="open",
                            service="microsoft-ds",
                            scripts=(
                                ScriptResult(
                                    script_id="smb2-security-mode",
                                    output="Message signing enabled but not required",
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        self.assertEqual(build_dynamic_evidence_actions(scan), ())

    def test_dynamic_actions_emerge_after_explicit_requirement_approval(self) -> None:
        from investigation_orchestration import build_dynamic_evidence_actions
        from models import Host, Port, Scan, ScriptResult

        scan = Scan(
            source="merged evidence",
            hosts=(
                Host(
                    address="192.0.2.81",
                    status="up",
                    ports=(
                        Port(
                            port=445,
                            protocol="tcp",
                            state="open",
                            service="microsoft-ds",
                            scripts=(
                                ScriptResult(
                                    script_id="smb2-security-mode",
                                    output="Message signing enabled but not required",
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        actions = build_dynamic_evidence_actions(
            scan,
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].script_ids, ("smb-enum-shares",))
        self.assertEqual(actions[0].host, "192.0.2.81")
        self.assertEqual(actions[0].port, 445)


class DynamicReevaluationIntegrationTests(unittest.TestCase):
    def test_reevaluation_does_not_surface_unapproved_dynamic_action(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import re_evaluate_investigation
        from models import Host, Port, Scan, ScriptResult

        discovery = Scan(
            source="discovery",
            hosts=(Host(
                address="192.0.2.90",
                status="up",
                ports=(Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),),
            ),),
        )
        collected = Scan(
            source="evidence",
            hosts=(Host(
                address="192.0.2.90",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(
                        script_id="smb2-security-mode",
                        output="Message signing enabled but not required",
                    ),),
                ),),
            ),),
        )
        outcome = ParsedCollectionResult(
            CollectionResult(NmapCommand(("nmap",)), 0, "", ""),
            collected,
        )

        snapshot = re_evaluate_investigation(discovery, (outcome,))
        self.assertNotIn(("smb-enum-shares",), tuple(a.script_ids for a in snapshot.actions))

    def test_reevaluation_surfaces_approved_dynamic_action(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import re_evaluate_investigation
        from models import Host, Port, Scan, ScriptResult

        discovery = Scan(
            source="discovery",
            hosts=(Host(
                address="192.0.2.91",
                status="up",
                ports=(Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),),
            ),),
        )
        collected = Scan(
            source="evidence",
            hosts=(Host(
                address="192.0.2.91",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    scripts=(ScriptResult(
                        script_id="smb2-security-mode",
                        output="Message signing enabled but not required",
                    ),),
                ),),
            ),),
        )
        outcome = ParsedCollectionResult(
            CollectionResult(NmapCommand(("nmap",)), 0, "", ""),
            collected,
        )

        snapshot = re_evaluate_investigation(
            discovery,
            (outcome,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )
        dynamic = tuple(a for a in snapshot.actions if a.script_ids == ("smb-enum-shares",))
        self.assertEqual(len(dynamic), 1)
        self.assertEqual(dynamic[0].host, "192.0.2.91")
        self.assertEqual(dynamic[0].port, 445)


class DynamicContinuationEmergenceTests(unittest.TestCase):
    def test_new_approved_finding_action_emerges_as_continuation_next_action(self) -> None:
        from unittest.mock import patch
        from evidence_action_plan import EvidenceAction
        from evidence_collector import CollectionResult
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
            execute_selected_evidence_actions,
        )
        from investigation_state import summarize_investigation_state
        from evidence_gaps import summarize_evidence_gaps
        from models import Host, Port, Scan

        scan = Scan(
            source="discovery",
            hosts=(Host(
                address="192.0.2.92",
                status="up",
                ports=(Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),),
            ),),
        )
        primary = EvidenceAction(
            host="192.0.2.92",
            port=445,
            protocol="tcp",
            script_ids=("smb2-security-mode",),
            purposes=("review SMB signing configuration",),
            command=("nmap", "-p", "445", "--script", "smb2-security-mode", "-oX", "-", "192.0.2.92"),
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=summarize_evidence_gaps(scan),
            actions=(primary,),
            states=summarize_investigation_state(scan),
            error=None,
        )
        xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="192.0.2.92" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open"/>
<script id="smb2-security-mode" output="Message signing enabled but not required"/>
</port></ports></host>
<runstats><finished time="0"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"""

        with patch(
            "investigation_orchestration.execute_nmap_command",
            return_value=CollectionResult(
                command=type("Command", (), {"arguments": primary.command})(),
                returncode=0,
                stdout=xml,
                stderr="",
            ),
        ):
            round_result = execute_selected_evidence_actions(
                before,
                (primary,),
                explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            )

        decision = assess_investigation_continuation(
            before,
            round_result.snapshot,
            attempted_actions=(primary,),
        )

        self.assertEqual(decision.status, "progressed")
        self.assertEqual(
            tuple(action.script_ids for action in decision.next_actions),
            (("smb-protocols",), ("smb-enum-shares",)),
        )
        self.assertIn(
            ("smb-enum-shares",),
            tuple(action.script_ids for action in decision.next_actions),
        )


class DynamicContinuationSemanticTests(unittest.TestCase):
    def test_new_dynamic_action_prevents_completion_when_primary_gaps_are_resolved(self) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        dynamic = EvidenceAction(
            host="192.0.2.93",
            port=445,
            protocol="tcp",
            script_ids=("smb-enum-shares",),
            purposes=("review SMB access controls in the context of the observed signing configuration",),
            command=("nmap", "-p", "445", "--script", "smb-enum-shares", "-oX", "-", "192.0.2.93"),
        )
        before = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="before.xml"),
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )
        after = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="after.xml"),
            gaps=(),
            actions=(dynamic,),
            states=(),
            error=None,
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "progressed")
        self.assertEqual(decision.next_actions, (dynamic,))


    def test_attempted_dynamic_action_does_not_prevent_completion_without_primary_gaps(self) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            InvestigationSnapshot,
            assess_investigation_continuation,
        )
        from models import Scan

        dynamic = EvidenceAction(
            host="192.0.2.94",
            port=445,
            protocol="tcp",
            script_ids=("smb-enum-shares",),
            purposes=("review SMB access controls in the context of the observed signing configuration",),
            command=("nmap", "-p", "445", "--script", "smb-enum-shares", "-oX", "-", "192.0.2.94"),
        )
        before = InvestigationSnapshot(True, Scan(source="before.xml"), (), (), (), None)
        after = InvestigationSnapshot(True, Scan(source="after.xml"), (), (dynamic,), (), None)

        decision = assess_investigation_continuation(
            before,
            after,
            attempted_actions=(dynamic,),
        )

        self.assertEqual(decision.status, "complete")
        self.assertEqual(decision.next_actions, ())
        self.assertEqual(decision.repeat_blocked_actions, (dynamic,))


    @patch("investigation_orchestration.execute_nmap_command")
    def test_dynamic_requirement_verification_is_preserved_in_updated_snapshot(self, execute_mock) -> None:
        from evidence_collector import CollectionResult, NmapCommand
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_selected_evidence_actions,
            re_evaluate_investigation,
        )

        discovery = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.95",
                status="up",
                ports=(Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),),
            ),),
        )
        security_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><host><status state="up"/><address addr="192.0.2.95" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open"/>
<script id="smb2-security-mode" output="Message signing enabled but not required"/>
</port></ports></host><runstats><finished time="0"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""
        from evidence_collector import ParsedCollectionResult
        security_outcome = ParsedCollectionResult(
            CollectionResult(NmapCommand(("nmap",)), 0, security_xml, ""),
            Scan(
                source="security.xml",
                hosts=(Host(
                    address="192.0.2.95",
                    status="up",
                    ports=(Port(
                        port=445,
                        protocol="tcp",
                        state="open",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),),
                    ),),
                ),),
            ),
        )
        snapshot = re_evaluate_investigation(
            discovery,
            (security_outcome,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )
        dynamic = next(
            action for action in snapshot.actions
            if action.script_ids == ("smb-enum-shares",)
        )
        execute_mock.return_value = CollectionResult(
            NmapCommand(dynamic.command),
            0,
            "<nmaprun><host><status state=\"up\"/><address addr=\"192.0.2.95\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"445\"><state state=\"open\"/></port></ports></host><runstats><finished time=\"0\"/><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats></nmaprun>",
            "",
        )

        result = execute_selected_evidence_actions(
            snapshot,
            (dynamic,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

        self.assertEqual(len(result.finding_requirement_verifications), 1)
        self.assertEqual(
            result.finding_requirement_verifications[0].status,
            "unsatisfied",
        )
        self.assertEqual(
            result.snapshot.finding_requirement_verifications,
            result.finding_requirement_verifications,
        )

    def test_reevaluation_does_not_regenerate_attempted_unsatisfied_dynamic_action(self) -> None:
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import re_evaluate_investigation

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.96",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        verification = FindingRequirementVerification(
            requirement=requirement,
            status="unsatisfied",
            observed_script_ids=(),
        )
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.96",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(ScriptResult(
                        "smb2-security-mode",
                        "Message signing enabled but not required",
                    ),),
                ),),
            ),),
        )

        snapshot = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            prior_finding_requirement_verifications=(verification,),
        )

        self.assertEqual(
            snapshot.finding_requirement_verifications,
            (verification,),
        )
        self.assertTrue(
            any(
                plan.requirement.requirement_id == "smb_access_control_context"
                for plan in snapshot.finding_collection_plans
            )
        )
        self.assertNotIn(
            ("smb-enum-shares",),
            tuple(action.script_ids for action in snapshot.actions),
        )

    def test_reevaluation_does_not_regenerate_satisfied_dynamic_action(self) -> None:
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import re_evaluate_investigation

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.97",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        verification = FindingRequirementVerification(
            requirement=requirement,
            status="satisfied",
            observed_script_ids=("smb-enum-shares",),
        )
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.97",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(
                        ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),
                        ScriptResult("smb-enum-shares", "account_used: guest"),
                    ),
                ),),
            ),),
        )

        snapshot = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            prior_finding_requirement_verifications=(verification,),
        )

        self.assertEqual(
            snapshot.finding_requirement_verifications,
            (verification,),
        )
        self.assertTrue(
            any(
                plan.requirement.requirement_id == "smb_access_control_context"
                for plan in snapshot.finding_collection_plans
            )
        )
        self.assertNotIn(
            ("smb-enum-shares",),
            tuple(action.script_ids for action in snapshot.actions),
        )

    def test_finding_requirement_states_project_full_lifecycle(self) -> None:
        from finding_collection_planner import (
            FindingRequirementVerification,
            finding_requirement_states,
        )

        def plan(host, allowed, reason):
            requirement = FindingDerivedRequirement(
                requirement_id="smb_access_control_context",
                host=host,
                port=445,
                protocol="tcp",
                purpose="review SMB access controls",
                finding_id="smb.signing.review",
                evidence_source="nse:smb2-security-mode",
            )
            return FindingCollectionPlan(
                requirement=requirement,
                strategy=RequirementCollectionStrategy(
                    requirement_id="smb_access_control_context",
                    status="supported",
                    script_ids=("smb-enum-shares",),
                    risk_class="intrusive",
                    authorization="requires_approval",
                ),
                authorization=CollectionAuthorizationDecision(allowed, reason),
            )

        pending = plan("192.0.2.101", False, "explicit_approval_required")
        authorized = plan("192.0.2.102", True, "explicitly_approved")
        satisfied = plan("192.0.2.103", True, "explicitly_approved")
        unsatisfied = plan("192.0.2.104", True, "explicitly_approved")
        verifications = (
            FindingRequirementVerification(
                satisfied.requirement, "satisfied", ("smb-enum-shares",)
            ),
            FindingRequirementVerification(
                unsatisfied.requirement, "unsatisfied", ()
            ),
        )

        states = finding_requirement_states(
            (pending, authorized, satisfied, unsatisfied),
            verifications,
        )

        self.assertEqual(
            tuple(state.status for state in states),
            (
                "pending_approval",
                "authorized_pending",
                "satisfied",
                "attempted_unsatisfied",
            ),
        )
        self.assertEqual(
            tuple(state.requirement.host for state in states),
            ("192.0.2.101", "192.0.2.102", "192.0.2.103", "192.0.2.104"),
        )
        self.assertEqual(
            states[2].observed_script_ids,
            ("smb-enum-shares",),
        )

    def test_snapshot_lifecycle_and_suppression_are_endpoint_scoped(self) -> None:
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import re_evaluate_investigation

        resolved_requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.111",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        verification = FindingRequirementVerification(
            resolved_requirement,
            "unsatisfied",
            (),
        )
        scan = Scan(
            source="multi-host.xml",
            hosts=tuple(
                Host(
                    address=host,
                    status="up",
                    ports=(Port(
                        port=445,
                        protocol="tcp",
                        state="open",
                        service="microsoft-ds",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),),
                    ),),
                )
                for host in ("192.0.2.111", "192.0.2.112")
            ),
        )

        snapshot = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            prior_finding_requirement_verifications=(verification,),
        )

        lifecycle = {
            state.requirement.host: state.status
            for state in snapshot.finding_requirement_states
        }
        self.assertEqual(lifecycle["192.0.2.111"], "attempted_unsatisfied")
        self.assertEqual(lifecycle["192.0.2.112"], "authorized_pending")
        dynamic_hosts = {
            action.host
            for action in snapshot.actions
            if action.script_ids == ("smb-enum-shares",)
        }
        self.assertNotIn("192.0.2.111", dynamic_hosts)
        self.assertIn("192.0.2.112", dynamic_hosts)

    @patch("investigation_orchestration.execute_nmap_command")
    def test_unrelated_round_preserves_prior_finding_requirement_lifecycle(
        self,
        execute_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_collector import CollectionResult, NmapCommand
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_selected_evidence_actions,
        )

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.130",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        prior = FindingRequirementVerification(requirement, "unsatisfied", ())
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.130",
                status="up",
                ports=(
                    Port(
                        port=445,
                        protocol="tcp",
                        state="open",
                        service="microsoft-ds",
                        scripts=(ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),),
                    ),
                    Port(port=5357, protocol="tcp", state="open", service="http"),
                ),
            ),),
        )
        http_action = EvidenceAction(
            host="192.0.2.130",
            port=5357,
            protocol="tcp",
            script_ids=("http-headers",),
            purposes=("review HTTP response headers",),
            command=(
                "nmap", "-p", "5357", "--script", "http-headers",
                "-oX", "-", "192.0.2.130",
            ),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(),
            actions=(http_action,),
            states=(),
            error=None,
            finding_requirement_verifications=(prior,),
        )
        execute_mock.return_value = CollectionResult(
            command=NmapCommand(arguments=http_action.command),
            returncode=0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
        )

        result = execute_selected_evidence_actions(
            snapshot,
            (http_action,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

        self.assertEqual(
            result.snapshot.finding_requirement_verifications,
            (prior,),
        )
        self.assertEqual(
            {
                state.requirement.requirement_id: state.status
                for state in result.snapshot.finding_requirement_states
            }["smb_access_control_context"],
            "attempted_unsatisfied",
        )

    @patch("investigation_orchestration.execute_nmap_command")
    def test_unrelated_round_preserves_prior_satisfied_finding_requirement_lifecycle(
        self,
        execute_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_collector import CollectionResult, NmapCommand
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import (
            InvestigationSnapshot,
            execute_selected_evidence_actions,
        )

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.131",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        prior = FindingRequirementVerification(
            requirement,
            "satisfied",
            ("smb-enum-shares",),
        )
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.131",
                status="up",
                ports=(
                    Port(
                        port=445,
                        protocol="tcp",
                        state="open",
                        service="microsoft-ds",
                        scripts=(
                            ScriptResult(
                                "smb2-security-mode",
                                "Message signing enabled but not required",
                            ),
                            ScriptResult("smb-enum-shares", "account_used: guest"),
                        ),
                    ),
                    Port(port=5357, protocol="tcp", state="open", service="http"),
                ),
            ),),
        )
        http_action = EvidenceAction(
            host="192.0.2.131",
            port=5357,
            protocol="tcp",
            script_ids=("http-headers",),
            purposes=("review HTTP response headers",),
            command=(
                "nmap", "-p", "5357", "--script", "http-headers",
                "-oX", "-", "192.0.2.131",
            ),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(),
            actions=(http_action,),
            states=(),
            error=None,
            finding_requirement_verifications=(prior,),
        )
        execute_mock.return_value = CollectionResult(
            command=NmapCommand(arguments=http_action.command),
            returncode=0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
        )

        result = execute_selected_evidence_actions(
            snapshot,
            (http_action,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

        self.assertEqual(
            result.snapshot.finding_requirement_verifications,
            (prior,),
        )
        state = next(
            state
            for state in result.snapshot.finding_requirement_states
            if state.requirement.requirement_id == "smb_access_control_context"
        )
        self.assertEqual(state.status, "satisfied")
        self.assertEqual(state.observed_script_ids, ("smb-enum-shares",))
        self.assertNotIn(
            ("smb-enum-shares",),
            tuple(action.script_ids for action in result.snapshot.actions),
        )

    @patch("investigation_orchestration.execute_nmap_command")
    def test_current_verification_replaces_prior_same_requirement_identity(
        self,
        execute_mock,
    ) -> None:
        from dataclasses import replace
        from evidence_collector import CollectionResult, NmapCommand
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import execute_selected_evidence_actions

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.132",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        prior = FindingRequirementVerification(requirement, "unsatisfied", ())
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.132",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(ScriptResult(
                        "smb2-security-mode",
                        "Message signing enabled but not required",
                    ),),
                ),),
            ),),
        )
        snapshot = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )
        dynamic = next(
            action
            for action in snapshot.actions
            if action.script_ids == ("smb-enum-shares",)
        )
        snapshot = replace(
            snapshot,
            finding_requirement_verifications=(prior,),
        )
        execute_mock.return_value = CollectionResult(
            command=NmapCommand(arguments=dynamic.command),
            returncode=0,
            stdout=(
                '<nmaprun><host><status state="up"/>'
                '<address addr="192.0.2.132" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="445"><state state="open"/>'
                '<script id="smb-enum-shares" output="account_used: guest"/>'
                '</port></ports></host><runstats><finished time="0"/>'
                '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
            ),
            stderr="",
        )

        result = execute_selected_evidence_actions(
            snapshot,
            (dynamic,),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

        matching = tuple(
            verification
            for verification in result.snapshot.finding_requirement_verifications
            if (
                verification.requirement.requirement_id,
                verification.requirement.host,
                verification.requirement.port,
                verification.requirement.protocol,
            ) == ("smb_access_control_context", "192.0.2.132", 445, "tcp")
        )
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].status, "satisfied")
        self.assertEqual(matching[0].observed_script_ids, ("smb-enum-shares",))

    def test_continuation_does_not_complete_with_attempted_unsatisfied_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import (
            assess_investigation_continuation,
            re_evaluate_investigation,
        )

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.133",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        verification = FindingRequirementVerification(requirement, "unsatisfied", ())
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.133",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(ScriptResult(
                        "smb2-security-mode",
                        "Message signing enabled but not required",
                    ),),
                ),),
            ),),
        )
        before = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )
        after = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            prior_finding_requirement_verifications=(verification,),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "finding_requirement_unsatisfied")

    def test_continuation_can_complete_with_satisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementVerification
        from investigation_orchestration import (
            assess_investigation_continuation,
            re_evaluate_investigation,
        )

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.134",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        verification = FindingRequirementVerification(
            requirement,
            "satisfied",
            ("smb-enum-shares",),
        )
        scan = Scan(
            source="discovery.xml",
            hosts=(Host(
                address="192.0.2.134",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(
                        ScriptResult(
                            "smb2-security-mode",
                            "Message signing enabled but not required",
                        ),
                        ScriptResult("smb-protocols", "SMBv2/SMBv3 supported"),
                        ScriptResult("smb-enum-shares", "account_used: guest"),
                    ),
                ),),
            ),),
        )
        before = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            prior_finding_requirement_verifications=(verification,),
        )
        after = re_evaluate_investigation(
            scan,
            (),
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
            prior_finding_requirement_verifications=(verification,),
        )

        decision = assess_investigation_continuation(before, after)

        self.assertEqual(decision.status, "complete")
        self.assertIsNone(decision.stall_reason)
        self.assertEqual(decision.next_actions, ())

    def test_finding_requirement_verification_requires_nonempty_requested_evidence(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.95",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        plan = FindingCollectionPlan(
            requirement=requirement,
            strategy=RequirementCollectionStrategy(
                requirement_id="smb_access_control_context",
                status="supported",
                script_ids=("smb-enum-shares",),
                risk_class="intrusive",
                authorization="requires_approval",
            ),
            authorization=CollectionAuthorizationDecision(True, "explicitly_approved"),
        )

        observed = Scan(
            source="observed.xml",
            hosts=(Host(
                address="192.0.2.95",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(ScriptResult("smb-enum-shares", "account_used: guest"),),
                ),),
            ),),
        )
        empty = Scan(
            source="empty.xml",
            hosts=(Host(
                address="192.0.2.95",
                status="up",
                ports=(Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                    scripts=(ScriptResult("smb-enum-shares", "   "),),
                ),),
            ),),
        )

        satisfied = verify_finding_collection_plan(plan, observed)
        unsatisfied = verify_finding_collection_plan(plan, empty)

        self.assertEqual(satisfied.status, "satisfied")
        self.assertEqual(satisfied.observed_script_ids, ("smb-enum-shares",))
        self.assertEqual(unsatisfied.status, "unsatisfied")
        self.assertEqual(unsatisfied.observed_script_ids, ())



    def test_finalize_complete_continuation(self) -> None:
        decision = InvestigationContinuationDecision("complete", (), (), ())
        final = finalize_continuation_decision(decision)
        self.assertIsNot(final, decision)
        self.assertEqual(final.status, "complete")
        self.assertEqual(final.reason, "all_gaps_resolved")
        self.assertEqual(final.remaining_gaps, ())
        self.assertEqual(final.further_actions, ())
        self.assertEqual(final.remaining_requirements, ())
        self.assertEqual(final.satisfied_requirements, ())
        self.assertEqual(final.remaining_finding_requirements, ())
        self.assertEqual(decision.status, "complete")
        self.assertEqual(decision.next_actions, ())
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.resolved_requirements, ())
        self.assertEqual(decision.remaining_finding_requirements, ())

    def test_finalize_stalled_continuation_preserves_reason(self) -> None:
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), stall_reason="repeated_actions_exhausted"
        )
        final = finalize_continuation_decision(decision)
        self.assertIsNot(final, decision)
        self.assertEqual(final.status, "stalled")
        self.assertEqual(final.reason, "repeated_actions_exhausted")
        self.assertEqual(final.further_actions, ())
        self.assertEqual(final.remaining_gaps, ())
        self.assertEqual(final.remaining_requirements, ())
        self.assertEqual(final.satisfied_requirements, ())
        self.assertEqual(final.remaining_finding_requirements, ())
        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.stall_reason, "repeated_actions_exhausted")
        self.assertEqual(decision.next_actions, ())
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.resolved_requirements, ())

    def test_finalize_stalled_continuation_preserves_remaining_requirements(self) -> None:
        gap = EvidenceGap(
            "192.0.2.241",
            5357,
            "tcp",
            "http-title",
            "review HTTP service identity and exposed content context",
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (gap,), (), stall_reason="repeated_actions_exhausted"
        )

        final = finalize_continuation_decision(decision)

        self.assertEqual(len(final.remaining_requirements), 1)
        self.assertEqual(
            final.remaining_requirements[0].requirement.requirement_id,
            "http_identity_context",
        )
        self.assertEqual(final.remaining_gaps, (gap,))
        self.assertIs(final.remaining_gaps[0], gap)
        self.assertEqual(final.further_actions, ())
        self.assertEqual(final.satisfied_requirements, ())
        self.assertEqual(final.remaining_finding_requirements, ())
        self.assertEqual(final.remaining_requirements[0].host, "192.0.2.241")
        self.assertEqual(final.remaining_requirements[0].port, 5357)
        self.assertEqual(final.remaining_requirements[0].protocol, "tcp")
        self.assertEqual(
            final.remaining_requirements[0].requirement.purpose,
            gap.purpose,
        )
        self.assertEqual(
            final.remaining_requirements[0].requirement.requirement_id,
            "http_identity_context",
        )

    def test_finalize_preserves_pending_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.242",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="pending_approval",
            authorization_reason="explicit_approval_required",
        )
        decision = InvestigationContinuationDecision(
            "stalled",
            (),
            (),
            (),
            stall_reason="explicit_approval_required",
            remaining_finding_requirements=(state,),
        )

        final = finalize_continuation_decision(decision)

        self.assertEqual(final.status, "stalled")
        self.assertEqual(final.reason, "explicit_approval_required")
        self.assertEqual(final.remaining_finding_requirements, (state,))
        self.assertEqual(final.remaining_gaps, ())
        self.assertEqual(final.remaining_requirements, ())
        self.assertEqual(final.further_actions, ())
        self.assertEqual(final.satisfied_requirements, ())
        self.assertEqual(decision.remaining_finding_requirements, (state,))
        self.assertEqual(decision.stall_reason, "explicit_approval_required")
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.resolved_requirements, ())
        self.assertIs(final.remaining_finding_requirements[0], state)
        self.assertEqual(
            final.remaining_finding_requirements[0].authorization_reason,
            "explicit_approval_required",
        )

    def test_finalize_preserves_attempted_unsatisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.253",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="attempted_unsatisfied",
            authorization_reason="explicitly_approved",
        )
        decision = InvestigationContinuationDecision(
            "stalled",
            (),
            (),
            (),
            stall_reason="finding_requirement_unsatisfied",
            remaining_finding_requirements=(state,),
        )

        final = finalize_continuation_decision(decision)

        self.assertEqual(final.status, "stalled")
        self.assertEqual(final.reason, "finding_requirement_unsatisfied")
        self.assertEqual(final.remaining_finding_requirements, (state,))
        self.assertEqual(final.remaining_gaps, ())
        self.assertEqual(final.remaining_requirements, ())
        self.assertEqual(final.further_actions, ())
        self.assertEqual(final.satisfied_requirements, ())
        self.assertIs(final.remaining_finding_requirements[0], state)
        self.assertEqual(
            final.remaining_finding_requirements[0].authorization_reason,
            "explicitly_approved",
        )
        self.assertEqual(
            final.remaining_finding_requirements[0].status,
            "attempted_unsatisfied",
        )
        self.assertEqual(decision.remaining_finding_requirements, (state,))
        self.assertEqual(decision.stall_reason, "finding_requirement_unsatisfied")
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.resolved_requirements, ())
        self.assertIs(decision.remaining_finding_requirements[0], state)

    def test_alternative_incomplete_preserves_pending_finding_requirement(self) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_gaps import EvidenceGap
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationSnapshot,
            assess_final_investigation_decision,
            AlternativeEvidenceVerification,
        )

        gap = EvidenceGap(
            "192.0.2.254", 5357, "tcp", "http-title",
            "review HTTP service identity and exposed content context",
        )
        finding = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.254", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            finding, "pending_approval", "explicit_approval_required", ()
        )
        action = EvidenceAction(
            "192.0.2.254", 5357, "tcp", ("http-headers",),
            ("review HTTP service identity and exposed content context",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.254"),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=None,
            gaps=(gap,),
            actions=(action,),
            states=(),
            error=None,
            finding_requirement_states=(pending,),
        )
        verification = AlternativeEvidenceVerification("incomplete", action, ())
        result = AlternativeEvidenceRoundResult((), (verification,), snapshot)

        decision = assess_final_investigation_decision(result)

        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "alternative_evidence_incomplete")
        self.assertEqual(decision.status, "stalled")
        self.assertEqual(decision.reason, "alternative_evidence_incomplete")
        self.assertEqual(decision.remaining_gaps, (gap,))
        self.assertEqual(decision.further_actions, ())
        self.assertIs(decision.remaining_gaps[0], gap)
        self.assertEqual(len(decision.remaining_requirements), 1)
        self.assertEqual(
            decision.remaining_requirements[0].requirement.requirement_id,
            "http_identity_context",
        )
        self.assertEqual(decision.remaining_requirements[0].host, gap.host)
        self.assertEqual(decision.remaining_requirements[0].port, gap.port)
        self.assertEqual(decision.remaining_requirements[0].protocol, gap.protocol)
        self.assertEqual(
            decision.remaining_requirements[0].requirement.purpose,
            gap.purpose,
        )
        self.assertEqual(
            decision.remaining_requirements[0].requirement.requirement_id,
            "http_identity_context",
        )
        self.assertEqual(decision.satisfied_requirements, ())
        self.assertEqual(decision.remaining_finding_requirements, (pending,))
        self.assertIs(decision.remaining_finding_requirements[0], pending)
        self.assertEqual(
            decision.remaining_finding_requirements[0].authorization_reason,
            "explicit_approval_required",
        )
        self.assertEqual(
            tuple(state.status for state in decision.remaining_finding_requirements),
            ("pending_approval",),
        )

    def test_finalize_continuation_accepts_controller_stop_reason(self) -> None:
        decision = InvestigationContinuationDecision("progressed", (), (), ())
        final = finalize_continuation_decision(
            decision, stop_reason="adaptive_round_limit_reached"
        )
        self.assertIsNot(final, decision)
        self.assertEqual(final.status, "stalled")
        self.assertEqual(final.reason, "adaptive_round_limit_reached")
        self.assertEqual(final.remaining_gaps, ())
        self.assertEqual(final.further_actions, ())
        self.assertEqual(final.remaining_requirements, ())
        self.assertEqual(final.satisfied_requirements, ())
        self.assertEqual(final.remaining_finding_requirements, ())
        self.assertEqual(decision.status, "progressed")
        self.assertEqual(decision.next_actions, ())
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.resolved_requirements, ())
        self.assertEqual(decision.remaining_finding_requirements, ())

    def test_finalize_rejects_progressed_continuation_without_stop_reason(self) -> None:
        decision = InvestigationContinuationDecision("progressed", (), (), ())

        with self.assertRaisesRegex(
            ValueError,
            "Cannot finalize a non-terminal continuation decision",
        ):
            finalize_continuation_decision(decision)

        self.assertEqual(decision.status, "progressed")
        self.assertEqual(decision.next_actions, ())
        self.assertEqual(decision.remaining_gaps, ())
        self.assertEqual(decision.resolved_requirements, ())
        self.assertEqual(decision.remaining_finding_requirements, ())


if __name__ == "__main__":
    unittest.main()
