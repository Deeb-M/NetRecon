"""Contract tests for factual investigation explanation."""

import unittest

from finding_collection_planner import FindingRequirementState
from finding_requirements import FindingDerivedRequirement
from investigation_explanation import build_investigation_explanation
from investigation_orchestration import InvestigationSnapshot
from models import Scan


class InvestigationExplanationTests(unittest.TestCase):
    def test_attempted_unsatisfied_is_explained_without_inventing_next_action(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.138",
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

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(explanation.known, ("smb.signing.review from nse:smb2-security-mode",))
        self.assertEqual(
            explanation.unresolved,
            ("192.0.2.138:445/tcp smb_access_control_context — review SMB access controls",),
        )
        self.assertEqual(
            explanation.blocked,
            ("smb_access_control_context — requested evidence was not observed",),
        )
        self.assertEqual(explanation.next_actions, ())


    def test_pending_approval_is_explained_without_presenting_blocked_action_as_next(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.139",
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

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(explanation.known, ("smb.signing.review from nse:smb2-security-mode",))
        self.assertEqual(
            explanation.unresolved,
            ("192.0.2.139:445/tcp smb_access_control_context — review SMB access controls",),
        )
        self.assertEqual(
            explanation.blocked,
            ("smb_access_control_context — explicit approval required",),
        )
        self.assertEqual(explanation.next_actions, ())


    def test_authorized_pending_exposes_only_existing_snapshot_action_as_next(self) -> None:
        from evidence_action_plan import EvidenceAction

        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.140",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="authorized_pending",
            authorization_reason="explicitly_approved",
        )
        action = EvidenceAction(
            host="192.0.2.140",
            port=445,
            protocol="tcp",
            script_ids=("smb-enum-shares",),
            purposes=("review SMB access controls",),
            command=("nmap", "-p", "445", "--script", "smb-enum-shares", "-oX", "-", "192.0.2.140"),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(action,),
            states=(),
            error=None,
            finding_requirement_states=(state,),
        )

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(
            explanation.unresolved,
            ("192.0.2.140:445/tcp smb_access_control_context — review SMB access controls",),
        )
        self.assertEqual(explanation.blocked, ())
        self.assertEqual(
            explanation.next_actions,
            ("nmap -p 445 --script smb-enum-shares -oX - 192.0.2.140",),
        )


    def test_satisfied_requirement_is_known_but_not_unresolved_or_actionable(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.141",
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

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(explanation.known, ("smb.signing.review from nse:smb2-security-mode",))
        self.assertEqual(explanation.unresolved, ())
        self.assertEqual(explanation.blocked, ())
        self.assertEqual(explanation.next_actions, ())


    def test_primary_evidence_gap_is_unresolved_with_existing_planned_action(self) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_gaps import EvidenceGap

        gap = EvidenceGap(
            host="192.0.2.142",
            port=5357,
            protocol="tcp",
            script_id="http-title",
            purpose="identify the HTTP service",
        )
        action = EvidenceAction(
            host="192.0.2.142",
            port=5357,
            protocol="tcp",
            script_ids=("http-title",),
            purposes=("identify the HTTP service",),
            command=("nmap", "-p", "5357", "--script", "http-title", "-oX", "-", "192.0.2.142"),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(gap,),
            actions=(action,),
            states=(),
            error=None,
        )

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(explanation.known, ())
        self.assertEqual(
            explanation.unresolved,
            ("192.0.2.142:5357/tcp http-title — identify the HTTP service",),
        )
        self.assertEqual(explanation.blocked, ())
        self.assertEqual(
            explanation.next_actions,
            ("nmap -p 5357 --script http-title -oX - 192.0.2.142",),
        )


    def test_endpoint_observed_facts_are_explained_as_known(self) -> None:
        from investigation_state import EndpointInvestigationState

        endpoint = EndpointInvestigationState(
            host="192.0.2.143",
            port=80,
            protocol="tcp",
            known=("state=open", "service=http", "product=Example HTTP Server"),
            unknown=(),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(),
            actions=(),
            states=(endpoint,),
            error=None,
        )

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(
            explanation.known,
            (
                "192.0.2.143:80/tcp state=open",
                "192.0.2.143:80/tcp service=http",
                "192.0.2.143:80/tcp product=Example HTTP Server",
            ),
        )
        self.assertEqual(explanation.unresolved, ())
        self.assertEqual(explanation.blocked, ())
        self.assertEqual(explanation.next_actions, ())


    def test_not_ready_snapshot_explains_discovery_error_as_blocked(self) -> None:
        snapshot = InvestigationSnapshot(
            ready=False,
            scan=None,
            gaps=(),
            actions=(),
            states=(),
            error="Nmap discovery failed",
        )

        explanation = build_investigation_explanation(snapshot)

        self.assertEqual(explanation.known, ())
        self.assertEqual(explanation.unresolved, ())
        self.assertEqual(explanation.blocked, ("discovery — Nmap discovery failed",))
        self.assertEqual(explanation.next_actions, ())


    def test_final_stalled_decision_suppresses_stale_snapshot_next_action(self) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_gaps import EvidenceGap
        from investigation_orchestration import FinalInvestigationDecision

        gap = EvidenceGap(
            host="192.0.2.144",
            port=5357,
            protocol="tcp",
            script_id="http-title",
            purpose="identify the HTTP service",
        )
        action = EvidenceAction(
            host="192.0.2.144",
            port=5357,
            protocol="tcp",
            script_ids=("http-title",),
            purposes=("identify the HTTP service",),
            command=("nmap", "-p", "5357", "--script", "http-title", "-oX", "-", "192.0.2.144"),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml", hosts=()),
            gaps=(gap,),
            actions=(action,),
            states=(),
            error=None,
        )
        final_decision = FinalInvestigationDecision(
            status="stalled",
            reason="alternative_evidence_incomplete",
            remaining_gaps=(gap,),
            further_actions=(),
        )

        explanation = build_investigation_explanation(
            snapshot,
            final_decision=final_decision,
        )

        self.assertEqual(
            explanation.unresolved,
            ("192.0.2.144:5357/tcp http-title — identify the HTTP service",),
        )
        self.assertEqual(explanation.next_actions, ())


if __name__ == "__main__":
    unittest.main()
