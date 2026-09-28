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


if __name__ == "__main__":
    unittest.main()
