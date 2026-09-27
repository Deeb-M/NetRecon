"""Choose the next bounded investigation step from existing factual decisions."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_action_plan import EvidenceAction
from investigation_orchestration import InvestigationContinuationDecision


@dataclass(frozen=True)
class AdaptiveInvestigationPlan:
    """One factual recommendation for the next bounded investigation step."""

    decision: str
    reason: str
    actions: tuple[EvidenceAction, ...] = ()


def build_adaptive_investigation_plan(
    continuation: InvestigationContinuationDecision,
) -> AdaptiveInvestigationPlan:
    """Project existing continuation truth into continue, alternative, or stop."""
    if continuation.status == "complete":
        return AdaptiveInvestigationPlan("stop", "investigation_complete")

    if continuation.next_actions:
        return AdaptiveInvestigationPlan(
            "continue",
            "new_supported_actions_available",
            continuation.next_actions,
        )

    if continuation.alternative_actions:
        return AdaptiveInvestigationPlan(
            "alternative",
            "supported_alternative_actions_available",
            continuation.alternative_actions,
        )

    reason = continuation.stall_reason or "no_supported_next_step"
    return AdaptiveInvestigationPlan("stop", reason)


def select_adaptive_actions(plan: AdaptiveInvestigationPlan) -> tuple[EvidenceAction, ...]:
    """Return only actions explicitly authorized by a non-terminal adaptive plan."""
    if plan.decision in {"continue", "alternative"}:
        return plan.actions
    return ()
