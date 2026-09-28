"""Evidence-backed synthesis of the final NetRecon investigation state."""

from __future__ import annotations

from dataclasses import dataclass

from analyst_attention import AnalystAttentionCorrelation, AnalystAttentionItem
from evidence_gaps import EvidenceRequirementState
from finding_collection_planner import FindingRequirementState
from investigation_orchestration import FinalInvestigationDecision


@dataclass(frozen=True)
class InvestigationSynthesis:
    """Compact factual summary derived only from existing investigation outputs."""

    status: str
    reason: str
    attention_items: int
    correlated_review_groups: int
    remaining_requirements: tuple[EvidenceRequirementState, ...]
    remaining_finding_requirements: tuple[FindingRequirementState, ...] = ()


def build_investigation_synthesis(
    final_decision: FinalInvestigationDecision,
    attention: tuple[AnalystAttentionItem, ...],
    correlations: tuple[AnalystAttentionCorrelation, ...],
) -> InvestigationSynthesis:
    """Summarize final investigation state without adding new conclusions."""
    return InvestigationSynthesis(
        status=final_decision.status,
        reason=final_decision.reason,
        attention_items=len(attention),
        correlated_review_groups=len(correlations),
        remaining_requirements=final_decision.remaining_requirements,
        remaining_finding_requirements=final_decision.remaining_finding_requirements,
    )
