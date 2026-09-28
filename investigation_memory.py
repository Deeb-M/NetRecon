"""Factual change memory across completed NetRecon investigations."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_gaps import EvidenceRequirementState
from investigation_synthesis import InvestigationSynthesis
from finding_collection_planner import FindingRequirementState


@dataclass(frozen=True)
class InvestigationMemory:
    """Observed changes between two investigation syntheses without interpretation."""

    status_changed: bool
    previous_status: str
    current_status: str
    reason_changed: bool
    previous_reason: str
    current_reason: str
    attention_item_change: int
    correlated_review_group_change: int
    added_requirements: tuple[EvidenceRequirementState, ...]
    resolved_requirements: tuple[EvidenceRequirementState, ...]
    added_finding_requirements: tuple[FindingRequirementState, ...] = ()
    resolved_finding_requirements: tuple[FindingRequirementState, ...] = ()


def _requirement_identity(state: EvidenceRequirementState) -> tuple[str, int, str, str]:
    return (
        state.host.strip(),
        state.port,
        state.protocol.strip().lower(),
        state.requirement.requirement_id,
    )

def _finding_requirement_identity(
    state: FindingRequirementState,
) -> tuple[str, int | None, str | None, str]:
    requirement = state.requirement
    return (
        requirement.host.strip(),
        requirement.port,
        requirement.protocol.strip().lower() if requirement.protocol else None,
        requirement.requirement_id,
    )


def compare_investigation_syntheses(
    previous: InvestigationSynthesis,
    current: InvestigationSynthesis,
) -> InvestigationMemory:
    """Compare two factual synthesis snapshots without judging the changes."""
    previous_requirements = {
        _requirement_identity(state): state for state in previous.remaining_requirements
    }
    current_requirements = {
        _requirement_identity(state): state for state in current.remaining_requirements
    }
    added_keys = sorted(current_requirements.keys() - previous_requirements.keys())
    resolved_keys = sorted(previous_requirements.keys() - current_requirements.keys())
    previous_finding_requirements = {
        _finding_requirement_identity(state): state
        for state in previous.remaining_finding_requirements
    }
    current_finding_requirements = {
        _finding_requirement_identity(state): state
        for state in current.remaining_finding_requirements
    }
    added_finding_keys = sorted(
        current_finding_requirements.keys() - previous_finding_requirements.keys()
    )
    resolved_finding_keys = sorted(
        previous_finding_requirements.keys() - current_finding_requirements.keys()
    )

    return InvestigationMemory(
        status_changed=previous.status != current.status,
        previous_status=previous.status,
        current_status=current.status,
        reason_changed=previous.reason != current.reason,
        previous_reason=previous.reason,
        current_reason=current.reason,
        attention_item_change=current.attention_items - previous.attention_items,
        correlated_review_group_change=(
            current.correlated_review_groups - previous.correlated_review_groups
        ),
        added_requirements=tuple(current_requirements[key] for key in added_keys),
        resolved_requirements=tuple(previous_requirements[key] for key in resolved_keys),
        added_finding_requirements=tuple(
            current_finding_requirements[key] for key in added_finding_keys
        ),
        resolved_finding_requirements=tuple(
            previous_finding_requirements[key] for key in resolved_finding_keys
        ),
    )
