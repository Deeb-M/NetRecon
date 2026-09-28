"""Factual explanation projected from an existing investigation snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from investigation_orchestration import InvestigationSnapshot


@dataclass(frozen=True)
class InvestigationExplanation:
    """Explain known, unresolved, blocked, and justified next actions without new inference."""

    known: tuple[str, ...]
    unresolved: tuple[str, ...]
    blocked: tuple[str, ...]
    next_actions: tuple[str, ...]


def build_investigation_explanation(
    snapshot: InvestigationSnapshot,
) -> InvestigationExplanation:
    """Project explanation text only from already-established investigation state."""
    known: list[str] = []
    unresolved: list[str] = []
    blocked: list[str] = []

    for gap in snapshot.gaps:
        unresolved.append(
            f"{gap.host}:{gap.port}/{gap.protocol} "
            f"{gap.script_id} — {gap.purpose}"
        )

    for state in snapshot.finding_requirement_states:
        requirement = state.requirement
        known_item = f"{requirement.finding_id} from {requirement.evidence_source}"
        if known_item not in known:
            known.append(known_item)

        if state.status in {"pending_approval", "authorized_pending", "attempted_unsatisfied"}:
            unresolved.append(
                f"{requirement.host}:{requirement.port}/{requirement.protocol} "
                f"{requirement.requirement_id} — {requirement.purpose}"
            )

        if state.status == "attempted_unsatisfied":
            blocked.append(
                f"{requirement.requirement_id} — requested evidence was not observed"
            )
        elif state.status == "pending_approval":
            blocked.append(
                f"{requirement.requirement_id} — explicit approval required"
            )

    return InvestigationExplanation(
        known=tuple(known),
        unresolved=tuple(unresolved),
        blocked=tuple(blocked),
        next_actions=tuple(" ".join(action.command) for action in snapshot.actions),
    )
