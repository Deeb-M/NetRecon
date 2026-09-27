"""Portable records for persisted NetRecon investigation history."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
from investigation_synthesis import InvestigationSynthesis


@dataclass(frozen=True)
class InvestigationHistoryRecord:
    """One completed factual investigation state suitable for append-only storage."""

    observed_at: int
    target: str
    synthesis: InvestigationSynthesis


def render_investigation_history_record_json(record: InvestigationHistoryRecord) -> str:
    """Serialize one history record without adding interpretation."""
    return json.dumps(asdict(record), ensure_ascii=False, sort_keys=True)


def parse_investigation_history_record_json(payload: str) -> InvestigationHistoryRecord:
    """Restore one history record from its portable JSON representation."""
    data = json.loads(payload)
    synthesis_data = data["synthesis"]
    requirements = tuple(
        EvidenceRequirementState(
            host=state["host"],
            port=state["port"],
            protocol=state["protocol"],
            requirement=EvidenceRequirement(**state["requirement"]),
        )
        for state in synthesis_data["remaining_requirements"]
    )
    synthesis = InvestigationSynthesis(
        status=synthesis_data["status"],
        reason=synthesis_data["reason"],
        attention_items=synthesis_data["attention_items"],
        correlated_review_groups=synthesis_data["correlated_review_groups"],
        remaining_requirements=requirements,
    )
    return InvestigationHistoryRecord(
        observed_at=data["observed_at"],
        target=data["target"],
        synthesis=synthesis,
    )
