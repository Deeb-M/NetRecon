"""Portable records for persisted NetRecon investigation history."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
from investigation_synthesis import InvestigationSynthesis
from finding_collection_planner import FindingRequirementState
from finding_requirements import FindingDerivedRequirement


@dataclass(frozen=True)
class InvestigationHistoryRecord:
    """One completed factual investigation state suitable for append-only storage."""

    observed_at: int
    target: str
    synthesis: InvestigationSynthesis
    schema_version: int = 2


def render_investigation_history_record_json(record: InvestigationHistoryRecord) -> str:
    """Serialize one history record without adding interpretation."""
    return json.dumps(asdict(record), ensure_ascii=False, sort_keys=True)


def parse_investigation_history_record_json(payload: str) -> InvestigationHistoryRecord:
    """Restore one history record from its portable JSON representation."""
    data = json.loads(payload)
    schema_version = data.get("schema_version")
    if schema_version not in {1, 2}:
        raise ValueError(
            f"Unsupported investigation history schema version: {schema_version!r}"
        )
    synthesis_data = data["synthesis"]
    requirements = tuple(
        EvidenceRequirementState(
            host=state["host"],
            port=state["port"],
            protocol=state["protocol"],
            requirement=EvidenceRequirement(
                requirement_id=state["requirement"]["requirement_id"],
                purpose=state["requirement"]["purpose"],
                primary_script_ids=tuple(state["requirement"]["primary_script_ids"]),
                alternative_script_ids=tuple(
                    state["requirement"]["alternative_script_ids"]
                ),
            ),
        )
        for state in synthesis_data["remaining_requirements"]
    )
    finding_requirements = tuple(
        FindingRequirementState(
            requirement=FindingDerivedRequirement(
                requirement_id=state["requirement"]["requirement_id"],
                host=state["requirement"]["host"],
                port=state["requirement"]["port"],
                protocol=state["requirement"]["protocol"],
                purpose=state["requirement"]["purpose"],
                finding_id=state["requirement"]["finding_id"],
                evidence_source=state["requirement"]["evidence_source"],
            ),
            status=state["status"],
            authorization_reason=state["authorization_reason"],
            observed_script_ids=tuple(state.get("observed_script_ids", ())),
        )
        for state in synthesis_data.get("remaining_finding_requirements", ())
    )
    synthesis = InvestigationSynthesis(
        status=synthesis_data["status"],
        reason=synthesis_data["reason"],
        attention_items=synthesis_data["attention_items"],
        correlated_review_groups=synthesis_data["correlated_review_groups"],
        remaining_requirements=requirements,
        remaining_finding_requirements=finding_requirements,
    )
    return InvestigationHistoryRecord(
        observed_at=data["observed_at"],
        target=data["target"],
        synthesis=synthesis,
        schema_version=schema_version,
    )


def append_investigation_history_record(
    path: str,
    record: InvestigationHistoryRecord,
) -> None:
    """Append one complete investigation record to a JSONL history file."""
    with open(path, "a", encoding="utf-8") as history_file:
        history_file.write(render_investigation_history_record_json(record))
        history_file.write("\n")


def load_investigation_history(path: str) -> tuple[InvestigationHistoryRecord, ...]:
    """Load complete non-empty JSONL investigation records in stored order."""
    records: list[InvestigationHistoryRecord] = []
    with open(path, "r", encoding="utf-8") as history_file:
        for line in history_file:
            payload = line.strip()
            if payload:
                records.append(parse_investigation_history_record_json(payload))
    return tuple(records)


def latest_investigation_for_target(
    records: tuple[InvestigationHistoryRecord, ...],
    target: str,
) -> InvestigationHistoryRecord | None:
    """Return the latest stored investigation for the exact normalized target."""
    normalized_target = target.strip()
    matches = (
        record
        for record in records
        if record.target.strip() == normalized_target
    )
    return max(matches, key=lambda record: record.observed_at, default=None)
