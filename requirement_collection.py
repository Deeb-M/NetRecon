"""Map semantic investigation requirements to explicitly supported collection strategies."""

from __future__ import annotations

from dataclasses import dataclass

from finding_requirements import FindingDerivedRequirement


@dataclass(frozen=True)
class RequirementCollectionStrategy:
    """Collection capability for one semantic requirement, separate from execution."""

    requirement_id: str
    status: str
    script_ids: tuple[str, ...] = ()
    risk_class: str | None = None
    authorization: str | None = None
    reason: str | None = None


SUPPORTED_REQUIREMENT_STRATEGIES: dict[str, tuple[tuple[str, ...], str, str]] = {
    "smb_access_control_context": (
        ("smb-enum-shares",),
        "intrusive",
        "requires_approval",
    ),
}


def collection_strategy_for_requirement(
    requirement: FindingDerivedRequirement,
) -> RequirementCollectionStrategy:
    """Return an explicit supported/unsupported strategy without inventing collection."""
    strategy = SUPPORTED_REQUIREMENT_STRATEGIES.get(requirement.requirement_id)
    if strategy is None:
        return RequirementCollectionStrategy(
            requirement_id=requirement.requirement_id,
            status="unsupported",
            reason="no_approved_collection_strategy",
        )
    script_ids, risk_class, authorization = strategy
    return RequirementCollectionStrategy(
        requirement_id=requirement.requirement_id,
        status="supported",
        script_ids=script_ids,
        risk_class=risk_class,
        authorization=authorization,
    )
