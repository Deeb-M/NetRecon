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
    reason: str | None = None


SUPPORTED_REQUIREMENT_STRATEGIES: dict[str, tuple[str, ...]] = {}


def collection_strategy_for_requirement(
    requirement: FindingDerivedRequirement,
) -> RequirementCollectionStrategy:
    """Return an explicit supported/unsupported strategy without inventing collection."""
    script_ids = SUPPORTED_REQUIREMENT_STRATEGIES.get(requirement.requirement_id)
    if script_ids is None:
        return RequirementCollectionStrategy(
            requirement_id=requirement.requirement_id,
            status="unsupported",
            reason="no_approved_collection_strategy",
        )
    return RequirementCollectionStrategy(
        requirement_id=requirement.requirement_id,
        status="supported",
        script_ids=script_ids,
    )
