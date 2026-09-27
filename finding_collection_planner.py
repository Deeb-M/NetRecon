"""Build non-executing collection plans from evidence-backed findings."""

from __future__ import annotations

from dataclasses import dataclass

from finding_requirements import FindingDerivedRequirement, derive_finding_requirements
from findings import Finding
from requirement_collection import (
    CollectionAuthorizationDecision,
    RequirementCollectionStrategy,
    authorize_collection_strategy,
    collection_strategy_for_requirement,
)


@dataclass(frozen=True)
class FindingCollectionPlan:
    requirement: FindingDerivedRequirement
    strategy: RequirementCollectionStrategy
    authorization: CollectionAuthorizationDecision


def build_finding_collection_plans(
    findings: tuple[Finding, ...],
    *,
    explicitly_approved_requirement_ids: frozenset[str] = frozenset(),
) -> tuple[FindingCollectionPlan, ...]:
    """Translate findings into bounded, non-executing collection decisions."""
    plans: list[FindingCollectionPlan] = []
    for requirement in derive_finding_requirements(findings):
        strategy = collection_strategy_for_requirement(requirement)
        authorization = authorize_collection_strategy(
            strategy,
            explicitly_approved=(
                requirement.requirement_id in explicitly_approved_requirement_ids
            ),
        )
        plans.append(
            FindingCollectionPlan(
                requirement=requirement,
                strategy=strategy,
                authorization=authorization,
            )
        )
    return tuple(plans)
