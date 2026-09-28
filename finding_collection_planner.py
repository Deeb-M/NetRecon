"""Build non-executing collection plans from evidence-backed findings."""

from __future__ import annotations

from dataclasses import dataclass

from finding_requirements import FindingDerivedRequirement, derive_finding_requirements
from findings import Finding
from evidence_action_plan import EvidenceAction
from evidence_collector import CollectionSpec, build_nmap_command
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



def evidence_action_for_finding_collection_plan(
    plan: FindingCollectionPlan,
) -> EvidenceAction | None:
    """Convert only an authorized finding-derived plan into a standard EvidenceAction."""
    if not plan.authorization.allowed:
        return None
    requirement = plan.requirement
    if requirement.port is None or requirement.protocol is None:
        return None
    if not plan.strategy.script_ids:
        return None

    spec = CollectionSpec(
        target=requirement.host,
        port=requirement.port,
        protocol=requirement.protocol,
        script_ids=plan.strategy.script_ids,
    )
    command = build_nmap_command(spec)
    return EvidenceAction(
        host=requirement.host,
        port=requirement.port,
        protocol=requirement.protocol,
        script_ids=plan.strategy.script_ids,
        purposes=(requirement.purpose,),
        command=command.arguments,
    )



def build_authorized_finding_evidence_actions(
    findings: tuple[Finding, ...],
    *,
    explicitly_approved_requirement_ids: frozenset[str] = frozenset(),
) -> tuple[EvidenceAction, ...]:
    """Return only authorized standard actions derived from evidence-backed findings."""
    plans = build_finding_collection_plans(
        findings,
        explicitly_approved_requirement_ids=explicitly_approved_requirement_ids,
    )
    return tuple(
        action
        for plan in plans
        if (action := evidence_action_for_finding_collection_plan(plan)) is not None
    )


@dataclass(frozen=True)
class FindingRequirementVerification:
    """Observed evidence that satisfies one finding-derived collection requirement."""

    requirement: FindingDerivedRequirement
    status: str
    observed_script_ids: tuple[str, ...]


def verify_finding_collection_plan(
    plan: FindingCollectionPlan,
    scan,
) -> FindingRequirementVerification:
    """Verify requested non-empty NSE evidence on the requirement's exact endpoint."""
    requirement = plan.requirement
    requested = {script_id.strip().lower() for script_id in plan.strategy.script_ids}
    observed: list[str] = []

    if requirement.port is not None and requirement.protocol is not None:
        for host in scan.hosts:
            if host.address.strip() != requirement.host.strip():
                continue
            for port in host.ports:
                if (
                    port.port != requirement.port
                    or port.protocol.strip().lower() != requirement.protocol.strip().lower()
                ):
                    continue
                for script in port.scripts:
                    script_id = script.script_id.strip().lower()
                    if (
                        script_id in requested
                        and script.output.strip()
                        and script_id not in observed
                    ):
                        observed.append(script_id)

    status = "satisfied" if requested and requested.issubset(observed) else "unsatisfied"
    return FindingRequirementVerification(
        requirement=requirement,
        status=status,
        observed_script_ids=tuple(observed),
    )


def unsatisfied_finding_requirements(
    verifications: tuple[FindingRequirementVerification, ...],
) -> tuple[FindingRequirementVerification, ...]:
    """Return attempted finding-derived requirements whose requested evidence was not observed."""
    return tuple(
        verification
        for verification in verifications
        if verification.status == "unsatisfied"
    )
