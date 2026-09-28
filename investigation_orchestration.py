"""Compose verified discovery with existing evidence intelligence layers."""

from __future__ import annotations

from dataclasses import dataclass, replace

from analyst_attention import AnalystAttentionItem, build_analyst_attention
from analyzer import analyze_scan

from evidence_action_plan import EvidenceAction, build_evidence_action_plan
from evidence_gaps import EvidenceGap, EvidenceRequirementState, requirement_state_for_gap, requirement_states_for_gaps, resolved_requirement_states, summarize_evidence_gaps
from evidence_collector import (
    NmapCommand,
    ParsedCollectionResult,
    execute_nmap_command,
    merge_collection_outcomes_into_host,
    parse_collection_outcome,
)
from investigation_state import EndpointInvestigationState, summarize_investigation_state
from finding_collection_planner import build_authorized_finding_evidence_actions, build_finding_collection_plans, evidence_action_for_finding_collection_plan, finding_requirement_states, FindingCollectionPlan, FindingRequirementState, FindingRequirementVerification, verify_finding_collection_plan
from models import Scan
from scan_orchestration import DiscoveryResult


@dataclass(frozen=True)
class InvestigationSnapshot:
    """Current evidence-aware investigation state after discovery."""

    ready: bool
    scan: Scan | None
    gaps: tuple[EvidenceGap, ...]
    actions: tuple[EvidenceAction, ...]
    states: tuple[EndpointInvestigationState, ...]
    error: str | None
    finding_collection_plans: tuple[FindingCollectionPlan, ...] = ()
    finding_requirement_verifications: tuple[FindingRequirementVerification, ...] = ()
    finding_requirement_states: tuple[FindingRequirementState, ...] = ()


def build_investigation_snapshot(
    discovery: DiscoveryResult,
) -> InvestigationSnapshot:
    """Compose a verified discovery result with existing evidence planning layers."""
    if not discovery.success:
        return InvestigationSnapshot(
            ready=False,
            scan=None,
            gaps=(),
            actions=(),
            states=(),
            error=discovery.error,
        )

    if discovery.scan is None:
        raise ValueError("Successful discovery must include a verified scan")

    return InvestigationSnapshot(
        ready=True,
        scan=discovery.scan,
        gaps=summarize_evidence_gaps(discovery.scan),
        actions=build_evidence_action_plan(discovery.scan),
        states=summarize_investigation_state(discovery.scan),
        error=None,
    )


def re_evaluate_investigation(
    discovery_scan: Scan,
    outcomes: tuple[ParsedCollectionResult, ...],
    *,
    explicitly_approved_requirement_ids: frozenset[str] = frozenset(),
    prior_finding_requirement_verifications: tuple[FindingRequirementVerification, ...] = (),
) -> InvestigationSnapshot:
    """Merge collected evidence and rebuild primary plus authorized dynamic actions."""
    merged_hosts = tuple(
        merge_collection_outcomes_into_host(host, outcomes)
        for host in discovery_scan.hosts
    )
    scan = replace(discovery_scan, hosts=merged_hosts)

    primary_actions = build_evidence_action_plan(scan)
    finding_plans = build_finding_collection_plans(
        analyze_scan(scan),
        explicitly_approved_requirement_ids=explicitly_approved_requirement_ids,
    )
    resolved_finding_requirement_keys = {
        (
            verification.requirement.requirement_id,
            verification.requirement.host,
            verification.requirement.port,
            verification.requirement.protocol,
        )
        for verification in prior_finding_requirement_verifications
        if verification.status in {"satisfied", "unsatisfied"}
    }
    dynamic_actions = tuple(
        action
        for plan in finding_plans
        if (
            plan.requirement.requirement_id,
            plan.requirement.host,
            plan.requirement.port,
            plan.requirement.protocol,
        ) not in resolved_finding_requirement_keys
        and (action := evidence_action_for_finding_collection_plan(plan)) is not None
    )
    actions_by_command = {action.command: action for action in primary_actions}
    for action in dynamic_actions:
        actions_by_command.setdefault(action.command, action)

    return InvestigationSnapshot(
        ready=True,
        scan=scan,
        gaps=summarize_evidence_gaps(scan),
        actions=tuple(actions_by_command.values()),
        states=summarize_investigation_state(scan),
        error=None,
        finding_collection_plans=finding_plans,
        finding_requirement_verifications=prior_finding_requirement_verifications,
        finding_requirement_states=finding_requirement_states(
            finding_plans,
            prior_finding_requirement_verifications,
        ),
    )




def build_dynamic_evidence_actions(
    scan: Scan,
    *,
    explicitly_approved_requirement_ids: frozenset[str] = frozenset(),
) -> tuple[EvidenceAction, ...]:
    """Derive authorized follow-up actions from findings in the current evidence state."""
    return build_authorized_finding_evidence_actions(
        analyze_scan(scan),
        explicitly_approved_requirement_ids=explicitly_approved_requirement_ids,
    )

def build_investigation_attention(
    snapshot: InvestigationSnapshot,
) -> tuple[AnalystAttentionItem, ...]:
    """Project analyst attention from the investigation's current merged evidence."""
    if not snapshot.ready or snapshot.scan is None:
        return ()
    return build_analyst_attention(analyze_scan(snapshot.scan))


@dataclass(frozen=True)
class InvestigationContinuationResult:
    """Evidence collection outcomes paired with the re-evaluated investigation."""

    outcomes: tuple[ParsedCollectionResult, ...]
    snapshot: InvestigationSnapshot
    finding_requirement_verifications: tuple[FindingRequirementVerification, ...] = ()


def execute_selected_evidence_actions(
    snapshot: InvestigationSnapshot,
    actions: tuple[EvidenceAction, ...],
    *,
    timeout: float | None = None,
    explicitly_approved_requirement_ids: frozenset[str] = frozenset(),
) -> InvestigationContinuationResult:
    """Execute exactly the supplied bounded actions and re-evaluate once."""
    if not snapshot.ready or snapshot.scan is None:
        raise ValueError("Selected evidence execution requires a ready investigation")

    outcomes = tuple(
        parse_collection_outcome(
            execute_nmap_command(
                NmapCommand(arguments=action.command),
                timeout=timeout,
            )
        )
        for action in actions
    )

    updated_snapshot = re_evaluate_investigation(
        snapshot.scan,
        outcomes,
        explicitly_approved_requirement_ids=explicitly_approved_requirement_ids,
        prior_finding_requirement_verifications=snapshot.finding_requirement_verifications,
    )
    selected_commands = {action.command for action in actions}
    finding_plans = build_finding_collection_plans(
        analyze_scan(snapshot.scan),
        explicitly_approved_requirement_ids=explicitly_approved_requirement_ids,
    )
    finding_verifications = tuple(
        verify_finding_collection_plan(plan, updated_snapshot.scan)
        for plan in finding_plans
        if (
            plan.authorization.allowed
            and (action := evidence_action_for_finding_collection_plan(plan)) is not None
            and action.command in selected_commands
        )
    )
    verification_by_key = {
        (
            verification.requirement.requirement_id,
            verification.requirement.host,
            verification.requirement.port,
            verification.requirement.protocol,
        ): verification
        for verification in snapshot.finding_requirement_verifications
    }
    for verification in finding_verifications:
        verification_by_key[
            (
                verification.requirement.requirement_id,
                verification.requirement.host,
                verification.requirement.port,
                verification.requirement.protocol,
            )
        ] = verification
    merged_finding_verifications = tuple(verification_by_key.values())
    updated_snapshot = replace(
        updated_snapshot,
        finding_requirement_verifications=merged_finding_verifications,
        finding_requirement_states=finding_requirement_states(
            updated_snapshot.finding_collection_plans,
            merged_finding_verifications,
        ),
    )
    return InvestigationContinuationResult(
        outcomes=outcomes,
        snapshot=updated_snapshot,
        finding_requirement_verifications=finding_verifications,
    )


def execute_approved_evidence_actions(
    snapshot: InvestigationSnapshot,
    *,
    timeout: float | None = None,
    explicitly_approved_requirement_ids: frozenset[str] = frozenset(),
) -> InvestigationContinuationResult:
    """Execute exactly the planner-approved actions and re-evaluate once."""
    if not snapshot.ready or snapshot.scan is None:
        raise ValueError("Approved evidence execution requires a ready investigation")
    return execute_selected_evidence_actions(
        snapshot,
        snapshot.actions,
        timeout=timeout,
        explicitly_approved_requirement_ids=explicitly_approved_requirement_ids,
    )




@dataclass(frozen=True)
class AlternativeEvidenceVerification:
    """Verified evidence outcome for one explicitly selected alternative action."""

    status: str
    action: EvidenceAction
    observed_script_ids: tuple[str, ...]


def verify_alternative_evidence(
    action: EvidenceAction,
    outcome: ParsedCollectionResult,
) -> AlternativeEvidenceVerification:
    """Verify non-empty requested NSE output on the action's exact endpoint."""
    if outcome.scan is None:
        return AlternativeEvidenceVerification("collection_failed", action, ())

    requested = {script_id.strip().lower() for script_id in action.script_ids}
    observed: list[str] = []
    for host in outcome.scan.hosts:
        if host.address.strip() != action.host.strip():
            continue
        for port in host.ports:
            if port.port != action.port or port.protocol.strip().lower() != action.protocol.strip().lower():
                continue
            for script in port.scripts:
                script_id = script.script_id.strip().lower()
                if script_id in requested and script.output.strip() and script_id not in observed:
                    observed.append(script_id)

    status = "observed" if requested and requested.issubset(observed) else "incomplete"
    return AlternativeEvidenceVerification(status, action, tuple(observed))



@dataclass(frozen=True)
class AlternativeEvidenceRoundResult:
    """One bounded alternative collection round with explicit verification."""

    outcomes: tuple[ParsedCollectionResult, ...]
    verifications: tuple[AlternativeEvidenceVerification, ...]
    snapshot: InvestigationSnapshot


def execute_alternative_evidence_round(
    snapshot: InvestigationSnapshot,
    actions: tuple[EvidenceAction, ...],
    *,
    timeout: float | None = None,
) -> AlternativeEvidenceRoundResult:
    """Execute selected alternatives once, verify them, and re-evaluate once."""
    continuation = execute_selected_evidence_actions(
        snapshot,
        actions,
        timeout=timeout,
    )
    verifications = tuple(
        verify_alternative_evidence(action, outcome)
        for action, outcome in zip(actions, continuation.outcomes, strict=True)
    )
    return AlternativeEvidenceRoundResult(
        outcomes=continuation.outcomes,
        verifications=verifications,
        snapshot=continuation.snapshot,
    )

@dataclass(frozen=True)
class FinalInvestigationDecision:
    """Terminal decision after a bounded alternative evidence round."""

    status: str
    reason: str
    remaining_gaps: tuple[EvidenceGap, ...]
    further_actions: tuple[EvidenceAction, ...] = ()
    remaining_requirements: tuple[EvidenceRequirementState, ...] = ()
    satisfied_requirements: tuple[EvidenceRequirementState, ...] = ()


def assess_final_investigation_decision(
    alternative_round: AlternativeEvidenceRoundResult,
) -> FinalInvestigationDecision:
    """Stop after the bounded alternative round and explain why."""
    remaining = alternative_round.snapshot.gaps
    requirements: list[EvidenceRequirementState] = []
    satisfied_requirements: list[EvidenceRequirementState] = []
    seen_requirements: set[tuple[str, str, int, str]] = set()
    observed_alternatives = {
        (
            verification.action.host.strip(),
            verification.action.port,
            verification.action.protocol.strip().lower(),
            script_id.strip().lower(),
        )
        for verification in alternative_round.verifications
        if verification.status == "observed"
        for script_id in verification.observed_script_ids
    }
    for gap in remaining:
        state = requirement_state_for_gap(gap)
        if state is None:
            continue
        requirement = state.requirement
        endpoint_key = (
            state.host,
            state.port,
            state.protocol,
            requirement.requirement_id,
        )
        if endpoint_key in seen_requirements:
            continue
        seen_requirements.add(endpoint_key)
        alternative_ids = {
            script_id.strip().lower()
            for script_id in requirement.alternative_script_ids
        }
        endpoint_observed_ids = {
            script_id
            for host, port, protocol, script_id in observed_alternatives
            if host == gap.host.strip()
            and port == gap.port
            and protocol == gap.protocol.strip().lower()
        }
        if alternative_ids and alternative_ids.issubset(endpoint_observed_ids):
            satisfied_requirements.append(state)
            continue
        requirements.append(state)
    remaining_requirements = tuple(requirements)
    satisfied_requirements_tuple = tuple(satisfied_requirements)
    statuses = {verification.status for verification in alternative_round.verifications}

    if not remaining:
        return FinalInvestigationDecision("complete", "all_gaps_resolved", (), (), (), ())

    if not remaining_requirements:
        return FinalInvestigationDecision(
            status="complete",
            reason="all_semantic_requirements_satisfied",
            remaining_gaps=remaining,
            further_actions=(),
            remaining_requirements=(),
            satisfied_requirements=satisfied_requirements_tuple,
        )

    if "collection_failed" in statuses:
        reason = "alternative_collection_failed"
    elif "incomplete" in statuses:
        reason = "alternative_evidence_incomplete"
    elif statuses and statuses == {"observed"}:
        reason = (
            "alternative_evidence_partially_satisfied_requirements"
            if remaining_requirements
            else "alternative_evidence_observed_gaps_remain"
        )
    else:
        reason = "no_verified_alternative_evidence"

    return FinalInvestigationDecision(
        "stalled",
        reason,
        remaining,
        (),
        remaining_requirements,
        satisfied_requirements_tuple,
    )


@dataclass(frozen=True)
class InvestigationContinuationDecision:
    """Describe whether a re-evaluated investigation can safely continue."""

    status: str
    resolved_gaps: tuple[EvidenceGap, ...]
    remaining_gaps: tuple[EvidenceGap, ...]
    next_actions: tuple[EvidenceAction, ...]
    repeat_blocked_actions: tuple[EvidenceAction, ...] = ()
    stall_reason: str | None = None
    alternative_actions: tuple[EvidenceAction, ...] = ()
    resolved_requirements: tuple[EvidenceRequirementState, ...] = ()


def _gap_identity(gap: EvidenceGap) -> tuple[str, int, str, str]:
    """Return the endpoint-scoped identity of one planner-supported evidence gap."""
    return (
        gap.host.strip(),
        gap.port,
        gap.protocol.strip().lower(),
        gap.script_id.strip().lower(),
    )


def _build_alternative_actions(
    decision_gaps: tuple[EvidenceGap, ...],
    repeat_blocked: tuple[EvidenceAction, ...],
) -> tuple[EvidenceAction, ...]:
    """Offer bounded evidence alternatives only after the primary action is exhausted."""
    blocked_endpoints = {
        (action.host.strip(), action.port, action.protocol.strip().lower())
        for action in repeat_blocked
    }
    alternatives: dict[tuple[str, int, str, tuple[str, ...]], EvidenceAction] = {}

    for gap in decision_gaps:
        endpoint = (gap.host.strip(), gap.port, gap.protocol.strip().lower())
        if endpoint not in blocked_endpoints:
            continue
        state = requirement_state_for_gap(gap)
        if state is None or not state.requirement.alternative_script_ids:
            continue
        requirement = state.requirement
        script_ids = tuple(script_id.strip().lower() for script_id in requirement.alternative_script_ids)
        key = (state.host, state.port, state.protocol, script_ids)
        alternatives[key] = EvidenceAction(
            host=endpoint[0], port=endpoint[1], protocol=endpoint[2],
            script_ids=script_ids, purposes=(requirement.purpose,),
            command=("nmap", *(("-sU",) if endpoint[2] == "udp" else ()), "-p", str(endpoint[1]),
                     "--script", ",".join(script_ids), "-oX", "-", endpoint[0]),
        )

    return tuple(alternatives[key] for key in sorted(alternatives))


def assess_investigation_continuation(
    before: InvestigationSnapshot,
    after: InvestigationSnapshot,
    attempted_actions: tuple[EvidenceAction, ...] = (),
) -> InvestigationContinuationDecision:
    """Classify re-evaluation without executing another collection round.

    A continuation is complete when no planner-supported gaps and no new safe
    actions remain. It is progressed when resolved primary evidence exposes a
    further supported action, including an authorized finding-derived action
    that remains after all primary gaps are resolved. Repeated
    actions are blocked from next_actions so callers do not blindly retry
    collection that already failed to resolve the requested evidence.
    """
    if not before.ready or not after.ready:
        raise ValueError("Continuation assessment requires ready investigations")

    after_ids = {_gap_identity(gap) for gap in after.gaps}
    resolved = tuple(
        gap for gap in before.gaps if _gap_identity(gap) not in after_ids
    )

    attempted_commands = {action.command for action in attempted_actions}
    repeat_blocked = tuple(
        action for action in after.actions if action.command in attempted_commands
    )
    safe_next_actions = tuple(
        action for action in after.actions if action.command not in attempted_commands
    )

    approval_blocked_plans = tuple(
        plan
        for plan in after.finding_collection_plans
        if (
            not plan.authorization.allowed
            and plan.authorization.reason == "explicit_approval_required"
        )
    )

    stall_reason = None
    if safe_next_actions and (resolved or not after.gaps):
        status = "progressed"
    elif not after.gaps and approval_blocked_plans:
        status = "stalled"
        stall_reason = "explicit_approval_required"
    elif not after.gaps:
        status = "complete"
    else:
        status = "stalled"
        if repeat_blocked and not safe_next_actions:
            stall_reason = "repeated_actions_exhausted"
        elif not after.actions:
            stall_reason = "no_supported_actions"
        else:
            stall_reason = "no_progress"

    alternative_actions = ()
    if stall_reason == "repeated_actions_exhausted":
        alternative_actions = _build_alternative_actions(after.gaps, repeat_blocked)

    return InvestigationContinuationDecision(
        status=status,
        resolved_gaps=resolved,
        remaining_gaps=after.gaps,
        next_actions=safe_next_actions,
        repeat_blocked_actions=repeat_blocked,
        stall_reason=stall_reason,
        alternative_actions=alternative_actions,
        resolved_requirements=resolved_requirement_states(before.gaps, after.gaps),
    )
