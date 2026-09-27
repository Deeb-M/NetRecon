"""Compose verified discovery with existing evidence intelligence layers."""

from __future__ import annotations

from dataclasses import dataclass, replace

from evidence_action_plan import EvidenceAction, build_evidence_action_plan
from evidence_gaps import EvidenceGap, summarize_evidence_gaps
from evidence_collector import (
    NmapCommand,
    ParsedCollectionResult,
    execute_nmap_command,
    merge_collection_outcomes_into_host,
    parse_collection_outcome,
)
from investigation_state import EndpointInvestigationState, summarize_investigation_state
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
) -> InvestigationSnapshot:
    """Merge collected evidence into discovery and rebuild investigation intelligence."""
    merged_hosts = tuple(
        merge_collection_outcomes_into_host(host, outcomes)
        for host in discovery_scan.hosts
    )
    scan = replace(discovery_scan, hosts=merged_hosts)

    return InvestigationSnapshot(
        ready=True,
        scan=scan,
        gaps=summarize_evidence_gaps(scan),
        actions=build_evidence_action_plan(scan),
        states=summarize_investigation_state(scan),
        error=None,
    )


@dataclass(frozen=True)
class InvestigationContinuationResult:
    """Evidence collection outcomes paired with the re-evaluated investigation."""

    outcomes: tuple[ParsedCollectionResult, ...]
    snapshot: InvestigationSnapshot


def execute_selected_evidence_actions(
    snapshot: InvestigationSnapshot,
    actions: tuple[EvidenceAction, ...],
    *,
    timeout: float | None = None,
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

    return InvestigationContinuationResult(
        outcomes=outcomes,
        snapshot=re_evaluate_investigation(snapshot.scan, outcomes),
    )


def execute_approved_evidence_actions(
    snapshot: InvestigationSnapshot,
    *,
    timeout: float | None = None,
) -> InvestigationContinuationResult:
    """Execute exactly the planner-approved actions and re-evaluate once."""
    if not snapshot.ready or snapshot.scan is None:
        raise ValueError("Approved evidence execution requires a ready investigation")
    return execute_selected_evidence_actions(
        snapshot,
        snapshot.actions,
        timeout=timeout,
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


def assess_final_investigation_decision(
    alternative_round: AlternativeEvidenceRoundResult,
) -> FinalInvestigationDecision:
    """Stop after the bounded alternative round and explain why."""
    remaining = alternative_round.snapshot.gaps
    statuses = {verification.status for verification in alternative_round.verifications}

    if not remaining:
        return FinalInvestigationDecision("complete", "all_gaps_resolved", (), ())

    if "collection_failed" in statuses:
        reason = "alternative_collection_failed"
    elif "incomplete" in statuses:
        reason = "alternative_evidence_incomplete"
    elif statuses and statuses == {"observed"}:
        reason = "alternative_evidence_observed_gaps_remain"
    else:
        reason = "no_verified_alternative_evidence"

    return FinalInvestigationDecision("stalled", reason, remaining, ())


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
    http_endpoints = {
        (gap.host.strip(), gap.port, gap.protocol.strip().lower())
        for gap in decision_gaps
        if gap.script_id.strip().lower() in {"http-title", "http-methods"}
    }
    eligible = blocked_endpoints & http_endpoints

    return tuple(
        EvidenceAction(
            host=host,
            port=port,
            protocol=protocol,
            script_ids=("http-headers",),
            purposes=("review HTTP response headers for service identity and context",),
            command=(
                "nmap",
                *(("-sU",) if protocol == "udp" else ()),
                "-p",
                str(port),
                "--script",
                "http-headers",
                "-oX",
                "-",
                host,
            ),
        )
        for host, port, protocol in sorted(eligible)
    )


def assess_investigation_continuation(
    before: InvestigationSnapshot,
    after: InvestigationSnapshot,
    attempted_actions: tuple[EvidenceAction, ...] = (),
) -> InvestigationContinuationDecision:
    """Classify re-evaluation without executing another collection round.

    A continuation is complete when no planner-supported gaps remain. It is
    progressed only when at least one previous gap was resolved and a further
    planner-supported action remains that was not already attempted. Repeated
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

    stall_reason = None
    if not after.gaps:
        status = "complete"
    elif resolved and safe_next_actions:
        status = "progressed"
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
    )
