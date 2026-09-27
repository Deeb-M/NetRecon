"""Compose verified discovery with existing evidence intelligence layers."""

from __future__ import annotations

from dataclasses import dataclass, replace

from evidence_action_plan import EvidenceAction, build_evidence_action_plan
from evidence_gaps import EvidenceGap, summarize_evidence_gaps
from evidence_collector import ParsedCollectionResult, merge_collection_outcomes_into_host
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
