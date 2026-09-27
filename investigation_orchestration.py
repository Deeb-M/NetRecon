"""Compose verified discovery with existing evidence intelligence layers."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_action_plan import EvidenceAction, build_evidence_action_plan
from evidence_gaps import EvidenceGap, summarize_evidence_gaps
from models import Scan
from scan_orchestration import DiscoveryResult


@dataclass(frozen=True)
class InvestigationSnapshot:
    """Current evidence-aware investigation state after discovery."""

    ready: bool
    scan: Scan | None
    gaps: tuple[EvidenceGap, ...]
    actions: tuple[EvidenceAction, ...]
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
            error=discovery.error,
        )

    if discovery.scan is None:
        raise ValueError("Successful discovery must include a verified scan")

    return InvestigationSnapshot(
        ready=True,
        scan=discovery.scan,
        gaps=summarize_evidence_gaps(discovery.scan),
        actions=build_evidence_action_plan(discovery.scan),
        error=None,
    )
