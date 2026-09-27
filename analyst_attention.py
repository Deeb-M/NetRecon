"""Analyst-attention projection over evidence-based NetRecon findings."""

from __future__ import annotations
from dataclasses import dataclass
from findings import Finding

_ATTENTION_CATEGORIES = frozenset({"configuration", "exposure", "transport", "visibility"})

@dataclass(frozen=True)
class AnalystAttentionItem:
    """A traceable analyst-review item derived from an existing Finding."""
    finding_id: str
    category: str
    host: str
    port: int | None
    protocol: str | None
    title: str
    evidence: str
    recommendation: str
    evidence_source: str | None

def build_analyst_attention(findings: tuple[Finding, ...]) -> tuple[AnalystAttentionItem, ...]:
    """Expose review-worthy findings without inventing scores or new conclusions."""
    return tuple(
        AnalystAttentionItem(
            finding_id=f.finding_id, category=f.category, host=f.host, port=f.port,
            protocol=f.protocol, title=f.title, evidence=f.evidence,
            recommendation=f.recommendation, evidence_source=f.evidence_source,
        )
        for f in findings if f.category.strip().lower() in _ATTENTION_CATEGORIES
    )


@dataclass(frozen=True)
class AnalystAttentionCorrelation:
    """A bounded review grouping derived only from existing attention items."""
    correlation_id: str
    host: str
    title: str
    finding_ids: tuple[str, ...]
    evidence_sources: tuple[str, ...]
    review: str


def correlate_analyst_attention(
    items: tuple[AnalystAttentionItem, ...],
) -> tuple[AnalystAttentionCorrelation, ...]:
    """Correlate explicitly supported attention relationships without risk scoring."""
    by_host: dict[str, list[AnalystAttentionItem]] = {}
    for item in items:
        by_host.setdefault(item.host, []).append(item)

    correlations: list[AnalystAttentionCorrelation] = []
    for host, host_items in by_host.items():
        smb_exposure = next(
            (item for item in host_items if item.finding_id == "service.smb.exposed"),
            None,
        )
        smb_signing = next(
            (item for item in host_items if item.finding_id == "smb.signing.review"),
            None,
        )
        if smb_exposure is None or smb_signing is None:
            continue
        sources = tuple(
            source
            for source in (smb_exposure.evidence_source, smb_signing.evidence_source)
            if source is not None
        )
        correlations.append(
            AnalystAttentionCorrelation(
                correlation_id="smb.exposure_and_signing_review",
                host=host,
                title="SMB exposure and signing configuration require joint review",
                finding_ids=(smb_exposure.finding_id, smb_signing.finding_id),
                evidence_sources=sources,
                review=(
                    "Review the exposed SMB service together with its observed signing "
                    "configuration and confirm that both match the host's intended role "
                    "and security policy."
                ),
            )
        )
    return tuple(correlations)
