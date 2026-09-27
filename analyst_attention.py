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
