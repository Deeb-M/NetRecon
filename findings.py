"""Analysis finding model used across NetRecon."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    finding_id: str
    category: str
    host: str
    port: int | None
    protocol: str | None
    severity: str
    title: str
    evidence: str
    recommendation: str
    evidence_source: str | None = None
