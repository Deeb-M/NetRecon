"""Analyst-facing evidence gaps derived from the existing evidence planner."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_planner import plan_evidence_requests
from models import Scan


EVIDENCE_PURPOSES: dict[str, str] = {
    "ssh2-enum-algos": "review SSH algorithm configuration",
    "http-title": "review HTTP service identity and exposed content context",
    "http-methods": "review supported HTTP methods",
    "ssl-cert": "review TLS certificate identity and validity",
    "ssl-enum-ciphers": "review TLS protocol and cipher configuration",
    "smb-protocols": "review SMB protocol dialect support",
    "smb2-security-mode": "review SMB signing configuration",
}


@dataclass(frozen=True)
class EvidenceGap:
    """One missing evidence source that the existing planner would collect."""

    host: str
    port: int
    protocol: str
    script_id: str
    purpose: str


def summarize_evidence_gaps(scan: Scan) -> tuple[EvidenceGap, ...]:
    """Describe evidence still requested by the existing planner."""
    gaps: list[EvidenceGap] = []

    for host in scan.hosts:
        for request in plan_evidence_requests(host):
            purpose = EVIDENCE_PURPOSES.get(request.script_id)
            if purpose is None:
                continue
            gaps.append(
                EvidenceGap(
                    host=host.address.strip(),
                    port=request.port,
                    protocol=request.protocol,
                    script_id=request.script_id,
                    purpose=purpose,
                )
            )

    return tuple(gaps)
