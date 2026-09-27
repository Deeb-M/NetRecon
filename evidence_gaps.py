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




@dataclass(frozen=True)
class EvidenceRequirement:
    """Semantic analyst need kept separate from its collection mechanism."""

    requirement_id: str
    purpose: str
    primary_script_ids: tuple[str, ...]
    alternative_script_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceRequirementState:
    """One unresolved semantic analyst need bound to a network endpoint."""

    host: str
    port: int
    protocol: str
    requirement: EvidenceRequirement


EVIDENCE_REQUIREMENTS: dict[str, EvidenceRequirement] = {
    "http-title": EvidenceRequirement(
        "http_identity_context",
        "review HTTP service identity and exposed content context",
        ("http-title",),
        ("http-headers",),
    ),
    "http-methods": EvidenceRequirement(
        "http_supported_methods",
        "review supported HTTP methods",
        ("http-methods",),
    ),
    "ssh2-enum-algos": EvidenceRequirement(
        "ssh_algorithm_configuration",
        "review SSH algorithm configuration",
        ("ssh2-enum-algos",),
    ),
    "ssl-cert": EvidenceRequirement(
        "tls_certificate_identity",
        "review TLS certificate identity and validity",
        ("ssl-cert",),
    ),
    "ssl-enum-ciphers": EvidenceRequirement(
        "tls_protocol_cipher_configuration",
        "review TLS protocol and cipher configuration",
        ("ssl-enum-ciphers",),
    ),
    "smb-protocols": EvidenceRequirement(
        "smb_protocol_support",
        "review SMB protocol dialect support",
        ("smb-protocols",),
    ),
    "smb2-security-mode": EvidenceRequirement(
        "smb_signing_configuration",
        "review SMB signing configuration",
        ("smb2-security-mode",),
    ),
}


def requirement_for_gap(gap: EvidenceGap) -> EvidenceRequirement | None:
    """Return the semantic analyst requirement represented by a script-specific gap."""
    return EVIDENCE_REQUIREMENTS.get(gap.script_id.strip().lower())


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
