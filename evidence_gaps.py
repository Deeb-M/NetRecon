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
    "ftp-syst": "review FTP server system and protocol context",
    "ftp-anon": "review anonymous FTP access behavior",
    "smtp-commands": "review advertised SMTP capabilities",
    "nfs-showmount": "review NFS export and client-scope context",
    "mysql-info": "review MySQL protocol and server capability context",
    "vnc-info": "review VNC protocol and advertised security types",
    "rpcinfo": "review RPC program, version, transport, and service mappings",
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
    "ftp-syst": EvidenceRequirement(
        "ftp_system_context",
        "review FTP server system and protocol context",
        ("ftp-syst",),
    ),
    "ftp-anon": EvidenceRequirement(
        "ftp_anonymous_access",
        "review anonymous FTP access behavior",
        ("ftp-anon",),
    ),
    "smtp-commands": EvidenceRequirement(
        "smtp_capability_context",
        "review advertised SMTP capabilities",
        ("smtp-commands",),
    ),
    "nfs-showmount": EvidenceRequirement(
        "nfs_export_context",
        "review NFS export and client-scope context",
        ("nfs-showmount",),
    ),
    "mysql-info": EvidenceRequirement(
        "mysql_capability_context",
        "review MySQL protocol and server capability context",
        ("mysql-info",),
    ),
    "vnc-info": EvidenceRequirement(
        "vnc_security_context",
        "review VNC protocol and advertised security types",
        ("vnc-info",),
    ),
    "rpcinfo": EvidenceRequirement(
        "rpc_service_mapping",
        "review RPC program, version, transport, and service mappings",
        ("rpcinfo",),
    ),
}


def requirement_for_gap(gap: EvidenceGap) -> EvidenceRequirement | None:
    """Return the semantic analyst requirement represented by a script-specific gap."""
    return EVIDENCE_REQUIREMENTS.get(gap.script_id.strip().lower())

def requirement_state_for_gap(gap: EvidenceGap) -> EvidenceRequirementState | None:
    """Bind a script-specific evidence gap to its semantic endpoint requirement."""
    requirement = requirement_for_gap(gap)
    if requirement is None:
        return None
    return EvidenceRequirementState(
        gap.host.strip(),
        gap.port,
        gap.protocol.strip().lower(),
        requirement,
    )


def requirement_states_for_gaps(
    gaps: tuple[EvidenceGap, ...],
) -> tuple[EvidenceRequirementState, ...]:
    """Return deduplicated endpoint-bound semantic requirements for evidence gaps."""
    states: dict[tuple[str, int, str, str], EvidenceRequirementState] = {}
    for gap in gaps:
        state = requirement_state_for_gap(gap)
        if state is None:
            continue
        key = (
            state.host,
            state.port,
            state.protocol,
            state.requirement.requirement_id,
        )
        states[key] = state
    return tuple(states[key] for key in sorted(states))


def resolved_requirement_states(
    before: tuple[EvidenceGap, ...],
    after: tuple[EvidenceGap, ...],
) -> tuple[EvidenceRequirementState, ...]:
    """Return semantic endpoint requirements present before but absent after collection."""
    before_states = requirement_states_for_gaps(before)
    after_keys = {
        (
            state.host,
            state.port,
            state.protocol,
            state.requirement.requirement_id,
        )
        for state in requirement_states_for_gaps(after)
    }
    return tuple(
        state
        for state in before_states
        if (
            state.host,
            state.port,
            state.protocol,
            state.requirement.requirement_id,
        )
        not in after_keys
    )


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
