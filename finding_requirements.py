"""Derive bounded investigation requirements from established findings."""

from __future__ import annotations

from dataclasses import dataclass

from findings import Finding


@dataclass(frozen=True)
class FindingDerivedRequirement:
    """One investigation need justified by an existing evidence-backed finding."""

    requirement_id: str
    host: str
    port: int | None
    protocol: str | None
    purpose: str
    finding_id: str
    evidence_source: str | None


FINDING_REQUIREMENTS: dict[str, tuple[str, str]] = {
    "smb.signing.review": (
        "smb_access_control_context",
        "review SMB access controls in the context of the observed signing configuration",
    ),
}


def derive_finding_requirements(
    findings: tuple[Finding, ...],
) -> tuple[FindingDerivedRequirement, ...]:
    """Return only explicitly mapped investigation needs from established findings."""
    requirements: list[FindingDerivedRequirement] = []
    seen: set[tuple[str, str, int | None, str | None]] = set()

    for finding in findings:
        mapped = FINDING_REQUIREMENTS.get(finding.finding_id)
        if mapped is None:
            continue
        requirement_id, purpose = mapped
        key = (
            requirement_id,
            finding.host.strip(),
            finding.port,
            finding.protocol.strip().lower() if finding.protocol else None,
        )
        if key in seen:
            continue
        seen.add(key)
        requirements.append(
            FindingDerivedRequirement(
                requirement_id=requirement_id,
                host=key[1],
                port=key[2],
                protocol=key[3],
                purpose=purpose,
                finding_id=finding.finding_id,
                evidence_source=finding.evidence_source,
            )
        )

    return tuple(requirements)
