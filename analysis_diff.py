"""Deterministic comparison of evidence-based NetRecon findings."""

from __future__ import annotations

from dataclasses import dataclass

from findings import Finding


@dataclass(frozen=True)
class FindingChange:
    change: str
    finding: Finding


def _identity(finding: Finding) -> tuple[str, str, int | None, str | None]:
    return (
        finding.finding_id,
        finding.host,
        finding.port,
        finding.protocol,
    )


def compare_findings(
    before: tuple[Finding, ...],
    after: tuple[Finding, ...],
) -> tuple[FindingChange, ...]:
    """Report findings that appeared or disappeared between analyses."""
    old = {_identity(finding): finding for finding in before}
    new = {_identity(finding): finding for finding in after}
    changes: list[FindingChange] = []

    for key in sorted(old.keys() | new.keys(), key=lambda item: (
        item[1],
        item[2] if item[2] is not None else -1,
        item[3] or "",
        item[0],
    )):
        old_finding = old.get(key)
        new_finding = new.get(key)

        if old_finding is None and new_finding is not None:
            changes.append(FindingChange("new", new_finding))
        elif new_finding is None and old_finding is not None:
            changes.append(FindingChange("resolved", old_finding))

    return tuple(changes)
