"""Build transparent evidence collection specifications without executing Nmap."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_planner import HostEvidencePlan


@dataclass(frozen=True)
class CollectionSpec:
    """One collection unit for a target port and its requested NSE scripts."""

    target: str
    port: int
    protocol: str
    script_ids: tuple[str, ...]


@dataclass(frozen=True)
class NmapCommand:
    """Transparent Nmap argv prepared for evidence collection."""

    arguments: tuple[str, ...]


def build_nmap_command(spec: CollectionSpec) -> NmapCommand:
    """Build Nmap argv for a collection specification without executing it."""
    return NmapCommand(
        arguments=(
            "nmap",
            "-p",
            str(spec.port),
            "--script",
            ",".join(spec.script_ids),
            "-oX",
            "-",
            spec.target,
        )
    )


def build_collection_specs(plan: HostEvidencePlan) -> tuple[CollectionSpec, ...]:
    """Group a host evidence plan into executable collection units."""
    grouped: dict[tuple[int, str], list[str]] = {}

    for request in plan.requests:
        key = (request.port, request.protocol)
        grouped.setdefault(key, []).append(request.script_id)

    return tuple(
        CollectionSpec(
            target=plan.target,
            port=port,
            protocol=protocol,
            script_ids=tuple(script_ids),
        )
        for (port, protocol), script_ids in grouped.items()
    )
