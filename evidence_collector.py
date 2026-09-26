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
    target = spec.target.strip()
    protocol = spec.protocol.strip().lower()

    if not target:
        raise ValueError("Evidence collection requires a target")
    if protocol not in {"tcp", "udp"}:
        raise ValueError(f"Unsupported collection protocol: {spec.protocol}")
    if not spec.script_ids:
        raise ValueError("Evidence collection requires at least one script")

    scan_type = ("-sU",) if protocol == "udp" else ()

    return NmapCommand(
        arguments=(
            "nmap",
            *scan_type,
            "-p",
            str(spec.port),
            "--script",
            ",".join(spec.script_ids),
            "-oX",
            "-",
            target,
        )
    )



def build_nmap_commands(plan: HostEvidencePlan) -> tuple[NmapCommand, ...]:
    """Build all Nmap commands required by a host evidence plan."""
    return tuple(
        build_nmap_command(spec)
        for spec in build_collection_specs(plan)
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
