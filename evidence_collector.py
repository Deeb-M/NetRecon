"""Build transparent evidence collection specifications without executing Nmap."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess

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


@dataclass(frozen=True)
class CollectionResult:
    """Captured result of one evidence collection command."""

    command: NmapCommand
    returncode: int
    stdout: str
    stderr: str


def build_nmap_command(spec: CollectionSpec) -> NmapCommand:
    """Build Nmap argv for a collection specification without executing it."""
    target = spec.target.strip()
    protocol = spec.protocol.strip().lower()

    if not target:
        raise ValueError("Evidence collection requires a target")
    if not 1 <= spec.port <= 65535:
        raise ValueError(f"Invalid collection port: {spec.port}")
    if protocol not in {"tcp", "udp"}:
        raise ValueError(f"Unsupported collection protocol: {spec.protocol}")
    if not spec.script_ids:
        raise ValueError("Evidence collection requires at least one script")

    script_ids = tuple(script_id.strip() for script_id in spec.script_ids)
    if any(not script_id for script_id in script_ids):
        raise ValueError("Evidence collection script IDs must not be blank")

    scan_type = ("-sU",) if protocol == "udp" else ()

    return NmapCommand(
        arguments=(
            "nmap",
            *scan_type,
            "-p",
            str(spec.port),
            "--script",
            ",".join(script_ids),
            "-oX",
            "-",
            target,
        )
    )



def execute_nmap_command(command: NmapCommand) -> CollectionResult:
    """Execute one prepared Nmap command and capture its process result."""
    completed = subprocess.run(
        command.arguments,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    return CollectionResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def execute_host_evidence_plan(
    plan: HostEvidencePlan,
) -> tuple[CollectionResult, ...]:
    """Execute every prepared command for one host evidence plan."""
    return tuple(
        execute_nmap_command(command)
        for command in build_nmap_commands(plan)
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
