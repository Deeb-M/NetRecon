"""Build transparent discovery plans without executing Nmap."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess

from models import Scan
from parser import NmapParseError, parse_nmap_xml_text


@dataclass(frozen=True)
class DiscoveryPlan:
    """One explicit discovery action proposed for analyst review."""

    target: str
    profile: str
    purpose: str
    command: tuple[str, ...]


def build_baseline_discovery_plan(target: str) -> DiscoveryPlan:
    """Build the conservative baseline TCP service-discovery plan."""
    normalized_target = target.strip()
    if not normalized_target:
        raise ValueError("Discovery target must not be blank")

    return DiscoveryPlan(
        target=normalized_target,
        profile="baseline",
        purpose="discover open TCP services with version detection",
        command=("nmap", "-sV", "-oX", "-", normalized_target),
    )



@dataclass(frozen=True)
class DiscoveryExecutionResult:
    """Observed outcome from executing one explicit discovery plan."""

    plan: DiscoveryPlan
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


def execute_discovery_plan(
    plan: DiscoveryPlan,
    *,
    timeout: float = 60.0,
) -> DiscoveryExecutionResult:
    """Execute exactly the argv stored in a discovery plan."""
    try:
        completed = subprocess.run(
            plan.command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return DiscoveryExecutionResult(
            plan=plan,
            returncode=124,
            stdout=exc.output or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )

    return DiscoveryExecutionResult(
        plan=plan,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
    )



@dataclass(frozen=True)
class DiscoveryResult:
    """Interpreted discovery outcome with a Scan only for verified success."""

    execution: DiscoveryExecutionResult
    success: bool
    scan: Scan | None
    error: str | None


def interpret_discovery_execution(
    execution: DiscoveryExecutionResult,
) -> DiscoveryResult:
    """Interpret one discovery execution without treating exit zero alone as success."""
    if execution.timed_out:
        return DiscoveryResult(
            execution=execution,
            success=False,
            scan=None,
            error="Nmap discovery timed out",
        )

    if execution.returncode != 0:
        return DiscoveryResult(
            execution=execution,
            success=False,
            scan=None,
            error=execution.stderr or f"Nmap discovery failed with exit code {execution.returncode}",
        )

    try:
        scan = parse_nmap_xml_text(
            execution.stdout,
            source=f"<discovery:{execution.plan.target}>",
        )
    except NmapParseError as exc:
        return DiscoveryResult(
            execution=execution,
            success=False,
            scan=None,
            error=str(exc),
        )

    return DiscoveryResult(
        execution=execution,
        success=True,
        scan=scan,
        error=None,
    )
