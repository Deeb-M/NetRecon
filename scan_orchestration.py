"""Build transparent discovery plans without executing Nmap."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess


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
