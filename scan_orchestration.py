"""Build transparent discovery plans without executing Nmap."""

from __future__ import annotations

from dataclasses import dataclass
import math
import subprocess
from urllib.parse import urlparse

from models import Scan
from parser import NmapParseError, parse_nmap_xml_text


@dataclass(frozen=True)
class DiscoveryPlan:
    """One explicit discovery action proposed for analyst review."""

    target: str
    profile: str
    purpose: str
    command: tuple[str, ...]
    input_target: str | None = None
    scheme: str | None = None
    port: int | None = None
    explicit_port: bool = False
    path: str | None = None


def build_baseline_discovery_plan(target: str) -> DiscoveryPlan:
    """Build the conservative baseline TCP service-discovery plan."""
    input_target = target.strip()
    if not input_target:
        raise ValueError("Discovery target must not be blank")

    parsed = urlparse(input_target)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        if not parsed.hostname:
            raise ValueError("Discovery URL must include a hostname")
        normalized_target = parsed.hostname
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError("Discovery URL contains an invalid port") from exc
        explicit_port = parsed_port is not None
        port = parsed_port if explicit_port else (443 if scheme == "https" else 80)
        path = parsed.path or "/"
    else:
        normalized_target = input_target
        scheme = None
        port = None
        explicit_port = False
        path = None

    if scheme in {"http", "https"}:
        profile = "web"
        purpose = "discover the explicitly supplied Web service with version detection"
        command = ("nmap", "-sV", "-p", str(port), "-oX", "-", normalized_target)
    else:
        profile = "baseline"
        purpose = "discover open TCP services with version detection"
        command = ("nmap", "-sV", "-oX", "-", normalized_target)

    return DiscoveryPlan(
        target=normalized_target,
        profile=profile,
        purpose=purpose,
        command=command,
        input_target=input_target,
        scheme=scheme,
        port=port,
        explicit_port=explicit_port,
        path=path,
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
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Discovery timeout must be a positive finite number")

    def normalize_output(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return value

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
            stdout=normalize_output(exc.output),
            stderr=normalize_output(exc.stderr),
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return DiscoveryExecutionResult(
            plan=plan,
            returncode=127,
            stdout="",
            stderr=str(exc),
            timed_out=False,
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
