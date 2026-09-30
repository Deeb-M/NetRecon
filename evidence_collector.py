"""Build, execute, parse, and analyze transparent Nmap evidence collection."""

from __future__ import annotations

from dataclasses import dataclass, replace
from ipaddress import ip_address
import subprocess

from analyzer import analyze_scan
from evidence_planner import HostEvidencePlan
from findings import Finding
from models import Host, Port, Scan
from parser import NmapParseError, parse_nmap_xml_text


class EvidenceCollectionError(RuntimeError):
    """Raised when an evidence collection command cannot be executed."""


@dataclass(frozen=True)
class CollectionSpec:
    """One collection unit for a target port and its requested NSE scripts."""

    target: str
    port: int
    protocol: str
    script_ids: tuple[str, ...]
    auth_context: str | None = None
    credentials_file: str | None = None


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


@dataclass(frozen=True)
class ParsedCollectionResult:
    """Collection result paired with its parsed scan when available."""

    result: CollectionResult
    scan: Scan | None

    @property
    def failure_message(self) -> str | None:
        """Return a concise collection failure message suitable for reporting."""
        if self.scan is not None:
            return None
        message = self.result.stderr.strip()
        if message:
            return message
        if self.result.returncode == 0:
            return "Nmap returned invalid XML"
        return f"Nmap exited with status {self.result.returncode}"


def _same_host_address(left: str, right: str) -> bool:
    """Compare host addresses safely, including equivalent IPv6 representations."""
    try:
        return ip_address(left.strip()) == ip_address(right.strip())
    except ValueError:
        return False


def merge_collection_outcomes_into_host(
    discovered: Host,
    outcomes: tuple[ParsedCollectionResult, ...],
) -> Host:
    """Merge ports from successful collection outcomes into a discovered host."""
    try:
        ip_address(discovered.address.strip())
    except ValueError as exc:
        raise ValueError("Cannot correlate evidence for an invalid discovery host address") from exc

    matching_hosts = tuple(
        host
        for outcome in outcomes
        if outcome.scan is not None
        for host in outcome.scan.hosts
        if _same_host_address(host.address, discovered.address)
    )
    collected_ports = tuple(
        port
        for host in matching_hosts
        for port in host.ports
    )
    merged = merge_host_evidence(discovered, collected_ports)

    scripts = list(merged.scripts)
    for host in matching_hosts:
        for script in host.scripts:
            if script not in scripts:
                scripts.append(script)

    return replace(merged, scripts=tuple(scripts))


def merge_host_evidence(
    discovered: Host,
    collected_ports: tuple[Port, ...],
) -> Host:
    """Merge collected evidence ports into a discovered host in collection order."""
    merged = discovered
    for collected in collected_ports:
        merged = merge_host_port_evidence(merged, collected)
    return merged


def merge_host_port_evidence(
    discovered: Host,
    collected: Port,
) -> Host:
    """Merge collected port evidence into the matching port of a discovered host."""
    matching_indexes = tuple(
        index
        for index, port in enumerate(discovered.ports)
        if (
            port.port == collected.port
            and port.protocol.strip().lower() == collected.protocol.strip().lower()
        )
    )
    if not matching_indexes:
        raise ValueError("Cannot merge evidence for an undiscovered port")

    index = matching_indexes[0]
    ports = list(discovered.ports)
    ports[index] = merge_port_evidence(ports[index], collected)
    return replace(discovered, ports=tuple(ports))


def merge_port_evidence(
    discovered: Port,
    collected: Port,
) -> Port:
    """Add collected scripts to a matching discovered port without replacing discovery metadata."""
    if (
        discovered.port != collected.port
        or discovered.protocol.strip().lower() != collected.protocol.strip().lower()
    ):
        raise ValueError("Cannot merge evidence from a different port")

    scripts = list(discovered.scripts)
    for script in collected.scripts:
        if script not in scripts:
            scripts.append(script)

    return replace(
        discovered,
        scripts=tuple(scripts),
    )


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

    auth_args: tuple[str, ...] = ()
    if spec.auth_context is not None or spec.credentials_file is not None:
        if spec.auth_context != "smb":
            raise ValueError("Unsupported evidence authentication context")
        credentials_file = (spec.credentials_file or "").strip()
        if not credentials_file:
            raise ValueError("Authenticated SMB collection requires a credentials file")
        auth_args = ("--script-args-file", credentials_file)

    return NmapCommand(
        arguments=(
            "nmap",
            *scan_type,
            "-p",
            str(spec.port),
            "--script",
            ",".join(script_ids),
            *auth_args,
            "-oX",
            "-",
            target,
        )
    )



def execute_nmap_command(
    command: NmapCommand,
    *,
    timeout: float | None = None,
) -> CollectionResult:
    """Execute one prepared Nmap command and capture its process result."""
    try:
        completed = subprocess.run(
            command.arguments,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise EvidenceCollectionError("Nmap executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        timeout_message = (
            "Nmap evidence collection timed out: "
            + " ".join(command.arguments)
        )
        stderr = f"{stderr.rstrip()}\n{timeout_message}".strip()
        return CollectionResult(
            command=command,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
        )
    return CollectionResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def parse_collection_result(result: CollectionResult) -> Scan:
    """Parse XML from a successful evidence collection result."""
    if result.returncode != 0:
        raise ValueError(
            f"Cannot parse failed evidence collection: return code {result.returncode}"
        )

    return parse_nmap_xml_text(
        result.stdout,
        source="nmap stdout",
    )


def parse_collection_outcome(
    result: CollectionResult,
) -> ParsedCollectionResult:
    """Preserve every collection result and parse successful XML output."""
    if result.returncode != 0:
        return ParsedCollectionResult(
            result=result,
            scan=None,
        )

    try:
        scan = parse_collection_result(result)
    except NmapParseError:
        return ParsedCollectionResult(
            result=result,
            scan=None,
        )

    return ParsedCollectionResult(
        result=result,
        scan=scan,
    )


def analyze_correlated_host_evidence(
    discovered: Host,
    outcomes: tuple[ParsedCollectionResult, ...],
) -> tuple[Finding, ...]:
    """Analyze a discovered host after merging its successfully collected evidence."""
    merged = merge_collection_outcomes_into_host(discovered, outcomes)
    return analyze_scan(
        Scan(
            source="correlated evidence",
            hosts=(merged,),
        )
    )


def analyze_collection_outcome(
    outcome: ParsedCollectionResult,
) -> tuple[Finding, ...]:
    """Analyze parsed evidence while preserving failed collection outcomes."""
    if outcome.scan is None:
        return ()

    return analyze_scan(outcome.scan)


def analyze_collection_outcomes(
    outcomes: tuple[ParsedCollectionResult, ...],
) -> tuple[Finding, ...]:
    """Analyze collected evidence outcomes in collection order."""
    return tuple(
        finding
        for outcome in outcomes
        for finding in analyze_collection_outcome(outcome)
    )


@dataclass(frozen=True)
class CorrelatedEvidenceResult:
    outcomes: tuple[ParsedCollectionResult, ...]
    host: Host
    findings: tuple[Finding, ...]

    @property
    def collection_complete(self) -> bool:
        """Return True only when every requested collection outcome parsed successfully."""
        return all(outcome.scan is not None for outcome in self.outcomes)

    @property
    def failed_outcomes(self) -> tuple[ParsedCollectionResult, ...]:
        """Return only collection outcomes that did not produce parsed evidence."""
        return tuple(outcome for outcome in self.outcomes if outcome.scan is None)


def collect_correlated_host_evidence(
    discovered: Host,
    plan: HostEvidencePlan,
    *,
    timeout: float | None = None,
) -> CorrelatedEvidenceResult:
    """Collect evidence while preserving collection outcomes and correlated context."""
    if not _same_host_address(plan.target, discovered.address):
        raise ValueError("Evidence plan target does not match discovery host")

    outcomes = collect_host_evidence(plan, timeout=timeout)
    host = merge_collection_outcomes_into_host(discovered, outcomes)
    findings = analyze_scan(
        Scan(
            source="correlated evidence",
            hosts=(host,),
        )
    )
    return CorrelatedEvidenceResult(
        outcomes=outcomes,
        host=host,
        findings=findings,
    )


def collect_correlate_and_analyze_host_evidence(
    discovered: Host,
    plan: HostEvidencePlan,
    *,
    timeout: float | None = None,
) -> tuple[Finding, ...]:
    """Compatibility wrapper returning findings from correlated evidence collection."""
    return collect_correlated_host_evidence(
        discovered,
        plan,
        timeout=timeout,
    ).findings


def collect_and_analyze_host_evidence(
    plan: HostEvidencePlan,
    *,
    timeout: float | None = None,
) -> tuple[Finding, ...]:
    """Collect, parse, and analyze all requested evidence for one host."""
    return analyze_collection_outcomes(
        collect_host_evidence(plan, timeout=timeout)
    )


def collect_host_evidence(
    plan: HostEvidencePlan,
    *,
    timeout: float | None = None,
) -> tuple[ParsedCollectionResult, ...]:
    """Execute and parse every collection unit for one host evidence plan."""
    return tuple(
        parse_collection_outcome(result)
        for result in execute_host_evidence_plan(plan, timeout=timeout)
    )


def execute_host_evidence_plan(
    plan: HostEvidencePlan,
    *,
    timeout: float | None = None,
) -> tuple[CollectionResult, ...]:
    """Execute every prepared command for one host evidence plan."""
    return tuple(
        execute_nmap_command(command, timeout=timeout)
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
    target = plan.target.strip()
    if not target:
        raise ValueError("Evidence collection requires a target")

    grouped: dict[tuple[int, str], list[str]] = {}

    for request in plan.requests:
        if request.port < 1 or request.port > 65535:
            raise ValueError(f"Invalid collection port: {request.port}")
        protocol = request.protocol.strip().lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported collection protocol: {protocol or 'blank'}")
        key = (request.port, protocol)
        script_id = request.script_id.strip().lower()
        if not script_id:
            raise ValueError("Evidence collection script IDs must not be blank")
        script_ids = grouped.setdefault(key, [])
        if script_id not in script_ids:
            script_ids.append(script_id)

    return tuple(
        CollectionSpec(
            target=target,
            port=port,
            protocol=protocol,
            script_ids=tuple(script_ids),
        )
        for (port, protocol), script_ids in grouped.items()
    )
