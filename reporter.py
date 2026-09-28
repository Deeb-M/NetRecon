"""Human-readable reporting for NetRecon."""

from __future__ import annotations

from investigation_explanation import InvestigationExplanation
from dataclasses import asdict
from datetime import datetime, timezone
import json

from adaptive_investigation import AdaptiveInvestigationPlan
from analysis_diff import FindingChange
from analyst_attention import AnalystAttentionCorrelation, AnalystAttentionItem
from analysis_summary import summarize_analysis
from evidence_collector import CorrelatedEvidenceResult
from exposure_history import ExposureHistory
from evidence_action_plan import EvidenceAction
from evidence_gaps import EvidenceGap
from finding_history import FindingHistory
from findings import Finding
from host_summary import summarize_hosts
from models import Host, Port, Scan, ScanScope
from network_summary import summarize_network, summarize_shared_services
from scan_diff import ExposureChange
from scan_orchestration import DiscoveryPlan, DiscoveryResult
from investigation_orchestration import InvestigationSnapshot
from investigation_synthesis import InvestigationSynthesis
from investigation_memory import InvestigationMemory


def _format_history_time(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")





def render_adaptive_investigation_plan(plan: AdaptiveInvestigationPlan) -> str:
    """Render the next bounded investigation decision transparently."""
    lines = [
        "Adaptive Investigation Plan",
        "---------------------------",
        f"Decision: {plan.decision}",
        f"Reason: {plan.reason}",
        f"Actions: {len(plan.actions)}",
    ]
    for action in plan.actions:
        lines.append(f"Action: {' '.join(action.command)}")
    return "\n".join(lines)


def render_adaptive_investigation_plan_json(plan: AdaptiveInvestigationPlan) -> str:
    """Render the adaptive decision as a stable machine-readable envelope."""
    return json.dumps(
        {
            "report_type": "adaptive_investigation_plan",
            "decision": plan.decision,
            "reason": plan.reason,
            "actions": [asdict(action) for action in plan.actions],
        },
        indent=2,
        ensure_ascii=False,
    )


def render_analyst_attention(items: tuple[AnalystAttentionItem, ...]) -> str:
    """Render traceable analyst-review items without ranking them."""
    lines = ["Analyst Attention", "-----------------", f"Items: {len(items)}"]
    for item in items:
        location = item.host
        if item.port is not None:
            location += f":{item.port}/{item.protocol or 'unknown'}"
        lines.extend([
            "",
            item.title,
            f"  Category: {item.category}",
            f"  Location: {location}",
            f"  Evidence: {item.evidence}",
            f"  Evidence Source: {item.evidence_source or 'unspecified'}",
            f"  Review: {item.recommendation}",
        ])
    return "\n".join(lines)


def render_analyst_attention_json(items: tuple[AnalystAttentionItem, ...]) -> str:
    """Render analyst-review items as a stable machine-readable envelope."""
    return json.dumps(
        {
            "report_type": "analyst_attention",
            "summary": {"items": len(items)},
            "items": [asdict(item) for item in items],
        },
        indent=2,
        ensure_ascii=False,
    )



def render_analyst_attention_correlations(
    correlations: tuple[AnalystAttentionCorrelation, ...],
) -> str:
    """Render evidence-traceable review correlations without ranking."""
    lines = [
        "Correlated Review",
        "-----------------",
        f"Groups: {len(correlations)}",
    ]
    for correlation in correlations:
        lines.extend([
            "",
            correlation.title,
            f"  Host: {correlation.host}",
            f"  Findings: {', '.join(correlation.finding_ids)}",
            f"  Evidence Sources: {', '.join(correlation.evidence_sources) or 'unspecified'}",
            f"  Review: {correlation.review}",
        ])
    return "\n".join(lines)


def render_analyst_attention_correlations_json(
    correlations: tuple[AnalystAttentionCorrelation, ...],
) -> str:
    """Render review correlations as a stable machine-readable envelope."""
    return json.dumps(
        {
            "report_type": "analyst_attention_correlations",
            "summary": {"groups": len(correlations)},
            "groups": [asdict(correlation) for correlation in correlations],
        },
        indent=2,
        ensure_ascii=False,
    )



def render_investigation_memory(memory: InvestigationMemory) -> str:
    """Render factual changes between two investigation syntheses."""
    lines = [
        "Investigation Memory",
        "--------------------",
        f"Status: {memory.previous_status} -> {memory.current_status}",
        f"Status Changed: {'yes' if memory.status_changed else 'no'}",
        f"Reason: {memory.previous_reason} -> {memory.current_reason}",
        f"Reason Changed: {'yes' if memory.reason_changed else 'no'}",
        f"Attention Item Change: {memory.attention_item_change:+d}",
        f"Correlated Review Group Change: {memory.correlated_review_group_change:+d}",
        f"Added Requirements: {len(memory.added_requirements)}",
    ]
    for state in memory.added_requirements:
        lines.append(
            f"Added: {state.host}:{state.port}/{state.protocol}  "
            f"{state.requirement.requirement_id} — {state.requirement.purpose}"
        )
    lines.append(f"Resolved Requirements: {len(memory.resolved_requirements)}")
    for state in memory.resolved_requirements:
        lines.append(
            f"Resolved: {state.host}:{state.port}/{state.protocol}  "
            f"{state.requirement.requirement_id} — {state.requirement.purpose}"
        )
    lines.append(
        f"Added Finding Requirements: {len(memory.added_finding_requirements)}"
    )
    for state in memory.added_finding_requirements:
        requirement = state.requirement
        lines.append(
            f"Added Finding: {requirement.host}:{requirement.port}/{requirement.protocol}  "
            f"{requirement.requirement_id} [{state.status}]"
        )
    lines.append(
        f"Resolved Finding Requirements: {len(memory.resolved_finding_requirements)}"
    )
    for state in memory.resolved_finding_requirements:
        requirement = state.requirement
        lines.append(
            f"Resolved Finding: {requirement.host}:{requirement.port}/{requirement.protocol}  "
            f"{requirement.requirement_id} [{state.status}]"
        )
    lines.append(
        f"Changed Finding Requirements: {len(memory.changed_finding_requirements)}"
    )
    for previous, current in memory.changed_finding_requirements:
        requirement = current.requirement
        detail = f"{previous.status} -> {current.status}"
        if previous.authorization_reason != current.authorization_reason:
            detail += (
                f"; authorization: {previous.authorization_reason} -> "
                f"{current.authorization_reason}"
            )
        if previous.observed_script_ids != current.observed_script_ids:
            detail += (
                f"; observed scripts: {', '.join(previous.observed_script_ids) or 'none'} -> "
                f"{', '.join(current.observed_script_ids) or 'none'}"
            )
        lines.append(
            f"Changed Finding: {requirement.host}:{requirement.port}/{requirement.protocol}  "
            f"{requirement.requirement_id} [{detail}]"
        )
    return "\n".join(lines)


def render_investigation_memory_json(memory: InvestigationMemory) -> str:
    """Render factual investigation-memory changes as a stable JSON envelope."""
    return json.dumps(
        {
            "report_type": "investigation_memory",
            "status": {
                "previous": memory.previous_status,
                "current": memory.current_status,
                "changed": memory.status_changed,
            },
            "reason": {
                "previous": memory.previous_reason,
                "current": memory.current_reason,
                "changed": memory.reason_changed,
            },
            "summary": {
                "attention_item_change": memory.attention_item_change,
                "correlated_review_group_change": memory.correlated_review_group_change,
                "added_requirements": len(memory.added_requirements),
                "resolved_requirements": len(memory.resolved_requirements),
                "added_finding_requirements": len(memory.added_finding_requirements),
                "resolved_finding_requirements": len(memory.resolved_finding_requirements),
                "changed_finding_requirements": len(memory.changed_finding_requirements),
            },
            "added_requirements": [asdict(state) for state in memory.added_requirements],
            "resolved_requirements": [asdict(state) for state in memory.resolved_requirements],
            "added_finding_requirements": [
                asdict(state) for state in memory.added_finding_requirements
            ],
            "resolved_finding_requirements": [
                asdict(state) for state in memory.resolved_finding_requirements
            ],
            "changed_finding_requirements": [
                {"previous": asdict(previous), "current": asdict(current)}
                for previous, current in memory.changed_finding_requirements
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


def render_investigation_explanation(explanation: InvestigationExplanation) -> str:
    """Render a factual explanation of current investigation state."""
    lines = [
        "Investigation Explanation",
        "-------------------------",
        "Known",
    ]
    lines.extend(f"- {item}" for item in explanation.known)
    lines.append("Unresolved")
    lines.extend(f"- {item}" for item in explanation.unresolved)
    lines.append("Blocked")
    lines.extend(f"- {item}" for item in explanation.blocked)
    lines.append("Next")
    lines.extend(f"- {item}" for item in explanation.next_actions)
    return "\n".join(lines)


def render_investigation_explanation_json(explanation: InvestigationExplanation) -> str:
    """Render the factual investigation explanation as stable JSON."""
    return json.dumps(
        {
            "report_type": "investigation_explanation",
            "known": list(explanation.known),
            "unresolved": list(explanation.unresolved),
            "blocked": list(explanation.blocked),
            "next_actions": list(explanation.next_actions),
        },
        indent=2,
        ensure_ascii=False,
    )


def render_investigation_synthesis(synthesis: InvestigationSynthesis) -> str:
    """Render the factual final investigation synthesis."""
    lines = [
        "Investigation Synthesis",
        "-----------------------",
        f"Status: {synthesis.status}",
        f"Reason: {synthesis.reason}",
        f"Attention Items: {synthesis.attention_items}",
        f"Correlated Review Groups: {synthesis.correlated_review_groups}",
        f"Remaining Requirements: {len(synthesis.remaining_requirements)}",
        f"Remaining Finding Requirements: {len(synthesis.remaining_finding_requirements)}",
    ]
    for state in synthesis.remaining_requirements:
        requirement = state.requirement
        lines.append(
            f"Requirement: {state.host}:{state.port}/{state.protocol}  "
            f"{requirement.requirement_id} — {requirement.purpose}"
        )
    for state in synthesis.remaining_finding_requirements:
        requirement = state.requirement
        endpoint = (
            f"{requirement.host}:{requirement.port}/{requirement.protocol}"
            if requirement.port is not None and requirement.protocol is not None
            else requirement.host
        )
        lines.append(
            f"Finding Requirement: {endpoint}  {requirement.requirement_id} — "
            f"{requirement.purpose} [{state.status}]"
        )
    return "\n".join(lines)


def render_investigation_synthesis_json(synthesis: InvestigationSynthesis) -> str:
    """Render the factual synthesis as a stable machine-readable envelope."""
    return json.dumps(
        {
            "report_type": "investigation_synthesis",
            "status": synthesis.status,
            "reason": synthesis.reason,
            "summary": {
                "attention_items": synthesis.attention_items,
                "correlated_review_groups": synthesis.correlated_review_groups,
                "remaining_requirements": len(synthesis.remaining_requirements),
                "remaining_finding_requirements": len(synthesis.remaining_finding_requirements),
            },
            "remaining_requirements": [asdict(state) for state in synthesis.remaining_requirements],
            "remaining_finding_requirements": [
                asdict(state) for state in synthesis.remaining_finding_requirements
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


def render_evidence_gaps(gaps: tuple[EvidenceGap, ...]) -> str:
    """Render missing planner-supported evidence for analyst follow-up."""
    lines = [
        "Evidence Gaps",
        "-------------",
        f"Gaps: {len(gaps)}",
    ]
    for gap in gaps:
        lines.append(
            f"{gap.host}:{gap.port}/{gap.protocol}  {gap.script_id}"
        )
        lines.append(f"  Purpose: {gap.purpose}")
    return "\n".join(lines)


def render_evidence_gaps_json(gaps: tuple[EvidenceGap, ...]) -> str:
    """Render evidence gaps as a stable machine-readable envelope."""
    return json.dumps(
        {
            "report_type": "evidence_gaps",
            "summary": {"gaps": len(gaps)},
            "gaps": [asdict(gap) for gap in gaps],
        },
        indent=2,
        ensure_ascii=False,
    )


def render_exposure_history(history: tuple[ExposureHistory, ...]) -> str:
    """Render descriptive open-endpoint observation history."""
    lines = [
        "Exposure History",
        "----------------",
        f"Endpoints: {len(history)}",
    ]
    for item in history:
        lines.append(
            f"{item.host}:{item.port}/{item.protocol}  "
            f"first_observed={_format_history_time(item.first_seen)}  "
            f"last_observed={_format_history_time(item.last_seen)}  "
            f"observations={item.observations}  "
            f"opportunities={item.opportunities}"
        )
    return "\n".join(lines)


def render_exposure_history_json(history: tuple[ExposureHistory, ...]) -> str:
    """Render exposure history with exact numeric Nmap timestamps."""
    return json.dumps(
        {
            "report_type": "exposure_history",
            "summary": {"endpoints": len(history)},
            "history": [asdict(item) for item in history],
        },
        indent=2,
        ensure_ascii=False,
    )


def render_finding_history(history: tuple[FindingHistory, ...]) -> str:
    """Render evidence-aware finding observation history."""
    lines = [
        "Finding History",
        "---------------",
        f"Findings: {len(history)}",
    ]
    for item in history:
        location = item.host
        if item.port is not None:
            location += f":{item.port}/{item.protocol or 'unknown'}"
        lines.append(
            f"{item.finding_id}  {location}  "
            f"first_observed={_format_history_time(item.first_seen)}  "
            f"last_observed={_format_history_time(item.last_seen)}  "
            f"observations={item.observations}  "
            f"opportunities={item.opportunities}"
        )
    return "\n".join(lines)


def render_finding_history_json(history: tuple[FindingHistory, ...]) -> str:
    """Render finding history with exact numeric Nmap timestamps."""
    return json.dumps(
        {
            "report_type": "finding_history",
            "summary": {"findings": len(history)},
            "history": [asdict(item) for item in history],
        },
        indent=2,
        ensure_ascii=False,
    )


_SEVERITY_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def render_evidence_collection(result: CorrelatedEvidenceResult) -> str:
    """Render host-scoped evidence collection status without subprocess details."""
    status = "complete" if result.collection_complete else "partial"
    lines = [
        "Evidence Collection",
        "-------------------",
        f"Host: {result.host.address}",
        f"Status: {status}",
    ]
    for outcome in result.failed_outcomes:
        lines.append(f"Failure: {outcome.failure_message}")
    lines.extend(
        (
            "",
            render_host_summaries(
                Scan(source="correlated evidence", hosts=(result.host,)),
                result.findings,
            ),
        )
    )
    if result.findings:
        lines.extend(("", render_findings(result.findings)))
    return "\n".join(lines)


def evidence_collection_payload(result: CorrelatedEvidenceResult) -> dict[str, object]:
    """Return the JSON-ready payload for one host evidence collection result."""
    host_summary = summarize_hosts(
        Scan(source="correlated evidence", hosts=(result.host,)),
        result.findings,
    )[0]
    return {
        "host": result.host.address,
        "status": "complete" if result.collection_complete else "partial",
        "failures": [
            outcome.failure_message
            for outcome in result.failed_outcomes
        ],
        "host_summary": asdict(host_summary),
        "findings": [asdict(finding) for finding in prioritize_findings(result.findings)],
    }


def render_evidence_collection_json(result: CorrelatedEvidenceResult) -> str:
    """Render host-scoped evidence collection status as JSON."""
    return json.dumps(evidence_collection_payload(result), indent=2)


def render_evidence_collections_json(
    results: tuple[CorrelatedEvidenceResult, ...],
) -> str:
    """Render multi-host evidence collection results as one valid JSON document."""
    return json.dumps(
        [evidence_collection_payload(result) for result in results],
        indent=2,
    )


def render_evidence_collection_error_json(
    results: tuple[CorrelatedEvidenceResult, ...],
    error: str,
) -> str:
    """Render completed host results plus a collection error as valid JSON."""
    return json.dumps(
        {
            "results": [evidence_collection_payload(result) for result in results],
            "error": error,
        },
        indent=2,
    )


def prioritize_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Return findings in deterministic analyst-attention order."""
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                _SEVERITY_PRIORITY.get(finding.severity.lower(), 5),
                finding.host,
                finding.port if finding.port is not None else -1,
                finding.finding_id,
            ),
        )
    )


def _service_label(port: Port) -> str:
    parts = [
        value.strip()
        for value in (port.product, port.version, port.extra_info)
        if value and value.strip()
    ]
    detected = " ".join(parts)
    service = (
        port.service.strip().lower()
        if port.service and port.service.strip()
        else "unknown"
    )
    return f"{service} - {detected}" if detected else service


def _host_lines(host: Host) -> list[str]:
    label = host.hostname or host.address
    lines = [f"{label} [{host.address}] ({host.status.strip().lower()})"]

    if len(host.addresses) > 1:
        secondary = [
            f"{kind}:{address}"
            for address, kind in host.addresses
            if address != host.address
        ]
        if secondary:
            lines.append(f"  Addresses: {', '.join(secondary)}")

    if len(host.hostnames) > 1:
        lines.append(f"  Names: {', '.join(host.hostnames)}")

    if not host.ports:
        lines.append("  No ports reported")
    else:
        for port in host.ports:
            line = (
                f"  {port.port}/{port.protocol.strip().lower():<3} "
                f"{port.state.strip().lower():<12} {_service_label(port)}"
            )
            if port.tunnel and port.tunnel.strip():
                line += f" [tunnel:{port.tunnel.strip().lower()}]"
            if port.confidence is not None:
                line += f" [confidence:{port.confidence}]"
            lines.append(line)

            for script in port.scripts:
                output = " ".join(script.output.split())
                lines.append(f"    script {script.script_id}: {output}")

    for script in host.scripts:
        output = " ".join(script.output.split())
        lines.append(f"  host-script {script.script_id}: {output}")

    return lines


def render_text(scan: Scan) -> str:
    """Render a deterministic analyst-friendly text summary."""
    lines = ["NetRecon", "=" * 8, f"Source: {scan.source}"]

    scanner = scan.scanner or "unknown"
    if scan.scanner_version:
        scanner += f" {scan.scanner_version}"
    lines.append(f"Scanner: {scanner}")

    if scan.arguments:
        lines.append(f"Arguments: {scan.arguments}")
    if scan.elapsed is not None:
        lines.append(f"Elapsed: {scan.elapsed:.2f}s")

    reported = len(scan.hosts)
    if scan.hosts_total is not None:
        lines.append(
            f"Hosts: {reported} parsed / {scan.hosts_total} total "
            f"({scan.hosts_up or 0} up, {scan.hosts_down or 0} down)"
        )
    else:
        lines.append(f"Hosts: {reported}")

    summary = summarize_network(scan)
    lines.append(
        f"Network Summary: {summary.up_hosts} up, "
        f"{summary.open_ports} open ports, "
        f"{len(summary.unique_services)} unique services"
    )
    if summary.service_counts:
        services = ", ".join(
            f"{service} ({count})" for service, count in summary.service_counts
        )
        lines.append(f"Open Services: {services}")

    shared_services = summarize_shared_services(scan)
    if shared_services:
        lines.extend(["", "Shared Services", "---------------"])
        for shared in shared_services:
            lines.append(f"{shared.service}: {shared.host_count} hosts")
            for endpoint in shared.endpoints:
                details = " ".join(
                    value.strip()
                    for value in (endpoint.product, endpoint.version, endpoint.extra_info)
                    if value and value.strip()
                )
                suffix = f"  {details}" if details else ""
                lines.append(
                    f"  {endpoint.host}:{endpoint.port}/{endpoint.protocol}{suffix}"
                )

    for host in scan.hosts:
        lines.append("")
        lines.extend(_host_lines(host))

    return "\n".join(lines)



def render_host_summaries(scan: Scan, findings: tuple[Finding, ...]) -> str:
    """Render descriptive per-host analysis summaries without assigning risk scores."""
    summaries = summarize_hosts(scan, findings)
    lines = ["Host Summary", "------------"]
    for summary in summaries:
        services = ", ".join(summary.services) if summary.services else "no open services"
        lines.append(
            f"{summary.host} — {summary.open_ports} open ports — "
            f"{services} — {summary.findings} findings"
        )
        severity = (
            ", ".join(f"{name}={count}" for name, count in summary.severity_counts)
            if summary.severity_counts
            else "none"
        )
        lines.append(f"  Severity: {severity}")
    return "\n".join(lines)

def render_json(scan: Scan) -> str:
    """Render the complete parsed scan as stable, machine-readable JSON."""
    return json.dumps(asdict(scan), indent=2, ensure_ascii=False)


def render_analysis_json(scan: Scan, findings: tuple[Finding, ...]) -> str:
    """Render parsed scan data and findings in one machine-readable envelope."""
    payload = {
        "scan": asdict(scan),
        "summary": asdict(summarize_network(scan)),
        "analysis_summary": asdict(summarize_analysis(findings)),
        "shared_services": [asdict(service) for service in summarize_shared_services(scan)],
        "host_summaries": [asdict(summary) for summary in summarize_hosts(scan, findings)],
        "findings": [asdict(finding) for finding in prioritize_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)



def _change_summary(changes: tuple[ExposureChange | FindingChange, ...]) -> dict[str, int]:
    """Count changes by semantic change label in deterministic order."""
    counts: dict[str, int] = {}
    for change in changes:
        counts[change.change] = counts.get(change.change, 0) + 1
    return dict(sorted(counts.items()))


def _coverage_payload(scan: Scan) -> list[dict[str, str]]:
    """Return Nmap-reported scan coverage without inferring unreported scope."""
    return [asdict(scope) for scope in scan.scan_scopes]


def _coverage_text(scan: Scan) -> str:
    if not scan.scan_scopes:
        return "unknown"

    expanded = _expanded_coverage(scan)
    if len(expanded) > _COVERAGE_TEXT_DETAIL_LIMIT:
        protocols = sorted({protocol for protocol, _ in expanded})
        protocol_text = ",".join(protocols) or "unknown"
        return f"{len(expanded)} ports ({protocol_text}; details: --format json)"

    return "; ".join(
        f"{scope.protocol}:{scope.services}" for scope in scan.scan_scopes
    )


def _coverage_changed(before_scan: Scan, after_scan: Scan) -> bool:
    """Return whether the effective numeric protocol/port coverage differs."""
    return _expanded_coverage(before_scan) != _expanded_coverage(after_scan)


def _expanded_coverage(scan: Scan) -> set[tuple[str, int]]:
    """Expand numeric Nmap scan scopes into protocol/port pairs."""
    covered: set[tuple[str, int]] = set()
    for scope in scan.scan_scopes:
        protocol = scope.protocol.lower()
        for part in scope.services.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    start_text, end_text = part.split("-", 1)
                    start, end = int(start_text), int(end_text)
                    covered.update((protocol, port) for port in range(start, end + 1))
                else:
                    covered.add((protocol, int(part)))
            except ValueError:
                continue
    return covered


def _coverage_difference(before_scan: Scan, after_scan: Scan) -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    """Return newly scanned and no-longer-scanned protocol/port pairs."""
    before = _expanded_coverage(before_scan)
    after = _expanded_coverage(after_scan)
    return tuple(sorted(after - before)), tuple(sorted(before - after))


def _coverage_ports_text(items: tuple[tuple[str, int], ...]) -> str:
    """Render protocol/port coverage compactly by collapsing consecutive ports."""
    if not items:
        return "none"

    grouped: dict[str, list[int]] = {}
    for protocol, port in items:
        grouped.setdefault(protocol, []).append(port)

    parts: list[str] = []
    for protocol in sorted(grouped):
        ports = sorted(set(grouped[protocol]))
        start = previous = ports[0]
        for port in ports[1:]:
            if port == previous + 1:
                previous = port
                continue
            parts.append(
                f"{protocol}/{start}" if start == previous else f"{protocol}/{start}-{previous}"
            )
            start = previous = port
        parts.append(
            f"{protocol}/{start}" if start == previous else f"{protocol}/{start}-{previous}"
        )

    return ", ".join(parts)


_COVERAGE_TEXT_DETAIL_LIMIT = 50


def _coverage_difference_text(items: tuple[tuple[str, int], ...]) -> str:
    """Keep terminal coverage differences readable while preserving detail in JSON."""
    if len(items) > _COVERAGE_TEXT_DETAIL_LIMIT:
        return f"{len(items)} ports (details: --format json)"
    return _coverage_ports_text(items)


def render_diff_json(changes: tuple[ExposureChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render exposure changes as stable, machine-readable JSON."""
    payload = {
        "change_type": "exposure",
        "summary": _change_summary(changes),
        "changes": [asdict(change) for change in changes],
    }
    if before_scan is not None and after_scan is not None:
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        payload["coverage"] = {
            "changed": _coverage_changed(before_scan, after_scan),
            "before": _coverage_payload(before_scan),
            "after": _coverage_payload(after_scan),
            "newly_scanned": [f"{protocol}/{port}" for protocol, port in newly_scanned],
            "no_longer_scanned": [f"{protocol}/{port}" for protocol, port in no_longer_scanned],
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_analysis_diff_json(changes: tuple[FindingChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render finding changes as stable, machine-readable JSON."""
    payload = {
        "change_type": "analysis",
        "summary": _change_summary(changes),
        "changes": [
            {
                "change": change.change,
                "finding": asdict(change.finding),
                **({"before_evidence": change.before_evidence} if change.before_evidence is not None else {}),
            }
            for change in changes
        ],
    }
    if before_scan is not None and after_scan is not None:
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        payload["coverage"] = {
            "changed": _coverage_changed(before_scan, after_scan),
            "before": _coverage_payload(before_scan),
            "after": _coverage_payload(after_scan),
            "newly_scanned": [f"{protocol}/{port}" for protocol, port in newly_scanned],
            "no_longer_scanned": [f"{protocol}/{port}" for protocol, port in no_longer_scanned],
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_combined_diff(
    exposure_changes: tuple[ExposureChange, ...],
    analysis_changes: tuple[FindingChange, ...],
    before_scan: Scan,
    after_scan: Scan,
) -> str:
    """Render exposure and analysis changes as one analyst workflow."""
    return "\n\n".join((
        render_diff(exposure_changes, before_scan, after_scan),
        render_analysis_diff(analysis_changes, before_scan, after_scan),
    ))


def render_combined_diff_json(
    exposure_changes: tuple[ExposureChange, ...],
    analysis_changes: tuple[FindingChange, ...],
    before_scan: Scan,
    after_scan: Scan,
) -> str:
    """Render exposure and analysis changes in one machine-readable envelope."""
    return json.dumps(
        {
            "change_type": "combined",
            "exposure": json.loads(render_diff_json(exposure_changes, before_scan, after_scan)),
            "analysis": json.loads(render_analysis_diff_json(analysis_changes, before_scan, after_scan)),
        },
        indent=2,
        ensure_ascii=False,
    )


def render_findings(findings: tuple[Finding, ...]) -> str:
    """Render analysis findings separately from raw scan observations."""
    if not findings:
        return "Findings: none"

    ordered_findings = prioritize_findings(findings)
    lines = [f"Findings: {len(ordered_findings)}"]
    for finding in ordered_findings:
        location = finding.host
        if finding.port is not None:
            location += f":{finding.port}/{finding.protocol or 'unknown'}"
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.title}",
                f"  Location: {location}",
                f"  Evidence: {finding.evidence}",
                f"  Recommendation: {finding.recommendation}",
            ]
        )
    return "\n".join(lines)


def render_diff(changes: tuple[ExposureChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render scan-to-scan exposure changes for analyst review."""
    if not changes:
        if before_scan is None or after_scan is None:
            return "Exposure Changes: none"
        return "\n".join([
            "Exposure Changes",
            "----------------",
            "Summary: none",
            f"Before Coverage: {_coverage_text(before_scan)}",
            f"After Coverage:  {_coverage_text(after_scan)}",
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}",
            f"Newly Scanned: {_coverage_difference_text(_coverage_difference(before_scan, after_scan)[0])}",
            f"No Longer Scanned: {_coverage_difference_text(_coverage_difference(before_scan, after_scan)[1])}",
            "Changes: none",
        ])

    summary = _change_summary(changes)
    summary_text = ", ".join(f"{key.upper()}={value}" for key, value in summary.items())
    lines = ["Exposure Changes", "----------------", f"Summary: {summary_text}"]
    if before_scan is not None and after_scan is not None:
        lines.append(f"Before Coverage: {_coverage_text(before_scan)}")
        lines.append(f"After Coverage:  {_coverage_text(after_scan)}")
        lines.append(
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}"
        )
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        lines.append(f"Newly Scanned: {_coverage_difference_text(newly_scanned)}")
        lines.append(f"No Longer Scanned: {_coverage_difference_text(no_longer_scanned)}")
    for change in changes:
        if change.change == "host_not_observed":
            lines.append(f"HOST_NOT_OBSERVED {change.host}")
            continue
        if change.change == "host_newly_observed":
            lines.append(f"HOST_NEWLY_OBSERVED {change.host}")
            continue
        if change.change == "host_down":
            lines.append(f"HOST_DOWN {change.host}")
            continue
        if change.change == "host_up":
            lines.append(f"HOST_UP {change.host}")
            continue

        location = f"{change.host}:{change.port}/{change.protocol}"
        if change.change == "new":
            details = " ".join(
                value
                for value in (
                    change.after_service,
                    change.after_product,
                    change.after_version,
                )
                if value
            )
            lines.append(f"NEW     {location}  {details}".rstrip())
        elif change.change == "no_longer_open":
            details = " ".join(
                value
                for value in (
                    change.before_service,
                    change.before_product,
                    change.before_version,
                )
                if value
            )
            lines.append(f"NO_LONGER_OPEN {location}  {details}".rstrip())
        else:
            before = " ".join(
                value
                for value in (
                    change.before_service,
                    change.before_product,
                    change.before_version,
                )
                if value
            ) or "unknown"
            after = " ".join(
                value
                for value in (
                    change.after_service,
                    change.after_product,
                    change.after_version,
                )
                if value
            ) or "unknown"
            lines.append(f"CHANGED {location}  {before} -> {after}")
    return "\n".join(lines)


def render_analysis_diff(changes: tuple[FindingChange, ...], before_scan: Scan | None = None, after_scan: Scan | None = None) -> str:
    """Render finding changes between two analyzed scans."""
    if not changes:
        if before_scan is None or after_scan is None:
            return "Analysis Changes: none"
        return "\n".join([
            "Analysis Changes",
            "----------------",
            "Summary: none",
            f"Before Coverage: {_coverage_text(before_scan)}",
            f"After Coverage:  {_coverage_text(after_scan)}",
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}",
            f"Newly Scanned: {_coverage_difference_text(_coverage_difference(before_scan, after_scan)[0])}",
            f"No Longer Scanned: {_coverage_difference_text(_coverage_difference(before_scan, after_scan)[1])}",
            "Changes: none",
        ])

    summary = _change_summary(changes)
    summary_text = ", ".join(f"{key.upper()}={value}" for key, value in summary.items())
    lines = ["Analysis Changes", "----------------", f"Summary: {summary_text}"]
    if before_scan is not None and after_scan is not None:
        lines.append(f"Before Coverage: {_coverage_text(before_scan)}")
        lines.append(f"After Coverage:  {_coverage_text(after_scan)}")
        lines.append(
            f"Coverage Changed: {'YES' if _coverage_changed(before_scan, after_scan) else 'NO'}"
        )
        newly_scanned, no_longer_scanned = _coverage_difference(before_scan, after_scan)
        lines.append(f"Newly Scanned: {_coverage_difference_text(newly_scanned)}")
        lines.append(f"No Longer Scanned: {_coverage_difference_text(no_longer_scanned)}")
    for change in changes:
        finding = change.finding
        location = finding.host
        if finding.port is not None:
            location += f":{finding.port}/{finding.protocol or 'unknown'}"
        lines.append(
            f"{change.change.upper():8} [{finding.severity.upper()}] "
            f"{location}  {finding.title}"
        )
        if change.before_evidence is not None:
            lines.append(f"  Before Evidence: {change.before_evidence}")
            lines.append(f"  After Evidence:  {finding.evidence}")
        else:
            lines.append(f"  Evidence: {finding.evidence}")

    return "\n".join(lines)



def render_evidence_action_plan(actions: tuple[EvidenceAction, ...]) -> str:
    """Render transparent evidence collection actions for analyst review."""
    lines = [
        "Evidence Action Plan",
        "--------------------",
        f"Actions: {len(actions)}",
    ]
    for action in actions:
        lines.append(f"{action.host}:{action.port}/{action.protocol}")
        for purpose in action.purposes:
            lines.append(f"  Purpose: {purpose}")
        lines.append(f"  Suggested collection: {' '.join(action.command)}")
    return "\n".join(lines)


def render_evidence_action_plan_json(actions: tuple[EvidenceAction, ...]) -> str:
    """Render evidence collection actions as structured JSON."""
    return json.dumps(
        {
            "report_type": "evidence_action_plan",
            "summary": {"actions": len(actions)},
            "actions": [asdict(action) for action in actions],
        },
        indent=2,
        ensure_ascii=False,
    )



def render_discovery_plan(plan: DiscoveryPlan) -> str:
    """Render one transparent discovery plan for analyst review."""
    return "\n".join(
        (
            "Discovery Plan",
            "--------------",
            f"Target: {plan.target}",
            f"Profile: {plan.profile}",
            f"Purpose: {plan.purpose}",
            f"Suggested discovery: {' '.join(plan.command)}",
        )
    )


def render_discovery_plan_json(plan: DiscoveryPlan) -> str:
    """Render one discovery plan as structured JSON with exact argv."""
    return json.dumps(
        {
            "report_type": "discovery_plan",
            "target": plan.target,
            "profile": plan.profile,
            "purpose": plan.purpose,
            "command": plan.command,
        },
        indent=2,
        ensure_ascii=False,
    )



def render_discovery_execution(result: DiscoveryResult) -> str:
    """Render one verified discovery execution with explicit provenance."""
    execution = result.execution
    lines = [
        "Discovery Execution",
        "-------------------",
        f"Status: {'success' if result.success else 'failed'}",
        f"Target: {execution.plan.target}",
        f"Profile: {execution.plan.profile}",
        f"Command: {' '.join(execution.plan.command)}",
    ]
    if result.success and result.scan is not None:
        lines.extend(("", render_text(result.scan)))
    else:
        lines.append(f"Error: {result.error or 'unknown discovery failure'}")
    return "\n".join(lines)


def render_discovery_execution_json(result: DiscoveryResult) -> str:
    """Render one discovery execution as structured JSON with provenance."""
    execution = result.execution
    scan_payload = json.loads(render_json(result.scan)) if result.scan is not None else None
    return json.dumps(
        {
            "report_type": "discovery_execution",
            "status": "success" if result.success else "failed",
            "target": execution.plan.target,
            "profile": execution.plan.profile,
            "purpose": execution.plan.purpose,
            "command": execution.plan.command,
            "returncode": execution.returncode,
            "timed_out": execution.timed_out,
            "error": result.error,
            "scan": scan_payload,
        },
        indent=2,
        ensure_ascii=False,
    )



def render_investigation_continuation(result, decision=None, alternative_round=None, final_decision=None, attention=None, correlations=None, final_snapshot=None) -> str:
    """Render collection execution separately from requested-evidence completeness."""
    lines = [
        "Investigation Continuation",
        "--------------------------",
        "Evidence Collection Outcomes",
    ]
    if not result.outcomes:
        lines.append("None")

    remaining = {
        (gap.host, gap.port, gap.protocol, gap.script_id)
        for gap in result.snapshot.gaps
    }

    for outcome in result.outcomes:
        collection = outcome.result
        arguments = collection.command.arguments
        lines.append(f"Command: {' '.join(arguments)}")
        collection_status = "success" if outcome.scan is not None else "failed"
        lines.append(f"Collection Status: {collection_status}")

        missing_scripts = []
        for action in result.snapshot.actions:
            if action.command == arguments:
                missing_scripts.extend(
                    script_id
                    for script_id in action.script_ids
                    if (action.host, action.port, action.protocol, script_id) in remaining
                )

        if missing_scripts:
            lines.append("Requested Evidence: incomplete")
            lines.append(f"Missing Evidence: {', '.join(missing_scripts)}")
        elif outcome.scan is not None:
            lines.append("Requested Evidence: observed")
        else:
            lines.append("Requested Evidence: not observed")

        lines.append(f"Return Code: {collection.returncode}")
        if outcome.failure_message is not None:
            lines.append(f"Failure: {outcome.failure_message}")

    if decision is not None:
        lines.append("")
        lines.append("Continuation Decision")
        lines.append("---------------------")
        lines.append(f"Status: {decision.status}")
        if decision.stall_reason is not None:
            lines.append(f"Stall Reason: {decision.stall_reason}")
        lines.append(f"Resolved Gaps: {len(decision.resolved_gaps)}")
        lines.append(f"Resolved Requirements: {len(decision.resolved_requirements)}")
        for state in decision.resolved_requirements:
            requirement = state.requirement
            lines.append(
                f"Resolved: {state.host}:{state.port}/{state.protocol}  "
                f"{requirement.requirement_id} — {requirement.purpose}"
            )
        lines.append(f"Remaining Gaps: {len(decision.remaining_gaps)}")
        lines.append(f"Next Actions: {len(decision.next_actions)}")
        lines.append(f"Repeat-Blocked Actions: {len(decision.repeat_blocked_actions)}")
        lines.append(f"Alternative Actions: {len(decision.alternative_actions)}")
        for action in decision.alternative_actions:
            lines.append("Alternative: " + " ".join(action.command))

    if decision is not None and final_decision is not None:
        lines.append("")
        lines.append("Semantic Requirement Progress")
        lines.append("-----------------------------")
        lines.append(f"Resolved by Primary: {len(decision.resolved_requirements)}")
        lines.append(
            f"Satisfied by Alternative: {len(final_decision.satisfied_requirements)}"
        )
        lines.append(f"Remaining: {len(final_decision.remaining_requirements)}")

    if alternative_round is not None:
        lines.append("")
        lines.append("Alternative Evidence Round")
        lines.append("--------------------------")
        for verification in alternative_round.verifications:
            lines.append("Command: " + " ".join(verification.action.command))
            lines.append(f"Verification: {verification.status}")
            if verification.observed_script_ids:
                lines.append("Observed Evidence: " + ", ".join(verification.observed_script_ids))

    if final_decision is not None:
        lines.append("")
        lines.append("Final Investigation Decision")
        lines.append("----------------------------")
        lines.append(f"Status: {final_decision.status}")
        lines.append(f"Reason: {final_decision.reason}")
        lines.append(f"Remaining Gaps: {len(final_decision.remaining_gaps)}")
        lines.append(f"Further Supported Actions: {len(final_decision.further_actions)}")
        lines.append(f"Satisfied Requirements: {len(final_decision.satisfied_requirements)}")
        for state in final_decision.satisfied_requirements:
            requirement = state.requirement
            lines.append(
                f"Satisfied: {state.host}:{state.port}/{state.protocol}  "
                f"{requirement.requirement_id} — {requirement.purpose}"
            )
        lines.append(f"Remaining Requirements: {len(final_decision.remaining_requirements)}")
        for state in final_decision.remaining_requirements:
            requirement = state.requirement
            lines.append(
                f"Requirement: {state.host}:{state.port}/{state.protocol}  "
                f"{requirement.requirement_id} — {requirement.purpose}"
            )

    lines.append("")
    lines.append(render_investigation_snapshot(
        final_snapshot
        if final_snapshot is not None
        else (alternative_round.snapshot if alternative_round is not None else result.snapshot)
    ))
    if attention is not None:
        lines.append("")
        lines.append(render_analyst_attention(attention))
    if correlations is not None:
        lines.append("")
        lines.append(render_analyst_attention_correlations(correlations))
    return "\n".join(lines)



def render_dynamic_evidence_round(result) -> str:
    """Render provenance for one bounded adaptive Continue evidence round."""
    lines = [
        "Dynamic Evidence Round",
        "----------------------",
    ]
    if not result.outcomes and not result.finding_requirement_verifications:
        lines.append("None")
        return "\n".join(lines)

    for outcome in result.outcomes:
        collection = outcome.result
        lines.append("Command: " + " ".join(collection.command.arguments))
        lines.append(
            "Collection Status: " + ("success" if outcome.scan is not None else "failed")
        )
        lines.append(f"Return Code: {collection.returncode}")
        if outcome.failure_message is not None:
            lines.append(f"Failure: {outcome.failure_message}")

    for verification in result.finding_requirement_verifications:
        requirement = verification.requirement
        lines.append(
            f"Requirement: {requirement.requirement_id} — {verification.status}"
        )
        if verification.observed_script_ids:
            lines.append(
                "Observed Evidence: " + ", ".join(verification.observed_script_ids)
            )
        elif verification.status == "unsatisfied":
            lines.append("Outcome: requested evidence was not observed")
            lines.append("Next Step: no automatic retry or unsupported alternative")
    return "\n".join(lines)



def render_dynamic_evidence_rounds(results) -> str:
    """Render ordered provenance for all bounded adaptive Continue rounds."""
    rounds = tuple(results)
    lines = [
        "Dynamic Evidence Rounds",
        "-----------------------",
    ]
    if not rounds:
        lines.append("None")
        return "\n".join(lines)

    for index, result in enumerate(rounds, start=1):
        lines.append(f"Round {index}")
        rendered = render_dynamic_evidence_round(result).splitlines()
        lines.extend(rendered[2:])
        if index != len(rounds):
            lines.append("")
    return "\n".join(lines)


def render_dynamic_evidence_rounds_json(results) -> list[dict]:
    """Return ordered machine-readable provenance for adaptive Continue rounds."""
    rendered = []
    for index, result in enumerate(results, start=1):
        rendered.append(
            {
                "round": index,
                "collection_outcomes": [
                    {
                        "argv": list(outcome.result.command.arguments),
                        "collection_status": "success" if outcome.scan is not None else "failed",
                        "returncode": outcome.result.returncode,
                        "failure": outcome.failure_message,
                    }
                    for outcome in result.outcomes
                ],
                "finding_requirement_verifications": [
                    {
                        "requirement_id": verification.requirement.requirement_id,
                        "status": verification.status,
                        "observed_script_ids": list(verification.observed_script_ids),
                    }
                    for verification in result.finding_requirement_verifications
                ],
            }
        )
    return rendered


def _investigation_continuation_outcomes(result):
    remaining = {
        (gap.host, gap.port, gap.protocol, gap.script_id)
        for gap in result.snapshot.gaps
    }
    rendered = []
    for outcome in result.outcomes:
        collection = outcome.result
        arguments = collection.command.arguments
        missing_scripts = []
        for action in result.snapshot.actions:
            if action.command == arguments:
                missing_scripts.extend(
                    script_id
                    for script_id in action.script_ids
                    if (action.host, action.port, action.protocol, script_id) in remaining
                )
        if missing_scripts:
            requested_evidence = "incomplete"
        elif outcome.scan is not None:
            requested_evidence = "observed"
        else:
            requested_evidence = "not observed"
        rendered.append(
            {
                "argv": list(arguments),
                "collection_status": "success" if outcome.scan is not None else "failed",
                "requested_evidence": requested_evidence,
                "missing_evidence": missing_scripts,
                "returncode": collection.returncode,
                "failure": outcome.failure_message,
            }
        )
    return rendered


def render_investigation_continuation_json(result, decision=None, alternative_round=None, final_decision=None, attention=None, correlations=None, final_snapshot=None) -> str:
    """Render continuation provenance and updated investigation as JSON."""
    rendered_snapshot = (
        final_snapshot
        if final_snapshot is not None
        else (alternative_round.snapshot if alternative_round is not None else result.snapshot)
    )
    updated = json.loads(render_investigation_snapshot_json(rendered_snapshot))
    payload = {
        "report_type": "investigation_continuation",
        "collection_outcomes": _investigation_continuation_outcomes(result),
        "updated_investigation": updated,
    }
    if alternative_round is not None:
        payload["alternative_evidence_round"] = [
            {
                "status": verification.status,
                "observed_script_ids": list(verification.observed_script_ids),
                "command": list(verification.action.command),
            }
            for verification in alternative_round.verifications
        ]
    if final_decision is not None:
        payload["final_investigation_decision"] = {
            "status": final_decision.status,
            "reason": final_decision.reason,
            "remaining_gaps": len(final_decision.remaining_gaps),
            "further_supported_actions": len(final_decision.further_actions),
            "satisfied_requirements": [
                {
                    "host": state.host,
                    "port": state.port,
                    "protocol": state.protocol,
                    "requirement_id": state.requirement.requirement_id,
                    "purpose": state.requirement.purpose,
                    "primary_script_ids": list(state.requirement.primary_script_ids),
                    "alternative_script_ids": list(state.requirement.alternative_script_ids),
                }
                for state in final_decision.satisfied_requirements
            ],
            "remaining_requirements": [
                {
                    "host": state.host,
                    "port": state.port,
                    "protocol": state.protocol,
                    "requirement_id": state.requirement.requirement_id,
                    "purpose": state.requirement.purpose,
                    "primary_script_ids": list(state.requirement.primary_script_ids),
                    "alternative_script_ids": list(state.requirement.alternative_script_ids),
                }
                for state in final_decision.remaining_requirements
            ],
        }
    if decision is not None and final_decision is not None:
        payload["semantic_requirement_progress"] = {
            "resolved_by_primary": len(decision.resolved_requirements),
            "satisfied_by_alternative": len(final_decision.satisfied_requirements),
            "remaining": len(final_decision.remaining_requirements),
        }
    if attention is not None:
        payload["analyst_attention"] = json.loads(render_analyst_attention_json(attention))
    if correlations is not None:
        payload["correlated_review"] = json.loads(
            render_analyst_attention_correlations_json(correlations)
        )
    if decision is not None:
        payload["continuation_decision"] = {
            "status": decision.status,
            "stall_reason": decision.stall_reason,
            "resolved_gaps": len(decision.resolved_gaps),
            "resolved_requirements": [
                {
                    "host": state.host,
                    "port": state.port,
                    "protocol": state.protocol,
                    "requirement_id": state.requirement.requirement_id,
                    "purpose": state.requirement.purpose,
                    "primary_script_ids": list(state.requirement.primary_script_ids),
                    "alternative_script_ids": list(state.requirement.alternative_script_ids),
                }
                for state in decision.resolved_requirements
            ],
            "remaining_gaps": len(decision.remaining_gaps),
            "next_actions": len(decision.next_actions),
            "repeat_blocked_actions": len(decision.repeat_blocked_actions),
            "alternative_actions": [
                {
                    "host": action.host,
                    "port": action.port,
                    "protocol": action.protocol,
                    "script_ids": list(action.script_ids),
                    "purposes": list(action.purposes),
                    "command": list(action.command),
                }
                for action in decision.alternative_actions
            ],
        }
    return json.dumps(
        payload,
        indent=2,
        ensure_ascii=False,
    )


def render_investigation_snapshot(snapshot: InvestigationSnapshot) -> str:
    """Render the current evidence-aware investigation state for analyst review."""
    lines = [
        "Investigation Snapshot",
        "----------------------",
        f"Status: {'ready' if snapshot.ready else 'blocked'}",
        f"Evidence Gaps: {len(snapshot.gaps)}",
        f"Proposed Actions: {len(snapshot.actions)}",
    ]
    if not snapshot.ready:
        lines.append(f"Error: {snapshot.error or 'unknown investigation failure'}")
        return "\n".join(lines)

    if snapshot.states:
        lines.append("Investigation State")
        for state in snapshot.states:
            lines.append(f"{state.host}:{state.port}/{state.protocol}")
            for fact in state.known:
                lines.append(f"  Known: {fact}")
            for gap in state.unknown:
                lines.append(f"  Unknown: {gap.script_id} — {gap.purpose}")

    for gap in snapshot.gaps:
        lines.append(
            f"Gap: {gap.host}:{gap.port}/{gap.protocol}  {gap.script_id}"
        )
        lines.append(f"  Purpose: {gap.purpose}")

    approval_blocked_plans = tuple(
        plan
        for plan in snapshot.finding_collection_plans
        if (
            not plan.authorization.allowed
            and plan.authorization.reason == "explicit_approval_required"
        )
    )
    for plan in approval_blocked_plans:
        requirement = plan.requirement
        location = (
            f"{requirement.host}:{requirement.port}/{requirement.protocol}"
            if requirement.port is not None and requirement.protocol is not None
            else requirement.host
        )
        lines.append(f"Pending Approval: {location}")
        lines.append(
            f"  Requirement: {requirement.requirement_id} — {requirement.purpose}"
        )
        lines.append(f"  Finding: {requirement.finding_id}")
        if requirement.evidence_source is not None:
            lines.append(f"  Evidence Source: {requirement.evidence_source}")
        if plan.strategy.script_ids:
            lines.append(
                "  Proposed collection: " + ", ".join(plan.strategy.script_ids)
            )
        if plan.strategy.risk_class is not None:
            lines.append(f"  Risk: {plan.strategy.risk_class}")
        lines.append("  Authorization: explicit approval required")

    if snapshot.finding_requirement_states:
        lines.append("Finding Requirement Lifecycle")
        for state in snapshot.finding_requirement_states:
            requirement = state.requirement
            location = (
                f"{requirement.host}:{requirement.port}/{requirement.protocol}"
                if requirement.port is not None and requirement.protocol is not None
                else requirement.host
            )
            lines.append(
                f"Requirement State: {location}  {requirement.requirement_id} — {state.status}"
            )
            lines.append(f"  Purpose: {requirement.purpose}")
            lines.append(f"  Finding: {requirement.finding_id}")
            if requirement.evidence_source is not None:
                lines.append(f"  Evidence Source: {requirement.evidence_source}")
            lines.append(f"  Authorization: {state.authorization_reason}")
            if state.observed_script_ids:
                lines.append(
                    "  Observed Evidence: " + ", ".join(state.observed_script_ids)
                )

    for action in snapshot.actions:
        lines.append(f"Action: {action.host}:{action.port}/{action.protocol}")
        for purpose in action.purposes:
            lines.append(f"  Purpose: {purpose}")
        lines.append(f"  Suggested collection: {' '.join(action.command)}")

    return "\n".join(lines)


def render_investigation_snapshot_json(snapshot: InvestigationSnapshot) -> str:
    """Render an investigation snapshot as a stable machine-readable envelope."""
    return json.dumps(
        {
            "report_type": "investigation_snapshot",
            "status": "ready" if snapshot.ready else "blocked",
            "summary": {
                "evidence_gaps": len(snapshot.gaps),
                "proposed_actions": len(snapshot.actions),
                "investigation_states": len(snapshot.states),
                "pending_approvals": sum(
                    1
                    for plan in snapshot.finding_collection_plans
                    if (
                        not plan.authorization.allowed
                        and plan.authorization.reason == "explicit_approval_required"
                    )
                ),
                "finding_requirement_states": len(snapshot.finding_requirement_states),
            },
            "error": snapshot.error,
            "gaps": [asdict(gap) for gap in snapshot.gaps],
            "states": [asdict(state) for state in snapshot.states],
            "actions": [asdict(action) for action in snapshot.actions],
            "finding_requirement_states": [
                {
                    "host": state.requirement.host,
                    "port": state.requirement.port,
                    "protocol": state.requirement.protocol,
                    "requirement_id": state.requirement.requirement_id,
                    "purpose": state.requirement.purpose,
                    "finding_id": state.requirement.finding_id,
                    "evidence_source": state.requirement.evidence_source,
                    "status": state.status,
                    "authorization_reason": state.authorization_reason,
                    "observed_script_ids": list(state.observed_script_ids),
                }
                for state in snapshot.finding_requirement_states
            ],
            "pending_approvals": [
                {
                    "host": plan.requirement.host,
                    "port": plan.requirement.port,
                    "protocol": plan.requirement.protocol,
                    "requirement_id": plan.requirement.requirement_id,
                    "purpose": plan.requirement.purpose,
                    "finding_id": plan.requirement.finding_id,
                    "evidence_source": plan.requirement.evidence_source,
                    "script_ids": list(plan.strategy.script_ids),
                    "risk_class": plan.strategy.risk_class,
                    "authorization": plan.strategy.authorization,
                    "reason": plan.authorization.reason,
                }
                for plan in snapshot.finding_collection_plans
                if (
                    not plan.authorization.allowed
                    and plan.authorization.reason == "explicit_approval_required"
                )
            ],
        },
        indent=2,
        ensure_ascii=False,
    )
