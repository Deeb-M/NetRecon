#!/usr/bin/env python3
"""NetRecon command-line entry point."""

from __future__ import annotations

import math
import argparse
import time
from importlib.metadata import version
from pathlib import Path

from adaptive_investigation import AdaptiveInvestigationPlan, build_adaptive_investigation_plan, select_adaptive_actions
from analysis_diff import compare_findings
from analyzer import analyze_scan
from analyst_attention import build_analyst_attention, correlate_analyst_attention
from evidence_action_plan import build_evidence_action_plan
from evidence_collector import EvidenceCollectionError, collect_correlated_host_evidence
from evidence_gaps import summarize_evidence_gaps
from evidence_planner import plan_host_evidence
from exposure_history import summarize_exposure_history
from finding_history import summarize_finding_history
from investigation_orchestration import assess_final_investigation_decision, assess_final_protocol_investigation_decision, assess_investigation_continuation, build_investigation_attention, build_investigation_snapshot, execute_alternative_evidence_round, execute_approved_evidence_actions, execute_protocol_alternative_round, execute_selected_evidence_actions, finalize_continuation_decision
from investigation_explanation import build_investigation_explanation
from investigation_synthesis import build_investigation_synthesis
from investigation_memory import compare_investigation_syntheses
from investigation_history import (
    InvestigationHistoryRecord,
    append_investigation_history_record,
    latest_investigation_for_target,
    load_investigation_history,
)
from parser import NmapParseError, parse_nmap_xml
from reporter import render_analysis_diff, render_analysis_diff_json, render_analysis_json, render_combined_diff, render_combined_diff_json, render_diff, render_diff_json, render_discovery_execution, render_discovery_execution_json, render_discovery_plan, render_discovery_plan_json, render_evidence_collection, render_evidence_collection_error_json, render_evidence_collections_json, render_evidence_gaps, render_evidence_gaps_json, render_evidence_action_plan, render_evidence_action_plan_json, render_exposure_history, render_exposure_history_json, render_finding_history, render_finding_history_json, render_findings, render_host_summaries, render_json, render_text, render_investigation_snapshot, render_investigation_snapshot_json, render_investigation_continuation, render_investigation_continuation_json, render_analyst_attention, render_analyst_attention_json, render_investigation_explanation, render_investigation_explanation_json, render_investigation_synthesis, render_investigation_synthesis_json, render_investigation_memory, render_investigation_memory_json, render_adaptive_investigation_plan, render_adaptive_investigation_plan_json, render_dynamic_evidence_round, render_dynamic_evidence_rounds, render_dynamic_evidence_rounds_json
from scan_diff import compare_scans
from scan_orchestration import build_baseline_discovery_plan, execute_discovery_plan, interpret_discovery_execution


class AtLeastTwoPaths(argparse.Action):
    """Collect a history scan list while enforcing the CLI minimum."""

    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) < 2:
            parser.error(f"{option_string} requires at least two scan files")
        setattr(namespace, self.dest, values)


def positive_timeout(value: str) -> float:
    """Parse a strictly positive evidence collection timeout."""
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("evidence timeout must be a finite number greater than zero")
    return timeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Analyze Nmap XML and run bounded, evidence-driven investigation workflows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  netrecon examples/sample.xml --analyze
  netrecon examples/before.xml examples/after.xml --combined-diff
  netrecon --investigate <authorized-target>
  netrecon --investigate-collect <authorized-target> --adaptive-plan

See USER_GUIDE.md for workflow guidance, approvals, history, and exit behavior.""",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('netrecon')}",
    )
    inputs = parser.add_argument_group("XML scan inputs")
    inputs.add_argument("scan", nargs="?", type=Path, help="Path to an Nmap XML (-oX) file")
    inputs.add_argument(
        "compare_scan",
        nargs="?",
        type=Path,
        help="Second Nmap XML file used with --diff, --analysis-diff, or --combined-diff",
    )
    output = parser.add_argument_group("output and collection controls")
    output.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    output.add_argument(
        "--evidence-timeout",
        type=positive_timeout,
        default=60.0,
        help="Per-command evidence collection timeout in seconds (default: 60)",
    )
    output.add_argument(
        "--smb-credentials-file",
        type=Path,
        metavar="FILE",
        help="Read authorized SMB NSE credentials from a file instead of command-line secrets",
    )
    investigation_controls = parser.add_argument_group("investigation controls")
    investigation_controls.add_argument(
        "--investigation-history",
        type=Path,
        metavar="FILE",
        help="Persist and compare completed --investigate-collect synthesis records in an append-only JSONL file",
    )
    investigation_controls.add_argument(
        "--adaptive-plan",
        action="store_true",
        help="Show the terminal adaptive decision reached by --investigate-collect",
    )
    investigation_controls.add_argument(
        "--approve-requirement",
        action="append",
        default=[],
        metavar="REQUIREMENT_ID",
        help="Explicitly approve a finding-derived collection requirement during --investigate-collect; repeat for multiple approvals",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--discover",
        metavar="TARGET",
        help="Run the transparent baseline Nmap discovery plan for a target",
    )
    mode.add_argument(
        "--investigate",
        metavar="TARGET",
        help="Run baseline discovery and show planner-supported next evidence actions",
    )
    mode.add_argument(
        "--investigate-collect",
        metavar="TARGET",
        help="Run baseline discovery, execute the explicitly planned evidence actions, and re-evaluate the investigation",
    )
    mode.add_argument(
        "--discovery-plan",
        metavar="TARGET",
        help="Show the transparent baseline discovery plan for a target without running Nmap",
    )
    mode.add_argument(
        "--analyze",
        action="store_true",
        help="Add conservative evidence-based findings",
    )
    mode.add_argument(
        "--attention",
        action="store_true",
        help="Show evidence-based findings that warrant analyst review without ranking them",
    )
    mode.add_argument(
        "--diff",
        action="store_true",
        help="Compare two Nmap XML scans and report exposure changes",
    )
    mode.add_argument(
        "--analysis-diff",
        action="store_true",
        help="Compare evidence-based findings between two Nmap XML scans",
    )
    mode.add_argument(
        "--combined-diff",
        action="store_true",
        help="Compare exposure and evidence-based finding changes together",
    )
    mode.add_argument(
        "--collect-evidence",
        action="store_true",
        help="Collect targeted evidence for services already discovered in the input scan",
    )
    mode.add_argument(
        "--evidence-gaps",
        action="store_true",
        help="Show planner-supported evidence that is still missing from the input scan",
    )
    mode.add_argument(
        "--evidence-actions",
        action="store_true",
        help="Show transparent collection actions for planner-supported missing evidence",
    )
    mode.add_argument(
        "--history",
        nargs="+",
        type=Path,
        action=AtLeastTwoPaths,
        metavar="SCAN",
        help="Summarize open-endpoint observations across multiple Nmap XML scans",
    )
    mode.add_argument(
        "--finding-history",
        nargs="+",
        type=Path,
        action=AtLeastTwoPaths,
        metavar="SCAN",
        help="Summarize evidence-backed finding observations across multiple Nmap XML scans",
    )
    return parser


def render_protocol_alternative_progress(protocol_round) -> str:
    """Render protocol-level evidence without rewriting primary NSE provenance."""
    if protocol_round is None:
        return ""

    lines = [
        "Protocol Alternative Evidence",
        "-----------------------------",
        f"Satisfied by Protocol Alternative: {len(protocol_round.satisfied_requirement_ids)}",
    ]
    for requirement_id in protocol_round.satisfied_requirement_ids:
        lines.append(f"Satisfied: {requirement_id}")

    for result in protocol_round.results:
        evidence = result.evidence
        endpoint = f"{result.action.host}:{result.action.port}/{result.action.protocol}"
        lines.append(f"Endpoint: {endpoint}")
        lines.append(f"Anonymous Login: {evidence.anonymous_login}")
        if evidence.syst is not None:
            lines.append(f"SYST: {evidence.syst}")
        if evidence.stat is not None:
            lines.append(f"STAT: {evidence.stat}")

    lines.append(f"Primary NSE Gaps Preserved: {len(protocol_round.snapshot.gaps)}")
    return "\n".join(lines)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.investigation_history is not None and args.investigate_collect is None:
        parser.error("--investigation-history requires --investigate-collect")
    if args.adaptive_plan and args.investigate_collect is None:
        parser.error("--adaptive-plan requires --investigate-collect")
    if args.approve_requirement and args.investigate_collect is None:
        parser.error("--approve-requirement requires --investigate-collect")
    if args.smb_credentials_file is not None and args.investigate_collect is None:
        parser.error("--smb-credentials-file requires --investigate-collect")
    if (
        args.smb_credentials_file is not None
        and "smb_access_control_context" not in args.approve_requirement
    ):
        parser.error(
            "--smb-credentials-file requires explicit approval of "
            "smb_access_control_context"
        )

    approved_requirement_ids = frozenset(args.approve_requirement)

    if args.investigate_collect is not None:
        if args.scan is not None or args.compare_scan is not None:
            parser.error("--investigate-collect does not accept scan files")
        try:
            plan = build_baseline_discovery_plan(args.investigate_collect)
        except ValueError as exc:
            print(f"Error: {exc}")
            return 2
        execution = execute_discovery_plan(plan, timeout=args.evidence_timeout)
        discovery = interpret_discovery_execution(execution)
        snapshot = build_investigation_snapshot(discovery)
        if not snapshot.ready:
            print(
                render_investigation_snapshot_json(snapshot)
                if args.format == "json"
                else render_investigation_snapshot(snapshot)
            )
            return 2
        if approved_requirement_ids:
            continuation = execute_approved_evidence_actions(
                snapshot,
                timeout=args.evidence_timeout,
                explicitly_approved_requirement_ids=approved_requirement_ids,
            )
        else:
            continuation = execute_approved_evidence_actions(
                snapshot,
                timeout=args.evidence_timeout,
            )
        updated = continuation.snapshot
        decision = assess_investigation_continuation(
            snapshot,
            updated,
            attempted_actions=snapshot.actions,
        )
        adaptive_plan = build_adaptive_investigation_plan(decision)
        adaptive_actions = select_adaptive_actions(adaptive_plan)
        dynamic_round = None
        dynamic_rounds = []
        attempted_adaptive_actions: tuple = ()
        max_adaptive_rounds = 8
        adaptive_round_count = 0
        while (
            adaptive_plan.decision == "continue"
            and adaptive_actions
            and adaptive_round_count < max_adaptive_rounds
        ):
            if approved_requirement_ids:
                selected_kwargs = {
                    "timeout": args.evidence_timeout,
                    "explicitly_approved_requirement_ids": approved_requirement_ids,
                }
                if args.smb_credentials_file is not None:
                    selected_kwargs["smb_credentials_file"] = str(
                        args.smb_credentials_file
                    )
                continued = execute_selected_evidence_actions(
                    updated,
                    adaptive_actions,
                    **selected_kwargs,
                )
            else:
                continued = execute_selected_evidence_actions(
                    updated,
                    adaptive_actions,
                    timeout=args.evidence_timeout,
                )
            dynamic_round = continued
            dynamic_rounds.append(continued)
            attempted_adaptive_actions += adaptive_actions
            decision = assess_investigation_continuation(
                updated,
                continued.snapshot,
                attempted_actions=snapshot.actions + attempted_adaptive_actions,
            )
            updated = continued.snapshot
            adaptive_plan = build_adaptive_investigation_plan(decision)
            adaptive_actions = select_adaptive_actions(adaptive_plan)
            adaptive_round_count += 1
        adaptive_stop_reason = None
        if (
            adaptive_round_count >= max_adaptive_rounds
            and adaptive_plan.decision == "continue"
            and adaptive_actions
        ):
            adaptive_stop_reason = "adaptive_round_limit_reached"
            adaptive_plan = AdaptiveInvestigationPlan(
                "stop",
                adaptive_stop_reason,
            )
            adaptive_actions = ()
        final_continuation_decision = decision
        alternative_round = None
        protocol_round = None
        final_decision = None
        if adaptive_plan.decision == "alternative" and adaptive_actions:
            alternative_round = execute_alternative_evidence_round(
                updated,
                adaptive_actions,
                timeout=args.evidence_timeout,
                explicitly_approved_requirement_ids=approved_requirement_ids,
            )
            final_decision = assess_final_investigation_decision(alternative_round)
        elif final_continuation_decision.protocol_alternative_actions:
            protocol_round = execute_protocol_alternative_round(
                updated,
                final_continuation_decision.protocol_alternative_actions,
                timeout=args.evidence_timeout,
            )
            final_decision = assess_final_protocol_investigation_decision(protocol_round)
        elif adaptive_plan.decision == "stop":
            final_decision = finalize_continuation_decision(
                final_continuation_decision,
                stop_reason=adaptive_stop_reason,
            )
        if final_decision is None:
            # Defensive E2E boundary: every completed collect workflow must expose
            # one canonical terminal decision to downstream reporting/synthesis.
            final_decision = finalize_continuation_decision(final_continuation_decision)
        final_snapshot = alternative_round.snapshot if alternative_round is not None else updated
        # Reporting must describe the terminal state, not the pre-execution plan
        # that may already have been consumed by a bounded alternative round.
        reported_adaptive_plan = AdaptiveInvestigationPlan(
            "stop",
            final_decision.reason,
        )
        explanation = build_investigation_explanation(
            final_snapshot,
            final_decision=final_decision,
        )
        attention = build_investigation_attention(final_snapshot)
        correlations = correlate_analyst_attention(attention)
        synthesis = build_investigation_synthesis(
            final_decision, attention, correlations
        )
        investigation_memory = None
        if args.investigation_history is not None:
            history_path = args.investigation_history
            try:
                records = (
                    load_investigation_history(str(history_path))
                    if history_path.exists()
                    else ()
                )
            except (OSError, ValueError) as exc:
                print(f"Error: unable to load investigation history: {exc}")
                return 2
            previous = latest_investigation_for_target(
                records,
                args.investigate_collect,
            )
            if previous is not None:
                investigation_memory = compare_investigation_syntheses(
                    previous.synthesis,
                    synthesis,
                )
            try:
                append_investigation_history_record(
                    str(history_path),
                    InvestigationHistoryRecord(
                        observed_at=int(time.time()),
                        target=args.investigate_collect,
                        synthesis=synthesis,
                    ),
                )
            except OSError as exc:
                print(f"Error: unable to write investigation history: {exc}")
                return 2
        if args.format == "json":
            report = render_investigation_continuation_json(
                continuation, final_continuation_decision, alternative_round, final_decision, attention, correlations,
                final_snapshot=final_snapshot,
            )
            import json
            payload = json.loads(report)
            payload["investigation_explanation"] = json.loads(
                render_investigation_explanation_json(explanation)
            )
            if dynamic_rounds:
                payload["dynamic_evidence_rounds"] = render_dynamic_evidence_rounds_json(
                    dynamic_rounds
                )
            report = json.dumps(payload, indent=2, ensure_ascii=False)
            if args.adaptive_plan:
                import json
                payload = json.loads(report)
                payload["adaptive_investigation_plan"] = json.loads(
                    render_adaptive_investigation_plan_json(reported_adaptive_plan)
                )
                report = json.dumps(payload, indent=2, ensure_ascii=False)
            import json
            payload = json.loads(report)
            payload["investigation_synthesis"] = json.loads(
                render_investigation_synthesis_json(synthesis)
            )
            if investigation_memory is not None:
                payload["investigation_memory"] = json.loads(
                    render_investigation_memory_json(investigation_memory)
                )
            report = json.dumps(payload, indent=2, ensure_ascii=False)
        else:
            report = render_investigation_continuation(
                continuation, final_continuation_decision, alternative_round, final_decision, attention, correlations,
                final_snapshot=final_snapshot,
            )
            if protocol_round is not None:
                report += "\n\n" + render_protocol_alternative_progress(protocol_round)
            report += "\n\n" + render_investigation_explanation(explanation)
            if dynamic_rounds:
                report += "\n\n" + render_dynamic_evidence_rounds(dynamic_rounds)
            if args.adaptive_plan:
                report += "\n\n" + render_adaptive_investigation_plan(reported_adaptive_plan)
            report += "\n\n" + render_investigation_synthesis(synthesis)
            if investigation_memory is not None:
                report += "\n\n" + render_investigation_memory(investigation_memory)
        print(report)
        # A stalled investigation is a valid bounded outcome, not a CLI failure.
        # Non-zero remains reserved for discovery/processing failures handled above.
        return 0

    if args.investigate is not None:
        if args.scan is not None or args.compare_scan is not None:
            parser.error("--investigate does not accept scan files")
        try:
            plan = build_baseline_discovery_plan(args.investigate)
        except ValueError as exc:
            print(f"Error: {exc}")
            return 2
        execution = execute_discovery_plan(plan, timeout=args.evidence_timeout)
        discovery = interpret_discovery_execution(execution)
        snapshot = build_investigation_snapshot(discovery)
        print(
            render_investigation_snapshot_json(snapshot)
            if args.format == "json"
            else render_investigation_snapshot(snapshot)
        )
        return 0 if snapshot.ready else 2

    if args.discover is not None:
        if args.scan is not None or args.compare_scan is not None:
            parser.error("--discover does not accept scan files")
        try:
            plan = build_baseline_discovery_plan(args.discover)
        except ValueError as exc:
            print(f"Error: {exc}")
            return 2
        execution = execute_discovery_plan(plan, timeout=args.evidence_timeout)
        result = interpret_discovery_execution(execution)
        print(
            render_discovery_execution_json(result)
            if args.format == "json"
            else render_discovery_execution(result)
        )
        return 0 if result.success else 2

    if args.discovery_plan is not None:
        if args.scan is not None or args.compare_scan is not None:
            parser.error("--discovery-plan does not accept scan files")
        try:
            plan = build_baseline_discovery_plan(args.discovery_plan)
        except ValueError as exc:
            print(f"Error: {exc}")
            return 2
        print(
            render_discovery_plan_json(plan)
            if args.format == "json"
            else render_discovery_plan(plan)
        )
        return 0

    if args.history is not None:
        if args.scan is not None or args.compare_scan is not None:
            parser.error("--history scan files must be supplied after --history")
        try:
            scans = tuple(parse_nmap_xml(path) for path in args.history)
            history = summarize_exposure_history(scans)
        except (NmapParseError, ValueError) as exc:
            print(f"Error: {exc}")
            return 2
        print(
            render_exposure_history_json(history)
            if args.format == "json"
            else render_exposure_history(history)
        )
        return 0

    if args.finding_history is not None:
        if args.scan is not None or args.compare_scan is not None:
            parser.error("--finding-history scan files must be supplied after --finding-history")
        try:
            scans = tuple(parse_nmap_xml(path) for path in args.finding_history)
            findings_by_scan = tuple(analyze_scan(scan) for scan in scans)
            history = summarize_finding_history(scans, findings_by_scan)
        except (NmapParseError, ValueError) as exc:
            print(f"Error: {exc}")
            return 2
        print(
            render_finding_history_json(history)
            if args.format == "json"
            else render_finding_history(history)
        )
        return 0

    if args.scan is None:
        parser.error("a scan file is required unless --investigate, --investigate-collect, --discover, --discovery-plan, --history, or --finding-history is used")

    if args.compare_scan is not None and not (args.diff or args.analysis_diff or args.combined_diff):
        parser.error("a second scan file requires --diff, --analysis-diff, or --combined-diff")

    try:
        scan = parse_nmap_xml(args.scan)
        compare_scan = parse_nmap_xml(args.compare_scan) if args.compare_scan else None
    except NmapParseError as exc:
        print(f"Error: {exc}")
        return 2

    if args.evidence_gaps:
        gaps = summarize_evidence_gaps(scan)
        print(
            render_evidence_gaps_json(gaps)
            if args.format == "json"
            else render_evidence_gaps(gaps)
        )
        return 0

    if args.evidence_actions:
        actions = build_evidence_action_plan(scan)
        print(
            render_evidence_action_plan_json(actions)
            if args.format == "json"
            else render_evidence_action_plan(actions)
        )
        return 0

    if args.collect_evidence:
        results = []
        try:
            for host in scan.hosts:
                plan = plan_host_evidence(host)
                result = collect_correlated_host_evidence(
                    host,
                    plan,
                    timeout=args.evidence_timeout,
                )
                results.append(result)
                if args.format == "text":
                    print(render_evidence_collection(result))
        except EvidenceCollectionError as exc:
            if args.format == "json":
                print(render_evidence_collection_error_json(tuple(results), str(exc)))
            else:
                print(f"Error: {exc}")
            return 2
        if args.format == "json":
            print(render_evidence_collections_json(tuple(results)))
        return 0

    if args.diff:
        if compare_scan is None:
            print("Error: --diff requires a second scan file")
            return 2
        changes = compare_scans(scan, compare_scan)
        print(
            render_diff_json(changes, scan, compare_scan)
            if args.format == "json"
            else render_diff(changes, scan, compare_scan)
        )
        return 0

    if args.combined_diff:
        if compare_scan is None:
            print("Error: --combined-diff requires a second scan file")
            return 2
        exposure_changes = compare_scans(scan, compare_scan)
        before_findings = analyze_scan(scan)
        after_findings = analyze_scan(compare_scan)
        analysis_changes = compare_findings(before_findings, after_findings, scan, compare_scan)
        print(
            render_combined_diff_json(exposure_changes, analysis_changes, scan, compare_scan)
            if args.format == "json"
            else render_combined_diff(exposure_changes, analysis_changes, scan, compare_scan)
        )
        return 0

    if args.analysis_diff:
        if compare_scan is None:
            print("Error: --analysis-diff requires a second scan file")
            return 2
        before_findings = analyze_scan(scan)
        after_findings = analyze_scan(compare_scan)
        changes = compare_findings(before_findings, after_findings, scan, compare_scan)
        print(
            render_analysis_diff_json(changes, scan, compare_scan)
            if args.format == "json"
            else render_analysis_diff(changes, scan, compare_scan)
        )
        return 0

    if args.attention:
        attention = build_analyst_attention(analyze_scan(scan))
        print(
            render_analyst_attention_json(attention)
            if args.format == "json"
            else render_analyst_attention(attention)
        )
        return 0

    findings = analyze_scan(scan) if args.analyze else ()

    if args.format == "json":
        output = (
            render_analysis_json(scan, findings)
            if args.analyze
            else render_json(scan)
        )
        print(output)
        return 0

    print(render_text(scan))
    if args.analyze:
        print()
        print(render_host_summaries(scan, findings))
        print()
        print(render_findings(findings))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
