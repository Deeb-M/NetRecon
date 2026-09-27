#!/usr/bin/env python3
"""NetRecon command-line entry point."""

from __future__ import annotations

import math
import argparse
from importlib.metadata import version
from pathlib import Path

from analysis_diff import compare_findings
from analyzer import analyze_scan
from evidence_action_plan import build_evidence_action_plan
from evidence_collector import EvidenceCollectionError, collect_correlated_host_evidence
from evidence_gaps import summarize_evidence_gaps
from evidence_planner import plan_host_evidence
from exposure_history import summarize_exposure_history
from finding_history import summarize_finding_history
from parser import NmapParseError, parse_nmap_xml
from reporter import render_analysis_diff, render_analysis_diff_json, render_analysis_json, render_combined_diff, render_combined_diff_json, render_diff, render_diff_json, render_discovery_plan, render_discovery_plan_json, render_evidence_collection, render_evidence_collection_error_json, render_evidence_collections_json, render_evidence_gaps, render_evidence_gaps_json, render_evidence_action_plan, render_evidence_action_plan_json, render_exposure_history, render_exposure_history_json, render_finding_history, render_finding_history_json, render_findings, render_host_summaries, render_json, render_text
from scan_diff import compare_scans
from scan_orchestration import build_baseline_discovery_plan


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
        description="Analyze and compare Nmap XML scans with evidence-based findings and exposure summaries.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('netrecon')}",
    )
    parser.add_argument("scan", nargs="?", type=Path, help="Path to an Nmap XML (-oX) file")
    parser.add_argument(
        "compare_scan",
        nargs="?",
        type=Path,
        help="Second Nmap XML file used with --diff, --analysis-diff, or --combined-diff",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--evidence-timeout",
        type=positive_timeout,
        default=60.0,
        help="Per-command evidence collection timeout in seconds (default: 60)",
    )
    mode = parser.add_mutually_exclusive_group()
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


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
        parser.error("a scan file is required unless --discovery-plan, --history, or --finding-history is used")

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
