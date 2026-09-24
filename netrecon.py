#!/usr/bin/env python3
"""NetRecon command-line entry point."""

from __future__ import annotations

import argparse
from pathlib import Path

from analysis_diff import compare_findings
from analyzer import analyze_scan
from parser import NmapParseError, parse_nmap_xml
from reporter import render_analysis_diff, render_analysis_diff_json, render_analysis_json, render_diff, render_diff_json, render_findings, render_json, render_text
from scan_diff import compare_scans


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Parse Nmap XML and summarize discovered hosts, ports, and services.",
    )
    parser.add_argument("scan", type=Path, help="Path to an Nmap XML (-oX) file")
    parser.add_argument("compare_scan", nargs="?", type=Path, help="Second Nmap XML file used with --diff")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    mode = parser.add_mutually_exclusive_group()
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
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.compare_scan is not None and not (args.diff or args.analysis_diff):
        parser.error("a second scan file requires --diff or --analysis-diff")

    try:
        scan = parse_nmap_xml(args.scan)
        compare_scan = parse_nmap_xml(args.compare_scan) if args.compare_scan else None
    except NmapParseError as exc:
        print(f"Error: {exc}")
        return 2

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

    if args.analysis_diff:
        if compare_scan is None:
            print("Error: --analysis-diff requires a second scan file")
            return 2
        before_findings = analyze_scan(scan)
        after_findings = analyze_scan(compare_scan)
        changes = compare_findings(before_findings, after_findings, scan, compare_scan)
        print(render_analysis_diff_json(changes) if args.format == "json" else render_analysis_diff(changes))
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
        print(render_findings(findings))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
