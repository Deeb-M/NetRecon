#!/usr/bin/env python3
"""NetRecon command-line entry point."""

from __future__ import annotations

import argparse
from pathlib import Path

from analyzer import analyze_scan
from parser import NmapParseError, parse_nmap_xml
from reporter import render_findings, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Parse Nmap XML and summarize discovered hosts, ports, and services.",
    )
    parser.add_argument("scan", type=Path, help="Path to an Nmap XML (-oX) file")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Add conservative evidence-based findings",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        scan = parse_nmap_xml(args.scan)
    except NmapParseError as exc:
        print(f"Error: {exc}")
        return 2

    renderer = render_json if args.format == "json" else render_text
    print(renderer(scan))

    if args.analyze:
        if args.format == "json":
            print("Error: --analyze currently supports text output only")
            return 2
        print()
        print(render_findings(analyze_scan(scan)))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
