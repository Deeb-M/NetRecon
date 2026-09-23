#!/usr/bin/env python3
"""NetRecon command-line entry point."""

from __future__ import annotations

import argparse
from pathlib import Path

from parser import NmapParseError, parse_nmap_xml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Parse Nmap XML and summarize discovered hosts, ports, and services.",
    )
    parser.add_argument("scan", type=Path, help="Path to an Nmap XML (-oX) file")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        scan = parse_nmap_xml(args.scan)
    except NmapParseError as exc:
        print(f"Error: {exc}")
        return 2

    print(f"NetRecon | source: {scan.source}")
    print(f"Hosts: {len(scan.hosts)}")

    for host in scan.hosts:
        label = host.hostname or host.address
        print(f"\n{label} ({host.status})")
        for port in host.ports:
            service = port.service or "unknown"
            version = f" {port.product} {port.version}".strip()
            details = f" - {version}" if version else ""
            print(f"  {port.port}/{port.protocol} {port.state} {service}{details}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
