"""Evidence-based analysis of normalized Nmap scan data."""

from __future__ import annotations

from datetime import datetime, timezone

from findings import Finding
from models import Scan
from nse_rules import analyze_nse_scripts
from service_rules import analyze_service_context



def analyze_scan(scan: Scan, *, now: datetime | None = None) -> tuple[Finding, ...]:
    """Return conservative findings that are directly supported by scan evidence."""
    findings: list[Finding] = []
    reference_time = now or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    for host in scan.hosts:
        user_hostnames = tuple(
            name.rstrip(".").lower()
            for name, hostname_type in host.hostname_records
            if hostname_type.lower() == "user"
        )
        findings.extend(analyze_service_context(host))

        findings.extend(
            analyze_nse_scripts(host, user_hostnames, reference_time)
        )


    return tuple(findings)
