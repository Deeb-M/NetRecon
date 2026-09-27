"""Descriptive history of observed open network endpoints."""

from __future__ import annotations

from dataclasses import dataclass

from models import Scan
from scan_diff import _host_identity


@dataclass(frozen=True)
class ExposureHistory:
    host: str
    port: int
    protocol: str
    first_seen: int
    last_seen: int
    observations: int


def _scan_timestamp(scan: Scan) -> int:
    """Return the Nmap observation time, failing closed when it is unavailable."""
    if scan.started_at is not None:
        return scan.started_at
    if scan.finished_at is not None:
        return scan.finished_at
    raise ValueError(f"scan timestamp unavailable: {scan.source}")


def summarize_exposure_history(scans: tuple[Scan, ...]) -> tuple[ExposureHistory, ...]:
    """Summarize when open endpoints were actually observed across scans."""
    observations: dict[tuple[str, int, str], list[int]] = {}

    for scan in scans:
        timestamp = _scan_timestamp(scan)
        observed_in_scan: set[tuple[str, int, str]] = set()
        for host in scan.hosts:
            host_identity = _host_identity(host.address)
            for port in host.ports:
                if port.state.strip().lower() != "open":
                    continue
                protocol = port.protocol.strip().lower()
                observed_in_scan.add((host_identity, port.port, protocol))

        for key in observed_in_scan:
            observations.setdefault(key, []).append(timestamp)

    return tuple(
        ExposureHistory(
            host=host,
            port=port,
            protocol=protocol,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            observations=len(timestamps),
        )
        for (host, port, protocol), timestamps in sorted(observations.items())
    )
