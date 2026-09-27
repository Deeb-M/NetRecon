"""Evidence-traceable investigation state derived from discovery and planner gaps."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_gaps import EvidenceGap, summarize_evidence_gaps
from models import Port, Scan


@dataclass(frozen=True)
class EndpointInvestigationState:
    """Known discovery facts and planner-supported unknowns for one open endpoint."""

    host: str
    port: int
    protocol: str
    known: tuple[str, ...]
    unknown: tuple[EvidenceGap, ...]


def _observed_facts(port: Port) -> tuple[str, ...]:
    facts = [f"state={port.state.strip().lower()}"]

    optional = (
        ("service", port.service),
        ("product", port.product),
        ("version", port.version),
    )
    for name, value in optional:
        if value is not None and value.strip():
            normalized = value.strip().lower() if name == "service" else value.strip()
            facts.append(f"{name}={normalized}")

    return tuple(facts)


def summarize_investigation_state(
    scan: Scan,
) -> tuple[EndpointInvestigationState, ...]:
    """Describe observed open endpoints and only planner-supported unknowns."""
    gaps = summarize_evidence_gaps(scan)
    gaps_by_endpoint: dict[tuple[str, int, str], list[EvidenceGap]] = {}
    for gap in gaps:
        key = (gap.host, gap.port, gap.protocol.strip().lower())
        gaps_by_endpoint.setdefault(key, []).append(gap)

    states: list[EndpointInvestigationState] = []
    for host in scan.hosts:
        host_address = host.address.strip()
        for port in host.ports:
            if port.state.strip().lower() != "open":
                continue
            protocol = port.protocol.strip().lower()
            key = (host_address, port.port, protocol)
            states.append(
                EndpointInvestigationState(
                    host=host_address,
                    port=port.port,
                    protocol=protocol,
                    known=_observed_facts(port),
                    unknown=tuple(gaps_by_endpoint.get(key, ())),
                )
            )

    return tuple(states)
