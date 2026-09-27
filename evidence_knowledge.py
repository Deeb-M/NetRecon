"""Represent knowledge learned from collected evidence without mutating discovery facts."""

from __future__ import annotations

from dataclasses import dataclass

from models import Scan


@dataclass(frozen=True)
class EvidenceDerivedKnowledge:
    """One normalized fact learned from a specific collected evidence source."""

    host: str
    port: int
    protocol: str
    fact_type: str
    value: str
    evidence_source: str


def derive_evidence_knowledge(scan: Scan) -> tuple[EvidenceDerivedKnowledge, ...]:
    """Project explicit knowledge from observed NSE output with source provenance.

    This layer is intentionally descriptive only. It does not create evidence
    requirements, construct commands, or authorize further collection.
    """
    knowledge: list[EvidenceDerivedKnowledge] = []

    for host in scan.hosts:
        for port in host.ports:
            endpoint = (host.address.strip(), port.port, port.protocol.strip().lower())
            for script in port.scripts:
                script_id = script.script_id.strip().lower()
                output = script.output.strip()
                if not script_id or not output:
                    continue
                knowledge.append(
                    EvidenceDerivedKnowledge(
                        host=endpoint[0],
                        port=endpoint[1],
                        protocol=endpoint[2],
                        fact_type="nse_observation",
                        value=output,
                        evidence_source=f"nse:{script_id}",
                    )
                )

    return tuple(knowledge)
