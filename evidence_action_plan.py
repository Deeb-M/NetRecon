"""Build transparent analyst-facing collection actions from existing evidence plans."""

from __future__ import annotations

from dataclasses import dataclass

from evidence_collector import build_collection_specs, build_nmap_command
from evidence_gaps import EVIDENCE_PURPOSES
from evidence_planner import plan_host_evidence
from models import Scan


@dataclass(frozen=True)
class EvidenceAction:
    """One transparent collection action proposed for analyst review."""

    host: str
    port: int
    protocol: str
    script_ids: tuple[str, ...]
    purposes: tuple[str, ...]
    command: tuple[str, ...]


def build_evidence_action_plan(scan: Scan) -> tuple[EvidenceAction, ...]:
    """Translate existing planner requests into grouped transparent actions."""
    actions: list[EvidenceAction] = []

    for host in scan.hosts:
        plan = plan_host_evidence(host)
        for spec in build_collection_specs(plan):
            script_ids = tuple(
                script_id
                for script_id in spec.script_ids
                if script_id in EVIDENCE_PURPOSES
            )
            if not script_ids:
                continue

            command = build_nmap_command(spec)
            actions.append(
                EvidenceAction(
                    host=spec.target,
                    port=spec.port,
                    protocol=spec.protocol,
                    script_ids=script_ids,
                    purposes=tuple(
                        EVIDENCE_PURPOSES[script_id]
                        for script_id in script_ids
                    ),
                    command=command.arguments,
                )
            )

    return tuple(actions)
