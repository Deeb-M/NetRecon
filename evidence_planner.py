"""Plan evidence collection from normalized service discovery."""

from __future__ import annotations

from dataclasses import dataclass

from models import Host


@dataclass(frozen=True)
class EvidenceRequest:
    """One requested NSE evidence collection action for a specific port."""

    port: int
    protocol: str
    script_id: str


def plan_evidence_requests(host: Host) -> tuple[EvidenceRequest, ...]:
    """Return detailed NSE evidence requests for discovered open services."""
    requests: list[EvidenceRequest] = []

    for port in host.ports:
        if port.state.lower() != "open":
            continue

        service = (port.service or "").strip().lower()
        existing_scripts = {
            script.script_id.strip().lower()
            for script in port.scripts
        }

        requested: tuple[str, ...] = ()

        if service == "ssh":
            requested = ("ssh2-enum-algos",)

        if service == "http":
            requested = ("http-title", "http-methods")

        if service == "https":
            requested = (
                "http-title",
                "http-methods",
                "ssl-cert",
                "ssl-enum-ciphers",
            )

        if service in {"microsoft-ds", "smb"} or (
            not service
            and port.port == 445
            and port.protocol.lower() == "tcp"
        ):
            requested = (
                "smb-protocols",
                "smb2-security-mode",
            )

        requests.extend(
            EvidenceRequest(
                port=port.port,
                protocol=port.protocol.lower(),
                script_id=script_id,
            )
            for script_id in requested
            if script_id not in existing_scripts
        )

    return tuple(requests)


def plan_evidence(host: Host) -> tuple[str, ...]:
    """Return NSE script IDs still needed for discovered open services."""
    return tuple(
        request.script_id
        for request in plan_evidence_requests(host)
    )
