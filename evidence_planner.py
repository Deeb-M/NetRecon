"""Plan evidence collection from normalized service discovery."""

from __future__ import annotations

from dataclasses import dataclass

from models import Host


SERVICE_EVIDENCE: dict[str, tuple[str, ...]] = {
    "ssh": ("ssh2-enum-algos",),
    "http": ("http-title", "http-methods"),
    "https": (
        "http-title",
        "http-methods",
        "ssl-cert",
        "ssl-enum-ciphers",
    ),
    "microsoft-ds": ("smb-protocols", "smb2-security-mode"),
    "smb": ("smb-protocols", "smb2-security-mode"),
}

SMB_EVIDENCE = SERVICE_EVIDENCE["smb"]


@dataclass(frozen=True)
class EvidenceRequest:
    """One requested NSE evidence collection action for a specific port."""

    port: int
    protocol: str
    script_id: str


@dataclass(frozen=True)
class HostEvidencePlan:
    """Evidence collection plan for one discovered host."""

    target: str
    requests: tuple[EvidenceRequest, ...]


def plan_evidence_requests(host: Host) -> tuple[EvidenceRequest, ...]:
    """Return detailed NSE evidence requests for discovered open services."""
    requests: list[EvidenceRequest] = []

    for port in host.ports:
        if port.state.strip().lower() != "open":
            continue

        service = (port.service or "").strip().lower()
        existing_scripts = {
            script.script_id.strip().lower()
            for script in port.scripts
        }

        requested = SERVICE_EVIDENCE.get(service, ())

        if (
            not service
            and port.port == 445
            and port.protocol.strip().lower() == "tcp"
        ):
            requested = SMB_EVIDENCE

        requests.extend(
            EvidenceRequest(
                port=port.port,
                protocol=port.protocol.strip().lower(),
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


def plan_host_evidence(host: Host) -> HostEvidencePlan:
    """Return a complete evidence collection plan for one host."""
    return HostEvidencePlan(
        target=host.address,
        requests=plan_evidence_requests(host),
    )
