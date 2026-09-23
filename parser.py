"""Nmap XML parser for NetRecon."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from models import Host, Port, Scan


class NmapParseError(ValueError):
    """Raised when an Nmap XML file cannot be parsed safely."""


def parse_nmap_xml(path: str | Path) -> Scan:
    source = Path(path)

    if not source.is_file():
        raise NmapParseError(f"scan file not found: {source}")

    try:
        root = ET.parse(source).getroot()
    except (ET.ParseError, OSError) as exc:
        raise NmapParseError(f"invalid Nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError("XML root is not <nmaprun>")

    hosts: list[Host] = []

    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        if address_node is None or not address_node.get("addr"):
            continue

        status_node = host_node.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"

        hostname_node = host_node.find("./hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None

        ports: list[Port] = []
        for port_node in host_node.findall("./ports/port"):
            port_id = port_node.get("portid")
            protocol = port_node.get("protocol", "unknown")
            if port_id is None:
                continue

            try:
                port_number = int(port_id)
            except ValueError:
                continue

            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"

            service_node = port_node.find("service")
            ports.append(
                Port(
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service=service_node.get("name") if service_node is not None else None,
                    product=service_node.get("product") if service_node is not None else None,
                    version=service_node.get("version") if service_node is not None else None,
                )
            )

        hosts.append(
            Host(
                address=address_node.get("addr", ""),
                status=status,
                hostname=hostname,
                ports=tuple(ports),
            )
        )

    return Scan(source=str(source), hosts=tuple(hosts))
