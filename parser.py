"""Nmap XML parser for NetRecon."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from models import Host, Port, Scan, ScriptResult


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
        address_nodes = [
            node for node in host_node.findall("address") if node.get("addr")
        ]
        if not address_nodes:
            continue

        addresses = tuple(
            (node.get("addr", ""), node.get("addrtype", "unknown"))
            for node in address_nodes
        )
        primary_node = next(
            (node for node in address_nodes if node.get("addrtype") in {"ipv4", "ipv6"}),
            address_nodes[0],
        )

        status_node = host_node.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"

        hostnames = tuple(
            node.get("name", "")
            for node in host_node.findall("./hostnames/hostname")
            if node.get("name")
        )
        hostname = hostnames[0] if hostnames else None

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
            confidence = None
            if service_node is not None and service_node.get("conf"):
                try:
                    confidence = int(service_node.get("conf", ""))
                except ValueError:
                    confidence = None

            scripts = tuple(
                ScriptResult(
                    script_id=node.get("id", "unknown"),
                    output=node.get("output", ""),
                )
                for node in port_node.findall("script")
            )

            ports.append(
                Port(
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service=service_node.get("name") if service_node is not None else None,
                    product=service_node.get("product") if service_node is not None else None,
                    version=service_node.get("version") if service_node is not None else None,
                    extra_info=service_node.get("extrainfo") if service_node is not None else None,
                    tunnel=service_node.get("tunnel") if service_node is not None else None,
                    detection_method=service_node.get("method") if service_node is not None else None,
                    confidence=confidence,
                    scripts=scripts,
                )
            )

        host_scripts = tuple(
            ScriptResult(
                script_id=node.get("id", "unknown"),
                output=node.get("output", ""),
            )
            for node in host_node.findall("./hostscript/script")
        )

        hosts.append(
            Host(
                address=primary_node.get("addr", ""),
                status=status,
                hostname=hostname,
                addresses=addresses,
                hostnames=hostnames,
                scripts=host_scripts,
                ports=tuple(ports),
            )
        )

    return Scan(source=str(source), hosts=tuple(hosts))
