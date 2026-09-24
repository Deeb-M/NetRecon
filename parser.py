"""Nmap XML parser for NetRecon."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from models import Host, Port, Scan, ScanScope, ScriptResult


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

    def _int_attr(node: ET.Element | None, name: str) -> int | None:
        if node is None or not node.get(name):
            return None
        try:
            return int(node.get(name, ""))
        except ValueError:
            return None

    def _float_attr(node: ET.Element | None, name: str) -> float | None:
        if node is None or not node.get(name):
            return None
        try:
            return float(node.get(name, ""))
        except ValueError:
            return None

    finished_node = root.find("./runstats/finished")
    hosts_node = root.find("./runstats/hosts")

    scan_scopes = tuple(
        ScanScope(
            protocol=node.get("protocol", "").strip() or "unknown",
            services=node.get("services", "").strip(),
        )
        for node in root.findall("scaninfo")
        if node.get("services") and node.get("services", "").strip()
    )

    hosts: list[Host] = []

    for host_node in root.findall("host"):
        address_nodes = [
            node for node in host_node.findall("address") if node.get("addr") and node.get("addr", "").strip()
        ]
        if not address_nodes:
            continue

        addresses = tuple(
            (node.get("addr", "").strip(), node.get("addrtype", "").strip() or "unknown")
            for node in address_nodes
        )
        primary_node = next(
            (node for node in address_nodes if node.get("addrtype", "").strip() in {"ipv4", "ipv6"}),
            address_nodes[0],
        )

        status_node = host_node.find("status")
        status = status_node.get("state", "").strip() or "unknown" if status_node is not None else "unknown"

        hostname_records = tuple(
            (node.get("name", "").strip(), node.get("type", "").strip() or "unknown")
            for node in host_node.findall("./hostnames/hostname")
            if node.get("name") and node.get("name", "").strip()
        )
        hostnames = tuple(name for name, _ in hostname_records)
        hostname = hostnames[0] if hostnames else None

        ports: list[Port] = []
        for port_node in host_node.findall("./ports/port"):
            port_id = port_node.get("portid")
            protocol = port_node.get("protocol", "").strip() or "unknown"
            if port_id is None:
                continue

            try:
                port_number = int(port_id)
            except ValueError:
                continue

            state_node = port_node.find("state")
            state = state_node.get("state", "").strip() or "unknown" if state_node is not None else "unknown"

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
                    service=(service_node.get("name", "").strip() or None) if service_node is not None else None,
                    product=(service_node.get("product", "").strip() or None) if service_node is not None else None,
                    version=(service_node.get("version", "").strip() or None) if service_node is not None else None,
                    extra_info=(service_node.get("extrainfo", "").strip() or None) if service_node is not None else None,
                    tunnel=(service_node.get("tunnel", "").strip() or None) if service_node is not None else None,
                    detection_method=(service_node.get("method", "").strip() or None) if service_node is not None else None,
                    confidence=confidence,
                    os_type=service_node.get("ostype") if service_node is not None else None,
                    device_type=service_node.get("devicetype") if service_node is not None else None,
                    cpes=tuple(
                        node.text.strip()
                        for node in service_node.findall("cpe")
                        if node.text and node.text.strip()
                    ) if service_node is not None else (),
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
                address=primary_node.get("addr", "").strip(),
                status=status,
                hostname=hostname,
                addresses=addresses,
                hostnames=hostnames,
                hostname_records=hostname_records,
                scripts=host_scripts,
                ports=tuple(ports),
            )
        )

    return Scan(
        source=str(source),
        scanner=root.get("scanner"),
        scanner_version=root.get("version"),
        arguments=root.get("args"),
        started_at=_int_attr(root, "start"),
        finished_at=_int_attr(finished_node, "time"),
        elapsed=_float_attr(finished_node, "elapsed"),
        hosts_up=_int_attr(hosts_node, "up"),
        hosts_down=_int_attr(hosts_node, "down"),
        hosts_total=_int_attr(hosts_node, "total"),
        scan_scopes=scan_scopes,
        hosts=tuple(hosts),
    )
