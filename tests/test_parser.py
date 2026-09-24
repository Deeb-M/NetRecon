"""Tests for the NetRecon Nmap XML parser."""

from pathlib import Path
import tempfile
import unittest

from parser import NmapParseError, parse_nmap_xml


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" args="nmap -sV -oX scan.xml 192.0.2.10" start="1790180000">
  <scaninfo type="syn" protocol="tcp" numservices="3" services="22,80,443"/>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames>
      <hostname name="lab.example" type="user"/>
      <hostname name="alias.example" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"
                 extrainfo="Ubuntu Linux" tunnel="ssl" method="probed" conf="10"
                 ostype="Linux" devicetype="general purpose">
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
        <script id="ssh-hostkey" output="2048 SHA256:example RSA"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
    <hostscript>
      <script id="uptime" output="System uptime: 2 days"/>
    </hostscript>
  </host>
  <runstats>
    <finished time="1790180012" elapsed="12.34"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""


class ParserTests(unittest.TestCase):
    def test_parses_host_ports_and_service_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(SAMPLE_XML, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(scan.scanner, "nmap")
        self.assertEqual(scan.scanner_version, "7.95")
        self.assertIn("-sV", scan.arguments or "")
        self.assertEqual(scan.started_at, 1790180000)
        self.assertEqual(scan.finished_at, 1790180012)
        self.assertEqual(scan.elapsed, 12.34)
        self.assertEqual(scan.hosts_up, 1)
        self.assertEqual(scan.hosts_down, 0)
        self.assertEqual(scan.hosts_total, 1)
        self.assertEqual(len(scan.scan_scopes), 1)
        self.assertEqual(scan.scan_scopes[0].protocol, "tcp")
        self.assertEqual(scan.scan_scopes[0].services, "22,80,443")
        self.assertEqual(len(scan.hosts), 1)
        host = scan.hosts[0]
        self.assertEqual(host.address, "192.0.2.10")
        self.assertEqual(host.hostname, "lab.example")
        self.assertEqual(host.hostnames, ("lab.example", "alias.example"))
        self.assertEqual(host.hostname_records, (("lab.example", "user"), ("alias.example", "PTR")))
        self.assertEqual(
            host.addresses,
            (("192.0.2.10", "ipv4"), ("00:11:22:33:44:55", "mac")),
        )
        self.assertEqual(host.status, "up")
        self.assertEqual(len(host.ports), 2)
        self.assertEqual(host.ports[0].service, "ssh")
        self.assertEqual(host.ports[0].product, "OpenSSH")
        self.assertEqual(host.ports[0].version, "9.6")
        self.assertEqual(host.ports[0].extra_info, "Ubuntu Linux")
        self.assertEqual(host.ports[0].tunnel, "ssl")
        self.assertEqual(host.ports[0].detection_method, "probed")
        self.assertEqual(host.ports[0].confidence, 10)
        self.assertEqual(host.ports[0].os_type, "Linux")
        self.assertEqual(host.ports[0].device_type, "general purpose")
        self.assertEqual(host.ports[0].cpes, ("cpe:/o:linux:linux_kernel",))
        self.assertEqual(host.ports[0].scripts[0].script_id, "ssh-hostkey")
        self.assertIn("RSA", host.ports[0].scripts[0].output)
        self.assertEqual(host.scripts[0].script_id, "uptime")
        self.assertIn("2 days", host.scripts[0].output)

    def test_skips_host_without_address_but_keeps_valid_hosts(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.0.2.20" addrtype="ipv4"/>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(len(scan.hosts), 1)
        self.assertEqual(scan.hosts[0].address, "192.0.2.20")

    def test_skips_port_without_portid_but_keeps_valid_ports(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(len(scan.hosts), 1)
        self.assertEqual(len(scan.hosts[0].ports), 1)
        self.assertEqual(scan.hosts[0].ports[0].port, 443)

    def test_skips_port_with_non_numeric_portid_but_keeps_valid_ports(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="http"><state state="open"/></port>
      <port protocol="tcp" portid="22"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(len(scan.hosts[0].ports), 1)
        self.assertEqual(scan.hosts[0].ports[0].port, 22)

    def test_invalid_service_confidence_becomes_none_without_losing_service(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" conf="high"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        port = scan.hosts[0].ports[0]
        self.assertEqual(port.service, "ssh")
        self.assertEqual(port.product, "OpenSSH")
        self.assertIsNone(port.confidence)

    def test_invalid_numeric_scan_metadata_becomes_none(self) -> None:
        xml = """<nmaprun scanner="nmap" start="not-a-number">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="invalid" elapsed="unknown"/>
    <hosts up="one" down="zero" total="one"/>
  </runstats>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertIsNone(scan.started_at)
        self.assertIsNone(scan.finished_at)
        self.assertIsNone(scan.elapsed)
        self.assertIsNone(scan.hosts_up)
        self.assertIsNone(scan.hosts_down)
        self.assertIsNone(scan.hosts_total)
        self.assertEqual(scan.hosts[0].address, "192.0.2.10")

    def test_missing_numeric_scan_metadata_remains_none(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished/>
    <hosts/>
  </runstats>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertIsNone(scan.started_at)
        self.assertIsNone(scan.finished_at)
        self.assertIsNone(scan.elapsed)
        self.assertIsNone(scan.hosts_up)
        self.assertIsNone(scan.hosts_down)
        self.assertIsNone(scan.hosts_total)
        self.assertEqual(scan.hosts[0].address, "192.0.2.10")

    def test_prefers_ip_address_when_mac_address_appears_first(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        self.assertEqual(host.address, "192.0.2.10")
        self.assertEqual(
            host.addresses,
            (("00:11:22:33:44:55", "mac"), ("192.0.2.10", "ipv4")),
        )

    def test_uses_first_address_when_no_ip_address_type_is_available(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <address addr="node-identifier" addrtype="custom"/>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        self.assertEqual(host.address, "00:11:22:33:44:55")
        self.assertEqual(
            host.addresses,
            (("00:11:22:33:44:55", "mac"), ("node-identifier", "custom")),
        )

    def test_missing_host_status_port_protocol_and_state_default_to_unknown(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port portid="80"/>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        port = host.ports[0]
        self.assertEqual(host.status, "unknown")
        self.assertEqual(port.protocol, "unknown")
        self.assertEqual(port.state, "unknown")

    def test_skips_scaninfo_without_services_but_keeps_valid_scope(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <scaninfo type="syn" protocol="tcp"/>
  <scaninfo type="udp" protocol="udp" services="53,161"/>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(len(scan.scan_scopes), 1)
        self.assertEqual(scan.scan_scopes[0].protocol, "udp")
        self.assertEqual(scan.scan_scopes[0].services, "53,161")

    def test_scaninfo_with_services_and_missing_protocol_defaults_to_unknown(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <scaninfo type="custom" services="80,443"/>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(len(scan.scan_scopes), 1)
        self.assertEqual(scan.scan_scopes[0].protocol, "unknown")
        self.assertEqual(scan.scan_scopes[0].services, "80,443")

    def test_skips_hostname_without_name_but_keeps_valid_hostname(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname type="PTR"/>
      <hostname name="lab.example" type="user"/>
    </hostnames>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        self.assertEqual(host.hostname, "lab.example")
        self.assertEqual(host.hostnames, ("lab.example",))
        self.assertEqual(host.hostname_records, (("lab.example", "user"),))

    def test_hostname_without_type_defaults_to_unknown(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="lab.example"/>
    </hostnames>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        self.assertEqual(host.hostname, "lab.example")
        self.assertEqual(host.hostnames, ("lab.example",))
        self.assertEqual(host.hostname_records, (("lab.example", "unknown"),))

    def test_address_without_addrtype_defaults_to_unknown(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="node-identifier"/>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        self.assertEqual(host.address, "node-identifier")
        self.assertEqual(host.addresses, (("node-identifier", "unknown"),))

    def test_skips_address_without_addr_but_keeps_valid_address(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addrtype="mac"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        host = scan.hosts[0]
        self.assertEqual(host.address, "192.0.2.10")
        self.assertEqual(host.addresses, (("192.0.2.10", "ipv4"),))

    def test_service_cpes_are_trimmed_and_blank_entries_are_skipped(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http">
          <cpe>   </cpe>
          <cpe>  cpe:/a:apache:http_server:2.4.68  </cpe>
          <cpe></cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(
            scan.hosts[0].ports[0].cpes,
            ("cpe:/a:apache:http_server:2.4.68",),
        )

    def test_port_script_missing_id_and_output_uses_safe_defaults(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <script/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        script = scan.hosts[0].ports[0].scripts[0]
        self.assertEqual(script.script_id, "unknown")
        self.assertEqual(script.output, "")

    def test_host_script_missing_id_and_output_uses_safe_defaults(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostscript>
      <script/>
    </hostscript>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        script = scan.hosts[0].scripts[0]
        self.assertEqual(script.script_id, "unknown")
        self.assertEqual(script.output, "")

    def test_port_without_service_preserves_port_with_empty_service_metadata(self) -> None:
        xml = """<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(xml, encoding="utf-8")

            scan = parse_nmap_xml(path)

        port = scan.hosts[0].ports[0]
        self.assertEqual(port.port, 8080)
        self.assertIsNone(port.service)
        self.assertIsNone(port.product)
        self.assertIsNone(port.version)
        self.assertIsNone(port.extra_info)
        self.assertIsNone(port.tunnel)
        self.assertIsNone(port.detection_method)
        self.assertIsNone(port.confidence)
        self.assertIsNone(port.os_type)
        self.assertIsNone(port.device_type)
        self.assertEqual(port.cpes, ())

    def test_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.xml"
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)

    def test_rejects_malformed_xml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text("<nmaprun><host>", encoding="utf-8")
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)

    def test_accepts_empty_nmap_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text("<nmaprun scanner=\"nmap\"/>", encoding="utf-8")
            scan = parse_nmap_xml(path)

        self.assertEqual(scan.scanner, "nmap")
        self.assertEqual(scan.hosts, ())

    def test_rejects_non_nmap_xml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text("<root/>", encoding="utf-8")
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)


if __name__ == "__main__":
    unittest.main()
