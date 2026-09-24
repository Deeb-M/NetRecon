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
