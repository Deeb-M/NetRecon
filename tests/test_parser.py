"""Tests for the NetRecon Nmap XML parser."""

from pathlib import Path
import tempfile
import unittest

from parser import NmapParseError, parse_nmap_xml


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames>
      <hostname name="lab.example"/>
      <hostname name="alias.example"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"
                 extrainfo="Ubuntu Linux" tunnel="ssl" method="probed" conf="10"/>
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
</nmaprun>
"""


class ParserTests(unittest.TestCase):
    def test_parses_host_ports_and_service_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(SAMPLE_XML, encoding="utf-8")

            scan = parse_nmap_xml(path)

        self.assertEqual(len(scan.hosts), 1)
        host = scan.hosts[0]
        self.assertEqual(host.address, "192.0.2.10")
        self.assertEqual(host.hostname, "lab.example")
        self.assertEqual(host.hostnames, ("lab.example", "alias.example"))
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
        self.assertEqual(host.ports[0].scripts[0].script_id, "ssh-hostkey")
        self.assertIn("RSA", host.ports[0].scripts[0].output)
        self.assertEqual(host.scripts[0].script_id, "uptime")
        self.assertIn("2 days", host.scripts[0].output)

    def test_rejects_non_nmap_xml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text("<root/>", encoding="utf-8")
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)


if __name__ == "__main__":
    unittest.main()
