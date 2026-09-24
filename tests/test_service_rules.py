import unittest

from models import Host, Port
from service_rules import analyze_service_context


class ServiceRulesTests(unittest.TestCase):
    def test_telnet_open_port_produces_transport_finding(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(Port(port=23, protocol="tcp", state="open", service="telnet"),),
        )

        findings = analyze_service_context(host)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "service.telnet.exposed")
        self.assertEqual(finding.category, "transport")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.host, "192.0.2.10")
        self.assertEqual(finding.port, 23)
        self.assertEqual(finding.protocol, "tcp")
        self.assertEqual(finding.evidence_source, "service:detection")


if __name__ == "__main__":
    unittest.main()
