import unittest

from host_summary import summarize_hosts
from models import Host, Port, Scan


class HostSummaryTests(unittest.TestCase):
    def test_summarizes_open_ports_services_and_findings(self) -> None:
        from findings import Finding

        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service="http"),
                        Port(port=22, protocol="tcp", state="closed", service="ssh"),
                    ),
                ),
            ),
        )
        findings = (
            Finding(
                finding_id="F-1",
                category="service",
                host="192.0.2.10",
                port=80,
                protocol="tcp",
                severity="info",
                title="HTTP observed",
                evidence="port 80",
                recommendation="Review service",
            ),
        )

        summaries = summarize_hosts(scan, findings)

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0].host, "192.0.2.10")
        self.assertEqual(summaries[0].status, "up")
        self.assertEqual(summaries[0].open_ports, 1)
        self.assertEqual(summaries[0].services, ("http",))
        self.assertEqual(summaries[0].findings, 1)


if __name__ == "__main__":
    unittest.main()
