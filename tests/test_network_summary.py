import unittest

from models import Host, Port, Scan
from network_summary import summarize_network


class NetworkSummaryTests(unittest.TestCase):
    def test_summarizes_hosts_open_ports_and_services(self) -> None:
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
                Host(
                    address="192.0.2.20",
                    status="down",
                    ports=(Port(port=443, protocol="tcp", state="open", service="https"),),
                ),
            ),
        )

        summary = summarize_network(scan)

        self.assertEqual(summary.parsed_hosts, 2)
        self.assertEqual(summary.up_hosts, 1)
        self.assertEqual(summary.open_ports, 2)
        self.assertEqual(summary.unique_services, ("http", "https"))
        self.assertEqual(summary.service_counts, (("http", 1), ("https", 1)))


if __name__ == "__main__":
    unittest.main()
