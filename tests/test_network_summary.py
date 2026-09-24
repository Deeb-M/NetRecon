import unittest

from models import Host, Port, Scan
from network_summary import summarize_network, summarize_shared_services


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

    def test_normalizes_services_and_orders_counts(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status=" UP ",
                    ports=(
                        Port(port=80, protocol="tcp", state=" OPEN ", service=" HTTP "),
                        Port(port=8080, protocol="tcp", state="open", service="http"),
                        Port(port=443, protocol="tcp", state="open", service="   "),
                    ),
                ),
                Host(
                    address="192.0.2.20",
                    status="up",
                    ports=(Port(port=22, protocol="tcp", state="open", service="SSH"),),
                ),
            ),
        )

        summary = summarize_network(scan)

        self.assertEqual(summary.up_hosts, 2)
        self.assertEqual(summary.open_ports, 4)
        self.assertEqual(summary.unique_services, ("http", "ssh", "unknown"))
        self.assertEqual(summary.service_counts, (("http", 2), ("ssh", 1), ("unknown", 1)))

    def test_shared_services_require_multiple_unique_hosts(self) -> None:
        scan = Scan(
            source="scan.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service="http"),
                        Port(port=8080, protocol="tcp", state="open", service="http"),
                    ),
                ),
                Host(
                    address="192.0.2.20",
                    status="up",
                    ports=(Port(port=80, protocol="tcp", state="open", service="http"),),
                ),
                Host(
                    address="192.0.2.30",
                    status="up",
                    ports=(Port(port=22, protocol="tcp", state="open", service="ssh"),),
                ),
            ),
        )

        shared = summarize_shared_services(scan)

        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0].service, "http")
        self.assertEqual(shared[0].host_count, 2)
        self.assertEqual(len(shared[0].endpoints), 3)


if __name__ == "__main__":
    unittest.main()
