"""Tests for NetRecon exposure history across timestamped scans."""

import unittest

from exposure_history import summarize_exposure_history
from models import Host, Port, Scan


class ExposureHistoryTests(unittest.TestCase):
    def test_tracks_first_last_seen_and_observation_count_in_time_order(self) -> None:
        later = Scan(
            source="later.xml",
            started_at=300,
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(22, "tcp", "open", "ssh", "OpenSSH", "10.4"),
            )),),
        )
        earlier = Scan(
            source="earlier.xml",
            started_at=100,
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(22, "tcp", "open", "ssh", "OpenSSH", "9.9"),
            )),),
        )
        middle = Scan(
            source="middle.xml",
            started_at=200,
            hosts=(Host(address="192.0.2.10", status="up", ports=(
                Port(22, "tcp", "open", "ssh", "OpenSSH", "10.0"),
            )),),
        )

        history = summarize_exposure_history((later, earlier, middle))

        self.assertEqual(len(history), 1)
        item = history[0]
        self.assertEqual((item.host, item.port, item.protocol), ("192.0.2.10", 22, "tcp"))
        self.assertEqual(item.first_seen, 100)
        self.assertEqual(item.last_seen, 300)
        self.assertEqual(item.observations, 3)

    def test_service_or_product_changes_do_not_split_endpoint_identity(self) -> None:
        scans = (
            Scan(source="one.xml", started_at=100, hosts=(Host(
                address="192.0.2.10", status="up",
                ports=(Port(8080, "tcp", "open", "http", "Apache httpd", "2.4"),),
            ),)),
            Scan(source="two.xml", started_at=200, hosts=(Host(
                address="192.0.2.10", status="up",
                ports=(Port(8080, "tcp", "open", "http-proxy", "nginx", "1.26"),),
            ),)),
        )

        history = summarize_exposure_history(scans)

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].observations, 2)
        self.assertEqual(history[0].first_seen, 100)
        self.assertEqual(history[0].last_seen, 200)

    def test_equivalent_ipv6_addresses_share_history_identity(self) -> None:
        scans = (
            Scan(source="one.xml", started_at=100, hosts=(Host(
                address="2001:0db8:0000:0000:0000:0000:0000:0001", status="up",
                ports=(Port(443, "tcp", "open", "https"),),
            ),)),
            Scan(source="two.xml", started_at=200, hosts=(Host(
                address="2001:db8::1", status="up",
                ports=(Port(443, "TCP", "open", "https"),),
            ),)),
        )

        history = summarize_exposure_history(scans)

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].host, "2001:db8::1")
        self.assertEqual(history[0].observations, 2)

    def test_non_open_ports_are_not_exposure_observations(self) -> None:
        scan = Scan(source="scan.xml", started_at=100, hosts=(Host(
            address="192.0.2.10", status="up",
            ports=(
                Port(22, "tcp", "closed", "ssh"),
                Port(80, "tcp", "filtered", "http"),
            ),
        ),))

        self.assertEqual(summarize_exposure_history((scan,)), ())

    def test_missing_scan_timestamp_fails_closed(self) -> None:
        scan = Scan(source="scan.xml", hosts=(Host(
            address="192.0.2.10", status="up",
            ports=(Port(22, "tcp", "open", "ssh"),),
        ),))

        with self.assertRaisesRegex(ValueError, "timestamp"):
            summarize_exposure_history((scan,))


    def test_duplicate_endpoint_entries_in_one_scan_count_as_one_observation(self) -> None:
        scan = Scan(source="scan.xml", started_at=100, hosts=(Host(
            address="192.0.2.10", status="up",
            ports=(
                Port(443, "tcp", "open", "https"),
                Port(443, "TCP", "open", "https"),
            ),
        ),))

        history = summarize_exposure_history((scan,))

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].observations, 1)

    def test_started_at_is_preferred_over_finished_at_for_observation_time(self) -> None:
        scan = Scan(
            source="scan.xml",
            started_at=100,
            finished_at=150,
            hosts=(Host(
                address="192.0.2.10", status="up",
                ports=(Port(22, "tcp", "open", "ssh"),),
            ),),
        )

        history = summarize_exposure_history((scan,))

        self.assertEqual(history[0].first_seen, 100)
        self.assertEqual(history[0].last_seen, 100)

    def test_finished_at_is_used_when_started_at_is_missing(self) -> None:
        scan = Scan(
            source="scan.xml",
            finished_at=150,
            hosts=(Host(
                address="192.0.2.10", status="up",
                ports=(Port(22, "tcp", "open", "ssh"),),
            ),),
        )

        history = summarize_exposure_history((scan,))

        self.assertEqual(history[0].first_seen, 150)
        self.assertEqual(history[0].last_seen, 150)


if __name__ == "__main__":
    unittest.main()
