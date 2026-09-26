import unittest

from evidence_collector import (
    CollectionSpec,
    NmapCommand,
    build_collection_specs,
    build_nmap_command,
    build_nmap_commands,
)
from evidence_planner import EvidenceRequest, HostEvidencePlan


class EvidenceCollectorTests(unittest.TestCase):
    def test_groups_scripts_for_same_target_port_and_protocol(self) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.10",
            requests=(
                EvidenceRequest(443, "tcp", "http-title"),
                EvidenceRequest(443, "tcp", "http-methods"),
                EvidenceRequest(443, "tcp", "ssl-cert"),
                EvidenceRequest(443, "tcp", "ssl-enum-ciphers"),
            ),
        )

        specs = build_collection_specs(plan)

        self.assertEqual(
            specs,
            (
                CollectionSpec(
                    target="192.0.2.10",
                    port=443,
                    protocol="tcp",
                    script_ids=(
                        "http-title",
                        "http-methods",
                        "ssl-cert",
                        "ssl-enum-ciphers",
                    ),
                ),
            ),
        )

    def test_keeps_different_ports_as_separate_collection_units(self) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.20",
            requests=(
                EvidenceRequest(80, "tcp", "http-title"),
                EvidenceRequest(443, "tcp", "http-title"),
            ),
        )

        specs = build_collection_specs(plan)

        self.assertEqual(
            specs,
            (
                CollectionSpec("192.0.2.20", 80, "tcp", ("http-title",)),
                CollectionSpec("192.0.2.20", 443, "tcp", ("http-title",)),
            ),
        )

    def test_empty_host_plan_produces_no_collection_specs(self) -> None:
        plan = HostEvidencePlan(target="192.0.2.30", requests=())

        self.assertEqual(build_collection_specs(plan), ())


    def test_builds_transparent_nmap_argv_without_execution(self) -> None:
        spec = CollectionSpec(
            target="192.0.2.40",
            port=443,
            protocol="tcp",
            script_ids=(
                "http-title",
                "http-methods",
                "ssl-cert",
                "ssl-enum-ciphers",
            ),
        )

        command = build_nmap_command(spec)

        self.assertEqual(
            command,
            NmapCommand(
                arguments=(
                    "nmap",
                    "-p",
                    "443",
                    "--script",
                    "http-title,http-methods,ssl-cert,ssl-enum-ciphers",
                    "-oX",
                    "-",
                    "192.0.2.40",
                )
            ),
        )


    def test_udp_collection_command_uses_udp_scan(self) -> None:
        spec = CollectionSpec(
            target="192.0.2.50",
            port=161,
            protocol="udp",
            script_ids=("snmp-info",),
        )

        command = build_nmap_command(spec)

        self.assertEqual(
            command,
            NmapCommand(
                arguments=(
                    "nmap",
                    "-sU",
                    "-p",
                    "161",
                    "--script",
                    "snmp-info",
                    "-oX",
                    "-",
                    "192.0.2.50",
                )
            ),
        )


    def test_rejects_unsupported_collection_protocol(self) -> None:
        spec = CollectionSpec(
            target="192.0.2.60",
            port=9999,
            protocol="unknown",
            script_ids=("example-script",),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported collection protocol: unknown",
        ):
            build_nmap_command(spec)


    def test_builds_all_commands_from_host_evidence_plan(self) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.70",
            requests=(
                EvidenceRequest(80, "tcp", "http-title"),
                EvidenceRequest(443, "tcp", "ssl-cert"),
            ),
        )

        self.assertEqual(
            build_nmap_commands(plan),
            (
                NmapCommand(
                    ("nmap", "-p", "80", "--script", "http-title", "-oX", "-", "192.0.2.70")
                ),
                NmapCommand(
                    ("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.70")
                ),
            ),
        )


    def test_empty_host_plan_builds_no_nmap_commands(self) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.80",
            requests=(),
        )

        self.assertEqual(build_nmap_commands(plan), ())


if __name__ == "__main__":
    unittest.main()
