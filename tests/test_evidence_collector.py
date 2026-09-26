import unittest

from evidence_collector import CollectionSpec, NmapCommand, build_collection_specs, build_nmap_command
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


if __name__ == "__main__":
    unittest.main()
