import subprocess
import unittest
from unittest.mock import patch

from evidence_collector import (
    CollectionResult,
    CollectionSpec,
    NmapCommand,
    ParsedCollectionResult,
    build_collection_specs,
    build_nmap_command,
    build_nmap_commands,
    execute_host_evidence_plan,
    execute_nmap_command,
    parse_collection_outcome,
    parse_collection_result,
)
from evidence_planner import EvidenceRequest, HostEvidencePlan
from models import Scan


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


    def test_rejects_collection_spec_without_scripts(self) -> None:
        spec = CollectionSpec(
            target="192.0.2.90",
            port=443,
            protocol="tcp",
            script_ids=(),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Evidence collection requires at least one script",
        ):
            build_nmap_command(spec)


    def test_normalizes_collection_protocol_before_building_command(self) -> None:
        spec = CollectionSpec(
            target="192.0.2.91",
            port=161,
            protocol=" UDP ",
            script_ids=("snmp-info",),
        )

        self.assertEqual(
            build_nmap_command(spec).arguments,
            (
                "nmap",
                "-sU",
                "-p",
                "161",
                "--script",
                "snmp-info",
                "-oX",
                "-",
                "192.0.2.91",
            ),
        )


    def test_rejects_collection_spec_without_target(self) -> None:
        spec = CollectionSpec(
            target="   ",
            port=443,
            protocol="tcp",
            script_ids=("ssl-cert",),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Evidence collection requires a target",
        ):
            build_nmap_command(spec)


    def test_rejects_collection_port_outside_valid_range(self) -> None:
        for port in (0, -1, 65536):
            with self.subTest(port=port):
                spec = CollectionSpec(
                    target="192.0.2.92",
                    port=port,
                    protocol="tcp",
                    script_ids=("http-title",),
                )

                with self.assertRaisesRegex(
                    ValueError,
                    f"Invalid collection port: {port}",
                ):
                    build_nmap_command(spec)


    def test_rejects_blank_collection_script_id(self) -> None:
        spec = CollectionSpec(
            target="192.0.2.93",
            port=443,
            protocol="tcp",
            script_ids=("   ",),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Evidence collection script IDs must not be blank",
        ):
            build_nmap_command(spec)


    def test_collection_result_preserves_command_and_process_output(self) -> None:
        command = NmapCommand(
            arguments=("nmap", "-p", "443", "192.0.2.94"),
        )

        result = CollectionResult(
            command=command,
            returncode=0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
        )

        self.assertEqual(result.command, command)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "<nmaprun></nmaprun>")
        self.assertEqual(result.stderr, "")


    @patch("evidence_collector.subprocess.run")
    def test_executes_nmap_command_without_shell(
        self,
        run_mock,
    ) -> None:
        command = NmapCommand(
            arguments=("nmap", "-p", "443", "192.0.2.95"),
        )
        run_mock.return_value = subprocess.CompletedProcess(
            args=command.arguments,
            returncode=0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
        )

        result = execute_nmap_command(command)

        run_mock.assert_called_once_with(
            command.arguments,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
        self.assertEqual(
            result,
            CollectionResult(
                command=command,
                returncode=0,
                stdout="<nmaprun></nmaprun>",
                stderr="",
            ),
        )


    @patch("evidence_collector.subprocess.run")
    def test_preserves_failed_nmap_process_result(
        self,
        run_mock,
    ) -> None:
        command = NmapCommand(
            arguments=("nmap", "-p", "443", "192.0.2.96"),
        )
        run_mock.return_value = subprocess.CompletedProcess(
            args=command.arguments,
            returncode=2,
            stdout="",
            stderr="nmap failed",
        )

        result = execute_nmap_command(command)

        self.assertEqual(result.command, command)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "nmap failed")


    @patch("evidence_collector.execute_nmap_command")
    def test_executes_complete_host_evidence_plan_in_order(
        self,
        execute_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.97",
            requests=(
                EvidenceRequest(80, "tcp", "http-title"),
                EvidenceRequest(443, "tcp", "ssl-cert"),
            ),
        )
        commands = build_nmap_commands(plan)
        execute_mock.side_effect = (
            CollectionResult(commands[0], 0, "<http />", ""),
            CollectionResult(commands[1], 0, "<tls />", ""),
        )

        results = execute_host_evidence_plan(plan)

        self.assertEqual(
            [call.args[0] for call in execute_mock.call_args_list],
            list(commands),
        )
        self.assertEqual(
            results,
            (
                CollectionResult(commands[0], 0, "<http />", ""),
                CollectionResult(commands[1], 0, "<tls />", ""),
            ),
        )


    @patch("evidence_collector.execute_nmap_command")
    def test_host_plan_preserves_results_after_command_failure(
        self,
        execute_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.98",
            requests=(
                EvidenceRequest(80, "tcp", "http-title"),
                EvidenceRequest(443, "tcp", "ssl-cert"),
            ),
        )
        commands = build_nmap_commands(plan)
        execute_mock.side_effect = (
            CollectionResult(commands[0], 2, "", "first command failed"),
            CollectionResult(commands[1], 0, "<tls />", ""),
        )

        results = execute_host_evidence_plan(plan)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].returncode, 2)
        self.assertEqual(results[0].stderr, "first command failed")
        self.assertEqual(results[1].returncode, 0)
        self.assertEqual(results[1].stdout, "<tls />")


    @patch("evidence_collector.execute_nmap_command")
    def test_empty_host_plan_executes_no_commands(
        self,
        execute_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.99",
            requests=(),
        )

        self.assertEqual(execute_host_evidence_plan(plan), ())
        execute_mock.assert_not_called()


    def test_parses_successful_collection_result_from_stdout(self) -> None:
        command = NmapCommand(
            arguments=("nmap", "-p", "443", "192.0.2.100"),
        )
        result = CollectionResult(
            command=command,
            returncode=0,
            stdout=(
                '<nmaprun scanner="nmap">'
                '<host><status state="up"/>'
                '<address addr="192.0.2.100" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="443">'
                '<state state="open"/><service name="https"/>'
                '</port></ports></host>'
                '</nmaprun>'
            ),
            stderr="",
        )

        scan = parse_collection_result(result)

        self.assertEqual(scan.source, "nmap stdout")
        self.assertEqual(scan.hosts[0].address, "192.0.2.100")
        self.assertEqual(scan.hosts[0].ports[0].service, "https")


    @patch("evidence_collector.parse_nmap_xml_text")
    def test_rejects_failed_collection_before_parsing_stdout(
        self,
        parse_mock,
    ) -> None:
        result = CollectionResult(
            command=NmapCommand(
                arguments=("nmap", "-p", "443", "192.0.2.101"),
            ),
            returncode=2,
            stdout="<partial />",
            stderr="nmap failed",
        )

        with self.assertRaisesRegex(
            ValueError,
            "Cannot parse failed evidence collection: return code 2",
        ):
            parse_collection_result(result)

        parse_mock.assert_not_called()


    def test_parsed_collection_result_preserves_result_without_scan(self) -> None:
        result = CollectionResult(
            command=NmapCommand(
                arguments=("nmap", "-p", "443", "192.0.2.102"),
            ),
            returncode=2,
            stdout="",
            stderr="nmap failed",
        )

        parsed = ParsedCollectionResult(
            result=result,
            scan=None,
        )

        self.assertEqual(parsed.result, result)
        self.assertIsNone(parsed.scan)


    @patch("evidence_collector.parse_collection_result")
    def test_failed_collection_outcome_preserves_result_without_parsing(
        self,
        parse_mock,
    ) -> None:
        result = CollectionResult(
            command=NmapCommand(
                arguments=("nmap", "-p", "443", "192.0.2.103"),
            ),
            returncode=2,
            stdout="<partial />",
            stderr="nmap failed",
        )

        outcome = parse_collection_outcome(result)

        self.assertEqual(
            outcome,
            ParsedCollectionResult(result=result, scan=None),
        )
        parse_mock.assert_not_called()


    @patch("evidence_collector.parse_collection_result")
    def test_successful_collection_outcome_preserves_result_and_scan(
        self,
        parse_mock,
    ) -> None:
        result = CollectionResult(
            command=NmapCommand(
                arguments=("nmap", "-p", "443", "192.0.2.104"),
            ),
            returncode=0,
            stdout="<nmaprun />",
            stderr="",
        )
        scan = Scan(source="nmap stdout")
        parse_mock.return_value = scan

        outcome = parse_collection_outcome(result)

        parse_mock.assert_called_once_with(result)
        self.assertEqual(
            outcome,
            ParsedCollectionResult(result=result, scan=scan),
        )


if __name__ == "__main__":
    unittest.main()
