import subprocess
import unittest
from unittest.mock import patch

from evidence_collector import (
    CorrelatedEvidenceResult,
    CollectionResult,
    CollectionSpec,
    EvidenceCollectionError,
    NmapCommand,
    ParsedCollectionResult,
    analyze_collection_outcome,
    analyze_correlated_host_evidence,
    analyze_collection_outcomes,
    build_collection_specs,
    build_nmap_command,
    build_nmap_commands,
    collect_and_analyze_host_evidence,
    collect_correlate_and_analyze_host_evidence,
    collect_correlated_host_evidence,
    collect_host_evidence,
    execute_host_evidence_plan,
    execute_nmap_command,
    merge_collection_outcomes_into_host,
    merge_host_evidence,
    merge_host_port_evidence,
    merge_port_evidence,
    parse_collection_outcome,
    parse_collection_result,
)
from evidence_planner import EvidenceRequest, HostEvidencePlan
from findings import Finding
from models import Host, Port, Scan, ScriptResult


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
            timeout=None,
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


    @patch("evidence_collector.parse_collection_outcome")
    @patch("evidence_collector.execute_host_evidence_plan")
    def test_collects_and_parses_complete_host_plan_in_order(
        self,
        execute_mock,
        parse_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.105",
            requests=(
                EvidenceRequest(80, "tcp", "http-title"),
                EvidenceRequest(443, "tcp", "ssl-cert"),
            ),
        )
        first = CollectionResult(
            NmapCommand(("nmap", "-p", "80", "192.0.2.105")),
            0,
            "<http />",
            "",
        )
        second = CollectionResult(
            NmapCommand(("nmap", "-p", "443", "192.0.2.105")),
            2,
            "",
            "failed",
        )
        execute_mock.return_value = (first, second)
        outcomes = (
            ParsedCollectionResult(first, Scan(source="first")),
            ParsedCollectionResult(second, None),
        )
        parse_mock.side_effect = outcomes

        result = collect_host_evidence(plan)

        execute_mock.assert_called_once_with(plan, timeout=None)
        self.assertEqual(
            [call.args[0] for call in parse_mock.call_args_list],
            [first, second],
        )
        self.assertEqual(result, outcomes)


    @patch("evidence_collector.parse_collection_outcome")
    @patch("evidence_collector.execute_host_evidence_plan")
    def test_empty_host_plan_collection_is_safe_no_op(
        self,
        execute_mock,
        parse_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.106",
            requests=(),
        )
        execute_mock.return_value = ()

        self.assertEqual(collect_host_evidence(plan), ())
        execute_mock.assert_called_once_with(plan, timeout=None)
        parse_mock.assert_not_called()


    @patch("evidence_collector.analyze_scan")
    def test_failed_collection_outcome_is_not_analyzed(
        self,
        analyze_mock,
    ) -> None:
        result = CollectionResult(
            NmapCommand(("nmap", "-p", "443", "192.0.2.107")),
            2,
            "",
            "failed",
        )
        outcome = ParsedCollectionResult(result=result, scan=None)

        self.assertEqual(analyze_collection_outcome(outcome), ())
        analyze_mock.assert_not_called()


    @patch("evidence_collector.analyze_scan")
    def test_successful_collection_outcome_is_analyzed(
        self,
        analyze_mock,
    ) -> None:
        result = CollectionResult(
            NmapCommand(("nmap", "-p", "443", "192.0.2.108")),
            0,
            "<nmaprun />",
            "",
        )
        scan = Scan(source="nmap stdout")
        outcome = ParsedCollectionResult(result=result, scan=scan)
        findings = (
            Finding(
                finding_id="test-finding",
                category="test",
                host="192.0.2.108",
                port=443,
                protocol="tcp",
                severity="info",
                title="Test finding",
                evidence="Test evidence",
                recommendation="Test recommendation",
            ),
        )
        analyze_mock.return_value = findings

        self.assertEqual(analyze_collection_outcome(outcome), findings)
        analyze_mock.assert_called_once_with(scan)


    @patch("evidence_collector.analyze_collection_outcome")
    def test_analyzes_collection_outcomes_in_order(
        self,
        analyze_mock,
    ) -> None:
        first = ParsedCollectionResult(
            CollectionResult(
                NmapCommand(("nmap", "-p", "80", "192.0.2.109")),
                0,
                "<nmaprun />",
                "",
            ),
            Scan(source="first"),
        )
        second = ParsedCollectionResult(
            CollectionResult(
                NmapCommand(("nmap", "-p", "443", "192.0.2.109")),
                2,
                "",
                "failed",
            ),
            None,
        )
        first_finding = Finding(
            "first",
            "test",
            "192.0.2.109",
            80,
            "tcp",
            "info",
            "First",
            "First evidence",
            "Review",
        )
        analyze_mock.side_effect = ((first_finding,), ())

        findings = analyze_collection_outcomes((first, second))

        self.assertEqual(findings, (first_finding,))
        self.assertEqual(
            [call.args[0] for call in analyze_mock.call_args_list],
            [first, second],
        )


    @patch("evidence_collector.analyze_collection_outcomes")
    @patch("evidence_collector.collect_host_evidence")
    def test_collects_and_analyzes_complete_host_plan(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.110",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        outcomes = (
            ParsedCollectionResult(
                CollectionResult(
                    NmapCommand(("nmap", "-p", "443", "192.0.2.110")),
                    0,
                    "<nmaprun />",
                    "",
                ),
                Scan(source="nmap stdout"),
            ),
        )
        finding = Finding(
            "tls-evidence",
            "test",
            "192.0.2.110",
            443,
            "tcp",
            "info",
            "TLS evidence",
            "Collected evidence",
            "Review",
        )
        collect_mock.return_value = outcomes
        analyze_mock.return_value = (finding,)

        self.assertEqual(
            collect_and_analyze_host_evidence(plan),
            (finding,),
        )
        collect_mock.assert_called_once_with(plan, timeout=None)
        analyze_mock.assert_called_once_with(outcomes)


    @patch("evidence_collector.subprocess.run")
    def test_reports_missing_nmap_executable(
        self,
        run_mock,
    ) -> None:
        run_mock.side_effect = FileNotFoundError
        command = NmapCommand(
            ("nmap", "-p", "443", "192.0.2.111"),
        )

        with self.assertRaisesRegex(
            EvidenceCollectionError,
            "Nmap executable not found",
        ):
            execute_nmap_command(command)


    @patch("evidence_collector.subprocess.run")
    def test_reports_nmap_collection_timeout(
        self,
        run_mock,
    ) -> None:
        run_mock.side_effect = subprocess.TimeoutExpired(
            cmd=("nmap", "-p", "443", "192.0.2.112"),
            timeout=30,
        )
        command = NmapCommand(
            ("nmap", "-p", "443", "192.0.2.112"),
        )

        with self.assertRaisesRegex(
            EvidenceCollectionError,
            "Nmap evidence collection timed out",
        ):
            execute_nmap_command(command, timeout=30)

        run_mock.assert_called_once_with(
            command.arguments,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=30,
        )


    @patch("evidence_collector.execute_nmap_command")
    def test_host_plan_propagates_collection_timeout(
        self,
        execute_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.113",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        execute_mock.return_value = CollectionResult(
            NmapCommand(
                (
                    "nmap",
                    "-p",
                    "443",
                    "--script",
                    "ssl-cert",
                    "-oX",
                    "-",
                    "192.0.2.113",
                )
            ),
            0,
            "<nmaprun />",
            "",
        )

        execute_host_evidence_plan(plan, timeout=45)

        execute_mock.assert_called_once()
        self.assertEqual(execute_mock.call_args.kwargs, {"timeout": 45})


    @patch("evidence_collector.analyze_collection_outcomes")
    @patch("evidence_collector.collect_host_evidence")
    def test_host_analysis_pipeline_propagates_collection_timeout(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        plan = HostEvidencePlan(
            target="192.0.2.114",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        collect_mock.return_value = ()
        analyze_mock.return_value = ()

        self.assertEqual(
            collect_and_analyze_host_evidence(plan, timeout=60),
            (),
        )
        collect_mock.assert_called_once_with(plan, timeout=60)
        analyze_mock.assert_called_once_with(())


    def test_port_evidence_merge_preserves_discovery_metadata(self) -> None:
        discovered = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            product="nginx",
            version="1.24",
        )
        collected = Port(
            port=443,
            protocol="TCP",
            state="open",
            service="ssl/http",
            product="different",
            version="different",
            scripts=(ScriptResult("ssl-cert", "certificate evidence"),),
        )

        merged = merge_port_evidence(discovered, collected)

        self.assertEqual(merged.service, "https")
        self.assertEqual(merged.product, "nginx")
        self.assertEqual(merged.version, "1.24")
        self.assertEqual(
            merged.scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )


    def test_port_evidence_merge_rejects_different_port(self) -> None:
        discovered = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
        )
        collected = Port(
            port=8443,
            protocol="tcp",
            state="open",
            service="https",
            scripts=(ScriptResult("ssl-cert", "certificate evidence"),),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Cannot merge evidence from a different port",
        ):
            merge_port_evidence(discovered, collected)


    def test_port_evidence_merge_deduplicates_identical_script_result(self) -> None:
        evidence = ScriptResult("ssl-cert", "certificate evidence")
        discovered = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            scripts=(evidence,),
        )
        collected = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            scripts=(evidence,),
        )

        merged = merge_port_evidence(discovered, collected)

        self.assertEqual(merged.scripts, (evidence,))


    def test_port_evidence_merge_preserves_changed_output_for_same_script(self) -> None:
        old_evidence = ScriptResult("ssl-cert", "old certificate evidence")
        new_evidence = ScriptResult("ssl-cert", "new certificate evidence")
        discovered = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            scripts=(old_evidence,),
        )
        collected = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            scripts=(new_evidence,),
        )

        merged = merge_port_evidence(discovered, collected)

        self.assertEqual(
            merged.scripts,
            (old_evidence, new_evidence),
        )


    def test_host_port_evidence_merge_updates_only_matching_port(self) -> None:
        http = Port(port=80, protocol="tcp", state="open", service="http")
        https = Port(port=443, protocol="tcp", state="open", service="https")
        discovered = Host(
            address="192.0.2.115",
            status="up",
            ports=(http, https),
        )
        collected = Port(
            port=443,
            protocol="TCP",
            state="open",
            service="ssl/http",
            scripts=(ScriptResult("ssl-cert", "certificate evidence"),),
        )

        merged = merge_host_port_evidence(discovered, collected)

        self.assertEqual(merged.ports[0], http)
        self.assertEqual(merged.ports[1].service, "https")
        self.assertEqual(
            merged.ports[1].scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )


    def test_host_port_evidence_merge_rejects_undiscovered_port(self) -> None:
        discovered = Host(
            address="192.0.2.116",
            status="up",
            ports=(
                Port(port=80, protocol="tcp", state="open", service="http"),
            ),
        )
        collected = Port(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            scripts=(ScriptResult("ssl-cert", "certificate evidence"),),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Cannot merge evidence for an undiscovered port",
        ):
            merge_host_port_evidence(discovered, collected)


    def test_host_evidence_merge_accumulates_multiple_collected_ports(self) -> None:
        discovered = Host(
            address="192.0.2.117",
            status="up",
            ports=(
                Port(port=80, protocol="tcp", state="open", service="http"),
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        collected_ports = (
            Port(
                port=80,
                protocol="tcp",
                state="open",
                scripts=(ScriptResult("http-title", "Example"),),
            ),
            Port(
                port=443,
                protocol="tcp",
                state="open",
                scripts=(ScriptResult("ssl-cert", "certificate evidence"),),
            ),
        )

        merged = merge_host_evidence(discovered, collected_ports)

        self.assertEqual(
            merged.ports[0].scripts,
            (ScriptResult("http-title", "Example"),),
        )
        self.assertEqual(
            merged.ports[1].scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )


    def test_collection_outcomes_merge_only_successful_evidence_into_host(self) -> None:
        discovered = Host(
            address="192.0.2.118",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        command = NmapCommand(("nmap",))
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "failed"),
            scan=None,
        )
        successful = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", ""),
            scan=Scan(
                source="nmap stdout",
                hosts=(
                    Host(
                        address="192.0.2.118",
                        status="up",
                        ports=(
                            Port(
                                port=443,
                                protocol="tcp",
                                state="open",
                                scripts=(
                                    ScriptResult("ssl-cert", "certificate evidence"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        merged = merge_collection_outcomes_into_host(
            discovered,
            (failed, successful),
        )

        self.assertEqual(
            merged.ports[0].scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )


    def test_collection_outcomes_ignore_evidence_from_different_host(self) -> None:
        discovered = Host(
            address="192.0.2.119",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        command = NmapCommand(("nmap",))
        outcome = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", ""),
            scan=Scan(
                source="nmap stdout",
                hosts=(
                    Host(
                        address="192.0.2.120",
                        status="up",
                        ports=(
                            Port(
                                port=443,
                                protocol="tcp",
                                state="open",
                                scripts=(
                                    ScriptResult("ssl-cert", "wrong host evidence"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        merged = merge_collection_outcomes_into_host(discovered, (outcome,))

        self.assertEqual(merged, discovered)


    def test_collection_outcomes_match_equivalent_ipv6_host_address(self) -> None:
        discovered = Host(
            address="2001:db8::1",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        command = NmapCommand(("nmap",))
        outcome = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", ""),
            scan=Scan(
                source="nmap stdout",
                hosts=(
                    Host(
                        address="2001:0db8:0000:0000:0000:0000:0000:0001",
                        status="up",
                        ports=(
                            Port(
                                port=443,
                                protocol="tcp",
                                state="open",
                                scripts=(
                                    ScriptResult("ssl-cert", "certificate evidence"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        merged = merge_collection_outcomes_into_host(discovered, (outcome,))

        self.assertEqual(
            merged.ports[0].scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )


    def test_collection_outcomes_ignore_invalid_host_address(self) -> None:
        discovered = Host(
            address="192.0.2.121",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        command = NmapCommand(("nmap",))
        outcome = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", ""),
            scan=Scan(
                source="nmap stdout",
                hosts=(
                    Host(
                        address="not-an-ip",
                        status="up",
                        ports=(
                            Port(
                                port=443,
                                protocol="tcp",
                                state="open",
                                scripts=(
                                    ScriptResult("ssl-cert", "wrong host evidence"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        merged = merge_collection_outcomes_into_host(discovered, (outcome,))

        self.assertEqual(merged, discovered)


    def test_collection_outcomes_reject_invalid_discovery_host_address(self) -> None:
        discovered = Host(
            address="not-an-ip",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Cannot correlate evidence for an invalid discovery host address",
        ):
            merge_collection_outcomes_into_host(discovered, ())


    @patch("evidence_collector.analyze_scan")
    def test_correlated_host_analysis_preserves_discovery_context(
        self,
        analyze_mock,
    ) -> None:
        discovered = Host(
            address="192.0.2.122",
            status="up",
            hostname="web.example",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                    product="nginx",
                ),
            ),
        )
        command = NmapCommand(("nmap",))
        outcomes = (
            ParsedCollectionResult(
                result=CollectionResult(command, 0, "<nmaprun />", ""),
                scan=Scan(
                    source="nmap stdout",
                    hosts=(
                        Host(
                            address="192.0.2.122",
                            status="up",
                            ports=(
                                Port(
                                    port=443,
                                    protocol="tcp",
                                    state="open",
                                    scripts=(
                                        ScriptResult("ssl-cert", "certificate evidence"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
        analyze_mock.return_value = ()

        self.assertEqual(
            analyze_correlated_host_evidence(discovered, outcomes),
            (),
        )

        correlated_scan = analyze_mock.call_args.args[0]
        merged = correlated_scan.hosts[0]
        self.assertEqual(merged.hostname, "web.example")
        self.assertEqual(merged.ports[0].product, "nginx")
        self.assertEqual(
            merged.ports[0].scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )


    @patch("evidence_collector.analyze_scan")
    @patch("evidence_collector.collect_host_evidence")
    def test_correlated_host_orchestration_collects_then_analyzes_discovery_context(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        discovered = Host(
            address="192.0.2.123",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        plan = HostEvidencePlan(
            target="192.0.2.123",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        outcomes = ()
        collect_mock.return_value = outcomes
        analyze_mock.return_value = ()

        self.assertEqual(
            collect_correlate_and_analyze_host_evidence(
                discovered,
                plan,
                timeout=30,
            ),
            (),
        )
        collect_mock.assert_called_once_with(plan, timeout=30)
        correlated_scan = analyze_mock.call_args.args[0]
        self.assertEqual(correlated_scan.hosts, (discovered,))


    @patch("evidence_collector.collect_host_evidence")
    def test_correlated_host_orchestration_rejects_mismatched_plan_target(
        self,
        collect_mock,
    ) -> None:
        discovered = Host(
            address="192.0.2.124",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        plan = HostEvidencePlan(
            target="192.0.2.125",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Evidence plan target does not match discovery host",
        ):
            collect_correlate_and_analyze_host_evidence(discovered, plan)

        collect_mock.assert_not_called()


    @patch("evidence_collector.analyze_scan")
    @patch("evidence_collector.collect_host_evidence")
    def test_correlated_host_orchestration_accepts_equivalent_ipv6_plan_target(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        discovered = Host(
            address="2001:db8::2",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        plan = HostEvidencePlan(
            target="2001:0db8:0000:0000:0000:0000:0000:0002",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        collect_mock.return_value = ()
        analyze_mock.return_value = ()

        self.assertEqual(
            collect_correlate_and_analyze_host_evidence(discovered, plan),
            (),
        )
        collect_mock.assert_called_once_with(plan, timeout=None)
        correlated_scan = analyze_mock.call_args.args[0]
        self.assertEqual(correlated_scan.hosts, (discovered,))


    @patch("evidence_collector.analyze_scan")
    @patch("evidence_collector.collect_host_evidence")
    def test_correlated_evidence_result_preserves_outcomes_host_and_findings(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        discovered = Host(
            address="192.0.2.126",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        plan = HostEvidencePlan(
            target="192.0.2.126",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        command = NmapCommand(("nmap",))
        outcomes = (
            ParsedCollectionResult(
                result=CollectionResult(command, 1, "", "collection failed"),
                scan=None,
            ),
        )
        finding = Finding(
            finding_id="test-finding",
            category="test",
            host="192.0.2.126",
            port=443,
            protocol="tcp",
            severity="info",
            title="Test",
            evidence="evidence",
            recommendation="review",
        )
        collect_mock.return_value = outcomes
        analyze_mock.return_value = (finding,)

        result = collect_correlated_host_evidence(discovered, plan, timeout=15)

        self.assertEqual(result.outcomes, outcomes)
        self.assertEqual(result.host, discovered)
        self.assertEqual(result.findings, (finding,))
        collect_mock.assert_called_once_with(plan, timeout=15)


    @patch("evidence_collector.collect_correlated_host_evidence")
    def test_findings_wrapper_uses_correlated_evidence_result(
        self,
        collect_mock,
    ) -> None:
        discovered = Host(address="192.0.2.127", status="up")
        plan = HostEvidencePlan(target="192.0.2.127", requests=())
        finding = Finding(
            finding_id="wrapper-finding",
            category="test",
            host="192.0.2.127",
            port=None,
            protocol=None,
            severity="info",
            title="Test",
            evidence="evidence",
            recommendation="review",
        )
        collect_mock.return_value = CorrelatedEvidenceResult(
            outcomes=(),
            host=discovered,
            findings=(finding,),
        )

        self.assertEqual(
            collect_correlate_and_analyze_host_evidence(
                discovered,
                plan,
                timeout=20,
            ),
            (finding,),
        )
        collect_mock.assert_called_once_with(
            discovered,
            plan,
            timeout=20,
        )


    @patch("evidence_collector.analyze_scan")
    @patch("evidence_collector.collect_host_evidence")
    def test_correlated_result_keeps_failed_outcome_while_analyzing_discovery_host(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        discovered = Host(
            address="192.0.2.128",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                    product="nginx",
                ),
            ),
        )
        plan = HostEvidencePlan(
            target="192.0.2.128",
            requests=(EvidenceRequest(443, "tcp", "ssl-cert"),),
        )
        command = NmapCommand(("nmap",))
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "collection failed"),
            scan=None,
        )
        collect_mock.return_value = (failed,)
        analyze_mock.return_value = ()

        result = collect_correlated_host_evidence(discovered, plan)

        self.assertEqual(result.outcomes, (failed,))
        self.assertEqual(result.host, discovered)
        analyzed_scan = analyze_mock.call_args.args[0]
        self.assertEqual(analyzed_scan.hosts, (discovered,))


    @patch("evidence_collector.analyze_scan")
    @patch("evidence_collector.collect_host_evidence")
    def test_correlated_result_merges_success_while_preserving_failed_outcome(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        discovered = Host(
            address="192.0.2.129",
            status="up",
            ports=(
                Port(port=443, protocol="tcp", state="open", service="https"),
            ),
        )
        plan = HostEvidencePlan(
            target="192.0.2.129",
            requests=(
                EvidenceRequest(443, "tcp", "ssl-cert"),
                EvidenceRequest(443, "tcp", "ssl-enum-ciphers"),
            ),
        )
        command = NmapCommand(("nmap",))
        successful = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", ""),
            scan=Scan(
                source="nmap stdout",
                hosts=(
                    Host(
                        address="192.0.2.129",
                        status="up",
                        ports=(
                            Port(
                                port=443,
                                protocol="tcp",
                                state="open",
                                scripts=(
                                    ScriptResult("ssl-cert", "certificate evidence"),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "cipher collection failed"),
            scan=None,
        )
        collect_mock.return_value = (successful, failed)
        analyze_mock.return_value = ()

        result = collect_correlated_host_evidence(discovered, plan)

        self.assertEqual(result.outcomes, (successful, failed))
        self.assertEqual(
            result.host.ports[0].scripts,
            (ScriptResult("ssl-cert", "certificate evidence"),),
        )
        analyzed_scan = analyze_mock.call_args.args[0]
        self.assertEqual(analyzed_scan.hosts, (result.host,))


    def test_correlated_result_reports_incomplete_collection(self) -> None:
        host = Host(address="192.0.2.130", status="up")
        command = NmapCommand(("nmap",))
        result = CorrelatedEvidenceResult(
            outcomes=(
                ParsedCollectionResult(
                    result=CollectionResult(command, 0, "<nmaprun />", ""),
                    scan=Scan(source="nmap stdout"),
                ),
                ParsedCollectionResult(
                    result=CollectionResult(command, 1, "", "collection failed"),
                    scan=None,
                ),
            ),
            host=host,
            findings=(),
        )

        self.assertFalse(result.collection_complete)


    def test_correlated_result_reports_complete_collection(self) -> None:
        host = Host(address="192.0.2.131", status="up")
        command = NmapCommand(("nmap",))
        result = CorrelatedEvidenceResult(
            outcomes=(
                ParsedCollectionResult(
                    result=CollectionResult(command, 0, "<nmaprun />", ""),
                    scan=Scan(source="nmap stdout"),
                ),
                ParsedCollectionResult(
                    result=CollectionResult(command, 0, "<nmaprun />", ""),
                    scan=Scan(source="nmap stdout"),
                ),
            ),
            host=host,
            findings=(),
        )

        self.assertTrue(result.collection_complete)


    @patch("evidence_collector.analyze_scan")
    @patch("evidence_collector.collect_host_evidence")
    def test_empty_correlated_plan_is_complete_and_preserves_discovery_host(
        self,
        collect_mock,
        analyze_mock,
    ) -> None:
        discovered = Host(address="192.0.2.132", status="up")
        plan = HostEvidencePlan(target="192.0.2.132", requests=())
        collect_mock.return_value = ()
        analyze_mock.return_value = ()

        result = collect_correlated_host_evidence(discovered, plan)

        self.assertTrue(result.collection_complete)
        self.assertEqual(result.outcomes, ())
        self.assertEqual(result.host, discovered)
        collect_mock.assert_called_once_with(plan, timeout=None)
        analyzed_scan = analyze_mock.call_args.args[0]
        self.assertEqual(analyzed_scan.hosts, (discovered,))


    def test_failed_collection_outcome_exposes_stderr_for_reporting(self) -> None:
        command = NmapCommand(("nmap",))
        outcome = ParsedCollectionResult(
            result=CollectionResult(
                command,
                1,
                "",
                "  permission denied  ",
            ),
            scan=None,
        )

        self.assertEqual(outcome.failure_message, "permission denied")


    def test_failed_collection_outcome_falls_back_to_returncode_message(self) -> None:
        command = NmapCommand(("nmap",))
        outcome = ParsedCollectionResult(
            result=CollectionResult(command, 7, "", "   "),
            scan=None,
        )

        self.assertEqual(outcome.failure_message, "Nmap exited with status 7")


if __name__ == "__main__":
    unittest.main()
