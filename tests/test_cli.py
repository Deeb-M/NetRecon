"""Tests for NetRecon command-line argument validation."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from netrecon import build_parser


class CliTests(unittest.TestCase):
    def test_version_reports_installed_package_version_without_scan(self) -> None:
        parser = build_parser()
        output = StringIO()

        with redirect_stdout(output):
            with self.assertRaises(SystemExit) as context:
                parser.parse_args(["--version"])

        self.assertEqual(context.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "netrecon 0.1.0")

    def test_help_describes_analysis_and_both_comparison_modes(self) -> None:
        parser = build_parser()
        help_text = parser.format_help()
        normalized_help = " ".join(help_text.split())

        self.assertIn(
            "Analyze and compare Nmap XML scans with evidence-based findings and exposure summaries.",
            normalized_help,
        )

        option_strings = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertTrue(
            {"--analyze", "--diff", "--analysis-diff", "--combined-diff", "--collect-evidence"}
            <= option_strings
        )
        self.assertTrue(
            any(action.dest == "compare_scan" for action in parser._actions)
        )

    def test_accepts_combined_diff_mode(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["before.xml", "after.xml", "--combined-diff"])

        self.assertTrue(args.combined_diff)

    def test_rejects_analyze_with_diff(self) -> None:
        parser = build_parser()

        with self.assertRaises(SystemExit) as context:
            parser.parse_args(["scan.xml", "compare.xml", "--analyze", "--diff"])

        self.assertEqual(context.exception.code, 2)

    def test_rejects_diff_with_analysis_diff(self) -> None:
        parser = build_parser()

        with self.assertRaises(SystemExit) as context:
            parser.parse_args(["scan.xml", "compare.xml", "--diff", "--analysis-diff"])

        self.assertEqual(context.exception.code, 2)

    def test_accepts_each_operation_mode_individually(self) -> None:
        parser = build_parser()

        self.assertTrue(parser.parse_args(["scan.xml", "--analyze"]).analyze)
        self.assertTrue(parser.parse_args(["scan.xml", "compare.xml", "--diff"]).diff)
        self.assertTrue(
            parser.parse_args(["scan.xml", "compare.xml", "--analysis-diff"]).analysis_diff
        )
        self.assertTrue(
            parser.parse_args(["scan.xml", "--collect-evidence"]).collect_evidence
        )

    def test_rejects_second_scan_without_comparison_mode(self) -> None:
        from netrecon import main

        with patch("sys.argv", ["netrecon", "scan.xml", "compare.xml"]):
            with self.assertRaises(SystemExit) as context:
                main()

        self.assertEqual(context.exception.code, 2)


    @patch("netrecon.render_evidence_collection", return_value="Evidence report")
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_plans_each_discovered_host(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_mock,
    ) -> None:
        from models import Host, Scan
        from netrecon import main

        first = Host(address="192.0.2.10", status="up")
        second = Host(address="192.0.2.11", status="up")
        parse_mock.return_value = Scan(
            source="scan.xml",
            hosts=(first, second),
        )
        collect_mock.return_value = unittest.mock.MagicMock()

        with patch("sys.argv", ["netrecon", "scan.xml", "--collect-evidence"]):
            self.assertEqual(main(), 0)

        self.assertEqual(
            [call.args[0] for call in plan_mock.call_args_list],
            [first, second],
        )


    @patch("netrecon.render_evidence_collection", return_value="Evidence report")
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_executes_correlated_plan_and_renders_result(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_mock,
    ) -> None:
        from evidence_collector import CorrelatedEvidenceResult
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.20", status="up")
        plan = HostEvidencePlan(target=host.address, requests=())
        result = CorrelatedEvidenceResult(outcomes=(), host=host, findings=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        plan_mock.return_value = plan
        collect_mock.return_value = result
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--collect-evidence"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        collect_mock.assert_called_once_with(host, plan, timeout=60.0)
        render_mock.assert_called_once_with(result)
        self.assertEqual(output.getvalue().strip(), "Evidence report")


    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_reports_collection_error_without_traceback(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
    ) -> None:
        from evidence_collector import EvidenceCollectionError
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.30", status="up")
        plan_mock.return_value = HostEvidencePlan(target=host.address, requests=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        collect_mock.side_effect = EvidenceCollectionError("Nmap executable not found")
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--collect-evidence"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 2)

        self.assertEqual(output.getvalue().strip(), "Error: Nmap executable not found")


    @patch("netrecon.render_evidence_collection", return_value="First host evidence")
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_preserves_prior_host_report_when_later_host_fails(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_mock,
    ) -> None:
        from evidence_collector import CorrelatedEvidenceResult, EvidenceCollectionError
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        first = Host(address="192.0.2.40", status="up")
        second = Host(address="192.0.2.41", status="up")
        first_plan = HostEvidencePlan(target=first.address, requests=())
        second_plan = HostEvidencePlan(target=second.address, requests=())
        first_result = CorrelatedEvidenceResult(outcomes=(), host=first, findings=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(first, second))
        plan_mock.side_effect = (first_plan, second_plan)
        collect_mock.side_effect = (
            first_result,
            EvidenceCollectionError("collection timed out"),
        )
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--collect-evidence"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 2)

        self.assertEqual(
            output.getvalue().strip().splitlines(),
            ["First host evidence", "Error: collection timed out"],
        )
        render_mock.assert_called_once_with(first_result)


    @patch("netrecon.render_evidence_collections_json", return_value='[{"status": "complete"}]')
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_honors_json_format(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_json_mock,
    ) -> None:
        from evidence_collector import CorrelatedEvidenceResult
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.50", status="up")
        plan = HostEvidencePlan(target=host.address, requests=())
        result = CorrelatedEvidenceResult(outcomes=(), host=host, findings=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        plan_mock.return_value = plan
        collect_mock.return_value = result
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--collect-evidence", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        render_json_mock.assert_called_once_with((result,))
        self.assertEqual(output.getvalue().strip(), '[{"status": "complete"}]')


    @patch("netrecon.render_evidence_collections_json", return_value='[{"host": "first"}, {"host": "second"}]')
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_json_batches_multiple_hosts_into_one_document(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_json_mock,
    ) -> None:
        from evidence_collector import CorrelatedEvidenceResult
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        first = Host(address="192.0.2.60", status="up")
        second = Host(address="192.0.2.61", status="up")
        first_result = CorrelatedEvidenceResult(outcomes=(), host=first, findings=())
        second_result = CorrelatedEvidenceResult(outcomes=(), host=second, findings=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(first, second))
        plan_mock.side_effect = (
            HostEvidencePlan(target=first.address, requests=()),
            HostEvidencePlan(target=second.address, requests=()),
        )
        collect_mock.side_effect = (first_result, second_result)
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--collect-evidence", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        render_json_mock.assert_called_once_with((first_result, second_result))
        self.assertEqual(
            output.getvalue().strip(),
            '[{"host": "first"}, {"host": "second"}]',
        )


    @patch("netrecon.render_evidence_collection", return_value="Partial evidence report")
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_cli_returns_success_for_reportable_partial_result(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_mock,
    ) -> None:
        from evidence_collector import CollectionResult, CorrelatedEvidenceResult, NmapCommand, ParsedCollectionResult
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.145", status="up")
        plan = HostEvidencePlan(target=host.address, requests=())
        timed_out = ParsedCollectionResult(
            result=CollectionResult(
                NmapCommand(("nmap",)),
                124,
                "",
                "Nmap evidence collection timed out",
            ),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(timed_out,),
            host=host,
            findings=(),
        )
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        plan_mock.return_value = plan
        collect_mock.return_value = result
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--collect-evidence"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        render_mock.assert_called_once_with(result)
        self.assertEqual(output.getvalue().strip(), "Partial evidence report")

    @patch("netrecon.render_evidence_collections_json")
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_json_preserves_reportable_partial_result(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_json_mock,
    ) -> None:
        import json

        from evidence_collector import CollectionResult, CorrelatedEvidenceResult, NmapCommand, ParsedCollectionResult
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.146", status="up")
        timed_out = ParsedCollectionResult(
            result=CollectionResult(
                NmapCommand(("nmap",)),
                124,
                "",
                "Nmap evidence collection timed out",
            ),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(timed_out,),
            host=host,
            findings=(),
        )
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        plan_mock.return_value = HostEvidencePlan(target=host.address, requests=())
        collect_mock.return_value = result
        render_json_mock.return_value = (
            '[{"host":"192.0.2.146","status":"partial",'
            '"failures":["Nmap evidence collection timed out"],"findings":[]}]'
        )
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--collect-evidence", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        render_json_mock.assert_called_once_with((result,))
        self.assertEqual(
            json.loads(output.getvalue())[0]["status"],
            "partial",
        )

    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_json_failure_remains_valid_json(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
    ) -> None:
        import json

        from evidence_collector import EvidenceCollectionError
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.70", status="up")
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        plan_mock.return_value = HostEvidencePlan(target=host.address, requests=())
        collect_mock.side_effect = EvidenceCollectionError("collection timed out")
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--collect-evidence", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 2)

        self.assertEqual(
            json.loads(output.getvalue()),
            {"results": [], "error": "collection timed out"},
        )


    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_json_failure_preserves_completed_hosts(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
    ) -> None:
        import json

        from evidence_collector import CorrelatedEvidenceResult, EvidenceCollectionError
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        first = Host(address="192.0.2.80", status="up")
        second = Host(address="192.0.2.81", status="up")
        first_result = CorrelatedEvidenceResult(outcomes=(), host=first, findings=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(first, second))
        plan_mock.side_effect = (
            HostEvidencePlan(target=first.address, requests=()),
            HostEvidencePlan(target=second.address, requests=()),
        )
        collect_mock.side_effect = (
            first_result,
            EvidenceCollectionError("second host timed out"),
        )
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--collect-evidence", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 2)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["error"], "second host timed out")
        self.assertEqual(payload["results"][0]["host"], first.address)
        self.assertEqual(payload["results"][0]["status"], "complete")


    @patch("netrecon.render_evidence_collection", return_value="Evidence report")
    @patch("netrecon.collect_correlated_host_evidence")
    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_passes_explicit_timeout_to_collector(
        self,
        parse_mock,
        plan_mock,
        collect_mock,
        render_mock,
    ) -> None:
        from evidence_collector import CorrelatedEvidenceResult
        from evidence_planner import HostEvidencePlan
        from models import Host, Scan
        from netrecon import main

        host = Host(address="192.0.2.90", status="up")
        plan = HostEvidencePlan(target=host.address, requests=())
        result = CorrelatedEvidenceResult(outcomes=(), host=host, findings=())
        parse_mock.return_value = Scan(source="scan.xml", hosts=(host,))
        plan_mock.return_value = plan
        collect_mock.return_value = result

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--collect-evidence", "--evidence-timeout", "12.5"],
        ):
            self.assertEqual(main(), 0)

        collect_mock.assert_called_once_with(host, plan, timeout=12.5)


    def test_rejects_non_positive_evidence_timeout(self) -> None:
        parser = build_parser()

        for value in ("0", "-1"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit) as context:
                    parser.parse_args(
                        ["scan.xml", "--collect-evidence", "--evidence-timeout", value]
                    )

                self.assertEqual(context.exception.code, 2)


    def test_rejects_non_finite_evidence_timeout(self) -> None:
        parser = build_parser()

        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit) as context:
                    parser.parse_args(
                        ["scan.xml", "--collect-evidence", "--evidence-timeout", value]
                    )

                self.assertEqual(context.exception.code, 2)


    @patch("netrecon.render_findings", return_value="Findings report")
    @patch("netrecon.render_host_summaries", return_value="Host summary report")
    @patch("netrecon.render_text", return_value="Scan report")
    @patch("netrecon.analyze_scan", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_analyze_text_includes_host_summary_before_findings(
        self,
        parse_mock,
        analyze_mock,
        render_text_mock,
        render_host_summaries_mock,
        render_findings_mock,
    ) -> None:
        from models import Scan
        from netrecon import main

        scan = Scan(source="scan.xml")
        parse_mock.return_value = scan
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--analyze"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        render_host_summaries_mock.assert_called_once_with(scan, ())
        self.assertEqual(
            output.getvalue().strip().splitlines(),
            ["Scan report", "", "Host summary report", "", "Findings report"],
        )


if __name__ == "__main__":
    unittest.main()
