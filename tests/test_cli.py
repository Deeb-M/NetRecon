"""Tests for NetRecon command-line argument validation."""

import subprocess
import sys
import json
import unittest
import tempfile
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from evidence_action_plan import EvidenceAction
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
            {"--analyze", "--diff", "--analysis-diff", "--combined-diff", "--collect-evidence", "--history", "--finding-history", "--evidence-gaps"}
            <= option_strings
        )
        self.assertTrue(
            any(action.dest == "compare_scan" for action in parser._actions)
        )

    def test_accepts_combined_diff_mode(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["before.xml", "after.xml", "--combined-diff"])

        self.assertTrue(args.combined_diff)


    def test_accepts_history_with_multiple_scan_files(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["--history", "one.xml", "two.xml", "three.xml"])

        self.assertEqual(
            [str(path) for path in args.history],
            ["one.xml", "two.xml", "three.xml"],
        )

    def test_history_requires_at_least_two_scan_files(self) -> None:
        parser = build_parser()

        with self.assertRaises(SystemExit) as context:
            parser.parse_args(["--history", "one.xml"])

        self.assertEqual(context.exception.code, 2)

    def test_rejects_history_with_other_operation_mode(self) -> None:
        parser = build_parser()

        with self.assertRaises(SystemExit) as context:
            parser.parse_args(["scan.xml", "--analyze", "--history", "one.xml", "two.xml"])

        self.assertEqual(context.exception.code, 2)



    @patch("netrecon.render_exposure_history", return_value="History report")
    @patch("netrecon.summarize_exposure_history", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_history_parses_all_scans_and_renders_text(
        self,
        parse_mock,
        summarize_mock,
        render_mock,
    ) -> None:
        from models import Scan
        from netrecon import main

        scans = (
            Scan(source="one.xml"),
            Scan(source="two.xml"),
            Scan(source="three.xml"),
        )
        parse_mock.side_effect = scans
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--history", "one.xml", "two.xml", "three.xml"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        self.assertEqual(parse_mock.call_count, 3)
        summarize_mock.assert_called_once_with(scans)
        render_mock.assert_called_once_with(())
        self.assertEqual(output.getvalue().strip(), "History report")

    @patch("netrecon.render_exposure_history_json", return_value='{"report_type":"exposure_history"}')
    @patch("netrecon.summarize_exposure_history", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_history_honors_json_format(
        self,
        parse_mock,
        summarize_mock,
        render_json_mock,
    ) -> None:
        from models import Scan
        from netrecon import main

        scans = (Scan(source="one.xml"), Scan(source="two.xml"))
        parse_mock.side_effect = scans
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--history", "one.xml", "two.xml", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        summarize_mock.assert_called_once_with(scans)
        render_json_mock.assert_called_once_with(())
        self.assertEqual(
            output.getvalue().strip(),
            '{"report_type":"exposure_history"}',
        )


    def test_accepts_finding_history_with_multiple_scan_files(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["--finding-history", "one.xml", "two.xml"])

        self.assertEqual([str(path) for path in args.finding_history], ["one.xml", "two.xml"])

    def test_finding_history_requires_at_least_two_scan_files(self) -> None:
        parser = build_parser()

        with self.assertRaises(SystemExit) as context:
            parser.parse_args(["--finding-history", "one.xml"])

        self.assertEqual(context.exception.code, 2)

    @patch("netrecon.render_finding_history", return_value="Finding history report")
    @patch("netrecon.summarize_finding_history", return_value=())
    @patch("netrecon.analyze_scan")
    @patch("netrecon.parse_nmap_xml")
    def test_finding_history_analyzes_each_scan_and_renders_text(
        self, parse_mock, analyze_mock, summarize_mock, render_mock
    ) -> None:
        from models import Scan
        from netrecon import main

        scans = (Scan(source="one.xml"), Scan(source="two.xml"))
        findings = ((), ())
        parse_mock.side_effect = scans
        analyze_mock.side_effect = findings
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--finding-history", "one.xml", "two.xml"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        self.assertEqual(parse_mock.call_count, 2)
        self.assertEqual([call.args[0] for call in analyze_mock.call_args_list], list(scans))
        summarize_mock.assert_called_once_with(scans, findings)
        render_mock.assert_called_once_with(())
        self.assertEqual(output.getvalue().strip(), "Finding history report")

    @patch("netrecon.render_finding_history_json", return_value='{"report_type":"finding_history"}')
    @patch("netrecon.summarize_finding_history", return_value=())
    @patch("netrecon.analyze_scan", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_finding_history_honors_json_format(
        self, parse_mock, analyze_mock, summarize_mock, render_json_mock
    ) -> None:
        from models import Scan
        from netrecon import main

        scans = (Scan(source="one.xml"), Scan(source="two.xml"))
        parse_mock.side_effect = scans
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--finding-history", "one.xml", "two.xml", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        summarize_mock.assert_called_once_with(scans, ((), ()))
        render_json_mock.assert_called_once_with(())
        self.assertEqual(output.getvalue().strip(), '{"report_type":"finding_history"}')

    def test_finding_history_cli_integrates_parser_analyzer_engine_and_reporter(self) -> None:
        from netrecon import main

        xml_template = """<?xml version="1.0"?>
<nmaprun start="{timestamp}">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="445"/>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb2-security-mode" output="Message signing enabled but not required"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="{timestamp}"/></runstats>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "one.xml"
            second = Path(directory) / "two.xml"
            first.write_text(xml_template.format(timestamp=100), encoding="utf-8")
            second.write_text(xml_template.format(timestamp=200), encoding="utf-8")
            output = StringIO()

            with patch("sys.argv", ["netrecon", "--finding-history", str(first), str(second)]):
                with redirect_stdout(output):
                    self.assertEqual(main(), 0)

        report = output.getvalue()
        self.assertIn("Finding History", report)
        self.assertIn("smb.signing.review", report)
        self.assertIn("observations=2", report)
        self.assertIn("opportunities=2", report)

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


    def test_accepts_evidence_gaps_mode(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["scan.xml", "--evidence-gaps"])

        self.assertTrue(args.evidence_gaps)

    @patch("netrecon.render_evidence_gaps", return_value="Evidence gaps report")
    @patch("netrecon.summarize_evidence_gaps", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_evidence_gaps_renders_text(
        self, parse_mock, summarize_mock, render_mock
    ) -> None:
        from models import Scan
        from netrecon import main

        scan = Scan(source="scan.xml")
        parse_mock.return_value = scan
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--evidence-gaps"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        summarize_mock.assert_called_once_with(scan)
        render_mock.assert_called_once_with(())
        self.assertEqual(output.getvalue().strip(), "Evidence gaps report")

    @patch("netrecon.render_evidence_gaps_json", return_value='{"report_type":"evidence_gaps"}')
    @patch("netrecon.summarize_evidence_gaps", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_evidence_gaps_honors_json_format(
        self, parse_mock, summarize_mock, render_json_mock
    ) -> None:
        from models import Scan
        from netrecon import main

        scan = Scan(source="scan.xml")
        parse_mock.return_value = scan
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--evidence-gaps", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        summarize_mock.assert_called_once_with(scan)
        render_json_mock.assert_called_once_with(())
        self.assertEqual(output.getvalue().strip(), '{"report_type":"evidence_gaps"}')


    def test_evidence_gaps_integration_from_real_xml_to_cli_output(self) -> None:
        from netrecon import main

        xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 445 -oX - 192.0.2.60" start="100">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="445"/>
  <host>
    <status state="up"/>
    <address addr="192.0.2.60" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="101"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "scan.xml"
            path.write_text(xml, encoding="utf-8")
            output = StringIO()

            with patch("sys.argv", ["netrecon", str(path), "--evidence-gaps"]):
                with redirect_stdout(output):
                    self.assertEqual(main(), 0)

        report = output.getvalue()
        self.assertIn("Evidence Gaps", report)
        self.assertIn("Gaps: 2", report)
        self.assertIn("192.0.2.60:445/tcp  smb-protocols", report)
        self.assertIn("review SMB protocol dialect support", report)
        self.assertIn("192.0.2.60:445/tcp  smb2-security-mode", report)
        self.assertIn("review SMB signing configuration", report)


    def test_accepts_evidence_actions_mode(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["scan.xml", "--evidence-actions"])

        self.assertTrue(args.evidence_actions)

    @patch("netrecon.render_evidence_action_plan", return_value="Evidence action plan")
    @patch("netrecon.build_evidence_action_plan", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_evidence_actions_renders_text(
        self, parse_mock, build_mock, render_mock
    ) -> None:
        from models import Scan
        from netrecon import main

        scan = Scan(source="scan.xml")
        parse_mock.return_value = scan
        output = StringIO()

        with patch("sys.argv", ["netrecon", "scan.xml", "--evidence-actions"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_mock.assert_called_once_with(scan)
        render_mock.assert_called_once_with(())
        self.assertEqual(output.getvalue().strip(), "Evidence action plan")

    @patch(
        "netrecon.render_evidence_action_plan_json",
        return_value='{"report_type":"evidence_action_plan"}',
    )
    @patch("netrecon.build_evidence_action_plan", return_value=())
    @patch("netrecon.parse_nmap_xml")
    def test_evidence_actions_honors_json_format(
        self, parse_mock, build_mock, render_json_mock
    ) -> None:
        from models import Scan
        from netrecon import main

        scan = Scan(source="scan.xml")
        parse_mock.return_value = scan
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "scan.xml", "--evidence-actions", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_mock.assert_called_once_with(scan)
        render_json_mock.assert_called_once_with(())
        self.assertEqual(
            output.getvalue().strip(),
            '{"report_type":"evidence_action_plan"}',
        )


    def test_evidence_actions_integration_from_real_xml_to_cli_output(self) -> None:
        from netrecon import main

        xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -p 445 -oX - 192.0.2.70" start="100">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="445"/>
  <host>
    <status state="up"/>
    <address addr="192.0.2.70" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="101"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "scan.xml"
            path.write_text(xml, encoding="utf-8")
            output = StringIO()

            with patch("sys.argv", ["netrecon", str(path), "--evidence-actions"]):
                with redirect_stdout(output):
                    self.assertEqual(main(), 0)

        report = output.getvalue()
        self.assertIn("Evidence Action Plan", report)
        self.assertIn("Actions: 1", report)
        self.assertIn("192.0.2.70:445/tcp", report)
        self.assertIn("review SMB protocol dialect support", report)
        self.assertIn("review SMB signing configuration", report)
        self.assertIn(
            "nmap -p 445 --script smb-protocols,smb2-security-mode -oX - 192.0.2.70",
            report,
        )


    def test_accepts_discovery_plan_target(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["--discovery-plan", "192.0.2.10"])

        self.assertEqual(args.discovery_plan, "192.0.2.10")

    @patch("netrecon.render_discovery_plan", return_value="Discovery plan report")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_discovery_plan_renders_text_without_execution(
        self, build_mock, render_mock
    ) -> None:
        from netrecon import main
        from scan_orchestration import DiscoveryPlan

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        build_mock.return_value = plan
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--discovery-plan", "192.0.2.10"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_mock.assert_called_once_with("192.0.2.10")
        render_mock.assert_called_once_with(plan)
        self.assertEqual(output.getvalue().strip(), "Discovery plan report")

    @patch(
        "netrecon.render_discovery_plan_json",
        return_value='{"report_type":"discovery_plan"}',
    )
    @patch("netrecon.build_baseline_discovery_plan")
    def test_discovery_plan_honors_json_format(
        self, build_mock, render_json_mock
    ) -> None:
        from netrecon import main
        from scan_orchestration import DiscoveryPlan

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        build_mock.return_value = plan
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--discovery-plan", "192.0.2.10", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_mock.assert_called_once_with("192.0.2.10")
        render_json_mock.assert_called_once_with(plan)
        self.assertEqual(output.getvalue().strip(), '{"report_type":"discovery_plan"}')


    def test_discovery_plan_integration_from_target_to_text_output(self) -> None:
        from netrecon import main

        output = StringIO()
        with patch("sys.argv", ["netrecon", "--discovery-plan", "192.0.2.10"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        report = output.getvalue()
        self.assertIn("Discovery Plan", report)
        self.assertIn("Target: 192.0.2.10", report)
        self.assertIn("Profile: baseline", report)
        self.assertIn(
            "Purpose: discover open TCP services with version detection",
            report,
        )
        self.assertIn(
            "Suggested discovery: nmap -sV -oX - 192.0.2.10",
            report,
        )

    def test_discovery_plan_integration_from_target_to_json_output(self) -> None:
        from netrecon import main

        output = StringIO()
        with patch(
            "sys.argv",
            ["netrecon", "--discovery-plan", "192.0.2.10", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["report_type"], "discovery_plan")
        self.assertEqual(payload["target"], "192.0.2.10")
        self.assertEqual(payload["profile"], "baseline")
        self.assertEqual(
            payload["command"],
            ["nmap", "-sV", "-oX", "-", "192.0.2.10"],
        )


    def test_accepts_discover_target(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["--discover", "192.0.2.10"])

        self.assertEqual(args.discover, "192.0.2.10")

    @patch("netrecon.render_discovery_execution", return_value="Discovery execution report")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_discover_executes_only_the_built_plan_and_renders_text(
        self, build_mock, execute_mock, interpret_mock, render_mock
    ) -> None:
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        result = DiscoveryResult(execution, True, None, None)
        build_mock.return_value = plan
        execute_mock.return_value = execution
        interpret_mock.return_value = result
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--discover", "192.0.2.10"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_mock.assert_called_once_with("192.0.2.10")
        execute_mock.assert_called_once_with(plan, timeout=60.0)
        interpret_mock.assert_called_once_with(execution)
        render_mock.assert_called_once_with(result)
        self.assertEqual(output.getvalue().strip(), "Discovery execution report")

    @patch("netrecon.render_discovery_execution_json", return_value='{"status":"failed"}')
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_discover_returns_two_for_failed_execution_and_honors_json(
        self, build_mock, execute_mock, interpret_mock, render_mock
    ) -> None:
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 2, "", "nmap failed", False)
        result = DiscoveryResult(execution, False, None, "nmap failed")
        build_mock.return_value = plan
        execute_mock.return_value = execution
        interpret_mock.return_value = result
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--discover", "192.0.2.10", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 2)

        execute_mock.assert_called_once_with(plan, timeout=60.0)
        render_mock.assert_called_once_with(result)
        self.assertEqual(output.getvalue().strip(), '{"status":"failed"}')


    def test_accepts_investigate_target(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["--investigate", "192.0.2.10"])

        self.assertEqual(args.investigate, "192.0.2.10")

    @patch("netrecon.render_investigation_snapshot", return_value="Investigation report")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_runs_baseline_discovery_then_builds_snapshot(
        self,
        build_plan_mock,
        execute_mock,
        interpret_mock,
        snapshot_mock,
        render_mock,
    ) -> None:
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        discovery = DiscoveryResult(execution, True, object(), None)
        from investigation_orchestration import InvestigationSnapshot
        snapshot = InvestigationSnapshot(True, discovery.scan, (), (), (), None)
        build_plan_mock.return_value = plan
        execute_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = snapshot
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--investigate", "192.0.2.10"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_plan_mock.assert_called_once_with("192.0.2.10")
        execute_mock.assert_called_once_with(plan, timeout=60.0)
        interpret_mock.assert_called_once_with(execution)
        snapshot_mock.assert_called_once_with(discovery)
        render_mock.assert_called_once_with(snapshot)
        self.assertEqual(output.getvalue().strip(), "Investigation report")

    @patch("netrecon.render_investigation_snapshot_json", return_value='{"status":"blocked"}')
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_failed_discovery_returns_two_and_honors_json(
        self,
        build_plan_mock,
        execute_mock,
        interpret_mock,
        snapshot_mock,
        render_mock,
    ) -> None:
        from investigation_orchestration import InvestigationSnapshot
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 2, "", "nmap failed", False)
        discovery = DiscoveryResult(execution, False, None, "nmap failed")
        snapshot = InvestigationSnapshot(False, None, (), (), (), "nmap failed")
        build_plan_mock.return_value = plan
        execute_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = snapshot
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--investigate", "192.0.2.10", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 2)

        snapshot_mock.assert_called_once_with(discovery)
        render_mock.assert_called_once_with(snapshot)
        self.assertEqual(output.getvalue().strip(), '{"status":"blocked"}')


    def test_installed_cli_help_exposes_discover_mode(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "netrecon", "--help"],
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--investigate TARGET", completed.stdout)
        self.assertIn("--discover TARGET", completed.stdout)
        self.assertIn("--discovery-plan TARGET", completed.stdout)


    def test_accepts_explicit_investigate_collect_target(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["--investigate-collect", "192.0.2.10"])

        self.assertEqual(args.investigate_collect, "192.0.2.10")

    @patch("netrecon.build_investigation_explanation", return_value="explanation-model")
    @patch("netrecon.render_investigation_explanation", return_value="Investigation Explanation")
    @patch("netrecon.render_investigation_continuation", return_value="Investigation continuation")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_explicitly_executes_planned_evidence_then_renders_updated_snapshot(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        render_mock,
        render_explanation_mock,
        build_explanation_mock,
    ) -> None:
        from investigation_orchestration import (
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult
        from models import Scan

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        scan = Scan(source="discovery.xml")
        discovery = DiscoveryResult(execution, True, scan, None)
        initial = InvestigationSnapshot(True, scan, (), (), (), None)
        updated = InvestigationSnapshot(True, scan, (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        from investigation_orchestration import InvestigationContinuationDecision, FinalInvestigationDecision
        decision = InvestigationContinuationDecision("complete", (), (), ())
        final_decision = FinalInvestigationDecision("complete", "all_gaps_resolved", ())
        decision_mock.return_value = decision
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--investigate-collect", "192.0.2.10"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        snapshot_mock.assert_called_once_with(discovery)
        execute_evidence_mock.assert_called_once_with(initial, timeout=60.0)
        decision_mock.assert_called_once_with(
            initial,
            updated,
            attempted_actions=initial.actions,
        )
        render_mock.assert_called_once_with(
            continuation, decision, None, final_decision, (), (),
            final_snapshot=continuation.snapshot,
        )
        build_explanation_mock.assert_called_once_with(continuation.snapshot, final_decision=final_decision)
        render_explanation_mock.assert_called_once_with("explanation-model")
        rendered = output.getvalue()
        self.assertIn("Investigation continuation", rendered)
        self.assertIn("Investigation Explanation", rendered)
        self.assertIn("Investigation Synthesis", rendered)
        self.assertIn("Status: complete", rendered)
        self.assertIn("Reason: all_gaps_resolved", rendered)


    @patch("netrecon.render_investigation_continuation", return_value="Investigation continuation")
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_executes_one_selected_alternative_round(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        alternative_round_mock,
        render_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan("192.0.2.10", "baseline", "purpose", ("nmap", "-sV", "-oX", "-", "192.0.2.10"))
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        scan = Scan(source="discovery.xml")
        discovery = DiscoveryResult(execution, True, scan, None)
        initial = InvestigationSnapshot(True, scan, (), (), (), None)
        updated = InvestigationSnapshot(True, scan, (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        alternative = EvidenceAction(
            host="192.0.2.10",
            port=5357,
            protocol="tcp",
            script_ids=("http-headers",),
            purposes=("review HTTP response headers for service identity and context",),
            command=("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.10"),
        )
        decision = InvestigationContinuationDecision(
            "stalled",
            (),
            (),
            (),
            repeat_blocked_actions=(),
            stall_reason="repeated_actions_exhausted",
            alternative_actions=(alternative,),
        )
        alternative_result = AlternativeEvidenceRoundResult((), (), updated)
        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        alternative_round_mock.return_value = alternative_result
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.10", "--evidence-timeout", "7"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        alternative_round_mock.assert_called_once_with(
            updated,
            (alternative,),
            timeout=7.0,
            explicitly_approved_requirement_ids=frozenset(),
        )
        from investigation_orchestration import FinalInvestigationDecision
        render_mock.assert_called_once_with(
            continuation,
            decision,
            alternative_result,
            FinalInvestigationDecision("complete", "all_gaps_resolved", (), ()),
            (),
            (),
            final_snapshot=updated,
        )

    @patch("netrecon.render_investigation_continuation_json", return_value='{"report_type":"investigation_continuation"}')
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_investigation_explanation", return_value="explanation-model")
    @patch("netrecon.render_investigation_explanation_json", return_value='{"report_type":"investigation_explanation","known":[],"unresolved":[],"blocked":[],"next_actions":[]}' )
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_json_renders_continuation_provenance(
        self,
        build_plan_mock,
        render_explanation_json_mock,
        build_explanation_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        render_json_mock,
    ) -> None:
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from models import Scan
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        scan = Scan(source="discovery.xml")
        discovery = DiscoveryResult(execution, True, scan, None)
        initial = InvestigationSnapshot(True, scan, (), (), (), None)
        updated = InvestigationSnapshot(True, scan, (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        from investigation_orchestration import InvestigationContinuationDecision, FinalInvestigationDecision
        decision = InvestigationContinuationDecision("complete", (), (), ())
        final_decision = FinalInvestigationDecision("complete", "all_gaps_resolved", ())
        decision_mock.return_value = decision
        output = StringIO()

        with patch(
            "sys.argv",
            ["netrecon", "--investigate-collect", "192.0.2.10", "--format", "json"],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        decision_mock.assert_called_once_with(
            initial,
            updated,
            attempted_actions=initial.actions,
        )
        render_json_mock.assert_called_once_with(
            continuation, decision, None, final_decision, (), (),
            final_snapshot=continuation.snapshot,
        )
        build_explanation_mock.assert_called_once_with(continuation.snapshot, final_decision=final_decision)
        render_explanation_json_mock.assert_called_once_with("explanation-model")
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["report_type"], "investigation_continuation")
        self.assertEqual(
            payload["investigation_explanation"]["report_type"],
            "investigation_explanation",
        )


    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_blocked_discovery_does_not_execute_evidence(
        self, build_plan_mock, execute_discovery_mock, interpret_mock, snapshot_mock, execute_evidence_mock
    ) -> None:
        from investigation_orchestration import InvestigationSnapshot
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan("192.0.2.10", "baseline", "purpose", ("nmap", "-sV", "-oX", "-", "192.0.2.10"))
        execution = DiscoveryExecutionResult(plan, 2, "", "failed", False)
        discovery = DiscoveryResult(execution, False, None, "failed")
        blocked = InvestigationSnapshot(False, None, (), (), (), "failed")
        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = blocked

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.10"]):
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 2)

        execute_evidence_mock.assert_not_called()

    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_passes_custom_timeout_to_discovery_and_evidence(
        self, build_plan_mock, execute_discovery_mock, interpret_mock, snapshot_mock, execute_evidence_mock
    ) -> None:
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from models import Scan
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan("192.0.2.10", "baseline", "purpose", ("nmap", "-sV", "-oX", "-", "192.0.2.10"))
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        scan = Scan(source="discovery.xml")
        discovery = DiscoveryResult(execution, True, scan, None)
        snapshot = InvestigationSnapshot(True, scan, (), (), (), None)
        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.10", "--evidence-timeout", "7"]):
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)

        execute_discovery_mock.assert_called_once_with(plan, timeout=7.0)
        execute_evidence_mock.assert_called_once_with(snapshot, timeout=7.0)

    @patch("netrecon.execute_approved_evidence_actions")
    def test_investigate_preview_never_executes_approved_evidence(self, execute_evidence_mock) -> None:
        from netrecon import main

        with patch("netrecon.build_baseline_discovery_plan") as build_plan_mock, \
             patch("netrecon.execute_discovery_plan") as execute_discovery_mock, \
             patch("netrecon.interpret_discovery_execution") as interpret_mock, \
             patch("netrecon.build_investigation_snapshot") as snapshot_mock, \
             patch("netrecon.render_investigation_snapshot", return_value="preview"), \
             patch("sys.argv", ["netrecon", "--investigate", "192.0.2.10"]):
            from investigation_orchestration import InvestigationSnapshot
            from models import Scan
            from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult
            plan = DiscoveryPlan("192.0.2.10", "baseline", "purpose", ("nmap", "-sV", "-oX", "-", "192.0.2.10"))
            execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
            scan = Scan(source="discovery.xml")
            discovery = DiscoveryResult(execution, True, scan, None)
            snapshot = InvestigationSnapshot(True, scan, (), (), (), None)
            build_plan_mock.return_value = plan
            execute_discovery_mock.return_value = execution
            interpret_mock.return_value = discovery
            snapshot_mock.return_value = snapshot
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)

        execute_evidence_mock.assert_not_called()



    def test_attention_cli_integrates_parser_analyzer_and_reporter_without_collection(self) -> None:
        from netrecon import main

        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.40" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="100"/></runstats>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "scan.xml"
            scan.write_text(xml, encoding="utf-8")
            output = StringIO()

            with patch("netrecon.collect_correlated_host_evidence") as collect_mock:
                with patch("sys.argv", ["netrecon", str(scan), "--attention"]):
                    with redirect_stdout(output):
                        self.assertEqual(main(), 0)

            collect_mock.assert_not_called()

        report = output.getvalue()
        self.assertIn("Analyst Attention", report)
        self.assertIn("SMB service exposed", report)
        self.assertIn("Evidence Source: service:detection", report)
        self.assertIn("Location: 192.0.2.40:445/tcp", report)



    @patch("netrecon.render_investigation_continuation", return_value="Investigation with attention")
    @patch("netrecon.correlate_analyst_attention", return_value=("correlation-item",))
    @patch("netrecon.build_investigation_attention", return_value=("attention-item",))
    @patch("netrecon.assess_final_investigation_decision")
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_builds_attention_from_final_alternative_snapshot(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        alternative_round_mock,
        final_decision_mock,
        attention_mock,
        correlation_mock,
        render_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            FinalInvestigationDecision,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        initial = InvestigationSnapshot(True, Scan(source="initial.xml"), (), (), (), None)
        updated = InvestigationSnapshot(True, Scan(source="updated.xml"), (), (), (), None)
        final_snapshot = InvestigationSnapshot(True, Scan(source="final.xml"), (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        alternative = EvidenceAction(
            "192.0.2.10", 5357, "tcp", ("http-headers",),
            ("review HTTP response headers for service identity and context",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.10"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )
        alternative_result = AlternativeEvidenceRoundResult((), (), final_snapshot)
        final_decision = FinalInvestigationDecision("complete", "all_gaps_resolved", ())

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        alternative_round_mock.return_value = alternative_result
        final_decision_mock.return_value = final_decision
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.10"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        attention_mock.assert_called_once_with(final_snapshot)
        correlation_mock.assert_called_once_with(("attention-item",))
        render_mock.assert_called_once_with(
            continuation,
            decision,
            alternative_result,
            final_decision,
            ("attention-item",),
            ("correlation-item",),
            final_snapshot=final_snapshot,
        )


    @patch("netrecon.render_investigation_explanation", return_value="Investigation Explanation\n-------------------------\nKnown\nUnresolved\nBlocked\nNext")
    @patch("netrecon.build_investigation_explanation", return_value="explanation-model")
    @patch("netrecon.render_investigation_synthesis", return_value="Investigation Synthesis\nStatus: stalled")
    @patch("netrecon.build_investigation_synthesis", return_value="synthesis-result")
    @patch("netrecon.render_investigation_continuation", return_value="Investigation Continuation")
    @patch("netrecon.correlate_analyst_attention", return_value=("correlation-item",))
    @patch("netrecon.build_investigation_attention", return_value=("attention-item",))
    @patch("netrecon.assess_final_investigation_decision")
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_appends_synthesis_after_terminal_decision(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        alternative_round_mock,
        final_decision_mock,
        attention_mock,
        correlation_mock,
        render_continuation_mock,
        synthesis_mock,
        render_synthesis_mock,
        build_explanation_mock,
        render_explanation_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            FinalInvestigationDecision,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        initial = InvestigationSnapshot(True, Scan("initial.xml"), (), (), (), None)
        updated = InvestigationSnapshot(True, Scan("updated.xml"), (), (), (), None)
        final_snapshot = InvestigationSnapshot(True, Scan("final.xml"), (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        alternative = EvidenceAction(
            "192.0.2.120", 5357, "tcp", ("http-headers",), ("purpose",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.120"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )
        alternative_result = AlternativeEvidenceRoundResult((), (), final_snapshot)
        final_decision = FinalInvestigationDecision(
            "stalled", "alternative_evidence_incomplete", ()
        )

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        alternative_round_mock.return_value = alternative_result
        final_decision_mock.return_value = final_decision
        output = StringIO()

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.120"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_explanation_mock.assert_called_once_with(
            final_snapshot,
            final_decision=final_decision,
        )
        synthesis_mock.assert_called_once_with(
            final_decision,
            ("attention-item",),
            ("correlation-item",),
        )
        render_synthesis_mock.assert_called_once_with("synthesis-result")
        self.assertEqual(
            output.getvalue().strip(),
            "Investigation Continuation\n\n"
            "Investigation Explanation\n-------------------------\n"
            "Known\nUnresolved\nBlocked\nNext\n\n"
            "Investigation Synthesis\nStatus: stalled",
        )




    def test_investigation_history_path_is_not_a_standalone_mode(self) -> None:
        from netrecon import build_parser

        parser = build_parser()
        args = parser.parse_args(
            ["--investigate-collect", "192.0.2.170", "--investigation-history", "history.jsonl"]
        )

        self.assertEqual(args.investigate_collect, "192.0.2.170")
        self.assertEqual(str(args.investigation_history), "history.jsonl")
        self.assertIsNone(args.history)
        self.assertIsNone(args.finding_history)




    def test_investigation_history_v1_remains_readable(self) -> None:
        import json
        from investigation_history import parse_investigation_history_record_json

        payload = json.dumps({
            "schema_version": 1,
            "observed_at": 1,
            "target": "192.0.2.244",
            "synthesis": {
                "status": "complete",
                "reason": "all_gaps_resolved",
                "attention_items": 0,
                "correlated_review_groups": 0,
                "remaining_requirements": [],
            },
        })

        record = parse_investigation_history_record_json(payload)

        self.assertEqual(record.schema_version, 1)
        self.assertEqual(record.synthesis.remaining_finding_requirements, ())

    def test_investigation_history_v2_round_trip_preserves_finding_requirements(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_history import (
            InvestigationHistoryRecord,
            parse_investigation_history_record_json,
            render_investigation_history_record_json,
        )
        from investigation_synthesis import InvestigationSynthesis

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.251",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement,
            "pending_approval",
            "explicit_approval_required",
            ("smb2-security-mode",),
        )
        original = InvestigationHistoryRecord(
            123,
            "192.0.2.251",
            InvestigationSynthesis(
                "stalled",
                "explicit_approval_required",
                1,
                0,
                (),
                (state,),
            ),
        )

        restored = parse_investigation_history_record_json(
            render_investigation_history_record_json(original)
        )

        self.assertEqual(restored.schema_version, 2)
        self.assertEqual(restored.synthesis.remaining_finding_requirements, (state,))

    def test_investigation_history_v2_round_trip_preserves_unsatisfied_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_history import (
            InvestigationHistoryRecord,
            parse_investigation_history_record_json,
            render_investigation_history_record_json,
        )
        from investigation_synthesis import InvestigationSynthesis

        requirement = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.253", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement,
            "attempted_unsatisfied",
            "explicitly_approved",
            ("smb-enum-shares",),
        )
        original = InvestigationHistoryRecord(
            124,
            "192.0.2.253",
            InvestigationSynthesis(
                "stalled",
                "finding_requirement_unsatisfied",
                1,
                0,
                (),
                (state,),
            ),
        )

        restored = parse_investigation_history_record_json(
            render_investigation_history_record_json(original)
        )

        self.assertEqual(restored.schema_version, 2)
        self.assertEqual(restored.synthesis.remaining_finding_requirements, (state,))

    def test_investigation_history_rejects_unknown_schema_version(self) -> None:
        import json
        from investigation_history import parse_investigation_history_record_json

        payload = json.dumps({
            "schema_version": 3,
            "observed_at": 1,
            "target": "192.0.2.252",
            "synthesis": {},
        })

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported investigation history schema version: 3",
        ):
            parse_investigation_history_record_json(payload)

    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.load_investigation_history", return_value=())
    @patch("netrecon.build_investigation_synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_completed_investigation_is_appended_to_history_without_alternative_round(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        load_history_mock,
        append_mock,
    ) -> None:
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from investigation_synthesis import InvestigationSynthesis
        from models import Scan
        from netrecon import main

        complete_synthesis = InvestigationSynthesis("complete", "all_gaps_resolved", 0, 0, ())
        synthesis_mock.return_value = complete_synthesis
        snapshot = InvestigationSnapshot(True, Scan("complete.xml"), (), (), (), None)
        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)
        decision_mock.return_value = InvestigationContinuationDecision("complete", (), (), ())

        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.240",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        synthesis_mock.assert_called_once()
        load_history_mock.assert_not_called()
        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(appended.target, "192.0.2.240")
        self.assertIs(appended.synthesis, complete_synthesis)


    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.build_investigation_synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_stalled_investigation_is_appended_to_history_without_alternative_round(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        append_mock,
    ) -> None:
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from investigation_synthesis import InvestigationSynthesis
        from models import Scan
        from netrecon import main

        stalled_synthesis = InvestigationSynthesis(
            "stalled", "no_supported_actions", 0, 0, ()
        )
        synthesis_mock.return_value = stalled_synthesis
        snapshot = InvestigationSnapshot(True, Scan("stalled.xml"), (), (), (), None)
        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)
        decision_mock.return_value = InvestigationContinuationDecision(
            "stalled", (), (), (), stall_reason="no_supported_actions"
        )

        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.245",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(appended.target, "192.0.2.245")
        self.assertIs(appended.synthesis, stalled_synthesis)

    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.compare_investigation_syntheses")
    @patch("netrecon.latest_investigation_for_target")
    @patch("netrecon.load_investigation_history")
    @patch("netrecon.build_investigation_synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_terminal_investigation_flows_through_synthesis_history_and_memory(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        load_history_mock,
        latest_mock,
        compare_mock,
        append_mock,
    ) -> None:
        from investigation_history import InvestigationHistoryRecord
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from investigation_synthesis import InvestigationSynthesis
        from models import Scan
        from netrecon import main

        snapshot = InvestigationSnapshot(True, Scan("e2e.xml"), (), (), (), None)
        decision = InvestigationContinuationDecision("complete", (), (), ())
        current = InvestigationSynthesis("complete", "all_gaps_resolved", 0, 0, ())
        previous_synthesis = InvestigationSynthesis(
            "stalled", "no_supported_actions", 0, 0, ()
        )
        previous = InvestigationHistoryRecord(100, "192.0.2.203", previous_synthesis)

        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)
        decision_mock.return_value = decision
        synthesis_mock.return_value = current
        load_history_mock.return_value = (previous,)
        latest_mock.return_value = previous
        from investigation_memory import InvestigationMemory
        compare_mock.return_value = InvestigationMemory(
            True,
            "stalled",
            "complete",
            True,
            "no_supported_actions",
            "all_gaps_resolved",
            0,
            0,
            (),
            (),
        )

        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.touch()
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.203",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        synthesis_mock.assert_called_once()
        load_history_mock.assert_called_once_with(str(history_path))
        latest_mock.assert_called_once_with((previous,), "192.0.2.203")
        compare_mock.assert_called_once_with(previous_synthesis, current)
        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(appended.target, "192.0.2.203")
        self.assertIs(appended.synthesis, current)

    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.compare_investigation_syntheses")
    @patch("netrecon.latest_investigation_for_target")
    @patch("netrecon.load_investigation_history")
    @patch("netrecon.build_investigation_synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_terminal_stalled_investigation_flows_through_synthesis_history_and_memory(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        load_history_mock,
        latest_mock,
        compare_mock,
        append_mock,
    ) -> None:
        from investigation_history import InvestigationHistoryRecord
        from investigation_memory import InvestigationMemory
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from investigation_synthesis import InvestigationSynthesis
        from models import Scan
        from netrecon import main

        snapshot = InvestigationSnapshot(True, Scan("e2e-stalled.xml"), (), (), (), None)
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), stall_reason="no_supported_actions"
        )
        current = InvestigationSynthesis("stalled", "no_supported_actions", 0, 0, ())
        previous_synthesis = InvestigationSynthesis(
            "complete", "all_gaps_resolved", 0, 0, ()
        )
        previous = InvestigationHistoryRecord(100, "192.0.2.204", previous_synthesis)

        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)
        decision_mock.return_value = decision
        synthesis_mock.return_value = current
        load_history_mock.return_value = (previous,)
        latest_mock.return_value = previous
        compare_mock.return_value = InvestigationMemory(
            True, "complete", "stalled", True,
            "all_gaps_resolved", "no_supported_actions",
            0, 0, (), (),
        )

        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.touch()
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.204",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        compare_mock.assert_called_once_with(previous_synthesis, current)
        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(appended.target, "192.0.2.204")
        self.assertIs(appended.synthesis, current)

    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.compare_investigation_syntheses")
    @patch("netrecon.latest_investigation_for_target")
    @patch("netrecon.load_investigation_history")
    @patch("netrecon.build_investigation_synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_terminal_pending_approval_is_persisted_and_compared(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        load_history_mock,
        latest_mock,
        compare_mock,
        append_mock,
    ) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_history import InvestigationHistoryRecord
        from investigation_memory import InvestigationMemory
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from investigation_synthesis import InvestigationSynthesis
        from models import Scan
        from netrecon import main

        requirement = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.205", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            requirement, "pending_approval", "explicit_approval_required", ()
        )
        snapshot = InvestigationSnapshot(
            True, Scan("e2e-approval.xml"), (), (), (), None,
            finding_requirement_states=(pending,),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), stall_reason="explicit_approval_required",
            remaining_finding_requirements=(pending,),
        )
        current = InvestigationSynthesis(
            "stalled", "explicit_approval_required", 0, 0, (), (pending,)
        )
        previous_synthesis = InvestigationSynthesis(
            "complete", "all_gaps_resolved", 0, 0, ()
        )
        previous = InvestigationHistoryRecord(100, "192.0.2.205", previous_synthesis)

        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)
        decision_mock.return_value = decision
        synthesis_mock.return_value = current
        load_history_mock.return_value = (previous,)
        latest_mock.return_value = previous
        compare_mock.return_value = InvestigationMemory(
            True, "complete", "stalled", True,
            "all_gaps_resolved", "explicit_approval_required",
            0, 0, (), (), (pending,), (),
        )

        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.touch()
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.205",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        compare_mock.assert_called_once_with(previous_synthesis, current)
        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(
            appended.synthesis.remaining_finding_requirements,
            (pending,),
        )
        self.assertEqual(appended.synthesis.status, "stalled")
        self.assertEqual(
            appended.synthesis.reason,
            "explicit_approval_required",
        )

    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.compare_investigation_syntheses")
    @patch("netrecon.latest_investigation_for_target")
    @patch("netrecon.load_investigation_history")
    @patch("netrecon.build_investigation_synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_terminal_unsatisfied_finding_is_persisted_and_compared(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        load_history_mock,
        latest_mock,
        compare_mock,
        append_mock,
    ) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_history import InvestigationHistoryRecord
        from investigation_memory import InvestigationMemory
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from investigation_synthesis import InvestigationSynthesis
        from models import Scan
        from netrecon import main

        requirement = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.206", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        attempted = FindingRequirementState(
            requirement, "attempted_unsatisfied", "explicitly_approved", ()
        )
        snapshot = InvestigationSnapshot(
            True, Scan("e2e-unsatisfied.xml"), (), (), (), None,
            finding_requirement_states=(attempted,),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), stall_reason="finding_requirement_unsatisfied",
            remaining_finding_requirements=(attempted,),
        )
        current = InvestigationSynthesis(
            "stalled", "finding_requirement_unsatisfied", 0, 0, (), (attempted,)
        )
        previous_synthesis = InvestigationSynthesis(
            "stalled", "explicit_approval_required", 0, 0, ()
        )
        previous = InvestigationHistoryRecord(100, "192.0.2.206", previous_synthesis)

        snapshot_mock.return_value = snapshot
        execute_evidence_mock.return_value = InvestigationContinuationResult((), snapshot)
        decision_mock.return_value = decision
        synthesis_mock.return_value = current
        load_history_mock.return_value = (previous,)
        latest_mock.return_value = previous
        compare_mock.return_value = InvestigationMemory(
            False, "stalled", "stalled", True,
            "explicit_approval_required", "finding_requirement_unsatisfied",
            0, 0, (), (), (attempted,), (),
        )

        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.touch()
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.206",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        compare_mock.assert_called_once_with(previous_synthesis, current)
        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(
            appended.synthesis.remaining_finding_requirements,
            (attempted,),
        )
        self.assertEqual(appended.synthesis.status, "stalled")
        self.assertEqual(
            appended.synthesis.reason,
            "finding_requirement_unsatisfied",
        )

    @patch("netrecon.render_investigation_memory", return_value="Investigation Memory")
    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.compare_investigation_syntheses", return_value="memory-result")
    @patch("netrecon.latest_investigation_for_target")
    @patch("netrecon.load_investigation_history")
    @patch("netrecon.render_investigation_synthesis", return_value="Investigation Synthesis")
    @patch("netrecon.build_investigation_synthesis", return_value="current-synthesis")
    @patch("netrecon.render_investigation_continuation", return_value="Investigation Continuation")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_final_investigation_decision")
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_compares_previous_history_and_appends_current(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        alternative_round_mock,
        final_decision_mock,
        attention_mock,
        correlation_mock,
        render_continuation_mock,
        synthesis_mock,
        render_synthesis_mock,
        load_history_mock,
        latest_mock,
        compare_mock,
        append_mock,
        render_memory_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_history import InvestigationHistoryRecord
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            FinalInvestigationDecision,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        initial = InvestigationSnapshot(True, Scan("initial.xml"), (), (), (), None)
        updated = InvestigationSnapshot(True, Scan("updated.xml"), (), (), (), None)
        final_snapshot = InvestigationSnapshot(True, Scan("final.xml"), (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        alternative = EvidenceAction(
            "192.0.2.180", 5357, "tcp", ("http-headers",), ("purpose",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.180"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )
        alternative_result = AlternativeEvidenceRoundResult((), (), final_snapshot)
        final_decision = FinalInvestigationDecision(
            "stalled", "alternative_evidence_incomplete", ()
        )
        previous = InvestigationHistoryRecord(100, "192.0.2.180", "previous-synthesis")

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        alternative_round_mock.return_value = alternative_result
        final_decision_mock.return_value = final_decision
        load_history_mock.return_value = (previous,)
        latest_mock.return_value = previous

        with tempfile.TemporaryDirectory() as directory:
            history_path = Path(directory) / "history.jsonl"
            history_path.touch()
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.180",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(), 0)

        load_history_mock.assert_called_once()
        latest_mock.assert_called_once_with((previous,), "192.0.2.180")
        compare_mock.assert_called_once_with("previous-synthesis", "current-synthesis")
        render_memory_mock.assert_called_once_with("memory-result")
        append_mock.assert_called_once()
        appended = append_mock.call_args.args[1]
        self.assertEqual(appended.target, "192.0.2.180")
        self.assertEqual(appended.synthesis, "current-synthesis")
        self.assertIs(
            final_decision_mock.call_args.args[0],
            alternative_result,
        )
        self.assertIs(
            synthesis_mock.call_args.args[0],
            final_snapshot,
        )
        self.assertIs(
            synthesis_mock.call_args.args[3],
            final_decision,
        )



    @patch("netrecon.render_investigation_memory", return_value="Investigation Memory\nReason Changed: yes")
    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.compare_investigation_syntheses", return_value="memory-result")
    @patch("netrecon.latest_investigation_for_target")
    @patch("netrecon.load_investigation_history")
    @patch("netrecon.render_investigation_synthesis", return_value="Investigation Synthesis\nStatus: stalled")
    @patch("netrecon.build_investigation_synthesis", return_value="current-synthesis")
    @patch("netrecon.render_investigation_continuation", return_value="Investigation Continuation")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_final_investigation_decision")
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_reports_memory_when_previous_history_exists(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        alternative_round_mock,
        final_decision_mock,
        attention_mock,
        correlation_mock,
        render_continuation_mock,
        synthesis_mock,
        render_synthesis_mock,
        load_history_mock,
        latest_mock,
        compare_mock,
        append_mock,
        render_memory_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_history import InvestigationHistoryRecord
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            FinalInvestigationDecision,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        initial = InvestigationSnapshot(True, Scan("initial.xml"), (), (), (), None)
        updated = InvestigationSnapshot(True, Scan("updated.xml"), (), (), (), None)
        final_snapshot = InvestigationSnapshot(True, Scan("final.xml"), (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        alternative = EvidenceAction(
            "192.0.2.190", 5357, "tcp", ("http-headers",), ("purpose",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.190"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )
        alternative_result = AlternativeEvidenceRoundResult((), (), final_snapshot)
        final_decision = FinalInvestigationDecision(
            "stalled", "alternative_evidence_incomplete", ()
        )
        previous = InvestigationHistoryRecord(100, "192.0.2.190", "previous-synthesis")

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        alternative_round_mock.return_value = alternative_result
        final_decision_mock.return_value = final_decision
        load_history_mock.return_value = (previous,)
        latest_mock.return_value = previous
        output = StringIO()

        with tempfile.TemporaryDirectory() as directory:
            history_path = Path(directory) / "history.jsonl"
            history_path.touch()
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.190",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(output):
                    self.assertEqual(main(), 0)

        render_memory_mock.assert_called_once_with("memory-result")
        self.assertEqual(
            output.getvalue().strip(),
            "Investigation Continuation\n\n"
            "Investigation Explanation\n-------------------------\n"
            "Known\nUnresolved\nBlocked\nNext\n\n"
            "Investigation Synthesis\nStatus: stalled\n\n"
            "Investigation Memory\nReason Changed: yes",
        )


    @patch("netrecon.append_investigation_history_record")
    @patch("netrecon.load_investigation_history", side_effect=ValueError("invalid history"))
    @patch("netrecon.build_investigation_synthesis", return_value="current-synthesis")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_final_investigation_decision")
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_fails_closed_on_invalid_history(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        alternative_round_mock,
        final_decision_mock,
        attention_mock,
        correlation_mock,
        synthesis_mock,
        load_history_mock,
        append_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            AlternativeEvidenceRoundResult,
            FinalInvestigationDecision,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        initial = InvestigationSnapshot(True, Scan("initial.xml"), (), (), (), None)
        updated = InvestigationSnapshot(True, Scan("updated.xml"), (), (), (), None)
        final_snapshot = InvestigationSnapshot(True, Scan("final.xml"), (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        alternative = EvidenceAction(
            "192.0.2.191", 5357, "tcp", ("http-headers",), ("purpose",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.191"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )
        alternative_result = AlternativeEvidenceRoundResult((), (), final_snapshot)
        final_decision = FinalInvestigationDecision(
            "stalled", "alternative_evidence_incomplete", ()
        )

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        alternative_round_mock.return_value = alternative_result
        final_decision_mock.return_value = final_decision
        output = StringIO()

        with tempfile.TemporaryDirectory() as directory:
            history_path = Path(directory) / "history.jsonl"
            history_path.write_text("{broken}\n", encoding="utf-8")
            with patch(
                "sys.argv",
                [
                    "netrecon",
                    "--investigate-collect",
                    "192.0.2.191",
                    "--investigation-history",
                    str(history_path),
                ],
            ):
                with redirect_stdout(output):
                    self.assertEqual(main(), 2)

        self.assertIn(
            "Error: unable to load investigation history: invalid history",
            output.getvalue(),
        )
        append_mock.assert_not_called()


    def test_investigation_history_requires_investigate_collect(self) -> None:
        from netrecon import main

        stderr = StringIO()
        with patch(
            "sys.argv",
            ["netrecon", "--investigation-history", "history.jsonl"],
        ):
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main()

        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "--investigation-history requires --investigate-collect",
            stderr.getvalue(),
        )


    @patch("netrecon.render_adaptive_investigation_plan", return_value="Adaptive Investigation Plan\nDecision: alternative")
    @patch("netrecon.build_adaptive_investigation_plan")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.assess_final_investigation_decision", return_value=None)
    @patch("netrecon.execute_alternative_evidence_round", return_value=None)
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_adaptive_plan_flag_reports_without_replacing_existing_execution(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_approved_mock,
        assess_continuation_mock,
        execute_alternative_mock,
        assess_final_mock,
        attention_mock,
        correlations_mock,
        build_adaptive_mock,
        render_adaptive_mock,
    ) -> None:
        from adaptive_investigation import AdaptiveInvestigationPlan
        from investigation_orchestration import InvestigationContinuationDecision
        from netrecon import main

        plan = object()
        execution = object()
        discovery = object()
        snapshot = unittest.mock.MagicMock(ready=True, actions=())
        updated = unittest.mock.MagicMock(ready=True)
        continuation = unittest.mock.MagicMock(snapshot=updated)
        alternative = EvidenceAction(
            "192.0.2.210", 5357, "tcp", ("http-headers",), ("review HTTP identity",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.210"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )

        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = snapshot
        execute_approved_mock.return_value = continuation
        assess_continuation_mock.return_value = decision
        adaptive_plan = AdaptiveInvestigationPlan(
            "alternative", "supported_alternative_actions_available", (alternative,)
        )
        build_adaptive_mock.return_value = adaptive_plan

        output = StringIO()
        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.210", "--adaptive-plan"]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        build_adaptive_mock.assert_called_once_with(decision)
        render_adaptive_mock.assert_called_once_with(adaptive_plan)
        execute_alternative_mock.assert_called_once_with(
            updated,
            decision.alternative_actions,
            timeout=60.0,
            explicitly_approved_requirement_ids=frozenset(),
        )
        self.assertIn("Adaptive Investigation Plan", output.getvalue())


    @patch("netrecon.build_adaptive_investigation_plan")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_adaptive_stop_blocks_alternative_execution(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_approved_mock,
        assess_continuation_mock,
        execute_alternative_mock,
        attention_mock,
        correlations_mock,
        build_adaptive_mock,
    ) -> None:
        from adaptive_investigation import AdaptiveInvestigationPlan
        from investigation_orchestration import InvestigationContinuationDecision
        from netrecon import main

        snapshot = unittest.mock.MagicMock(ready=True, actions=())
        updated = unittest.mock.MagicMock(ready=True)
        alternative = EvidenceAction(
            "192.0.2.211", 5357, "tcp", ("http-headers",), ("review HTTP identity",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.211"),
        )
        decision = InvestigationContinuationDecision(
            "stalled", (), (), (), (), "repeated_actions_exhausted", (alternative,)
        )

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = snapshot
        execute_approved_mock.return_value = unittest.mock.MagicMock(snapshot=updated)
        assess_continuation_mock.return_value = decision
        build_adaptive_mock.return_value = AdaptiveInvestigationPlan(
            "stop", "no_supported_next_step", (alternative,)
        )

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.211"]):
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)

        execute_alternative_mock.assert_not_called()


    @patch("netrecon.render_investigation_continuation", return_value="Investigation continuation")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.execute_selected_evidence_actions")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_executes_one_adaptive_continue_round(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_approved_mock,
        assess_continuation_mock,
        execute_selected_mock,
        attention_mock,
        correlations_mock,
        render_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        scan = Scan(source="discovery.xml")
        initial_action = EvidenceAction(
            "192.0.2.220", 445, "tcp", ("smb-protocols",), ("review SMB dialects",),
            ("nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.220"),
        )
        next_action = EvidenceAction(
            "192.0.2.220", 443, "tcp", ("ssl-cert",), ("review TLS certificate",),
            ("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.220"),
        )
        initial = InvestigationSnapshot(True, scan, (), (initial_action,), (), None)
        updated = InvestigationSnapshot(True, scan, (), (next_action,), (), None)
        continued = InvestigationSnapshot(True, scan, (), (), (), None)

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_approved_mock.return_value = InvestigationContinuationResult((), updated)
        first_decision = InvestigationContinuationDecision(
            "progressed", (), (), (next_action,)
        )
        second_decision = InvestigationContinuationDecision(
            "complete", (), (), ()
        )
        assess_continuation_mock.side_effect = (first_decision, second_decision)
        execute_selected_mock.return_value = InvestigationContinuationResult((), continued)

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.220"]):
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)

        execute_selected_mock.assert_called_once_with(
            updated,
            (next_action,),
            timeout=60.0,
        )
        self.assertEqual(assess_continuation_mock.call_count, 2)
        assess_continuation_mock.assert_any_call(
            updated,
            continued,
            attempted_actions=(initial_action, next_action),
        )


    @patch("netrecon.render_investigation_continuation", return_value="Investigation continuation")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.execute_selected_evidence_actions")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_adaptive_continue_runs_until_terminal_decision(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_approved_mock,
        assess_continuation_mock,
        execute_selected_mock,
        execute_alternative_mock,
        attention_mock,
        correlations_mock,
        render_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        scan = Scan(source="discovery.xml")
        initial_action = EvidenceAction(
            "192.0.2.221", 445, "tcp", ("smb-protocols",), ("review SMB dialects",),
            ("nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.221"),
        )
        second_action = EvidenceAction(
            "192.0.2.221", 443, "tcp", ("ssl-cert",), ("review TLS certificate",),
            ("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.221"),
        )
        third_action = EvidenceAction(
            "192.0.2.221", 22, "tcp", ("ssh-hostkey",), ("review SSH host key",),
            ("nmap", "-p", "22", "--script", "ssh-hostkey", "-oX", "-", "192.0.2.221"),
        )
        initial = InvestigationSnapshot(True, scan, (), (initial_action,), (), None)
        updated = InvestigationSnapshot(True, scan, (), (second_action,), (), None)
        second = InvestigationSnapshot(True, scan, (), (third_action,), (), None)
        final = InvestigationSnapshot(True, scan, (), (), (), None)

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_approved_mock.return_value = InvestigationContinuationResult((), updated)
        first_decision = InvestigationContinuationDecision("progressed", (), (), (second_action,))
        second_decision = InvestigationContinuationDecision("progressed", (), (), (third_action,))
        terminal_decision = InvestigationContinuationDecision("complete", (), (), ())
        assess_continuation_mock.side_effect = (
            first_decision,
            second_decision,
            terminal_decision,
        )
        execute_selected_mock.side_effect = (
            InvestigationContinuationResult((), second),
            InvestigationContinuationResult((), final),
        )

        with patch("sys.argv", ["netrecon", "--investigate-collect", "192.0.2.221"]):
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)

        self.assertEqual(execute_selected_mock.call_count, 2)
        self.assertEqual(
            execute_selected_mock.call_args_list[0].args,
            (updated, (second_action,)),
        )
        self.assertEqual(
            execute_selected_mock.call_args_list[1].args,
            (second, (third_action,)),
        )
        self.assertEqual(assess_continuation_mock.call_count, 3)
        assess_continuation_mock.assert_any_call(
            second,
            final,
            attempted_actions=(initial_action, second_action, third_action),
        )
        execute_alternative_mock.assert_not_called()
        self.assertIs(render_mock.call_args.args[1], terminal_decision)


    @patch("netrecon.render_investigation_continuation", return_value="Investigation continuation")
    @patch("netrecon.correlate_analyst_attention", return_value=())
    @patch("netrecon.build_investigation_attention", return_value=())
    @patch("netrecon.execute_alternative_evidence_round")
    @patch("netrecon.execute_selected_evidence_actions")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_adaptive_continue_stops_explicitly_at_round_limit(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_approved_mock,
        assess_continuation_mock,
        execute_selected_mock,
        execute_alternative_mock,
        attention_mock,
        correlations_mock,
        render_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        scan = Scan(source="discovery.xml")
        initial_action = EvidenceAction(
            "192.0.2.230", 445, "tcp", ("smb-protocols",), ("review SMB dialects",),
            ("nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.230"),
        )
        next_action = EvidenceAction(
            "192.0.2.230", 443, "tcp", ("ssl-cert",), ("review TLS certificate",),
            ("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.230"),
        )
        initial = InvestigationSnapshot(True, scan, (), (initial_action,), (), None)
        updated = InvestigationSnapshot(True, scan, (), (next_action,), (), None)
        continued = InvestigationSnapshot(True, scan, (), (next_action,), (), None)

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_approved_mock.return_value = InvestigationContinuationResult((), updated)
        assess_continuation_mock.return_value = InvestigationContinuationDecision(
            "progressed", (), (), (next_action,)
        )
        execute_selected_mock.return_value = InvestigationContinuationResult((), continued)

        output = StringIO()
        with patch("sys.argv", [
            "netrecon", "--investigate-collect", "192.0.2.230", "--adaptive-plan"
        ]):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        self.assertEqual(execute_selected_mock.call_count, 8)
        self.assertEqual(assess_continuation_mock.call_count, 9)
        execute_alternative_mock.assert_not_called()
        self.assertIn("adaptive_round_limit_reached", output.getvalue())
        self.assertIn("Investigation Synthesis", output.getvalue())
        self.assertIn("Status: stalled", output.getvalue())
        self.assertIn("Reason: adaptive_round_limit_reached", output.getvalue())
        self.assertNotIn("Status: complete", output.getvalue())
        self.assertIn("Remaining Requirements:", output.getvalue())
        for call in execute_selected_mock.call_args_list:
            self.assertEqual(call.args[1], (next_action,))
        self.assertEqual(
            assess_continuation_mock.call_args_list[-1].kwargs["attempted_actions"],
            (initial_action,) + (next_action,) * 8,
        )


    @patch("netrecon.render_investigation_continuation", return_value="Investigation continuation")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_passes_explicit_requirement_approval(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        render_mock,
    ) -> None:
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main
        from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult

        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        scan = Scan(source="discovery.xml")
        discovery = DiscoveryResult(execution, True, scan, None)
        initial = InvestigationSnapshot(True, scan, (), (), (), None)
        updated = InvestigationSnapshot(True, scan, (), (), (), None)
        continuation = InvestigationContinuationResult((), updated)
        decision = InvestigationContinuationDecision("complete", (), (), ())
        build_plan_mock.return_value = plan
        execute_discovery_mock.return_value = execution
        interpret_mock.return_value = discovery
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = continuation
        decision_mock.return_value = decision
        output = StringIO()

        with patch(
            "sys.argv",
            [
                "netrecon",
                "--investigate-collect",
                "192.0.2.10",
                "--approve-requirement",
                "smb_access_control_context",
            ],
        ):
            with redirect_stdout(output):
                self.assertEqual(main(), 0)

        execute_evidence_mock.assert_called_once_with(
            initial,
            timeout=60.0,
            explicitly_approved_requirement_ids=frozenset({"smb_access_control_context"}),
        )

    def test_approve_requirement_requires_investigate_collect(self) -> None:
        from netrecon import main

        with patch(
            "sys.argv",
            ["netrecon", "--approve-requirement", "smb_access_control_context"],
        ):
            with self.assertRaises(SystemExit) as raised:
                main()

        self.assertEqual(raised.exception.code, 2)


    @patch("netrecon.render_investigation_continuation", return_value="Dynamic continue")
    @patch("netrecon.execute_selected_evidence_actions")
    @patch("netrecon.assess_investigation_continuation")
    @patch("netrecon.execute_approved_evidence_actions")
    @patch("netrecon.build_investigation_snapshot")
    @patch("netrecon.interpret_discovery_execution")
    @patch("netrecon.execute_discovery_plan")
    @patch("netrecon.build_baseline_discovery_plan")
    def test_investigate_collect_executes_one_approved_dynamic_continue_round(
        self,
        build_plan_mock,
        execute_discovery_mock,
        interpret_mock,
        snapshot_mock,
        execute_evidence_mock,
        decision_mock,
        execute_selected_mock,
        render_mock,
    ) -> None:
        from evidence_action_plan import EvidenceAction
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from netrecon import main

        initial = InvestigationSnapshot(True, Scan(source="initial.xml"), (), (), (), None)
        updated = InvestigationSnapshot(True, Scan(source="updated.xml"), (), (), (), None)
        final = InvestigationSnapshot(True, Scan(source="final.xml"), (), (), (), None)
        dynamic = EvidenceAction(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_ids=("smb-enum-shares",),
            purposes=("review SMB access controls in the context of the observed signing configuration",),
            command=("nmap", "-p", "445", "--script", "smb-enum-shares", "-oX", "-", "192.0.2.10"),
        )
        first_round = InvestigationContinuationResult((), updated)
        second_round = InvestigationContinuationResult((), final)
        progressed = InvestigationContinuationDecision(
            status="progressed",
            resolved_gaps=(),
            remaining_gaps=(),
            next_actions=(dynamic,),
        )
        complete = InvestigationContinuationDecision(
            status="complete",
            resolved_gaps=(),
            remaining_gaps=(),
            next_actions=(),
        )

        build_plan_mock.return_value = object()
        execute_discovery_mock.return_value = object()
        interpret_mock.return_value = object()
        snapshot_mock.return_value = initial
        execute_evidence_mock.return_value = first_round
        decision_mock.side_effect = (progressed, complete)
        execute_selected_mock.return_value = second_round

        with patch(
            "sys.argv",
            [
                "netrecon",
                "--investigate-collect",
                "192.0.2.10",
                "--approve-requirement",
                "smb_access_control_context",
                "--adaptive-plan",
            ],
        ):
            with redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)

        approval = frozenset({"smb_access_control_context"})
        execute_evidence_mock.assert_called_once_with(
            initial,
            timeout=60.0,
            explicitly_approved_requirement_ids=approval,
        )
        execute_selected_mock.assert_called_once_with(
            updated,
            (dynamic,),
            timeout=60.0,
            explicitly_approved_requirement_ids=approval,
        )
        self.assertEqual(decision_mock.call_count, 2)
        self.assertEqual(
            execute_selected_mock.call_args.kwargs["explicitly_approved_requirement_ids"],
            frozenset({"smb_access_control_context"}),
        )
        self.assertIs(
            decision_mock.call_args_list[-1].args[0],
            updated,
        )
        self.assertIs(
            decision_mock.call_args_list[-1].args[1],
            final,
        )
        self.assertEqual(
            decision_mock.call_args_list[-1].kwargs["attempted_actions"],
            initial.actions + (dynamic,),
        )
        self.assertEqual(
            execute_selected_mock.call_args.args[1],
            progressed.next_actions,
        )
        self.assertEqual(
            decision_mock.call_args_list[0].kwargs["attempted_actions"],
            initial.actions,
        )
        self.assertEqual(
            decision_mock.call_args_list[1].kwargs["attempted_actions"],
            initial.actions + progressed.next_actions,
        )
        self.assertIs(
            execute_selected_mock.call_args.args[0],
            updated,
        )
        self.assertIs(
            decision_mock.call_args_list[1].args[0],
            updated,
        )
        self.assertIs(
            decision_mock.call_args_list[1].args[1],
            final,
        )


if __name__ == "__main__":
    unittest.main()
