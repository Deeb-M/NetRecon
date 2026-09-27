"""Tests for NetRecon command-line argument validation."""

import subprocess
import sys
import json
import unittest
import tempfile
from pathlib import Path
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
        snapshot = object()
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
        snapshot = InvestigationSnapshot(False, None, (), (), "nmap failed")
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
        self.assertIn("--discover TARGET", completed.stdout)
        self.assertIn("--discovery-plan TARGET", completed.stdout)


if __name__ == "__main__":
    unittest.main()
