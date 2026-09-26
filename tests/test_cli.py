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
            {"--analyze", "--diff", "--analysis-diff", "--collect-evidence"}
            <= option_strings
        )
        self.assertTrue(
            any(action.dest == "compare_scan" for action in parser._actions)
        )

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


    @patch("netrecon.plan_host_evidence")
    @patch("netrecon.parse_nmap_xml")
    def test_collect_evidence_plans_each_discovered_host(
        self,
        parse_mock,
        plan_mock,
    ) -> None:
        from models import Host, Scan
        from netrecon import main

        first = Host(address="192.0.2.10", status="up")
        second = Host(address="192.0.2.11", status="up")
        parse_mock.return_value = Scan(
            source="scan.xml",
            hosts=(first, second),
        )

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

        collect_mock.assert_called_once_with(host, plan)
        render_mock.assert_called_once_with(result)
        self.assertEqual(output.getvalue().strip(), "Evidence report")


if __name__ == "__main__":
    unittest.main()
