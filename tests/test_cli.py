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
        help_text = build_parser().format_help()

        self.assertIn(
            "Analyze and compare Nmap XML scans with evidence-based findings and exposure summaries.",
            help_text,
        )
        self.assertIn(
            "Second Nmap XML file used with --diff or --analysis-diff",
            help_text,
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

    def test_rejects_second_scan_without_comparison_mode(self) -> None:
        from netrecon import main

        with patch("sys.argv", ["netrecon", "scan.xml", "compare.xml"]):
            with self.assertRaises(SystemExit) as context:
                main()

        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
