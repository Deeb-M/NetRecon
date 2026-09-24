"""Tests for NetRecon command-line argument validation."""

import unittest
from unittest.mock import patch

from netrecon import build_parser


class CliTests(unittest.TestCase):
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
