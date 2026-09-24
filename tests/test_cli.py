"""Tests for NetRecon command-line argument validation."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
