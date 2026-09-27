"""Contract tests for transparent discovery execution."""

import subprocess
import unittest
from unittest.mock import patch

from scan_orchestration import (
    DiscoveryExecutionResult,
    build_baseline_discovery_plan,
    execute_discovery_plan,
)


class DiscoveryExecutionTests(unittest.TestCase):
    @patch("scan_orchestration.subprocess.run")
    def test_executes_exact_plan_argv_without_shell(
        self, run_mock
    ) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        run_mock.return_value = subprocess.CompletedProcess(
            plan.command,
            0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
        )

        result = execute_discovery_plan(plan)

        run_mock.assert_called_once_with(
            plan.command,
            capture_output=True,
            text=True,
            shell=False,
            timeout=60.0,
        )
        self.assertEqual(
            result,
            DiscoveryExecutionResult(
                plan=plan,
                returncode=0,
                stdout="<nmaprun></nmaprun>",
                stderr="",
                timed_out=False,
            ),
        )

    @patch("scan_orchestration.subprocess.run")
    def test_preserves_nonzero_nmap_outcome(self, run_mock) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        run_mock.return_value = subprocess.CompletedProcess(
            plan.command,
            2,
            stdout="",
            stderr="nmap failed",
        )

        result = execute_discovery_plan(plan)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "nmap failed")
        self.assertFalse(result.timed_out)

    @patch("scan_orchestration.subprocess.run")
    def test_timeout_becomes_explicit_failed_outcome(self, run_mock) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        run_mock.side_effect = subprocess.TimeoutExpired(
            plan.command,
            0.001,
            output="partial xml",
            stderr="timed out",
        )

        result = execute_discovery_plan(plan, timeout=0.001)

        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, "partial xml")
        self.assertEqual(result.stderr, "timed out")
        self.assertTrue(result.timed_out)


    @patch("scan_orchestration.subprocess.run")
    def test_missing_nmap_becomes_explicit_failed_outcome(self, run_mock) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        run_mock.side_effect = FileNotFoundError(2, "No such file or directory", "nmap")

        result = execute_discovery_plan(plan)

        self.assertEqual(result.returncode, 127)
        self.assertEqual(result.stdout, "")
        self.assertIn("nmap", result.stderr.lower())
        self.assertFalse(result.timed_out)

    @patch("scan_orchestration.subprocess.run")
    def test_timeout_normalizes_byte_output_to_text(self, run_mock) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        run_mock.side_effect = subprocess.TimeoutExpired(
            plan.command,
            0.001,
            output=b"partial xml",
            stderr=b"timed out",
        )

        result = execute_discovery_plan(plan, timeout=0.001)

        self.assertEqual(result.stdout, "partial xml")
        self.assertEqual(result.stderr, "timed out")
        self.assertIsInstance(result.stdout, str)
        self.assertIsInstance(result.stderr, str)

    def test_rejects_non_positive_or_non_finite_timeout(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")

        for timeout in (0.0, -1.0, float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(
                    ValueError,
                    "Discovery timeout must be a positive finite number",
                ):
                    execute_discovery_plan(plan, timeout=timeout)


if __name__ == "__main__":
    unittest.main()
