"""Contract tests for interpreting discovery execution outcomes."""

import unittest

from scan_orchestration import (
    DiscoveryExecutionResult,
    DiscoveryResult,
    build_baseline_discovery_plan,
    interpret_discovery_execution,
)


class DiscoveryInterpretationTests(unittest.TestCase):
    def test_success_requires_parseable_nmap_xml(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=0,
            stdout="""<nmaprun scanner="nmap"><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>""",
            stderr="",
            timed_out=False,
        )

        result = interpret_discovery_execution(execution)

        self.assertIsInstance(result, DiscoveryResult)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.scan)
        self.assertEqual(result.error, None)
        self.assertEqual(result.scan.source, "<discovery:192.0.2.10>")

    def test_zero_exit_with_invalid_xml_is_not_success(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=0,
            stdout="not xml",
            stderr="",
            timed_out=False,
        )

        result = interpret_discovery_execution(execution)

        self.assertFalse(result.success)
        self.assertIsNone(result.scan)
        self.assertIn("invalid Nmap XML", result.error)

    def test_nonzero_exit_is_not_parsed_as_success(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=2,
            stdout="""<nmaprun></nmaprun>""",
            stderr="nmap failed",
            timed_out=False,
        )

        result = interpret_discovery_execution(execution)

        self.assertFalse(result.success)
        self.assertIsNone(result.scan)
        self.assertEqual(result.error, "nmap failed")

    def test_timeout_is_not_parsed_as_success(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=124,
            stdout="partial xml",
            stderr="",
            timed_out=True,
        )

        result = interpret_discovery_execution(execution)

        self.assertFalse(result.success)
        self.assertIsNone(result.scan)
        self.assertEqual(result.error, "Nmap discovery timed out")


if __name__ == "__main__":
    unittest.main()
