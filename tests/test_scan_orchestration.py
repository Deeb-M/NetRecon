"""Contract tests for the first conservative Scan Orchestration proof of concept."""

import unittest

from scan_orchestration import build_baseline_discovery_plan


class ScanOrchestrationTests(unittest.TestCase):
    def test_builds_transparent_baseline_discovery_plan_for_single_host(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")

        self.assertEqual(plan.target, "192.0.2.10")
        self.assertEqual(plan.profile, "baseline")
        self.assertEqual(
            plan.purpose,
            "discover open TCP services with version detection",
        )
        self.assertEqual(
            plan.command,
            ("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )

    def test_normalizes_outer_target_whitespace(self) -> None:
        plan = build_baseline_discovery_plan(" 192.0.2.10 ")

        self.assertEqual(plan.target, "192.0.2.10")
        self.assertEqual(plan.command[-1], "192.0.2.10")

    def test_rejects_blank_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "target"):
            build_baseline_discovery_plan("   ")

    def test_plan_does_not_hide_or_expand_the_target(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.0/24")

        self.assertEqual(plan.target, "192.0.2.0/24")
        self.assertEqual(plan.command[-1], "192.0.2.0/24")


if __name__ == "__main__":
    unittest.main()
