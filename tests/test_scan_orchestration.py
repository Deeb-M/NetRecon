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

    def test_extracts_hostname_from_https_url_for_nmap(self) -> None:
        plan = build_baseline_discovery_plan("https://example.com/")

        self.assertEqual(plan.target, "example.com")
        self.assertEqual(plan.command[-1], "example.com")
        self.assertEqual(plan.input_target, "https://example.com/")
        self.assertEqual(plan.scheme, "https")
        self.assertEqual(plan.port, 443)
        self.assertFalse(plan.explicit_port)
        self.assertEqual(plan.path, "/")

    def test_extracts_hostname_from_url_with_port_and_path(self) -> None:
        plan = build_baseline_discovery_plan(
            "https://example.com:8443/admin"
        )

        self.assertEqual(plan.target, "example.com")
        self.assertEqual(plan.command[-1], "example.com")
        self.assertEqual(plan.input_target, "https://example.com:8443/admin")
        self.assertEqual(plan.scheme, "https")
        self.assertEqual(plan.port, 8443)
        self.assertTrue(plan.explicit_port)
        self.assertEqual(plan.path, "/admin")

    def test_url_uses_web_aware_discovery_profile_and_explicit_port(self) -> None:
        plan = build_baseline_discovery_plan(
            "https://example.com:8443/admin"
        )

        self.assertEqual(plan.profile, "web")
        self.assertEqual(
            plan.purpose,
            "discover the explicitly supplied Web service with version detection",
        )
        self.assertEqual(
            plan.command,
            ("nmap", "-sV", "-p", "8443", "-oX", "-", "example.com"),
        )

    def test_https_url_uses_implicit_https_port(self) -> None:
        plan = build_baseline_discovery_plan("https://example.com/")

        self.assertEqual(plan.profile, "web")
        self.assertEqual(plan.port, 443)
        self.assertEqual(
            plan.command,
            ("nmap", "-sV", "-p", "443", "-oX", "-", "example.com"),
        )

    def test_plain_target_keeps_baseline_discovery_profile(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")

        self.assertEqual(plan.profile, "baseline")
        self.assertEqual(
            plan.command,
            ("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )

    def test_extracts_ip_address_from_http_url(self) -> None:
        plan = build_baseline_discovery_plan(
            "http://192.0.2.10/test"
        )

        self.assertEqual(plan.target, "192.0.2.10")
        self.assertEqual(plan.command[-1], "192.0.2.10")
        self.assertEqual(plan.input_target, "http://192.0.2.10/test")
        self.assertEqual(plan.scheme, "http")
        self.assertEqual(plan.port, 80)
        self.assertFalse(plan.explicit_port)
        self.assertEqual(plan.path, "/test")


if __name__ == "__main__":
    unittest.main()
