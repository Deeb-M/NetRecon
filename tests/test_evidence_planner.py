import unittest

from evidence_planner import (\n    EvidenceRequest,\n    HostEvidencePlan,\n    plan_evidence,\n    plan_evidence_requests,\n    plan_host_evidence,\n)
from models import Host, Port, ScriptResult


class EvidencePlannerTests(unittest.TestCase):
    def test_open_ssh_service_requests_supported_ssh_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(plan, ("ssh2-enum-algos",))


    def test_closed_ssh_service_requests_no_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol="tcp",
                    state="closed",
                    service="ssh",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(plan, ())


    def test_open_http_service_requests_supported_http_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(plan, ("http-title", "http-methods"))


    def test_open_https_service_requests_http_and_tls_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(
            plan,
            (
                "http-title",
                "http-methods",
                "ssl-cert",
                "ssl-enum-ciphers",
            ),
        )


    def test_existing_http_evidence_is_not_requested_again(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                    scripts=(
                        ScriptResult(
                            script_id="http-title",
                            output="Example",
                        ),
                    ),
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(plan, ("http-methods",))


    def test_open_smb_service_requests_supported_smb_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="microsoft-ds",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(
            plan,
            (
                "smb-protocols",
                "smb2-security-mode",
            ),
        )


    def test_multiple_open_services_combine_evidence_requests(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                ),
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(
            plan,
            (
                "ssh2-enum-algos",
                "http-title",
                "http-methods",
            ),
        )


    def test_same_evidence_needed_on_multiple_ports_preserves_each_request(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
                Port(
                    port=8080,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
            ),
        )

        plan = plan_evidence(host)

        self.assertEqual(
            plan,
            (
                "http-title",
                "http-methods",
                "http-title",
                "http-methods",
            ),
        )


    def test_detailed_plan_preserves_port_protocol_and_script(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(
            plan,
            (
                EvidenceRequest(
                    port=80,
                    protocol="tcp",
                    script_id="http-title",
                ),
                EvidenceRequest(
                    port=80,
                    protocol="tcp",
                    script_id="http-methods",
                ),
            ),
        )


    def test_detailed_plan_preserves_same_scripts_on_different_ports(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
                Port(
                    port=8080,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(
            plan,
            (
                EvidenceRequest(80, "tcp", "http-title"),
                EvidenceRequest(80, "tcp", "http-methods"),
                EvidenceRequest(8080, "tcp", "http-title"),
                EvidenceRequest(8080, "tcp", "http-methods"),
            ),
        )


    def test_existing_evidence_on_one_port_does_not_suppress_another_port(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                    scripts=(
                        ScriptResult(
                            script_id="http-title",
                            output="Example",
                        ),
                    ),
                ),
                Port(
                    port=8080,
                    protocol="tcp",
                    state="open",
                    service="http",
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(
            plan,
            (
                EvidenceRequest(80, "tcp", "http-methods"),
                EvidenceRequest(8080, "tcp", "http-title"),
                EvidenceRequest(8080, "tcp", "http-methods"),
            ),
        )


    def test_open_smb_alias_requests_supported_smb_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="smb",
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(
            plan,
            (
                EvidenceRequest(445, "tcp", "smb-protocols"),
                EvidenceRequest(445, "tcp", "smb2-security-mode"),
            ),
        )


    def test_open_port_445_without_service_requests_smb_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service=None,
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(
            plan,
            (
                EvidenceRequest(445, "tcp", "smb-protocols"),
                EvidenceRequest(445, "tcp", "smb2-security-mode"),
            ),
        )


    def test_port_445_with_explicit_other_service_does_not_force_smb(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=445,
                    protocol="tcp",
                    state="open",
                    service="https",
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(
            plan,
            (
                EvidenceRequest(445, "tcp", "http-title"),
                EvidenceRequest(445, "tcp", "http-methods"),
                EvidenceRequest(445, "tcp", "ssl-cert"),
                EvidenceRequest(445, "tcp", "ssl-enum-ciphers"),
            ),
        )


    def test_planner_normalizes_service_state_protocol_and_existing_script_id(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol=" TCP ",
                    state=" OPEN ",
                    service=" SSH ",
                    scripts=(
                        ScriptResult(
                            script_id=" SSH2-ENUM-ALGOS ",
                            output="Example",
                        ),
                    ),
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(plan, ())


    def test_unsupported_open_service_requests_no_evidence(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=5432,
                    protocol="tcp",
                    state="open",
                    service="postgresql",
                ),
            ),
        )

        plan = plan_evidence_requests(host)

        self.assertEqual(plan, ())


    def test_host_plan_binds_target_to_detailed_requests(self) -> None:
        host = Host(
            address="192.0.2.10",
            status="up",
            ports=(
                Port(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                ),
                Port(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                ),
            ),
        )

        plan = plan_host_evidence(host)

        self.assertEqual(
            plan,
            HostEvidencePlan(
                target="192.0.2.10",
                requests=(
                    EvidenceRequest(22, "tcp", "ssh2-enum-algos"),
                    EvidenceRequest(443, "tcp", "http-title"),
                    EvidenceRequest(443, "tcp", "http-methods"),
                    EvidenceRequest(443, "tcp", "ssl-cert"),
                    EvidenceRequest(443, "tcp", "ssl-enum-ciphers"),
                ),
            ),
        )


    def test_host_plan_preserves_target_when_no_evidence_is_needed(self) -> None:
        host = Host(
            address="192.0.2.20",
            status="up",
            ports=(
                Port(
                    port=5432,
                    protocol="tcp",
                    state="open",
                    service="postgresql",
                ),
            ),
        )

        plan = plan_host_evidence(host)

        self.assertEqual(
            plan,
            HostEvidencePlan(
                target="192.0.2.20",
                requests=(),
            ),
        )


if __name__ == "__main__":
    unittest.main()
