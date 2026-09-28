"""Tests for NetRecon text reporting."""

import json
import unittest

from adaptive_investigation import AdaptiveInvestigationPlan
from analyzer import Finding
from evidence_gaps import EvidenceGap
from evidence_action_plan import EvidenceAction
from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
from finding_collection_planner import FindingCollectionPlan, FindingRequirementState, FindingRequirementVerification
from finding_requirements import FindingDerivedRequirement
from requirement_collection import CollectionAuthorizationDecision, RequirementCollectionStrategy
from investigation_state import EndpointInvestigationState
from investigation_explanation import InvestigationExplanation
from evidence_collector import (
    CollectionResult,
    CorrelatedEvidenceResult,
    NmapCommand,
    ParsedCollectionResult,
)
from models import Host, Port, Scan, ScriptResult
from scan_orchestration import DiscoveryExecutionResult, DiscoveryPlan, DiscoveryResult
from reporter import render_investigation_explanation, render_investigation_explanation_json, render_adaptive_investigation_plan, render_adaptive_investigation_plan_json, render_discovery_execution, render_discovery_execution_json, render_discovery_plan, render_discovery_plan_json, render_evidence_action_plan, render_evidence_action_plan_json, render_evidence_collection, render_evidence_collection_json, render_evidence_collections_json, render_evidence_gaps, render_evidence_gaps_json, render_findings, render_host_summaries, render_text, render_investigation_snapshot, render_investigation_snapshot_json, render_dynamic_evidence_round, render_dynamic_evidence_rounds, render_dynamic_evidence_rounds_json


class ReporterTests(unittest.TestCase):
    def test_renders_scan_host_service_and_script_context(self) -> None:
        scan = Scan(
            source="scan.xml",
            scanner="nmap",
            scanner_version="7.95",
            arguments="nmap -sV -oX scan.xml 192.0.2.10",
            elapsed=12.34,
            hosts_up=1,
            hosts_down=0,
            hosts_total=1,
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    hostname="lab.example",
                    addresses=(
                        ("192.0.2.10", "ipv4"),
                        ("00:11:22:33:44:55", "mac"),
                    ),
                    hostnames=("lab.example", "alias.example"),
                    ports=(
                        Port(
                            port=22,
                            protocol="tcp",
                            state="open",
                            service="ssh",
                            product="OpenSSH",
                            version="9.6",
                            confidence=10,
                            scripts=(
                                ScriptResult("ssh-hostkey", "2048 SHA256:example RSA"),
                            ),
                        ),
                    ),
                ),
            ),
        )

        report = render_text(scan)

        self.assertIn("Scanner: nmap 7.95", report)
        self.assertIn("Hosts: 1 parsed / 1 total (1 up, 0 down)", report)
        self.assertIn("Network Summary: 1 up, 1 open ports, 1 unique services", report)
        self.assertIn("Open Services: ssh (1)", report)
        self.assertIn("lab.example [192.0.2.10] (up)", report)
        self.assertIn("mac:00:11:22:33:44:55", report)
        self.assertIn("22/tcp", report)
        self.assertIn("ssh - OpenSSH 9.6", report)
        self.assertIn("[confidence:10]", report)
        self.assertIn("script ssh-hostkey:", report)


    def test_text_report_shows_cross_host_shared_services(self) -> None:
        scan = Scan(
            source="multi.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service="http", product="Apache httpd", version="2.4.68"),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=5357, protocol="tcp", state="open", service="http", product="Microsoft HTTPAPI httpd", version="2.0"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("Shared Services", report)
        self.assertIn("http: 2 hosts", report)
        self.assertIn("192.0.2.10:80/tcp  Apache httpd 2.4.68", report)
        self.assertIn("192.0.2.20:5357/tcp  Microsoft HTTPAPI httpd 2.0", report)

    def test_text_report_normalizes_service_names_in_summaries(self) -> None:
        scan = Scan(
            source="normalized-services.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service=" HTTP "),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
                Host(address="192.0.2.30", status="up", ports=(
                    Port(port=9999, protocol="tcp", state="open", service="   "),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("Network Summary: 3 up, 3 open ports, 2 unique services", report)
        self.assertIn("Open Services: http (2), unknown (1)", report)
        self.assertIn("http: 2 hosts", report)
        self.assertNotIn(" HTTP : 2 hosts", report)

    def test_text_report_normalizes_service_name_in_host_detail(self) -> None:
        scan = Scan(
            source="host-service-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state="open", service=" HTTP "),
                    Port(port=9999, protocol="tcp", state="open", service="   "),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("80/tcp open         http", report)
        self.assertIn("9999/tcp open         unknown", report)
        self.assertNotIn(" HTTP ", report)

    def test_text_report_strips_service_metadata_in_host_detail(self) -> None:
        scan = Scan(
            source="host-metadata-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product=" OpenSSH ",
                        version=" 9.6 ",
                        extra_info=" Ubuntu ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("ssh - OpenSSH 9.6 Ubuntu", report)
        self.assertNotIn("  OpenSSH ", report)
        self.assertNotIn(" 9.6  ", report)

    def test_text_report_ignores_whitespace_only_service_metadata(self) -> None:
        scan = Scan(
            source="blank-service-metadata.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product="   ",
                        version=" \t ",
                        extra_info="  ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("22/tcp open         ssh", report)
        self.assertNotIn("ssh -", report)

    def test_text_report_handles_partial_service_metadata(self) -> None:
        scan = Scan(
            source="partial-service-metadata.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=22,
                        protocol="tcp",
                        state="open",
                        service="ssh",
                        product=" OpenSSH ",
                        version=None,
                        extra_info=" Ubuntu ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("ssh - OpenSSH Ubuntu", report)
        self.assertNotIn("OpenSSH  Ubuntu", report)

    def test_text_report_normalizes_protocol_in_host_detail(self) -> None:
        scan = Scan(
            source="host-protocol-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=53, protocol=" UDP ", state="open", service="domain"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("53/udp open", report)
        self.assertNotIn("53/ UDP ", report)

    def test_text_report_normalizes_state_in_host_detail(self) -> None:
        scan = Scan(
            source="host-state-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol="tcp", state=" OPEN ", service="http"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("80/tcp open         http", report)
        self.assertNotIn(" OPEN ", report)

    def test_text_report_normalizes_host_status(self) -> None:
        scan = Scan(
            source="host-status-normalization.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status=" UP ",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service="http"),
                    ),
                ),
            ),
        )

        report = render_text(scan)

        self.assertIn("Network Summary: 1 up, 1 open ports, 1 unique services", report)
        self.assertIn("192.0.2.10 [192.0.2.10] (up)", report)
        self.assertNotIn("( UP )", report)

    def test_text_report_normalizes_protocol_in_shared_service_endpoint(self) -> None:
        scan = Scan(
            source="shared-protocol-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(port=80, protocol=" TCP ", state="open", service="http"),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("192.0.2.10:80/tcp", report)
        self.assertNotIn("192.0.2.10:80/ TCP ", report)

    def test_text_report_strips_metadata_in_shared_service_endpoint(self) -> None:
        scan = Scan(
            source="shared-metadata-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        product=" Apache httpd ",
                        version=" 2.4.68 ",
                        extra_info="   ",
                    ),
                )),
                Host(address="192.0.2.20", status="up", ports=(
                    Port(port=8080, protocol="tcp", state="open", service="http"),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("192.0.2.10:80/tcp  Apache httpd 2.4.68", report)
        self.assertNotIn("  Apache httpd  ", report)
        self.assertNotIn(" 2.4.68  ", report)

    def test_text_report_normalizes_tunnel_in_host_detail(self) -> None:
        scan = Scan(
            source="host-tunnel-normalization.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=443,
                        protocol="tcp",
                        state="open",
                        service="https",
                        tunnel=" SSL ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("[tunnel:ssl]", report)
        self.assertNotIn("[tunnel: SSL ]", report)

    def test_text_report_ignores_whitespace_only_tunnel(self) -> None:
        scan = Scan(
            source="blank-tunnel.xml",
            hosts=(
                Host(address="192.0.2.10", status="up", ports=(
                    Port(
                        port=443,
                        protocol="tcp",
                        state="open",
                        service="https",
                        tunnel="   ",
                    ),
                )),
            ),
        )

        report = render_text(scan)

        self.assertIn("443/tcp open         https", report)
        self.assertNotIn("[tunnel:", report)

    def test_findings_are_prioritized_by_severity(self) -> None:
        findings = (
            Finding("info.context", "context", "192.0.2.10", None, None, "info", "Context", "info evidence", "Review."),
            Finding("medium.config", "configuration", "192.0.2.10", 445, "tcp", "medium", "Configuration review", "medium evidence", "Review."),
            Finding("low.review", "configuration", "192.0.2.10", 80, "tcp", "low", "Low review", "low evidence", "Review."),
        )

        report = render_findings(findings)

        self.assertLess(report.index("[MEDIUM]"), report.index("[LOW]"))
        self.assertLess(report.index("[LOW]"), report.index("[INFO]"))


    def test_equivalent_ipv6_addresses_do_not_create_false_shared_service(self) -> None:
        scan = Scan(source="ipv6.xml", hosts=(
            Host(address="2001:0db8:0000:0000:0000:0000:0000:0001", status="up", ports=(
                Port(port=80, protocol="tcp", state="open", service="http"),
            )),
            Host(address="2001:db8::1", status="up", ports=(
                Port(port=443, protocol="tcp", state="open", service="http"),
            )),
        ))

        report = render_text(scan)
        self.assertNotIn("Shared Services Across Hosts", report)

    def test_summary_status_and_open_state_are_case_insensitive(self) -> None:
        scan = Scan(source="case.xml", hosts=(Host(
            address="192.0.2.10", status="UP", ports=(
                Port(port=80, protocol="tcp", state="OPEN", service="http"),
            ),
        ),))

        report = render_text(scan)
        self.assertIn("Network Summary: 1 up, 1 open ports, 1 unique services", report)
        self.assertIn("80/tcp open", report)


    def test_renders_partial_evidence_collection_failure(self) -> None:
        command = NmapCommand(("nmap",))
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "permission denied"),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(failed,),
            host=Host(address="192.0.2.134", status="up"),
            findings=(),
        )

        report = render_evidence_collection(result)

        self.assertIn("Host: 192.0.2.134", report)
        self.assertIn("Status: partial", report)
        self.assertIn("Failure: permission denied", report)


    def test_renders_timeout_as_partial_evidence_collection_failure(self) -> None:
        command = NmapCommand(("nmap", "-p", "445", "192.0.2.143"))
        timed_out = ParsedCollectionResult(
            result=CollectionResult(
                command,
                124,
                "",
                "Nmap evidence collection timed out",
            ),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(timed_out,),
            host=Host(address="192.0.2.143", status="up"),
            findings=(),
        )

        report = render_evidence_collection(result)

        self.assertIn("Status: partial", report)
        self.assertIn("Failure: Nmap evidence collection timed out", report)

    def test_renders_complete_evidence_collection_without_failure(self) -> None:
        command = NmapCommand(("nmap",))
        successful = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", "warning text"),
            scan=Scan(source="nmap stdout"),
        )
        result = CorrelatedEvidenceResult(
            outcomes=(successful,),
            host=Host(address="192.0.2.135", status="up"),
            findings=(),
        )

        report = render_evidence_collection(result)

        self.assertIn("Host: 192.0.2.135", report)
        self.assertIn("Status: complete", report)
        self.assertNotIn("Failure:", report)


    def test_renders_partial_evidence_collection_as_json(self) -> None:
        command = NmapCommand(("nmap",))
        failed = ParsedCollectionResult(
            result=CollectionResult(command, 1, "", "permission denied"),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(failed,),
            host=Host(address="192.0.2.136", status="up"),
            findings=(),
        )

        payload = json.loads(render_evidence_collection_json(result))

        self.assertEqual(payload["host"], "192.0.2.136")
        self.assertEqual(payload["status"], "partial")
        self.assertEqual(payload["failures"], ["permission denied"])


    def test_renders_timeout_as_partial_evidence_collection_json(self) -> None:
        command = NmapCommand(("nmap", "-p", "445", "192.0.2.144"))
        timed_out = ParsedCollectionResult(
            result=CollectionResult(
                command,
                124,
                "",
                "Nmap evidence collection timed out",
            ),
            scan=None,
        )
        result = CorrelatedEvidenceResult(
            outcomes=(timed_out,),
            host=Host(address="192.0.2.144", status="up"),
            findings=(),
        )

        payload = json.loads(render_evidence_collection_json(result))

        self.assertEqual(payload["status"], "partial")
        self.assertEqual(
            payload["failures"],
            ["Nmap evidence collection timed out"],
        )

    def test_renders_multiple_evidence_collections_as_one_json_document(self) -> None:
        first = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.137", status="up"),
            findings=(),
        )
        second = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.138", status="up"),
            findings=(),
        )

        payload = json.loads(render_evidence_collections_json((first, second)))

        self.assertEqual(
            [item["host"] for item in payload],
            ["192.0.2.137", "192.0.2.138"],
        )
        self.assertEqual([item["status"] for item in payload], ["complete", "complete"])


    def test_evidence_collection_text_report_includes_correlated_findings(self) -> None:
        finding = Finding(
            finding_id="test-evidence",
            category="evidence",
            host="192.0.2.139",
            port=443,
            protocol="tcp",
            severity="info",
            title="Collected TLS evidence",
            evidence="TLS evidence was collected",
            recommendation="Review the collected evidence",
        )
        result = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.139", status="up"),
            findings=(finding,),
        )

        report = render_evidence_collection(result)

        self.assertIn("Findings", report)
        self.assertIn("Collected TLS evidence", report)
        self.assertIn("TLS evidence was collected", report)
        self.assertIn("Host Summary", report)
        self.assertIn(
            "192.0.2.139 — 0 open ports — no open services — 1 findings",
            report,
        )
        self.assertIn("  Severity: info=1", report)


    def test_evidence_collection_json_includes_correlated_findings(self) -> None:
        finding = Finding(
            finding_id="json-evidence",
            category="evidence",
            host="192.0.2.140",
            port=22,
            protocol="tcp",
            severity="info",
            title="Collected SSH evidence",
            evidence="SSH algorithms were collected",
            recommendation="Review the collected algorithms",
        )
        result = CorrelatedEvidenceResult(
            outcomes=(),
            host=Host(address="192.0.2.140", status="up"),
            findings=(finding,),
        )

        payload = json.loads(render_evidence_collection_json(result))

        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["finding_id"], "json-evidence")
        self.assertEqual(payload["findings"][0]["title"], "Collected SSH evidence")
        self.assertEqual(payload["host_summary"]["host"], "192.0.2.140")
        self.assertEqual(payload["host_summary"]["status"], "up")
        self.assertEqual(payload["host_summary"]["open_ports"], 0)
        self.assertEqual(payload["host_summary"]["services"], [])
        self.assertEqual(payload["host_summary"]["findings"], 1)
        self.assertEqual(payload["host_summary"]["severity_counts"], [["info", 1]])


    def test_renders_host_summaries_with_finding_severity_breakdown(self) -> None:
        scan = Scan(
            source="analysis.xml",
            hosts=(
                Host(
                    address="192.0.2.10",
                    status="up",
                    ports=(
                        Port(port=80, protocol="tcp", state="open", service="http"),
                        Port(port=445, protocol="tcp", state="open", service="microsoft-ds"),
                    ),
                ),
                Host(address="192.0.2.20", status="up"),
            ),
        )
        findings = (
            Finding("high.one", "test", "192.0.2.10", 445, "tcp", "high", "High", "evidence", "Review."),
            Finding("medium.one", "test", "192.0.2.10", 80, "tcp", "medium", "Medium", "evidence", "Review."),
            Finding("info.one", "test", "192.0.2.10", None, None, "info", "Info", "evidence", "Review."),
        )

        report = render_host_summaries(scan, findings)

        self.assertIn("Host Summary", report)
        self.assertIn("192.0.2.10 — 2 open ports — http, microsoft-ds — 3 findings", report)
        self.assertIn("  Severity: high=1, medium=1, info=1", report)
        self.assertIn("192.0.2.20 — 0 open ports — no open services — 0 findings", report)
        self.assertIn("  Severity: none", report)


    def test_renders_evidence_gaps_as_text(self) -> None:
        gaps = (
            EvidenceGap(
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                script_id="smb2-security-mode",
                purpose="review SMB signing configuration",
            ),
        )

        report = render_evidence_gaps(gaps)

        self.assertIn("Evidence Gaps", report)
        self.assertIn("Gaps: 1", report)
        self.assertIn("192.0.2.10:445/tcp", report)
        self.assertIn("smb2-security-mode", report)
        self.assertIn("review SMB signing configuration", report)

    def test_renders_evidence_gaps_as_json(self) -> None:
        gaps = (
            EvidenceGap(
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                script_id="smb2-security-mode",
                purpose="review SMB signing configuration",
            ),
        )

        payload = json.loads(render_evidence_gaps_json(gaps))

        self.assertEqual(payload["report_type"], "evidence_gaps")
        self.assertEqual(payload["summary"], {"gaps": 1})
        self.assertEqual(
            payload["gaps"][0],
            {
                "host": "192.0.2.10",
                "port": 445,
                "protocol": "tcp",
                "script_id": "smb2-security-mode",
                "purpose": "review SMB signing configuration",
            },
        )

    def test_renders_empty_evidence_gaps_without_inventing_actions(self) -> None:
        self.assertIn("Gaps: 0", render_evidence_gaps(()))
        payload = json.loads(render_evidence_gaps_json(()))
        self.assertEqual(payload["summary"], {"gaps": 0})
        self.assertEqual(payload["gaps"], [])


    def test_renders_evidence_action_plan_as_text(self) -> None:
        actions = (
            EvidenceAction(
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                script_ids=("smb-protocols", "smb2-security-mode"),
                purposes=(
                    "review SMB protocol dialect support",
                    "review SMB signing configuration",
                ),
                command=(
                    "nmap", "-p", "445", "--script",
                    "smb-protocols,smb2-security-mode",
                    "-oX", "-", "192.0.2.10",
                ),
            ),
        )

        report = render_evidence_action_plan(actions)

        self.assertIn("Evidence Action Plan", report)
        self.assertIn("Actions: 1", report)
        self.assertIn("192.0.2.10:445/tcp", report)
        self.assertIn("review SMB protocol dialect support", report)
        self.assertIn("review SMB signing configuration", report)
        self.assertIn(
            "nmap -p 445 --script smb-protocols,smb2-security-mode -oX - 192.0.2.10",
            report,
        )

    def test_renders_evidence_action_plan_as_json_with_argv_command(self) -> None:
        actions = (
            EvidenceAction(
                host="192.0.2.10",
                port=445,
                protocol="tcp",
                script_ids=("smb-protocols", "smb2-security-mode"),
                purposes=(
                    "review SMB protocol dialect support",
                    "review SMB signing configuration",
                ),
                command=(
                    "nmap", "-p", "445", "--script",
                    "smb-protocols,smb2-security-mode",
                    "-oX", "-", "192.0.2.10",
                ),
            ),
        )

        payload = json.loads(render_evidence_action_plan_json(actions))

        self.assertEqual(payload["report_type"], "evidence_action_plan")
        self.assertEqual(payload["summary"], {"actions": 1})
        self.assertEqual(
            payload["actions"][0],
            {
                "host": "192.0.2.10",
                "port": 445,
                "protocol": "tcp",
                "script_ids": ["smb-protocols", "smb2-security-mode"],
                "purposes": [
                    "review SMB protocol dialect support",
                    "review SMB signing configuration",
                ],
                "command": [
                    "nmap", "-p", "445", "--script",
                    "smb-protocols,smb2-security-mode",
                    "-oX", "-", "192.0.2.10",
                ],
            },
        )

    def test_renders_empty_evidence_action_plan_without_inventing_actions(self) -> None:
        self.assertIn("Actions: 0", render_evidence_action_plan(()))
        payload = json.loads(render_evidence_action_plan_json(()))
        self.assertEqual(payload["summary"], {"actions": 0})
        self.assertEqual(payload["actions"], [])


    def test_renders_discovery_plan_as_text(self) -> None:
        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )

        report = render_discovery_plan(plan)

        self.assertIn("Discovery Plan", report)
        self.assertIn("Target: 192.0.2.10", report)
        self.assertIn("Profile: baseline", report)
        self.assertIn("Purpose: discover open TCP services with version detection", report)
        self.assertIn("Suggested discovery: nmap -sV -oX - 192.0.2.10", report)

    def test_renders_discovery_plan_as_json_with_argv_command(self) -> None:
        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )

        payload = json.loads(render_discovery_plan_json(plan))

        self.assertEqual(payload["report_type"], "discovery_plan")
        self.assertEqual(payload["target"], "192.0.2.10")
        self.assertEqual(payload["profile"], "baseline")
        self.assertEqual(
            payload["purpose"],
            "discover open TCP services with version detection",
        )
        self.assertEqual(
            payload["command"],
            ["nmap", "-sV", "-oX", "-", "192.0.2.10"],
        )


    def test_renders_successful_discovery_execution_as_text(self) -> None:
        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 0, "<nmaprun/>", "", False)
        result = DiscoveryResult(
            execution=execution,
            success=True,
            scan=Scan(source="<discovery:192.0.2.10>", hosts_up=0, hosts_down=1, hosts_total=1),
            error=None,
        )

        report = render_discovery_execution(result)

        self.assertIn("Discovery Execution", report)
        self.assertIn("Status: success", report)
        self.assertIn("Command: nmap -sV -oX - 192.0.2.10", report)
        self.assertIn("Hosts: 0 parsed / 1 total (0 up, 1 down)", report)

    def test_renders_failed_discovery_execution_as_text(self) -> None:
        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 2, "", "nmap failed", False)
        result = DiscoveryResult(execution, False, None, "nmap failed")

        report = render_discovery_execution(result)

        self.assertIn("Status: failed", report)
        self.assertIn("Command: nmap -sV -oX - 192.0.2.10", report)
        self.assertIn("Error: nmap failed", report)

    def test_renders_discovery_execution_json_with_provenance(self) -> None:
        plan = DiscoveryPlan(
            target="192.0.2.10",
            profile="baseline",
            purpose="discover open TCP services with version detection",
            command=("nmap", "-sV", "-oX", "-", "192.0.2.10"),
        )
        execution = DiscoveryExecutionResult(plan, 2, "", "nmap failed", False)
        result = DiscoveryResult(execution, False, None, "nmap failed")

        payload = json.loads(render_discovery_execution_json(result))

        self.assertEqual(payload["report_type"], "discovery_execution")
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["target"], "192.0.2.10")
        self.assertEqual(payload["profile"], "baseline")
        self.assertEqual(payload["command"], ["nmap", "-sV", "-oX", "-", "192.0.2.10"])
        self.assertEqual(payload["returncode"], 2)
        self.assertFalse(payload["timed_out"])
        self.assertEqual(payload["error"], "nmap failed")
        self.assertIsNone(payload["scan"])


    def test_renders_investigation_snapshot_for_analyst_review(self) -> None:
        scan = Scan(source="<discovery:192.0.2.10>")
        gap = EvidenceGap(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_id="smb-protocols",
            purpose="review SMB protocol dialect support",
        )
        action = EvidenceAction(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_ids=("smb-protocols",),
            purposes=("review SMB protocol dialect support",),
            command=("nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.10"),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(gap,),
            actions=(action,),
            states=(),
            error=None,
        )

        report = render_investigation_snapshot(snapshot)

        self.assertIn("Investigation Snapshot", report)
        self.assertIn("Status: ready", report)
        self.assertIn("Evidence Gaps: 1", report)
        self.assertIn("Proposed Actions: 1", report)
        self.assertIn("192.0.2.10:445/tcp", report)
        self.assertIn("smb-protocols", report)
        self.assertIn(
            "Suggested collection: nmap -p 445 --script smb-protocols -oX - 192.0.2.10",
            report,
        )

    def test_renders_approval_blocked_finding_requirement(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        plan = FindingCollectionPlan(
            requirement=requirement,
            strategy=RequirementCollectionStrategy(
                requirement_id="smb_access_control_context",
                status="supported",
                script_ids=("smb-enum-shares",),
                risk_class="intrusive",
                authorization="requires_approval",
            ),
            authorization=CollectionAuthorizationDecision(
                allowed=False,
                reason="explicit_approval_required",
            ),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml"),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_collection_plans=(plan,),
        )

        report = render_investigation_snapshot(snapshot)

        self.assertIn("Pending Approval: 192.0.2.10:445/tcp", report)
        self.assertIn("Requirement: smb_access_control_context", report)
        self.assertIn("Finding: smb.signing.review", report)
        self.assertIn("Evidence Source: nse:smb2-security-mode", report)
        self.assertIn("Proposed collection: smb-enum-shares", report)
        self.assertIn("Risk: intrusive", report)
        self.assertIn("Authorization: explicit approval required", report)

    def test_renders_approval_blocked_requirement_in_snapshot_json(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        plan = FindingCollectionPlan(
            requirement=requirement,
            strategy=RequirementCollectionStrategy(
                requirement_id="smb_access_control_context",
                status="supported",
                script_ids=("smb-enum-shares",),
                risk_class="intrusive",
                authorization="requires_approval",
            ),
            authorization=CollectionAuthorizationDecision(
                allowed=False,
                reason="explicit_approval_required",
            ),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml"),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_collection_plans=(plan,),
        )

        payload = json.loads(render_investigation_snapshot_json(snapshot))

        self.assertEqual(payload["summary"]["pending_approvals"], 1)
        self.assertEqual(len(payload["pending_approvals"]), 1)
        pending = payload["pending_approvals"][0]
        self.assertEqual(pending["requirement_id"], "smb_access_control_context")
        self.assertEqual(pending["finding_id"], "smb.signing.review")
        self.assertEqual(pending["script_ids"], ["smb-enum-shares"])
        self.assertEqual(pending["risk_class"], "intrusive")
        self.assertEqual(pending["reason"], "explicit_approval_required")

    def test_renders_finding_requirement_lifecycle_states(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.20",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="attempted_unsatisfied",
            authorization_reason="explicitly_approved",
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml"),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(state,),
        )

        report = render_investigation_snapshot(snapshot)

        self.assertIn("Finding Requirement Lifecycle", report)
        self.assertIn(
            "Requirement State: 192.0.2.20:445/tcp  smb_access_control_context — attempted_unsatisfied",
            report,
        )
        self.assertIn("Finding: smb.signing.review", report)
        self.assertIn("Evidence Source: nse:smb2-security-mode", report)
        self.assertIn("Authorization: explicitly_approved", report)

    def test_renders_finding_requirement_lifecycle_json(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.21",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement=requirement,
            status="satisfied",
            authorization_reason="explicitly_approved",
            observed_script_ids=("smb-enum-shares",),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="test.xml"),
            gaps=(),
            actions=(),
            states=(),
            error=None,
            finding_requirement_states=(state,),
        )

        payload = json.loads(render_investigation_snapshot_json(snapshot))

        self.assertEqual(payload["summary"]["finding_requirement_states"], 1)
        self.assertEqual(
            payload["finding_requirement_states"],
            [
                {
                    "host": "192.0.2.21",
                    "port": 445,
                    "protocol": "tcp",
                    "requirement_id": "smb_access_control_context",
                    "purpose": "review SMB access controls",
                    "finding_id": "smb.signing.review",
                    "evidence_source": "nse:smb2-security-mode",
                    "status": "satisfied",
                    "authorization_reason": "explicitly_approved",
                    "observed_script_ids": ["smb-enum-shares"],
                }
            ],
        )

    def test_renders_blocked_investigation_snapshot_without_actions(self) -> None:
        snapshot = InvestigationSnapshot(
            ready=False,
            scan=None,
            gaps=(),
            actions=(),
            states=(),
            error="nmap failed",
        )

        report = render_investigation_snapshot(snapshot)

        self.assertIn("Status: blocked", report)
        self.assertIn("Evidence Gaps: 0", report)
        self.assertIn("Proposed Actions: 0", report)
        self.assertIn("Error: nmap failed", report)

    def test_renders_investigation_snapshot_json(self) -> None:
        scan = Scan(source="<discovery:192.0.2.10>")
        gap = EvidenceGap(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_id="smb-protocols",
            purpose="review SMB protocol dialect support",
        )
        action = EvidenceAction(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_ids=("smb-protocols",),
            purposes=("review SMB protocol dialect support",),
            command=("nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.10"),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=scan,
            gaps=(gap,),
            actions=(action,),
            states=(),
            error=None,
        )

        payload = json.loads(render_investigation_snapshot_json(snapshot))

        self.assertEqual(payload["report_type"], "investigation_snapshot")
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(
            payload["summary"],
            {
                "evidence_gaps": 1,
                "proposed_actions": 1,
                "investigation_states": 0,
                "pending_approvals": 0,
                "finding_requirement_states": 0,
            },
        )
        self.assertEqual(payload["error"], None)
        self.assertEqual(payload["gaps"][0]["script_id"], "smb-protocols")
        self.assertEqual(
            payload["actions"][0]["command"],
            ["nmap", "-p", "445", "--script", "smb-protocols", "-oX", "-", "192.0.2.10"],
        )


    def test_investigation_snapshot_renders_known_and_unknown_endpoint_state(self) -> None:
        gap = EvidenceGap(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_id="smb-protocols",
            purpose="review SMB protocol dialect support",
        )
        state = EndpointInvestigationState(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            known=("state=open", "service=microsoft-ds"),
            unknown=(gap,),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="<discovery:192.0.2.10>"),
            gaps=(gap,),
            actions=(),
            states=(state,),
            error=None,
        )

        report = render_investigation_snapshot(snapshot)

        self.assertIn("Investigation State", report)
        self.assertIn("192.0.2.10:445/tcp", report)
        self.assertIn("Known: state=open", report)
        self.assertIn("Known: service=microsoft-ds", report)
        self.assertIn(
            "Unknown: smb-protocols — review SMB protocol dialect support",
            report,
        )

    def test_investigation_snapshot_json_preserves_structured_endpoint_state(self) -> None:
        gap = EvidenceGap(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            script_id="smb2-security-mode",
            purpose="review SMB signing configuration",
        )
        state = EndpointInvestigationState(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            known=("state=open", "service=microsoft-ds"),
            unknown=(gap,),
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="<discovery:192.0.2.10>"),
            gaps=(gap,),
            actions=(),
            states=(state,),
            error=None,
        )

        data = json.loads(render_investigation_snapshot_json(snapshot))

        self.assertEqual(data["summary"]["investigation_states"], 1)
        self.assertEqual(
            data["states"],
            [
                {
                    "host": "192.0.2.10",
                    "port": 445,
                    "protocol": "tcp",
                    "known": ["state=open", "service=microsoft-ds"],
                    "unknown": [
                        {
                            "host": "192.0.2.10",
                            "port": 445,
                            "protocol": "tcp",
                            "script_id": "smb2-security-mode",
                            "purpose": "review SMB signing configuration",
                        }
                    ],
                }
            ],
        )


    def test_investigation_continuation_report_preserves_collection_outcomes(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from reporter import render_investigation_continuation
        from models import Scan

        command = NmapCommand(
            arguments=(
                "nmap", "-p", "5357", "--script", "http-title,http-methods",
                "-oX", "-", "192.0.2.120",
            )
        )
        outcome = ParsedCollectionResult(
            result=CollectionResult(
                command=command,
                returncode=124,
                stdout="",
                stderr="Nmap evidence collection timed out",
            ),
            scan=None,
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="discovery.xml"),
            gaps=(),
            actions=(),
            states=(),
            error=None,
        )

        report = render_investigation_continuation(
            InvestigationContinuationResult((outcome,), snapshot)
        )

        self.assertIn("Evidence Collection Outcomes", report)
        self.assertIn("nmap -p 5357 --script http-title,http-methods -oX - 192.0.2.120", report)
        self.assertIn("Status: failed", report)
        self.assertIn("Return Code: 124", report)
        self.assertIn("Failure: Nmap evidence collection timed out", report)


    def test_investigation_continuation_distinguishes_collection_success_from_missing_requested_evidence(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from reporter import render_investigation_continuation
        from models import Scan

        command = NmapCommand(
            arguments=(
                "nmap", "-p", "5357", "--script", "http-title,http-methods",
                "-oX", "-", "192.0.2.120",
            )
        )
        outcome = ParsedCollectionResult(
            result=CollectionResult(command=command, returncode=0, stdout="<nmaprun/>", stderr=""),
            scan=Scan(source="<collection>"),
        )
        remaining_title = EvidenceGap(
            host="192.0.2.120", port=5357, protocol="tcp",
            script_id="http-title",
            purpose="review HTTP service identity and exposed content context",
        )
        remaining_methods = EvidenceGap(
            host="192.0.2.120", port=5357, protocol="tcp",
            script_id="http-methods",
            purpose="review supported HTTP methods",
        )
        action = EvidenceAction(
            host="192.0.2.120", port=5357, protocol="tcp",
            script_ids=("http-title", "http-methods"),
            purposes=(
                "review HTTP service identity and exposed content context",
                "review supported HTTP methods",
            ),
            command=command.arguments,
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="discovery.xml"),
            gaps=(remaining_title, remaining_methods),
            actions=(action,),
            states=(),
            error=None,
        )

        report = render_investigation_continuation(
            InvestigationContinuationResult((outcome,), snapshot)
        )

        self.assertIn("Collection Status: success", report)
        self.assertIn("Requested Evidence: incomplete", report)
        self.assertIn("Missing Evidence: http-title, http-methods", report)
        self.assertNotIn("\nStatus: success\n", f"\n{report}\n")


    def test_investigation_continuation_json_preserves_collection_and_evidence_status(self) -> None:
        from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from reporter import render_investigation_continuation_json
        from models import Scan

        command = NmapCommand(
            arguments=(
                "nmap", "-p", "5357", "--script", "http-title,http-methods",
                "-oX", "-", "192.0.2.120",
            )
        )
        outcome = ParsedCollectionResult(
            result=CollectionResult(command=command, returncode=0, stdout="<nmaprun/>", stderr=""),
            scan=Scan(source="<collection>"),
        )
        remaining_title = EvidenceGap(
            host="192.0.2.120", port=5357, protocol="tcp",
            script_id="http-title",
            purpose="review HTTP service identity and exposed content context",
        )
        remaining_methods = EvidenceGap(
            host="192.0.2.120", port=5357, protocol="tcp",
            script_id="http-methods",
            purpose="review supported HTTP methods",
        )
        action = EvidenceAction(
            host="192.0.2.120", port=5357, protocol="tcp",
            script_ids=("http-title", "http-methods"),
            purposes=(
                "review HTTP service identity and exposed content context",
                "review supported HTTP methods",
            ),
            command=command.arguments,
        )
        snapshot = InvestigationSnapshot(
            ready=True,
            scan=Scan(source="discovery.xml"),
            gaps=(remaining_title, remaining_methods),
            actions=(action,),
            states=(),
            error=None,
        )

        data = json.loads(
            render_investigation_continuation_json(
                InvestigationContinuationResult((outcome,), snapshot)
            )
        )

        self.assertEqual(data["report_type"], "investigation_continuation")
        self.assertEqual(data["collection_outcomes"][0]["argv"], list(command.arguments))
        self.assertEqual(data["collection_outcomes"][0]["collection_status"], "success")
        self.assertEqual(data["collection_outcomes"][0]["requested_evidence"], "incomplete")
        self.assertEqual(
            data["collection_outcomes"][0]["missing_evidence"],
            ["http-title", "http-methods"],
        )
        self.assertEqual(data["collection_outcomes"][0]["returncode"], 0)
        self.assertEqual(data["updated_investigation"]["summary"]["evidence_gaps"], 2)


    def test_investigation_continuation_text_exposes_stalled_decision(self) -> None:
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import render_investigation_continuation

        snapshot = InvestigationSnapshot(True, Scan("test.xml", ()), (), (), (), None)
        decision = InvestigationContinuationDecision("stalled", (), (), ())
        report = render_investigation_continuation(
            InvestigationContinuationResult((), snapshot),
            decision,
        )

        self.assertIn("Continuation Decision", report)
        self.assertIn("Status: stalled", report)

    def test_investigation_continuation_json_exposes_decision_counts(self) -> None:
        import json
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import render_investigation_continuation_json

        snapshot = InvestigationSnapshot(True, Scan("test.xml", ()), (), (), (), None)
        decision = InvestigationContinuationDecision("complete", (), (), ())
        data = json.loads(
            render_investigation_continuation_json(
                InvestigationContinuationResult((), snapshot),
                decision,
            )
        )

        self.assertEqual(
            data["continuation_decision"],
            {
                "status": "complete",
                "stall_reason": None,
                "resolved_gaps": 0,
                "resolved_requirements": [],
                "remaining_gaps": 0,
                "next_actions": 0,
                "repeat_blocked_actions": 0,
                "alternative_actions": [],
            },
        )


    def test_investigation_continuation_text_exposes_final_decision(self) -> None:
        from investigation_orchestration import (
            FinalInvestigationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan
        from reporter import render_investigation_continuation

        gap = EvidenceGap("192.0.2.110", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        final = FinalInvestigationDecision(
            "stalled",
            "alternative_evidence_incomplete",
            (gap,),
            (),
        )

        report = render_investigation_continuation(
            InvestigationContinuationResult((), snapshot),
            None,
            None,
            final,
        )

        self.assertIn("Final Investigation Decision", report)
        self.assertIn("Status: stalled", report)
        self.assertIn("Reason: alternative_evidence_incomplete", report)
        self.assertIn("Remaining Gaps: 1", report)
        self.assertIn("Further Supported Actions: 0", report)
        self.assertIn("Remaining Requirements: 0", report)

    def test_investigation_continuation_json_exposes_final_decision(self) -> None:
        import json
        from investigation_orchestration import (
            FinalInvestigationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from evidence_gaps import EvidenceGap
        from models import Scan
        from reporter import render_investigation_continuation_json

        gap = EvidenceGap("192.0.2.111", 5357, "tcp", "http-methods", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        final = FinalInvestigationDecision(
            "stalled",
            "alternative_collection_failed",
            (gap,),
            (),
        )

        data = json.loads(
            render_investigation_continuation_json(
                InvestigationContinuationResult((), snapshot),
                None,
                None,
                final,
            )
        )

        self.assertEqual(
            data["final_investigation_decision"],
            {
                "status": "stalled",
                "reason": "alternative_collection_failed",
                "remaining_gaps": 1,
                "further_supported_actions": 0,
                "satisfied_requirements": [],
                "remaining_requirements": [],
                "remaining_finding_requirements": [],
            },
        )


    def test_final_decision_reports_real_remaining_semantic_requirement(self) -> None:
        import json
        from evidence_gaps import EvidenceGap, EvidenceRequirement, EvidenceRequirementState
        from investigation_orchestration import (
            FinalInvestigationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import (
            render_investigation_continuation,
            render_investigation_continuation_json,
        )

        gap = EvidenceGap("192.0.2.112", 5357, "tcp", "http-methods", "purpose")
        requirement = EvidenceRequirement(
            "http_supported_methods",
            "review supported HTTP methods",
            ("http-methods",),
        )
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        final = FinalInvestigationDecision(
            "stalled",
            "alternative_evidence_incomplete",
            (gap,),
            (),
            (EvidenceRequirementState("192.0.2.112", 5357, "tcp", requirement),),
        )
        result = InvestigationContinuationResult((), snapshot)

        text_report = render_investigation_continuation(result, None, None, final)
        json_report = json.loads(
            render_investigation_continuation_json(result, None, None, final)
        )

        self.assertIn("Remaining Requirements: 1", text_report)
        self.assertIn(
            "Requirement: 192.0.2.112:5357/tcp  http_supported_methods — review supported HTTP methods",
            text_report,
        )
        self.assertEqual(
            json_report["final_investigation_decision"]["remaining_requirements"],
            [
                {
                    "host": "192.0.2.112",
                    "port": 5357,
                    "protocol": "tcp",
                    "requirement_id": "http_supported_methods",
                    "purpose": "review supported HTTP methods",
                    "primary_script_ids": ["http-methods"],
                    "alternative_script_ids": [],
                }
            ],
        )


    def test_semantic_complete_report_preserves_raw_gap_provenance(self) -> None:
        from evidence_gaps import EvidenceGap
        from investigation_orchestration import (
            FinalInvestigationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import (
            render_investigation_continuation,
            render_investigation_continuation_json,
        )

        gap = EvidenceGap("192.0.2.113", 5357, "tcp", "http-title", "purpose")
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (gap,), (), (), None)
        final = FinalInvestigationDecision(
            "complete",
            "all_semantic_requirements_satisfied",
            (gap,),
            (),
            (),
        )
        result = InvestigationContinuationResult((), snapshot)

        text_report = render_investigation_continuation(result, None, None, final)
        json_report = json.loads(
            render_investigation_continuation_json(result, None, None, final)
        )
        final_json = json_report["final_investigation_decision"]

        self.assertIn("Status: complete", text_report)
        self.assertIn("Reason: all_semantic_requirements_satisfied", text_report)
        self.assertIn("Remaining Gaps: 1", text_report)
        self.assertIn("Remaining Requirements: 0", text_report)
        self.assertEqual(final_json["status"], "complete")
        self.assertEqual(final_json["reason"], "all_semantic_requirements_satisfied")
        self.assertEqual(final_json["remaining_gaps"], 1)
        self.assertEqual(final_json["remaining_requirements"], [])


    def test_report_distinguishes_satisfied_and_remaining_semantic_requirements(self) -> None:
        from evidence_gaps import (
            EvidenceGap,
            EvidenceRequirement,
            EvidenceRequirementState,
        )
        from investigation_orchestration import (
            FinalInvestigationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import (
            render_investigation_continuation,
            render_investigation_continuation_json,
        )

        gaps = (
            EvidenceGap("192.0.2.114", 5357, "tcp", "http-title", "purpose"),
            EvidenceGap("192.0.2.114", 5357, "tcp", "http-methods", "purpose"),
        )
        satisfied = EvidenceRequirementState(
            "192.0.2.114",
            5357,
            "tcp",
            EvidenceRequirement(
                "http_identity_context",
                "review HTTP service identity and exposed content context",
                ("http-title",),
                ("http-headers",),
            ),
        )
        remaining = EvidenceRequirementState(
            "192.0.2.114",
            5357,
            "tcp",
            EvidenceRequirement(
                "http_supported_methods",
                "review supported HTTP methods",
                ("http-methods",),
            ),
        )
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), gaps, (), (), None)
        final = FinalInvestigationDecision(
            status="stalled",
            reason="alternative_evidence_partially_satisfied_requirements",
            remaining_gaps=gaps,
            remaining_requirements=(remaining,),
            satisfied_requirements=(satisfied,),
        )
        result = InvestigationContinuationResult((), snapshot)

        text_report = render_investigation_continuation(result, None, None, final)
        json_report = json.loads(
            render_investigation_continuation_json(result, None, None, final)
        )["final_investigation_decision"]

        self.assertIn("Satisfied Requirements: 1", text_report)
        self.assertIn(
            "Satisfied: 192.0.2.114:5357/tcp  http_identity_context",
            text_report,
        )
        self.assertIn("Remaining Requirements: 1", text_report)
        self.assertIn(
            "Requirement: 192.0.2.114:5357/tcp  http_supported_methods",
            text_report,
        )
        self.assertEqual(
            json_report["satisfied_requirements"][0]["requirement_id"],
            "http_identity_context",
        )
        self.assertEqual(
            json_report["remaining_requirements"][0]["requirement_id"],
            "http_supported_methods",
        )



    def test_continuation_report_exposes_resolved_semantic_requirement(self) -> None:
        from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
        from investigation_orchestration import (
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import (
            render_investigation_continuation,
            render_investigation_continuation_json,
        )

        state = EvidenceRequirementState(
            "192.0.2.115",
            445,
            "tcp",
            EvidenceRequirement(
                "smb_protocol_support",
                "review SMB protocol dialect support",
                ("smb-protocols",),
            ),
        )
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (), (), (), None)
        decision = InvestigationContinuationDecision(
            status="progressed",
            resolved_gaps=(),
            remaining_gaps=(),
            next_actions=(),
            resolved_requirements=(state,),
        )
        result = InvestigationContinuationResult((), snapshot)

        text_report = render_investigation_continuation(result, decision)
        json_report = json.loads(
            render_investigation_continuation_json(result, decision)
        )["continuation_decision"]

        self.assertIn("Resolved Requirements: 1", text_report)
        self.assertIn(
            "Resolved: 192.0.2.115:445/tcp  smb_protocol_support",
            text_report,
        )
        self.assertEqual(
            json_report["resolved_requirements"][0]["requirement_id"],
            "smb_protocol_support",
        )



    def test_continuation_report_summarizes_semantic_requirement_progress(self) -> None:
        from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
        from investigation_orchestration import (
            FinalInvestigationDecision,
            InvestigationContinuationDecision,
            InvestigationContinuationResult,
            InvestigationSnapshot,
        )
        from models import Scan
        from reporter import (
            render_investigation_continuation,
            render_investigation_continuation_json,
        )

        primary = EvidenceRequirementState(
            "192.0.2.116", 445, "tcp",
            EvidenceRequirement(
                "smb_protocol_support",
                "review SMB protocol dialect support",
                ("smb-protocols",),
            ),
        )
        remaining = EvidenceRequirementState(
            "192.0.2.116", 5357, "tcp",
            EvidenceRequirement(
                "http_supported_methods",
                "review supported HTTP methods",
                ("http-methods",),
            ),
        )
        snapshot = InvestigationSnapshot(True, Scan("test.xml"), (), (), (), None)
        decision = InvestigationContinuationDecision(
            status="stalled",
            resolved_gaps=(),
            remaining_gaps=(),
            next_actions=(),
            resolved_requirements=(primary,),
        )
        final = FinalInvestigationDecision(
            status="stalled",
            reason="alternative_evidence_partially_satisfied_requirements",
            remaining_gaps=(),
            remaining_requirements=(remaining,),
            satisfied_requirements=(primary,),
        )
        result = InvestigationContinuationResult((), snapshot)

        text_report = render_investigation_continuation(
            result, decision, final_decision=final
        )
        json_report = json.loads(
            render_investigation_continuation_json(
                result, decision, final_decision=final
            )
        )

        self.assertIn("Semantic Requirement Progress", text_report)
        self.assertIn("Resolved by Primary: 1", text_report)
        self.assertIn("Satisfied by Alternative: 1", text_report)
        self.assertIn("Remaining: 1", text_report)
        self.assertEqual(
            json_report["semantic_requirement_progress"],
            {
                "resolved_by_primary": 1,
                "satisfied_by_alternative": 1,
                "remaining": 1,
            },
        )



    def test_analyst_attention_report_preserves_provenance_and_order(self) -> None:
        from analyst_attention import AnalystAttentionItem
        from reporter import render_analyst_attention, render_analyst_attention_json

        items = (
            AnalystAttentionItem(
                "visibility.first", "visibility", "192.0.2.30", 80, "tcp",
                "Visibility review", "First evidence.", "Review first.",
                "service:detection",
            ),
            AnalystAttentionItem(
                "configuration.second", "configuration", "192.0.2.30", 443, "tcp",
                "Configuration review", "Second evidence.", "Review second.",
                "nse:example",
            ),
        )

        text_report = render_analyst_attention(items)
        json_report = json.loads(render_analyst_attention_json(items))

        self.assertIn("Analyst Attention", text_report)
        self.assertIn("Evidence Source: service:detection", text_report)
        self.assertIn("Evidence Source: nse:example", text_report)
        self.assertLess(
            text_report.index("Visibility review"),
            text_report.index("Configuration review"),
        )
        self.assertEqual(json_report["report_type"], "analyst_attention")
        self.assertEqual(json_report["summary"], {"items": 2})
        self.assertEqual(
            [item["finding_id"] for item in json_report["items"]],
            ["visibility.first", "configuration.second"],
        )



    def test_continuation_report_embeds_analyst_attention_with_provenance(self) -> None:
        from analyst_attention import AnalystAttentionItem
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from models import Scan
        from reporter import render_investigation_continuation, render_investigation_continuation_json

        snapshot = InvestigationSnapshot(True, Scan("final.xml"), (), (), (), None)
        result = InvestigationContinuationResult((), snapshot)
        attention = (
            AnalystAttentionItem(
                "smb.signing.review",
                "configuration",
                "192.0.2.50",
                445,
                "tcp",
                "SMB signing configuration requires review",
                "SMB message signing is enabled but not required.",
                "Review whether SMB signing should be required.",
                "nse:smb2-security-mode",
            ),
        )

        text_report = render_investigation_continuation(
            result, attention=attention
        )
        json_report = json.loads(
            render_investigation_continuation_json(
                result, attention=attention
            )
        )

        self.assertIn("Analyst Attention", text_report)
        self.assertIn("SMB signing configuration requires review", text_report)
        self.assertIn("Evidence Source: nse:smb2-security-mode", text_report)
        self.assertEqual(
            json_report["analyst_attention"]["report_type"],
            "analyst_attention",
        )
        self.assertEqual(
            json_report["analyst_attention"]["items"][0]["evidence_source"],
            "nse:smb2-security-mode",
        )



    def test_attention_correlation_report_preserves_source_findings_and_provenance(self) -> None:
        from analyst_attention import AnalystAttentionCorrelation
        from reporter import (
            render_analyst_attention_correlations,
            render_analyst_attention_correlations_json,
        )

        correlations = (
            AnalystAttentionCorrelation(
                "smb.exposure_and_signing_review",
                "192.0.2.70",
                "SMB exposure and signing configuration require joint review",
                ("service.smb.exposed", "smb.signing.review"),
                ("service:detection", "nse:smb2-security-mode"),
                "Review SMB exposure together with its signing configuration.",
            ),
        )

        text_report = render_analyst_attention_correlations(correlations)
        json_report = json.loads(
            render_analyst_attention_correlations_json(correlations)
        )

        self.assertIn("Correlated Review", text_report)
        self.assertIn(
            "Findings: service.smb.exposed, smb.signing.review",
            text_report,
        )
        self.assertIn(
            "Evidence Sources: service:detection, nse:smb2-security-mode",
            text_report,
        )
        self.assertEqual(
            json_report["report_type"],
            "analyst_attention_correlations",
        )
        self.assertEqual(json_report["summary"], {"groups": 1})
        self.assertEqual(
            json_report["groups"][0]["finding_ids"],
            ["service.smb.exposed", "smb.signing.review"],
        )
        self.assertEqual(
            json_report["groups"][0]["evidence_sources"],
            ["service:detection", "nse:smb2-security-mode"],
        )


    def test_continuation_report_embeds_correlated_review(self) -> None:
        from analyst_attention import AnalystAttentionCorrelation
        from investigation_orchestration import InvestigationContinuationResult, InvestigationSnapshot
        from models import Scan
        from reporter import render_investigation_continuation, render_investigation_continuation_json

        result = InvestigationContinuationResult(
            (),
            InvestigationSnapshot(True, Scan("final.xml"), (), (), (), None),
        )
        correlations = (
            AnalystAttentionCorrelation(
                "smb.exposure_and_signing_review",
                "192.0.2.80",
                "SMB exposure and signing configuration require joint review",
                ("service.smb.exposed", "smb.signing.review"),
                ("service:detection", "nse:smb2-security-mode"),
                "Review SMB exposure together with signing configuration.",
            ),
        )

        text_report = render_investigation_continuation(
            result, correlations=correlations
        )
        json_report = json.loads(
            render_investigation_continuation_json(
                result, correlations=correlations
            )
        )

        self.assertIn("Correlated Review", text_report)
        self.assertIn(
            "Findings: service.smb.exposed, smb.signing.review",
            text_report,
        )
        self.assertEqual(
            json_report["correlated_review"]["report_type"],
            "analyst_attention_correlations",
        )
        self.assertEqual(
            json_report["correlated_review"]["groups"][0]["evidence_sources"],
            ["service:detection", "nse:smb2-security-mode"],
        )


    def test_investigation_synthesis_renders_remaining_finding_requirement(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_synthesis import InvestigationSynthesis
        from reporter import render_investigation_synthesis, render_investigation_synthesis_json

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.243",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement,
            "attempted_unsatisfied",
            "explicitly_approved",
            (),
        )
        synthesis = InvestigationSynthesis(
            "stalled",
            "finding_requirement_unsatisfied",
            1,
            0,
            (),
            (state,),
        )

        text_report = render_investigation_synthesis(synthesis)
        payload = json.loads(render_investigation_synthesis_json(synthesis))

        self.assertIn("Remaining Finding Requirements: 1", text_report)
        self.assertIn("smb_access_control_context", text_report)
        self.assertEqual(payload["summary"]["remaining_finding_requirements"], 1)
        self.assertEqual(
            payload["remaining_finding_requirements"][0]["status"],
            "attempted_unsatisfied",
        )

    def test_investigation_synthesis_report_preserves_factual_state(self) -> None:
        from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
        from investigation_synthesis import InvestigationSynthesis
        from reporter import (
            render_investigation_synthesis,
            render_investigation_synthesis_json,
        )

        remaining = EvidenceRequirementState(
            "192.0.2.90",
            5357,
            "tcp",
            EvidenceRequirement(
                "http_supported_methods",
                "review supported HTTP methods",
                ("http-methods",),
            ),
        )
        synthesis = InvestigationSynthesis(
            status="stalled",
            reason="alternative_evidence_incomplete",
            attention_items=4,
            correlated_review_groups=1,
            remaining_requirements=(remaining,),
        )

        text_report = render_investigation_synthesis(synthesis)
        json_report = json.loads(render_investigation_synthesis_json(synthesis))

        self.assertIn("Investigation Synthesis", text_report)
        self.assertIn("Status: stalled", text_report)
        self.assertIn("Reason: alternative_evidence_incomplete", text_report)
        self.assertIn("Attention Items: 4", text_report)
        self.assertIn("Correlated Review Groups: 1", text_report)
        self.assertIn("Remaining Requirements: 1", text_report)
        self.assertIn("http_supported_methods", text_report)
        self.assertEqual(json_report["report_type"], "investigation_synthesis")
        self.assertEqual(json_report["status"], "stalled")
        self.assertEqual(json_report["reason"], "alternative_evidence_incomplete")
        self.assertEqual(
            json_report["summary"],
            {
                "attention_items": 4,
                "correlated_review_groups": 1,
                "remaining_requirements": 1,
                "remaining_finding_requirements": 0,
            },
        )
        self.assertEqual(
            json_report["remaining_requirements"][0]["requirement"]["requirement_id"],
            "http_supported_methods",
        )



    def test_investigation_memory_report_preserves_factual_changes(self) -> None:
        from evidence_gaps import EvidenceRequirement, EvidenceRequirementState
        from investigation_memory import InvestigationMemory
        from reporter import render_investigation_memory, render_investigation_memory_json

        added = EvidenceRequirementState(
            "192.0.2.91",
            443,
            "tcp",
            EvidenceRequirement(
                "tls_certificate_identity",
                "review TLS certificate identity",
                ("ssl-cert",),
            ),
        )
        resolved = EvidenceRequirementState(
            "192.0.2.91",
            5357,
            "tcp",
            EvidenceRequirement(
                "http_identity_context",
                "review HTTP service identity and exposed content context",
                ("http-title",),
                ("http-headers",),
            ),
        )
        memory = InvestigationMemory(
            status_changed=False,
            previous_status="stalled",
            current_status="stalled",
            reason_changed=True,
            previous_reason="alternative_evidence_incomplete",
            current_reason="no_supported_actions",
            attention_item_change=1,
            correlated_review_group_change=-1,
            added_requirements=(added,),
            resolved_requirements=(resolved,),
        )

        text_report = render_investigation_memory(memory)
        json_report = json.loads(render_investigation_memory_json(memory))

        self.assertIn("Investigation Memory", text_report)
        self.assertIn("Status: stalled -> stalled", text_report)
        self.assertIn("Status Changed: no", text_report)
        self.assertIn(
            "Reason: alternative_evidence_incomplete -> no_supported_actions",
            text_report,
        )
        self.assertIn("Reason Changed: yes", text_report)
        self.assertIn("Attention Item Change: +1", text_report)
        self.assertIn("Correlated Review Group Change: -1", text_report)
        self.assertIn("Added Requirements: 1", text_report)
        self.assertIn("tls_certificate_identity", text_report)
        self.assertIn("Resolved Requirements: 1", text_report)
        self.assertIn("http_identity_context", text_report)

        self.assertEqual(json_report["report_type"], "investigation_memory")
        self.assertEqual(
            json_report["status"],
            {"previous": "stalled", "current": "stalled", "changed": False},
        )
        self.assertEqual(
            json_report["reason"],
            {
                "previous": "alternative_evidence_incomplete",
                "current": "no_supported_actions",
                "changed": True,
            },
        )
        self.assertEqual(
            json_report["summary"],
            {
                "attention_item_change": 1,
                "correlated_review_group_change": -1,
                "added_requirements": 1,
                "resolved_requirements": 1,
                "added_finding_requirements": 0,
                "resolved_finding_requirements": 0,
                "changed_finding_requirements": 0,
            },
        )
        self.assertEqual(
            json_report["added_requirements"][0]["requirement"]["requirement_id"],
            "tls_certificate_identity",
        )
        self.assertEqual(
            json_report["resolved_requirements"][0]["requirement"]["requirement_id"],
            "http_identity_context",
        )


    def test_compare_investigation_syntheses_tracks_finding_requirement_changes(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import compare_investigation_syntheses
        from investigation_synthesis import InvestigationSynthesis

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.247",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement,
            "attempted_unsatisfied",
            "explicitly_approved",
            (),
        )
        previous = InvestigationSynthesis("complete", "all_gaps_resolved", 0, 0, ())
        current = InvestigationSynthesis(
            "stalled",
            "finding_requirement_unsatisfied",
            0,
            0,
            (),
            (state,),
        )

        memory = compare_investigation_syntheses(previous, current)

        self.assertEqual(memory.added_finding_requirements, (state,))
        self.assertEqual(memory.resolved_finding_requirements, ())

    def test_compare_investigation_syntheses_tracks_finding_requirement_resolution(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import compare_investigation_syntheses
        from investigation_synthesis import InvestigationSynthesis

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.248",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement,
            "pending_approval",
            "explicit_approval_required",
            (),
        )
        previous = InvestigationSynthesis(
            "stalled", "explicit_approval_required", 0, 0, (), (state,)
        )
        current = InvestigationSynthesis("complete", "all_gaps_resolved", 0, 0, ())

        memory = compare_investigation_syntheses(previous, current)

        self.assertEqual(memory.added_finding_requirements, ())
        self.assertEqual(memory.resolved_finding_requirements, (state,))

    def test_compare_investigation_syntheses_tracks_finding_requirement_lifecycle_change(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import compare_investigation_syntheses
        from investigation_synthesis import InvestigationSynthesis

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.249",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            requirement, "pending_approval", "explicit_approval_required", ()
        )
        attempted = FindingRequirementState(
            requirement, "attempted_unsatisfied", "explicitly_approved", ()
        )
        previous = InvestigationSynthesis(
            "stalled", "explicit_approval_required", 0, 0, (), (pending,)
        )
        current = InvestigationSynthesis(
            "stalled", "finding_requirement_unsatisfied", 0, 0, (), (attempted,)
        )

        memory = compare_investigation_syntheses(previous, current)

        self.assertEqual(memory.added_finding_requirements, ())
        self.assertEqual(memory.resolved_finding_requirements, ())
        self.assertEqual(memory.changed_finding_requirements, ((pending, attempted),))

    def test_history_round_trip_finding_lifecycle_feeds_investigation_memory(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_history import (
            InvestigationHistoryRecord,
            parse_investigation_history_record_json,
            render_investigation_history_record_json,
        )
        from investigation_memory import compare_investigation_syntheses
        from investigation_synthesis import InvestigationSynthesis

        requirement = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.254", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            requirement, "pending_approval", "explicit_approval_required", ()
        )
        attempted = FindingRequirementState(
            requirement, "attempted_unsatisfied", "explicitly_approved",
            ("smb-enum-shares",),
        )
        previous = InvestigationHistoryRecord(
            100,
            "192.0.2.254",
            InvestigationSynthesis(
                "stalled", "explicit_approval_required", 0, 0, (), (pending,)
            ),
        )
        restored = parse_investigation_history_record_json(
            render_investigation_history_record_json(previous)
        )
        current = InvestigationSynthesis(
            "stalled", "finding_requirement_unsatisfied", 0, 0, (), (attempted,)
        )

        memory = compare_investigation_syntheses(restored.synthesis, current)

        self.assertEqual(memory.added_finding_requirements, ())
        self.assertEqual(memory.resolved_finding_requirements, ())
        self.assertEqual(memory.changed_finding_requirements, ((pending, attempted),))

    def test_investigation_memory_renders_finding_requirement_lifecycle_change(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import InvestigationMemory
        from reporter import render_investigation_memory, render_investigation_memory_json

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.250",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        pending = FindingRequirementState(
            requirement, "pending_approval", "explicit_approval_required", ()
        )
        attempted = FindingRequirementState(
            requirement, "attempted_unsatisfied", "explicitly_approved", ()
        )
        memory = InvestigationMemory(
            False,
            "stalled",
            "stalled",
            True,
            "explicit_approval_required",
            "finding_requirement_unsatisfied",
            0,
            0,
            (),
            (),
            (),
            (),
            ((pending, attempted),),
        )

        text_report = render_investigation_memory(memory)
        payload = json.loads(render_investigation_memory_json(memory))

        self.assertIn("Changed Finding Requirements: 1", text_report)
        self.assertIn("pending_approval -> attempted_unsatisfied", text_report)
        self.assertEqual(payload["summary"]["changed_finding_requirements"], 1)
        self.assertEqual(
            payload["changed_finding_requirements"][0]["previous"]["status"],
            "pending_approval",
        )
        self.assertEqual(
            payload["changed_finding_requirements"][0]["current"]["status"],
            "attempted_unsatisfied",
        )

    def test_investigation_memory_renders_authorization_only_finding_change(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import InvestigationMemory
        from reporter import render_investigation_memory

        requirement = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.251", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        previous = FindingRequirementState(
            requirement, "pending_approval", "explicit_approval_required", ()
        )
        current = FindingRequirementState(
            requirement, "pending_approval", "approval_deferred", ()
        )
        memory = InvestigationMemory(
            False, "stalled", "stalled", False,
            "explicit_approval_required", "explicit_approval_required",
            0, 0, (), (), (), (), ((previous, current),),
        )

        text_report = render_investigation_memory(memory)

        self.assertIn(
            "authorization: explicit_approval_required -> approval_deferred",
            text_report,
        )

    def test_investigation_memory_renders_observed_script_only_finding_change(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import InvestigationMemory
        from reporter import render_investigation_memory

        requirement = FindingDerivedRequirement(
            "smb_access_control_context", "192.0.2.252", 445, "tcp",
            "review SMB access controls", "smb.signing.review",
            "nse:smb2-security-mode",
        )
        previous = FindingRequirementState(
            requirement, "attempted_unsatisfied", "explicitly_approved", ()
        )
        current = FindingRequirementState(
            requirement, "attempted_unsatisfied", "explicitly_approved",
            ("smb-enum-shares",),
        )
        memory = InvestigationMemory(
            False, "stalled", "stalled", False,
            "finding_requirement_unsatisfied", "finding_requirement_unsatisfied",
            0, 0, (), (), (), (), ((previous, current),),
        )

        text_report = render_investigation_memory(memory)

        self.assertIn(
            "observed scripts: none -> smb-enum-shares",
            text_report,
        )

    def test_investigation_memory_reports_finding_requirement_changes(self) -> None:
        from finding_collection_planner import FindingRequirementState
        from finding_requirements import FindingDerivedRequirement
        from investigation_memory import InvestigationMemory
        from reporter import render_investigation_memory, render_investigation_memory_json

        requirement = FindingDerivedRequirement(
            "smb_access_control_context",
            "192.0.2.246",
            445,
            "tcp",
            "review SMB access controls",
            "smb.signing.review",
            "nse:smb2-security-mode",
        )
        state = FindingRequirementState(
            requirement,
            "pending_approval",
            "explicit_approval_required",
            (),
        )
        memory = InvestigationMemory(
            False,
            "stalled",
            "stalled",
            False,
            "explicit_approval_required",
            "explicit_approval_required",
            0,
            0,
            (),
            (),
            (state,),
            (),
        )

        text_report = render_investigation_memory(memory)
        payload = json.loads(render_investigation_memory_json(memory))

        self.assertIn("Added Finding Requirements: 1", text_report)
        self.assertIn("smb_access_control_context", text_report)
        self.assertEqual(payload["summary"]["added_finding_requirements"], 1)
        self.assertEqual(
            payload["added_finding_requirements"][0]["status"],
            "pending_approval",
        )

    def test_adaptive_investigation_plan_reporting_preserves_decision_and_action(self) -> None:
        action = EvidenceAction(
            "192.0.2.200", 5357, "tcp", ("http-headers",),
            ("review HTTP service identity and exposed content context",),
            ("nmap", "-p", "5357", "--script", "http-headers", "-oX", "-", "192.0.2.200"),
        )
        plan = AdaptiveInvestigationPlan(
            "alternative", "supported_alternative_actions_available", (action,)
        )

        rendered = render_adaptive_investigation_plan(plan)
        self.assertIn("Decision: alternative", rendered)
        self.assertIn("Reason: supported_alternative_actions_available", rendered)
        self.assertIn("Actions: 1", rendered)
        self.assertIn(
            "Action: nmap -p 5357 --script http-headers -oX - 192.0.2.200",
            rendered,
        )

        payload = json.loads(render_adaptive_investigation_plan_json(plan))
        self.assertEqual(payload["report_type"], "adaptive_investigation_plan")
        self.assertEqual(payload["decision"], "alternative")
        self.assertEqual(payload["reason"], "supported_alternative_actions_available")
        self.assertEqual(len(payload["actions"]), 1)
        self.assertEqual(payload["actions"][0]["script_ids"], ["http-headers"])


    def test_renders_dynamic_evidence_round_command_provenance(self) -> None:
        command = NmapCommand((
            "nmap", "-p", "445", "--script", "smb-enum-shares",
            "-oX", "-", "192.0.2.138",
        ))
        outcome = ParsedCollectionResult(
            result=CollectionResult(command, 0, "<nmaprun />", ""),
            scan=Scan(source="nmap stdout"),
        )
        result = InvestigationContinuationResult(
            outcomes=(outcome,),
            snapshot=InvestigationSnapshot(
                ready=True,
                scan=Scan(source="updated.xml"),
                gaps=(),
                actions=(),
                states=(),
                error=None,
            ),
        )

        report = render_dynamic_evidence_round(result)

        self.assertIn("Dynamic Evidence Round", report)
        self.assertIn(
            "Command: nmap -p 445 --script smb-enum-shares -oX - 192.0.2.138",
            report,
        )
        self.assertIn("Collection Status: success", report)
        self.assertIn("Return Code: 0", report)

    def test_renders_all_dynamic_evidence_rounds_in_order(self) -> None:
        first_command = NmapCommand(("nmap", "-p", "80", "--script", "http-title", "-oX", "-", "192.0.2.138"))
        second_command = NmapCommand(("nmap", "-p", "443", "--script", "ssl-cert", "-oX", "-", "192.0.2.138"))
        snapshot = InvestigationSnapshot(True, Scan(source="updated.xml"), (), (), (), None)
        first = InvestigationContinuationResult(
            outcomes=(ParsedCollectionResult(CollectionResult(first_command, 0, "<nmaprun />", ""), Scan(source="first")),),
            snapshot=snapshot,
        )
        second = InvestigationContinuationResult(
            outcomes=(ParsedCollectionResult(CollectionResult(second_command, 0, "<nmaprun />", ""), Scan(source="second")),),
            snapshot=snapshot,
        )

        report = render_dynamic_evidence_rounds((first, second))
        payload = render_dynamic_evidence_rounds_json((first, second))

        self.assertIn("Dynamic Evidence Rounds", report)
        self.assertIn("Round 1", report)
        self.assertIn("Round 2", report)
        self.assertLess(report.index("http-title"), report.index("ssl-cert"))
        self.assertEqual([item["round"] for item in payload], [1, 2])
        self.assertEqual(payload[0]["collection_outcomes"][0]["argv"], list(first_command.arguments))
        self.assertEqual(payload[1]["collection_outcomes"][0]["argv"], list(second_command.arguments))

    def test_renders_dynamic_requirement_verification(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.138",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        result = InvestigationContinuationResult(
            outcomes=(),
            snapshot=InvestigationSnapshot(
                ready=True,
                scan=Scan(source="updated.xml"),
                gaps=(),
                actions=(),
                states=(),
                error=None,
            ),
            finding_requirement_verifications=(
                FindingRequirementVerification(
                    requirement=requirement,
                    status="satisfied",
                    observed_script_ids=("smb-enum-shares",),
                ),
            ),
        )

        report = render_dynamic_evidence_round(result)

        self.assertIn(
            "Requirement: smb_access_control_context — satisfied",
            report,
        )
        self.assertIn("Observed Evidence: smb-enum-shares", report)

    def test_renders_unsatisfied_dynamic_requirement_without_retry(self) -> None:
        requirement = FindingDerivedRequirement(
            requirement_id="smb_access_control_context",
            host="192.0.2.138",
            port=445,
            protocol="tcp",
            purpose="review SMB access controls",
            finding_id="smb.signing.review",
            evidence_source="nse:smb2-security-mode",
        )
        result = InvestigationContinuationResult(
            outcomes=(),
            snapshot=InvestigationSnapshot(
                ready=True,
                scan=Scan(source="updated.xml"),
                gaps=(),
                actions=(),
                states=(),
                error=None,
            ),
            finding_requirement_verifications=(
                FindingRequirementVerification(
                    requirement=requirement,
                    status="unsatisfied",
                    observed_script_ids=(),
                ),
            ),
        )

        report = render_dynamic_evidence_round(result)

        self.assertIn(
            "Requirement: smb_access_control_context — unsatisfied",
            report,
        )
        self.assertIn("Outcome: requested evidence was not observed", report)
        self.assertIn(
            "Next Step: no automatic retry or unsupported alternative",
            report,
        )


    def test_render_investigation_explanation_text(self) -> None:
        explanation = InvestigationExplanation(
            known=("192.0.2.143:80/tcp state=open",),
            unresolved=("192.0.2.143:80/tcp http-title — identify the HTTP service",),
            blocked=("smb_access_control_context — explicit approval required",),
            next_actions=("nmap -p 80 --script http-title -oX - 192.0.2.143",),
        )

        rendered = render_investigation_explanation(explanation)

        self.assertEqual(
            rendered,
            "Investigation Explanation\n"
            "-------------------------\n"
            "Known\n"
            "- 192.0.2.143:80/tcp state=open\n"
            "Unresolved\n"
            "- 192.0.2.143:80/tcp http-title — identify the HTTP service\n"
            "Blocked\n"
            "- smb_access_control_context — explicit approval required\n"
            "Next\n"
            "- nmap -p 80 --script http-title -oX - 192.0.2.143",
        )


    def test_render_investigation_explanation_json(self) -> None:
        explanation = InvestigationExplanation(
            known=("192.0.2.143:80/tcp state=open",),
            unresolved=("192.0.2.143:80/tcp http-title — identify the HTTP service",),
            blocked=("smb_access_control_context — explicit approval required",),
            next_actions=("nmap -p 80 --script http-title -oX - 192.0.2.143",),
        )

        data = json.loads(render_investigation_explanation_json(explanation))

        self.assertEqual(data["report_type"], "investigation_explanation")
        self.assertEqual(data["known"], ["192.0.2.143:80/tcp state=open"])
        self.assertEqual(
            data["unresolved"],
            ["192.0.2.143:80/tcp http-title — identify the HTTP service"],
        )
        self.assertEqual(
            data["blocked"],
            ["smb_access_control_context — explicit approval required"],
        )
        self.assertEqual(
            data["next_actions"],
            ["nmap -p 80 --script http-title -oX - 192.0.2.143"],
        )


if __name__ == "__main__":
    unittest.main()
