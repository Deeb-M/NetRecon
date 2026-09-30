import unittest
from analyst_attention import build_analyst_attention
from findings import Finding

class AnalystAttentionTests(unittest.TestCase):
    def test_projects_review_worthy_finding_with_evidence_provenance(self) -> None:
        finding = Finding("http.methods.review", "configuration", "192.0.2.20", 80, "tcp", "medium", "HTTP methods require review", "Nmap http-methods reported PUT.", "Confirm that the method is intentionally enabled.", "nse:http-methods")
        items = build_analyst_attention((finding,))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].finding_id, finding.finding_id)
        self.assertEqual(items[0].host, finding.host)
        self.assertEqual(items[0].port, finding.port)
        self.assertEqual(items[0].protocol, finding.protocol)
        self.assertEqual(items[0].evidence, finding.evidence)
        self.assertEqual(items[0].evidence_source, "nse:http-methods")

    def test_informational_context_does_not_become_attention(self) -> None:
        findings = (
            Finding("host.platform.context", "context", "192.0.2.21", None, None, "info", "Host platform context identified", "Windows.", "Use as context.", "service:platform"),
            Finding("ssh.algorithms.inventory", "protocol", "192.0.2.21", 22, "tcp", "info", "SSH algorithm inventory collected", "Algorithms observed.", "Use as context.", "nse:ssh2-enum-algos"),
        )
        self.assertEqual(build_analyst_attention(findings), ())

    def test_attention_preserves_finding_order_without_ranking(self) -> None:
        findings = (
            Finding("a", "visibility", "h", 1, "tcp", "info", "A", "e", "r"),
            Finding("b", "transport", "h", 2, "tcp", "medium", "B", "e", "r"),
        )
        items = build_analyst_attention(findings)
        self.assertEqual(tuple(item.finding_id for item in items), ("a", "b"))


    def test_correlates_smb_exposure_and_signing_on_same_host(self) -> None:
        from analyst_attention import AnalystAttentionItem, correlate_analyst_attention

        items = (
            AnalystAttentionItem(
                "service.smb.exposed", "exposure", "192.0.2.60", 445, "tcp",
                "SMB service exposed", "445/tcp is open.", "Review SMB exposure.",
                "service:detection",
            ),
            AnalystAttentionItem(
                "smb.signing.review", "configuration", "192.0.2.60", 445, "tcp",
                "SMB signing configuration requires review",
                "Message signing enabled but not required.", "Review signing policy.",
                "nse:smb2-security-mode",
            ),
        )

        correlations = correlate_analyst_attention(items)

        self.assertEqual(len(correlations), 1)
        self.assertEqual(
            correlations[0].correlation_id,
            "smb.exposure_and_signing_review",
        )
        self.assertEqual(
            correlations[0].finding_ids,
            ("service.smb.exposed", "smb.signing.review"),
        )
        self.assertEqual(
            correlations[0].evidence_sources,
            ("service:detection", "nse:smb2-security-mode"),
        )

    def test_does_not_correlate_smb_items_across_hosts(self) -> None:
        from analyst_attention import AnalystAttentionItem, correlate_analyst_attention

        items = (
            AnalystAttentionItem(
                "service.smb.exposed", "exposure", "192.0.2.61", 445, "tcp",
                "SMB service exposed", "445/tcp is open.", "Review SMB exposure.",
                "service:detection",
            ),
            AnalystAttentionItem(
                "smb.signing.review", "configuration", "192.0.2.62", 445, "tcp",
                "SMB signing configuration requires review",
                "Message signing enabled but not required.", "Review signing policy.",
                "nse:smb2-security-mode",
            ),
        )

        self.assertEqual(correlate_analyst_attention(items), ())


    def test_prioritizes_actionable_attention_before_visibility_without_scores(self) -> None:
        from analyst_attention import prioritize_analyst_attention

        items = build_analyst_attention((
            Finding("visibility", "visibility", "h", 111, "tcp", "info", "Visibility", "e", "r"),
            Finding("transport", "transport", "h", 21, "tcp", "medium", "Transport", "e", "r"),
            Finding("configuration", "configuration", "h", 22, "tcp", "medium", "Configuration", "e", "r"),
            Finding("exposure", "exposure", "h", 445, "tcp", "medium", "Exposure", "e", "r"),
        ))

        prioritized = prioritize_analyst_attention(items)

        self.assertEqual(
            tuple(item.category for item in prioritized),
            ("configuration", "transport", "exposure", "visibility"),
        )

    def test_correlates_multiple_ftp_service_instances_on_same_host(self) -> None:
        from analyst_attention import AnalystAttentionItem, correlate_analyst_attention

        items = (
            AnalystAttentionItem(
                "service.ftp.exposed", "transport", "192.0.2.70", 21, "tcp",
                "FTP service exposed", "21/tcp is open.", "Review FTP.", "service:detection",
            ),
            AnalystAttentionItem(
                "service.ftp.exposed", "transport", "192.0.2.70", 2121, "tcp",
                "FTP service exposed", "2121/tcp is open.", "Review FTP.", "service:detection",
            ),
        )

        correlations = correlate_analyst_attention(items)

        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0].correlation_id, "ftp.multiple_service_instances")
        self.assertEqual(correlations[0].finding_ids, ("service.ftp.exposed", "service.ftp.exposed"))

    def test_correlates_netbios_and_smb_transport_ports_on_same_host(self) -> None:
        from analyst_attention import AnalystAttentionItem, correlate_analyst_attention

        items = (
            AnalystAttentionItem(
                "service.netbios.exposed", "exposure", "192.0.2.71", 139, "tcp",
                "NetBIOS session service exposed", "139/tcp is open.", "Review NetBIOS.", "service:detection",
            ),
            AnalystAttentionItem(
                "service.smb.exposed", "exposure", "192.0.2.71", 445, "tcp",
                "SMB service exposed", "445/tcp is open and identified as netbios-ssn.", "Review SMB context.", "service:detection",
            ),
        )

        correlations = correlate_analyst_attention(items)

        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0].correlation_id, "smb.netbios_transport_context")
        self.assertEqual(correlations[0].finding_ids, ("service.netbios.exposed", "service.smb.exposed"))

if __name__ == "__main__":
    unittest.main()
