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

if __name__ == "__main__":
    unittest.main()
