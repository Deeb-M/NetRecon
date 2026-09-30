import unittest

from investigation_orchestration import FinalInvestigationDecision
from reporter import render_investigation_summary


class InvestigationSummaryReporterTests(unittest.TestCase):
    def test_default_summary_is_concise_and_decision_oriented(self):
        decision = FinalInvestigationDecision(
            "complete",
            "all_supported_requirements_resolved",
            (),
        )

        rendered = render_investigation_summary(decision, (), ())

        self.assertIn("Investigation Summary", rendered)
        self.assertIn("Status: complete", rendered)
        self.assertIn("Reason: all_supported_requirements_resolved", rendered)
        self.assertIn("Remaining Requirements: 0", rendered)
        self.assertNotIn("Investigation Continuation", rendered)
        self.assertNotIn("Investigation Snapshot", rendered)
        self.assertNotIn("Investigation Explanation", rendered)
        self.assertNotIn("Investigation Synthesis", rendered)


if __name__ == "__main__":
    unittest.main()
