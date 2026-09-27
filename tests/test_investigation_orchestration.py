"""Contract tests for composing verified discovery into an investigation snapshot."""

import unittest
from unittest.mock import patch

from evidence_action_plan import EvidenceAction
from evidence_gaps import EvidenceGap
from scan_orchestration import (
    DiscoveryExecutionResult,
    DiscoveryResult,
    build_baseline_discovery_plan,
)

from investigation_orchestration import build_investigation_snapshot


class InvestigationOrchestrationTests(unittest.TestCase):
    @patch("investigation_orchestration.build_evidence_action_plan")
    @patch("investigation_orchestration.summarize_evidence_gaps")
    def test_verified_discovery_composes_existing_intelligence_layers(
        self, gaps_mock, actions_mock
    ) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=0,
            stdout="<nmaprun></nmaprun>",
            stderr="",
            timed_out=False,
        )
        scan = object()
        discovery = DiscoveryResult(
            execution=execution,
            success=True,
            scan=scan,
            error=None,
        )
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
            command=(
                "nmap",
                "-p",
                "445",
                "--script",
                "smb-protocols",
                "-oX",
                "-",
                "192.0.2.10",
            ),
        )
        gaps_mock.return_value = (gap,)
        actions_mock.return_value = (action,)

        snapshot = build_investigation_snapshot(discovery)

        self.assertTrue(snapshot.ready)
        self.assertIs(snapshot.scan, scan)
        self.assertEqual(snapshot.gaps, (gap,))
        self.assertEqual(snapshot.actions, (action,))
        self.assertIsNone(snapshot.error)
        gaps_mock.assert_called_once_with(scan)
        actions_mock.assert_called_once_with(scan)

    @patch("investigation_orchestration.build_evidence_action_plan")
    @patch("investigation_orchestration.summarize_evidence_gaps")
    def test_failed_discovery_stops_without_planning_evidence(
        self, gaps_mock, actions_mock
    ) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=2,
            stdout="",
            stderr="nmap failed",
            timed_out=False,
        )
        discovery = DiscoveryResult(
            execution=execution,
            success=False,
            scan=None,
            error="nmap failed",
        )

        snapshot = build_investigation_snapshot(discovery)

        self.assertFalse(snapshot.ready)
        self.assertIsNone(snapshot.scan)
        self.assertEqual(snapshot.gaps, ())
        self.assertEqual(snapshot.actions, ())
        self.assertEqual(snapshot.error, "nmap failed")
        gaps_mock.assert_not_called()
        actions_mock.assert_not_called()

    def test_inconsistent_success_without_verified_scan_fails_closed(self) -> None:
        plan = build_baseline_discovery_plan("192.0.2.10")
        execution = DiscoveryExecutionResult(
            plan=plan,
            returncode=0,
            stdout="",
            stderr="",
            timed_out=False,
        )
        discovery = DiscoveryResult(
            execution=execution,
            success=True,
            scan=None,
            error=None,
        )

        with self.assertRaisesRegex(
            ValueError,
            "Successful discovery must include a verified scan",
        ):
            build_investigation_snapshot(discovery)


if __name__ == "__main__":
    unittest.main()
