"""Tests for SMB2/SMB3 authenticated evidence collection."""

import os
import tempfile
import unittest
from unittest.mock import patch

from smb_evidence_collector import collect_authenticated_smb_shares


class AuthenticatedSmbCollectorTests(unittest.TestCase):
    def _credentials_file(self) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
        handle.write(
            "smbusername=netrecon_lab\n"
            "smbpassword=secret-value\n"
            "smbdomain=LABHOST\n"
        )
        handle.close()
        os.chmod(handle.name, 0o600)
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        return handle.name

    @patch("smb_evidence_collector.subprocess.run")
    def test_successful_collection_returns_synthetic_endpoint_evidence(self, run_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = (
            "Disk|ADMIN$|Remote Admin\n"
            "IPC|IPC$|Remote IPC\n"
            "Disk|NetReconLab|\n"
        )
        run_mock.return_value.stderr = ""

        result = collect_authenticated_smb_shares(
            "192.0.2.50", 445, self._credentials_file()
        )

        self.assertIsNotNone(result.scan)
        port = result.scan.hosts[0].ports[0]
        self.assertEqual(port.port, 445)
        self.assertEqual(port.scripts[0].script_id, "smb-enum-shares")
        self.assertIn("authenticated_smbclient", port.scripts[0].output)
        self.assertIn("NetReconLab", port.scripts[0].output)
        argv = run_mock.call_args.args[0]
        self.assertEqual(argv[0], "smbclient")
        self.assertNotIn("secret-value", argv)
        self.assertNotIn("secret-value", result.result.command.arguments)
        self.assertNotIn("netrecon_lab", result.result.command.arguments)

    @patch("smb_evidence_collector.subprocess.run")
    def test_failed_collection_does_not_create_evidence(self, run_mock) -> None:
        run_mock.return_value.returncode = 1
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = "session setup failed"

        result = collect_authenticated_smb_shares(
            "192.0.2.50", 445, self._credentials_file()
        )

        self.assertIsNone(result.scan)
        self.assertEqual(result.result.returncode, 1)

    @patch("smb_evidence_collector.subprocess.run")
    def test_runtime_auth_file_is_removed_after_collection(self, run_mock) -> None:
        observed = {}

        def fake_run(argv, **kwargs):
            auth_path = argv[argv.index("-A") + 1]
            observed["path"] = auth_path
            self.assertTrue(os.path.exists(auth_path))
            self.assertEqual(os.stat(auth_path).st_mode & 0o777, 0o600)

            class Completed:
                returncode = 0
                stdout = "Disk|NetReconLab|\n"
                stderr = ""

            return Completed()

        run_mock.side_effect = fake_run

        collect_authenticated_smb_shares(
            "192.0.2.50", 445, self._credentials_file()
        )

        self.assertFalse(os.path.exists(observed["path"]))


if __name__ == "__main__":
    unittest.main()
