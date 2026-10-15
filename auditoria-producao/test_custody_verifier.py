"""Synthetic encrypted-backup tests. No real keys or RPC."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_custody_local as V
C = V.C

class BackupVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.first = Path(self.temp.name) / "synthetic-primary.json"
        self.backup = Path(self.temp.name) / "synthetic-backup.json"
        self.password = "synthetic-test-password"
        self.wallets = [{"addr": C.priv_to_address(1), "priv": "0x1"}]
        self.write(self.first, self.wallets); self.write(self.backup, self.wallets)
    def write(self, path, wallets):
        path.write_text(json.dumps(C.encrypt_keystore(json.dumps(wallets).encode(), self.password)))
        path.chmod(0o600)
    def test_recovery_and_addresses_verified_readonly(self):
        before = (self.first.read_bytes(), self.backup.read_bytes())
        result = V.verify_backup(self.first, self.backup, self.password)
        self.assertTrue(result["verified"]); self.assertEqual(result["wallet_count"], 1)
        self.assertEqual(before, (self.first.read_bytes(), self.backup.read_bytes()))
    def test_wrong_password_rejected(self):
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, "wrong-synthetic")
    def test_different_backup_rejected(self):
        self.write(self.backup, [{"addr": C.priv_to_address(2), "priv": "0x2"}])
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, self.password)
    def test_same_inode_rejected(self):
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.first, self.password)
    def test_hardlinked_backup_rejected(self):
        self.backup.unlink(); os.link(self.first, self.backup)
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, self.password)
    def test_symlink_rejected(self):
        self.backup.unlink(); self.backup.symlink_to(self.first)
        with self.assertRaises(OSError): V.verify_backup(self.first, self.backup, self.password)
    def test_world_readable_rejected(self):
        self.backup.chmod(0o644)
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, self.password)
    def test_plaintext_rejected(self):
        self.first.write_text(json.dumps(self.wallets))
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, self.password)
    def test_mismatched_public_address_rejected(self):
        wallet = [{"addr": C.priv_to_address(2), "priv": "0x1"}]
        self.write(self.first, wallet); self.write(self.backup, wallet)
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, self.password)
    def test_duplicate_addresses_rejected(self):
        self.write(self.first, self.wallets * 2); self.write(self.backup, self.wallets * 2)
        with self.assertRaises(ValueError): V.verify_backup(self.first, self.backup, self.password)
    def test_cli_never_prints_recovered_data(self):
        stdout = io.StringIO(); stderr = io.StringIO()
        with patch.object(sys, "argv", ["verify", "--primary", str(self.first), "--backup", str(self.backup)]), \
             patch.object(V.getpass, "getpass", return_value=self.password), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(V.main(), 0)
        self.assertTrue(json.loads(stdout.getvalue())["verified"])
        for value in (self.password, self.wallets[0]["addr"], '"priv"'):
            self.assertNotIn(value, stdout.getvalue() + stderr.getvalue())
    def test_cli_failure_output_is_sanitized(self):
        stdout = io.StringIO(); stderr = io.StringIO()
        with patch.object(sys, "argv", ["verify", "--primary", str(self.first), "--backup", str(self.backup)]), \
             patch.object(V.getpass, "getpass", return_value="wrong-synthetic"), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(V.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn('"priv"', stderr.getvalue())

if __name__ == "__main__": unittest.main(verbosity=2)
