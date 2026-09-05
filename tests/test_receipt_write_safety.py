"""Offline regressions for exclusive receipt/log ownership; never run target samples."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "public-template"
MODULE = (TEMPLATE if TEMPLATE.is_dir() else ROOT) / "skills/auto-re/scripts/run_next_action.py"
SPEC = importlib.util.spec_from_file_location("receipt_write_safety_runner", MODULE)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ReceiptWriteSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "receipt.json"

    def write(self) -> None:
        runner._write_private_bytes(self.path, b"new receipt", "test receipt")

    def test_existing_file_is_preserved(self) -> None:
        self.path.write_bytes(b"existing evidence")
        before = self.path.stat()
        with self.assertRaises(runner.ActionError):
            self.write()
        self.assertTrue(self.path.exists(), "exclusive-create failure deleted prior evidence")
        self.assertEqual(self.path.read_bytes(), b"existing evidence")
        self.assertTrue(os.path.samestat(before, self.path.stat()))

    def test_existing_symlink_is_preserved(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"target evidence")
        try:
            self.path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises(runner.ActionError):
            self.write()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_bytes(), b"target evidence")

    def test_dangling_symlink_is_preserved(self) -> None:
        try:
            self.path.symlink_to(self.root / "missing")
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises(runner.ActionError):
            self.write()
        self.assertTrue(self.path.is_symlink())

    def test_existing_directory_reports_action_error(self) -> None:
        self.path.mkdir()
        sentinel = self.path / "keep"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(runner.ActionError):
            self.write()
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_successful_write_and_readonly_mode(self) -> None:
        self.write()
        self.assertEqual(self.path.read_bytes(), b"new receipt")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o400)

    def test_second_write_preserves_successful_receipt(self) -> None:
        self.write()
        with self.assertRaises(runner.ActionError):
            self.write()
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.read_bytes(), b"new receipt")

    def test_preflight_does_not_authorize_deletion_of_later_file(self) -> None:
        receipt, _ = runner.prepare_receipt_paths(self.path)
        receipt.write_bytes(b"written after preflight")
        with self.assertRaises(runner.ActionError):
            runner._write_receipt(receipt, {"ok": True})
        self.assertTrue(receipt.exists())
        self.assertEqual(receipt.read_bytes(), b"written after preflight")

    def test_fsync_failure_cleans_owned_partial(self) -> None:
        with mock.patch.object(runner.os, "fsync", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(runner.ActionError, "disk failure"):
                self.write()
        self.assertFalse(self.path.exists())

    def test_cleanup_failure_preserves_primary_diagnostic(self) -> None:
        with mock.patch.object(runner.os, "fsync", side_effect=OSError("primary failure")):
            with mock.patch.object(Path, "unlink", side_effect=PermissionError("cleanup failure")):
                with self.assertRaisesRegex(runner.ActionError, "primary failure"):
                    self.write()
        self.assertTrue(self.path.exists())

    @unittest.skipIf(os.name == "nt", "open-file replacement requires POSIX semantics")
    def test_replacement_object_is_not_deleted(self) -> None:
        def replace_then_fail(_fd: int) -> None:
            self.path.rename(self.root / "owned-object")
            self.path.write_bytes(b"replacement evidence")
            raise OSError("injected failure after replacement")

        with mock.patch.object(runner.os, "fsync", side_effect=replace_then_fail):
            with self.assertRaises(runner.ActionError):
                self.write()
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.read_bytes(), b"replacement evidence")

    @unittest.skipIf(os.name == "nt", "POSIX permission assertion")
    def test_file_is_private_during_write_even_with_permissive_umask(self) -> None:
        observed = []
        def inspect(fd: int) -> None:
            observed.append(stat.S_IMODE(os.fstat(fd).st_mode))
        previous = os.umask(0)
        try:
            with mock.patch.object(runner.os, "fsync", side_effect=inspect):
                self.write()
        finally:
            os.umask(previous)
        self.assertEqual(observed, [0o600])

    def test_permission_failure_cleans_owned_partial(self) -> None:
        target = runner.os if hasattr(runner.os, "fchmod") else Path
        method = "fchmod" if hasattr(runner.os, "fchmod") else "chmod"
        with mock.patch.object(target, method, side_effect=OSError("mode failure")):
            with self.assertRaisesRegex(runner.ActionError, "mode failure"):
                self.write()
        self.assertFalse(self.path.exists())

    def test_open_failure_does_not_attempt_unlink(self) -> None:
        with mock.patch.object(runner.os, "open", side_effect=PermissionError("denied")):
            with mock.patch.object(Path, "unlink") as unlink:
                with self.assertRaisesRegex(runner.ActionError, "denied"):
                    self.write()
        unlink.assert_not_called()

    def test_empty_payload_is_supported(self) -> None:
        runner._write_private_bytes(self.path, b"", "empty log")
        self.assertEqual(self.path.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
