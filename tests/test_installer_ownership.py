"""Installer ownership regressions using only temporary, inert files."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ENTRY = Path(__file__).resolve().parents[1] / "scripts/autore_distribution.py"
SPEC = importlib.util.spec_from_file_location("installer_ownership_public", ENTRY)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


class InstallerOwnershipTests(unittest.TestCase):
    def test_standalone_binary_keeps_replacement_after_first_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "bin/auto-re-cli"
            marker = destination.parent / installer.BINARY_MARKER
            destination.parent.mkdir()
            source.write_bytes(b"new")
            destination.write_bytes(b"old")
            real = installer._run_install_transaction

            def swap(paths, mutate, verify=None, **kwargs):
                destination.unlink()
                destination.write_bytes(b"foreign sentinel")
                return real(paths, mutate, verify, **kwargs)

            with mock.patch.object(installer, "_run_install_transaction", side_effect=swap):
                with self.assertRaisesRegex(installer.DistributionError,
                                            "changed after preflight"):
                    installer.replace_binary(source, destination, marker,
                                             {"generation": "new"})
            self.assertEqual(destination.read_bytes(), b"foreign sentinel")
            self.assertFalse(marker.exists())

    def test_cleanup_preserves_child_replaced_before_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "owned"
            path.mkdir()
            (path / "child").write_bytes(b"owned")
            recorded = installer._record_object(path)
            real = installer._rename_no_replace
            swapped = False

            def replace_child(source, destination):
                nonlocal swapped
                if source.name == "child" and not swapped:
                    swapped = True
                    source.unlink()
                    source.write_bytes(b"foreign sentinel")
                return real(source, destination)

            with mock.patch.object(installer, "_rename_no_replace", side_effect=replace_child):
                with self.assertRaisesRegex(installer.DistributionError, "cleanup was incomplete"):
                    installer._remove_recorded(path, recorded)
            self.assertTrue(swapped)
            self.assertEqual((path / "child").read_bytes(), b"foreign sentinel")

    def test_absent_capture_keeps_foreign_file_directory_and_link(self):
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "first"
                target = root / "target"
                target.write_bytes(b"outside")
                transaction = installer._CommandTransaction()
                transaction.capture(path, ".backup.", expected_exists=False)
                if kind == "file":
                    path.write_bytes(b"foreign")
                elif kind == "directory":
                    path.mkdir()
                    (path / "foreign").write_bytes(b"foreign")
                else:
                    try:
                        path.symlink_to(target)
                    except (OSError, NotImplementedError) as error:
                        self.skipTest(f"symlink unavailable: {error}")
                with self.assertRaises(installer.DistributionError):
                    transaction.capture(root / "missing", ".backup.", expected_exists=True)
                with self.assertRaisesRegex(installer.DistributionError, "rollback was incomplete"):
                    transaction.rollback(RuntimeError("later capture failed"))
                self.assertTrue(path.exists() or path.is_symlink())
                if kind == "directory":
                    self.assertEqual((path / "foreign").read_bytes(), b"foreign")
                elif kind == "file":
                    self.assertEqual(path.read_bytes(), b"foreign")
                else:
                    self.assertTrue(path.is_symlink())
                    self.assertEqual(target.read_bytes(), b"outside")

    def test_backup_and_promotion_are_registered_before_rename_returns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "component"
            stage = root / "stage"
            path.write_bytes(b"old")
            stage.write_bytes(b"new")
            transaction = installer._CommandTransaction()
            transaction.capture(path, ".backup.", expected_exists=True)
            real = installer._rename_no_replace

            def moved_then_failed(source, destination):
                real(source, destination)
                if source == stage:
                    raise PermissionError("after publication syscall")

            with mock.patch.object(installer, "_rename_no_replace", side_effect=moved_then_failed):
                with self.assertRaises(PermissionError):
                    transaction.promote(stage, path)
            transaction.rollback(RuntimeError("later failure"))
            self.assertEqual(path.read_bytes(), b"old")
            self.assertFalse(stage.exists())

    def test_unknown_directory_member_keeps_promoted_tree_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "skill"
            stage = root / "stage"
            path.mkdir()
            (path / "old").write_bytes(b"old")
            stage.mkdir()
            (stage / "managed").write_bytes(b"new")
            transaction = installer._CommandTransaction()
            transaction.capture(path, ".backup.", expected_exists=True)
            backup = transaction.snapshot_for(path).backup
            assert backup is not None
            transaction.promote(stage, path)
            root_id = path.lstat()
            (path / "foreign").write_bytes(b"foreign")
            self.assertTrue(os.path.samestat(root_id, path.lstat()))
            with self.assertRaisesRegex(installer.DistributionError, "unknown members"):
                transaction.rollback(RuntimeError("verify failed"))
            self.assertEqual((path / "foreign").read_bytes(), b"foreign")
            self.assertEqual((backup / "old").read_bytes(), b"old")

    def test_standalone_skill_keeps_destination_created_during_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "SKILL.md").write_bytes(b"controlled")
            destination = root / "skill"
            real = installer._stage_skill

            def create_foreign(*args):
                result = real(*args)
                destination.write_bytes(b"foreign")
                return result

            with mock.patch.object(installer, "_stage_skill", side_effect=create_foreign):
                with self.assertRaisesRegex(installer.DistributionError, "rollback was incomplete"):
                    installer.replace_skill(source, destination, {"generation": "new"})
            self.assertEqual(destination.read_bytes(), b"foreign")


if __name__ == "__main__":
    unittest.main()
