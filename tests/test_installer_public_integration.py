"""Public command-transaction recovery checks with inert temporary files."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ENTRY = Path(__file__).resolve().parents[1] / "scripts/autore_distribution.py"
SPEC = importlib.util.spec_from_file_location("installer_public_integration", ENTRY)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


class InstallerPublicIntegrationTests(unittest.TestCase):
    def test_late_capture_failure_keeps_foreign_object_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            missing = root / "missing-second"
            calls = []
            original = installer._CommandTransaction.capture

            def capture(transaction, path, prefix, *, expected_exists,
                        expected_original=None):
                original(transaction, path, prefix, expected_exists=expected_exists,
                         expected_original=expected_original)
                if path == first:
                    first.write_bytes(b"foreign sentinel")

            with mock.patch.object(installer._CommandTransaction, "capture", new=capture):
                with self.assertRaises(installer.DistributionError):
                    installer._run_install_transaction(
                        [(first, ".first.", False), (missing, ".second.", True)],
                        lambda: calls.append("mutated"),
                    )
            self.assertEqual(calls, [])
            self.assertEqual(first.read_bytes(), b"foreign sentinel")

    def test_same_version_managed_repack_remains_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_binary = root / "new-binary"
            old_binary = root / "bin/auto-re-cli"
            binary_marker = old_binary.parent / installer.BINARY_MARKER
            old_binary.parent.mkdir()
            source_binary.write_bytes(b"new")
            old_binary.write_bytes(b"old")
            existing_binary = {"schema_version": installer.SCHEMA_VERSION,
                               "product": installer.PRODUCT, "kind": "binary-install",
                               "version": "0.1.7", "sha256": installer.sha256_file(old_binary)}
            binary_marker.write_text(json.dumps(existing_binary), encoding="utf-8")
            candidate_binary = {**existing_binary, "sha256": installer.sha256_file(source_binary)}
            with self.assertRaisesRegex(installer.DistributionError,
                                        "same-version binary repack"):
                installer.preflight_binary_install(
                    source_binary, old_binary, binary_marker, candidate_binary,
                    replace_unmanaged=True,
                )

            source_skill = root / "new-skill"
            old_skill = root / "skills/auto-re"
            source_skill.mkdir(parents=True)
            old_skill.mkdir(parents=True)
            (source_skill / "SKILL.md").write_bytes(b"new")
            (old_skill / "SKILL.md").write_bytes(b"old")
            existing_skill = {"schema_version": installer.SCHEMA_VERSION,
                              "product": installer.PRODUCT, "kind": "skill-install",
                              "version": "0.1.7", "managed_files": ["SKILL.md"],
                              "sha256": installer.installed_skill_digest(old_skill)}
            (old_skill / installer.SKILL_MARKER).write_text(
                json.dumps(existing_skill), encoding="utf-8")
            candidate_skill = {**existing_skill,
                               "sha256": installer.installed_skill_digest(source_skill)}
            with self.assertRaisesRegex(installer.DistributionError,
                                        "same-version skill repack"):
                installer.preflight_skill_install(
                    source_skill, old_skill, candidate_skill, replace_unmanaged=True,
                )

    def test_uninstall_keeps_extra_hardlink_and_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin/tool"
            marker = binary.parent / installer.BINARY_MARKER
            binary.parent.mkdir()
            binary.write_bytes(b"managed binary")
            marker.write_bytes(b"managed marker")
            skill = root / "skills/auto-re"
            skill.mkdir(parents=True)
            (skill / "managed").write_bytes(b"managed")
            (skill / "extra").write_bytes(b"user extra")
            (skill / "empty").mkdir()
            external = root / "external"
            try:
                os.link(skill / "extra", external)
            except OSError as error:
                self.skipTest(f"hardlinks unavailable: {error}")
            plan = {"ok": True, "action": "uninstall", "dry_run": True,
                    "operations": [
                        {"kind": "binary", "operation": "remove", "path": str(binary)},
                        {"kind": "trae-skill", "operation": "remove-managed-files",
                         "path": str(skill), "extra_files_preserved": ["extra"]},
                    ]}
            with mock.patch.object(installer, "_command_uninstall_before_transaction",
                                   return_value=plan), \
                 mock.patch.object(installer, "selected_components",
                                   return_value=(True, True)), \
                 mock.patch.object(installer, "installed_binary_name", return_value="tool"), \
                 mock.patch.object(installer, "agent_destinations",
                                   return_value=[("trae", skill)]):
                result = installer.command_uninstall(
                    argparse.Namespace(dry_run=False, install_dir=str(binary.parent)))
            self.assertFalse(result["dry_run"])
            self.assertFalse(binary.exists())
            self.assertFalse(marker.exists())
            self.assertFalse((skill / "managed").exists())
            self.assertTrue(os.path.samefile(skill / "extra", external))
            self.assertTrue((skill / "empty").is_dir())

    def test_missing_or_replaced_backup_keeps_last_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "component"
            stage = root / "stage"
            path.write_bytes(b"old")
            stage.write_bytes(b"new")
            transaction = installer._CommandTransaction()
            transaction.capture(path, ".backup.", expected_exists=True)
            backup = transaction.snapshot_for(path).backup
            assert backup is not None
            transaction.promote(stage, path)
            backup.unlink()
            backup.write_bytes(b"foreign backup")
            with self.assertRaisesRegex(installer.DistributionError, "backup is missing or changed"):
                transaction.rollback(RuntimeError("late failure"))
            self.assertEqual(path.read_bytes(), b"new")
            self.assertEqual(backup.read_bytes(), b"foreign backup")

    def test_commit_cleanup_failure_does_not_rollback_new_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "component"
            path.write_bytes(b"old")
            original_remove = installer._remove_recorded

            def publish():
                stage = root / "stage"
                stage.write_bytes(b"new")
                assert installer._ACTIVE_TRANSACTION is not None
                installer._ACTIVE_TRANSACTION.promote(stage, path)

            def fail_backup_cleanup(candidate, recorded):
                if candidate.name.startswith(".backup."):
                    raise PermissionError("injected cleanup failure")
                return original_remove(candidate, recorded)

            with mock.patch.object(installer, "_remove_recorded",
                                   side_effect=fail_backup_cleanup):
                with self.assertRaisesRegex(installer.DistributionError, "committed"):
                    installer._run_install_transaction([(path, ".backup.", True)], publish)
            self.assertEqual(path.read_bytes(), b"new")
            backups = list(root.glob(".backup.*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), b"old")

    def test_install_dry_run_has_no_capture(self):
        expected = {"ok": True, "action": "install", "dry_run": True,
                    "operations": []}
        with mock.patch.object(installer, "_command_install_before_transaction",
                               return_value=expected), \
             mock.patch.object(installer._CommandTransaction, "capture") as capture:
            self.assertIs(installer.command_install(argparse.Namespace(dry_run=True)), expected)
        capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
