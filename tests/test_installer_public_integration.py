"""Public command-transaction recovery checks with inert temporary files."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import test_release_assets_safety as release_fixtures
from tests.subprocess_timeout import subprocess_timeout


ENTRY = Path(__file__).resolve().parents[1] / "scripts/autore_distribution.py"
SPEC = importlib.util.spec_from_file_location("installer_public_integration", ENTRY)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)

DOCTOR_SPEC = importlib.util.spec_from_file_location(
    "installer_public_skill_doctor",
    ENTRY.parents[1] / "skills/auto-re/scripts/skill_doctor.py",
)
assert DOCTOR_SPEC is not None and DOCTOR_SPEC.loader is not None
doctor = importlib.util.module_from_spec(DOCTOR_SPEC)
DOCTOR_SPEC.loader.exec_module(doctor)


class InstallerSkillMarkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "codex"
        self.skill = self.home / "skills/auto-re"
        self.skill.mkdir(parents=True)
        (self.skill / "SKILL.md").write_bytes(b"controlled managed skill\n")
        self.marker = {
            "schema_version": 1, "product": "AutoRE-CLI", "kind": "skill-install",
            "skill": "auto-re", "version": "0.1.7", "managed_files": ["SKILL.md"],
            "sha256": self.expected_digest(self.skill, ["SKILL.md"]),
        }
        self.write_marker()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "SKILL.md").write_bytes(b"new controlled managed skill\n")
        self.candidate = {
            **self.marker, "version": "0.1.13",
            "sha256": self.expected_digest(self.source, ["SKILL.md"]),
        }

    @staticmethod
    def expected_digest(root, files):
        entries = b"".join(
            relative.encode("utf-8") + b"\0"
            + hashlib.sha256((root / relative).read_bytes()).digest()
            for relative in sorted(files)
        )
        return hashlib.sha256(entries).hexdigest()

    def write_marker(self):
        (self.skill / installer.SKILL_MARKER).write_text(
            json.dumps(self.marker), encoding="utf-8")

    def add_extra(self, name):
        extra = self.skill / "user-data" / name
        extra.parent.mkdir()
        extra.write_bytes(b"user sentinel must survive\x00\xff\n")
        return extra

    def snapshot(self):
        return {
            path.relative_to(self.root).as_posix():
                path.read_bytes() if path.is_file() else None
            for path in self.root.rglob("*")
        }

    def uninstall(self, *options):
        return subprocess.run(
            [sys.executable, "-B", str(ENTRY), "uninstall", "--skill-only",
             "--agents", "codex", "--codex-home", str(self.home), *options],
            capture_output=True, text=True, timeout=subprocess_timeout(10),
        )

    def assert_uninstall_preserves(self, name):
        extra = self.add_extra(name)
        original = extra.read_bytes()
        relative = extra.relative_to(self.skill).as_posix()
        before = self.snapshot()
        plan = self.uninstall("--dry-run")
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertEqual(json.loads(plan.stdout)["operations"][0]["extra_files_preserved"],
                         [relative])
        self.assertEqual(self.snapshot(), before)
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["operations"][0]["extra_files_preserved"],
                         [relative])
        self.assertEqual(extra.read_bytes(), original)
        self.assertFalse((self.skill / "SKILL.md").exists())
        self.assertFalse((self.skill / installer.SKILL_MARKER).exists())
        self.assertEqual(sorted(path.name for path in self.skill.parent.iterdir()),
                         ["auto-re"])

    def test_uninstall_preserves_nested_marker_named_user_file(self):
        self.assert_uninstall_preserves(".autore-managed.json")

    def test_uninstall_preserves_nested_ordinary_user_file(self):
        self.assert_uninstall_preserves("notes.txt")

    def assert_update_refuses_extra(self, name):
        self.add_extra(name)
        before = self.snapshot()
        with self.assertRaisesRegex(installer.DistributionError,
                                    "managed skill file-set drift detected"):
            installer.preflight_skill_install(
                self.source, self.skill, self.candidate, replace_unmanaged=False)
        self.assertEqual(self.snapshot(), before)

    def test_update_refuses_nested_marker_named_user_file(self):
        self.assert_update_refuses_extra(".autore-managed.json")

    def test_update_refuses_nested_ordinary_user_file(self):
        self.assert_update_refuses_extra("notes.txt")

    def test_root_marker_remains_exempt(self):
        expected = hashlib.sha256(
            b"SKILL.md\0"
            + hashlib.sha256((self.skill / "SKILL.md").read_bytes()).digest()
        ).hexdigest()
        self.assertEqual(installer.skill_file_inventory(self.skill), ["SKILL.md"])
        self.assertEqual(installer.installed_skill_digest(self.skill), expected)
        self.assertEqual(installer.preflight_skill_install(
            self.source, self.skill, self.candidate, replace_unmanaged=False), "update")
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["operations"][0]["extra_files_preserved"],
                         [])
        self.assertFalse(self.skill.exists())

    def test_nested_marker_changes_inventory_and_digest(self):
        before = installer.installed_skill_digest(self.skill)
        self.add_extra(".autore-managed.json")
        files = ["SKILL.md", "user-data/.autore-managed.json"]
        self.assertEqual(installer.skill_file_inventory(self.skill), files)
        self.assertEqual(installer.installed_skill_digest(self.skill),
                         self.expected_digest(self.skill, files))
        self.assertNotEqual(installer.installed_skill_digest(self.skill), before)

    def test_nested_marker_symlink_fails_closed(self):
        target = self.root / "outside"
        target.write_bytes(b"outside sentinel")
        link = self.skill / "user-data/.autore-managed.json"
        link.parent.mkdir()
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        for operation in ("inventory", "update", "uninstall"):
            with self.subTest(operation=operation):
                if operation == "uninstall":
                    result = self.uninstall("--dry-run")
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn("skill contains a symlink", result.stderr)
                else:
                    with self.assertRaisesRegex(installer.DistributionError,
                                                "skill contains a symlink"):
                        if operation == "inventory":
                            installer.skill_file_inventory(self.skill)
                        else:
                            installer.preflight_skill_install(
                                self.source, self.skill, self.candidate,
                                replace_unmanaged=False)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), b"outside sentinel")
        self.assertTrue((self.skill / "SKILL.md").exists())
        self.assertTrue((self.skill / installer.SKILL_MARKER).exists())

    def test_doctor_detects_nested_marker_drift_without_mutation(self):
        (self.skill / "SKILL.md").write_bytes(
            b"---\nname: auto-re\ndescription: controlled fixture\n---\n")
        (self.skill / "VERSION").write_bytes(b"0.1.7\n")
        self.marker["managed_files"] = ["SKILL.md", "VERSION"]
        self.marker["sha256"] = self.expected_digest(
            self.skill, self.marker["managed_files"])
        self.write_marker()
        executable = self.root / "inert-cli"
        executable.write_bytes(b"inert fixture, never executed")
        with mock.patch.object(doctor, "probe_cli_version",
                               return_value=("0.1.7", "auto-re-cli 0.1.7")):
            before = self.snapshot()
            clean = doctor.diagnose(self.skill, executable=executable,
                                    candidate_roots=[self.skill])
            self.assertTrue(clean["ok"], clean)
            self.assertTrue(clean["managed_content_match"])
            self.assertEqual(clean["warnings"], [])
            self.assertEqual(self.snapshot(), before)
            self.add_extra(".autore-managed.json")
            before = self.snapshot()
            drift = doctor.diagnose(self.skill, executable=executable,
                                    candidate_roots=[self.skill])
            self.assertFalse(drift["ok"], drift)
            self.assertFalse(drift["managed_content_match"])
            self.assertIn("managed Skill file inventory or content digest has drifted",
                          drift["warnings"])
            self.assertEqual(self.snapshot(), before)

    def release_fixture(self):
        fixture = release_fixtures.ReleaseAssetsSafetyTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        return fixture

    def test_release_verifier_rejects_unlisted_nested_marker(self):
        fixture = self.release_fixture()
        self.assertTrue(installer.verify_distribution(fixture.root)["ok"])
        extra = fixture.root / "skills/auto-re/user-data/.autore-managed.json"
        extra.parent.mkdir()
        extra.write_bytes(b"unlisted nested marker")
        with self.assertRaisesRegex(installer.DistributionError,
                                    "checksum file set mismatch"):
            installer.verify_distribution(fixture.root)

    def test_release_verifier_checks_nested_marker_in_managed_inventory(self):
        fixture = self.release_fixture()
        self.assertTrue(installer.verify_distribution(fixture.root)["ok"])
        extra = fixture.root / "skills/auto-re/user-data/.autore-managed.json"
        extra.parent.mkdir()
        extra.write_bytes(b"checksummed but not managed nested marker")
        fixture.rebuild_checksums()
        with self.assertRaisesRegex(installer.DistributionError,
                                    "manifest managed skill file set does not match disk"):
            installer.verify_distribution(fixture.root)


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
