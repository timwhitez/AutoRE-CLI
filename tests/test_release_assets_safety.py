"""Offline release-builder regressions using inert fixture files, never real binaries."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

MODULE = Path(__file__).resolve().parents[1] / "scripts/build_release_assets.py"
SPEC = importlib.util.spec_from_file_location("release_assets_safety", MODULE)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class ReleaseAssetsSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        self.root = self.work / "repository"
        self.root.mkdir()
        self.output = self.work / "output"
        self.home = self.work / "home"
        self.home.mkdir()
        self.manifest = {"distribution_scope": "repository", "version": "0.1.3", "artifacts": [
            {"target": "linux-x86_64", "path": "bin/linux-x86_64/auto-re-cli"},
            {"target": "windows-x86_64", "path": "bin/windows-x86_64/auto-re-cli.exe"},
        ]}
        for artifact in self.manifest["artifacts"]:
            path = self.root / artifact["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"inert packaging fixture; do not execute")
        skill = self.root / "skills/auto-re/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("fixture skill\n", encoding="utf-8")
        self.manifest_path = self.root / "manifest/release.json"
        self.manifest_path.parent.mkdir()
        self.save_manifest()
        verifier = self.root / "scripts/autore_distribution.py"
        verifier.parent.mkdir()
        verifier.write_text(
            "import json,pathlib\n"
            "m=json.loads(pathlib.Path('manifest/release.json').read_text())\n"
            "print(json.dumps({'ok':True,'distribution_scope':m['distribution_scope'],"
            "'package_target':m['package_target'],'artifact_count':len(m['artifacts'])}))\n",
            encoding="utf-8",
        )
        for name, value in (("ROOT", self.root), ("MANIFEST_PATH", self.manifest_path),
                            ("DEFAULT_OUTPUT", self.root / "release-assets")):
            patcher = mock.patch.object(builder, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def save_manifest(self) -> None:
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_nonempty_output_is_rejected_without_deletion(self) -> None:
        self.output.mkdir()
        keep = self.output / "previous-release.zip"
        keep.write_bytes(b"previous release")
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertEqual(keep.read_bytes(), b"previous release")

    def test_repository_root_is_never_cleared(self) -> None:
        sentinel = self.root / "keep-source"
        sentinel.write_bytes(b"source")
        try:
            builder.build_assets(self.root)
        except (builder.ReleaseAssetError, OSError):
            pass
        self.assertTrue(sentinel.exists(), "repository root was cleared")

    def test_repository_ancestor_is_never_cleared(self) -> None:
        sentinel = self.work / "keep"
        sentinel.write_bytes(b"ancestor")
        try:
            builder.build_assets(self.work)
        except (builder.ReleaseAssetError, OSError):
            pass
        self.assertTrue(sentinel.exists(), "repository ancestor was cleared")

    def test_home_directory_is_preserved(self) -> None:
        sentinel = self.home / "keep"
        sentinel.write_bytes(b"home")
        try:
            builder.build_assets(self.home)
        except (builder.ReleaseAssetError, OSError):
            pass
        self.assertTrue(sentinel.exists(), "home directory was cleared")

    def test_output_symlink_is_rejected(self) -> None:
        target = self.work / "target"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_bytes(b"keep")
        try:
            self.output.symlink_to(target, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertEqual(sentinel.read_bytes(), b"keep")
        self.assertTrue(self.output.is_symlink())

    def test_symlinked_parent_is_rejected(self) -> None:
        alias = self.work / "alias"
        try:
            alias.symlink_to(self.home, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(alias / "new-output")
        self.assertFalse((self.home / "new-output").exists())

    def test_verification_failure_does_not_publish_partial_release(self) -> None:
        with mock.patch.object(builder, "verify_package", side_effect=builder.ReleaseAssetError("verify failed")):
            with self.assertRaisesRegex(builder.ReleaseAssetError, "verify failed"):
                builder.build_assets(self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.work.glob(".autore-release-*")))

    def test_checksum_failure_does_not_publish(self) -> None:
        with mock.patch.object(builder, "write_release_checksums", side_effect=OSError("checksum failure")):
            with self.assertRaisesRegex(OSError, "checksum failure"):
                builder.build_assets(self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.work.glob(".autore-release-*")))

    def test_invalid_version_is_rejected_before_mutation(self) -> None:
        for version in ("../escape", "1.0.0/../../escape", "", "a" * 100):
            with self.subTest(version=version):
                self.manifest["version"] = version
                self.save_manifest()
                with self.assertRaises(builder.ReleaseAssetError):
                    builder.build_assets(self.output)
                self.assertFalse(self.output.exists())

    def test_invalid_target_is_rejected_before_mutation(self) -> None:
        for target in ("../escape", "", [], "linux-unknown"):
            with self.subTest(target=target):
                self.manifest["artifacts"][0]["target"] = target
                self.save_manifest()
                with self.assertRaises(builder.ReleaseAssetError):
                    builder.build_assets(self.output)
                self.assertFalse(self.output.exists())

    def test_artifact_path_traversal_is_rejected(self) -> None:
        self.manifest["artifacts"][0]["path"] = "../outside"
        self.save_manifest()
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_duplicate_targets_are_rejected(self) -> None:
        self.manifest["artifacts"].append(dict(self.manifest["artifacts"][0]))
        self.save_manifest()
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_empty_artifact_list_is_rejected(self) -> None:
        self.manifest["artifacts"] = []
        self.save_manifest()
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_nonobject_verifier_reply_is_diagnostic(self) -> None:
        completed = mock.Mock(returncode=0, stdout="[]", stderr="")
        with mock.patch.object(builder.subprocess, "run", return_value=completed):
            with self.assertRaises(builder.ReleaseAssetError):
                builder.verify_package(self.root, "linux-x86_64")

    def test_malformed_verifier_reply_is_diagnostic(self) -> None:
        completed = mock.Mock(returncode=0, stdout="not JSON", stderr="")
        with mock.patch.object(builder.subprocess, "run", return_value=completed):
            with self.assertRaises(builder.ReleaseAssetError):
                builder.verify_package(self.root, "linux-x86_64")

    def test_success_builds_verifiable_deterministic_archives(self) -> None:
        first = builder.build_assets(self.output)
        second = builder.build_assets(self.work / "second-output")
        self.assertTrue(first["ok"])
        self.assertEqual(len(first["assets"]), 3)
        self.assertEqual([a["sha256"] for a in first["assets"]], [a["sha256"] for a in second["assets"]])
        for line in (self.output / "SHA256SUMS.release").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)
        archive = next(self.output.glob("*.tar.gz"))
        with tarfile.open(archive) as handle:
            members = {m.name: handle.extractfile(m).read() for m in handle.getmembers() if m.isfile()}
        prefix = "AutoRE-CLI-0.1.3-linux-x86_64/"
        for line in members[prefix + "SHA256SUMS"].decode().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256(members[prefix + name]).hexdigest(), digest)
        self.assertFalse(any("windows-x86_64" in name for name in members))
        with zipfile.ZipFile(self.output / "AutoRE-CLI-0.1.3-auto-re-skill.zip") as handle:
            self.assertIn("SKILL.md", handle.namelist())

    def test_default_output_does_not_package_its_staging_tree(self) -> None:
        output = self.root / "release-assets"
        builder.build_assets(output)
        with tarfile.open(next(output.glob("*.tar.gz"))) as handle:
            names = handle.getnames()
        self.assertFalse(any(".autore-release-" in n or "release-assets/" in n for n in names))
        self.assertFalse(list(self.root.glob(".autore-release-*")))


if __name__ == "__main__":
    unittest.main()
