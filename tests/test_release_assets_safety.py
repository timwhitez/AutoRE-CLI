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


RELEASE_CONTRACT = {
    "macos-arm64": ("aarch64-apple-darwin", "bin/macos-arm64/auto-re-cli", "adhoc"),
    "macos-x86_64": ("x86_64-apple-darwin", "bin/macos-x86_64/auto-re-cli", "adhoc"),
    "linux-arm64": ("aarch64-unknown-linux-gnu", "bin/linux-arm64/auto-re-cli", "not_applicable"),
    "linux-x86_64": ("x86_64-unknown-linux-gnu", "bin/linux-x86_64/auto-re-cli", "not_applicable"),
    "windows-x86_64": ("x86_64-pc-windows-gnullvm", "bin/windows-x86_64/auto-re-cli.exe", "not_applicable"),
}
SKILL_FILES = ("SKILL.md", "VERSION", "agents/openai.yaml", "scripts/run_next_action.py")


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
        self.manifest_path = self.root / "manifest/release.json"
        for name, value in (("ROOT", self.root), ("MANIFEST_PATH", self.manifest_path),
                            ("DEFAULT_OUTPUT", self.root / "release-assets")):
            patcher = mock.patch.object(builder, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.build_repository(sorted(RELEASE_CONTRACT))
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def build_repository(self, targets: list[str]) -> None:
        """Create a fixture repository that passes the full input gate."""
        (self.root / "LICENSE-MIT").write_text("fixture license\n", encoding="utf-8")
        switch = "[English](README.md) | [简体中文](README_zh.md)\n"
        for name in ("README.md", "README_zh.md"):
            (self.root / name).write_text(
                switch + "five platforms including windows-x86_64\n", encoding="utf-8"
            )
        for relative in SKILL_FILES:
            path = self.root / "skills/auto-re" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "VERSION":
                path.write_text("0.1.3\n", encoding="utf-8")
            elif relative == "SKILL.md":
                path.write_text(
                    "---\nname: auto-re\ndescription: fixture skill\n---\n"
                    "fixture skill payload\n",
                    encoding="utf-8",
                )
            elif relative == "agents/openai.yaml":
                path.write_text(
                    "display_name: Auto-RE\n"
                    "$auto-re static analysis\n"
                    "allow_implicit_invocation: true\n",
                    encoding="utf-8",
                )
            else:
                path.write_text("fixture skill payload\n", encoding="utf-8")
        verifier = self.root / "scripts/autore_distribution.py"
        verifier.parent.mkdir(parents=True, exist_ok=True)
        verifier.write_text(
            "import json,pathlib\n"
            "m=json.loads(pathlib.Path('manifest/release.json').read_text())\n"
            "print(json.dumps({'ok':True,'distribution_scope':m['distribution_scope'],"
            "'package_target':m['package_target'],'artifact_count':len(m['artifacts'])}))\n",
            encoding="utf-8",
        )
        artifacts = []
        for target in targets:
            rust_target, path_text, signing = RELEASE_CONTRACT[target]
            binary = self.root / path_text
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(f"inert packaging fixture {target}; do not execute".encode())
            binary.chmod(0o755)
            artifact = {
                "target": target,
                "rust_target": rust_target,
                "path": path_text,
                "signing": signing,
                "bytes": binary.stat().st_size,
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            if target.startswith("windows-"):
                artifact["pe"] = {
                    "architecture": "x86_64",
                    "subsystem": "console",
                    "imported_dlls": ["KERNEL32.dll"],
                    "llvm_mingw_runtime": "static",
                    "timestamp": 0,
                }
            artifacts.append(artifact)
        manifest = {
            "schema_version": 1,
            "kind": "autore_cli_binary_distribution",
            "product": "AutoRE-CLI",
            "publisher": "timwhitez",
            "repository": "AutoRE-CLI",
            "repository_url": "https://github.com/timwhitez/AutoRE-CLI",
            "distribution_scope": "repository",
            "version": "0.1.3",
            "source_revision": "a" * 40,
            "safety": {
                "target_execution": False,
                "shellcode_execution": False,
                "generated_artifact_execution": False,
                "dynamic_analysis": False,
                "dynamic_evidence": False,
            },
            "artifacts": artifacts,
            "skill": {
                "name": "auto-re",
                "path": "skills/auto-re",
                "version": "0.1.3",
                "managed_files": sorted(
                    f"skills/auto-re/{relative}" for relative in SKILL_FILES
                ),
            },
        }
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        self.rebuild_checksums()

    def rebuild_checksums(self) -> None:
        rows = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.name == "SHA256SUMS":
                continue
            rows.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.root).as_posix()}\n"
            )
        (self.root / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")

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
        self.assertEqual(len(first["assets"]), 6)
        self.assertEqual([a["sha256"] for a in first["assets"]], [a["sha256"] for a in second["assets"]])
        for line in (self.output / "SHA256SUMS.release").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)
        archive = next(self.output.glob("*linux-x86_64.tar.gz"))
        with tarfile.open(archive) as handle:
            members = {m.name: handle.extractfile(m).read() for m in handle.getmembers() if m.isfile()}
        prefix = "AutoRE-CLI-0.1.3-linux-x86_64/"
        for line in members[prefix + "SHA256SUMS"].decode().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256(members[prefix + name]).hexdigest(), digest)
        self.assertFalse(any("windows-x86_64" in name for name in members))
        with zipfile.ZipFile(self.output / "AutoRE-CLI-0.1.3-auto-re-skill.zip") as handle:
            self.assertIn("SKILL.md", handle.namelist())

    def test_incomplete_platform_matrix_is_rejected(self) -> None:
        # A four-target manifest that is internally self-consistent (checksums
        # regenerated) must still be rejected: standard releases are complete.
        # The full input gate fires before the builder's own preflight.
        targets = [t for t in sorted(RELEASE_CONTRACT) if t != "linux-arm64"]
        self.build_repository(targets)
        with self.assertRaisesRegex(
            builder.ReleaseAssetError, "release artifact target set mismatch"
        ):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_manifest_preflight_alone_requires_every_platform(self) -> None:
        targets = [t for t in sorted(RELEASE_CONTRACT) if t != "macos-arm64"]
        self.build_repository(targets)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(
            builder.ReleaseAssetError, "missing targets: \\['macos-arm64'\\]"
        ):
            builder.validate_asset_manifest(manifest)

    def test_missing_platform_in_stale_checksum_state_is_rejected(self) -> None:
        # Even without regenerating checksums, removing a platform from the
        # manifest must never produce a publishable release.
        self.manifest["artifacts"] = [
            artifact
            for artifact in self.manifest["artifacts"]
            if artifact["target"] != "macos-x86_64"
        ]
        self.save_manifest()
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_unregistered_local_file_is_rejected_before_packaging(self) -> None:
        sentinel = self.root / ".env"
        sentinel.write_text("SECRET=fixture\n", encoding="utf-8")
        with self.assertRaisesRegex(
            builder.ReleaseAssetError, "failed verification before packaging"
        ):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())
        self.assertTrue(sentinel.exists(), "builder must not delete working-tree files")

    def test_unregistered_plain_file_is_rejected(self) -> None:
        (self.root / "local-notes.txt").write_text("scratch\n", encoding="utf-8")
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_pycache_residue_is_rejected_rather_than_packaged(self) -> None:
        cache = self.root / "tests/__pycache__"
        cache.mkdir(parents=True)
        (cache / "test.cpython-312.pyc").write_bytes(b"\x00pyc")
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_modified_registered_file_is_rejected(self) -> None:
        skill = self.root / "skills/auto-re/SKILL.md"
        skill.write_text("tampered after checksums\n", encoding="utf-8")
        with self.assertRaisesRegex(
            builder.ReleaseAssetError, "failed verification before packaging"
        ):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_skill_zip_members_match_platform_packages_exactly(self) -> None:
        result = builder.build_assets(self.output)
        skill_zip = self.output / "AutoRE-CLI-0.1.3-auto-re-skill.zip"
        with zipfile.ZipFile(skill_zip) as handle:
            names = sorted(handle.namelist())
            digests = {
                name: hashlib.sha256(handle.read(name)).hexdigest() for name in names
            }
        expected = sorted(SKILL_FILES)
        self.assertEqual(names, expected)
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))
        # Cross-channel: every member is byte-identical inside a platform
        # package archive.
        archive = next(self.output.glob("*linux-x86_64.tar.gz"))
        with tarfile.open(archive) as handle:
            members = {
                m.name.removeprefix("AutoRE-CLI-0.1.3-linux-x86_64/"): handle.extractfile(m).read()
                for m in handle.getmembers()
                if m.isfile()
            }
        for name in names:
            packaged = f"skills/auto-re/{name}"
            self.assertEqual(
                hashlib.sha256(members[packaged]).hexdigest(), digests[name], name
            )
        # The success result lists every archive with its digest.
        self.assertEqual(len(result["assets"]), 6)
        listed = {Path(a["path"]).name: a["sha256"] for a in result["assets"]}
        self.assertEqual(listed[skill_zip.name], hashlib.sha256(skill_zip.read_bytes()).hexdigest())

    def test_default_output_does_not_package_its_staging_tree(self) -> None:
        output = self.root / "release-assets"
        builder.build_assets(output)
        with tarfile.open(next(output.glob("*.tar.gz"))) as handle:
            names = handle.getnames()
        self.assertFalse(any(".autore-release-" in n or "release-assets/" in n for n in names))
        self.assertFalse(list(self.root.glob(".autore-release-*")))


if __name__ == "__main__":
    unittest.main()
