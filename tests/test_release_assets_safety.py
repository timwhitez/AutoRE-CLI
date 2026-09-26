"""Offline release-builder regressions using inert fixture files, never real binaries."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
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
        for name, value in (("ROOT", self.root),
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
        installer_stub = self.root / "scripts/autore_distribution.py"
        installer_stub.parent.mkdir(parents=True, exist_ok=True)
        installer_stub.write_text("# inert fixture helper; never executed\n", encoding="utf-8")
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

    def assert_archived_readmes(self, expected: bytes) -> None:
        archives = list(self.output.glob("AutoRE-CLI-0.1.3-*.tar.gz"))
        archives.extend(path for path in self.output.glob("AutoRE-CLI-0.1.3-*.zip")
                        if "auto-re-skill" not in path.name)
        self.assertEqual(len(archives), 5)
        for archive in archives:
            root_name = archive.name.removesuffix(".tar.gz").removesuffix(".zip")
            member = f"{root_name}/README.md"
            if archive.suffix == ".zip":
                with zipfile.ZipFile(archive) as handle:
                    actual = handle.read(member)
            else:
                with tarfile.open(archive) as handle:
                    file = handle.extractfile(member)
                    assert file is not None
                    actual = file.read()
            self.assertEqual(actual, expected, archive.name)

    def test_source_edit_before_first_package_cannot_be_rehashed_into_release(self):
        readme = self.root / "README.md"
        admitted = readme.read_bytes()
        original = builder.prepare_package
        changed = False

        def edit_then_prepare(*args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                readme.write_bytes(admitted + b"changed after admission\n")
                self.rebuild_checksums()
            return original(*args, **kwargs)

        with mock.patch.object(builder, "prepare_package", side_effect=edit_then_prepare):
            try:
                builder.build_assets(self.output)
            except builder.ReleaseAssetError:
                self.assertFalse(self.output.exists())
            else:
                self.assert_archived_readmes(admitted)
        self.assertTrue(changed)

    def test_source_edit_between_platforms_cannot_diverge_common_files(self):
        readme = self.root / "README.md"
        admitted = readme.read_bytes()
        original = builder.prepare_package
        calls = 0

        def prepare_then_edit(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 1:
                readme.write_bytes(admitted + b"changed between platforms\n")
                self.rebuild_checksums()
            return result

        with mock.patch.object(builder, "prepare_package", side_effect=prepare_then_edit):
            try:
                builder.build_assets(self.output)
            except builder.ReleaseAssetError:
                self.assertFalse(self.output.exists())
            else:
                self.assert_archived_readmes(admitted)
        self.assertGreaterEqual(calls, 1)

    def test_snapshot_is_independent_and_manifest_replacement_is_not_admitted(self):
        admitted_revision = self.manifest["source_revision"]
        original = builder.verify_input_distribution

        def replace_original_after_snapshot(snapshot):
            result = original(snapshot)
            self.assertFalse(os.path.samefile(self.root / "README.md", snapshot / "README.md"))
            self.manifest["source_revision"] = "b" * 40
            self.save_manifest()
            self.rebuild_checksums()
            return result

        with mock.patch.object(builder, "verify_input_distribution",
                               side_effect=replace_original_after_snapshot):
            try:
                builder.build_assets(self.output)
            except builder.ReleaseAssetError:
                self.assertFalse(self.output.exists())
            else:
                archive = next(self.output.glob("*linux-x86_64.tar.gz"))
                with tarfile.open(archive) as handle:
                    path = "AutoRE-CLI-0.1.3-linux-x86_64/manifest/release.json"
                    member = handle.extractfile(path)
                    assert member is not None
                    self.assertEqual(json.load(member)["source_revision"], admitted_revision)

    def test_verified_snapshot_stops_original_member_opens(self):
        original_verify = builder.verify_input_distribution
        original_open = Path.open
        frozen = False

        def mark_frozen(snapshot):
            nonlocal frozen
            result = original_verify(snapshot)
            frozen = True
            return result

        def reject_original(path, *args, **kwargs):
            if frozen and path.absolute().is_relative_to(self.root):
                raise AssertionError(f"original member reopened after snapshot: {path}")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(builder, "verify_input_distribution", side_effect=mark_frozen), \
             mock.patch.object(Path, "open", new=reject_original):
            builder.build_assets(self.output)
        self.assertTrue(frozen)
        self.assert_archived_readmes((self.root / "README.md").read_bytes())

    def test_same_size_source_mutation_during_snapshot_is_not_accepted(self):
        source = self.root / "README.md"
        original_bytes = source.read_bytes()
        original_copy = builder.copy_file
        mutated = False

        def mutate_at_copy(path, destination, **kwargs):
            nonlocal mutated
            if path == source and not mutated:
                mutated = True
                source.write_bytes(original_bytes.replace(b"five", b"nine"))
            return original_copy(path, destination, **kwargs)

        with mock.patch.object(builder, "copy_file", side_effect=mutate_at_copy):
            with self.assertRaises(builder.ReleaseAssetError):
                builder.build_assets(self.output)
        self.assertTrue(mutated)
        self.assertFalse(self.output.exists())

    def test_streaming_copy_detects_truncation_and_growth(self):
        source = self.work / "large-controlled.bin"
        original_bytes = b"A" * (2 * 1024 * 1024)
        digest = hashlib.sha256(original_bytes).hexdigest()
        real_fdopen = builder.os.fdopen

        for change in ("truncate", "grow"):
            with self.subTest(change=change):
                source.write_bytes(original_bytes)
                destination = self.work / f"copied-{change}.bin"

                class MutatingReader:
                    def __init__(self, handle):
                        self.handle = handle
                        self.changed = False

                    def __enter__(self):
                        self.handle.__enter__()
                        return self

                    def __exit__(self, *args):
                        return self.handle.__exit__(*args)

                    def fileno(self):
                        return self.handle.fileno()

                    def read(self, size):
                        block = self.handle.read(size)
                        if not self.changed:
                            self.changed = True
                            if change == "truncate":
                                with source.open("r+b") as output:
                                    output.truncate(512 * 1024)
                            else:
                                with source.open("ab") as output:
                                    output.write(b"B" * (512 * 1024))
                        return block

                with mock.patch.object(builder.os, "fdopen",
                                       side_effect=lambda fd, mode: MutatingReader(real_fdopen(fd, mode))):
                    with self.assertRaises(builder.ReleaseAssetError):
                        builder.copy_file(source, destination, expected_sha256=digest)

    def test_late_symlink_source_does_not_enter_fixed_snapshot(self):
        readme = self.root / "README.md"
        admitted = readme.read_bytes()
        external = self.work / "foreign-readme"
        external.write_bytes(b"foreign content")
        original = builder.prepare_package
        changed = False

        def replace_source(*args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                readme.unlink()
                try:
                    readme.symlink_to(external)
                except (OSError, NotImplementedError) as error:
                    self.skipTest(f"symlinks unavailable: {error}")
            return original(*args, **kwargs)

        with mock.patch.object(builder, "prepare_package", side_effect=replace_source):
            builder.build_assets(self.output)
        self.assertTrue(changed)
        self.assert_archived_readmes(admitted)
        self.assertEqual(external.read_bytes(), b"foreign content")

    def test_initial_symlink_source_is_rejected_before_output(self):
        readme = self.root / "README.md"
        external = self.work / "foreign-readme"
        external.write_bytes(b"foreign content")
        readme.unlink()
        try:
            readme.symlink_to(external)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaises(builder.ReleaseAssetError):
            builder.build_assets(self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(external.read_bytes(), b"foreign content")

    def test_stage_drift_after_static_verification_fails_before_publication(self):
        for target in ("linux-x86_64", "windows-x86_64"):
            with self.subTest(target=target):
                original = builder.verify_package

                def change_verified_stage(package_root, actual_target):
                    original(package_root, actual_target)
                    if actual_target == target:
                        (package_root / "README.md").write_bytes(b"foreign staged bytes")

                with mock.patch.object(builder, "verify_package",
                                       side_effect=change_verified_stage):
                    with self.assertRaises(builder.ReleaseAssetError):
                        builder.build_assets(self.output)
                self.assertFalse(self.output.exists())

    def test_skill_stage_drift_after_verification_fails_before_publication(self):
        original = builder.verify_package

        def change_skill(package_root, target):
            original(package_root, target)
            if target == "windows-x86_64":
                (package_root / "skills/auto-re/SKILL.md").write_bytes(b"foreign skill")

        with mock.patch.object(builder, "verify_package", side_effect=change_skill):
            with self.assertRaises(builder.ReleaseAssetError):
                builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_late_skill_zip_duplicate_is_rejected_by_archive_readback(self):
        original = builder.write_skill_zip_from_files

        def duplicate_skill_member(files, skill_root, archive):
            original(files, skill_root, archive)
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Duplicate name")
                with zipfile.ZipFile(archive, "a") as handle:
                    handle.writestr("SKILL.md", b"foreign")

        with mock.patch.object(builder, "write_skill_zip_from_files",
                               side_effect=duplicate_skill_member):
            with self.assertRaisesRegex(builder.ReleaseAssetError,
                                        "duplicate archive members"):
                builder.build_assets(self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_created_at_publication_is_preserved(self):
        original = builder._publish_directory_no_replace

        def occupy_then_publish(stage, output):
            output.mkdir()
            (output / "sentinel").write_bytes(b"foreign")
            return original(stage, output)

        with mock.patch.object(builder, "_publish_directory_no_replace",
                               side_effect=occupy_then_publish):
            with self.assertRaises(OSError):
                builder.build_assets(self.output)
        self.assertEqual((self.output / "sentinel").read_bytes(), b"foreign")

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
