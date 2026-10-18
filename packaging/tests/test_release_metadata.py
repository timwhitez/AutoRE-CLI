"""Offline metadata regressions; no Ruby, package manager, binary, or network runs."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_release_metadata", ROOT / "packaging/check_release_metadata.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
FIXTURE = Path(__file__).with_name("fixtures") / "release-v0.1.11.json"
OLD_HASHES = {
    "macos-arm64": "161022fd85940743a6c3f93b1daadfc62e54e2c3d5f5048dd31cb1f104c3b075",
    "macos-x86_64": "d61b60d74f31639bafd3374d4316b6d46463b1bfc43cac6038061f93807d0241",
    "linux-arm64": "bc7f8a3ef0cf5e4661b9d0ceae241a2e6134e34f19c0bdb0f4d9fba6908aa2e3",
    "linux-x86_64": "10a42c7c9dc1a62df0a66bc7d17541cb3fc3d0dfc1d076912c8593829e26062e",
    "windows-x86_64": "18b7ef6960752a27b16a7e67eb023038e73691b32cfc14095084d6a2292010d3",
}


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in checker.RECIPES:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Freeze the historical recipes with their release metadata across future releases.
            suffix = Path(relative).suffix
            destination.write_bytes((FIXTURE.parent / ("autore-cli-v0.1.11" + suffix)).read_bytes())
        self.release = json.loads(FIXTURE.read_text())
        self.sums()

    def sums(self):
        (self.root / "SHA256SUMS").write_text("".join(
            hashlib.sha256((self.root / p).read_bytes()).hexdigest() + "  " + p + "\n"
            for p in checker.RECIPES))

    def replace(self, old, new, target="macos-arm64"):
        path = self.root / checker.RECIPES[target == "windows-x86_64"]
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new))
        self.sums()

    def asset(self, target="macos-arm64", release=None):
        return next(a for a in (release or self.release)["assets"]
                    if a["name"] == checker.asset_name("0.1.11", target))

    def rejected(self, release=None, after=None):
        release = self.release if release is None else release
        with self.assertRaises(checker.MetadataError):
            checker.check(self.root, release, release if after is None else after)

    def test_exact_five_target_match_and_repository_sums(self):
        result = checker.check(self.root, self.release, copy.deepcopy(self.release))
        self.assertTrue(result["ok"])
        self.assertEqual(result["targets_checked"], list(checker.TARGETS))

    def test_current_recipes_match_distribution_version_and_checksums(self):
        version, recipes = checker.read_recipes(ROOT)
        self.assertEqual(version, (ROOT / "VERSION").read_text().strip())
        self.assertEqual(set(recipes), set(checker.TARGETS))
        checker.verify_recipe_checksums(ROOT)

    def test_each_old_recipe_hash_is_rejected(self):
        for target, old in OLD_HASHES.items():
            with self.subTest(target=target):
                current = self.asset(target)["digest"][7:]
                self.replace(current, old, target)
                self.rejected()
                self.replace(old, current, target)

    def test_same_version_replacement_with_stable_snapshots_is_rejected(self):
        changed = copy.deepcopy(self.release)
        self.asset(release=changed)["digest"] = "sha256:" + "0" * 64
        self.rejected(changed)

    def test_concurrent_release_or_asset_change_is_rejected(self):
        mutations = [("release", "id", 987), ("release", "updated_at", "later"),
                     ("release", "target_commitish", "another-commit"),
                     ("asset", "id", 987), ("asset", "digest", "sha256:" + "0" * 64),
                     ("asset", "updated_at", "later"), ("asset", "size", 1)]
        for kind, key, value in mutations:
            with self.subTest(kind=kind, key=key):
                after = copy.deepcopy(self.release)
                (after if kind == "release" else self.asset(release=after))[key] = value
                self.rejected(after=after)

    def test_download_counts_and_asset_order_are_not_identity(self):
        after = copy.deepcopy(self.release)
        after["assets"].reverse()
        after["assets"][0]["download_count"] = 100
        self.assertTrue(checker.check(self.root, self.release, after)["ok"])

    def test_each_missing_release_target_is_rejected(self):
        for target in checker.TARGETS:
            with self.subTest(target=target):
                release = copy.deepcopy(self.release)
                release["assets"].remove(self.asset(target, release))
                self.rejected(release)

    def test_duplicate_asset_names_ids_and_missing_assets_are_rejected(self):
        for kind in ("name", "id", "none", "empty"):
            with self.subTest(kind=kind):
                release = copy.deepcopy(self.release)
                if kind in ("name", "id"):
                    release["assets"][1][kind] = release["assets"][0][kind]
                else:
                    release["assets"] = None if kind == "none" else []
                self.rejected(release)

    def test_invalid_release_and_asset_fields_are_rejected(self):
        for key, value in (("id", None), ("id", True), ("tag_name", "v0.1.10"),
                           ("draft", True), ("prerelease", True), ("updated_at", None)):
            with self.subTest(key=key, value=value):
                release = copy.deepcopy(self.release)
                release[key] = value
                self.rejected(release)
        for key, value in (("digest", None), ("digest", "sha256:" + "g" * 64),
                           ("digest", "sha256:" + "a" * 63), ("digest", "md5:" + "a" * 64),
                           ("state", "new"), ("size", 0), ("browser_download_url", "https://example.org/a")):
            with self.subTest(key=key, value=value):
                release = copy.deepcopy(self.release)
                self.asset(release=release)[key] = value
                self.rejected(release)
        self.rejected([])

    def test_recipe_versions_and_malformed_hashes_are_rejected(self):
        for target in checker.TARGETS:
            with self.subTest(target=target):
                current = self.asset(target)["digest"][7:]
                self.replace(current, "invalid", target)
                self.rejected()
                self.replace("invalid", current, target)
        self.replace('version "0.1.11"', 'version "0.1.10"')
        self.rejected()

    def test_swapped_recipe_urls_and_hashes_are_rejected(self):
        for target in checker.TARGETS:
            with self.subTest(target=target):
                other = "linux-x86_64" if target != "linux-x86_64" else "macos-arm64"
                url = checker.asset_url("0.1.11", target)
                swapped = checker.asset_url("0.1.11", other)
                self.replace(url, swapped, target)
                self.rejected()
                # Restore this target only, without undoing the original other URL.
                path = self.root / checker.RECIPES[target == "windows-x86_64"]
                path.write_bytes((FIXTURE.parent / ("autore-cli-v0.1.11" + path.suffix)).read_bytes())
                self.sums()
        first, second = (self.asset(t)["digest"][7:] for t in checker.TARGETS[:2])
        path = self.root / checker.RECIPES[0]
        path.write_text(path.read_text().replace(first, "PLACEHOLDER").replace(second, first).replace("PLACEHOLDER", second))
        self.sums()
        self.rejected()

    def test_missing_duplicate_or_changed_platform_selectors_are_rejected(self):
        path = self.root / checker.RECIPES[0]
        original = path.read_text()
        for text in (original.replace('if Hardware::CPU.arm?', 'if Hardware::CPU.intel?', 1),
                     original.replace('  on_linux do', '  on_macos do'),
                     original + '\nurl "extra"\nsha256 "' + 'a' * 64 + '"\n',
                     original.replace('      sha256 "' + self.asset()["digest"][7:] + '"\n', '')):
            with self.subTest(text=text):
                path.write_text(text)
                self.sums()
                self.rejected()
        path.write_text(original)
        scoop = self.root / checker.RECIPES[1]
        data = json.loads(scoop.read_text())
        for architecture in ({}, {"32bit": data["architecture"]["64bit"]},
                             {**data["architecture"], "arm64": data["architecture"]["64bit"]}):
            data["architecture"] = architecture
            scoop.write_text(json.dumps(data))
            self.sums()
            self.rejected()

    def test_dead_or_block_commented_selectors_are_rejected(self):
        path = self.root / checker.RECIPES[0]
        original = path.read_text()
        start = original.index("  on_macos do")
        stop = original.index("  def install")
        for opening, closing in (("if false\n", "end\n"), ("=begin\n", "=end\n")):
            with self.subTest(opening=opening):
                path.write_text(original[:start] + opening + original[start:stop] + closing + original[stop:])
                self.sums()
                self.rejected()

    def test_recipe_repository_checksum_drift_is_rejected(self):
        self.replace('version "0.1.11"', 'version "0.1.11"  ')
        (self.root / "SHA256SUMS").write_text("0" * 64 + "  " + checker.RECIPES[0] + "\n")
        self.rejected()

    def test_json_duplicate_keys_are_rejected(self):
        with self.assertRaises(checker.MetadataError):
            checker.read_json('{"id": 1, "id": 2}')

    def test_cli_missing_unreadable_malformed_snapshots_fail(self):
        before, after = self.root / "before.json", self.root / "after.json"
        before.write_text(json.dumps(self.release))
        for data in (None, "{", "null", "[]"):
            if data is not None:
                after.write_text(data)
            with self.subTest(data=data), contextlib.redirect_stderr(io.StringIO()) as errors:
                status = checker.main(["--root", str(self.root), "--release-before", str(before), "--release-after", str(after)])
                self.assertEqual(status, 1)
                self.assertFalse(json.loads(errors.getvalue())["ok"])

    def test_live_reads_twice_and_read_failures_never_pass(self):
        with mock.patch.object(checker, "fetch_release", side_effect=[self.release, self.release]) as fetch:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(checker.main(["--root", str(self.root), "--online"]), 0)
            self.assertEqual(fetch.call_count, 2)
        changed = copy.deepcopy(self.release)
        changed["id"] += 1
        for responses in ([OSError("unavailable")], [self.release, OSError("unavailable")], [self.release, changed]):
            with self.subTest(responses=responses), mock.patch.object(checker, "fetch_release", side_effect=responses):
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(checker.main(["--root", str(self.root), "--online"]), 1)
                    self.assertFalse(json.loads(errors.getvalue())["ok"])

    def test_local_change_during_live_collection_is_rejected(self):
        def after_read(version):
            self.replace('version "0.1.11"', 'version "0.1.11"  ')
            return self.release
        count = 0
        def fetch(version):
            nonlocal count
            count += 1
            return self.release if count == 1 else after_read(version)
        with mock.patch.object(checker, "fetch_release", side_effect=fetch), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checker.main(["--root", str(self.root), "--online"]), 1)


if __name__ == "__main__":
    unittest.main()
