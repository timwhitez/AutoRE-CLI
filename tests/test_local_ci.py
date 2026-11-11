"""Local runner ordering, host coverage and task-owned cleanup."""
from __future__ import annotations
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "public_local_ci_tested", Path(__file__).resolve().parents[1] / "scripts/local_ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class LocalCiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-local-ci-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "scripts/build_release_assets.py").write_text("# controlled placeholder\n")
        (self.root / "VERSION").write_text("0.1.13\n")

    def test_real_command_failure_is_not_reported_as_success(self):
        with mock.patch.object(ci, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            ci.run_command([ci.sys.executable, "-c", "raise SystemExit(7)"], dict(os.environ))

    def test_checks_order_and_success_cleanup(self):
        calls = []
        def command(argv, env, capture=False):
            calls.append(list(map(str, argv)))
            self.assertTrue(Path(env["TMPDIR"]).is_dir())
            Path(env["TMPDIR"], "created-by-child").write_text("scratch")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(ci, "ROOT", self.root), mock.patch.object(ci, "run_command", side_effect=command), mock.patch.object(ci.tempfile, "tempdir", str(self.root)), contextlib.redirect_stdout(io.StringIO()):
            ci.run_ci("checks")
        self.assertEqual([c[2] for c in calls[:2]], [str(self.root / "scripts/autore_distribution.py"), str(self.root / "scripts/quick_validate_skill.py")])
        self.assertIn("unittest", calls[2])
        self.assertIn("tests", calls[2])
        self.assertFalse(list(self.root.glob("autore-local-ci-*")))

    def test_failed_command_propagates_and_cleans_only_owned_tree(self):
        sentinel = self.root / "keep.txt"
        sentinel.write_text("user data")
        calls = []
        def fail(argv, env, capture=False):
            calls.append(argv)
            Path(env["TMPDIR"], "partial-output").write_text("scratch")
            raise subprocess.CalledProcessError(7, argv)
        with mock.patch.object(ci, "ROOT", self.root), mock.patch.object(ci, "run_command", side_effect=fail), mock.patch.object(ci.tempfile, "tempdir", str(self.root)), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            ci.run_ci("all")
        self.assertEqual(len(calls), 1)
        self.assertEqual(sentinel.read_text(), "user data")
        self.assertFalse(list(self.root.glob("autore-local-ci-*")))

    def test_native_host_smoke_uses_only_temporary_destinations(self):
        for host, object_format in (("linux-x86_64", "elf"),
                                    ("macos-arm64", "mach_o"),
                                    ("macos-x86_64", "mach_o"),
                                    ("windows-x86_64", "coff"),
                                    ("linux-x86_64", "invalid")):
            with self.subTest(host=host, object_format=object_format), tempfile.TemporaryDirectory(dir=self.root) as td:
                work = Path(td)
                calls = []
                def command(argv, env, capture=False):
                    argv = list(map(str, argv));calls.append(argv)
                    if "--version" in argv:
                        return subprocess.CompletedProcess(argv, 0, "auto-re-cli 0.1.13\n", "")
                    if "install" in argv:
                        dest = Path(argv[argv.index("--install-dir")+1]);dest.mkdir()
                        (dest / ("auto-re-cli.exe" if host.startswith("windows") else "auto-re-cli")).write_text("trusted fixture")
                    if "uninstall" in argv:
                        Path(argv[argv.index("--install-dir")+1], "auto-re-cli.exe" if host.startswith("windows") else "auto-re-cli").unlink()
                    if "analyze" in argv:
                        Path(argv[argv.index("--output")+1]).write_text(json.dumps({"schema_version": "0.1.0", "metadata": {"format": object_format}}))
                    return subprocess.CompletedProcess(argv, 0, "", "")
                with mock.patch.object(ci, "ROOT", self.root), mock.patch.object(ci.distribution, "host_target", return_value=host), mock.patch.object(ci, "run_command", side_effect=command):
                    if object_format == "invalid":
                        with self.assertRaisesRegex(ValueError, "metadata contract"):
                            ci.native_smoke(work, dict(os.environ))
                        continue
                    ci.native_smoke(work, dict(os.environ))
                install = next(c for c in calls if "install" in c)
                for flag in ("--install-dir", "--codex-home", "--trae-home"):
                    self.assertTrue(Path(install[install.index(flag)+1]).is_relative_to(work))
                self.assertTrue(any("uninstall" in c for c in calls))
                self.assertTrue(any("candidate_roots" in arg for c in calls for arg in c))
                self.assertEqual(any("analyze" in c for c in calls), not host.startswith("windows"))
                self.assertFalse(any(c[0].endswith("controlled.o") for c in calls))

    def test_archive_lane_uses_existing_builder_and_cleans_output(self):
        calls = []
        def command(argv, env, capture=False):
            calls.append(list(map(str, argv)))
            if "--output" in argv:
                Path(argv[argv.index("--output")+1]).mkdir()
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(ci, "ROOT", self.root), mock.patch.object(ci, "run_command", side_effect=command), mock.patch.object(ci.tempfile, "tempdir", str(self.root)), contextlib.redirect_stdout(io.StringIO()):
            ci.run_ci("archives")
        self.assertEqual(calls[-1][2], str(self.root / "scripts/build_release_assets.py"))
        self.assertFalse(list(self.root.glob("autore-local-ci-*")))
        self.assertFalse(any("gh" in c or "release" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
