"""Offline continuation preflight regressions; only controlled Python is executed."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "public-template"
MODULE = (TEMPLATE if TEMPLATE.is_dir() else ROOT) / "skills/auto-re/scripts/run_next_action.py"
SPEC = importlib.util.spec_from_file_location("action_preflight_safety_runner", MODULE)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ActionPreflightSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.receipt = self.root / "receipt.json"
        self.logs = runner.receipt_log_dir(self.receipt)

    def prepared(self, sink: Path, *, owned: bool = True) -> dict:
        return {
            "action_stage": "test",
            "reason": "controlled regression",
            "expected_output": "controlled JSON",
            "stop_condition": "controlled process exits",
            "command_owned_sink": owned,
            "argv": ["auto-re-cli", "function", "fixture.bin",
                     "--bundle-dir" if owned else "--output", str(sink)],
        }

    def separate(self, sink: Path, *, owned: bool = True) -> None:
        runner.validate_receipt_sink_separation(
            self.prepared(sink, owned=owned), self.receipt, self.logs
        )

    def test_disjoint_sinks_are_accepted(self) -> None:
        for owned in (True, False):
            with self.subTest(owned=owned):
                self.separate(self.root / "analysis", owned=owned)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_command_sink_symlink_alias_is_rejected(self) -> None:
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaises(runner.ActionError):
            self.separate(alias)

    def test_dot_segment_alias_is_rejected(self) -> None:
        (self.root / "child").mkdir()
        with self.assertRaises(runner.ActionError):
            self.separate(self.root / "child" / "..")

    def test_sink_inside_diagnostic_directory_is_rejected(self) -> None:
        for owned in (True, False):
            with self.subTest(owned=owned), self.assertRaises(runner.ActionError):
                self.separate(self.logs / "analysis", owned=owned)

    def test_sink_below_receipt_path_is_rejected(self) -> None:
        with self.assertRaises(runner.ActionError):
            self.separate(self.receipt / "analysis")

    def test_caller_sink_ancestor_is_rejected(self) -> None:
        with self.assertRaises(runner.ActionError):
            self.separate(self.root, owned=False)

    def test_equals_form_alias_is_rejected(self) -> None:
        prepared = self.prepared(self.root)
        prepared["argv"] = ["auto-re-cli", "report", "fixture.bin", f"--spill-dir={self.root}"]
        with self.assertRaises(runner.ActionError):
            runner.validate_receipt_sink_separation(prepared, self.receipt, self.logs)

    def test_non_string_manifest_kinds_fail_with_action_error(self) -> None:
        for kind in ([], {}, True, 1):
            with self.subTest(kind=kind), self.assertRaises(runner.ActionError):
                runner.validate_result_contract({
                    "schema_version": "0.1.0", "owner": "auto-re-cli",
                    "kind": kind, "files": [],
                })

    def test_known_manifest_kinds_still_work(self) -> None:
        for kind in runner.SUPPORTED_MANIFEST_KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(runner.validate_result_contract({
                    "schema_version": "0.1.0", "owner": "auto-re-cli",
                    "kind": kind, "files": [],
                }), f"manifest:{kind}")

    def dry_run(self, sink: Path) -> tuple[int, str, str]:
        args = mock.Mock(result=self.root / "result.json", action_stage="test",
                         output=None, receipt=self.receipt, dry_run=True)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(runner, "parse_args", return_value=args), \
             mock.patch.object(runner, "prepare_action", return_value=self.prepared(sink)), \
             mock.patch.object(runner.subprocess, "Popen") as popen, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = runner.main()
        popen.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_dry_run_rejects_same_overlap_as_execution(self) -> None:
        code, stdout, stderr = self.dry_run(self.root)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertFalse(json.loads(stderr)["ok"])

    def test_dry_run_accepts_disjoint_without_mutations(self) -> None:
        code, stdout, stderr = self.dry_run(self.root / "bundle")
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertEqual(result["planned_receipt"], str(self.receipt))
        self.assertEqual(result["planned_log_dir"], str(self.logs))

    def test_retention_limit_rejected_before_program_probe(self) -> None:
        for limit in (-1, True, 1.5, runner.LOG_TAIL_BYTES + 1):
            with self.subTest(limit=limit), \
                 mock.patch.object(runner, "probe_program_version") as probe, \
                 mock.patch.object(runner.subprocess, "Popen") as popen:
                with self.assertRaises(runner.ActionError):
                    runner.execute_prepared_with_receipt(
                        self.prepared(self.root / "bundle"), Path(sys.executable),
                        self.receipt, log_tail_bytes=limit,
                    )
                probe.assert_not_called()
                popen.assert_not_called()

    def test_late_receipt_collision_from_controlled_child_is_preserved(self) -> None:
        prepared = self.prepared(self.root / "bundle")
        code = "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'other writer')"
        prepared["argv"] = ["auto-re-cli", "-c", code, str(self.receipt),
                            "--spill-dir", str(self.root / "bundle")]
        with mock.patch.object(runner, "probe_program_version", return_value="auto-re-cli 1.2.3"):
            with self.assertRaises(runner.ActionError):
                runner.execute_prepared_with_receipt(prepared, Path(sys.executable), self.receipt)
        self.assertTrue(self.receipt.exists())
        self.assertEqual(self.receipt.read_bytes(), b"other writer")
        self.assertFalse(self.logs.exists(), "failed operation must clean its owned logs")


if __name__ == "__main__":
    unittest.main()
