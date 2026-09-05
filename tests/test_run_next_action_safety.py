"""Local-only continuation regressions; execute controlled Python, never samples."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "skills/auto-re/scripts/run_next_action.py"
SPEC = importlib.util.spec_from_file_location("run_next_action_safety", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RunNextActionSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="auto-re-safety-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()

    def prepared(self, sink: pathlib.Path, *, code: str = "pass") -> dict:
        return {
            "action_stage": "function.selected",
            "reason": "controlled safety regression",
            "expected_output": "controlled output",
            "stop_condition": "controlled process exits",
            "command_owned_sink": True,
            "argv": ["auto-re-cli", "-c", code, "--spill-dir", str(sink)],
        }

    def caller_prepared(self, output: pathlib.Path) -> dict:
        return {
            **self.prepared(self.root / "unused"),
            "command_owned_sink": False,
            "argv": ["auto-re-cli", "function", "--output", str(output)],
        }

    def result_file(self, argv: list[str] | None = None) -> pathlib.Path:
        result = self.root / "result.json"
        result.write_text(json.dumps({
            "schema_version": "0.1.0",
            "display_name": "controlled",
            "function": {},
            "next_actions": [{
                "stage": "function.selected",
                "reason": "controlled safety regression",
                "expected_output": "bounded JSON",
                "stop_condition": "controlled process exits",
                "argv": argv or ["auto-re-cli", "function", "controlled.bin"],
            }],
        }), encoding="utf-8")
        return result

    def dry_run(self, result: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), str(result),
             "--action-stage", "function.selected", "--dry-run", *args],
            capture_output=True, text=True, check=False, timeout=10,
        )

    def test_existing_receipt_is_preserved(self) -> None:
        path = self.root / "receipt.json"
        path.write_bytes(b"other writer's receipt")
        before = path.stat()
        with self.assertRaises(runner.ActionError):
            runner._write_private_bytes(path, b"replacement", "receipt")
        self.assertEqual(path.read_bytes(), b"other writer's receipt")
        self.assertTrue(os.path.samestat(before, path.stat()))

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlinks")
    def test_existing_symlink_is_preserved(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"user data")
        path = self.root / "receipt.json"
        path.symlink_to(target)
        with self.assertRaises(runner.ActionError):
            runner._write_private_bytes(path, b"replacement", "receipt")
        self.assertTrue(path.is_symlink())
        self.assertEqual(target.read_bytes(), b"user data")

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlinks")
    def test_dangling_symlink_is_preserved(self) -> None:
        path = self.root / "receipt.json"
        path.symlink_to(self.root / "absent")
        with self.assertRaises(runner.ActionError):
            runner._write_private_bytes(path, b"replacement", "receipt")
        self.assertTrue(path.is_symlink())

    def test_failed_write_removes_owned_file(self) -> None:
        path = self.root / "receipt.json"
        with mock.patch.object(runner.os, "fsync", side_effect=OSError("write failed")):
            with self.assertRaisesRegex(runner.ActionError, "write failed"):
                runner._write_private_bytes(path, b"partial", "receipt")
        self.assertFalse(path.exists())

    @unittest.skipUnless(os.name == "posix", "requires replacing an open file")
    def test_failed_write_preserves_replacement_file(self) -> None:
        path = self.root / "receipt.json"

        def replace_then_fail(_fd: int) -> None:
            path.unlink()
            path.write_bytes(b"concurrent replacement")
            raise OSError("write failed after replacement")

        with mock.patch.object(runner.os, "fsync", side_effect=replace_then_fail):
            with self.assertRaisesRegex(runner.ActionError, "write failed"):
                runner._write_private_bytes(path, b"partial", "receipt")
        self.assertEqual(path.read_bytes(), b"concurrent replacement")

    def test_cleanup_failure_does_not_mask_write_failure(self) -> None:
        path = self.root / "receipt.json"
        with mock.patch.object(runner.os, "fsync", side_effect=OSError("primary write failure")):
            with mock.patch.object(pathlib.Path, "unlink", side_effect=OSError("cleanup failure")):
                with self.assertRaisesRegex(runner.ActionError, "primary write failure"):
                    runner._write_private_bytes(path, b"partial", "receipt")
        if path.exists():
            path.chmod(0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX permission guarantee")
    def test_file_is_private_during_write_even_with_umask_zero(self) -> None:
        path = self.root / "receipt.json"
        real_fsync = os.fsync
        modes: list[int] = []

        def inspect(fd: int) -> None:
            modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
            real_fsync(fd)

        old_umask = os.umask(0)
        try:
            with mock.patch.object(runner.os, "fsync", side_effect=inspect):
                runner._write_private_bytes(path, b"private diagnostics", "receipt")
        finally:
            os.umask(old_umask)
        self.assertTrue(modes)
        self.assertTrue(all(mode & 0o077 == 0 for mode in modes), modes)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)

    def test_successful_receipt_contains_exact_bytes(self) -> None:
        path = self.root / "receipt.json"
        runner._write_private_bytes(path, b"exact bytes\x00\xff", "receipt")
        self.assertEqual(path.read_bytes(), b"exact bytes\x00\xff")
        path.chmod(0o600)

    def test_late_receipt_collision_preserves_other_writer(self) -> None:
        receipt = self.root / "receipt.json"
        code = f"from pathlib import Path; Path({str(receipt)!r}).write_bytes(b'other writer')"
        with mock.patch.object(runner, "probe_program_version", return_value="auto-re-cli 1.2.3"):
            with self.assertRaises(runner.ActionError):
                runner.execute_prepared_with_receipt(
                    self.prepared(self.root / "analysis", code=code),
                    pathlib.Path(sys.executable), receipt,
                )
        self.assertEqual(receipt.read_bytes(), b"other writer")
        self.assertFalse(runner.receipt_log_dir(receipt).exists())

    def test_malformed_manifest_kinds_are_validation_errors(self) -> None:
        for kind in ([], {}, ["context_bundle"], 0, True, None, "foreign"):
            with self.subTest(kind=kind), self.assertRaises(runner.ActionError):
                runner.validate_result_contract({
                    "schema_version": "0.1.0", "owner": "auto-re-cli",
                    "kind": kind, "files": [],
                })

    def test_supported_manifest_kinds_remain_accepted(self) -> None:
        for kind in ("context_bundle", "agent_spill_manifest"):
            with self.subTest(kind=kind):
                self.assertEqual(runner.validate_result_contract({
                    "schema_version": "0.1.0", "owner": "auto-re-cli",
                    "kind": kind, "files": [],
                }), f"manifest:{kind}")

    def test_cli_malformed_kind_returns_json_not_traceback(self) -> None:
        result = self.root / "bad.json"
        result.write_text(json.dumps({
            "schema_version": "0.1.0", "owner": "auto-re-cli",
            "kind": [], "files": [],
        }), encoding="utf-8")
        completed = self.dry_run(result, "--output", str(self.root / "out.json"))
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stderr)["ok"])
        self.assertNotIn("Traceback", completed.stderr)
        self.assertEqual(completed.stdout, "")

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlinks")
    def test_symlink_aliased_command_sink_is_rejected(self) -> None:
        sink = self.root / "bundle"
        sink.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(sink, target_is_directory=True)
        with self.assertRaises(runner.ActionError):
            runner.validate_receipt_sink_separation(
                self.prepared(alias), sink / "receipt.json", self.root / "logs",
            )

    def test_dot_segment_aliased_command_sink_is_rejected(self) -> None:
        sink = self.root / "bundle"
        sink.mkdir()
        with self.assertRaises(runner.ActionError):
            runner.validate_receipt_sink_separation(
                self.prepared(sink / ".." / "bundle"),
                sink / "receipt.json", self.root / "logs",
            )

    def test_command_sink_inside_log_directory_is_rejected(self) -> None:
        logs = self.root / "receipt.json.logs"
        with self.assertRaises(runner.ActionError):
            runner.validate_receipt_sink_separation(
                self.prepared(logs / "analysis"), self.root / "receipt.json", logs,
            )

    def test_caller_output_inside_log_directory_is_rejected(self) -> None:
        logs = self.root / "receipt.json.logs"
        with self.assertRaises(runner.ActionError):
            runner.validate_receipt_sink_separation(
                self.caller_prepared(logs / "analysis.json"),
                self.root / "receipt.json", logs,
            )

    def test_nonoverlapping_siblings_are_accepted(self) -> None:
        runner.validate_receipt_sink_separation(
            self.prepared(self.root / "analysis"),
            self.root / "analysis-receipt.json", self.root / "analysis-logs",
        )

    def test_literal_tilde_in_argv_is_not_shell_expanded(self) -> None:
        previous = pathlib.Path.cwd()
        try:
            os.chdir(self.root)
            self.assertEqual(
                runner._command_sink_values(["auto-re-cli", "report", "--spill-dir", "~/bundle"]),
                [self.root / "~" / "bundle"],
            )
        finally:
            os.chdir(previous)

    def test_malformed_command_sinks_are_rejected(self) -> None:
        for args in (["--spill-dir"], ["--spill-dir="], ["--spill-dir", "--bundle-dir=x"]):
            with self.subTest(args=args), self.assertRaises(runner.ActionError):
                runner.validate_receipt_sink_separation(
                    {"argv": ["auto-re-cli", "report", *args], "command_owned_sink": True},
                    self.root / "receipt.json", self.root / "logs",
                )

    def test_prepared_sink_ownership_cannot_be_mixed(self) -> None:
        with self.assertRaises(runner.ActionError):
            runner.validate_prepared_argv(
                ["auto-re-cli", "report", "--spill-dir", "bundle", "--output", "out.json"],
                command_owned_sink=False,
            )

    def test_dry_run_rejects_receipt_output_collision_without_writes(self) -> None:
        result = self.result_file()
        output = self.root / "same.json"
        completed = self.dry_run(result, "--output", str(output), "--receipt", str(output))
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stderr)["ok"])
        self.assertFalse(output.exists())
        self.assertFalse(runner.receipt_log_dir(output).exists())

    def test_valid_dry_run_is_side_effect_free(self) -> None:
        result = self.result_file()
        output, receipt = self.root / "out.json", self.root / "receipt.json"
        before = set(self.root.iterdir())
        completed = self.dry_run(result, "--output", str(output), "--receipt", str(receipt))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["planned_receipt"], str(receipt))
        self.assertEqual(set(self.root.iterdir()), before)

    @unittest.skipUnless(os.name == "posix", "requires POSIX symlinks")
    def test_dry_run_rejects_symlink_aliased_command_sink(self) -> None:
        sink = self.root / "bundle"
        sink.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(sink, target_is_directory=True)
        result = self.result_file(["auto-re-cli", "report", "--bundle-dir", str(alias)])
        before = set(sink.iterdir())
        completed = self.dry_run(result, "--receipt", str(sink / "receipt.json"))
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(completed.stderr)["ok"])
        self.assertEqual(set(sink.iterdir()), before)

    def test_log_tail_limits_reject_before_probing(self) -> None:
        for limit in (True, -1, 1.5, runner.LOG_TAIL_BYTES + 1):
            with self.subTest(limit=limit):
                with mock.patch.object(runner, "probe_program_version", side_effect=AssertionError("must reject before probing")):
                    with self.assertRaisesRegex(runner.ActionError, "log tail byte limit"):
                        runner.execute_prepared_with_receipt(
                            self.prepared(self.root / "analysis"), pathlib.Path(sys.executable),
                            self.root / "receipt.json", log_tail_bytes=limit,
                        )

    def test_zero_tail_retains_hashes_without_diagnostic_bytes(self) -> None:
        receipt = self.root / "receipt.json"
        code = "import os; os.write(1, b'hello'); os.write(2, b'error')"
        with mock.patch.object(runner, "probe_program_version", return_value="auto-re-cli 1.2.3"):
            exit_code, summary = runner.execute_prepared_with_receipt(
                self.prepared(self.root / "analysis", code=code), pathlib.Path(sys.executable),
                receipt, log_tail_bytes=0,
            )
        self.assertEqual(exit_code, 0)
        self.assertTrue(summary["ok"])
        value = json.loads(receipt.read_bytes())
        for stream, expected in (("stdout", b"hello"), ("stderr", b"error")):
            self.assertEqual(value[stream]["bytes_total"], len(expected))
            self.assertEqual(value[stream]["bytes_retained"], 0)
            self.assertEqual(value[stream]["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(pathlib.Path(value[stream]["path"]).read_bytes(), b"")
        for path in runner.receipt_log_dir(receipt).iterdir():
            path.chmod(0o600)
        receipt.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
