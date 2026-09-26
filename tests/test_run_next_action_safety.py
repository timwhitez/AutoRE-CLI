"""Local-only continuation regressions; execute controlled Python, never samples."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
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

    def test_call_graph_profile_type_error_stops_before_version_probe(self) -> None:
        base = {"schema_version": "0.1.0", "kind": "call_graph", "root": {},
                "budget": {}, "summary": {}, "nodes": [], "edges": [],
                "next_actions": [{"stage": "function.selected", "reason": "controlled",
                                  "expected_output": "JSON", "stop_condition": "one result",
                                  "argv": ["auto-re-cli", "function", "input.bin"]}]}
        for profile in ([], {}):
            with self.subTest(profile=profile):
                result = self.root / "call_graph.json"
                result.write_text(json.dumps({**base, "profile": profile}), encoding="utf-8")
                stderr = io.StringIO()
                receipt = self.root / "receipt.json"
                output = self.root / "next.json"
                with mock.patch.object(sys, "argv", ["run_next_action.py", str(result),
                                                    "--action-stage", "function.selected",
                                                    "--output", str(output),
                                                    "--receipt", str(receipt)]), \
                     mock.patch.object(runner.shutil, "which") as probe, \
                     contextlib.redirect_stderr(stderr):
                    self.assertEqual(runner.main(), 1)
                lines = stderr.getvalue().splitlines()
                self.assertEqual(len(lines), 1)
                self.assertIn("call_graph.profile", json.loads(lines[0])["error"])
                self.assertNotIn("Traceback", stderr.getvalue())
                probe.assert_not_called()
                self.assertFalse(output.exists())
                self.assertFalse(receipt.exists())
                self.assertFalse(runner.receipt_log_dir(receipt).exists())
        for profile in ("ai", "full"):
            self.assertEqual(runner.validate_result_contract({**base, "profile": profile}),
                             "wrapper:call_graph")
        with self.assertRaises(runner.ActionError):
            runner.validate_result_contract({"schema_version": "0.1.0", "profile": "full",
                                             "binary": {}, "summary": {}})

    def test_real_receipt_entry_allows_only_reaped_timeout_budget_increase(self) -> None:
        source = self.root / "input.bin"
        source.write_bytes(b"controlled")
        argv = ["auto-re-cli", "data-xrefs", str(source), "--offset", "1"]
        result = self.result_file(argv)
        executable = pathlib.Path(sys.executable).resolve()
        identity = runner.request_identity(argv, runner.sha256_file(executable))
        self.assertIsNotNone(identity)
        self.assertEqual(identity, runner.request_identity(
            argv + ["--output", str(self.root / "other.json")],
            runner.sha256_file(executable)))
        self.assertNotEqual(identity, runner.request_identity(
            argv[:-1] + ["2"], runner.sha256_file(executable)))
        prior = self.root / "prior.json"
        prior_value = {"schema_version": 1, "owner": "auto-re-skill",
                       "kind": "auto_re_action_execution_receipt",
                       "request_identity": identity, "execution_status": "timed_out",
                       "timeout_seconds": 1.0, "leader_reaped": True}
        prior.write_text(json.dumps(prior_value), encoding="utf-8")
        empty = runner.CapturedStream(b"", 0, hashlib.sha256(b"").hexdigest())
        captured = runner.process_control.ProcessResult(0, "completed", empty, empty, (), True)

        receipt = self.root / "allowed.json"
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["run_next_action.py", str(result),
                                            "--action-stage", "function.selected",
                                            "--output", str(self.root / "page.json"),
                                            "--receipt", str(receipt),
                                            "--prior-receipt", str(prior),
                                            "--timeout-seconds", "60"]), \
             mock.patch.object(runner.shutil, "which", return_value=str(executable)), \
             mock.patch.object(runner, "probe_program_version",
                               return_value="auto-re-cli 0.1.7") as probe, \
             mock.patch.object(runner.process_control, "run_process",
                               return_value=captured) as run, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["continuation_check"],
                         "increased_timeout_after_timeout")
        self.assertEqual(json.loads(receipt.read_text())["continuation_check"],
                         "increased_timeout_after_timeout")
        probe.assert_called_once()
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["timeout_seconds"], 60.0)

        prior_value.update(execution_status="completed", exit_code=124)
        prior.write_text(json.dumps(prior_value), encoding="utf-8")
        blocked_receipt = self.root / "blocked.json"
        blocked_output = self.root / "blocked-output.json"
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["run_next_action.py", str(result),
                                            "--action-stage", "function.selected",
                                            "--output", str(blocked_output),
                                            "--receipt", str(blocked_receipt),
                                            "--prior-receipt", str(prior),
                                            "--timeout-seconds", "60"]), \
             mock.patch.object(runner.shutil, "which", return_value=str(executable)), \
             mock.patch.object(runner, "probe_program_version",
                               return_value="auto-re-cli 0.1.7") as probe, \
             mock.patch.object(runner.process_control, "run_process") as run, \
             contextlib.redirect_stderr(stderr):
            self.assertEqual(runner.main(), 1)
        self.assertIn("no_progress", json.loads(stderr.getvalue())["error"])
        probe.assert_called_once()
        run.assert_not_called()
        self.assertFalse(blocked_receipt.exists())
        self.assertFalse(runner.receipt_log_dir(blocked_receipt).exists())
        self.assertFalse(blocked_output.exists())

        preview_receipt = self.root / "preview.json"
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["run_next_action.py", str(result),
                                            "--action-stage", "function.selected",
                                            "--output", str(self.root / "preview-output.json"),
                                            "--receipt", str(preview_receipt),
                                            "--prior-receipt", str(prior), "--dry-run"]), \
             mock.patch.object(runner.shutil, "which") as which, \
             mock.patch.object(runner, "probe_program_version") as probe, \
             mock.patch.object(runner.process_control, "run_process") as run, \
             contextlib.redirect_stdout(stdout):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue())["continuation_check"],
                         "not_evaluated_dry_run")
        which.assert_not_called()
        probe.assert_not_called()
        run.assert_not_called()
        self.assertFalse(preview_receipt.exists())

        prior_value["request_identity"] = None
        prior.write_text(json.dumps(prior_value), encoding="utf-8")
        unknown_receipt = self.root / "unknown-identity.json"
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["run_next_action.py", str(result),
                                            "--action-stage", "function.selected",
                                            "--output", str(self.root / "unknown-output.json"),
                                            "--receipt", str(unknown_receipt),
                                            "--prior-receipt", str(prior)]), \
             mock.patch.object(runner.shutil, "which", return_value=str(executable)), \
             mock.patch.object(runner, "probe_program_version",
                               return_value="auto-re-cli 0.1.7"), \
             mock.patch.object(runner.process_control, "run_process",
                               return_value=captured) as run, \
             contextlib.redirect_stdout(stdout):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue())["continuation_check"],
                         "not_evaluated_unavailable_identity")
        self.assertEqual(json.loads(unknown_receipt.read_text())["request_identity"],
                         identity)
        run.assert_called_once()

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
