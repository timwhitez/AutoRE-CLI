"""Regression tests for source issues #270–#273; only trusted fixture programs run."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

subprocess_timeout = runpy.run_path(str(Path(__file__).with_name("subprocess_timeout.py")))["subprocess_timeout"]

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/auto-re/scripts"

def load(name):
    spec = importlib.util.spec_from_file_location("boundary_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

runner = load("run_next_action")
doctor = load("skill_doctor")


def document(argv):
    return {"schema_version": "0.1.0", "profile": "ai", "flat": False, "inspections": {}, "recovered_types": [], "functions": [], "binary": {}, "summary": {},
            "next_actions": [{"stage": "next", "reason": "inspect evidence",
                              "expected_output": "JSON", "stop_condition": "one result",
                              "argv": argv}]}


class JsonAndPreflightTests(unittest.TestCase):
    def test_integer_conversion_errors_are_domain_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = root / "result.json"
            result.write_text("{}")
            (root / ".autore-managed.json").write_text("{}")
            for module, fn, path, kind in (
                (runner, runner.load_json_object, result, runner.ActionError),
                (doctor, doctor.read_managed_marker, root, doctor.DoctorError),
            ):
                with self.subTest(module=module.__name__):
                    with patch.object(module.json, "loads", side_effect=ValueError("integer limit")):
                        with self.assertRaises(kind):
                            fn(path)

    def test_native_integer_limit_and_legal_integer(self):
        limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text('{"n":123}')
            self.assertEqual(runner.load_json_object(path), {"n": 123})
            if limit:
                for digits in (limit, limit + 1):
                    path.write_text('{"unknown":' + '7' * digits + '}')
                    if digits == limit:
                        self.assertIsInstance(runner.load_json_object(path)["unknown"], int)
                    else:
                        with self.assertRaises(runner.ActionError):
                            runner.load_json_object(path)

    def test_malformed_sinks_rejected_in_all_four_entry_modes(self):
        cases = (["--spill-dir"], ["--spill-dir="],
                 ["--bundle-dir", "--format", "json"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = root / "result.json"
            for flags in cases:
                result.write_text(json.dumps(document(["auto-re-cli", "report", "sample.bin", *flags])))
                for preview in (False, True):
                    for receipt in (False, True):
                        argv = [str(SCRIPTS / "run_next_action.py"), str(result), "--action-stage", "next"]
                        if preview:
                            argv.append("--dry-run")
                        if receipt:
                            argv += ["--receipt", str(root / "receipt.json")]
                        with self.subTest(flags=flags, preview=preview, receipt=receipt):
                            with patch.object(sys, "argv", argv), patch.object(runner.shutil, "which") as which:
                                with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
                                    self.assertEqual(runner.main(), 1)
                                which.assert_not_called()
                                self.assertIn("requires an output directory", json.loads(err.getvalue())["error"])
                        self.assertFalse((root / "receipt.json").exists())
                        self.assertFalse((root / "receipt.json.logs").exists())

    def test_literal_tilde_and_normal_paths_keep_shell_false_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            argv = ["auto-re-cli", "report", "sample.bin", "--spill-dir", "~/literal"]
            result.write_text(json.dumps(document(argv)))
            prepared = runner.prepare_action(result, "next", None)
            self.assertEqual(prepared["argv"], argv)
            self.assertEqual(runner._command_sink_values(argv), [Path("~/literal").resolve()])


class ControlJsonFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="control-json-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "control.json"

    def test_regular_file_exact_limit_and_symlink(self):
        policy = runner.RECEIPT_POLICY._replace(max_encoded_bytes=32)
        self.path.write_bytes(b'{"n":1}' + b' ' * 25)
        self.assertEqual(runner.load_json_object(self.path, policy=policy), {"n": 1})
        if os.name == "posix":
            link = self.root / "link.json"
            link.symlink_to(self.path)
            self.assertEqual(runner.load_json_object(link, policy=policy), {"n": 1})
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with self.assertRaisesRegex(runner.ActionError, "control_file_too_large"):
            runner.load_json_object(self.path, policy=policy)

    def test_shape_nonobject_and_directory_are_domain_errors(self):
        for data, message in ((b'[]', "root must be an object"),
                              (b'{"a":[[[0]]]}', "control_file_structure_limit")):
            self.path.write_bytes(data)
            with self.subTest(data=data), self.assertRaisesRegex(runner.ActionError, message):
                runner.load_json_object(self.path, policy=runner.RECEIPT_POLICY._replace(max_depth=2))
        with self.assertRaises(runner.ActionError):
            runner.load_json_object(self.root)

    def test_descriptor_closed_on_success_and_each_io_failure(self):
        self.path.write_bytes(b'{}')
        real_open = os.open
        for stage in (None, "fstat", "fdopen", "read"):
            opened = []
            def tracked_open(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd
            with self.subTest(stage=stage), patch.object(runner.os, "open", side_effect=tracked_open):
                if stage is None:
                    self.assertEqual(runner.load_json_object(self.path), {})
                else:
                    owner, name = ((runner, "_read_bounded_control_bytes") if stage == "read"
                                   else (runner.os, stage))
                    with patch.object(owner, name, side_effect=OSError("injected IO failure")):
                        with self.assertRaisesRegex(runner.ActionError, "injected IO failure"):
                            runner.load_json_object(self.path)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_prior_rejection_follows_successful_version_and_hash_preflight(self):
        parent = self.root / "parent.json"
        parent.write_text(json.dumps(document(["auto-re-cli", "describe"])))
        prepared = runner.prepare_action(parent, "next", self.root / "analysis.json")
        executable = Path(sys.executable).resolve()
        with patch.object(runner, "probe_program_version", return_value="auto-re-cli 0.1.11") as probe, \
             patch.object(runner, "sha256_file", wraps=runner.sha256_file) as digest, \
             patch.object(runner.process_control, "run_process") as analysis:
            with self.assertRaises(runner.ActionError):
                runner.execute_prepared_with_receipt(prepared, executable,
                    self.root / "new-receipt.json", prior_receipt=self.root)
            probe.assert_called_once_with(executable)
            digest.assert_called_once_with(executable)
            analysis.assert_not_called()
        self.assert_no_analysis()

    def test_stream_gate_handles_growth_and_short_reads(self):
        policy = runner.RECEIPT_POLICY._replace(max_encoded_bytes=32)
        self.path.write_bytes(b'{}')
        original = runner._read_bounded_control_bytes
        def grow(handle, policy):
            with self.path.open("ab") as writer:
                writer.write(b' ' * 31)
            return original(handle, policy)
        with patch.object(runner, "_read_bounded_control_bytes", side_effect=grow):
            with self.assertRaisesRegex(runner.ActionError, "observed_at_least=33"):
                runner.load_json_object(self.path, policy=policy)
        class ShortReader(io.BytesIO):
            def read(self, size):
                return super().read(min(size, 2))
        self.assertEqual(original(ShortReader(b'{}'), policy), b'{}')

    def run_cli(self, *, prior=False, dry_run=False):
        cli = self.root / "auto-re-cli"
        cli.write_text(f"#!{sys.executable}\nimport pathlib,sys\n"
                       f"root = pathlib.Path({str(self.root)!r})\n"
                       "if '--version' in sys.argv:\n"
                       " (root / 'version-probed').write_text('yes')\n"
                       " print('auto-re-cli 0.1.11')\n"
                       "else:\n"
                       " (root / 'analysis-ran').write_text('yes')\n")
        cli.chmod(0o700)
        parent = self.path
        if prior:
            parent = self.root / "parent.json"
            parent.write_text(json.dumps(document(["auto-re-cli", "describe"])))
        argv = [sys.executable, "-B", str(SCRIPTS / "run_next_action.py"), str(parent),
                "--action-stage", "next", "--output", str(self.root / "analysis.json"),
                "--receipt", str(self.root / "new-receipt.json")]
        if prior:
            argv += ["--prior-receipt", str(self.path)]
        if dry_run:
            argv.append("--dry-run")
        return subprocess.run(argv, capture_output=True, text=True,
                              env={**os.environ, "PATH": str(self.root) + os.pathsep + os.environ.get("PATH", "")},
                              timeout=subprocess_timeout(5))

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_parent_normal_and_dry_run_rejected_without_writer(self):
        os.mkfifo(self.path)
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run):
                result = self.run_cli(dry_run=dry_run)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("regular file", json.loads(result.stderr)["error"])
                self.assertFalse((self.root / "version-probed").exists())
                self.assert_no_analysis()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_prior_after_version_probe_and_dry_run_without_read(self):
        os.mkfifo(self.path)
        result = self.run_cli(prior=True, dry_run=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["continuation_check"], "not_evaluated_dry_run")
        self.assertFalse((self.root / "version-probed").exists())
        self.assert_no_analysis()
        result = self.run_cli(prior=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("regular file", json.loads(result.stderr)["error"])
        self.assertTrue((self.root / "version-probed").exists())
        self.assert_no_analysis()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_with_writer_held_open_rejected_before_read(self):
        os.mkfifo(self.path)
        reader = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        writer = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, writer)
        os.write(writer, b'{}')
        for prior in (False, True):
            with self.subTest(prior=prior):
                result = self.run_cli(prior=prior)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("regular file", json.loads(result.stderr)["error"])
                self.assert_no_analysis()

    @unittest.skipUnless(os.name == "posix", "trusted POSIX executable fixture")
    def test_regular_parent_and_prior_reach_analysis(self):
        self.path.write_text(json.dumps(document(["auto-re-cli", "describe"])))
        result = self.run_cli(dry_run=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_no_analysis()
        for prior in (False, True):
            if prior:
                self.path.write_text(json.dumps({"schema_version": 1, "owner": "auto-re-skill",
                    "kind": "auto_re_action_execution_receipt"}))
            before = self.path.read_bytes()
            result = self.run_cli(prior=prior)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((self.root / "version-probed").exists())
            self.assertTrue((self.root / "analysis-ran").exists())
            self.assertEqual(self.path.read_bytes(), before)
            receipt = self.root / "new-receipt.json"
            receipt.chmod(0o600)
            receipt.unlink()
            shutil.rmtree(self.root / "new-receipt.json.logs")
            (self.root / "analysis-ran").unlink()

    def assert_no_analysis(self):
        for name in ("analysis-ran", "analysis.json", "new-receipt.json", "new-receipt.json.logs"):
            self.assertFalse((self.root / name).exists(), name)


class ProcessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.control = load("process_control")

    def run_program(self, code, **kwargs):
        options = dict(timeout_seconds=3, drain_seconds=0.2, grace_seconds=0.1,
                       reap_seconds=1, tail_bytes=128)
        options.update(kwargs)
        return self.control.run_process([sys.executable, "-u", "-c", code], **options)

    def assert_not_live(self, pid):
        path = Path(f"/proc/{pid}/stat")
        if sys.platform.startswith("linux") and path.exists():
            self.assertEqual(path.read_text().rsplit(")", 1)[1].split()[0], "Z")
        elif os.name == "posix":
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_success_captures_both_streams_with_tail_hashes(self):
        result = self.run_program("import os; os.write(1,b'a'*1000); os.write(2,b'b'*2000)", tail_bytes=16)
        self.assertEqual((result.status, result.returncode), ("completed", 0))
        for name, byte, count in (("stdout", b'a', 1000), ("stderr", b'b', 2000)):
            stream = getattr(result, name)
            self.assertEqual(stream.tail, byte * 16)
            self.assertEqual(stream.bytes_total, count)
            self.assertEqual(stream.sha256, hashlib.sha256(byte * count).hexdigest())
            self.assertTrue(stream.complete)
        self.assertTrue(result.leader_reaped)

    def test_normal_nonzero_exit_preserved(self):
        result = self.run_program("raise SystemExit(23)")
        self.assertEqual((result.status, result.returncode), ("completed", 23))

    def test_exact_combined_probe_budget(self):
        result = self.run_program("import os; os.write(1,b'a'*32); os.write(2,b'b'*32)",
                                  max_output_bytes=64, tail_bytes=64)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.stdout.bytes_total + result.stderr.bytes_total, 64)

    def test_stdout_stderr_and_combined_excess_stop_at_one_sentinel_byte(self):
        for code in ("import os; os.write(1,b'a'*1000000)",
                     "import os; os.write(2,b'b'*1000000)",
                     "import os; os.write(1,b'a'*32); os.write(2,b'b'*1000000)"):
            with self.subTest(code=code):
                result = self.run_program(code, max_output_bytes=64, tail_bytes=64)
                self.assertEqual(result.status, "output_limit")
                self.assertEqual(result.stdout.bytes_total + result.stderr.bytes_total, 65)
                self.assertLessEqual(len(result.stdout.tail) + len(result.stderr.tail), 64)
                self.assertTrue(result.leader_reaped)

    def test_timeout_reaps_sleeping_process(self):
        result = self.run_program("import time; time.sleep(60)", timeout_seconds=0.15)
        self.assertEqual(result.status, "timed_out")
        self.assertTrue(result.leader_reaped)

    @unittest.skipUnless(os.name == "posix", "POSIX signals")
    def test_ignored_term_escalates_to_kill(self):
        result = self.run_program("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)",
                                  timeout_seconds=2.0)
        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertTrue(result.leader_reaped)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group fixture")
    def test_exited_leader_with_descendant_holding_pipes_is_bounded(self):
        code = "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print(p.pid,flush=True)"
        result = self.run_program(code)
        self.assertEqual(result.status, "capture_failed")
        self.assertIn("pipe_drain_timeout", result.diagnostics)
        self.assertTrue(result.leader_reaped)
        self.assert_not_live(int(result.stdout.tail.strip()))

    def test_event_cancellation_reaps_process(self):
        event = threading.Event()
        timer = threading.Timer(0.15, event.set)
        timer.start()
        try:
            result = self.run_program("import time; time.sleep(60)", cancel_event=event)
        finally:
            timer.join()
        self.assertEqual(result.status, "cancelled")
        self.assertTrue(result.leader_reaped)

    def test_reader_error_is_reported_and_process_reaped(self):
        with patch.object(self.control, "_read_pipe", side_effect=OSError("injected reader failure")):
            result = self.run_program("import time; time.sleep(60)")
        self.assertEqual(result.status, "capture_failed")
        self.assertTrue(result.leader_reaped)
        self.assertTrue(any("injected reader failure" in item for item in result.diagnostics))

    def test_invalid_budgets_fail_before_spawn(self):
        for value in (0, -1, float('nan'), float('inf'), True, '1'):
            with self.subTest(value=value), patch.object(self.control.subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    self.run_program("pass", timeout_seconds=value)
                spawn.assert_not_called()

    def test_inherited_output_path_preserves_nonzero_and_timeout(self):
        self.assertEqual(self.run_program("raise SystemExit(7)", capture=False).returncode, 7)
        self.assertEqual(self.run_program("import time;time.sleep(60)", capture=False,
                                         timeout_seconds=0.15).status, "timed_out")


if __name__ == "__main__":
    unittest.main()
