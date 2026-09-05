"""Full-module integration checks. Only controlled Python fixture programs run."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/auto-re/scripts"


def load(name):
    spec = importlib.util.spec_from_file_location("integration_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("run_next_action")
doctor = load("skill_doctor")
control = runner.process_control


class ReceiptTests(unittest.TestCase):
    def prepared(self, root, code):
        return {"action_stage": "controlled.fixture", "reason": "test orchestration",
                "expected_output": "fixture diagnostics", "stop_condition": "one fixture exits",
                "command_owned_sink": False,
                "argv": [runner.TRUSTED_PROGRAM, "-c", code, "--output", str(root / "analysis.json")]}

    def execute(self, root, code, **kwargs):
        with patch.object(runner, "probe_program_version", return_value="auto-re-cli 0.1.3"):
            status, summary = runner.execute_prepared_with_receipt(
                self.prepared(root, code), Path(sys.executable), root / "receipt.json", **kwargs)
        receipt = json.loads((root / "receipt.json").read_text())
        self.assertEqual(receipt["exit_code"], status)
        self.assertEqual(receipt["execution_status"], summary["execution_status"])
        self.assertTrue(receipt["leader_reaped"])
        for stream in ("stdout", "stderr"):
            data = Path(receipt[stream]["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), receipt[stream]["retained_sha256"])
            self.assertEqual(len(data), receipt[stream]["bytes_retained"])
        return status, summary, receipt

    def test_success_nonzero_and_bounded_tails(self):
        for code in (0, 23):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                result, _, receipt = self.execute(Path(directory),
                    f"import os;os.write(1,b'a'*70000);os.write(2,b'b'*80000);raise SystemExit({code})",
                    log_tail_bytes=31)
                self.assertEqual(result, code)
                self.assertEqual(receipt["process_exit_code"], code)
                self.assertEqual(receipt["execution_status"], "completed")
                for name, expected in (("stdout", b'a'*70000), ("stderr", b'b'*80000)):
                    item = receipt[name]
                    self.assertTrue(item["truncated"])
                    self.assertTrue(item["capture_complete"])
                    self.assertEqual(item["digest_scope"], "complete_stream")
                    self.assertEqual(item["sha256"], hashlib.sha256(expected).hexdigest())
                    self.assertEqual(item["bytes_retained"], 31)

    def test_timeout_receipt_preserves_partial_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import pathlib,sys,time;pathlib.Path(sys.argv[-1]).write_text('partial');print('before timeout',flush=True);time.sleep(60)"
            status, _, receipt = self.execute(root, code, timeout_seconds=1.0)
            self.assertEqual(status, 124)
            self.assertEqual(receipt["execution_status"], "timed_out")
            self.assertEqual((root / "analysis.json").read_text(), "partial")
            self.assertIn(b"before timeout", Path(receipt["stdout"]["path"]).read_bytes())
            self.assertEqual(receipt["timeout_seconds"], 1.0)

    def test_capture_failure_retains_an_operational_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(control, "_read_pipe", side_effect=OSError("injected read failure")):
                status, _, receipt = self.execute(Path(directory), "import time;time.sleep(60)")
            self.assertEqual(status, 125)
            self.assertEqual(receipt["execution_status"], "capture_failed")
            self.assertTrue(receipt["diagnostics"])
            self.assertFalse(receipt["stdout"]["capture_complete"])
            self.assertEqual(receipt["stdout"]["digest_scope"], "observed_prefix")

    def test_invalid_timeout_is_rejected_before_probe_or_files(self):
        for value in (0, -1, True, float("nan"), float("inf"), 10**1000):
            with self.subTest(value=str(type(value))), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.object(runner, "probe_program_version") as probe:
                    with self.assertRaises(runner.ActionError):
                        runner.execute_prepared_with_receipt(self.prepared(root, "pass"),
                            Path(sys.executable), root / "receipt.json", timeout_seconds=value)
                    probe.assert_not_called()
                self.assertEqual(list(root.iterdir()), [])

    def test_signal_exit_code_mapping_is_not_wrapped_modulo_256(self):
        empty = control.CapturedStream(b"", 0, hashlib.sha256(b"").hexdigest())
        result = control.ProcessResult(-15, "completed", empty, empty, (), True)
        self.assertEqual(runner.execution_exit_code(result), 143)

    @unittest.skipUnless(os.name == "posix", "POSIX signal integration requires POSIX")
    def test_sigint_and_sigterm_write_cancelled_receipts(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=number), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                started = root / "started"
                cli = root / "auto-re-cli"
                cli.write_text(f"#!{sys.executable}\nimport sys,os,time,pathlib\n"
                    "if '--version' in sys.argv:\n print('auto-re-cli 0.1.3');raise SystemExit(0)\n"
                    f"pathlib.Path({str(started)!r}).write_text(str(os.getpid()))\n"
                    "print('started',flush=True)\ntime.sleep(60)\n")
                cli.chmod(0o700)
                parent = root / "result.json"
                parent.write_text(json.dumps({"schema_version": "0.1.0", "profile": "ai",
                    "binary": {}, "summary": {}, "next_actions": [{"stage": "fixture", "reason": "test",
                    "expected_output": "fixture", "stop_condition": "one run",
                    "argv": [runner.TRUSTED_PROGRAM, "fixture"]}]}))
                env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ.get("PATH", ""))
                process = subprocess.Popen([sys.executable, "-B", str(SCRIPTS / "run_next_action.py"),
                    str(parent), "--action-stage", "fixture", "--output", str(root / "analysis.json"),
                    "--receipt", str(root / "receipt.json")], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic()+10
                    while not started.exists() and process.poll() is None and time.monotonic()<deadline:
                        time.sleep(0.01)
                    self.assertTrue(started.exists(), "controlled child did not start")
                    process.send_signal(number)
                    out, err = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 130, err.decode(errors="replace"))
                    self.assertEqual(json.loads(out)["execution_status"], "cancelled")
                    receipt = json.loads((root / "receipt.json").read_text())
                    self.assertEqual(receipt["execution_status"], "cancelled")
                    self.assertTrue(receipt["leader_reaped"])
                    self.assertNotIn(b"Traceback", err)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=10)
                    if started.exists():
                        with contextlib.suppress(ProcessLookupError):
                            os.kill(int(started.read_text()), signal.SIGKILL)


class ProbeTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "executable shebang fixtures require POSIX")
    def test_entrypoint_probes_strict_utf8_exit_and_combined_limits(self):
        cases = [("import os;os.write(1,b'auto-re-cli 0.1.3'+b' '*(4096-len(b'auto-re-cli 0.1.3')))", True),
                 ("import os;os.write(1,b'auto-re-cli 0.1.3'+b' '*(4097-len(b'auto-re-cli 0.1.3')))", False),
                 ("import os;os.write(2,b'auto-re-cli 0.1.3')", True),
                 ("import os;os.write(1,b'auto-re-cli ');os.write(2,b'0.1.3')", True),
                 ("import os;os.write(1,b'\\xff')", False),
                 ("print('auto-re-cli 0.1.3');raise SystemExit(7)", False),
                 ("pass", False), ("print('wrong-product 0.1.3')", False)]
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "fixture-cli"
            for body, accepted in cases:
                executable.write_text(f"#!{sys.executable}\n{body}\n")
                executable.chmod(0o700)
                for module, name, expected in ((runner, "probe_program_version", "auto-re-cli 0.1.3"),
                        (doctor, "probe_cli_version", ("0.1.3", "auto-re-cli 0.1.3"))):
                    with self.subTest(body=body, module=module.__name__):
                        if accepted:
                            self.assertEqual(getattr(module, name)(executable), expected)
                        else:
                            error = runner.ActionError if module is runner else doctor.DoctorError
                            with self.assertRaises(error):
                                getattr(module, name)(executable)

    def test_internal_job_gate_blocks_execution_until_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/"started"
            argv = [sys.executable, "-B", str(SCRIPTS / "process_control.py"), "--job-worker",
                    sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).write_text('ok')"]
            for gate, expected in ((b"", 125), (b"x", 125), (b"1", 0)):
                result = subprocess.run(argv, input=gate, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(marker.exists(), gate == b"1")
                marker.unlink(missing_ok=True)

    def test_managed_imports_do_not_create_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("run_next_action.py", "skill_doctor.py", "process_control.py"):
                (root/name).write_bytes((SCRIPTS/name).read_bytes())
            for name in ("run_next_action.py", "skill_doctor.py"):
                result = subprocess.run([sys.executable, str(root/name), "--help"],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root/"__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
