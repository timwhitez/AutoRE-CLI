"""Receipt producer/reader closure; only controlled Python fixtures execute."""
import argparse
import contextlib
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/auto-re/scripts"
spec = importlib.util.spec_from_file_location("admission_runner", SCRIPTS / "run_next_action.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReceiptAdmissionTests(unittest.TestCase):
    def prepared(self, root):
        return {"action_stage": "fixture", "reason": "static evidence",
                "expected_output": "bounded JSON", "stop_condition": "one run",
                "command_owned_sink": False,
                "argv": ["auto-re-cli", "report", str(root / "input.bin"),
                         "--output", str(root / "output.json")]}

    def roundtrip(self, path):
        return runner.validate_prior_receipt(runner.load_json_object(
            path, policy=runner.RECEIPT_POLICY))

    def test_metadata_rejected_before_probe_analysis_or_outputs(self):
        changes = [{field: "A" * 70000} for field in
                   ("reason", "expected_output", "stop_condition", "action_stage", "action_stage_source")]
        changes += [{"reason": "A" * 262144},
                    {field: "\U0001f600" * 15000 for field in
                     ("reason", "expected_output", "stop_condition")},
                    {"argv": ["auto-re-cli", "report", "missing", *(["--x"] * 1000),
                              "--output", "output.json"]},
                    {"argv": ["auto-re-cli", "report", "missing", "--symbol", "A" * 70000,
                              "--output", "output.json"]},
                    {"argv": ["auto-re-cli", "report", "missing", "--output", "A" * 70000]}]
        changes += [{"command_owned_sink": True,
                     "argv": ["auto-re-cli", "report", "missing", "--bundle-dir=" + "A" * 70000]}]
        for change in changes:
            with self.subTest(fields=list(change)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prepared = {**self.prepared(root), **change}
                with self.assertRaises(runner.ActionError):
                    runner.prepare_action_receipt_paths(prepared, root / "receipt.json")
                with patch.object(runner, "probe_program_version") as probe, \
                     patch.object(runner.process_control, "run_process") as process:
                    with self.assertRaises(runner.ActionError):
                        runner.execute_prepared_with_receipt(prepared, Path(sys.executable), root / "receipt.json")
                    probe.assert_not_called()
                    process.assert_not_called()
                self.assertEqual(list(root.iterdir()), [])

    def test_writer_shares_prior_shape_and_identity_validation(self):
        base = {"schema_version": 1, "owner": "auto-re-skill",
                "kind": "auto_re_action_execution_receipt", "request_identity": None}
        bad_values = ["A" * 65537, [0] * 1001, "A" * 70000]
        deep = 0
        for _ in range(16):
            deep = [deep]
        bad_values += [deep, [[0] * 1000 for _ in range(10)]]
        for value in bad_values:
            with self.subTest(type=type(value)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "receipt.json"
                with self.assertRaises(runner.ActionError):
                    runner._write_receipt(path, {**base, "metadata": value})
                self.assertFalse(path.exists())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with self.assertRaises(runner.ActionError):
                runner._write_receipt(path, {**base, "request_identity": {}})
            self.assertFalse(path.exists())
            with self.assertRaises(runner.ActionError):
                runner._write_receipt(path, {**base, "A" * 65537: 0})
            self.assertFalse(path.exists())

    def test_inclusive_shape_and_encoded_newline_boundaries(self):
        for value in ("A" * 65536, {"A" * 65536: 0}, [0] * 1000,
                      {str(i): [0] * 998 for i in range(10)}):
            runner._validate_json_shape(value, runner.RECEIPT_POLICY)
        deep = 0
        for _ in range(15):
            deep = [deep]
        runner._validate_json_shape(deep, runner.RECEIPT_POLICY)
        # Exact node boundary: root + nine arrays with 999 nodes + one with 999.
        nodes = [[0] * 999 for _ in range(9)] + [[0] * 998]
        runner._validate_json_shape(nodes, runner.RECEIPT_POLICY)
        nodes[-1].append(0)
        with self.assertRaises(runner.ActionError):
            runner._validate_json_shape(nodes, runner.RECEIPT_POLICY)
        base = {"schema_version": 1, "owner": "auto-re-skill",
                "kind": "auto_re_action_execution_receipt", "request_identity": None,
                "chunks": ["A" * 65000 for _ in range(4)], "padding": ""}
        encoded = len((json.dumps(base, indent=2, sort_keys=True) + "\n").encode())
        base["padding"] = "A" * (runner.RECEIPT_MAX_BYTES - encoded)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            runner._write_receipt(path, base)
            self.assertEqual(path.stat().st_size, runner.RECEIPT_MAX_BYTES)
            self.roundtrip(path)
            path.chmod(0o600)
            path.unlink()
            base["padding"] += "A"
            with self.assertRaises(runner.ActionError):
                runner._write_receipt(path, base)
            self.assertFalse(path.exists())

    def test_encoding_amplification_is_measured_in_final_json(self):
        for text in ("A" * 65536, "\U0001f600" * 16384,
                     "\x01" * 30000, '\\"' * 30000):
            with self.subTest(text=text[:2]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prepared = {**self.prepared(root), "reason": text}
                plan = runner.receipt_budget_plan(prepared, root / "receipt.json.logs")
                self.assertLessEqual(plan["encoded_upper_bound"], runner.RECEIPT_MAX_BYTES)
                self.assertGreaterEqual(plan["encoded_upper_bound"], len(json.dumps(text)))

    def test_all_dynamic_outcomes_roundtrip_and_fit_the_admitted_plan(self):
        control = runner.process_control
        for status in ("completed", "timed_out", "cancelled", "capture_failed", "cleanup_failed", "output_limit"):
            for code in (0, 23, None, -15):
                with self.subTest(status=status, code=code), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "input.bin").write_bytes(b"controlled input, never executed")
                    prepared = self.prepared(root)
                    stream = control.CapturedStream(b"", (1 << 64) - 1, "f" * 64, False)
                    result = control.ProcessResult(code, status, stream, stream,
                        tuple("capture_or_setup_failed: " + "\U0001f600" * 256 for _ in range(8)), code is not None)
                    program_sha = runner.sha256_file(Path(sys.executable).resolve())
                    plan = runner.receipt_budget_plan(prepared, root / "receipt.json.logs",
                        executable=str(Path(sys.executable).resolve()), program_version="auto-re-cli 0.1.10",
                        program_sha256=program_sha, identity=runner.request_identity(prepared["argv"], program_sha),
                        continuation_check="not_requested")
                    with patch.object(runner, "probe_program_version", return_value="auto-re-cli 0.1.10"), \
                         patch.object(control, "run_process", return_value=result):
                        runner.execute_prepared_with_receipt(prepared, Path(sys.executable), root / "receipt.json")
                    receipt = self.roundtrip(root / "receipt.json")
                    self.assertEqual(receipt["execution_status"], status)
                    self.assertEqual(receipt["stdout"]["bytes_total"], (1 << 64) - 1)
                    self.assertLessEqual((root / "receipt.json").stat().st_size, plan["encoded_upper_bound"])

    def test_input_change_writes_roundtrippable_unavailable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.bin"
            source.write_bytes(b"before")
            prepared = self.prepared(root)
            empty = runner.process_control.CapturedStream(b"", 0, hashlib.sha256(b"").hexdigest())
            def changed(*args, **kwargs):
                source.write_bytes(b"after")
                return runner.process_control.ProcessResult(0, "completed", empty, empty, (), True)
            with patch.object(runner, "probe_program_version", return_value="auto-re-cli 0.1.10"), \
                 patch.object(runner.process_control, "run_process", side_effect=changed):
                runner.execute_prepared_with_receipt(prepared, Path(sys.executable), root / "receipt.json")
            receipt = self.roundtrip(root / "receipt.json")
            self.assertIsNone(receipt["request_identity"])
            self.assertEqual(receipt["request_identity_unavailable_reason"], "input_unstable_after_execution")

    def test_entrypoint_rejects_known_invalid_fields_without_probes(self):
        for dry_run in (False, True):
            for field in ("reason", "expected_output", "stop_condition", "stage"):
                with self.subTest(dry_run=dry_run, field=field), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    action = {"stage": "next", "reason": "reason", "expected_output": "JSON",
                              "stop_condition": "one run", "argv": ["auto-re-cli", "report", "missing"]}
                    action[field] = "A" * 70000
                    parent = root / "parent.json"
                    parent.write_text(json.dumps({"schema_version": "0.1.0", "profile": "ai",
                        "binary": {}, "summary": {}, "next_actions": [action]}))
                    args = argparse.Namespace(result=parent, action_stage=action["stage"],
                        output=root / "analysis.json", receipt=root / "receipt.json",
                        prior_receipt=None, timeout_seconds=900, dry_run=dry_run)
                    with patch.object(runner, "parse_args", return_value=args), \
                         patch.object(runner.shutil, "which", return_value=sys.executable), \
                         patch.object(runner, "probe_program_version") as probe, \
                         patch.object(runner.process_control, "run_process") as process, \
                         contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(runner.main(), 1)
                        probe.assert_not_called()
                        process.assert_not_called()
                    self.assertEqual(list(root.iterdir()), [parent])

    def test_no_receipt_retains_large_action_result_metadata_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent.json"
            parent.write_text(json.dumps({"schema_version": "0.1.0", "profile": "ai",
                "binary": {}, "summary": {}, "next_actions": [{"stage": "next", "reason": "A" * 70000,
                "expected_output": "JSON", "stop_condition": "one run",
                "argv": ["auto-re-cli", "report", "missing"]}]}))
            args = argparse.Namespace(result=parent, action_stage="next", output=root / "analysis.json",
                receipt=None, prior_receipt=None, timeout_seconds=900, dry_run=True)
            output = io.StringIO()
            with patch.object(runner, "parse_args", return_value=args), contextlib.redirect_stdout(output):
                self.assertEqual(runner.main(), 0)
            self.assertEqual(len(json.loads(output.getvalue())["reason"]), 70000)
            self.assertEqual(runner.ACTION_RESULT_POLICY.max_encoded_bytes, 64 * 1024 * 1024)

    def test_finite_continuation_and_unavailable_identity_outcomes_fit_resolved_plan(self):
        control = runner.process_control
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = self.prepared(root)
            identity = runner._make_request_identity(prepared["argv"], "f" * 64, "f" * 64, 0)
            empty = control.CapturedStream(b"", 0, "f" * 64)
            captured = control.ProcessResult(0, "completed", empty, empty, (), True)
            for continuation in runner.CONTINUATION_CHECKS:
                plan = runner.receipt_budget_plan(prepared, root / "logs", executable="trusted-cli",
                    program_version="auto-re-cli 0.1.9", identity=identity,
                    continuation_check=continuation)
                for reason in runner.IDENTITY_REASONS | {None}:
                    for actual_identity in (None, identity):
                        value = runner._receipt_value(prepared, "trusted-cli", "auto-re-cli 0.1.9", "f" * 64,
                            actual_identity, reason, continuation, root / "logs", captured,
                            "2026-10-08T00:00:00Z", "2026-10-08T00:00:01Z", 1000, runner.LOG_TAIL_BYTES, 900.0)
                        path = root / "receipt.json"
                        runner._write_receipt(path, value)
                        self.roundtrip(path)
                        self.assertLessEqual(path.stat().st_size, plan["encoded_upper_bound"])
                        path.chmod(0o600)
                        path.unlink()

    def test_dynamic_generator_maxima_and_out_of_range_fail_without_clipping(self):
        control = runner.process_control
        maximum = runner.RECEIPT_UINT_MAX
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = self.prepared(root)
            stream = control.CapturedStream(b"", maximum, "f" * 64, False)
            def value(code=-maximum, duration=maximum, result_stream=stream):
                result = control.ProcessResult(code, "completed", result_stream, stream,
                    ("capture_or_setup_failed: " + "\U0001f600" * 256,) * 8, False)
                return runner._receipt_value(prepared, "trusted-cli", "auto-re-cli 0.1.9",
                    "f" * 64, None, "input_unstable_after_execution", "not_requested",
                    root / "logs", result, "9999-12-31T23:59:59.999999Z",
                    "9999-12-31T23:59:59.999999Z", duration, 0, sys.float_info.max)
            result = value()
            self.assertEqual(result["duration_ms"], maximum)
            self.assertEqual(result["exit_code"], maximum + 128)
            path = root / "receipt.json"
            runner._write_receipt(path, result)
            self.roundtrip(path)
            for kwargs in ({"duration": maximum + 1}, {"duration": -1},
                           {"code": maximum + 1}, {"code": -maximum - 1},
                           {"result_stream": control.CapturedStream(b"", maximum + 1, "f" * 64)},
                           {"result_stream": control.CapturedStream(b"x", 0, "f" * 64)}):
                with self.subTest(kwargs=kwargs), self.assertRaisesRegex(runner.ActionError, "dynamic invariant"):
                    value(**kwargs)
            for field, invalid in (("diagnostics", ["pipe_drain_timeout"] * 9),
                ("diagnostics", ["capture_or_setup_failed: " + "x" * 257]),
                ("started_at", "A" * 28), ("ended_at", "\U0001f600"),
                ("execution_status", "unknown"), ("continuation_check", "unknown"),
                ("request_identity_unavailable_reason", "unknown")):
                with self.subTest(field=field), self.assertRaisesRegex(runner.ActionError, "dynamic invariant"):
                    runner._validate_generated_receipt_fields({**result, field: invalid})

    def test_resolved_program_admission_is_before_analysis_and_file_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = {**self.prepared(root), "reason": "A" * 65536,
                        "expected_output": "A" * 65536, "stop_condition": "A" * 65536}
            plan = runner.receipt_budget_plan(prepared, root / "receipt.json.logs")
            prepared["action_stage"] += "A" * (runner.RECEIPT_MAX_BYTES - plan["encoded_upper_bound"])
            runner.prepare_action_receipt_paths(prepared, root / "receipt.json")
            version = "auto-re-cli " + "9" * (runner.PROGRAM_VERSION_MAX_BYTES - 16) + ".9.9"
            with patch.object(runner, "probe_program_version", return_value=version) as probe, \
                 patch.object(runner.process_control, "run_process") as process:
                with self.assertRaises(runner.ActionError):
                    runner.execute_prepared_with_receipt(prepared, Path(sys.executable), root / "receipt.json")
                probe.assert_called_once()
                process.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
