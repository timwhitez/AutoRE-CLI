"""Pinned release identity coverage; inert bytes and mocked process control only."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "identity_runner", ROOT / "skills/auto-re/scripts/run_next_action.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
CONTRACT = json.loads((Path(__file__).parent / "fixtures/cli_identity_0_1_11.json").read_text())
VERSION = "auto-re-cli " + CONTRACT["version"]


class RequestIdentityContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input.bin"
        self.input.write_bytes(b"controlled static bytes")

    def identity(self, args, version=VERSION):
        return runner._request_identity_with_reason(
            ["auto-re-cli", *args], "a" * 64, version)

    def test_documented_commands_have_identity(self):
        for command in ("dump-il", "dump-cfg", "inspect-flow", "aarch64-refs", "function-bounds"):
            with self.subTest(command=command):
                self.assertIsNotNone(runner.request_identity(
                    ["auto-re-cli", command, str(self.input)], "a" * 64))

    def test_table_matches_committed_release_contract(self):
        self.assertEqual(runner.IDENTITY_CONTRACT_VERSION, CONTRACT["version"])
        self.assertEqual(runner.IDENTITY_COMMAND_CONTRACT, CONTRACT["commands"])
        self.assertEqual(runner.IDENTITY_GLOBAL_VALUE_OPTIONS, CONTRACT["global_value_options"])

    def test_every_single_input_command_and_option_arity(self):
        for command, shape in CONTRACT["commands"].items():
            if shape["classification"] != "single_input":
                continue
            with self.subTest(command=command):
                identity, reason = self.identity([command, str(self.input)])
                self.assertEqual(reason, "available")
                self.assertEqual(identity["input_bytes"], self.input.stat().st_size)
                self.assertEqual(identity["analysis_argv"][0], command)
            for flag in shape["value_options"]:
                with self.subTest(command=command, flag=flag):
                    # A selector resembling a path must never become the input.
                    args = [command, flag, str(self.root / "selector"), str(self.input)]
                    self.assertEqual(self.identity(args)[1], "available")
                    self.assertEqual(self.identity([command, flag + "=selector", str(self.input)])[1], "available")
            for flag in shape["switch_options"]:
                with self.subTest(command=command, flag=flag):
                    self.assertEqual(self.identity([command, flag, str(self.input)])[1], "available")

    def test_excluded_categories_and_unjustified_aliases(self):
        categories = set()
        for command, shape in CONTRACT["commands"].items():
            if shape["classification"] == "single_input":
                self.assertEqual(shape["aliases"], [])
                continue
            categories.add(shape["classification"])
            with self.subTest(command=command), patch.object(runner.os, "open") as opened:
                self.assertEqual(self.identity([command, str(self.input), str(self.input)])[1], "unsupported_command")
                opened.assert_not_called()
        self.assertEqual(categories, {"multi_input", "batch", "archive_replay", "metadata_no_input"})
        for command in ("cfg", "il", "inspect-aarch64-refs", "xrefs", "inspect-pe", "inspect-vmprotect", "arbitrary-command"):
            with self.subTest(command=command):
                self.assertEqual(self.identity([command, str(self.input)])[1], "unsupported_command")

    def test_global_placement_and_exact_projection(self):
        args = ["--output", "one.json", "function", "--symbol", str(self.root / "selector"),
                str(self.input), "--format=json"]
        first, reason = self.identity(args)
        self.assertEqual(reason, "available")
        self.assertEqual(first, self.identity(["--output=two.json", *args[2:]])[0])
        digest = hashlib.sha256(self.input.read_bytes()).hexdigest()
        self.assertEqual(first["analysis_argv"], ["function", "--symbol", str(self.root / "selector"),
                                                "<input-sha256>=" + digest, "--format=json"])
        self.assertNotEqual(first, self.identity(["function", str(self.input), "--symbol",
                                                 str(self.root / "selector"), "--format=json"])[0])
        self.assertEqual(self.identity(["--format", "json", "function", str(self.input)])[1], "unsupported_shape")

    def test_double_dash_and_sink_like_selector(self):
        dash_input = self.root / "-input"
        dash_input.write_bytes(b"leading-hyphen input")
        open_input = runner.os.open
        # Keep process CWD fixed while testing a relative leading-hyphen name.
        with patch.object(runner.os, "open", side_effect=lambda name, flags:
                          open_input(str(dash_input) if name == "-input" else name, flags)):
            value, reason = self.identity(["function", "--symbol=--output", "--output", "one.json", "--", "-input"])
        self.assertEqual(reason, "available")
        self.assertEqual(value["input_sha256"], hashlib.sha256(dash_input.read_bytes()).hexdigest())
        self.assertIn("--symbol=--output", value["analysis_argv"])
        self.assertIn("--", value["analysis_argv"])
        self.assertEqual(self.identity(["function", "-input"])[1], "unsupported_shape")
        self.assertEqual(self.identity(["function", "--", str(self.input), "--output", "one.json"])[1], "unsupported_shape")
        self.assertEqual(self.identity(["function", "--symbol", "--output", str(self.input)])[1], "unsupported_shape")

    def test_release_options_preserve_identity_and_no_progress(self):
        selected = ("function", "dump-cfg", "slice-function", "inspect-flow",
                    "dump-il", "inspect-passes", "decompile", "report")
        for command in selected:
            for prefix in (["--diagnostic-format", "json"], ["--diagnostic-format=json"]):
                with self.subTest(command=command, prefix=prefix):
                    args = [*prefix, "--output", "one.json", command,
                            "--result-contract", "kinds-v1", "--", str(self.input)]
                    identity, reason = self.identity(args)
                    self.assertEqual(reason, "available")
                    self.assertEqual(identity["analysis_argv"][:len(prefix)], prefix)
                    self.assertIn("--result-contract", identity["analysis_argv"])
                    self.assertIn("--", identity["analysis_argv"])
                    args[args.index("one.json")] = "two.json"
                    self.assertEqual(self.identity(args)[0], identity)
                    prior = {"request_identity": identity, "execution_status": "completed"}
                    with self.assertRaisesRegex(runner.ActionError, "no_progress"):
                        runner.assess_continuation(prior, identity, 60)
                    self.assertNotEqual(self.identity([a.replace("kinds-v1", "legacy") for a in args])[0], identity)
                    self.assertNotEqual(self.identity([a.replace("json", "text") for a in args])[0], identity)
            self.assertEqual(self.identity([command, "--diagnostic-format", "json",
                                           "--result-contract=kinds-v1", str(self.input)])[1], "available")
        for args in (["--diagnostic-format"], ["--diagnostic-format", "--output", "x"],
                     ["analyze", "--result-contract", "kinds-v1", str(self.input)],
                     ["function", "--", str(self.input), "--diagnostic-format=json"]):
            with self.subTest(args=args), patch.object(runner.os, "open") as opened:
                self.assertEqual(self.identity(args)[1], "unsupported_shape")
                opened.assert_not_called()

    def test_describe_never_hashes_input(self):
        for args in (["describe", "--format", "json"],
                     ["--diagnostic-format=json", "describe", "--format", "json", "--command", "function"]):
            with self.subTest(args=args), patch.object(runner.os, "open") as opened:
                self.assertEqual(self.identity(args)[1], "unsupported_command")
                opened.assert_not_called()

    def test_unknown_incomplete_or_extra_arguments_fail_closed(self):
        for args in (["function"], ["function", "--symbol"], ["function", str(self.input), str(self.input)],
                     ["function", "--unknown", str(self.input)], ["function", "--flat=true", str(self.input)],
                     ["function", "--execute", str(self.input)], ["function", "-h", str(self.input)]):
            with self.subTest(args=args), patch.object(runner.os, "open") as opened:
                self.assertEqual(self.identity(args)[1], "unsupported_shape")
                opened.assert_not_called()

    def test_unavailable_input_reasons(self):
        self.assertEqual(self.identity(["report", str(self.root / "missing")])[1], "input_unreadable")
        self.assertEqual(self.identity(["report", str(self.root)])[1], "input_nonregular")
        with patch.object(runner, "IDENTITY_INPUT_MAX_BYTES", 1):
            self.assertEqual(self.identity(["report", str(self.input)])[1], "input_too_large")
        with patch.object(runner.os, "open", side_effect=PermissionError):
            self.assertEqual(self.identity(["report", str(self.input)])[1], "input_unreadable")
        before = self.input.stat()
        after = type("ChangedStat", (), {"st_size": before.st_size, "st_mtime_ns": before.st_mtime_ns + 1,
                                          "st_ctime_ns": before.st_ctime_ns})()
        with patch.object(runner.os, "fstat", side_effect=[before, after]):
            self.assertEqual(self.identity(["report", str(self.input)])[1], "input_unstable")
        if hasattr(os, "mkfifo"):
            fifo = self.root / "fifo"
            os.mkfifo(fifo)
            self.assertEqual(self.identity(["report", str(fifo)])[1], "input_nonregular")

    def test_existing_projection_is_byte_stable_and_only_sinks_are_removed(self):
        digest = hashlib.sha256(self.input.read_bytes()).hexdigest()
        payload = {"input_sha256": digest, "input_bytes": self.input.stat().st_size,
                   "program_sha256": "a" * 64,
                   "analysis_argv": ["report", "<input-sha256>=" + digest, "--format", "json"]}
        expected = {**payload, "sha256": hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        for sinks in (["--output", "one.json"], ["--output=two.json"],
                      ["--bundle-dir", "bundle", "--output", "one.json"], ["--spill-dir=spill"]):
            with self.subTest(sinks=sinks):
                self.assertEqual(self.identity(["report", str(self.input), "--format", "json", *sinks])[0], expected)
        reordered = self.identity(["report", str(self.input), "--format=json"])[0]
        self.assertNotEqual(reordered, expected)

    def test_release_version_mismatch_does_not_hash_input(self):
        for version in ("auto-re-cli 0.1.9", "auto-re-cli 0.1.10", "auto-re-cli 0.1.12", "auto-re-cli 1.2.3", "", None):
            with self.subTest(version=version), patch.object(runner.os, "open") as opened:
                self.assertEqual(self.identity(["dump-il", str(self.input)], version)[1], "unsupported_command")
                opened.assert_not_called()

    def test_new_commands_preserve_no_progress_and_timeout_exception(self):
        for command in ("dump-il", "dump-cfg", "inspect-flow", "aarch64-refs", "function-bounds",
                        "dump-llvm", "inspect-passes", "recover-bytes", "fold-pair-bytes", "bench"):
            with self.subTest(command=command):
                identity, reason = self.identity([command, str(self.input)])
                self.assertEqual(reason, "available")
                prior = {"request_identity": identity, "execution_status": "completed", "exit_code": 124,
                         "leader_reaped": True, "timeout_seconds": 1.0}
                with self.assertRaisesRegex(runner.ActionError, "no_progress"):
                    runner.assess_continuation(prior, identity, 60)
                prior["execution_status"] = "timed_out"
                self.assertEqual(runner.assess_continuation(prior, identity, 60), "increased_timeout_after_timeout")
                for overrides, timeout in (({}, 1), ({"leader_reaped": False}, 60)):
                    with self.assertRaises(runner.ActionError):
                        runner.assess_continuation({**prior, **overrides}, identity, timeout)

    def test_execution_version_gate_keeps_admission_and_prior_reader(self):
        prepared = {"action_stage": "controlled.identity", "reason": "controlled", "expected_output": "JSON",
                    "stop_condition": "one static action", "command_owned_sink": False,
                    "argv": ["auto-re-cli", "dump-cfg", str(self.input), "--output", str(self.root / "out.json")]}
        empty = runner.CapturedStream(b"", 0, hashlib.sha256(b"").hexdigest())
        result = runner.process_control.ProcessResult(0, "completed", empty, empty, (), True)
        with patch.object(runner, "probe_program_version", return_value="auto-re-cli 0.1.10"), \
             patch.object(runner.process_control, "run_process", return_value=result) as run:
            code, summary = runner.execute_prepared_with_receipt(prepared, Path(sys.executable), self.root / "receipt.json")
        self.assertEqual(code, 0)
        run.assert_called_once()
        receipt = runner.validate_prior_receipt(runner.load_json_object(self.root / "receipt.json", policy=runner.RECEIPT_POLICY))
        self.assertIsNone(receipt["request_identity"])
        self.assertEqual(receipt["request_identity_unavailable_reason"], "unsupported_command")
        self.assertEqual(summary["continuation_check"], "not_requested")


if __name__ == "__main__":
    unittest.main()
