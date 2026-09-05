#!/usr/bin/env python3
"""One-shot routing and failure contracts, not model or engine effectiveness."""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

import test_start_analysis as fixtures


@unittest.skipUnless(os.name == "posix", "controlled analyzer fixture requires POSIX")
class FirstEvidenceContractTests(unittest.TestCase):
    # Reuse the fixture, not its test methods (no duplicate test accounting).
    setUp = fixtures.StartAnalysisTests.setUp
    invoke = fixtures.StartAnalysisTests.invoke
    recorded = fixtures.StartAnalysisTests.recorded
    analysis_calls = fixtures.StartAnalysisTests.analysis_calls
    assert_blocked = fixtures.StartAnalysisTests.assert_blocked

    def failure(self, mode):
        self.env["AUTORE_TEST_MODE"] = mode
        completed = self.invoke()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stdout, "")
        result = json.loads(completed.stderr)
        self.assertFalse(result["ok"])
        self.assertFalse(result["investigation_complete"])
        self.assertEqual(result["failure_phase"], "result_validation")
        self.assertEqual(result["result_validation"], "failed")
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["process_exit_code"], 0)
        self.assertTrue(result["analysis_executed"])
        self.assertTrue(result["readiness_checked"])
        receipt = Path(result["receipt_path"])
        self.assertTrue(receipt.is_file())
        self.assertEqual(Path(result["result_path"]), self.output / "analysis.json")
        stored = json.loads(receipt.read_text())
        self.assertEqual(stored["exit_code"], 0)
        self.assertEqual(stored["process_exit_code"], 0)
        for stream in ("stdout", "stderr"):
            self.assertTrue(Path(stored[stream]["path"]).is_file())
        self.assertEqual(len(self.analysis_calls()), 1)
        self.assertIn("receipt", result["next_step"])
        return result

    def inject_result(self, expression):
        """Alter only the controlled analyzer's output, never the target."""
        code = self.cli.read_text()
        old = "with output.open('x') as f:"
        self.assertEqual(code.count(old), 1)
        self.cli.write_text(code.replace(old, f"value = {expression}\n{old}"))

    def test_missing_output_preserves_execution_evidence(self):
        self.failure("missing")
        self.assertFalse((self.output / "analysis.json").exists())

    def test_invalid_json_preserves_execution_evidence(self):
        self.failure("invalid")
        self.assertEqual((self.output / "analysis.json").read_text(), "{")

    def test_unrecognized_json_preserves_execution_evidence(self):
        self.failure("wrong-shape")
        self.assertTrue((self.output / "analysis.json").is_file())

    def test_report_rejects_recognized_but_wrong_function_wrapper(self):
        self.inject_result("{'schema_version': '0.1.0', 'display_name': 'f', 'function': {}}")
        self.failure("ok")

    def test_function_rejects_ai_report_wrapper(self):
        self.inject_result("{'schema_version': '0.1.0', 'profile': 'ai', 'binary': {}, 'summary': {}}")
        completed = self.invoke("--addr", "0x10")
        self.assertEqual(completed.returncode, 1)
        result = json.loads(completed.stderr)
        self.assertEqual(result["failure_phase"], "result_validation")
        self.assertTrue(Path(result["receipt_path"]).is_file())
        self.assertEqual(len(self.analysis_calls()), 1)

    def test_report_rejects_manifest_in_place_of_document(self):
        self.inject_result("{'schema_version': '0.1.0', 'owner': 'auto-re-cli', 'kind': 'context_bundle', 'files': []}")
        self.failure("ok")

    def test_error_message_is_bounded(self):
        self.inject_result("{'schema_version': 'x' * 100000}")
        result = self.failure("ok")
        self.assertLessEqual(len(result["error"]), 600)

    def test_success_distinguishes_shape_validation_from_investigation(self):
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["result_validation"], "passed")
        self.assertEqual(result["result_wrapper"], "profile:ai")
        self.assertNotIn("failure_phase", result)
        self.assertFalse(result["investigation_complete"])

    def test_nonzero_execution_does_not_claim_result_validation(self):
        self.env["AUTORE_TEST_MODE"] = "fail"
        completed = self.invoke()
        self.assertEqual(completed.returncode, 7)
        result = json.loads(completed.stdout)
        self.assertEqual(result["result_validation"], "not_attempted")
        self.assertEqual(result["failure_phase"], "execution")
        self.assertEqual(result["process_exit_code"], 7)
        self.assertTrue(Path(result["receipt_path"]).exists())
        self.assertEqual(len(self.analysis_calls()), 1)

    def test_narrow_inspections_invoke_exactly_one_selected_command(self):
        commands = ("inspect-go", "inspect-rust", "inspect-die", "inspect-upx",
                    "inspect-vmp", "pe-strings", "pe-resources")
        for command in commands:
            with self.subTest(command=command):
                before = len(self.analysis_calls())
                completed = self.invoke("--command", command, output=self.root / command)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                calls = self.analysis_calls()[before:]
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][:2], [command, str(self.target)])
                self.assertEqual(calls[0][calls[0].index("--json-profile") + 1], "ai")
                self.assertEqual(calls[0][-2], "--output")
                self.assertNotIn("--sections", calls[0])
                result = json.loads(completed.stdout)
                self.assertEqual(result["result_validation"], "passed")
                self.assertTrue(Path(result["receipt_path"]).is_file())

    def test_explicit_function_routes_without_report(self):
        completed = self.invoke("--command", "function", "--symbol", "main")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.analysis_calls()[0][0], "function")
        self.assertNotIn("--json-profile", self.analysis_calls()[0])
        self.assertEqual(json.loads(completed.stdout)["result_wrapper"], "wrapper:function")

    def test_explicit_report_keeps_default_budget(self):
        completed = self.invoke("--command", "report")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        args = self.analysis_calls()[0]
        self.assertEqual(args[0], "report")
        self.assertEqual(args[args.index("--limit") + 1], "8")

    def test_invalid_command_combinations_fail_before_probe(self):
        cases = (("--command", "function"),
                 ("--command", "report", "--addr", "1"),
                 ("--command", "inspect-go", "--symbol", "main"),
                 ("--command", "pe-resources", "--arch", "x86"),
                 ("--command", "pe-resources", "--raw-shellcode", "--arch", "x86", "--base-address", "0"),
                 ("--command", "report;echo PWN"), ("--command", "execute"))
        for args in cases:
            with self.subTest(args=args):
                self.assert_blocked(self.invoke(*args))
                self.assertEqual(self.recorded(), [])

    def test_narrow_dry_run_never_probes_or_creates_output(self):
        completed = self.invoke("--command", "inspect-rust", "--dry-run", cli=self.root / "missing")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["argv"][1], "inspect-rust")
        self.assertFalse(result["analysis_executed"])
        self.assertEqual(result["result_validation"], "not_attempted")
        self.assertFalse(self.output.exists())
        self.assertEqual(self.recorded(), [])

    def test_narrow_command_keeps_cli_identity_gate(self):
        self.assert_blocked(self.invoke("--command", "inspect-go", cli=self.target))
        self.assertEqual(self.recorded(), [])

    def test_narrow_command_keeps_readiness_gate(self):
        self.env["AUTORE_TEST_VERSION"] = "999.0.0"
        self.assert_blocked(self.invoke("--command", "pe-strings"))

    def test_narrow_command_preserves_supported_raw_context(self):
        completed = self.invoke("--command", "inspect-die", "--raw-shellcode", "--arch", "x86",
                                "--base-address", "0x1000", "--entry-address", "0x1010")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        args = self.analysis_calls()[0]
        for flag, value in (("--arch", "x86"), ("--base-address", "0x1000"), ("--entry-address", "0x1010")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--raw-shellcode", args)

    def test_timeout_is_execution_failure_not_invalid_result(self):
        self.cli.write_text(self.cli.read_text().replace(
            "mode = os.environ.get('AUTORE_TEST_MODE', 'ok')", "import time\ntime.sleep(5)"))
        completed = self.invoke("--command", "inspect-go", "--timeout-seconds", "0.5")
        self.assertEqual(completed.returncode, 124, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["execution_status"], "timed_out")
        self.assertEqual(result["result_validation"], "not_attempted")
        self.assertEqual(result["failure_phase"], "execution")
        self.assertTrue(Path(result["receipt_path"]).is_file())
        self.assertEqual(len(self.analysis_calls()), 1)


if __name__ == "__main__":
    unittest.main()
