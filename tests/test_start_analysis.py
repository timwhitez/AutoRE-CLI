#!/usr/bin/env python3
"""First-evidence launcher tests; the executable fixture is not the analyzer.

Run with: python3 -B -m unittest discover -s tests -p 'test_start_analysis.py' -v
These tests measure wrapper behavior, not model tool-use rates or Rust semantics.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "auto-re"


@unittest.skipUnless(os.name == "posix", "controlled shebang fixture requires POSIX")
class StartAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="autore-first-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.skill = self.root / "skill"
        shutil.copytree(SKILL, self.skill, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        self.launcher = self.skill / "scripts" / "start_analysis.py"
        self.samples = self.root / "samples"
        self.samples.mkdir()
        self.target = self.samples / "unknown ; echo NEVER.exe"
        self.marker = self.root / "TARGET_EXECUTED"
        self.target.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\n"
            f"Path({str(self.marker)!r}).write_text('must never happen')\n",
            encoding="utf-8",
        )
        self.target.chmod(0o700)
        self.original = self.target.read_bytes()
        self.output = self.root / "results"
        self.cli = self.root / "trusted-cli"
        version = (self.skill / "VERSION").read_text().strip()
        self.cli.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['AUTORE_TEST_EVENTS'], 'a') as f:\n"
            "    f.write(json.dumps(args) + '\\n')\n"
            "if args == ['--version']:\n"
            f"    print('auto-re-cli ' + os.environ.get('AUTORE_TEST_VERSION', {version!r}))\n"
            "    raise SystemExit(0)\n"
            "mode = os.environ.get('AUTORE_TEST_MODE', 'ok')\n"
            "if mode == 'fail':\n"
            "    print('controlled failure', file=sys.stderr)\n"
            "    raise SystemExit(7)\n"
            "if mode == 'missing':\n"
            "    raise SystemExit(0)\n"
            "output = pathlib.Path(args[args.index('--output') + 1])\n"
            "value = {'schema_version': '0.1.0', 'next_actions': [], 'warnings': []}\n"
            "if args[0] == 'function':\n"
            "    value.update(display_name='controlled', function={})\n"
            "else:\n"
            "    value.update(profile='ai', binary={}, summary={})\n"
            "if mode == 'wrong-shape':\n"
            "    value = {'unrelated': True}\n"
            "with output.open('x') as f:\n"
            "    f.write('{' if mode == 'invalid' else json.dumps(value))\n"
            "if mode == 'verbose':\n"
            "    print('x' * 70000)\n"
            "    print('y' * 90000, file=sys.stderr)\n",
            encoding="utf-8",
        )
        self.cli.chmod(0o700)
        self.events = self.root / "events.jsonl"
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = dict(os.environ)
        self.env.update(HOME=str(self.home), CODEX_HOME=str(self.home / ".codex"),
                        AUTORE_TEST_EVENTS=str(self.events), PYTHONDONTWRITEBYTECODE="1")
        self.env.pop("AUTORE_TEST_VERSION", None)
        self.env.pop("AUTORE_TEST_MODE", None)

    def invoke(self, *extra, cli=None, output=None, target=None):
        completed = subprocess.run(
            [sys.executable, str(self.launcher), str(target or self.target),
             "--result-dir", str(output or self.output), "--cli", str(cli or self.cli), *extra],
            cwd=self.root, env=self.env, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertFalse(self.marker.exists(), "target bytes executed")
        return completed

    def recorded(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def analysis_calls(self):
        return [args for args in self.recorded() if args != ["--version"]]

    def assert_blocked(self, completed):
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(self.analysis_calls(), [])
        self.assertFalse(self.output.exists())

    def test_default_collects_one_report_and_returns_evidence_paths(self):
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["analysis_executed"])
        self.assertTrue(result["readiness_checked"])
        self.assertFalse(result["investigation_complete"])
        self.assertTrue(Path(result["result_path"]).is_file())
        self.assertTrue(Path(result["receipt_path"]).is_file())
        calls = self.analysis_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ["report", str(self.target)])
        self.assertEqual(calls[0][calls[0].index("--limit") + 1], "8")
        self.assertIn("--json-profile", calls[0])
        self.assertEqual(calls[0][-2], "--output")

    def test_explicit_address_goes_directly_to_function(self):
        completed = self.invoke("--addr", "0x401000")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = self.analysis_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "function")
        self.assertIn("0x401000", calls[0])
        self.assertNotIn("--json-profile", calls[0])
        self.assertNotIn("--limit", calls[0])

    def test_symbol_and_input_metacharacters_are_literal_arguments(self):
        symbol = "decode ; touch SHOULD_NOT_EXIST"
        completed = self.invoke("--symbol", symbol)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(symbol, self.analysis_calls()[0])
        self.assertFalse((self.root / "SHOULD_NOT_EXIST").exists())

    def test_conflicting_function_selectors_are_rejected(self):
        self.assert_blocked(self.invoke("--addr", "1", "--symbol", "f"))

    def test_dry_run_does_not_probe_create_or_execute(self):
        completed = self.invoke("--dry-run", cli=self.root / "not-installed")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertFalse(result["readiness_checked"])
        self.assertFalse(result["analysis_executed"])
        self.assertEqual(result["argv"][0], "auto-re-cli")
        self.assertEqual(self.recorded(), [])
        self.assertFalse(self.output.exists())

    def test_raw_requires_architecture_and_base(self):
        self.assert_blocked(self.invoke("--raw-shellcode"))
        self.assertEqual(self.recorded(), [])

    def test_raw_arguments_are_preserved(self):
        completed = self.invoke("--raw-shellcode", "--arch", "x86_64", "--base-address", "0x1000", "--entry-address", "0x1010")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        args = self.analysis_calls()[0]
        for flag, value in [("--arch", "x86_64"), ("--base-address", "0x1000"), ("--entry-address", "0x1010")]:
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--raw-shellcode", args)

    def test_architecture_spellings_reach_selected_raw_function(self):
        for arch in ("x86", "x86_64", "x86-64", "aarch64"):
            with self.subTest(arch=arch):
                before = len(self.analysis_calls())
                completed = self.invoke(
                    "--raw-shellcode", "--arch", arch,
                    "--base-address", "0x1000", "--entry-address", "0x1010",
                    "--addr", "0x1010", output=self.root / ("results-" + arch),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                calls = self.analysis_calls()
                self.assertEqual(len(calls), before + 1)
                self.assertEqual(calls[-1][0], "function")
                for flag, value in (("--arch", arch), ("--base-address", "0x1000"),
                                    ("--entry-address", "0x1010"), ("--addr", "0x1010")):
                    self.assertEqual(calls[-1][calls[-1].index(flag) + 1], value)
                self.assertIn("--raw-shellcode", calls[-1])

    def test_hyphenated_architecture_dry_run_has_no_side_effects(self):
        completed = self.invoke(
            "--dry-run", "--raw-shellcode", "--arch", "x86-64",
            "--base-address", "0x1000", "--addr", "0x1000",
            cli=self.root / "not-installed",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["argv"][result["argv"].index("--arch") + 1], "x86-64")
        self.assertFalse(result["analysis_executed"])
        self.assertFalse(result["readiness_checked"])
        self.assertEqual(self.recorded(), [])
        self.assertFalse(self.output.exists())

    def test_unknown_architecture_is_rejected_before_cli_probe(self):
        self.assert_blocked(self.invoke(
            "--raw-shellcode", "--arch", "x86--64", "--base-address", "0x1000",
        ))
        self.assertEqual(self.recorded(), [])

    def test_non_raw_base_is_rejected(self):
        self.assert_blocked(self.invoke("--base-address", "0"))

    def test_negative_address_is_rejected(self):
        self.assert_blocked(self.invoke("--addr", "-1"))

    def test_address_overflow_is_rejected(self):
        self.assert_blocked(self.invoke("--addr", str(1 << 64)))

    def test_dynamic_flag_is_not_forwarded(self):
        self.assert_blocked(self.invoke("--execute"))

    def test_missing_input_is_rejected_before_cli_probe(self):
        self.assert_blocked(self.invoke(target=self.samples / "absent"))
        self.assertEqual(self.recorded(), [])

    def test_directory_input_is_rejected(self):
        self.assert_blocked(self.invoke(target=self.samples))

    def test_fifo_input_is_rejected_without_reading_it(self):
        fifo = self.samples / "fifo"
        os.mkfifo(fifo)
        self.assert_blocked(self.invoke(target=fifo))

    def test_existing_result_directory_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_text("unchanged")
        completed = self.invoke()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertEqual(self.recorded(), [])

    def test_output_symlink_is_preserved(self):
        self.output.symlink_to(self.root / "does-not-exist", target_is_directory=True)
        completed = self.invoke()
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(self.recorded(), [])

    def test_output_inside_input_directory_is_rejected(self):
        path = self.samples / "results"
        completed = self.invoke(output=path)
        self.assert_blocked(completed)
        error = json.loads(completed.stderr)["error"]
        self.assertIn("input file parent directory", error)
        self.assertIn("separate from samples", error)
        self.assertIn(f"result_dir={path.resolve()}", error)
        self.assertIn(f"input_dir={self.samples.resolve()}", error)
        self.assertEqual(self.recorded(), [])
        self.assertFalse(path.exists())

    def test_input_alias_diagnostic_uses_resolved_sample_directory(self):
        alias = self.root / "input-alias"
        alias.symlink_to(self.target)
        path = self.samples / "results"
        completed = self.invoke(target=alias, output=path)
        self.assert_blocked(completed)
        error = json.loads(completed.stderr)["error"]
        self.assertIn(f"result_dir={path.resolve()}", error)
        self.assertIn(f"input_dir={self.samples.resolve()}", error)
        self.assertEqual(self.recorded(), [])
        self.assertFalse(path.exists())

    def test_output_parent_alias_diagnostic_uses_resolved_directory(self):
        alias = self.root / "output-parent-alias"
        alias.symlink_to(self.samples, target_is_directory=True)
        path = alias / "results"
        completed = self.invoke(output=path)
        self.assert_blocked(completed)
        error = json.loads(completed.stderr)["error"]
        self.assertIn(f"result_dir={path.resolve()}", error)
        self.assertIn(f"input_dir={self.samples.resolve()}", error)
        self.assertNotIn(str(alias), error)
        self.assertEqual(self.recorded(), [])
        self.assertFalse(path.exists())

    def test_result_equal_to_input_parent_keeps_existing_path_guard(self):
        completed = self.invoke(output=self.samples)
        self.assert_blocked(completed)
        self.assertIn("already exists", completed.stderr)
        self.assertTrue(self.samples.is_dir())
        self.assertEqual(self.recorded(), [])

    def test_help_explains_result_directory_without_side_effects(self):
        completed = self.invoke("--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        text = " ".join(completed.stdout.split())
        self.assertIn("input file parent directory", text)
        self.assertIn("installed Skill", text)
        self.assertEqual(self.recorded(), [])
        self.assertFalse(self.output.exists())

    def test_output_inside_skill_is_rejected(self):
        path = self.skill / "results"
        self.assert_blocked(self.invoke(output=path))
        self.assertFalse(path.exists())

    def test_target_cannot_be_the_cli_even_for_version_probe(self):
        self.assert_blocked(self.invoke(cli=self.target))
        self.assertEqual(self.recorded(), [])

    def test_hardlinked_target_cannot_be_the_cli(self):
        alias = self.root / "target-alias"
        os.link(self.target, alias)
        self.assert_blocked(self.invoke(cli=alias))
        self.assertEqual(self.recorded(), [])

    def test_cli_unavailable_does_not_create_outputs(self):
        self.assert_blocked(self.invoke(cli=self.root / "missing-cli"))

    def test_version_mismatch_keeps_doctor_gate(self):
        self.env["AUTORE_TEST_VERSION"] = "999.0.0"
        completed = self.invoke()
        self.assert_blocked(completed)
        self.assertIn("agree", completed.stderr)

    def test_duplicate_registration_keeps_doctor_gate(self):
        duplicate = self.home / ".agents" / "skills" / "auto-re"
        duplicate.mkdir(parents=True)
        (duplicate / "SKILL.md").write_text("---\nname: auto-re\n---\n")
        completed = self.invoke()
        self.assert_blocked(completed)
        self.assertIn("duplicate", completed.stderr)

    def test_managed_content_drift_keeps_doctor_gate(self):
        (self.skill / ".autore-managed.json").write_text(json.dumps({
            "schema_version": 1, "kind": "skill-install", "skill": "auto-re",
            "version": (self.skill / "VERSION").read_text().strip(),
            "managed_files": ["SKILL.md"], "sha256": "0" * 64,
        }))
        completed = self.invoke()
        self.assert_blocked(completed)
        self.assertIn("drift", completed.stderr)

    def test_imports_do_not_mutate_managed_skill_inventory(self):
        files = sorted(p.relative_to(self.skill).as_posix() for p in self.skill.rglob("*") if p.is_file())
        digest = hashlib.sha256()
        for name in files:
            digest.update(name.encode() + b"\0")
            digest.update(hashlib.sha256((self.skill / name).read_bytes()).digest())
        (self.skill / ".autore-managed.json").write_text(json.dumps({
            "schema_version": 1, "kind": "skill-install", "skill": "auto-re",
            "version": (self.skill / "VERSION").read_text().strip(),
            "managed_files": files, "sha256": digest.hexdigest(),
        }))
        self.env.pop("PYTHONDONTWRITEBYTECODE", None)
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(list(self.skill.rglob("*.pyc")), [])

    def test_nonzero_cli_exit_is_preserved_with_receipt(self):
        self.env["AUTORE_TEST_MODE"] = "fail"
        completed = self.invoke()
        self.assertEqual(completed.returncode, 7, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertFalse(result["ok"])
        self.assertTrue(Path(result["receipt_path"]).exists())
        self.assertEqual(len(self.analysis_calls()), 1)

    def test_zero_exit_without_result_is_not_success(self):
        self.env["AUTORE_TEST_MODE"] = "missing"
        completed = self.invoke()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(len(self.analysis_calls()), 1)
        self.assertTrue((self.output / "receipts" / "initial.json").is_file())

    def test_invalid_json_is_not_success(self):
        self.env["AUTORE_TEST_MODE"] = "invalid"
        completed = self.invoke()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("JSON", completed.stderr)

    def test_unrelated_json_is_not_success(self):
        self.env["AUTORE_TEST_MODE"] = "wrong-shape"
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_noisy_cli_logs_are_bounded_and_not_returned_as_findings(self):
        self.env["AUTORE_TEST_MODE"] = "verbose"
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertLess(len(completed.stdout), 8192)
        summary = json.loads(completed.stdout)
        receipt = json.loads(Path(summary["receipt_path"]).read_text())
        self.assertEqual(receipt["evidence_boundary"], "operational_diagnostics_not_target_analysis_evidence")
        for stream in ["stdout", "stderr"]:
            self.assertTrue(receipt[stream]["truncated"])
            self.assertLessEqual(Path(receipt[stream]["path"]).stat().st_size, 16384)


class SkillEntrypointTests(unittest.TestCase):
    def test_action_first_description_is_bounded_and_specific(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        front = text.split("---", 2)[1].strip().splitlines()
        self.assertEqual({line.split(":", 1)[0] for line in front}, {"name", "description"})
        description = next(line.split(": ", 1)[1] for line in front if line.startswith("description:"))
        self.assertLessEqual(len(description), 400)
        self.assertIn("what does this executable do", description)
        self.assertIn("这个程序是干什么的", description)
        self.assertIn("start_analysis.py", text)
        self.assertLessEqual(len(text.splitlines()), 500)

    def test_implicit_invocation_and_evidence_prompt_remain_enabled(self):
        text = (SKILL / "agents/openai.yaml").read_text(encoding="utf-8")
        self.assertRegex(text, r"allow_implicit_invocation:\s*true")
        prompt = next(line for line in text.splitlines() if "default_prompt:" in line)
        self.assertIn("$auto-re", prompt)
        self.assertIn("collect static evidence", prompt)
        self.assertIn("never target-derived bytes", prompt)

    def test_trigger_corpus_retains_positive_negative_and_narrow_routes(self):
        data = json.loads((SKILL / "evals/trigger_cases.json").read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["kind"], "auto_re_skill_trigger_cases")
        cases = data["cases"]
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        self.assertGreaterEqual(sum(case["should_trigger"] for case in cases), 11)
        self.assertGreaterEqual(sum(not case["should_trigger"] for case in cases), 9)
        routes = {"report", "function", "dump-cfg", "pe-strings", "inspect-go", "diff"}
        for case in cases:
            self.assertIsInstance(case["should_trigger"], bool)
            self.assertTrue(case["reason"].strip())
            self.assertTrue(0 < len(case["prompt"]) <= 1000)
            if case["should_trigger"]:
                self.assertIn(case["expected_route"], routes)
            else:
                self.assertIsNone(case["expected_route"])
        self.assertIn("known_function", {case["id"] for case in cases})
        self.assertIn("no_tool_request", {case["id"] for case in cases})

    def test_all_helper_python_sources_compile_without_writing_bytecode(self):
        for path in (SKILL / "scripts").glob("*.py"):
            compile(path.read_bytes(), str(path), "exec")


if __name__ == "__main__":
    unittest.main()
