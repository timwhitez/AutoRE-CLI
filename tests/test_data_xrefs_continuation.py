"""Data-xref action contracts use controlled JSON and never run analyzed inputs."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "skills/auto-re/scripts/run_next_action.py"
RUST_FIXTURE = Path(__file__).with_name("fixtures") / "data_xrefs_contract.json"
SPEC = importlib.util.spec_from_file_location("data_xref_action_runner", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def document(input_path: Path) -> dict:
    return {
        "schema_version": "0.1.0", "kind": "data_xrefs", "profile": "ai",
        "direction": "code_to_data", "selector": {"kind": "all"},
        "budget": {}, "summary": {}, "records": [], "stop_reasons": [],
        "warnings": [], "next_actions": [
            {"stage": "data_xrefs.page", "reason": "record_limit",
             "argv": ["auto-re-cli", "data-xrefs", str(input_path), "--offset", "1",
                      "--format", "json", "--json-profile", "ai"],
             "expected_output": "next bounded page", "stop_condition": "no more records"},
            {"stage": "data_xrefs.provenance", "reason": "provenance_limit",
             "argv": ["auto-re-cli", "slice-function", str(input_path), "--addr", "0x401000",
                      "--slice-size", "32", "--format", "json"],
             "expected_output": "local slice", "stop_condition": "one local slice"},
        ],
    }


class DataXrefContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / "input.bin"
        self.input.write_bytes(b"controlled")

    def prepare(self, value: dict, stage: str = "data_xrefs.page") -> dict:
        path = self.root / "result.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return runner.prepare_action(path, stage, self.root / "next.json")

    def test_serialized_rust_fixture_prepares_both_stages(self):
        value = json.loads(RUST_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(value["summary"]["validated_count"], 1)
        self.assertEqual(value["summary"]["unresolved_count"], 1)
        for action in value["next_actions"]:
            self.assertEqual(action["argv"][2], "input.bin")
            action["argv"][2] = str(self.input)
        for legacy in (False, True):
            if legacy:
                for action in value["next_actions"]:
                    del action["stage"]
            for stage in ("data_xrefs.page", "data_xrefs.provenance"):
                prepared = self.prepare(value, stage)
                self.assertEqual(prepared["result_wrapper"], "wrapper:data_xrefs")
                self.assertEqual(prepared["action_stage_source"],
                                 "legacy_reason" if legacy else "explicit")
                self.assertIn("--raw-shellcode", prepared["argv"])

    def test_typed_wrapper_accepts_ai_full_and_both_directions(self):
        for profile in ("ai", "full"):
            for direction in ("code_to_data", "data_to_code"):
                with self.subTest(profile=profile, direction=direction):
                    value = document(self.input)
                    value.update(profile=profile, direction=direction)
                    self.assertEqual(runner.validate_result_contract(value),
                                     "wrapper:data_xrefs")
                    prepared = self.prepare(value)
                    self.assertEqual(prepared["action_stage"], "data_xrefs.page")
                    self.assertEqual(prepared["action_stage_source"], "explicit")
                    self.assertIn("--offset", prepared["argv"])
        value["selector"] = {"kind": "data_address_range",
                             "value": {"start": 1, "end": 2}}
        self.assertEqual(runner.validate_result_contract(value), "wrapper:data_xrefs")

    def test_legacy_stage_derives_only_from_known_reason_and_command(self):
        value = document(self.input)
        for item in value["next_actions"]:
            del item["stage"]
        page = self.prepare(value)
        provenance = self.prepare(value, "data_xrefs.provenance")
        self.assertEqual(page["action_stage_source"], "legacy_reason")
        self.assertEqual(provenance["action_stage_source"], "legacy_reason")
        self.assertEqual(page["argv"][1], "data-xrefs")
        self.assertEqual(provenance["argv"][1], "slice-function")
        self.assertEqual(runner.request_identity(page["argv"], "a" * 64),
                         runner.request_identity(self.prepare(document(self.input))["argv"], "a" * 64))

    def test_bad_stage_and_ambiguous_legacy_actions_fail_closed(self):
        for stage in (None, "", [], {}):
            with self.subTest(stage=stage):
                value = document(self.input)
                value["next_actions"][0]["stage"] = stage
                with self.assertRaises(runner.ActionError):
                    self.prepare(value)
        for change in ({"reason": "future_reason"},
                       {"argv": ["auto-re-cli", "function", str(self.input)]}):
            value = document(self.input)
            value["next_actions"][0].pop("stage")
            value["next_actions"][0].update(change)
            with self.subTest(change=change), self.assertRaises(runner.ActionError):
                self.prepare(value)
        value = document(self.input)
        value["next_actions"][1].pop("stage")
        value["next_actions"][1]["reason"] = "record_limit"
        value["next_actions"][1]["argv"][1] = "data-xrefs"
        with self.assertRaises(runner.ActionError):
            self.prepare(value)

        value = document(self.input)
        value["next_actions"] = []
        self.assertEqual(runner.validate_result_contract(value), "wrapper:data_xrefs")
        with self.assertRaisesRegex(runner.ActionError, "exactly one"):
            self.prepare(value)

    def test_malformed_wrapper_and_unsafe_selected_argv_fail_closed(self):
        for change in ({"owner": "foreign"}, {"kind": "foreign"},
                       {"profile": []}, {"profile": "future"},
                       {"warnings": [123]}, {"direction": "sideways"},
                       {"selector": {"kind": "unknown"}},
                       {"selector": {"kind": "data_address_range", "start": 1, "end": 2}}):
            value = {**document(self.input), **change}
            with self.subTest(change=change), self.assertRaises(runner.ActionError):
                self.prepare(value)
        for argv in (["other-cli", "data-xrefs", str(self.input)],
                     ["auto-re-cli", "data-xrefs", str(self.input), "--execute"],
                     ["auto-re-cli", "data-xrefs", str(self.input), "--output", "old.json"]):
            value = document(self.input)
            value["next_actions"][0]["argv"] = argv
            with self.subTest(argv=argv), self.assertRaises(runner.ActionError):
                self.prepare(value)


if __name__ == "__main__":
    unittest.main()
