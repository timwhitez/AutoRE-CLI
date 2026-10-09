"""Exact C1 admission against real P0 DTOs and producer-verified P1 forms."""
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kind_contract_runner", ROOT / "skills/auto-re/scripts/run_next_action.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
BUNDLE_SPEC = importlib.util.spec_from_file_location("kind_contract_bundle", ROOT / "skills/auto-re/scripts/verify_bundle.py")
bundle = importlib.util.module_from_spec(BUNDLE_SPEC)
BUNDLE_SPEC.loader.exec_module(bundle)
FIXTURE = json.loads((ROOT / "tests/fixtures/result_contract_0_1_10.json").read_text())
CASES = FIXTURE["cases"]


def dto(command, selected=False):
    return copy.deepcopy(next(row["result"] for row in CASES
        if row["command"] == command and ("derived_from" in row) == selected))


class ResultKindContractTests(unittest.TestCase):
    def reject(self, result, prefix):
        with self.assertRaisesRegex(runner.ActionError, "^" + prefix):
            runner.validate_result_contract(result)

    def test_real_and_producer_verified_supported_pairs(self):
        for row in CASES:
            with self.subTest(case=row["id"]):
                self.assertEqual(runner.validate_result_contract(row["result"]), row["label"])
                self.assertEqual(runner.validate_result_contract(row["result"], command=row["command"]), row["label"])
                if "derived_from" in row:
                    original = next(r["result"] for r in CASES if r["id"] == row["derived_from"])
                    self.assertEqual({k: v for k, v in row["result"].items() if k != "kind"}, original)
                    self.assertIn("producer-verified", row["provenance"])

    def test_kind_and_version_reject_before_shape_fallback(self):
        for row in CASES:
            for key, values, reason in (
                ("kind", (None, "", 1, True, [], {}, "future"), "unsupported_result_kind"),
                ("schema_version", (None, "", 1, True, [], {}, "0.2.0", "0.1.1"), "unsupported_result_version"),
            ):
                for value in values:
                    with self.subTest(case=row["id"], key=key, value=value):
                        self.reject({**row["result"], key: value}, reason)
            missing = dict(row["result"]); del missing["schema_version"]
            self.reject(missing, "unsupported_result_version")

    def test_exact_profiles_and_owner_presence(self):
        for row in CASES:
            for value in (None, "", [], {}, 1, True, "future", "full", "ai"):
                if value == row["result"].get("profile") and "profile" in row["result"]:
                    continue
                with self.subTest(case=row["id"], profile=value):
                    if row["command"] in ("call-graph", "data-xrefs") and value in ("ai", "full"):
                        continue
                    self.reject({**row["result"], "profile": value}, "invalid_result_profile")
            if "profile" in row["result"]:
                missing = dict(row["result"]); del missing["profile"]
                self.reject(missing, "invalid_result_profile")
            for value in (None, "", "auto-re-cli", [], {}):
                self.reject({**row["result"], "owner": value}, "invalid_result_boundary")

    def test_required_root_members_and_types(self):
        # Every baseline member except optional evidence must survive admission.
        optional = {"next_actions", "warnings", "current_findings", "global_string_samples",
                    "go_compiler_function", "rust_symbol_name_hint", "rust_source_context",
                    "slice_budget", "inferred_role", "package"}
        for row in CASES:
            for key in row["result"]:
                if row["command"] == "call-graph" and key == "stop_reasons": continue
                if key in optional | {"schema_version", "kind", "profile"}:
                    continue
                for mutation in ("absent", "wrong_type"):
                    result = copy.deepcopy(row["result"])
                    if mutation == "absent": del result[key]
                    else: result[key] = "wrong" if not isinstance(result[key], str) else []
                    with self.subTest(case=row["id"], key=key, mutation=mutation):
                        with self.assertRaises(runner.ActionError): runner.validate_result_contract(result)

    def test_legacy_and_selected_hybrids(self):
        mutations = (("function", {"basic_blocks": []}), ("dump-cfg", {"slice": {}}),
            ("slice-function", {"basic_blocks": []}), ("function", {"root": {}, "nodes": [], "edges": []}),
            ("dump-il", {"hlil_passes": []}), ("inspect-passes", {"level": "llil"}),
            ("report", {"flat": False}), ("decompile", {"sections": []}),
            ("inspect-go", {"rust": None}), ("inspect-rust", {"go": None}),
            ("inspect-die", {"binary": {}}), ("inspect-upx", {"function": {}}),
            ("call-graph", {"sections": []}), ("data-xrefs", {"level": "llil"}))
        for command, fields in mutations:
            for selected in (False, True) if command in ("function", "dump-cfg", "slice-function", "dump-il", "inspect-passes", "report", "decompile") else (False,):
                result = dto(command, selected); result.update(fields)
                with self.subTest(command=command, selected=selected):
                    self.reject(result, "invalid_result_fields" if "kind" in result else "ambiguous_legacy_result")
        for row in CASES:
            if row["command"] == "dump-il":
                for level in (None, "", "future", True, [], {}):
                    self.reject({**row["result"], "level": level}, "invalid_result_fields")
        for fields in ({"statements": []}, {"summary": {}}, {"semantic_ast": {}}):
            self.reject({**dto("dump-il"), **fields}, "ambiguous_legacy_result")

    def test_known_kind_cannot_relabel_another_family(self):
        for row in CASES:
            kind = "function_cfg" if row["command"] != "dump-cfg" else "function_detail"
            self.reject({**row["result"], "kind": kind}, "invalid_result_fields" if "profile" not in row["result"] else "invalid_result_profile")

    def test_data_xref_address_selectors_are_u64(self):
        for value in (-1, True, 2**64):
            result = dto("data-xrefs"); result["selector"] = {"kind": "data_address", "value": value}
            self.reject(result, "invalid_result_fields")
        result = dto("data-xrefs"); result["selector"] = {"kind": "data_address_range", "value": {"start": 0, "end": 2**64}}
        self.reject(result, "invalid_result_fields")

    def test_command_binding_is_independent_of_normalized_labels(self):
        for command, foreign in (("function", "dump-il"), ("function", "inspect-passes"),
                ("report", "decompile"), ("inspect-go", "inspect-rust"),
                ("inspect-upx", "inspect-vmp"), ("pe-resources", "pe-strings")):
            for row in CASES:
                if row["command"] == foreign:
                    with self.subTest(command=command, case=row["id"]):
                        with self.assertRaisesRegex(runner.ActionError, "^result_command_mismatch"):
                            runner.validate_result_contract(row["result"], command=command)

    def test_action_controls_are_validated_even_when_unselected(self):
        action = {"stage": "next", "reason": "inspect", "expected_output": "JSON", "stop_condition": "one", "argv": ["auto-re-cli", "function", "ret.bin"]}
        base = dto("function")
        for key in action:
            for value in (None, [], 1, ""):
                if key == "argv" and value == []: continue
                self.reject({**base, "next_actions": [{**action, key: value}]}, "invalid_result_boundary")
            missing = dict(action); del missing[key]
            self.reject({**base, "next_actions": [missing]}, "invalid_result_boundary")
        self.reject({**base, "next_actions": [action, action]}, "invalid_result_boundary")
        self.reject({**base, "next_actions": {}}, "invalid_result_fields")

    def test_additive_evidence_cannot_change_prepared_argv_or_sink(self):
        action = {"stage": "next", "reason": "inspect", "expected_output": "JSON", "stop_condition": "one", "argv": ["auto-re-cli", "function", "ret.bin"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "result.json"; sink = root / "next.json"
            for row in CASES:
                if row["command"] in ("data-xrefs", "pe-resources", "pe-strings"): continue
                result = {**row["result"], "next_actions": [action]}
                path.write_text(json.dumps(result))
                first = runner.prepare_action(path, "next", sink)
                result["future_evidence"] = {"kind": "unknown", "argv": ["execute"], "sink": "forbidden"}
                path.write_text(json.dumps(result))
                second = runner.prepare_action(path, "next", sink)
                self.assertEqual(first["argv"], second["argv"])
                self.assertEqual(first["command_owned_sink"], second["command_owned_sink"])

    def test_non_action_nested_evidence_and_unused_paging_are_passive(self):
        result = dto("function"); result["function"] = {"address": "unvalidated", "name": None}
        self.assertEqual(runner.validate_result_contract(result), "wrapper:function")
        result = dto("decompile"); result["summary"]["has_more"] = "unvalidated"
        self.assertEqual(runner.validate_result_contract(result), "profile:ai")

    def test_optional_top_level_types_numbers_sections_and_il_subshapes(self):
        for selected in (False, True):
            for field, value in (("inferred_role", None), ("rust_symbol_name_hint", {}), ("slice_budget", []), ("next_actions", None)):
                self.reject({**dto("function", selected), field: value}, "invalid_result_fields")
            for value in (0, -1, True, 1.5):
                self.reject({**dto("slice-function", selected), "slice_size": value}, "invalid_result_fields")
            for value in (["binary", "binary"], ["unknown"], [1]):
                self.reject({**dto("report", selected), "sections": value}, "invalid_result_fields")
        for row in CASES:
            if row["command"] != "dump-il": continue
            result = row["result"]
            fields = {"instructions": []} if result["level"] in ("hlil", "custom") else {"statements": []}
            self.reject({**result, **fields}, "invalid_result_fields" if "kind" in result else "ambiguous_legacy_result")
            if result["level"] == "custom":
                for field, value in (("statement_offset", -1), ("statement_limit", True), ("statement_address", 2**64), ("statements_truncated", 1)):
                    self.reject({**result, field: value}, "invalid_result_fields")

    def test_other_inventory_roots_remain_unsupported_and_reader_is_distinct(self):
        for kind in ("aarch64_reference_slices", "pe_runtime_function_bounds", "function_text_comparison", "static_byte_recovery", "byte_fold_candidate"):
            self.reject({**dto("function"), "kind": kind}, "unsupported_result_kind")
        self.assertIn("UNSUPPORTED, fail closed", FIXTURE["c0_p1"])

    def test_pe_legacy_paging_adapter_keeps_exact_argv(self):
        result = copy.deepcopy(next(row["result"] for row in CASES if row["id"] == "pe-strings-page"))
        self.assertEqual(len(result["next_actions"]), 1)
        self.assertNotIn("stage", result["next_actions"][0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "result.json"
            path.write_text(json.dumps(result))
            normalized = runner._pe_actions(result["next_actions"], "pe_strings")
            self.assertEqual(normalized[0]["argv"], result["next_actions"][0]["argv"])
            self.assertEqual(normalized[0]["stage"], "pe_strings.page")
            with self.assertRaisesRegex(runner.ActionError, "trusted auto-re-cli program"):
                runner.prepare_action(path, "pe_strings.page", root / "next.json")
        for reason in ("future", None):
            bad = copy.deepcopy(result); bad["next_actions"][0]["reason"] = reason
            self.reject(bad, "invalid_result_boundary")
        bad = copy.deepcopy(result); bad["next_actions"][0]["argv"][0] = "pe-resources"
        self.reject(bad, "invalid_result_boundary")

    def test_discriminator_errors_are_bounded_at_the_validator(self):
        for field in ("kind", "schema_version", "profile"):
            with self.subTest(field=field):
                with self.assertRaises(runner.ActionError) as caught:
                    runner.validate_result_contract({**dto("function"), field: "x" * 100000})
                self.assertLess(len(str(caught.exception)), 256)

    def test_real_manifests_keep_independent_integrity_boundary(self):
        for row in FIXTURE["manifests"]:
            with self.subTest(kind=row["label"]):
                self.assertEqual(runner.validate_result_contract(row["result"]), row["label"])
                with self.assertRaisesRegex(runner.ActionError, "^result_command_mismatch"):
                    runner.validate_result_contract(row["result"], command=row["command"])
                # Shape admission never verifies referenced files or their hashes.
                mutated = copy.deepcopy(row["result"]); mutated["files"][0]["sha256"] = "not-verified-here"
                self.assertEqual(runner.validate_result_contract(mutated), row["label"])

    def test_review_verifier_operational_outputs_are_not_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload = root / "payload.json"
            content = b'{"static_fixture":true}'
            payload.write_bytes(content)
            for row in FIXTURE["manifests"]:
                with self.subTest(kind=row["label"]):
                    manifest = {**row["result"], "files": [{"path": payload.name,
                        "ownership": "command", "bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()}]}
                    self.assertEqual(runner.validate_result_contract(manifest), row["label"])
                    passive = {**manifest, "warnings": [], "summary": {"note": "passive"}}
                    path = root / "manifest.json"; path.write_text(json.dumps(manifest))
                    output = bundle.validate_manifest(path)
                    try:
                        self.assertTrue({"verified_root", "cleanup_token", "consumption_contract"} <= output.keys())
                        self.reject(output, "invalid_result_boundary")
                    finally:
                        bundle.remove_verified_root(Path(output["verified_root"]))
                    self.assertEqual(payload.read_bytes(), content)
                    self.assertEqual(runner.validate_result_contract(passive), row["label"])

    def test_review_passive_warnings_preserve_function_argv_and_sink(self):
        action = {"stage": "next", "reason": "inspect", "expected_output": "JSON",
                  "stop_condition": "one", "argv": ["auto-re-cli", "function", "ret.bin"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "result.json"; sink = root / "next.json"
            for selected in (False, True):
                with self.subTest(selected=selected):
                    result = {**dto("function", selected), "next_actions": [action]}
                    path.write_text(json.dumps(result))
                    baseline = runner.prepare_action(path, "next", sink)
                    path.write_text(json.dumps({**result, "warnings": []}))
                    amended = runner.prepare_action(path, "next", sink)
                    self.assertEqual(baseline["argv"], amended["argv"])
                    self.assertEqual(baseline["command_owned_sink"], amended["command_owned_sink"])
                    self.assertEqual(baseline["result_wrapper"], amended["result_wrapper"])
                    self.assertFalse(sink.exists())

    def test_review_passive_shared_fields_do_not_define_another_family(self):
        for selected in (False, True):
            for field, value in (("summary", {}), ("budget", {}),
                                 ("current_findings", []), ("flat", False)):
                with self.subTest(selected=selected, field=field):
                    self.assertEqual(runner.validate_result_contract(
                        {**dto("function", selected), field: value}), "wrapper:function")

    def test_manifest_identity_tuples(self):
        for kind, profile in (("context_bundle", "ai"), ("agent_spill_manifest", None)):
            result = {"schema_version": "0.1.0", "kind": kind, "owner": "auto-re-cli", "files": []}
            if profile: result["profile"] = profile
            self.assertEqual(runner.validate_result_contract(result), "manifest:" + kind)
            wrong = dict(result)
            if profile: del wrong["profile"]
            else: wrong["profile"] = "ai"
            self.reject(wrong, "invalid_result_profile")
            self.reject({**result, "owner": None}, "invalid_result_boundary")
            self.reject({**result, "function": {}}, "invalid_result_fields")


class ResultJsonBoundaryTests(unittest.TestCase):
    def test_duplicates_nonfinite_and_invalid_utf8_reject_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            for encoded in (b'{"kind":"function_detail","kind":null}',
                    b'{"carried":{"duplicate":1,"duplicate":2}}',
                    b'{"carried":NaN}', b'{"carried":Infinity}', b'{"carried":1e999}',
                    b'{"carried":"\xff"}', b'{"carried":"\\ud800"}'):
                with self.subTest(encoded=encoded):
                    path.write_bytes(encoded)
                    with self.assertRaises(runner.ActionError): runner.load_json_object(path)
