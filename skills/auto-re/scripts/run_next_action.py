#!/usr/bin/env python3
"""Validate and run one emitted Auto-RE static next action."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import shutil
import stat
import subprocess  # retained test seam; lifecycle is owned by process_control
import sys
import time
from datetime import datetime, timezone
from typing import Any, BinaryIO, NamedTuple, Optional


# Import only the helper shipped beside this script, not a module from CWD/PATH.
# Managed Skill inventories must not acquire import-time bytecode files.
sys.dont_write_bytecode = True
_PROCESS_SPEC = importlib.util.spec_from_file_location(
    "auto_re_process_control", pathlib.Path(__file__).with_name("process_control.py")
)
assert _PROCESS_SPEC is not None and _PROCESS_SPEC.loader is not None
process_control = importlib.util.module_from_spec(_PROCESS_SPEC)
_PROCESS_SPEC.loader.exec_module(process_control)
DEFAULT_TIMEOUT_SECONDS = process_control.DEFAULT_TIMEOUT_SECONDS

TRUSTED_PROGRAM = "auto-re-cli"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"0.1.0"})
SUPPORTED_PROFILES = frozenset({"ai"})
SUPPORTED_MANIFEST_KINDS = frozenset({"context_bundle", "agent_spill_manifest"})
# Audited CLI contract, not an execution authorization list. Keep the release
# fixture and source Clap drift test in sync when auditing another version.
IDENTITY_CONTRACT_VERSION = "0.1.11"
IDENTITY_GLOBAL_VALUE_OPTIONS = ["--output", "--diagnostic-format"]
IDENTITY_COMMAND_CONTRACT = {
    "aarch64-refs": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--address --arch --base-address --entry-address --format --function --function-addr "
            "--instruction-limit --json-profile --limit --max-functions --max-input-bytes "
            "--max-instructions-per-function --offset --output --spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "analyze": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --max-functions --max-input-bytes "
            "--max-instructions-per-function --output --spill-dir --style --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "archive": {"classification": "archive_replay", "aliases": []},
    "batch": {"classification": "batch", "aliases": []},
    "batch-diff": {"classification": "batch", "aliases": []},
    "batch-replay": {"classification": "batch", "aliases": []},
    "bench": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --iterations --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --style --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "call-graph": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --depth --edge-limit --entry-address --format "
            "--json-profile --max-functions --max-input-bytes --max-instructions-per-function "
            "--node-limit --output --spill-dir --symbol --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "compare-functions": {"classification": "multi_input", "aliases": []},
    "data-xrefs": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--address --address-end --arch --base-address --direction --entry-address --format "
            "--function --function-addr --global --json-profile --limit --max-functions "
            "--max-input-bytes --max-instructions-per-function --offset --output --provenance-limit "
            "--spill-dir --string --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "decompile": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --function-offset --json-profile "
            "--limit --max-functions --max-input-bytes --max-instructions-per-function "
            "--max-output-lines --output --spill-dir --style --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--flat --include-noise --raw-shellcode --split-output".split(),
    },
    "describe": {"classification": "metadata_no_input", "aliases": []},
    "diff": {"classification": "archive_replay", "aliases": []},
    "dump-cfg": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --entry-address --format --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --symbol --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "dump-il": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --entry-address --format --level --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir "
            "--statement-address --statement-contains --statement-limit --statement-offset --symbol --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--flat --raw-shellcode".split(),
    },
    "dump-llvm": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --entry-address --max-functions --max-input-bytes "
            "--max-instructions-per-function --output --spill-dir --symbol --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "fold-pair-bytes": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": "--output --spill-dir --diagnostic-format".split(),
        "switch_options": "".split(),
    },
    "function": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --entry-address --format --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --style "
            "--symbol --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--flat --raw-shellcode".split(),
    },
    "function-bounds": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": "--addr --format --max-input-bytes --output --spill-dir --diagnostic-format".split(),
        "switch_options": "".split(),
    },
    "help": {"classification": "metadata_no_input", "aliases": []},
    "inspect-die": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --json-profile --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-flow": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --depth --entry-address --format --max-functions "
            "--max-input-bytes --max-instructions-per-function --node-limit --output "
            "--per-node-limit --spill-dir --symbol --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-go": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --function-offset --json-profile "
            "--limit --max-functions --max-input-bytes --max-instructions-per-function --output "
            "--spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-passes": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --entry-address --format --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --symbol --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-rust": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --function-offset --json-profile "
            "--limit --max-functions --max-input-bytes --max-instructions-per-function --output "
            "--spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-types": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --max-functions --max-input-bytes "
            "--max-instructions-per-function --output --scalar-evidence-limit "
            "--scalar-evidence-offset --spill-dir --variable-function-limit "
            "--variable-function-offset --variable-hint-limit --variable-hint-offset --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-upx": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --json-profile --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "inspect-vmp": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --entry-address --format --json-profile --max-functions "
            "--max-input-bytes --max-instructions-per-function --output --spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "pe-resources": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--decoded-characters --format --json-profile --limit --max-input-bytes --offset "
            "--output --reference-provenance --resource-depth --resource-entries "
            "--resource-payload-bytes --scan-bytes --spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "".split(),
    },
    "pe-strings": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --decoded-characters --entry-address --format --json-profile "
            "--limit --max-functions --max-input-bytes --max-instructions-per-function --offset "
            "--output --reference-provenance --resource-depth --resource-entries "
            "--resource-payload-bytes --scan-bytes --spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
    "recover-bytes": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --max-functions --max-input-bytes --max-instructions-per-function --output "
            "--spill-dir --diagnostic-format"
        ).split(),
        "switch_options": "".split(),
    },
    "replay": {"classification": "archive_replay", "aliases": []},
    "report": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--arch --base-address --bundle-dir --entry-address --flow-depth --flow-node-limit "
            "--flow-per-node-limit --format --function-offset --json-profile --limit "
            "--max-functions --max-input-bytes --max-instructions-per-function --max-output-lines "
            "--output --sections --spill-dir --style --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--flat --include-noise --raw-shellcode --split-output".split(),
    },
    "slice-function": {
        "classification": "single_input", "aliases": [], "input_position": 1,
        "value_options": (
            "--addr --arch --base-address --contains-call --contains-string --entry-address "
            "--format --max-functions --max-input-bytes --max-instructions-per-function --output "
            "--slice-index --slice-size --slice-start --spill-dir --style --symbol --diagnostic-format --result-contract"
        ).split(),
        "switch_options": "--raw-shellcode".split(),
    },
}
FORBIDDEN_FLAGS = {"--execute"}
COMMAND_OWNED_SINK_FLAGS = {"--bundle-dir", "--spill-dir"}
CONTROL_READ_CHUNK_BYTES = 64 * 1024
LOG_TAIL_BYTES = 1024 * 1024
RECEIPT_MAX_BYTES = 256 * 1024
PROGRAM_VERSION_MAX_BYTES = 4096
PROGRAM_VERSION_PATTERN = re.compile(r"^auto-re-cli [0-9]+\.[0-9]+\.[0-9]+$")


class ControlJsonPolicy(NamedTuple):
    kind: str
    max_encoded_bytes: int
    max_depth: int
    max_values: int
    max_container_entries: int
    max_string_bytes: int


ACTION_RESULT_POLICY = ControlJsonPolicy(
    "action_result",
    64 * 1024 * 1024,
    64,
    2_000_000,
    500_000,
    16 * 1024 * 1024,
)
RECEIPT_POLICY = ControlJsonPolicy("prior_receipt", RECEIPT_MAX_BYTES, 16, 10000, 1000, 65536)
RECEIPT_UINT_MAX = (1 << 64) - 1
IDENTITY_INPUT_MAX_BYTES = 512 * 1024 * 1024
IDENTITY_REASONS = frozenset({"unsupported_command", "unsupported_shape", "input_nonregular",
    "input_too_large", "input_unstable", "input_unreadable", "available",
    "input_unstable_after_execution"})
CONTINUATION_CHECKS = frozenset({"not_requested", "not_evaluated_unavailable_identity",
    "changed_analysis", "increased_timeout_after_timeout"})


class ActionError(ValueError):
    pass


CapturedStream = process_control.CapturedStream


def _control_file_too_large(policy: ControlJsonPolicy, observed: int) -> ActionError:
    return ActionError(
        "control_file_too_large: "
        f"kind={policy.kind} limit={policy.max_encoded_bytes} "
        f"observed_at_least={observed}"
    )


def _control_file_structure_limit(
    policy: ControlJsonPolicy,
    dimension: str,
    limit: int,
    observed: int,
) -> ActionError:
    return ActionError(
        "control_file_structure_limit: "
        f"kind={policy.kind} dimension={dimension} limit={limit} "
        f"observed_at_least={observed}"
    )


def _read_bounded_control_bytes(
    handle: BinaryIO,
    policy: ControlJsonPolicy,
) -> bytes:
    data = bytearray()
    limit_plus_one = policy.max_encoded_bytes + 1
    while len(data) < limit_plus_one:
        remaining = limit_plus_one - len(data)
        chunk = handle.read(min(CONTROL_READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > policy.max_encoded_bytes:
        raise _control_file_too_large(policy, len(data))
    return bytes(data)


def _utf8_length(value: str) -> int:
    if any(0xD800 <= code <= 0xDFFF for code in map(ord, value)):
        raise ActionError("invalid_result_boundary: unpaired JSON surrogate")
    return sum(
        1 if code <= 0x7F else 2 if code <= 0x7FF else 3 if code <= 0xFFFF else 4
        for code in map(ord, value)
    )


def _validate_json_shape(value: Any, policy: ControlJsonPolicy) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    value_count = 0
    while stack:
        current, depth = stack.pop()
        if depth > policy.max_depth:
            raise _control_file_structure_limit(
                policy, "depth", policy.max_depth, depth
            )
        value_count += 1
        if value_count > policy.max_values:
            raise _control_file_structure_limit(
                policy, "values", policy.max_values, value_count
            )
        if isinstance(current, str):
            length = _utf8_length(current)
            if length > policy.max_string_bytes:
                raise _control_file_structure_limit(
                    policy, "string_bytes", policy.max_string_bytes, length
                )
        elif isinstance(current, float) and not math.isfinite(current):
            raise ActionError("invalid_result_boundary: non-finite JSON number")
        elif isinstance(current, list):
            if len(current) > policy.max_container_entries:
                raise _control_file_structure_limit(
                    policy,
                    "container_entries",
                    policy.max_container_entries,
                    len(current),
                )
            stack.extend((child, depth + 1) for child in reversed(current))
        elif isinstance(current, dict):
            if len(current) > policy.max_container_entries:
                raise _control_file_structure_limit(
                    policy,
                    "container_entries",
                    policy.max_container_entries,
                    len(current),
                )
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ActionError(f"control_file_structure_limit: kind={policy.kind} object keys must be strings")
                key_length = _utf8_length(key)
                if key_length > policy.max_string_bytes:
                    raise _control_file_structure_limit(
                        policy,
                        "string_bytes",
                        policy.max_string_bytes,
                        key_length,
                    )
                stack.append((child, depth + 1))


def _unique_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ActionError("invalid_result_boundary: duplicate JSON member")
        value[key] = child
    return value


def load_json_object(
    path: pathlib.Path,
    *,
    policy: ControlJsonPolicy = ACTION_RESULT_POLICY,
) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            opened_size = os.fstat(handle.fileno()).st_size
            if opened_size > policy.max_encoded_bytes:
                raise _control_file_too_large(policy, opened_size)
            data = _read_bounded_control_bytes(handle, policy)
        try:
            value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_members)
        except RecursionError as error:
            raise _control_file_structure_limit(policy, "depth", policy.max_depth, policy.max_depth + 1) from error
        except ActionError:
            raise
        except ValueError as error:
            raise ActionError(f"invalid_result_boundary: cannot read result JSON: {str(error)[:512]}") from error
    except ActionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ActionError(f"invalid_result_boundary: cannot read result JSON: {error}") from error
    _validate_json_shape(value, policy)
    if not isinstance(value, dict):
        raise ActionError("invalid_result_boundary: result JSON root must be an object")
    return value


def _matches_shape(result: dict[str, Any], shape: dict[str, type]) -> bool:
    return all(isinstance(result.get(field), expected) for field, expected in shape.items())


# Admission freezes root DTO fields, not nested evidence semantics. Unknown
# evidence stays passive; only reviewed controls can select actions/authority.
_FUNCTION_META = {"go_compiler_function": dict, "rust_symbol_name_hint": str,
                  "rust_source_context": dict, "slice_budget": dict, "next_actions": list}
_IDENTITY = {"display_name": str, "function": dict}
_NULL_OBJECT = (dict, type(None))
_NULL_ARRAY = (list, type(None))
_RESULT_FIELDS = {
    "function_detail": ({**_IDENTITY, "static_byte_evidence": dict},
                        {**_FUNCTION_META, "inferred_role": dict}),
    "function_cfg": ({**_IDENTITY, "basic_blocks": list}, _FUNCTION_META),
    "function_slice": ({**_IDENTITY, "slice_size": int, "slice": dict,
        "semantic_summary": dict, "block_summaries": list, "instructions": list,
        "mlil": list, "hlil_flat": list, "pseudo_function_flat": str, "pseudo_flat": str},
        {**{k: v for k, v in _FUNCTION_META.items() if k != "slice_budget"},
         "inferred_role": dict, "warnings": list}),
    "function_flow_graph": ({"root": dict, "summary": dict, "nodes": list,
                             "edges": list, "warnings": list}, {"next_actions": list}),
    "function_il": ({**_IDENTITY, "level": str}, {**_FUNCTION_META, "inferred_role": dict}),
    "function_passes": ({**_IDENTITY, "hlil_passes": list, "render_passes": list}, _FUNCTION_META),
    "decompile_ai": ({"flat": bool, "binary": dict, "inspections": dict,
        "summary": dict, "recovered_types": list, "functions": list}, {"next_actions": list}),
    "report_ai": ({"sections": list, "binary": _NULL_OBJECT, "inspections": _NULL_OBJECT,
        "summary": _NULL_OBJECT, "flow": _NULL_OBJECT, "recovered_types": _NULL_ARRAY,
        "functions": _NULL_ARRAY, "protection_playbook_count": int, "protection_playbooks": list},
        {"global_string_samples": list, "current_findings": list, "next_actions": list}),
    "inspect-go": ({"binary": dict, "language": dict, "go": _NULL_OBJECT,
                    "warnings": list}, {"next_actions": list}),
    "inspect-rust": ({"binary": dict, "language": dict, "rust": _NULL_OBJECT,
                      "warnings": list}, {"next_actions": list}),
    "inspect-die": ({"file": dict, "fingerprint": dict, "language": dict,
        "protections": list, "normalizations": list, "summary": dict,
        "flow_root": _NULL_OBJECT, "recovered_types": list, "interesting_functions": list,
        "warnings": list}, {"package": dict, "global_string_samples": list, "next_actions": list}),
    "upx": ({"inspection": _NULL_OBJECT, "next_actions": list, "warnings": list}, {}),
    "vm_protect": ({"inspection": _NULL_OBJECT, "next_actions": list, "warnings": list}, {}),
    "pe_resources": ({"input": dict, "budget": dict, "summary": dict, "records": list,
        "stop_reasons": list, "next_actions": list, "warnings": list}, {}),
    "pe_strings": ({"input": dict, "budget": dict, "summary": dict, "records": list,
        "stop_reasons": list, "next_actions": list, "warnings": list}, {}),
    "call_graph": ({"root": dict, "budget": dict, "summary": dict, "nodes": list,
                    "edges": list}, {"stop_reasons": list, "next_actions": list, "warnings": list}),
    "data_xrefs": ({"direction": str, "selector": dict, "budget": dict, "summary": dict,
        "records": list, "stop_reasons": list, "next_actions": list, "warnings": list}, {}),
    "context_bundle": ({"files": list}, {"next_actions": list}),
    "agent_spill_manifest": ({"files": list}, {"next_actions": list}),
}
_IL_PAGING = {"statement_limit": int, "statement_contains": str, "statement_address": int,
    "statement_contains_search_offset": int, "statement_address_search_offset": int,
    "next_statement_offset": int, "next_statement_contains_offset": int}
_IL_FIELDS = {
    "llil": ({"instructions": list}, {}), "mlil": ({"instructions": list}, {}),
    "hlil": ({"flat": bool, "statements": list}, {}),
    "custom": ({"summary": dict, "semantic_ast": dict, "statement_offset": int,
                "statements_truncated": bool, "statements": list}, _IL_PAGING),
}
_RESULT_COMMANDS = {
    "function_detail": "function", "function_cfg": "dump-cfg",
    "function_slice": "slice-function", "function_flow_graph": "inspect-flow",
    "function_il": "dump-il", "function_passes": "inspect-passes",
    "decompile_ai": "decompile", "report_ai": "report",
    "upx": "inspect-upx", "vm_protect": "inspect-vmp",
    "pe_resources": "pe-resources", "pe_strings": "pe-strings",
    "call_graph": "call-graph", "data_xrefs": "data-xrefs",
}
_RESULT_LABELS = {"function_detail": "wrapper:function", "function_cfg": "wrapper:cfg",
    "function_slice": "wrapper:slice_function", "function_flow_graph": "wrapper:flow_graph",
    "function_il": "wrapper:function", "function_passes": "wrapper:function",
    "call_graph": "wrapper:call_graph", "data_xrefs": "wrapper:data_xrefs"}
_SELECTED_KINDS = frozenset(_RESULT_COMMANDS) - {
    "upx", "vm_protect", "pe_resources", "pe_strings", "call_graph", "data_xrefs"}
_LEGACY_SIGNATURES = {
    family: set(_RESULT_FIELDS[family][0])
    for family in _SELECTED_KINDS | {"inspect-go", "inspect-rust", "inspect-die"}
}
_IL_SUBSHAPE_FIELDS = set().union(
    *(set(required) | set(optional) for required, optional in _IL_FIELDS.values()))


def _validate_result_actions(result: dict[str, Any], family: str) -> None:
    if "next_actions" not in result:
        return
    actions = result["next_actions"]
    if family == "data_xrefs":
        try:
            _data_xref_actions(actions)
        except ActionError as error:
            raise ActionError("invalid_result_boundary: " + str(error)) from error
        return
    if family in {"pe_resources", "pe_strings"}:
        actions = _pe_actions(actions, family)
    stages = set()
    for row in actions:
        if (not isinstance(row, dict)
                or any(not isinstance(row.get(field), str) or not row[field].strip()
                       for field in ("stage", "reason", "expected_output", "stop_condition"))
                or not isinstance(row.get("argv"), list)
                or any(not isinstance(arg, str) for arg in row["argv"])):
            raise ActionError("invalid_result_boundary: invalid next action stage or controls")
        if row["stage"] in stages:
            raise ActionError("invalid_result_boundary: duplicate next action stage")
        stages.add(row["stage"])


def _pe_actions(actions: list[Any], family: str) -> list[dict[str, Any]]:
    normalized = []
    for row in actions:
        if isinstance(row, dict) and "stage" not in row:
            argv = row.get("argv")
            if (row.get("reason") != "record_limit" or not isinstance(argv, list)
                    or not argv or argv[0] != _RESULT_COMMANDS[family]):
                raise ActionError("invalid_result_boundary: invalid PE legacy action")
            row = {**row, "stage": family + ".page"}
        normalized.append(row)
    return normalized


def validate_result_contract(result: dict[str, Any], *, command: str | None = None) -> str:
    schema_version = result.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ActionError(f"unsupported_result_version: unsupported result schema_version {repr(schema_version)[:128]}")
    explicit = "kind" in result
    if explicit:
        kind = result["kind"]
        if not isinstance(kind, str) or kind not in _SELECTED_KINDS | {
                "call_graph", "data_xrefs", "upx", "vm_protect", "pe_resources", "pe_strings",
                *SUPPORTED_MANIFEST_KINDS}:
            raise ActionError(f"unsupported_result_kind: {repr(kind)[:128]}")
        family = kind
    else:
        candidates = [family for family, fields in _LEGACY_SIGNATURES.items()
                      if fields <= result.keys()]
        if len(candidates) > 1:
            raise ActionError("ambiguous_legacy_result: conflicting family discriminators")
        if not candidates:
            raise ActionError("invalid_result_fields: result is not a supported Auto-RE wrapper")
        family = candidates[0]
    manifest = family in SUPPORTED_MANIFEST_KINDS
    if manifest and {"verified_root", "cleanup_token", "consumption_contract"} <= result.keys():
        raise ActionError("invalid_result_boundary: verifier operational output is not a result manifest")
    if (manifest and result.get("owner") != "auto-re-cli") or (not manifest and "owner" in result):
        raise ActionError("invalid_result_boundary: invalid result owner")
    expected_profile = ({"ai", "full"} if family in {"call_graph", "data_xrefs"} else
                        {"ai"} if family in {"decompile_ai", "report_ai", "inspect-go", "inspect-rust",
                            "inspect-die", "upx", "vm_protect", "pe_resources", "pe_strings", "context_bundle"}
                        else None)
    profile = result.get("profile")
    if ((expected_profile is None and "profile" in result) or
            (expected_profile is not None and (not isinstance(profile, str) or profile not in expected_profile))):
        raise ActionError(f"invalid_result_profile: invalid {family}.profile: {repr(profile)[:128]}")
    required, optional = _RESULT_FIELDS[family]
    if family == "function_il":
        level = result.get("level")
        if not isinstance(level, str) or level not in _IL_FIELDS:
            raise ActionError("invalid_result_fields: unsupported IL level")
        il_required, il_optional = _IL_FIELDS[level]
        required = {**required, **il_required}
        optional = {**optional, **il_optional}
    conflicts = set()
    if family != "function_il" and "level" in result:
        conflicts.add("level")
    if family not in {"report_ai", "context_bundle"} and "sections" in result:
        conflicts.add("sections")
    function_root = _IDENTITY.keys() <= required.keys()
    if function_root:
        for foreign, fields in (("function_cfg", {"basic_blocks"}),
                                ("function_slice", {"slice", "slice_size"}),
                                ("function_passes", {"hlil_passes", "render_passes"})):
            if family != foreign:
                conflicts |= fields & result.keys()
        conflicts |= {"root", "nodes", "edges"} & result.keys()
    elif "function" in result:
        conflicts.add("function")
    if family == "inspect-die" and "binary" in result:
        conflicts.add("binary")
    if family == "report_ai" and "flat" in result:
        conflicts.add("flat")
    if family == "function_il":
        conflicts |= (_IL_SUBSHAPE_FIELDS & result.keys()) - (set(il_required) | set(il_optional))
    for foreign, fields in _LEGACY_SIGNATURES.items():
        # Explicit call_graph shares the frozen flow shape.
        if foreign == family or (family == "call_graph" and foreign == "function_flow_graph"):
            continue
        if fields <= result.keys():
            conflicts |= fields
    if conflicts:
        reason = "invalid_result_fields" if explicit else "ambiguous_legacy_result"
        raise ActionError(f"{reason}: foreign family fields: {', '.join(sorted(conflicts))}")
    for field, expected in {**required, **optional}.items():
        if field not in result and field in optional:
            continue
        value = result.get(field)
        if field not in result or not isinstance(value, expected) or (expected is int and type(value) is not int):
            raise ActionError(f"invalid_result_fields: invalid {family}.{field}")
        if expected is int:
            minimum = 1 if field in {"slice_size", "statement_limit"} else 0
            if value < minimum or (field == "statement_address" and value > 2**64 - 1):
                raise ActionError(f"invalid_result_fields: invalid {family}.{field}")
    if family == "report_ai":
        sections = result["sections"]
        if (any(not isinstance(section, str) or section not in {
                "binary", "inspections", "summary", "types", "flow", "functions"} for section in sections)
                or len(set(sections)) != len(sections)):
            raise ActionError("invalid_result_fields: invalid report sections")
    if family == "data_xrefs":
        direction = result.get("direction")
        if not isinstance(direction, str) or direction not in {"code_to_data", "data_to_code"}:
            raise ActionError("invalid_result_fields: invalid data_xrefs.direction")
        selector = result.get("selector")
        if not isinstance(selector, dict) or not isinstance(selector.get("kind"), str):
            raise ActionError("invalid_result_fields: invalid data_xrefs.selector")
        selector_kind = selector["kind"]
        if selector_kind == "all":
            if "value" in selector:
                raise ActionError("invalid_result_fields: invalid data_xrefs.selector")
        elif selector_kind in {"function", "string_exact", "global_exact"}:
            if not isinstance(selector.get("value"), str):
                raise ActionError("invalid_result_fields: invalid data_xrefs.selector")
        elif selector_kind in {"function_address", "data_address"}:
            if type(selector.get("value")) is not int or not 0 <= selector["value"] <= 2**64 - 1:
                raise ActionError("invalid_result_fields: invalid data_xrefs.selector")
        elif selector_kind == "data_address_range":
            value = selector.get("value")
            if (not isinstance(value, dict) or type(value.get("start")) is not int
                    or type(value.get("end")) is not int
                    or not 0 <= value["start"] < value["end"] <= 2**64 - 1):
                raise ActionError("invalid_result_fields: invalid data_xrefs.selector")
        else:
            raise ActionError("invalid_result_fields: invalid data_xrefs.selector")
        if (not _matches_shape(result, {"budget": dict, "summary": dict,
                                        "records": list, "stop_reasons": list,
                                        "next_actions": list, "warnings": list})
                or any(not isinstance(row, dict) for row in result["records"])
                or any(not isinstance(row, dict) for row in result["stop_reasons"])
                or any(not isinstance(warning, str) for warning in result["warnings"])):
            raise ActionError("invalid_result_fields: invalid data_xrefs wrapper")

    _validate_result_actions(result, family)
    if command is not None and command != _RESULT_COMMANDS.get(family, family):
        raise ActionError(f"result_command_mismatch: {command} received {family}")
    return (f"manifest:{family}" if manifest else _RESULT_LABELS.get(family, "profile:ai"))


def _data_xref_actions(actions: list[Any]) -> list[dict[str, Any]]:
    legacy = {"record_limit": ("data_xrefs.page", "data-xrefs"),
              "provenance_limit": ("data_xrefs.provenance", "slice-function")}
    normalized = []
    stages = set()
    for action in actions:
        if (not isinstance(action, dict)
                or not isinstance(action.get("reason"), str)
                or not action["reason"].strip()
                or not isinstance(action.get("argv"), list)
                or len(action["argv"]) < 2
                or any(not isinstance(item, str) for item in action["argv"])
                or any(not isinstance(action.get(field), str) or not action[field].strip()
                       for field in ("expected_output", "stop_condition"))):
            raise ActionError("invalid data_xrefs next action")
        if "stage" in action:
            stage = action["stage"]
            if not isinstance(stage, str) or not stage.strip():
                raise ActionError("invalid data_xrefs next action stage")
            source = "explicit"
        else:
            pair = legacy.get(action["reason"])
            if pair is None or action["argv"][1] != pair[1]:
                raise ActionError("cannot derive data_xrefs legacy action stage")
            stage, _command = pair
            source = "legacy_reason"
        if stage in stages:
            raise ActionError("duplicate data_xrefs next action stage")
        stages.add(stage)
        normalized.append({**action, "stage": stage, "_stage_source": source})
    return normalized


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ActionError(f"cannot hash trusted program: {error}") from error
    return digest.hexdigest()


def _identity_argv_shape(argv: list[str]) -> tuple[int | None, set[int], str]:
    """Locate the sole positional and parsed sinks using the pinned arity table."""
    index = 1
    sinks: set[int] = set()
    while index < len(argv) and argv[index].startswith("-"):
        flag, equals, _value = argv[index].partition("=")
        if flag not in IDENTITY_GLOBAL_VALUE_OPTIONS:
            return None, sinks, "unsupported_shape"
        if flag == "--output":
            sinks.add(index)
        if not equals:
            index += 1
            if index >= len(argv) or argv[index].startswith("-"):
                return None, sinks, "unsupported_shape"
            if flag == "--output":
                sinks.add(index)
        index += 1
    if index >= len(argv):
        return None, sinks, "unsupported_command"
    contract = IDENTITY_COMMAND_CONTRACT.get(argv[index])
    if contract is None or contract["classification"] != "single_input":
        return None, sinks, "unsupported_command"
    index += 1
    input_index = None
    positional_only = False
    while index < len(argv):
        argument = argv[index]
        if argument == "--" and not positional_only:
            positional_only = True
        elif argument.startswith("-") and not positional_only:
            flag, equals, _value = argument.partition("=")
            if flag in contract["value_options"]:
                if flag in COMMAND_OWNED_SINK_FLAGS | {"--output"}:
                    sinks.add(index)
                    if not equals:
                        sinks.add(index + 1)
                if not equals:
                    index += 1
                    if index >= len(argv) or argv[index].startswith("-"):
                        return None, sinks, "unsupported_shape"
            elif flag not in contract["switch_options"] or equals:
                return None, sinks, "unsupported_shape"
        elif input_index is None:
            input_index = index
        else:
            return None, sinks, "unsupported_shape"
        index += 1
    return input_index, sinks, "available" if input_index is not None else "unsupported_shape"


def _request_identity_with_reason(argv: list[str], program_sha256: str,
                                  program_version: str = "auto-re-cli " + IDENTITY_CONTRACT_VERSION) -> tuple[dict[str, Any] | None, str]:
    """Identify an audited single-input request without its output destinations."""
    if program_version != "auto-re-cli " + IDENTITY_CONTRACT_VERSION:
        return None, "unsupported_command"
    input_index, _sinks, reason = _identity_argv_shape(argv)
    if input_index is None:
        return None, reason
    try:
        fd = os.open(argv[input_index], os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
        except OSError:
            os.close(fd)
            raise
        if not stat.S_ISREG(before.st_mode):
            os.close(fd)
            return None, "input_nonregular"
        with os.fdopen(fd, "rb") as handle:
            if before.st_size > IDENTITY_INPUT_MAX_BYTES:
                return None, "input_too_large"
            digest = hashlib.sha256()
            observed = 0
            for chunk in iter(lambda: handle.read(CONTROL_READ_CHUNK_BYTES), b""):
                observed += len(chunk)
                if observed > before.st_size:
                    return None, "input_unstable"
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            if observed != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return None, "input_unstable"
    except OSError:
        return None, "input_unreadable"
    return _make_request_identity(argv, program_sha256, digest.hexdigest(), before.st_size), "available"


def _make_request_identity(argv: list[str], program_sha256: str,
                           input_sha256: str, input_bytes: int) -> dict[str, Any]:
    """Share the exact duplicated argv projection with side-effect-free admission."""
    input_index, sinks, reason = _identity_argv_shape(argv)
    if input_index is None:
        raise ActionError("cannot project request identity: " + reason)
    arguments = ["<input-sha256>=" + input_sha256 if index == input_index else argument
                 for index, argument in enumerate(argv) if index > 0 and index not in sinks]
    identity = {"input_sha256": input_sha256, "input_bytes": input_bytes,
                "program_sha256": program_sha256, "analysis_argv": arguments}
    identity["sha256"] = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return identity


def request_identity(argv: list[str], program_sha256: str,
                     program_version: str = "auto-re-cli " + IDENTITY_CONTRACT_VERSION) -> dict[str, Any] | None:
    return _request_identity_with_reason(argv, program_sha256, program_version)[0]


def validate_prior_receipt(prior: dict[str, Any]) -> dict[str, Any]:
    if (type(prior.get("schema_version")) is not int or prior["schema_version"] != 1
            or prior.get("owner") != "auto-re-skill"
            or prior.get("kind") != "auto_re_action_execution_receipt"):
        raise ActionError("invalid prior receipt identity")
    identity = prior.get("request_identity")
    if identity is not None:
        if not isinstance(identity, dict) or set(identity) != {
            "input_sha256", "input_bytes", "program_sha256", "analysis_argv", "sha256"
        }:
            raise ActionError("invalid prior request_identity")
        digest_fields = ("input_sha256", "program_sha256", "sha256")
        if any(not isinstance(identity.get(field), str) or
               re.fullmatch(r"[0-9a-f]{64}", identity[field]) is None
               for field in digest_fields):
            raise ActionError("invalid prior request_identity hash")
        if (type(identity.get("input_bytes")) is not int or identity["input_bytes"] < 0
                or not isinstance(identity.get("analysis_argv"), list)
                or not identity["analysis_argv"]
                or any(not isinstance(item, str) for item in identity["analysis_argv"])):
            raise ActionError("invalid prior request_identity fields")
        payload = {field: identity[field] for field in
                   ("input_sha256", "input_bytes", "program_sha256", "analysis_argv")}
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()
        if identity["sha256"] != expected:
            raise ActionError("invalid prior request_identity digest")
    if "execution_status" in prior and (not isinstance(prior["execution_status"], str)
                                        or not prior["execution_status"]):
        raise ActionError("invalid prior execution_status")
    if "timeout_seconds" in prior:
        try:
            process_control.validate_seconds(prior["timeout_seconds"])
        except process_control.ProcessError as error:
            raise ActionError("invalid prior timeout_seconds") from error
    if "leader_reaped" in prior and not isinstance(prior["leader_reaped"], bool):
        raise ActionError("invalid prior leader_reaped")
    return prior


def assess_continuation(prior: dict[str, Any] | None, identity: dict[str, Any] | None,
                        timeout_seconds: float) -> str:
    if prior is None:
        return "not_requested"
    prior_identity = prior.get("request_identity")
    if prior_identity is None or identity is None:
        return "not_evaluated_unavailable_identity"
    if prior_identity != identity:
        return "changed_analysis"
    if prior.get("execution_status") == "timed_out":
        if prior.get("leader_reaped") is not True:
            raise ActionError("unresolved_prior_process: timed out leader was not confirmed reaped")
        previous_timeout = prior.get("timeout_seconds")
        if previous_timeout is not None and timeout_seconds > previous_timeout:
            return "increased_timeout_after_timeout"
    if "execution_status" not in prior or "timeout_seconds" not in prior:
        raise ActionError("no_progress: prior receipt lacks status or timeout needed for a safe exception")
    raise ActionError("no_progress: identical input, tool, selector and budget; inspect the prior result instead of renaming and repeating it")


def receipt_log_dir(receipt_path: pathlib.Path) -> pathlib.Path:
    requested = receipt_path.expanduser().absolute()
    return requested.parent / f"{requested.name}.logs"


def _require_absent(path: pathlib.Path, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ActionError(f"cannot inspect {label}: {error}") from error
    raise ActionError(f"{label} already exists: {path}")


def prepare_receipt_paths(receipt_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    requested = receipt_path.expanduser().absolute()
    try:
        parent = requested.parent.resolve(strict=True)
    except OSError as error:
        raise ActionError(f"receipt output parent is unavailable: {error}") from error
    receipt = parent / requested.name
    logs = parent / f"{requested.name}.logs"
    _require_absent(receipt, "receipt output")
    _require_absent(logs, "log directory")
    return receipt, logs




def _write_private_bytes(path: pathlib.Path, data: bytes, label: str) -> None:
    created: Optional[os.stat_result] = None

    def private_opener(name: str, flags: int) -> int:
        return os.open(name, flags, 0o600)

    try:
        with open(path, "xb", opener=private_opener) as output:
            created = os.fstat(output.fileno())
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            if hasattr(os, "fchmod"):
                os.fchmod(output.fileno(), 0o400)
        if not os.path.samestat(created, path.lstat()):
            raise OSError("output object changed during write")
        if not hasattr(os, "fchmod"):
            path.chmod(0o400)
    except OSError as error:
        cleanup_error = None
        # A failed exclusive open never grants ownership of the destination.
        # Also preserve any replacement object observed after a later failure.
        if created is not None:
            try:
                if os.path.samestat(created, path.lstat()):
                    path.unlink()
            except FileNotFoundError:
                pass
            except OSError as failure:
                cleanup_error = failure
        detail = f"cannot write {label}: {error}"
        if cleanup_error is not None:
            detail += f"; cannot remove incomplete owned output: {cleanup_error}"
        raise ActionError(detail) from error


def _encode_receipt(value: dict[str, Any]) -> bytes:
    _validate_json_shape(value, RECEIPT_POLICY)
    validate_prior_receipt(value)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > RECEIPT_MAX_BYTES:
        raise ActionError(
            "execution receipt exceeds limit: "
            f"limit={RECEIPT_MAX_BYTES} observed={len(encoded)}"
        )
    return encoded


def _write_receipt(path: pathlib.Path, value: dict[str, Any]) -> None:
    _write_private_bytes(path, _encode_receipt(value), "execution receipt")


def probe_program_version(executable: pathlib.Path) -> str:
    try:
        combined = process_control.probe_output(executable, max_bytes=PROGRAM_VERSION_MAX_BYTES)
    except process_control.ProcessError as error:
        raise ActionError(f"cannot probe trusted program version: {error}") from error
    try:
        output = combined.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ActionError("trusted program version output is not UTF-8") from error
    if not output:
        raise ActionError("trusted program version output is empty")
    if PROGRAM_VERSION_PATTERN.fullmatch(output) is None:
        raise ActionError(f"unexpected trusted program version output: {output!r}")
    return output


def _stream_receipt(
    path: pathlib.Path,
    captured: CapturedStream,
    tail_limit: int,
) -> dict[str, Any]:
    return {
        "path": str(path),
        "retention": "tail",
        "tail_limit_bytes": tail_limit,
        "bytes_total": captured.bytes_total,
        "bytes_retained": len(captured.tail),
        "sha256": captured.sha256,
        "retained_sha256": hashlib.sha256(captured.tail).hexdigest(),
        "truncated": captured.bytes_total > len(captured.tail),
        "capture_complete": captured.complete,
        "digest_scope": "complete_stream" if captured.complete else "observed_prefix",
    }


def _sink_record(prepared: dict[str, Any]) -> dict[str, Any]:
    argv = prepared["argv"]
    if prepared["command_owned_sink"]:
        flags = [
            argument
            for argument in argv
            if any(
                argument == flag or argument.startswith(f"{flag}=")
                for flag in COMMAND_OWNED_SINK_FLAGS
            )
        ]
        return {"ownership": "command", "arguments": flags}
    output_index = len(argv) - 2
    if output_index >= 0 and argv[output_index] == "--output":
        return {"ownership": "caller", "path": argv[output_index + 1]}
    return {"ownership": "unresolved"}


def _receipt_value(prepared, executable, program_version, program_sha256, identity,
                   identity_reason, continuation_check, log_dir, captured, started_at,
                   ended_at, duration_ms, log_tail_bytes, timeout_seconds):
    stdout_path = log_dir / "stdout.tail.log"
    stderr_path = log_dir / "stderr.tail.log"
    argv = [str(executable), *prepared["argv"][1:]]
    exit_code = execution_exit_code(captured)
    value = {
        "schema_version": 1,
        "owner": "auto-re-skill",
        "kind": "auto_re_action_execution_receipt",
        "action_stage": prepared["action_stage"],
        "reason": prepared["reason"],
        "expected_output": prepared["expected_output"],
        "stop_condition": prepared["stop_condition"],
        "program": {
            "path": str(executable),
            "version_output": program_version,
            "sha256": program_sha256,
        },
        "argv": argv,
        "request_identity": identity,
        "request_identity_unavailable_reason": identity_reason,
        "continuation_check": continuation_check,
        "sink": _sink_record(prepared),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "process_exit_code": captured.returncode,
        "execution_status": captured.status,
        "timeout_seconds": timeout_seconds,
        "leader_reaped": captured.leader_reaped,
        "diagnostics": list(captured.diagnostics),
        "stdout": _stream_receipt(
            stdout_path, captured.stdout, log_tail_bytes
        ),
        "stderr": _stream_receipt(
            stderr_path, captured.stderr, log_tail_bytes
        ),
        "evidence_boundary": "operational_diagnostics_not_target_analysis_evidence",
    }
    if "action_stage_source" in prepared:
        value["action_stage_source"] = prepared["action_stage_source"]
    _validate_generated_receipt_fields(value)
    return value


def _validate_generated_receipt_fields(value: dict[str, Any]) -> None:
    """Explicit generator ceilings; invariant failure never clips evidence."""
    def integer(number, low, high, field):
        if type(number) is not int or not low <= number <= high:
            raise ActionError(f"receipt dynamic invariant: {field} outside {low}..{high}")

    integer(value["duration_ms"], 0, RECEIPT_UINT_MAX, "duration_ms")
    integer(value["exit_code"], -RECEIPT_UINT_MAX, RECEIPT_UINT_MAX + 128, "exit_code")
    if value["process_exit_code"] is not None:
        integer(value["process_exit_code"], -RECEIPT_UINT_MAX, RECEIPT_UINT_MAX, "process_exit_code")
    if value["execution_status"] not in process_control.PROCESS_STATUSES:
        raise ActionError("receipt dynamic invariant: unsupported execution_status")
    if value["continuation_check"] not in CONTINUATION_CHECKS:
        raise ActionError("receipt dynamic invariant: unsupported continuation_check")
    if (value["request_identity_unavailable_reason"] is not None
            and value["request_identity_unavailable_reason"] not in IDENTITY_REASONS):
        raise ActionError("receipt dynamic invariant: unsupported identity reason")
    for field in ("started_at", "ended_at"):
        if not isinstance(value[field], str) or len(value[field]) > 27 or not value[field].isascii():
            raise ActionError(f"receipt dynamic invariant: invalid {field}")
    diagnostics = value["diagnostics"]
    if len(diagnostics) > process_control.DIAGNOSTIC_MAX_ENTRIES:
        raise ActionError("receipt dynamic invariant: too many diagnostics")
    for diagnostic in diagnostics:
        if diagnostic == "pipe_drain_timeout":
            continue
        if not isinstance(diagnostic, str) or not any(
            diagnostic.startswith(prefix)
            and len(diagnostic) - len(prefix) <= process_control.DIAGNOSTIC_EXCEPTION_CHARACTERS
            for prefix in process_control.DIAGNOSTIC_PREFIXES
        ):
            raise ActionError("receipt dynamic invariant: invalid diagnostic")
    for name in ("stdout", "stderr"):
        stream = value[name]
        integer(stream["bytes_total"], 0, RECEIPT_UINT_MAX, f"{name}.bytes_total")
        integer(stream["bytes_retained"], 0, stream["tail_limit_bytes"], f"{name}.bytes_retained")
        if stream["bytes_retained"] > stream["bytes_total"]:
            raise ActionError("receipt dynamic invariant: retained bytes exceed observed bytes")


def receipt_budget_plan(prepared: dict[str, Any], log_dir: pathlib.Path, *,
                        executable: str = "", program_version: str | None = None,
                        program_sha256: str = "f" * 64,
                        identity: dict[str, Any] | None = None,
                        continuation_check: str | None = None,
                        log_tail_bytes: int = LOG_TAIL_BYTES,
                        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Encode the common schema with maxima derived from bounded generators.

    The known pass reserves a possible identity without reading the target.
    The resolved pass also covers an identity disappearing after execution.
    False is the largest boolean encoding; None is smaller than reserved strings,
    signed return code and identity object. Hash lengths and argv projection are
    exact. UTF-16 surrogate pairs cost at most twelve JSON bytes per character.
    """
    try:
        timeout_seconds = process_control.validate_seconds(timeout_seconds)
    except process_control.ProcessError as error:
        raise ActionError(str(error)) from error
    for field in ("action_stage", "reason", "expected_output", "stop_condition"):
        if not isinstance(prepared.get(field), str) or not prepared[field].strip():
            raise ActionError(f"prepared action is missing {field}")
    if "action_stage_source" in prepared and not isinstance(prepared["action_stage_source"], str):
        raise ActionError("prepared action_stage_source must be a string")
    if type(log_tail_bytes) is not int or not 0 <= log_tail_bytes <= LOG_TAIL_BYTES:
        raise ActionError(f"log tail byte limit must be an integer between 0 and {LOG_TAIL_BYTES}")
    argv = prepared["argv"]
    if identity is None and _identity_argv_shape(argv)[0] is not None:
        identity = _make_request_identity(argv, program_sha256, "f" * 64, IDENTITY_INPUT_MAX_BYTES)
    if program_version is None:
        program_version = "auto-re-cli " + "9" * (PROGRAM_VERSION_MAX_BYTES - 16) + ".9.9"
    if len(program_version.encode("utf-8")) > PROGRAM_VERSION_MAX_BYTES or PROGRAM_VERSION_PATTERN.fullmatch(program_version) is None:
        raise ActionError("receipt dynamic invariant: invalid version output")
    if continuation_check is None:
        continuation_check = max(CONTINUATION_CHECKS, key=len)
    diagnostic = max(process_control.DIAGNOSTIC_PREFIXES, key=len) + "\U0001f600" * process_control.DIAGNOSTIC_EXCEPTION_CHARACTERS
    stream = CapturedStream(b"", RECEIPT_UINT_MAX, "f" * 64, False)
    captured = process_control.ProcessResult(-RECEIPT_UINT_MAX,
        max(process_control.PROCESS_STATUSES, key=len), stream, stream,
        (diagnostic,) * process_control.DIAGNOSTIC_MAX_ENTRIES, False)
    value = _receipt_value(prepared, executable, program_version, program_sha256,
        identity, max(IDENTITY_REASONS, key=len), continuation_check, log_dir,
        captured, "9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59.999999Z",
        RECEIPT_UINT_MAX, log_tail_bytes, timeout_seconds)
    for name in ("stdout", "stderr"):
        value[name]["bytes_retained"] = log_tail_bytes
        value[name]["truncated"] = False
    # The longest status and the longest mapped exit do not occur together;
    # reserving each field's maximum covers all admitted status/exit pairs.
    value["exit_code"] = RECEIPT_UINT_MAX + 128
    encoded = _encode_receipt(value)
    return {"encoded_upper_bound": len(encoded), "encoded_limit": RECEIPT_MAX_BYTES,
            "program_and_identity_checked": bool(executable)}


def _command_sink_values(argv: list[str]) -> list[pathlib.Path]:
    sinks: list[pathlib.Path] = []
    for index, argument in enumerate(argv):
        for flag in COMMAND_OWNED_SINK_FLAGS:
            if argument == flag:
                if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                    raise ActionError(f"{flag} requires an output directory")
                value = argv[index + 1]
            elif argument.startswith(f"{flag}="):
                value = argument.split("=", 1)[1]
            else:
                continue
            if not value:
                raise ActionError(f"{flag} requires an output directory")
            # argv is passed with shell=False: a literal ~ is not expanded.
            sinks.append(pathlib.Path(value).resolve())
    if not sinks:
        raise ActionError("command-owned action is missing an output directory")
    return sinks


def validate_receipt_sink_separation(
    prepared: dict[str, Any],
    receipt: pathlib.Path,
    log_dir: pathlib.Path,
) -> None:
    def overlaps(left: pathlib.Path, right: pathlib.Path) -> bool:
        return left == right or left in right.parents or right in left.parents

    try:
        receipt = receipt.expanduser().resolve()
        log_dir = log_dir.expanduser().resolve()
        argv = prepared["argv"]
        if prepared["command_owned_sink"]:
            for sink in _command_sink_values(argv):
                if overlaps(receipt, sink) or overlaps(log_dir, sink):
                    raise ActionError(
                        "receipt or log path overlaps a command-owned action sink"
                    )
            return
        output = pathlib.Path(argv[-1]).resolve()
        if overlaps(receipt, output) or overlaps(log_dir, output):
            raise ActionError("receipt or log path aliases action output")
    except ActionError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ActionError(f"cannot resolve receipt/action sink paths: {error}") from error


def prepare_action_receipt_paths(
    prepared: dict[str, Any], receipt_path: pathlib.Path, *,
    log_tail_bytes: int = LOG_TAIL_BYTES,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Apply the same side-effect-free receipt preflight to preview and execution."""
    validate_prepared_argv(
        prepared.get("argv"),
        command_owned_sink=prepared.get("command_owned_sink") is True,
    )
    receipt, logs = prepare_receipt_paths(receipt_path)
    validate_receipt_sink_separation(prepared, receipt, logs)
    receipt_budget_plan(prepared, logs, log_tail_bytes=log_tail_bytes,
                        timeout_seconds=timeout_seconds)
    return receipt, logs


def execute_prepared_with_receipt(
    prepared: dict[str, Any],
    executable: pathlib.Path,
    receipt_path: pathlib.Path,
    *,
    log_tail_bytes: int = LOG_TAIL_BYTES,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    prior_receipt: pathlib.Path | None = None,
) -> tuple[int, dict[str, Any]]:
    if (
        not isinstance(log_tail_bytes, int)
        or isinstance(log_tail_bytes, bool)
        or not 0 <= log_tail_bytes <= LOG_TAIL_BYTES
    ):
        raise ActionError(
            f"log tail byte limit must be an integer between 0 and {LOG_TAIL_BYTES}"
        )
    try:
        timeout_seconds = process_control.validate_seconds(timeout_seconds)
    except process_control.ProcessError as error:
        raise ActionError(str(error)) from error
    receipt, log_dir = prepare_action_receipt_paths(prepared, receipt_path,
        log_tail_bytes=log_tail_bytes, timeout_seconds=timeout_seconds)
    try:
        resolved_executable = executable.expanduser().resolve(strict=True)
    except OSError as error:
        raise ActionError(f"cannot resolve trusted program: {error}") from error
    if not resolved_executable.is_file():
        raise ActionError("trusted program must be a regular file")
    program_version = probe_program_version(resolved_executable)
    program_sha256 = sha256_file(resolved_executable)
    identity, identity_reason = _request_identity_with_reason(prepared["argv"], program_sha256, program_version)
    prior = None
    if prior_receipt is not None:
        prior = validate_prior_receipt(load_json_object(
            prior_receipt, policy=RECEIPT_POLICY))
    continuation_check = assess_continuation(prior, identity, timeout_seconds)
    receipt_budget_plan(prepared, log_dir, executable=str(resolved_executable),
        program_version=program_version, program_sha256=program_sha256,
        identity=identity, continuation_check=continuation_check,
        log_tail_bytes=log_tail_bytes, timeout_seconds=timeout_seconds)

    try:
        log_dir.mkdir(mode=0o700)
    except OSError as error:
        raise ActionError(f"cannot create log directory: {error}") from error
    stdout_path = log_dir / "stdout.tail.log"
    stderr_path = log_dir / "stderr.tail.log"
    argv = [str(resolved_executable), *prepared["argv"][1:]]
    started_at = utc_now()
    started_monotonic = time.monotonic()
    try:
        captured = process_control.run_process(
            argv, timeout_seconds=timeout_seconds, tail_bytes=log_tail_bytes,
        )
    except process_control.ProcessError as error:
        shutil.rmtree(log_dir, ignore_errors=True)
        raise ActionError(str(error)) from error
    results = {"stdout": captured.stdout, "stderr": captured.stderr}
    exit_code = execution_exit_code(captured)
    ended_at = utc_now()
    duration_ms = round((time.monotonic() - started_monotonic) * 1000)
    final_identity, final_reason = _request_identity_with_reason(prepared["argv"], program_sha256, program_version)
    if final_identity != identity:
        identity_reason = "input_unstable_after_execution"
    elif identity is None:
        identity_reason = final_reason

    try:
        _write_private_bytes(stdout_path, results["stdout"].tail, "stdout tail log")
        _write_private_bytes(stderr_path, results["stderr"].tail, "stderr tail log")
        receipt_value = _receipt_value(
            prepared, resolved_executable, program_version, program_sha256,
            identity if final_identity == identity else None,
            None if final_identity == identity and identity is not None else identity_reason,
            continuation_check, log_dir, captured, started_at, ended_at, duration_ms,
            log_tail_bytes, timeout_seconds,
        )
        _write_receipt(receipt, receipt_value)
    except BaseException:
        shutil.rmtree(log_dir, ignore_errors=True)
        raise

    summary = {
        "ok": exit_code == 0,
        "owner": "auto-re-skill",
        "kind": "auto_re_action_execution_summary",
        "receipt_path": str(receipt),
        "exit_code": exit_code,
        "process_exit_code": captured.returncode,
        "execution_status": captured.status,
        "continuation_check": continuation_check,
        "request_identity_unavailable_reason": receipt_value["request_identity_unavailable_reason"],
        "diagnostics": list(captured.diagnostics),
        "stdout_truncated": receipt_value["stdout"]["truncated"],
        "stderr_truncated": receipt_value["stderr"]["truncated"],
    }
    return exit_code, summary


def select_action(result: dict[str, Any], action_stage: str) -> dict[str, Any]:
    actions = result.get("next_actions")
    if not isinstance(actions, list):
        raise ActionError("result next_actions must be an array")
    matches = [
        action
        for action in actions
        if isinstance(action, dict) and action.get("stage") == action_stage
    ]
    if len(matches) != 1:
        raise ActionError(
            "action stage must select exactly one next action: "
            f"{action_stage!r}"
        )
    action = matches[0]
    for field in ("reason", "expected_output", "stop_condition"):
        if not isinstance(action.get(field), str) or not action[field].strip():
            raise ActionError(f"selected action is missing {field}")
    return action


def validate_argv(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ActionError("selected action argv must be a non-empty array")
    if any(
        not isinstance(argument, str) or not argument or "\0" in argument
        for argument in value
    ):
        raise ActionError("selected action argv must contain non-empty strings")
    argv = list(value)
    if argv[0] != TRUSTED_PROGRAM:
        raise ActionError("selected action must use the trusted auto-re-cli program")
    for flag in FORBIDDEN_FLAGS:
        if any(argument == flag or argument.startswith(f"{flag}=") for argument in argv):
            raise ActionError(f"forbidden action flag: {flag}")
    if any(
        argument == "--output" or argument.startswith("--output=")
        for argument in argv
    ):
        raise ActionError("emitted next action must not inherit --output")
    return argv


def validate_prepared_argv(value: Any, *, command_owned_sink: bool) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ActionError("prepared action argv must be a non-empty array")
    if any(
        not isinstance(argument, str) or not argument or "\0" in argument
        for argument in value
    ):
        raise ActionError("prepared action argv must contain non-empty strings")
    argv = list(value)
    if argv[0] != TRUSTED_PROGRAM:
        raise ActionError("prepared action must use the trusted auto-re-cli program")
    for flag in FORBIDDEN_FLAGS:
        if any(argument == flag or argument.startswith(f"{flag}=") for argument in argv):
            raise ActionError(f"forbidden action flag: {flag}")
    output_positions = [
        index
        for index, argument in enumerate(argv)
        if argument == "--output" or argument.startswith("--output=")
    ]
    has_command_sink = any(
        argument == flag or argument.startswith(f"{flag}=")
        for argument in argv
        for flag in COMMAND_OWNED_SINK_FLAGS
    )
    if command_owned_sink:
        if not has_command_sink or output_positions:
            raise ActionError("prepared command-owned action has an invalid sink")
        try:
            _command_sink_values(argv)
        except (OSError, RuntimeError) as error:
            raise ActionError(f"cannot resolve action output directories: {error}") from error
    elif (
        has_command_sink
        or len(output_positions) != 1
        or output_positions[0] != len(argv) - 2
        or argv[output_positions[0]] != "--output"
    ):
        raise ActionError("prepared caller-owned action must end with one --output path")
    return argv


def prepare_action(
    result_path: pathlib.Path,
    action_stage: str,
    output: Optional[pathlib.Path],
) -> dict[str, Any]:
    result_path = result_path.expanduser().resolve()
    result = load_json_object(result_path)
    result_wrapper = validate_result_contract(result)
    if result_wrapper == "wrapper:data_xrefs":
        result = {**result, "next_actions": _data_xref_actions(result["next_actions"])}
    elif result.get("kind") in {"pe_resources", "pe_strings"}:
        result = {**result, "next_actions": _pe_actions(result["next_actions"], result["kind"])}
    action = select_action(result, action_stage)
    argv = validate_argv(action.get("argv"))
    command_owned_sink = any(
        argument == flag or argument.startswith(f"{flag}=")
        for argument in argv
        for flag in COMMAND_OWNED_SINK_FLAGS
    )

    if command_owned_sink:
        if output is not None:
            raise ActionError(
                "selected action already owns its output sink; omit --output"
            )
    else:
        if output is None:
            raise ActionError("selected action requires a new explicit --output path")
        output = output.expanduser().resolve()
        if output == result_path:
            raise ActionError("selected action output must not overwrite its parent result")
        if not output.parent.is_dir():
            raise ActionError(
                f"selected action output parent does not exist: {output.parent}"
            )
        argv.extend(["--output", str(output)])

    validate_prepared_argv(argv, command_owned_sink=command_owned_sink)
    prepared = {
        "ok": True,
        "schema_version": result["schema_version"],
        "result_wrapper": result_wrapper,
        "action_stage": action_stage,
        "reason": action["reason"],
        "expected_output": action["expected_output"],
        "stop_condition": action["stop_condition"],
        "command_owned_sink": command_owned_sink,
        "argv": argv,
    }
    if "_stage_source" in action:
        prepared["action_stage_source"] = action["_stage_source"]
    return prepared


def execution_exit_code(result) -> int:
    if result.status == "timed_out":
        return 124
    if result.status == "cancelled":
        return 130
    if result.status != "completed" or result.returncode is None:
        return 125
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def positive_seconds(text: str) -> float:
    try:
        return process_control.validate_seconds(float(text))
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and run one exact static next_actions[] command."
    )
    parser.add_argument("result", type=pathlib.Path)
    parser.add_argument("--action-stage", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--prior-receipt", type=pathlib.Path, help="stop before repeating an identical recorded request")
    parser.add_argument("--timeout-seconds", type=positive_seconds, default=DEFAULT_TIMEOUT_SECONDS,
                        help="analysis execution budget; increase for long static analyses (default: 900)")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.prior_receipt is not None and args.receipt is None:
            raise ActionError("--prior-receipt requires --receipt")
        prepared = prepare_action(args.result, args.action_stage, args.output)
        if args.dry_run:
            if args.prior_receipt is not None:
                prepared["continuation_check"] = "not_evaluated_dry_run"
            if args.receipt is not None:
                receipt, logs = prepare_action_receipt_paths(prepared, args.receipt,
                    timeout_seconds=args.timeout_seconds)
                prepared["planned_receipt"] = str(receipt)
                prepared["planned_log_dir"] = str(logs)
                prepared["receipt_budget"] = receipt_budget_plan(
                    prepared, logs, timeout_seconds=args.timeout_seconds)
            json.dump(prepared, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0

        executable = shutil.which(TRUSTED_PROGRAM)
        if executable is None:
            raise ActionError("auto-re-cli is not available on PATH")
        if args.receipt is not None:
            exit_code, summary = execute_prepared_with_receipt(
                prepared,
                pathlib.Path(executable),
                args.receipt,
                timeout_seconds=args.timeout_seconds,
                prior_receipt=args.prior_receipt,
            )
            json.dump(summary, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return exit_code
        argv = [executable, *prepared["argv"][1:]]
        try:
            completed = process_control.run_process(
                argv, timeout_seconds=args.timeout_seconds, capture=False,
            )
        except process_control.ProcessError as error:
            raise ActionError(str(error)) from error
        if completed.status != "completed":
            json.dump({"ok": False, "error": completed.status,
                       "diagnostics": list(completed.diagnostics)}, sys.stderr, sort_keys=True)
            sys.stderr.write("\n")
        return execution_exit_code(completed)
    except (ActionError, OSError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
