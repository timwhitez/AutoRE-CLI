#!/usr/bin/env python3
"""Validate and run one emitted Auto-RE static next action."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, BinaryIO, NamedTuple, Optional


TRUSTED_PROGRAM = "auto-re-cli"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"0.1.0"})
SUPPORTED_PROFILES = frozenset({"ai"})
SUPPORTED_MANIFEST_KINDS = frozenset({"context_bundle", "agent_spill_manifest"})
FORBIDDEN_FLAGS = {"--execute"}
COMMAND_OWNED_SINK_FLAGS = {"--bundle-dir", "--spill-dir"}
CONTROL_READ_CHUNK_BYTES = 64 * 1024


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


class ActionError(ValueError):
    pass


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
                key_length = _utf8_length(key)
                if key_length > policy.max_string_bytes:
                    raise _control_file_structure_limit(
                        policy,
                        "string_bytes",
                        policy.max_string_bytes,
                        key_length,
                    )
                stack.append((child, depth + 1))


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
        value = json.loads(data.decode("utf-8"))
    except ActionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ActionError(f"cannot read result JSON: {error}") from error
    _validate_json_shape(value, policy)
    if not isinstance(value, dict):
        raise ActionError("result JSON root must be an object")
    return value


def _matches_shape(result: dict[str, Any], shape: dict[str, type]) -> bool:
    return all(isinstance(result.get(field), expected) for field, expected in shape.items())


def validate_result_contract(result: dict[str, Any]) -> str:
    schema_version = result.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
        raise ActionError(
            f"unsupported result schema_version {schema_version!r}; supported: {supported}"
        )

    owner = result.get("owner")
    kind = result.get("kind")
    if owner is not None or kind is not None:
        if owner != "auto-re-cli" or kind not in SUPPORTED_MANIFEST_KINDS:
            raise ActionError(
                "unsupported Auto-RE manifest identity: "
                f"owner={owner!r} kind={kind!r}"
            )
        if not isinstance(result.get("files"), list):
            raise ActionError("Auto-RE manifest wrapper must contain files[]")
        profile = result.get("profile")
        if profile is not None and (
            not isinstance(profile, str) or profile not in SUPPORTED_PROFILES
        ):
            raise ActionError(f"unsupported result profile: {profile!r}")
        return f"manifest:{kind}"

    profile = result.get("profile")
    if profile is not None:
        if not isinstance(profile, str) or profile not in SUPPORTED_PROFILES:
            raise ActionError(f"unsupported result profile: {profile!r}")
        if not _matches_shape(result, {"binary": dict, "summary": dict}):
            raise ActionError(
                "profile:ai result must contain binary and summary objects"
            )
        return "profile:ai"

    wrapper_shapes: tuple[tuple[str, dict[str, type]], ...] = (
        (
            "flow_graph",
            {"root": dict, "summary": dict, "nodes": list, "edges": list},
        ),
        (
            "slice_function",
            {
                "display_name": str,
                "function": dict,
                "slice": dict,
                "instructions": list,
            },
        ),
        (
            "cfg",
            {"display_name": str, "function": dict, "basic_blocks": list},
        ),
        ("function", {"display_name": str, "function": dict}),
    )
    for wrapper_name, shape in wrapper_shapes:
        if _matches_shape(result, shape):
            return f"wrapper:{wrapper_name}"

    raise ActionError("result is not a supported Auto-RE wrapper")


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


def prepare_action(
    result_path: pathlib.Path,
    action_stage: str,
    output: Optional[pathlib.Path],
) -> dict[str, Any]:
    result_path = result_path.expanduser().resolve()
    result = load_json_object(result_path)
    result_wrapper = validate_result_contract(result)
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

    return {
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and run one exact static next_actions[] command."
    )
    parser.add_argument("result", type=pathlib.Path)
    parser.add_argument("--action-stage", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        prepared = prepare_action(args.result, args.action_stage, args.output)
        if args.dry_run:
            json.dump(prepared, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0

        executable = shutil.which(TRUSTED_PROGRAM)
        if executable is None:
            raise ActionError("auto-re-cli is not available on PATH")
        argv = [executable, *prepared["argv"][1:]]
        completed = subprocess.run(argv, shell=False, check=False)
        return completed.returncode
    except (ActionError, OSError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
