#!/usr/bin/env python3
"""Validate and run one emitted Auto-RE static next action."""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Optional


TRUSTED_PROGRAM = "auto-re-cli"
FORBIDDEN_FLAGS = {"--execute"}
COMMAND_OWNED_SINK_FLAGS = {"--bundle-dir", "--spill-dir"}


class ActionError(ValueError):
    pass


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActionError(f"cannot read result JSON: {error}") from error
    if not isinstance(value, dict):
        raise ActionError("result JSON root must be an object")
    return value


def select_action(result: dict[str, Any], action_id: str) -> dict[str, Any]:
    actions = result.get("next_actions")
    if not isinstance(actions, list):
        raise ActionError("result next_actions must be an array")
    matches = [
        action
        for action in actions
        if isinstance(action, dict) and action.get("id") == action_id
    ]
    if len(matches) != 1:
        raise ActionError(
            f"action id must select exactly one next action: {action_id!r}"
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
    action_id: str,
    output: Optional[pathlib.Path],
) -> dict[str, Any]:
    result_path = result_path.expanduser().resolve()
    action = select_action(load_json_object(result_path), action_id)
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
        "action_id": action_id,
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
    parser.add_argument("--action-id", required=True)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        prepared = prepare_action(args.result, args.action_id, args.output)
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
