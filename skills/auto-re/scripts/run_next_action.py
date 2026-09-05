#!/usr/bin/env python3
"""Validate and run one emitted Auto-RE static next action."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, BinaryIO, NamedTuple, Optional


TRUSTED_PROGRAM = "auto-re-cli"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"0.1.0"})
SUPPORTED_PROFILES = frozenset({"ai"})
SUPPORTED_MANIFEST_KINDS = frozenset({"context_bundle", "agent_spill_manifest"})
FORBIDDEN_FLAGS = {"--execute"}
COMMAND_OWNED_SINK_FLAGS = {"--bundle-dir", "--spill-dir"}
CONTROL_READ_CHUNK_BYTES = 64 * 1024
LOG_READ_CHUNK_BYTES = 64 * 1024
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


class ActionError(ValueError):
    pass


class CapturedStream(NamedTuple):
    tail: bytes
    bytes_total: int
    sha256: str


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
        if (
            owner != "auto-re-cli"
            or not isinstance(kind, str)
            or kind not in SUPPORTED_MANIFEST_KINDS
        ):
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


def _capture_stream(
    handle: BinaryIO,
    tail_bytes: int,
    results: dict[str, CapturedStream],
    errors: list[BaseException],
    key: str,
) -> None:
    digest = hashlib.sha256()
    total = 0
    tail = bytearray()
    try:
        while True:
            chunk = handle.read(LOG_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if tail_bytes:
                tail.extend(chunk)
                if len(tail) > tail_bytes:
                    del tail[: len(tail) - tail_bytes]
        results[key] = CapturedStream(bytes(tail), total, digest.hexdigest())
    except BaseException as error:
        errors.append(error)
    finally:
        handle.close()


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


def _write_receipt(path: pathlib.Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > RECEIPT_MAX_BYTES:
        raise ActionError(
            "execution receipt exceeds limit: "
            f"limit={RECEIPT_MAX_BYTES} observed={len(encoded)}"
        )
    _write_private_bytes(path, encoded, "execution receipt")


def probe_program_version(executable: pathlib.Path) -> str:
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ActionError(f"cannot probe trusted program version: {error}") from error
    combined = completed.stdout + completed.stderr
    if len(combined) > PROGRAM_VERSION_MAX_BYTES:
        raise ActionError(
            "trusted program version output exceeds limit: "
            f"limit={PROGRAM_VERSION_MAX_BYTES} observed={len(combined)}"
        )
    if completed.returncode != 0:
        raise ActionError(
            f"trusted program version probe failed with exit code {completed.returncode}"
        )
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


def _command_sink_values(argv: list[str]) -> list[pathlib.Path]:
    sinks: list[pathlib.Path] = []
    for index, argument in enumerate(argv):
        for flag in COMMAND_OWNED_SINK_FLAGS:
            if argument == flag and index + 1 < len(argv):
                sinks.append(pathlib.Path(argv[index + 1]).expanduser().absolute())
            elif argument.startswith(f"{flag}="):
                sinks.append(
                    pathlib.Path(argument.split("=", 1)[1]).expanduser().absolute()
                )
    return sinks


def validate_receipt_sink_separation(
    prepared: dict[str, Any],
    receipt: pathlib.Path,
    log_dir: pathlib.Path,
) -> None:
    argv = prepared["argv"]
    sinks = (
        _command_sink_values(argv)
        if prepared["command_owned_sink"]
        else [pathlib.Path(argv[-1])]
    )
    try:
        diagnostics = [receipt.resolve(), log_dir.resolve()]
        resolved_sinks = [sink.expanduser().resolve() for sink in sinks]
    except (OSError, RuntimeError) as error:
        raise ActionError(f"cannot resolve diagnostic or action sink: {error}") from error
    for sink in resolved_sinks:
        for diagnostic in diagnostics:
            if (
                sink == diagnostic
                or sink in diagnostic.parents
                or diagnostic in sink.parents
            ):
                if prepared["command_owned_sink"]:
                    raise ActionError(
                        "receipt or log path overlaps a command-owned action sink"
                    )
                raise ActionError("receipt or log path aliases action output")


def prepare_action_receipt_paths(
    prepared: dict[str, Any], receipt_path: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Use the same non-mutating diagnostic preflight for dry-run and execution."""
    receipt, logs = prepare_receipt_paths(receipt_path)
    validate_receipt_sink_separation(prepared, receipt, logs)
    return receipt, logs


def execute_prepared_with_receipt(
    prepared: dict[str, Any],
    executable: pathlib.Path,
    receipt_path: pathlib.Path,
    *,
    log_tail_bytes: int = LOG_TAIL_BYTES,
) -> tuple[int, dict[str, Any]]:
    if (
        not isinstance(log_tail_bytes, int)
        or isinstance(log_tail_bytes, bool)
        or not 0 <= log_tail_bytes <= LOG_TAIL_BYTES
    ):
        raise ActionError(f"log tail byte limit must be an integer from 0 to {LOG_TAIL_BYTES}")
    validate_prepared_argv(
        prepared.get("argv"),
        command_owned_sink=prepared.get("command_owned_sink") is True,
    )
    try:
        resolved_executable = executable.expanduser().resolve(strict=True)
    except OSError as error:
        raise ActionError(f"cannot resolve trusted program: {error}") from error
    if not resolved_executable.is_file():
        raise ActionError("trusted program must be a regular file")
    receipt, log_dir = prepare_action_receipt_paths(prepared, receipt_path)
    program_version = probe_program_version(resolved_executable)
    program_sha256 = sha256_file(resolved_executable)

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
        process = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        shutil.rmtree(log_dir, ignore_errors=True)
        raise ActionError(f"cannot launch trusted program: {error}") from error
    assert process.stdout is not None and process.stderr is not None
    results: dict[str, CapturedStream] = {}
    errors: list[BaseException] = []
    threads = [
        threading.Thread(
            target=_capture_stream,
            args=(process.stdout, log_tail_bytes, results, errors, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=_capture_stream,
            args=(process.stderr, log_tail_bytes, results, errors, "stderr"),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    exit_code = process.wait()
    for thread in threads:
        thread.join()
    ended_at = utc_now()
    duration_ms = round((time.monotonic() - started_monotonic) * 1000)
    if errors:
        raise ActionError(f"cannot capture trusted program output: {errors[0]}")
    if set(results) != {"stdout", "stderr"}:
        raise ActionError("trusted program output capture did not complete")

    try:
        _write_private_bytes(stdout_path, results["stdout"].tail, "stdout tail log")
        _write_private_bytes(stderr_path, results["stderr"].tail, "stderr tail log")
        receipt_value = {
            "schema_version": 1,
            "owner": "auto-re-skill",
            "kind": "auto_re_action_execution_receipt",
            "action_stage": prepared["action_stage"],
            "reason": prepared["reason"],
            "expected_output": prepared["expected_output"],
            "stop_condition": prepared["stop_condition"],
            "program": {
                "path": str(resolved_executable),
                "version_output": program_version,
                "sha256": program_sha256,
            },
            "argv": argv,
            "sink": _sink_record(prepared),
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "stdout": _stream_receipt(
                stdout_path, results["stdout"], log_tail_bytes
            ),
            "stderr": _stream_receipt(
                stderr_path, results["stderr"], log_tail_bytes
            ),
            "evidence_boundary": "operational_diagnostics_not_target_analysis_evidence",
        }
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
    elif (
        len(output_positions) != 1
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
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        prepared = prepare_action(args.result, args.action_stage, args.output)
        if args.dry_run:
            if args.receipt is not None:
                receipt, logs = prepare_action_receipt_paths(prepared, args.receipt)
                prepared["planned_receipt"] = str(receipt)
                prepared["planned_log_dir"] = str(logs)
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
            )
            json.dump(summary, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return exit_code
        argv = [executable, *prepared["argv"][1:]]
        completed = subprocess.run(argv, shell=False, check=False)
        return completed.returncode
    except (ActionError, OSError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())