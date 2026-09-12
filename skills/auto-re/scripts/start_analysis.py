#!/usr/bin/env python3
"""Collect one static Auto-RE result with preflight and bounded diagnostic logs."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Optional

# A managed Skill's inventory is immutable; importing helpers must not add .pyc.
sys.dont_write_bytecode = True
import run_next_action as actions
import skill_doctor as doctor


SKILL_ROOT = Path(__file__).resolve().parents[1]
LOG_TAIL_BYTES = 16 * 1024
# Each entry has a known JSON contract; this is not arbitrary CLI passthrough.
FIRST_COMMANDS = (
    "report", "function", "inspect-go", "inspect-rust", "inspect-die",
    "inspect-upx", "inspect-vmp", "pe-strings", "pe-resources",
)


def address(text: str) -> str:
    try:
        value = int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("address must be decimal or hexadecimal") from error
    if not 0 <= value < 1 << 64:
        raise argparse.ArgumentTypeError("address must be an unsigned 64-bit integer")
    return hex(value)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("input", type=Path)
    parser.add_argument("--result-dir", type=Path, required=True,
                        help="new result directory with an existing parent, outside the input file parent directory "
                             "(including its descendants) and the installed Skill")
    parser.add_argument("--cli", type=Path, help="trusted installed analyzer, never the input")
    parser.add_argument("--command", choices=FIRST_COMMANDS,
                        help="one static query; default: function with a selector, otherwise report")
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--addr", type=address)
    selector.add_argument("--symbol")
    parser.add_argument("--raw-shellcode", action="store_true")
    parser.add_argument("--arch", choices=("x86", "x86-64", "x86_64", "aarch64"),
                        help="target architecture; x86-64 and x86_64 are equivalent")
    parser.add_argument("--base-address", type=address)
    parser.add_argument("--entry-address", type=address)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout-seconds", type=actions.positive_seconds,
                        default=actions.DEFAULT_TIMEOUT_SECONDS,
                        help="analysis execution budget; increase for long static analyses (default: 900)")
    args = parser.parse_args(argv)
    selected = args.addr is not None or args.symbol is not None
    args.command = args.command or ("function" if selected else "report")
    if args.command == "function" and not selected:
        parser.error("--command function requires --addr or --symbol")
    if args.command != "function" and selected:
        parser.error("--addr and --symbol are only supported by --command function")
    if args.command == "pe-resources" and (
        args.arch is not None or args.raw_shellcode
        or args.base_address is not None or args.entry_address is not None
    ):
        parser.error("pe-resources does not accept architecture or raw-input arguments")
    if args.raw_shellcode and (args.arch is None or args.base_address is None):
        parser.error("raw shellcode requires explicit --arch and --base-address")
    if not args.raw_shellcode and (args.base_address is not None or args.entry_address is not None):
        parser.error("--base-address and --entry-address require --raw-shellcode")
    if args.symbol is not None and (not args.symbol.strip() or args.symbol.startswith("-")):
        parser.error("--symbol must be non-empty and must not start with '-' (use --addr instead)")
    return args


def within(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def preflight_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    target = args.input.expanduser().resolve(strict=True)
    if not stat.S_ISREG(target.stat().st_mode):
        raise actions.ActionError("input must be a regular file")
    requested = args.result_dir.expanduser().absolute()
    # Check before resolve: do not follow a dangling output symlink into creation.
    actions._require_absent(requested, "result directory")
    output = requested.parent.resolve(strict=True) / requested.name
    actions._require_absent(output, "result directory")
    if within(output, target.parent):
        raise actions.ActionError(
            "result directory must be outside the input file parent directory "
            "to keep analysis output separate from samples: "
            f"result_dir={output}; input_dir={target.parent}"
        )
    if within(output, SKILL_ROOT):
        raise actions.ActionError("result directory must be outside the installed Skill")
    return target, output


def prepare(args: argparse.Namespace, target: Path, output: Path) -> dict:
    command = args.command
    argv = [actions.TRUSTED_PROGRAM, command, str(target)]
    if args.addr is not None:
        argv += ["--addr", args.addr]
    if args.symbol is not None:
        argv += ["--symbol", args.symbol]
    argv += ["--format", "json"]
    if command != "function":
        argv += ["--json-profile", "ai"]
    if command == "report":
        argv += ["--sections", "binary,summary,inspections,flow,functions,types", "--limit", "8"]
    if args.raw_shellcode:
        argv.append("--raw-shellcode")
    for flag, value in (("--arch", args.arch), ("--base-address", args.base_address),
                        ("--entry-address", args.entry_address)):
        if value is not None:
            argv += [flag, value]
    argv += ["--output", str(output / "analysis.json")]
    return {
        "ok": True, "action_stage": f"initial.{command}",
        "reason": "collect first static evidence for the supplied input and selector",
        "expected_output": "one bounded Auto-RE JSON result",
        "stop_condition": "initial result collected; agent must inspect evidence before continuing",
        "command_owned_sink": False, "argv": argv,
    }


def trusted_cli(args: argparse.Namespace, target: Path) -> Path:
    candidate = args.cli if args.cli is not None else shutil.which(actions.TRUSTED_PROGRAM)
    if candidate is None:
        raise actions.ActionError("auto-re-cli is not available on PATH")
    executable = Path(candidate).expanduser().resolve(strict=True)
    if not executable.is_file():
        raise actions.ActionError("trusted CLI must be a regular file")
    # This must precede doctor/--version, which executes the trusted analyzer.
    if os.path.samefile(executable, target):
        raise actions.ActionError("input must never be used as the CLI, including aliases")
    return executable


def run(args: argparse.Namespace) -> tuple[int, dict]:
    target, output = preflight_paths(args)
    prepared = prepare(args, target, output)
    actions.validate_prepared_argv(prepared["argv"], command_owned_sink=False)
    if args.dry_run:
        return 0, dict(prepared, readiness_checked=False, analysis_executed=False,
                       investigation_complete=False, result_dir=str(output),
                       result_validation="not_attempted")

    executable = trusted_cli(args, target)
    readiness = doctor.diagnose(SKILL_ROOT, executable=executable)
    if not readiness["ok"]:
        raise actions.ActionError("Skill preflight failed: " + "; ".join(readiness["warnings"]))
    # No replacement or automatic recursive cleanup: existing user paths survive.
    output.mkdir(mode=0o700)
    receipts = output / "receipts"
    receipts.mkdir(mode=0o700)
    code, summary = actions.execute_prepared_with_receipt(
        prepared, executable, receipts / "initial.json", log_tail_bytes=LOG_TAIL_BYTES,
        timeout_seconds=args.timeout_seconds,
    )
    result_path = output / "analysis.json"
    summary.update(readiness_checked=True, analysis_executed=True,
                   investigation_complete=False, result_path=str(result_path),
                   result_validation="not_attempted",
                   warnings=readiness["warnings"],
                   next_step="Read result JSON; inspect warnings, completion and next_actions before choosing one relevant follow-up.")
    if code != 0:
        summary.update(
            failure_phase="execution",
            next_step="Inspect the execution receipt and bounded logs before changing the query or budget; partial results are not validated evidence.",
        )
        return code, summary

    try:
        if not stat.S_ISREG(result_path.lstat().st_mode):
            raise actions.ActionError("analysis JSON must be a direct regular file")
        result = actions.load_json_object(result_path)
        wrapper = actions.validate_result_contract(result)
        expected = "wrapper:function" if args.command == "function" else "profile:ai"
        if wrapper != expected:
            raise actions.ActionError(f"{args.command} expected {expected}, received {wrapper}")
    except (actions.ActionError, OSError, RuntimeError, ValueError) as error:
        # The receipt describes the process; this failure belongs to the launcher.
        # Keep its paths/status rather than losing them in main's preflight error.
        summary.update(
            ok=False, exit_code=1, result_validation="failed",
            failure_phase="result_validation",
            error="result JSON validation failed: " + str(error)[:512],
            next_step="Inspect the retained receipt, bounded logs and result path; correct the output/contract problem before retrying into a new result directory. Do not treat the invalid result as evidence.",
        )
        return 1, summary
    summary.update(result_wrapper=wrapper, result_validation="passed")
    return code, summary


def main() -> int:
    try:
        code, result = run(parse_args())
        # Keep post-execution validation errors on stderr for existing callers.
        stream = sys.stderr if result.get("failure_phase") == "result_validation" else sys.stdout
        json.dump(result, stream, sort_keys=True)
        stream.write("\n")
        # Preserve normal error codes; map POSIX signal termination to shell form.
        return code if code >= 0 else 128 - code
    except (actions.ActionError, doctor.DoctorError, OSError, RuntimeError, ValueError) as error:
        json.dump({"ok": False, "error": str(error), "investigation_complete": False},
                  sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
