#!/usr/bin/env python3
"""Diagnose Auto-RE Skill/CLI version cohesion and duplicate registration."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess  # retained test seam; lifecycle is owned by process_control
import sys
from typing import Any, Optional


# Import only the helper shipped beside this script, not a module from CWD/PATH.
# Managed Skill inventories must not acquire import-time bytecode files.
sys.dont_write_bytecode = True
_PROCESS_SPEC = importlib.util.spec_from_file_location(
    "auto_re_process_control", pathlib.Path(__file__).with_name("process_control.py")
)
assert _PROCESS_SPEC is not None and _PROCESS_SPEC.loader is not None
process_control = importlib.util.module_from_spec(_PROCESS_SPEC)
_PROCESS_SPEC.loader.exec_module(process_control)

SKILL_NAME = "auto-re"
TRUSTED_PROGRAM = "auto-re-cli"
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CLI_VERSION_PATTERN = re.compile(r"^auto-re-cli ([0-9]+\.[0-9]+\.[0-9]+)$")
VERSION_MAX_BYTES = 128
MANAGED_MARKER_MAX_BYTES = 256 * 1024
SKILL_FILE_MAX_BYTES = 64 * 1024
DOCTOR_OUTPUT_MAX_BYTES = 64 * 1024
PROBE_OUTPUT_MAX_BYTES = 4096
MAX_MANAGED_SKILL_FILES = 256


class DoctorError(ValueError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise DoctorError(f"cannot hash CLI: {error}") from error
    return digest.hexdigest()


def read_bounded_regular_file(
    path: pathlib.Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DoctorError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DoctorError(f"{label} must be a direct regular file")
    if metadata.st_size > max_bytes:
        raise DoctorError(f"{label} is too large: limit={max_bytes} observed={metadata.st_size}")
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as error:
        raise DoctorError(f"cannot read {label}: {error}") from error
    if len(data) > max_bytes:
        raise DoctorError(f"{label} is too large: limit={max_bytes} observed={len(data)}")
    return data


def read_skill_version(skill_root: pathlib.Path) -> str:
    data = read_bounded_regular_file(
        skill_root / "VERSION",
        max_bytes=VERSION_MAX_BYTES,
        label="version file",
    )
    try:
        version = data.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise DoctorError("version file is not UTF-8") from error
    if not VERSION_PATTERN.fullmatch(version):
        raise DoctorError(f"version file is not semantic x.y.z: {version!r}")
    return version


def read_managed_marker(skill_root: pathlib.Path) -> Optional[dict[str, Any]]:
    marker_path = skill_root / ".autore-managed.json"
    try:
        marker_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise DoctorError(f"cannot inspect managed marker: {error}") from error
    data = read_bounded_regular_file(
        marker_path,
        max_bytes=MANAGED_MARKER_MAX_BYTES,
        label="managed marker",
    )
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise DoctorError(f"cannot parse managed marker: {str(error)[:512]}") from error
    if not isinstance(value, dict):
        raise DoctorError("managed marker root must be an object")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "skill-install"
        or value.get("skill") != SKILL_NAME
        or not isinstance(value.get("version"), str)
        or not VERSION_PATTERN.fullmatch(value["version"])
    ):
        raise DoctorError("managed marker identity or version is invalid")
    managed_files = value.get("managed_files")
    digest = value.get("sha256")
    if (
        not isinstance(managed_files, list)
        or not managed_files
        or len(managed_files) > MAX_MANAGED_SKILL_FILES
        or any(not isinstance(item, str) or not item for item in managed_files)
        or len(set(managed_files)) != len(managed_files)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise DoctorError("managed marker file inventory or digest is invalid")
    return value


def skill_file_inventory(skill_root: pathlib.Path) -> list[str]:
    files: list[str] = []
    try:
        items = sorted(skill_root.rglob("*"))
    except OSError as error:
        raise DoctorError(f"cannot inventory managed Skill: {error}") from error
    for item in items:
        if item.name == ".autore-managed.json":
            continue
        if item.is_symlink():
            raise DoctorError(f"managed Skill contains a symlink: {item}")
        if item.is_file():
            files.append(item.relative_to(skill_root).as_posix())
            if len(files) > MAX_MANAGED_SKILL_FILES:
                raise DoctorError(
                    f"managed Skill exceeds {MAX_MANAGED_SKILL_FILES} files"
                )
        elif not item.is_dir():
            raise DoctorError(f"managed Skill contains a special file: {item}")
    return files


def installed_skill_digest(skill_root: pathlib.Path, files: list[str]) -> str:
    digest = hashlib.sha256()
    for relative_text in files:
        digest.update(relative_text.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(skill_root / relative_text)))
    return digest.hexdigest()


def probe_cli_version(executable: pathlib.Path) -> tuple[str, str]:
    try:
        output_bytes = process_control.probe_output(executable, max_bytes=PROBE_OUTPUT_MAX_BYTES)
    except process_control.ProcessError as error:
        raise DoctorError(f"cannot probe CLI version: {error}") from error
    try:
        output = output_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise DoctorError("CLI version output is not UTF-8") from error
    match = CLI_VERSION_PATTERN.fullmatch(output)
    if match is None:
        raise DoctorError(f"unexpected CLI version output: {output!r}")
    return match.group(1), output


def is_auto_re_skill(path: pathlib.Path) -> bool:
    skill_file = path / "SKILL.md"
    try:
        data = read_bounded_regular_file(
            skill_file,
            max_bytes=SKILL_FILE_MAX_BYTES,
            label=f"Skill entrypoint {skill_file}",
        )
        text = data.decode("utf-8")
    except (DoctorError, UnicodeDecodeError):
        return False
    return bool(re.search(r"^name:\s*auto-re\s*$", text, re.MULTILINE))


def default_candidate_roots(active_root: pathlib.Path) -> list[pathlib.Path]:
    home = pathlib.Path.home()
    candidates = [
        active_root,
        home / ".agents/skills/auto-re",
        home / ".codex/skills/auto-re",
    ]
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        candidates.append(pathlib.Path(codex_home).expanduser() / "skills/auto-re")
    current = pathlib.Path.cwd().absolute()
    for parent in [current, *current.parents]:
        candidates.append(parent / ".agents/skills/auto-re")
        if (parent / ".git").exists():
            break
    return candidates


def existing_skill_roots(candidates: list[pathlib.Path]) -> list[pathlib.Path]:
    roots: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir() or not is_auto_re_skill(resolved):
            continue
        seen.add(resolved)
        roots.append(resolved)
    return roots


def diagnose(
    skill_root: pathlib.Path,
    *,
    executable: Optional[pathlib.Path] = None,
    candidate_roots: Optional[list[pathlib.Path]] = None,
) -> dict[str, Any]:
    try:
        active_root = skill_root.expanduser().resolve(strict=True)
    except OSError as error:
        raise DoctorError(f"cannot resolve active Skill root: {error}") from error
    if not active_root.is_dir() or not is_auto_re_skill(active_root):
        raise DoctorError("active Skill root is not an auto-re Skill")
    skill_version = read_skill_version(active_root)
    marker = read_managed_marker(active_root)

    if executable is None:
        resolved_program = shutil.which(TRUSTED_PROGRAM)
        if resolved_program is None:
            raise DoctorError("auto-re-cli is not available on PATH")
        executable = pathlib.Path(resolved_program)
    try:
        cli_path = executable.expanduser().resolve(strict=True)
    except OSError as error:
        raise DoctorError(f"cannot resolve CLI: {error}") from error
    if not cli_path.is_file():
        raise DoctorError("CLI path must be a regular file")
    cli_version, version_output = probe_cli_version(cli_path)

    candidates = (
        candidate_roots
        if candidate_roots is not None
        else default_candidate_roots(active_root)
    )
    roots = existing_skill_roots(candidates)
    duplicates = [path for path in roots if path != active_root]
    marker_version = marker.get("version") if marker is not None else None
    version_match = cli_version == skill_version and (
        marker_version is None or marker_version == skill_version
    )
    managed_content_match: Optional[bool] = None
    if marker is not None:
        current_files = skill_file_inventory(active_root)
        managed_content_match = current_files == sorted(marker["managed_files"]) and (
            installed_skill_digest(active_root, current_files) == marker["sha256"]
        )
    warnings: list[str] = []
    if not version_match:
        warnings.append("CLI, Skill VERSION, and managed marker versions do not agree")
    if duplicates:
        warnings.append("duplicate auto-re Skill registrations were found")
    if managed_content_match is False:
        warnings.append("managed Skill file inventory or content digest has drifted")
    if marker is None:
        warnings.append("active Skill has no AutoRE managed-install marker")

    return {
        "schema_version": 1,
        "kind": "auto_re_skill_doctor",
        "ok": version_match and not duplicates and managed_content_match is not False,
        "skill": {
            "name": SKILL_NAME,
            "root": str(active_root),
            "version": skill_version,
            "managed": marker is not None,
            "managed_marker_version": marker_version,
        },
        "cli": {
            "path": str(cli_path),
            "version": cli_version,
            "version_output": version_output,
            "sha256": sha256_file(cli_path),
        },
        "version_match": version_match,
        "managed_content_match": managed_content_match,
        "duplicate_count": len(duplicates),
        "duplicate_skill_roots": [str(path) for path in duplicates],
        "discovery_roots_checked": [str(path) for path in roots],
        "warnings": warnings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = pathlib.Path(__file__).resolve().parents[1]
    parser.add_argument("--skill-root", type=pathlib.Path, default=default_root)
    parser.add_argument("--cli", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = diagnose(args.skill_root, executable=args.cli)
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > DOCTOR_OUTPUT_MAX_BYTES:
            raise DoctorError(
                "doctor output is too large: "
                f"limit={DOCTOR_OUTPUT_MAX_BYTES} observed={len(encoded)}"
            )
    except DoctorError as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    sys.stdout.buffer.write(encoded)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())