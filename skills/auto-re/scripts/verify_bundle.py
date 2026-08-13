#!/usr/bin/env python3
"""Validate Auto-RE bundle/spill ownership and payload integrity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import sys
from typing import Any


SUPPORTED_KINDS = {"context_bundle", "agent_spill_manifest"}
EXPECTED_OWNER = "auto-re-cli"
EXPECTED_OWNERSHIP = "command"


class ValidationError(Exception):
    pass


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read JSON manifest: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError("manifest root must be an object")
    return value


def safe_relative_path(value: Any) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ValidationError("files[].path must be a non-empty string")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or value.startswith(("/", "\\")):
        raise ValidationError(f"absolute payload path is forbidden: {value}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValidationError(f"non-canonical payload path is forbidden: {value}")
    if "\\" in value:
        raise ValidationError(f"backslash payload path is forbidden: {value}")
    return path


def regular_file_without_links(path: pathlib.Path, root: pathlib.Path) -> os.stat_result:
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ValidationError(f"cannot inspect payload path {current}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ValidationError(f"symlink payload path is forbidden: {current}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"payload is not a regular file: {path}")
    return metadata


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ValidationError(f"cannot hash payload {path}: {error}") from error
    return digest.hexdigest()


def validate_manifest(path: pathlib.Path) -> dict[str, Any]:
    try:
        manifest_metadata = path.lstat()
    except OSError as error:
        raise ValidationError(f"cannot inspect manifest: {error}") from error
    if stat.S_ISLNK(manifest_metadata.st_mode) or not stat.S_ISREG(
        manifest_metadata.st_mode
    ):
        raise ValidationError("manifest must be a non-symlink regular file")

    manifest = load_json_object(path)
    if manifest.get("owner") != EXPECTED_OWNER:
        raise ValidationError("manifest owner must be auto-re-cli")
    if manifest.get("kind") not in SUPPORTED_KINDS:
        raise ValidationError(f"unsupported manifest kind: {manifest.get('kind')!r}")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValidationError("manifest files[] must be a non-empty array")

    root = path.parent.resolve()
    seen_paths: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, row in enumerate(files):
        if not isinstance(row, dict):
            raise ValidationError(f"files[{index}] must be an object")
        if row.get("ownership") != EXPECTED_OWNERSHIP:
            raise ValidationError(f"files[{index}].ownership must be command")
        relative = safe_relative_path(row.get("path"))
        relative_text = relative.as_posix()
        if relative_text in seen_paths:
            raise ValidationError(f"duplicate payload path: {relative_text}")
        seen_paths.add(relative_text)

        expected_bytes = row.get("bytes")
        if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool):
            raise ValidationError(f"files[{index}].bytes must be an integer")
        if expected_bytes < 0:
            raise ValidationError(f"files[{index}].bytes must not be negative")

        expected_sha256 = row.get("sha256")
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ValidationError(
                f"files[{index}].sha256 must be lowercase hexadecimal SHA-256"
            )

        payload = root.joinpath(*relative.parts)
        metadata = regular_file_without_links(payload, root)
        if metadata.st_size != expected_bytes:
            raise ValidationError(
                f"payload size mismatch for {relative_text}: "
                f"expected {expected_bytes}, got {metadata.st_size}"
            )
        actual_sha256 = sha256_file(payload)
        if actual_sha256 != expected_sha256:
            raise ValidationError(
                f"payload SHA-256 mismatch for {relative_text}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )

        validated.append(
            {
                "path": str(payload),
                "relative_path": relative_text,
                "bytes": expected_bytes,
                "sha256": actual_sha256,
                "section_id": row.get("section_id", row.get("section")),
            }
        )

    return {
        "ok": True,
        "owner": manifest["owner"],
        "kind": manifest["kind"],
        "schema_version": manifest.get("schema_version"),
        "manifest_path": str(path.resolve()),
        "file_count": len(validated),
        "files": validated,
        "completion": manifest.get("completion"),
        "next_action_count": len(manifest.get("next_actions", []))
        if isinstance(manifest.get("next_actions", []), list)
        else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate an Auto-RE context bundle or direct spill manifest."
    )
    parser.add_argument("manifest", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = validate_manifest(args.manifest)
    except ValidationError as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
