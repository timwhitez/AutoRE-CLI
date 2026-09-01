#!/usr/bin/env python3
"""Validate Auto-RE bundle/spill ownership and payload integrity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, BinaryIO, NamedTuple


SUPPORTED_SCHEMA_VERSIONS = {"0.1.0"}
SUPPORTED_KINDS = {"context_bundle", "agent_spill_manifest"}
EXPECTED_OWNER = "auto-re-cli"
EXPECTED_OWNERSHIP = "command"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
COPY_CHUNK_BYTES = 1024 * 1024
CONTROL_READ_CHUNK_BYTES = 64 * 1024
MAX_BUNDLE_FILE_COUNT = 64
MAX_TOTAL_PAYLOAD_BYTES = 64 * 1024 * 1024
VERIFICATION_RECEIPT_MAX_BYTES = 1024 * 1024
VERIFIED_ROOT_MARKER = ".auto-re-verified-root.json"
VERIFIED_ROOT_PREFIX = "auto-re-verified-bundle."


class ControlJsonPolicy(NamedTuple):
    kind: str
    max_encoded_bytes: int
    max_depth: int
    max_values: int
    max_container_entries: int
    max_string_bytes: int


VERIFIED_BUNDLE_MANIFEST_POLICY = ControlJsonPolicy(
    "verified_bundle_manifest",
    8 * 1024 * 1024,
    64,
    262_144,
    100_000,
    1024 * 1024,
)

VERIFICATION_RECEIPT_POLICY = ControlJsonPolicy(
    "bundle_verification_receipt",
    VERIFICATION_RECEIPT_MAX_BYTES,
    64,
    4096,
    1024,
    1024 * 1024,
)

VERIFIED_ROOT_MARKER_POLICY = ControlJsonPolicy(
    "verified_root_marker",
    8192,
    8,
    64,
    32,
    4096,
)


class ManifestFileRow(NamedTuple):
    relative: pathlib.PurePosixPath
    relative_text: str
    expected_bytes: int
    expected_sha256: str
    section_id: Any


class ValidationError(Exception):
    pass


def _control_file_too_large(
    policy: ControlJsonPolicy, observed: int
) -> ValidationError:
    return ValidationError(
        "control_file_too_large: "
        f"kind={policy.kind} limit={policy.max_encoded_bytes} "
        f"observed_at_least={observed}"
    )


def _control_file_structure_limit(
    policy: ControlJsonPolicy,
    dimension: str,
    limit: int,
    observed: int,
) -> ValidationError:
    return ValidationError(
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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _materialization_limit(dimension: str, limit: int, observed: int) -> ValidationError:
    return ValidationError(
        "bundle_materialization_limit: "
        f"dimension={dimension} limit={limit} observed={observed}"
    )


def prepare_manifest_rows(files: Any) -> tuple[list[ManifestFileRow], int]:
    if not isinstance(files, list) or not files:
        raise ValidationError("manifest files[] must be a non-empty array")
    if len(files) > MAX_BUNDLE_FILE_COUNT:
        raise _materialization_limit(
            "file_count", MAX_BUNDLE_FILE_COUNT, len(files)
        )

    rows: list[ManifestFileRow] = []
    seen_paths: set[str] = set()
    total_payload_bytes = 0
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
        total_payload_bytes += expected_bytes
        if total_payload_bytes > MAX_TOTAL_PAYLOAD_BYTES:
            raise _materialization_limit(
                "total_payload_bytes",
                MAX_TOTAL_PAYLOAD_BYTES,
                total_payload_bytes,
            )

        expected_sha256 = row.get("sha256")
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ValidationError(
                f"files[{index}].sha256 must be lowercase hexadecimal SHA-256"
            )
        rows.append(
            ManifestFileRow(
                relative,
                relative_text,
                expected_bytes,
                expected_sha256,
                row.get("section_id", row.get("section")),
            )
        )
    return rows, total_payload_bytes


def path_is_indirection(path: pathlib.Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError as error:
            raise ValidationError(
                f"cannot classify payload path indirection {path}: {error}"
            ) from error
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def regular_file_without_links(path: pathlib.Path, root: pathlib.Path) -> os.stat_result:
    current = root
    metadata: os.stat_result | None = None
    for part in path.relative_to(root).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ValidationError(f"cannot inspect payload path {current}: {error}") from error
        if path_is_indirection(current, metadata):
            raise ValidationError(f"reparse or symlink payload path is forbidden: {current}")
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"payload is not a regular file: {path}")
    return metadata


def stable_identity(metadata: os.stat_result, label: str) -> tuple[int, int]:
    device = getattr(metadata, "st_dev", None)
    inode = getattr(metadata, "st_ino", None)
    if (
        not isinstance(device, int)
        or not isinstance(inode, int)
        or device < 0
        or inode <= 0
    ):
        raise ValidationError(f"stable file identity is unavailable for {label}")
    return device, inode


def metadata_matches_opened(
    checked: os.stat_result,
    opened: os.stat_result,
    label: str,
) -> bool:
    return (
        stat.S_IFMT(checked.st_mode) == stat.S_IFMT(opened.st_mode)
        and stable_identity(checked, label) == stable_identity(opened, label)
    )


def open_regular_file_stably(
    path: pathlib.Path,
    root: pathlib.Path,
    label: str,
) -> tuple[BinaryIO, os.stat_result]:
    checked = regular_file_without_links(path, root)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValidationError(f"cannot open {label} {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if path_is_indirection(path, opened) or not stat.S_ISREG(opened.st_mode):
            raise ValidationError(f"{label} is not a direct regular file: {path}")
        if not metadata_matches_opened(checked, opened, label):
            raise ValidationError(f"{label} changed before open: {path}")
        current = regular_file_without_links(path, root)
        if not metadata_matches_opened(current, opened, label):
            raise ValidationError(f"{label} changed during open: {path}")
        return os.fdopen(descriptor, "rb", closefd=True), opened
    except BaseException:
        os.close(descriptor)
        raise


def read_json_object_stably(
    path: pathlib.Path,
    root: pathlib.Path,
    label: str,
    *,
    policy: ControlJsonPolicy = VERIFIED_BUNDLE_MANIFEST_POLICY,
) -> dict[str, Any]:
    handle, opened = open_regular_file_stably(path, root, label)
    try:
        try:
            if opened.st_size > policy.max_encoded_bytes:
                raise _control_file_too_large(policy, opened.st_size)
            data = _read_bounded_control_bytes(handle, policy)
        except OSError as error:
            raise ValidationError(f"cannot read JSON {label}: {error}") from error
        after = os.fstat(handle.fileno())
        if (
            not metadata_matches_opened(opened, after, label)
            or after.st_size != opened.st_size
        ):
            raise ValidationError(f"{label} changed while it was read: {path}")
    finally:
        handle.close()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError(f"cannot read JSON {label}: {error}") from error
    _validate_json_shape(value, policy)
    if not isinstance(value, dict):
        raise ValidationError(f"{label} root must be an object")
    return value


def copy_and_hash_opened_payload(
    handle: BinaryIO,
    opened: os.stat_result,
    destination: pathlib.Path,
    expected_bytes: int,
    expected_sha256: str,
    label: str,
) -> tuple[int, str]:
    if opened.st_size != expected_bytes:
        raise ValidationError(
            f"payload size mismatch for {label}: "
            f"expected {expected_bytes}, got {opened.st_size}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        with destination.open("xb") as output:
            while observed_bytes < expected_bytes:
                remaining = expected_bytes - observed_bytes
                chunk = handle.read(min(COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                observed_bytes += len(chunk)
                digest.update(chunk)
                output.write(chunk)
            trailing = handle.read(1)
            if trailing:
                observed_bytes += len(trailing)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(handle.fileno())
    except OSError as error:
        destination.unlink(missing_ok=True)
        raise ValidationError(f"cannot materialize verified {label}: {error}") from error

    actual_sha256 = digest.hexdigest()
    if (
        not metadata_matches_opened(opened, after, label)
        or after.st_size != opened.st_size
    ):
        destination.unlink(missing_ok=True)
        raise ValidationError(f"{label} changed while it was read")
    if observed_bytes != expected_bytes:
        destination.unlink(missing_ok=True)
        raise ValidationError(
            f"payload size mismatch for {label}: expected {expected_bytes}, got {observed_bytes}"
        )
    if actual_sha256 != expected_sha256:
        destination.unlink(missing_ok=True)
        raise ValidationError(
            f"payload SHA-256 mismatch for {label}: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )
    destination.chmod(0o400)
    return observed_bytes, actual_sha256


def _retry_remove_readonly(function, path: str, exception_info) -> None:
    error = exception_info[1]
    if not isinstance(error, PermissionError):
        raise error
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    function(path)


def remove_verified_root(root: pathlib.Path) -> None:
    """Remove a private verified tree, including read-only files on Windows."""
    shutil.rmtree(root, onerror=_retry_remove_readonly)


def resolve_new_output(path: pathlib.Path, label: str) -> pathlib.Path:
    requested = path.expanduser().absolute()
    try:
        requested.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ValidationError(f"cannot inspect {label} output: {error}") from error
    else:
        raise ValidationError(f"{label} output already exists: {requested}")
    try:
        parent = requested.parent.resolve(strict=True)
    except OSError as error:
        raise ValidationError(f"{label} output parent is unavailable: {error}") from error
    return parent / requested.name


def write_json_exclusive(
    path: pathlib.Path,
    value: dict[str, Any],
    *,
    label: str,
    max_encoded_bytes: int,
) -> pathlib.Path:
    target = resolve_new_output(path, label)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > max_encoded_bytes:
        raise ValidationError(
            f"{label} output exceeds limit: limit={max_encoded_bytes} "
            f"observed={len(encoded)}"
        )
    try:
        with target.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        target.chmod(0o400)
    except OSError as error:
        target.unlink(missing_ok=True)
        raise ValidationError(f"cannot write {label} output: {error}") from error
    return target


def write_verified_root_marker(
    verified_root: pathlib.Path,
    cleanup_token: str,
) -> dict[str, Any]:
    root_metadata = verified_root.lstat()
    device, inode = stable_identity(root_metadata, "verified root")
    marker = {
        "schema_version": 1,
        "owner": "auto-re-skill",
        "kind": "auto_re_verified_root",
        "cleanup_token": cleanup_token,
        "root_identity": {"device": device, "inode": inode},
    }
    write_json_exclusive(
        verified_root / VERIFIED_ROOT_MARKER,
        marker,
        label="verified-root marker",
        max_encoded_bytes=VERIFIED_ROOT_MARKER_POLICY.max_encoded_bytes,
    )
    return marker


def validate_manifest(path: pathlib.Path) -> dict[str, Any]:
    root = path.parent.resolve(strict=True)
    manifest_path = root / path.name
    manifest = read_json_object_stably(manifest_path, root, "manifest")
    schema_version = manifest.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValidationError(
            "unsupported manifest schema_version: "
            f"{schema_version!r}; supported={sorted(SUPPORTED_SCHEMA_VERSIONS)!r}"
        )
    if manifest.get("owner") != EXPECTED_OWNER:
        raise ValidationError("manifest owner must be auto-re-cli")
    if manifest.get("kind") not in SUPPORTED_KINDS:
        raise ValidationError(f"unsupported manifest kind: {manifest.get('kind')!r}")

    rows, total_payload_bytes = prepare_manifest_rows(manifest.get("files"))

    verified_root = pathlib.Path(
        tempfile.mkdtemp(prefix=VERIFIED_ROOT_PREFIX)
    )
    cleanup_token = secrets.token_hex(32)
    validated: list[dict[str, Any]] = []
    try:
        verified_root.chmod(0o700)
        write_verified_root_marker(verified_root, cleanup_token)
        for row in rows:
            payload = root.joinpath(*row.relative.parts)
            handle, opened = open_regular_file_stably(payload, root, "payload")
            destination = verified_root.joinpath(*row.relative.parts)
            try:
                observed_bytes, actual_sha256 = copy_and_hash_opened_payload(
                    handle,
                    opened,
                    destination,
                    row.expected_bytes,
                    row.expected_sha256,
                    row.relative_text,
                )
            finally:
                handle.close()

            device, inode = stable_identity(opened, row.relative_text)
            validated.append(
                {
                    "path": str(destination),
                    "source_path": str(payload),
                    "relative_path": row.relative_text,
                    "bytes": observed_bytes,
                    "sha256": actual_sha256,
                    "stable_identity": {
                        "device": device,
                        "inode": inode,
                    },
                    "section_id": row.section_id,
                }
            )
    except BaseException as error:
        try:
            remove_verified_root(verified_root)
        except OSError as cleanup_error:
            raise ValidationError(
                "bundle validation failed and verified-copy cleanup failed: "
                f"{cleanup_error}; retained recovery path: {verified_root}"
            ) from error
        raise

    return {
        "ok": True,
        "owner": manifest["owner"],
        "kind": manifest["kind"],
        "schema_version": schema_version,
        "manifest_path": str(manifest_path),
        "verified_root": str(verified_root),
        "cleanup_required": True,
        "cleanup_token": cleanup_token,
        "consumption_contract": "read_materialized_verified_paths_only",
        "file_count": len(validated),
        "total_payload_bytes": total_payload_bytes,
        "files": validated,
        "completion": manifest.get("completion"),
        "next_action_count": len(manifest.get("next_actions", []))
        if isinstance(manifest.get("next_actions", []), list)
        else None,
    }


def build_verification_receipt(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "owner": "auto-re-skill",
        "kind": "auto_re_bundle_verification_receipt",
        "created_at": utc_now(),
        "manifest": {
            "path": result["manifest_path"],
            "owner": result["owner"],
            "kind": result["kind"],
            "schema_version": result["schema_version"],
        },
        "verified_root": result["verified_root"],
        "cleanup_required": result["cleanup_required"],
        "cleanup_token": result["cleanup_token"],
        "consumption_contract": result["consumption_contract"],
        "limits": {
            "max_file_count": MAX_BUNDLE_FILE_COUNT,
            "max_total_payload_bytes": MAX_TOTAL_PAYLOAD_BYTES,
        },
        "file_count": result["file_count"],
        "total_payload_bytes": result["total_payload_bytes"],
        "files": result["files"],
        "completion": result["completion"],
        "next_action_count": result["next_action_count"],
    }


def validate_manifest_to_receipt(
    manifest_path: pathlib.Path,
    receipt_path: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt_target = resolve_new_output(receipt_path, "receipt")
    result = validate_manifest(manifest_path)
    try:
        receipt = build_verification_receipt(result)
        written = write_json_exclusive(
            receipt_target,
            receipt,
            label="receipt",
            max_encoded_bytes=VERIFICATION_RECEIPT_MAX_BYTES,
        )
    except BaseException as error:
        try:
            remove_verified_root(pathlib.Path(result["verified_root"]))
        except OSError as cleanup_error:
            raise ValidationError(
                "verification receipt failed and verified-copy cleanup failed: "
                f"{cleanup_error}; retained recovery path: {result['verified_root']}"
            ) from error
        raise
    summary = {
        "ok": True,
        "owner": "auto-re-skill",
        "kind": "auto_re_bundle_verification_summary",
        "receipt_path": str(written),
        "verified_root": receipt["verified_root"],
        "cleanup_required": True,
        "file_count": receipt["file_count"],
        "total_payload_bytes": receipt["total_payload_bytes"],
    }
    return receipt, summary


def _read_verification_receipt(path: pathlib.Path) -> tuple[pathlib.Path, dict[str, Any]]:
    requested = path.expanduser().absolute()
    try:
        root = requested.parent.resolve(strict=True)
    except OSError as error:
        raise ValidationError(f"cannot resolve receipt parent: {error}") from error
    receipt_path = root / requested.name
    receipt = read_json_object_stably(
        receipt_path,
        root,
        "verification receipt",
        policy=VERIFICATION_RECEIPT_POLICY,
    )
    if receipt.get("schema_version") != 1:
        raise ValidationError("unsupported verification receipt schema_version")
    if receipt.get("owner") != "auto-re-skill":
        raise ValidationError("verification receipt owner must be auto-re-skill")
    if receipt.get("kind") != "auto_re_bundle_verification_receipt":
        raise ValidationError("unsupported verification receipt kind")
    return receipt_path, receipt


def cleanup_verified_receipt(path: pathlib.Path) -> dict[str, Any]:
    receipt_path, receipt = _read_verification_receipt(path)
    root_text = receipt.get("verified_root")
    cleanup_token = receipt.get("cleanup_token")
    if not isinstance(root_text, str) or not pathlib.PurePath(root_text).is_absolute():
        raise ValidationError("verification receipt verified_root must be absolute")
    if (
        not isinstance(cleanup_token, str)
        or len(cleanup_token) != 64
        or any(character not in "0123456789abcdef" for character in cleanup_token)
    ):
        raise ValidationError("verification receipt cleanup_token is invalid")

    temporary_root = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    verified_root = pathlib.Path(root_text)
    if verified_root.name.startswith(VERIFIED_ROOT_PREFIX) is False:
        raise ValidationError("verification receipt verified_root prefix is invalid")
    try:
        if verified_root.parent.resolve(strict=True) != temporary_root:
            raise ValidationError("verification receipt verified_root is outside temp root")
        root_metadata = verified_root.lstat()
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError(f"cannot inspect verified root: {error}") from error
    if path_is_indirection(verified_root, root_metadata) or not stat.S_ISDIR(
        root_metadata.st_mode
    ):
        raise ValidationError("verified root must be a direct directory")

    marker_path = verified_root / VERIFIED_ROOT_MARKER
    try:
        marker = read_json_object_stably(
            marker_path,
            verified_root,
            "verified-root marker",
            policy=VERIFIED_ROOT_MARKER_POLICY,
        )
    except ValidationError as error:
        raise ValidationError(f"verified-root marker is invalid: {error}") from error
    if (
        marker.get("schema_version") != 1
        or marker.get("owner") != "auto-re-skill"
        or marker.get("kind") != "auto_re_verified_root"
        or marker.get("cleanup_token") != cleanup_token
    ):
        raise ValidationError("verified-root marker identity does not match receipt")
    expected_identity = marker.get("root_identity")
    actual_device, actual_inode = stable_identity(root_metadata, "verified root")
    if expected_identity != {"device": actual_device, "inode": actual_inode}:
        raise ValidationError("verified-root marker stable identity does not match")

    remove_verified_root(verified_root)
    return {
        "ok": True,
        "owner": "auto-re-skill",
        "kind": "auto_re_bundle_cleanup_summary",
        "receipt_path": str(receipt_path),
        "verified_root": str(verified_root),
        "removed": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate an Auto-RE context bundle or direct spill manifest."
    )
    parser.add_argument("manifest", type=pathlib.Path, nargs="?")
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--cleanup-receipt", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.cleanup_receipt is not None:
            if args.manifest is not None or args.receipt is not None:
                raise ValidationError(
                    "--cleanup-receipt cannot be combined with a manifest or --receipt"
                )
            result = cleanup_verified_receipt(args.cleanup_receipt)
        else:
            if args.manifest is None:
                raise ValidationError("a manifest is required")
            if args.receipt is not None:
                _receipt, result = validate_manifest_to_receipt(
                    args.manifest, args.receipt
                )
            else:
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
