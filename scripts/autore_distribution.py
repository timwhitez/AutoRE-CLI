#!/usr/bin/env python3
"""Verify, install, and uninstall the AutoRE-CLI binary distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Optional


SCHEMA_VERSION = 1
MANIFEST_KIND = "autore_cli_binary_distribution"
PRODUCT = "AutoRE-CLI"
PUBLISHER = "timwhitez"
REPOSITORY_URL = "https://github.com/timwhitez/AutoRE-CLI"
SKILL_NAME = "auto-re"
CHECKSUM_FILE = "SHA256SUMS"
MANIFEST_FILE = "manifest/release.json"
BINARY_NAME = "auto-re-cli"
BINARY_MARKER = ".auto-re-cli.autore-managed.json"
SKILL_MARKER = ".autore-managed.json"
FORBIDDEN_ROOT_NAMES = {
    "benchmarks",
    "context",
    "crates",
    "malware",
    "report",
    "spec",
    "target",
}
FORBIDDEN_FILE_NAMES = {
    "Cargo.lock",
    "Cargo.toml",
    "AGENTS.md",
    "CLAUDE.md",
    "agent-harness-context.json",
}
FORBIDDEN_SUFFIXES = {".rs", ".rlib", ".rmeta"}
FORBIDDEN_BYTE_PATTERNS = (
    b"/private" + b"/var/root",
    b"/var/root/" + b"auto-re",
    b"/var/root/" + b"auto_re",
    b"/" + b"Users/",
)
FORBIDDEN_PUBLIC_IDENTITY_PATTERNS = (
    b"byte" + b"dance",
    b"noreply@" + b"byte" + b"dance" + b".com",
    b"system " + b"administrator",
    b"twhite.zh" + b"@gmail.com",
)
SUPPORTED_TARGETS = {
    ("Darwin", "arm64"): "macos-arm64",
    ("Darwin", "aarch64"): "macos-arm64",
    ("Darwin", "x86_64"): "macos-x86_64",
    ("Darwin", "amd64"): "macos-x86_64",
    ("Linux", "x86_64"): "linux-x86_64",
    ("Linux", "amd64"): "linux-x86_64",
    ("Linux", "i386"): "linux-x86",
    ("Linux", "i486"): "linux-x86",
    ("Linux", "i586"): "linux-x86",
    ("Linux", "i686"): "linux-x86",
    ("Linux", "aarch64"): "linux-arm64",
    ("Linux", "arm64"): "linux-arm64",
}


class DistributionError(ValueError):
    pass


def distribution_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise DistributionError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def safe_relative_path(value: str, label: str) -> pathlib.PurePosixPath:
    if not value or "\\" in value:
        raise DistributionError(f"{label} is not a canonical relative path: {value!r}")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise DistributionError(f"{label} is not a canonical relative path: {value!r}")
    return path


def load_json_object(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DistributionError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise DistributionError(f"{label} must be a JSON object: {path}")
    return value


def require_regular_file(path: pathlib.Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DistributionError(f"cannot inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DistributionError(f"{label} must be a non-symlink regular file: {path}")
    return metadata


def iter_public_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise DistributionError(f"public repository contains a symlink: {relative}")
        if path.is_file():
            yield path


def parse_checksums(root: pathlib.Path) -> dict[str, str]:
    checksum_path = root / CHECKSUM_FILE
    require_regular_file(checksum_path, "checksum file")
    rows: dict[str, str] = {}
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise DistributionError(f"cannot read {checksum_path}: {error}") from error
    for number, line in enumerate(lines, start=1):
        digest, separator, relative_text = line.partition("  ")
        if (
            not separator
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise DistributionError(f"invalid checksum row {number}")
        relative = safe_relative_path(relative_text, f"checksum row {number}")
        normalized = relative.as_posix()
        if normalized in rows:
            raise DistributionError(f"duplicate checksum path: {normalized}")
        rows[normalized] = digest
    if not rows:
        raise DistributionError("checksum file must not be empty")
    return rows


def parse_skill_frontmatter(path: pathlib.Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise DistributionError(f"cannot read skill frontmatter: {error}") from error
    if not lines or lines[0] != "---":
        raise DistributionError("SKILL.md must start with YAML frontmatter")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line == "---":
            break
        key, separator, value = line.partition(":")
        if not separator or not key or not value.strip():
            raise DistributionError(f"invalid SKILL.md frontmatter line: {line!r}")
        fields[key.strip()] = value.strip().strip('"')
    else:
        raise DistributionError("SKILL.md frontmatter is not closed")
    if set(fields) != {"name", "description"}:
        raise DistributionError(
            "SKILL.md frontmatter must contain only name and description"
        )
    if fields["name"] != SKILL_NAME:
        raise DistributionError(f"unexpected skill name: {fields['name']!r}")
    return fields


def validate_public_allowlist(root: pathlib.Path, files: list[pathlib.Path]) -> None:
    mit_license = root / "LICENSE-MIT"
    require_regular_file(mit_license, "project MIT license")
    if (root / "LICENSE-APACHE").exists():
        raise DistributionError("unexpected project license: LICENSE-APACHE")
    for path in files:
        relative = path.relative_to(root)
        if relative.parts[0] in FORBIDDEN_ROOT_NAMES:
            raise DistributionError(f"forbidden private-source root: {relative}")
        if path.name in FORBIDDEN_FILE_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise DistributionError(f"forbidden private-source file: {relative}")
        try:
            content = path.read_bytes()
        except OSError as error:
            raise DistributionError(f"cannot scan {relative}: {error}") from error
        normalized = content.lower()
        for pattern in FORBIDDEN_PUBLIC_IDENTITY_PATTERNS:
            if pattern in normalized:
                raise DistributionError(
                    f"forbidden public identity marker {pattern!r} leaked into {relative}"
                )
        for pattern in FORBIDDEN_BYTE_PATTERNS:
            if pattern in content:
                raise DistributionError(
                    f"private workspace path leaked into public file {relative}"
                )


def validate_manifest(
    root: pathlib.Path, manifest: dict[str, Any], checksums: dict[str, str]
) -> list[dict[str, Any]]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise DistributionError("unsupported release manifest schema")
    if manifest.get("kind") != MANIFEST_KIND or manifest.get("product") != PRODUCT:
        raise DistributionError("unexpected release manifest identity")
    if (
        manifest.get("publisher") != PUBLISHER
        or manifest.get("repository_url") != REPOSITORY_URL
    ):
        raise DistributionError("unexpected release publisher identity")
    version = manifest.get("version")
    source_revision = manifest.get("source_revision")
    if not isinstance(version, str) or not version:
        raise DistributionError("manifest version must be a non-empty string")
    if (
        not isinstance(source_revision, str)
        or len(source_revision) != 40
        or any(character not in "0123456789abcdef" for character in source_revision)
    ):
        raise DistributionError("manifest source_revision must be a Git object id")
    safety = manifest.get("safety")
    if not isinstance(safety, dict):
        raise DistributionError("manifest safety must be an object")
    for field in (
        "target_execution",
        "shellcode_execution",
        "generated_artifact_execution",
        "dynamic_analysis",
        "dynamic_evidence",
    ):
        if safety.get(field) is not False:
            raise DistributionError(f"manifest safety.{field} must be false")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise DistributionError("manifest artifacts[] must be a non-empty array")
    targets: set[str] = set()
    paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise DistributionError(f"artifacts[{index}] must be an object")
        target = artifact.get("target")
        relative_text = artifact.get("path")
        signing = artifact.get("signing")
        if not isinstance(target, str) or target in targets:
            raise DistributionError(f"invalid or duplicate artifact target: {target!r}")
        targets.add(target)
        expected_signing = "adhoc" if target.startswith("macos-") else "not_applicable"
        if signing != expected_signing:
            raise DistributionError(
                f"unexpected signing disposition for {target}: {signing!r}"
            )
        if not isinstance(relative_text, str):
            raise DistributionError(f"artifacts[{index}].path must be a string")
        relative = safe_relative_path(relative_text, f"artifacts[{index}].path")
        normalized = relative.as_posix()
        if normalized in paths:
            raise DistributionError(f"duplicate artifact path: {normalized}")
        paths.add(normalized)
        binary = root.joinpath(*relative.parts)
        metadata = require_regular_file(binary, "release binary")
        expected_bytes = artifact.get("bytes")
        expected_digest = artifact.get("sha256")
        if metadata.st_size != expected_bytes:
            raise DistributionError(f"artifact byte count mismatch: {normalized}")
        actual_digest = sha256_file(binary)
        if actual_digest != expected_digest or checksums.get(normalized) != actual_digest:
            raise DistributionError(f"artifact digest mismatch: {normalized}")
        if not os.access(binary, os.X_OK):
            raise DistributionError(f"release binary is not executable: {normalized}")

    skill = manifest.get("skill")
    if not isinstance(skill, dict) or skill.get("name") != SKILL_NAME:
        raise DistributionError("manifest skill identity is invalid")
    skill_path_text = skill.get("path")
    managed_files = skill.get("managed_files")
    if not isinstance(skill_path_text, str) or not isinstance(managed_files, list):
        raise DistributionError("manifest skill path or managed_files is invalid")
    skill_path = safe_relative_path(skill_path_text, "manifest skill path")
    expected_skill_files: set[str] = set()
    for index, value in enumerate(managed_files):
        if not isinstance(value, str):
            raise DistributionError(f"skill managed_files[{index}] must be a string")
        relative = safe_relative_path(value, f"skill managed_files[{index}]")
        normalized = relative.as_posix()
        if normalized in expected_skill_files:
            raise DistributionError(f"duplicate managed skill file: {normalized}")
        expected_skill_files.add(normalized)
        if checksums.get(normalized) != sha256_file(root.joinpath(*relative.parts)):
            raise DistributionError(f"managed skill checksum mismatch: {normalized}")
    actual_skill_files = {
        path.relative_to(root).as_posix()
        for path in (root.joinpath(*skill_path.parts)).rglob("*")
        if path.is_file() and path.name != SKILL_MARKER
    }
    if actual_skill_files != expected_skill_files:
        raise DistributionError("manifest managed skill file set does not match disk")
    parse_skill_frontmatter(root.joinpath(*skill_path.parts) / "SKILL.md")
    openai_yaml = root.joinpath(*skill_path.parts) / "agents/openai.yaml"
    openai_text = openai_yaml.read_text(encoding="utf-8")
    if "display_name:" not in openai_text or "$auto-re" not in openai_text:
        raise DistributionError("agents/openai.yaml is missing required interface metadata")
    return artifacts


def verify_distribution(root: pathlib.Path) -> dict[str, Any]:
    root = root.resolve()
    checksums = parse_checksums(root)
    files = list(iter_public_files(root))
    validate_public_allowlist(root, files)
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in files
        if path.name != CHECKSUM_FILE
    }
    if set(checksums) != actual_paths:
        missing = sorted(actual_paths - set(checksums))
        extra = sorted(set(checksums) - actual_paths)
        raise DistributionError(
            f"checksum file set mismatch: missing={missing!r} extra={extra!r}"
        )
    for relative_text, expected in checksums.items():
        relative = safe_relative_path(relative_text, "checksum path")
        path = root.joinpath(*relative.parts)
        require_regular_file(path, "checksummed file")
        actual = sha256_file(path)
        if actual != expected:
            raise DistributionError(
                f"checksum mismatch for {relative_text}: expected {expected}, got {actual}"
            )
    manifest_path = root / MANIFEST_FILE
    manifest = load_json_object(manifest_path, "release manifest")
    artifacts = validate_manifest(root, manifest, checksums)
    return {
        "ok": True,
        "product": manifest["product"],
        "version": manifest["version"],
        "source_revision": manifest["source_revision"],
        "artifact_count": len(artifacts),
        "checksummed_file_count": len(checksums),
        "skill": manifest["skill"]["name"],
    }


def host_target() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    try:
        return SUPPORTED_TARGETS[(system, machine)]
    except KeyError as error:
        raise DistributionError(
            f"unsupported installation host: system={system!r} machine={machine!r}"
        ) from error


def parse_agents(value: str) -> list[str]:
    normalized = [item.strip().lower() for item in value.split(",") if item.strip()]
    if normalized == ["both"]:
        normalized = ["trae", "codex"]
    if normalized == ["none"]:
        return []
    if not normalized or any(item not in {"trae", "codex"} for item in normalized):
        raise DistributionError("--agents must be trae, codex, both, none, or a list")
    result: list[str] = []
    for item in normalized:
        if item not in result:
            result.append(item)
    return result


def atomic_write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_text = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_text)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def reserve_absent_path(parent: pathlib.Path, prefix: str) -> pathlib.Path:
    descriptor, temporary_text = tempfile.mkstemp(prefix=prefix, dir=parent)
    os.close(descriptor)
    temporary = pathlib.Path(temporary_text)
    temporary.unlink()
    return temporary


def load_managed_marker(path: pathlib.Path, kind: str) -> Optional[dict[str, Any]]:
    if not path_exists_without_follow(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise DistributionError(f"managed marker is not a regular file: {path}")
    marker = load_json_object(path, "managed marker")
    if (
        marker.get("schema_version") != SCHEMA_VERSION
        or marker.get("product") != PRODUCT
        or marker.get("kind") != kind
    ):
        raise DistributionError(f"unrecognized managed marker: {path}")
    return marker


def replace_binary(
    source: pathlib.Path,
    destination: pathlib.Path,
    marker_path: pathlib.Path,
    marker: dict[str, Any],
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_text = tempfile.mkstemp(
        prefix=".auto-re-cli.", dir=destination.parent
    )
    temporary = pathlib.Path(temporary_text)
    backup_binary: Optional[pathlib.Path] = None
    backup_marker: Optional[pathlib.Path] = None
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        if path_exists_without_follow(destination):
            backup_binary = reserve_absent_path(
                destination.parent, ".auto-re-cli-backup."
            )
            os.replace(destination, backup_binary)
        if path_exists_without_follow(marker_path):
            backup_marker = reserve_absent_path(
                marker_path.parent, ".auto-re-cli-marker-backup."
            )
            os.replace(marker_path, backup_marker)
        os.replace(temporary, destination)
        atomic_write_json(marker_path, marker)
        if backup_binary is not None:
            backup_binary.unlink()
        if backup_marker is not None:
            backup_marker.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        if path_exists_without_follow(destination):
            destination.unlink()
        if backup_binary is not None and path_exists_without_follow(backup_binary):
            os.replace(backup_binary, destination)
        if path_exists_without_follow(marker_path):
            marker_path.unlink()
        if backup_marker is not None and path_exists_without_follow(backup_marker):
            os.replace(backup_marker, marker_path)
        raise


def path_exists_without_follow(path: pathlib.Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def remove_empty_parents(path: pathlib.Path, stop: pathlib.Path) -> None:
    current = path
    while current != stop and current.is_relative_to(stop):
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def replace_skill(
    source: pathlib.Path,
    destination: pathlib.Path,
    marker: dict[str, Any],
) -> None:
    existing = path_exists_without_follow(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(
        tempfile.mkdtemp(prefix=".auto-re-skill-stage.", dir=destination.parent)
    )
    backup: Optional[pathlib.Path] = None
    try:
        shutil.rmtree(stage)
        shutil.copytree(source, stage, symlinks=False)
        atomic_write_json(stage / SKILL_MARKER, marker)
        if existing:
            if destination.is_symlink() or not destination.is_dir():
                destination.unlink()
            else:
                backup = pathlib.Path(
                    tempfile.mkdtemp(
                        prefix=".auto-re-skill-backup.", dir=destination.parent
                    )
                )
                backup.rmdir()
                os.replace(destination, backup)
        os.replace(stage, destination)
        if backup is not None:
            shutil.rmtree(backup)
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        if backup is not None and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise


def agent_destinations(args: argparse.Namespace) -> list[tuple[str, pathlib.Path]]:
    trae_root = pathlib.Path(
        args.trae_home
        or os.environ.get("TRAE_HOME")
        or pathlib.Path.home() / ".trae"
    ).expanduser()
    codex_root = (
        pathlib.Path(args.codex_home).expanduser() / "skills"
        if args.codex_home
        else pathlib.Path.home() / ".agents" / "skills"
    )
    roots = {"trae": trae_root / "skills", "codex": codex_root}
    return [(agent, roots[agent] / SKILL_NAME) for agent in parse_agents(args.agents)]


def selected_components(args: argparse.Namespace) -> tuple[bool, bool]:
    if args.cli_only and args.skill_only:
        raise DistributionError("--cli-only and --skill-only are mutually exclusive")
    return (not args.skill_only, not args.cli_only)


def parse_release_version(value: Any) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise DistributionError(f"release version must be a string: {value!r}")
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise DistributionError(f"release version must use x.y.z form: {value!r}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def compare_install_versions(current: Any, candidate: Any) -> int:
    current_key = parse_release_version(current)
    candidate_key = parse_release_version(candidate)
    return (candidate_key > current_key) - (candidate_key < current_key)


def skill_file_inventory(path: pathlib.Path) -> list[str]:
    files: list[str] = []
    for item in sorted(path.rglob("*")):
        if item.name == SKILL_MARKER:
            continue
        if item.is_symlink():
            raise DistributionError(f"skill contains a symlink: {item}")
        if item.is_file():
            files.append(item.relative_to(path).as_posix())
        elif not item.is_dir():
            raise DistributionError(f"skill contains a special file: {item}")
    return files


def installed_skill_digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for relative_text in skill_file_inventory(path):
        digest.update(relative_text.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path / relative_text)))
    return digest.hexdigest()


def preflight_binary_install(
    source: pathlib.Path,
    destination: pathlib.Path,
    marker_path: pathlib.Path,
    marker: dict[str, Any],
    *,
    replace_unmanaged: bool,
) -> str:
    destination_exists = path_exists_without_follow(destination)
    existing_marker = load_managed_marker(marker_path, "binary-install")
    if existing_marker is None:
        if not destination_exists:
            return "install"
        if not replace_unmanaged:
            raise DistributionError(
                "refusing to overwrite unmanaged binary: "
                f"{destination}; use --replace-unmanaged"
            )
        return "replace-unmanaged"
    if not destination_exists:
        raise DistributionError(f"managed binary is missing: {destination}")
    if destination.is_symlink() or not destination.is_file():
        raise DistributionError(f"managed binary changed type: {destination}")
    if sha256_file(destination) != existing_marker.get("sha256"):
        raise DistributionError(f"managed binary drift detected: {destination}")
    version_order = compare_install_versions(
        existing_marker.get("version"), marker["version"]
    )
    if version_order < 0:
        raise DistributionError(
            f"refusing binary downgrade from {existing_marker.get('version')} "
            f"to {marker['version']}"
        )
    if version_order == 0:
        if existing_marker.get("sha256") != marker["sha256"]:
            raise DistributionError(
                f"refusing same-version binary repack at {destination}"
            )
        return "noop"
    return "update"


def preflight_skill_install(
    source: pathlib.Path,
    destination: pathlib.Path,
    marker: dict[str, Any],
    *,
    replace_unmanaged: bool,
) -> str:
    existing = path_exists_without_follow(destination)
    if not existing:
        return "install"
    if destination.is_symlink() or not destination.is_dir():
        if not replace_unmanaged:
            raise DistributionError(
                f"refusing to replace unmanaged skill destination: {destination}"
            )
        return "replace-unmanaged"
    current_marker = load_managed_marker(
        destination / SKILL_MARKER, "skill-install"
    )
    if current_marker is None:
        if not replace_unmanaged:
            raise DistributionError(
                "refusing to overwrite unmanaged skill: "
                f"{destination}; use --replace-unmanaged"
            )
        return "replace-unmanaged"
    current_files = skill_file_inventory(destination)
    marker_files = current_marker.get("managed_files")
    if not isinstance(marker_files, list) or any(
        not isinstance(item, str) for item in marker_files
    ):
        raise DistributionError(f"managed skill marker has invalid file list: {destination}")
    if current_files != sorted(marker_files):
        raise DistributionError(f"managed skill file-set drift detected: {destination}")
    if installed_skill_digest(destination) != current_marker.get("sha256"):
        raise DistributionError(f"managed skill content drift detected: {destination}")
    version_order = compare_install_versions(
        current_marker.get("version"), marker["version"]
    )
    if version_order < 0:
        raise DistributionError(
            f"refusing skill downgrade from {current_marker.get('version')} "
            f"to {marker['version']}"
        )
    if version_order == 0:
        if current_marker.get("sha256") != marker["sha256"]:
            raise DistributionError(
                f"refusing same-version skill repack at {destination}"
            )
        return "noop"
    return "update"


def command_install(args: argparse.Namespace) -> dict[str, Any]:
    root = distribution_root()
    verification = verify_distribution(root)
    manifest = load_json_object(root / MANIFEST_FILE, "release manifest")
    install_cli, install_skill = selected_components(args)
    operations: list[dict[str, Any]] = []
    binary_operation: Optional[dict[str, Any]] = None
    skill_operations: list[dict[str, Any]] = []

    if install_cli:
        target = host_target()
        matches = [
            item for item in manifest["artifacts"] if item.get("target") == target
        ]
        if len(matches) != 1:
            raise DistributionError(f"release has no unique artifact for {target}")
        artifact = matches[0]
        relative = safe_relative_path(artifact["path"], "artifact path")
        source = root.joinpath(*relative.parts)
        probe = subprocess.run(
            [str(source), "--version"],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        expected_version = f"{BINARY_NAME} {manifest['version']}\n"
        if probe.returncode != 0 or probe.stdout != expected_version or probe.stderr:
            raise DistributionError(
                f"verified host binary failed version probe for target {target}"
            )
        install_dir = pathlib.Path(
            args.install_dir
            or os.environ.get("AUTORE_INSTALL_DIR")
            or pathlib.Path.home() / ".local" / "bin"
        ).expanduser()
        destination = install_dir / BINARY_NAME
        marker_path = install_dir / BINARY_MARKER
        marker = {
            "schema_version": SCHEMA_VERSION,
            "product": PRODUCT,
            "kind": "binary-install",
            "version": manifest["version"],
            "source_revision": manifest["source_revision"],
            "target": target,
            "path": str(destination),
            "sha256": artifact["sha256"],
        }
        operation = preflight_binary_install(
            source,
            destination,
            marker_path,
            marker,
            replace_unmanaged=args.replace_unmanaged,
        )
        binary_operation = {
            "kind": "binary",
            "operation": operation,
            "source": str(source),
            "path": str(destination),
            "marker_path": str(marker_path),
            "marker": marker,
        }
        operations.append(
            {
                "kind": "binary",
                "operation": operation,
                "source": str(source),
                "path": str(destination),
            }
        )

    if install_skill:
        skill = manifest["skill"]
        source_relative = safe_relative_path(skill["path"], "skill path")
        source = root.joinpath(*source_relative.parts)
        digest = installed_skill_digest(source)
        managed_files = skill_file_inventory(source)
        for agent, destination in agent_destinations(args):
            marker = {
                "schema_version": SCHEMA_VERSION,
                "product": PRODUCT,
                "kind": "skill-install",
                "skill": SKILL_NAME,
                "agent": agent,
                "version": skill["version"],
                "source_revision": manifest["source_revision"],
                "sha256": digest,
                "managed_files": managed_files,
            }
            operation = preflight_skill_install(
                source,
                destination,
                marker,
                replace_unmanaged=args.replace_unmanaged,
            )
            skill_operations.append(
                {
                    "kind": f"{agent}-skill",
                    "operation": operation,
                    "source": source,
                    "path": destination,
                    "marker": marker,
                }
            )
            operations.append(
                {
                    "kind": f"{agent}-skill",
                    "operation": operation,
                    "source": str(source),
                    "path": str(destination),
                }
            )

    if not args.dry_run:
        if binary_operation is not None and binary_operation["operation"] != "noop":
            replace_binary(
                pathlib.Path(binary_operation["source"]),
                pathlib.Path(binary_operation["path"]),
                pathlib.Path(binary_operation["marker_path"]),
                binary_operation["marker"],
            )
        for item in skill_operations:
            if item["operation"] != "noop":
                replace_skill(
                    item["source"],
                    item["path"],
                    item["marker"],
                )
    return {
        "ok": True,
        "action": "install",
        "dry_run": args.dry_run,
        "version": verification["version"],
        "operations": operations,
    }
def command_uninstall(args: argparse.Namespace) -> dict[str, Any]:
    install_cli, install_skill = selected_components(args)
    operations: list[dict[str, Any]] = []
    binary_removal: Optional[tuple[pathlib.Path, pathlib.Path]] = None
    skill_removals: list[tuple[str, pathlib.Path, list[str]]] = []
    if install_cli:
        install_dir = pathlib.Path(
            args.install_dir
            or os.environ.get("AUTORE_INSTALL_DIR")
            or pathlib.Path.home() / ".local" / "bin"
        ).expanduser()
        destination = install_dir / BINARY_NAME
        marker_path = install_dir / BINARY_MARKER
        marker = load_managed_marker(marker_path, "binary-install")
        if marker is not None:
            if not path_exists_without_follow(destination):
                raise DistributionError(f"managed binary is missing: {destination}")
            if destination.is_symlink() or not destination.is_file():
                raise DistributionError(
                    f"managed binary destination changed type: {destination}"
                )
            if (
                sha256_file(destination) != marker.get("sha256")
                and not args.force_managed
            ):
                raise DistributionError(
                    "managed binary was modified: "
                    f"{destination}; use --force-managed"
                )
            operations.append(
                {"kind": "binary", "operation": "remove", "path": str(destination)}
            )
            binary_removal = (destination, marker_path)

    if install_skill:
        for agent, destination in agent_destinations(args):
            marker_path = destination / SKILL_MARKER
            if not path_exists_without_follow(destination):
                continue
            if destination.is_symlink() or not destination.is_dir():
                raise DistributionError(
                    f"managed {agent} skill destination changed type: {destination}"
                )
            marker = load_managed_marker(marker_path, "skill-install")
            if marker is None:
                continue
            managed_files = marker.get("managed_files")
            if not isinstance(managed_files, list) or any(
                not isinstance(item, str) for item in managed_files
            ):
                raise DistributionError(
                    f"managed {agent} skill marker has invalid file list: {destination}"
                )
            current_files = skill_file_inventory(destination)
            extra_files = sorted(set(current_files) - set(managed_files))
            missing_files = sorted(set(managed_files) - set(current_files))
            if missing_files:
                raise DistributionError(
                    f"managed {agent} skill is missing files: {missing_files!r}"
                )
            managed_digest = hashlib.sha256()
            for relative_text in sorted(managed_files):
                relative = safe_relative_path(relative_text, "managed skill file")
                managed_digest.update(relative.as_posix().encode("utf-8"))
                managed_digest.update(b"\0")
                managed_digest.update(
                    bytes.fromhex(sha256_file(destination.joinpath(*relative.parts)))
                )
            if (
                managed_digest.hexdigest() != marker.get("sha256")
                and not args.force_managed
            ):
                raise DistributionError(
                    "managed "
                    f"{agent} skill was modified: {destination}; use --force-managed"
                )
            operations.append(
                {
                    "kind": f"{agent}-skill",
                    "operation": "remove-managed-files",
                    "path": str(destination),
                    "extra_files_preserved": extra_files,
                }
            )
            skill_removals.append((agent, destination, sorted(managed_files)))

    if not args.dry_run:
        if binary_removal is not None:
            binary_removal[0].unlink()
            binary_removal[1].unlink()
        for _agent, destination, managed_files in skill_removals:
            for relative_text in managed_files:
                relative = safe_relative_path(relative_text, "managed skill file")
                path = destination.joinpath(*relative.parts)
                path.unlink()
                remove_empty_parents(path.parent, destination)
            (destination / SKILL_MARKER).unlink()
            try:
                destination.rmdir()
            except OSError:
                pass
    return {
        "ok": True,
        "action": "uninstall",
        "dry_run": args.dry_run,
        "operations": operations,
    }


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cli-only", action="store_true")
    parser.add_argument("--skill-only", action="store_true")
    parser.add_argument(
        "--agents",
        default="trae,codex",
        help="comma-separated trae/codex targets, both, or none",
    )
    parser.add_argument("--install-dir")
    parser.add_argument("--trae-home")
    parser.add_argument(
        "--codex-home",
        help="legacy Codex home whose skills/ child should be used",
    )
    parser.add_argument("--dry-run", action="store_true")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify", help="verify checksums and public boundaries")
    install = subparsers.add_parser("install", help="install the CLI and agent skill")
    add_common_options(install)
    install.add_argument(
        "--replace-unmanaged",
        action="store_true",
        help="replace only the exact unmanaged binary or skill leaf",
    )
    uninstall = subparsers.add_parser(
        "uninstall", help="remove only managed CLI and skill files"
    )
    add_common_options(uninstall)
    uninstall.add_argument(
        "--force-managed",
        action="store_true",
        help="remove marker-listed managed files even when their content drifted",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "verify":
            result = verify_distribution(distribution_root())
        elif args.command == "install":
            result = command_install(args)
        else:
            result = command_uninstall(args)
    except (DistributionError, OSError, subprocess.SubprocessError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
