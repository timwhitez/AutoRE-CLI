#!/usr/bin/env python3
"""Build deterministic, independently verifiable platform release archives."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "release-assets"

# Import the canonical distribution verifier shipped beside this script.
# The builder must never grow a second, weaker copy of those checks, and no
# bytecode may leak into the release-boundary tree while loading it.
sys.dont_write_bytecode = True
_IMPL_SPEC = importlib.util.spec_from_file_location(
    "autore_distribution_impl_for_builder",
    pathlib.Path(__file__).with_name("autore_distribution_impl.py"),
)
assert _IMPL_SPEC is not None and _IMPL_SPEC.loader is not None
_impl = importlib.util.module_from_spec(_IMPL_SPEC)
_IMPL_SPEC.loader.exec_module(_impl)
PACKAGE_EXCLUDED_ROOTS = {
    ".git",
    ".github",
    "bin",
    "packaging",
    "promotion",
    "release-notes",
    "release-assets",
}
PACKAGE_EXCLUDED_FILES = {
    ".gitignore",
    "SHA256SUMS",
    "scripts/build_release_assets.py",
}
ARCHIVE_EPOCH = 946684800
SUPPORTED_TARGETS = frozenset({
    "macos-arm64", "macos-x86_64", "linux-arm64", "linux-x86_64", "windows-x86_64",
})
SKILL_PATH = "skills/auto-re"
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class ReleaseAssetError(ValueError):
    pass


def load_manifest(root: pathlib.Path) -> dict[str, Any]:
    try:
        manifest = _impl.load_json_object(root / "manifest/release.json", "release manifest")
    except (_impl.DistributionError, OSError, ValueError) as error:
        raise ReleaseAssetError(f"cannot read release manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ReleaseAssetError("release manifest must be a JSON object")
    if manifest.get("distribution_scope") != "repository":
        raise ReleaseAssetError("source manifest must describe the repository distribution")
    return manifest


def verify_input_distribution(snapshot: pathlib.Path) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """Freeze one checksum-bound byte view, then apply the canonical gate to it."""
    try:
        copy_file(ROOT / "SHA256SUMS", snapshot / "SHA256SUMS")
        inventory = _impl.parse_checksums(snapshot)
        source_files = list(_impl.iter_public_files(ROOT))
        actual = {path.relative_to(ROOT).as_posix() for path in source_files
                  if path.name != "SHA256SUMS"}
        if actual != set(inventory):
            raise ReleaseAssetError("source file set differs from fixed checksum inventory")
        members = {}
        for relative_text, digest in inventory.items():
            relative = _impl.safe_relative_path(relative_text, "fixed checksum path")
            members[relative_text] = copy_file(
                ROOT.joinpath(*relative.parts), snapshot.joinpath(*relative.parts),
                expected_sha256=digest,
            )
        after = {path.relative_to(ROOT).as_posix() for path in _impl.iter_public_files(ROOT)
                 if path.name != "SHA256SUMS"}
        if after != actual:
            raise ReleaseAssetError("source file set changed during snapshot")
        _impl.verify_distribution(snapshot)
        return inventory, members
    except (ReleaseAssetError, _impl.DistributionError, OSError, RecursionError) as error:
        raise ReleaseAssetError(
            f"repository distribution failed verification before packaging: {str(error)[:512]}"
        ) from error


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(source: pathlib.Path, destination: pathlib.Path,
              *, expected_sha256: str | None = None,
              source_mode: int | None = None) -> dict[str, Any]:
    """Copy one independent regular-file snapshot without following the leaf."""
    reject_link_components(source.absolute())
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(source, flags)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(descriptor, "rb") as input_file:
        before = os.fstat(input_file.fileno())
        if not stat.S_ISREG(before.st_mode) or not before.st_ino:
            raise ReleaseAssetError(f"source is not a stable regular file: {source}")
        if getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ReleaseAssetError(f"source is a reparse point: {source}")
        if not os.path.samestat(before, source.lstat()):
            raise ReleaseAssetError(f"source changed before snapshot: {source}")
        digest = hashlib.sha256()
        count = 0
        with destination.open("xb") as output_file:
            for block in iter(lambda: input_file.read(1024 * 1024), b""):
                count += len(block)
                if count > before.st_size:
                    raise ReleaseAssetError(f"source grew during snapshot: {source}")
                output_file.write(block)
                digest.update(block)
        after = os.fstat(input_file.fileno())
        if (count != before.st_size or not os.path.samestat(before, after)
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                   (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or not os.path.samestat(before, source.lstat())):
            raise ReleaseAssetError(f"source changed during snapshot: {source}")
        actual = digest.hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise ReleaseAssetError(f"fixed checksum mismatch for {source.name}")
        mode = source_mode if source_mode is not None else stat.S_IMODE(before.st_mode)
        destination.chmod(mode)
        return {"sha256": actual, "bytes": count,
                "source_mode": mode, "mode": 0o755 if mode & 0o111 else 0o644}


def package_common_files(
    inventory: dict[str, str],
    root: pathlib.Path,
) -> list[pathlib.Path]:
    """Select package files from the checksum-verified inventory.

    Only files registered in the verified repository SHA256SUMS are eligible;
    the per-platform manifest is regenerated later, so it is not copied from
    the inventory. Unregistered working-tree files never reach this function
    because ``verify_input_distribution`` already rejected them.
    """
    selected: list[pathlib.Path] = []
    for relative_text in sorted(inventory):
        relative = pathlib.PurePosixPath(relative_text)
        if relative.parts[0] in PACKAGE_EXCLUDED_ROOTS:
            continue
        if relative_text in PACKAGE_EXCLUDED_FILES or relative_text == "manifest/release.json":
            continue
        if "__pycache__" in relative.parts:
            raise ReleaseAssetError(
                f"registered file lives under __pycache__: {relative_text}"
            )
        selected.append(root.joinpath(*relative.parts))
    if not selected:
        raise ReleaseAssetError("verified inventory selected no common files")
    return selected


def skill_inventory_files(inventory: dict[str, str], root: pathlib.Path) -> list[pathlib.Path]:
    """Select the managed Skill files from the verified inventory."""
    skill_root = pathlib.PurePosixPath(SKILL_PATH)
    selected = [
        root.joinpath(*pathlib.PurePosixPath(relative).parts)
        for relative in sorted(inventory)
        if pathlib.PurePosixPath(relative).is_relative_to(skill_root)
    ]
    if not selected:
        raise ReleaseAssetError("verified inventory contains no managed Skill files")
    return selected


def iter_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ReleaseAssetError(f"release package contains a symlink: {path}")
        if path.is_file():
            yield path


def write_checksums(root: pathlib.Path, members: dict[str, dict[str, Any]]) -> None:
    rows = [f"{members[relative]['sha256']}  {relative}\n" for relative in sorted(members)]
    encoded = "".join(rows).encode("utf-8")
    with (root / "SHA256SUMS").open("xb") as handle:
        handle.write(encoded)
    members["SHA256SUMS"] = {"sha256": hashlib.sha256(encoded).hexdigest(),
                              "bytes": len(encoded), "source_mode": 0o644, "mode": 0o644}


def prepare_package(
    package_root: pathlib.Path,
    manifest: dict[str, Any],
    artifact: dict[str, Any],
    common_files: list[pathlib.Path],
    source_root: pathlib.Path,
    fixed_members: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    members: dict[str, dict[str, Any]] = {}
    for source in common_files:
        relative = source.relative_to(source_root).as_posix()
        fixed = fixed_members[relative]
        members[relative] = copy_file(
            source, package_root / relative, expected_sha256=fixed["sha256"],
            source_mode=fixed["source_mode"],
        )

    artifact_path = pathlib.PurePosixPath(artifact["path"])
    artifact_text = artifact_path.as_posix()
    fixed = fixed_members[artifact_text]
    members[artifact_text] = copy_file(
        source_root.joinpath(*artifact_path.parts), package_root.joinpath(*artifact_path.parts),
        expected_sha256=fixed["sha256"], source_mode=fixed["source_mode"],
    )

    package_manifest = dict(manifest)
    package_manifest["artifacts"] = [artifact]
    package_manifest["distribution_scope"] = "platform"
    package_manifest["package_target"] = artifact["target"]
    manifest_destination = package_root / "manifest/release.json"
    manifest_destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(package_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with manifest_destination.open("xb") as handle:
        handle.write(encoded)
    members["manifest/release.json"] = {
        "sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded),
        "source_mode": 0o644, "mode": 0o644,
    }
    write_checksums(package_root, members)
    return members


def normalized_mode(path: pathlib.Path) -> int:
    return 0o755 if os.access(path, os.X_OK) else 0o644


def write_tar_gz(source: pathlib.Path, archive: pathlib.Path) -> None:
    root_name = source.name
    with archive.open("wb") as raw_handle:
        import gzip

        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_handle,
            mtime=ARCHIVE_EPOCH,
        ) as gzip_handle:
            with tarfile.open(fileobj=gzip_handle, mode="w") as tar_handle:
                directories = [source]
                directories.extend(path for path in sorted(source.rglob("*")) if path.is_dir())
                files = list(iter_files(source))
                for path in [*directories, *files]:
                    relative = pathlib.Path(root_name) / path.relative_to(source)
                    info = tar_handle.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = ARCHIVE_EPOCH
                    info.mode = 0o755 if path.is_dir() else normalized_mode(path)
                    if path.is_file():
                        with path.open("rb") as handle:
                            tar_handle.addfile(info, handle)
                    else:
                        tar_handle.addfile(info)


def write_zip(source: pathlib.Path, archive: pathlib.Path) -> None:
    root_name = source.name
    with zipfile.ZipFile(
        archive,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_handle:
        for path in iter_files(source):
            relative = pathlib.Path(root_name) / path.relative_to(source)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=(2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | normalized_mode(path)) << 16
            with path.open("rb") as input_file, zip_handle.open(info, "w") as member:
                shutil.copyfileobj(input_file, member, length=1024 * 1024)


def _stream_identity(handle, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        count += len(block)
        if count > limit:
            raise ReleaseAssetError("archive member exceeds admitted byte count")
        digest.update(block)
    return count, digest.hexdigest()


def verify_archive_members(
    archive: pathlib.Path,
    expected: dict[str, dict[str, Any]],
    *,
    prefix: str | None,
) -> None:
    """Read the finished archive, including member bytes and normalized modes."""
    found: set[str] = set()
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as handle:
            entries = handle.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                raise ReleaseAssetError(f"duplicate archive members: {archive.name}")
            for entry in entries:
                name = entry.filename
                relative = name.removeprefix(f"{prefix}/") if prefix else name
                if (prefix and not name.startswith(f"{prefix}/")) or relative not in expected:
                    raise ReleaseAssetError(f"unexpected archive member: {name}")
                record = expected[relative]
                archive_mode = entry.external_attr >> 16
                if (entry.is_dir() or stat.S_IFMT(archive_mode) != stat.S_IFREG
                        or archive_mode & 0o777 != record["mode"]
                        or entry.file_size != record["bytes"]):
                    raise ReleaseAssetError(f"invalid archive member metadata: {name}")
                with handle.open(entry) as payload:
                    count, digest = _stream_identity(payload, record["bytes"])
                if count != record["bytes"] or digest != record["sha256"]:
                    raise ReleaseAssetError(f"archive member drift: {name}")
                found.add(relative)
    else:
        assert prefix is not None
        directories = {prefix}
        for relative in expected:
            parent = pathlib.PurePosixPath(relative).parent
            while str(parent) != ".":
                directories.add(f"{prefix}/{parent.as_posix()}")
                parent = parent.parent
        found_dirs: set[str] = set()
        with tarfile.open(archive, "r:gz") as handle:
            entries = handle.getmembers()
            names = [entry.name.rstrip("/") for entry in entries]
            if len(names) != len(set(names)):
                raise ReleaseAssetError(f"duplicate archive members: {archive.name}")
            for entry in entries:
                name = entry.name.rstrip("/")
                if entry.isdir():
                    if name not in directories or entry.mode & 0o777 != 0o755:
                        raise ReleaseAssetError(f"unexpected archive directory: {name}")
                    found_dirs.add(name)
                    continue
                if not entry.isfile() or not name.startswith(f"{prefix}/"):
                    raise ReleaseAssetError(f"unsupported archive member: {name}")
                relative = name[len(prefix) + 1:]
                if relative not in expected:
                    raise ReleaseAssetError(f"unexpected archive member: {name}")
                record = expected[relative]
                if entry.mode & 0o777 != record["mode"] or entry.size != record["bytes"]:
                    raise ReleaseAssetError(f"invalid archive member metadata: {name}")
                payload = handle.extractfile(entry)
                if payload is None:
                    raise ReleaseAssetError(f"cannot read archive member: {name}")
                with payload:
                    count, digest = _stream_identity(payload, record["bytes"])
                if count != record["bytes"] or digest != record["sha256"]:
                    raise ReleaseAssetError(f"archive member drift: {name}")
                found.add(relative)
        if found_dirs != directories:
            raise ReleaseAssetError(f"archive directory set mismatch: {archive.name}")
    if found != set(expected):
        raise ReleaseAssetError(f"archive member set mismatch: {archive.name}")


def write_skill_zip_from_files(
    files: list[pathlib.Path], skill_root: pathlib.Path, archive: pathlib.Path
) -> None:
    with zipfile.ZipFile(
        archive,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_handle:
        for path in sorted(files, key=lambda item: item.relative_to(skill_root).as_posix()):
            relative = path.relative_to(skill_root)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=(2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | normalized_mode(path)) << 16
            with path.open("rb") as input_file, zip_handle.open(info, "w") as member:
                shutil.copyfileobj(input_file, member, length=1024 * 1024)


def verify_package(package_root: pathlib.Path, target: str) -> None:
    try:
        result = _impl.verify_distribution(package_root)
    except _impl.DistributionError as error:
        raise ReleaseAssetError(f"package verification failed for {target}: {error}") from error
    if (
        not isinstance(result, dict)
        or result.get("ok") is not True
        or result.get("distribution_scope") != "platform"
        or result.get("package_target") != target
        or result.get("artifact_count") != 1
    ):
        raise ReleaseAssetError(f"unexpected verification result for {target}: {result!r}")


def write_release_checksums(output: pathlib.Path, archives: list[pathlib.Path]) -> None:
    rows = [f"{sha256_file(path)}  {path.name}\n" for path in sorted(archives)]
    with (output / "SHA256SUMS.release").open("x", encoding="utf-8") as handle:
        handle.write("".join(rows))


def build_skill_archive(
    output: pathlib.Path,
    version: str,
    skill_files: list[pathlib.Path],
    skill_root: pathlib.Path,
    fixed_members: dict[str, dict[str, Any]],
    packages: list[dict[str, dict[str, Any]]],
) -> tuple[pathlib.Path, dict[str, dict[str, Any]]]:
    """Package the fixed Skill and compare every platform's admitted members."""
    archive = output / f"AutoRE-CLI-{version}-auto-re-skill.zip"
    write_skill_zip_from_files(skill_files, skill_root, archive)
    expected = {path.relative_to(skill_root).as_posix(): fixed_members[path.relative_to(skill_root.parent.parent).as_posix()]
                for path in skill_files}
    for package in packages:
        for relative, record in expected.items():
            package_record = package.get(f"{SKILL_PATH}/{relative}")
            if package_record is None or package_record["sha256"] != record["sha256"]:
                raise ReleaseAssetError(f"Skill differs from a platform package: {relative}")
    return archive, expected


def reject_link_components(path: pathlib.Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ReleaseAssetError(f"symlink/reparse path is not allowed: {component}")


def validate_output_path(output: pathlib.Path) -> pathlib.Path:
    requested = output.expanduser()
    if ".." in requested.parts:
        raise ReleaseAssetError("output path must not contain '..'")
    requested = requested.absolute()
    reject_link_components(requested)
    repository = ROOT.resolve()
    home = pathlib.Path.home().resolve()
    if requested in (repository, home) or requested in repository.parents or requested in home.parents:
        raise ReleaseAssetError("output must not be a repository, home, or ancestor directory")
    default = repository / "release-assets"
    if repository in requested.parents and requested != default and default not in requested.parents:
        raise ReleaseAssetError("in-repository output must be under release-assets")
    if requested.exists():
        raise ReleaseAssetError("output already exists; choose a new directory (existing data is never cleared)")
    if not requested.parent.is_dir():
        raise ReleaseAssetError("output parent must already be an existing directory")
    return requested


def _publish_directory_no_replace(stage: pathlib.Path, output: pathlib.Path) -> None:
    if os.name == "nt":
        os.rename(stage, output)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise ReleaseAssetError("exclusive output publication is unavailable")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1)
    elif sys.platform == "darwin":
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise ReleaseAssetError("exclusive output publication is unavailable")
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(stage), os.fsencode(output), 0x00000004)
    else:
        raise ReleaseAssetError("exclusive output publication is unsupported")
    if result != 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
            raise ReleaseAssetError("exclusive output publication is unsupported by this filesystem")
        raise OSError(error, os.strerror(error), str(output))


def validate_asset_manifest(manifest: dict[str, Any], root: pathlib.Path | None = None) -> tuple[str, list[dict[str, Any]]]:
    root = ROOT if root is None else root
    version = manifest.get("version")
    artifacts = manifest.get("artifacts")
    if not isinstance(version, str) or len(version) > 64 or VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseAssetError("release manifest version must use x.y.z form")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseAssetError("release manifest must contain a non-empty artifacts list")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ReleaseAssetError("release manifest contains an invalid artifact")
        target = artifact.get("target")
        if not isinstance(target, str) or target not in SUPPORTED_TARGETS or target in seen:
            raise ReleaseAssetError("release manifest contains an unsupported or duplicate target")
        seen.add(target)
        filename = "auto-re-cli.exe" if target.startswith("windows-") else "auto-re-cli"
        expected = f"bin/{target}/{filename}"
        if artifact.get("path") != expected:
            raise ReleaseAssetError(f"artifact path must be {expected}")
        source = root / expected
        reject_link_components(source.absolute())
        if not source.is_file():
            raise ReleaseAssetError(f"artifact is not a regular file: {source}")
    if seen != SUPPORTED_TARGETS:
        missing = sorted(SUPPORTED_TARGETS - seen)
        raise ReleaseAssetError(
            "standard releases must cover every supported platform; "
            f"missing targets: {missing}"
        )
    return version, artifacts


def build_assets(output: pathlib.Path) -> dict[str, Any]:
    # Do not resolve away caller-supplied links before validating the path.
    output = validate_output_path(output)
    # A separate byte copy prevents later source edits from becoming new inputs.
    with tempfile.TemporaryDirectory(prefix=".autore-release-input-", dir=ROOT.parent) as snapshot_text:
        snapshot = pathlib.Path(snapshot_text)
        inventory, fixed_members = verify_input_distribution(snapshot)
        manifest = load_manifest(snapshot)
        version, artifacts = validate_asset_manifest(manifest, snapshot)
        common_files = package_common_files(inventory, snapshot)
        skill_files = skill_inventory_files(inventory, snapshot)

        # Stage on the destination filesystem and publish only a complete release.
        with tempfile.TemporaryDirectory(prefix=".autore-release-", dir=output.parent) as temporary_text:
            temporary = pathlib.Path(temporary_text)
            staging = temporary / "assets"
            staging.mkdir()
            packages = temporary / "packages"
            packages.mkdir()
            archives: list[pathlib.Path] = []
            expected_archives: list[tuple[pathlib.Path, dict[str, dict[str, Any]], str | None]] = []
            package_members: list[dict[str, dict[str, Any]]] = []
            for artifact in artifacts:
                target = artifact["target"]
                package_name = f"AutoRE-CLI-{version}-{target}"
                package_root = packages / package_name
                package_root.mkdir()
                members = prepare_package(
                    package_root, manifest, artifact, common_files, snapshot, fixed_members)
                verify_package(package_root, target)
                if target.startswith("windows-"):
                    archive = staging / f"{package_name}.zip"
                    write_zip(package_root, archive)
                else:
                    archive = staging / f"{package_name}.tar.gz"
                    write_tar_gz(package_root, archive)
                archives.append(archive)
                expected_archives.append((archive, members, package_name))
                package_members.append(members)
            skill_archive, skill_members = build_skill_archive(
                staging, version, skill_files, snapshot / SKILL_PATH,
                fixed_members, package_members,
            )
            archives.append(skill_archive)
            expected_archives.append((skill_archive, skill_members, None))
            write_release_checksums(staging, archives)
            for archive, members, prefix in expected_archives:
                try:
                    verify_archive_members(archive, members, prefix=prefix)
                except (zipfile.BadZipFile, tarfile.TarError, EOFError) as error:
                    raise ReleaseAssetError(f"cannot verify archive {archive.name}: {error}") from error
            result = {
                "ok": True,
                "version": version,
                "output": str(output),
                "assets": [
                    {
                        "path": str(output / path.name),
                        "bytes": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                    for path in sorted(archives)
                ],
                "checksum_file": str(output / "SHA256SUMS.release"),
            }
            validate_output_path(output)
            _publish_directory_no_replace(staging, output)
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=pathlib.Path, default=DEFAULT_OUTPUT,
        help="new output directory in an existing trusted parent; existing paths are never cleared",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = build_assets(args.output)
    except (ReleaseAssetError, OSError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
