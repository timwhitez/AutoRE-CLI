#!/usr/bin/env python3
"""Build deterministic, independently verifiable platform release archives."""

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
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "manifest/release.json"
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


def load_manifest() -> dict[str, Any]:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ReleaseAssetError(f"cannot read release manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ReleaseAssetError("release manifest must be a JSON object")
    if manifest.get("distribution_scope") != "repository":
        raise ReleaseAssetError("source manifest must describe the repository distribution")
    return manifest


def verify_input_distribution() -> dict[str, str]:
    """Run the full repository-distribution gate before anything is rewritten.

    This proves the inputs are exactly the registered, checksum-verified
    public files: the complete five-platform artifact set, matching
    digests/bytes, and the managed Skill inventory. It fails closed on any
    unregistered working-tree file (for example a local `.env` or test
    cache), so packages can select files from the verified inventory below
    instead of re-enumerating a mutable directory.
    """
    try:
        result = _impl.verify_distribution(ROOT)
    except _impl.DistributionError as error:
        raise ReleaseAssetError(
            f"repository distribution failed verification before packaging: {error}"
        ) from error
    except (OSError, ValueError, RecursionError) as error:
        raise ReleaseAssetError(
            f"cannot verify repository distribution: {str(error)[:512]}"
        ) from error
    try:
        inventory = _impl.parse_checksums(ROOT)
    except _impl.DistributionError as error:
        raise ReleaseAssetError(f"cannot read verified checksum inventory: {error}") from error
    return inventory


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def package_common_files(
    inventory: dict[str, str],
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
        selected.append(ROOT.joinpath(*relative.parts))
    if not selected:
        raise ReleaseAssetError("verified inventory selected no common files")
    return selected


def skill_inventory_files(inventory: dict[str, str]) -> list[pathlib.Path]:
    """Select the managed Skill files from the verified inventory."""
    skill_root = pathlib.PurePosixPath(SKILL_PATH)
    selected = [
        ROOT.joinpath(*pathlib.PurePosixPath(relative).parts)
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


def write_checksums(root: pathlib.Path) -> None:
    rows = []
    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        if relative == "SHA256SUMS":
            continue
        rows.append(f"{sha256_file(path)}  {relative}\n")
    (root / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")


def prepare_package(
    package_root: pathlib.Path,
    manifest: dict[str, Any],
    artifact: dict[str, Any],
    common_files: list[pathlib.Path],
) -> None:
    for source in common_files:
        copy_file(source, package_root / source.relative_to(ROOT))

    artifact_path = pathlib.PurePosixPath(artifact["path"])
    copy_file(
        ROOT.joinpath(*artifact_path.parts),
        package_root.joinpath(*artifact_path.parts),
    )

    package_manifest = dict(manifest)
    package_manifest["artifacts"] = [artifact]
    package_manifest["distribution_scope"] = "platform"
    package_manifest["package_target"] = artifact["target"]
    manifest_destination = package_root / "manifest/release.json"
    manifest_destination.parent.mkdir(parents=True, exist_ok=True)
    manifest_destination.write_text(
        json.dumps(package_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_checksums(package_root)


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
            zip_handle.writestr(info, path.read_bytes())


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
            zip_handle.writestr(info, path.read_bytes())


def verify_package(package_root: pathlib.Path, target: str) -> None:
    completed = subprocess.run(
        [sys.executable, str(package_root / "scripts/autore_distribution.py"), "verify"],
        cwd=package_root,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseAssetError(
            f"package verification failed for {target}: {completed.stderr.strip()}"
        )
    try:
        result = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseAssetError(f"invalid verification JSON for {target}: {error}") from error
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
    (output / "SHA256SUMS.release").write_text("".join(rows), encoding="utf-8")


def build_skill_archive(
    output: pathlib.Path,
    version: str,
    skill_files: list[pathlib.Path],
    reference_package: pathlib.Path,
) -> pathlib.Path:
    """Write the standalone Skill ZIP from the same verified inventory as the
    platform packages, then read it back and cross-check every member against
    the identical file inside a platform package."""
    archive = output / f"AutoRE-CLI-{version}-auto-re-skill.zip"
    skill_root = ROOT / SKILL_PATH
    write_skill_zip_from_files(skill_files, skill_root, archive)

    expected = {
        path.relative_to(skill_root).as_posix(): path for path in skill_files
    }
    with zipfile.ZipFile(archive) as handle:
        names = [info.filename for info in handle.infolist()]
        if len(names) != len(set(names)):
            raise ReleaseAssetError("Skill ZIP contains duplicate members")
        if set(names) != set(expected):
            missing = sorted(set(expected) - set(names))
            extra = sorted(set(names) - set(expected))
            raise ReleaseAssetError(
                f"Skill ZIP member set mismatch: missing={missing!r} extra={extra!r}"
            )
        for name, source in expected.items():
            member_sha256 = hashlib.sha256(handle.read(name)).hexdigest()
            if member_sha256 != sha256_file(source):
                raise ReleaseAssetError(f"Skill ZIP member digest mismatch: {name}")
            packaged = reference_package / SKILL_PATH / name
            if not packaged.is_file() or sha256_file(packaged) != member_sha256:
                raise ReleaseAssetError(
                    f"Skill ZIP diverges from platform package for member: {name}"
                )
    return archive


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


def validate_asset_manifest(manifest: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
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
        source = ROOT / expected
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
    # Verify the complete input distribution before any output manifest or
    # checksum is written; freshly generated package checksums can never
    # legitimize unverified working-tree inputs.
    inventory = verify_input_distribution()
    manifest = load_manifest()
    version, artifacts = validate_asset_manifest(manifest)
    common_files = package_common_files(inventory)
    skill_files = skill_inventory_files(inventory)

    # Stage on the destination filesystem and publish only a complete release.
    # The parent must be trusted; this is not a hostile-directory locking API.
    with tempfile.TemporaryDirectory(prefix=".autore-release-", dir=output.parent) as temporary_text:
        temporary = pathlib.Path(temporary_text)
        staging = temporary / "assets"
        staging.mkdir()
        packages = temporary / "packages"
        packages.mkdir()
        archives: list[pathlib.Path] = []
        reference_package: pathlib.Path | None = None
        for artifact in artifacts:
            target = artifact["target"]
            package_name = f"AutoRE-CLI-{version}-{target}"
            package_root = packages / package_name
            package_root.mkdir()
            prepare_package(package_root, manifest, artifact, common_files)
            verify_package(package_root, target)
            if reference_package is None:
                reference_package = package_root
            if target.startswith("windows-"):
                archive = staging / f"{package_name}.zip"
                write_zip(package_root, archive)
            else:
                archive = staging / f"{package_name}.tar.gz"
                write_tar_gz(package_root, archive)
            archives.append(archive)
        assert reference_package is not None
        archives.append(
            build_skill_archive(staging, version, skill_files, reference_package)
        )
        write_release_checksums(staging, archives)
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
        staging.rename(output)
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
    except (ReleaseAssetError, OSError, subprocess.SubprocessError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
