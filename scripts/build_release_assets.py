#!/usr/bin/env python3
"""Build deterministic, independently verifiable platform release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
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


class ReleaseAssetError(ValueError):
    pass


def load_manifest() -> dict[str, Any]:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseAssetError(f"cannot read release manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ReleaseAssetError("release manifest must be a JSON object")
    if manifest.get("distribution_scope") != "repository":
        raise ReleaseAssetError("source manifest must describe the repository distribution")
    return manifest


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def package_common_files() -> Iterable[pathlib.Path]:
    for path in sorted(ROOT.rglob("*")):
        if path.is_symlink():
            raise ReleaseAssetError(f"repository contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.parts[0] in PACKAGE_EXCLUDED_ROOTS:
            continue
        if relative.as_posix() in PACKAGE_EXCLUDED_FILES:
            continue
        yield path


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
) -> None:
    for source in package_common_files():
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


def write_skill_zip(source: pathlib.Path, archive: pathlib.Path) -> None:
    with zipfile.ZipFile(
        archive,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_handle:
        for path in iter_files(source):
            relative = path.relative_to(source)
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
    result = json.loads(completed.stdout)
    if (
        result.get("ok") is not True
        or result.get("distribution_scope") != "platform"
        or result.get("package_target") != target
        or result.get("artifact_count") != 1
    ):
        raise ReleaseAssetError(f"unexpected verification result for {target}: {result!r}")


def write_release_checksums(output: pathlib.Path, archives: list[pathlib.Path]) -> None:
    rows = [f"{sha256_file(path)}  {path.name}\n" for path in sorted(archives)]
    (output / "SHA256SUMS.release").write_text("".join(rows), encoding="utf-8")


def build_skill_archive(
    output: pathlib.Path, version: str
) -> pathlib.Path:
    archive = output / f"AutoRE-CLI-{version}-auto-re-skill.zip"
    write_skill_zip(ROOT / "skills/auto-re", archive)
    return archive


def build_assets(output: pathlib.Path) -> dict[str, Any]:
    manifest = load_manifest()
    version = manifest.get("version")
    artifacts = manifest.get("artifacts")
    if not isinstance(version, str) or not isinstance(artifacts, list):
        raise ReleaseAssetError("release manifest version or artifacts are invalid")

    output.mkdir(parents=True, exist_ok=True)
    for stale in output.iterdir():
        if stale.is_dir():
            shutil.rmtree(stale)
        else:
            stale.unlink()

    archives: list[pathlib.Path] = []
    with tempfile.TemporaryDirectory(prefix="autore-release-") as temporary_text:
        temporary = pathlib.Path(temporary_text)
        for artifact in artifacts:
            if not isinstance(artifact, dict) or not isinstance(artifact.get("target"), str):
                raise ReleaseAssetError("release manifest contains an invalid artifact")
            target = artifact["target"]
            package_name = f"AutoRE-CLI-{version}-{target}"
            package_root = temporary / package_name
            package_root.mkdir()
            prepare_package(package_root, manifest, artifact)
            verify_package(package_root, target)
            if target.startswith("windows-"):
                archive = output / f"{package_name}.zip"
                write_zip(package_root, archive)
            else:
                archive = output / f"{package_name}.tar.gz"
                write_tar_gz(package_root, archive)
            archives.append(archive)

    archives.append(build_skill_archive(output, version))
    write_release_checksums(output, archives)
    return {
        "ok": True,
        "version": version,
        "output": str(output),
        "assets": [
            {
                "path": str(path),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(archives)
        ],
        "checksum_file": str(output / "SHA256SUMS.release"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = build_assets(args.output.expanduser().resolve())
    except (ReleaseAssetError, OSError, subprocess.SubprocessError) as error:
        json.dump({"ok": False, "error": str(error)}, sys.stderr, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
