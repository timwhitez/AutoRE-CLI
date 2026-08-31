#!/usr/bin/env python3
"""Public entry point for the AutoRE-CLI distribution manager.

The implementation is executed in this module's namespace so its established import
and monkeypatch surface remains stable. This shim adds fail-closed installer safety
boundaries before delegating to the implementation.
"""

from __future__ import annotations

import pathlib as _bootstrap_pathlib


_runtime_name = __name__
_impl_path = _bootstrap_pathlib.Path(__file__).with_name("autore_distribution_impl.py")
_source = _impl_path.read_bytes()
__name__ = "_autore_distribution_impl"
exec(compile(_source, str(_impl_path), "exec"), globals(), globals())
__name__ = _runtime_name

del _source

_original_command_install = command_install


def _static_dry_run_version_probe(argv, **_kwargs):
    """Return manifest-derived version data without starting any process."""

    if len(argv) != 2 or argv[1] != "--version":
        raise DistributionError(
            "install --dry-run attempted an unexpected subprocess execution"
        )
    manifest = load_json_object(distribution_root() / MANIFEST_FILE, "release manifest")
    return subprocess.CompletedProcess(
        args=argv,
        returncode=0,
        stdout=f"{BINARY_NAME} {manifest['version']}\n",
        stderr="",
    )


def command_install(args):
    """Plan a dry-run install without executing the candidate release binary."""

    if not args.dry_run:
        return _original_command_install(args)

    original_run = subprocess.run
    subprocess.run = _static_dry_run_version_probe
    try:
        return _original_command_install(args)
    finally:
        subprocess.run = original_run


def replace_binary(
    source: pathlib.Path,
    destination: pathlib.Path,
    marker_path: pathlib.Path,
    marker: dict[str, Any],
) -> None:
    """Replace one managed binary/marker pair without losing the old generation."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_text = tempfile.mkstemp(
        prefix=".auto-re-cli.", dir=destination.parent
    )
    temporary = pathlib.Path(temporary_text)
    backup_binary: Optional[pathlib.Path] = None
    backup_marker: Optional[pathlib.Path] = None
    old_binary_backed_up = False
    old_marker_backed_up = False
    new_binary_promoted = False
    new_marker_written = False
    commit_complete = False
    os.close(descriptor)

    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        if path_exists_without_follow(destination):
            backup_binary = reserve_absent_path(
                destination.parent, ".auto-re-cli-backup."
            )
            os.replace(destination, backup_binary)
            old_binary_backed_up = True
        if path_exists_without_follow(marker_path):
            backup_marker = reserve_absent_path(
                marker_path.parent, ".auto-re-cli-marker-backup."
            )
            os.replace(marker_path, backup_marker)
            old_marker_backed_up = True
        os.replace(temporary, destination)
        new_binary_promoted = True
        atomic_write_json(marker_path, marker)
        new_marker_written = True
        commit_complete = True
    except BaseException as error:
        rollback_errors: list[str] = []

        try:
            temporary.unlink(missing_ok=True)
        except OSError as rollback_error:
            rollback_errors.append(
                f"cannot remove staged binary {temporary}: {rollback_error}"
            )

        if new_marker_written and path_exists_without_follow(marker_path):
            try:
                marker_path.unlink()
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot remove promoted marker {marker_path}: {rollback_error}"
                )
        if old_marker_backed_up and backup_marker is not None:
            try:
                if path_exists_without_follow(marker_path):
                    marker_path.unlink()
                os.replace(backup_marker, marker_path)
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot restore binary marker from {backup_marker}: "
                    f"{rollback_error}"
                )

        if new_binary_promoted and path_exists_without_follow(destination):
            try:
                destination.unlink()
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot remove promoted binary {destination}: {rollback_error}"
                )
        if old_binary_backed_up and backup_binary is not None:
            try:
                if path_exists_without_follow(destination):
                    destination.unlink()
                os.replace(backup_binary, destination)
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot restore binary from {backup_binary}: {rollback_error}"
                )

        if rollback_errors:
            retained = [
                str(path)
                for path in (temporary, backup_binary, backup_marker)
                if path is not None and path_exists_without_follow(path)
            ]
            raise DistributionError(
                "binary installation failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
                + f"; retained recovery paths: {retained!r}"
            ) from error
        raise

    if not commit_complete:
        raise DistributionError("binary installation did not reach a committed state")

    cleanup_errors: list[str] = []
    for backup, label in (
        (backup_binary, "binary backup"),
        (backup_marker, "marker backup"),
    ):
        if backup is None or not path_exists_without_follow(backup):
            continue
        try:
            backup.unlink()
        except OSError as error:
            cleanup_errors.append(f"cannot remove {label} {backup}: {error}")
    if cleanup_errors:
        retained = [
            str(path)
            for path in (backup_binary, backup_marker)
            if path is not None and path_exists_without_follow(path)
        ]
        raise DistributionError(
            "binary installation committed but backup cleanup failed: "
            + "; ".join(cleanup_errors)
            + f"; retained recovery paths: {retained!r}"
        )


def remove_path_without_follow(path: pathlib.Path) -> None:
    """Remove one filesystem object without traversing a symbolic-link target."""

    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def replace_skill(
    source: pathlib.Path,
    destination: pathlib.Path,
    marker: dict[str, Any],
) -> None:
    """Replace one skill tree while preserving the exact prior leaf on failure."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(
        tempfile.mkdtemp(prefix=".auto-re-skill-stage.", dir=destination.parent)
    )
    backup: Optional[pathlib.Path] = None
    old_destination_backed_up = False
    new_destination_promoted = False
    commit_complete = False

    try:
        shutil.rmtree(stage)
        shutil.copytree(source, stage, symlinks=False)
        atomic_write_json(stage / SKILL_MARKER, marker)
        if path_exists_without_follow(destination):
            backup = reserve_absent_path(
                destination.parent, ".auto-re-skill-backup."
            )
            os.replace(destination, backup)
            old_destination_backed_up = True
        os.replace(stage, destination)
        new_destination_promoted = True
        commit_complete = True
    except BaseException as error:
        rollback_errors: list[str] = []

        if path_exists_without_follow(stage):
            try:
                remove_path_without_follow(stage)
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot remove staged skill {stage}: {rollback_error}"
                )

        if new_destination_promoted and path_exists_without_follow(destination):
            try:
                remove_path_without_follow(destination)
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot remove promoted skill {destination}: {rollback_error}"
                )

        if old_destination_backed_up and backup is not None:
            try:
                if path_exists_without_follow(destination):
                    remove_path_without_follow(destination)
                os.replace(backup, destination)
            except OSError as rollback_error:
                rollback_errors.append(
                    f"cannot restore skill destination from {backup}: {rollback_error}"
                )

        if rollback_errors:
            retained = [
                str(path)
                for path in (stage, destination, backup)
                if path is not None and path_exists_without_follow(path)
            ]
            raise DistributionError(
                "skill installation failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
                + f"; retained recovery paths: {retained!r}"
            ) from error
        raise

    if not commit_complete:
        raise DistributionError("skill installation did not reach a committed state")

    if backup is not None and path_exists_without_follow(backup):
        try:
            remove_path_without_follow(backup)
        except OSError as error:
            raise DistributionError(
                "skill installation committed but backup cleanup failed: "
                f"cannot remove {backup}: {error}; retained recovery path: {backup}"
            ) from error


_transaction_impl_path = _bootstrap_pathlib.Path(__file__).with_name(
    "autore_distribution_transaction.py"
)
_transaction_impl_source = _transaction_impl_path.read_bytes()
exec(
    compile(
        _transaction_impl_source,
        str(_transaction_impl_path),
        "exec",
    ),
    globals(),
    globals(),
)
del _transaction_impl_source

if _runtime_name == "__main__":
    raise SystemExit(main())
