#!/usr/bin/env python3
"""Command-wide installer transaction overrides.

This module is executed in ``autore_distribution.py``'s namespace after the
base implementation and leaf safety overrides are loaded.
"""

from __future__ import annotations

import ctypes
import errno
import secrets


_UNSPECIFIED_ORIGINAL = object()


def _candidate_absent_path(parent: pathlib.Path, prefix: str) -> pathlib.Path:
    # The name is only a candidate; exclusive rename/mkdir establishes ownership.
    for _ in range(4):
        candidate = parent / f"{prefix}{secrets.token_hex(16)}"
        if not path_exists_without_follow(candidate):
            return candidate
    raise DistributionError(f"cannot choose an unused transaction path under {parent}")


def _rename_no_replace(source: pathlib.Path, destination: pathlib.Path) -> None:
    """Publish one same-filesystem object without replacing another writer's name."""
    if os.name == "nt":
        os.rename(source, destination)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise DistributionError("exclusive rename is unavailable on this host")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin":
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise DistributionError("exclusive rename is unavailable on this host")
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 0x00000004)
    else:
        raise DistributionError("exclusive rename is unsupported on this host")
    if result != 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
            raise DistributionError("exclusive rename is unsupported by this filesystem")
        raise OSError(error, os.strerror(error), str(destination))


def _record_one(path: pathlib.Path) -> tuple[int, int, int, str | None]:
    before = path.lstat()
    if not before.st_ino:
        raise DistributionError(f"stable object identity unavailable: {path}")
    if os.name == "nt" and getattr(before, "st_reparse_tag", 0):
        raise DistributionError(f"cannot own a Windows reparse point: {path}")
    kind = stat.S_IFMT(before.st_mode)
    content: str | None = None
    if stat.S_ISREG(before.st_mode):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not os.path.samestat(before, opened):
                raise DistributionError(f"object changed during identity capture: {path}")
            digest = hashlib.sha256()
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(handle.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise DistributionError(f"object changed during identity capture: {path}")
            content = digest.hexdigest()
    elif stat.S_ISLNK(before.st_mode):
        content = os.readlink(path)
    elif not stat.S_ISDIR(before.st_mode):
        raise DistributionError(f"unsupported transaction object type: {path}")
    if not os.path.samestat(before, path.lstat()):
        raise DistributionError(f"object changed during identity capture: {path}")
    return before.st_dev, before.st_ino, kind, content


def _record_object(path: pathlib.Path) -> dict[str, tuple[int, int, int, str | None]]:
    recorded: dict[str, tuple[int, int, int, str | None]] = {}

    def visit(item: pathlib.Path, relative: str) -> None:
        identity = _record_one(item)
        recorded[relative] = identity
        if stat.S_ISDIR(identity[2]):
            for name in sorted(os.listdir(item)):
                child_relative = f"{relative}/{name}" if relative else name
                visit(item / name, child_relative)
            if _record_one(item) != identity:
                raise DistributionError(f"directory changed during identity capture: {item}")

    visit(path, "")
    return recorded


def _matches_record(path: pathlib.Path, recorded: dict[str, tuple]) -> bool:
    try:
        return _record_object(path) == recorded
    except (OSError, DistributionError):
        return False


def _remove_recorded(path: pathlib.Path, recorded: dict[str, tuple]) -> None:
    if not _matches_record(path, recorded):
        raise DistributionError(f"transaction object changed or gained unknown members: {path}")
    quarantine = pathlib.Path(tempfile.mkdtemp(prefix=".auto-re-owned-cleanup.",
                                               dir=path.parent))
    held = quarantine / "owned"
    trash = quarantine / "trash"
    try:
        trash.mkdir(mode=0o700)
        _rename_no_replace(path, held)
        if not _matches_record(held, recorded):
            raise DistributionError(f"transaction object changed before cleanup: {path}")
        for relative in sorted(recorded,
                               key=lambda value: (value.count("/"), value), reverse=True):
            item = held.joinpath(*relative.split("/")) if relative else held
            name = path.name if not relative else item.name
            discarded = _candidate_absent_path(trash, f"{name[:48]}.owned.")
            _rename_no_replace(item, discarded)
            try:
                if _record_one(discarded) != recorded[relative]:
                    raise DistributionError(f"transaction object changed during cleanup: {item}")
                if stat.S_ISDIR(recorded[relative][2]):
                    discarded.rmdir()
                else:
                    discarded.unlink()
            except BaseException:
                if path_exists_without_follow(discarded) and not path_exists_without_follow(item):
                    _rename_no_replace(discarded, item)
                raise
        trash.rmdir()
        quarantine.rmdir()
    except BaseException as cause:
        if path_exists_without_follow(held) and not path_exists_without_follow(path):
            try:
                _rename_no_replace(held, path)
            except (OSError, DistributionError):
                pass
        for empty in (trash, quarantine):
            try:
                empty.rmdir()
            except OSError:
                pass
        raise DistributionError(
            f"owned cleanup was incomplete: {cause}; retained recovery path: {quarantine}"
        ) from cause


class _CommandSnapshot:
    """One destination captured by a command-wide filesystem transaction."""

    def __init__(self, path: pathlib.Path, expected_exists: bool) -> None:
        self.path = path
        self.expected_exists = expected_exists
        self.backup: Optional[pathlib.Path] = None
        self.original: Optional[dict[str, tuple]] = None
        self.stage: Optional[pathlib.Path] = None
        self.promoted: Optional[dict[str, tuple]] = None
        self.capture_completed = False


class _CommandTransaction:
    """Coordinate preflighted component mutations as one rollback boundary."""

    def __init__(self) -> None:
        self.snapshots: list[_CommandSnapshot] = []

    def capture(
        self,
        path: pathlib.Path,
        prefix: str,
        *,
        expected_exists: bool,
        expected_original: Any = _UNSPECIFIED_ORIGINAL,
    ) -> None:
        actual_exists = path_exists_without_follow(path)
        if actual_exists != expected_exists:
            expected = "exist" if expected_exists else "be absent"
            raise DistributionError(
                "transaction destination changed after preflight: "
                f"expected {path} to {expected}"
            )

        original = _record_object(path) if actual_exists else None
        if expected_original is not _UNSPECIFIED_ORIGINAL and original != expected_original:
            raise DistributionError(f"transaction destination changed after preflight: {path}")
        snapshot = _CommandSnapshot(path, expected_exists)
        snapshot.original = original
        self.snapshots.append(snapshot)
        if actual_exists:
            snapshot.backup = _candidate_absent_path(path.parent, prefix)
            _rename_no_replace(path, snapshot.backup)
            if not _matches_record(snapshot.backup, original):
                raise DistributionError(f"transaction backup changed during capture: {snapshot.backup}")
        snapshot.capture_completed = True

    def promote(self, stage: pathlib.Path, destination: pathlib.Path,
                *, expected_stage: Optional[dict[str, tuple]] = None) -> None:
        snapshot = self.snapshot_for(destination)
        if snapshot.promoted is not None:
            raise DistributionError(f"transaction path already has a promotion: {destination}")
        snapshot.stage = stage
        snapshot.promoted = expected_stage if expected_stage is not None else _record_object(stage)
        if not _matches_record(stage, snapshot.promoted):
            raise DistributionError(f"transaction stage changed before publication: {stage}")
        _rename_no_replace(stage, destination)
        if not _matches_record(destination, snapshot.promoted):
            raise DistributionError(f"transaction promotion changed during publication: {destination}")

    def snapshot_for(self, path: pathlib.Path) -> _CommandSnapshot:
        for snapshot in self.snapshots:
            if snapshot.path == path:
                return snapshot
        raise DistributionError(f"transaction did not capture expected path: {path}")

    @staticmethod
    def _path_state(path: pathlib.Path) -> Optional[bool]:
        try:
            return path_exists_without_follow(path)
        except OSError:
            return None

    def _retained_paths(self, *, backups_only: bool = False) -> list[str]:
        retained: list[str] = []
        for snapshot in self.snapshots:
            candidates = (
                (snapshot.backup,)
                if backups_only
                else (snapshot.path, snapshot.backup, snapshot.stage)
            )
            for candidate in candidates:
                if candidate is None:
                    continue
                state = self._path_state(candidate)
                if state is not False and str(candidate) not in retained:
                    retained.append(str(candidate))
        return retained

    def rollback(self, cause: BaseException) -> None:
        errors: list[str] = []
        for snapshot in reversed(self.snapshots):
            path = snapshot.path
            backup = snapshot.backup
            stage = snapshot.stage
            backup_valid = (backup is not None and snapshot.original is not None
                            and _matches_record(backup, snapshot.original))
            if backup is not None and self._path_state(backup) is not False and not backup_valid:
                errors.append(f"transaction backup changed or became unreadable: {backup}")
            if stage is not None and self._path_state(stage) is not False:
                try:
                    if snapshot.promoted is None:
                        raise DistributionError("unregistered stage identity")
                    _remove_recorded(stage, snapshot.promoted)
                except (OSError, DistributionError) as error:
                    errors.append(f"cannot remove staged transaction object {stage}: {error}")
            path_exists = self._path_state(path)
            if path_exists is None:
                errors.append(f"cannot inspect transaction path during rollback: {path}")
                continue
            if path_exists and snapshot.promoted is not None:
                if not _matches_record(path, snapshot.promoted):
                    errors.append(f"transaction path changed or gained unknown members: {path}")
                elif snapshot.original is not None and not backup_valid:
                    errors.append(f"cannot restore {path}: recovery backup is missing or changed")
                else:
                    try:
                        _remove_recorded(path, snapshot.promoted)
                        path_exists = False
                    except (OSError, DistributionError) as error:
                        errors.append(f"cannot remove promoted transaction path {path}: {error}")
            elif path_exists and snapshot.original is None:
                errors.append(f"foreign object at uncaptured transaction path: {path}")
            elif path_exists and backup_valid:
                errors.append(f"foreign replacement blocks backup restoration: {path}")

            if snapshot.original is not None:
                if backup_valid and not path_exists:
                    try:
                        _rename_no_replace(backup, path)
                    except (OSError, DistributionError) as error:
                        errors.append(f"cannot restore {path} from {backup}: {error}")
                elif not backup_valid and not _matches_record(path, snapshot.original):
                    errors.append(f"cannot restore {path}: recovery backup is missing or changed")

        if errors:
            raise DistributionError(
                "command transaction failed and rollback was incomplete: "
                + "; ".join(errors)
                + f"; retained recovery paths: {self._retained_paths()!r}"
            ) from cause

    def commit(self) -> None:
        errors: list[str] = []
        for snapshot in self.snapshots:
            backup = snapshot.backup
            if backup is None:
                continue
            try:
                if snapshot.original is None:
                    raise DistributionError("missing original identity")
                _remove_recorded(backup, snapshot.original)
            except (OSError, DistributionError) as error:
                errors.append(f"cannot remove transaction backup {backup}: {error}")
        if errors:
            raise DistributionError(
                "command transaction committed but backup cleanup failed: "
                + "; ".join(errors)
                + "; retained recovery paths: "
                + repr(self._retained_paths(backups_only=True))
            )


# ponytail: one recorder per CLI process; use a context variable if threaded entrypoints arrive.
_ACTIVE_TRANSACTION: Optional[_CommandTransaction] = None


def _normalized_transaction_path(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(path))


def _transaction_path_key(path: pathlib.Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _validate_transaction_paths(paths: list[pathlib.Path]) -> None:
    normalized: list[pathlib.Path] = []
    for path in paths:
        candidate = _normalized_transaction_path(path)
        for prior in normalized:
            if (
                candidate == prior
                or candidate in prior.parents
                or prior in candidate.parents
            ):
                raise DistributionError(
                    "overlapping command transaction paths are forbidden: "
                    f"{prior} and {candidate}"
                )
        normalized.append(candidate)


def _run_install_transaction(
    paths: list[tuple[pathlib.Path, str, bool]],
    mutate,
    verify=None,
    *,
    expected_originals: Optional[dict[str, Optional[dict[str, tuple]]]] = None,
) -> None:
    _validate_transaction_paths([path for path, _prefix, _exists in paths])
    expected = []
    for path, _prefix, exists in paths:
        key = _transaction_path_key(path)
        if expected_originals is None:
            expected.append(_record_object(path) if exists and path_exists_without_follow(path) else None)
        elif key in expected_originals:
            expected.append(expected_originals[key])
        else:
            raise DistributionError(f"install mutation lacks a preflight identity: {path}")
    transaction = _CommandTransaction()
    try:
        for (path, prefix, expected_exists), original in zip(paths, expected):
            transaction.capture(
                path,
                prefix,
                expected_exists=expected_exists,
                expected_original=original,
            )
        global _ACTIVE_TRANSACTION
        if _ACTIVE_TRANSACTION is not None:
            raise DistributionError("nested command transaction is forbidden")
        _ACTIVE_TRANSACTION = transaction
        try:
            mutate()
        finally:
            _ACTIVE_TRANSACTION = None
        if verify is not None:
            verify()
        else:
            missing = [
                str(path)
                for path, _prefix, _exists in paths
                if not path_exists_without_follow(path)
            ]
            if missing:
                raise DistributionError(
                    f"install transaction did not produce expected paths: {missing!r}"
                )
        if any(snapshot.promoted is None for snapshot in transaction.snapshots):
            raise DistributionError("install transaction did not register every publication")
    except BaseException as error:
        transaction.rollback(error)
        raise
    transaction.commit()


def _preserved_skill_directories(
    destination: pathlib.Path,
    extra_files: list[str],
) -> list[str]:
    preserved: set[pathlib.PurePosixPath] = set()

    def include_ancestors(relative: pathlib.PurePosixPath) -> None:
        current = relative
        while current.parts:
            preserved.add(current)
            current = current.parent
            if str(current) == ".":
                break

    for relative_text in extra_files:
        relative = safe_relative_path(relative_text, "extra skill file")
        parent = relative.parent
        if str(parent) != ".":
            include_ancestors(parent)

    try:
        directories: list[pathlib.Path] = []
        for item in sorted(destination.rglob("*")):
            if item.is_symlink():
                raise DistributionError(
                    f"skill contains a symlink during uninstall planning: {item}"
                )
            if item.is_dir():
                directories.append(item)
            elif not item.is_file():
                raise DistributionError(
                    f"skill contains a special file during uninstall planning: {item}"
                )
        for directory in directories:
            try:
                next(directory.iterdir())
            except StopIteration:
                relative = pathlib.PurePosixPath(
                    directory.relative_to(destination).as_posix()
                )
                include_ancestors(relative)
    except OSError as error:
        raise DistributionError(
            f"cannot inventory unmanaged skill directories under {destination}: {error}"
        ) from error

    return [
        relative.as_posix()
        for relative in sorted(
            preserved,
            key=lambda item: (len(item.parts), item.as_posix()),
        )
    ]


def _materialize_extra_skill_tree(
    backup: pathlib.Path,
    destination: pathlib.Path,
    extra_files: list[str],
    preserved_directories: list[str],
) -> Optional[dict[str, tuple]]:
    if not extra_files and not preserved_directories:
        return None

    relative_directories: set[pathlib.PurePosixPath] = {
        safe_relative_path(relative, "preserved skill directory")
        for relative in preserved_directories
    }
    for relative_text in extra_files:
        relative = safe_relative_path(relative_text, "extra skill file")
        parent = relative.parent
        while str(parent) != ".":
            relative_directories.add(parent)
            parent = parent.parent

    destination.mkdir(parents=True, exist_ok=False)
    owned = {"": _record_one(destination)}
    ordered_directories = sorted(
        relative_directories,
        key=lambda item: (len(item.parts), item.as_posix()),
    )
    try:
        for relative in ordered_directories:
            target = destination.joinpath(*relative.parts)
            target.mkdir(exist_ok=False)
            owned[relative.as_posix()] = _record_one(target)

        for relative_text in extra_files:
            relative = safe_relative_path(relative_text, "extra skill file")
            source = backup.joinpath(*relative.parts)
            target = destination.joinpath(*relative.parts)
            if source.is_symlink() or not source.is_file():
                raise DistributionError(
                    f"preserved extra skill file changed type: {source}"
                )
            try:
                os.link(source, target)
            except OSError as error:
                raise DistributionError(
                    f"cannot preserve extra skill file {source} at {target}: {error}"
                ) from error
            owned[relative.as_posix()] = _record_one(target)

        for relative in reversed(ordered_directories):
            shutil.copystat(
                backup.joinpath(*relative.parts),
                destination.joinpath(*relative.parts),
                follow_symlinks=False,
            )
        shutil.copystat(backup, destination, follow_symlinks=False)
        if not _matches_record(destination, owned):
            raise DistributionError(f"extra skill stage gained unknown members: {destination}")
        return owned
    except BaseException as cause:
        try:
            _remove_recorded(destination, owned)
        except (OSError, DistributionError) as error:
            raise DistributionError(
                f"extra skill stage failed and cleanup was incomplete: {error}; retained recovery path: {destination}"
            ) from cause
        raise


def _run_uninstall_transaction(
    binary_paths: list[pathlib.Path],
    skill_specs: list[tuple[pathlib.Path, list[str], list[str]]],
    *,
    expected_originals: Optional[dict[pathlib.Path, dict[str, tuple]]] = None,
) -> None:
    transaction_paths = [
        *binary_paths,
        *(destination for destination, _extras, _directories in skill_specs),
    ]
    _validate_transaction_paths(transaction_paths)
    expected = (expected_originals if expected_originals is not None else
                {path: _record_object(path) for path in transaction_paths})
    transaction = _CommandTransaction()
    try:
        for path in binary_paths:
            transaction.capture(
                path,
                f".{path.name}.uninstall-backup.",
                expected_exists=True,
                expected_original=expected[path],
            )
        for destination, _extras, _directories in skill_specs:
            transaction.capture(
                destination,
                f".{destination.name}.uninstall-backup.",
                expected_exists=True,
                expected_original=expected[destination],
            )

        for destination, extras, directories in skill_specs:
            snapshot = transaction.snapshot_for(destination)
            if snapshot.backup is None:
                raise DistributionError(
                    f"uninstall transaction did not preserve skill: {destination}"
                )
            if extras or directories:
                stage = _candidate_absent_path(destination.parent,
                                               ".auto-re-uninstall-stage.")
                owned = _materialize_extra_skill_tree(
                    snapshot.backup, stage, extras, directories,
                )
                assert owned is not None
                transaction.promote(stage, destination, expected_stage=owned)

        remaining_binary_paths = [
            str(path) for path in binary_paths if path_exists_without_follow(path)
        ]
        if remaining_binary_paths:
            raise DistributionError(
                "uninstall transaction retained managed binary paths: "
                f"{remaining_binary_paths!r}"
            )

        for destination, extras, directories in skill_specs:
            should_exist = bool(extras or directories)
            if path_exists_without_follow(destination) != should_exist:
                raise DistributionError(
                    "uninstall transaction produced an unexpected skill state: "
                    f"{destination}"
                )
            if should_exist:
                if destination.is_symlink() or not destination.is_dir():
                    raise DistributionError(
                        f"preserved skill destination changed type: {destination}"
                    )
                if skill_file_inventory(destination) != sorted(extras):
                    raise DistributionError(
                        "uninstall transaction preserved the wrong skill files: "
                        f"{destination}"
                    )
                for relative_text in directories:
                    relative = safe_relative_path(
                        relative_text,
                        "preserved skill directory",
                    )
                    directory = destination.joinpath(*relative.parts)
                    if directory.is_symlink() or not directory.is_dir():
                        raise DistributionError(
                            "uninstall transaction lost preserved directory: "
                            f"{directory}"
                        )
    except BaseException as error:
        transaction.rollback(error)
        raise
    transaction.commit()


def _bind_install_operations(
    mutations: list[dict[str, Any]],
    result: dict[str, Any],
) -> None:
    operations = result.get("operations")
    if not isinstance(operations, list):
        raise DistributionError("install preflight did not return an operation list")

    reported: dict[tuple[str, str], dict[str, Any]] = {}
    for operation in operations:
        if not isinstance(operation, dict):
            raise DistributionError("install preflight returned a non-object operation")
        operation_name = operation.get("operation")
        if operation_name == "noop":
            continue
        kind = operation.get("kind")
        path_value = operation.get("path")
        if not isinstance(kind, str) or not isinstance(path_value, str):
            raise DistributionError("install preflight returned an invalid operation")
        key = (kind, _transaction_path_key(pathlib.Path(path_value)))
        if key in reported:
            raise DistributionError(
                f"install preflight returned a duplicate operation: {key!r}"
            )
        reported[key] = operation

    for mutation in mutations:
        key = (
            mutation["report_kind"],
            _transaction_path_key(mutation["path"]),
        )
        operation = reported.pop(key, None)
        if operation is None:
            raise DistributionError(
                "install mutation was not present in the completed preflight: "
                f"{key!r}"
            )
        operation_name = operation.get("operation")
        if operation_name not in {"install", "replace-unmanaged", "update"}:
            raise DistributionError(
                f"unsupported install operation for {key!r}: {operation_name!r}"
            )
        mutation["operation"] = operation_name

    if reported:
        raise DistributionError(
            "install preflight reported mutations that were not collected: "
            f"{sorted(reported)!r}"
        )


def _install_transaction_paths(
    mutations: list[dict[str, Any]],
) -> list[tuple[pathlib.Path, str, bool]]:
    paths: list[tuple[pathlib.Path, str, bool]] = []
    for mutation in mutations:
        operation = mutation["operation"]
        if mutation["kind"] == "binary":
            destination = mutation["path"]
            marker_path = mutation["marker_path"]
            paths.extend(
                [
                    (
                        destination,
                        ".auto-re-command-binary-backup.",
                        operation in {"replace-unmanaged", "update"},
                    ),
                    (
                        marker_path,
                        ".auto-re-command-marker-backup.",
                        operation == "update",
                    ),
                ]
            )
        else:
            paths.append(
                (
                    mutation["path"],
                    ".auto-re-command-skill-backup.",
                    operation in {"replace-unmanaged", "update"},
                )
            )
    return paths


def _verify_install_mutations(mutations: list[dict[str, Any]]) -> None:
    for mutation in mutations:
        values = mutation["values"]
        if mutation["kind"] == "binary":
            _source, destination, marker_path, marker = values
            destination = pathlib.Path(destination)
            marker_path = pathlib.Path(marker_path)
            if destination.is_symlink() or not destination.is_file():
                raise DistributionError(
                    f"installed binary changed type: {destination}"
                )
            if sha256_file(destination) != marker.get("sha256"):
                raise DistributionError(
                    f"installed binary digest mismatch: {destination}"
                )
            if load_managed_marker(marker_path, "binary-install") != marker:
                raise DistributionError(
                    f"installed binary marker mismatch: {marker_path}"
                )
        else:
            _source, destination, marker = values
            destination = pathlib.Path(destination)
            if destination.is_symlink() or not destination.is_dir():
                raise DistributionError(
                    f"installed skill changed type: {destination}"
                )
            if load_managed_marker(
                destination / SKILL_MARKER,
                "skill-install",
            ) != marker:
                raise DistributionError(
                    f"installed skill marker mismatch: {destination}"
                )
            managed_files = marker.get("managed_files")
            if (
                not isinstance(managed_files, list)
                or any(not isinstance(item, str) for item in managed_files)
                or skill_file_inventory(destination) != sorted(managed_files)
                or installed_skill_digest(destination) != marker.get("sha256")
            ):
                raise DistributionError(
                    f"installed skill content mismatch: {destination}"
                )


def _stage_binary(source: pathlib.Path, destination: pathlib.Path) -> tuple[pathlib.Path, dict[str, tuple]]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".auto-re-cli.", dir=destination.parent)
    stage = pathlib.Path(name)
    created = os.fstat(descriptor)
    os.close(descriptor)
    try:
        shutil.copyfile(source, stage)
        stage.chmod(0o755)
        if not os.path.samestat(created, stage.lstat()):
            raise DistributionError(f"binary stage changed during preparation: {stage}")
        return stage, _record_object(stage)
    except BaseException:
        if os.path.samestat(created, stage.lstat()):
            stage.unlink()
        raise


def _stage_marker(marker_path: pathlib.Path, marker: dict[str, Any]) -> tuple[pathlib.Path, dict[str, tuple]]:
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".auto-re-cli-marker-stage.",
                                        dir=marker_path.parent)
    stage = pathlib.Path(name)
    created = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(marker, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if not os.path.samestat(created, stage.lstat()):
            raise DistributionError(f"marker stage changed during preparation: {stage}")
        return stage, _record_object(stage)
    except BaseException:
        if os.path.samestat(created, stage.lstat()):
            stage.unlink()
        raise


def _stage_skill(source: pathlib.Path, destination: pathlib.Path,
                 marker: dict[str, Any]) -> tuple[pathlib.Path, dict[str, tuple]]:
    if source.is_symlink() or not source.is_dir():
        raise FileNotFoundError(f"skill source directory is unavailable: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".auto-re-skill-stage.",
                                          dir=destination.parent))
    owned = {"": _record_one(stage)}
    directories: list[tuple[pathlib.Path, pathlib.Path]] = []
    try:
        for item in sorted(source.rglob("*"),
                           key=lambda path: (len(path.relative_to(source).parts), str(path))):
            relative = item.relative_to(source)
            target = stage / relative
            if item.is_symlink():
                raise DistributionError(f"skill source contains a symlink: {item}")
            if item.is_dir():
                target.mkdir()
                directories.append((item, target))
            elif item.is_file():
                with item.open("rb") as input_file, target.open("xb") as output_file:
                    shutil.copyfileobj(input_file, output_file)
                    output_file.flush()
                    os.fsync(output_file.fileno())
                shutil.copystat(item, target, follow_symlinks=False)
            else:
                raise DistributionError(f"skill source contains a special file: {item}")
            owned[relative.as_posix()] = _record_one(target)
        marker_file = stage / SKILL_MARKER
        with marker_file.open("x", encoding="utf-8") as handle:
            json.dump(marker, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        marker_file.chmod(0o600)
        owned[SKILL_MARKER] = _record_one(marker_file)
        for original, copied in reversed(directories):
            shutil.copystat(original, copied, follow_symlinks=False)
        shutil.copystat(source, stage, follow_symlinks=False)
        if not _matches_record(stage, owned):
            raise DistributionError(f"skill stage gained unknown members: {stage}")
        return stage, owned
    except BaseException as cause:
        try:
            _remove_recorded(stage, owned)
        except (OSError, DistributionError) as error:
            raise DistributionError(
                f"skill stage failed and cleanup was incomplete: {error}; retained recovery path: {stage}"
            ) from cause
        raise


def _publish_binary(source: pathlib.Path, destination: pathlib.Path,
                    marker_path: pathlib.Path, marker: dict[str, Any],
                    transaction: _CommandTransaction) -> None:
    stage, owned = _stage_binary(source, destination)
    transaction.promote(stage, destination, expected_stage=owned)
    marker_stage, marker_owned = _stage_marker(marker_path, marker)
    transaction.promote(marker_stage, marker_path, expected_stage=marker_owned)


def _publish_skill(source: pathlib.Path, destination: pathlib.Path,
                   marker: dict[str, Any], transaction: _CommandTransaction) -> None:
    stage, owned = _stage_skill(source, destination, marker)
    transaction.promote(stage, destination, expected_stage=owned)


def _leaf_original(path: pathlib.Path) -> Optional[dict[str, tuple]]:
    try:
        return _record_object(path)
    except FileNotFoundError:
        return None


def replace_binary(source: pathlib.Path, destination: pathlib.Path,
                   marker_path: pathlib.Path, marker: dict[str, Any]) -> None:
    if _ACTIVE_TRANSACTION is not None:
        _publish_binary(source, destination, marker_path, marker, _ACTIVE_TRANSACTION)
        return
    originals = {destination: _leaf_original(destination),
                 marker_path: _leaf_original(marker_path)}
    paths = [(destination, ".auto-re-cli-backup.", originals[destination] is not None),
             (marker_path, ".auto-re-cli-marker-backup.", originals[marker_path] is not None)]

    def mutate() -> None:
        assert _ACTIVE_TRANSACTION is not None
        _publish_binary(source, destination, marker_path, marker, _ACTIVE_TRANSACTION)

    _run_install_transaction(
        paths, mutate,
        expected_originals={_transaction_path_key(path): original
                            for path, original in originals.items()},
    )


def replace_skill(source: pathlib.Path, destination: pathlib.Path,
                  marker: dict[str, Any]) -> None:
    if _ACTIVE_TRANSACTION is not None:
        _publish_skill(source, destination, marker, _ACTIVE_TRANSACTION)
        return
    original = _leaf_original(destination)
    paths = [(destination, ".auto-re-skill-backup.", original is not None)]

    def mutate() -> None:
        assert _ACTIVE_TRANSACTION is not None
        _publish_skill(source, destination, marker, _ACTIVE_TRANSACTION)

    _run_install_transaction(
        paths, mutate,
        expected_originals={_transaction_path_key(destination): original},
    )


_command_install_before_transaction = command_install
_command_uninstall_before_transaction = command_uninstall


def command_install(args):
    """Preflight all selected components, then apply one command transaction."""

    if args.dry_run:
        return _command_install_before_transaction(args)

    mutations: list[dict[str, Any]] = []
    preflight_originals: dict[str, Optional[dict[str, tuple]]] = {}
    active_replace_binary = globals()["replace_binary"]
    active_replace_skill = globals()["replace_skill"]
    active_binary_preflight = globals()["preflight_binary_install"]
    active_skill_preflight = globals()["preflight_skill_install"]

    def preflight_identity(path: pathlib.Path) -> Optional[dict[str, tuple]]:
        return _record_object(path) if path_exists_without_follow(path) else None

    def remember_unchanged(path: pathlib.Path, before: Optional[dict[str, tuple]]) -> None:
        if preflight_identity(path) != before:
            raise DistributionError(f"transaction destination changed during preflight: {path}")
        preflight_originals[_transaction_path_key(path)] = before

    def checked_binary_preflight(source, destination, marker_path, marker,
                                 *, replace_unmanaged):
        destination = pathlib.Path(destination)
        marker_path = pathlib.Path(marker_path)
        before_destination = preflight_identity(destination)
        before_marker = preflight_identity(marker_path)
        operation = active_binary_preflight(
            source, destination, marker_path, marker,
            replace_unmanaged=replace_unmanaged,
        )
        remember_unchanged(destination, before_destination)
        remember_unchanged(marker_path, before_marker)
        return operation

    def checked_skill_preflight(source, destination, marker, *, replace_unmanaged):
        destination = pathlib.Path(destination)
        before_destination = preflight_identity(destination)
        operation = active_skill_preflight(
            source, destination, marker, replace_unmanaged=replace_unmanaged,
        )
        remember_unchanged(destination, before_destination)
        return operation

    def collect_binary(source, destination, marker_path, marker):
        mutations.append(
            {
                "kind": "binary",
                "report_kind": "binary",
                "path": pathlib.Path(destination),
                "marker_path": pathlib.Path(marker_path),
                "values": (source, destination, marker_path, marker),
            }
        )

    def collect_skill(source, destination, marker):
        agent = marker.get("agent") if isinstance(marker, dict) else None
        if not isinstance(agent, str) or agent not in {"trae", "codex"}:
            raise DistributionError(
                f"install preflight produced an invalid skill marker: {marker!r}"
            )
        mutations.append(
            {
                "kind": "skill",
                "report_kind": f"{agent}-skill",
                "path": pathlib.Path(destination),
                "values": (source, destination, marker),
            }
        )

    globals()["replace_binary"] = collect_binary
    globals()["replace_skill"] = collect_skill
    globals()["preflight_binary_install"] = checked_binary_preflight
    globals()["preflight_skill_install"] = checked_skill_preflight
    try:
        result = _command_install_before_transaction(args)
    finally:
        globals()["replace_binary"] = active_replace_binary
        globals()["replace_skill"] = active_replace_skill
        globals()["preflight_binary_install"] = active_binary_preflight
        globals()["preflight_skill_install"] = active_skill_preflight

    if not isinstance(result, dict) or result.get("dry_run") is not False:
        raise DistributionError("install preflight returned an invalid result")
    _bind_install_operations(mutations, result)
    paths = _install_transaction_paths(mutations)

    def mutate() -> None:
        for mutation in mutations:
            if mutation["kind"] == "binary":
                active_replace_binary(*mutation["values"])
            else:
                active_replace_skill(*mutation["values"])

    _run_install_transaction(
        paths,
        mutate,
        lambda: _verify_install_mutations(mutations),
        expected_originals=preflight_originals,
    )
    return result


def command_uninstall(args):
    """Quarantine every selected component before committing an uninstall."""

    if args.dry_run:
        return _command_uninstall_before_transaction(args)

    install_cli, install_skill = selected_components(args)
    candidates: list[pathlib.Path] = []
    if install_cli:
        install_dir = pathlib.Path(
            args.install_dir or os.environ.get("AUTORE_INSTALL_DIR")
            or pathlib.Path.home() / ".local" / "bin"
        ).expanduser()
        candidates.extend([install_dir / installed_binary_name(), install_dir / BINARY_MARKER])
    if install_skill:
        candidates.extend(destination for _agent, destination in agent_destinations(args))
    if len(candidates) != len(set(candidates)):
        raise DistributionError("duplicate uninstall candidate path")
    before_preflight = {
        path: _record_object(path) if path_exists_without_follow(path) else None
        for path in candidates
    }

    plan_args = argparse.Namespace(**vars(args))
    plan_args.dry_run = True
    result = _command_uninstall_before_transaction(plan_args)
    if not isinstance(result, dict) or result.get("dry_run") is not True:
        raise DistributionError("uninstall preflight returned an invalid result")
    operations = result.get("operations")
    if not isinstance(operations, list):
        raise DistributionError("uninstall preflight did not return an operation list")

    expected_originals: dict[pathlib.Path, dict[str, tuple]] = {}
    for operation in operations:
        if not isinstance(operation, dict) or not isinstance(operation.get("path"), str):
            raise DistributionError("uninstall preflight returned an invalid operation")
        path = pathlib.Path(operation["path"])
        kind = operation.get("kind")
        if kind == "binary":
            targets = (path, path.parent / BINARY_MARKER)
        elif kind in {"trae-skill", "codex-skill"}:
            targets = (path,)
        else:
            raise DistributionError(f"unsupported uninstall operation kind: {kind!r}")
        for target in targets:
            if target in expected_originals:
                raise DistributionError(f"duplicate uninstall transaction path: {target}")
            if target not in before_preflight or before_preflight[target] is None:
                raise DistributionError(f"uninstall target changed during preflight: {target}")
            current = _record_object(target) if path_exists_without_follow(target) else None
            if current != before_preflight[target]:
                raise DistributionError(f"uninstall target changed during preflight: {target}")
            expected_originals[target] = before_preflight[target]

    binary_paths: list[pathlib.Path] = []
    skill_specs: list[tuple[pathlib.Path, list[str], list[str]]] = []
    for operation in operations:
        if not isinstance(operation, dict):
            raise DistributionError(
                "uninstall preflight returned a non-object operation"
            )
        kind = operation.get("kind")
        path_value = operation.get("path")
        if not isinstance(kind, str) or not isinstance(path_value, str):
            raise DistributionError("uninstall preflight returned an invalid operation")
        path = pathlib.Path(path_value)
        if kind == "binary":
            if operation.get("operation") != "remove":
                raise DistributionError(
                    f"unsupported binary uninstall operation: {operation!r}"
                )
            binary_paths.extend([path, path.parent / BINARY_MARKER])
        elif kind in {"trae-skill", "codex-skill"}:
            if operation.get("operation") != "remove-managed-files":
                raise DistributionError(
                    f"unsupported skill uninstall operation: {operation!r}"
                )
            extras = operation.get("extra_files_preserved", [])
            if not isinstance(extras, list) or any(
                not isinstance(item, str) for item in extras
            ):
                raise DistributionError(
                    f"invalid preserved skill file list: {operation!r}"
                )
            directories = _preserved_skill_directories(path, extras)
            skill_specs.append((path, list(extras), directories))
        else:
            raise DistributionError(
                f"unsupported uninstall operation kind: {kind!r}"
            )

    _run_uninstall_transaction(binary_paths, skill_specs,
                               expected_originals=expected_originals)
    result["dry_run"] = False
    return result
