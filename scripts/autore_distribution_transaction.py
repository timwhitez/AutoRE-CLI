#!/usr/bin/env python3
"""Command-wide installer transaction overrides.

This module is executed in ``autore_distribution.py``'s namespace after the
base implementation and leaf safety overrides are loaded.
"""

from __future__ import annotations


class _CommandSnapshot:
    """One destination captured by a command-wide filesystem transaction."""

    def __init__(self, path: pathlib.Path, expected_exists: bool) -> None:
        self.path = path
        self.expected_exists = expected_exists
        self.backup: Optional[pathlib.Path] = None
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
    ) -> None:
        actual_exists = path_exists_without_follow(path)
        if actual_exists != expected_exists:
            expected = "exist" if expected_exists else "be absent"
            raise DistributionError(
                "transaction destination changed after preflight: "
                f"expected {path} to {expected}"
            )

        snapshot = _CommandSnapshot(path, expected_exists)
        self.snapshots.append(snapshot)
        if actual_exists:
            snapshot.backup = reserve_absent_path(path.parent, prefix)
            os.replace(path, snapshot.backup)
        snapshot.capture_completed = True

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
                else (snapshot.path, snapshot.backup)
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
            path_exists = self._path_state(path)
            backup_exists = (
                self._path_state(backup) if backup is not None else False
            )

            if path_exists is None:
                errors.append(
                    "cannot inspect transaction path during rollback: "
                    f"{path}"
                )
            if backup is not None and backup_exists is None:
                errors.append(
                    f"cannot inspect transaction backup during rollback: {backup}"
                )

            if snapshot.expected_exists:
                if backup_exists is True and backup is not None:
                    if path_exists is None:
                        continue
                    try:
                        if path_exists:
                            remove_path_without_follow(path)
                        os.replace(backup, path)
                    except OSError as error:
                        errors.append(f"cannot restore {path} from {backup}: {error}")
                elif snapshot.capture_completed:
                    errors.append(
                        f"cannot restore {path}: recovery backup is missing"
                    )
                elif path_exists is False:
                    errors.append(
                        f"cannot restore {path}: original and recovery backup "
                        "are missing"
                    )
            elif path_exists is True:
                try:
                    remove_path_without_follow(path)
                except OSError as error:
                    errors.append(
                        f"cannot remove newly created transaction path {path}: {error}"
                    )

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
            backup_exists = self._path_state(backup)
            if backup_exists is False:
                continue
            if backup_exists is None:
                errors.append(f"cannot inspect transaction backup {backup}")
                continue
            try:
                remove_path_without_follow(backup)
            except OSError as error:
                errors.append(f"cannot remove transaction backup {backup}: {error}")
        if errors:
            raise DistributionError(
                "command transaction committed but backup cleanup failed: "
                + "; ".join(errors)
                + "; retained recovery paths: "
                + repr(self._retained_paths(backups_only=True))
            )


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
) -> None:
    _validate_transaction_paths([path for path, _prefix, _exists in paths])
    transaction = _CommandTransaction()
    try:
        for path, prefix, expected_exists in paths:
            transaction.capture(
                path,
                prefix,
                expected_exists=expected_exists,
            )
        mutate()
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
) -> None:
    if not extra_files and not preserved_directories:
        return

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
    ordered_directories = sorted(
        relative_directories,
        key=lambda item: (len(item.parts), item.as_posix()),
    )
    for relative in ordered_directories:
        destination.joinpath(*relative.parts).mkdir(exist_ok=False)

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

    for relative in reversed(ordered_directories):
        shutil.copystat(
            backup.joinpath(*relative.parts),
            destination.joinpath(*relative.parts),
            follow_symlinks=False,
        )
    shutil.copystat(backup, destination, follow_symlinks=False)


def _run_uninstall_transaction(
    binary_paths: list[pathlib.Path],
    skill_specs: list[tuple[pathlib.Path, list[str], list[str]]],
) -> None:
    transaction_paths = [
        *binary_paths,
        *(destination for destination, _extras, _directories in skill_specs),
    ]
    _validate_transaction_paths(transaction_paths)
    transaction = _CommandTransaction()
    try:
        for path in binary_paths:
            transaction.capture(
                path,
                f".{path.name}.uninstall-backup.",
                expected_exists=True,
            )
        for destination, _extras, _directories in skill_specs:
            transaction.capture(
                destination,
                f".{destination.name}.uninstall-backup.",
                expected_exists=True,
            )

        for destination, extras, directories in skill_specs:
            snapshot = transaction.snapshot_for(destination)
            if snapshot.backup is None:
                raise DistributionError(
                    f"uninstall transaction did not preserve skill: {destination}"
                )
            _materialize_extra_skill_tree(
                snapshot.backup,
                destination,
                extras,
                directories,
            )

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


_command_install_before_transaction = command_install
_command_uninstall_before_transaction = command_uninstall


def command_install(args):
    """Preflight all selected components, then apply one command transaction."""

    if args.dry_run:
        return _command_install_before_transaction(args)

    mutations: list[dict[str, Any]] = []
    active_replace_binary = globals()["replace_binary"]
    active_replace_skill = globals()["replace_skill"]

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
    try:
        result = _command_install_before_transaction(args)
    finally:
        globals()["replace_binary"] = active_replace_binary
        globals()["replace_skill"] = active_replace_skill

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
    )
    return result


def command_uninstall(args):
    """Quarantine every selected component before committing an uninstall."""

    if args.dry_run:
        return _command_uninstall_before_transaction(args)

    plan_args = argparse.Namespace(**vars(args))
    plan_args.dry_run = True
    result = _command_uninstall_before_transaction(plan_args)
    if not isinstance(result, dict) or result.get("dry_run") is not True:
        raise DistributionError("uninstall preflight returned an invalid result")
    operations = result.get("operations")
    if not isinstance(operations, list):
        raise DistributionError("uninstall preflight did not return an operation list")

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

    _run_uninstall_transaction(binary_paths, skill_specs)
    result["dry_run"] = False
    return result
