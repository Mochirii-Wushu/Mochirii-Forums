#!/usr/bin/python3 -B
"""Race-safe inherited locks for privileged Mochirii Forums host operations."""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import os
import pathlib
import stat
import sys
from collections.abc import Sequence


sys.dont_write_bytecode = True

CANONICAL_ROOT = pathlib.Path("/")
LOCK_DIRECTORY = "mochirii-forums"
LOCK_ORDER = ("primary", "media")
LOCK_FILES = {
    "primary": "primary.lock",
    "media": "media-certificate.lock",
}
LOCK_FDS = {
    "primary": 200,
    "media": 201,
}
CONTEXT_ENV = "MOCHIRII_FORUMS_HOST_LOCK_FDS"
CONTEXT_VERSION = "v1"
CHILD_ENVIRONMENT = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "HOME": "/nonexistent",
}
PRESERVED_CHILD_ENVIRONMENT = ("SUDO_USER", "SSH_CONNECTION")
MAX_PRESERVED_ENVIRONMENT_LENGTH = 512

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)
_LOCK_FLAGS = (
    os.O_RDWR
    | os.O_NONBLOCK
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)


class LockBoundaryError(RuntimeError):
    """The lock namespace, request, or inherited context is unsafe."""


class MissingLockContext(LockBoundaryError):
    """No inherited lock context was supplied to an assertion."""


class LockContention(LockBoundaryError):
    """A requested nonblocking lock is already held."""


def parse_lock_set(value: str) -> tuple[str, ...]:
    if not value or value.strip() != value:
        raise LockBoundaryError("Host lock set is malformed.")
    requested = tuple(value.split(","))
    if any(not item or item not in LOCK_FILES for item in requested):
        raise LockBoundaryError("Host lock set contains an unknown identifier.")
    if len(set(requested)) != len(requested):
        raise LockBoundaryError("Host lock set contains a duplicate identifier.")
    canonical = tuple(item for item in LOCK_ORDER if item in requested)
    if requested != canonical:
        raise LockBoundaryError("Host lock acquisition order is unsafe.")
    return requested


def _context_value(lock_ids: Sequence[str]) -> str:
    rows = [CONTEXT_VERSION]
    rows.extend(f"{lock_id}={LOCK_FDS[lock_id]}" for lock_id in lock_ids)
    return ";".join(rows)


def _close(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def close_lock_fds(lock_ids: Sequence[str]) -> None:
    for lock_id in reversed(tuple(lock_ids)):
        _close(LOCK_FDS[lock_id])


def _require_reserved_lock_fds_available() -> None:
    for lock_id in LOCK_ORDER:
        try:
            os.fstat(LOCK_FDS[lock_id])
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise LockBoundaryError(
                "Reserved host lock descriptor inspection failed."
            ) from error
        raise LockBoundaryError("Reserved host lock descriptor is occupied.")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise LockBoundaryError("Host operation locks require effective root.")


def _directory_mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _validate_root_directory(metadata: os.stat_result) -> None:
    mode = _directory_mode(metadata)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or not mode & stat.S_IXUSR
        or mode & 0o022
    ):
        raise LockBoundaryError("Host lock filesystem root is unsafe.")


def _validate_run_directory(metadata: os.stat_result) -> None:
    mode = _directory_mode(metadata)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or not mode & stat.S_IXUSR
        or mode & 0o022
    ):
        raise LockBoundaryError("System runtime directory is unsafe.")


def _validate_system_lock_directory(metadata: os.stat_result) -> None:
    mode = _directory_mode(metadata)
    secure_nonwritable = bool(mode & stat.S_IXUSR) and not mode & 0o022
    ubuntu_sticky = mode == 0o1777
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or not (secure_nonwritable or ubuntu_sticky)
    ):
        raise LockBoundaryError("System lock directory is unsafe.")


def _validate_private_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or _directory_mode(metadata) != 0o700
    ):
        raise LockBoundaryError("Private host lock directory is unsafe.")


def _validate_lock_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise LockBoundaryError("Host lock file metadata is unsafe.")


def _open_directory(name: str | os.PathLike[str], *, dir_fd: int | None = None) -> int:
    try:
        if dir_fd is None:
            return os.open(name, _DIRECTORY_FLAGS)
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=dir_fd)
    except OSError as error:
        raise LockBoundaryError("Host lock directory traversal failed.") from error


def _open_private_directory(root: pathlib.Path, *, create: bool) -> int:
    root_fd = _open_directory(root)
    run_fd = -1
    lock_fd = -1
    private_fd = -1
    try:
        _validate_root_directory(os.fstat(root_fd))
        run_fd = _open_directory("run", dir_fd=root_fd)
        _validate_run_directory(os.fstat(run_fd))
        lock_fd = _open_directory("lock", dir_fd=run_fd)
        _validate_system_lock_directory(os.fstat(lock_fd))
        if create:
            try:
                os.mkdir(LOCK_DIRECTORY, 0o700, dir_fd=lock_fd)
            except FileExistsError:
                pass
            except OSError as error:
                raise LockBoundaryError("Private host lock directory creation failed.") from error
        private_fd = _open_directory(LOCK_DIRECTORY, dir_fd=lock_fd)
        _validate_private_directory(os.fstat(private_fd))
        result = private_fd
        private_fd = -1
        return result
    finally:
        _close(private_fd)
        _close(lock_fd)
        _close(run_fd)
        _close(root_fd)


def _open_existing_lock(private_fd: int, lock_id: str) -> int:
    try:
        descriptor = os.open(LOCK_FILES[lock_id], _LOCK_FLAGS, dir_fd=private_fd)
    except OSError as error:
        raise LockBoundaryError("Host lock file open failed.") from error
    try:
        _validate_lock_metadata(os.fstat(descriptor))
        return descriptor
    except BaseException:
        _close(descriptor)
        raise


def _open_or_create_lock(private_fd: int, lock_id: str) -> int:
    for _attempt in range(3):
        try:
            return _open_existing_lock(private_fd, lock_id)
        except LockBoundaryError as error:
            cause = error.__cause__
            if not isinstance(cause, OSError) or cause.errno != errno.ENOENT:
                raise
        try:
            descriptor = os.open(
                LOCK_FILES[lock_id],
                _LOCK_FLAGS | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=private_fd,
            )
        except FileExistsError:
            continue
        except OSError as error:
            raise LockBoundaryError("Host lock file creation failed.") from error
        try:
            _validate_lock_metadata(os.fstat(descriptor))
            return descriptor
        except BaseException:
            _close(descriptor)
            raise
    raise LockBoundaryError("Host lock file creation raced repeatedly.")


def _move_to_fixed_fd(descriptor: int, lock_id: str) -> int:
    target = LOCK_FDS[lock_id]
    duplicate = -1
    try:
        duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, target)
        if duplicate != target:
            raise LockBoundaryError("Reserved host lock descriptor is occupied.")
        result = duplicate
        duplicate = -1
        return result
    finally:
        _close(duplicate)
        _close(descriptor)


def acquire_lock_set(
    lock_ids: Sequence[str], *, root: pathlib.Path = CANONICAL_ROOT
) -> tuple[int, ...]:
    _require_root()
    requested = parse_lock_set(",".join(lock_ids))
    private_fd = _open_private_directory(root, create=True)
    acquired: list[int] = []
    try:
        for lock_id in requested:
            descriptor = _open_or_create_lock(private_fd, lock_id)
            fixed = _move_to_fixed_fd(descriptor, lock_id)
            try:
                fcntl.flock(fixed, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                _close(fixed)
                raise LockContention("Another protected host operation is active.") from error
            except OSError as error:
                _close(fixed)
                raise LockBoundaryError("Host lock acquisition failed.") from error
            acquired.append(fixed)
        return tuple(acquired)
    except BaseException:
        for descriptor in reversed(acquired):
            _close(descriptor)
        raise
    finally:
        _close(private_fd)


def verify_nodes(
    lock_ids: Sequence[str], *, root: pathlib.Path = CANONICAL_ROOT
) -> None:
    _require_root()
    requested = parse_lock_set(",".join(lock_ids))
    private_fd = _open_private_directory(root, create=False)
    try:
        for lock_id in requested:
            descriptor = _open_existing_lock(private_fd, lock_id)
            _close(descriptor)
    finally:
        _close(private_fd)


def verify_namespace(
    lock_ids: Sequence[str], *, root: pathlib.Path = CANONICAL_ROOT
) -> None:
    """Verify the namespace and all present requested nodes without creating any."""

    _require_root()
    requested = parse_lock_set(",".join(lock_ids))
    private_fd = _open_private_directory(root, create=False)
    try:
        for lock_id in requested:
            try:
                descriptor = _open_existing_lock(private_fd, lock_id)
            except LockBoundaryError as error:
                cause = error.__cause__
                if isinstance(cause, OSError) and cause.errno == errno.ENOENT:
                    continue
                raise
            _close(descriptor)
    finally:
        _close(private_fd)


def assert_held(
    lock_ids: Sequence[str], *, root: pathlib.Path = CANONICAL_ROOT
) -> None:
    _require_root()
    requested = parse_lock_set(",".join(lock_ids))
    context = os.environ.get(CONTEXT_ENV)
    if context is None:
        raise MissingLockContext("Inherited host lock context is absent.")
    if context != _context_value(requested):
        raise LockBoundaryError("Inherited host lock context differs.")

    private_fd = _open_private_directory(root, create=False)
    try:
        for lock_id in requested:
            inherited = LOCK_FDS[lock_id]
            try:
                inherited_metadata = os.fstat(inherited)
            except OSError as error:
                raise LockBoundaryError("Inherited host lock descriptor is absent.") from error
            _validate_lock_metadata(inherited_metadata)
            if not os.get_inheritable(inherited):
                raise LockBoundaryError("Inherited host lock descriptor is close-on-exec.")

            probe = _open_existing_lock(private_fd, lock_id)
            try:
                probe_metadata = os.fstat(probe)
                if (
                    inherited_metadata.st_dev != probe_metadata.st_dev
                    or inherited_metadata.st_ino != probe_metadata.st_ino
                ):
                    raise LockBoundaryError("Inherited host lock inode differs.")
                try:
                    fcntl.flock(inherited, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    raise LockBoundaryError("Inherited host lock is not held.") from error
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    fcntl.flock(probe, fcntl.LOCK_UN)
                    raise LockBoundaryError("Inherited host lock exclusion is absent.")
            finally:
                _close(probe)
    finally:
        _close(private_fd)


def run_locked(
    lock_ids: Sequence[str],
    command: Sequence[str],
    *,
    root: pathlib.Path = CANONICAL_ROOT,
    environment: dict[str, str] | None = None,
) -> None:
    _require_root()
    requested = parse_lock_set(",".join(lock_ids))
    if os.environ.get(CONTEXT_ENV) is not None:
        raise LockBoundaryError("A host lock context is already present.")
    if not command or not os.path.isabs(command[0]):
        raise LockBoundaryError("Locked command must use an absolute executable path.")
    source_environment = os.environ if environment is None else environment
    child_environment = dict(CHILD_ENVIRONMENT)
    for name in PRESERVED_CHILD_ENVIRONMENT:
        value = source_environment.get(name)
        if value is None:
            continue
        if (
            not value
            or len(value) > MAX_PRESERVED_ENVIRONMENT_LENGTH
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise LockBoundaryError("Preserved host operation environment is malformed.")
        if name == "SUDO_USER" and value not in {
            "mochirii-forums-deploy",
            "mochirii-forums-operator",
        }:
            raise LockBoundaryError("Preserved host operation environment is malformed.")
        if name == "SSH_CONNECTION":
            fields = value.split(" ")
            try:
                if len(fields) != 4:
                    raise ValueError
                ipaddress.ip_address(fields[0])
                ipaddress.ip_address(fields[2])
                valid_connection = (
                    fields[1].isdigit()
                    and 1 <= int(fields[1]) <= 65535
                    and fields[3].isdigit()
                    and 1 <= int(fields[3]) <= 65535
                )
            except (ValueError, IndexError):
                valid_connection = False
            if not valid_connection:
                raise LockBoundaryError("Preserved host operation environment is malformed.")
        child_environment[name] = value
    child_environment[CONTEXT_ENV] = _context_value(requested)
    _require_reserved_lock_fds_available()
    acquire_lock_set(requested, root=root)
    try:
        for lock_id in requested:
            os.set_inheritable(LOCK_FDS[lock_id], True)
        os.execve(command[0], list(command), child_environment)
    except BaseException:
        close_lock_fds(requested)
        raise


def _parse_cli(argv: Sequence[str]) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if len(argv) < 3 or argv[1] != "--locks":
        raise LockBoundaryError("Host lock command syntax is invalid.")
    action = argv[0]
    requested = parse_lock_set(argv[2])
    if action in {"assert-held", "verify-namespace", "verify-nodes"}:
        if len(argv) != 3:
            raise LockBoundaryError("Host lock assertion syntax is invalid.")
        return action, requested, ()
    if action == "run":
        if len(argv) < 5 or argv[3] != "--":
            raise LockBoundaryError("Host lock run syntax is invalid.")
        return action, requested, tuple(argv[4:])
    raise LockBoundaryError("Unknown host lock command.")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        action, requested, command = _parse_cli(arguments)
        if action == "assert-held":
            assert_held(requested)
        elif action == "verify-namespace":
            verify_namespace(requested)
        elif action == "verify-nodes":
            verify_nodes(requested)
        else:
            run_locked(requested, command)
        return 0
    except MissingLockContext as error:
        print(str(error), file=sys.stderr)
        return 3
    except (LockBoundaryError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
