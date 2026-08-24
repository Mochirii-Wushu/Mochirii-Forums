#!/usr/bin/python3
"""Forced-command boundary for the automation-only Forums SSH key."""

from __future__ import annotations

import hashlib
import fcntl
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path


INCOMING = Path("/var/lib/mochirii/forums/incoming")
COMMIT = r"([0-9a-f]{40})"
DIGEST = r"([0-9a-f]{64})"
SIZE = r"([1-9][0-9]{0,8})"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_RECEIVE_SECONDS = 300
PARTIAL_NAME = ".receive.partial"
ROOT_OPERATION_LIMITS = {
    "deploy": 8400,
    "verify": 600,
    "backup": 4800,
    "restore": 13200,
}
ROOT_CONTAINMENT_GRACE_SECONDS = 300
COMMANDS = {
    "receive": re.compile(rf"\Areceive {COMMIT} {DIGEST} {SIZE}\Z"),
    "deploy": re.compile(rf"\Adeploy {COMMIT} {DIGEST} {SIZE} (bootstrap|rebuild)\Z"),
    "verify": re.compile(rf"\Averify {COMMIT}\Z"),
    "backup": re.compile(rf"\Abackup {COMMIT} {DIGEST}\Z"),
    "restore": re.compile(rf"\Arestore {COMMIT}\Z"),
}


class DispatchError(RuntimeError):
    pass


def acquire_dispatch_lock(allowed_archive: Path | None = None, allow_partial: bool = False) -> int:
    safe_incoming(allowed_archive, allow_partial=allow_partial)
    path = INCOMING / ".ssh-dispatch.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        os.close(descriptor)
        raise DispatchError("SSH dispatch lock metadata is invalid.")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise DispatchError("Another protected SSH operation is active.") from error
    return descriptor


def receive_interrupted(signum: int, _frame: object) -> None:
    if signum == signal.SIGALRM:
        raise DispatchError("Incoming release exceeded its read deadline.")
    raise DispatchError(f"Incoming release was interrupted by signal {signum}.")


def safe_incoming(allowed_archive: Path | None = None, *, allow_partial: bool = False) -> None:
    metadata = INCOMING.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DispatchError("Incoming release boundary is invalid.")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise DispatchError("Incoming release boundary permissions are invalid.")
    if allowed_archive is not None and allowed_archive.parent != INCOMING:
        raise DispatchError("Incoming release allowance escaped its exact directory.")
    allowed_name = allowed_archive.name if allowed_archive is not None else None
    entries = list(INCOMING.iterdir())
    maximum_entries = 3 if allow_partial else 2
    if len(entries) > maximum_entries:
        raise DispatchError("Incoming release inventory exceeds its exact one-slot boundary.")
    for entry in entries:
        entry_metadata = entry.lstat()
        if entry.name == ".ssh-dispatch.lock":
            if (
                not stat.S_ISREG(entry_metadata.st_mode)
                or stat.S_ISLNK(entry_metadata.st_mode)
                or entry_metadata.st_uid != os.geteuid()
                or entry_metadata.st_mode & 0o077
                or entry_metadata.st_size != 0
            ):
                raise DispatchError("Incoming dispatch lock metadata is invalid.")
        elif entry.name == allowed_name:
            if (
                not stat.S_ISREG(entry_metadata.st_mode)
                or stat.S_ISLNK(entry_metadata.st_mode)
                or entry_metadata.st_uid != os.geteuid()
                or entry_metadata.st_mode & 0o077
                or entry_metadata.st_size > MAX_ARCHIVE_BYTES
            ):
                raise DispatchError("Incoming release slot metadata is invalid.")
        elif allow_partial and entry.name == PARTIAL_NAME:
            if (
                not stat.S_ISREG(entry_metadata.st_mode)
                or stat.S_ISLNK(entry_metadata.st_mode)
                or entry_metadata.st_uid != os.geteuid()
                or entry_metadata.st_mode & 0o077
                or entry_metadata.st_size > MAX_ARCHIVE_BYTES
            ):
                raise DispatchError("Incoming partial slot metadata is invalid.")
        else:
            raise DispatchError("Incoming release inventory contains an unexpected or stale entry.")


def fsync_incoming() -> None:
    directory = os.open(INCOMING, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def reconcile_partial() -> None:
    partial = INCOMING / PARTIAL_NAME
    try:
        metadata = partial.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
        or metadata.st_size > MAX_ARCHIVE_BYTES
    ):
        raise DispatchError("Incoming partial slot cannot be safely reconciled.")
    partial.unlink()
    fsync_incoming()


def existing_archive(path: Path, expected_size: int, expected_digest: str) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise DispatchError("Existing incoming release is not one regular file.")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077 or metadata.st_size != expected_size:
        raise DispatchError("Existing incoming release metadata differs.")
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected_digest:
        raise DispatchError("Existing incoming release digest differs.")
    return True


def receive(commit: str, expected_digest: str, size_text: str) -> None:
    size = int(size_text)
    if size > MAX_ARCHIVE_BYTES:
        raise DispatchError("Incoming release exceeds the byte boundary.")
    target = INCOMING / f"{commit}.tar"
    safe_incoming(target, allow_partial=True)
    reconcile_partial()
    target_exists = existing_archive(target, size, expected_digest)
    partial = INCOMING / PARTIAL_NAME
    descriptor = -1
    if not target_exists:
        descriptor = os.open(
            partial,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    digest = hashlib.sha256()
    remaining = size
    previous_handlers: dict[int, signal.Handlers] = {}
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        previous_handlers[signum] = signal.signal(signum, receive_interrupted)
    try:
        signal.alarm(MAX_RECEIVE_SECONDS)
        while remaining:
            block = os.read(0, min(1024 * 1024, remaining))
            if not block:
                raise DispatchError("Incoming release ended before its exact byte size.")
            if descriptor >= 0:
                offset = 0
                while offset < len(block):
                    written = os.write(descriptor, block[offset:])
                    if written <= 0:
                        raise DispatchError("Incoming release could not be written completely.")
                    offset += written
            digest.update(block)
            remaining -= len(block)
        if os.read(0, 1):
            raise DispatchError("Incoming release exceeded its exact byte size.")
        if digest.hexdigest() != expected_digest:
            raise DispatchError("Incoming release digest differs.")
        if target_exists:
            if not existing_archive(target, size, expected_digest):
                raise DispatchError("Existing incoming release changed during idempotent intake.")
        else:
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                os.link(partial, target, follow_symlinks=False)
            except FileExistsError:
                if not existing_archive(target, size, expected_digest):
                    raise
            partial.unlink()
        fsync_incoming()
    finally:
        signal.alarm(0)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if descriptor >= 0:
            os.close(descriptor)
        if partial.exists():
            metadata = partial.lstat()
            if stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode) and metadata.st_uid == os.geteuid():
                partial.unlink()
                fsync_incoming()


def terminate_root_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=ROOT_CONTAINMENT_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired as error:
        raise DispatchError("Protected root operation could not be contained.") from error


def run_root(arguments: list[str], timeout_seconds: int) -> None:
    if timeout_seconds not in ROOT_OPERATION_LIMITS.values():
        raise DispatchError("Protected root operation timeout is outside the exact allowlist.")
    process = subprocess.Popen(
        ["/usr/bin/sudo", "--", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    previous_handlers: dict[int, signal.Handlers] = {}

    def interrupted(signum: int, _frame: object) -> None:
        terminate_root_group(process)
        raise DispatchError(f"Protected root operation was interrupted by signal {signum}.")

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupted)
    try:
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            terminate_root_group(process)
            raise DispatchError("Protected root operation exceeded its cumulative deadline.") from error
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    if returncode != 0:
        raise DispatchError("Protected Forums operation failed.")


def main() -> int:
    if os.geteuid() == 0:
        raise DispatchError("SSH dispatcher must run only as the restricted deploy account.")
    if pwd.getpwuid(os.geteuid()).pw_name != "mochirii-forums-deploy":
        raise DispatchError("SSH dispatcher account differs from the exact deploy principal.")
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not original or len(original) > 512 or any(ord(character) < 32 or ord(character) == 127 for character in original):
        raise DispatchError("SSH command is absent or malformed.")
    selected: tuple[str, re.Match[str]] | None = None
    for verb, pattern in COMMANDS.items():
        match = pattern.fullmatch(original)
        if match is not None:
            selected = (verb, match)
            break
    if selected is None:
        raise DispatchError("SSH command is outside the exact automation allowlist.")
    verb, match = selected
    values = match.groups()
    allowed_archive = INCOMING / f"{values[0]}.tar" if verb in {"receive", "deploy"} else None
    lock = acquire_dispatch_lock(allowed_archive, allow_partial=verb == "receive")
    try:
        if verb == "receive":
            receive(values[0], values[1], values[2])
        elif verb == "deploy":
            commit, digest, size, mode = values
            archive = INCOMING / f"{commit}.tar"
            if not existing_archive(archive, int(size), digest):
                raise DispatchError("Exact incoming release is absent.")
            run_root(
                ["/usr/local/sbin/mochirii-forums-deploy", str(archive), commit, digest, size, mode],
                ROOT_OPERATION_LIMITS["deploy"],
            )
        elif verb == "verify":
            run_root(["/usr/local/sbin/mochirii-forums-verify", values[0]], ROOT_OPERATION_LIMITS["verify"])
        elif verb == "backup":
            run_root(
                ["/usr/local/sbin/mochirii-forums-backup", values[0], values[1]],
                ROOT_OPERATION_LIMITS["backup"],
            )
        elif verb == "restore":
            run_root(
                [
                    "/usr/local/sbin/mochirii-forums-restore",
                    values[0],
                    "RESTORE DISPOSABLE MOCHIRII FORUMS",
                ],
                ROOT_OPERATION_LIMITS["restore"],
            )
        else:
            raise DispatchError("SSH command dispatch failed closed.")
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
    print("Mochirii Forums protected SSH operation completed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DispatchError, OSError, subprocess.SubprocessError):
        print("Mochirii Forums protected SSH operation failed.", file=sys.stderr)
        raise SystemExit(1) from None
