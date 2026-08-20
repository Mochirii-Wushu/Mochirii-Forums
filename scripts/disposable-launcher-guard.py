#!/usr/bin/env python3
"""Fail-closed wrapper for Discourse launcher operations on disposable CI hosts.

The official launcher can unlink its bootstrap CID before its final container
removal and can leave an untagged image behind.  This wrapper prearms a durable
operation identity, records the complete pre-operation Docker inventory, and
reconciles by immutable container/image ID as well as by operation label.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


OPERATION_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
OPERATIONS = {"bootstrap", "start", "restart", "rebuild"}
LABEL_KEY = "mochirii.forums.disposable-operation"
MAX_JOURNAL_BYTES = 65536
COMMAND_TIMEOUT = 45
LAUNCHER_TIMEOUT = 7200


class GuardError(RuntimeError):
    pass


def fail(message: str) -> "NoReturn":
    raise GuardError(message)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sha256_file(path: Path, maximum: int = MAX_JOURNAL_BYTES) -> str:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > maximum
    ):
        fail(f"Protected file is unsafe: {path}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"Protected file exceeds its byte boundary: {path}")
            digest.update(chunk)
    return digest.hexdigest()


def write_journal(path: Path, document: dict[str, object]) -> None:
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_JOURNAL_BYTES:
        fail("Disposable launcher journal exceeds its byte boundary.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Disposable launcher journal directory is unsafe.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_journal(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 1
        or metadata.st_size > MAX_JOURNAL_BYTES
    ):
        fail("Disposable launcher journal ownership, mode, or size is unsafe.")
    try:
        document = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuardError("Disposable launcher journal is malformed.") from error
    expected = {
        "schemaVersion", "operation", "phase", "operationToken", "checkoutGate",
        "checkoutGateSha256", "preexistingContainerIds", "preexistingImageIds",
        "createdContainerIds", "createdImageIds", "launcherPid", "cleanupProved",
    }
    if not isinstance(document, dict) or set(document) != expected:
        fail("Disposable launcher journal schema differs.")
    if (
        document.get("schemaVersion") != 1
        or document.get("operation") not in OPERATIONS
        or document.get("phase") not in {"armed", "launcher-active", "cleanup-armed", "terminal-proved"}
        or not isinstance(document.get("operationToken"), str)
        or OPERATION_ID_PATTERN.fullmatch(str(document["operationToken"])) is None
        or not isinstance(document.get("checkoutGate"), str)
        or not isinstance(document.get("checkoutGateSha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(document["checkoutGateSha256"])) is None
        or not isinstance(document.get("launcherPid"), int)
        or isinstance(document.get("launcherPid"), bool)
        or int(document["launcherPid"]) < 0
        or not isinstance(document.get("cleanupProved"), bool)
    ):
        fail("Disposable launcher journal values differ.")
    for key, pattern in (
        ("preexistingContainerIds", CONTAINER_ID),
        ("createdContainerIds", CONTAINER_ID),
        ("preexistingImageIds", IMAGE_ID),
        ("createdImageIds", IMAGE_ID),
    ):
        values = document.get(key)
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or any(not isinstance(value, str) or pattern.fullmatch(value) is None for value in values)
        ):
            fail(f"Disposable launcher journal {key} differs.")
    return document


class Runtime:
    def __init__(self, root: Path, adapter: Path | None) -> None:
        self.root = root
        self.adapter = adapter
        self.discourse = root / "var/discourse"
        self.cid = self.discourse / "cids/app_bootstrap.cid"
        self.journal = self.discourse / ".mochirii-disposable-launcher.transaction.json"
        self.launcher = self.discourse / "launcher"

    def run(self, arguments: list[str], *, timeout: int = COMMAND_TIMEOUT, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = ([sys.executable, "-B", str(self.adapter)] if self.adapter else []) + arguments
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise GuardError("Bounded disposable Docker command timed out.") from error
        if check and result.returncode:
            fail("Bounded disposable Docker command failed.")
        return result

    def docker(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.run((["docker"] if self.adapter else ["docker"]) + list(arguments), check=check)

    def container_ids(self) -> set[str]:
        output = self.docker("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}").stdout.splitlines()
        values = {value.strip() for value in output if value.strip()}
        if any(CONTAINER_ID.fullmatch(value) is None for value in values):
            fail("Disposable container inventory is malformed.")
        return values

    def image_ids(self) -> set[str]:
        output = self.docker("image", "ls", "--all", "--no-trunc", "--quiet").stdout.splitlines()
        values = {value.strip() for value in output if value.strip()}
        if any(IMAGE_ID.fullmatch(value) is None for value in values):
            fail("Disposable image inventory is malformed.")
        return values

    def labeled_containers(self, token: str) -> set[str]:
        output = self.docker(
            "container", "ls", "--all", "--no-trunc",
            "--filter", f"label={LABEL_KEY}={token}", "--format", "{{.ID}}",
        ).stdout.splitlines()
        values = {value.strip() for value in output if value.strip()}
        if any(CONTAINER_ID.fullmatch(value) is None for value in values):
            fail("Disposable operation-label inventory is malformed.")
        return values

    def named_app(self) -> tuple[str, bool, str] | None:
        result = self.docker(
            "container", "inspect", "--format", "{{.Id}} {{.State.Running}} {{.Image}}", "app", check=False,
        )
        if result.returncode:
            return None
        parts = result.stdout.strip().split()
        if (
            len(parts) != 3
            or CONTAINER_ID.fullmatch(parts[0]) is None
            or parts[1] not in {"true", "false"}
            or IMAGE_ID.fullmatch(parts[2]) is None
        ):
            fail("Disposable named application identity is malformed.")
        return parts[0], parts[1] == "true", parts[2]

    def tagged_app_image(self) -> str | None:
        result = self.docker("image", "inspect", "--format", "{{.Id}}", "local_discourse/app", check=False)
        if result.returncode:
            return None
        value = result.stdout.strip()
        if IMAGE_ID.fullmatch(value) is None:
            fail("Disposable tagged application image identity is malformed.")
        return value

    def remove_container(self, identity: str) -> None:
        self.docker("container", "rm", "--force", identity, check=False)

    def remove_image(self, identity: str) -> None:
        self.docker("image", "rm", "--force", identity, check=False)


def marked_processes(token: str) -> list[int]:
    marker = f"MOCHIRII_DISPOSABLE_OPERATION_TOKEN={token}".encode()
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            fields = (entry / "environ").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if marker in fields:
            found.append(int(entry.name))
    return found


def stop_marked_processes(token: str) -> None:
    for process_id in marked_processes(token):
        try:
            os.kill(process_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while marked_processes(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    for process_id in marked_processes(token):
        try:
            os.kill(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while marked_processes(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    if marked_processes(token):
        fail("Disposable launcher operation process survived reconciliation.")


def refresh_created(runtime: Runtime, document: dict[str, object]) -> tuple[set[str], set[str]]:
    containers = runtime.container_ids()
    images = runtime.image_ids()
    created_containers = (
        set(document["createdContainerIds"])
        | (containers - set(document["preexistingContainerIds"]))
        | runtime.labeled_containers(str(document["operationToken"]))
    )
    created_images = set(document["createdImageIds"]) | (images - set(document["preexistingImageIds"]))
    document["createdContainerIds"] = sorted(created_containers)
    document["createdImageIds"] = sorted(created_images)
    return created_containers, created_images


def reconcile(runtime: Runtime, document: dict[str, object], success: bool) -> None:
    token = str(document["operationToken"])
    stop_marked_processes(token)
    created_containers, created_images = refresh_created(runtime, document)
    document["phase"] = "cleanup-armed"
    document["cleanupProved"] = False
    write_journal(runtime.journal, document)

    allowed_containers: set[str] = set()
    allowed_images: set[str] = set()
    if success:
        tagged = runtime.tagged_app_image()
        operation = str(document["operation"])
        if operation == "bootstrap":
            if tagged is None:
                fail("Disposable launcher did not produce the exact application image.")
            allowed_images.add(tagged)
        else:
            named = runtime.named_app()
            if tagged is None:
                fail("Disposable launcher did not retain the exact tagged application image.")
            if named is None or not named[1]:
                fail("Disposable launcher did not leave the exact named application running.")
            if named[2] != tagged:
                fail("Disposable named application image differs from the exact tagged application image.")
            allowed_containers.add(named[0])
            allowed_images.add(tagged)

    for identity in sorted(created_containers - allowed_containers):
        runtime.remove_container(identity)
    remaining_containers = runtime.container_ids()
    remaining_labeled = runtime.labeled_containers(token)
    if (created_containers - allowed_containers) & remaining_containers or (remaining_labeled - allowed_containers):
        fail("Disposable operation-created container survived reconciliation.")

    for identity in sorted(created_images - allowed_images):
        runtime.remove_image(identity)
    remaining_images = runtime.image_ids()
    if (created_images - allowed_images) & remaining_images:
        fail("Disposable operation-created image survived reconciliation.")

    if runtime.cid.exists() or runtime.cid.is_symlink():
        fail("Disposable launcher CID survived reconciliation.")
    document["phase"] = "terminal-proved"
    document["cleanupProved"] = True
    document["launcherPid"] = 0
    write_journal(runtime.journal, document)
    runtime.journal.unlink()
    fsync_directory(runtime.journal.parent)


def reconcile_prior(runtime: Runtime, operation: str, gate: Path, gate_sha: str) -> None:
    if not runtime.journal.exists() and not runtime.journal.is_symlink():
        return
    document = read_journal(runtime.journal)
    if (
        document["operation"] != operation
        or document["checkoutGate"] != str(gate)
        or document["checkoutGateSha256"] != gate_sha
    ):
        fail("Disposable launcher retry identity differs from its durable journal.")
    reconcile(runtime, document, False)


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in OPERATIONS:
        fail("Usage: disposable-launcher-guard.py OPERATION CHECKOUT_GATE")
    operation = sys.argv[1]
    gate = Path(sys.argv[2]).resolve()
    fixture_root_value = os.environ.get("MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_ROOT", "")
    adapter: Path | None = None
    if fixture_root_value:
        if os.environ.get("MOCHIRII_DISPOSABLE_LAUNCHER_MODE") != "source-only-hostile-fixture":
            fail("Disposable launcher fixture root requires its exact source-only mode.")
        root = Path(fixture_root_value).resolve()
        if root == Path("/tmp") or not str(root).startswith("/tmp/"):
            fail("Disposable launcher fixture root must be below /tmp.")
        adapter = root / "adapter.py"
        metadata = adapter.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail("Disposable launcher fixture adapter is unsafe.")
    else:
        if os.geteuid() != 0:
            fail("Disposable launcher guard must run as root.")
        root = Path("/")
    runtime = Runtime(root, adapter)
    if not gate.is_file() or gate.is_symlink():
        fail("Disposable launcher checkout gate is absent or linked.")
    gate_sha = sha256_file(gate)
    gate_result = subprocess.run(["bash", str(gate)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if gate_result.returncode:
        fail("Disposable launcher refused unsealed deployment source.")
    runtime.discourse.mkdir(mode=0o700, parents=True, exist_ok=True)
    reconcile_prior(runtime, operation, gate, gate_sha)
    if runtime.cid.exists() or runtime.cid.is_symlink():
        fail("Unowned disposable launcher CID exists before prearm.")

    token = os.urandom(16).hex()
    pre_containers = runtime.container_ids()
    pre_images = runtime.image_ids()
    if runtime.labeled_containers(token):
        fail("Disposable operation label existed before prearm.")
    document: dict[str, object] = {
        "schemaVersion": 1,
        "operation": operation,
        "phase": "armed",
        "operationToken": token,
        "checkoutGate": str(gate),
        "checkoutGateSha256": gate_sha,
        "preexistingContainerIds": sorted(pre_containers),
        "preexistingImageIds": sorted(pre_images),
        "createdContainerIds": [],
        "createdImageIds": [],
        "launcherPid": 0,
        "cleanupProved": False,
    }
    write_journal(runtime.journal, document)
    environment = {
        **os.environ,
        "MOCHIRII_DISPOSABLE_OPERATION_TOKEN": token,
    }
    docker_arguments = (
        f"--label={LABEL_KEY}={token} --cpuset-cpus=0 "
        "--memory=2g --memory-swap=4g"
    )
    command = [
        str(runtime.launcher), operation, "app", "--skip-prereqs", "--docker-args", docker_arguments,
    ]
    if adapter:
        command = [sys.executable, "-B", str(adapter), "launcher", *command[1:]]
    process = subprocess.Popen(
        command,
        cwd=runtime.discourse,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    document["phase"] = "launcher-active"
    document["launcherPid"] = process.pid
    write_journal(runtime.journal, document)
    deadline = time.monotonic() + LAUNCHER_TIMEOUT
    while process.poll() is None and time.monotonic() < deadline:
        refresh_created(runtime, document)
        write_journal(runtime.journal, document)
        time.sleep(0.1)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    status = process.returncode if process.returncode is not None else 124
    refresh_created(runtime, document)
    write_journal(runtime.journal, document)
    if os.environ.get("MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_FAIL_AFTER") == "launcher-returned":
        os.kill(os.getpid(), signal.SIGKILL)
    if status == 0:
        try:
            reconcile(runtime, document, True)
        except GuardError as terminal_error:
            # Exit zero is not terminal evidence.  If the launcher left an
            # invalid output or anonymous residue, contain it under the same
            # durable identity before reporting the original failure.
            if runtime.journal.exists() and not runtime.journal.is_symlink():
                reconcile(runtime, read_journal(runtime.journal), False)
            raise terminal_error
    else:
        reconcile(runtime, document, False)
    if status:
        fail("Disposable launcher operation failed; operation-created residue was contained.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GuardError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
