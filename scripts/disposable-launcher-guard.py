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
MAX_EVENT_BYTES = 1024 * 1024
MAX_EVENT_LINE_BYTES = 65536
MAX_EVENT_COUNT = 512
MAX_CONTAINER_IDENTITIES = 64
MAX_CID_BYTES = 65
MAX_EVENT_DRAIN_BYTES = 256 * 1024
EVENT_SETTLE_TIMEOUT = 0.25
EVENT_STOP_TIMEOUT = 5
MAX_MEMINFO_BYTES = 65536
RESOURCE_COMMAND_TIMEOUT = 5


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

    def event_command(self, token: str) -> list[str]:
        if self.adapter:
            return [sys.executable, "-B", str(self.adapter), "events"]
        return [
            "docker", "events", "--since", str(max(0, int(time.time()) - 1)),
            "--filter", f"label={LABEL_KEY}={token}", "--format", "{{json .}}",
        ]


class ContainerLifecycle:
    def __init__(self) -> None:
        self.event_count = 0
        self.create_count = 0
        self.start_count = 0
        self.die_count = 0
        self.destroy_count = 0
        self.oom_count = 0
        self.die_exit_codes: list[int] = []


class LifecycleRecorder:
    """Retain only bounded, non-secret facts from exact-label Docker events."""

    def __init__(self, runtime: Runtime, token: str, environment: dict[str, str]) -> None:
        self.runtime = runtime
        self.token = token
        self.environment = environment
        self.process: subprocess.Popen[bytes] | None = None
        self.stream: object | None = None
        self.buffer = bytearray()
        self.bytes_read = 0
        self.event_count = 0
        self.create_count = 0
        self.start_count = 0
        self.die_count = 0
        self.destroy_count = 0
        self.oom_count = 0
        self.containers: dict[str, ContainerLifecycle] = {}
        self.bootstrap_identity: str | None = None
        self.cid_incomplete_seen = False
        self.cid_malformed = False
        self.malformed = False
        self.overflow = False
        self.recorder_failed = False

    def start(self) -> None:
        try:
            self.process = subprocess.Popen(
                self.runtime.event_command(self.token),
                cwd=self.runtime.discourse,
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                bufsize=0,
            )
        except OSError:
            self.recorder_failed = True
            return
        if self.process.stdout is None:
            self.recorder_failed = True
            return
        self.stream = self.process.stdout
        try:
            os.set_blocking(self.process.stdout.fileno(), False)
        except OSError:
            self.recorder_failed = True
            self._close_stream()

    def _close_stream(self) -> None:
        if self.stream is not None:
            try:
                self.stream.close()  # type: ignore[union-attr]
            except OSError:
                pass
            self.stream = None

    def _invalidate_stream(self, *, overflow: bool = False) -> None:
        self.overflow = self.overflow or overflow
        self.malformed = self.malformed or not overflow
        self.buffer.clear()
        self._close_stream()

    def _parse_event(self, payload: bytes) -> None:
        if not payload or len(payload) > MAX_EVENT_LINE_BYTES or self.event_count >= MAX_EVENT_COUNT:
            self._invalidate_stream(overflow=self.event_count >= MAX_EVENT_COUNT)
            return
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._invalidate_stream()
            return
        if not isinstance(document, dict):
            self._invalidate_stream()
            return
        actor = document.get("Actor")
        attributes = actor.get("Attributes") if isinstance(actor, dict) else None
        identity = actor.get("ID") if isinstance(actor, dict) else None
        event_type = document.get("Type")
        action = document.get("Action", document.get("status"))
        if (
            not isinstance(attributes, dict)
            or attributes.get(LABEL_KEY) != self.token
            or not isinstance(identity, str)
            or CONTAINER_ID.fullmatch(identity) is None
            or event_type != "container"
            or not isinstance(action, str)
        ):
            self._invalidate_stream()
            return
        lifecycle = self.containers.get(identity)
        if lifecycle is None:
            if len(self.containers) >= MAX_CONTAINER_IDENTITIES:
                self._invalidate_stream(overflow=True)
                return
            lifecycle = ContainerLifecycle()
            self.containers[identity] = lifecycle
        self.event_count += 1
        lifecycle.event_count += 1
        if action == "create":
            self.create_count += 1
            lifecycle.create_count += 1
        elif action == "start":
            self.start_count += 1
            lifecycle.start_count += 1
        elif action == "die":
            value = attributes.get("exitCode")
            if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,3}", value) is None or int(value) > 255:
                self._invalidate_stream()
                return
            self.die_count += 1
            lifecycle.die_count += 1
            lifecycle.die_exit_codes.append(int(value))
        elif action == "destroy":
            self.destroy_count += 1
            lifecycle.destroy_count += 1
        elif action == "oom":
            self.oom_count += 1
            lifecycle.oom_count += 1

    def observe_bootstrap_cid(self, path: Path, *, final: bool = False) -> None:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            if final and self.cid_incomplete_seen:
                self.cid_malformed = True
            return
        except OSError:
            self.cid_malformed = True
            return
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                self.cid_malformed = True
                return
            # Docker creates/truncates --cidfile before ContainerCreate and
            # writes the identity only after creation succeeds.  A poll may
            # therefore see a legitimate short in-progress file.  Only the
            # final observation treats a still-short file as malformed.
            if metadata.st_size < 64:
                self.cid_incomplete_seen = True
                self.cid_malformed = self.cid_malformed or final
                return
            if metadata.st_size not in {64, MAX_CID_BYTES}:
                self.cid_malformed = True
                return
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    self.cid_malformed = True
                    return
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if os.read(descriptor, 1):
                self.cid_malformed = True
                return
            value = payload.strip()
            if re.fullmatch(rb"[0-9a-f]{64}", value) is None:
                self.cid_malformed = True
                return
            identity = value.decode("ascii")
            if self.bootstrap_identity is not None and self.bootstrap_identity != identity:
                self.cid_malformed = True
                return
            self.bootstrap_identity = identity
            self.cid_incomplete_seen = False
        finally:
            os.close(descriptor)

    def drain(self) -> None:
        if self.stream is None:
            return
        drained = 0
        descriptor = self.stream.fileno()  # type: ignore[union-attr]
        while drained < MAX_EVENT_DRAIN_BYTES and self.stream is not None:
            try:
                chunk = os.read(descriptor, min(65536, MAX_EVENT_DRAIN_BYTES - drained))
            except BlockingIOError:
                break
            except OSError:
                self.recorder_failed = True
                self._close_stream()
                break
            if not chunk:
                self._close_stream()
                break
            drained += len(chunk)
            self.bytes_read += len(chunk)
            if self.bytes_read > MAX_EVENT_BYTES:
                self._invalidate_stream(overflow=True)
                break
            self.buffer.extend(chunk)
            while self.stream is not None and b"\n" in self.buffer:
                payload, _, remainder = self.buffer.partition(b"\n")
                self.buffer = bytearray(remainder)
                self._parse_event(payload)
            if len(self.buffer) > MAX_EVENT_LINE_BYTES:
                self._invalidate_stream(overflow=True)

    def stop(self) -> None:
        process = self.process
        if process is None:
            self._close_stream()
            return
        self.drain()
        if process.poll() is not None:
            self.recorder_failed = True
        else:
            settle_deadline = time.monotonic() + EVENT_SETTLE_TIMEOUT
            while self.stream is not None and time.monotonic() < settle_deadline:
                self.drain()
                time.sleep(0.01)
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + EVENT_STOP_TIMEOUT
            while process.poll() is None and time.monotonic() < deadline:
                self.drain()
                time.sleep(0.02)
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=EVENT_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    self.recorder_failed = True
            else:
                process.wait()
        self.drain()
        if self.buffer:
            self.malformed = True
            self.buffer.clear()
        self._close_stream()
        self.process = None

    def failure_message(
        self,
        operation: str,
        launcher_status: int,
        elapsed_seconds: int,
        resources_before: dict[str, int],
        resources_after: dict[str, int],
    ) -> str:
        valid = not (self.malformed or self.overflow or self.recorder_failed or self.cid_malformed)
        bootstrap = self.containers.get(self.bootstrap_identity) if self.bootstrap_identity is not None else None
        exact_die_code = bootstrap.die_exit_codes[0] if bootstrap is not None and len(bootstrap.die_exit_codes) == 1 else -1
        if not valid:
            failure_class = "incomplete-unknown"
        elif self.bootstrap_identity is None:
            failure_class = "pre-container" if self.event_count == 0 else "bootstrap-unobserved"
        elif bootstrap is None or bootstrap.die_count != 1:
            failure_class = "incomplete-unknown"
        elif exact_die_code == 0 and bootstrap.oom_count == 0:
            failure_class = "post-bootstrap-launcher-failure"
        elif exact_die_code == 0:
            failure_class = "incomplete-unknown"
        elif bootstrap.oom_count:
            failure_class = "oom-container-exit"
        else:
            failure_class = "non-oom-container-exit"
        bootstrap_code = exact_die_code if operation == "bootstrap" else -1
        bootstrap_event_count = bootstrap.event_count if bootstrap is not None else 0
        fields = (
            f"failure_class={failure_class}",
            f"launcher_rc={launcher_status}",
            f"elapsed_seconds={elapsed_seconds}",
            f"lifecycle_valid={'true' if valid else 'false'}",
            f"bootstrap_identity_observed={'true' if self.bootstrap_identity is not None else 'false'}",
            f"event_count={self.event_count}",
            f"bootstrap_event_count={bootstrap_event_count}",
            f"helper_event_count={self.event_count - bootstrap_event_count}",
            f"container_create_count={self.create_count}",
            f"container_start_count={self.start_count}",
            f"container_die_count={self.die_count}",
            f"container_destroy_count={self.destroy_count}",
            f"oom_observed={'true' if bootstrap is not None and bootstrap.oom_count > 0 else 'false'}",
            f"die_exit_code_observed={'true' if exact_die_code >= 0 else 'false'}",
            f"die_exit_code={exact_die_code}",
            f"bootstrap_exit_code_observed={'true' if bootstrap_code >= 0 else 'false'}",
            f"bootstrap_exit_code={bootstrap_code}",
            f"docker_free_pre_bytes={resources_before['dockerFreeBytes']}",
            f"docker_free_post_bytes={resources_after['dockerFreeBytes']}",
            f"mem_available_pre_bytes={resources_before['memAvailableBytes']}",
            f"mem_available_post_bytes={resources_after['memAvailableBytes']}",
            f"swap_free_pre_bytes={resources_before['swapFreeBytes']}",
            f"swap_free_post_bytes={resources_after['swapFreeBytes']}",
            f"swap_total_pre_bytes={resources_before['swapTotalBytes']}",
            f"swap_total_post_bytes={resources_after['swapTotalBytes']}",
        )
        return (
            "Disposable launcher operation failed; operation-created residue was contained. "
            + " ".join(fields)
        )


def resource_snapshot(runtime: Runtime) -> dict[str, int]:
    values = {
        "dockerFreeBytes": -1,
        "memAvailableBytes": -1,
        "swapFreeBytes": -1,
        "swapTotalBytes": -1,
    }
    try:
        result = runtime.run(
            ["docker", "info", "--format", "{{.DockerRootDir}}"],
            timeout=RESOURCE_COMMAND_TIMEOUT,
            check=False,
        )
        lines = result.stdout.splitlines()
        if result.returncode == 0 and len(lines) == 1 and 0 < len(lines[0]) <= 4096:
            docker_root = Path(lines[0])
            if docker_root.is_absolute():
                filesystem = os.statvfs(docker_root)
                free_bytes = filesystem.f_bavail * filesystem.f_frsize
                if 0 <= free_bytes <= (2**63 - 1):
                    values["dockerFreeBytes"] = free_bytes
    except (GuardError, OSError, UnicodeError, ValueError):
        pass
    try:
        with Path("/proc/meminfo").open("rb") as source:
            payload = source.read(MAX_MEMINFO_BYTES + 1)
        if len(payload) <= MAX_MEMINFO_BYTES:
            fields: dict[bytes, int] = {}
            for line in payload.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[0] in {b"MemAvailable:", b"SwapFree:", b"SwapTotal:"} and parts[2] == b"kB":
                    if re.fullmatch(rb"[0-9]{1,20}", parts[1]) is not None:
                        amount = int(parts[1]) * 1024
                        if 0 <= amount <= (2**63 - 1):
                            fields[parts[0]] = amount
            if set(fields) == {b"MemAvailable:", b"SwapFree:", b"SwapTotal:"}:
                values["memAvailableBytes"] = fields[b"MemAvailable:"]
                values["swapFreeBytes"] = fields[b"SwapFree:"]
                values["swapTotalBytes"] = fields[b"SwapTotal:"]
    except (OSError, ValueError):
        pass
    return values


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
    resources_before = resource_snapshot(runtime)
    recorder = LifecycleRecorder(runtime, token, environment)
    recorder.start()
    launcher_started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=runtime.discourse,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        recorder.stop()
        reconcile(runtime, document, False)
        raise GuardError("Disposable launcher process could not start; operation-created residue was contained.") from error
    try:
        document["phase"] = "launcher-active"
        document["launcherPid"] = process.pid
        write_journal(runtime.journal, document)
        deadline = time.monotonic() + LAUNCHER_TIMEOUT
        while process.poll() is None and time.monotonic() < deadline:
            recorder.observe_bootstrap_cid(runtime.cid)
            recorder.drain()
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
        recorder.observe_bootstrap_cid(runtime.cid, final=True)
        status = process.returncode if process.returncode is not None else 124
        elapsed_seconds = min(LAUNCHER_TIMEOUT + 60, max(0, int(time.monotonic() - launcher_started)))
    finally:
        recorder.stop()
    resources_after = resource_snapshot(runtime)
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
        fail(recorder.failure_message(operation, status, elapsed_seconds, resources_before, resources_after))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GuardError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
