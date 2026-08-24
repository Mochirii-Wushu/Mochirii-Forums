#!/usr/bin/python3 -B
"""Hostile Linux fixture for the privileged host-operation lock boundary."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types


sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts/host-operation-lock.py"
TEST_PATH = pathlib.Path(__file__).resolve()
BASE_IMAGE = "discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"


def load_helper():
    specification = importlib.util.spec_from_file_location(
        "mochirii_host_operation_lock", HELPER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Host-operation lock helper could not be loaded.")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


HELPER = load_helper() if os.name == "posix" else None


def clean_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop(HELPER.CONTEXT_ENV, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def boot_root(root: pathlib.Path, *, private: bool = False) -> pathlib.Path:
    run = root / "run"
    locks = run / "lock"
    run.mkdir(mode=0o755)
    locks.mkdir(mode=0o1777)
    run.chmod(0o755)
    locks.chmod(0o1777)
    if private:
        boundary = locks / HELPER.LOCK_DIRECTORY
        boundary.mkdir(mode=0o700)
        boundary.chmod(0o700)
    return locks


def assert_no_lock_artifacts(root: pathlib.Path) -> None:
    boundary = root / "run/lock" / HELPER.LOCK_DIRECTORY
    if boundary.exists() or boundary.is_symlink():
        raise RuntimeError("Rejected lock boundary created a private lock artifact.")


def expect_boundary_error(action, label: str) -> None:
    try:
        action()
    except HELPER.LockBoundaryError:
        return
    raise RuntimeError(f"{label} crossed the host-operation lock boundary.")


def close_requested(lock_ids: tuple[str, ...]) -> None:
    HELPER.close_lock_fds(lock_ids)


def wait_for(path: pathlib.Path, label: str, seconds: float = 8.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file() and not path.is_symlink():
            return
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {label}.")


def assert_pid_absent(pid: int) -> None:
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        try:
            fields = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
            if len(fields) >= 3 and fields[2] == "Z":
                return
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            return
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        time.sleep(0.05)
    raise RuntimeError("Detached lock inheritor did not exit.")


def subprocess_result(*arguments: str, environment: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, "-B", str(TEST_PATH), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=clean_environment() if environment is None else environment,
        timeout=20,
    )


def malicious_directory_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-lock-run-link-") as temporary:
        root = pathlib.Path(temporary)
        victim = root / "victim"
        victim.mkdir()
        (root / "run").symlink_to(victim, target_is_directory=True)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "linked /run parent",
        )
        if any(victim.iterdir()):
            raise RuntimeError("Linked /run parent received a lock artifact.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-system-link-") as temporary:
        root = pathlib.Path(temporary)
        run = root / "run"
        run.mkdir(mode=0o755)
        run.chmod(0o755)
        victim = root / "victim"
        victim.mkdir()
        (run / "lock").symlink_to(victim, target_is_directory=True)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "linked /run/lock parent",
        )
        if any(victim.iterdir()):
            raise RuntimeError("Linked system lock parent received a lock artifact.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-private-link-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root)
        victim = root / "victim"
        victim.mkdir()
        (locks / HELPER.LOCK_DIRECTORY).symlink_to(victim, target_is_directory=True)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "linked private lock directory",
        )
        if any(victim.iterdir()):
            raise RuntimeError("Linked private lock directory received a lock artifact.")


def malicious_file_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-lock-file-link-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        boundary = locks / HELPER.LOCK_DIRECTORY
        victim = root / "victim.txt"
        original = b"immutable victim bytes\n"
        victim.write_bytes(original)
        victim.chmod(0o600)
        (boundary / HELPER.LOCK_FILES["primary"]).symlink_to(victim)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "linked lock file",
        )
        if victim.read_bytes() != original:
            raise RuntimeError("Linked lock victim bytes changed.")

    constructors = {
        "directory": lambda path: path.mkdir(mode=0o600),
        "fifo": lambda path: os.mkfifo(path, 0o600),
        "socket": _create_socket_entry,
    }
    for label, constructor in constructors.items():
        with tempfile.TemporaryDirectory(prefix=f"mochirii-lock-{label}-") as temporary:
            root = pathlib.Path(temporary)
            locks = boot_root(root, private=True)
            entry = locks / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["primary"]
            handle = constructor(entry)
            try:
                expect_boundary_error(
                    lambda: HELPER.acquire_lock_set(("primary",), root=root),
                    f"nonregular {label} lock",
                )
            finally:
                if handle is not None:
                    handle.close()


def _create_socket_entry(path: pathlib.Path):
    handle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    handle.bind(str(path))
    return handle


def metadata_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-lock-private-mode-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        boundary = locks / HELPER.LOCK_DIRECTORY
        boundary.chmod(0o755)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "unsafe private-directory mode",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-private-owner-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        boundary = locks / HELPER.LOCK_DIRECTORY
        try:
            os.chown(boundary, 65534, 65534)
        except PermissionError:
            pass
        else:
            expect_boundary_error(
                lambda: HELPER.acquire_lock_set(("primary",), root=root),
                "unsafe private-directory owner",
            )

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-file-mode-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        entry = locks / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["primary"]
        entry.write_bytes(b"")
        entry.chmod(0o644)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "unsafe lock-file mode",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-hardlink-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        boundary = locks / HELPER.LOCK_DIRECTORY
        entry = boundary / HELPER.LOCK_FILES["primary"]
        entry.write_bytes(b"")
        entry.chmod(0o600)
        try:
            os.link(entry, boundary / "second-name")
        except OSError:
            pass
        else:
            expect_boundary_error(
                lambda: HELPER.acquire_lock_set(("primary",), root=root),
                "hardlinked lock file",
            )

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-file-owner-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        entry = locks / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["primary"]
        entry.write_bytes(b"")
        entry.chmod(0o600)
        try:
            os.chown(entry, 65534, 65534)
        except PermissionError:
            pass
        else:
            expect_boundary_error(
                lambda: HELPER.acquire_lock_set(("primary",), root=root),
                "unsafe lock-file owner",
            )
            if entry.lstat().st_uid != 65534:
                raise RuntimeError("Filesystem owner hostile did not retain its unsafe owner.")

    valid = os.stat_result((stat.S_IFREG | 0o600, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    synthetic = types.SimpleNamespace(
        st_mode=valid.st_mode,
        st_uid=65534,
        st_gid=65534,
        st_nlink=1,
    )
    expect_boundary_error(
        lambda: HELPER._validate_lock_metadata(synthetic),
        "synthetic unsafe lock owner",
    )
    synthetic_directory = types.SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_uid=65534,
        st_gid=65534,
    )
    expect_boundary_error(
        lambda: HELPER._validate_private_directory(synthetic_directory),
        "synthetic unsafe private-directory owner",
    )
def boot_and_alias_boundaries() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-lock-no-run-") as temporary:
        root = pathlib.Path(temporary)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "absent /run",
        )
        if (root / "run").exists() or (root / "run").is_symlink():
            raise RuntimeError("Helper created an absent system runtime directory.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-no-system-lock-") as temporary:
        root = pathlib.Path(temporary)
        run = root / "run"
        run.mkdir(mode=0o755)
        run.chmod(0o755)
        expect_boundary_error(
            lambda: HELPER.acquire_lock_set(("primary",), root=root),
            "absent /run/lock",
        )
        if (run / "lock").exists() or (run / "lock").is_symlink():
            raise RuntimeError("Helper created an absent system lock directory.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-clean-boot-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        result = subprocess_result("--run-once", str(root), "primary")
        if result.returncode != 0:
            raise RuntimeError(
                f"Clean-boot helper run failed: stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        boundary = root / "run/lock" / HELPER.LOCK_DIRECTORY
        entry = boundary / HELPER.LOCK_FILES["primary"]
        if mode(boundary) != 0o700 or boundary.stat().st_uid != 0 or boundary.stat().st_gid != 0:
            raise RuntimeError("Clean boot private lock directory metadata differs.")
        metadata = entry.stat()
        if (
            mode(entry) != 0o600
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("Clean boot lock-file metadata differs.")
        HELPER.verify_nodes(("primary",), root=root)

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-verify-no-create-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root, private=True)
        missing = locks / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["primary"]
        expect_boundary_error(
            lambda: HELPER.verify_nodes(("primary",), root=root),
            "verify-nodes missing lock",
        )
        if missing.exists() or missing.is_symlink():
            raise RuntimeError("verify-nodes created a missing lock file.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-var-alias-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        var = root / "var"
        var.mkdir()
        (var / "lock").symlink_to("../run/lock", target_is_directory=True)
        descriptors = HELPER.acquire_lock_set(("primary",), root=root)
        close_requested(("primary",))
        if descriptors != (HELPER.LOCK_FDS["primary"],):
            raise RuntimeError("Canonical lock descriptor differs under /var/lock alias.")
        canonical = root / "run/lock" / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["primary"]
        alias = root / "var/lock" / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["primary"]
        if canonical.stat().st_ino != alias.stat().st_ino:
            raise RuntimeError("Ubuntu /var/lock alias produced a second lock namespace.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-var-hostile-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        var = root / "var"
        var.mkdir()
        victim = root / "alias-victim"
        victim.mkdir()
        (var / "lock").symlink_to(victim, target_is_directory=True)
        HELPER.acquire_lock_set(("primary",), root=root)
        close_requested(("primary",))
        if any(victim.iterdir()):
            raise RuntimeError("Helper traversed the noncanonical /var/lock alias.")


def reboot_namespace_boundary() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-lock-reboot-namespace-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        result = subprocess_result("--run-once", str(root), "primary")
        if result.returncode != 0:
            raise RuntimeError(
                f"Clean-reboot primary acquisition failed: stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        boundary = root / "run/lock" / HELPER.LOCK_DIRECTORY
        media = boundary / HELPER.LOCK_FILES["media"]
        if media.exists() or media.is_symlink():
            raise RuntimeError("Primary-only clean reboot unexpectedly created the media lock.")
        HELPER.verify_namespace(("primary", "media"), root=root)
        if media.exists() or media.is_symlink():
            raise RuntimeError("Namespace verification created the absent media lock.")
        expect_boundary_error(
            lambda: HELPER.verify_nodes(("primary", "media"), root=root),
            "exact-existing verification with absent media lock",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-namespace-absent-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        expect_boundary_error(
            lambda: HELPER.verify_namespace(("primary", "media"), root=root),
            "namespace verification with absent private directory",
        )
        assert_no_lock_artifacts(root)

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-namespace-symlink-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        HELPER.acquire_lock_set(("primary",), root=root)
        close_requested(("primary",))
        boundary = root / "run/lock" / HELPER.LOCK_DIRECTORY
        victim = root / "media-victim"
        original = b"media lock victim bytes\n"
        victim.write_bytes(original)
        victim.chmod(0o600)
        (boundary / HELPER.LOCK_FILES["media"]).symlink_to(victim)
        expect_boundary_error(
            lambda: HELPER.verify_namespace(("primary", "media"), root=root),
            "linked existing media lock",
        )
        if victim.read_bytes() != original:
            raise RuntimeError("Namespace verification changed linked media victim bytes.")

    constructors = {
        "directory": lambda path: path.mkdir(mode=0o600),
        "fifo": lambda path: os.mkfifo(path, 0o600),
        "socket": _create_socket_entry,
    }
    for label, constructor in constructors.items():
        with tempfile.TemporaryDirectory(prefix=f"mochirii-lock-namespace-{label}-") as temporary:
            root = pathlib.Path(temporary)
            boot_root(root)
            HELPER.acquire_lock_set(("primary",), root=root)
            close_requested(("primary",))
            media = root / "run/lock" / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["media"]
            handle = constructor(media)
            try:
                expect_boundary_error(
                    lambda: HELPER.verify_namespace(("primary", "media"), root=root),
                    f"nonregular existing media {label}",
                )
            finally:
                if handle is not None:
                    handle.close()

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-namespace-mode-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        HELPER.acquire_lock_set(("primary",), root=root)
        close_requested(("primary",))
        media = root / "run/lock" / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["media"]
        media.write_bytes(b"")
        media.chmod(0o644)
        expect_boundary_error(
            lambda: HELPER.verify_namespace(("primary", "media"), root=root),
            "unsafe existing media mode",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-namespace-owner-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        HELPER.acquire_lock_set(("primary",), root=root)
        close_requested(("primary",))
        media = root / "run/lock" / HELPER.LOCK_DIRECTORY / HELPER.LOCK_FILES["media"]
        media.write_bytes(b"")
        media.chmod(0o600)
        try:
            os.chown(media, 65534, 65534)
        except PermissionError:
            pass
        else:
            expect_boundary_error(
                lambda: HELPER.verify_namespace(("primary", "media"), root=root),
                "unsafe existing media owner",
            )


def try_acquire(root: pathlib.Path, lock_set: str) -> subprocess.CompletedProcess[str]:
    return subprocess_result("--try-acquire", str(root), lock_set)


def order_and_contention_boundaries() -> None:
    expect_boundary_error(
        lambda: HELPER.parse_lock_set("media,primary"),
        "reverse primary/media acquisition",
    )
    if HELPER.parse_lock_set("primary,media") != ("primary", "media"):
        raise RuntimeError("Canonical primary/media ordering differs.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-contention-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        descriptors = HELPER.acquire_lock_set(("primary", "media"), root=root)
        if descriptors != (HELPER.LOCK_FDS["primary"], HELPER.LOCK_FDS["media"]):
            raise RuntimeError("Fixed primary/media descriptors differ.")
        try:
            HELPER.verify_nodes(("primary", "media"), root=root)
            result = try_acquire(root, "primary")
            if result.returncode != 4:
                raise RuntimeError(
                    f"Contending primary acquisition was not blocked: {result.returncode}, {result.stderr!r}"
                )
            result = try_acquire(root, "media")
            if result.returncode != 4:
                raise RuntimeError(
                    f"Contending media acquisition was not blocked: {result.returncode}, {result.stderr!r}"
                )
        finally:
            close_requested(("primary", "media"))
        if try_acquire(root, "primary,media").returncode != 0:
            raise RuntimeError("Primary/media retry failed after exact lock release.")


def reserved_descriptor_collision_boundary() -> None:
    for descriptor in HELPER.LOCK_FDS.values():
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        raise RuntimeError("Fixture inherited an unexpected reserved lock descriptor.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-fd-primary-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        marker = root / "caller-primary-fd"
        source = os.open(marker, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.dup2(source, HELPER.LOCK_FDS["primary"], inheritable=False)
            before = os.fstat(HELPER.LOCK_FDS["primary"])
            expect_boundary_error(
                lambda: HELPER.acquire_lock_set(("primary",), root=root),
                "occupied primary descriptor",
            )
            after = os.fstat(HELPER.LOCK_FDS["primary"])
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("Primary FD collision clobbered its caller-owned descriptor.")
        finally:
            os.close(HELPER.LOCK_FDS["primary"])
            os.close(source)

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-fd-media-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        marker = root / "caller-media-fd"
        source = os.open(marker, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.dup2(source, HELPER.LOCK_FDS["media"], inheritable=False)
            before = os.fstat(HELPER.LOCK_FDS["media"])
            expect_boundary_error(
                lambda: HELPER.acquire_lock_set(("primary", "media"), root=root),
                "occupied media descriptor",
            )
            after = os.fstat(HELPER.LOCK_FDS["media"])
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("Media FD collision clobbered its caller-owned descriptor.")
            try:
                os.fstat(HELPER.LOCK_FDS["primary"])
            except OSError:
                pass
            else:
                raise RuntimeError("Failed dual acquisition retained the newly acquired primary FD.")
        finally:
            os.close(HELPER.LOCK_FDS["media"])
            os.close(source)


def assert_held_tamper_boundaries() -> None:
    missing_environment = clean_environment()
    result = subprocess.run(
        [sys.executable, "-B", str(HELPER_PATH), "assert-held", "--locks", "primary"],
        check=False,
        capture_output=True,
        text=True,
        env=missing_environment,
        timeout=10,
    )
    if result.returncode != 3:
        raise RuntimeError("Absent inherited context did not return exit 3.")

    malformed_environment = clean_environment()
    malformed_environment[HELPER.CONTEXT_ENV] = "v1;primary=201"
    result = subprocess.run(
        [sys.executable, "-B", str(HELPER_PATH), "assert-held", "--locks", "primary"],
        check=False,
        capture_output=True,
        text=True,
        env=malformed_environment,
        timeout=10,
    )
    if result.returncode != 1:
        raise RuntimeError("Malformed inherited context did not return exit 1.")

    result = subprocess.run(
        [sys.executable, "-B", str(HELPER_PATH), "verify-nodes", "--locks", "primary", "--root", "/tmp"],
        check=False,
        capture_output=True,
        text=True,
        env=clean_environment(),
        timeout=10,
    )
    if result.returncode != 1:
        raise RuntimeError("Production CLI accepted an alternate lock root.")

    with tempfile.TemporaryDirectory(prefix="mochirii-lock-assert-tamper-") as temporary:
        root = pathlib.Path(temporary)
        locks = boot_root(root)
        HELPER.acquire_lock_set(("primary",), root=root)
        os.set_inheritable(HELPER.LOCK_FDS["primary"], True)
        previous = os.environ.get(HELPER.CONTEXT_ENV)
        os.environ[HELPER.CONTEXT_ENV] = HELPER._context_value(("primary",))
        try:
            HELPER.assert_held(("primary",), root=root)
            boundary = locks / HELPER.LOCK_DIRECTORY
            lock = boundary / HELPER.LOCK_FILES["primary"]
            retired = boundary / "retired.lock"
            lock.rename(retired)
            lock.write_bytes(b"")
            lock.chmod(0o600)
            expect_boundary_error(
                lambda: HELPER.assert_held(("primary",), root=root),
                "inherited/path inode mismatch",
            )
        finally:
            close_requested(("primary",))
            if previous is None:
                os.environ.pop(HELPER.CONTEXT_ENV, None)
            else:
                os.environ[HELPER.CONTEXT_ENV] = previous


def sigkill_inheritance_boundary() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-lock-inheritance-") as temporary:
        root = pathlib.Path(temporary)
        boot_root(root)
        ready = root / "descendant-ready.json"
        closed = root / "descendant-closed"
        process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(TEST_PATH),
                "--run-holder",
                str(root),
                str(ready),
                str(closed),
            ],
            env=clean_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        descendant = 0
        try:
            wait_for(ready, "detached lock inheritor")
            document = json.loads(ready.read_text(encoding="utf-8"))
            descendant = document.get("pid", 0)
            if not isinstance(descendant, int) or descendant <= 1:
                raise RuntimeError("Detached lock inheritor PID is malformed.")
            process.kill()
            process.wait(timeout=5)
            if try_acquire(root, "primary").returncode != 4:
                raise RuntimeError("Parent SIGKILL released a descendant-owned lock.")
            os.kill(descendant, signal.SIGUSR1)
            wait_for(closed, "explicit inherited descriptor close")
            if try_acquire(root, "primary").returncode != 0:
                raise RuntimeError("Retry remained blocked after the last inherited FD closed.")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if descendant > 1:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                assert_pid_absent(descendant)


def run_linux() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Host-operation lock fixture requires isolated Linux root.")
    malicious_directory_boundaries()
    malicious_file_boundaries()
    metadata_boundaries()
    boot_and_alias_boundaries()
    reboot_namespace_boundary()
    order_and_contention_boundaries()
    reserved_descriptor_collision_boundary()
    assert_held_tamper_boundaries()
    sigkill_inheritance_boundary()
    if any((ROOT / "scripts").glob("__pycache__/host-operation-lock*.pyc")):
        raise RuntimeError("Host-operation lock fixture created bytecode cache files.")
    print("Host-operation lock hostile fixture passed.")


def run_in_container() -> None:
    command = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "-v",
        f"{ROOT}:/repo:ro",
        "--entrypoint",
        "python3",
        BASE_IMAGE,
        "-B",
        "/repo/scripts/test-host-operation-lock.py",
        "--inside-linux",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            f"Pinned host-operation lock fixture failed: stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    print(result.stdout.strip())


def child_try_acquire(root: pathlib.Path, lock_set: str) -> int:
    requested = HELPER.parse_lock_set(lock_set)
    try:
        HELPER.acquire_lock_set(requested, root=root)
    except HELPER.LockContention:
        return 4
    except HELPER.LockBoundaryError as error:
        print(str(error), file=sys.stderr)
        return 5
    close_requested(requested)
    return 0


def child_assert_and_exit(root: pathlib.Path, lock_set: str) -> int:
    requested = HELPER.parse_lock_set(lock_set)
    HELPER.assert_held(requested, root=root)
    return 0


def child_run_once(root: pathlib.Path, lock_set: str) -> None:
    requested = HELPER.parse_lock_set(lock_set)
    HELPER.run_locked(
        requested,
        (
            sys.executable,
            "-B",
            str(TEST_PATH),
            "--assert-and-exit",
            str(root),
            lock_set,
        ),
        root=root,
        environment=clean_environment(),
    )


def child_run_holder(root: pathlib.Path, ready: pathlib.Path, closed: pathlib.Path) -> None:
    HELPER.run_locked(
        ("primary",),
        (
            sys.executable,
            "-B",
            str(TEST_PATH),
            "--holder",
            str(root),
            str(ready),
            str(closed),
        ),
        root=root,
        environment=clean_environment(),
    )


def child_holder(root: pathlib.Path, ready: pathlib.Path, closed: pathlib.Path) -> None:
    HELPER.assert_held(("primary",), root=root)
    descendant = os.fork()
    if descendant:
        while True:
            signal.pause()

    def release(_signum: int, _frame: object) -> None:
        HELPER.close_lock_fds(("primary",))
        descriptor = os.open(closed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)

    signal.signal(signal.SIGUSR1, release)
    descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump({"pid": os.getpid()}, output)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    while True:
        signal.pause()


def main() -> int:
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--try-acquire":
        return child_try_acquire(pathlib.Path(arguments[1]), arguments[2])
    if arguments and arguments[0] == "--assert-and-exit":
        return child_assert_and_exit(pathlib.Path(arguments[1]), arguments[2])
    if arguments and arguments[0] == "--run-once":
        child_run_once(pathlib.Path(arguments[1]), arguments[2])
        raise RuntimeError("Locked clean-boot runner unexpectedly returned.")
    if arguments and arguments[0] == "--run-holder":
        child_run_holder(pathlib.Path(arguments[1]), pathlib.Path(arguments[2]), pathlib.Path(arguments[3]))
        raise RuntimeError("Locked inheritance runner unexpectedly returned.")
    if arguments and arguments[0] == "--holder":
        child_holder(pathlib.Path(arguments[1]), pathlib.Path(arguments[2]), pathlib.Path(arguments[3]))
        raise RuntimeError("Inheritance holder unexpectedly returned.")
    if os.name == "nt" and "--inside-linux" not in arguments:
        run_in_container()
    else:
        run_linux()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
