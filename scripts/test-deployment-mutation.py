#!/usr/bin/env python3
"""Hostile lifecycle checks for the durable deployment mutation journal."""

from __future__ import annotations

import json
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "deployment-mutation.py"
COMMIT = "1" * 40
TARGET_BYTES = b"target-production\n"
RESTORE_BYTES = b"target-restore\n"
ACTIVATION_BYTES = b"target-activation\n"
PREVIOUS_BYTES = b"prior-production\n"
CONFIGURATION = hashlib.sha256(TARGET_BYTES).hexdigest()
ARCHIVE = "3" * 64
RESTORE_SHA = hashlib.sha256(RESTORE_BYTES).hexdigest()
ACTIVATION_SHA = hashlib.sha256(ACTIVATION_BYTES).hexdigest()
PREVIOUS_COMMIT = "6" * 40
PREVIOUS_CONFIGURATION = hashlib.sha256(PREVIOUS_BYTES).hexdigest()
PREVIOUS_CURRENT_SHA = "8" * 64


def run(*arguments: str, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, "-B", str(HELPER), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if success != (result.returncode == 0):
        raise AssertionError(
            f"deployment mutation helper expectation differed: {arguments!r}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def write_config(path: pathlib.Path, payload: bytes, expected: str) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)
    if hashlib.sha256(payload).hexdigest() != expected:
        raise AssertionError("fixture digest differs")


def create_arguments(root: pathlib.Path, journal: pathlib.Path) -> list[str]:
    target = root / "target"
    previous = root / "previous"
    target.mkdir()
    previous.mkdir()
    app = target / "app.yml"
    restore = target / "restore.yml"
    activation = target / "activation.yml"
    prior = previous / "app.yml"
    write_config(app, TARGET_BYTES, CONFIGURATION)
    write_config(restore, RESTORE_BYTES, RESTORE_SHA)
    write_config(activation, ACTIVATION_BYTES, ACTIVATION_SHA)
    write_config(prior, PREVIOUS_BYTES, PREVIOUS_CONFIGURATION)
    return [
        "create",
        "--path",
        str(journal),
        "--mode",
        "rebuild",
        "--commit",
        COMMIT,
        "--configuration",
        CONFIGURATION,
        "--archive-sha",
        ARCHIVE,
        "--requested-connect",
        "true",
        "--target-app-config",
        str(app),
        "--target-restore-config",
        str(restore),
        "--target-restore-sha",
        RESTORE_SHA,
        "--target-activation-config",
        str(activation),
        "--target-activation-sha",
        ACTIVATION_SHA,
        "--previous-commit",
        PREVIOUS_COMMIT,
        "--previous-configuration",
        PREVIOUS_CONFIGURATION,
        "--previous-current-sha",
        PREVIOUS_CURRENT_SHA,
        "--previous-app-config",
        str(prior),
        "--previous-app-sha",
        PREVIOUS_CONFIGURATION,
        "--previous-current-target",
        str(root / "prior-release"),
    ]


def inspect_arguments(journal: pathlib.Path) -> list[str]:
    return [
        "inspect",
        "--path",
        str(journal),
        "--mode",
        "rebuild",
        "--commit",
        COMMIT,
        "--configuration",
        CONFIGURATION,
        "--archive-sha",
        ARCHIVE,
        "--requested-connect",
        "true",
    ]


def main() -> None:
    source = HELPER.read_text(encoding="utf-8")
    for required in (
        'os.link(candidate, path, follow_symlinks=False)',
        "os.fsync(target.fileno())",
        "fsync_directory(path.parent)",
        'path.parent / f".{path.name}.partial"',
        'path.parent / f".{path.name}.update"',
        '"databaseMutationPossible"',
    ):
        if required not in source:
            raise AssertionError(f"deployment mutation durability primitive is absent: {required}")

    with tempfile.TemporaryDirectory(prefix="mochirii-deployment-mutation-") as temporary:
        root = pathlib.Path(temporary)
        root.chmod(0o700)
        journal = root / "deployment-mutation.json"
        create = create_arguments(root, journal)
        run(*create)
        document = json.loads(journal.read_text(encoding="utf-8"))
        if document["phase"] != "prepared" or document["databaseMutationPossible"] is not False:
            raise AssertionError("initial deployment mutation state differs")

        # Exact create is idempotent; a changed archive tuple is rejected.
        run(*create)
        changed = list(create)
        changed[changed.index(ARCHIVE)] = "9" * 64
        run(*changed, success=False)

        # A linked initial-publication partial is adopted and retired. An
        # unlinked update orphan is non-authoritative and also retired.
        partial = root / ".deployment-mutation.json.partial"
        os.link(journal, partial)
        run(*inspect_arguments(journal))
        if partial.exists():
            raise AssertionError("linked deployment mutation partial survived reconciliation")
        update = root / ".deployment-mutation.json.update"
        update.write_bytes(journal.read_bytes())
        update.chmod(0o600)
        run(*inspect_arguments(journal))
        if update.exists():
            raise AssertionError("unlinked deployment mutation update survived reconciliation")

        activation = root / "target" / "activation.yml"
        app = root / "target" / "app.yml"
        run("set-config", "--path", str(journal), "--configuration-file", str(activation))
        run(
            "arm-launcher",
            "--path",
            str(journal),
            "--configuration-file",
            str(activation),
            "--token",
            "a" * 32,
            "--previous-image",
            "-",
            "--command",
            "rebuild",
        )
        armed = json.loads(journal.read_text(encoding="utf-8"))
        if armed["phase"] != "launcher-armed" or armed["databaseMutationPossible"] is not True:
            raise AssertionError("launcher mutation was not durably armed before the migration boundary")
        run("finish-launcher", "--path", str(journal), "--token", "b" * 32, "--outcome", "failure", success=False)
        run("finish-launcher", "--path", str(journal), "--token", "a" * 32, "--outcome", "failure")
        contained = json.loads(journal.read_text(encoding="utf-8"))
        if contained["phase"] != "runtime-contained" or contained["applicationStopped"] is not True:
            raise AssertionError("launcher failure containment state differs")

        run("set-config", "--path", str(journal), "--configuration-file", str(app))
        run(
            "arm-launcher",
            "--path",
            str(journal),
            "--configuration-file",
            str(app),
            "--token",
            "c" * 32,
            "--previous-image",
            "sha256:" + "d" * 64,
            "--command",
            "start",
        )
        run("finish-launcher", "--path", str(journal), "--token", "c" * 32, "--outcome", "success")
        run("mark-verified", "--path", str(journal))
        verified = json.loads(journal.read_text(encoding="utf-8"))
        if verified["phase"] != "verified" or verified["databaseMutationPossible"] is not True:
            raise AssertionError("verified deployment mutation lost the irreversible boundary")
        run(
            "clear",
            "--path",
            str(journal),
            "--commit",
            COMMIT,
            "--configuration",
            CONFIGURATION,
            "--archive-sha",
            ARCHIVE,
        )
        if journal.exists():
            raise AssertionError("terminal deployment mutation journal survived exact clear")

        # An unsafe orphan must be retained and block a fresh operation.
        partial.write_text("{}\n", encoding="utf-8")
        partial.chmod(0o644)
        run(*create, success=False)
        if not partial.exists():
            raise AssertionError("unsafe deployment mutation orphan was silently removed")

    print("deployment mutation transaction tests passed")


if __name__ == "__main__":
    main()
