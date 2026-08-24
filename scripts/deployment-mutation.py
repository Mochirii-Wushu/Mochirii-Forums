#!/usr/bin/env python3
"""Durable authority for a deployment's pre-terminal runtime mutations."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any


MAX_BYTES = 65_536
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
LAUNCHER_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z")
PHASES = {
    "prepared",
    "config-armed",
    "launcher-armed",
    "runtime-active",
    "runtime-contained",
    "verified",
}
COMMANDS = {"bootstrap", "start", "restart", "rebuild", "destroy"}
KEYS = {
    "schemaVersion",
    "phase",
    "recordedAt",
    "updatedAt",
    "deploymentMode",
    "repositoryCommit",
    "productionConfigurationSha256",
    "releaseArchiveSha256",
    "requestedDiscourseConnect",
    "targetAppConfigurationFile",
    "targetAppConfigurationSha256",
    "targetRestoreConfigurationFile",
    "targetRestoreConfigurationSha256",
    "targetActivationConfigurationFile",
    "targetActivationConfigurationSha256",
    "previousRepositoryCommit",
    "previousProductionConfigurationSha256",
    "previousCurrentReleaseSha256",
    "previousAppConfigurationFile",
    "previousAppConfigurationSha256",
    "previousCurrentTarget",
    "activeConfigurationFile",
    "activeConfigurationSha256",
    "launcherOperationToken",
    "launcherPreviousImageId",
    "launcherCommand",
    "databaseMutationPossible",
    "applicationStopped",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def protected_file(path: pathlib.Path, label: str) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > MAX_BYTES
    ):
        fail(f"{label} is unsafe")
    return path.read_bytes()


def configuration_file(path_value: str, expected_sha: str, label: str) -> pathlib.Path:
    path = pathlib.Path(path_value)
    if not path.is_absolute() or not HEX64.fullmatch(expected_sha):
        fail(f"{label} identity is malformed")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size <= 0
        or metadata.st_size > 1_048_576
        or digest(path) != expected_sha
    ):
        fail(f"{label} bytes differ")
    return path


def optional(value: str) -> str | None:
    return None if value == "-" else value


def validate(document: Any, path: pathlib.Path) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != KEYS:
        fail("deployment mutation journal schema differs")
    if document.get("schemaVersion") != 1 or document.get("phase") not in PHASES:
        fail("deployment mutation journal phase differs")
    if document.get("deploymentMode") not in {"bootstrap", "rebuild"}:
        fail("deployment mutation mode differs")
    if not HEX40.fullmatch(str(document.get("repositoryCommit", ""))):
        fail("deployment mutation commit is malformed")
    for key in (
        "productionConfigurationSha256",
        "releaseArchiveSha256",
        "targetAppConfigurationSha256",
        "targetRestoreConfigurationSha256",
    ):
        if not HEX64.fullmatch(str(document.get(key, ""))):
            fail(f"deployment mutation digest is malformed: {key}")
    if not isinstance(document.get("requestedDiscourseConnect"), bool):
        fail("deployment mutation consumer state differs")
    for key in ("recordedAt", "updatedAt"):
        if not TIMESTAMP.fullmatch(str(document.get(key, ""))):
            fail(f"deployment mutation timestamp is malformed: {key}")

    app_path = configuration_file(
        str(document["targetAppConfigurationFile"]),
        str(document["targetAppConfigurationSha256"]),
        "target production configuration",
    )
    restore_path = configuration_file(
        str(document["targetRestoreConfigurationFile"]),
        str(document["targetRestoreConfigurationSha256"]),
        "target restore configuration",
    )
    if app_path.parent != restore_path.parent or app_path.name != "app.yml" or restore_path.name != "restore.yml":
        fail("deployment mutation target configuration layout differs")
    expected_parent = pathlib.Path("/var/discourse/containers/releases") / document["repositoryCommit"] / document["productionConfigurationSha256"]
    if path.as_posix().startswith("/var/lib/mochirii/forums/") and app_path != expected_parent / "app.yml":
        fail("deployment mutation target configuration escaped its exact host path")

    activation_path = document.get("targetActivationConfigurationFile")
    activation_sha = document.get("targetActivationConfigurationSha256")
    if (activation_path is None) != (activation_sha is None):
        fail("deployment mutation activation configuration is incomplete")
    if document["requestedDiscourseConnect"]:
        if activation_path is None:
            fail("deployment mutation consumer activation configuration is absent")
        activation = configuration_file(str(activation_path), str(activation_sha), "target activation configuration")
        if activation.parent != app_path.parent or activation.name != "activation.yml":
            fail("deployment mutation activation configuration layout differs")
    elif activation_path is not None:
        fail("deployment mutation disabled consumer has an activation configuration")

    previous_values = [
        document.get("previousRepositoryCommit"),
        document.get("previousProductionConfigurationSha256"),
        document.get("previousCurrentReleaseSha256"),
        document.get("previousAppConfigurationFile"),
        document.get("previousAppConfigurationSha256"),
        document.get("previousCurrentTarget"),
    ]
    if document["deploymentMode"] == "bootstrap":
        if any(value is not None for value in previous_values):
            fail("bootstrap deployment mutation unexpectedly names a prior release")
    else:
        if any(value is None for value in previous_values):
            fail("rebuild deployment mutation prior release binding is incomplete")
        if not HEX40.fullmatch(str(previous_values[0])) or any(
            not HEX64.fullmatch(str(value)) for value in (previous_values[1], previous_values[2], previous_values[4])
        ):
            fail("deployment mutation prior release identity is malformed")
        previous_config = configuration_file(str(previous_values[3]), str(previous_values[4]), "prior production configuration")
        expected_previous = pathlib.Path("/var/discourse/containers/releases") / str(previous_values[0]) / str(previous_values[1]) / "app.yml"
        expected_target = pathlib.Path("/opt/mochirii/forums/releases") / str(previous_values[0])
        if path.as_posix().startswith("/var/lib/mochirii/forums/") and (
            previous_config != expected_previous or pathlib.Path(str(previous_values[5])) != expected_target
        ):
            fail("deployment mutation prior release path differs")

    active_path = document.get("activeConfigurationFile")
    active_sha = document.get("activeConfigurationSha256")
    if (active_path is None) != (active_sha is None):
        fail("deployment mutation active configuration is incomplete")
    allowed = {
        str(document["targetAppConfigurationFile"]): document["targetAppConfigurationSha256"],
        str(document["targetRestoreConfigurationFile"]): document["targetRestoreConfigurationSha256"],
    }
    if document["previousAppConfigurationFile"] is not None:
        allowed[str(document["previousAppConfigurationFile"])] = document["previousAppConfigurationSha256"]
    if activation_path is not None:
        allowed[str(activation_path)] = activation_sha
    if active_path is not None:
        if allowed.get(str(active_path)) != active_sha:
            fail("deployment mutation active configuration is not an exact target configuration")
        configuration_file(str(active_path), str(active_sha), "active target configuration")

    token = document.get("launcherOperationToken")
    image = document.get("launcherPreviousImageId")
    command = document.get("launcherCommand")
    if token is None:
        if image is not None or command is not None:
            fail("deployment mutation launcher binding is incomplete")
        if document["phase"] == "launcher-armed":
            fail("deployment mutation armed launcher identity is absent")
    else:
        if (
            not LAUNCHER_ID_PATTERN.fullmatch(str(token))
            or (image != "-" and not IMAGE.fullmatch(str(image)))
            or command not in COMMANDS
            or document["phase"] != "launcher-armed"
            or active_path is None
        ):
            fail("deployment mutation launcher binding differs")
    if not isinstance(document.get("databaseMutationPossible"), bool) or not isinstance(document.get("applicationStopped"), bool):
        fail("deployment mutation containment booleans differ")
    if document["phase"] == "verified" and (active_path != str(app_path) or document["applicationStopped"]):
        fail("verified deployment mutation runtime state differs")
    return document


def read(path: pathlib.Path) -> dict[str, Any]:
    return validate(json.loads(protected_file(path, "deployment mutation journal")), path)


def reconcile_orphan(path: pathlib.Path) -> None:
    partial = path.parent / f".{path.name}.partial"
    update = path.parent / f".{path.name}.update"
    for candidate, initial in ((partial, True), (update, False)):
        if not candidate.exists() and not candidate.is_symlink():
            continue
        candidate_bytes = protected_file(candidate, "deployment mutation journal partial")
        if initial and (path.exists() or path.is_symlink()):
            final_bytes = protected_file(path, "deployment mutation journal")
            if candidate.stat().st_ino != path.stat().st_ino or candidate_bytes != final_bytes:
                fail("deployment mutation journal linked partial differs")
        candidate.unlink()
        fsync_directory(path.parent)


def atomic_write(path: pathlib.Path, document: dict[str, Any], *, create: bool) -> None:
    validate(document, path)
    candidate = path.parent / f".{path.name}.{'partial' if create else 'update'}"
    if candidate.exists() or candidate.is_symlink():
        fail("deployment mutation journal candidate was not reconciled")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(candidate, flags, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write((json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        target.flush()
        os.fsync(target.fileno())
    os.chmod(candidate, 0o600)
    if create:
        os.link(candidate, path, follow_symlinks=False)
        fsync_directory(path.parent)
        candidate.unlink()
        fsync_directory(path.parent)
    else:
        os.replace(candidate, path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(path.parent)


def stable_from_args(args: argparse.Namespace) -> dict[str, Any]:
    activation_file = optional(args.target_activation_config)
    activation_sha = optional(args.target_activation_sha)
    previous_commit = optional(args.previous_commit)
    previous_configuration = optional(args.previous_configuration)
    previous_current_sha = optional(args.previous_current_sha)
    previous_app_config = optional(args.previous_app_config)
    previous_app_sha = optional(args.previous_app_sha)
    previous_current_target = optional(args.previous_current_target)
    stamp = now()
    return {
        "schemaVersion": 1,
        "phase": "prepared",
        "recordedAt": stamp,
        "updatedAt": stamp,
        "deploymentMode": args.mode,
        "repositoryCommit": args.commit,
        "productionConfigurationSha256": args.configuration,
        "releaseArchiveSha256": args.archive_sha,
        "requestedDiscourseConnect": args.requested_connect == "true",
        "targetAppConfigurationFile": args.target_app_config,
        "targetAppConfigurationSha256": args.configuration,
        "targetRestoreConfigurationFile": args.target_restore_config,
        "targetRestoreConfigurationSha256": args.target_restore_sha,
        "targetActivationConfigurationFile": activation_file,
        "targetActivationConfigurationSha256": activation_sha,
        "previousRepositoryCommit": previous_commit,
        "previousProductionConfigurationSha256": previous_configuration,
        "previousCurrentReleaseSha256": previous_current_sha,
        "previousAppConfigurationFile": previous_app_config,
        "previousAppConfigurationSha256": previous_app_sha,
        "previousCurrentTarget": previous_current_target,
        "activeConfigurationFile": None,
        "activeConfigurationSha256": None,
        "launcherOperationToken": None,
        "launcherPreviousImageId": None,
        "launcherCommand": None,
        "databaseMutationPossible": False,
        "applicationStopped": False,
    }


def stable_identity(document: dict[str, Any]) -> dict[str, Any]:
    mutable = {
        "phase",
        "recordedAt",
        "updatedAt",
        "activeConfigurationFile",
        "activeConfigurationSha256",
        "launcherOperationToken",
        "launcherPreviousImageId",
        "launcherCommand",
        "databaseMutationPossible",
        "applicationStopped",
    }
    return {key: value for key, value in document.items() if key not in mutable}


def validate_host_creation_boundary(args: argparse.Namespace, path: pathlib.Path) -> None:
    if path != pathlib.Path("/var/lib/mochirii/forums/deployment-mutation.json"):
        return
    current_release = path.parent / "current-release.json"
    current_target = pathlib.Path("/opt/mochirii/forums/current")
    if args.mode == "bootstrap":
        if current_release.exists() or current_release.is_symlink() or current_target.exists() or current_target.is_symlink():
            fail("bootstrap deployment mutation requires complete prior-publication absence")
        return
    current_bytes = protected_file(current_release, "deployment mutation prior current-release evidence")
    if hashlib.sha256(current_bytes).hexdigest() != args.previous_current_sha:
        fail("deployment mutation prior current-release bytes differ")
    metadata = current_target.lstat()
    if (
        not stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or current_target.resolve(strict=True) != pathlib.Path(args.previous_current_target)
    ):
        fail("deployment mutation prior current-release target differs")


def command_create(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)
    validate_host_creation_boundary(args, path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reconcile_orphan(path)
    document = stable_from_args(args)
    validate(document, path)
    if path.exists() or path.is_symlink():
        existing = read(path)
        if stable_identity(existing) != stable_identity(document):
            fail("active deployment mutation belongs to another exact operation")
        return
    atomic_write(path, document, create=True)


def mutate(path: pathlib.Path, transform: Any) -> dict[str, Any]:
    reconcile_orphan(path)
    document = read(path)
    updated = transform(dict(document))
    updated["updatedAt"] = now()
    if document["databaseMutationPossible"] and not updated["databaseMutationPossible"]:
        fail("deployment mutation database boundary cannot move backward")
    atomic_write(path, updated, create=False)
    return updated


def command_inspect(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)
    reconcile_orphan(path)
    document = read(path)
    for key, expected in (
        ("deploymentMode", args.mode),
        ("repositoryCommit", args.commit),
        ("productionConfigurationSha256", args.configuration),
        ("releaseArchiveSha256", args.archive_sha),
        ("requestedDiscourseConnect", args.requested_connect == "true"),
    ):
        if document[key] != expected:
            fail(f"deployment mutation exact operation differs: {key}")
    fields = (
        "phase",
        "previousRepositoryCommit",
        "previousProductionConfigurationSha256",
        "previousCurrentReleaseSha256",
        "previousAppConfigurationFile",
        "previousAppConfigurationSha256",
        "previousCurrentTarget",
        "activeConfigurationFile",
        "activeConfigurationSha256",
        "launcherOperationToken",
        "launcherPreviousImageId",
        "launcherCommand",
        "databaseMutationPossible",
        "applicationStopped",
    )
    for field in fields:
        value = document[field]
        if value is None:
            print("-")
        elif isinstance(value, bool):
            print("true" if value else "false")
        else:
            print(value)


def command_set_config(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)

    def transform(document: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            document["targetAppConfigurationFile"]: document["targetAppConfigurationSha256"],
            document["targetRestoreConfigurationFile"]: document["targetRestoreConfigurationSha256"],
        }
        if document["previousAppConfigurationFile"] is not None:
            allowed[document["previousAppConfigurationFile"]] = document["previousAppConfigurationSha256"]
        if document["targetActivationConfigurationFile"] is not None:
            allowed[document["targetActivationConfigurationFile"]] = document["targetActivationConfigurationSha256"]
        if args.configuration_file not in allowed:
            fail("deployment mutation refused an unbound configuration")
        if document["launcherOperationToken"] is not None:
            fail("deployment mutation cannot switch configuration while a launcher is armed")
        document["phase"] = "config-armed"
        document["activeConfigurationFile"] = args.configuration_file
        document["activeConfigurationSha256"] = allowed[args.configuration_file]
        document["applicationStopped"] = False
        return document

    mutate(path, transform)


def command_arm_launcher(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)

    def transform(document: dict[str, Any]) -> dict[str, Any]:
        if document["activeConfigurationFile"] != args.configuration_file:
            fail("deployment mutation launcher configuration differs")
        if document["launcherOperationToken"] is not None or args.command not in COMMANDS:
            fail("deployment mutation launcher is already armed or malformed")
        if not LAUNCHER_ID_PATTERN.fullmatch(args.token) or (args.previous_image != "-" and not IMAGE.fullmatch(args.previous_image)):
            fail("deployment mutation launcher identity is malformed")
        document["phase"] = "launcher-armed"
        document["launcherOperationToken"] = args.token
        document["launcherPreviousImageId"] = args.previous_image
        document["launcherCommand"] = args.command
        if args.command in {"bootstrap", "rebuild"}:
            document["databaseMutationPossible"] = True
        document["applicationStopped"] = False
        return document

    mutate(path, transform)


def command_finish_launcher(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)

    def transform(document: dict[str, Any]) -> dict[str, Any]:
        if document["launcherOperationToken"] != args.token or document["phase"] != "launcher-armed":
            fail("deployment mutation launcher completion differs")
        document["phase"] = "runtime-active" if args.outcome == "success" else "runtime-contained"
        document["launcherOperationToken"] = None
        document["launcherPreviousImageId"] = None
        document["launcherCommand"] = None
        document["applicationStopped"] = args.outcome == "failure"
        return document

    mutate(path, transform)


def command_contained(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)

    def transform(document: dict[str, Any]) -> dict[str, Any]:
        if document["launcherOperationToken"] is not None:
            fail("deployment mutation cannot mark containment before launcher reconciliation")
        document["phase"] = "runtime-contained"
        document["applicationStopped"] = True
        return document

    mutate(path, transform)


def command_verified(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)

    def transform(document: dict[str, Any]) -> dict[str, Any]:
        if document["launcherOperationToken"] is not None:
            fail("deployment mutation cannot verify with an armed launcher")
        if document["activeConfigurationFile"] != document["targetAppConfigurationFile"]:
            fail("deployment mutation verified configuration differs")
        document["phase"] = "verified"
        document["applicationStopped"] = False
        return document

    mutate(path, transform)


def command_clear(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.path)
    reconcile_orphan(path)
    document = read(path)
    if document["phase"] != "verified":
        fail("deployment mutation journal is not terminal")
    for key, expected in (
        ("repositoryCommit", args.commit),
        ("productionConfigurationSha256", args.configuration),
        ("releaseArchiveSha256", args.archive_sha),
    ):
        if document[key] != expected:
            fail(f"deployment mutation clear identity differs: {key}")
    path.unlink()
    fsync_directory(path.parent)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create")
    create.add_argument("--path", required=True)
    create.add_argument("--mode", choices=("bootstrap", "rebuild"), required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--configuration", required=True)
    create.add_argument("--archive-sha", required=True)
    create.add_argument("--requested-connect", choices=("true", "false"), required=True)
    create.add_argument("--target-app-config", required=True)
    create.add_argument("--target-restore-config", required=True)
    create.add_argument("--target-restore-sha", required=True)
    create.add_argument("--target-activation-config", required=True)
    create.add_argument("--target-activation-sha", required=True)
    create.add_argument("--previous-commit", required=True)
    create.add_argument("--previous-configuration", required=True)
    create.add_argument("--previous-current-sha", required=True)
    create.add_argument("--previous-app-config", required=True)
    create.add_argument("--previous-app-sha", required=True)
    create.add_argument("--previous-current-target", required=True)
    create.set_defaults(function=command_create)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--path", required=True)
    inspect.add_argument("--mode", choices=("bootstrap", "rebuild"), required=True)
    inspect.add_argument("--commit", required=True)
    inspect.add_argument("--configuration", required=True)
    inspect.add_argument("--archive-sha", required=True)
    inspect.add_argument("--requested-connect", choices=("true", "false"), required=True)
    inspect.set_defaults(function=command_inspect)

    set_config = sub.add_parser("set-config")
    set_config.add_argument("--path", required=True)
    set_config.add_argument("--configuration-file", required=True)
    set_config.set_defaults(function=command_set_config)

    arm = sub.add_parser("arm-launcher")
    arm.add_argument("--path", required=True)
    arm.add_argument("--configuration-file", required=True)
    arm.add_argument("--token", required=True)
    arm.add_argument("--previous-image", required=True)
    arm.add_argument("--command", required=True)
    arm.set_defaults(function=command_arm_launcher)

    finish = sub.add_parser("finish-launcher")
    finish.add_argument("--path", required=True)
    finish.add_argument("--token", required=True)
    finish.add_argument("--outcome", choices=("success", "failure"), required=True)
    finish.set_defaults(function=command_finish_launcher)

    contained = sub.add_parser("mark-contained")
    contained.add_argument("--path", required=True)
    contained.set_defaults(function=command_contained)

    verified = sub.add_parser("mark-verified")
    verified.add_argument("--path", required=True)
    verified.set_defaults(function=command_verified)

    clear = sub.add_parser("clear")
    clear.add_argument("--path", required=True)
    clear.add_argument("--commit", required=True)
    clear.add_argument("--configuration", required=True)
    clear.add_argument("--archive-sha", required=True)
    clear.set_defaults(function=command_clear)
    return result


def main() -> None:
    args = parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
