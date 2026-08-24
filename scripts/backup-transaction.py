#!/usr/bin/env python3
"""Durable host-side commit protocol for one verified application backup."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, NoReturn


MAX_STATE_BYTES = 4096
MAX_EVIDENCE_BYTES = 65536
TRANSACTION_KEYS = {
    "schemaVersion",
    "repositoryCommit",
    "productionConfigurationSha256",
    "backupOperationSha256",
    "timestamp",
    "evidenceFile",
    "previousLatestEvidenceFile",
    "previousLatestPointerSha256",
    "phase",
    "evidenceSha256",
    "latestPointerSha256",
    "runtimeRecoveryPhase",
    "runtimeRecoveryJournalFile",
    "runtimeRecoveryJournalSha256",
    "originalRuntimeState",
    "runtimeIdentitySha256",
    "currentReleaseSha256",
    "discourseRevision",
    "dockerManagerRevision",
    "runtimeEnvironmentSha256",
    "runtimePortBindingsSha256",
    "runtimeContainerImage",
    "runtimeOperationPhase",
    "runtimeOperationLabel",
    "runtimeOperationToken",
}
CURRENT_KEYS = {
    "schemaVersion",
    "repositoryCommit",
    "productionConfigurationSha256",
    "backupOperationSha256",
    "evidenceFile",
    "evidenceSha256",
    "latestPointerSha256",
    "phase",
    "originalRuntimeState",
    "runtimeIdentitySha256",
    "currentReleaseSha256",
    "discourseRevision",
    "dockerManagerRevision",
    "runtimeEnvironmentSha256",
    "runtimePortBindingsSha256",
    "runtimeContainerImage",
}
PHASES = {"prepared": 0, "pointer-committed": 1, "event-committed": 2}
RUNTIME_RECOVERY_PHASES = {
    "none",
    "cleanup-pending",
    "cleanup-proved",
}
RUNTIME_OPERATION_PHASES = {
    "initial-stopped",
    "initial-start-authorized",
    "idle",
    "temporary-stop-authorized",
    "operation-armed",
    "operation-absence-proved",
    "restart-authorized",
    "original-stop-authorized",
    "original-restored",
}
RUNTIME_OPERATION_LABEL = re.compile(r"[a-z][a-z0-9-]{0,31}")
BACKUP_UPLOAD_JOURNAL_KEYS = {
    "schemaVersion",
    "repositoryCommit",
    "productionConfigurationSha256",
    "backupOperationSha256",
    "transactionId",
    "pluginStoreKey",
    "phase",
}
RECOVERY_STATE_KEYS = {
    "schemaVersion",
    "repositoryCommit",
    "uploadId",
    "uploadSha1",
    "originalFilename",
    "objectPath",
    "tombstonePath",
    "contentSha256",
    "publicUrlSha256",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Backup transaction failed: {message}")


def digest(value: Any, size: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{size}}}", value) is not None


def canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def runtime_identity_digest(
    commit: str,
    configuration: str,
    current_release_sha: str,
    discourse_revision: str,
    docker_manager_revision: str,
    environment_sha: str,
    ports_sha: str,
    image: str,
) -> str:
    document = {
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "currentReleaseSha256": current_release_sha,
        "discourseRevision": discourse_revision,
        "dockerManagerRevision": docker_manager_revision,
        "runtimeEnvironmentSha256": environment_sha,
        "runtimePortBindingsSha256": ports_sha,
        "runtimeContainerImage": image,
    }
    return hashlib.sha256(canonical(document)).hexdigest()


def safe_directory(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("protected parent is not one directory")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        fail("protected parent permissions differ")


def protected_bytes(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("protected state is not one regular file")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("protected state ownership or mode differs")
    if not 0 < metadata.st_size <= maximum:
        fail("protected state exceeds its byte boundary")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        fail("protected state changed while it was read")
    return raw


def exact_evidence_name(commit: str, configuration: str, timestamp: str) -> str:
    if not digest(commit, 40) or not digest(configuration):
        fail("release tuple is malformed")
    if re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", timestamp) is None:
        fail("backup timestamp is malformed")
    return f"{commit}-{configuration}-{timestamp}-backup.json"


def prior_evidence_name(value: Any) -> bool:
    return value is None or (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{40}-[0-9a-f]{64}-[0-9]{8}T[0-9]{6}Z-backup[.]json", value) is not None
    )


def load_transaction(
    path: Path, commit: str, configuration: str, operation_sha: str
) -> dict[str, Any]:
    raw = protected_bytes(path, MAX_STATE_BYTES)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("transaction JSON is malformed")
    if not isinstance(document, dict) or set(document) != TRANSACTION_KEYS or raw != canonical(document):
        fail("transaction schema or canonical bytes differ")
    timestamp = document.get("timestamp", "")
    expected_name = exact_evidence_name(commit, configuration, timestamp)
    if (
        document.get("schemaVersion") != 2
        or document.get("repositoryCommit") != commit
        or document.get("productionConfigurationSha256") != configuration
        or document.get("backupOperationSha256") != operation_sha
        or document.get("evidenceFile") != expected_name
        or not prior_evidence_name(document.get("previousLatestEvidenceFile"))
        or (document.get("previousLatestEvidenceFile") is None)
        != (document.get("previousLatestPointerSha256") is None)
        or (
            document.get("previousLatestPointerSha256") is not None
            and not digest(document["previousLatestPointerSha256"])
        )
        or document.get("phase") not in PHASES
        or document.get("runtimeRecoveryPhase") not in RUNTIME_RECOVERY_PHASES
        or document.get("originalRuntimeState") not in {"running", "stopped"}
        or not digest(document.get("runtimeIdentitySha256"))
        or not digest(document.get("currentReleaseSha256"))
        or not digest(document.get("discourseRevision"), 40)
        or not digest(document.get("dockerManagerRevision"), 40)
        or not digest(document.get("runtimeEnvironmentSha256"))
        or not digest(document.get("runtimePortBindingsSha256"))
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(document.get("runtimeContainerImage", ""))
        )
        is None
        or document.get("runtimeIdentitySha256")
        != runtime_identity_digest(
            commit,
            configuration,
            document.get("currentReleaseSha256", ""),
            document.get("discourseRevision", ""),
            document.get("dockerManagerRevision", ""),
            document.get("runtimeEnvironmentSha256", ""),
            document.get("runtimePortBindingsSha256", ""),
            document.get("runtimeContainerImage", ""),
        )
        or document.get("runtimeOperationPhase") not in RUNTIME_OPERATION_PHASES
    ):
        fail("transaction identity differs")
    if document["phase"] == "prepared":
        if document.get("evidenceSha256") is not None or document.get("latestPointerSha256") is not None:
            fail("prepared transaction has terminal identity")
    elif not digest(document.get("evidenceSha256")) or not digest(document.get("latestPointerSha256")):
        fail("committed transaction identity is malformed")
    recovery_phase = document["runtimeRecoveryPhase"]
    recovery_file = document.get("runtimeRecoveryJournalFile")
    recovery_sha = document.get("runtimeRecoveryJournalSha256")
    if recovery_phase == "none":
        if recovery_file is not None or recovery_sha is not None:
            fail("inactive runtime recovery retained a journal identity")
    elif (recovery_file is None) != (recovery_sha is None):
        fail("runtime recovery journal identity is incomplete")
    elif recovery_file is not None and (
        re.fullmatch(
            rf"{commit}-{configuration}-[0-9a-f]{{32}}-backup-upload-cleanup-required[.]json",
            str(recovery_file),
        )
        is None
        or not digest(recovery_sha)
    ):
        fail("runtime recovery journal identity is malformed")
    operation_phase = document["runtimeOperationPhase"]
    operation_label = document.get("runtimeOperationLabel")
    operation_token = document.get("runtimeOperationToken")
    operation_bound_phases = {
        "operation-armed",
        "operation-absence-proved",
        "restart-authorized",
    }
    if operation_phase in operation_bound_phases:
        if (
            not isinstance(operation_label, str)
            or RUNTIME_OPERATION_LABEL.fullmatch(operation_label) is None
            or not digest(operation_token, 32)
        ):
            fail("runtime operation identity is malformed")
    elif operation_label is not None or operation_token is not None:
        fail("inactive runtime operation retained an identity")
    if operation_phase in {
        "initial-stopped",
        "initial-start-authorized",
        "temporary-stop-authorized",
        "original-stop-authorized",
    } and document["originalRuntimeState"] != "stopped":
        fail("running-origin transaction gained stopped-origin authority")
    if document["phase"] != "prepared" and (
        recovery_phase != "none" or operation_phase != "original-restored"
    ):
        fail("terminal backup transaction retained incomplete runtime ownership")
    if operation_phase == "original-restored" and recovery_phase != "none":
        fail("restored original runtime retained cleanup ownership")
    return document


def runtime_argument_document(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "runtimeIdentitySha256": args.runtime_identity_sha,
        "currentReleaseSha256": args.current_release_sha,
        "discourseRevision": args.discourse_revision,
        "dockerManagerRevision": args.docker_manager_revision,
        "runtimeEnvironmentSha256": args.runtime_environment_sha,
        "runtimePortBindingsSha256": args.runtime_ports_sha,
        "runtimeContainerImage": args.runtime_image,
    }


def validate_runtime_arguments(args: argparse.Namespace) -> dict[str, Any]:
    document = runtime_argument_document(args)
    if (
        not digest(document["runtimeIdentitySha256"])
        or not digest(document["currentReleaseSha256"])
        or not digest(document["discourseRevision"], 40)
        or not digest(document["dockerManagerRevision"], 40)
        or not digest(document["runtimeEnvironmentSha256"])
        or not digest(document["runtimePortBindingsSha256"])
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(document["runtimeContainerImage"]))
        is None
        or document["runtimeIdentitySha256"]
        != runtime_identity_digest(
            args.commit,
            args.configuration,
            document["currentReleaseSha256"],
            document["discourseRevision"],
            document["dockerManagerRevision"],
            document["runtimeEnvironmentSha256"],
            document["runtimePortBindingsSha256"],
            document["runtimeContainerImage"],
        )
    ):
        fail("runtime binding arguments are malformed")
    return document


def optional_runtime_arguments(args: argparse.Namespace) -> dict[str, Any] | None:
    values = runtime_argument_document(args)
    present = [value is not None for value in values.values()]
    if not any(present):
        return None
    if not all(present):
        fail("runtime binding arguments are incomplete")
    return validate_runtime_arguments(args)


def load_action_transaction(args: argparse.Namespace) -> dict[str, Any]:
    document = load_transaction(
        args.transaction, args.commit, args.configuration, args.operation_sha
    )
    expected = validate_runtime_arguments(args)
    if any(document.get(key) != value for key, value in expected.items()):
        fail("runtime binding differs from the prepared backup transaction")
    return document


def validate_backup_upload_journal(
    path: Path,
    evidence_root: Path,
    commit: str,
    configuration: str,
    operation_sha: str,
) -> str:
    if path.parent != evidence_root:
        fail("backup upload journal escaped its evidence root")
    raw = protected_bytes(path, MAX_STATE_BYTES)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("backup upload journal JSON is malformed")
    transaction_id = document.get("transactionId", "") if isinstance(document, dict) else ""
    expected_name = (
        f"{commit}-{configuration}-{transaction_id}-backup-upload-cleanup-required.json"
    )
    expected = {
        "schemaVersion": 1,
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "backupOperationSha256": operation_sha,
        "transactionId": transaction_id,
        "pluginStoreKey": f"normal_upload_transaction:{transaction_id}",
        "phase": "prepared",
    }
    if (
        not isinstance(document, dict)
        or set(document) != BACKUP_UPLOAD_JOURNAL_KEYS
        or not digest(transaction_id, 32)
        or path.name != expected_name
        or document != expected
        or raw != canonical(expected)
    ):
        fail("backup upload journal identity differs")
    return hashlib.sha256(raw).hexdigest()


def current_pointer_identity(pointer: Path, evidence_root: Path) -> tuple[str | None, str | None]:
    if not pointer.exists() and not pointer.is_symlink():
        return None, None
    raw = protected_bytes(pointer, MAX_STATE_BYTES)
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("latest-backup pointer is not UTF-8")
    if not value.endswith("\n") or value.count("\n") != 1:
        fail("latest-backup pointer is malformed")
    evidence = Path(value[:-1])
    if evidence.parent != evidence_root or not prior_evidence_name(evidence.name):
        fail("latest-backup pointer escaped its evidence boundary")
    protected_bytes(evidence, MAX_EVIDENCE_BYTES)
    return evidence.name, hashlib.sha256(raw).hexdigest()


def atomic_write(path: Path, payload: bytes, *, replace: bool) -> None:
    safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        protected_bytes(path, MAX_STATE_BYTES)
        if not replace:
            fail("protected state already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def create_exclusive(path: Path, payload: bytes) -> None:
    safe_directory(path.parent)
    partial = path.with_name(f".{path.name}.partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(partial, flags, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        os.fchmod(target.fileno(), 0o600)
        os.fchown(target.fileno(), 0, 0)
        target.write(payload)
        target.flush()
        os.fsync(target.fileno())
    os.link(partial, path, follow_symlinks=False)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        partial.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)


def reconcile_exclusive_partial(path: Path) -> None:
    """Retire only a proven non-authoritative or exact-linked prearm partial."""

    safe_directory(path.parent)
    partial = path.with_name(f".{path.name}.partial")
    if not partial.exists() and not partial.is_symlink():
        return
    metadata = partial.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_STATE_BYTES
    ):
        fail("transaction prearm partial is unsafe")
    partial_raw = partial.read_bytes()
    if len(partial_raw) != metadata.st_size:
        fail("transaction prearm partial changed while it was read")
    if path.exists() or path.is_symlink():
        final_raw = protected_bytes(path, MAX_STATE_BYTES)
        final_metadata = path.lstat()
        if (
            partial_raw != final_raw
            or metadata.st_dev != final_metadata.st_dev
            or metadata.st_ino != final_metadata.st_ino
        ):
            fail("transaction prearm partial differs from its final authority")
    partial.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_evidence(
    transaction: dict[str, Any], evidence_root: Path
) -> tuple[Path, str]:
    if (
        "runtimeRecoveryPhase" in transaction
        and transaction.get("runtimeRecoveryPhase") != "none"
    ):
        fail("backup evidence cannot publish during runtime recovery")
    if (
        "runtimeOperationPhase" in transaction
        and transaction.get("runtimeOperationPhase") != "original-restored"
    ):
        fail("backup evidence cannot publish before original runtime restoration")
    path = evidence_root / transaction["evidenceFile"]
    raw = protected_bytes(path, MAX_EVIDENCE_BYTES)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("backup evidence JSON is malformed")
    if not isinstance(document, dict):
        fail("backup evidence is not an object")
    commit = transaction["repositoryCommit"]
    configuration = transaction["productionConfigurationSha256"]
    if (
        document.get("schemaVersion") != 3
        or document.get("repositoryCommit") != commit
        or document.get("productionConfigurationSha256") != configuration
        or document.get("releaseEvidenceFile") != f"{commit}-{configuration}-release.json"
        or not digest(document.get("releaseEvidenceSha256"))
        or not digest(document.get("restoreConfigurationSha256"))
        or not digest(document.get("themeArchiveSha256"))
        or not digest(document.get("mailMetadataPluginSha256"))
        or not digest(document.get("discourseDockerRevision"), 40)
        or not digest(document.get("discourseRevision"), 40)
        or document.get("discourseRevision") != transaction["discourseRevision"]
        or not digest(document.get("dockerManagerRevision"), 40)
        or document.get("dockerManagerRevision") != transaction["dockerManagerRevision"]
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(document.get("baseImageDigest", ""))) is None
        or type(document.get("discourseConnectEnabled")) is not bool
        or document.get("privateAdminRetrievalUrlPresent") is not True
        or document.get("anonymousRetrievalDenied") is not True
        or document.get("anonymousCdnRetrievalDenied") is not True
        or document.get("backupPrefix") != "backups/"
        or type(document.get("size")) is not int
        or not 0 < document["size"] <= 50 * 1024 * 1024 * 1024
        or not digest(document.get("sha256"))
        or not isinstance(document.get("filename"), str)
        or len(document["filename"].encode("utf-8")) > 200
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", document["filename"]) is None
        or ".." in document["filename"]
        or document.get("disasterRecoveryEvidencePublished") is not True
        or document.get("disasterRecoveryPointerSelected") is not True
        or document.get("disasterRecoveryPrivateAclPassed") is not True
        or document.get("disasterRecoveryEvidenceObjectKey") is None
        or not digest(document.get("disasterRecoveryEvidenceObjectSha256"))
        or document.get("disasterRecoveryPointerObjectKey") != "backups/recovery-evidence/current.json"
        or not digest(document.get("disasterRecoveryPointerObjectSha256"))
        or not digest(document.get("disasterRecoveryRepositoryTree"), 40)
        or document.get("disasterRecoveryReleaseArchivePublished") is not True
        or not digest(document.get("disasterRecoveryReleaseArchiveSha256"))
        or type(document.get("disasterRecoveryReleaseArchiveBytes")) is not int
        or not 1 <= document["disasterRecoveryReleaseArchiveBytes"] <= 64 * 1024 * 1024
        or not digest(document.get("disasterRecoveryReleaseArchiveContentManifestSha256"))
        or document.get("disasterRecoveryReleaseArchiveSourceFormat") != "git-archive-tar-v1"
        or document.get("disasterRecoveryReleaseSourceAuthorityPublished") is not True
        or not digest(document.get("disasterRecoveryReleaseSourceAuthoritySha256"))
        or document.get("disasterRecoveryOrdinaryDeploymentRequiresCurrentMain") is not True
        or document.get("disasterRecoveryHistoricalReleaseAdoptionScope")
        != "clean-target-disaster-recovery-only"
        or type(document.get("normalUploadInventoryCount")) is not int
        or not 0 <= document["normalUploadInventoryCount"] <= 10_000
        or not digest(document.get("normalUploadInventorySha256"))
    ):
        fail("backup evidence terminal contract differs")
    evidence_object_sha = document["disasterRecoveryEvidenceObjectSha256"]
    if document["disasterRecoveryEvidenceObjectKey"] != f"backups/recovery-evidence/records/{evidence_object_sha}.json":
        fail("backup evidence disaster-recovery object binding differs")
    release_archive_sha = document["disasterRecoveryReleaseArchiveSha256"]
    if (
        document.get("disasterRecoveryReleaseArchiveObjectKey")
        != f"backups/recovery-releases/archives/{release_archive_sha}.tar"
    ):
        fail("backup evidence disaster-recovery release archive binding differs")
    authority_sha = document["disasterRecoveryReleaseSourceAuthoritySha256"]
    if (
        document.get("disasterRecoveryReleaseSourceAuthorityObjectKey")
        != f"backups/recovery-releases/authorities/{authority_sha}.json"
    ):
        fail("backup evidence disaster-recovery source authority binding differs")
    marker_file = document.get("memberRolloutMarkerFile")
    marker_sha = document.get("memberRolloutMarkerSha256")
    if (marker_file is None) != (marker_sha is None) or (
        marker_file is not None and (marker_file != "member-rollout-enabled" or not digest(marker_sha))
    ):
        fail("backup evidence member-rollout binding differs")
    included = document.get("recoveryUploadIncluded")
    if type(included) is not bool:
        fail("backup evidence recovery-upload flag is malformed")
    if included:
        state = document.get("recoveryUploadState")
        state_sha = document.get("recoveryUploadStateSha256")
        if (
            not isinstance(state, dict)
            or set(state) != RECOVERY_STATE_KEYS
            or state.get("schemaVersion") != 1
            or state.get("repositoryCommit") != commit
            or type(state.get("uploadId")) is not int
            or state["uploadId"] <= 0
            or not digest(state.get("publicUrlSha256"))
            or not digest(state_sha)
            or document.get("recoveryUploadDeletedAfterBackup") is not True
        ):
            fail("backup evidence recovery-upload identity is incomplete")
        marker_base = base64.b64decode(
            "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==", validate=True
        )
        marker_comment = f"mochirii-recovery-{commit}".encode("ascii")
        marker_bytes = (
            marker_base[:-1]
            + b"!\xfe"
            + bytes([len(marker_comment)])
            + marker_comment
            + b"\x00;"
        )
        expected_sha1 = hashlib.sha1(marker_bytes).hexdigest()
        object_path = state.get("objectPath", "")
        if (
            state.get("uploadSha1") != expected_sha1
            or state.get("contentSha256") != hashlib.sha256(marker_bytes).hexdigest()
            or state.get("originalFilename") != f"mochirii-recovery-{commit[:12]}.gif"
            or not isinstance(object_path, str)
            or re.fullmatch(
                rf"original/[1-9][0-9]*X/(?:[0-9a-f]/)*{expected_sha1}[.]gif", object_path
            )
            is None
            or state.get("tombstonePath") != f"tombstone/{object_path}"
        ):
            fail("backup evidence recovery-upload deep binding differs")
        if hashlib.sha256(canonical(state)).hexdigest() != state_sha:
            fail("backup evidence recovery-upload digest differs")
    elif (
        document.get("recoveryUploadState") is not None
        or document.get("recoveryUploadStateSha256") is not None
        or document.get("recoveryUploadDeletedAfterBackup") is not False
    ):
        fail("clean backup evidence retained recovery-upload identity")
    evidence_sha = hashlib.sha256(raw).hexdigest()
    committed_sha = transaction.get("evidenceSha256")
    if committed_sha is not None and committed_sha != evidence_sha:
        fail("backup evidence changed after its commit point")
    return path, evidence_sha


def pointer_payload(evidence: Path) -> bytes:
    return f"{evidence}\n".encode("utf-8")


def validate_selected_pointer(pointer: Path, evidence: Path) -> str:
    raw = protected_bytes(pointer, MAX_STATE_BYTES)
    expected = pointer_payload(evidence)
    if raw != expected:
        fail("latest-backup pointer does not select the transaction evidence")
    return hashlib.sha256(raw).hexdigest()


def current_document(
    transaction: dict[str, Any], evidence_sha: str, pointer_sha: str, phase: str
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "repositoryCommit": transaction["repositoryCommit"],
        "productionConfigurationSha256": transaction["productionConfigurationSha256"],
        "backupOperationSha256": transaction["backupOperationSha256"],
        "evidenceFile": transaction["evidenceFile"],
        "evidenceSha256": evidence_sha,
        "latestPointerSha256": pointer_sha,
        "phase": phase,
        "originalRuntimeState": transaction["originalRuntimeState"],
        "runtimeIdentitySha256": transaction["runtimeIdentitySha256"],
        "currentReleaseSha256": transaction["currentReleaseSha256"],
        "discourseRevision": transaction["discourseRevision"],
        "dockerManagerRevision": transaction["dockerManagerRevision"],
        "runtimeEnvironmentSha256": transaction["runtimeEnvironmentSha256"],
        "runtimePortBindingsSha256": transaction["runtimePortBindingsSha256"],
        "runtimeContainerImage": transaction["runtimeContainerImage"],
    }


def load_current(path: Path) -> dict[str, Any]:
    raw = protected_bytes(path, MAX_STATE_BYTES)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("current-backup JSON is malformed")
    if not isinstance(document, dict) or set(document) != CURRENT_KEYS or raw != canonical(document):
        fail("current-backup schema or canonical bytes differ")
    commit = document.get("repositoryCommit", "")
    configuration = document.get("productionConfigurationSha256", "")
    evidence_file = document.get("evidenceFile", "")
    match = re.fullmatch(
        rf"{re.escape(str(commit))}-{re.escape(str(configuration))}-([0-9]{{8}}T[0-9]{{6}}Z)-backup[.]json",
        str(evidence_file),
    )
    if (
        document.get("schemaVersion") != 1
        or not digest(commit, 40)
        or not digest(configuration)
        or not digest(document.get("backupOperationSha256"))
        or match is None
        or evidence_file != exact_evidence_name(commit, configuration, match.group(1))
        or not digest(document.get("evidenceSha256"))
        or not digest(document.get("latestPointerSha256"))
        or document.get("phase") not in {"pointer-committed", "event-committed"}
        or document.get("originalRuntimeState") not in {"running", "stopped"}
        or not digest(document.get("runtimeIdentitySha256"))
        or not digest(document.get("currentReleaseSha256"))
        or not digest(document.get("discourseRevision"), 40)
        or not digest(document.get("dockerManagerRevision"), 40)
        or not digest(document.get("runtimeEnvironmentSha256"))
        or not digest(document.get("runtimePortBindingsSha256"))
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(document.get("runtimeContainerImage", ""))
        )
        is None
        or document.get("runtimeIdentitySha256")
        != runtime_identity_digest(
            commit,
            configuration,
            document.get("currentReleaseSha256", ""),
            document.get("discourseRevision", ""),
            document.get("dockerManagerRevision", ""),
            document.get("runtimeEnvironmentSha256", ""),
            document.get("runtimePortBindingsSha256", ""),
            document.get("runtimeContainerImage", ""),
        )
    ):
        fail("current-backup identity differs")
    return document


def validate_terminal_current(
    document: dict[str, Any], evidence_root: Path, pointer: Path
) -> tuple[Path, str, str]:
    if document["phase"] != "event-committed":
        fail("current-backup is not event-committed")
    evidence, evidence_sha = validate_evidence(document, evidence_root)
    pointer_sha = validate_selected_pointer(pointer, evidence)
    if (
        document["evidenceSha256"] != evidence_sha
        or document["latestPointerSha256"] != pointer_sha
    ):
        fail("current-backup terminal identity differs")
    return evidence, evidence_sha, pointer_sha


def replace_transaction(path: Path, document: dict[str, Any]) -> None:
    atomic_write(path, canonical(document), replace=True)


def action_create(args: argparse.Namespace) -> None:
    safe_directory(args.state_root)
    safe_directory(args.evidence_root)
    expected_name = exact_evidence_name(args.commit, args.configuration, args.timestamp)
    if args.evidence_file != expected_name:
        fail("new transaction evidence filename differs")
    if args.current.exists() or args.current.is_symlink():
        fail("terminal current-backup must be retired before a new transaction")
    evidence = args.evidence_root / expected_name
    if evidence.exists() or evidence.is_symlink():
        fail("new transaction evidence target already exists")
    previous_file, previous_sha = current_pointer_identity(args.pointer, args.evidence_root)
    runtime = validate_runtime_arguments(args)
    if args.original_runtime_state not in {"running", "stopped"}:
        fail("original runtime state is malformed")
    document = {
        "schemaVersion": 2,
        "repositoryCommit": args.commit,
        "productionConfigurationSha256": args.configuration,
        "backupOperationSha256": args.operation_sha,
        "timestamp": args.timestamp,
        "evidenceFile": expected_name,
        "previousLatestEvidenceFile": previous_file,
        "previousLatestPointerSha256": previous_sha,
        "phase": "prepared",
        "evidenceSha256": None,
        "latestPointerSha256": None,
        "runtimeRecoveryPhase": "none",
        "runtimeRecoveryJournalFile": None,
        "runtimeRecoveryJournalSha256": None,
        "originalRuntimeState": args.original_runtime_state,
        **runtime,
        "runtimeOperationPhase": (
            "idle" if args.original_runtime_state == "running" else "initial-stopped"
        ),
        "runtimeOperationLabel": None,
        "runtimeOperationToken": None,
    }
    create_exclusive(args.transaction, canonical(document))


def action_inspect(args: argparse.Namespace) -> None:
    document = load_action_transaction(args)
    print(document["timestamp"])
    print(document["evidenceFile"])
    print(document["phase"])
    print(document["evidenceSha256"] or "-")
    print(document["latestPointerSha256"] or "-")
    print(document["runtimeRecoveryPhase"])
    print(document["runtimeRecoveryJournalFile"] or "-")
    print(document["runtimeRecoveryJournalSha256"] or "-")
    print(document["originalRuntimeState"])
    print(document["runtimeIdentitySha256"])
    print(document["currentReleaseSha256"])
    print(document["discourseRevision"])
    print(document["dockerManagerRevision"])
    print(document["runtimeEnvironmentSha256"])
    print(document["runtimePortBindingsSha256"])
    print(document["runtimeContainerImage"])
    print(document["runtimeOperationPhase"])
    print(document["runtimeOperationLabel"] or "-")
    print(document["runtimeOperationToken"] or "-")


def requested_recovery_journal(
    args: argparse.Namespace, *, required: bool
) -> tuple[str | None, str | None]:
    if args.recovery_journal == "-":
        if args.recovery_journal_sha != "-":
            fail("journal-free runtime recovery retained a digest")
        if required:
            fail("runtime recovery requires a backup upload journal")
        return None, None
    if not isinstance(args.recovery_journal, str):
        fail("runtime recovery journal argument is absent")
    path = args.evidence_root / args.recovery_journal
    journal_sha = validate_backup_upload_journal(
        path,
        args.evidence_root,
        args.commit,
        args.configuration,
        args.operation_sha,
    )
    if args.recovery_journal_sha != journal_sha:
        fail("runtime recovery journal digest differs")
    return path.name, journal_sha


def replace_runtime_recovery(
    args: argparse.Namespace,
    transaction: dict[str, Any],
    phase: str,
    journal_file: str | None,
    journal_sha: str | None,
) -> None:
    if phase not in RUNTIME_RECOVERY_PHASES:
        fail("runtime recovery phase is malformed")
    transaction.update(
        {
            "runtimeRecoveryPhase": phase,
            "runtimeRecoveryJournalFile": journal_file,
            "runtimeRecoveryJournalSha256": journal_sha,
        }
    )
    replace_transaction(args.transaction, transaction)


def action_bind_cleanup(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    if transaction["phase"] != "prepared" or transaction["runtimeOperationPhase"] not in {
        "idle",
        "initial-stopped",
        "temporary-stop-authorized",
    }:
        fail("runtime cleanup cannot bind to a terminal backup transaction")
    journal_file, journal_sha = requested_recovery_journal(args, required=True)
    current_phase = transaction["runtimeRecoveryPhase"]
    if current_phase == "cleanup-pending":
        if (
            transaction["runtimeRecoveryJournalFile"] != journal_file
            or transaction["runtimeRecoveryJournalSha256"] != journal_sha
        ):
            fail("pending runtime cleanup was rebound")
        return
    if current_phase != "none":
        fail("runtime cleanup cannot bind during another recovery phase")
    replace_runtime_recovery(
        args, transaction, "cleanup-pending", journal_file, journal_sha
    )


def requested_operation(args: argparse.Namespace) -> tuple[str, str]:
    label = args.runtime_operation_label
    token = args.runtime_operation_token
    if (
        not isinstance(label, str)
        or RUNTIME_OPERATION_LABEL.fullmatch(label) is None
        or not digest(token, 32)
    ):
        fail("runtime operation arguments are malformed")
    return label, token


def replace_runtime_operation(
    args: argparse.Namespace,
    transaction: dict[str, Any],
    phase: str,
    label: str | None,
    token: str | None,
) -> None:
    if phase not in RUNTIME_OPERATION_PHASES:
        fail("runtime operation phase is malformed")
    transaction.update(
        {
            "runtimeOperationPhase": phase,
            "runtimeOperationLabel": label,
            "runtimeOperationToken": token,
        }
    )
    replace_transaction(args.transaction, transaction)


def require_same_operation(
    args: argparse.Namespace, transaction: dict[str, Any]
) -> tuple[str, str]:
    label, token = requested_operation(args)
    if (
        transaction["runtimeOperationLabel"] != label
        or transaction["runtimeOperationToken"] != token
    ):
        fail("runtime operation identity changed")
    return label, token


def action_arm_operation(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    label, token = requested_operation(args)
    if (
        transaction["phase"] != "prepared"
        or transaction["runtimeOperationPhase"] != "idle"
    ):
        fail("runtime operation cannot arm outside the exact idle backup transaction")
    replace_runtime_operation(args, transaction, "operation-armed", label, token)


def action_complete_operation(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    label, token = require_same_operation(args, transaction)
    if (
        transaction["phase"] != "prepared"
        or transaction["runtimeOperationPhase"] != "operation-armed"
    ):
        fail("runtime operation completion lacks exact armed authority")
    replace_runtime_operation(args, transaction, "idle", None, None)


def action_prove_operation_absent(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    label, token = require_same_operation(args, transaction)
    phase = transaction["runtimeOperationPhase"]
    if phase == "operation-absence-proved":
        return
    if phase != "operation-armed" or transaction["phase"] != "prepared":
        fail("runtime operation absence has no armed authority")
    replace_runtime_operation(
        args, transaction, "operation-absence-proved", label, token
    )


def action_authorize_restart(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    label, token = require_same_operation(args, transaction)
    phase = transaction["runtimeOperationPhase"]
    if phase == "restart-authorized":
        return
    if phase != "operation-absence-proved" or transaction["phase"] != "prepared":
        fail("runtime restart requires exact operation absence proof")
    replace_runtime_operation(args, transaction, "restart-authorized", label, token)


def action_complete_restart(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    require_same_operation(args, transaction)
    if (
        transaction["phase"] != "prepared"
        or transaction["runtimeOperationPhase"] != "restart-authorized"
    ):
        fail("runtime restart completion lacks exact operation authority")
    replace_runtime_operation(args, transaction, "idle", None, None)


def action_authorize_initial_start(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    phase = transaction["runtimeOperationPhase"]
    if phase == "initial-start-authorized":
        return
    if (
        transaction["phase"] != "prepared"
        or transaction["originalRuntimeState"] != "stopped"
        or phase != "initial-stopped"
    ):
        fail("temporary backup start lacks stopped-origin authority")
    replace_runtime_operation(args, transaction, "initial-start-authorized", None, None)


def action_complete_initial_start(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    if (
        transaction["phase"] != "prepared"
        or transaction["originalRuntimeState"] != "stopped"
        or transaction["runtimeOperationPhase"] != "initial-start-authorized"
    ):
        fail("temporary backup start completion lacks exact authority")
    replace_runtime_operation(args, transaction, "idle", None, None)


def action_contain_temporary_runtime(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    phase = transaction["runtimeOperationPhase"]
    if phase == "initial-stopped":
        return
    if (
        transaction["phase"] != "prepared"
        or transaction["originalRuntimeState"] != "stopped"
        or phase not in {"idle", "temporary-stop-authorized"}
    ):
        fail("temporary runtime containment lacks stopped-origin authority")
    next_phase = (
        "temporary-stop-authorized" if phase == "idle" else "initial-stopped"
    )
    replace_runtime_operation(args, transaction, next_phase, None, None)


def action_complete_cleanup(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    if transaction["phase"] != "prepared" or transaction["runtimeOperationPhase"] != "idle":
        fail("runtime cleanup cannot complete on a terminal backup transaction")
    current_phase = transaction["runtimeRecoveryPhase"]
    if current_phase not in {"cleanup-pending", "cleanup-proved"}:
        fail("runtime cleanup completion has no durable authority")
    journal_file = transaction["runtimeRecoveryJournalFile"]
    journal_sha = transaction["runtimeRecoveryJournalSha256"]
    if journal_file is None or journal_sha is None:
        fail("runtime cleanup completion lost its journal identity")
    observed_file, observed_sha = requested_recovery_journal(args, required=True)
    if observed_file != journal_file or observed_sha != journal_sha:
        fail("runtime cleanup completion identity changed")
    if current_phase != "cleanup-proved":
        replace_runtime_recovery(
            args, transaction, "cleanup-proved", journal_file, journal_sha
        )


def action_resume_runtime(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    if (
        transaction["phase"] != "prepared"
        or transaction["runtimeRecoveryPhase"] != "cleanup-proved"
        or transaction["runtimeOperationPhase"] != "idle"
    ):
        fail("backup runtime is not ready to resume")
    journal_file = transaction["runtimeRecoveryJournalFile"]
    if journal_file is None or transaction["runtimeRecoveryJournalSha256"] is None:
        fail("backup runtime resume lost its cleanup journal identity")
    if args.recovery_journal != "-" or args.recovery_journal_sha != "-":
        fail("backup runtime resume must observe journal-free arguments")
    journal = args.evidence_root / journal_file
    if journal.exists() or journal.is_symlink():
        fail("backup runtime cannot resume before cleanup journal retirement")
    replace_runtime_recovery(args, transaction, "none", None, None)


def action_authorize_original_stop(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    phase = transaction["runtimeOperationPhase"]
    if phase == "original-stop-authorized":
        return
    if (
        transaction["phase"] != "prepared"
        or transaction["originalRuntimeState"] != "stopped"
        or transaction["runtimeRecoveryPhase"] != "none"
        or phase != "idle"
    ):
        fail("original stopped-state restoration lacks exact authority")
    validate_evidence_for_runtime_restoration(transaction, args.evidence_root)
    replace_runtime_operation(args, transaction, "original-stop-authorized", None, None)


def validate_evidence_for_runtime_restoration(
    transaction: dict[str, Any], evidence_root: Path
) -> None:
    candidate = dict(transaction)
    candidate["runtimeOperationPhase"] = "original-restored"
    validate_evidence(candidate, evidence_root)


def action_complete_original_state(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    observed = args.observed_runtime_state
    if observed not in {"running", "stopped"} or observed != transaction["originalRuntimeState"]:
        fail("observed runtime state differs from the transaction origin")
    if transaction["runtimeOperationPhase"] == "original-restored":
        return
    expected_phase = "idle" if observed == "running" else "original-stop-authorized"
    if (
        transaction["phase"] != "prepared"
        or transaction["runtimeRecoveryPhase"] != "none"
        or transaction["runtimeOperationPhase"] != expected_phase
    ):
        fail("original runtime restoration lacks exact terminal authority")
    validate_evidence_for_runtime_restoration(transaction, args.evidence_root)
    replace_runtime_operation(args, transaction, "original-restored", None, None)


def action_retire_prepared(args: argparse.Namespace) -> None:
    load_action_transaction(args)
    fail("prepared backup ownership cannot retire before terminal runtime restoration")


def action_evidence_sha(args: argparse.Namespace) -> None:
    document = load_action_transaction(args)
    _, evidence_sha = validate_evidence(document, args.evidence_root)
    print(evidence_sha)


def action_select_pointer(args: argparse.Namespace) -> None:
    document = load_action_transaction(args)
    evidence, _ = validate_evidence(document, args.evidence_root)
    target_payload = pointer_payload(evidence)
    target_sha = hashlib.sha256(target_payload).hexdigest()
    current_file, current_sha = current_pointer_identity(args.pointer, args.evidence_root)
    if current_file == evidence.name and current_sha == target_sha:
        print(target_sha)
        return
    if (
        current_file != document["previousLatestEvidenceFile"]
        or current_sha != document["previousLatestPointerSha256"]
    ):
        fail("latest-backup pointer changed outside this transaction")
    atomic_write(args.pointer, target_payload, replace=current_file is not None)
    if validate_selected_pointer(args.pointer, evidence) != target_sha:
        fail("latest-backup pointer readback differs")
    print(target_sha)


def action_publish_phase(args: argparse.Namespace) -> None:
    if args.phase not in {"pointer-committed", "event-committed"}:
        fail("published phase is not terminal")
    transaction = load_action_transaction(args)
    evidence, evidence_sha = validate_evidence(transaction, args.evidence_root)
    pointer_sha = validate_selected_pointer(args.pointer, evidence)
    if args.evidence_sha != evidence_sha or args.pointer_sha != pointer_sha:
        fail("published terminal identity differs")
    current_phase = transaction["phase"]
    if PHASES[args.phase] < PHASES[current_phase] or PHASES[args.phase] > PHASES[current_phase] + 1:
        fail("transaction phase transition differs")
    expected_current = current_document(transaction, evidence_sha, pointer_sha, args.phase)
    if args.current.exists() or args.current.is_symlink():
        existing = load_current(args.current)
        if any(
            existing.get(key) != value
            for key, value in expected_current.items()
            if key != "phase"
        ):
            fail("current-backup identity differs from this transaction")
        if PHASES[existing["phase"]] > PHASES[current_phase] + 1:
            fail("current-backup advanced beyond one recoverable commit point")
        if PHASES[existing["phase"]] < PHASES[args.phase]:
            atomic_write(args.current, canonical(expected_current), replace=True)
        elif PHASES[existing["phase"]] == PHASES[args.phase] and existing != expected_current:
            fail("same-phase current-backup identity differs")
    else:
        atomic_write(args.current, canonical(expected_current), replace=False)
    transaction.update(
        {
            "phase": args.phase,
            "evidenceSha256": evidence_sha,
            "latestPointerSha256": pointer_sha,
        }
    )
    replace_transaction(args.transaction, transaction)


def action_clear(args: argparse.Namespace) -> None:
    transaction = load_action_transaction(args)
    if transaction["phase"] != "event-committed":
        fail("transaction is not event-committed")
    evidence, evidence_sha = validate_evidence(transaction, args.evidence_root)
    pointer_sha = validate_selected_pointer(args.pointer, evidence)
    expected = current_document(transaction, evidence_sha, pointer_sha, "event-committed")
    if load_current(args.current) != expected:
        fail("terminal current-backup record differs")
    args.transaction.unlink()
    directory = os.open(args.transaction.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def action_inspect_current(args: argparse.Namespace) -> None:
    document = load_current(args.current)
    print(document["repositoryCommit"])
    print(document["productionConfigurationSha256"])
    print(document["backupOperationSha256"])
    print(document["evidenceFile"])
    print(document["phase"])
    if args.include_runtime_contract:
        print(document["originalRuntimeState"])
        print(document["runtimeIdentitySha256"])
        print(document["currentReleaseSha256"])
        print(document["discourseRevision"])
        print(document["dockerManagerRevision"])
        print(document["runtimeEnvironmentSha256"])
        print(document["runtimePortBindingsSha256"])
        print(document["runtimeContainerImage"])


def action_adopt_current(args: argparse.Namespace) -> None:
    document = load_current(args.current)
    runtime = validate_runtime_arguments(args)
    if (
        document["repositoryCommit"] != args.commit
        or document["productionConfigurationSha256"] != args.configuration
        or document["backupOperationSha256"] != args.operation_sha
        or any(document.get(key) != value for key, value in runtime.items())
    ):
        fail("current-backup does not belong to this operation")
    _, evidence_sha, _ = validate_terminal_current(
        document, args.evidence_root, args.pointer
    )
    print(evidence_sha)


def action_retire_current(args: argparse.Namespace) -> None:
    document = load_current(args.current)
    runtime = optional_runtime_arguments(args)
    if document["backupOperationSha256"] == args.operation_sha:
        fail("current-backup cannot be retired by its own operation")
    same_release = (
        document["repositoryCommit"] == args.commit
        and document["productionConfigurationSha256"] == args.configuration
    )
    if (
        same_release
        and runtime is not None
        and any(document.get(key) != value for key, value in runtime.items())
    ):
        fail("current-backup runtime binding differs")
    validate_terminal_current(document, args.evidence_root, args.pointer)
    args.current.unlink()
    directory = os.open(args.current.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "action",
        choices=(
            "create",
            "inspect",
            "inspect-current",
            "adopt-current",
            "retire-current",
            "bind-cleanup",
            "arm-operation",
            "complete-operation",
            "prove-operation-absent",
            "authorize-restart",
            "complete-restart",
            "authorize-initial-start",
            "complete-initial-start",
            "contain-temporary-runtime",
            "authorize-original-stop",
            "complete-original-state",
            "complete-cleanup",
            "resume-runtime",
            "retire-prepared",
            "evidence-sha",
            "select-pointer",
            "publish-phase",
            "clear",
        ),
    )
    result.add_argument("--state-root", type=Path, required=True)
    result.add_argument("--evidence-root", type=Path, required=True)
    result.add_argument("--transaction", type=Path, required=True)
    result.add_argument("--current", type=Path, required=True)
    result.add_argument("--pointer", type=Path, required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--configuration", required=True)
    result.add_argument("--operation-sha", required=True)
    result.add_argument("--timestamp")
    result.add_argument("--evidence-file")
    result.add_argument("--phase")
    result.add_argument("--evidence-sha")
    result.add_argument("--pointer-sha")
    result.add_argument("--recovery-journal", default="-")
    result.add_argument("--recovery-journal-sha", default="-")
    result.add_argument("--original-runtime-state")
    result.add_argument("--runtime-identity-sha")
    result.add_argument("--current-release-sha")
    result.add_argument("--discourse-revision")
    result.add_argument("--docker-manager-revision")
    result.add_argument("--runtime-environment-sha")
    result.add_argument("--runtime-ports-sha")
    result.add_argument("--runtime-image")
    result.add_argument("--runtime-operation-label")
    result.add_argument("--runtime-operation-token")
    result.add_argument("--observed-runtime-state")
    result.add_argument("--include-runtime-contract", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    if os.geteuid() != 0:
        fail("helper must run as root")
    if args.transaction != args.state_root / "backup-transaction.json":
        fail("transaction path differs")
    if args.current != args.state_root / "current-backup.json":
        fail("current-backup path differs")
    if args.pointer != args.state_root / "latest-backup-evidence":
        fail("latest-backup pointer path differs")
    if args.evidence_root != args.state_root / "evidence":
        fail("evidence root differs")
    if not digest(args.operation_sha):
        fail("backup operation digest is malformed")
    reconcile_exclusive_partial(args.transaction)
    actions = {
        "create": action_create,
        "inspect": action_inspect,
        "inspect-current": action_inspect_current,
        "adopt-current": action_adopt_current,
        "retire-current": action_retire_current,
        "bind-cleanup": action_bind_cleanup,
        "arm-operation": action_arm_operation,
        "complete-operation": action_complete_operation,
        "prove-operation-absent": action_prove_operation_absent,
        "authorize-restart": action_authorize_restart,
        "complete-restart": action_complete_restart,
        "authorize-initial-start": action_authorize_initial_start,
        "complete-initial-start": action_complete_initial_start,
        "contain-temporary-runtime": action_contain_temporary_runtime,
        "authorize-original-stop": action_authorize_original_stop,
        "complete-original-state": action_complete_original_state,
        "complete-cleanup": action_complete_cleanup,
        "resume-runtime": action_resume_runtime,
        "retire-prepared": action_retire_prepared,
        "evidence-sha": action_evidence_sha,
        "select-pointer": action_select_pointer,
        "publish-phase": action_publish_phase,
        "clear": action_clear,
    }
    actions[args.action](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
