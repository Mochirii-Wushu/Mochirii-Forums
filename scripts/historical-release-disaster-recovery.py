#!/usr/bin/env python3
"""Validate and stage an exact prior Forums release for clean-host recovery.

This helper is intentionally separate from the ordinary deployment path. It
does not fetch from GitHub, start containers, select a runtime configuration,
or restore data. It converts one private, digest-bound recovery receipt plus
its exact Git archive into a root-readable source/configuration authorization
that a clean-target restore wrapper can consume explicitly.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO


MAX_RECEIPT_BYTES = 64 * 1024
MAX_STATE_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096
CONFIRMATION = "PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"
AUTHORIZE_CONFIRMATION = "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"
BEGIN_BOOTSTRAP_CONFIRMATION = "BEGIN HISTORICAL MOCHIRII FORUMS BOOTSTRAP"
COMPLETE_BOOTSTRAP_CONFIRMATION = "COMPLETE HISTORICAL MOCHIRII FORUMS BOOTSTRAP"
BEGIN_RESTORE_CONFIRMATION = "BEGIN HISTORICAL MOCHIRII FORUMS RESTORE"
COMPLETE_RECOVERY_CONFIRMATION = "COMPLETE HISTORICAL MOCHIRII FORUMS RECOVERY"
ARCHIVE_FORMAT = "git-archive-tar-v1"
ADOPTION_SCOPE = "clean-target-disaster-recovery-only"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
ALLOWED_ROOTS = {
    ".env.example",
    ".gitattributes",
    ".github",
    ".gitignore",
    "AGENTS.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    "config",
    "docs",
    "plugins",
    "scripts",
    "theme",
}
REQUIRED_SOURCE_FILES = {
    "AGENTS.md",
    "config/app.yml.example",
    "docs/operations/RECOVERY.md",
    "scripts/render-app-config.py",
    "scripts/validate-repository.py",
}
RECEIPT_KEYS = {
    "schemaVersion",
    "repositoryCommit",
    "productionConfigurationSha256",
    "filename",
    "size",
    "sha256",
    "lastModified",
    "privateAdminRetrievalUrlPresent",
    "anonymousRetrievalDenied",
    "anonymousCdnRetrievalDenied",
    "backupPrefix",
    "normalUploadInventoryCount",
    "normalUploadInventorySha256",
    "restoreConfigurationSha256",
    "themeArchiveSha256",
    "mailMetadataPluginSha256",
    "releaseEvidenceFile",
    "releaseEvidenceSha256",
    "discourseDockerRevision",
    "discourseRevision",
    "dockerManagerRevision",
    "baseImageDigest",
    "discourseConnectEnabled",
    "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
    "recoveryUploadIncluded",
    "recoveryUploadState",
    "recoveryUploadStateSha256",
    "recoveryUploadDeletedAfterBackup",
    "disasterRecoveryImported",
    "disasterRecoveryFetchMode",
    "disasterRecoveryBootstrapCommit",
    "disasterRecoveryEvidenceObjectKey",
    "disasterRecoveryEvidenceObjectSha256",
    "disasterRecoveryPointerObjectKey",
    "disasterRecoveryPointerObjectSha256",
    "disasterRecoveryRepositoryTree",
    "disasterRecoveryReleaseArchiveObjectKey",
    "disasterRecoveryReleaseArchiveSha256",
    "disasterRecoveryReleaseArchiveBytes",
    "disasterRecoveryReleaseArchiveContentManifestSha256",
    "disasterRecoveryReleaseArchiveSourceFormat",
    "disasterRecoveryReleaseSourceAuthorityObjectKey",
    "disasterRecoveryReleaseSourceAuthoritySha256",
    "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain",
    "disasterRecoveryHistoricalReleaseAdoptionScope",
    "disasterRecoveryPrivateAclPassed",
}


class RecoveryError(RuntimeError):
    """A historical release failed its exact recovery contract."""


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    executable: bool
    sha256: str
    git_blob: bytes


@dataclass(frozen=True)
class ArchiveIdentity:
    repository_commit: str
    repository_tree: str
    archive_sha256: str
    archive_bytes: int
    content_manifest_sha256: str
    files: tuple[FileEntry, ...]


@dataclass(frozen=True)
class RecoveryContext:
    current_host_control_file: Path
    current_host_control_sha256: str
    scratch_absence_file: Path
    scratch_absence_sha256: str
    reader_operation_id: str


class TreeNode:
    def __init__(self) -> None:
        self.files: dict[str, tuple[bool, bytes]] = {}
        self.directories: dict[str, TreeNode] = {}


def fail(message: str) -> None:
    raise RecoveryError(message)


def canonical(document: dict[str, object], *, pretty: bool = False) -> bytes:
    if pretty:
        return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_file(path: Path, maximum: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            size += len(chunk)
            if size > maximum:
                fail("Release archive exceeds its byte boundary.")
            digest.update(chunk)
    return size, digest.hexdigest()


def regular_file(path: Path, label: str, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RecoveryError(f"{label} is absent.") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is linked or non-regular.")
    if not 1 <= metadata.st_size <= maximum:
        fail(f"{label} is outside its byte boundary.")
    return metadata


def safe_parent(path: Path, label: str) -> Path:
    if not path.is_absolute():
        fail(f"{label} must use an absolute path.")
    parent = path.parent
    try:
        metadata = parent.lstat()
    except FileNotFoundError as error:
        raise RecoveryError(f"{label} parent is absent.") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} parent is linked or non-directory.")
    return parent


def safe_member_name(raw: str) -> tuple[str, ...]:
    if not raw or not raw.isascii() or raw.startswith("/") or "\\" in raw:
        fail("Release archive contains an unsafe member path.")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        fail("Release archive contains a control character.")
    normalized = raw.rstrip("/")
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} or ":" in part for part in parts):
        fail("Release archive contains an unsafe path component.")
    if parts[0] not in ALLOWED_ROOTS:
        fail("Release archive member is outside the exact repository inventory.")
    return parts


def git_object(kind: bytes, payload: bytes) -> bytes:
    return hashlib.sha1(kind + b" " + str(len(payload)).encode("ascii") + b"\0" + payload).digest()


def tree_digest(node: TreeNode) -> bytes:
    rows: list[tuple[bytes, bytes]] = []
    for name, (executable, blob) in node.files.items():
        encoded = name.encode("ascii")
        mode = b"100755" if executable else b"100644"
        rows.append((encoded + b"\0", mode + b" " + encoded + b"\0" + blob))
    for name, child in node.directories.items():
        encoded = name.encode("ascii")
        rows.append((encoded + b"/", b"40000 " + encoded + b"\0" + tree_digest(child)))
    payload = b"".join(row for _key, row in sorted(rows, key=lambda item: item[0]))
    return git_object(b"tree", payload)


def build_tree(files: list[FileEntry]) -> str:
    root = TreeNode()
    for entry in files:
        parts = entry.path.split("/")
        node = root
        for part in parts[:-1]:
            if part in node.files:
                fail("Release archive path conflicts with a file.")
            node = node.directories.setdefault(part, TreeNode())
        basename = parts[-1]
        if basename in node.files or basename in node.directories:
            fail("Release archive contains a duplicate or conflicting member.")
        node.files[basename] = (entry.executable, entry.git_blob)
    return tree_digest(root).hex()


def manifest_digest(files: list[FileEntry]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda item: item.path.encode("ascii")):
        mode = "100755" if entry.executable else "100644"
        digest.update(entry.path.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(mode.encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.sha256.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def inspect_archive(path: Path, expected_commit: str | None = None) -> ArchiveIdentity:
    regular_file(path, "Historical release archive", MAX_ARCHIVE_BYTES)
    archive_bytes, archive_sha = sha256_file(path, MAX_ARCHIVE_BYTES)
    files: list[FileEntry] = []
    seen: set[str] = set()
    expanded = 0
    with tarfile.open(path, mode="r:") as source:
        commit = source.pax_headers.get("comment")
        if set(source.pax_headers) != {"comment"} or not isinstance(commit, str) or HEX40.fullmatch(commit) is None:
            fail("Release archive lacks its exact Git commit authority.")
        if expected_commit is not None and commit != expected_commit:
            fail("Release archive Git commit differs from recovery evidence.")
        members = source.getmembers()
        if not 1 <= len(members) <= MAX_MEMBERS:
            fail("Release archive member count is outside its bound.")
        for member in members:
            parts = safe_member_name(member.name)
            normalized = "/".join(parts)
            if normalized in seen:
                fail("Release archive contains a duplicate member.")
            seen.add(normalized)
            if member.isdir():
                if member.mode & ~0o777 or member.mode & 0o002:
                    fail("Release archive directory mode is unsafe.")
                continue
            if not member.isfile():
                fail("Release archive contains a forbidden member type.")
            if member.mode & ~0o777 or member.mode & 0o002:
                fail("Release archive file mode is unsafe.")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                fail("Release archive member size is outside its bound.")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                fail("Release archive expanded size exceeds its bound.")
            extracted = source.extractfile(member)
            if extracted is None:
                fail("Release archive member bytes are unavailable.")
            payload = extracted.read(MAX_MEMBER_BYTES + 1)
            if len(payload) != member.size or len(payload) > MAX_MEMBER_BYTES:
                fail("Release archive member bytes differ from its header.")
            executable = bool(member.mode & 0o111)
            files.append(
                FileEntry(
                    path=normalized,
                    size=len(payload),
                    executable=executable,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    git_blob=git_object(b"blob", payload),
                )
            )
    paths = {entry.path for entry in files}
    if not REQUIRED_SOURCE_FILES.issubset(paths):
        fail("Release archive lacks the minimum reviewed recovery source.")
    repository_tree = build_tree(files)
    return ArchiveIdentity(
        repository_commit=commit,
        repository_tree=repository_tree,
        archive_sha256=archive_sha,
        archive_bytes=archive_bytes,
        content_manifest_sha256=manifest_digest(files),
        files=tuple(sorted(files, key=lambda item: item.path.encode("ascii"))),
    )


def read_receipt(path: Path) -> tuple[dict[str, object], str]:
    regular_file(path, "Disaster-recovery receipt", MAX_RECEIPT_BYTES)
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryError("Disaster-recovery receipt is malformed.") from error
    if not isinstance(document, dict) or set(document) != RECEIPT_KEYS:
        fail("Disaster-recovery receipt schema differs.")
    commit = document.get("repositoryCommit")
    configuration = document.get("productionConfigurationSha256")
    bootstrap = document.get("disasterRecoveryBootstrapCommit")
    archive_sha = document.get("disasterRecoveryReleaseArchiveSha256")
    archive_bytes = document.get("disasterRecoveryReleaseArchiveBytes")
    authority_sha = document.get("disasterRecoveryReleaseSourceAuthoritySha256")
    if (
        document.get("schemaVersion") != 3
        or not isinstance(commit, str)
        or HEX40.fullmatch(commit) is None
        or not isinstance(configuration, str)
        or HEX64.fullmatch(configuration) is None
        or not isinstance(bootstrap, str)
        or HEX40.fullmatch(bootstrap) is None
        or bootstrap == commit
        or not isinstance(archive_sha, str)
        or HEX64.fullmatch(archive_sha) is None
        or not isinstance(archive_bytes, int)
        or isinstance(archive_bytes, bool)
        or not 1 <= archive_bytes <= MAX_ARCHIVE_BYTES
        or not isinstance(authority_sha, str)
        or HEX64.fullmatch(authority_sha) is None
        or not isinstance(document.get("disasterRecoveryEvidenceObjectSha256"), str)
        or HEX64.fullmatch(str(document.get("disasterRecoveryEvidenceObjectSha256"))) is None
        or document.get("disasterRecoveryEvidenceObjectKey")
        != f"backups/recovery-evidence/records/{document.get('disasterRecoveryEvidenceObjectSha256')}.json"
        or not isinstance(document.get("disasterRecoveryPointerObjectSha256"), str)
        or HEX64.fullmatch(str(document.get("disasterRecoveryPointerObjectSha256"))) is None
        or document.get("disasterRecoveryPointerObjectKey") != "backups/recovery-evidence/current.json"
        or document.get("disasterRecoveryImported") is not True
        or document.get("disasterRecoveryFetchMode") != "clean-target-historical"
        or document.get("disasterRecoveryPrivateAclPassed") is not True
        or document.get("privateAdminRetrievalUrlPresent") is not True
        or document.get("anonymousRetrievalDenied") is not True
        or document.get("anonymousCdnRetrievalDenied") is not True
        or document.get("backupPrefix") != "backups/"
        or not isinstance(document.get("sha256"), str)
        or HEX64.fullmatch(str(document.get("sha256"))) is None
        or document.get("disasterRecoveryOrdinaryDeploymentRequiresCurrentMain") is not True
        or document.get("disasterRecoveryHistoricalReleaseAdoptionScope") != ADOPTION_SCOPE
        or document.get("disasterRecoveryReleaseArchiveSourceFormat") != ARCHIVE_FORMAT
        or document.get("disasterRecoveryReleaseArchiveObjectKey")
        != f"backups/recovery-releases/archives/{archive_sha}.tar"
        or document.get("disasterRecoveryReleaseSourceAuthorityObjectKey")
        != f"backups/recovery-releases/authorities/{authority_sha}.json"
        or not isinstance(document.get("disasterRecoveryRepositoryTree"), str)
        or HEX40.fullmatch(str(document.get("disasterRecoveryRepositoryTree"))) is None
        or not isinstance(document.get("disasterRecoveryReleaseArchiveContentManifestSha256"), str)
        or HEX64.fullmatch(str(document.get("disasterRecoveryReleaseArchiveContentManifestSha256"))) is None
        or not isinstance(document.get("restoreConfigurationSha256"), str)
        or HEX64.fullmatch(str(document.get("restoreConfigurationSha256"))) is None
    ):
        fail("Disaster-recovery receipt release authority differs.")
    return document, hashlib.sha256(raw).hexdigest()


def boundary_paths() -> dict[str, Path]:
    fixture = os.environ.get("MOCHIRII_HISTORICAL_BOUNDARY_ROOT", "")
    if fixture:
        root = Path(fixture).resolve()
        if root == Path("/tmp") or Path("/tmp") not in root.parents:
            fail("Historical fixture boundary must be one exact child of /tmp.")
        state = root / "var/lib/mochirii/forums"
        return {
            "state": state,
            "stage": state / "historical-recovery",
            "archives": state / "recovery-release-archives",
            "sources": root / "opt/mochirii/forums/recovery-releases",
            "configs": root / "var/discourse/containers/historical-recovery",
            "evidence": state / "evidence",
            "host_control_releases": root / "opt/mochirii/forums/host-control-releases",
            "deployment_source": root / "opt/mochirii/forums/deployment-source",
        }
    state = Path("/var/lib/mochirii/forums")
    return {
        "state": state,
        "stage": state / "historical-recovery",
        "archives": state / "recovery-release-archives",
        "sources": Path("/opt/mochirii/forums/recovery-releases"),
        "configs": Path("/var/discourse/containers/historical-recovery"),
        "evidence": state / "evidence",
        "host_control_releases": Path("/opt/mochirii/forums/host-control-releases"),
        "deployment_source": Path("/opt/mochirii/forums/deployment-source"),
    }


def exact_boundary(path: Path, expected: Path, label: str) -> None:
    if path != expected:
        fail(f"{label} escaped its fixed historical recovery boundary.")


def protected_authority_file(path: Path, label: str, maximum: int) -> tuple[int, str]:
    metadata = regular_file(path, label, maximum)
    if not os.environ.get("MOCHIRII_HISTORICAL_BOUNDARY_ROOT"):
        if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail(f"{label} has unsafe ownership or mode.")
    return sha256_file(path, maximum)


def read_recovery_context(
    current_host_control: Path,
    scratch_absence: Path,
    receipt_path: Path,
    receipt: dict[str, object],
    receipt_sha: str,
    bootstrap_commit: str,
    archive_sha: str,
) -> RecoveryContext:
    boundaries = boundary_paths()
    exact_boundary(current_host_control, boundaries["state"] / "current-host-control.json", "Current host-control evidence")
    exact_boundary(scratch_absence, boundaries["stage"] / "scratch-reader-absence.json", "Scratch-absence evidence")
    exact_boundary(receipt_path, boundaries["stage"] / "fetched-recovery-receipt.json", "Disaster-recovery receipt")
    _control_size, control_sha = protected_authority_file(
        current_host_control, "Current host-control evidence", MAX_STATE_BYTES
    )
    control = json.loads(current_host_control.read_bytes())
    control_keys = {
        "schemaVersion",
        "phase",
        "repositoryCommit",
        "repositoryTree",
        "manifestSha256",
        "targetSetSha256",
        "controlEvidenceFile",
        "controlEvidenceSha256",
        "releaseArchiveFile",
        "releaseArchiveSha256",
        "releaseArchiveBytes",
        "releaseArchiveContentManifestSha256",
        "deploymentSourceRevision",
        "deploymentSourceTree",
        "deploymentSourceArchiveFile",
        "deploymentSourceArchiveSha256",
        "deploymentSourceArchiveBytes",
        "deploymentSourceContentManifestSha256",
    }
    if (
        not isinstance(control, dict)
        or set(control) != control_keys
        or control.get("schemaVersion") != 1
        or control.get("phase") != "hardened"
        or control.get("repositoryCommit") != bootstrap_commit
        or any(HEX64.fullmatch(str(control.get(key, ""))) is None for key in (
            "manifestSha256", "targetSetSha256", "controlEvidenceSha256",
            "releaseArchiveSha256", "releaseArchiveContentManifestSha256",
            "deploymentSourceArchiveSha256", "deploymentSourceContentManifestSha256",
        ))
        or HEX40.fullmatch(str(control.get("repositoryTree", ""))) is None
        or (
            not os.environ.get("MOCHIRII_HISTORICAL_BOUNDARY_ROOT")
            and control.get("deploymentSourceRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b"
        )
        or (
            os.environ.get("MOCHIRII_HISTORICAL_BOUNDARY_ROOT")
            and HEX40.fullmatch(str(control.get("deploymentSourceRevision", ""))) is None
        )
        or (
            not os.environ.get("MOCHIRII_HISTORICAL_BOUNDARY_ROOT")
            and control.get("deploymentSourceTree") != "588498dffbea91592fd4e2f10166bc11c8fe7a61"
        )
    ):
        fail("Current host-control release differs from the exact C1 authority.")
    for path, file_key, sha_key, bytes_key in (
        (
            boundaries["host_control_releases"] / bootstrap_commit / "mochirii-release.tar",
            "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
        ),
        (
            boundaries["deployment_source"] / f"{control['deploymentSourceRevision']}.tar",
            "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
        ),
    ):
        if control.get(file_key) != str(path):
            fail("Current host-control retained archive path differs.")
        size, digest = protected_authority_file(path, "Current host-control retained archive", MAX_ARCHIVE_BYTES)
        if control.get(sha_key) != digest or control.get(bytes_key) != size:
            fail("Current host-control retained archive bytes differ.")
    _absence_size, absence_sha = protected_authority_file(
        scratch_absence, "Scratch-absence evidence", MAX_STATE_BYTES
    )
    absence = json.loads(scratch_absence.read_bytes())
    absence_keys = {
        "schemaVersion",
        "operation",
        "phase",
        "recordedAt",
        "bootstrapRepositoryCommit",
        "readerOperationId",
        "readerIntentSha256",
        "terminalReaderTransactionPhase",
        "terminalReaderTransactionSha256",
        "currentHostControlFile",
        "currentHostControlSha256",
        "disasterRecoveryReceiptFile",
        "disasterRecoveryReceiptSha256",
        "releaseArchiveFile",
        "releaseArchiveSha256",
        "scratchRoot",
        "scratchDirectoryAbsent",
        "readerContainerAbsent",
        "readerOperationImageIds",
        "readerOperationImageLabel",
        "readerOperationImagesAbsent",
        "readerProcessAbsent",
        "readerLauncherStateAbsent",
        "realPersistentTargetAbsent",
    }
    operation_id = absence.get("readerOperationId")
    if (
        not isinstance(absence, dict)
        or set(absence) != absence_keys
        or absence.get("schemaVersion") != 1
        or absence.get("operation") != "current-main-historical-recovery-reader"
        or absence.get("phase") != "scratch-absence-proved"
        or absence.get("bootstrapRepositoryCommit") != bootstrap_commit
        or not isinstance(operation_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None
        or absence.get("terminalReaderTransactionPhase") != "outputs-published"
        or HEX64.fullmatch(str(absence.get("terminalReaderTransactionSha256", ""))) is None
        or absence.get("currentHostControlFile") != str(current_host_control)
        or absence.get("currentHostControlSha256") != control_sha
        or absence.get("disasterRecoveryReceiptFile") != str(receipt_path)
        or absence.get("disasterRecoveryReceiptSha256") != receipt_sha
        or absence.get("releaseArchiveFile") != str(boundaries["stage"] / "fetched-release.tar")
        or absence.get("releaseArchiveSha256") != archive_sha
        or absence.get("scratchRoot") != str(boundaries["state"] / "historical-reader" / operation_id)
        or not isinstance(absence.get("readerOperationImageIds"), list)
        or absence["readerOperationImageIds"] != sorted(set(absence["readerOperationImageIds"]))
        or len(absence["readerOperationImageIds"]) != 1
        or any(not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in absence["readerOperationImageIds"])
        or absence.get("readerOperationImageLabel") != f"mochirii.forums.historical-reader={operation_id}"
        or any(absence.get(key) is not True for key in (
            "scratchDirectoryAbsent",
            "readerContainerAbsent",
            "readerOperationImagesAbsent",
            "readerProcessAbsent",
            "readerLauncherStateAbsent",
            "realPersistentTargetAbsent",
        ))
        or receipt.get("disasterRecoveryBootstrapCommit") != bootstrap_commit
    ):
        fail("Scratch-reader absence evidence differs from the exact C1 recovery authority.")
    return RecoveryContext(
        current_host_control_file=current_host_control,
        current_host_control_sha256=control_sha,
        scratch_absence_file=scratch_absence,
        scratch_absence_sha256=absence_sha,
        reader_operation_id=operation_id,
    )


def inspect_document(identity: ArchiveIdentity) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "repositoryCommit": identity.repository_commit,
        "repositoryTree": identity.repository_tree,
        "releaseArchiveSha256": identity.archive_sha256,
        "releaseArchiveBytes": identity.archive_bytes,
        "releaseArchiveContentManifestSha256": identity.content_manifest_sha256,
        "releaseArchiveSourceFormat": ARCHIVE_FORMAT,
        "containsSecrets": False,
        "containsSignedUrls": False,
        "ordinaryDeploymentRequiresCurrentMain": True,
        "historicalReleaseAdoptionScope": ADOPTION_SCOPE,
    }


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # Windows does not expose a Python directory handle that fsync accepts;
        # production clean-host recovery is Linux and takes this durability path.
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_file_exact(source: Path, target: Path, expected_sha: str, expected_size: int) -> None:
    parent = safe_parent(target, "Sealed archive")
    if target.exists() or target.is_symlink():
        regular_file(target, "Existing sealed archive", MAX_ARCHIVE_BYTES)
        size, digest = sha256_file(target, MAX_ARCHIVE_BYTES)
        if size != expected_size or digest != expected_sha:
            fail("Existing sealed archive differs from recovery authority.")
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".partial", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as destination, source.open("rb") as origin:
            shutil.copyfileobj(origin, destination, length=64 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        size, digest = sha256_file(temporary, MAX_ARCHIVE_BYTES)
        if size != expected_size or digest != expected_sha:
            fail("Copied sealed archive differs from recovery authority.")
        os.link(temporary, target, follow_symlinks=False)
        fsync_directory(parent)
        temporary.unlink()
        fsync_directory(parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            fsync_directory(parent)


def source_identity(path: Path) -> tuple[str, str]:
    try:
        root_metadata = path.lstat()
    except FileNotFoundError as error:
        raise RecoveryError("Prepared historical source is absent.") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        fail("Prepared historical source is linked or non-directory.")
    files: list[FileEntry] = []
    for entry in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix().encode("ascii")):
        metadata = entry.lstat()
        relative = entry.relative_to(path).as_posix()
        safe_member_name(relative)
        if stat.S_ISDIR(metadata.st_mode):
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
                fail("Prepared historical source directory is writable outside its owner.")
            continue
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail("Prepared historical source contains a linked or non-regular entry.")
        if metadata.st_size > MAX_MEMBER_BYTES:
            fail("Prepared historical source file exceeds its byte boundary.")
        payload = entry.read_bytes()
        executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
        files.append(
            FileEntry(
                path=relative,
                size=len(payload),
                executable=executable,
                sha256=hashlib.sha256(payload).hexdigest(),
                git_blob=git_object(b"blob", payload),
            )
        )
    if not REQUIRED_SOURCE_FILES.issubset({entry.path for entry in files}):
        fail("Prepared historical source lacks required files.")
    return build_tree(files), manifest_digest(files)


def extract_exact(archive: Path, identity: ArchiveIdentity, destination: Path) -> None:
    parent = safe_parent(destination, "Prepared source")
    if destination.name != identity.repository_commit:
        fail("Prepared source directory is not named by the recovered commit.")
    if destination.exists() or destination.is_symlink():
        tree, manifest = source_identity(destination)
        if tree != identity.repository_tree or manifest != identity.content_manifest_sha256:
            fail("Existing prepared source differs from the historical release authority.")
        return
    candidate = Path(tempfile.mkdtemp(prefix=f".{identity.repository_commit}.", suffix=".partial", dir=parent))
    try:
        os.chmod(candidate, 0o700)
        with tarfile.open(archive, mode="r:") as source:
            for member in source.getmembers():
                parts = safe_member_name(member.name)
                target = candidate.joinpath(*parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    os.chmod(target, 0o755)
                    continue
                if not member.isfile():
                    fail("Release archive contains a forbidden member type.")
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = source.extractfile(member)
                if extracted is None:
                    fail("Release archive member bytes are unavailable.")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(target, flags, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(extracted, output, length=64 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
        for directory in sorted(
            (entry for entry in candidate.rglob("*") if entry.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            os.chmod(directory, 0o755)
            fsync_directory(directory)
        os.chmod(candidate, 0o755)
        fsync_directory(candidate)
        tree, manifest = source_identity(candidate)
        if tree != identity.repository_tree or manifest != identity.content_manifest_sha256:
            fail("Extracted historical source differs from its archive authority.")
        os.rename(candidate, destination)
        fsync_directory(parent)
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)
            fsync_directory(parent)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_state(path: Path, document: dict[str, object]) -> None:
    parent = safe_parent(path, "Historical adoption state")
    payload = canonical(document, pretty=True)
    if len(payload) > MAX_STATE_BYTES:
        fail("Historical adoption state exceeds its byte boundary.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        fsync_directory(parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            fsync_directory(parent)


def read_state(path: Path) -> dict[str, object]:
    regular_file(path, "Historical adoption state", MAX_STATE_BYTES)
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryError("Historical adoption state is malformed.") from error
    if not isinstance(value, dict):
        fail("Historical adoption state is not one object.")
    return value


def stable_state(
    receipt: dict[str, object],
    receipt_sha: str,
    receipt_file: Path,
    identity: ArchiveIdentity,
    bootstrap_commit: str,
    sealed_archive: Path,
    source_dir: Path,
    context: RecoveryContext,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "operation": "historical-release-clean-target-adoption",
        "historicalReleaseAdoptionScope": ADOPTION_SCOPE,
        "ordinaryDeploymentRequiresCurrentMain": True,
        "bootstrapRepositoryCommit": bootstrap_commit,
        "recoveredRepositoryCommit": identity.repository_commit,
        "recoveredRepositoryTree": identity.repository_tree,
        "recoveredProductionConfigurationSha256": receipt["productionConfigurationSha256"],
        "recoveredRestoreConfigurationSha256": receipt["restoreConfigurationSha256"],
        "disasterRecoveryReceiptFile": str(receipt_file),
        "releaseArchiveFile": str(sealed_archive),
        "releaseArchiveSha256": identity.archive_sha256,
        "releaseArchiveBytes": identity.archive_bytes,
        "releaseArchiveContentManifestSha256": identity.content_manifest_sha256,
        "releaseArchiveSourceFormat": ARCHIVE_FORMAT,
        "preparedSourceDirectory": str(source_dir),
        "disasterRecoveryReceiptSha256": receipt_sha,
        "disasterRecoveryPointerObjectSha256": receipt["disasterRecoveryPointerObjectSha256"],
        "disasterRecoveryEvidenceObjectSha256": receipt["disasterRecoveryEvidenceObjectSha256"],
        "disasterRecoveryReleaseSourceAuthoritySha256": receipt[
            "disasterRecoveryReleaseSourceAuthoritySha256"
        ],
        "currentHostControlFile": str(context.current_host_control_file),
        "currentHostControlSha256": context.current_host_control_sha256,
        "scratchAbsenceEvidenceFile": str(context.scratch_absence_file),
        "scratchAbsenceEvidenceSha256": context.scratch_absence_sha256,
        "readerOperationId": context.reader_operation_id,
        "privateRecoveryAuthorityPassed": True,
        "containsSecrets": False,
        "containsSignedUrls": False,
    }


def validate_state(
    state: dict[str, object],
    stable: dict[str, object],
    allowed_phases: set[str],
) -> None:
    dynamic = {
        "phase",
        "recordedAt",
        "updatedAt",
        "productionConfigurationFile",
        "restoreConfigurationFile",
        "bootstrapReleaseEvidenceFile",
        "bootstrapReleaseEvidenceSha256",
        "restoreTerminalEvidenceFile",
        "restoreTerminalEvidenceSha256",
        "cleanBackupEvidenceFile",
        "cleanBackupEvidenceSha256",
        "completionRecordedAt",
    }
    if set(state) != set(stable) | dynamic:
        fail("Historical adoption state schema differs.")
    if state.get("phase") not in allowed_phases:
        fail("Historical adoption state phase differs.")
    for key, value in stable.items():
        if state.get(key) != value:
            fail(f"Historical adoption state binding differs: {key}.")
    for key in ("recordedAt", "updatedAt"):
        if not isinstance(state.get(key), str) or not str(state[key]).endswith("Z"):
            fail("Historical adoption state timestamp is malformed.")
    if state.get("phase") == "source-prepared":
        if state.get("productionConfigurationFile") is not None or state.get("restoreConfigurationFile") is not None:
            fail("Source-prepared state prematurely selected a configuration.")
    else:
        for key in ("productionConfigurationFile", "restoreConfigurationFile"):
            value = state.get(key)
            if not isinstance(value, str) or not Path(value).is_absolute():
                fail("Authorized historical configuration path is malformed.")
    bootstrap_pairs = (
        ("bootstrapReleaseEvidenceFile", "bootstrapReleaseEvidenceSha256"),
        ("restoreTerminalEvidenceFile", "restoreTerminalEvidenceSha256"),
        ("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256"),
    )
    for path_key, digest_key in bootstrap_pairs:
        path_value = state.get(path_key)
        digest_value = state.get(digest_key)
        if (path_value is None) != (digest_value is None):
            fail("Historical adoption terminal evidence binding is incomplete.")
        if path_value is not None and (
            not isinstance(path_value, str)
            or not Path(path_value).is_absolute()
            or not isinstance(digest_value, str)
            or HEX64.fullmatch(digest_value) is None
        ):
            fail("Historical adoption terminal evidence binding is malformed.")
    phase = str(state.get("phase"))
    if phase in {"source-prepared", "configuration-authorized", "bootstrap-started"}:
        if any(state.get(key) is not None for pair in bootstrap_pairs for key in pair):
            fail("Historical adoption recorded terminal evidence before bootstrap completion.")
        if state.get("completionRecordedAt") is not None:
            fail("Historical adoption recorded a completion timestamp prematurely.")
    elif phase == "bootstrap-complete":
        if state.get("bootstrapReleaseEvidenceFile") is None:
            fail("Historical bootstrap completion evidence is absent.")
        if any(state.get(key) is not None for pair in bootstrap_pairs[1:] for key in pair):
            fail("Historical restore evidence was recorded before restore start.")
        if state.get("completionRecordedAt") is not None:
            fail("Historical adoption recorded a completion timestamp prematurely.")
    elif phase == "restore-started":
        if state.get("bootstrapReleaseEvidenceFile") is None:
            fail("Historical restore lacks bootstrap completion evidence.")
        if any(state.get(key) is not None for pair in bootstrap_pairs[1:] for key in pair):
            fail("Historical restore-started state prematurely recorded terminal evidence.")
        if state.get("completionRecordedAt") is not None:
            fail("Historical restore-started state prematurely recorded completion.")
    elif phase == "restore-complete":
        if any(state.get(key) is None for pair in bootstrap_pairs for key in pair):
            fail("Historical restore completion evidence is incomplete.")
        if not isinstance(state.get("completionRecordedAt"), str) or not str(state["completionRecordedAt"]).endswith("Z"):
            fail("Historical restore completion timestamp is malformed.")


def command_inspect(args: argparse.Namespace) -> None:
    expected = args.expected_commit
    if expected is not None and HEX40.fullmatch(expected) is None:
        fail("Expected release commit is malformed.")
    identity = inspect_archive(args.archive, expected)
    print(canonical(inspect_document(identity)).decode("utf-8"), end="")


def command_prepare(args: argparse.Namespace) -> None:
    if args.confirmation != CONFIRMATION:
        fail("Historical release preparation confirmation differs.")
    if HEX40.fullmatch(args.bootstrap_commit) is None:
        fail("Bootstrap current-main commit is malformed.")
    boundaries = boundary_paths()
    exact_boundary(args.receipt, boundaries["stage"] / "fetched-recovery-receipt.json", "Disaster-recovery receipt")
    exact_boundary(args.archive, boundaries["stage"] / "fetched-release.tar", "Fetched historical archive")
    exact_boundary(args.journal, boundaries["state"] / "historical-release-adoption.json", "Historical adoption journal")
    receipt, receipt_sha = read_receipt(args.receipt)
    if receipt["disasterRecoveryBootstrapCommit"] != args.bootstrap_commit:
        fail("Bootstrap commit differs from the private recovery receipt.")
    identity = inspect_archive(args.archive, str(receipt["repositoryCommit"]))
    expected = {
        "repository_tree": receipt["disasterRecoveryRepositoryTree"],
        "archive_sha256": receipt["disasterRecoveryReleaseArchiveSha256"],
        "archive_bytes": receipt["disasterRecoveryReleaseArchiveBytes"],
        "content_manifest_sha256": receipt["disasterRecoveryReleaseArchiveContentManifestSha256"],
    }
    for field, value in expected.items():
        if getattr(identity, field) != value:
            fail(f"Historical release archive {field} differs from recovery authority.")
    exact_boundary(
        args.sealed_archive,
        boundaries["archives"] / f"{identity.repository_commit}-{identity.archive_sha256}.tar",
        "Sealed historical archive",
    )
    exact_boundary(
        args.source_dir,
        boundaries["sources"] / identity.repository_commit,
        "Prepared historical source",
    )
    context = read_recovery_context(
        args.current_host_control,
        args.scratch_absence,
        args.receipt,
        receipt,
        receipt_sha,
        args.bootstrap_commit,
        identity.archive_sha256,
    )
    install_file_exact(args.archive, args.sealed_archive, identity.archive_sha256, identity.archive_bytes)
    extract_exact(args.sealed_archive, identity, args.source_dir)
    stable = stable_state(
        receipt,
        receipt_sha,
        args.receipt,
        identity,
        args.bootstrap_commit,
        args.sealed_archive,
        args.source_dir,
        context,
    )
    timestamp = now()
    if args.journal.exists() or args.journal.is_symlink():
        existing = read_state(args.journal)
        validate_state(existing, stable, {"source-prepared", "configuration-authorized"})
        return
    document = {
        **stable,
        "phase": "source-prepared",
        "recordedAt": timestamp,
        "updatedAt": timestamp,
        "productionConfigurationFile": None,
        "restoreConfigurationFile": None,
        "bootstrapReleaseEvidenceFile": None,
        "bootstrapReleaseEvidenceSha256": None,
        "restoreTerminalEvidenceFile": None,
        "restoreTerminalEvidenceSha256": None,
        "cleanBackupEvidenceFile": None,
        "cleanBackupEvidenceSha256": None,
        "completionRecordedAt": None,
    }
    atomic_state(args.journal, document)


def recovery_authority(
    receipt_path: Path, journal_path: Path
) -> tuple[dict[str, object], str, dict[str, object], ArchiveIdentity, dict[str, object]]:
    receipt, receipt_sha = read_receipt(receipt_path)
    state = read_state(journal_path)
    boundaries = boundary_paths()
    exact_boundary(receipt_path, boundaries["stage"] / "fetched-recovery-receipt.json", "Disaster-recovery receipt")
    exact_boundary(journal_path, boundaries["state"] / "historical-release-adoption.json", "Historical adoption journal")
    archive = Path(str(state.get("releaseArchiveFile", "")))
    source_dir = Path(str(state.get("preparedSourceDirectory", "")))
    bootstrap = str(state.get("bootstrapRepositoryCommit", ""))
    exact_boundary(
        archive,
        boundaries["archives"] / f"{receipt['repositoryCommit']}-{receipt['disasterRecoveryReleaseArchiveSha256']}.tar",
        "Sealed historical archive",
    )
    exact_boundary(source_dir, boundaries["sources"] / str(receipt["repositoryCommit"]), "Prepared historical source")
    identity = inspect_archive(archive, str(receipt["repositoryCommit"]))
    context = read_recovery_context(
        Path(str(state.get("currentHostControlFile", ""))),
        Path(str(state.get("scratchAbsenceEvidenceFile", ""))),
        receipt_path,
        receipt,
        receipt_sha,
        bootstrap,
        identity.archive_sha256,
    )
    stable = stable_state(
        receipt,
        receipt_sha,
        receipt_path,
        identity,
        bootstrap,
        archive,
        source_dir,
        context,
    )
    return receipt, receipt_sha, state, identity, stable


def validate_prepared_source(state: dict[str, object], identity: ArchiveIdentity) -> None:
    source_dir = Path(str(state["preparedSourceDirectory"]))
    tree, manifest = source_identity(source_dir)
    if tree != identity.repository_tree or manifest != identity.content_manifest_sha256:
        fail("Prepared historical source changed after authorization.")


def validate_authorized_configurations(state: dict[str, object]) -> None:
    for key, digest_key in (
        ("productionConfigurationFile", "recoveredProductionConfigurationSha256"),
        ("restoreConfigurationFile", "recoveredRestoreConfigurationSha256"),
    ):
        path = Path(str(state[key]))
        regular_file(path, "Authorized historical configuration", 1024 * 1024)
        _size, digest = sha256_file(path, 1024 * 1024)
        if digest != state[digest_key]:
            fail("Authorized historical configuration changed.")


def command_authorize(args: argparse.Namespace) -> None:
    if args.confirmation != AUTHORIZE_CONFIRMATION:
        fail("Historical release authorization confirmation differs.")
    receipt, _receipt_sha, state, identity, stable = recovery_authority(args.receipt, args.journal)
    validate_state(state, stable, {"source-prepared", "configuration-authorized"})
    validate_prepared_source(state, identity)
    boundaries = boundary_paths()
    exact_boundary(
        args.production_config,
        boundaries["configs"] / str(receipt["repositoryCommit"]) / "app.yml",
        "Historical production configuration",
    )
    exact_boundary(
        args.restore_config,
        boundaries["configs"] / str(receipt["repositoryCommit"]) / "restore.yml",
        "Historical restore configuration",
    )
    for path, receipt_key, label in (
        (args.production_config, "productionConfigurationSha256", "Production configuration"),
        (args.restore_config, "restoreConfigurationSha256", "Restore configuration"),
    ):
        regular_file(path, label, 1024 * 1024)
        _size, digest = sha256_file(path, 1024 * 1024)
        if digest != receipt[receipt_key]:
            fail(f"{label} differs from the recovered release evidence.")
    if state["phase"] == "configuration-authorized":
        if (
            state["productionConfigurationFile"] != str(args.production_config)
            or state["restoreConfigurationFile"] != str(args.restore_config)
        ):
            fail("Authorized historical configuration paths changed on retry.")
        return
    document = {
        **stable,
        "phase": "configuration-authorized",
        "recordedAt": state["recordedAt"],
        "updatedAt": now(),
        "productionConfigurationFile": str(args.production_config),
        "restoreConfigurationFile": str(args.restore_config),
        "bootstrapReleaseEvidenceFile": None,
        "bootstrapReleaseEvidenceSha256": None,
        "restoreTerminalEvidenceFile": None,
        "restoreTerminalEvidenceSha256": None,
        "cleanBackupEvidenceFile": None,
        "cleanBackupEvidenceSha256": None,
        "completionRecordedAt": None,
    }
    atomic_state(args.journal, document)


def command_verify(args: argparse.Namespace) -> None:
    _receipt, _receipt_sha, state, identity, stable = recovery_authority(args.receipt, args.journal)
    validate_state(state, stable, {args.require_phase})
    validate_prepared_source(state, identity)
    if args.require_phase != "source-prepared":
        validate_authorized_configurations(state)
    print("Historical disaster-recovery release authorization verified.")


def transition_state(
    journal: Path,
    state: dict[str, object],
    stable: dict[str, object],
    phase: str,
    **updates: object,
) -> None:
    document = {**state, **stable, **updates, "phase": phase, "updatedAt": now()}
    atomic_state(journal, document)


def command_begin_bootstrap(args: argparse.Namespace) -> None:
    if args.confirmation != BEGIN_BOOTSTRAP_CONFIRMATION:
        fail("Historical bootstrap confirmation differs.")
    _receipt, _receipt_sha, state, identity, stable = recovery_authority(args.receipt, args.journal)
    validate_state(state, stable, {"configuration-authorized", "bootstrap-started"})
    validate_prepared_source(state, identity)
    validate_authorized_configurations(state)
    if state["phase"] == "configuration-authorized":
        transition_state(args.journal, state, stable, "bootstrap-started")


def validate_bootstrap_release(
    current_release: Path,
    release_evidence: Path,
    receipt: dict[str, object],
    state: dict[str, object],
    identity: ArchiveIdentity,
) -> str:
    boundaries = boundary_paths()
    commit = str(receipt["repositoryCommit"])
    configuration = str(receipt["productionConfigurationSha256"])
    exact_boundary(current_release, boundaries["state"] / "current-release.json", "Current release evidence")
    exact_boundary(
        release_evidence,
        boundaries["evidence"] / f"{commit}-{configuration}-release.json",
        "Bootstrap release evidence",
    )
    _pointer_size, _pointer_sha = protected_authority_file(current_release, "Current release evidence", MAX_STATE_BYTES)
    _record_size, record_sha = protected_authority_file(release_evidence, "Bootstrap release evidence", MAX_STATE_BYTES)
    pointer = json.loads(current_release.read_bytes())
    if set(pointer) != {
        "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
        "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
        "memberRolloutMarkerSha256",
    } or (
        pointer.get("repositoryCommit") != commit
        or pointer.get("productionConfigurationSha256") != configuration
        or pointer.get("releaseEvidenceFile") != release_evidence.name
        or pointer.get("releaseEvidenceSha256") != record_sha
        or pointer.get("discourseConnectEnabled") is not False
        or pointer.get("memberRolloutMarkerFile") is not None
        or pointer.get("memberRolloutMarkerSha256") is not None
    ):
        fail("Current release does not select the exact recovered bootstrap tuple.")
    document = json.loads(release_evidence.read_bytes())
    required = {
        "schemaVersion", "recordedAt", "repositoryCommit", "repositoryTree",
        "releaseArchiveSha256", "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
        "discourseDockerRevision", "discourseRevision", "dockerManagerRevision", "baseImageDigest",
        "productionConfigurationSha256", "restoreConfigurationSha256",
        "containedActivationConfigurationSha256", "containedActivationPassed", "activationPhase",
        "themeArchiveSha256", "mailMetadataPluginSha256", "discourseConnectEnabled",
        "memberRolloutMarkerFile", "memberRolloutMarkerSha256", "hostVerificationPassed",
        "storageEvidenceFile", "storageEvidenceSha256", "hostedStoragePassed",
        "storageRestartPersistencePassed", "storageRebuildPersistencePassed", "storageCleanupPassed",
    }
    expected = {
        "repositoryCommit": commit,
        "repositoryTree": identity.repository_tree,
        "releaseArchiveSha256": identity.archive_sha256,
        "releaseArchiveBytes": identity.archive_bytes,
        "releaseArchiveContentManifestSha256": identity.content_manifest_sha256,
        "productionConfigurationSha256": configuration,
        "restoreConfigurationSha256": receipt["restoreConfigurationSha256"],
        "themeArchiveSha256": receipt["themeArchiveSha256"],
        "mailMetadataPluginSha256": receipt["mailMetadataPluginSha256"],
        "discourseDockerRevision": receipt["discourseDockerRevision"],
        "discourseRevision": receipt["discourseRevision"],
        "dockerManagerRevision": receipt["dockerManagerRevision"],
        "baseImageDigest": receipt["baseImageDigest"],
    }
    if (
        set(document) != required
        or document.get("schemaVersion") != 2
        or any(document.get(key) != value for key, value in expected.items())
        or document.get("discourseConnectEnabled") is not False
        or document.get("memberRolloutMarkerFile") is not None
        or document.get("memberRolloutMarkerSha256") is not None
        or document.get("activationPhase") != "consumer-disabled"
        or document.get("containedActivationPassed") is not False
        or any(document.get(key) is not True for key in (
            "hostVerificationPassed", "hostedStoragePassed", "storageRestartPersistencePassed",
            "storageRebuildPersistencePassed", "storageCleanupPassed",
        ))
    ):
        fail("Regenerated bootstrap release evidence differs from the recovered release authority.")
    for key, digest_key in (
        ("productionConfigurationFile", "productionConfigurationSha256"),
        ("restoreConfigurationFile", "restoreConfigurationSha256"),
    ):
        path = Path(str(state[key]))
        _size, digest = sha256_file(path, 1024 * 1024)
        if digest != document[digest_key]:
            fail("Regenerated release evidence differs from its authorized configuration bytes.")
    return record_sha


def command_complete_bootstrap(args: argparse.Namespace) -> None:
    if args.confirmation != COMPLETE_BOOTSTRAP_CONFIRMATION:
        fail("Historical bootstrap completion confirmation differs.")
    receipt, _receipt_sha, state, identity, stable = recovery_authority(args.receipt, args.journal)
    validate_state(state, stable, {"bootstrap-started", "bootstrap-complete"})
    validate_prepared_source(state, identity)
    validate_authorized_configurations(state)
    release_sha = validate_bootstrap_release(args.current_release, args.release_evidence, receipt, state, identity)
    if state["phase"] == "bootstrap-complete":
        if state["bootstrapReleaseEvidenceFile"] != str(args.release_evidence) or state["bootstrapReleaseEvidenceSha256"] != release_sha:
            fail("Bootstrap completion evidence changed on retry.")
        return
    transition_state(
        args.journal,
        state,
        stable,
        "bootstrap-complete",
        bootstrapReleaseEvidenceFile=str(args.release_evidence),
        bootstrapReleaseEvidenceSha256=release_sha,
    )


def command_begin_restore(args: argparse.Namespace) -> None:
    if args.confirmation != BEGIN_RESTORE_CONFIRMATION:
        fail("Historical restore confirmation differs.")
    receipt, _receipt_sha, state, identity, stable = recovery_authority(args.receipt, args.journal)
    validate_state(state, stable, {"bootstrap-complete", "restore-started"})
    release_path = Path(str(state["bootstrapReleaseEvidenceFile"]))
    current_release = boundary_paths()["state"] / "current-release.json"
    validate_bootstrap_release(current_release, release_path, receipt, state, identity)
    if state["phase"] == "bootstrap-complete":
        transition_state(args.journal, state, stable, "restore-started")


def publish_completion(path: Path, document: dict[str, object]) -> str:
    payload = canonical(document, pretty=True)
    if path.exists() or path.is_symlink():
        protected_authority_file(path, "Historical recovery completion evidence", MAX_STATE_BYTES)
        if path.read_bytes() != payload:
            fail("Existing historical recovery completion evidence differs.")
        return hashlib.sha256(payload).hexdigest()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, path, follow_symlinks=False)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def command_complete(args: argparse.Namespace) -> None:
    if args.confirmation != COMPLETE_RECOVERY_CONFIRMATION:
        fail("Historical recovery completion confirmation differs.")
    receipt, receipt_sha, state, identity, stable = recovery_authority(args.receipt, args.journal)
    validate_state(state, stable, {"restore-started", "restore-complete"})
    release_path = Path(str(state["bootstrapReleaseEvidenceFile"]))
    release_sha = validate_bootstrap_release(args.current_release, release_path, receipt, state, identity)
    boundaries = boundary_paths()
    exact_boundary(args.restore_terminal, boundaries["state"] / "current-restore.json", "Restore terminal evidence")
    _terminal_size, terminal_sha = protected_authority_file(args.restore_terminal, "Restore terminal evidence", MAX_STATE_BYTES)
    terminal = json.loads(args.restore_terminal.read_bytes())
    if (
        terminal.get("schemaVersion") != 1
        or terminal.get("phase") != "complete"
        or terminal.get("restoreMode") != "clean-target-disaster"
        or terminal.get("repositoryCommit") != receipt["repositoryCommit"]
        or terminal.get("productionConfigurationSha256") != receipt["productionConfigurationSha256"]
        or terminal.get("cleanBackupEvidenceFile") != str(args.clean_backup)
    ):
        fail("Restore terminal evidence does not complete the exact historical recovery tuple.")
    _clean_size, clean_sha = protected_authority_file(args.clean_backup, "Final clean backup evidence", MAX_STATE_BYTES)
    if terminal.get("cleanBackupEvidenceSha256") != clean_sha:
        fail("Restore terminal clean-backup binding differs.")
    clean = json.loads(args.clean_backup.read_bytes())
    if (
        clean.get("repositoryCommit") != receipt["repositoryCommit"]
        or clean.get("productionConfigurationSha256") != receipt["productionConfigurationSha256"]
        or clean.get("releaseEvidenceFile") != release_path.name
        or clean.get("releaseEvidenceSha256") != release_sha
        or clean.get("finalCleanAfterRestore") is not True
        or clean.get("recoveryUploadIncluded") is not False
        or clean.get("disasterRecoveryImported") is not True
    ):
        fail("Final clean backup evidence does not close the historical recovery chain.")
    exact_boundary(args.backup_pointer, boundaries["state"] / "latest-backup-evidence", "Latest backup evidence pointer")
    protected_authority_file(args.backup_pointer, "Latest backup evidence pointer", MAX_STATE_BYTES)
    try:
        pointer_value = args.backup_pointer.read_text(encoding="utf-8").rstrip("\n")
    except UnicodeDecodeError as error:
        raise RecoveryError("Latest backup evidence pointer is malformed.") from error
    if pointer_value != str(args.clean_backup) or args.backup_pointer.read_bytes() != (str(args.clean_backup) + "\n").encode("utf-8"):
        fail("Latest backup evidence pointer does not select the exact final clean backup.")
    if state["phase"] == "restore-started":
        completion_timestamp = now()
        transition_state(
            args.journal,
            state,
            stable,
            "restore-complete",
            restoreTerminalEvidenceFile=str(args.restore_terminal),
            restoreTerminalEvidenceSha256=terminal_sha,
            cleanBackupEvidenceFile=str(args.clean_backup),
            cleanBackupEvidenceSha256=clean_sha,
            completionRecordedAt=completion_timestamp,
        )
        state = read_state(args.journal)
        validate_state(state, stable, {"restore-complete"})
        if (
            os.environ.get("MOCHIRII_HISTORICAL_BOUNDARY_ROOT")
            and os.environ.get("MOCHIRII_HISTORICAL_FIXTURE_CRASH_AFTER")
            == "restore-complete-transition"
        ):
            fail("Historical fixture stopped after the durable restore-complete transition.")
    else:
        if (
            state["restoreTerminalEvidenceFile"] != str(args.restore_terminal)
            or state["restoreTerminalEvidenceSha256"] != terminal_sha
            or state["cleanBackupEvidenceFile"] != str(args.clean_backup)
            or state["cleanBackupEvidenceSha256"] != clean_sha
        ):
            fail("Historical restore-complete evidence changed on retry.")
    completion_timestamp = str(state["completionRecordedAt"])
    completion = boundaries["evidence"] / f"{receipt['repositoryCommit']}-{receipt['productionConfigurationSha256']}-historical-recovery-complete.json"
    document = {
        "schemaVersion": 1,
        "phase": "complete",
        "operation": "historical-release-clean-target-adoption",
        "bootstrapRepositoryCommit": state["bootstrapRepositoryCommit"],
        "recoveredRepositoryCommit": state["recoveredRepositoryCommit"],
        "readerOperationId": state["readerOperationId"],
        "disasterRecoveryReceiptFile": str(args.receipt),
        "disasterRecoveryReceiptSha256": receipt_sha,
        "originalReleaseEvidenceSha256": receipt["releaseEvidenceSha256"],
        "regeneratedReleaseEvidenceFile": str(release_path),
        "regeneratedReleaseEvidenceSha256": release_sha,
        "restoreTerminalEvidenceFile": str(args.restore_terminal),
        "restoreTerminalEvidenceSha256": terminal_sha,
        "cleanBackupEvidenceFile": str(args.clean_backup),
        "cleanBackupEvidenceSha256": clean_sha,
        "recordedAt": completion_timestamp,
    }
    publish_completion(completion, document)
    args.journal.unlink()
    fsync_directory(args.journal.parent)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subcommands = value.add_subparsers(dest="command", required=True)

    inspect = subcommands.add_parser("inspect")
    inspect.add_argument("--archive", type=Path, required=True)
    inspect.add_argument("--expected-commit")
    inspect.set_defaults(handler=command_inspect)

    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--receipt", type=Path, required=True)
    prepare.add_argument("--archive", type=Path, required=True)
    prepare.add_argument("--bootstrap-commit", required=True)
    prepare.add_argument("--sealed-archive", type=Path, required=True)
    prepare.add_argument("--source-dir", type=Path, required=True)
    prepare.add_argument("--journal", type=Path, required=True)
    prepare.add_argument("--current-host-control", type=Path, required=True)
    prepare.add_argument("--scratch-absence", type=Path, required=True)
    prepare.add_argument("--confirmation", required=True)
    prepare.set_defaults(handler=command_prepare)

    authorize = subcommands.add_parser("authorize")
    authorize.add_argument("--receipt", type=Path, required=True)
    authorize.add_argument("--journal", type=Path, required=True)
    authorize.add_argument("--production-config", type=Path, required=True)
    authorize.add_argument("--restore-config", type=Path, required=True)
    authorize.add_argument("--confirmation", required=True)
    authorize.set_defaults(handler=command_authorize)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--journal", type=Path, required=True)
    verify.add_argument(
        "--require-phase",
        choices=("source-prepared", "configuration-authorized", "bootstrap-started", "bootstrap-complete", "restore-started", "restore-complete"),
        default="configuration-authorized",
    )
    verify.set_defaults(handler=command_verify)

    begin_bootstrap = subcommands.add_parser("begin-bootstrap")
    begin_bootstrap.add_argument("--receipt", type=Path, required=True)
    begin_bootstrap.add_argument("--journal", type=Path, required=True)
    begin_bootstrap.add_argument("--confirmation", required=True)
    begin_bootstrap.set_defaults(handler=command_begin_bootstrap)

    complete_bootstrap = subcommands.add_parser("complete-bootstrap")
    complete_bootstrap.add_argument("--receipt", type=Path, required=True)
    complete_bootstrap.add_argument("--journal", type=Path, required=True)
    complete_bootstrap.add_argument("--current-release", type=Path, required=True)
    complete_bootstrap.add_argument("--release-evidence", type=Path, required=True)
    complete_bootstrap.add_argument("--confirmation", required=True)
    complete_bootstrap.set_defaults(handler=command_complete_bootstrap)

    begin_restore = subcommands.add_parser("begin-restore")
    begin_restore.add_argument("--receipt", type=Path, required=True)
    begin_restore.add_argument("--journal", type=Path, required=True)
    begin_restore.add_argument("--confirmation", required=True)
    begin_restore.set_defaults(handler=command_begin_restore)

    complete = subcommands.add_parser("complete")
    complete.add_argument("--receipt", type=Path, required=True)
    complete.add_argument("--journal", type=Path, required=True)
    complete.add_argument("--current-release", type=Path, required=True)
    complete.add_argument("--restore-terminal", type=Path, required=True)
    complete.add_argument("--clean-backup", type=Path, required=True)
    complete.add_argument("--backup-pointer", type=Path, required=True)
    complete.add_argument("--confirmation", required=True)
    complete.set_defaults(handler=command_complete)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (OSError, RecoveryError, tarfile.TarError, ValueError) as error:
        print(f"Historical disaster-recovery release operation failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
