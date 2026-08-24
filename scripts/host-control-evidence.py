#!/usr/bin/env python3
"""Seal non-secret host-access and installed-control evidence durably."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import tarfile
from pathlib import PurePosixPath


STATE_ROOT = Path("/var/lib/mochirii/forums")
EVIDENCE_ROOT = STATE_ROOT / "evidence"
DEPLOYMENT_SOURCE_COMMIT = "ed9f680b0df1de28f062de1769d89d22b2644d1b"
DEPLOYMENT_SOURCE_TREE = "588498dffbea91592fd4e2f10166bc11c8fe7a61"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024


def git_object(kind: bytes, payload: bytes) -> bytes:
    return hashlib.sha1(kind + b" " + str(len(payload)).encode("ascii") + b"\0" + payload).digest()


def archive_identity(path: Path, expected_commit: str) -> dict[str, object]:
    raw = protected_regular(path, 0o600, maximum=MAX_ARCHIVE_BYTES)
    files: list[tuple[str, int, str, bytes]] = []
    seen: set[str] = set()
    expanded = 0
    with tarfile.open(path, mode="r:") as source:
        if set(source.pax_headers) != {"comment"} or source.pax_headers.get("comment") != expected_commit:
            fail(f"retained recovery archive commit differs: {path}")
        members = source.getmembers()
        if not 1 <= len(members) <= 4096:
            fail(f"retained recovery archive inventory differs: {path}")
        for member in members:
            raw_name = member.name.rstrip("/")
            if not raw_name or not raw_name.isascii() or raw_name.startswith("/") or "\\" in raw_name:
                fail(f"retained recovery archive path is unsafe: {path}")
            parts = PurePosixPath(raw_name).parts
            if any(part in {"", ".", ".."} or ":" in part for part in parts):
                fail(f"retained recovery archive component is unsafe: {path}")
            normalized = "/".join(parts)
            if normalized in seen:
                fail(f"retained recovery archive contains a duplicate: {path}")
            seen.add(normalized)
            if member.isdir():
                continue
            if not member.isfile() or member.size < 0 or member.size > 32 * 1024 * 1024:
                fail(f"retained recovery archive member type differs: {path}")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                fail(f"retained recovery archive expansion exceeds its bound: {path}")
            extracted = source.extractfile(member)
            if extracted is None:
                fail(f"retained recovery archive member is unreadable: {path}")
            payload = extracted.read(32 * 1024 * 1024 + 1)
            if len(payload) != member.size:
                fail(f"retained recovery archive member bytes differ: {path}")
            mode = "100755" if member.mode & 0o111 else "100644"
            files.append((normalized, len(payload), mode, payload))
    nodes: dict[tuple[str, ...], list[tuple[bytes, bytes]]] = {}
    for name, _size, mode, payload in files:
        parts = tuple(name.split("/"))
        nodes.setdefault(parts[:-1], []).append(
            (parts[-1].encode("ascii") + b"\0", mode.encode("ascii") + b" " + parts[-1].encode("ascii") + b"\0" + git_object(b"blob", payload))
        )
        for index in range(len(parts) - 1):
            nodes.setdefault(parts[:index], [])
            nodes.setdefault(parts[: index + 1], [])
    tree_hashes: dict[tuple[str, ...], bytes] = {}
    for node in sorted(nodes, key=len, reverse=True):
        rows = list(nodes[node])
        children = {key[len(node)] for key in nodes if len(key) == len(node) + 1 and key[:-1] == node}
        for child in children:
            encoded = child.encode("ascii")
            rows.append((encoded + b"/", b"40000 " + encoded + b"\0" + tree_hashes[node + (child,)]))
        tree_hashes[node] = git_object(b"tree", b"".join(row for _key, row in sorted(rows, key=lambda item: item[0])))
    manifest = hashlib.sha256()
    for name, size, mode, payload in sorted(files, key=lambda item: item[0].encode("ascii")):
        manifest.update(f"{name}\0{size}\0{mode}\0{hashlib.sha256(payload).hexdigest()}\n".encode("ascii"))
    return {
        "commit": expected_commit,
        "tree": tree_hashes.get((), git_object(b"tree", b"")).hex(),
        "file": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "manifestSha256": manifest.hexdigest(),
        "paths": {name for name, _size, _mode, _payload in files},
    }


def fail(message: str) -> "None":
    raise SystemExit(message)


def protected_regular(path: Path, mode: int, *, maximum: int | None = None) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        fail(f"protected path is unsafe: {path}")
    if metadata.st_size < 1 or (maximum is not None and metadata.st_size > maximum):
        fail(f"protected path size is unsafe: {path}")
    with path.open("rb") as source:
        raw = source.read((maximum if maximum is not None else metadata.st_size) + 1)
    if len(raw) != metadata.st_size or (maximum is not None and len(raw) > maximum):
        fail(f"protected path changed or exceeds its byte boundary: {path}")
    return raw


def atomic_replace_json(path: Path, document: object) -> None:
    descriptor, candidate_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".json", dir=path.parent
    )
    candidate = Path(candidate_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            descriptor = -1
            json.dump(document, target, sort_keys=True, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.chown(candidate, 0, 0)
        os.replace(candidate, path)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        candidate.unlink(missing_ok=True)


def publish_immutable_json(path: Path, document: dict[str, object]) -> bytes:
    if path.exists() or path.is_symlink():
        raw = protected_regular(path, 0o600, maximum=65536)
        existing = json.loads(raw)
        for key in set(document) - {"recordedAt"}:
            if existing.get(key) != document[key]:
                fail(f"existing immutable evidence tuple differs: {path.name}")
        return raw
    descriptor, candidate_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".json", dir=path.parent
    )
    candidate = Path(candidate_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            descriptor = -1
            json.dump(document, target, sort_keys=True, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.chown(candidate, 0, 0)
        os.link(candidate, path, follow_symlinks=False)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        candidate.unlink(missing_ok=True)
    return protected_regular(path, 0o600, maximum=65536)


def timestamp() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def seal_access() -> None:
    deploy = protected_regular(
        STATE_ROOT / "deploy/.ssh/authorized_keys", 0o644
    )
    operator = protected_regular(
        STATE_ROOT / "operator/.ssh/authorized_keys", 0o644
    )
    proof = protected_regular(STATE_ROOT / "operator-ssh-proved", 0o600, maximum=65536)
    if proof != b"operatorSshAndSudoVerified=true\n":
        fail("operator SSH proof content differs")
    digests = {
        "deployAuthorizedKeysSha256": hashlib.sha256(deploy).hexdigest(),
        "operatorAuthorizedKeysSha256": hashlib.sha256(operator).hexdigest(),
        "operatorProofSha256": hashlib.sha256(proof).hexdigest(),
    }
    identity = hashlib.sha256(
        b"".join(f"{key}\0{value}\n".encode() for key, value in sorted(digests.items()))
    ).hexdigest()
    name = f"host-access-hardened-{identity}.json"
    document: dict[str, object] = {
        "schemaVersion": 1,
        "recordedAt": timestamp(),
        "phase": "hardened",
        **digests,
    }
    raw = publish_immutable_json(EVIDENCE_ROOT / name, document)
    atomic_replace_json(
        STATE_ROOT / "current-host-access.json",
        {
            "schemaVersion": 1,
            "phase": "hardened",
            "accessEvidenceFile": name,
            "accessEvidenceSha256": hashlib.sha256(raw).hexdigest(),
        },
    )


def load_manifest(source_root: Path) -> tuple[bytes, dict[str, object]]:
    path = source_root / "config/host-control-manifest.v1.json"
    raw = path.read_bytes()
    document = json.loads(raw)
    if (
        set(document)
        != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"}
        or document.get("schemaVersion") != 1
    ):
        fail("host-control manifest schema differs")
    return raw, document


def seal_control(operation: str, commit: str, source_root: Path, previous: str) -> None:
    if operation not in {"initial-install", "upgrade", "certificate-install"}:
        fail("host-control evidence operation differs")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("host-control commit differs")
    previous_value: str | None = None if previous == "-" else previous
    if previous_value is not None and not re.fullmatch(r"[0-9a-f]{64}", previous_value):
        fail("host-control predecessor differs")
    manifest_raw, manifest = load_manifest(source_root)
    release_archive = Path(f"/opt/mochirii/forums/host-control-releases/{commit}/mochirii-release.tar")
    deployment_archive = Path(f"/opt/mochirii/forums/deployment-source/{DEPLOYMENT_SOURCE_COMMIT}.tar")
    release_identity = archive_identity(release_archive, commit)
    deployment_identity = archive_identity(deployment_archive, DEPLOYMENT_SOURCE_COMMIT)
    if release_identity["tree"] == DEPLOYMENT_SOURCE_TREE or not {
        "config/host-control-manifest.v1.json",
        "scripts/historical-recovery-scratch-reader.sh",
        "scripts/host-historical-disaster-recovery.sh",
    }.issubset(release_identity["paths"]):
        fail("retained host-control recovery archive inventory differs")
    if deployment_identity["tree"] != DEPLOYMENT_SOURCE_TREE or "launcher" not in deployment_identity["paths"]:
        fail("retained official deployment-source archive identity differs")
    archive_bindings: dict[str, object] = {
        "repositoryTree": release_identity["tree"],
        "releaseArchiveFile": release_identity["file"],
        "releaseArchiveSha256": release_identity["sha256"],
        "releaseArchiveBytes": release_identity["bytes"],
        "releaseArchiveContentManifestSha256": release_identity["manifestSha256"],
        "deploymentSourceRevision": DEPLOYMENT_SOURCE_COMMIT,
        "deploymentSourceTree": DEPLOYMENT_SOURCE_TREE,
        "deploymentSourceArchiveFile": deployment_identity["file"],
        "deploymentSourceArchiveSha256": deployment_identity["sha256"],
        "deploymentSourceArchiveBytes": deployment_identity["bytes"],
        "deploymentSourceContentManifestSha256": deployment_identity["manifestSha256"],
    }
    targets: dict[str, dict[str, str]] = {}
    for group in ("coreTargets", "hostPolicyTargets"):
        rows = manifest[group]
        assert isinstance(rows, list)
        for item in rows:
            assert isinstance(item, dict)
            source = source_root / str(item["source"])
            target = Path(str(item["target"]))
            mode_text = str(item["mode"])
            source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            actual = protected_regular(target, int(mode_text, 8))
            if hashlib.sha256(actual).hexdigest() != source_digest:
                fail(f"installed host-control target differs: {target}")
            targets[str(target)] = {"mode": mode_text, "sha256": source_digest}
    certificate_rows = manifest["certificateTargets"]
    assert isinstance(certificate_rows, list)
    presence = [
        Path(str(item["target"])).exists() or Path(str(item["target"])).is_symlink()
        for item in certificate_rows
    ]
    if any(presence) and not all(presence):
        fail("certificate automation target set is partial")
    if all(presence):
        for item in certificate_rows:
            assert isinstance(item, dict)
            source = source_root / str(item["source"])
            target = Path(str(item["target"]))
            mode_text = str(item["mode"])
            source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            actual = protected_regular(target, int(mode_text, 8))
            if hashlib.sha256(actual).hexdigest() != source_digest:
                fail(f"installed certificate control differs: {target}")
            targets[str(target)] = {"mode": mode_text, "sha256": source_digest}
    records = [
        f"{target}\0{item['mode']}\0{item['sha256']}\n".encode()
        for target, item in sorted(targets.items())
    ]
    target_set_sha = hashlib.sha256(b"".join(records)).hexdigest()
    name = f"{commit}-{target_set_sha}-host-control.json"
    document: dict[str, object] = {
        "schemaVersion": 1,
        "recordedAt": timestamp(),
        "operation": operation,
        "phase": "hardened",
        "repositoryCommit": commit,
        "manifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
        "targetSetSha256": target_set_sha,
        "previousControlEvidenceSha256": previous_value,
        "targets": targets,
        **archive_bindings,
    }
    raw = publish_immutable_json(EVIDENCE_ROOT / name, document)
    atomic_replace_json(
        STATE_ROOT / "current-host-control.json",
        {
            "schemaVersion": 1,
            "phase": "hardened",
            "repositoryCommit": commit,
            "manifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
            "targetSetSha256": target_set_sha,
            "controlEvidenceFile": name,
            "controlEvidenceSha256": hashlib.sha256(raw).hexdigest(),
            **archive_bindings,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("seal-access")
    control = subparsers.add_parser("seal-control")
    control.add_argument(
        "--operation",
        choices=("initial-install", "upgrade", "certificate-install"),
        required=True,
    )
    control.add_argument("--commit", required=True)
    control.add_argument("--source-root", type=Path, required=True)
    control.add_argument("--previous-evidence-sha256", default="-")
    arguments = parser.parse_args()
    EVIDENCE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if arguments.action == "seal-access":
        seal_access()
    else:
        seal_control(
            arguments.operation,
            arguments.commit,
            arguments.source_root.resolve(strict=True),
            arguments.previous_evidence_sha256,
        )


if __name__ == "__main__":
    main()
