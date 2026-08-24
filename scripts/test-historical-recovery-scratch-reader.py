#!/usr/bin/env python3
"""Hostile source-only fixture for the isolated historical recovery reader."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "historical-recovery-scratch-reader.sh"
BASE_IMAGE = "discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
C1 = ""
C0 = "b" * 40
OPERATION = "c" * 32
DEPLOYMENT_REVISION = ""
CONFIRMATION = "FETCH HISTORICAL MOCHIRII FORUMS RECOVERY SOURCE"
ARCHIVE_BYTES = b"fixture exact historical C0 Git archive\n"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class Node:
    def __init__(self) -> None:
        self.files: dict[str, tuple[bool, bytes]] = {}
        self.directories: dict[str, Node] = {}


def git_object(kind: bytes, payload: bytes) -> bytes:
    return hashlib.sha1(kind + b" " + str(len(payload)).encode("ascii") + b"\0" + payload).digest()


def tree_digest(node: Node) -> bytes:
    rows: list[tuple[bytes, bytes]] = []
    for name, (executable, blob) in node.files.items():
        encoded = name.encode("ascii")
        mode = b"100755" if executable else b"100644"
        rows.append((encoded + b"\0", mode + b" " + encoded + b"\0" + blob))
    for name, child in node.directories.items():
        encoded = name.encode("ascii")
        rows.append((encoded + b"/", b"40000 " + encoded + b"\0" + tree_digest(child)))
    return git_object(b"tree", b"".join(row for _key, row in sorted(rows, key=lambda item: item[0])))


def identities(files: dict[str, tuple[bytes, bool]]) -> tuple[str, str]:
    root = Node()
    for path, (payload, executable) in files.items():
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            node = node.directories.setdefault(part, Node())
        node.files[parts[-1]] = (executable, git_object(b"blob", payload))
    manifest = hashlib.sha256()
    for path in sorted(files, key=lambda value: value.encode("ascii")):
        payload, executable = files[path]
        manifest.update(path.encode("ascii"))
        manifest.update(b"\0")
        manifest.update(str(len(payload)).encode("ascii"))
        manifest.update(b"\0")
        manifest.update(b"100755" if executable else b"100644")
        manifest.update(b"\0")
        manifest.update(sha(payload).encode("ascii"))
        manifest.update(b"\n")
    return tree_digest(root).hex(), manifest.hexdigest()


def git_archive(
    path: Path, files: dict[str, tuple[bytes, bool]], message: str
) -> tuple[str, str, int, str, str]:
    """Create the exact fixture input with real Git, including Git tar modes."""
    repository = path.parent / f".{path.stem}-repository"
    repository.mkdir(parents=True)
    run_environment = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    }

    def git(*arguments: str) -> str:
        result = subprocess.run(
            [
                "git", "-c", "core.autocrlf=false", "-c", "core.filemode=true",
                "-c", "tar.umask=0002", *arguments,
            ],
            cwd=repository,
            env=run_environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init", "--quiet")
    git("config", "user.name", "Mochirii fixture")
    git("config", "user.email", "fixture@example.invalid")
    for name, (payload, executable) in files.items():
        target = repository / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        target.chmod(0o755 if executable else 0o644)
    git("add", "--all")
    git("commit", "--quiet", "--no-gpg-sign", "-m", message)
    commit = git("rev-parse", "--verify", "HEAD^{commit}")
    repository_tree = git("rev-parse", "--verify", "HEAD^{tree}")
    path.parent.mkdir(parents=True, exist_ok=True)
    git("archive", "--format=tar", f"--output={path}", commit)
    shutil.rmtree(repository)
    path.chmod(0o600)
    raw = path.read_bytes()
    tree, manifest = identities(files)
    if tree != repository_tree:
        raise RuntimeError("real Git archive fixture tree differs from the normalized identity")
    with tarfile.open(path, "r:") as archive:
        file_modes = {member.mode for member in archive.getmembers() if member.isfile()}
        directory_modes = {member.mode for member in archive.getmembers() if member.isdir()}
    if file_modes != {0o664, 0o775} or (directory_modes and directory_modes != {0o775}):
        raise RuntimeError(
            f"real Git archive fixture did not retain canonical Git tar modes: files={file_modes!r}, dirs={directory_modes!r}"
        )
    return commit, sha(raw), len(raw), tree, manifest


RENDERER = textwrap.dedent(
    r"""#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--mode")
parser.add_argument("--runtime-json")
parser.add_argument("--repository-commit", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
text = f'''base_image: "fixture"
templates:
  - "templates/postgres.template.yml"
  - "templates/redis.template.yml"
  - "templates/web.template.yml"
expose:
  - "127.0.0.1:18080:80"

params:
  version: "fixture"
env:
  MOCHIRII_REPOSITORY_COMMIT: "{args.repository_commit}"
  MOCHIRII_RELEASE_ASSET_ROOT: "/opt/mochirii-release"
  DISCOURSE_DISABLE_EMAILS: "yes"
volumes:
  - volume:
      host: /var/discourse/shared/standalone
      guest: /shared
  - volume:
      host: /var/discourse/shared/standalone/log/var-log
      guest: /var/log
  - volume:
      host: /opt/mochirii/forums/runtime-assets/{args.repository_commit}
      guest: /opt/mochirii-release:ro
'''
args.output.write_text(text, encoding="utf-8")
args.output.chmod(0o600)
"""
).encode("utf-8")

THEME_BUILDER = textwrap.dedent(
    r'''#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.write_bytes(b"PK fixture theme")
'''
).encode("utf-8")

ADAPTER = textwrap.dedent(
    r'''#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import subprocess
import sys

stage = sys.argv[1]
if sys.argv[2] != "--":
    raise SystemExit(97)
argv = sys.argv[3:]
root = pathlib.Path(os.environ["MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_ROOT"])
operation = os.environ["MOCHIRII_HISTORICAL_READER_OPERATION_ID"]
scratch = pathlib.Path(os.environ["MOCHIRII_HISTORICAL_SCRATCH_ROOT"])
log_path = root / "adapter-log.jsonl"
state_path = root / "adapter-state.json"
state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {
    "container": False, "image": False, "imageTagged": False,
    "imageLabel": "", "started": False,
}
entry = {
    "stage": stage,
    "argv": argv,
    "operation": operation,
    "scratch": str(scratch),
}
if stage.startswith("launcher-"):
    config = scratch / "discourse" / "containers" / f"mochirii-dr-reader-{operation}.yml"
    text = config.read_text(encoding="utf-8")
    entry["configHasProductionShared"] = "/var/discourse/shared/standalone" in text
    entry["configHasRealTarget"] = str(root / "var/discourse/shared/standalone") in text
    entry["configPublishesPort"] = '80:80' in text or '443:443' in text or "18080:80" in text
with log_path.open("a", encoding="utf-8") as output:
    output.write(json.dumps(entry, sort_keys=True) + "\n")

if os.environ.get("MOCHIRII_FIXTURE_TIMEOUT_STAGE") == stage:
    raise SystemExit(124)

if stage == "launcher-bootstrap":
    state["image"] = True
    state["imageTagged"] = True
    state["imageLabel"] = operation
elif stage == "launcher-start":
    state["container"] = True
    state["started"] = True
elif stage == "fetch-evidence":
    archive = base64.b64decode(os.environ["MOCHIRII_FIXTURE_C0_ARCHIVE_BASE64"])
    receipt = {
        "schemaVersion": 3,
        "repositoryCommit": os.environ["MOCHIRII_FIXTURE_C0"],
        "productionConfigurationSha256": "1" * 64,
        "disasterRecoveryImported": True,
        "disasterRecoveryFetchMode": "clean-target-historical",
        "disasterRecoveryBootstrapCommit": os.environ["MOCHIRII_FIXTURE_C1"],
        "disasterRecoveryReleaseArchiveSha256": __import__("hashlib").sha256(archive).hexdigest(),
        "disasterRecoveryReleaseArchiveBytes": len(archive),
        "disasterRecoveryReleaseArchiveContentManifestSha256": "2" * 64,
        "disasterRecoveryReleaseSourceAuthoritySha256": "3" * 64,
        "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain": True,
        "disasterRecoveryHistoricalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
        "disasterRecoveryPrivateAclPassed": True,
    }
    sys.stdout.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
elif stage == "fetch-release":
    sys.stdout.buffer.write(base64.b64decode(os.environ["MOCHIRII_FIXTURE_C0_ARCHIVE_BASE64"]))
elif stage == "inspect-mounts":
    shared_source = (
        "/var/discourse/shared/standalone"
        if os.environ.get("MOCHIRII_FIXTURE_REAL_MOUNT") == "1"
        else str(scratch / "shared/standalone")
    )
    mounts = [
        {"Type": "bind", "Source": shared_source, "Destination": "/shared", "RW": True},
        {"Type": "bind", "Source": str(scratch / "shared/standalone/log/var-log"), "Destination": "/var/log", "RW": True},
        {"Type": "bind", "Source": str(scratch / "runtime-assets"), "Destination": "/opt/mochirii-release", "RW": False},
    ]
    sys.stdout.write(json.dumps(mounts) + "\n")
elif stage == "inspect-ports":
    sys.stdout.write("{}\n")
elif stage == "inspect-label":
    sys.stdout.write(operation + "\n")
elif stage == "inspect-running":
    sys.stdout.write("true\n")
elif stage == "inventory":
    command = argv[argv.index("docker") + 1:] if "docker" in argv else []
    if command[:2] == ["container", "ls"]:
        selector = command[command.index("--filter") + 1]
        if selector.startswith("label="):
            if state["container"]:
                sys.stdout.write("4" * 64 + "\n")
        elif selector.startswith("name="):
            if state["container"]:
                sys.stdout.write("4" * 64 + " " + operation + "\n")
    elif command[:2] == ["image", "ls"] and state["image"]:
        reference_selected = "--filter" in command and command[command.index("--filter") + 1].startswith("reference=")
        if not reference_selected or state["imageTagged"]:
            sys.stdout.write("sha256:" + "5" * 64 + "\n")
    elif command[:2] == ["image", "inspect"] and state["image"]:
        sys.stdout.write(state["imageLabel"] + "\n")
elif stage == "cleanup":
    command = argv[argv.index("docker") + 1:] if "docker" in argv else []
    hostile = os.environ.get("MOCHIRII_FIXTURE_CONTAINER_SURVIVOR") == "1" and state["started"]
    if command[:1] == ["rm"] and not hostile:
        state["container"] = False
    elif command[:2] == ["image", "rm"]:
        target = command[-1]
        if target.startswith("local_discourse/"):
            state["imageTagged"] = False
        else:
            if not state["image"]:
                raise SystemExit(1)
            state["image"] = False
            state["imageTagged"] = False

if stage.startswith("launcher-") or stage == "cleanup":
    temporary_state = state_path.with_name(f".{state_path.name}.{os.getpid()}.partial")
    temporary_state.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    temporary_state.chmod(0o600)
    temporary_state.replace(state_path)
'''
).encode("utf-8")


def forum_files() -> dict[str, tuple[bytes, bool]]:
    return {
        "AGENTS.md": (b"fixture authority\n", False),
        "config/app.yml.example": (b"fixture template\n", False),
        "docs/operations/RECOVERY.md": (b"fixture recovery\n", False),
        "scripts/render-app-config.py": (RENDERER, True),
        "scripts/build-theme-archive.py": (THEME_BUILDER, True),
        "scripts/configure-site.rb": (b"# fixture\n", False),
        "scripts/fetch-disaster-recovery-evidence.rb": (b"# fixture\n", False),
        "scripts/fetch-disaster-recovery-release.rb": (b"# fixture\n", False),
        "plugins/mochirii_email_metadata/plugin.rb": (b"# fixture\n", False),
    }


def deployment_files() -> dict[str, tuple[bytes, bool]]:
    return {
        "launcher": (b"#!/usr/bin/env bash\nexit 97\n", True),
        "templates/web.template.yml": (b"fixture web\n", False),
        "templates/postgres.template.yml": (b"fixture postgres\n", False),
        "templates/redis.template.yml": (b"fixture redis\n", False),
    }


def write_protected(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(0o600)


def setup(root: Path) -> dict[str, str]:
    global C1, DEPLOYMENT_REVISION
    state = root / "var/lib/mochirii/forums"
    stage = state / "historical-recovery"
    state.mkdir(parents=True)
    stage.mkdir()
    # Match the installed production host-control state-root invariant.  Only
    # the historical operation's staging and scratch children are private.
    state.chmod(0o755)
    stage.chmod(0o700)
    (root / "adapter.py").write_bytes(ADAPTER)
    (root / "adapter.py").chmod(0o600)
    write_protected(root / "etc/mochirii/forums.runtime.json", b"{}\n")

    source_temporary = root / "sealed-forums-source.tar"
    source_commit, source_sha, source_bytes, source_tree, source_manifest = git_archive(
        source_temporary, forum_files(), "C1 current-main recovery reader"
    )
    if C1 and C1 != source_commit:
        raise RuntimeError("deterministic real Git C1 fixture commit changed")
    C1 = source_commit
    source_path = root / f"opt/mochirii/forums/host-control-releases/{C1}/mochirii-release.tar"
    source_path.parent.mkdir(parents=True)
    source_temporary.replace(source_path)

    deployment_temporary = root / "sealed-deployment-source.tar"
    deployment_commit, deployment_sha, deployment_bytes, deployment_tree, deployment_manifest = git_archive(
        deployment_temporary, deployment_files(), "Pinned deployment source"
    )
    if DEPLOYMENT_REVISION and DEPLOYMENT_REVISION != deployment_commit:
        raise RuntimeError("deterministic real Git deployment fixture commit changed")
    DEPLOYMENT_REVISION = deployment_commit
    deployment_path = root / f"opt/mochirii/forums/deployment-source/{DEPLOYMENT_REVISION}.tar"
    deployment_path.parent.mkdir(parents=True)
    deployment_temporary.replace(deployment_path)
    control = {
        "schemaVersion": 1,
        "phase": "hardened",
        "repositoryCommit": C1,
        "repositoryTree": source_tree,
        "manifestSha256": "6" * 64,
        "targetSetSha256": "7" * 64,
        "controlEvidenceFile": str(state / "host-control-evidence.json"),
        "controlEvidenceSha256": "8" * 64,
        "releaseArchiveFile": str(source_path),
        "releaseArchiveSha256": source_sha,
        "releaseArchiveBytes": source_bytes,
        "releaseArchiveContentManifestSha256": source_manifest,
        "deploymentSourceArchiveFile": str(deployment_path),
        "deploymentSourceRevision": DEPLOYMENT_REVISION,
        "deploymentSourceTree": deployment_tree,
        "deploymentSourceArchiveSha256": deployment_sha,
        "deploymentSourceArchiveBytes": deployment_bytes,
        "deploymentSourceContentManifestSha256": deployment_manifest,
    }
    control_raw = (json.dumps(control, sort_keys=True, indent=2) + "\n").encode("utf-8")
    control_path = state / "current-host-control.json"
    write_protected(control_path, control_raw)
    intent = {
        "schemaVersion": 1,
        "operation": "current-main-historical-recovery-reader",
        "phase": "reader-armed",
        "recordedAt": "2026-08-20T00:00:00Z",
        "bootstrapRepositoryCommit": C1,
        "readerOperationId": OPERATION,
        "scratchRoot": str(state / f"historical-reader/{OPERATION}"),
        "currentHostControlFile": str(control_path),
        "currentHostControlSha256": sha(control_raw),
        "realPersistentTarget": str(root / "var/discourse/shared/standalone"),
        "realPersistentTargetInitiallyAbsent": True,
    }
    write_protected(state / "historical-reader.json", (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "MOCHIRII_HISTORICAL_SCRATCH_MODE": "source-only-hostile-fixture",
        "MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_ROOT": str(root),
        "MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_DEPLOYMENT_REVISION": DEPLOYMENT_REVISION,
        "MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_DEPLOYMENT_TREE": deployment_tree,
        "MOCHIRII_FIXTURE_C0": C0,
        "MOCHIRII_FIXTURE_C1": C1,
        "MOCHIRII_FIXTURE_C0_ARCHIVE_BASE64": base64.b64encode(ARCHIVE_BYTES).decode("ascii"),
    }


def invoke(root: Path, env: dict[str, str], *, passed: bool, commit: str | None = None) -> subprocess.CompletedProcess[str]:
    if commit is None:
        commit = env["MOCHIRII_FIXTURE_C1"]
    result = subprocess.run(
        ["bash", str(SCRIPT), commit, OPERATION, CONFIRMATION],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if (result.returncode == 0) != passed:
        diagnostic = {}
        for name in ("adapter-log.jsonl", "adapter-state.json"):
            path = root / name
            diagnostic[name] = path.read_text(encoding="utf-8") if path.exists() else "<absent>"
        raise RuntimeError(
            f"scratch reader returned {result.returncode}, expected passed={passed}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}\nadapter={diagnostic!r}"
        )
    return result


def outputs(root: Path) -> tuple[Path, Path]:
    stage = root / "var/lib/mochirii/forums/historical-recovery"
    return stage / "fetched-recovery-receipt.json", stage / "fetched-release.tar"


def assert_terminal(root: Path) -> None:
    receipt, archive = outputs(root)
    if not receipt.is_file() or receipt.is_symlink() or stat.S_IMODE(receipt.stat().st_mode) != 0o600:
        raise RuntimeError("fixture receipt did not reach its protected terminal state")
    if not archive.is_file() or archive.is_symlink() or stat.S_IMODE(archive.stat().st_mode) != 0o600:
        raise RuntimeError("fixture archive did not reach its protected terminal state")
    document = json.loads(receipt.read_text(encoding="utf-8"))
    if document.get("disasterRecoveryBootstrapCommit") != C1 or archive.read_bytes() != ARCHIVE_BYTES:
        raise RuntimeError("fixture terminal outputs differ")
    scratch = root / f"var/lib/mochirii/forums/historical-reader/{OPERATION}"
    transaction = root / f"var/lib/mochirii/forums/historical-recovery/historical-reader-{OPERATION}.transaction.json"
    real_shared = root / "var/discourse/shared/standalone"
    if scratch.exists() or scratch.is_symlink() or real_shared.exists() or real_shared.is_symlink():
        raise RuntimeError("fixture terminal absence proof differs")
    if not transaction.is_file() or transaction.is_symlink() or stat.S_IMODE(transaction.stat().st_mode) != 0o600:
        raise RuntimeError("fixture terminal controller-readback transaction is unsafe")
    terminal = json.loads(transaction.read_text(encoding="utf-8"))
    if (
        terminal.get("phase") != "outputs-published"
        or terminal.get("cleanupProved") is not True
        or terminal.get("operationImageLabel") != f"mochirii.forums.historical-reader={OPERATION}"
        or terminal.get("operationImageIds") != ["sha256:" + "5" * 64]
        or not isinstance(terminal.get("preexistingImageIds"), list)
    ):
        raise RuntimeError("fixture terminal controller-readback transaction differs")


def happy_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-scratch-reader-") as temporary:
        root = Path(temporary).resolve()
        env = setup(root)
        invoke(root, env, passed=True)
        assert_terminal(root)
        invoke(root, env, passed=True)
        assert_terminal(root)
        entries = [json.loads(line) for line in (root / "adapter-log.jsonl").read_text(encoding="utf-8").splitlines()]
        stages = [entry["stage"] for entry in entries]
        for required in ("launcher-bootstrap", "launcher-start", "inspect-mounts", "inspect-ports", "fetch-evidence", "fetch-release", "cleanup"):
            if required not in stages:
                raise RuntimeError(f"actual adapter command construction missed {required}")
        launchers = [entry for entry in entries if entry["stage"].startswith("launcher-")]
        if any(entry.get("configHasProductionShared") or entry.get("configHasRealTarget") or entry.get("configPublishesPort") for entry in launchers):
            raise RuntimeError("actual launcher adapter observed a production mount or listener")
        joined_evidence = "\0".join(next(entry["argv"] for entry in entries if entry["stage"] == "fetch-evidence"))
        joined_release = "\0".join(next(entry["argv"] for entry in entries if entry["stage"] == "fetch-release"))
        if "MOCHIRII_DR_FETCH_MODE=clean-target-historical" not in joined_evidence or f"MOCHIRII_DR_BOOTSTRAP_COMMIT={C1}" not in joined_evidence:
            raise RuntimeError("historical evidence fetch environment construction differs")
        if "MOCHIRII_DR_FETCH_RECEIPT_BASE64=" not in joined_release:
            raise RuntimeError("historical archive fetch receipt environment is absent")
        if not any(f"--label=mochirii.forums.historical-reader={OPERATION}" in argument for entry in launchers for argument in entry["argv"]):
            raise RuntimeError("historical launcher operation label is absent")


def hostile_case(name: str, mutate, *, expected_stderr: str | None = None) -> None:
    with tempfile.TemporaryDirectory(prefix=f"mochirii-scratch-{name}-") as temporary:
        root = Path(temporary).resolve()
        env = setup(root)
        mutation_result = mutate(root, env)
        commit = mutation_result if isinstance(mutation_result, str) else C1
        result = invoke(root, env, passed=False, commit=commit)
        if expected_stderr is not None and expected_stderr not in result.stderr:
            raise RuntimeError(f"{name} fixture failed for the wrong reason: {result.stderr!r}")
        receipt, archive = outputs(root)
        if receipt.exists() or receipt.is_symlink() or archive.exists() or archive.is_symlink():
            raise RuntimeError(f"{name} fixture published an output")


def crash_recovery_fixture(point: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"mochirii-scratch-crash-{point}-") as temporary:
        root = Path(temporary).resolve()
        env = setup(root)
        crashed = {**env, "MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_CRASH_AFTER": point}
        invoke(root, crashed, passed=False)
        transaction_path = root / f"var/lib/mochirii/forums/historical-recovery/historical-reader-{OPERATION}.transaction.json"
        if point in ("after-reader-image-untag", "after-reader-image-delete"):
            adapter_state = json.loads((root / "adapter-state.json").read_text(encoding="utf-8"))
            transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        if point == "after-reader-image-untag":
            if (
                adapter_state.get("image") is not True
                or adapter_state.get("imageTagged") is not False
                or transaction.get("operationImageIds") != ["sha256:" + "5" * 64]
                or transaction.get("operationImageLabel") != f"mochirii.forums.historical-reader={OPERATION}"
            ):
                raise RuntimeError("post-untag crash did not retain exact immutable image ownership")
        if point == "after-reader-image-delete":
            if (
                adapter_state.get("image") is not False
                or adapter_state.get("imageTagged") is not False
                or transaction.get("phase") != "archive-fetched"
                or transaction.get("operationImageIds") != ["sha256:" + "5" * 64]
                or transaction.get("operationImageLabel") != f"mochirii.forums.historical-reader={OPERATION}"
            ):
                raise RuntimeError("post-ID-delete crash did not retain exact durable image authority")
        invoke(root, env, passed=True)
        assert_terminal(root)
        if point == "after-reader-image-delete":
            image_id = "sha256:" + "5" * 64
            entries = [json.loads(line) for line in (root / "adapter-log.jsonl").read_text(encoding="utf-8").splitlines()]
            immutable_removals = []
            for entry in entries:
                argv = entry.get("argv", [])
                if entry.get("stage") != "cleanup" or "docker" not in argv:
                    continue
                command = argv[argv.index("docker") + 1:]
                if command[:2] == ["image", "rm"] and command[-1:] == [image_id]:
                    immutable_removals.append(command)
            if len(immutable_removals) != 1:
                raise RuntimeError("post-ID-delete retry repeated or omitted immutable image deletion")
            probe_env = {
                **env,
                "MOCHIRII_HISTORICAL_READER_OPERATION_ID": OPERATION,
                "MOCHIRII_HISTORICAL_SCRATCH_ROOT": str(root / f"var/lib/mochirii/forums/historical-reader/{OPERATION}"),
            }
            absent_remove = subprocess.run(
                [sys.executable, "-B", str(root / "adapter.py"), "cleanup", "--", "docker", "image", "rm", "--force", image_id],
                check=False,
                capture_output=True,
                text=True,
                env=probe_env,
            )
            if absent_remove.returncode == 0:
                raise RuntimeError("fixture adapter unrealistically accepted removal of an absent image ID")


def damaged_operation_image_identity_fixture(name: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"mochirii-scratch-image-identity-{name}-") as temporary:
        root = Path(temporary).resolve()
        env = setup(root)
        crashed = {**env, "MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_CRASH_AFTER": "after-archive-fetch"}
        invoke(root, crashed, passed=False)
        transaction_path = root / f"var/lib/mochirii/forums/historical-recovery/historical-reader-{OPERATION}.transaction.json"
        transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        if name == "missing":
            transaction.pop("operationImageIds")
            expected_stderr = "historical reader transaction authority differs"
        elif name == "altered":
            transaction["operationImageIds"] = ["sha256:" + "9" * 64]
            expected_stderr = "historical reader operation image inventory is ambiguous"
        else:
            raise RuntimeError(f"unsupported operation image identity fixture: {name}")
        write_protected(transaction_path, (json.dumps(transaction, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        result = invoke(root, env, passed=False)
        if expected_stderr not in result.stderr:
            raise RuntimeError(f"{name} durable image identity was refused for the wrong reason: {result.stderr!r}")
        adapter_state = json.loads((root / "adapter-state.json").read_text(encoding="utf-8"))
        if adapter_state.get("image") is not True or adapter_state.get("imageTagged") is not True:
            raise RuntimeError(f"{name} durable image identity refusal mutated the historical image")
        receipt, archive = outputs(root)
        if receipt.exists() or receipt.is_symlink() or archive.exists() or archive.is_symlink():
            raise RuntimeError(f"{name} durable image identity refusal published an output")


def ordinary_failure_recovery_fixture(stage: str, value: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"mochirii-scratch-failure-{stage}-") as temporary:
        root = Path(temporary).resolve()
        env = setup(root)
        failed = {**env, stage: value}
        invoke(root, failed, passed=False)
        invoke(root, env, passed=True)
        assert_terminal(root)


def marked_process_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-scratch-process-") as temporary:
        root = Path(temporary).resolve()
        env = setup(root)
        marked_env = {**env, "MOCHIRII_HISTORICAL_READER_OPERATION_ID": OPERATION}
        process = subprocess.Popen(["sleep", "60"], env=marked_env)
        try:
            invoke(root, env, passed=True)
            assert_terminal(root)
            for _ in range(30):
                if process.poll() is not None:
                    break
                time.sleep(0.1)
            if process.poll() is None:
                raise RuntimeError("actual NUL-delimited marked process survived reconciliation")
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=5)


def run_linux() -> None:
    happy_fixture()
    hostile_case("timeout", lambda _root, env: env.update({"MOCHIRII_FIXTURE_TIMEOUT_STAGE": "fetch-evidence"}))
    hostile_case(
        "mount",
        lambda _root, env: env.update({"MOCHIRII_FIXTURE_REAL_MOUNT": "1"}),
        expected_stderr="scratch container retained a forbidden mount",
    )
    hostile_case(
        "tamper",
        lambda root, _env: (root / f"opt/mochirii/forums/host-control-releases/{C1}/mochirii-release.tar").write_bytes(b"tampered\n"),
    )

    def wrong_c1(root: Path, _env: dict[str, str]):
        intent_path = root / "var/lib/mochirii/forums/historical-reader.json"
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent["bootstrapRepositoryCommit"] = "e" * 40
        write_protected(intent_path, (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode("utf-8"))

    hostile_case("wrong-c1", wrong_c1)
    hostile_case("container-survivor", lambda _root, env: env.update({"MOCHIRII_FIXTURE_CONTAINER_SURVIVOR": "1"}))
    marked_process_fixture()
    ordinary_failure_recovery_fixture("MOCHIRII_FIXTURE_TIMEOUT_STAGE", "fetch-release")
    ordinary_failure_recovery_fixture("MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_FAIL_AFTER", "after-first-rename")
    damaged_operation_image_identity_fixture("missing")
    damaged_operation_image_identity_fixture("altered")
    for point in (
        "after-receipt-fetch",
        "after-archive-fetch",
        "after-reader-image-untag",
        "after-reader-image-delete",
        "after-cleanup-proof",
        "after-first-rename",
        "after-second-rename",
    ):
        crash_recovery_fixture(point)
    print("Historical recovery scratch-reader hostile fixture passed.")


def run_in_container() -> None:
    command = [
        "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "--memory-swap", "256m",
        "-v", f"{ROOT}:/repo:ro", "--entrypoint", "python3", BASE_IMAGE,
        "-B", "/repo/scripts/test-historical-recovery-scratch-reader.py", "--inside-linux",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"pinned Linux scratch-reader fixture failed\nstdout={result.stdout!r}\nstderr={result.stderr!r}")
    print(result.stdout.strip())


if __name__ == "__main__":
    if os.name == "nt" and "--inside-linux" not in sys.argv:
        run_in_container()
    else:
        if os.geteuid() != 0:
            raise SystemExit("Scratch-reader fixture requires an isolated root Linux context.")
        run_linux()
