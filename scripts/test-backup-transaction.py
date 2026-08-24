#!/usr/bin/env python3
"""Hostile filesystem tests for the durable backup terminal protocol."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
CONFIGURATION = "b" * 64
TIMESTAMP = "20260815T010203Z"
OPERATION_SHA = "f" * 64
CURRENT_RELEASE_SHA = "2" * 64
DISCOURSE_REVISION = "3" * 40
DOCKER_MANAGER_REVISION = "4" * 40
RUNTIME_ENVIRONMENT_SHA = "5" * 64
RUNTIME_PORTS_SHA = "6" * 64
RUNTIME_IMAGE = f"sha256:{'7' * 64}"
RUNTIME_IDENTITY_DOCUMENT = {
    "repositoryCommit": COMMIT,
    "productionConfigurationSha256": CONFIGURATION,
    "currentReleaseSha256": CURRENT_RELEASE_SHA,
    "discourseRevision": DISCOURSE_REVISION,
    "dockerManagerRevision": DOCKER_MANAGER_REVISION,
    "runtimeEnvironmentSha256": RUNTIME_ENVIRONMENT_SHA,
    "runtimePortBindingsSha256": RUNTIME_PORTS_SHA,
    "runtimeContainerImage": RUNTIME_IMAGE,
}
RUNTIME_IDENTITY_SHA = hashlib.sha256(
    json.dumps(RUNTIME_IDENTITY_DOCUMENT, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
).hexdigest()


def load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "backup_transaction", ROOT / "scripts" / "backup-transaction.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("backup transaction helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def protected_write(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def expect_blocked(operation, label: str) -> None:
    try:
        operation()
    except SystemExit:
        return
    raise RuntimeError(f"Hostile backup transaction was accepted: {label}")


def quietly(operation) -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        operation()


def assert_sigkill_releases_operation_lock(lock_path: Path) -> None:
    script = r'''
exec 9>"$1"
flock -n 9
(exec 9>&-; exec sleep 30) &
printf '%s\n' "$!"
read -r _
'''
    holder = subprocess.Popen(
        ["bash", "-c", script, "backup-lock-fixture", str(lock_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child_pid = 0
    try:
        if holder.stdout is None:
            raise RuntimeError("Lock SIGKILL fixture lost its child output.")
        child_pid = int(holder.stdout.readline().strip())
        os.kill(holder.pid, signal.SIGKILL)
        if holder.wait(timeout=5) != -signal.SIGKILL:
            raise RuntimeError("Lock SIGKILL fixture did not kill its owning shell.")
        os.kill(child_pid, 0)
        probe = subprocess.run(
            ["flock", "-n", str(lock_path), "true"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode != 0:
            raise RuntimeError(
                "SIGKILL survivor inherited the host-operation lock and blocked recovery."
            )
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=5)
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def assert_host_containment_sigkill(host_source: str, state_root: Path) -> None:
    function_start = host_source.index("contain_temporary_runtime_on_failure() {")
    function_end = host_source.index("\n}\n\nfinish_backup_transaction() {", function_start) + 3
    containment_function = host_source[function_start:function_end]
    phase_file = state_root / "host-containment-phase"
    runtime_file = state_root / "host-containment-runtime"
    protected_write(phase_file, b"idle\n")
    protected_write(runtime_file, b"running\n")
    preamble = r'''
set -euo pipefail
phase_file="$1"
runtime_file="$2"
original_runtime_state=stopped
runtime_operation_phase=idle
backup_transaction_command() {
  [[ "$1" == contain-temporary-runtime ]]
  local phase
  IFS= read -r phase < "${phase_file}"
  case "${phase}" in
    idle) printf '%s\n' temporary-stop-authorized > "${phase_file}" ;;
    temporary-stop-authorized) printf '%s\n' initial-stopped > "${phase_file}" ;;
    *) return 1 ;;
  esac
}
timeout() { printf '%s\n' true; }
prove_running_backup_identity() {
  local observed
  IFS= read -r observed < "${runtime_file}"
  [[ ${observed} == running ]]
}
stop_app_safely() { printf '%s\n' stopped > "${runtime_file}"; }
prove_stopped_backup_identity() {
  local observed
  IFS= read -r observed < "${runtime_file}"
  [[ ${observed} == stopped ]]
  printf '%s\n' stopped-proved
  kill -STOP "$$"
}
'''
    script = preamble + "\n" + containment_function + "\ncontain_temporary_runtime_on_failure\n"
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            script,
            "containment-crash-fixture",
            str(phase_file),
            str(runtime_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if process.stdout is None or process.stdout.readline() != "stopped-proved\n":
            raise RuntimeError("Containment crash fixture did not prove stopped state.")
        os.kill(process.pid, signal.SIGKILL)
        if process.wait(timeout=5) != -signal.SIGKILL:
            raise RuntimeError("Containment crash fixture did not stop at its hostile window.")
        if phase_file.read_bytes() != b"temporary-stop-authorized\n":
            raise RuntimeError("Host containment stop was not durably pre-authorized.")
        if runtime_file.read_bytes() != b"stopped\n":
            raise RuntimeError("Host containment fixture did not stop the runtime before SIGKILL.")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def assert_host_containment_retry(
    host_source: str, state_root: Path, initial_runtime: str
) -> None:
    if initial_runtime not in {"running", "stopped"}:
        raise RuntimeError("Containment retry fixture runtime is malformed.")
    function_start = host_source.index("reconcile_bound_runtime_ownership() {")
    function_end = host_source.index("\n}\n\nrestore_original_runtime_state() {", function_start) + 3
    reconcile_function = host_source[function_start:function_end]
    phase_file = state_root / f"host-retry-{initial_runtime}-phase"
    runtime_file = state_root / f"host-retry-{initial_runtime}-runtime"
    protected_write(phase_file, b"temporary-stop-authorized\n")
    protected_write(runtime_file, f"{initial_runtime}\n".encode("ascii"))
    preamble = r'''
set -euo pipefail
phase_file="$1"
runtime_file="$2"
original_runtime_state=stopped
runtime_operation_phase=temporary-stop-authorized
runtime_operation_label=-
runtime_operation_token=-
backup_transaction_command() {
  local action="$1"
  local phase
  IFS= read -r phase < "${phase_file}"
  case "${action}:${phase}" in
    contain-temporary-runtime:temporary-stop-authorized)
      printf '%s\n' initial-stopped > "${phase_file}" ;;
    authorize-initial-start:initial-stopped)
      printf '%s\n' initial-start-authorized > "${phase_file}" ;;
    complete-initial-start:initial-start-authorized)
      printf '%s\n' idle > "${phase_file}" ;;
    *) return 1 ;;
  esac
}
timeout() {
  local observed
  IFS= read -r observed < "${runtime_file}"
  [[ ${observed} == running ]] && printf '%s\n' true || printf '%s\n' false
}
prove_running_backup_identity() {
  local observed
  IFS= read -r observed < "${runtime_file}"
  [[ ${observed} == running ]]
}
prove_stopped_backup_identity() {
  local observed
  IFS= read -r observed < "${runtime_file}"
  [[ ${observed} == stopped ]]
}
stop_app_safely() { printf '%s\n' stopped > "${runtime_file}"; }
start_app_for_backup_recovery() { printf '%s\n' running > "${runtime_file}"; }
'''
    script = preamble + "\n" + reconcile_function + r'''
reconcile_bound_runtime_ownership
printf '%s\n' reconciled
'''
    result = subprocess.run(
        [
            "bash",
            "-c",
            script,
            "containment-retry-fixture",
            str(phase_file),
            str(runtime_file),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or result.stdout != "reconciled\n":
        raise RuntimeError(
            f"Host containment retry failed from {initial_runtime}: {result.stderr.strip()}"
        )
    if phase_file.read_bytes() != b"idle\n" or runtime_file.read_bytes() != b"running\n":
        raise RuntimeError(
            f"Host containment retry did not resume exact stopped-origin work from {initial_runtime}."
        )


def evidence_document(
    filename: str,
    backup_sha: str,
    *,
    commit: str = COMMIT,
    configuration: str = CONFIGURATION,
    discourse_revision: str = DISCOURSE_REVISION,
    docker_manager_revision: str = DOCKER_MANAGER_REVISION,
) -> dict[str, object]:
    evidence_object_sha = "c" * 64
    return {
        "schemaVersion": 3,
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "releaseEvidenceFile": f"{commit}-{configuration}-release.json",
        "releaseEvidenceSha256": "5" * 64,
        "restoreConfigurationSha256": "6" * 64,
        "themeArchiveSha256": "7" * 64,
        "mailMetadataPluginSha256": "8" * 64,
        "discourseDockerRevision": "9" * 40,
        "discourseRevision": discourse_revision,
        "dockerManagerRevision": docker_manager_revision,
        "baseImageDigest": f"sha256:{'c' * 64}",
        "discourseConnectEnabled": False,
        "memberRolloutMarkerFile": None,
        "memberRolloutMarkerSha256": None,
        "privateAdminRetrievalUrlPresent": True,
        "anonymousRetrievalDenied": True,
        "anonymousCdnRetrievalDenied": True,
        "backupPrefix": "backups/",
        "normalUploadInventoryCount": 17,
        "normalUploadInventorySha256": "4" * 64,
        "size": 1234,
        "sha256": backup_sha,
        "filename": filename,
        "recoveryUploadIncluded": False,
        "recoveryUploadState": None,
        "recoveryUploadStateSha256": None,
        "recoveryUploadDeletedAfterBackup": False,
        "disasterRecoveryEvidencePublished": True,
        "disasterRecoveryEvidenceObjectKey": f"backups/recovery-evidence/records/{evidence_object_sha}.json",
        "disasterRecoveryEvidenceObjectSha256": evidence_object_sha,
        "disasterRecoveryPointerSelected": True,
        "disasterRecoveryPointerObjectKey": "backups/recovery-evidence/current.json",
        "disasterRecoveryPointerObjectSha256": "d" * 64,
        "disasterRecoveryPrivateAclPassed": True,
        "disasterRecoveryRepositoryTree": "4" * 40,
        "disasterRecoveryReleaseArchivePublished": True,
        "disasterRecoveryReleaseArchiveObjectKey": f"backups/recovery-releases/archives/{'1' * 64}.tar",
        "disasterRecoveryReleaseArchiveSha256": "1" * 64,
        "disasterRecoveryReleaseArchiveBytes": 8192,
        "disasterRecoveryReleaseArchiveContentManifestSha256": "2" * 64,
        "disasterRecoveryReleaseArchiveSourceFormat": "git-archive-tar-v1",
        "disasterRecoveryReleaseSourceAuthorityPublished": True,
        "disasterRecoveryReleaseSourceAuthorityObjectKey": f"backups/recovery-releases/authorities/{'3' * 64}.json",
        "disasterRecoveryReleaseSourceAuthoritySha256": "3" * 64,
        "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain": True,
        "disasterRecoveryHistoricalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
    }


def main() -> None:
    helper = load_helper()
    with tempfile.TemporaryDirectory() as temporary:
        state_root = Path(temporary) / "state"
        evidence_root = state_root / "evidence"
        state_root.mkdir(mode=0o700)
        evidence_root.mkdir(mode=0o700)
        state_root.chmod(0o700)
        evidence_root.chmod(0o700)
        transaction = state_root / "backup-transaction.json"
        current = state_root / "current-backup.json"
        pointer = state_root / "latest-backup-evidence"
        assert_sigkill_releases_operation_lock(state_root / "host-operation.lock")

        previous_name = f"{'1' * 40}-{'2' * 64}-20260814T010203Z-backup.json"
        previous_evidence = evidence_root / previous_name
        protected_write(previous_evidence, b"{}\n")
        previous_pointer = f"{previous_evidence}\n".encode("utf-8")
        protected_write(pointer, previous_pointer)

        evidence_name = helper.exact_evidence_name(COMMIT, CONFIGURATION, TIMESTAMP)
        common = argparse.Namespace(
            state_root=state_root,
            evidence_root=evidence_root,
            transaction=transaction,
            current=current,
            pointer=pointer,
            commit=COMMIT,
            configuration=CONFIGURATION,
            operation_sha=OPERATION_SHA,
            timestamp=TIMESTAMP,
            evidence_file=evidence_name,
            phase=None,
            evidence_sha=None,
            pointer_sha=None,
            recovery_journal="-",
            recovery_journal_sha="-",
            original_runtime_state="running",
            runtime_identity_sha=RUNTIME_IDENTITY_SHA,
            current_release_sha=CURRENT_RELEASE_SHA,
            discourse_revision=DISCOURSE_REVISION,
            docker_manager_revision=DOCKER_MANAGER_REVISION,
            runtime_environment_sha=RUNTIME_ENVIRONMENT_SHA,
            runtime_ports_sha=RUNTIME_PORTS_SHA,
            runtime_image=RUNTIME_IMAGE,
            runtime_operation_label=None,
            runtime_operation_token=None,
            observed_runtime_state=None,
            include_runtime_contract=False,
        )

        transaction_partial = transaction.with_name(f".{transaction.name}.partial")
        protected_write(transaction_partial, b'{"schemaVersion":')
        helper.reconcile_exclusive_partial(transaction)
        if transaction_partial.exists():
            raise RuntimeError("Uncommitted transaction partial was not retired.")

        helper.action_create(common)
        os.link(transaction, transaction_partial)
        helper.reconcile_exclusive_partial(transaction)
        if transaction_partial.exists() or not transaction.exists():
            raise RuntimeError("Exact linked transaction partial was not reconciled.")
        protected_write(transaction_partial, b"{}\n")
        expect_blocked(
            lambda: helper.reconcile_exclusive_partial(transaction),
            "mismatched transaction partial was retired",
        )
        if not transaction_partial.exists():
            raise RuntimeError("Mismatched transaction partial was not retained.")
        transaction_partial.unlink()
        prepared = helper.load_transaction(transaction, COMMIT, CONFIGURATION, OPERATION_SHA)
        if (
            prepared["phase"] != "prepared"
            or prepared["previousLatestEvidenceFile"] != previous_name
            or prepared["backupOperationSha256"] != OPERATION_SHA
            or prepared["runtimeRecoveryPhase"] != "none"
            or prepared["originalRuntimeState"] != "running"
            or prepared["runtimeOperationPhase"] != "idle"
            or prepared["runtimeIdentitySha256"] != RUNTIME_IDENTITY_SHA
        ):
            raise RuntimeError("Backup transaction did not durably bind its prior pointer.")

        # A timeout may stop the application while an exact recovery upload is
        # still owned by this prepared operation. The bounded command token,
        # not the cleanup journal, grants narrowly scoped restart authority.
        recovery_id = "d" * 32
        recovery_name = (
            f"{COMMIT}-{CONFIGURATION}-{recovery_id}-"
            "backup-upload-cleanup-required.json"
        )
        recovery = evidence_root / recovery_name
        recovery_document = {
            "schemaVersion": 1,
            "repositoryCommit": COMMIT,
            "productionConfigurationSha256": CONFIGURATION,
            "backupOperationSha256": OPERATION_SHA,
            "transactionId": recovery_id,
            "pluginStoreKey": f"normal_upload_transaction:{recovery_id}",
            "phase": "prepared",
        }
        recovery_bytes = helper.canonical(recovery_document)
        protected_write(recovery, recovery_bytes)
        common.recovery_journal = recovery_name
        common.recovery_journal_sha = hashlib.sha256(recovery_bytes).hexdigest()
        helper.action_bind_cleanup(common)
        common.runtime_operation_label = "cleanup-backup-upload"
        common.runtime_operation_token = "8" * 32
        helper.action_arm_operation(common)
        expect_blocked(
            lambda: helper.action_retire_prepared(common),
            "timeout-owned stopped runtime retired its prepared transaction",
        )
        helper.action_prove_operation_absent(common)
        helper.action_authorize_restart(common)
        helper.action_authorize_restart(common)
        wrong_operation = argparse.Namespace(**vars(common))
        wrong_operation.runtime_operation_token = "9" * 32
        expect_blocked(
            lambda: helper.action_complete_restart(wrong_operation),
            "stopped recovery accepted a changed operation token",
        )
        helper.action_complete_restart(common)
        helper.action_complete_cleanup(common)
        expect_blocked(
            lambda: helper.action_resume_runtime(common),
            "crash-recovered backup resumed before journal retirement",
        )
        recovery.unlink()
        resume = argparse.Namespace(**vars(common))
        resume.recovery_journal = "-"
        resume.recovery_journal_sha = "-"
        helper.action_resume_runtime(resume)
        resumed = helper.load_transaction(
            transaction, COMMIT, CONFIGURATION, OPERATION_SHA
        )
        if (
            resumed["runtimeRecoveryPhase"] != "none"
            or resumed["runtimeRecoveryJournalFile"] is not None
            or resumed["runtimeOperationPhase"] != "idle"
        ):
            raise RuntimeError("Stopped upload-cleanup recovery did not resume exactly.")

        # Hostile post-upload-cleanup SIGKILL: the cleanup journal is already
        # absent, but the later verification token remains durable and the
        # prepared transaction cannot be retired or generically restarted.
        common.recovery_journal = "-"
        common.recovery_journal_sha = "-"
        common.runtime_operation_label = "verify-backup"
        common.runtime_operation_token = "a" * 32
        helper.action_arm_operation(common)
        post_cleanup = helper.load_transaction(
            transaction, COMMIT, CONFIGURATION, OPERATION_SHA
        )
        if (
            post_cleanup["runtimeRecoveryPhase"] != "none"
            or post_cleanup["runtimeOperationPhase"] != "operation-armed"
            or post_cleanup["runtimeOperationToken"] != common.runtime_operation_token
        ):
            raise RuntimeError("Post-cleanup SIGKILL lost exact runtime ownership.")
        expect_blocked(
            lambda: helper.action_retire_prepared(common),
            "post-cleanup SIGKILL retired runtime ownership",
        )
        changed_runtime = argparse.Namespace(**vars(common))
        changed_runtime.runtime_ports_sha = "0" * 64
        expect_blocked(
            lambda: helper.action_prove_operation_absent(changed_runtime),
            "post-cleanup recovery accepted changed ports",
        )
        helper.action_prove_operation_absent(common)
        helper.action_authorize_restart(common)
        helper.action_complete_restart(common)

        # Hostile post-rollout timeout/SIGKILL: member-rollout backups have no
        # disposable upload journal at all. The publication token still owns
        # the stopped runtime and supports only the exact bounded retry.
        common.runtime_operation_label = "publish-recovery-evidence"
        common.runtime_operation_token = "b" * 32
        helper.action_arm_operation(common)
        post_rollout = helper.load_transaction(
            transaction, COMMIT, CONFIGURATION, OPERATION_SHA
        )
        if (
            post_rollout["runtimeRecoveryJournalFile"] is not None
            or post_rollout["runtimeOperationPhase"] != "operation-armed"
        ):
            raise RuntimeError("Post-rollout timeout lost journal-free operation ownership.")
        helper.action_prove_operation_absent(common)
        helper.action_authorize_restart(common)
        helper.action_complete_restart(common)
        expect_blocked(
            lambda: helper.action_authorize_restart(common),
            "idle journal-free backup gained generic restart authority",
        )

        evidence = evidence_root / evidence_name
        document = evidence_document("mochirii-2026-08-15-010203-v20260815010203.tar.gz", "e" * 64)
        evidence_bytes = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
        protected_write(evidence, evidence_bytes)
        evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()

        expect_blocked(
            lambda: helper.action_select_pointer(common),
            "terminal publication preceded original runtime restoration",
        )
        common.observed_runtime_state = "running"
        helper.action_complete_original_state(common)

        changed_core_document = dict(document)
        changed_core_document["discourseRevision"] = "0" * 40
        protected_write(
            evidence,
            (json.dumps(changed_core_document, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        expect_blocked(
            lambda: helper.action_select_pointer(common),
            "terminal evidence contradicted the prepared Discourse revision",
        )
        changed_manager_document = dict(document)
        changed_manager_document["dockerManagerRevision"] = "1" * 40
        protected_write(
            evidence,
            (json.dumps(changed_manager_document, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        expect_blocked(
            lambda: helper.action_select_pointer(common),
            "terminal evidence contradicted the prepared Docker Manager revision",
        )
        protected_write(evidence, evidence_bytes)

        interference_name = f"{'3' * 40}-{'4' * 64}-20260815T020304Z-backup.json"
        interference = evidence_root / interference_name
        protected_write(interference, b"{}\n")
        protected_write(pointer, f"{interference}\n".encode("utf-8"))
        expect_blocked(lambda: helper.action_select_pointer(common), "intervening latest pointer")
        protected_write(pointer, previous_pointer)

        quietly(lambda: helper.action_select_pointer(common))
        pointer_sha = hashlib.sha256(f"{evidence}\n".encode("utf-8")).hexdigest()
        common.phase = "pointer-committed"
        common.evidence_sha = evidence_sha
        common.pointer_sha = pointer_sha

        # A crash may durably publish current-backup before the transaction
        # phase replacement. One phase ahead is adopted; two phases ahead is
        # not a possible write ordering and remains blocked.
        prepared = helper.load_transaction(
            transaction, COMMIT, CONFIGURATION, OPERATION_SHA
        )
        impossible_current = helper.current_document(
            prepared, evidence_sha, pointer_sha, "event-committed"
        )
        protected_write(current, helper.canonical(impossible_current))
        expect_blocked(
            lambda: helper.action_publish_phase(common),
            "current receipt advanced two commit points",
        )
        pointer_current = helper.current_document(
            prepared, evidence_sha, pointer_sha, "pointer-committed"
        )
        protected_write(current, helper.canonical(pointer_current))
        helper.action_publish_phase(common)
        expect_blocked(lambda: helper.action_clear(common), "clear before durable passed event")

        protected_write(evidence, evidence_bytes + b" ")
        common.phase = "event-committed"
        expect_blocked(lambda: helper.action_publish_phase(common), "evidence changed after pointer commit")
        protected_write(evidence, evidence_bytes)

        # A retry after lost stdout/power repeats pointer publication and the
        # pointer-committed phase without changing identity. This also models
        # a crash after the event-committed current receipt was fsynced but
        # before the transaction phase replacement was fsynced.
        quietly(lambda: helper.action_select_pointer(common))
        pointer_committed = helper.load_transaction(
            transaction, COMMIT, CONFIGURATION, OPERATION_SHA
        )
        event_current = helper.current_document(
            pointer_committed, evidence_sha, pointer_sha, "event-committed"
        )
        protected_write(current, helper.canonical(event_current))
        common.phase = "pointer-committed"
        helper.action_publish_phase(common)
        common.phase = "event-committed"
        helper.action_publish_phase(common)
        helper.action_clear(common)
        terminal_current = helper.load_current(current)
        if (
            transaction.exists()
            or terminal_current["phase"] != "event-committed"
            or terminal_current["backupOperationSha256"] != OPERATION_SHA
        ):
            raise RuntimeError("Terminal backup transaction was not cleared exactly once.")

        restore_compatible = io.StringIO()
        with contextlib.redirect_stdout(restore_compatible):
            helper.action_inspect_current(common)
        if len(restore_compatible.getvalue().splitlines()) != 5:
            raise RuntimeError("Restore-compatible current-backup inspection changed shape.")
        runtime_inspection = argparse.Namespace(**vars(common))
        runtime_inspection.include_runtime_contract = True
        runtime_contract = io.StringIO()
        with contextlib.redirect_stdout(runtime_contract):
            helper.action_inspect_current(runtime_inspection)
        if len(runtime_contract.getvalue().splitlines()) != 13:
            raise RuntimeError("Backup current-runtime inspection lost its exact binding.")

        # A retry of the same opaque caller operation adopts the exact terminal
        # evidence/current pointer even after transaction removal and lost
        # command success. It cannot retire its own receipt.
        adopted = io.StringIO()
        with contextlib.redirect_stdout(adopted):
            helper.action_adopt_current(common)
        if adopted.getvalue() != f"{evidence_sha}\n":
            raise RuntimeError("Same-operation terminal backup was not adopted.")
        expect_blocked(
            lambda: helper.action_retire_current(common),
            "same operation retired its terminal receipt",
        )

        same_release_stopped = argparse.Namespace(**vars(common))
        same_release_stopped.operation_sha = "8" * 64
        same_release_stopped.original_runtime_state = "stopped"
        helper.action_retire_current(same_release_stopped)
        if current.exists():
            raise RuntimeError("Running-origin receipt blocked a stopped-origin same-release backup.")
        protected_write(current, helper.canonical(terminal_current))

        # A C0 terminal receipt survives an ordinary deployment. A distinct C1
        # operation must be able to self-validate and retire that receipt before
        # binding its new commit, configuration, and exact runtime tuple.
        next_operation = argparse.Namespace(**vars(common))
        next_operation.operation_sha = "0" * 64
        next_operation.commit = "e" * 40
        next_operation.configuration = "9" * 64
        next_operation.current_release_sha = "a" * 64
        next_operation.discourse_revision = "b" * 40
        next_operation.docker_manager_revision = "c" * 40
        next_operation.runtime_environment_sha = "d" * 64
        next_operation.runtime_ports_sha = "e" * 64
        next_operation.runtime_image = f"sha256:{'f' * 64}"
        next_operation.runtime_identity_sha = helper.runtime_identity_digest(
            next_operation.commit,
            next_operation.configuration,
            next_operation.current_release_sha,
            next_operation.discourse_revision,
            next_operation.docker_manager_revision,
            next_operation.runtime_environment_sha,
            next_operation.runtime_ports_sha,
            next_operation.runtime_image,
        )
        next_operation.timestamp = "20260815T020304Z"
        next_operation.evidence_file = helper.exact_evidence_name(
            next_operation.commit, next_operation.configuration, next_operation.timestamp
        )
        rebound_operation = argparse.Namespace(**vars(next_operation))
        rebound_operation.operation_sha = OPERATION_SHA
        expect_blocked(
            lambda: helper.action_retire_current(rebound_operation),
            "same opaque operation retired its C0 receipt through a C1 tuple",
        )
        expect_blocked(
            lambda: helper.action_create(next_operation),
            "new operation prearmed before terminal receipt retirement",
        )
        protected_write(pointer, f"{interference}\n".encode("utf-8"))
        expect_blocked(
            lambda: helper.action_retire_current(next_operation),
            "different operation retired an intervened pointer",
        )
        protected_write(pointer, f"{evidence}\n".encode("utf-8"))
        helper.action_retire_current(next_operation)
        if current.exists():
            raise RuntimeError("C1 operation did not retire the self-validated C0 terminal receipt.")
        next_operation.original_runtime_state = "stopped"
        next_operation.runtime_operation_label = None
        next_operation.runtime_operation_token = None
        next_operation.observed_runtime_state = None
        helper.action_create(next_operation)
        next_prepared = helper.load_transaction(
            transaction,
            next_operation.commit,
            next_operation.configuration,
            next_operation.operation_sha,
        )
        if (
            next_prepared["backupOperationSha256"] != next_operation.operation_sha
            or next_prepared["originalRuntimeState"] != "stopped"
            or next_prepared["runtimeOperationPhase"] != "initial-stopped"
        ):
            raise RuntimeError(
                "New backup transaction did not bind its caller operation. "
                "Stopped-origin runtime state also differed."
            )

        # Hostile unbound-journal window: journal fsync completed, but the host
        # was interrupted before bind and then restored stopped-origin
        # containment. Exact recovery must bind while still initial-stopped.
        next_recovery_id = "2" * 32
        next_recovery_name = (
            f"{next_operation.commit}-{next_operation.configuration}-{next_recovery_id}-"
            "backup-upload-cleanup-required.json"
        )
        next_recovery = evidence_root / next_recovery_name
        next_recovery_document = {
            "schemaVersion": 1,
            "repositoryCommit": next_operation.commit,
            "productionConfigurationSha256": next_operation.configuration,
            "backupOperationSha256": next_operation.operation_sha,
            "transactionId": next_recovery_id,
            "pluginStoreKey": f"normal_upload_transaction:{next_recovery_id}",
            "phase": "prepared",
        }
        next_recovery_bytes = helper.canonical(next_recovery_document)
        protected_write(next_recovery, next_recovery_bytes)
        next_operation.recovery_journal = next_recovery_name
        next_operation.recovery_journal_sha = hashlib.sha256(next_recovery_bytes).hexdigest()
        helper.action_bind_cleanup(next_operation)
        rebound_cleanup = helper.load_transaction(
            transaction,
            next_operation.commit,
            next_operation.configuration,
            next_operation.operation_sha,
        )
        if (
            rebound_cleanup["runtimeRecoveryPhase"] != "cleanup-pending"
            or rebound_cleanup["runtimeOperationPhase"] != "initial-stopped"
        ):
            raise RuntimeError("Stopped-origin unbound journal was not durably adopted.")
        expect_blocked(
            lambda: helper.action_complete_initial_start(next_operation),
            "stopped-origin transaction completed an unauthorized temporary start",
        )
        helper.action_authorize_initial_start(next_operation)
        helper.action_authorize_initial_start(next_operation)
        helper.action_complete_initial_start(next_operation)
        helper.action_complete_cleanup(next_operation)
        next_recovery.unlink()
        next_operation.recovery_journal = "-"
        next_operation.recovery_journal_sha = "-"
        helper.action_resume_runtime(next_operation)

        # Hostile stopped-origin containment SIGKILL: exact stop authority is
        # durable before the stop. Kill after stop proof but before the second
        # phase advance; retry must see authority, never idle + stopped.
        helper.action_contain_temporary_runtime(next_operation)
        containment_armed = helper.load_transaction(
            transaction,
            next_operation.commit,
            next_operation.configuration,
            next_operation.operation_sha,
        )
        if (
            containment_armed["runtimeOperationPhase"]
            != "temporary-stop-authorized"
            or containment_armed["originalRuntimeState"] != "stopped"
            or containment_armed["runtimeRecoveryPhase"] != "none"
        ):
            raise RuntimeError("Temporary runtime stop was not durably pre-authorized.")
        hostile_host_source = (ROOT / "scripts" / "host-backup.sh").read_text(
            encoding="utf-8"
        )
        assert_host_containment_sigkill(hostile_host_source, state_root)
        assert_host_containment_retry(hostile_host_source, state_root, "running")
        assert_host_containment_retry(hostile_host_source, state_root, "stopped")
        post_stop_kill = helper.load_transaction(
            transaction,
            next_operation.commit,
            next_operation.configuration,
            next_operation.operation_sha,
        )
        if post_stop_kill["runtimeOperationPhase"] != "temporary-stop-authorized":
            raise RuntimeError("Post-stop SIGKILL reverted to unowned idle state.")
        helper.action_contain_temporary_runtime(next_operation)
        helper.action_contain_temporary_runtime(next_operation)
        contained = helper.load_transaction(
            transaction,
            next_operation.commit,
            next_operation.configuration,
            next_operation.operation_sha,
        )
        if contained["runtimeOperationPhase"] != "initial-stopped":
            raise RuntimeError("Retry did not durably complete temporary containment.")
        helper.action_authorize_initial_start(next_operation)
        helper.action_complete_initial_start(next_operation)

        # A stopped-origin post-rollout SIGKILL may restart only to continue
        # this transaction, then terminalization must restore stopped state.
        next_operation.runtime_operation_label = "publish-recovery-evidence"
        next_operation.runtime_operation_token = "c" * 32
        helper.action_arm_operation(next_operation)
        helper.action_prove_operation_absent(next_operation)
        helper.action_authorize_restart(next_operation)
        helper.action_complete_restart(next_operation)

        next_evidence = evidence_root / next_operation.evidence_file
        next_document = evidence_document(
            "mochirii-2026-08-15-020304-v20260815020304.tar.gz",
            "d" * 64,
            commit=next_operation.commit,
            configuration=next_operation.configuration,
            discourse_revision=next_operation.discourse_revision,
            docker_manager_revision=next_operation.docker_manager_revision,
        )
        next_bytes = (json.dumps(next_document, sort_keys=True, indent=2) + "\n").encode("utf-8")
        protected_write(next_evidence, next_bytes)
        helper.action_authorize_original_stop(next_operation)
        helper.action_authorize_original_stop(next_operation)
        wrong_state = argparse.Namespace(**vars(next_operation))
        wrong_state.observed_runtime_state = "running"
        expect_blocked(
            lambda: helper.action_complete_original_state(wrong_state),
            "stopped-origin terminal accepted a running final state",
        )
        next_operation.observed_runtime_state = "stopped"
        helper.action_complete_original_state(next_operation)
        restored = helper.load_transaction(
            transaction,
            next_operation.commit,
            next_operation.configuration,
            next_operation.operation_sha,
        )
        if restored["runtimeOperationPhase"] != "original-restored":
            raise RuntimeError("Stopped-origin runtime was not durably restored.")

        quietly(lambda: helper.action_select_pointer(next_operation))
        next_evidence_sha = hashlib.sha256(next_bytes).hexdigest()
        next_pointer_sha = hashlib.sha256(f"{next_evidence}\n".encode("utf-8")).hexdigest()
        next_operation.evidence_sha = next_evidence_sha
        next_operation.pointer_sha = next_pointer_sha
        next_operation.phase = "pointer-committed"
        helper.action_publish_phase(next_operation)
        next_operation.phase = "event-committed"
        helper.action_publish_phase(next_operation)
        helper.action_clear(next_operation)
        terminal_stopped = helper.load_current(current)
        if transaction.exists() or terminal_stopped["originalRuntimeState"] != "stopped":
            raise RuntimeError("Stopped-origin terminal receipt was not cleared exactly once.")
        same_release_running = argparse.Namespace(**vars(next_operation))
        same_release_running.operation_sha = "1" * 64
        same_release_running.original_runtime_state = "running"
        helper.action_retire_current(same_release_running)
        if current.exists():
            raise RuntimeError("Stopped-origin receipt blocked a running-origin same-release backup.")
        protected_write(current, helper.canonical(terminal_stopped))
        restore_retirement = argparse.Namespace(**vars(next_operation))
        restore_retirement.operation_sha = "2" * 64
        restore_retirement.runtime_identity_sha = None
        restore_retirement.current_release_sha = None
        restore_retirement.discourse_revision = None
        restore_retirement.docker_manager_revision = None
        restore_retirement.runtime_environment_sha = None
        restore_retirement.runtime_ports_sha = None
        restore_retirement.runtime_image = None
        helper.action_retire_current(restore_retirement)
        if current.exists():
            raise RuntimeError("Restore-compatible terminal receipt retirement failed.")

        host_source = (ROOT / "scripts" / "host-backup.sh").read_text(encoding="utf-8")
        deploy_source = (ROOT / "scripts" / "host-deploy.sh").read_text(encoding="utf-8")
        restore_source = (ROOT / "scripts" / "host-restore-validate.sh").read_text(encoding="utf-8")
        runtime_wrapper = host_source[
            host_source.index("run_container_command() {") : host_source.index("record_event() {")
        ]
        containment_wrapper = host_source[
            host_source.index("contain_temporary_runtime_on_failure() {") : host_source.index(
                "finish_backup_transaction() {"
            )
        ]
        containment_arm = containment_wrapper.index(
            "backup_transaction_command contain-temporary-runtime"
        )
        containment_stop = containment_wrapper.index("stop_app_safely")
        containment_complete = containment_wrapper.rindex(
            "backup_transaction_command contain-temporary-runtime"
        )
        if not containment_arm < containment_stop < containment_complete:
            raise RuntimeError("Temporary containment was not durably armed before app stop.")
        ordered_runtime = (
            "backup_runtime_operation_command arm-operation",
            "docker exec -e MOCHIRII_OPERATION_TOKEN",
            'container_operation_absent "${operation_token}"',
            "contain_failed_container_operation",
            "backup_runtime_operation_command complete-operation",
        )
        positions = [runtime_wrapper.index(value) for value in ordered_runtime]
        if positions != sorted(positions):
            raise RuntimeError("Host backup runtime arm, execution, absence, containment, or completion order differs.")
        for required in (
            "currentReleaseSha256",
            "discourseRevision",
            "dockerManagerRevision",
            "runtimeEnvironmentSha256",
            "runtimePortBindingsSha256",
            "runtimeContainerImage",
            "(ulimit -f 128; exec 200>&- 201>&-; exec timeout",
            "temporary-stop-authorized)",
            "reconcile_bound_runtime_ownership",
            "restore_original_runtime_state",
            "Backup refuses an active deployment transaction.",
            "Backup refuses an active nonterminal restore transaction.",
        ):
            if required not in host_source:
                raise RuntimeError(f"Host runtime recovery canary is absent: {required}")
        for forbidden in (
            "backup_transaction_command retire-prepared",
            "Same-release current-backup original runtime state differs.",
            "mochirii-forums-deploy",
            "mochirii-forums-restore",
        ):
            if forbidden in host_source:
                raise RuntimeError(f"Backup runtime recovery gained a deploy/restore bypass: {forbidden}")
        if (
            "Deployment refuses an active backup transaction; only the protected backup command may reconcile it."
            not in deploy_source
            or "Restore refuses an active backup transaction; only the protected backup command may reconcile it."
            not in restore_source
        ):
            raise RuntimeError("Deploy or restore can bypass exact backup runtime ownership.")

    print("Backup transaction fault checks passed.")


if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("Backup transaction fault checks require a root test namespace.")
    main()
