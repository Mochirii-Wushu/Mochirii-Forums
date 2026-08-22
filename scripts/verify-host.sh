#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Host verification must run as root."
[[ $# -eq 2 || ( $# -eq 3 && ( $3 == --deployment-transaction || $3 == --deployment-prior-rollback || $3 == --restore-transaction ) ) ]] || fail "Usage: verify-host.sh EXPECTED_COMMIT EXPECTED_CONFIGURATION_SHA256 [--deployment-transaction|--deployment-prior-rollback|--restore-transaction]"
expected_commit="$1"
expected_configuration="$2"
transaction_owner="${3:-standalone}"
[[ ${expected_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Expected commit is malformed."
[[ ${expected_configuration} =~ ^[0-9a-f]{64}$ ]] || fail "Expected configuration digest is malformed."
nginx_log=""
trap '[[ -z ${nginx_log} || ! -e ${nginx_log} ]] || rm -f -- "${nginx_log}"' EXIT
release_dir="/opt/mochirii/forums/releases/${expected_commit}"

python3 -B - /var/lib/mochirii/forums "${expected_commit}" "${expected_configuration}" "${transaction_owner}" <<'PY' >/dev/null
import hashlib
import json
import pathlib
import re
import stat
import sys

state_root = pathlib.Path(sys.argv[1])
commit = sys.argv[2]
configuration = sys.argv[3]
owner = sys.argv[4]
evidence_root = state_root / "evidence"
deployment_journal = state_root / "deployment-transaction.json"
deployment_mutation_journal = state_root / "deployment-mutation.json"
backup_journal = state_root / "backup-transaction.json"
restore_journal = state_root / "restore-transaction.json"
deployment_terminal = state_root / "current-deployment.json"
current_release_path = state_root / "current-release.json"
current_authentication_path = state_root / "current-authentication.json"


def protected_json(path: pathlib.Path, label: str) -> tuple[dict[str, object], bytes]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 65536
    ):
        raise SystemExit(f"{label} is unsafe")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(f"{label} JSON is malformed")
    if not isinstance(document, dict):
        raise SystemExit(f"{label} is not one object")
    return document, raw


def digest(value: object, size: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{size}}}", value) is not None


def timestamp(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 64
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", value) is not None
    )


def exact_protected_file(value: object, expected_sha: object, expected: pathlib.Path | None = None) -> pathlib.Path:
    if not isinstance(value, str) or not value.startswith("/") or not digest(expected_sha):
        raise SystemExit("transaction file binding is malformed")
    path = pathlib.Path(value)
    if expected is not None and path != expected:
        raise SystemExit("transaction file path differs")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o077
        or metadata.st_size > 2 * 1024 * 1024
        or hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha
    ):
        raise SystemExit("transaction file binding differs")
    return path


release_keys = {
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


def valid_release_archive_authority(document):
    return (
        digest(document.get("repositoryTree"), 40)
        and type(document.get("releaseArchiveBytes")) is int
        and 1 <= document["releaseArchiveBytes"] <= 67108864
        and digest(document.get("releaseArchiveContentManifestSha256"))
    )
authentication_suffixes = {
    "consumer-public-producer-pending": "authentication-pending",
    "complete": "authentication-complete",
    "contained-after-e2e-failure": "authentication-contained",
    "contained-producer-state-unproved": "authentication-containment-unproved",
    "activation-deploy-failed": "authentication-activation-failed",
    "activation-deploy-failed-producer-unproved": "authentication-activation-failed-unproved",
}
authentication_common_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "releaseEvidenceFile", "releaseEvidenceSha256", "currentReleaseSha256", "activationPhase",
}
authentication_phase_keys = {
    "consumer-public-producer-pending": authentication_common_keys | {
        "websiteProducerDisabledProved", "containedActivationPassed", "publicForumsVerificationPassed",
    },
    "complete": authentication_common_keys | {
        "pendingAuthenticationEvidenceFile", "pendingAuthenticationEvidenceSha256",
        "websiteEvidenceFile", "websiteEvidenceSha256", "websiteRepositoryCommit",
        "websiteProducerEnabled", "producerFailClosedBeforeEnablePassed", "activeMemberAllowed",
        "inactiveMemberDenied", "unverifiedMemberDenied", "invalidSignatureDenied",
        "malformedRequestDenied", "expiredRequestDenied", "replayDenied", "alternateLoginDisabled",
        "callbackLogRedactionPassed", "callbackBrowserQueryScrubPassed",
        "callbackBrowserPrivateResponsePassed", "terminalHostVerificationPassed",
    },
    "contained-after-e2e-failure": authentication_common_keys | {
        "pendingAuthenticationEvidenceFile", "pendingAuthenticationEvidenceSha256",
        "websiteProducerDisabledProved", "applicationStopped",
    },
    "contained-producer-state-unproved": authentication_common_keys | {
        "pendingAuthenticationEvidenceFile", "pendingAuthenticationEvidenceSha256",
        "websiteProducerDisabledProved", "applicationStopped",
    },
    "activation-deploy-failed": {
        "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
        "previousRepositoryCommit", "previousProductionConfigurationSha256", "releaseEvidenceFile",
        "releaseEvidenceSha256", "currentReleaseSha256", "activationPhase",
        "websiteProducerDisabledProved", "applicationStopped",
    },
    "activation-deploy-failed-producer-unproved": {
        "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
        "previousRepositoryCommit", "previousProductionConfigurationSha256", "releaseEvidenceFile",
        "releaseEvidenceSha256", "currentReleaseSha256", "activationPhase",
        "websiteProducerDisabledProved", "applicationStopped",
    },
}


def validate_published_state(
    reference: dict[str, object],
    release_path: pathlib.Path,
    *,
    allow_marker_transition: bool,
    allow_authentication_transition: bool,
    require_disabled_authentication_absent: bool,
) -> None:
    current, current_raw = protected_json(current_release_path, "current release evidence")
    current_keys = {
        "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
        "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
        "memberRolloutMarkerSha256",
    }
    connect = reference.get("requestedDiscourseConnect")
    if (
        set(current) != current_keys
        or type(current.get("discourseConnectEnabled")) is not bool
        or current.get("repositoryCommit") != reference.get("repositoryCommit")
        or current.get("productionConfigurationSha256") != reference.get("productionConfigurationSha256")
        or current.get("releaseEvidenceFile") != release_path.name
        or current.get("releaseEvidenceSha256") != reference.get("releaseEvidenceSha256")
        or current.get("discourseConnectEnabled") is not connect
    ):
        raise SystemExit("completed deployment differs from current release evidence")

    reference_marker_file = reference.get("memberRolloutMarkerFile")
    reference_marker_sha = reference.get("memberRolloutMarkerSha256")
    current_marker_file = current.get("memberRolloutMarkerFile")
    current_marker_sha = current.get("memberRolloutMarkerSha256")
    marker_transition = (
        allow_marker_transition
        and reference_marker_file is None
        and reference_marker_sha is None
        and current_marker_file == "member-rollout-enabled"
        and digest(current_marker_sha)
    )
    if not marker_transition and (current_marker_file != reference_marker_file or current_marker_sha != reference_marker_sha):
        raise SystemExit("completed deployment member marker transition differs")
    marker = state_root / "member-rollout-enabled"
    if current_marker_file is not None:
        metadata = marker.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or hashlib.sha256(marker.read_bytes()).hexdigest() != current_marker_sha:
            raise SystemExit("current member-rollout marker differs")
    elif marker.exists() or marker.is_symlink():
        raise SystemExit("unrecorded member-rollout marker exists")

    authentication_present = current_authentication_path.exists() or current_authentication_path.is_symlink()
    authentication = None
    if authentication_present:
        authentication, _ = protected_json(current_authentication_path, "current authentication evidence")
        auth_keys = {
            "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
            "authenticationEvidenceSha256", "activationPhase",
        }
        auth_commit = authentication.get("repositoryCommit")
        auth_configuration = authentication.get("productionConfigurationSha256")
        auth_phase = authentication.get("activationPhase")
        suffix = authentication_suffixes.get(auth_phase)
        auth_name = authentication.get("authenticationEvidenceFile")
        auth_sha = authentication.get("authenticationEvidenceSha256")
        if (
            set(authentication) != auth_keys
            or not digest(auth_commit, 40)
            or not digest(auth_configuration)
            or suffix is None
            or auth_name != f"{auth_commit}-{auth_configuration}-{suffix}.json"
            or not digest(auth_sha)
        ):
            raise SystemExit("current authentication evidence schema differs")
        auth_path = evidence_root / str(auth_name)
        auth_record, auth_raw = protected_json(auth_path, "current authentication record")
        if (
            hashlib.sha256(auth_raw).hexdigest() != auth_sha
            or set(auth_record) != authentication_phase_keys[auth_phase]
            or auth_record.get("schemaVersion") != 1
            or not timestamp(auth_record.get("recordedAt"))
            or auth_record.get("repositoryCommit") != auth_commit
            or auth_record.get("productionConfigurationSha256") != auth_configuration
            or auth_record.get("activationPhase") != auth_phase
        ):
            raise SystemExit("current authentication evidence record differs")
    same_auth_tuple = (
        authentication is not None
        and authentication.get("repositoryCommit") == reference.get("repositoryCommit")
        and authentication.get("productionConfigurationSha256") == reference.get("productionConfigurationSha256")
    )
    action = reference.get("authenticationAction")
    if connect:
        if not same_auth_tuple:
            raise SystemExit("completed deployment lost its current authentication tuple")
        allowed_phases = {"consumer-public-producer-pending"}
        if action == "preserve-complete":
            allowed_phases = {"complete"}
        elif allow_authentication_transition and action == "pending":
            allowed_phases.add("complete")
        if authentication.get("activationPhase") not in allowed_phases:
            raise SystemExit("completed deployment authentication transition differs")
        if (
            auth_record.get("releaseEvidenceFile") != release_path.name
            or auth_record.get("releaseEvidenceSha256") != reference.get("releaseEvidenceSha256")
            or (
                not allow_marker_transition
                and not allow_authentication_transition
                and auth_record.get("currentReleaseSha256") != hashlib.sha256(current_raw).hexdigest()
            )
        ):
            raise SystemExit("completed deployment authentication release binding differs")
    elif same_auth_tuple or (require_disabled_authentication_absent and authentication_present):
        raise SystemExit("consumer-disabled deployment retains authentication evidence")


active = {
    "deployment": deployment_journal.exists() or deployment_journal.is_symlink(),
    "deployment-mutation": deployment_mutation_journal.exists() or deployment_mutation_journal.is_symlink(),
    "backup": backup_journal.exists() or backup_journal.is_symlink(),
    "restore": restore_journal.exists() or restore_journal.is_symlink(),
}
allowed_active = {
    "standalone": {frozenset()},
    "--deployment-transaction": {
        frozenset({"deployment-mutation"}),
        frozenset({"deployment", "deployment-mutation"}),
    },
    "--deployment-prior-rollback": {frozenset({"deployment-mutation"})},
    "--restore-transaction": {frozenset({"restore"})},
}[owner]
active_inventory = frozenset(name for name, present in active.items() if present)
if active_inventory not in allowed_active:
    raise SystemExit("active host-operation transaction inventory differs from the verifier owner")

deployment_mutation = None
completed_terminal_matches_expected = False
if deployment_terminal.exists() or deployment_terminal.is_symlink():
    terminal_candidate, _ = protected_json(deployment_terminal, "completed deployment record")
    completed_terminal_matches_expected = (
        terminal_candidate.get("schemaVersion") == 1
        and terminal_candidate.get("phase") == "complete"
        and terminal_candidate.get("repositoryCommit") == commit
        and terminal_candidate.get("productionConfigurationSha256") == configuration
    )
if active["deployment-mutation"]:
    deployment_mutation, _ = protected_json(deployment_mutation_journal, "deployment mutation journal")
    deployment_mutation_keys = {
        "schemaVersion", "phase", "recordedAt", "updatedAt", "deploymentMode",
        "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
        "requestedDiscourseConnect", "targetAppConfigurationFile", "targetAppConfigurationSha256",
        "targetRestoreConfigurationFile", "targetRestoreConfigurationSha256",
        "targetActivationConfigurationFile", "targetActivationConfigurationSha256",
        "previousRepositoryCommit", "previousProductionConfigurationSha256",
        "previousCurrentReleaseSha256", "previousAppConfigurationFile",
        "previousAppConfigurationSha256", "previousCurrentTarget", "activeConfigurationFile",
        "activeConfigurationSha256", "launcherOperationToken", "launcherPreviousImageId",
        "launcherCommand", "databaseMutationPossible", "applicationStopped",
    }
    mutation_phase = deployment_mutation.get("phase")
    mutation_mode = deployment_mutation.get("deploymentMode")
    mutation_commit = deployment_mutation.get("repositoryCommit")
    mutation_configuration = deployment_mutation.get("productionConfigurationSha256")
    mutation_connect = deployment_mutation.get("requestedDiscourseConnect")
    target_parent = pathlib.Path("/var/discourse/containers/releases") / str(mutation_commit) / str(mutation_configuration)
    target_app = str(target_parent / "app.yml")
    target_restore = str(target_parent / "restore.yml")
    target_activation = str(target_parent / "activation.yml")
    if (
        set(deployment_mutation) != deployment_mutation_keys
        or deployment_mutation.get("schemaVersion") != 1
        or mutation_phase not in {
            "prepared", "config-armed", "launcher-armed", "runtime-active", "runtime-contained", "verified",
        }
        or mutation_mode not in {"bootstrap", "rebuild"}
        or not digest(mutation_commit, 40)
        or not digest(mutation_configuration)
        or not digest(deployment_mutation.get("releaseArchiveSha256"))
        or type(mutation_connect) is not bool
        or not timestamp(deployment_mutation.get("recordedAt"))
        or not timestamp(deployment_mutation.get("updatedAt"))
        or deployment_mutation.get("targetAppConfigurationFile") != target_app
        or deployment_mutation.get("targetAppConfigurationSha256") != mutation_configuration
        or deployment_mutation.get("targetRestoreConfigurationFile") != target_restore
        or not digest(deployment_mutation.get("targetRestoreConfigurationSha256"))
        or type(deployment_mutation.get("databaseMutationPossible")) is not bool
        or type(deployment_mutation.get("applicationStopped")) is not bool
    ):
        raise SystemExit("deployment mutation journal tuple, schema, path, or phase differs")
    if owner == "--deployment-prior-rollback":
        if (
            mutation_mode != "rebuild"
            or deployment_mutation.get("previousRepositoryCommit") != commit
            or deployment_mutation.get("previousProductionConfigurationSha256") != configuration
        ):
            raise SystemExit("deployment prior-rollback owner differs from the mutation journal")
    elif mutation_commit != commit or mutation_configuration != configuration:
        raise SystemExit("deployment mutation journal belongs to another target release")
    activation_file = deployment_mutation.get("targetActivationConfigurationFile")
    activation_sha = deployment_mutation.get("targetActivationConfigurationSha256")
    if mutation_connect:
        if activation_file != target_activation or not digest(activation_sha):
            raise SystemExit("deployment mutation activation path differs")
    elif activation_file is not None or activation_sha is not None:
        raise SystemExit("deployment mutation disabled activation path is present")
    declared_configurations = {
        target_app: mutation_configuration,
        target_restore: deployment_mutation["targetRestoreConfigurationSha256"],
    }
    if activation_file is not None:
        declared_configurations[str(activation_file)] = activation_sha
    previous_commit = deployment_mutation.get("previousRepositoryCommit")
    previous_configuration = deployment_mutation.get("previousProductionConfigurationSha256")
    previous_current_sha = deployment_mutation.get("previousCurrentReleaseSha256")
    previous_app = deployment_mutation.get("previousAppConfigurationFile")
    previous_app_sha = deployment_mutation.get("previousAppConfigurationSha256")
    previous_current_target = deployment_mutation.get("previousCurrentTarget")
    previous_values = (
        previous_commit, previous_configuration, previous_current_sha,
        previous_app, previous_app_sha, previous_current_target,
    )
    if mutation_mode == "bootstrap":
        if any(value is not None for value in previous_values):
            raise SystemExit("bootstrap deployment mutation unexpectedly names a prior release")
    else:
        if (
            any(value is None for value in previous_values)
            or not digest(previous_commit, 40)
            or not digest(previous_configuration)
            or not digest(previous_current_sha)
            or not digest(previous_app_sha)
        ):
            raise SystemExit("deployment mutation prior release binding is incomplete")
        expected_previous_app = pathlib.Path("/var/discourse/containers/releases") / str(previous_commit) / str(previous_configuration) / "app.yml"
        expected_previous_target = pathlib.Path("/opt/mochirii/forums/releases") / str(previous_commit)
        exact_protected_file(previous_app, previous_app_sha, expected_previous_app)
        if pathlib.Path(str(previous_current_target)) != expected_previous_target:
            raise SystemExit("deployment mutation prior release target differs")
        declared_configurations[str(previous_app)] = previous_app_sha
    active_configuration = deployment_mutation.get("activeConfigurationFile")
    active_configuration_sha = deployment_mutation.get("activeConfigurationSha256")
    if (active_configuration is None) != (active_configuration_sha is None):
        raise SystemExit("deployment mutation active configuration path is incomplete")
    if active_configuration is not None and declared_configurations.get(str(active_configuration)) != active_configuration_sha:
        raise SystemExit("deployment mutation active configuration path differs")
    launcher_token = deployment_mutation.get("launcherOperationToken")
    launcher_image = deployment_mutation.get("launcherPreviousImageId")
    launcher_command = deployment_mutation.get("launcherCommand")
    if launcher_token is None:
        if launcher_image is not None or launcher_command is not None or mutation_phase == "launcher-armed":
            raise SystemExit("deployment mutation launcher identity is incomplete")
    elif (
        not isinstance(launcher_token, str)
        or re.fullmatch(r"[0-9a-f]{32}", launcher_token) is None
        or not isinstance(launcher_image, str)
        or (launcher_image != "-" and re.fullmatch(r"sha256:[0-9a-f]{64}", launcher_image) is None)
        or launcher_command not in {"bootstrap", "start", "restart", "rebuild", "destroy"}
        or mutation_phase != "launcher-armed"
        or active_configuration is None
    ):
        raise SystemExit("deployment mutation launcher token or command differs")
    if mutation_phase == "verified" and (
        active_configuration != target_app or deployment_mutation.get("applicationStopped") is not False
    ):
        raise SystemExit("verified deployment mutation runtime state differs")
    if owner == "--deployment-prior-rollback" and (
        mutation_phase != "runtime-active"
        or active_configuration != previous_app
        or active_configuration_sha != previous_app_sha
        or deployment_mutation.get("applicationStopped") is not False
        or launcher_token is not None
    ):
        raise SystemExit("deployment prior-rollback runtime state differs")
    if owner == "--deployment-transaction":
        if active["deployment"]:
            if mutation_phase != "verified":
                raise SystemExit("deployment promotion requires a verified mutation journal")
        elif mutation_phase == "verified":
            if not completed_terminal_matches_expected:
                raise SystemExit("verified deployment mutation lacks its completed terminal record")
        elif (
            mutation_phase != "runtime-active"
            or active_configuration != target_app
            or active_configuration_sha != mutation_configuration
            or deployment_mutation.get("applicationStopped") is not False
            or launcher_token is not None
        ):
            raise SystemExit("pre-promotion deployment runtime state differs")

deployment = None
if active["deployment"]:
    deployment, _ = protected_json(deployment_journal, "deployment transaction")
    deployment_keys = {
        "schemaVersion", "phase", "recordedAt", "updatedAt", "deploymentMode",
        "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
        "releaseEvidenceFile", "releaseEvidenceSha256", "requestedDiscourseConnect",
        "memberRolloutMarkerFile", "memberRolloutMarkerSha256", "authenticationAction",
        "forwardFixEvidenceSha256",
    }
    if (
        set(deployment) != deployment_keys
        or deployment.get("schemaVersion") != 1
        or deployment.get("phase") not in {"prepared", "state-committed", "event-committed"}
        or deployment.get("deploymentMode") not in {"bootstrap", "rebuild"}
        or deployment.get("repositoryCommit") != commit
        or deployment.get("productionConfigurationSha256") != configuration
        or not digest(deployment.get("releaseArchiveSha256"))
        or not timestamp(deployment.get("recordedAt"))
        or not timestamp(deployment.get("updatedAt"))
    ):
        raise SystemExit("deployment transaction tuple or phase differs")
    if deployment_mutation is not None and (
        deployment_mutation.get("deploymentMode") != deployment.get("deploymentMode")
        or deployment_mutation.get("releaseArchiveSha256") != deployment.get("releaseArchiveSha256")
        or deployment_mutation.get("requestedDiscourseConnect") is not deployment.get("requestedDiscourseConnect")
    ):
        raise SystemExit("deployment transaction and mutation journal identities differ")
    release = exact_protected_file(
        deployment.get("releaseEvidenceFile"),
        deployment.get("releaseEvidenceSha256"),
        evidence_root / f"{commit}-{configuration}-release.json",
    )
    connect = deployment.get("requestedDiscourseConnect")
    action = deployment.get("authenticationAction")
    if type(connect) is not bool or action not in {"pending", "preserve-complete", "advance-complete", "absent"} or connect != (action in {"pending", "preserve-complete"}):
        raise SystemExit("deployment transaction authentication action differs")
    marker_file = deployment.get("memberRolloutMarkerFile")
    marker_sha = deployment.get("memberRolloutMarkerSha256")
    if (marker_file is None) != (marker_sha is None) or (marker_file is not None and (marker_file != "member-rollout-enabled" or not digest(marker_sha))):
        raise SystemExit("deployment transaction member marker differs")
    forward_sha = deployment.get("forwardFixEvidenceSha256")
    if forward_sha is not None and not digest(forward_sha):
        raise SystemExit("deployment transaction forward-fix digest differs")
    release_document, _ = protected_json(release, "deployment release evidence")
    if (
        set(release_document) != release_keys
        or release_document.get("schemaVersion") != 2
        or not valid_release_archive_authority(release_document)
        or release_document.get("repositoryCommit") != commit
        or release_document.get("productionConfigurationSha256") != configuration
        or release_document.get("releaseArchiveSha256") != deployment.get("releaseArchiveSha256")
        or release_document.get("discourseConnectEnabled") is not connect
        or release_document.get("memberRolloutMarkerFile") != marker_file
        or release_document.get("memberRolloutMarkerSha256") != marker_sha
    ):
        raise SystemExit("deployment transaction release evidence differs")
    validate_published_state(
        deployment,
        release,
        allow_marker_transition=False,
        allow_authentication_transition=False,
        require_disabled_authentication_absent=True,
    )

if active["restore"]:
    restore, _ = protected_json(restore_journal, "restore transaction")
    restore_keys = {
        "schemaVersion", "phase", "restoreMode", "recordedAt", "updatedAt", "repositoryCommit",
        "productionConfigurationSha256", "productionConfigurationFile", "productionConfigurationFileSha256",
        "restoreConfigurationFile", "restoreConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256",
        "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "recoveryUploadIncluded",
        "recoveryUploadStateSha256", "normalUploadInventoryCount", "normalUploadInventorySha256",
        "cleanBackupIntentAt",
        "cleanBackupEvidenceFile", "cleanBackupEvidenceSha256", "cleanBackupFilename", "cleanBackupSha256",
        "restoreEvidenceFile", "restoreEvidenceSha256",
        "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
        "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
    }
    phases = {
        "prepared", "isolating", "isolated", "restoring", "data-restored", "verified-restored",
        "cleaning-fixture", "fixture-cleaned", "member-marker-committed", "production-reopening",
        "production-reopened", "clean-backup-creating", "clean-backup-committed",
        "restore-evidence-committed", "pointer-committed", "event-committed",
    }
    if (
        set(restore) != restore_keys
        or restore.get("schemaVersion") != 1
        or restore.get("phase") not in phases
        or restore.get("restoreMode") not in {"disposable-rehearsal", "clean-target-disaster"}
        or restore.get("repositoryCommit") != commit
        or restore.get("productionConfigurationSha256") != configuration
        or not timestamp(restore.get("recordedAt"))
        or not timestamp(restore.get("updatedAt"))
    ):
        raise SystemExit("restore transaction tuple or phase differs")
    production_configuration_file = exact_protected_file(
        restore.get("productionConfigurationFile"),
        restore.get("productionConfigurationFileSha256"),
        pathlib.Path(f"/var/discourse/containers/releases/{commit}/{configuration}/app.yml"),
    )
    if restore.get("productionConfigurationFileSha256") != configuration:
        raise SystemExit("restore transaction production configuration digest differs")
    restore_configuration_file = exact_protected_file(
        restore.get("restoreConfigurationFile"),
        restore.get("restoreConfigurationSha256"),
        pathlib.Path(f"/var/discourse/containers/releases/{commit}/{configuration}/restore.yml"),
    )
    launcher_values = tuple(restore.get(key) for key in (
        "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
        "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
    ))
    if launcher_values[0] is None:
        if any(value is not None for value in launcher_values):
            raise SystemExit("restore transaction launcher binding is incomplete")
    else:
        allowed_launcher_configurations = {
            str(production_configuration_file): restore["productionConfigurationFileSha256"],
            str(restore_configuration_file): restore["restoreConfigurationSha256"],
        }
        if (
            re.fullmatch(r"[0-9a-f]{32}", str(launcher_values[0])) is None
            or (launcher_values[1] != "-" and re.fullmatch(r"sha256:[0-9a-f]{64}", str(launcher_values[1])) is None)
            or (launcher_values[2] is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", str(launcher_values[2])) is None)
            or launcher_values[2] == launcher_values[1]
            or launcher_values[3] not in {"bootstrap", "start", "restart", "rebuild", "destroy"}
            or allowed_launcher_configurations.get(launcher_values[4]) != launcher_values[5]
            or launcher_values[6] != restore["phase"]
        ):
            raise SystemExit("restore transaction launcher binding differs")
    exact_protected_file(
        restore.get("releaseEvidenceFile"),
        restore.get("releaseEvidenceSha256"),
        evidence_root / f"{commit}-{configuration}-release.json",
    )
    exact_protected_file(restore.get("testedBackupEvidenceFile"), restore.get("testedBackupEvidenceSha256"))
    recovery_included = restore.get("recoveryUploadIncluded")
    recovery_sha = restore.get("recoveryUploadStateSha256")
    if type(recovery_included) is not bool or recovery_included != (recovery_sha is not None) or (recovery_sha is not None and not digest(recovery_sha)):
        raise SystemExit("restore transaction recovery-upload binding differs")
    inventory_count = restore.get("normalUploadInventoryCount")
    if type(inventory_count) is not int or not 0 <= inventory_count <= 10000 or not digest(restore.get("normalUploadInventorySha256")):
        raise SystemExit("restore transaction normal-upload inventory differs")
    clean_phases = {
        "clean-backup-creating", "clean-backup-committed", "pointer-committed",
        "production-reopening", "production-reopened", "restore-evidence-committed", "event-committed",
    }
    clean_intent = restore.get("cleanBackupIntentAt")
    if (restore["phase"] in clean_phases) != (clean_intent is not None) or (clean_intent is not None and not timestamp(clean_intent)):
        raise SystemExit("restore transaction clean-backup intent differs")
    for file_key, sha_key in (
        ("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256"),
        ("restoreEvidenceFile", "restoreEvidenceSha256"),
    ):
        value = restore.get(file_key)
        sha = restore.get(sha_key)
        if (value is None) != (sha is None):
            raise SystemExit("restore transaction optional file binding is incomplete")
        if value is not None:
            exact_protected_file(value, sha)
    filename = restore.get("cleanBackupFilename")
    backup_sha = restore.get("cleanBackupSha256")
    if (filename is None) != (backup_sha is None) or (filename is not None and (not isinstance(filename, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", filename) is None or ".." in filename or not digest(backup_sha))):
        raise SystemExit("restore transaction clean-backup identity differs")


def validate_current_target(expected: pathlib.Path | None) -> None:
    current_target = pathlib.Path("/opt/mochirii/forums/current")
    present = current_target.exists() or current_target.is_symlink()
    if expected is None:
        if present:
            raise SystemExit("bootstrap deployment unexpectedly has a published current release target")
        return
    if not present:
        raise SystemExit("published current release target is absent")
    metadata = current_target.lstat()
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit("published current release target is unsafe")
    try:
        resolved = current_target.resolve(strict=True)
    except (OSError, RuntimeError):
        raise SystemExit("published current release target cannot be resolved")
    if resolved != expected:
        raise SystemExit("published current release target differs from the verifier owner")


def validate_mutation_prior_publication() -> None:
    if deployment_mutation is None or mutation_mode != "rebuild":
        raise SystemExit("deployment mutation has no prior publication to verify")
    current, current_raw = protected_json(current_release_path, "prior current release evidence")
    current_keys = {
        "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
        "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
        "memberRolloutMarkerSha256",
    }
    release_name = f"{previous_commit}-{previous_configuration}-release.json"
    if (
        set(current) != current_keys
        or current.get("repositoryCommit") != previous_commit
        or current.get("productionConfigurationSha256") != previous_configuration
        or current.get("releaseEvidenceFile") != release_name
        or not digest(current.get("releaseEvidenceSha256"))
        or type(current.get("discourseConnectEnabled")) is not bool
        or hashlib.sha256(current_raw).hexdigest() != previous_current_sha
    ):
        raise SystemExit("deployment mutation prior current-release evidence differs")
    release_path = evidence_root / release_name
    release_document, release_raw = protected_json(release_path, "prior immutable release evidence")
    if (
        hashlib.sha256(release_raw).hexdigest() != current.get("releaseEvidenceSha256")
        or set(release_document) != release_keys
        or release_document.get("schemaVersion") != 2
        or not valid_release_archive_authority(release_document)
        or release_document.get("repositoryCommit") != previous_commit
        or release_document.get("productionConfigurationSha256") != previous_configuration
        or release_document.get("discourseConnectEnabled") is not current.get("discourseConnectEnabled")
        or not timestamp(release_document.get("recordedAt"))
    ):
        raise SystemExit("deployment mutation prior release evidence chain differs")
    marker_file = current.get("memberRolloutMarkerFile")
    marker_sha = current.get("memberRolloutMarkerSha256")
    release_marker_file = release_document.get("memberRolloutMarkerFile")
    release_marker_sha = release_document.get("memberRolloutMarkerSha256")
    marker_transition = (
        marker_file == "member-rollout-enabled"
        and digest(marker_sha)
        and release_marker_file is None
        and release_marker_sha is None
    )
    if (
        (marker_file is None) != (marker_sha is None)
        or (marker_file is not None and (marker_file != "member-rollout-enabled" or not digest(marker_sha)))
        or (not marker_transition and (marker_file != release_marker_file or marker_sha != release_marker_sha))
    ):
        raise SystemExit("deployment mutation prior member-rollout evidence differs")
    marker = state_root / "member-rollout-enabled"
    if marker_file is None:
        if marker.exists() or marker.is_symlink():
            raise SystemExit("deployment mutation prior publication has an unrecorded member marker")
    else:
        marker_metadata = marker.lstat()
        if (
            not stat.S_ISREG(marker_metadata.st_mode)
            or stat.S_ISLNK(marker_metadata.st_mode)
            or marker_metadata.st_uid != 0
            or marker_metadata.st_gid != 0
            or stat.S_IMODE(marker_metadata.st_mode) != 0o600
            or marker_metadata.st_size > 65536
            or hashlib.sha256(marker.read_bytes()).hexdigest() != marker_sha
        ):
            raise SystemExit("deployment mutation prior member-rollout marker differs")
    connect = current["discourseConnectEnabled"]
    if connect:
        if (
            release_document.get("activationPhase") != "consumer-public-producer-pending"
            or release_document.get("containedActivationPassed") is not True
            or not digest(release_document.get("containedActivationConfigurationSha256"))
        ):
            raise SystemExit("deployment mutation prior consumer activation differs")
    elif (
        release_document.get("activationPhase") != "consumer-disabled"
        or release_document.get("containedActivationPassed") is not False
        or release_document.get("containedActivationConfigurationSha256") is not None
    ):
        raise SystemExit("deployment mutation prior disabled-consumer state differs")
    for gate in (
        "hostVerificationPassed", "hostedStoragePassed", "storageRestartPersistencePassed",
        "storageRebuildPersistencePassed", "storageCleanupPassed",
    ):
        if release_document.get(gate) is not True:
            raise SystemExit("deployment mutation prior release contains an unpassed gate")


expected_release_target = pathlib.Path("/opt/mochirii/forums/releases") / commit
if owner == "--deployment-transaction" and not active["deployment"]:
    if mutation_phase == "verified":
        validate_current_target(expected_release_target)
    elif mutation_mode == "bootstrap":
        validate_current_target(None)
        if current_release_path.exists() or current_release_path.is_symlink():
            raise SystemExit("bootstrap deployment unexpectedly has current-release evidence")
    else:
        validate_current_target(pathlib.Path(str(previous_current_target)))
        validate_mutation_prior_publication()
elif owner == "--deployment-prior-rollback":
    validate_current_target(expected_release_target)
    validate_mutation_prior_publication()
else:
    validate_current_target(expected_release_target)


def validate_terminal() -> None:
    if not (deployment_terminal.exists() or deployment_terminal.is_symlink()):
        return
    terminal, _ = protected_json(deployment_terminal, "completed deployment record")
    terminal_keys = {
        "schemaVersion", "phase", "recordedAt", "completedAt", "deploymentMode",
        "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
        "releaseEvidenceFile", "releaseEvidenceSha256", "requestedDiscourseConnect",
        "memberRolloutMarkerFile", "memberRolloutMarkerSha256", "authenticationAction",
        "forwardFixEvidenceSha256",
    }
    terminal_commit = terminal.get("repositoryCommit")
    terminal_configuration = terminal.get("productionConfigurationSha256")
    if (
        set(terminal) != terminal_keys
        or terminal.get("schemaVersion") != 1
        or terminal.get("phase") != "complete"
        or terminal.get("deploymentMode") not in {"bootstrap", "rebuild"}
        or not digest(terminal_commit, 40)
        or not digest(terminal_configuration)
        or not digest(terminal.get("releaseArchiveSha256"))
        or not timestamp(terminal.get("recordedAt"))
        or not timestamp(terminal.get("completedAt"))
    ):
        raise SystemExit("completed deployment record schema or identity differs")
    terminal_release = exact_protected_file(
        terminal.get("releaseEvidenceFile"),
        terminal.get("releaseEvidenceSha256"),
        evidence_root / f"{terminal_commit}-{terminal_configuration}-release.json",
    )
    connect = terminal.get("requestedDiscourseConnect")
    action = terminal.get("authenticationAction")
    marker_file = terminal.get("memberRolloutMarkerFile")
    marker_sha = terminal.get("memberRolloutMarkerSha256")
    forward_sha = terminal.get("forwardFixEvidenceSha256")
    if type(connect) is not bool or action not in {"pending", "preserve-complete", "advance-complete", "absent"} or connect != (action in {"pending", "preserve-complete"}):
        raise SystemExit("completed deployment authentication action differs")
    if (marker_file is None) != (marker_sha is None) or (marker_file is not None and (marker_file != "member-rollout-enabled" or not digest(marker_sha))):
        raise SystemExit("completed deployment marker binding differs")
    if forward_sha is not None and not digest(forward_sha):
        raise SystemExit("completed deployment forward-fix binding differs")
    release_document, _ = protected_json(terminal_release, "completed deployment release evidence")
    if (
        set(release_document) != release_keys
        or release_document.get("schemaVersion") != 2
        or not valid_release_archive_authority(release_document)
        or release_document.get("repositoryCommit") != terminal_commit
        or release_document.get("productionConfigurationSha256") != terminal_configuration
        or release_document.get("releaseArchiveSha256") != terminal.get("releaseArchiveSha256")
        or release_document.get("discourseConnectEnabled") is not connect
        or release_document.get("memberRolloutMarkerFile") != marker_file
        or release_document.get("memberRolloutMarkerSha256") != marker_sha
    ):
        raise SystemExit("completed deployment release evidence differs")

    # While a promotion journal is armed, or while a mutation-only runtime is
    # still pre-promotion, the old completed record remains authoritative. A
    # verified mutation-only terminal adoption must instead revalidate the
    # newly completed publication before the mutation journal can be cleared.
    if owner == "--deployment-transaction" and (active["deployment"] or mutation_phase != "verified"):
        return
    validate_published_state(
        terminal,
        terminal_release,
        allow_marker_transition=True,
        allow_authentication_transition=True,
        require_disabled_authentication_absent=False,
    )


validate_terminal()
PY

[[ -L /var/discourse/containers/app.yml ]] || fail "Active configuration is not versioned."
[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "/var/discourse/containers/releases/${expected_commit}/${expected_configuration}/app.yml" ]] || fail "Active configuration does not match the expected release."
[[ "$(sha256sum -- /var/discourse/containers/app.yml | awk '{print $1}')" == "${expected_configuration}" ]] || fail "Active configuration digest changed."
[[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "Expected immutable release is absent."
timeout --signal=TERM --kill-after=15s 300s bash "${release_dir}/scripts/verify-host-security.sh" "${expected_commit}" "${release_dir}" >/dev/null 2>&1 || fail "Host security or installed control digests differ."
timeout --signal=TERM --kill-after=15s 180s bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh" >/dev/null 2>&1 || fail "Deployment checkout is not the exact sealed clean source."
timeout --signal=TERM --kill-after=10s 180s bash "${release_dir}/scripts/verify-runtime-assets.sh" "${expected_commit}" --require-container >/dev/null 2>&1 || fail "Runtime assets or their read-only mount differ from the sealed release."
[[ "$(nproc)" -eq 1 ]] || fail "Host does not expose exactly one CPU."
memory_mib="$(awk '/MemTotal/ { print int($2 / 1024) }' /proc/meminfo)"
[[ ${memory_mib} -ge 1900 && ${memory_mib} -le 2300 ]] || fail "Host memory is outside the reviewed 2 GiB class."
swap_bytes="$(timeout --signal=TERM --kill-after=5s 15s swapon --show=SIZE --bytes --noheadings | awk '{ total += $1 } END { print total + 0 }')" || fail "Host swap readback failed or timed out."
[[ ${swap_bytes} -ge 2147483648 ]] || fail "Host has less than 2 GiB active swap."

[[ "$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.State.Running}}' app)" == true ]] || fail "Application container is not running."
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.State.Status}}' app)" == running ]] || fail "Application container state is not healthy-running."
[[ "$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' app)" == always ]] || fail "Application restart policy changed."
port_bindings="$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{json .HostConfig.PortBindings}}' app)" || fail "Application port readback failed or timed out."
python3 - "${port_bindings}" <<'PY' >/dev/null
import json
import sys
bindings = json.loads(sys.argv[1])
if set(bindings) != {"80/tcp", "443/tcp"}:
    raise SystemExit("unexpected container port inventory")
for container_port, expected_host_port in (("80/tcp", "80"), ("443/tcp", "443")):
    rows = bindings.get(container_port)
    if not isinstance(rows, list) or not rows:
        raise SystemExit("missing public host binding")
    for row in rows:
        if row.get("HostPort") != expected_host_port or row.get("HostIp", "") not in {"", "0.0.0.0", "::"}:
            raise SystemExit("unexpected public host binding")
PY
container_image="$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.Config.Image}}' app)" || fail "Application image-name readback failed or timed out."
[[ ${container_image} == local_discourse/app ]] || fail "Application container image name differs from the official launcher output."
container_image_id="$(timeout --signal=TERM --kill-after=5s 30s docker inspect --format '{{.Image}}' app)" || fail "Application image identity readback failed or timed out."
local_image_id="$(timeout --signal=TERM --kill-after=5s 30s docker image inspect --format '{{.Id}}' "${container_image}")" || fail "Application image object readback failed or timed out."
[[ ${container_image_id} == "${local_image_id}" && ${container_image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Running container differs from the exact local launcher image."
timeout --signal=TERM --kill-after=5s 30s docker exec app bash -lc 'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1"' bash "${expected_commit}"
timeout --signal=TERM --kill-after=5s 30s docker exec app bash -lc 'test "$MOCHIRII_RELEASE_ASSET_ROOT" = "/opt/mochirii-release"'
timeout --signal=TERM --kill-after=5s 30s docker exec -u discourse app bash -lc 'test "$(cd /var/www/discourse && git rev-parse HEAD)" = cbf996f65aae3da1843224aa624bcd9a225931ac'
timeout --signal=TERM --kill-after=5s 30s docker exec -u discourse app bash -lc 'test "$(cd /var/www/discourse/plugins/docker_manager && git rev-parse HEAD)" = c008c3ca7fcc44775215843992e88190adb7b3bf'
timeout --signal=TERM --kill-after=10s 60s docker exec -u discourse app bash -lc '
  set -e
  export GIT_OPTIONAL_LOCKS=0
  git -C /var/www/discourse diff --no-ext-diff --quiet HEAD --
  git -C /var/www/discourse diff --no-ext-diff --cached --quiet
  test -z "$(git -c core.fsmonitor=false -C /var/www/discourse status --porcelain=v1 --untracked-files=all)"
  git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --quiet HEAD --
  git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --cached --quiet
  test -z "$(git -c core.fsmonitor=false -C /var/www/discourse/plugins/docker_manager status --porcelain=v1 --untracked-files=all)"
  cmp -s /var/www/discourse/plugins/mochirii_email_metadata/plugin.rb /opt/mochirii-release/mochirii-email-metadata-plugin.rb
' || fail "Running core, Docker Manager, or mandatory mail component bytes differ."
timeout --signal=TERM --kill-after=10s 180s docker exec app bash -lc '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-site.rb"'
timeout --signal=TERM --kill-after=10s 180s docker exec app bash -lc '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/render-branding-email.rb"'
timeout --signal=TERM --kill-after=5s 60s docker exec -i app python3 -B - <<'PY_NGINX_FILES' >/dev/null || fail "Active nginx configuration files differ from the exact reviewed inventory."
import hashlib
import os
import pathlib
import stat
import sys

MAX_CONFIG_BYTES = 1_048_576
MAX_DIRECTORY_ENTRIES = 32
EXPECTED_DIRECTORY_CHILDREN = {
    "/etc/nginx/conf.d": ("discourse.conf", "outlets"),
    "/etc/nginx/conf.d/outlets": ("before-server", "discourse", "server"),
    "/etc/nginx/conf.d/outlets/before-server": (
        "20-redirect-http-to-https.conf",
        "30-ratelimited.conf",
    ),
    "/etc/nginx/conf.d/outlets/discourse": (
        "20-https.conf",
        "30-ratelimited.conf",
        "35-mochirii-public-response-headers.inc",
        "40-mochirii-public-metadata.conf",
    ),
    "/etc/nginx/conf.d/outlets/server": (
        "10-http.conf",
        "20-https.conf",
        "30-offline-page.conf",
        "35-mochirii-public-response-headers.conf",
        "40-mochirii-feed-denial.conf",
    ),
    "/etc/nginx/modules-enabled": (),
    "/etc/nginx/sites-enabled": (),
}
EXPECTED_FILE_SHA256 = {
    "/etc/nginx/nginx.conf": (
        "942f01a5cce65339d54ef67df4427768473f26b89e348926c8e65929b7863952",
    ),
    "/etc/nginx/mime.types": (
        "d2404914bf644ebde13c987081c3259bdd40e2e31985b90a77c08e42f64efe4e",
    ),
    "/etc/nginx/conf.d/discourse.conf": (
        "fe954577f31a53e71e6dca29eea779e00744969834d1b5301873cddee77295dc",
    ),
    "/etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc": (
        "efff4b424cc29b3a0a20ffcef8d6bf67f9bb8c51db55d124012dbdc0cd69d53b",
    ),
    "/etc/nginx/conf.d/outlets/before-server/20-redirect-http-to-https.conf": (
        "7bb5588965b9122d7dba2a9cf7ff1c5fd9e933b278eacaf0f88176aa8fd72312",
    ),
    "/etc/nginx/conf.d/outlets/before-server/30-ratelimited.conf": (
        "13a8adb310d300c3e1a4525421c0d28c218617316014baabd583394e10cafd52",
    ),
    "/etc/nginx/conf.d/outlets/discourse/20-https.conf": (
        "cfc7898c735f0ca38c2acaeab9165bcceebe3519db1a19593628d368f5fbba09",
    ),
    "/etc/nginx/conf.d/outlets/discourse/30-ratelimited.conf": (
        "855b446d8b3d803097b970fd14f5696f0395e01464d8518dba152a200d51bfa2",
    ),
    "/etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf": (
        "12bb9c934b236c6885b02f3dbf59d809ce66a5ea75b8522f76f9f59cc626df2e",
    ),
    "/etc/nginx/conf.d/outlets/server/10-http.conf": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "/etc/nginx/conf.d/outlets/server/20-https.conf": (
        "5e2dc26f2148bdb83a4927f1e162b959579a8b800f3514272245ca440af21248",
        "6d26204383871f0e76013485555459940ff6f78df1ee7ac7857a58904d49a162",
    ),
    "/etc/nginx/conf.d/outlets/server/30-offline-page.conf": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "/etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf": (
        "2c5be5f9dc56632ddd56e6af8ca2f08028f515e41179be90c5cfa31ec8cbc566",
    ),
    "/etc/nginx/conf.d/outlets/server/40-mochirii-feed-denial.conf": (
        "c82653d574f1747c7ed0822d1423833af8acc982e8d01df96b9072d2bd8b0c87",
    ),
}

if len(sys.argv) not in {1, 2}:
    raise SystemExit("invalid nginx verification root")
root = pathlib.Path(sys.argv[1]) if len(sys.argv) == 2 else pathlib.Path("/")
if not root.is_absolute():
    raise SystemExit("invalid nginx verification root")


def rooted(absolute_path):
    return root / absolute_path.removeprefix("/")


def canonical(path):
    return os.path.normcase(os.path.realpath(path)) == os.path.normcase(os.path.abspath(path))


def directory_children(absolute_path):
    path = rooted(absolute_path)
    try:
        metadata = os.lstat(path)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or not canonical(path):
            raise SystemExit("nginx configuration directory differs")
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= MAX_DIRECTORY_ENTRIES:
                    raise SystemExit("nginx configuration inventory exceeds its bound")
                names.append(entry.name)
    except OSError as error:
        raise SystemExit("nginx configuration directory is unreadable") from error
    return tuple(sorted(names))


def normalized_file_sha256(absolute_path):
    path = rooted(absolute_path)
    try:
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > MAX_CONFIG_BYTES
            or not canonical(path)
        ):
            raise SystemExit("nginx configuration file type or size differs")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size > MAX_CONFIG_BYTES
            ):
                raise SystemExit("nginx configuration file changed during verification")
            data = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError as error:
        raise SystemExit("nginx configuration file is unreadable") from error
    if len(data) > MAX_CONFIG_BYTES:
        raise SystemExit("nginx configuration file exceeds its bound")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SystemExit("nginx configuration file is not UTF-8") from error
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


for directory, expected_children in EXPECTED_DIRECTORY_CHILDREN.items():
    if directory_children(directory) != tuple(sorted(expected_children)):
        raise SystemExit("nginx configuration inventory differs")
for path, expected_digests in EXPECTED_FILE_SHA256.items():
    if normalized_file_sha256(path) not in expected_digests:
        raise SystemExit("nginx configuration content differs")
PY_NGINX_FILES
nginx_log="$(mktemp /var/lib/mochirii/forums/logs/${expected_commit}-nginx.XXXXXXXX.log)"
chmod 0600 "${nginx_log}"
timeout --signal=TERM --kill-after=5s 60s docker exec app nginx -T >"${nginx_log}" 2>&1
grep -F 'include conf.d/outlets/discourse/*.conf;' "${nginx_log}" >/dev/null
grep -F 'include conf.d/outlets/server/*.conf;' "${nginx_log}" >/dev/null
grep -F '<meta name="generator" content="Mochirii Forums">' "${nginx_log}" >/dev/null
grep -F 'location ~* \.(?:rss|atom)$' "${nginx_log}" >/dev/null
grep -F 'location ~ ^/(?:u|users)/admin-login(?:\.[A-Za-z0-9]+)?/?$ { return 419; }' "${nginx_log}" >/dev/null
python3 -B - "${nginx_log}" <<'PY' >/dev/null
import pathlib
import re
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")

def contains_unquoted_block_delimiter(line):
    quote = None
    escaped = False
    for character in line:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote is not None:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == "#":
            break
        elif character in {"{", "}"}:
            return True
    return False

def location_body(marker, label):
    matches = tuple(re.finditer(re.escape(marker) + r"(?P<body>.*?)\n\s*\}", text, re.S))
    if len(matches) != 1:
        raise SystemExit(f"{label} location is absent or duplicated")
    body = matches[0].group("body")
    if any(contains_unquoted_block_delimiter(line) for line in body.splitlines()):
        raise SystemExit(f"{label} location contains a nested block")
    return body

def nginx_directives(source):
    directives = []
    current = []
    quote = None
    escaped = False
    comment = False
    for character in source:
        if comment:
            if character in {"\r", "\n"}:
                comment = False
                current.append(" ")
        elif escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif quote is not None:
            current.append(character)
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            current.append(character)
            quote = character
        elif character == "#":
            comment = True
        elif character == ";":
            directive = "".join(current).strip()
            if directive:
                directives.append(directive + ";")
            current = []
        elif character == "{":
            directive = "".join(current).strip()
            if directive:
                directives.append(directive + " {")
            current = []
        elif character == "}":
            current = []
        else:
            current.append(character)
    return tuple(directives)

def directive_name(directive):
    token = directive.split(None, 1)[0]
    return token.replace('"', "").replace("'", "").replace("\\", "").lower()

if any(
    directive_name(directive) == "proxy_pass_header"
    for directive in nginx_directives(text)
):
    raise SystemExit("rendered proxy configuration can re-enable an upstream response header")

required = {
    "access_log off;", "log_not_found off;", "error_log /dev/null emerg;",
    "proxy_hide_header Cache-Control;", "proxy_hide_header Pragma;",
    "proxy_hide_header Expires;", "proxy_hide_header Referrer-Policy;",
    "expires off;",
    'add_header Cache-Control "private, no-store, max-age=0" always;',
    'add_header Pragma "no-cache" always;', 'add_header Expires "0" always;',
    'add_header Referrer-Policy "no-referrer" always;',
    "include conf.d/outlets/discourse/*.conf;", "proxy_pass http://discourse;",
    "proxy_set_header Host $http_host;", 'proxy_set_header X-Request-Start "t=${msec}";',
    "proxy_set_header X-Forwarded-For $remote_addr;", "proxy_set_header X-Forwarded-Proto $thescheme;",
    'proxy_set_header X-Sendfile-Type "";', 'proxy_set_header X-Accel-Mapping "";',
    'proxy_set_header Client-Ip "";',
}

def verify_sensitive_location(body, label, extra=()):
    directives = nginx_directives(body)
    expected = required | set(extra)
    if len(directives) != len(expected) or set(directives) != expected:
        raise SystemExit(f"{label} logging or proxy boundary differs")
    forbidden = ("$request", "$request_uri", "$args", "$query_string", "$http_referer", "$http_cookie")
    if any(value in directive for value in forbidden for directive in directives):
        raise SystemExit(f"{label} can persist request data")

callback_marker = r"location ~* ^/session/sso_login(?:\.[A-Za-z0-9]+)?/?$ {"
verify_sensitive_location(location_body(callback_marker, "sensitive callback"), "sensitive callback")

email_marker = 'location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$" {'
verify_sensitive_location(
    location_body(email_marker, "administrator recovery privacy"),
    "administrator recovery",
    {'add_header X-Content-Type-Options "nosniff" always;'},
)

denial_marker = r"location ~* ^/session/email-login/ {"
denial_directives = nginx_directives(location_body(denial_marker, "administrator recovery denial"))
if any(denial_directives.count(value) != 1 for value in ("access_log off;", "error_log /dev/null emerg;", "return 420;")):
    raise SystemExit("noncanonical administrator recovery route does not fail privately")

avatar_marker = r"location ~ ^/(svg-sprite/|letter_avatar/|letter_avatar_proxy/|user_avatar|highlight-js|stylesheets|theme-javascripts|favicon/proxied|service-worker|extra-locales/) {"
avatar_directives = nginx_directives(location_body(avatar_marker, "cache-accelerated asset"))
avatar_required = {
    "brotli_comp_level 6;",
    'proxy_ignore_headers "Set-Cookie";',
    'proxy_hide_header "Set-Cookie";',
    'proxy_hide_header "X-Discourse-Username";',
    'proxy_hide_header "X-Runtime";',
    "include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;",
    "proxy_cache one;",
    'proxy_cache_key "$scheme,$host,$request_uri";',
    "proxy_cache_valid 200 301 302 7d;",
    "proxy_cache_bypass $bypass_cache;",
    "proxy_pass http://discourse;",
    "break;",
}
if len(avatar_directives) != len(avatar_required) or set(avatar_directives) != avatar_required:
    raise SystemExit("cache-accelerated asset response-header boundary differs")
PY
for hidden_header in X-Discourse-Route X-Discourse-Username X-Discourse-Crawler-View Discourse-No-Onebox Discourse-Rate-Limit-Error-Code Discourse-Xhr-Redirect Discourse-Actions-Remaining Discourse-Actions-Max Discourse-Logged-Out X-Discourse-TrackView X-Discourse-BrowserPageView X-Discourse-Cached; do
  grep -F "proxy_hide_header ${hidden_header};" "${nginx_log}" >/dev/null
done
timeout --signal=TERM --kill-after=10s 120s docker exec app bash -lc '
  set -euo pipefail
  count=$(find /var/www/discourse/public -maxdepth 1 -type f \( -name "403*.html" -o -name "422*.html" -o -name "500*.html" -o -name "503*.html" \) | wc -l)
  test "$count" -eq 196
  forbidden=$(find /var/www/discourse/public -maxdepth 1 -type f \( -name "403*.html" -o -name "422*.html" -o -name "500*.html" -o -name "503*.html" \) \
    -exec grep -Eil "powered by discourse|discourse[.]org|digitaloceanspaces[.]com|amazonaws[.]com" {} + || true)
  test -z "$forbidden"
  missing=$(find /var/www/discourse/public -maxdepth 1 -type f \( -name "403*.html" -o -name "422*.html" -o -name "500*.html" -o -name "503*.html" \) \
    -exec grep -FL "Mochirii" {} + || true)
  test -z "$missing"
'

listeners="$(timeout --signal=TERM --kill-after=5s 15s ss -H -ltn | awk '{print $4}')" || fail "Host listener readback failed or timed out."
if grep -Eq '(^|:)(5432|6379)$' <<<"${listeners}"; then
  fail "PostgreSQL or Redis is exposed on a host TCP listener."
fi

timeout --signal=TERM --kill-after=10s 300s python3 "${release_dir}/scripts/verify-public-branding.py" --base-url https://forums.mochirii.com --host-header forums.mochirii.com
timeout --signal=TERM --kill-after=10s 180s bash "${release_dir}/scripts/verify-runtime-assets.sh" "${expected_commit}" --require-container >/dev/null 2>&1 || fail "Runtime assets changed during host verification."
printf '%s\n' "Mochirii Forums host verification passed."
