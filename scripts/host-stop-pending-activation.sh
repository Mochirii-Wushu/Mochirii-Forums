#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Pending activation stop must run as root through the distinct operator boundary."
if [[ -n ${SUDO_USER:-} && ${SUDO_USER} != mochirii-forums-operator ]]; then
  fail "Pending activation stop is restricted to the distinct operator or provider console."
fi
[[ $# -eq 3 ]] || fail "Usage: mochirii-forums-stop-pending-activation COMMIT CONFIGURATION_SHA256 'STOP MOCHIRII FORUMS PENDING ACTIVATION'"
commit="$1"
configuration="$2"
confirmation="$3"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Pending activation commit is malformed."
[[ ${configuration} =~ ^[0-9a-f]{64}$ ]] || fail "Pending activation configuration is malformed."
[[ ${confirmation} == "STOP MOCHIRII FORUMS PENDING ACTIVATION" ]] || fail "Exact pending activation stop confirmation is required."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if python3 -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
state_root=/var/lib/mochirii/forums
deployment_mutation="${state_root}/deployment-mutation.json"
deployment_mutation_active=false
if [[ -e ${deployment_mutation} || -L ${deployment_mutation} ]]; then
  deployment_mutation_active=true
fi
for active_transaction in \
  "${state_root}/deployment-transaction.json" \
  "${state_root}/backup-transaction.json" \
  "${state_root}/restore-transaction.json"; do
  [[ ! -e ${active_transaction} && ! -L ${active_transaction} ]] || fail "Pending activation containment refuses an active protected host transaction."
done
current=/var/lib/mochirii/forums/current-release.json
current_authentication=/var/lib/mochirii/forums/current-authentication.json
evidence_root=/var/lib/mochirii/forums/evidence
[[ -z "$(find "${evidence_root}" -maxdepth 1 \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) -print -quit 2>/dev/null || true)" ]] || fail "Pending activation containment refuses unresolved hosted-storage cleanup."
[[ -f ${current} && ! -L ${current} ]] || fail "Current release evidence is absent."
[[ "$(stat -c '%U:%G %a' "${current}")" == "root:root 600" ]] || fail "Current release evidence permissions differ."
[[ -f ${current_authentication} && ! -L ${current_authentication} ]] || fail "Pending authentication evidence is absent."
[[ "$(stat -c '%U:%G %a' "${current_authentication}")" == "root:root 600" ]] || fail "Pending authentication evidence permissions differ."
authentication_phase="$(python3 -B - "${current_authentication}" "${commit}" "${configuration}" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}
if set(document) != required or document.get("repositoryCommit") != sys.argv[2] or document.get("productionConfigurationSha256") != sys.argv[3]:
    raise SystemExit("authentication pointer tuple differs")
print(document.get("activationPhase", ""))
PY
)" || fail "Pending authentication pointer is malformed."
if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved && ${deployment_mutation_active} != true ]]; then
  fail "Activation failure producer reconciliation requires its exact deployment mutation journal."
fi
if [[ ${deployment_mutation_active} == true && ${authentication_phase} != activation-deploy-failed-producer-unproved ]]; then
  fail "Pending activation containment refuses this active deployment mutation state."
fi
if [[ ${authentication_phase} == contained-after-e2e-failure || ${authentication_phase} == activation-deploy-failed ]]; then
  release_state="/opt/mochirii/forums/releases/${commit}/scripts/authentication-state.py"
  [[ -f ${release_state} && ! -L ${release_state} ]] || fail "Terminal containment state validator is absent."
  validated_phase="$(python3 -B "${release_state}" --pointer "${current_authentication}" --expected-commit "${commit}" --expected-configuration "${configuration}")" || fail "Terminal containment evidence chain differs."
  [[ ${validated_phase} == "${authentication_phase}" ]] || fail "Terminal containment phase differs after validation."
  timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
  stopped_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null || true)"
  if [[ ${stopped_state} != false ]]; then
    stopped_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker ps -a --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || fail "Terminal containment inventory could not be read."
    [[ -z ${stopped_inventory} ]] || fail "Terminal containment application stop could not be proved."
  fi
  timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || fail "Terminal containment no longer proves the Website producer disabled."
  containment_sha="$(python3 -B - "${current_authentication}" <<'PY'
import json
import pathlib
import re
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("authenticationEvidenceSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", value):
    raise SystemExit("containment digest is malformed")
print(value)
PY
)" || fail "Terminal containment digest is malformed."
  python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
    --path /var/lib/mochirii/forums/logs/events.log --operation authentication-e2e --status blocked \
    --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
    --field "evidence_sha256=${containment_sha}" >/dev/null || fail "Terminal containment event could not be committed durably."
  printf '%s\n' "Mochirii Forums authentication containment was already terminal and was revalidated successfully."
  exit 0
fi
if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then
  readarray -t evidence < <(python3 -B - "${current}" "${current_authentication}" "${commit}" "${configuration}" "${deployment_mutation}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

current_path = pathlib.Path(sys.argv[1])
pointer_path = pathlib.Path(sys.argv[2])
target_commit = sys.argv[3]
target_configuration = sys.argv[4]
mutation_argument = sys.argv[5]
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
pointer_keys = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}
failure_name = f"{target_commit}-{target_configuration}-authentication-activation-failed-unproved.json"
failure_path = current_path.parent / "evidence" / failure_name
if (
    set(pointer) != pointer_keys
    or pointer.get("repositoryCommit") != target_commit
    or pointer.get("productionConfigurationSha256") != target_configuration
    or pointer.get("activationPhase") != "activation-deploy-failed-producer-unproved"
    or pointer.get("authenticationEvidenceFile") != failure_name
    or re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("authenticationEvidenceSha256", ""))) is None
):
    raise SystemExit("activation failure pointer differs")
metadata = failure_path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
    raise SystemExit("activation failure record is unsafe")
failure_bytes = failure_path.read_bytes()
if hashlib.sha256(failure_bytes).hexdigest() != pointer.get("authenticationEvidenceSha256"):
    raise SystemExit("activation failure record digest differs")
failure = json.loads(failure_bytes)
failure_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "previousRepositoryCommit", "previousProductionConfigurationSha256", "releaseEvidenceFile",
    "releaseEvidenceSha256", "currentReleaseSha256", "activationPhase",
    "websiteProducerDisabledProved", "applicationStopped",
}
previous_commit = failure.get("previousRepositoryCommit", "")
previous_configuration = failure.get("previousProductionConfigurationSha256", "")
release_name = f"{previous_commit}-{previous_configuration}-release.json"
if (
    set(failure) != failure_keys
    or failure.get("schemaVersion") != 1
    or failure.get("repositoryCommit") != target_commit
    or failure.get("productionConfigurationSha256") != target_configuration
    or not re.fullmatch(r"[0-9a-f]{40}", previous_commit)
    or not re.fullmatch(r"[0-9a-f]{64}", previous_configuration)
    or failure.get("releaseEvidenceFile") != release_name
    or failure.get("activationPhase") != "activation-deploy-failed-producer-unproved"
    or failure.get("websiteProducerDisabledProved") is not False
    or failure.get("applicationStopped") is not True
):
    raise SystemExit("activation failure record tuple differs")
current_bytes = current_path.read_bytes()
current_metadata = current_path.lstat()
if (
    not stat.S_ISREG(current_metadata.st_mode)
    or stat.S_ISLNK(current_metadata.st_mode)
    or current_metadata.st_uid != 0
    or current_metadata.st_gid != 0
    or stat.S_IMODE(current_metadata.st_mode) != 0o600
    or current_metadata.st_size > 65536
):
    raise SystemExit("stopped prior release pointer is unsafe")
current = json.loads(current_bytes)
current_keys = {
    "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
    "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
if (
    set(current) != current_keys
    or current.get("repositoryCommit") != previous_commit
    or current.get("productionConfigurationSha256") != previous_configuration
    or current.get("releaseEvidenceFile") != release_name
    or current.get("discourseConnectEnabled") is not False
    or current.get("memberRolloutMarkerFile") != "member-rollout-enabled"
    or failure.get("currentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()
):
    raise SystemExit("stopped prior release pointer differs")
release_path = current_path.parent / "evidence" / release_name
release_metadata = release_path.lstat()
if not stat.S_ISREG(release_metadata.st_mode) or stat.S_ISLNK(release_metadata.st_mode) or release_metadata.st_uid != 0 or release_metadata.st_gid != 0 or stat.S_IMODE(release_metadata.st_mode) != 0o600 or release_metadata.st_size > 65536:
    raise SystemExit("prior release evidence is unsafe")
release_sha = hashlib.sha256(release_path.read_bytes()).hexdigest()
release = json.loads(release_path.read_text(encoding="utf-8"))
if (
    failure.get("releaseEvidenceSha256") != release_sha
    or current.get("releaseEvidenceSha256") != release_sha
    or release.get("repositoryCommit") != previous_commit
    or release.get("productionConfigurationSha256") != previous_configuration
    or release.get("discourseConnectEnabled") is not False
    or release.get("activationPhase") != "consumer-disabled"
    or release.get("memberRolloutMarkerFile") != "member-rollout-enabled"
    or release.get("memberRolloutMarkerSha256") != current.get("memberRolloutMarkerSha256")
):
    raise SystemExit("prior release evidence chain differs")
marker = current_path.parent / "member-rollout-enabled"
marker_metadata = marker.lstat()
if (
    not stat.S_ISREG(marker_metadata.st_mode)
    or stat.S_ISLNK(marker_metadata.st_mode)
    or marker_metadata.st_uid != 0
    or marker_metadata.st_gid != 0
    or stat.S_IMODE(marker_metadata.st_mode) != 0o600
    or marker_metadata.st_size > 65536
):
    raise SystemExit("member-rollout marker is unsafe")
marker_bytes = marker.read_bytes()
if hashlib.sha256(marker_bytes).hexdigest() != current.get("memberRolloutMarkerSha256"):
    raise SystemExit("member-rollout marker digest differs")

def validate_mutation(mutation_path: pathlib.Path) -> None:
    mutation_metadata = mutation_path.lstat()
    if (
        mutation_path != current_path.parent / "deployment-mutation.json"
        or not stat.S_ISREG(mutation_metadata.st_mode)
        or stat.S_ISLNK(mutation_metadata.st_mode)
        or mutation_metadata.st_uid != 0
        or mutation_metadata.st_gid != 0
        or stat.S_IMODE(mutation_metadata.st_mode) != 0o600
        or mutation_metadata.st_size > 65536
    ):
        raise SystemExit("deployment mutation journal is unsafe")
    mutation = json.loads(mutation_path.read_text(encoding="utf-8"))
    mutation_keys = {
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
    target_root = pathlib.Path("/var/discourse/containers/releases") / target_commit / target_configuration
    previous_root = pathlib.Path("/var/discourse/containers/releases") / previous_commit / previous_configuration
    target_app = target_root / "app.yml"
    target_restore = target_root / "restore.yml"
    target_activation = target_root / "activation.yml"
    previous_app = previous_root / "app.yml"
    previous_target = pathlib.Path("/opt/mochirii/forums/releases") / previous_commit
    if (
        set(mutation) != mutation_keys
        or mutation.get("schemaVersion") != 1
        or mutation.get("phase") != "runtime-contained"
        or mutation.get("deploymentMode") != "rebuild"
        or mutation.get("repositoryCommit") != target_commit
        or mutation.get("productionConfigurationSha256") != target_configuration
        or re.fullmatch(r"[0-9a-f]{64}", str(mutation.get("releaseArchiveSha256", ""))) is None
        or mutation.get("requestedDiscourseConnect") is not True
        or mutation.get("targetAppConfigurationFile") != str(target_app)
        or mutation.get("targetAppConfigurationSha256") != target_configuration
        or mutation.get("targetRestoreConfigurationFile") != str(target_restore)
        or re.fullmatch(r"[0-9a-f]{64}", str(mutation.get("targetRestoreConfigurationSha256", ""))) is None
        or mutation.get("targetActivationConfigurationFile") != str(target_activation)
        or re.fullmatch(r"[0-9a-f]{64}", str(mutation.get("targetActivationConfigurationSha256", ""))) is None
        or mutation.get("previousRepositoryCommit") != previous_commit
        or mutation.get("previousProductionConfigurationSha256") != previous_configuration
        or mutation.get("previousCurrentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()
        or mutation.get("previousAppConfigurationFile") != str(previous_app)
        or mutation.get("previousAppConfigurationSha256") != previous_configuration
        or mutation.get("previousCurrentTarget") != str(previous_target)
        or mutation.get("activeConfigurationFile") != str(previous_app)
        or mutation.get("activeConfigurationSha256") != previous_configuration
        or mutation.get("launcherOperationToken") is not None
        or mutation.get("launcherPreviousImageId") is not None
        or mutation.get("launcherCommand") is not None
        or type(mutation.get("databaseMutationPossible")) is not bool
        or mutation.get("applicationStopped") is not True
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(mutation.get("recordedAt", ""))) is None
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(mutation.get("updatedAt", ""))) is None
    ):
        raise SystemExit("deployment mutation stopped retry tuple differs")

    def exact_configuration(path: pathlib.Path, expected_sha: str) -> None:
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
            raise SystemExit("deployment mutation configuration binding differs")

    exact_configuration(target_app, target_configuration)
    exact_configuration(target_restore, mutation["targetRestoreConfigurationSha256"])
    exact_configuration(target_activation, mutation["targetActivationConfigurationSha256"])
    exact_configuration(previous_app, previous_configuration)
    active_link = pathlib.Path("/var/discourse/containers/app.yml")
    current_target = pathlib.Path("/opt/mochirii/forums/current")
    for link, expected in ((active_link, previous_app), (current_target, previous_target)):
        link_metadata = link.lstat()
        if (
            not stat.S_ISLNK(link_metadata.st_mode)
            or link_metadata.st_uid != 0
            or link_metadata.st_gid != 0
            or link.resolve(strict=True) != expected
        ):
            raise SystemExit("deployment mutation published target binding differs")
validate_mutation(pathlib.Path(mutation_argument))
print(release_name)
print(release_sha)
print(hashlib.sha256(current_bytes).hexdigest())
print(previous_commit)
print(previous_configuration)
print("activation-deploy-failed-producer-unproved")
PY
  )
else
readarray -t evidence < <(python3 -B - "${current}" "${current_authentication}" "${commit}" "${configuration}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
authentication_path = pathlib.Path(sys.argv[2])
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
    "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
if set(document) != required:
    raise SystemExit("current evidence schema differs")
if document.get("repositoryCommit") != sys.argv[3] or document.get("productionConfigurationSha256") != sys.argv[4]:
    raise SystemExit("current evidence identity differs")
if document.get("discourseConnectEnabled") is not True:
    raise SystemExit("consumer is not pending public authentication")
record = path.parent / "evidence" / document.get("releaseEvidenceFile", "")
if not record.is_file() or record.is_symlink() or record.stat().st_uid != 0 or record.stat().st_mode & 0o077:
    raise SystemExit("release evidence is unsafe")
digest = hashlib.sha256(record.read_bytes()).hexdigest()
if digest != document.get("releaseEvidenceSha256"):
    raise SystemExit("release evidence digest differs")
release = json.loads(record.read_text(encoding="utf-8"))
if (
    release.get("repositoryCommit") != sys.argv[3]
    or release.get("productionConfigurationSha256") != sys.argv[4]
    or release.get("discourseConnectEnabled") is not True
    or release.get("containedActivationPassed") is not True
    or release.get("activationPhase") != "consumer-public-producer-pending"
):
    raise SystemExit("release activation phase differs")
authentication = json.loads(authentication_path.read_text(encoding="utf-8"))
pointer_keys = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}
if set(authentication) != pointer_keys:
    raise SystemExit("current authentication evidence schema differs")
pending_name = f"{sys.argv[3]}-{sys.argv[4]}-authentication-pending.json"
if (
    authentication.get("repositoryCommit") != sys.argv[3]
    or authentication.get("productionConfigurationSha256") != sys.argv[4]
    or authentication.get("activationPhase") not in {
        "consumer-public-producer-pending", "contained-producer-state-unproved"
    }
):
    raise SystemExit("authentication is not pending or awaiting producer-state reconciliation")
pending = path.parent / "evidence" / pending_name
if (
    not pending.is_file()
    or pending.is_symlink()
    or pending.stat().st_uid != 0
    or pending.stat().st_mode & 0o077
    or pending.stat().st_size > 65536
):
    raise SystemExit("pending authentication evidence is unsafe")
pending_sha = hashlib.sha256(pending.read_bytes()).hexdigest()
pending_document = json.loads(pending.read_text(encoding="utf-8"))
pending_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "releaseEvidenceFile", "releaseEvidenceSha256", "currentReleaseSha256",
    "activationPhase", "websiteProducerDisabledProved", "containedActivationPassed",
    "publicForumsVerificationPassed",
}
if (
    set(pending_document) != pending_keys
    or pending_document.get("schemaVersion") != 1
    or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(pending_document.get("recordedAt", "")))
    or (
        pending_document.get("repositoryCommit") != sys.argv[3]
        or pending_document.get("productionConfigurationSha256") != sys.argv[4]
        or pending_document.get("releaseEvidenceFile") != record.name
        or pending_document.get("releaseEvidenceSha256") != digest
        or pending_document.get("currentReleaseSha256") != hashlib.sha256(path.read_bytes()).hexdigest()
        or pending_document.get("activationPhase") != "consumer-public-producer-pending"
        or pending_document.get("websiteProducerDisabledProved") is not True
        or pending_document.get("containedActivationPassed") is not True
        or pending_document.get("publicForumsVerificationPassed") is not True
    )
):
    raise SystemExit("pending authentication evidence tuple differs")
phase = authentication.get("activationPhase")
if phase == "consumer-public-producer-pending":
    if (
        authentication.get("authenticationEvidenceFile") != pending_name
        or authentication.get("authenticationEvidenceSha256") != pending_sha
    ):
        raise SystemExit("pending authentication evidence digest differs")
else:
    unproved_name = f"{sys.argv[3]}-{sys.argv[4]}-authentication-containment-unproved.json"
    unproved = path.parent / "evidence" / unproved_name
    if (
        authentication.get("authenticationEvidenceFile") != unproved_name
        or not unproved.is_file()
        or unproved.is_symlink()
        or unproved.stat().st_uid != 0
        or unproved.stat().st_mode & 0o077
        or unproved.stat().st_size > 65536
    ):
        raise SystemExit("unproved containment evidence is unsafe")
    unproved_sha = hashlib.sha256(unproved.read_bytes()).hexdigest()
    if authentication.get("authenticationEvidenceSha256") != unproved_sha:
        raise SystemExit("unproved containment evidence digest differs")
    unproved_document = json.loads(unproved.read_text(encoding="utf-8"))
    unproved_keys = {
        "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
        "releaseEvidenceFile", "releaseEvidenceSha256", "currentReleaseSha256",
        "pendingAuthenticationEvidenceFile", "pendingAuthenticationEvidenceSha256",
        "activationPhase", "websiteProducerDisabledProved", "applicationStopped",
    }
    if (
        set(unproved_document) != unproved_keys
        or unproved_document.get("schemaVersion") != 1
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(unproved_document.get("recordedAt", "")))
        or unproved_document.get("repositoryCommit") != sys.argv[3]
        or unproved_document.get("productionConfigurationSha256") != sys.argv[4]
        or unproved_document.get("releaseEvidenceFile") != record.name
        or unproved_document.get("releaseEvidenceSha256") != digest
        or unproved_document.get("currentReleaseSha256") != hashlib.sha256(path.read_bytes()).hexdigest()
        or unproved_document.get("pendingAuthenticationEvidenceFile") != pending_name
        or unproved_document.get("pendingAuthenticationEvidenceSha256") != pending_sha
        or unproved_document.get("activationPhase") != "contained-producer-state-unproved"
        or unproved_document.get("websiteProducerDisabledProved") is not False
        or unproved_document.get("applicationStopped") is not True
    ):
        raise SystemExit("unproved containment evidence tuple differs")
print(record.name)
print(digest)
print(hashlib.sha256(path.read_bytes()).hexdigest())
print(pending_name)
print(pending_sha)
print(phase)
PY
)
fi
if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then
  [[ ${#evidence[@]} -eq 6 && ${evidence[1]} =~ ^[0-9a-f]{64}$ && ${evidence[2]} =~ ^[0-9a-f]{64}$ && ${evidence[3]} =~ ^[0-9a-f]{40}$ && ${evidence[4]} =~ ^[0-9a-f]{64}$ && ${evidence[5]} == activation-deploy-failed-producer-unproved ]] || fail "Activation-deploy failure evidence is malformed."
else
  [[ ${#evidence[@]} -eq 6 && ${evidence[1]} =~ ^[0-9a-f]{64}$ && ${evidence[2]} =~ ^[0-9a-f]{64}$ && ${evidence[4]} =~ ^[0-9a-f]{64}$ ]] || fail "Pending activation evidence is malformed."
  [[ ${evidence[5]} == consumer-public-producer-pending || ${evidence[5]} == contained-producer-state-unproved ]] || fail "Pending activation phase is malformed."
fi

timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
stopped=false
if state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)"; then
  [[ ${state} == false ]] && stopped=true
elif inventory="$(timeout --signal=TERM --kill-after=5s 15 docker ps -a --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)"; then
  [[ -z ${inventory} ]] && stopped=true
fi
[[ ${stopped} == true ]] || fail "CRITICAL: pending activation application stop could not be proved."
producer_disabled_proved=false
if timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1; then
  producer_disabled_proved=true
fi
if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then
  containment_phase=activation-deploy-failed-producer-unproved
  containment_suffix=authentication-activation-failed-unproved
  if [[ ${producer_disabled_proved} == true ]]; then
    containment_phase=activation-deploy-failed
    containment_suffix=authentication-activation-failed
  fi
else
  containment_phase=contained-producer-state-unproved
  [[ ${producer_disabled_proved} == false ]] || containment_phase=contained-after-e2e-failure
  containment_suffix=authentication-containment-unproved
  [[ ${producer_disabled_proved} == false ]] || containment_suffix=authentication-contained
fi
containment_record="${evidence_root}/${commit}-${configuration}-${containment_suffix}.json"
if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then
python3 -B - "${containment_record}" "${commit}" "${configuration}" "${evidence[3]}" "${evidence[4]}" "${evidence[0]}" "${evidence[1]}" "${evidence[2]}" "${containment_phase}" "${producer_disabled_proved}" <<'PY'
import datetime
import json
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
if sys.argv[10] not in {"true", "false"}:
    raise SystemExit("producer-state evidence is malformed")
document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "previousRepositoryCommit": sys.argv[4],
    "previousProductionConfigurationSha256": sys.argv[5],
    "releaseEvidenceFile": sys.argv[6],
    "releaseEvidenceSha256": sys.argv[7],
    "currentReleaseSha256": sys.argv[8],
    "activationPhase": sys.argv[9],
    "websiteProducerDisabledProved": sys.argv[10] == "true",
    "applicationStopped": True,
}
def discard_safe_partial():
    if not candidate.exists() and not candidate.is_symlink():
        return
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("activation failure evidence partial is unsafe")
    candidate.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("existing activation failure evidence is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document) or any(existing.get(key) != value for key, value in document.items() if key != "recordedAt"):
        raise SystemExit("existing activation failure evidence differs")
    discard_safe_partial()
else:
    discard_safe_partial()
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
        target.flush()
        os.fsync(target.fileno())
    os.link(candidate, path, follow_symlinks=False)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        candidate.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)
PY
else
python3 -B - "${containment_record}" "${commit}" "${configuration}" "${evidence[0]}" "${evidence[1]}" "${evidence[2]}" "${evidence[3]}" "${evidence[4]}" "${containment_phase}" "${producer_disabled_proved}" <<'PY'
import datetime
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
if sys.argv[10] not in {"true", "false"}:
    raise SystemExit("producer-state evidence is malformed")
document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "releaseEvidenceFile": sys.argv[4],
    "releaseEvidenceSha256": sys.argv[5],
    "currentReleaseSha256": sys.argv[6],
    "pendingAuthenticationEvidenceFile": sys.argv[7],
    "pendingAuthenticationEvidenceSha256": sys.argv[8],
    "activationPhase": sys.argv[9],
    "websiteProducerDisabledProved": sys.argv[10] == "true",
    "applicationStopped": True,
}
def discard_safe_partial():
    if not candidate.exists() and not candidate.is_symlink():
        return
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit("containment evidence partial is unsafe")
    candidate.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

if path.exists() or path.is_symlink():
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise SystemExit("existing containment evidence is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document):
        raise SystemExit("existing containment evidence schema differs")
    for key, value in document.items():
        if key != "recordedAt" and existing.get(key) != value:
            raise SystemExit("existing containment evidence tuple differs")
    discard_safe_partial()
else:
    discard_safe_partial()
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
        target.flush()
        os.fsync(target.fileno())
    os.link(candidate, path, follow_symlinks=False)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        candidate.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)
PY
fi
[[ "$(stat -c '%U:%G %a' "${containment_record}")" == "root:root 600" ]] || fail "Authentication containment evidence permissions differ."
containment_sha="$(sha256sum -- "${containment_record}" | awk '{print $1}')"
[[ ${containment_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Authentication containment evidence digest is malformed."
python3 -B - "${current_authentication}" "${commit}" "${configuration}" "$(basename -- "${containment_record}")" "${containment_sha}" "${containment_phase}" <<'PY'
import json
import os
import pathlib
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
document = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "authenticationEvidenceFile": sys.argv[4],
    "authenticationEvidenceSha256": sys.argv[5],
    "activationPhase": sys.argv[6],
}
with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as candidate:
    json.dump(document, candidate, sort_keys=True)
    candidate.write("\n")
    candidate.flush()
    os.fsync(candidate.fileno())
    temporary = pathlib.Path(candidate.name)
temporary.chmod(0o600)
os.replace(temporary, path)
directory = os.open(path.parent, os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
[[ "$(stat -c '%U:%G %a' "${current_authentication}")" == "root:root 600" ]] || fail "Current authentication containment pointer permissions differ."

python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
  --path /var/lib/mochirii/forums/logs/events.log --operation authentication-e2e --status blocked \
  --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
  --field "evidence_sha256=${containment_sha}" >/dev/null || fail "Authentication containment event could not be committed durably."
[[ ${producer_disabled_proved} == true ]] || fail "The Forums application is stopped, but the Website producer-disabled state could not be proved."
if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then
  printf '%s\n' "Mochirii Forums failed activation retry was stopped and its Website producer-disabled state was independently verified."
else
  printf '%s\n' "Mochirii Forums pending authentication activation was stopped and independently verified."
fi
