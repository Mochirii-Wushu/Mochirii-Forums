#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly docker_revision="ed9f680b0df1de28f062de1769d89d22b2644d1b"
readonly core_revision="cbf996f65aae3da1843224aa624bcd9a225931ac"
readonly manager_revision="c008c3ca7fcc44775215843992e88190adb7b3bf"
readonly base_image="discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
readonly incoming_root="/var/lib/mochirii/forums/incoming"
readonly quarantine_root="/var/lib/mochirii/forums/quarantine"
readonly evidence_root="/var/lib/mochirii/forums/evidence"
readonly logs_root="/var/lib/mochirii/forums/logs"
readonly releases_root="/opt/mochirii/forums/releases"
readonly assets_root="/opt/mochirii/forums/runtime-assets"
readonly configs_root="/var/discourse/containers/releases"
readonly runtime_json="/etc/mochirii/forums.runtime.json"
readonly app_config="/var/discourse/containers/app.yml"
readonly canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"
readonly launcher_bootstrap_cid="/var/discourse/cids/app_bootstrap.cid"
readonly deployment_recovery_journal="/var/lib/mochirii/forums/deployment-forward-fix-required.json"
readonly deployment_mutation_journal="/var/lib/mochirii/forums/deployment-mutation.json"
readonly deployment_transaction="/var/lib/mochirii/forums/deployment-transaction.json"
readonly deployment_terminal="/var/lib/mochirii/forums/current-deployment.json"
readonly launcher_timeout_seconds=7200
readonly launcher_cumulative_budget_seconds=7800
readonly repository_validator_sha256="1216b2bfd1c00789083af7df118efced18e49635b9609be3e105f7e5f44ecdf1"
readonly repository_contract_tests_sha256="c29082ea3b53512c12a0b8f62e679ea7f7eb8e5709627317d2923d1931d2cd0c"
readonly repository_python_acceptance_root_sha256="2897b38002c51c9e551db8faec33639d803dc4488aa14f624b0963c9359ad32a"
readonly operation_started_epoch="$(date +%s)"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "The host deployer must run as root."
[[ $# -eq 5 || $# -eq 7 ]] || fail "Usage: host-deploy.sh ARCHIVE COMMIT SHA256 SIZE bootstrap|rebuild"

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi

archive="$1"
commit="$2"
expected_archive_sha="$3"
expected_archive_size="$4"
mode="$5"
backup_evidence=""
historical_bootstrap=false
historical_journal=""
historical_journal_sha=""
historical_bootstrap_commit=""
historical_bootstrap_phase=""
historical_bootstrap_already_complete=false
historical_repository_tree=""
historical_production_config=""
historical_restore_config=""
historical_receipt="/var/lib/mochirii/forums/historical-recovery/fetched-recovery-receipt.json"
historical_helper="/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py"

if [[ $# -eq 7 ]]; then
  [[ ${mode} == historical-bootstrap ]] || fail "The extended deploy contract is reserved for historical bootstrap."
  [[ ${SUDO_USER:-root} != mochirii-forums-deploy ]] || fail "The deploy principal may not invoke historical bootstrap."
  historical_bootstrap=true
  historical_journal="$6"
  historical_journal_sha="$7"
  # All existing mutation and terminal journals retain their reviewed
  # bootstrap vocabulary; the non-reusable authority remains the separate
  # historical adoption journal and boolean branch.
  mode=bootstrap
else
  [[ ${mode} == "bootstrap" || ${mode} == "rebuild" ]] || fail "Deployment mode must be bootstrap or rebuild."
fi

[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Release commit must be one lowercase full SHA."
[[ ${expected_archive_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Archive digest must be lowercase SHA-256."
[[ ${expected_archive_size} =~ ^[1-9][0-9]{0,8}$ ]] || fail "Archive size must be one bounded positive integer."
(( expected_archive_size <= 67108864 )) || fail "Release archive exceeds the 64 MiB transport boundary."
[[ -f ${archive} && ! -L ${archive} ]] || fail "Release archive must be one regular file."

if [[ ${historical_bootstrap} == true ]]; then
  [[ ${historical_journal} == /var/lib/mochirii/forums/historical-release-adoption.json ]] || fail "Historical bootstrap journal path differs."
  [[ ${historical_journal_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Historical bootstrap journal digest is malformed."
  [[ -f ${historical_journal} && ! -L ${historical_journal} ]] || fail "Historical bootstrap journal is absent or linked."
  [[ "$(stat -c '%U:%G %a' "${historical_journal}")" == "root:root 600" ]] || fail "Historical bootstrap journal has unsafe ownership or mode."
  [[ "$(sha256sum -- "${historical_journal}" | awk '{print $1}')" == "${historical_journal_sha}" ]] || fail "Historical bootstrap journal changed before entry."
  [[ -x ${historical_helper} && ! -L ${historical_helper} ]] || fail "Installed historical recovery helper is absent or linked."
  readarray -t historical_contract < <(python3 -B - "${historical_journal}" "${commit}" "${expected_archive_sha}" "${expected_archive_size}" <<'PY'
import json
import pathlib
import re
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("phase") not in {"bootstrap-started", "bootstrap-complete"} or document.get("recoveredRepositoryCommit") != sys.argv[2]:
    raise SystemExit("historical bootstrap tuple differs")
if document.get("releaseArchiveSha256") != sys.argv[3] or document.get("releaseArchiveBytes") != int(sys.argv[4]):
    raise SystemExit("historical bootstrap archive differs")
for key in ("bootstrapRepositoryCommit", "recoveredRepositoryTree"):
    if re.fullmatch(r"[0-9a-f]{40}", str(document.get(key, ""))) is None:
        raise SystemExit("historical bootstrap Git identity is malformed")
for key in ("productionConfigurationFile", "restoreConfigurationFile"):
    if not isinstance(document.get(key), str) or not pathlib.Path(document[key]).is_absolute():
        raise SystemExit("historical bootstrap configuration path is malformed")
print(document["phase"])
print(document["bootstrapRepositoryCommit"])
print(document["recoveredRepositoryTree"])
print(document["productionConfigurationFile"])
print(document["restoreConfigurationFile"])
PY
  ) || fail "Historical bootstrap journal authority is malformed."
  [[ ${#historical_contract[@]} -eq 5 ]] || fail "Historical bootstrap journal authority is incomplete."
  historical_bootstrap_phase="${historical_contract[0]}"
  historical_bootstrap_commit="${historical_contract[1]}"
  historical_repository_tree="${historical_contract[2]}"
  historical_production_config="${historical_contract[3]}"
  historical_restore_config="${historical_contract[4]}"
  python3 -B "${historical_helper}" verify --receipt "${historical_receipt}" \
    --journal "${historical_journal}" --require-phase "${historical_bootstrap_phase}" >/dev/null
  if [[ ${historical_bootstrap_phase} == bootstrap-complete ]]; then
    historical_bootstrap_already_complete=true
  fi
fi

resolved_archive="$(readlink -f -- "${archive}")"
[[ ${resolved_archive} == "${incoming_root}/${commit}.tar" ]] || fail "Release archive path is not the exact protected incoming name."
[[ "$(stat -c '%s' "${resolved_archive}")" == "${expected_archive_size}" ]] || fail "Incoming release archive size mismatch."
[[ -d /var/discourse/.git ]] || fail "Official deployment source is absent."
[[ "$(git -C /var/discourse rev-parse HEAD)" == "${docker_revision}" ]] || fail "Deployment source revision mismatch."
[[ -f ${runtime_json} && ! -L ${runtime_json} ]] || fail "Protected runtime JSON is absent."
[[ "$(stat -c '%U:%G %a' "${runtime_json}")" == "root:root 600" ]] || fail "Runtime JSON must be root:root mode 0600."
requested_discourse_connect="$(python3 - "${runtime_json}" <<'PY'
import json
import hashlib
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = document.get("FORUMS_DISCOURSE_CONNECT_ENABLED")
if value not in {"true", "false"}:
    raise SystemExit("DiscourseConnect runtime flag is malformed")
print(value)
PY
)" || fail "Protected runtime DiscourseConnect flag is malformed."
marker="/var/lib/mochirii/forums/member-rollout-enabled"
marker_file_for_evidence=""
marker_sha_for_evidence=""
if [[ ${mode} == bootstrap || ${historical_bootstrap} == true ]]; then
  [[ ${requested_discourse_connect} == false ]] || fail "Bootstrap must keep DiscourseConnect disabled through restore rehearsal."
  [[ ! -e ${marker} ]] || fail "Bootstrap refuses an existing member-rollout marker."
fi

install -d -m 0700 -o root -g root "${quarantine_root}" "${evidence_root}" "${logs_root}" "${configs_root}"
install -d -m 0755 -o root -g root "${releases_root}" "${assets_root}" /var/discourse/containers
[[ ! -e /var/lib/mochirii/forums/backup-transaction.json && ! -L /var/lib/mochirii/forums/backup-transaction.json ]] || fail "Deployment refuses an active backup transaction; only the protected backup command may reconcile it."
[[ ! -e /var/lib/mochirii/forums/restore-transaction.json && ! -L /var/lib/mochirii/forums/restore-transaction.json ]] || fail "Deployment refuses an active restore transaction; only the protected restore command may reconcile it."
if [[ ${historical_bootstrap} == false ]]; then
  [[ ! -e /var/lib/mochirii/forums/historical-release-adoption.json && ! -L /var/lib/mochirii/forums/historical-release-adoption.json ]] || fail "Ordinary deployment refuses an active historical disaster-recovery adoption."
fi
quarantine="$(mktemp "${quarantine_root}/${commit}.XXXXXXXX.tar")"
trusted_repository=""
trusted_archive=""
trusted_repository_tree=""
repository_tree=""
release_archive_bytes=""
release_archive_manifest_sha=""
candidate=""
asset_candidate=""
config_candidate=""
activation_started=false
contained_activation_required=false
contained_activation_passed=false
complete_authentication_rebuild=false
activation_failure_retry=false
stale_authentication_transition=false
automatic_rollback_compatible=false
target_database_mutation_possible=false
forward_fix_retry=false
deployment_success=false
deployment_commit_armed=false
deployment_state_committed=false
deployment_mutation_armed=false
deployment_mutation_resume=false
deployment_mutation_phase=""
deployment_mutation_active_config=""
deployment_mutation_database_possible=false
previous_config=""
previous_release=""
previous_configuration=""
previous_discourse_connect=""
previous_marker_file=""
previous_marker_sha=""
previous_current_target=""
storage_state=""
storage_cleanup_journal=""
storage_cleanup_journal_sha=""
storage_create_result=""
storage_restart_result=""
storage_rebuild_result=""
storage_delete_result=""
storage_fixture_created=false
storage_fixture_deleted=false
storage_cleanup_blocked=false
runtime_survivor_unproved=false
storage_evidence=""
active_bounded_pid=""
active_operation_kind=""
active_operation_token=""
active_parser_container=""
launcher_operation_token=""
launcher_previous_image_id=""
launcher_operation_command=""
if [[ ${mode} == rebuild && ${requested_discourse_connect} == true ]]; then
  contained_activation_required=true
fi

terminate_active_group() {
  local pid="${active_bounded_pid}"
  [[ -n ${pid} && ${pid} =~ ^[1-9][0-9]*$ ]] || return 0
  kill -TERM -- "-${pid}" >/dev/null 2>&1 || true
  local waited=0
  while kill -0 "${pid}" >/dev/null 2>&1 && (( waited < 30 )); do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill -KILL -- "-${pid}" >/dev/null 2>&1 || true
  fi
  wait "${pid}" >/dev/null 2>&1 || true
  active_bounded_pid=""
}

cleanup_parser_container() {
  local name="$1"
  local inventory
  [[ ${name} =~ ^mochirii-forums-config-parser-[0-9a-f]{32}$ ]] || return 1
  timeout --signal=TERM --kill-after=5s 15 docker rm --force "${name}" >/dev/null 2>&1 || true
  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter "name=^/${name}$" --format '{{.Names}}' 2>/dev/null)" || return 1
  [[ -z ${inventory} ]]
}

handle_operation_signal() {
  local kind="${active_operation_kind}"
  trap - HUP INT TERM
  terminate_active_group
  if [[ ${deployment_commit_armed} == true ]]; then
    printf '%s\n' "Deployment terminal publication was interrupted; the verified mutation and any durably published exact transaction are retained for retry adoption." >&2
  elif [[ ${kind} == launcher ]]; then
    reconcile_launcher_failure || true
  elif [[ ${kind} == container ]]; then
    emergency_stop || true
  elif [[ ${kind} == parser && -n ${active_parser_container} ]]; then
    cleanup_parser_container "${active_parser_container}" || runtime_survivor_unproved=true
    active_parser_container=""
  elif [[ ${activation_started} == true ]]; then
    emergency_stop || true
  fi
  exit 124
}

record_event() {
  local operation="$1"
  local status="$2"
  local configuration="${3:--}"
  local evidence_sha="${4:--}"
  [[ ${operation} =~ ^[a-z-]{1,32}$ ]] || return 1
  [[ ${status} == started || ${status} == passed || ${status} == failed || ${status} == blocked ]] || return 1
  [[ ${configuration} == - || ${configuration} =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ ${evidence_sha} == - || ${evidence_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
    --path "${logs_root}/events.log" --operation "${operation}" --status "${status}" \
    --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
    --field "evidence_sha256=${evidence_sha}" >/dev/null
}

write_deployment_transaction() {
  local next_phase="$1"
  local authentication_action="$2"
  local release_record="$3"
  local release_sha="$4"
  local forward_fix_sha="${5:--}"
  python3 -B - "${deployment_transaction}" "${next_phase}" "${mode}" "${commit}" \
    "${configuration_id}" "${expected_archive_sha}" "${release_record}" "${release_sha}" \
    "${requested_discourse_connect}" "${marker_file_for_evidence:--}" \
    "${marker_sha_for_evidence:--}" "${authentication_action}" "${forward_fix_sha}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
phase = sys.argv[2]
order = {"prepared": 10, "state-committed": 20, "event-committed": 30}
if phase not in order or sys.argv[3] not in {"bootstrap", "rebuild"}:
    raise SystemExit("deployment transaction phase or mode is invalid")
if not re.fullmatch(r"[0-9a-f]{40}", sys.argv[4]) or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[5]) or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[6]):
    raise SystemExit("deployment transaction identity is malformed")
release = pathlib.Path(sys.argv[7])
metadata = release.lstat()
if release.parent != path.parent / "evidence" or not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
    raise SystemExit("deployment release evidence is unsafe")
release_sha = hashlib.sha256(release.read_bytes()).hexdigest()
if release_sha != sys.argv[8] or not re.fullmatch(r"[0-9a-f]{64}", release_sha):
    raise SystemExit("deployment release evidence digest differs")
if sys.argv[9] not in {"true", "false"}:
    raise SystemExit("deployment consumer state is malformed")
marker_file = None if sys.argv[10] == "-" else sys.argv[10]
marker_sha = None if sys.argv[11] == "-" else sys.argv[11]
if (marker_file is None) != (marker_sha is None) or (marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha))):
    raise SystemExit("deployment member marker binding is malformed")
action = sys.argv[12]
if action not in {"pending", "preserve-complete", "advance-complete", "absent"}:
    raise SystemExit("deployment authentication action is invalid")
connect = sys.argv[9] == "true"
if connect != (action in {"pending", "preserve-complete"}):
    raise SystemExit("deployment authentication action differs from the consumer state")
forward_sha = None if sys.argv[13] == "-" else sys.argv[13]
if forward_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", forward_sha):
    raise SystemExit("deployment forward-fix binding is malformed")
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
stable = {
    "schemaVersion": 1,
    "deploymentMode": sys.argv[3],
    "repositoryCommit": sys.argv[4],
    "productionConfigurationSha256": sys.argv[5],
    "releaseArchiveSha256": sys.argv[6],
    "releaseEvidenceFile": str(release),
    "releaseEvidenceSha256": release_sha,
    "requestedDiscourseConnect": connect,
    "memberRolloutMarkerFile": marker_file,
    "memberRolloutMarkerSha256": marker_sha,
    "authenticationAction": action,
    "forwardFixEvidenceSha256": forward_sha,
}
existing = None
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("deployment transaction is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    required = set(stable) | {"phase", "recordedAt", "updatedAt"}
    if set(existing) != required or existing.get("phase") not in order or order[phase] < order[existing["phase"]]:
        raise SystemExit("deployment transaction phase cannot move backward")
    for key, value in stable.items():
        if existing.get(key) != value:
            raise SystemExit(f"deployment transaction stable field differs: {key}")
document = {
    **stable,
    "phase": phase,
    "recordedAt": existing.get("recordedAt", now) if existing else now,
    "updatedAt": now,
}
with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False, encoding="utf-8") as target:
    json.dump(document, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
    temporary = pathlib.Path(target.name)
temporary.chmod(0o600)
os.replace(temporary, path)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

deployment_state_contract() {
  python3 -B - "${deployment_transaction}" "${deployment_terminal}" "${mode}" "${commit}" \
    "${configuration_id}" "${expected_archive_sha}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

journal = pathlib.Path(sys.argv[1])
terminal = pathlib.Path(sys.argv[2])
expected = {
    "deploymentMode": sys.argv[3],
    "repositoryCommit": sys.argv[4],
    "productionConfigurationSha256": sys.argv[5],
    "releaseArchiveSha256": sys.argv[6],
}
if expected["deploymentMode"] not in {"bootstrap", "rebuild"} or not re.fullmatch(r"[0-9a-f]{40}", expected["repositoryCommit"]) or any(not re.fullmatch(r"[0-9a-f]{64}", expected[key]) for key in ("productionConfigurationSha256", "releaseArchiveSha256")):
    raise SystemExit("requested deployment transaction identity is malformed")

def protected(path, label):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit(f"{label} is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{label} is not one object")
    return value

source = None
phase = None
if journal.exists() or journal.is_symlink():
    source = protected(journal, "deployment transaction")
    phase = source.get("phase")
    required = {
        "schemaVersion", "phase", "recordedAt", "updatedAt", "deploymentMode",
        "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
        "releaseEvidenceFile", "releaseEvidenceSha256", "requestedDiscourseConnect",
        "memberRolloutMarkerFile", "memberRolloutMarkerSha256", "authenticationAction",
        "forwardFixEvidenceSha256",
    }
    if set(source) != required or source.get("schemaVersion") != 1 or phase not in {"prepared", "state-committed", "event-committed"}:
        raise SystemExit("deployment transaction schema differs")
    if any(source.get(key) != value for key, value in expected.items()):
        raise SystemExit("an active deployment transaction belongs to another exact operation")
elif terminal.exists() or terminal.is_symlink():
    candidate = protected(terminal, "completed deployment record")
    required = {
        "schemaVersion", "phase", "recordedAt", "completedAt", "deploymentMode",
        "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
        "releaseEvidenceFile", "releaseEvidenceSha256", "requestedDiscourseConnect",
        "memberRolloutMarkerFile", "memberRolloutMarkerSha256", "authenticationAction",
        "forwardFixEvidenceSha256",
    }
    if set(candidate) != required or candidate.get("schemaVersion") != 1 or candidate.get("phase") != "complete":
        raise SystemExit("completed deployment record schema differs")
    if any(candidate.get(key) != value for key, value in expected.items()):
        print("none")
        raise SystemExit(0)
    source = candidate
    phase = "complete"
else:
    print("none")
    raise SystemExit(0)
release = pathlib.Path(str(source.get("releaseEvidenceFile", "")))
if release.parent != journal.parent / "evidence" or release.name != f"{expected['repositoryCommit']}-{expected['productionConfigurationSha256']}-release.json":
    raise SystemExit("deployment release evidence reference differs")
metadata = release.lstat()
release_sha = source.get("releaseEvidenceSha256")
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not re.fullmatch(r"[0-9a-f]{64}", str(release_sha)) or hashlib.sha256(release.read_bytes()).hexdigest() != release_sha:
    raise SystemExit("deployment release evidence binding differs")
connect = source.get("requestedDiscourseConnect")
action = source.get("authenticationAction")
if not isinstance(connect, bool) or action not in {"pending", "preserve-complete", "advance-complete", "absent"} or connect != (action in {"pending", "preserve-complete"}):
    raise SystemExit("deployment authentication binding differs")
marker_file = source.get("memberRolloutMarkerFile")
marker_sha = source.get("memberRolloutMarkerSha256")
if (marker_file is None) != (marker_sha is None) or (marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", str(marker_sha)))):
    raise SystemExit("deployment member marker binding differs")
forward_sha = source.get("forwardFixEvidenceSha256")
if forward_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", str(forward_sha)):
    raise SystemExit("deployment forward-fix binding differs")
print(phase)
print(action)
print(release)
print(release_sha)
print("true" if connect else "false")
print(marker_file or "-")
print(marker_sha or "-")
print(forward_sha or "-")
PY
}

publish_deployment_terminal() {
  python3 -B - "${deployment_transaction}" "${deployment_terminal}" <<'PY'
import datetime
import json
import os
import pathlib
import stat
import tempfile
import sys

journal = pathlib.Path(sys.argv[1])
path = pathlib.Path(sys.argv[2])
metadata = journal.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
    raise SystemExit("deployment transaction is unsafe")
source = json.loads(journal.read_text(encoding="utf-8"))
if source.get("phase") != "event-committed":
    raise SystemExit("deployment transaction event is not committed")
document = {key: value for key, value in source.items() if key not in {"updatedAt"}}
document["phase"] = "complete"
document["completedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
if path.exists() or path.is_symlink():
    current_meta = path.lstat()
    if not stat.S_ISREG(current_meta.st_mode) or stat.S_ISLNK(current_meta.st_mode) or current_meta.st_uid != 0 or stat.S_IMODE(current_meta.st_mode) != 0o600 or current_meta.st_size > 65536:
        raise SystemExit("completed deployment record is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document) or existing.get("schemaVersion") != 1 or existing.get("phase") != "complete":
        raise SystemExit("completed deployment record schema differs")
    if all(key == "completedAt" or existing.get(key) == value for key, value in document.items()):
        raise SystemExit(0)
with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False, encoding="utf-8") as target:
    json.dump(document, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
    temporary = pathlib.Path(target.name)
temporary.chmod(0o600)
os.replace(temporary, path)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

clear_deployment_transaction() {
  python3 -B - "${deployment_transaction}" <<'PY'
import json
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
if json.loads(path.read_text(encoding="utf-8")).get("phase") != "event-committed":
    raise SystemExit("deployment transaction is not terminal")
path.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

deployment_mutation() {
  [[ -n ${release_dir:-} && -f ${release_dir}/scripts/deployment-mutation.py && ! -L ${release_dir}/scripts/deployment-mutation.py ]] || return 1
  python3 -B "${release_dir}/scripts/deployment-mutation.py" "$@"
}

inspect_deployment_mutation() {
  deployment_mutation inspect --path "${deployment_mutation_journal}" \
    --mode "${mode}" --commit "${commit}" --configuration "${configuration_id}" \
    --archive-sha "${expected_archive_sha}" --requested-connect "${requested_discourse_connect}"
}

create_deployment_mutation() {
  local previous_current_sha="-"
  local activation_file="-"
  local activation_sha="-"
  local prior_commit="-"
  local prior_configuration="-"
  local prior_config="-"
  local prior_config_sha="-"
  local prior_target="-"
  if [[ ${requested_discourse_connect} == true ]]; then
    activation_file="${config_dir}/activation.yml"
    activation_sha="${activation_config_sha}"
  fi
  if [[ ${mode} == rebuild ]]; then
    prior_commit="${previous_release}"
    prior_configuration="${previous_configuration}"
    prior_config="${previous_config}"
    prior_config_sha="$(sha256sum -- "${previous_config}" | awk '{print $1}')" || return 1
    prior_target="${previous_current_target}"
    previous_current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk '{print $1}')" || return 1
    [[ ${prior_config_sha} == "${previous_configuration}" && ${previous_current_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  fi
  deployment_mutation create --path "${deployment_mutation_journal}" \
    --mode "${mode}" --commit "${commit}" --configuration "${configuration_id}" \
    --archive-sha "${expected_archive_sha}" --requested-connect "${requested_discourse_connect}" \
    --target-app-config "${config_dir}/app.yml" \
    --target-restore-config "${config_dir}/restore.yml" --target-restore-sha "${restore_config_sha}" \
    --target-activation-config "${activation_file}" --target-activation-sha "${activation_sha}" \
    --previous-commit "${prior_commit}" --previous-configuration "${prior_configuration}" \
    --previous-current-sha "${previous_current_sha}" --previous-app-config "${prior_config}" \
    --previous-app-sha "${prior_config_sha}" --previous-current-target "${prior_target}" || return 1
  deployment_mutation_armed=true
  return 0
}

mark_deployment_mutation_contained() {
  [[ ${deployment_mutation_armed} == true ]] || return 0
  deployment_mutation mark-contained --path "${deployment_mutation_journal}" || return 1
  deployment_mutation_phase=runtime-contained
  return 0
}

mark_deployment_mutation_verified() {
  [[ ${deployment_mutation_armed} == true ]] || return 1
  deployment_mutation mark-verified --path "${deployment_mutation_journal}" || return 1
  deployment_mutation_phase=verified
  return 0
}

clear_deployment_mutation() {
  [[ ${deployment_mutation_armed} == true ]] || return 0
  deployment_mutation clear --path "${deployment_mutation_journal}" \
    --commit "${commit}" --configuration "${configuration_id}" --archive-sha "${expected_archive_sha}" || return 1
  deployment_mutation_armed=false
  deployment_mutation_resume=false
  deployment_mutation_phase=""
  return 0
}

remaining_mutation_seconds() {
  local requested="$1"
  local now
  local remaining
  [[ ${requested} =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  now="$(date +%s)"
  remaining=$((operation_started_epoch + launcher_cumulative_budget_seconds - now))
  (( remaining >= 60 )) || return 1
  (( requested <= remaining )) || requested="${remaining}"
  printf '%s\n' "${requested}"
}

run_config_parser() {
  local rendered="$1"
  local operation_token
  local parser_status=0
  local bounded_seconds
  [[ -f ${rendered} && ! -L ${rendered} ]] || return 1
  operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  bounded_seconds="$(remaining_mutation_seconds 90)" || return 1
  active_operation_kind="parser"
  active_parser_container="mochirii-forums-config-parser-${operation_token}"
  (exec 200>&- 201>&-; exec timeout --signal=TERM --kill-after=5s "${bounded_seconds}" docker run --rm -i --pull=never \
    --name "${active_parser_container}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --memory 256m --memory-swap 256m \
    "${base_image}" ruby -ryaml -e '
      expected_image, expected_core = ARGV
      config = YAML.safe_load(STDIN.read, aliases: true)
      abort "wrong base image" unless config["base_image"] == expected_image
      abort "wrong core revision" unless config.dig("params", "version") == expected_core
      abort "runtime config missing persistent shared mount" unless config.fetch("volumes").any? { |v| v.dig("volume", "guest") == "/shared" }
    ' "${base_image}" "${core_revision}") <"${rendered}" >/dev/null 2>&1 &
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || parser_status=$?
  active_bounded_pid=""
  if ! cleanup_parser_container "${active_parser_container}"; then
    runtime_survivor_unproved=true
    active_parser_container=""
    active_operation_kind=""
    return 1
  fi
  active_parser_container=""
  active_operation_kind=""
  (( parser_status == 0 ))
}

run_launcher() {
  local label="$1"
  local launcher_status=0
  local bounded_seconds
  local preexisting_operation_inventory
  local requested_command
  local selected_configuration
  shift
  requested_command="${1:-}"
  [[ ${requested_command} == bootstrap || ${requested_command} == start || ${requested_command} == restart || ${requested_command} == rebuild || ${requested_command} == destroy ]] || return 1
  if [[ -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ]] || ! launcher_processes_absent; then
    # Reconcile prior CID/process residue before creating this operation's
    # identity. The reconciliation helper deliberately clears all launcher
    # globals, so doing this later would erase the new durable identity.
    reconcile_launcher_failure || return 1
    [[ ! -e ${launcher_bootstrap_cid} && ! -L ${launcher_bootstrap_cid} ]] || return 1
  fi
  launcher_processes_absent || return 1
  launcher_operation_command="${requested_command}"
  if [[ ${label} != rollback && ( ${launcher_operation_command} == bootstrap || ${launcher_operation_command} == rebuild ) ]]; then
    # The pinned launcher can run migrations before it returns. Once a target
    # rebuild begins, absence of database mutation is no longer provable and
    # old-code automatic rollback is permanently ineligible for this attempt.
    target_database_mutation_possible=true
  fi
  if ! timeout --signal=TERM --kill-after=5s 90 bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh" >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums launcher refused unsealed deployment source." >&2
    reconcile_launcher_failure || true
    return 1
  fi
  launcher_operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  launcher_previous_image_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
  [[ -z ${launcher_previous_image_id} || ${launcher_previous_image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  preexisting_operation_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
    --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}}' 2>/dev/null)" || return 1
  [[ -z ${preexisting_operation_inventory} ]] || return 1
  if [[ ${deployment_mutation_armed} == true ]]; then
    selected_configuration="$(readlink -f -- "${app_config}")" || return 1
    if ! deployment_mutation arm-launcher --path "${deployment_mutation_journal}" \
      --configuration-file "${selected_configuration}" --token "${launcher_operation_token}" \
      --previous-image "${launcher_previous_image_id:--}" --command "${launcher_operation_command}"; then
      launcher_operation_token=""
      launcher_previous_image_id=""
      launcher_operation_command=""
      return 1
    fi
    deployment_mutation_phase=launcher-armed
  fi
  bounded_seconds="$(remaining_mutation_seconds "${launcher_timeout_seconds}")" || {
    printf '%s\n' "Mochirii Forums cumulative launcher budget is exhausted." >&2
    reconcile_launcher_failure || true
    return 1
  }
  active_operation_kind="launcher"
  (exec 200>&- 201>&-; exec timeout --signal=TERM --kill-after=30s "${bounded_seconds}" \
    bash -c 'cd /var/discourse && exec ./launcher "$@"' bash "$@" \
      --docker-args "--label=mochirii.forums.operation=${launcher_operation_token}") >/dev/null 2>&1 &
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || launcher_status=$?
  active_bounded_pid=""
  if (( launcher_status != 0 )); then
    printf '%s\n' "Mochirii Forums launcher operation failed; raw launcher output was suppressed." >&2
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  if ! reconcile_launcher_operation success; then
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  if [[ ${deployment_mutation_armed} == true ]]; then
    if ! deployment_mutation finish-launcher --path "${deployment_mutation_journal}" \
      --token "${launcher_operation_token}" --outcome success; then
      reconcile_launcher_failure || true
      active_operation_kind=""
      return 1
    fi
    deployment_mutation_phase=runtime-active
  fi
  active_operation_kind=""
  launcher_operation_token=""
  launcher_previous_image_id=""
  launcher_operation_command=""
}

container_operation_absent() {
  local token="$1"
  [[ ${token} =~ ^[0-9a-f]{32}$ ]] || return 1
  timeout --signal=TERM --kill-after=5s 30 docker exec app ruby -e '
    token = ARGV.fetch(0)
    marker = "MOCHIRII_OPERATION_TOKEN=#{token}"
    found = Dir.glob("/proc/[0-9]*/environ").any? do |path|
      begin
        File.binread(path).split("\0", -1).include?(marker)
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        false
      end
    end
    exit(found ? 1 : 0)
  ' "${token}" >/dev/null 2>&1
}

run_release_verification() {
  local release="$1"
  local configuration="$2"
  local transaction_flag="${3:-}"
  local verification_seconds
  local -a verify_arguments
  [[ -z ${transaction_flag} || ${transaction_flag} == --deployment-transaction || ${transaction_flag} == --deployment-prior-rollback ]] || return 1
  if [[ -z ${transaction_flag} && ${deployment_mutation_armed} == true && ${release} == "${commit}" && ${configuration} == "${configuration_id}" ]]; then
    transaction_flag=--deployment-transaction
  fi
  if ! bash "${releases_root}/${release}/scripts/verify-runtime-assets.sh" "${release}" --require-container >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums runtime-asset verification failed before application verification." >&2
    return 1
  fi
  verification_seconds="$(remaining_mutation_seconds 600)" || return 1
  verify_arguments=("${release}" "${configuration}")
  [[ -z ${transaction_flag} ]] || verify_arguments+=("${transaction_flag}")
  if ! timeout --signal=TERM --kill-after=10s "${verification_seconds}" bash "${releases_root}/${release}/scripts/verify-host.sh" "${verify_arguments[@]}" >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums release verification failed; raw runtime output was suppressed." >&2
    return 1
  fi
  if ! bash "${releases_root}/${release}/scripts/verify-runtime-assets.sh" "${release}" --require-container >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums runtime assets changed during application verification." >&2
    return 1
  fi
}

run_storage_fixture() {
  local action="$1"
  local output="$2"
  local input="${3:-}"
  local runner_status=0
  local operation_token
  local outer_seconds
  local inner_seconds
  [[ ${action} == create || ${action} == verify || ${action} == delete || ${action} == cleanup ]] || return 1
  [[ ${output} == "${evidence_root}/"* && ! -e ${output} ]] || return 1
  : >"${output}"
  chmod 0600 "${output}"
  operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  outer_seconds="$(remaining_mutation_seconds 300)" || return 1
  inner_seconds=$((outer_seconds - 20))
  (( inner_seconds >= 30 )) || return 1
  active_operation_kind="container"
  active_operation_token="${operation_token}"
  if [[ -n ${input} ]]; then
    [[ -f ${input} && ! -L ${input} ]] || return 1
    (ulimit -f 128; exec 200>&- 201>&-; exec timeout --signal=TERM --kill-after=10s "${outer_seconds}" docker exec -i -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app timeout --signal=TERM --kill-after=10s "${inner_seconds}" bash -lc \
      '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-storage-fixture.rb" "$1" "$2" "$3"' \
      bash "${action}" "${commit}" "${configuration_id}") <"${input}" >"${output}" 2>/dev/null &
  else
    (ulimit -f 128; exec 200>&- 201>&-; exec timeout --signal=TERM --kill-after=10s "${outer_seconds}" docker exec -i -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app timeout --signal=TERM --kill-after=10s "${inner_seconds}" bash -lc \
      '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-storage-fixture.rb" "$1" "$2" "$3"' \
      bash "${action}" "${commit}" "${configuration_id}") </dev/null >"${output}" 2>/dev/null &
  fi
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || runner_status=$?
  active_bounded_pid=""
  if ! container_operation_absent "${operation_token}"; then
    emergency_stop || true
    active_operation_kind=""
    active_operation_token=""
    return 1
  fi
  if (( runner_status == 124 || runner_status == 137 || runner_status == 143 )); then
    emergency_stop || true
    active_operation_kind=""
    active_operation_token=""
    return 1
  fi
  active_operation_kind=""
  active_operation_token=""
  (( runner_status == 0 )) || return 1
  [[ -s ${output} && "$(stat -c '%s' "${output}")" -le 65536 && "$(stat -c '%U:%G %a' "${output}")" == "root:root 600" ]] || return 1
  python3 -B - "${output}" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

fsync_directory() {
  python3 -B - "$1" <<'PY'
import os
import pathlib
import sys
descriptor = os.open(pathlib.Path(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

create_storage_cleanup_journal() {
  local transaction_id="$1"
  python3 -B - "${evidence_root}" "${commit}" "${configuration_id}" "${transaction_id}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
commit = sys.argv[2]
configuration = sys.argv[3]
transaction_id = sys.argv[4]
if (
    not re.fullmatch(r"[0-9a-f]{40}", commit)
    or not re.fullmatch(r"[0-9a-f]{64}", configuration)
    or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
):
    raise SystemExit("storage cleanup journal publication identity differs")
document = {
    "schemaVersion": 3,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "cleanupOnly": True,
    "transactionId": transaction_id,
    "pluginStoreNamespace": "mochirii-hosted-storage",
    "pluginStoreKey": f"fixture-transaction:{transaction_id}",
    "phase": "prepared",
}
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
digest = hashlib.sha256(payload).hexdigest()
path = root / f"{commit}-{configuration}-{digest}-storage-cleanup-required.json"
partial = root / ".storage-cleanup-journal.partial"
descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "wb") as target:
    metadata = os.fstat(target.fileno())
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("storage cleanup journal partial permissions differ")
    target.write(payload)
    target.flush()
    os.fsync(target.fileno())
os.link(partial, path, follow_symlinks=False)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
    partial.unlink()
    os.fsync(directory)
finally:
    os.close(directory)
print(path)
print(digest)
PY
}

reconcile_storage_cleanup_journal_partial() {
  python3 -B - "${evidence_root}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
partial = root / ".storage-cleanup-journal.partial"
if not partial.exists() and not partial.is_symlink():
    raise SystemExit(0)
metadata = partial.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size > 4096
):
    raise SystemExit("storage cleanup journal partial is unsafe")
raw = partial.read_bytes()
if len(raw) != metadata.st_size:
    raise SystemExit("storage cleanup journal partial changed while it was read")
linked = []
for candidate in root.glob("*-storage-cleanup-required.json"):
    candidate_metadata = candidate.lstat()
    if candidate_metadata.st_dev == metadata.st_dev and candidate_metadata.st_ino == metadata.st_ino:
        linked.append((candidate, candidate_metadata))
if linked:
    if len(linked) != 1 or metadata.st_nlink != 2:
        raise SystemExit("storage cleanup journal partial has ambiguous final links")
    final, final_metadata = linked[0]
    if (
        not stat.S_ISREG(final_metadata.st_mode)
        or stat.S_ISLNK(final_metadata.st_mode)
        or final_metadata.st_uid != 0
        or final_metadata.st_gid != 0
        or stat.S_IMODE(final_metadata.st_mode) != 0o600
        or final.read_bytes() != raw
    ):
        raise SystemExit("storage cleanup journal final link is unsafe")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("linked storage cleanup journal partial is malformed")
    transaction_id = document.get("transactionId", "") if isinstance(document, dict) else ""
    commit = document.get("repositoryCommit", "") if isinstance(document, dict) else ""
    configuration = document.get("productionConfigurationSha256", "") if isinstance(document, dict) else ""
    expected = {
        "schemaVersion": 3,
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "cleanupOnly": True,
        "transactionId": transaction_id,
        "pluginStoreNamespace": "mochirii-hosted-storage",
        "pluginStoreKey": f"fixture-transaction:{transaction_id}",
        "phase": "prepared",
    }
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    if (
        document != expected
        or raw != canonical
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"[0-9a-f]{64}", configuration)
        or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
        or final.name != f"{commit}-{configuration}-{digest}-storage-cleanup-required.json"
    ):
        raise SystemExit("linked storage cleanup journal identity differs")
elif metadata.st_nlink != 1:
    raise SystemExit("uncommitted storage cleanup journal partial has hidden links")
partial.unlink()
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

validate_storage_cleanup_journal() {
  local path="$1"
  python3 -B - "${path}" "${evidence_root}" "${commit}" "${configuration_id}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
configuration = sys.argv[4]
if path.parent != root or not path.is_file() or path.is_symlink():
    raise SystemExit("storage cleanup journal is not one protected file")
metadata = path.stat(follow_symlinks=False)
if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 4096:
    raise SystemExit("storage cleanup journal permissions or size are unsafe")
raw = path.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if path.name != f"{commit}-{configuration}-{digest}-storage-cleanup-required.json":
    raise SystemExit("storage cleanup journal digest filename differs")
document = json.loads(raw)
if set(document) != {
    "schemaVersion", "repositoryCommit", "productionConfigurationSha256", "cleanupOnly",
    "transactionId", "pluginStoreNamespace", "pluginStoreKey", "phase",
}:
    raise SystemExit("storage cleanup journal keys differ")
transaction_id = document.get("transactionId", "")
if (
    document.get("schemaVersion") != 3
    or document.get("repositoryCommit") != commit
    or document.get("productionConfigurationSha256") != configuration
    or document.get("cleanupOnly") is not True
    or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
    or document.get("pluginStoreNamespace") != "mochirii-hosted-storage"
    or document.get("pluginStoreKey") != f"fixture-transaction:{transaction_id}"
    or document.get("phase") != "prepared"
):
    raise SystemExit("storage cleanup journal tuple differs")
canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if raw != canonical:
    raise SystemExit("storage cleanup journal is not canonical")
print(digest)
PY
}

clear_storage_cleanup_journal() {
  local path="$1"
  validate_storage_cleanup_journal "${path}" >/dev/null || return 1
  python3 -B - "${path}" "${evidence_root}" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
if path.parent != root or not path.is_file() or path.is_symlink():
    raise SystemExit("storage cleanup journal is unsafe")
path.unlink()
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

validate_storage_terminal_result() {
  local action="$1"
  local path="$2"
  python3 -B - "${path}" "${evidence_root}" "${commit}" "${configuration_id}" "${action}" <<'PY'
import json
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
configuration = sys.argv[4]
action = sys.argv[5]
if path.parent != root or not path.is_file() or path.is_symlink():
    raise SystemExit("storage terminal result is not one protected file")
metadata = path.stat(follow_symlinks=False)
if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 65536:
    raise SystemExit("storage terminal result permissions or size differ")
document = json.loads(path.read_text(encoding="utf-8"))
if action == "cleanup":
    expected = {
        "schemaVersion": 1,
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "cleanupPassed": True,
    }
elif action == "delete":
    expected = {
        "schemaVersion": 1,
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "databaseRowsDeleted": True,
        "primaryObjectsDeleted": True,
        "tombstonesDeleted": True,
    }
else:
    raise SystemExit("storage terminal result action differs")
if document != expected:
    raise SystemExit("storage terminal absence proof differs")
PY
}

promote_storage_state() {
  local source="$1"
  local destination="$2"
  python3 -B - "${source}" "${destination}" "${evidence_root}" <<'PY'
import os
import pathlib
import sys
source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
root = pathlib.Path(sys.argv[3])
if source.parent != root or destination.parent != root:
    raise SystemExit("storage state escaped its protected root")
metadata = source.stat(follow_symlinks=False)
if not source.is_file() or source.is_symlink() or metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
    raise SystemExit("storage state source is unsafe")
if destination.exists() or destination.is_symlink():
    raise SystemExit("storage state destination already exists")
descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.replace(source, destination)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

activate_config() {
  local target="$1"
  if [[ ${deployment_mutation_armed} == true ]]; then
    deployment_mutation set-config --path "${deployment_mutation_journal}" \
      --configuration-file "${target}" || return 1
    deployment_mutation_phase=config-armed
    deployment_mutation_active_config="${target}"
  fi
  ln -sfn -- "${target}" "${app_config}.next" || return 1
  mv -Tf -- "${app_config}.next" "${app_config}" || return 1
  fsync_directory "$(dirname -- "${app_config}")" || return 1
  return 0
}

write_current_evidence() {
  local release="$1"
  local configuration="$2"
  local release_record="$3"
  local discourse_connect="$4"
  local marker_file="$5"
  local marker_sha="$6"
  python3 - /var/lib/mochirii/forums/current-release.json "${release}" "${configuration}" "${release_record}" "${discourse_connect}" "${marker_file}" "${marker_sha}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import tempfile
import sys
path = pathlib.Path(sys.argv[1])
record = pathlib.Path(sys.argv[4])
if not record.is_file() or record.is_symlink():
    raise SystemExit("release evidence is absent")
if record.stat().st_uid != 0 or record.stat().st_mode & 0o077:
    raise SystemExit("release evidence permissions are unsafe")
record_sha = hashlib.sha256(record.read_bytes()).hexdigest()
if sys.argv[5] not in {"true", "false"}:
    raise SystemExit("DiscourseConnect evidence is malformed")
marker_file = sys.argv[6] or None
marker_sha = sys.argv[7] or None
if (marker_file is None) != (marker_sha is None):
    raise SystemExit("member-rollout evidence is incomplete")
if marker_file is not None and (
    marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)
):
    raise SystemExit("member-rollout evidence is malformed")
document = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "releaseEvidenceFile": record.name,
    "releaseEvidenceSha256": record_sha,
    "discourseConnectEnabled": sys.argv[5] == "true",
    "memberRolloutMarkerFile": marker_file,
    "memberRolloutMarkerSha256": marker_sha,
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
}

stop_app_safely() {
  local running
  local inventory
  timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
  if running="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{.State.Running}}' app 2>/dev/null)"; then
    [[ ${running} == false ]]
    return
  fi
  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || return 1
  [[ -z ${inventory} ]]
}

emergency_stop() {
  if stop_app_safely; then
    printf '%s\n' "Mochirii Forums application stop was independently verified." >&2
    return 0
  fi
  record_event emergency-stop blocked "${configuration_id:--}" "${expected_archive_sha:--}" || true
  runtime_survivor_unproved=true
  printf '%s\n' "CRITICAL: Mochirii Forums application stop could not be verified." >&2
  return 1
}

remove_launcher_cid_safely() {
  local bootstrap_id=""
  local bootstrap_inventory=""
  [[ -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ]] || return 0
  if [[ ! -f ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} || "$(stat -c '%U:%G %a' "${launcher_bootstrap_cid}" 2>/dev/null)" != "root:root 600" || "$(stat -c '%s' "${launcher_bootstrap_cid}" 2>/dev/null)" -gt 128 ]]; then
    return 1
  fi
  IFS= read -r bootstrap_id <"${launcher_bootstrap_cid}" || true
  if [[ -n ${bootstrap_id} ]]; then
    [[ ${bootstrap_id} =~ ^[0-9a-f]{64}$ ]] || return 1
    timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 "${bootstrap_id}" >/dev/null 2>&1 || true
    timeout --signal=TERM --kill-after=5s 45 docker rm --force "${bootstrap_id}" >/dev/null 2>&1 || true
    bootstrap_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc --filter "id=${bootstrap_id}" --format '{{.ID}}' 2>/dev/null)" || return 1
    [[ -z ${bootstrap_inventory} ]] || return 1
  fi
  python3 -B - "${launcher_bootstrap_cid}" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

launcher_processes_absent() {
  timeout --signal=TERM --kill-after=5s 15 bash -c \
    'ps -eo args 2>/dev/null | awk '\''index($0, "." "/launcher") || index($0, "app_bootstrap" ".cid") { found = 1 } END { exit(found ? 1 : 0) }'\'' >/dev/null'
}

reconcile_launcher_image() {
  local expected_id="${launcher_previous_image_id}"
  local current_id=""
  local stable=0
  local attempts=0
  while (( attempts < 30 && stable < 5 )); do
    current_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
    [[ -z ${current_id} || ${current_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    if [[ ${current_id} != "${expected_id}" ]]; then
      if [[ -n ${expected_id} ]]; then
        timeout --signal=TERM --kill-after=5s 30 docker image inspect "${expected_id}" >/dev/null 2>&1 || return 1
        timeout --signal=TERM --kill-after=5s 30 docker image tag "${expected_id}" local_discourse/app >/dev/null 2>&1 || return 1
      elif [[ -n ${current_id} ]]; then
        timeout --signal=TERM --kill-after=5s 30 docker image rm --force local_discourse/app >/dev/null 2>&1 || return 1
      fi
      stable=0
    else
      stable=$((stable + 1))
    fi
    attempts=$((attempts + 1))
    (( stable >= 5 )) || sleep 1
  done
  (( stable >= 5 ))
}

reconcile_launcher_operation() {
  local outcome="$1"
  local inventory=""
  local app_state=""
  local current_image=""
  local container_id=""
  local container_name=""
  local stable=0
  local attempts=0
  [[ ${outcome} == success || ${outcome} == failure ]] || return 1
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  launcher_processes_absent || return 1
  if [[ ${outcome} == success && ( -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ) ]]; then
    return 1
  fi
  if [[ ${outcome} == failure ]]; then
    remove_launcher_cid_safely || return 1
    inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
      --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}} {{.Names}}' 2>/dev/null)" || return 1
    while IFS=' ' read -r container_id container_name; do
      [[ -n ${container_id} ]] || continue
      [[ ${container_id} =~ ^[0-9a-f]{64}$ && ${container_name} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || return 1
      timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 "${container_id}" >/dev/null 2>&1 || true
      timeout --signal=TERM --kill-after=5s 45 docker rm --force "${container_id}" >/dev/null 2>&1 || true
    done <<<"${inventory}"
    while (( attempts < 30 && stable < 5 )); do
      inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
        --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}}' 2>/dev/null)" || return 1
      if [[ -z ${inventory} ]]; then stable=$((stable + 1)); else stable=0; fi
      attempts=$((attempts + 1))
      (( stable >= 5 )) || sleep 1
    done
    (( stable >= 5 )) || return 1
    reconcile_launcher_image || return 1
    return 0
  fi

  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
    --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}} {{.Names}}' 2>/dev/null)" || return 1
  case "${launcher_operation_command}" in
    start|rebuild)
      [[ ${inventory} =~ ^[0-9a-f]{64}[[:space:]]app$ ]] || return 1
      ;;
    bootstrap|restart|destroy)
      [[ -z ${inventory} ]] || return 1
      ;;
    *) return 1 ;;
  esac
  if [[ ${launcher_operation_command} == start || ${launcher_operation_command} == rebuild || ${launcher_operation_command} == restart ]]; then
    app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
    [[ ${app_state} == true ]] || return 1
  elif [[ ${launcher_operation_command} == destroy ]]; then
    inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || return 1
    [[ -z ${inventory} ]] || return 1
  fi
  if [[ ${launcher_operation_command} == bootstrap || ${launcher_operation_command} == rebuild ]]; then
    current_image="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
    [[ ${current_image} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  fi
  launcher_processes_absent
}

reconcile_launcher_failure() {
  if [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]]; then
    if ! reconcile_launcher_operation failure; then
      runtime_survivor_unproved=true
      record_event launcher-reconcile blocked "${configuration_id:--}" "${expected_archive_sha:--}" || true
      printf '%s\n' "CRITICAL: Launcher container, process, or image reconciliation is unproved." >&2
      return 1
    fi
  else
    remove_launcher_cid_safely || {
      runtime_survivor_unproved=true
      return 1
    }
    launcher_processes_absent || {
      runtime_survivor_unproved=true
      return 1
    }
  fi
  if ! emergency_stop; then
    return 1
  fi
  if [[ ${deployment_mutation_armed} == true && ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]]; then
    if ! deployment_mutation finish-launcher --path "${deployment_mutation_journal}" \
      --token "${launcher_operation_token}" --outcome failure; then
      runtime_survivor_unproved=true
      printf '%s\n' "CRITICAL: Launcher containment was proved but its durable mutation journal could not advance." >&2
      return 1
    fi
    deployment_mutation_phase=runtime-contained
  fi
  launcher_operation_token=""
  launcher_previous_image_id=""
  launcher_operation_command=""
  record_event launcher-reconcile passed "${configuration_id:--}" "${expected_archive_sha:--}" || true
  return 0
}

restore_previous_release() {
  [[ ${automatic_rollback_compatible} == true ]] || return 1
  [[ ${target_database_mutation_possible} == false ]] || return 1
  [[ -n ${previous_config} && -n ${previous_release} && -n ${previous_configuration} ]] || return 1
  activate_config "${previous_config}" || return 1
  run_launcher rollback rebuild app || return 1
  run_release_verification "${previous_release}" "${previous_configuration}" --deployment-prior-rollback || return 1
  if [[ -n ${previous_current_target} ]]; then
    ln -sfn -- "${previous_current_target}" /opt/mochirii/forums/current.next || return 1
    mv -Tf -- /opt/mochirii/forums/current.next /opt/mochirii/forums/current || return 1
    fsync_directory /opt/mochirii/forums || return 1
  fi
  write_current_evidence "${previous_release}" "${previous_configuration}" "${evidence_root}/${previous_release}-${previous_configuration}-release.json" "${previous_discourse_connect}" "${previous_marker_file}" "${previous_marker_sha}" || return 1
  return 0
}

seal_forward_fix_required() {
  local current_sha
  emergency_stop || return 1
  [[ -f ${config_dir}/app.yml && ! -L ${config_dir}/app.yml ]] || return 1
  activate_config "${config_dir}/app.yml" || return 1
  current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk '{print $1}')" || return 1
  [[ ${current_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  python3 -B - "${deployment_recovery_journal}" "${commit}" "${configuration_id}" "${previous_release}" "${previous_configuration}" "${current_sha}" "${requested_discourse_connect}" "${docker_revision}" "${core_revision}" "${manager_revision}" "${base_image}" <<'PY' || return 1
import datetime
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "previousRepositoryCommit": sys.argv[4],
    "previousProductionConfigurationSha256": sys.argv[5],
    "previousCurrentReleaseSha256": sys.argv[6],
    "discourseConnectEnabled": sys.argv[7] == "true",
    "discourseDockerRevision": sys.argv[8],
    "discourseRevision": sys.argv[9],
    "dockerManagerRevision": sys.argv[10],
    "baseImageDigest": sys.argv[11],
    "applicationStopped": True,
    "recoveryMode": "forward-fix-or-clean-restore",
}
if sys.argv[7] not in {"true", "false"} or not all(
    re.fullmatch(r"[0-9a-f]{40}", value) for value in (sys.argv[2], sys.argv[4], sys.argv[8], sys.argv[9], sys.argv[10])
) or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (sys.argv[3], sys.argv[5], sys.argv[6])) or not re.fullmatch(r"sha256:[0-9a-f]{64}", sys.argv[11]):
    raise SystemExit("forward-fix identity is malformed")
candidate = path.parent / f".{path.name}.partial"
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("forward-fix journal is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document) or any(existing.get(key) != value for key, value in document.items() if key != "recordedAt"):
        raise SystemExit("forward-fix journal differs")
else:
    if candidate.exists() or candidate.is_symlink():
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
            raise SystemExit("forward-fix partial is unsafe")
        candidate.unlink()
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
        target.flush()
        os.fsync(target.fileno())
    os.link(candidate, path, follow_symlinks=False)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
        candidate.unlink()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
  record_event deployment-forward-fix blocked "${configuration_id}" "$(sha256sum -- "${deployment_recovery_journal}" | awk '{print $1}')" || true
  return 0
}

validate_forward_fix_retry() {
  python3 -B - "${deployment_recovery_journal}" "${commit}" "${configuration_id}" "${requested_discourse_connect}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
    raise SystemExit("forward-fix journal is unsafe")
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "previousRepositoryCommit", "previousProductionConfigurationSha256",
    "previousCurrentReleaseSha256", "discourseConnectEnabled", "discourseDockerRevision",
    "discourseRevision", "dockerManagerRevision", "baseImageDigest", "applicationStopped",
    "recoveryMode",
}
if (
    set(document) != required
    or document.get("schemaVersion") != 1
    or document.get("repositoryCommit") != sys.argv[2]
    or document.get("productionConfigurationSha256") != sys.argv[3]
    or document.get("discourseConnectEnabled") is not (sys.argv[4] == "true")
    or document.get("applicationStopped") is not True
    or document.get("recoveryMode") != "forward-fix-or-clean-restore"
):
    raise SystemExit("forward-fix journal tuple differs")
print(hashlib.sha256(path.read_bytes()).hexdigest())
PY
}

clear_forward_fix_journal() {
  local expected_sha="$1"
  python3 -B - "${deployment_recovery_journal}" "${expected_sha}" <<'PY'
import hashlib
import os
import pathlib
import re
import sys
path = pathlib.Path(sys.argv[1])
if not re.fullmatch(r"[0-9a-f]{64}", sys.argv[2]) or hashlib.sha256(path.read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit("forward-fix journal digest changed")
path.unlink()
descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

clear_target_authentication_pointer() {
  local pointer=/var/lib/mochirii/forums/current-authentication.json
  python3 -B - "${pointer}" "${commit}" "${configuration_id}" <<'PY'
import json
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists() and not path.is_symlink():
    raise SystemExit(0)
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
    raise SystemExit("authentication pointer is unsafe")
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}
allowed = {
    "consumer-public-producer-pending", "contained-after-e2e-failure",
    "contained-producer-state-unproved", "activation-deploy-failed",
    "activation-deploy-failed-producer-unproved",
}
if (
    set(document) != required
    or document.get("repositoryCommit") != sys.argv[2]
    or document.get("productionConfigurationSha256") != sys.argv[3]
    or document.get("activationPhase") not in allowed
):
    raise SystemExit("authentication pointer does not belong to the failed exact activation")
path.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

archive_stale_authentication_pointer() {
  local pointer=/var/lib/mochirii/forums/current-authentication.json
  python3 -B - "${pointer}" "${evidence_root}" "${commit}" "${configuration_id}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
evidence_root = pathlib.Path(sys.argv[2])
target_commit = sys.argv[3]
target_configuration = sys.argv[4]
state_root = path.parent
transition = evidence_root / f"{target_commit}-{target_configuration}-authentication-advance.json"

def protected_bytes(target, label):
    metadata = target.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit(f"{label} is unsafe")
    return target.read_bytes()

current_bytes = protected_bytes(state_root / "current-release.json", "target current-release evidence")
current = json.loads(current_bytes)
target_release_name = f"{target_commit}-{target_configuration}-release.json"
target_release = evidence_root / target_release_name
target_release_bytes = protected_bytes(target_release, "target release evidence")
target_release_sha = hashlib.sha256(target_release_bytes).hexdigest()
if (
    current.get("repositoryCommit") != target_commit
    or current.get("productionConfigurationSha256") != target_configuration
    or current.get("releaseEvidenceFile") != target_release_name
    or current.get("releaseEvidenceSha256") != target_release_sha
    or current.get("discourseConnectEnabled") is not False
):
    raise SystemExit("authentication advance target is not the exact verified consumer-disabled release")

if transition.exists() or transition.is_symlink():
    transition_bytes = protected_bytes(transition, "authentication advance evidence")
    existing = json.loads(transition_bytes)
    required = {
        "schemaVersion", "recordedAt", "previousRepositoryCommit",
        "previousProductionConfigurationSha256", "previousAuthenticationPointerFile",
        "previousAuthenticationPointerSha256", "repositoryCommit",
        "productionConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256",
        "currentReleaseSha256", "activationPhase",
    }
    archive = evidence_root / str(existing.get("previousAuthenticationPointerFile", ""))
    if (
        set(existing) != required
        or existing.get("schemaVersion") != 1
        or existing.get("repositoryCommit") != target_commit
        or existing.get("productionConfigurationSha256") != target_configuration
        or existing.get("releaseEvidenceFile") != target_release_name
        or existing.get("releaseEvidenceSha256") != target_release_sha
        or existing.get("currentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()
        or existing.get("activationPhase") != "consumer-disabled"
        or not archive.name.endswith("-authentication-complete-pointer.json")
        or archive.parent != evidence_root
    ):
        raise SystemExit("authentication advance evidence differs")
    archive_bytes = protected_bytes(archive, "authentication pointer archive")
    if hashlib.sha256(archive_bytes).hexdigest() != existing.get("previousAuthenticationPointerSha256"):
        raise SystemExit("authentication pointer archive digest differs")
    if path.exists() or path.is_symlink():
        if protected_bytes(path, "stale authentication pointer") != archive_bytes:
            raise SystemExit("current stale pointer differs from its committed archive")
        path.unlink()
        descriptor = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(hashlib.sha256(transition_bytes).hexdigest())
    raise SystemExit(0)

pointer_bytes = protected_bytes(path, "stale authentication pointer")
pointer = json.loads(pointer_bytes)
required_pointer = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}

previous_commit = pointer.get("repositoryCommit", "")
previous_configuration = pointer.get("productionConfigurationSha256", "")
if (
    set(pointer) != required_pointer
    or pointer.get("activationPhase") != "complete"
    or not re.fullmatch(r"[0-9a-f]{40}", previous_commit)
    or not re.fullmatch(r"[0-9a-f]{64}", previous_configuration)
    or (previous_commit == target_commit and previous_configuration == target_configuration)
):
    raise SystemExit("stale authentication pointer is not one completed prior tuple")
record_name = f"{previous_commit}-{previous_configuration}-authentication-complete.json"
record = evidence_root / record_name
record_bytes = protected_bytes(record, "stale authentication record")
if pointer.get("authenticationEvidenceFile") != record_name or hashlib.sha256(record_bytes).hexdigest() != pointer.get("authenticationEvidenceSha256"):
    raise SystemExit("stale authentication record reference differs")
archive = evidence_root / f"{previous_commit}-{previous_configuration}-authentication-complete-pointer.json"
archive_candidate = evidence_root / f".{archive.name}.partial"
if archive.exists() or archive.is_symlink():
    if protected_bytes(archive, "authentication pointer archive") != pointer_bytes:
        raise SystemExit("authentication pointer archive differs")
else:
    if archive_candidate.exists() or archive_candidate.is_symlink():
        protected_bytes(archive_candidate, "authentication pointer archive partial")
        archive_candidate.unlink()
    descriptor = os.open(archive_candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(pointer_bytes)
        target.flush()
        os.fsync(target.fileno())
    os.link(archive_candidate, archive, follow_symlinks=False)
    descriptor = os.open(evidence_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
        archive_candidate.unlink()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "previousRepositoryCommit": previous_commit,
    "previousProductionConfigurationSha256": previous_configuration,
    "previousAuthenticationPointerFile": archive.name,
    "previousAuthenticationPointerSha256": hashlib.sha256(pointer_bytes).hexdigest(),
    "repositoryCommit": target_commit,
    "productionConfigurationSha256": target_configuration,
    "releaseEvidenceFile": target_release_name,
    "releaseEvidenceSha256": target_release_sha,
    "currentReleaseSha256": hashlib.sha256(current_bytes).hexdigest(),
    "activationPhase": "consumer-disabled",
}
candidate = evidence_root / f".{transition.name}.partial"
if candidate.exists() or candidate.is_symlink():
    protected_bytes(candidate, "authentication advance partial")
    candidate.unlink()
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
    target.flush()
    os.fsync(target.fileno())
os.link(candidate, transition, follow_symlinks=False)
descriptor = os.open(evidence_root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
    candidate.unlink()
    os.fsync(descriptor)
finally:
    os.close(descriptor)
path.unlink()
descriptor = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
print(hashlib.sha256(transition.read_bytes()).hexdigest())
PY
}

ensure_pending_authentication() {
  local release_record="$1"
  python3 -B - "${current_authentication}" "${evidence_root}" "${release_record}" "${commit}" "${configuration_id}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import sys

pointer_path = pathlib.Path(sys.argv[1])
evidence_root = pathlib.Path(sys.argv[2])
release_path = pathlib.Path(sys.argv[3])
commit = sys.argv[4]
configuration = sys.argv[5]

def protected_bytes(path, label):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit(f"{label} is unsafe")
    return path.read_bytes()

release_bytes = protected_bytes(release_path, "pending release evidence")
release_sha = hashlib.sha256(release_bytes).hexdigest()
current_path = pointer_path.parent / "current-release.json"
current_bytes = protected_bytes(current_path, "pending current-release evidence")
current = json.loads(current_bytes)
release_name = f"{commit}-{configuration}-release.json"
if (
    release_path != evidence_root / release_name
    or current.get("repositoryCommit") != commit
    or current.get("productionConfigurationSha256") != configuration
    or current.get("releaseEvidenceFile") != release_name
    or current.get("releaseEvidenceSha256") != release_sha
    or current.get("discourseConnectEnabled") is not True
):
    raise SystemExit("pending authentication release binding differs")
record_path = evidence_root / f"{commit}-{configuration}-authentication-pending.json"
stable = {
    "schemaVersion": 1,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "releaseEvidenceFile": release_name,
    "releaseEvidenceSha256": release_sha,
    "currentReleaseSha256": hashlib.sha256(current_bytes).hexdigest(),
    "activationPhase": "consumer-public-producer-pending",
    "websiteProducerDisabledProved": True,
    "containedActivationPassed": True,
    "publicForumsVerificationPassed": True,
}
candidate = evidence_root / f".{record_path.name}.partial"
if record_path.exists() or record_path.is_symlink():
    existing = json.loads(protected_bytes(record_path, "pending authentication evidence"))
    if set(existing) != set(stable) | {"recordedAt"} or any(existing.get(key) != value for key, value in stable.items()) or not isinstance(existing.get("recordedAt"), str) or not existing["recordedAt"].endswith("Z"):
        raise SystemExit("pending authentication evidence differs")
    if candidate.exists() or candidate.is_symlink():
        protected_bytes(candidate, "pending authentication evidence partial")
        candidate.unlink()
else:
    if candidate.exists() or candidate.is_symlink():
        protected_bytes(candidate, "pending authentication evidence partial")
        candidate.unlink()
    document = {**stable, "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(document, target, sort_keys=True, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.link(candidate, record_path, follow_symlinks=False)
    directory = os.open(evidence_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        candidate.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)
record_sha = hashlib.sha256(protected_bytes(record_path, "pending authentication evidence")).hexdigest()
pointer = {
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "authenticationEvidenceFile": record_path.name,
    "authenticationEvidenceSha256": record_sha,
    "activationPhase": "consumer-public-producer-pending",
}
if pointer_path.exists() or pointer_path.is_symlink():
    existing_pointer = json.loads(protected_bytes(pointer_path, "pending authentication pointer"))
    if existing_pointer != pointer:
        raise SystemExit("pending authentication pointer differs")
else:
    with tempfile.NamedTemporaryFile("w", dir=pointer_path.parent, prefix=f".{pointer_path.name}.", delete=False, encoding="utf-8") as target:
        json.dump(pointer, target, sort_keys=True)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
        temporary = pathlib.Path(target.name)
    temporary.chmod(0o600)
    os.replace(temporary, pointer_path)
    descriptor = os.open(pointer_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(pointer_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
print(record_sha)
PY
}

finish_deployment_authentication() {
  local action="$1"
  local release_record="$2"
  local phase="$3"
  local state=none
  local evidence_sha
  if [[ -e ${current_authentication} || -L ${current_authentication} ]]; then
    state="$(python3 -B "${release_dir}/scripts/authentication-state.py" \
      --pointer "${current_authentication}" --expected-commit "${commit}" \
      --expected-configuration "${configuration_id}")" || return 1
  fi
  case "${action}" in
    pending)
      if [[ ${state} == contained-after-e2e-failure || ${state} == activation-deploy-failed ]]; then
        clear_target_authentication_pointer || return 1
        state=none
      fi
      [[ ${state} == none || ${state} == consumer-public-producer-pending ]] || return 1
      timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || return 1
      evidence_sha="$(ensure_pending_authentication "${release_record}")" || return 1
      record_event authentication-staging passed "${configuration_id}" "${evidence_sha}" || return 1
      ;;
    preserve-complete)
      [[ ${state} == complete ]] || return 1
      timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py enabled >/dev/null 2>&1 || return 1
      evidence_sha="$(python3 -B - "${current_authentication}" <<'PY'
import json
import pathlib
import re
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("authenticationEvidenceSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", value):
    raise SystemExit("completed authentication digest is malformed")
print(value)
PY
)" || return 1
      record_event authentication-rebuild passed "${configuration_id}" "${evidence_sha}" || return 1
      ;;
    advance-complete)
      [[ ${state} == none || ${state} == stale-other-tuple ]] || return 1
      timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || return 1
      evidence_sha="$(archive_stale_authentication_pointer)" || return 1
      [[ ${evidence_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
      record_event authentication-advance passed "${configuration_id}" "${evidence_sha}" || return 1
      ;;
    absent)
      [[ ${state} == none ]] || return 1
      ;;
    *) return 1 ;;
  esac
  [[ ${phase} == prepared || ${phase} == state-committed || ${phase} == event-committed || ${phase} == complete ]] || return 1
}

complete_deployment_commit() {
  local phase="$1"
  local authentication_action="$2"
  local release_record="$3"
  local release_sha="$4"
  local recorded_connect="$5"
  local recorded_marker_file="$6"
  local recorded_marker_sha="$7"
  local recorded_forward_sha="$8"
  [[ ${phase} == prepared || ${phase} == state-committed || ${phase} == event-committed || ${phase} == complete ]] || return 1
  [[ ${recorded_connect} == "${requested_discourse_connect}" ]] || return 1
  [[ ${recorded_marker_file} != - ]] || recorded_marker_file=""
  [[ ${recorded_marker_sha} != - ]] || recorded_marker_sha=""
  [[ ${recorded_forward_sha} != - ]] || recorded_forward_sha=""
  marker_file_for_evidence="${recorded_marker_file}"
  marker_sha_for_evidence="${recorded_marker_sha}"
  python3 -B - "${release_record}" "${commit}" "${configuration_id}" "${expected_archive_sha}" \
    "${release_sha}" "${requested_discourse_connect}" "${marker_file_for_evidence:--}" \
    "${marker_sha_for_evidence:--}" "${evidence_root}" "${repository_tree}" \
    "${release_archive_bytes}" "${release_archive_manifest_sha}" <<'PY' >/dev/null || return 1
import hashlib
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if path != pathlib.Path(sys.argv[9]) / f"{sys.argv[2]}-{sys.argv[3]}-release.json" or not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536 or hashlib.sha256(path.read_bytes()).hexdigest() != sys.argv[5]:
    raise SystemExit("deployment release evidence binding differs")
document = json.loads(path.read_text(encoding="utf-8"))
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
connect = sys.argv[6] == "true"
marker_file = None if sys.argv[7] == "-" else sys.argv[7]
marker_sha = None if sys.argv[8] == "-" else sys.argv[8]
if (
    set(document) != required
    or document.get("schemaVersion") != 2
    or document.get("repositoryCommit") != sys.argv[2]
    or document.get("productionConfigurationSha256") != sys.argv[3]
    or document.get("releaseArchiveSha256") != sys.argv[4]
    or document.get("repositoryTree") != sys.argv[10]
    or document.get("releaseArchiveBytes") != int(sys.argv[11])
    or document.get("releaseArchiveContentManifestSha256") != sys.argv[12]
    or document.get("discourseDockerRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b"
    or document.get("discourseRevision") != "cbf996f65aae3da1843224aa624bcd9a225931ac"
    or document.get("dockerManagerRevision") != "c008c3ca7fcc44775215843992e88190adb7b3bf"
    or document.get("baseImageDigest") != "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
    or document.get("discourseConnectEnabled") is not connect
    or document.get("memberRolloutMarkerFile") != marker_file
    or document.get("memberRolloutMarkerSha256") != marker_sha
    or any(document.get(key) is not True for key in ("hostVerificationPassed", "hostedStoragePassed", "storageRestartPersistencePassed", "storageRebuildPersistencePassed", "storageCleanupPassed"))
):
    raise SystemExit("deployment release evidence contract differs")
expected_phase = "consumer-public-producer-pending" if connect else "consumer-disabled"
if document.get("activationPhase") != expected_phase or document.get("containedActivationPassed") is not connect:
    raise SystemExit("deployment activation evidence differs")
storage_name = document.get("storageEvidenceFile", "")
storage_sha = document.get("storageEvidenceSha256", "")
storage = pathlib.Path(sys.argv[9]) / storage_name
storage_meta = storage.lstat()
if not re.fullmatch(rf"{sys.argv[2]}-{sys.argv[3]}-storage[.]json", storage_name) or not re.fullmatch(r"[0-9a-f]{64}", str(storage_sha)) or not stat.S_ISREG(storage_meta.st_mode) or stat.S_ISLNK(storage_meta.st_mode) or storage_meta.st_uid != 0 or storage_meta.st_mode & 0o077 or hashlib.sha256(storage.read_bytes()).hexdigest() != storage_sha:
    raise SystemExit("deployment storage evidence binding differs")
PY
  [[ -L ${app_config} && "$(readlink -f -- "${app_config}")" == "${config_dir}/app.yml" ]] || return 1
  [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == true ]] || return 1
  timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc \
    'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1" && test "$MOCHIRII_RELEASE_ASSET_ROOT" = /opt/mochirii-release && test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = "$2" && test "$DISCOURSE_DISABLE_EMAILS" = no' \
    bash "${commit}" "${requested_discourse_connect}" >/dev/null 2>&1 || return 1

  ln -sfn -- "${release_dir}" /opt/mochirii/forums/current.next || return 1
  mv -Tf -- /opt/mochirii/forums/current.next /opt/mochirii/forums/current || return 1
  fsync_directory /opt/mochirii/forums || return 1
  write_current_evidence "${commit}" "${configuration_id}" "${release_record}" \
    "${requested_discourse_connect}" "${marker_file_for_evidence}" "${marker_sha_for_evidence}" || return 1
  finish_deployment_authentication "${authentication_action}" "${release_record}" "${phase}" || return 1
  if [[ ${phase} == complete ]]; then
    if [[ ${deployment_mutation_armed} == true ]]; then
      run_release_verification "${commit}" "${configuration_id}" --deployment-transaction || return 1
    else
      run_release_verification "${commit}" "${configuration_id}" || return 1
    fi
  else
    run_release_verification "${commit}" "${configuration_id}" --deployment-transaction || return 1
  fi

  if [[ ${phase} == prepared ]]; then
    write_deployment_transaction state-committed "${authentication_action}" "${release_record}" \
      "${release_sha}" "${recorded_forward_sha:--}" || return 1
    phase=state-committed
  fi
  deployment_state_committed=true
  if [[ -n ${recorded_forward_sha} ]]; then
    record_event deployment-forward-fix passed "${configuration_id}" "${recorded_forward_sha}" || return 1
    if [[ -e ${deployment_recovery_journal} || -L ${deployment_recovery_journal} ]]; then
      clear_forward_fix_journal "${recorded_forward_sha}" || return 1
    fi
  fi
  record_event deployment passed "${configuration_id}" "${release_sha}" || return 1
  if [[ ${phase} == state-committed ]]; then
    write_deployment_transaction event-committed "${authentication_action}" "${release_record}" \
      "${release_sha}" "${recorded_forward_sha:--}" || return 1
    phase=event-committed
  fi
  if [[ ${phase} == event-committed ]]; then
    publish_deployment_terminal || return 1
    if [[ ${historical_bootstrap} == true ]]; then
      python3 -B "${historical_helper}" complete-bootstrap \
        --receipt "${historical_receipt}" --journal "${historical_journal}" \
        --current-release /var/lib/mochirii/forums/current-release.json \
        --release-evidence "${release_record}" \
        --confirmation "COMPLETE HISTORICAL MOCHIRII FORUMS BOOTSTRAP" || return 1
    fi
    clear_deployment_transaction || return 1
  fi
  if [[ ${historical_bootstrap} == true ]]; then
    python3 -B "${historical_helper}" complete-bootstrap \
      --receipt "${historical_receipt}" --journal "${historical_journal}" \
      --current-release /var/lib/mochirii/forums/current-release.json \
      --release-evidence "${release_record}" \
      --confirmation "COMPLETE HISTORICAL MOCHIRII FORUMS BOOTSTRAP" || return 1
    python3 -B "${historical_helper}" verify --receipt "${historical_receipt}" \
      --journal "${historical_journal}" --require-phase bootstrap-complete >/dev/null || return 1
  fi
  deployment_success=true
  return 0
}

seal_activation_deploy_failure() {
  local producer_proved=false
  local phase=activation-deploy-failed-producer-unproved
  local suffix=authentication-activation-failed-unproved
  local record
  local record_sha
  local current_sha
  [[ -n ${previous_config} && -n ${previous_release} && -n ${previous_configuration} ]] || return 1
  [[ ${previous_discourse_connect} == false && ${requested_discourse_connect} == true ]] || return 1
  emergency_stop || return 1
  activate_config "${previous_config}" || return 1
  if [[ -n ${previous_current_target} ]]; then
    ln -sfn -- "${previous_current_target}" /opt/mochirii/forums/current.next || return 1
    mv -Tf -- /opt/mochirii/forums/current.next /opt/mochirii/forums/current || return 1
    fsync_directory /opt/mochirii/forums || return 1
  fi
  write_current_evidence "${previous_release}" "${previous_configuration}" "${evidence_root}/${previous_release}-${previous_configuration}-release.json" false "${previous_marker_file}" "${previous_marker_sha}" || return 1
  [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || return 1
  if timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1; then
    producer_proved=true
    phase=activation-deploy-failed
    suffix=authentication-activation-failed
  fi
  current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk '{print $1}')" || return 1
  [[ ${current_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  record="${evidence_root}/${commit}-${configuration_id}-${suffix}.json"
  python3 -B - "${record}" "${commit}" "${configuration_id}" "${previous_release}" "${previous_configuration}" "${current_sha}" "${phase}" "${producer_proved}" <<'PY' || return 1
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
target_commit = sys.argv[2]
target_configuration = sys.argv[3]
previous_commit = sys.argv[4]
previous_configuration = sys.argv[5]
current_sha = sys.argv[6]
phase = sys.argv[7]
producer_proved = sys.argv[8]
if phase not in {"activation-deploy-failed", "activation-deploy-failed-producer-unproved"} or producer_proved not in {"true", "false"}:
    raise SystemExit("activation failure phase is malformed")
if (phase == "activation-deploy-failed") != (producer_proved == "true"):
    raise SystemExit("activation failure producer proof differs")
state_root = path.parent.parent
current_path = state_root / "current-release.json"
current_bytes = current_path.read_bytes()
if hashlib.sha256(current_bytes).hexdigest() != current_sha:
    raise SystemExit("prior current-release bytes changed")
current = json.loads(current_bytes)
current_keys = {
    "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
    "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
release_name = f"{previous_commit}-{previous_configuration}-release.json"
release_path = path.parent / release_name
if (
    set(current) != current_keys
    or current.get("repositoryCommit") != previous_commit
    or current.get("productionConfigurationSha256") != previous_configuration
    or current.get("releaseEvidenceFile") != release_name
    or current.get("discourseConnectEnabled") is not False
    or not release_path.is_file()
    or release_path.is_symlink()
):
    raise SystemExit("prior stopped release evidence differs")
release_metadata = release_path.stat()
if release_metadata.st_uid != 0 or stat.S_IMODE(release_metadata.st_mode) != 0o600 or release_metadata.st_size > 65536:
    raise SystemExit("prior release evidence is unsafe")
release_sha = hashlib.sha256(release_path.read_bytes()).hexdigest()
if current.get("releaseEvidenceSha256") != release_sha:
    raise SystemExit("prior release evidence digest differs")
release = json.loads(release_path.read_text(encoding="utf-8"))
if (
    release.get("schemaVersion") != 2
    or release.get("repositoryCommit") != previous_commit
    or release.get("productionConfigurationSha256") != previous_configuration
    or release.get("discourseConnectEnabled") is not False
    or release.get("activationPhase") != "consumer-disabled"
    or release.get("containedActivationPassed") is not False
    or current.get("memberRolloutMarkerFile") != "member-rollout-enabled"
    or current.get("memberRolloutMarkerFile") != release.get("memberRolloutMarkerFile")
    or current.get("memberRolloutMarkerSha256") != release.get("memberRolloutMarkerSha256")
):
    raise SystemExit("prior immutable release is not the exact consumer-disabled rollout state")
document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": target_commit,
    "productionConfigurationSha256": target_configuration,
    "previousRepositoryCommit": previous_commit,
    "previousProductionConfigurationSha256": previous_configuration,
    "releaseEvidenceFile": release_name,
    "releaseEvidenceSha256": release_sha,
    "currentReleaseSha256": current_sha,
    "activationPhase": phase,
    "websiteProducerDisabledProved": producer_proved == "true",
    "applicationStopped": True,
}
candidate = path.parent / f".{path.name}.partial"
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
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("activation failure evidence is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document) or any(existing.get(key) != value for key, value in document.items() if key != "recordedAt"):
        raise SystemExit("activation failure evidence differs")
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
  [[ "$(stat -c '%U:%G %a' "${record}")" == "root:root 600" ]] || return 1
  record_sha="$(sha256sum -- "${record}" | awk '{print $1}')" || return 1
  [[ ${record_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  python3 -B - /var/lib/mochirii/forums/current-authentication.json "${commit}" "${configuration_id}" "$(basename -- "${record}")" "${record_sha}" "${phase}" <<'PY' || return 1
import json
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
document = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "authenticationEvidenceFile": sys.argv[4],
    "authenticationEvidenceSha256": sys.argv[5],
    "activationPhase": sys.argv[6],
}
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("existing authentication pointer is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if existing.get("repositoryCommit") != sys.argv[2] or existing.get("productionConfigurationSha256") != sys.argv[3]:
        raise SystemExit("existing authentication pointer belongs to another tuple")
if candidate.exists() or candidate.is_symlink():
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("authentication pointer partial is unsafe")
    candidate.unlink()
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    target.write(json.dumps(document, sort_keys=True) + "\n")
    target.flush()
    os.fsync(target.fileno())
os.replace(candidate, path)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  record_event activation-recovery blocked "${configuration_id}" "${record_sha}" || true
  if [[ ${producer_proved} == true ]]; then
    printf '%s\n' "DiscourseConnect activation failed; an exact stopped retry state with Website producer disabled was sealed." >&2
  else
    printf '%s\n' "DiscourseConnect activation failed; the application is stopped, but Website producer disablement requires operator reconciliation." >&2
  fi
  return 0
}

recover_failed_activation() {
  if restore_previous_release &&
    timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 &&
    clear_target_authentication_pointer; then
    printf '%s\n' "Failed DiscourseConnect activation rolled back to the exact verified consumer-disabled release." >&2
    return 0
  fi
  [[ ${runtime_survivor_unproved} == false ]] || return 1
  seal_activation_deploy_failure
}

incoming_archive_consumed=false
consume_incoming_archive() {
  [[ ${incoming_archive_consumed} == false ]] || return 0
  if [[ -e ${resolved_archive} || -L ${resolved_archive} ]]; then
    [[ -f ${resolved_archive} && ! -L ${resolved_archive} ]] || return 1
    [[ "$(readlink -f -- "${resolved_archive}")" == "${incoming_root}/${commit}.tar" ]] || return 1
    [[ "$(stat -c '%u %a %s' "${resolved_archive}")" == "$(stat -c '%u' "${incoming_root}") 600 ${expected_archive_size}" ]] || return 1
    rm -f -- "${resolved_archive}" || return 1
  fi
  python3 -B - "${incoming_root}" <<'PY' >/dev/null
import os
import pathlib
import sys
directory = pathlib.Path(sys.argv[1])
descriptor = os.open(directory, os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  incoming_archive_consumed=true
}

on_exit() {
  local status=$?
  trap - EXIT
  if ! consume_incoming_archive; then
    printf '%s\n' "Incoming release transport cleanup could not be durably proved." >&2
    status=1
  fi
  [[ -z ${candidate} || ! -d ${candidate} ]] || rm -rf -- "${candidate}"
  [[ -z ${asset_candidate} || ! -d ${asset_candidate} ]] || rm -rf -- "${asset_candidate}"
  [[ -z ${config_candidate} || ! -d ${config_candidate} ]] || rm -rf -- "${config_candidate}"
  [[ -z ${trusted_repository} || ! -d ${trusted_repository} ]] || rm -rf -- "${trusted_repository}"
  [[ -z ${trusted_archive} || ! -f ${trusted_archive} ]] || rm -f -- "${trusted_archive}"
  [[ ! -f ${quarantine} ]] || rm -f -- "${quarantine}"
  if [[ ${storage_fixture_created} == true && ${storage_fixture_deleted} == false ]]; then
    if [[ -z ${storage_cleanup_journal} || ! -f ${storage_cleanup_journal} || -L ${storage_cleanup_journal} ]]; then
      printf '%s\n' "Hosted storage cleanup journal is absent or unsafe after transaction pre-arm." >&2
      storage_cleanup_blocked=true
      status=1
    else
    storage_state_sha="$(validate_storage_cleanup_journal "${storage_cleanup_journal}" 2>/dev/null || true)"
    cleanup_result=""
    if [[ ${storage_state_sha} =~ ^[0-9a-f]{64}$ && ${runtime_survivor_unproved} == false ]] && timeout --signal=TERM --kill-after=5s 15 docker inspect app >/dev/null 2>&1; then
      cleanup_result="$(mktemp "${evidence_root}/.storage-cleanup.XXXXXXXX.json")"
      chmod 0600 "${cleanup_result}"
      rm -f -- "${cleanup_result}"
    fi
    if [[ ${runtime_survivor_unproved} == false && -n ${cleanup_result} ]] &&
      run_storage_fixture cleanup "${cleanup_result}" "${storage_cleanup_journal}" >/dev/null 2>&1 &&
      validate_storage_terminal_result cleanup "${cleanup_result}" &&
      clear_storage_cleanup_journal "${storage_cleanup_journal}"; then
      storage_fixture_deleted=true
      storage_cleanup_journal=""
      record_event storage-cleanup passed "${configuration_id}" "${storage_state_sha}" || true
    else
      record_event storage-cleanup blocked "${configuration_id}" "${storage_state_sha}" || true
      printf '%s\n' "Hosted storage cleanup is blocked; the pre-armed exact root-only retry journal was retained and public ingress must remain closed." >&2
      storage_cleanup_blocked=true
      status=1
    fi
    [[ -z ${cleanup_result} || ! -f ${cleanup_result} ]] || rm -f -- "${cleanup_result}"
    fi
  fi
  for ephemeral in "${storage_state}" "${storage_create_result}" "${storage_restart_result}" "${storage_rebuild_result}" "${storage_delete_result}"; do
    [[ -z ${ephemeral} || ! -f ${ephemeral} ]] || rm -f -- "${ephemeral}"
  done
  if [[ ${status} -ne 0 && ${deployment_commit_armed} == true && ${deployment_success} == false ]]; then
    printf '%s\n' "Deployment verification passed before terminal publication; the verified mutation and any durably published exact transaction were retained for idempotent retry." >&2
  elif [[ ${status} -ne 0 && ${activation_started} == true && ${deployment_success} == false ]]; then
    if [[ ${runtime_survivor_unproved} == true ]]; then
      printf '%s\n' "CRITICAL: Runtime process termination is unproved; cleanup, rebuild, and public rollback are blocked." >&2
    elif [[ ${storage_cleanup_blocked} == true ]]; then
      containment_config="${config_dir}/restore.yml"
      containment_ok=false
      if [[ -f ${containment_config} && ! -L ${containment_config} ]]; then
        if activate_config "${containment_config}" &&
          run_launcher storage-containment rebuild app &&
          timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'test "$DISCOURSE_DISABLE_EMAILS" = non-staff && test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = false' >/dev/null 2>&1; then
          containment_ports="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{json .HostConfig.PortBindings}}' app 2>/dev/null || true)"
          if [[ ${containment_ports} == '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]}' ]]; then
            containment_ok=true
          fi
        fi
      fi
      if [[ ${containment_ok} == true ]]; then
        printf '%s\n' "Hosted storage cleanup remains blocked; loopback-only, non-staff-mail containment is active." >&2
      else
        if emergency_stop; then
          printf '%s\n' "Hosted storage cleanup remains blocked; independent stop readback replaced unproved containment." >&2
        fi
      fi
    elif [[ ${contained_activation_required} == true ]]; then
      if ! recover_failed_activation; then
        printf '%s\n' "CRITICAL: DiscourseConnect activation failure could not be rolled back or sealed as an exact stopped retry state." >&2
      fi
    elif [[ ${mode} == rebuild ]]; then
      if restore_previous_release; then
        printf '%s\n' "Previous Mochirii Forums release was restored and verified." >&2
      elif seal_forward_fix_required; then
        printf '%s\n' "Cross-version rollback was refused; an exact stopped forward-fix or clean-restore journal was sealed." >&2
      else
        if emergency_stop; then
          printf '%s\n' "Previous release recovery failed; the application stop was verified." >&2
        fi
      fi
    else
      run_launcher failed-bootstrap-cleanup destroy app || true
      if emergency_stop; then
        if [[ -L ${app_config} && "$(readlink -f -- "${app_config}")" == "${config_dir}/app.yml" ]]; then
          rm -f -- "${app_config}"
        fi
        printf '%s\n' "Failed initial container stop was verified; persistent data was retained for explicit disposal review." >&2
      fi
    fi
  fi
  if [[ ${status} -ne 0 && ${deployment_mutation_armed} == true && ${deployment_commit_armed} == false && ${deployment_success} == false && ${runtime_survivor_unproved} == false ]]; then
    if emergency_stop && mark_deployment_mutation_contained; then
      printf '%s\n' "Deployment runtime mutation remains stopped under its exact durable retry journal." >&2
    else
      runtime_survivor_unproved=true
      printf '%s\n' "CRITICAL: Deployment runtime mutation containment or its durable journal update is unproved." >&2
      status=1
    fi
  fi
  if [[ ${status} -ne 0 ]]; then
    record_event deployment failed "${configuration_id:--}" "${expected_archive_sha}" || true
  fi
  exit "${status}"
}
trap on_exit EXIT
trap handle_operation_signal HUP INT TERM
record_event deployment started - "${expected_archive_sha}" || fail "Protected deployment event evidence could not be initialized."

# Copy the uploader-writable file once into root-only quarantine. All hashing,
# listing, validation, and extraction below use only that immutable copy.
install -m 0600 -o root -g root -- "${resolved_archive}" "${quarantine}"
[[ "$(stat -c '%s' "${quarantine}")" == "${expected_archive_size}" ]] || fail "Quarantined release archive size mismatch."
actual_archive_sha="$(sha256sum -- "${quarantine}" | awk '{print $1}')"
[[ ${actual_archive_sha} == "${expected_archive_sha}" ]] || fail "Release archive digest mismatch."

# Before any archive-owned code runs as root, independently read exact public
# canonical main. Ordinary deployment requires the transported bytes to be
# that commit. The operator-only historical branch instead requires canonical
# main to remain the journal's C1 and accepts only the journal-sealed C0 bytes.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0
trusted_git_options=(
  -c credential.helper=
  -c core.askPass=
  -c init.templateDir=
  -c protocol.allow=never
  -c protocol.https.allow=always
  -c http.followRedirects=false
)
trusted_repository="$(mktemp -d "${quarantine_root}/trusted-${commit}.XXXXXXXX")"
trusted_archive="$(mktemp "${quarantine_root}/trusted-${commit}.XXXXXXXX.tar")"
git "${trusted_git_options[@]}" -C "${trusted_repository}" init --bare >/dev/null 2>&1 || fail "Canonical release verifier initialization failed."
git "${trusted_git_options[@]}" -C "${trusted_repository}" remote add origin "${canonical_repository}" >/dev/null 2>&1 || fail "Canonical release verifier remote initialization failed."
mapfile -t trusted_urls < <(git "${trusted_git_options[@]}" -C "${trusted_repository}" remote get-url --all origin)
[[ ${#trusted_urls[@]} -eq 1 && ${trusted_urls[0]} == "${canonical_repository}" ]] || fail "Canonical release verifier remote differs from the exact public repository."
timeout --signal=TERM --kill-after=10s 120 git "${trusted_git_options[@]}" -c protocol.version=2 -C "${trusted_repository}" fetch --no-tags --depth=1 --refmap= origin refs/heads/main >/dev/null 2>&1 || fail "Canonical main could not be read through the protected verifier."
trusted_commit="$(git "${trusted_git_options[@]}" -C "${trusted_repository}" rev-parse --verify FETCH_HEAD^{commit})" || fail "Canonical main did not resolve to one commit."
trusted_repository_tree="$(git "${trusted_git_options[@]}" -C "${trusted_repository}" rev-parse --verify "${trusted_commit}^{tree}")" || fail "Canonical main tree did not resolve."
[[ ${trusted_repository_tree} =~ ^[0-9a-f]{40}$ ]] || fail "Canonical main tree is malformed."
if [[ ${historical_bootstrap} == true ]]; then
  [[ ${trusted_commit} == "${historical_bootstrap_commit}" ]] || fail "Canonical main changed from the exact C1 historical bootstrap authority."
  rm -f -- "${trusted_archive}"
  trusted_archive="${quarantine}"
  trusted_repository_tree="${historical_repository_tree}"
else
  [[ ${trusted_commit} == "${commit}" ]] || fail "Requested release is not the exact current canonical main commit."
  git "${trusted_git_options[@]}" -c tar.umask=0002 -C "${trusted_repository}" archive --format=tar --output="${trusted_archive}" "${trusted_commit}" >/dev/null 2>&1 || fail "Canonical release archive construction failed."
  [[ "$(stat -c '%s' "${trusted_archive}")" == "${expected_archive_size}" ]] || fail "Canonical release archive size differs from the transported release."
  [[ "$(sha256sum -- "${trusted_archive}" | awk '{print $1}')" == "${expected_archive_sha}" ]] || fail "Canonical release archive digest differs from the transported release."
  cmp -s -- "${trusted_archive}" "${quarantine}" || fail "Transported release bytes differ from exact canonical main."
fi
consume_incoming_archive || fail "Incoming release transport cleanup could not be durably proved."

python3 - "${quarantine}" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
allowed_roots = {
    ".env.example", ".gitattributes", ".github", ".gitignore", "AGENTS.md",
    "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "README.md", "SECURITY.md",
    "config", "docs", "plugins", "scripts", "theme",
}
seen = set()
expanded = 0
with tarfile.open(archive, mode="r:") as source:
    members = source.getmembers()
    if not 1 <= len(members) <= 4096:
        raise SystemExit("Release archive member count is outside the reviewed bound.")
    for member in members:
        name = member.name
        if not name or name.startswith("/") or "\\" in name:
            raise SystemExit("Release archive contains an unsafe member path.")
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            raise SystemExit("Release archive contains a control character.")
        parts = name.rstrip("/").split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise SystemExit("Release archive contains an unsafe path component.")
        if parts[0] not in allowed_roots or any(":" in part for part in parts):
            raise SystemExit("Release archive member is outside the exact repository inventory.")
        normalized = "/".join(parts)
        if normalized in seen:
            raise SystemExit("Release archive contains a duplicate member.")
        seen.add(normalized)
        if not (member.isfile() or member.isdir()):
            raise SystemExit("Release archive contains a forbidden member type.")
        if member.isfile():
            if member.size < 0 or member.size > 32 * 1024 * 1024:
                raise SystemExit("Release archive member size is outside the reviewed bound.")
            expanded += member.size
            if expanded > 128 * 1024 * 1024:
                raise SystemExit("Release archive expanded size exceeds the reviewed bound.")
PY

candidate="$(mktemp -d "${releases_root}/.candidate-${commit}.XXXXXXXX")"
tar -xf "${quarantine}" -C "${candidate}" --no-same-owner --no-same-permissions --delay-directory-restore
[[ -z "$(find "${candidate}" -type l -print -quit)" ]] || fail "Extracted release contains a symbolic link."
chmod -R go-w "${candidate}"

export PYTHONDONTWRITEBYTECODE=1
[[ "$(sha256sum -- "${candidate}/scripts/validate-repository.py" | awk '{print $1}')" == "${repository_validator_sha256}" ]] || fail "Trusted repository validator source differs."
[[ "$(sha256sum -- "${candidate}/scripts/test-contracts.py" | awk '{print $1}')" == "${repository_contract_tests_sha256}" ]] || fail "Trusted hostile-fixture source differs."
observed_python_acceptance_root_sha256="$(printf 'mochirii-forums-python-acceptance-root-v1\0%s\0%s\n' "${repository_validator_sha256}" "${repository_contract_tests_sha256}" | sha256sum | awk '{print $1}')"
[[ "${observed_python_acceptance_root_sha256}" == "${repository_python_acceptance_root_sha256}" ]] || fail "Trusted Python acceptance root differs."
/usr/bin/python3 -I -S -B "${candidate}/scripts/validate-repository.py" --archive-root "${candidate}"
/usr/bin/python3 -I -S -B "${candidate}/scripts/test-contracts.py"
python3 "${candidate}/scripts/verify-pinned-source.py" --online
if [[ -n "$(find "${candidate}" \( \( -type d -name __pycache__ \) -o \( -type f \( -name '*.pyc' -o -name '*.pyo' \) \) \) -print -quit)" ]]; then
  fail "Generated Python cache entered the immutable release."
fi

release_archive_inspection="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "${candidate}/scripts/historical-release-disaster-recovery.py" inspect \
  --archive "${trusted_archive}" --expected-commit "${commit}")" || fail "Authorized release archive identity inspection failed."
readarray -t release_archive_identity < <(python3 -B - "${release_archive_inspection}" \
  "${commit}" "${trusted_repository_tree}" "${expected_archive_sha}" "${expected_archive_size}" <<'PY'
import json
import re
import sys

document = json.loads(sys.argv[1])
expected_keys = {
    "schemaVersion", "repositoryCommit", "repositoryTree", "releaseArchiveSha256",
    "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
    "releaseArchiveSourceFormat", "containsSecrets", "containsSignedUrls",
    "ordinaryDeploymentRequiresCurrentMain", "historicalReleaseAdoptionScope",
}
if set(document) != expected_keys or document.get("schemaVersion") != 1:
    raise SystemExit("release archive inspection schema differs")
archive_bytes = document.get("releaseArchiveBytes")
manifest_sha = document.get("releaseArchiveContentManifestSha256")
if (
    document.get("repositoryCommit") != sys.argv[2]
    or document.get("repositoryTree") != sys.argv[3]
    or document.get("releaseArchiveSha256") != sys.argv[4]
    or not isinstance(archive_bytes, int)
    or isinstance(archive_bytes, bool)
    or archive_bytes != int(sys.argv[5])
    or not isinstance(manifest_sha, str)
    or re.fullmatch(r"[0-9a-f]{64}", manifest_sha) is None
    or document.get("releaseArchiveSourceFormat") != "git-archive-tar-v1"
    or document.get("containsSecrets") is not False
    or document.get("containsSignedUrls") is not False
    or document.get("ordinaryDeploymentRequiresCurrentMain") is not True
    or document.get("historicalReleaseAdoptionScope") != "clean-target-disaster-recovery-only"
):
    raise SystemExit("release archive identity differs from its selected deployment authority")
print(document["repositoryTree"])
print(archive_bytes)
print(manifest_sha)
PY
)
[[ ${#release_archive_identity[@]} -eq 3 ]] || fail "Authorized release archive identity is malformed."
repository_tree="${release_archive_identity[0]}"
release_archive_bytes="${release_archive_identity[1]}"
release_archive_manifest_sha="${release_archive_identity[2]}"
[[ ${repository_tree} == "${trusted_repository_tree}" && ${release_archive_bytes} == "${expected_archive_size}" && ${release_archive_manifest_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Authorized release archive identity binding differs."

release_dir="${releases_root}/${commit}"
if [[ -e ${release_dir} ]]; then
  [[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "Existing release path is not an immutable directory."
  diff -qr --no-dereference "${candidate}" "${release_dir}" >/dev/null || fail "Existing same-commit release differs from the exact archive."
  rm -rf -- "${candidate}"
  candidate=""
else
  mv -- "${candidate}" "${release_dir}"
  fsync_directory "${releases_root}"
  candidate=""
fi

asset_candidate="$(mktemp -d "${assets_root}/.candidate-${commit}.XXXXXXXX")"
python3 "${release_dir}/scripts/build-theme-archive.py" --output "${asset_candidate}/mochirii-theme.zip"
install -m 0644 -o root -g root "${release_dir}/plugins/mochirii_email_metadata/plugin.rb" "${asset_candidate}/mochirii-email-metadata-plugin.rb"
install -m 0644 -o root -g root "${release_dir}/config/acme-sh-3.1.4.gz.b64" "${asset_candidate}/acme-sh-3.1.4.gz.b64"
install -m 0644 -o root -g root "${trusted_archive}" "${asset_candidate}/mochirii-release.tar"
for script in backup-transaction.py backup-url-boundary.rb configure-site.rb expire-discourse-connect-nonce.rb fetch-disaster-recovery-evidence.rb fetch-disaster-recovery-release.rb normal-upload-inventory.rb prepare-admin-recovery-fixture.rb prepare-backup-marker.rb publish-disaster-recovery-evidence.rb render-branding-email.rb storage-response-boundary.rb verify-backup.rb verify-break-glass-admin.rb verify-clean-disaster-target.rb verify-contained-discourse-connect.rb verify-discourse-connect-fixture.rb verify-restored-backup.rb verify-sensitive-log-redaction.rb verify-site.rb verify-storage-fixture.rb verify-zero-secure-uploads.rb; do
  install -m 0644 -o root -g root "${release_dir}/scripts/${script}" "${asset_candidate}/${script}"
done
chown -R root:root "${asset_candidate}"
find "${asset_candidate}" -type d -exec chmod 0755 {} +
find "${asset_candidate}" -type f -exec chmod 0644 {} +
asset_dir="${assets_root}/${commit}"
if [[ -e ${asset_dir} ]]; then
  [[ -d ${asset_dir} && ! -L ${asset_dir} ]] || fail "Existing release assets are invalid."
  diff -qr --no-dereference "${asset_candidate}" "${asset_dir}" >/dev/null || fail "Existing same-commit assets differ."
  [[ "$(stat -c '%U:%G %a' "${asset_dir}")" == "root:root 755" ]] || fail "Existing same-commit asset directory permissions differ."
  rm -rf -- "${asset_candidate}"
  asset_candidate=""
else
  mv -- "${asset_candidate}" "${asset_dir}"
  fsync_directory "${assets_root}"
  asset_candidate=""
fi
for runtime_asset in acme-sh-3.1.4.gz.b64 mochirii-release.tar mochirii-theme.zip mochirii-email-metadata-plugin.rb backup-transaction.py backup-url-boundary.rb configure-site.rb expire-discourse-connect-nonce.rb fetch-disaster-recovery-evidence.rb fetch-disaster-recovery-release.rb normal-upload-inventory.rb prepare-admin-recovery-fixture.rb prepare-backup-marker.rb publish-disaster-recovery-evidence.rb render-branding-email.rb storage-response-boundary.rb verify-backup.rb verify-break-glass-admin.rb verify-clean-disaster-target.rb verify-contained-discourse-connect.rb verify-discourse-connect-fixture.rb verify-restored-backup.rb verify-sensitive-log-redaction.rb verify-site.rb verify-storage-fixture.rb verify-zero-secure-uploads.rb; do
  [[ "$(stat -c '%U:%G %a' "${asset_dir}/${runtime_asset}")" == "root:root 644" ]] || fail "Runtime asset permissions differ from the reviewed boundary."
done
cmp -s -- "${trusted_archive}" "${asset_dir}/mochirii-release.tar" || fail "Versioned release archive differs from exact canonical main bytes."
bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" >/dev/null 2>&1 || fail "Runtime assets differ from the sealed release before configuration rendering."

config_candidate="$(mktemp -d "${configs_root}/.candidate-${commit}.XXXXXXXX")"
python3 "${release_dir}/scripts/render-app-config.py" \
  --mode production \
  --runtime-json "${runtime_json}" \
  --repository-commit "${commit}" \
  --output "${config_candidate}/app.yml"
python3 "${release_dir}/scripts/render-app-config.py" \
  --mode disposable-restore \
  --runtime-json "${runtime_json}" \
  --repository-commit "${commit}" \
  --output "${config_candidate}/restore.yml"
if [[ ${requested_discourse_connect} == true ]]; then
  python3 "${release_dir}/scripts/render-app-config.py" \
    --mode contained-activation \
    --runtime-json "${runtime_json}" \
    --repository-commit "${commit}" \
    --output "${config_candidate}/activation.yml"
fi
rendered_configs=("${config_candidate}/app.yml" "${config_candidate}/restore.yml")
[[ ${requested_discourse_connect} == false ]] || rendered_configs+=("${config_candidate}/activation.yml")
base_pull_seconds="$(remaining_mutation_seconds 900)" || fail "Pinned base-image pull budget is exhausted."
timeout --signal=TERM --kill-after=30s "${base_pull_seconds}" docker pull "${base_image}" >/dev/null 2>&1 || fail "Pinned deployment parser image pull failed."
timeout --signal=TERM --kill-after=5s 15 docker image inspect "${base_image}" >/dev/null 2>&1 || fail "Pinned deployment parser image is absent after pull."
for rendered in "${rendered_configs[@]}"; do
  run_config_parser "${rendered}" || fail "Rendered runtime configuration validation failed or parser containment was unproved."
done
production_config_sha="$(sha256sum -- "${config_candidate}/app.yml" | awk '{print $1}')"
restore_config_sha="$(sha256sum -- "${config_candidate}/restore.yml" | awk '{print $1}')"
if [[ ${historical_bootstrap} == true ]]; then
  [[ -f ${historical_production_config} && ! -L ${historical_production_config} && -f ${historical_restore_config} && ! -L ${historical_restore_config} ]] || fail "Authorized historical configuration is absent or linked."
  cmp -s -- "${config_candidate}/app.yml" "${historical_production_config}" || fail "Rendered production configuration differs from the journal-authorized C0 bytes."
  cmp -s -- "${config_candidate}/restore.yml" "${historical_restore_config}" || fail "Rendered restore configuration differs from the journal-authorized C0 bytes."
fi
activation_config_sha=""
if [[ ${requested_discourse_connect} == true ]]; then
  activation_config_sha="$(sha256sum -- "${config_candidate}/activation.yml" | awk '{print $1}')"
  [[ ${activation_config_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Rendered contained-activation configuration digest is malformed."
fi
theme_sha="$(sha256sum -- "${asset_dir}/mochirii-theme.zip" | awk '{print $1}')"
mail_metadata_plugin_sha="$(sha256sum -- "${asset_dir}/mochirii-email-metadata-plugin.rb" | awk '{print $1}')"
configuration_id="${production_config_sha}"
[[ ${configuration_id} =~ ^[0-9a-f]{64}$ ]] || fail "Rendered production configuration digest is malformed."
current_authentication=/var/lib/mochirii/forums/current-authentication.json
authentication_retry_state=none
if [[ -e ${current_authentication} || -L ${current_authentication} ]]; then
  [[ -f ${current_authentication} && ! -L ${current_authentication} ]] || fail "Current authentication evidence is not one regular file."
  [[ "$(stat -c '%U:%G %a' "${current_authentication}")" == "root:root 600" ]] || fail "Current authentication evidence has unsafe permissions."
  authentication_retry_state="$(python3 -B "${release_dir}/scripts/authentication-state.py" \
    --pointer "${current_authentication}" \
    --expected-commit "${commit}" \
    --expected-configuration "${configuration_id}")" || fail "Current authentication evidence could not be evaluated."
fi
if [[ ${authentication_retry_state} == contained-producer-state-unproved || ${authentication_retry_state} == activation-deploy-failed-producer-unproved ]]; then
  fail "Authentication retry is blocked until the Website producer-disabled state is proved while the application remains stopped."
fi
if [[ ${authentication_retry_state} == stale-other-tuple ]]; then
  [[ ${mode} == rebuild && ${requested_discourse_connect} == false ]] || fail "A completed authentication tuple may advance only through an exact consumer-disabled rebuild."
  stale_phase="$(python3 -B - "${current_authentication}" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(document.get("activationPhase", ""))
PY
)" || fail "Stale authentication phase could not be read."
  [[ ${stale_phase} == complete ]] || fail "Only a completed prior authentication tuple may enter the protected upgrade transition."
  timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || fail "A later release requires the Website producer to be exactly disabled before the consumer-disabled rebuild."
  stale_authentication_transition=true
fi
authentication_advance_record="${evidence_root}/${commit}-${configuration_id}-authentication-advance.json"
if [[ ${authentication_retry_state} == none && ( -e ${authentication_advance_record} || -L ${authentication_advance_record} ) ]]; then
  [[ ${mode} == rebuild && ${requested_discourse_connect} == false ]] || fail "Authentication advance adoption requires the exact consumer-disabled rebuild tuple."
  archive_stale_authentication_pointer >/dev/null || fail "Committed authentication advance evidence could not be adopted."
  timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || fail "Authentication advance adoption requires the Website producer to remain disabled."
  stale_authentication_transition=true
fi
if [[ ${authentication_retry_state} == activation-deploy-failed ]]; then
  [[ ${mode} == rebuild && ${requested_discourse_connect} == true ]] || fail "Stopped activation recovery requires the exact consumer-enabled rebuild tuple."
  activation_failure_retry=true
fi
if [[ ${authentication_retry_state} == complete ]]; then
  [[ ${mode} == rebuild && ${requested_discourse_connect} == true ]] || fail "Completed authentication can be rebuilt only for its exact consumer-enabled tuple."
  complete_authentication_rebuild=true
  contained_activation_required=false
  contained_activation_passed=true
fi
install -d -m 0700 -o root -g root "${configs_root}/${commit}"
config_dir="${configs_root}/${commit}/${configuration_id}"
if [[ -e ${config_dir} ]]; then
  [[ -d ${config_dir} && ! -L ${config_dir} ]] || fail "Existing release configuration is invalid."
  cmp -s -- "${config_candidate}/app.yml" "${config_dir}/app.yml" || fail "Existing same-commit production configuration differs."
  cmp -s -- "${config_candidate}/restore.yml" "${config_dir}/restore.yml" || fail "Existing same-commit restore configuration differs."
  if [[ ${requested_discourse_connect} == true ]]; then
    cmp -s -- "${config_candidate}/activation.yml" "${config_dir}/activation.yml" || fail "Existing same-commit contained-activation configuration differs."
  else
    [[ ! -e ${config_dir}/activation.yml && ! -L ${config_dir}/activation.yml ]] || fail "Disabled same-commit configuration unexpectedly retains an activation artifact."
  fi
  rm -rf -- "${config_candidate}"
  config_candidate=""
else
  chmod 0700 "${config_candidate}"
  mv -- "${config_candidate}" "${config_dir}"
  fsync_directory "${configs_root}/${commit}"
  config_candidate=""
fi

deployment_mutation_contract=()
if [[ -e ${deployment_mutation_journal} || -L ${deployment_mutation_journal} ]]; then
  readarray -t deployment_mutation_contract < <(inspect_deployment_mutation) || fail "Deployment mutation journal could not be evaluated."
  [[ ${#deployment_mutation_contract[@]} -eq 14 ]] || fail "Deployment mutation journal is incomplete."
  deployment_mutation_armed=true
  deployment_mutation_resume=true
  deployment_mutation_phase="${deployment_mutation_contract[0]}"
  deployment_mutation_active_config="${deployment_mutation_contract[7]}"
  deployment_mutation_database_possible="${deployment_mutation_contract[12]}"
  [[ ${deployment_mutation_database_possible} == true || ${deployment_mutation_database_possible} == false ]] || fail "Deployment mutation database boundary is malformed."
  [[ ${deployment_mutation_database_possible} == false ]] || target_database_mutation_possible=true
fi

readarray -t deployment_resume < <(deployment_state_contract) || fail "Deployment transaction or terminal evidence could not be evaluated."
[[ ${#deployment_resume[@]} -ge 1 ]] || fail "Deployment transaction evaluation returned no state."
if [[ ${deployment_resume[0]} != none ]]; then
  [[ ${#deployment_resume[@]} -eq 8 ]] || fail "Deployment transaction or terminal evidence is incomplete."
  resume_phase="${deployment_resume[0]}"
  resume_action="${deployment_resume[1]}"
  resume_allowed=false
  resume_marker_matches=false
  if [[ ${deployment_resume[5]} == - && ${deployment_resume[6]} == - ]]; then
    [[ ! -e ${marker} && ! -L ${marker} ]] && resume_marker_matches=true
  elif [[ ${deployment_resume[5]} == member-rollout-enabled && ${deployment_resume[6]} =~ ^[0-9a-f]{64}$ && -f ${marker} && ! -L ${marker} ]]; then
    [[ "$(sha256sum -- "${marker}" | awk '{print $1}')" == "${deployment_resume[6]}" ]] && resume_marker_matches=true
  fi
  case "${resume_action}" in
    pending)
      [[ ${authentication_retry_state} == consumer-public-producer-pending ]] && resume_allowed=true
      [[ ${resume_phase} != complete && ${authentication_retry_state} == none ]] && resume_allowed=true
      ;;
    preserve-complete)
      [[ ${authentication_retry_state} == complete ]] && resume_allowed=true
      ;;
    advance-complete)
      [[ ${authentication_retry_state} == stale-other-tuple || ${authentication_retry_state} == none ]] && resume_allowed=true
      ;;
    absent)
      [[ ${authentication_retry_state} == none ]] && resume_allowed=true
      ;;
  esac
  [[ ${resume_marker_matches} == true ]] || resume_allowed=false
  if [[ ${resume_allowed} == true ]]; then
    if [[ ${deployment_mutation_resume} == true ]]; then
      [[ ${deployment_mutation_phase} == verified ]] || fail "Deployment terminal publication exists without a verified runtime-mutation journal."
    fi
    deployment_commit_armed=true
    complete_deployment_commit "${deployment_resume[@]}" || fail "Deployment terminal transaction could not be reconciled safely."
    if [[ ${deployment_mutation_resume} == true ]]; then
      clear_deployment_mutation || {
        deployment_success=false
        fail "Completed deployment mutation journal could not be durably retired."
      }
    fi
    printf '%s\n' "Mochirii Forums release transaction reconciled and verified."
    exit 0
  fi
  [[ ${resume_phase} == complete ]] || fail "Active deployment transaction authentication state differs from its exact retry contract."
fi

if [[ ${historical_bootstrap_already_complete} == true ]]; then
  fail "A bootstrap-complete historical journal may only reconcile its same terminal deployment transaction; runtime mutation is forbidden."
fi

if [[ ${deployment_mutation_resume} == true ]]; then
  if [[ ${mode} == bootstrap ]]; then
    [[ ! -e /var/lib/mochirii/forums/current-release.json && ! -L /var/lib/mochirii/forums/current-release.json ]] || fail "Bootstrap mutation retry refuses existing current-release evidence."
    [[ ! -e /opt/mochirii/forums/current && ! -L /opt/mochirii/forums/current ]] || fail "Bootstrap mutation retry refuses an existing current-release target."
  else
    [[ ${deployment_mutation_contract[3]} =~ ^[0-9a-f]{64}$ ]] || fail "Deployment mutation prior current-release digest is malformed."
    [[ -f /var/lib/mochirii/forums/current-release.json && ! -L /var/lib/mochirii/forums/current-release.json ]] || fail "Deployment mutation prior current-release evidence is absent or unsafe."
    [[ "$(stat -c '%U:%G %a' /var/lib/mochirii/forums/current-release.json)" == "root:root 600" ]] || fail "Deployment mutation prior current-release evidence has unsafe ownership or mode."
    mutation_previous_current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk '{print $1}')" || fail "Deployment mutation prior current-release evidence could not be hashed."
    [[ ${mutation_previous_current_sha} == "${deployment_mutation_contract[3]}" ]] || fail "Deployment mutation prior current-release bytes differ from their sealed digest."
    [[ -L /opt/mochirii/forums/current && "$(readlink -f -- /opt/mochirii/forums/current)" == "${deployment_mutation_contract[6]}" ]] || fail "Deployment mutation prior current-release target differs before retry reconciliation."
  fi
  actual_mutation_config="-"
  if [[ -e ${app_config} || -L ${app_config} ]]; then
    [[ -L ${app_config} ]] || fail "Deployment mutation active configuration is not a versioned symlink."
    actual_mutation_config="$(readlink -f -- "${app_config}")"
  fi
  mutation_prior_config="${deployment_mutation_contract[4]}"
  if [[ ${mode} == bootstrap ]]; then
    [[ ${actual_mutation_config} == - || ${actual_mutation_config} == "${deployment_mutation_active_config}" ]] || fail "Bootstrap mutation configuration differs from its durable authority."
  else
    [[ ${actual_mutation_config} == "${mutation_prior_config}" || ${actual_mutation_config} == "${deployment_mutation_active_config}" ]] || fail "Rebuild mutation configuration differs from its durable authority."
  fi
  if [[ ${deployment_mutation_contract[9]} != - ]]; then
    launcher_operation_token="${deployment_mutation_contract[9]}"
    launcher_previous_image_id="${deployment_mutation_contract[10]}"
    [[ ${launcher_previous_image_id} != - ]] || launcher_previous_image_id=""
    launcher_operation_command="${deployment_mutation_contract[11]}"
    reconcile_launcher_failure || fail "Interrupted launcher mutation could not be reconciled safely."
  else
    emergency_stop || fail "Deployment mutation retry could not prove the application stopped."
    mark_deployment_mutation_contained || fail "Deployment mutation retry containment could not be durably recorded."
  fi
  if [[ ${mode} == bootstrap ]] && timeout --signal=TERM --kill-after=5s 15 docker inspect --type container app >/dev/null 2>&1; then
    target_environment="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{range .Config.Env}}{{println .}}{{end}}' app 2>/dev/null)" || fail "Bootstrap mutation container identity could not be read."
    grep -Fqx -- "MOCHIRII_REPOSITORY_COMMIT=${commit}" <<<"${target_environment}" || fail "Bootstrap mutation refuses an unbound app container."
    timeout --signal=TERM --kill-after=5s 45 docker rm --force app >/dev/null 2>&1 || fail "Bootstrap mutation target container could not be removed for exact retry."
    [[ -z "$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" ]] || fail "Bootstrap mutation target container survived cleanup."
  fi
fi

forward_fix_evidence_sha=""
if [[ -e ${deployment_recovery_journal} || -L ${deployment_recovery_journal} ]]; then
  [[ ${mode} == rebuild ]] || fail "A forward-fix recovery journal refuses bootstrap mode."
  forward_fix_evidence_sha="$(validate_forward_fix_retry)" || fail "Forward-fix recovery journal validation failed."
  [[ ${forward_fix_evidence_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Forward-fix recovery journal digest is malformed."
  [[ -L ${app_config} && "$(readlink -f -- "${app_config}")" == "${config_dir}/app.yml" ]] || fail "Forward-fix recovery requires the exact failed target configuration to remain selected."
  [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || fail "Forward-fix recovery requires the application to remain stopped."
  forward_fix_retry=true
fi

reconcile_storage_cleanup_journal_partial || fail "Hosted storage cleanup journal partial could not be safely reconciled."
pending_cleanup_candidates=("${evidence_root}/${commit}-${configuration_id}-"*-storage-cleanup-required.json)
pending_cleanup_present=false
for pending_cleanup in "${pending_cleanup_candidates[@]}"; do
  [[ -e ${pending_cleanup} ]] || continue
  pending_cleanup_present=true
done
if [[ ${pending_cleanup_present} == true ]]; then
  [[ ${deployment_mutation_resume} == true ]] || fail "Pending hosted storage cleanup lacks its exact deployment mutation authority."
  if [[ ${deployment_mutation_resume} == true && "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null || true)" != true ]]; then
    activate_config "${config_dir}/restore.yml" || fail "Pending hosted storage cleanup containment could not select the exact restore configuration."
    run_launcher storage-cleanup-resume rebuild app || fail "Pending hosted storage cleanup containment could not be rebuilt."
  fi
  [[ -L ${app_config} && "$(readlink -f -- "${app_config}")" == "${config_dir}/restore.yml" ]] || fail "Pending hosted storage cleanup requires the exact loopback containment configuration."
  timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc \
    'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1" && test "$MOCHIRII_RELEASE_ASSET_ROOT" = "/opt/mochirii-release" && test "$DISCOURSE_DISABLE_EMAILS" = non-staff && test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = false' \
    bash "${commit}" >/dev/null 2>&1 || fail "Pending hosted storage cleanup container identity differs from exact containment."
  containment_ports="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{json .HostConfig.PortBindings}}' app 2>/dev/null || true)"
  [[ ${containment_ports} == '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]}' ]] || fail "Pending hosted storage cleanup is not isolated to loopback."
  for pending_cleanup in "${pending_cleanup_candidates[@]}"; do
    [[ -e ${pending_cleanup} ]] || continue
    pending_name="$(basename -- "${pending_cleanup}")"
    [[ ${pending_name} =~ ^${commit}-${configuration_id}-([0-9a-f]{64})-storage-cleanup-required[.]json$ ]] || fail "Pending hosted storage cleanup filename is malformed."
    pending_sha="${BASH_REMATCH[1]}"
    [[ -f ${pending_cleanup} && ! -L ${pending_cleanup} ]] || fail "Pending hosted storage cleanup state is unsafe."
    [[ "$(stat -c '%U:%G %a' "${pending_cleanup}")" == "root:root 600" ]] || fail "Pending hosted storage cleanup state has unsafe permissions."
    [[ "$(sha256sum -- "${pending_cleanup}" | awk '{print $1}')" == "${pending_sha}" ]] || fail "Pending hosted storage cleanup digest differs from its exact retry name."
    pending_result="$(mktemp "${evidence_root}/.storage-pending-cleanup.XXXXXXXX.json")"
    rm -f -- "${pending_result}"
    if ! run_storage_fixture cleanup "${pending_result}" "${pending_cleanup}"; then
      record_event storage-cleanup blocked "${configuration_id}" "${pending_sha}" || true
      rm -f -- "${pending_result}"
      fail "Prior hosted storage cleanup remains blocked; exact retry state was preserved."
    fi
    if ! validate_storage_terminal_result cleanup "${pending_result}"; then
      record_event storage-cleanup blocked "${configuration_id}" "${pending_sha}" || true
      rm -f -- "${pending_result}"
      fail "Prior hosted storage cleanup returned no exact terminal absence proof."
    fi
    record_event storage-cleanup passed "${configuration_id}" "${pending_sha}" || fail "Protected storage-cleanup event evidence could not be completed."
    clear_storage_cleanup_journal "${pending_cleanup}" || fail "Reconciled hosted storage cleanup journal could not be durably cleared."
    rm -f -- "${pending_result}"
  done
  if [[ -f /var/lib/mochirii/forums/current-release.json && ! -L /var/lib/mochirii/forums/current-release.json ]]; then
    readarray -t cleanup_previous < <(python3 - /var/lib/mochirii/forums/current-release.json <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
if set(document) != {"repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile", "memberRolloutMarkerSha256"}:
    raise SystemExit("current evidence keys differ")
commit = document.get("repositoryCommit", "")
configuration = document.get("productionConfigurationSha256", "")
expected = f"{commit}-{configuration}-release.json"
record = path.parent / "evidence" / expected
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", configuration):
    raise SystemExit("current evidence identity is malformed")
if document.get("releaseEvidenceFile") != expected or not record.is_file() or record.is_symlink():
    raise SystemExit("current release evidence reference differs")
if record.stat().st_uid != 0 or record.stat().st_mode & 0o077 or document.get("releaseEvidenceSha256") != hashlib.sha256(record.read_bytes()).hexdigest():
    raise SystemExit("current release evidence digest differs")
connect = document.get("discourseConnectEnabled")
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if not isinstance(connect, bool) or (marker_file is None) != (marker_sha is None):
    raise SystemExit("current activation evidence is malformed")
if marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)):
    raise SystemExit("current member-rollout evidence is malformed")
print(commit)
print(configuration)
print("true" if connect else "false")
print(marker_file or "-")
print(marker_sha or "-")
PY
)
    [[ ${#cleanup_previous[@]} -eq 5 ]] || fail "Prior release evidence is malformed after storage cleanup."
    previous_release="${cleanup_previous[0]}"
    previous_configuration="${cleanup_previous[1]}"
    previous_discourse_connect="${cleanup_previous[2]}"
    previous_marker_file="${cleanup_previous[3]}"
    previous_marker_sha="${cleanup_previous[4]}"
    [[ ${previous_marker_file} != - ]] || previous_marker_file=""
    [[ ${previous_marker_sha} != - ]] || previous_marker_sha=""
    previous_config="${configs_root}/${previous_release}/${previous_configuration}/app.yml"
    [[ -f ${previous_config} && ! -L ${previous_config} ]] || fail "Prior production configuration is absent after storage cleanup."
    [[ -L /opt/mochirii/forums/current ]] || fail "Prior current-release target is absent after storage cleanup."
    previous_current_target="$(readlink -f -- /opt/mochirii/forums/current)"
    [[ ${previous_current_target} == "${releases_root}/${previous_release}" ]] || fail "Prior current-release target differs after storage cleanup."
    if ! restore_previous_release; then
      activate_config "${config_dir}/restore.yml" || fail "Hosted storage cleanup recovery could not select the exact containment configuration."
      containment_ports=""
      if run_launcher storage-recovery-containment rebuild app &&
        timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'test "$DISCOURSE_DISABLE_EMAILS" = non-staff && test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = false' >/dev/null 2>&1; then
        containment_ports="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{json .HostConfig.PortBindings}}' app 2>/dev/null || true)"
      fi
      if [[ ${containment_ports} != '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]}' ]]; then
        emergency_stop || fail "Hosted storage cleanup recovery could not prove containment or an application stop."
      fi
      fail "Hosted storage cleanup passed but prior public release recovery failed; containment remains required."
    fi
  else
    emergency_stop || fail "Hosted storage cleanup reconciliation could not prove an application stop."
  fi
  fail "Hosted storage cleanup was reconciled safely; rerun the exact deployment from a clean known-good runtime state."
fi
[[ -z "$(find "${evidence_root}" -maxdepth 1 -name '*-storage-cleanup-required.json' -print -quit)" ]] || fail "Hosted storage cleanup belongs to a different exact release; deploy that reviewed release only for reconciliation."

if [[ ${mode} == bootstrap ]]; then
  [[ ! -e /var/lib/mochirii/forums/current-release.json && ! -L /var/lib/mochirii/forums/current-release.json ]] || fail "Bootstrap mode refuses existing current-release evidence."
  [[ ! -e /opt/mochirii/forums/current && ! -L /opt/mochirii/forums/current ]] || fail "Bootstrap mode refuses an existing current-release target."
  timeout --signal=TERM --kill-after=5s 15 docker inspect app >/dev/null 2>&1 && fail "Bootstrap mode refuses an existing app container."
  if [[ ${deployment_mutation_resume} == false ]]; then
    [[ ! -d /var/discourse/shared/standalone/postgres_data ]] || fail "Bootstrap mode refuses existing PostgreSQL data."
    [[ ! -e ${app_config} ]] || fail "Bootstrap mode refuses an existing active app configuration."
  else
    [[ ! -e ${app_config} && ! -L ${app_config} ]] || {
      [[ -L ${app_config} ]] || fail "Bootstrap mutation retry configuration is unsafe."
      bootstrap_retry_config="$(readlink -f -- "${app_config}")"
      [[ ${bootstrap_retry_config} == "${config_dir}/app.yml" || ${bootstrap_retry_config} == "${config_dir}/restore.yml" ]] || fail "Bootstrap mutation retry configuration differs."
    }
  fi
else
  if [[ ${deployment_mutation_resume} == false ]]; then
    timeout --signal=TERM --kill-after=5s 15 docker inspect app >/dev/null 2>&1 || fail "Rebuild mode requires an existing app container."
  fi
  current_evidence="/var/lib/mochirii/forums/current-release.json"
  [[ -f ${current_evidence} && ! -L ${current_evidence} ]] || fail "Current release evidence is absent."
  [[ "$(stat -c '%U:%G %a' "${current_evidence}")" == "root:root 600" ]] || fail "Current release evidence has unsafe ownership or mode."
  readarray -t current_contract < <(python3 - "${current_evidence}" "${docker_revision}" "${core_revision}" "${manager_revision}" "${base_image}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
commit = document.get("repositoryCommit", "")
configuration = document.get("productionConfigurationSha256", "")
if set(document) != {"repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile", "memberRolloutMarkerSha256"}:
    raise SystemExit("current evidence keys differ")
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", configuration):
    raise SystemExit("current evidence values are malformed")
expected_name = f"{commit}-{configuration}-release.json"
record = path.parent / "evidence" / expected_name
if document.get("releaseEvidenceFile") != expected_name or not record.is_file() or record.is_symlink():
    raise SystemExit("current release evidence reference differs")
if record.stat().st_uid != 0 or record.stat().st_mode & 0o077:
    raise SystemExit("current release evidence permissions are unsafe")
if document.get("releaseEvidenceSha256") != hashlib.sha256(record.read_bytes()).hexdigest():
    raise SystemExit("current release evidence digest differs")
connect = document.get("discourseConnectEnabled")
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if not isinstance(connect, bool) or (marker_file is None) != (marker_sha is None):
    raise SystemExit("current activation evidence is malformed")
if marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)):
    raise SystemExit("current member-rollout evidence is malformed")
release = json.loads(record.read_text(encoding="utf-8"))
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
if set(release) != release_keys or release.get("schemaVersion") != 2:
    raise SystemExit("current immutable release schema differs")
archive = pathlib.Path("/opt/mochirii/forums/runtime-assets") / commit / "mochirii-release.tar"
archive_metadata = archive.lstat()
if (
    not re.fullmatch(r"[0-9a-f]{40}", str(release.get("repositoryTree", "")))
    or not isinstance(release.get("releaseArchiveBytes"), int)
    or isinstance(release.get("releaseArchiveBytes"), bool)
    or not 1 <= release["releaseArchiveBytes"] <= 67108864
    or not re.fullmatch(r"[0-9a-f]{64}", str(release.get("releaseArchiveContentManifestSha256", "")))
    or not stat.S_ISREG(archive_metadata.st_mode)
    or stat.S_ISLNK(archive_metadata.st_mode)
    or archive_metadata.st_uid != 0
    or archive_metadata.st_gid != 0
    or stat.S_IMODE(archive_metadata.st_mode) != 0o644
    or archive_metadata.st_size != release["releaseArchiveBytes"]
    or hashlib.sha256(archive.read_bytes()).hexdigest() != release.get("releaseArchiveSha256")
):
    raise SystemExit("current immutable release archive authority differs")
marker_transition_allowed = (
    marker_file == "member-rollout-enabled"
    and release.get("memberRolloutMarkerFile") is None
    and release.get("memberRolloutMarkerSha256") is None
)
if (
    release.get("repositoryCommit") != commit
    or release.get("productionConfigurationSha256") != configuration
    or release.get("discourseConnectEnabled") is not connect
    or (not marker_transition_allowed and release.get("memberRolloutMarkerFile") != marker_file)
    or (not marker_transition_allowed and release.get("memberRolloutMarkerSha256") != marker_sha)
):
    raise SystemExit("current immutable release tuple differs")
for gate in (
    "hostVerificationPassed", "hostedStoragePassed", "storageRestartPersistencePassed",
    "storageRebuildPersistencePassed", "storageCleanupPassed",
):
    if release.get(gate) is not True:
        raise SystemExit("current immutable release contains an unpassed gate")
if connect:
    if (
        release.get("activationPhase") != "consumer-public-producer-pending"
        or release.get("containedActivationPassed") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(release.get("containedActivationConfigurationSha256", "")))
    ):
        raise SystemExit("current immutable consumer activation evidence differs")
elif release.get("activationPhase") != "consumer-disabled" or release.get("containedActivationPassed") is not False or release.get("containedActivationConfigurationSha256") is not None:
    raise SystemExit("current immutable disabled-consumer evidence differs")
print(commit)
print(configuration)
print("true" if connect else "false")
print(marker_file or "-")
print(marker_sha or "-")
compatible = (
    release.get("discourseDockerRevision") == sys.argv[2]
    and release.get("discourseRevision") == sys.argv[3]
    and release.get("dockerManagerRevision") == sys.argv[4]
    and release.get("baseImageDigest") == sys.argv[5]
    and release.get("schemaVersion") == 2
)
print("true" if compatible else "false")
PY
)
  [[ ${#current_contract[@]} -eq 6 ]] || fail "Current release evidence is malformed."
  previous_release="${current_contract[0]}"
  previous_configuration="${current_contract[1]}"
  previous_discourse_connect="${current_contract[2]}"
  previous_marker_file="${current_contract[3]}"
  previous_marker_sha="${current_contract[4]}"
  automatic_rollback_compatible="${current_contract[5]}"
  [[ ${previous_marker_file} != - ]] || previous_marker_file=""
  [[ ${previous_marker_sha} != - ]] || previous_marker_sha=""
  [[ ${previous_release} =~ ^[0-9a-f]{40}$ ]] || fail "Current release evidence is malformed."
  [[ ${previous_configuration} =~ ^[0-9a-f]{64}$ ]] || fail "Current configuration evidence is malformed."
  [[ ${automatic_rollback_compatible} == true || ${automatic_rollback_compatible} == false ]] || fail "Automatic rollback compatibility evidence is malformed."
  [[ -L ${app_config} ]] || fail "Active runtime configuration is not a versioned symlink."
  if [[ ${forward_fix_retry} == true ]]; then
    [[ "$(readlink -f -- "${app_config}")" == "${config_dir}/app.yml" ]] || fail "Forward-fix active configuration differs from the exact failed target."
    previous_config="${configs_root}/${previous_release}/${previous_configuration}/app.yml"
    [[ -f ${previous_config} && ! -L ${previous_config} ]] || fail "Forward-fix prior production configuration is absent."
  elif [[ ${deployment_mutation_resume} == true ]]; then
    previous_config="${deployment_mutation_contract[4]}"
    [[ ${previous_config} == "${configs_root}/${previous_release}/${previous_configuration}/app.yml" ]] || fail "Deployment mutation prior configuration differs from current evidence."
    active_retry_config="$(readlink -f -- "${app_config}")"
    [[ ${active_retry_config} == "${previous_config}" || ${active_retry_config} == "${deployment_mutation_active_config}" ]] || fail "Deployment mutation active configuration changed after containment."
  else
    previous_config="$(readlink -f -- "${app_config}")"
    [[ ${previous_config} == "${configs_root}/${previous_release}/${previous_configuration}/app.yml" ]] || fail "Active runtime configuration does not match current release evidence."
  fi
  [[ "$(sha256sum -- "${previous_config}" | awk '{print $1}')" == "${previous_configuration}" ]] || fail "Prior runtime configuration digest changed."
  if [[ ${deployment_mutation_resume} == true ]]; then
    current_discourse_connect="${previous_discourse_connect}"
  elif [[ ${authentication_retry_state} == contained-after-e2e-failure ]]; then
    [[ ${previous_release} == "${commit}" && ${previous_configuration} == "${configuration_id}" ]] || fail "Stopped authentication retry differs from the exact reviewed release tuple."
    [[ ${previous_discourse_connect} == true && ${requested_discourse_connect} == true ]] || fail "Stopped authentication retry is not the exact consumer-enabled state."
    [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || fail "Stopped authentication retry cannot prove the application remains stopped."
    current_discourse_connect="${previous_discourse_connect}"
  elif [[ ${authentication_retry_state} == activation-deploy-failed ]]; then
    [[ ${requested_discourse_connect} == true && ${previous_discourse_connect} == false ]] || fail "Stopped activation-deploy retry does not begin from the exact consumer-disabled release."
    [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || fail "Stopped activation-deploy retry cannot prove the application remains stopped."
    current_discourse_connect="${previous_discourse_connect}"
  elif [[ ${forward_fix_retry} == true ]]; then
    [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || fail "Forward-fix retry cannot prove the application remains stopped."
    current_discourse_connect="${previous_discourse_connect}"
  elif [[ ${complete_authentication_rebuild} == true && "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]]; then
    current_discourse_connect="${previous_discourse_connect}"
  else
    current_discourse_connect="$(timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'case "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" in true|false) printf "%s" "$DISCOURSE_ENABLE_DISCOURSE_CONNECT";; *) exit 1;; esac' 2>/dev/null)" || fail "Running DiscourseConnect flag is malformed."
  fi
  [[ ${current_discourse_connect} == "${previous_discourse_connect}" ]] || fail "Current release evidence differs from the running DiscourseConnect flag."
  if [[ -e ${marker} ]]; then
    [[ -f ${marker} && ! -L ${marker} ]] || fail "Member-rollout marker is not one regular file."
    [[ "$(stat -c '%U:%G %a' "${marker}")" == "root:root 600" ]] || fail "Member-rollout marker has unsafe ownership or mode."
    marker_file_for_evidence="member-rollout-enabled"
    marker_sha_for_evidence="$(sha256sum -- "${marker}" | awk '{print $1}')"
    [[ ${previous_marker_file} == "${marker_file_for_evidence}" && ${previous_marker_sha} == "${marker_sha_for_evidence}" ]] || fail "Current evidence differs from the exact member-rollout marker."
    readarray -t marker_contract < <(python3 - "${marker}" "${evidence_root}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
marker = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
document = json.loads(marker.read_text(encoding="utf-8"))
common = {
    "repositoryCommit", "productionConfigurationSha256", "finalizedAt",
    "destructiveRestorePermanentlyDisabled",
}
standard = common | {"restoreEvidenceFile", "restoreEvidenceSha256"}
disaster = common | {
    "disasterRecoveryBackupEvidenceFile", "disasterRecoveryBackupEvidenceSha256",
    "sourceMemberRolloutMarkerSha256",
}
if set(document) not in (standard, disaster) or document.get("destructiveRestorePermanentlyDisabled") is not True:
    raise SystemExit("member-rollout marker keys differ")
commit = document.get("repositoryCommit", "")
configuration = document.get("productionConfigurationSha256", "")
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", configuration):
    raise SystemExit("member-rollout marker identity is malformed")
if set(document) == standard:
    evidence_file = document.get("restoreEvidenceFile", "")
    evidence_sha = document.get("restoreEvidenceSha256", "")
    expected_name = rf"{commit}-{configuration}-[0-9]{{8}}T[0-9]{{6}}Z-restore[.]json"
else:
    evidence_file = document.get("disasterRecoveryBackupEvidenceFile", "")
    evidence_sha = document.get("disasterRecoveryBackupEvidenceSha256", "")
    expected_name = rf"{commit}-{configuration}-[0-9]{{8}}T[0-9]{{6}}Z-backup[.]json"
    if not re.fullmatch(r"[0-9a-f]{64}", str(document.get("sourceMemberRolloutMarkerSha256", ""))):
        raise SystemExit("disaster member-rollout source marker is malformed")
if not re.fullmatch(expected_name, evidence_file):
    raise SystemExit("member-rollout evidence name is malformed")
evidence = root / evidence_file
if (
    not evidence.is_file()
    or evidence.is_symlink()
    or evidence.stat().st_uid != 0
    or evidence.stat().st_mode & 0o077
    or not re.fullmatch(r"[0-9a-f]{64}", str(evidence_sha))
    or hashlib.sha256(evidence.read_bytes()).hexdigest() != evidence_sha
):
    raise SystemExit("member-rollout evidence digest differs")
print(commit)
print(configuration)
PY
)
    [[ ${#marker_contract[@]} -eq 2 ]] || fail "Member-rollout marker contract is malformed."
    if [[ ${previous_discourse_connect} == false && ${requested_discourse_connect} == true ]]; then
      prior_true="$(python3 - "${evidence_root}" "${marker_sha_for_evidence}" <<'PY'
import json
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1])
for path in root.glob("*-release.json"):
    if path.is_symlink() or not path.is_file():
        continue
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        continue
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        continue
    commit = document.get("repositoryCommit", "")
    configuration = document.get("productionConfigurationSha256", "")
    expected_name = f"{commit}-{configuration}-release.json"
    if (
        path.name == expected_name
        and re.fullmatch(r"[0-9a-f]{40}", commit)
        and re.fullmatch(r"[0-9a-f]{64}", configuration)
        and document.get("discourseConnectEnabled") is True
        and document.get("memberRolloutMarkerFile") == "member-rollout-enabled"
        and document.get("memberRolloutMarkerSha256") == sys.argv[2]
    ):
        print("true")
        break
else:
    print("false")
PY
)" || fail "Prior activation evidence could not be evaluated."
      if [[ ${prior_true} == false ]]; then
        [[ ${marker_contract[0]} == "${previous_release}" && ${marker_contract[1]} == "${previous_configuration}" ]] || fail "First DiscourseConnect activation is not bound to the exact restored pre-activation configuration."
      fi
    fi
  else
    [[ -z ${previous_marker_file} && -z ${previous_marker_sha} ]] || fail "Current evidence names a missing member-rollout marker."
    [[ ${previous_discourse_connect} == false && ${requested_discourse_connect} == false ]] || fail "DiscourseConnect cannot be enabled before the member-rollout marker."
  fi
  [[ ${requested_discourse_connect} == false || -n ${marker_sha_for_evidence} ]] || fail "DiscourseConnect activation requires exact member-rollout evidence."
  [[ -L /opt/mochirii/forums/current ]] || fail "Current release target is absent."
  previous_current_target="$(readlink -f -- /opt/mochirii/forums/current)"
  [[ ${previous_current_target} == "${releases_root}/${previous_release}" ]] || fail "Current release target differs from durable evidence."
  backup_pointer="/var/lib/mochirii/forums/latest-backup-evidence"
  [[ -f ${backup_pointer} && ! -L ${backup_pointer} ]] || fail "Protected latest-backup pointer is absent."
  [[ "$(stat -c '%U:%G %a' "${backup_pointer}")" == "root:root 600" ]] || fail "Protected latest-backup pointer has unsafe ownership or mode."
  IFS= read -r backup_evidence < "${backup_pointer}"
  [[ ${backup_evidence} =~ ^/var/lib/mochirii/forums/evidence/${previous_release}-${previous_configuration}-[0-9]{8}T[0-9]{6}Z-backup[.]json$ ]] || fail "Latest backup evidence is not bound to the exact current release and configuration."
  [[ -f ${backup_evidence} && ! -L ${backup_evidence} ]] || fail "Protected backup evidence is absent."
  python3 - "${backup_evidence}" "${previous_release}" "${previous_configuration}" <<'PY' >/dev/null
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("repositoryCommit") != sys.argv[2]:
    raise SystemExit("Backup evidence release mismatch")
if document.get("productionConfigurationSha256") != sys.argv[3]:
    raise SystemExit("Backup evidence configuration mismatch")
if document.get("privateAdminRetrievalUrlPresent") is not True or document.get("size", 0) <= 0:
    raise SystemExit("Backup evidence is incomplete")
PY
  if [[ ${deployment_mutation_resume} == false && ${authentication_retry_state} != contained-after-e2e-failure && ${authentication_retry_state} != activation-deploy-failed && ! ( ${complete_authentication_rebuild} == true && ${current_discourse_connect} == true && "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ) ]]; then
    if ! timeout --signal=TERM --kill-after=10s 120 docker exec app bash -lc '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-zero-secure-uploads.rb"' >/dev/null 2>&1; then
      fail "Zero-secure-upload verification failed; raw runtime output was suppressed."
    fi
  fi
fi

create_deployment_mutation || fail "Deployment runtime mutation journal could not be durably pre-armed."

if [[ ${contained_activation_required} == true ]]; then
  [[ ${mode} == rebuild ]] || fail "Contained DiscourseConnect activation requires an existing restored release."
  [[ -f ${config_dir}/activation.yml && ! -L ${config_dir}/activation.yml ]] || fail "Contained activation configuration is absent."
  activate_config "${config_dir}/activation.yml" || fail "Contained activation configuration could not be durably selected."
  activation_started=true
  run_launcher activation-contained rebuild app
  verification_seconds="$(remaining_mutation_seconds 600)" || fail "Contained activation verification budget is exhausted."
  timeout --signal=TERM --kill-after=10s "${verification_seconds}" bash "${release_dir}/scripts/verify-contained-activation.sh" \
    "${commit}" "${configuration_id}" >/dev/null 2>&1 || fail "Contained DiscourseConnect activation verification failed."
  contained_activation_passed=true
  record_event contained-activation passed "${configuration_id}" "${activation_config_sha}" || fail "Contained activation evidence could not be recorded."
  timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || fail "Public consumer activation requires the exact Website producer-disabled state."
fi

if [[ ${complete_authentication_rebuild} == true ]]; then
  timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py enabled >/dev/null 2>&1 || fail "Completed authentication rebuild requires the exact Website producer-enabled state before public activation."
fi
activate_config "${config_dir}/app.yml" || fail "Production configuration could not be durably selected."
activation_started=true
if [[ ${mode} == bootstrap ]]; then
  run_launcher bootstrap bootstrap app
  run_launcher start start app
else
  run_launcher rebuild rebuild app
fi

run_release_verification "${commit}" "${configuration_id}"

# Exercise the real hosted object-store path through the application, survive
# both supported runtime transitions, and then remove the exact disposable
# database rows, primary objects, and tombstones. Runner output never reaches
# the workflow log. Transaction-keyed PluginStore state seals row-derived keys
# before each external PUT; the digest-bound root journal remains retry
# authority until terminal absence is proved.
[[ -z "$(find "${evidence_root}" -maxdepth 1 -name '*-storage-cleanup-required.json' -print -quit)" ]] || fail "Unresolved hosted storage cleanup exists before fixture creation."
storage_transaction_id="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ ${storage_transaction_id} =~ ^[0-9a-f]{32}$ ]] || fail "Hosted storage transaction identifier is malformed."
readarray -t storage_journal_contract < <(create_storage_cleanup_journal "${storage_transaction_id}")
[[ ${#storage_journal_contract[@]} -eq 2 ]] || fail "Hosted storage cleanup journal could not be durably pre-armed."
storage_cleanup_journal="${storage_journal_contract[0]}"
storage_cleanup_journal_sha="${storage_journal_contract[1]}"
[[ ${storage_cleanup_journal} == "${evidence_root}/${commit}-${configuration_id}-${storage_cleanup_journal_sha}-storage-cleanup-required.json" && ${storage_cleanup_journal_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Hosted storage cleanup journal identity is malformed."
[[ "$(validate_storage_cleanup_journal "${storage_cleanup_journal}")" == "${storage_cleanup_journal_sha}" ]] || fail "Hosted storage cleanup journal validation failed."
storage_fixture_created=true
storage_state="$(mktemp "${evidence_root}/.storage-state-${commit}-${configuration_id}.XXXXXXXX.json")"
rm -f -- "${storage_state}"
storage_create_result="$(mktemp "${evidence_root}/.storage-create-${commit}-${configuration_id}.XXXXXXXX.json")"
rm -f -- "${storage_create_result}"
if ! run_storage_fixture create "${storage_create_result}" "${storage_cleanup_journal}"; then
  fail "Hosted storage fixture creation failed; raw runtime output was suppressed."
fi
promote_storage_state "${storage_create_result}" "${storage_state}" || fail "Hosted storage state could not be atomically committed."
storage_create_result=""
run_launcher storage-restart restart app
run_release_verification "${commit}" "${configuration_id}"
storage_restart_result="$(mktemp "${evidence_root}/.storage-restart-${commit}-${configuration_id}.XXXXXXXX.json")"
rm -f -- "${storage_restart_result}"
run_storage_fixture verify "${storage_restart_result}" "${storage_state}" || fail "Hosted storage fixture did not survive restart."
run_launcher storage-rebuild rebuild app
run_release_verification "${commit}" "${configuration_id}"
storage_rebuild_result="$(mktemp "${evidence_root}/.storage-rebuild-${commit}-${configuration_id}.XXXXXXXX.json")"
rm -f -- "${storage_rebuild_result}"
run_storage_fixture verify "${storage_rebuild_result}" "${storage_state}" || fail "Hosted storage fixture did not survive rebuild."
storage_delete_result="$(mktemp "${evidence_root}/.storage-delete-${commit}-${configuration_id}.XXXXXXXX.json")"
rm -f -- "${storage_delete_result}"
run_storage_fixture delete "${storage_delete_result}" "${storage_state}" || fail "Hosted storage fixture cleanup failed."
validate_storage_terminal_result delete "${storage_delete_result}" || fail "Hosted storage fixture returned no exact terminal absence proof."
clear_storage_cleanup_journal "${storage_cleanup_journal}" || fail "Hosted storage cleanup journal could not be durably cleared after terminal absence proof."
storage_cleanup_journal=""
storage_fixture_deleted=true
storage_evidence="${evidence_root}/${commit}-${configuration_id}-storage.json"
python3 - "${storage_evidence}" "${commit}" "${configuration_id}" "${storage_restart_result}" "${storage_rebuild_result}" "${storage_delete_result}" <<'PY'
import datetime
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
commit = sys.argv[2]
configuration = sys.argv[3]
expected_verify = {
    "schemaVersion": 1,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "objectWriteReadPassed": True,
    "optimizedVariantPassed": True,
    "customHostnameOnlyPassed": True,
    "anonymousDirectRetrievalPassed": True,
    "anonymousListingDenied": True,
    "publicAclPassed": True,
}
for source in sys.argv[4:6]:
    if json.loads(pathlib.Path(source).read_text(encoding="utf-8")) != expected_verify:
        raise SystemExit("Hosted storage persistence evidence differs")
expected_delete = {
    "schemaVersion": 1,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "databaseRowsDeleted": True,
    "primaryObjectsDeleted": True,
    "tombstonesDeleted": True,
}
if json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8")) != expected_delete:
    raise SystemExit("Hosted storage deletion evidence differs")
document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "objectWriteReadPassed": True,
    "optimizedVariantPassed": True,
    "customHostnameOnlyPassed": True,
    "anonymousDirectRetrievalPassed": True,
    "anonymousListingDenied": True,
    "publicAclPassed": True,
    "restartPersistencePassed": True,
    "rebuildPersistencePassed": True,
    "databaseRowsDeleted": True,
    "primaryObjectsDeleted": True,
    "tombstonesDeleted": True,
}
def discard_safe_partial(label):
    if not candidate.exists() and not candidate.is_symlink():
        return
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit(f"{label} partial is unsafe")
    candidate.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

if path.exists() or path.is_symlink():
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise SystemExit("Existing hosted storage evidence is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document):
        raise SystemExit("Existing hosted storage evidence schema differs")
    for key, value in document.items():
        if key != "recordedAt" and existing.get(key) != value:
            raise SystemExit("Existing hosted storage evidence differs")
    discard_safe_partial("hosted storage evidence")
else:
    discard_safe_partial("hosted storage evidence")
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
storage_evidence_sha="$(sha256sum -- "${storage_evidence}" | awk '{print $1}')"
[[ ${storage_evidence_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Hosted storage evidence digest is malformed."
if [[ ${requested_discourse_connect} == true ]]; then
  [[ ${contained_activation_passed} == true ]] || fail "Public consumer staging lacks the contained consumer proof."
  if [[ ${complete_authentication_rebuild} == true ]]; then
    timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py enabled >/dev/null 2>&1 || fail "Completed authentication rebuild requires the exact Website producer-enabled state after hosted verification."
  else
    timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled >/dev/null 2>&1 || fail "Public consumer staging requires the exact Website producer-disabled state."
  fi
fi

release_evidence="${evidence_root}/${commit}-${configuration_id}-release.json"
python3 - "${release_evidence}" "${commit}" "${expected_archive_sha}" "${production_config_sha}" "${restore_config_sha}" "${activation_config_sha}" "${theme_sha}" "${mail_metadata_plugin_sha}" "${requested_discourse_connect}" "${marker_file_for_evidence}" "${marker_sha_for_evidence}" "$(basename -- "${storage_evidence}")" "${storage_evidence_sha}" "${repository_tree}" "${release_archive_bytes}" "${release_archive_manifest_sha}" <<'PY'
import datetime
import json
import os
import pathlib
import re
import sys
if sys.argv[9] not in {"true", "false"}:
    raise SystemExit("DiscourseConnect release evidence is malformed")
activation_sha = sys.argv[6] or None
if (sys.argv[9] == "true") != (activation_sha is not None):
    raise SystemExit("Contained activation evidence does not match the consumer state")
if activation_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", activation_sha):
    raise SystemExit("Contained activation configuration digest is malformed")
marker_file = sys.argv[10] or None
marker_sha = sys.argv[11] or None
if (marker_file is None) != (marker_sha is None):
    raise SystemExit("Member-rollout release evidence is incomplete")
if marker_file is not None and (
    marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)
):
    raise SystemExit("Member-rollout release evidence is malformed")
if (
    re.fullmatch(r"[0-9a-f]{40}", sys.argv[14]) is None
    or not sys.argv[15].isdigit()
    or not 1 <= int(sys.argv[15]) <= 67108864
    or re.fullmatch(r"[0-9a-f]{64}", sys.argv[16]) is None
):
    raise SystemExit("Historical release archive authority is malformed")
document = {
    "schemaVersion": 2,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": sys.argv[2],
    "repositoryTree": sys.argv[14],
    "releaseArchiveSha256": sys.argv[3],
    "releaseArchiveBytes": int(sys.argv[15]),
    "releaseArchiveContentManifestSha256": sys.argv[16],
    "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
    "discourseRevision": "cbf996f65aae3da1843224aa624bcd9a225931ac",
    "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
    "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
    "productionConfigurationSha256": sys.argv[4],
    "restoreConfigurationSha256": sys.argv[5],
    "containedActivationConfigurationSha256": activation_sha,
    "containedActivationPassed": sys.argv[9] == "true",
    "activationPhase": "consumer-public-producer-pending" if sys.argv[9] == "true" else "consumer-disabled",
    "themeArchiveSha256": sys.argv[7],
    "mailMetadataPluginSha256": sys.argv[8],
    "discourseConnectEnabled": sys.argv[9] == "true",
    "memberRolloutMarkerFile": marker_file,
    "memberRolloutMarkerSha256": marker_sha,
    "hostVerificationPassed": True,
    "storageEvidenceFile": sys.argv[12],
    "storageEvidenceSha256": sys.argv[13],
    "hostedStoragePassed": True,
    "storageRestartPersistencePassed": True,
    "storageRebuildPersistencePassed": True,
    "storageCleanupPassed": True,
}
path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
def discard_safe_partial():
    if not candidate.exists() and not candidate.is_symlink():
        return
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit("release evidence partial is unsafe")
    candidate.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

if path.exists() or path.is_symlink():
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise SystemExit("Existing release evidence is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document):
        raise SystemExit("Existing release evidence schema differs")
    for key, value in document.items():
        if key != "recordedAt" and existing.get(key) != value:
            raise SystemExit("Existing release evidence tuple differs")
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

release_evidence_sha="$(sha256sum -- "${release_evidence}" | awk '{print $1}')"
[[ ${release_evidence_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Release evidence digest is malformed before terminal publication."
if [[ ${requested_discourse_connect} == true ]]; then
  if [[ ${complete_authentication_rebuild} == true ]]; then
    deployment_authentication_action=preserve-complete
  else
    deployment_authentication_action=pending
  fi
elif [[ ${stale_authentication_transition} == true ]]; then
  deployment_authentication_action=advance-complete
else
  deployment_authentication_action=absent
fi
mark_deployment_mutation_verified || fail "Deployment runtime mutation journal could not seal the verified phase."
deployment_commit_armed=true
write_deployment_transaction prepared "${deployment_authentication_action}" "${release_evidence}" \
  "${release_evidence_sha}" "${forward_fix_evidence_sha:--}" || fail "Deployment terminal transaction could not be durably pre-armed."
complete_deployment_commit prepared "${deployment_authentication_action}" "${release_evidence}" \
  "${release_evidence_sha}" "${requested_discourse_connect}" \
  "${marker_file_for_evidence:--}" "${marker_sha_for_evidence:--}" \
  "${forward_fix_evidence_sha:--}" || fail "Deployment terminal state could not be committed or verified."
clear_deployment_mutation || {
  deployment_success=false
  fail "Completed deployment mutation journal could not be durably retired."
}
printf '%s\n' "Mochirii Forums release verified."
