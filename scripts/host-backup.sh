#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly operation_started_epoch="$(date +%s)"
readonly mutation_budget_seconds=4500
readonly state_root="/var/lib/mochirii/forums"
readonly backup_transaction="${state_root}/backup-transaction.json"
readonly current_backup="${state_root}/current-backup.json"
readonly latest_backup_pointer="${state_root}/latest-backup-evidence"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Backup verification must run as root."
[[ $# -eq 2 ]] || fail "Usage: host-backup.sh EXPECTED_COMMIT BACKUP_OPERATION_SHA256"
commit="$1"
backup_operation_sha="$2"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Expected commit is malformed."
[[ ${backup_operation_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Backup operation digest is malformed."
lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
current_evidence="/var/lib/mochirii/forums/current-release.json"
[[ -f ${current_evidence} && ! -L ${current_evidence} ]] || fail "Current release evidence is absent."
[[ "$(stat -c '%U:%G %a' "${current_evidence}")" == "root:root 600" ]] || fail "Current release evidence has unsafe ownership or mode."
readarray -t current_contract < <(python3 - "${current_evidence}" "${commit}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
if set(document) != {"repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile", "memberRolloutMarkerSha256"}:
    raise SystemExit("current evidence keys differ")
if document.get("repositoryCommit") != sys.argv[2]:
    raise SystemExit("current release differs")
value = document.get("productionConfigurationSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", value):
    raise SystemExit("configuration digest is malformed")
expected = f"{sys.argv[2]}-{value}-release.json"
record = path.parent / "evidence" / expected
if document.get("releaseEvidenceFile") != expected or not record.is_file() or record.is_symlink():
    raise SystemExit("release evidence reference differs")
if record.stat().st_uid != 0 or record.stat().st_mode & 0o077:
    raise SystemExit("release evidence permissions are unsafe")
record_raw = record.read_bytes()
if document.get("releaseEvidenceSha256") != hashlib.sha256(record_raw).hexdigest():
    raise SystemExit("release evidence digest differs")
release = json.loads(record_raw)
if (
    release.get("schemaVersion") != 2
    or release.get("repositoryCommit") != sys.argv[2]
    or release.get("productionConfigurationSha256") != value
    or release.get("discourseRevision") != "cbf996f65aae3da1843224aa624bcd9a225931ac"
    or release.get("dockerManagerRevision") != "c008c3ca7fcc44775215843992e88190adb7b3bf"
    or release.get("discourseConnectEnabled") is not document.get("discourseConnectEnabled")
):
    raise SystemExit("release runtime identity differs")
connect = document.get("discourseConnectEnabled")
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if not isinstance(connect, bool) or (marker_file is None) != (marker_sha is None):
    raise SystemExit("activation evidence is malformed")
if marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)):
    raise SystemExit("member-rollout evidence is malformed")
print(value)
print("true" if connect else "false")
print(marker_file or "-")
print(marker_sha or "-")
print(hashlib.sha256(path.read_bytes()).hexdigest())
print(release["discourseRevision"])
print(release["dockerManagerRevision"])
PY
)
[[ ${#current_contract[@]} -eq 7 ]] || fail "Current release evidence is malformed."
configuration="${current_contract[0]}"
discourse_connect="${current_contract[1]}"
marker_file="${current_contract[2]}"
marker_sha="${current_contract[3]}"
current_release_sha="${current_contract[4]}"
discourse_revision="${current_contract[5]}"
docker_manager_revision="${current_contract[6]}"
[[ ${marker_file} != - ]] || marker_file=""
[[ ${marker_sha} != - ]] || marker_sha=""
release_dir="/opt/mochirii/forums/releases/${commit}"
bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Backup refuses runtime assets that differ from the sealed release."
backup_transaction_helper="${release_dir}/scripts/backup-transaction.py"
rollout_marker="/var/lib/mochirii/forums/member-rollout-enabled"
if [[ -n ${marker_file} ]]; then
  [[ -f ${rollout_marker} && ! -L ${rollout_marker} ]] || fail "Member-rollout marker referenced by current evidence is absent."
  [[ "$(stat -c '%U:%G %a' "${rollout_marker}")" == "root:root 600" ]] || fail "Member-rollout marker has unsafe ownership or mode."
  [[ "$(sha256sum -- "${rollout_marker}" | awk '{print $1}')" == "${marker_sha}" ]] || fail "Member-rollout marker digest differs from current evidence."
else
  [[ ! -e ${rollout_marker} ]] || fail "Unrecorded member-rollout marker is present."
fi
production_config="/var/discourse/containers/releases/${commit}/${configuration}/app.yml"
restore_config="/var/discourse/containers/releases/${commit}/${configuration}/restore.yml"
theme_archive="/opt/mochirii/forums/runtime-assets/${commit}/mochirii-theme.zip"
mail_metadata_plugin="/opt/mochirii/forums/runtime-assets/${commit}/mochirii-email-metadata-plugin.rb"
release_archive="/opt/mochirii/forums/runtime-assets/${commit}/mochirii-release.tar"
release_record="/var/lib/mochirii/forums/evidence/${commit}-${configuration}-release.json"
[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${production_config}" ]] || fail "Backup refuses a non-production or mismatched runtime configuration."
for protected in "${production_config}" "${restore_config}" "${theme_archive}" "${mail_metadata_plugin}" "${release_archive}" "${release_record}"; do
  [[ -f ${protected} && ! -L ${protected} ]] || fail "Exact release evidence or runtime asset is absent."
done

evidence_root="/var/lib/mochirii/forums/evidence"
logs_root="/var/lib/mochirii/forums/logs"
install -d -m 0700 -o root -g root "${evidence_root}" "${logs_root}"
[[ ! -e ${state_root}/deployment-transaction.json && ! -L ${state_root}/deployment-transaction.json ]] || fail "Backup refuses an active deployment transaction."
[[ ! -e ${state_root}/deployment-mutation.json && ! -L ${state_root}/deployment-mutation.json ]] || fail "Backup refuses an active deployment mutation."
[[ ! -e /var/lib/mochirii/forums/restore-transaction.json && ! -L /var/lib/mochirii/forums/restore-transaction.json ]] || fail "Backup refuses an active nonterminal restore transaction."
[[ ! -e ${state_root}/historical-release-adoption.json && ! -L ${state_root}/historical-release-adoption.json ]] || fail "Backup refuses an active historical disaster-recovery adoption."
[[ -z "$(find "${evidence_root}" -maxdepth 1 -name '*-storage-cleanup-required.json' -print -quit 2>/dev/null || true)" ]] || fail "Backup refuses an unresolved hosted-storage cleanup transaction."
runtime_survivor_unproved=false
active_bounded_pid=""
active_operation_token=""
mutation_active=false
backup_upload_journal=""
original_runtime_state=""
runtime_identity_sha=""
runtime_environment_sha=""
runtime_ports_sha=""
runtime_container_image=""
runtime_operation_phase=""
runtime_operation_label="-"
runtime_operation_token="-"

stop_app_safely() {
  local inventory
  local running
  timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app 200>&- 201>&- >/dev/null 2>&1 || true
  if running="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{.State.Running}}' app 200>&- 201>&- 2>/dev/null)"; then
    [[ ${running} == false ]]
    return
  fi
  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 200>&- 201>&- 2>/dev/null)" || return 1
  [[ -z ${inventory} ]]
}

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

contain_failed_container_operation() {
  if stop_app_safely; then
    return 0
  fi
  runtime_survivor_unproved=true
  printf '%s\n' "CRITICAL: Backup in-container process termination could not be verified." >&2
  return 1
}

remaining_mutation_seconds() {
  local requested="$1"
  local now
  local remaining
  [[ ${requested} =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  now="$(date +%s)"
  remaining=$((operation_started_epoch + mutation_budget_seconds - now))
  (( remaining >= 60 )) || return 1
  (( requested <= remaining )) || requested="${remaining}"
  printf '%s\n' "${requested}"
}

run_container_command() {
  local label="$1"
  local inner_seconds="$2"
  local process_marker="$3"
  local output="$4"
  local command_status=0
  local operation_token
  local outer_seconds
  shift 4
  [[ ${label} =~ ^[a-z-]{1,32}$ && ${inner_seconds} =~ ^[1-9][0-9]{0,4}$ && ${process_marker} != *$'\n'* ]] || return 1
  [[ ${output} == /dev/null || ${output} == "${evidence_root}/"* ]] || return 1
  outer_seconds="$(remaining_mutation_seconds "$((inner_seconds + 30))")" || return 1
  if (( outer_seconds < inner_seconds + 30 )); then
    inner_seconds=$((outer_seconds - 30))
  fi
  operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  prove_running_backup_identity || return 1
  backup_runtime_operation_command arm-operation "${label}" "${operation_token}" || return 1
  runtime_operation_phase=operation-armed
  runtime_operation_label="${label}"
  runtime_operation_token="${operation_token}"
  active_operation_token="${operation_token}"
  mutation_active=true
  (ulimit -f 128; exec 200>&- 201>&-; exec timeout --signal=TERM --kill-after=10s "${outer_seconds}" docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app \
    timeout --signal=TERM --kill-after=15s "${inner_seconds}" "$@") \
    >"${output}" 2>/dev/null &
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || command_status=$?
  active_bounded_pid=""
  if ! container_operation_absent "${operation_token}"; then
    contain_failed_container_operation || true
    active_operation_token=""
    mutation_active=false
    return 1
  fi
  active_operation_token=""
  if (( command_status == 124 || command_status == 137 || command_status == 143 )); then
    contain_failed_container_operation || true
    mutation_active=false
    return 1
  fi
  prove_running_backup_identity || {
    contain_failed_container_operation || true
    mutation_active=false
    return 1
  }
  backup_runtime_operation_command complete-operation "${label}" "${operation_token}" || {
    contain_failed_container_operation || true
    mutation_active=false
    return 1
  }
  runtime_operation_phase=idle
  runtime_operation_label=-
  runtime_operation_token=-
  mutation_active=false
  (( command_status == 0 )) || return 1
  if [[ ${output} != /dev/null ]]; then
    [[ -f ${output} && ! -L ${output} && "$(stat -c '%U:%G %a' "${output}")" == "root:root 600" && "$(stat -c '%s' "${output}")" -le 65536 ]] || return 1
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
  fi
}

record_event() {
  local status="$1"
  local evidence_sha="${2:--}"
  [[ ${status} == started || ${status} == passed || ${status} == failed ]] || return 1
  [[ ${evidence_sha} == - || ${evidence_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
    --path "${logs_root}/events.log" --operation backup --status "${status}" \
    --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
    --field "backup_operation_sha256=${backup_operation_sha}" \
    --field "evidence_sha256=${evidence_sha}" >/dev/null
}

backup_transaction_command() {
  local action="$1"
  shift
  python3 -B "${backup_transaction_helper}" "${action}" \
    --state-root "${state_root}" --evidence-root "${evidence_root}" \
    --transaction "${backup_transaction}" --current "${current_backup}" \
    --pointer "${latest_backup_pointer}" --commit "${commit}" \
    --configuration "${configuration}" --operation-sha "${backup_operation_sha}" \
    --runtime-identity-sha "${runtime_identity_sha}" \
    --current-release-sha "${current_release_sha}" \
    --discourse-revision "${discourse_revision}" \
    --docker-manager-revision "${docker_manager_revision}" \
    --runtime-environment-sha "${runtime_environment_sha}" \
    --runtime-ports-sha "${runtime_ports_sha}" \
    --runtime-image "${runtime_container_image}" "$@"
}

backup_runtime_recovery_command() {
  local action="$1"
  local journal="${2:--}"
  local journal_name="-"
  local journal_sha="-"
  if [[ ${journal} != - ]]; then
    validate_backup_upload_journal "${journal}" >/dev/null || return 1
    journal_name="$(basename -- "${journal}")" || return 1
    journal_sha="$(sha256sum -- "${journal}" | awk '{print $1}')" || return 1
    [[ ${journal_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  fi
  backup_transaction_command "${action}" \
    --recovery-journal "${journal_name}" --recovery-journal-sha "${journal_sha}" >/dev/null
}

backup_runtime_operation_command() {
  local action="$1"
  local label="$2"
  local token="$3"
  [[ ${label} =~ ^[a-z][a-z0-9-]{0,31}$ && ${token} =~ ^[0-9a-f]{32}$ ]] || return 1
  backup_transaction_command "${action}" \
    --runtime-operation-label "${label}" --runtime-operation-token "${token}" >/dev/null
}

prove_production_selection() {
  [[ -L /var/discourse/containers/app.yml ]] || return 1
  [[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${production_config}" ]] || return 1
  [[ "$(sha256sum -- "${production_config}" | awk '{print $1}')" == "${configuration}" ]] || return 1
  [[ -L /opt/mochirii/forums/current ]] || return 1
  [[ "$(readlink -f -- /opt/mochirii/forums/current)" == "${release_dir}" ]] || return 1
}

runtime_environment_matches() {
  local expected
  local counts
  local key
  for expected in \
    "MOCHIRII_REPOSITORY_COMMIT=${commit}" \
    "MOCHIRII_RELEASE_ASSET_ROOT=/opt/mochirii-release" \
    "DISCOURSE_ENABLE_DISCOURSE_CONNECT=${discourse_connect}" \
    "DISCOURSE_DISABLE_EMAILS=no"; do
    key="${expected%%=*}="
    counts="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container \
      --format '{{range .Config.Env}}{{println .}}{{end}}' app 2>/dev/null | \
      awk -v key="${key}" -v exact="${expected}" '
        index($0, key) == 1 { key_count += 1 }
        $0 == exact { exact_count += 1 }
        END { printf "%d %d\n", key_count, exact_count }
      ')" || return 1
    [[ ${counts} == "1 1" ]] || return 1
  done
}

capture_backup_runtime_contract() {
  local app_state
  local container_image
  local environment_sha
  local identity_sha
  local port_bindings
  local ports_sha
  prove_production_selection || return 1
  bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || return 1
  app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
  [[ ${app_state} == true || ${app_state} == false ]] || return 1
  container_image="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.Image}}' app 2>/dev/null)" || return 1
  [[ ${container_image} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  runtime_environment_matches || return 1
  environment_sha="$(python3 -B - "${commit}" "${discourse_connect}" <<'PY'
import hashlib
import json
import sys

document = {
    "DISCOURSE_DISABLE_EMAILS": "no",
    "DISCOURSE_ENABLE_DISCOURSE_CONNECT": sys.argv[2],
    "MOCHIRII_RELEASE_ASSET_ROOT": "/opt/mochirii-release",
    "MOCHIRII_REPOSITORY_COMMIT": sys.argv[1],
}
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
print(hashlib.sha256(payload).hexdigest())
PY
)" || return 1
  [[ ${environment_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  port_bindings="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{json .HostConfig.PortBindings}}' app 2>/dev/null)" || return 1
  ports_sha="$(python3 -B - "${port_bindings}" <<'PY'
import hashlib
import json
import sys

document = json.loads(sys.argv[1])
if set(document) != {"80/tcp", "443/tcp"}:
    raise SystemExit("production port inventory differs")
for name, port in (("80/tcp", "80"), ("443/tcp", "443")):
    rows = document.get(name)
    if not isinstance(rows, list) or len(rows) != 1:
        raise SystemExit("production port binding differs")
    row = rows[0]
    if set(row) != {"HostIp", "HostPort"} or row["HostPort"] != port or row["HostIp"] not in {"", "0.0.0.0", "::"}:
        raise SystemExit("production host binding differs")
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
print(hashlib.sha256(payload).hexdigest())
PY
)" || return 1
  [[ ${ports_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  identity_sha="$(python3 -B - "${commit}" "${configuration}" "${current_release_sha}" \
    "${discourse_revision}" "${docker_manager_revision}" "${environment_sha}" \
    "${ports_sha}" "${container_image}" <<'PY'
import hashlib
import json
import sys

keys = (
    "repositoryCommit", "productionConfigurationSha256", "currentReleaseSha256",
    "discourseRevision", "dockerManagerRevision", "runtimeEnvironmentSha256",
    "runtimePortBindingsSha256", "runtimeContainerImage",
)
document = dict(zip(keys, sys.argv[1:], strict=True))
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
print(hashlib.sha256(payload).hexdigest())
PY
)" || return 1
  [[ ${identity_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${app_state}" "${identity_sha}" "${environment_sha}" "${ports_sha}" "${container_image}"
}

prove_bound_runtime_contract() {
  local expected_state="$1"
  local observed
  readarray -t observed < <(capture_backup_runtime_contract) || return 1
  [[ ${#observed[@]} -eq 5 ]] || return 1
  [[ ${observed[0]} == "${expected_state}" ]] || return 1
  [[ ${observed[1]} == "${runtime_identity_sha}" ]] || return 1
  [[ ${observed[2]} == "${runtime_environment_sha}" ]] || return 1
  [[ ${observed[3]} == "${runtime_ports_sha}" ]] || return 1
  [[ ${observed[4]} == "${runtime_container_image}" ]] || return 1
}

prove_stopped_backup_identity() {
  prove_bound_runtime_contract false
}

prove_running_backup_identity() {
  prove_bound_runtime_contract true || return 1
  [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Status}}' app 2>/dev/null)" == running ]] || return 1
  timeout --signal=TERM --kill-after=5s 30 docker exec -u discourse app bash -lc \
    'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1" && test "$MOCHIRII_RELEASE_ASSET_ROOT" = /opt/mochirii-release && test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = "$2" && test "$DISCOURSE_DISABLE_EMAILS" = no && test "$(git -C /var/www/discourse rev-parse HEAD)" = cbf996f65aae3da1843224aa624bcd9a225931ac && test "$(git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD)" = c008c3ca7fcc44775215843992e88190adb7b3bf' \
    bash "${commit}" "${discourse_connect}" >/dev/null 2>&1 || return 1
}

start_app_for_backup_recovery() {
  local attempts=0
  prove_production_selection || return 1
  [[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || return 1
  timeout --signal=TERM --kill-after=5s 45 docker start app >/dev/null 2>&1 || return 1
  while (( attempts < 30 )); do
    if prove_running_backup_identity; then
      return 0
    fi
    attempts=$((attempts + 1))
    (( attempts < 30 )) && sleep 1
  done
  stop_app_safely || runtime_survivor_unproved=true
  return 1
}

reconcile_bound_runtime_ownership() {
  local app_state
  local attempts=0
  while (( attempts < 8 )); do
    attempts=$((attempts + 1))
    case "${runtime_operation_phase}" in
      initial-stopped)
        prove_stopped_backup_identity || return 1
        backup_transaction_command authorize-initial-start >/dev/null || return 1
        runtime_operation_phase=initial-start-authorized
        ;;
      initial-start-authorized)
        app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
        if [[ ${app_state} == false ]]; then
          prove_stopped_backup_identity || return 1
          start_app_for_backup_recovery || return 1
        elif [[ ${app_state} == true ]]; then
          prove_running_backup_identity || return 1
        else
          return 1
        fi
        backup_transaction_command complete-initial-start >/dev/null || return 1
        runtime_operation_phase=idle
        ;;
      operation-armed)
        [[ ${runtime_operation_label} =~ ^[a-z][a-z0-9-]{0,31}$ && ${runtime_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
        app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
        if [[ ${app_state} == true ]] && container_operation_absent "${runtime_operation_token}"; then
          prove_running_backup_identity || return 1
          backup_runtime_operation_command complete-operation "${runtime_operation_label}" "${runtime_operation_token}" || return 1
          runtime_operation_phase=idle
          runtime_operation_label=-
          runtime_operation_token=-
        else
          contain_failed_container_operation || return 1
          prove_stopped_backup_identity || return 1
          backup_runtime_operation_command prove-operation-absent "${runtime_operation_label}" "${runtime_operation_token}" || return 1
          runtime_operation_phase=operation-absence-proved
        fi
        ;;
      operation-absence-proved)
        backup_runtime_operation_command authorize-restart "${runtime_operation_label}" "${runtime_operation_token}" || return 1
        runtime_operation_phase=restart-authorized
        ;;
      restart-authorized)
        app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
        if [[ ${app_state} == false ]]; then
          prove_stopped_backup_identity || return 1
          start_app_for_backup_recovery || return 1
        elif [[ ${app_state} == true ]]; then
          prove_running_backup_identity || return 1
        else
          return 1
        fi
        backup_runtime_operation_command complete-restart "${runtime_operation_label}" "${runtime_operation_token}" || return 1
        runtime_operation_phase=idle
        runtime_operation_label=-
        runtime_operation_token=-
        ;;
      idle)
        prove_running_backup_identity || return 1
        return 0
        ;;
      temporary-stop-authorized)
        app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
        if [[ ${app_state} == true ]]; then
          prove_running_backup_identity || return 1
          stop_app_safely || return 1
        elif [[ ${app_state} != false ]]; then
          return 1
        fi
        prove_stopped_backup_identity || return 1
        backup_transaction_command contain-temporary-runtime >/dev/null || return 1
        runtime_operation_phase=initial-stopped
        ;;
      original-stop-authorized)
        app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
        if [[ ${app_state} == true ]]; then
          prove_running_backup_identity || return 1
          stop_app_safely || return 1
        elif [[ ${app_state} != false ]]; then
          return 1
        fi
        prove_stopped_backup_identity || return 1
        backup_transaction_command complete-original-state --observed-runtime-state stopped >/dev/null || return 1
        runtime_operation_phase=original-restored
        return 0
        ;;
      original-restored)
        if [[ ${original_runtime_state} == running ]]; then
          prove_running_backup_identity || return 1
        else
          prove_stopped_backup_identity || return 1
        fi
        return 0
        ;;
      *) return 1 ;;
    esac
  done
  return 1
}

restore_original_runtime_state() {
  if [[ ${original_runtime_state} == running ]]; then
    [[ ${runtime_operation_phase} == idle ]] || return 1
    prove_running_backup_identity || return 1
    backup_transaction_command complete-original-state --observed-runtime-state running >/dev/null || return 1
    runtime_operation_phase=original-restored
    return 0
  fi
  [[ ${original_runtime_state} == stopped ]] || return 1
  if [[ ${runtime_operation_phase} == idle ]]; then
    backup_transaction_command authorize-original-stop >/dev/null || return 1
    runtime_operation_phase=original-stop-authorized
  fi
  reconcile_bound_runtime_ownership
}

contain_temporary_runtime_on_failure() {
  local app_state
  [[ ${original_runtime_state} == stopped ]] || return 0
  if [[ ${runtime_operation_phase} == idle ]]; then
    backup_transaction_command contain-temporary-runtime >/dev/null || return 1
    runtime_operation_phase=temporary-stop-authorized
  elif [[ ${runtime_operation_phase} == initial-stopped ]]; then
    prove_stopped_backup_identity
    return
  elif [[ ${runtime_operation_phase} != temporary-stop-authorized ]]; then
    return 0
  fi
  app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
  if [[ ${app_state} == true ]]; then
    prove_running_backup_identity || return 1
    stop_app_safely || return 1
  elif [[ ${app_state} != false ]]; then
    return 1
  fi
  prove_stopped_backup_identity || return 1
  backup_transaction_command contain-temporary-runtime >/dev/null || return 1
  runtime_operation_phase=initial-stopped
}

finish_backup_transaction() {
  local phase="$1"
  local evidence_path="$2"
  local evidence_sha
  local pointer_sha
  [[ ${phase} == prepared || ${phase} == pointer-committed || ${phase} == event-committed ]] || return 1
  [[ ${evidence_path} == "${evidence_root}/${commit}-${configuration}-"[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z-backup.json ]] || return 1
  evidence_sha="$(backup_transaction_command evidence-sha)" || return 1
  [[ ${evidence_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  pointer_sha="$(backup_transaction_command select-pointer)" || return 1
  [[ ${pointer_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ ${phase} == prepared || ${phase} == pointer-committed ]]; then
    backup_transaction_command publish-phase --phase pointer-committed \
      --evidence-sha "${evidence_sha}" --pointer-sha "${pointer_sha}" >/dev/null || return 1
  fi
  record_event passed "${evidence_sha}" || return 1
  backup_transaction_command publish-phase --phase event-committed \
    --evidence-sha "${evidence_sha}" --pointer-sha "${pointer_sha}" >/dev/null || return 1
  backup_transaction_command clear >/dev/null
}

validate_backup_upload_journal() {
  local path="$1"
  python3 -B - "${path}" "${evidence_root}" "${commit}" "${configuration}" "${backup_operation_sha}" <<'PY'
import base64
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
configuration = sys.argv[4]
if path.parent != root or not path.is_file() or path.is_symlink():
    raise SystemExit("backup upload journal is not one protected file")
metadata = path.stat(follow_symlinks=False)
if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 4096:
    raise SystemExit("backup upload journal permissions or size are unsafe")
match = re.fullmatch(
    rf"{commit}-{configuration}-([0-9a-f]{{32}})-backup-upload-cleanup-required[.]json",
    path.name,
)
if match is None:
    raise SystemExit("backup upload journal filename differs")
raw = path.read_bytes()
document = json.loads(raw)
expected = {
    "schemaVersion": 1,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "backupOperationSha256": sys.argv[5],
    "transactionId": match.group(1),
    "pluginStoreKey": f"normal_upload_transaction:{match.group(1)}",
    "phase": "prepared",
}
canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if document != expected or raw != canonical:
    raise SystemExit("backup upload journal tuple or canonical bytes differ")
print(base64.b64encode(raw).decode("ascii"))
PY
}

create_backup_upload_journal() {
  local transaction_id="$1"
  local path="$2"
  python3 -B - "${path}" "${evidence_root}" "${commit}" "${configuration}" "${transaction_id}" "${backup_operation_sha}" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
configuration = sys.argv[4]
transaction_id = sys.argv[5]
operation_sha = sys.argv[6]
if (
    path.parent != root
    or not re.fullmatch(r"[0-9a-f]{40}", commit)
    or not re.fullmatch(r"[0-9a-f]{64}", configuration)
    or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
    or not re.fullmatch(r"[0-9a-f]{64}", operation_sha)
    or path.name != f"{commit}-{configuration}-{transaction_id}-backup-upload-cleanup-required.json"
):
    raise SystemExit("backup upload journal publication identity differs")
document = {
    "schemaVersion": 1,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "backupOperationSha256": operation_sha,
    "transactionId": transaction_id,
    "pluginStoreKey": f"normal_upload_transaction:{transaction_id}",
    "phase": "prepared",
}
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
partial = root / ".backup-upload-cleanup-journal.partial"
descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "wb") as target:
    metadata = os.fstat(target.fileno())
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("backup upload journal partial permissions differ")
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
PY
}

reconcile_backup_upload_journal_partial() {
  python3 -B - "${evidence_root}" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
partial = root / ".backup-upload-cleanup-journal.partial"
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
    raise SystemExit("backup upload journal partial is unsafe")
raw = partial.read_bytes()
if len(raw) != metadata.st_size:
    raise SystemExit("backup upload journal partial changed while it was read")
linked = []
for candidate in root.glob("*-backup-upload-cleanup-required.json"):
    candidate_metadata = candidate.lstat()
    if candidate_metadata.st_dev == metadata.st_dev and candidate_metadata.st_ino == metadata.st_ino:
        linked.append((candidate, candidate_metadata))
if linked:
    if len(linked) != 1 or metadata.st_nlink != 2:
        raise SystemExit("backup upload journal partial has ambiguous final links")
    final, final_metadata = linked[0]
    if (
        not stat.S_ISREG(final_metadata.st_mode)
        or stat.S_ISLNK(final_metadata.st_mode)
        or final_metadata.st_uid != 0
        or final_metadata.st_gid != 0
        or stat.S_IMODE(final_metadata.st_mode) != 0o600
        or final.read_bytes() != raw
    ):
        raise SystemExit("backup upload journal final link is unsafe")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("linked backup upload journal partial is malformed")
    transaction_id = document.get("transactionId", "") if isinstance(document, dict) else ""
    commit = document.get("repositoryCommit", "") if isinstance(document, dict) else ""
    configuration = document.get("productionConfigurationSha256", "") if isinstance(document, dict) else ""
    operation_sha = document.get("backupOperationSha256", "") if isinstance(document, dict) else ""
    expected = {
        "schemaVersion": 1,
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "backupOperationSha256": operation_sha,
        "transactionId": transaction_id,
        "pluginStoreKey": f"normal_upload_transaction:{transaction_id}",
        "phase": "prepared",
    }
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if (
        document != expected
        or raw != canonical
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"[0-9a-f]{64}", configuration)
        or not re.fullmatch(r"[0-9a-f]{32}", transaction_id)
        or not re.fullmatch(r"[0-9a-f]{64}", operation_sha)
        or final.name != f"{commit}-{configuration}-{transaction_id}-backup-upload-cleanup-required.json"
    ):
        raise SystemExit("linked backup upload journal identity differs")
elif metadata.st_nlink != 1:
    raise SystemExit("uncommitted backup upload journal partial has hidden links")
partial.unlink()
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

clear_backup_upload_journal() {
  local path="$1"
  python3 -B - "${path}" "${evidence_root}" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
if path.parent != root:
    raise SystemExit("backup upload journal path escaped its evidence root")
if path.exists() or path.is_symlink():
    if not path.is_file() or path.is_symlink():
        raise SystemExit("backup upload journal is unsafe")
    path.unlink()
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

reconcile_backup_upload_journal() {
  local path="$1"
  local encoded
  local result
  local validation_status=0
  encoded="$(validate_backup_upload_journal "${path}")" || return 1
  [[ ${#encoded} -le 8192 && ${encoded} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
  result="$(mktemp "${evidence_root}/.backup-upload-cleanup.XXXXXXXX.json")" || return 1
  rm -f -- "${result}"
  if ! run_container_command cleanup-backup-upload 600 "prepare-backup-marker.rb transaction cleanup" "${result}" bash -lc \
    'export MOCHIRII_RECOVERY_UPLOAD_ACTION=cleanup MOCHIRII_RECOVERY_UPLOAD_TRANSACTION_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-backup-marker.rb"' \
    bash "${encoded}"; then
    rm -f -- "${result}"
    return 1
  fi
  python3 -B - "${result}" <<'PY' || validation_status=$?
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
document = json.loads(raw)
expected = {"recoveryUploadCleanupPassed": True}
canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if document != expected or raw != canonical:
    raise SystemExit("recovery-upload terminal absence proof differs")
PY
  rm -f -- "${result}"
  (( validation_status == 0 )) || return 1
}

candidate=""
recovery_upload_state=""
normal_upload_inventory_before=""
dr_payload=""
dr_result=""
recovery_upload_included=false
recovery_upload_deleted=false
backup_success=false
backup_event_started=false
cleanup() {
  local status=$?
  local app_state=""
  trap - EXIT
  if [[ -n ${backup_upload_journal} && ( -e ${backup_upload_journal} || -L ${backup_upload_journal} ) ]]; then
    app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null || true)"
    if [[ ${runtime_survivor_unproved} == false && ${app_state} == true ]] && \
      reconcile_backup_upload_journal "${backup_upload_journal}" && \
      backup_runtime_recovery_command complete-cleanup "${backup_upload_journal}" && \
      clear_backup_upload_journal "${backup_upload_journal}" && \
      backup_runtime_recovery_command resume-runtime -; then
      backup_upload_journal=""
    else
      printf '%s\n' "Recovery-upload cleanup remains unresolved; the exact root-only journal was retained." >&2
      status=1
    fi
  fi
  if [[ ${status} -ne 0 && ${backup_success} == false && -e ${backup_transaction} && ${runtime_identity_sha} =~ ^[0-9a-f]{64}$ ]]; then
    if ! contain_temporary_runtime_on_failure; then
      printf '%s\n' "CRITICAL: Backup could not restore its stopped-origin containment state." >&2
      status=1
    fi
  fi
  [[ -z ${candidate} || ! -f ${candidate} ]] || rm -f -- "${candidate}"
  [[ -z ${recovery_upload_state} || ! -f ${recovery_upload_state} ]] || rm -f -- "${recovery_upload_state}"
  [[ -z ${normal_upload_inventory_before} || ! -f ${normal_upload_inventory_before} ]] || rm -f -- "${normal_upload_inventory_before}"
  [[ -z ${dr_payload} || ! -f ${dr_payload} ]] || rm -f -- "${dr_payload}"
  [[ -z ${dr_result} || ! -f ${dr_result} ]] || rm -f -- "${dr_result}"
  if [[ ${status} -ne 0 && ${backup_success} == false && ${backup_event_started} == true ]]; then
    record_event failed || true
  fi
  exit "${status}"
}
trap cleanup EXIT

handle_operation_signal() {
  trap - HUP INT TERM
  terminate_active_group
  if [[ ${mutation_active} == true ]]; then
    contain_failed_container_operation || true
  fi
  exit 124
}
trap handle_operation_signal HUP INT TERM

readarray -t initial_runtime_contract < <(capture_backup_runtime_contract) || fail "Exact backup runtime identity could not be read."
[[ ${#initial_runtime_contract[@]} -eq 5 ]] || fail "Exact backup runtime identity is malformed."
case "${initial_runtime_contract[0]}" in
  true) original_runtime_state=running ;;
  false) original_runtime_state=stopped ;;
  *) fail "Original backup runtime state is malformed." ;;
esac
runtime_identity_sha="${initial_runtime_contract[1]}"
runtime_environment_sha="${initial_runtime_contract[2]}"
runtime_ports_sha="${initial_runtime_contract[3]}"
runtime_container_image="${initial_runtime_contract[4]}"
[[ ${runtime_identity_sha} =~ ^[0-9a-f]{64}$ && ${runtime_environment_sha} =~ ^[0-9a-f]{64}$ && ${runtime_ports_sha} =~ ^[0-9a-f]{64}$ && ${runtime_container_image} =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Exact backup runtime binding is malformed."

reconcile_backup_upload_journal_partial || fail "Backup upload journal partial could not be safely reconciled."
readarray -t pending_backup_upload_journals < <(find "${evidence_root}" -maxdepth 1 -name '*-backup-upload-cleanup-required.json' -print | sort)
(( ${#pending_backup_upload_journals[@]} <= 1 )) || fail "Multiple recovery-upload cleanup journals require manual review."
if (( ${#pending_backup_upload_journals[@]} == 1 )); then
  backup_upload_journal="${pending_backup_upload_journals[0]}"
fi
backup_transaction_phase=""
if [[ -e ${backup_transaction} || -L ${backup_transaction} ]]; then
  readarray -t backup_transaction_contract < <(backup_transaction_command inspect)
  [[ ${#backup_transaction_contract[@]} -eq 19 ]] || fail "Backup transaction contract is malformed."
else
  [[ -z ${backup_upload_journal} ]] || fail "Recovery-upload cleanup journal has no owning backup transaction."
  if [[ -e ${current_backup} || -L ${current_backup} ]]; then
    readarray -t current_backup_contract < <(backup_transaction_command inspect-current --include-runtime-contract)
    [[ ${#current_backup_contract[@]} -eq 13 ]] || fail "Terminal current-backup contract is malformed."
    current_backup_commit="${current_backup_contract[0]}"
    current_backup_configuration="${current_backup_contract[1]}"
    current_backup_operation="${current_backup_contract[2]}"
    current_backup_evidence="${current_backup_contract[3]}"
    current_backup_phase="${current_backup_contract[4]}"
    current_backup_original_state="${current_backup_contract[5]}"
    if [[ ${current_backup_operation} == "${backup_operation_sha}" ]]; then
      [[ ${current_backup_commit} == "${commit}" && ${current_backup_configuration} == "${configuration}" ]] || fail "Backup operation digest was rebound to another release tuple."
      [[ ${current_backup_contract[6]} == "${runtime_identity_sha}" && ${current_backup_contract[7]} == "${current_release_sha}" && ${current_backup_contract[8]} == "${discourse_revision}" && ${current_backup_contract[9]} == "${docker_manager_revision}" && ${current_backup_contract[10]} == "${runtime_environment_sha}" && ${current_backup_contract[11]} == "${runtime_ports_sha}" && ${current_backup_contract[12]} == "${runtime_container_image}" ]] || fail "Same-operation current-backup runtime binding differs."
      [[ ${current_backup_original_state} == "${original_runtime_state}" ]] || fail "Same-operation current-backup original runtime state differs."
      [[ ${current_backup_phase} == event-committed ]] || fail "Same-operation current-backup is not terminal."
      adopted_evidence_sha="$(backup_transaction_command adopt-current)" || fail "Same-operation terminal backup could not be exactly adopted."
      [[ ${adopted_evidence_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Adopted terminal backup digest is malformed."
      record_event passed "${adopted_evidence_sha}" || fail "Adopted terminal backup event could not be reconciled."
      printf '%s\n' "Mochirii Forums terminal backup operation reconciled."
      exit 0
    fi
    if [[ ${current_backup_commit} == "${commit}" && ${current_backup_configuration} == "${configuration}" ]]; then
      [[ ${current_backup_contract[6]} == "${runtime_identity_sha}" && ${current_backup_contract[7]} == "${current_release_sha}" && ${current_backup_contract[8]} == "${discourse_revision}" && ${current_backup_contract[9]} == "${docker_manager_revision}" && ${current_backup_contract[10]} == "${runtime_environment_sha}" && ${current_backup_contract[11]} == "${runtime_ports_sha}" && ${current_backup_contract[12]} == "${runtime_container_image}" ]] || fail "Same-release current-backup runtime binding differs."
    fi
    [[ ${current_backup_evidence} =~ ^[0-9a-f]{40}-[0-9a-f]{64}-[0-9]{8}T[0-9]{6}Z-backup[.]json$ ]] || fail "Prior terminal current-backup evidence identity is malformed."
    [[ ${current_backup_phase} == event-committed ]] || fail "A new backup operation cannot retire a nonterminal current-backup."
    backup_transaction_command retire-current >/dev/null || fail "Prior terminal current-backup could not be exactly validated and durably retired."
  fi
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  evidence_name="${commit}-${configuration}-${timestamp}-backup.json"
  evidence="${evidence_root}/${evidence_name}"
  backup_transaction_command create --timestamp "${timestamp}" --evidence-file "${evidence_name}" \
    --original-runtime-state "${original_runtime_state}" >/dev/null || fail "Backup transaction could not be durably pre-armed."
  backup_transaction_phase=prepared
  readarray -t backup_transaction_contract < <(backup_transaction_command inspect)
  [[ ${#backup_transaction_contract[@]} -eq 19 ]] || fail "New backup transaction contract is malformed."
fi

timestamp="${backup_transaction_contract[0]}"
evidence_name="${backup_transaction_contract[1]}"
backup_transaction_phase="${backup_transaction_contract[2]}"
runtime_recovery_phase="${backup_transaction_contract[5]}"
runtime_recovery_journal_name="${backup_transaction_contract[6]}"
runtime_recovery_journal_sha="${backup_transaction_contract[7]}"
original_runtime_state="${backup_transaction_contract[8]}"
[[ ${backup_transaction_contract[9]} == "${runtime_identity_sha}" && ${backup_transaction_contract[10]} == "${current_release_sha}" && ${backup_transaction_contract[11]} == "${discourse_revision}" && ${backup_transaction_contract[12]} == "${docker_manager_revision}" && ${backup_transaction_contract[13]} == "${runtime_environment_sha}" && ${backup_transaction_contract[14]} == "${runtime_ports_sha}" && ${backup_transaction_contract[15]} == "${runtime_container_image}" ]] || fail "Prepared backup runtime binding differs."
runtime_operation_phase="${backup_transaction_contract[16]}"
runtime_operation_label="${backup_transaction_contract[17]}"
runtime_operation_token="${backup_transaction_contract[18]}"
evidence="${evidence_root}/${evidence_name}"
[[ ${evidence_name} == "${commit}-${configuration}-${timestamp}-backup.json" ]] || fail "Backup transaction evidence identity differs."
if [[ ! -e ${evidence} && ! -L ${evidence} ]]; then
  [[ ${backup_transaction_phase} == prepared && ${backup_transaction_contract[3]} == - && ${backup_transaction_contract[4]} == - ]] || fail "Committed backup transaction lost its exact evidence."
fi

if [[ -n ${backup_upload_journal} ]]; then
  validate_backup_upload_journal "${backup_upload_journal}" >/dev/null || fail "Pending recovery-upload journal identity differs."
  observed_upload_journal_name="$(basename -- "${backup_upload_journal}")"
  observed_upload_journal_sha="$(sha256sum -- "${backup_upload_journal}" | awk '{print $1}')"
  [[ ${observed_upload_journal_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Pending recovery-upload journal digest is malformed."
  if [[ ${runtime_recovery_phase} == none ]]; then
    backup_runtime_recovery_command bind-cleanup "${backup_upload_journal}" || fail "Pending recovery-upload cleanup could not be bound to its backup transaction."
    runtime_recovery_phase=cleanup-pending
    runtime_recovery_journal_name="${observed_upload_journal_name}"
    runtime_recovery_journal_sha="${observed_upload_journal_sha}"
  else
    [[ ${runtime_recovery_journal_name} == "${observed_upload_journal_name}" && ${runtime_recovery_journal_sha} == "${observed_upload_journal_sha}" ]] || fail "Pending recovery-upload cleanup differs from its backup transaction."
  fi
elif [[ ${runtime_recovery_journal_name} != - && ${runtime_recovery_phase} != cleanup-proved ]]; then
  fail "Backup transaction lost its unresolved recovery-upload journal."
fi

reconcile_bound_runtime_ownership || fail "Backup runtime operation absence or exact restart remains unresolved; the application stays contained."
if [[ -e ${evidence} || -L ${evidence} ]]; then
  [[ -z ${backup_upload_journal} && ${runtime_recovery_phase} == none ]] || fail "Terminal backup evidence cannot coexist with upload-cleanup ownership."
  if [[ ${runtime_operation_phase} != original-restored ]]; then
    restore_original_runtime_state || fail "Terminal backup could not restore its exact original runtime state."
  fi
  finish_backup_transaction "${backup_transaction_phase}" "${evidence}" || fail "Terminal backup publication remains unresolved; no new backup was created."
  printf '%s\n' "Mochirii Forums terminal backup publication reconciled."
  exit 0
fi

if [[ ${runtime_recovery_phase} == cleanup-proved ]]; then
  if [[ -n ${backup_upload_journal} ]]; then
    clear_backup_upload_journal "${backup_upload_journal}" || fail "Proved recovery-upload journal could not be durably retired."
    backup_upload_journal=""
  fi
  backup_runtime_recovery_command resume-runtime - || fail "Proved backup runtime recovery could not resume."
  runtime_recovery_phase=none
  runtime_recovery_journal_name=-
  runtime_recovery_journal_sha=-
fi

prove_running_backup_identity || fail "Protected backup runtime differs from the exact current production selection."
if [[ -n ${backup_upload_journal} ]]; then
  if ! reconcile_backup_upload_journal "${backup_upload_journal}"; then
    fail "Prior recovery-upload cleanup remains unresolved; backup is contained."
  fi
  backup_runtime_recovery_command complete-cleanup "${backup_upload_journal}" || fail "Recovery-upload terminal absence could not be durably committed."
  clear_backup_upload_journal "${backup_upload_journal}" || fail "Recovery-upload journal could not be durably retired after terminal absence proof."
  backup_upload_journal=""
  backup_runtime_recovery_command resume-runtime - || fail "Recovery-upload cleanup could not resume its prepared backup transaction."
fi

prove_running_backup_identity || fail "Protected backup runtime changed during cleanup recovery."
readarray -t backup_transaction_contract < <(backup_transaction_command inspect)
[[ ${#backup_transaction_contract[@]} -eq 19 && ${backup_transaction_contract[5]} == none && ${backup_transaction_contract[6]} == - && ${backup_transaction_contract[7]} == - ]] || fail "Backup runtime recovery did not return to an exact cleanup-free state."
runtime_operation_phase="${backup_transaction_contract[16]}"
runtime_operation_label="${backup_transaction_contract[17]}"
runtime_operation_token="${backup_transaction_contract[18]}"
[[ -z "$(find "${evidence_root}" -maxdepth 1 -name '*-backup-upload-cleanup-required.json' -print -quit 2>/dev/null || true)" ]] || fail "Recovery-upload cleanup journal survived prepared-state recovery."
[[ ${backup_transaction_phase} == prepared && ${runtime_operation_phase} == idle ]] || fail "New backup work lacks an exact idle prepared transaction."
record_event started || fail "Protected backup event evidence could not be initialized."
backup_event_started=true
candidate="$(mktemp "${evidence_root}/.${commit}-${configuration}-${timestamp}-backup.XXXXXXXX.json")"

if [[ -z ${marker_file} ]]; then
  backup_upload_transaction="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${backup_upload_transaction} =~ ^[0-9a-f]{32}$ ]] || fail "Recovery-upload transaction identifier is malformed."
  backup_upload_journal="${evidence_root}/${commit}-${configuration}-${backup_upload_transaction}-backup-upload-cleanup-required.json"
  create_backup_upload_journal "${backup_upload_transaction}" "${backup_upload_journal}" || fail "Recovery-upload cleanup journal could not be durably pre-armed."
  backup_runtime_recovery_command bind-cleanup "${backup_upload_journal}" || fail "Recovery-upload cleanup journal could not be bound to its backup transaction."
  backup_upload_journal_base64="$(validate_backup_upload_journal "${backup_upload_journal}")" || fail "Recovery-upload cleanup journal validation failed."
  [[ ${#backup_upload_journal_base64} -le 8192 && ${backup_upload_journal_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Recovery-upload cleanup journal encoding is malformed."
  recovery_upload_state="$(mktemp "${evidence_root}/.recovery-upload-${commit}-${configuration}.XXXXXXXX.json")"
  if ! run_container_command prepare-backup 600 "prepare-backup-marker.rb" "${recovery_upload_state}" bash -lc 'export MOCHIRII_RECOVERY_UPLOAD_ACTION=prepare MOCHIRII_RECOVERY_UPLOAD_TRANSACTION_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-backup-marker.rb"' bash "${backup_upload_journal_base64}"; then
    fail "Backup recovery-upload preparation failed; raw runtime output was suppressed."
  fi
  [[ -f ${recovery_upload_state} && ! -L ${recovery_upload_state} && "$(stat -c '%U:%G %a' "${recovery_upload_state}")" == "root:root 600" ]] || fail "Backup recovery-upload state is unsafe."
  [[ "$(stat -c '%s' "${recovery_upload_state}")" -le 4096 ]] || fail "Backup recovery-upload state exceeds its byte boundary."
  recovery_upload_included=true
fi
normal_upload_inventory_before="$(mktemp "${evidence_root}/.normal-upload-inventory-${commit}-${configuration}.XXXXXXXX.json")"
if ! run_container_command inventory-before 600 "normal-upload-inventory.rb" "${normal_upload_inventory_before}" bash -lc 'export MOCHIRII_BACKUP_INVENTORY_ONLY=true; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"'; then
  fail "Normal-upload inventory failed before backup; raw runtime output was suppressed."
fi
normal_upload_inventory_base64="$(python3 -B - "${normal_upload_inventory_before}" <<'PY'
import base64
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.stat(follow_symlinks=False)
if not path.is_file() or path.is_symlink() or metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_mode & 0o077:
    raise SystemExit("normal upload inventory evidence is unsafe")
raw = path.read_bytes()
if len(raw) > 2048:
    raise SystemExit("normal upload inventory evidence exceeds its byte boundary")
document = json.loads(raw)
required = {"normalUploadInventoryCount", "normalUploadInventorySha256"}
if set(document) != required or type(document.get("normalUploadInventoryCount")) is not int or not 0 <= document["normalUploadInventoryCount"] <= 10_000:
    raise SystemExit("normal upload inventory evidence schema differs")
if re.fullmatch(r"[0-9a-f]{64}", str(document.get("normalUploadInventorySha256", ""))) is None:
    raise SystemExit("normal upload inventory evidence digest is malformed")
canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if raw != canonical:
    raise SystemExit("normal upload inventory evidence is not canonical")
print(base64.b64encode(raw).decode("ascii"))
PY
)" || fail "Normal-upload inventory evidence validation failed."
[[ ${#normal_upload_inventory_base64} -le 4096 && ${normal_upload_inventory_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Normal-upload inventory evidence encoding is malformed."
if ! run_container_command create-backup 2400 "discourse backup" /dev/null discourse backup; then
  fail "Application backup failed; raw runtime output was suppressed."
fi
if ! run_container_command verify-backup 600 "verify-backup.rb" "${candidate}" bash -lc 'export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"' bash "${normal_upload_inventory_base64}"; then
  fail "Backup validation failed; raw runtime output was suppressed."
fi
if [[ ${recovery_upload_included} == true ]]; then
  if ! reconcile_backup_upload_journal "${backup_upload_journal}"; then
    fail "Backup recovery-upload cleanup failed; raw runtime output was suppressed."
  fi
  backup_runtime_recovery_command complete-cleanup "${backup_upload_journal}" || fail "Backup recovery-upload terminal absence could not be durably committed."
  clear_backup_upload_journal "${backup_upload_journal}" || fail "Backup recovery-upload journal could not be durably retired."
  backup_upload_journal=""
  backup_runtime_recovery_command resume-runtime - || fail "Backup transaction could not resume after recovery-upload cleanup."
  recovery_upload_deleted=true
fi
bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Runtime assets changed during backup verification."
python3 - "${candidate}" "${commit}" "${configuration}" "${production_config}" "${restore_config}" "${theme_archive}" "${mail_metadata_plugin}" "${release_record}" "${discourse_connect}" "${marker_file}" "${marker_sha}" "${recovery_upload_state:--}" "${recovery_upload_included}" "${recovery_upload_deleted}" "${normal_upload_inventory_before}" <<'PY' >/dev/null
import base64
import hashlib
import json
import os
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
if document.get("repositoryCommit") != sys.argv[2]:
    raise SystemExit("Backup evidence is not bound to the running release.")
if document.get("privateAdminRetrievalUrlPresent") is not True:
    raise SystemExit("Backup evidence lacks protected retrieval.")
if document.get("anonymousRetrievalDenied") is not True or document.get("anonymousCdnRetrievalDenied") is not True or document.get("backupPrefix") != "backups/":
    raise SystemExit("Backup privacy evidence is incomplete.")
if document.get("size", 0) <= 0 or not re.fullmatch(r"[0-9a-f]{64}", document.get("sha256", "")):
    raise SystemExit("Backup integrity evidence is incomplete.")
inventory_path = pathlib.Path(sys.argv[15])
inventory_metadata = inventory_path.stat(follow_symlinks=False)
if not inventory_path.is_file() or inventory_path.is_symlink() or inventory_metadata.st_uid != 0 or inventory_metadata.st_gid != 0 or inventory_metadata.st_mode & 0o077 or inventory_metadata.st_size > 2048:
    raise SystemExit("Normal upload inventory evidence is unsafe")
inventory_bytes = inventory_path.read_bytes()
inventory = json.loads(inventory_bytes)
if set(inventory) != {"normalUploadInventoryCount", "normalUploadInventorySha256"}:
    raise SystemExit("Normal upload inventory evidence schema differs")
if type(inventory.get("normalUploadInventoryCount")) is not int or not 0 <= inventory["normalUploadInventoryCount"] <= 10_000:
    raise SystemExit("Normal upload inventory count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(inventory.get("normalUploadInventorySha256", ""))):
    raise SystemExit("Normal upload inventory digest is malformed")
if inventory_bytes != json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n":
    raise SystemExit("Normal upload inventory evidence is not canonical")
if document.get("normalUploadInventoryCount") != inventory["normalUploadInventoryCount"] or document.get("normalUploadInventorySha256") != inventory["normalUploadInventorySha256"]:
    raise SystemExit("Normal upload inventory changed across backup")
def digest(value):
    return hashlib.sha256(pathlib.Path(value).read_bytes()).hexdigest()
release = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
if release.get("repositoryCommit") != sys.argv[2] or release.get("productionConfigurationSha256") != sys.argv[3]:
    raise SystemExit("Release evidence tuple changed")
if sys.argv[9] not in {"true", "false"}:
    raise SystemExit("Activation evidence is malformed")
marker_file = sys.argv[10] or None
marker_sha = sys.argv[11] or None
if sys.argv[13] not in {"true", "false"} or sys.argv[14] not in {"true", "false"}:
    raise SystemExit("Recovery upload evidence flags are malformed")
recovery_included = sys.argv[13] == "true"
recovery_deleted = sys.argv[14] == "true"
if recovery_included:
    state_path = pathlib.Path(sys.argv[12])
    if not state_path.is_file() or state_path.is_symlink() or state_path.stat().st_uid != 0 or state_path.stat().st_mode & 0o077 or state_path.stat().st_size > 4096:
        raise SystemExit("Recovery upload state evidence is unsafe")
    state_bytes = state_path.read_bytes()
    recovery_state = json.loads(state_bytes)
    required_state = {
        "schemaVersion", "repositoryCommit", "uploadId", "uploadSha1", "originalFilename",
        "objectPath", "tombstonePath", "contentSha256", "publicUrlSha256",
    }
    if set(recovery_state) != required_state or recovery_state.get("schemaVersion") != 1 or recovery_state.get("repositoryCommit") != sys.argv[2]:
        raise SystemExit("Recovery upload state evidence differs")
    if type(recovery_state.get("uploadId")) is not int or recovery_state["uploadId"] <= 0:
        raise SystemExit("Recovery upload state identifier is malformed")
    marker_base = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==", validate=True)
    marker_comment = f"mochirii-recovery-{sys.argv[2]}".encode("ascii")
    marker_bytes = marker_base[:-1] + b"!\xfe" + bytes([len(marker_comment)]) + marker_comment + b"\x00;"
    expected_sha1 = hashlib.sha1(marker_bytes).hexdigest()
    if recovery_state.get("uploadSha1") != expected_sha1 or recovery_state.get("contentSha256") != hashlib.sha256(marker_bytes).hexdigest():
        raise SystemExit("Recovery upload state content identity differs")
    if recovery_state.get("originalFilename") != f"mochirii-recovery-{sys.argv[2][:12]}.gif":
        raise SystemExit("Recovery upload state filename differs")
    object_path = recovery_state.get("objectPath", "")
    if not re.fullmatch(rf"original/[1-9][0-9]*X/(?:[0-9a-f]/)*{expected_sha1}[.]gif", object_path):
        raise SystemExit("Recovery upload state object path differs")
    if recovery_state.get("tombstonePath") != f"tombstone/{object_path}":
        raise SystemExit("Recovery upload state tombstone path differs")
    if not re.fullmatch(r"[0-9a-f]{64}", recovery_state.get("publicUrlSha256", "")):
        raise SystemExit("Recovery upload state URL identity is malformed")
    canonical_state = json.dumps(recovery_state, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if state_bytes != canonical_state or not recovery_deleted:
        raise SystemExit("Recovery upload was not exactly sealed and deleted after backup")
    recovery_state_sha = hashlib.sha256(state_bytes).hexdigest()
else:
    if sys.argv[12] != "-" or recovery_deleted:
        raise SystemExit("Clean backup has unexpected recovery-upload evidence")
    recovery_state = None
    recovery_state_sha = None
document.update(
    {
        "schemaVersion": 3,
        "productionConfigurationSha256": sys.argv[3],
        "restoreConfigurationSha256": digest(sys.argv[5]),
        "themeArchiveSha256": digest(sys.argv[6]),
        "mailMetadataPluginSha256": digest(sys.argv[7]),
        "releaseEvidenceFile": pathlib.Path(sys.argv[8]).name,
        "releaseEvidenceSha256": digest(sys.argv[8]),
        "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
        "discourseRevision": "cbf996f65aae3da1843224aa624bcd9a225931ac",
        "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
        "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
        "discourseConnectEnabled": sys.argv[9] == "true",
        "memberRolloutMarkerFile": marker_file,
        "memberRolloutMarkerSha256": marker_sha,
        "recoveryUploadIncluded": recovery_included,
        "recoveryUploadState": recovery_state,
        "recoveryUploadStateSha256": recovery_state_sha,
        "recoveryUploadDeletedAfterBackup": recovery_deleted,
    }
)
path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
rm -f -- "${normal_upload_inventory_before}"
normal_upload_inventory_before=""
release_archive_inspection="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "${release_dir}/scripts/historical-release-disaster-recovery.py" inspect \
  --archive "${release_archive}" --expected-commit "${commit}")" || fail "Backup release archive identity inspection failed."
[[ ${#release_archive_inspection} -le 4096 ]] || fail "Backup release archive identity exceeds its byte boundary."
dr_payload="$(mktemp "${evidence_root}/.disaster-recovery-payload-${commit}-${configuration}.XXXXXXXX.json")"
python3 -B - "${candidate}" "${release_record}" "${release_archive}" "${release_archive_inspection}" "${dr_payload}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys

backup_path = pathlib.Path(sys.argv[1])
release_path = pathlib.Path(sys.argv[2])
archive_path = pathlib.Path(sys.argv[3])
inspection = json.loads(sys.argv[4])
output = pathlib.Path(sys.argv[5])
backup = json.loads(backup_path.read_text(encoding="utf-8"))
release = json.loads(release_path.read_text(encoding="utf-8"))
commit = backup.get("repositoryCommit", "")
configuration = backup.get("productionConfigurationSha256", "")
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", configuration):
    raise SystemExit("disaster-recovery release tuple is malformed")
if release.get("repositoryCommit") != commit or release.get("productionConfigurationSha256") != configuration:
    raise SystemExit("disaster-recovery release evidence tuple differs")
inspection_keys = {
    "schemaVersion", "repositoryCommit", "repositoryTree", "releaseArchiveSha256",
    "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
    "releaseArchiveSourceFormat", "containsSecrets", "containsSignedUrls",
    "ordinaryDeploymentRequiresCurrentMain", "historicalReleaseAdoptionScope",
}
if set(inspection) != inspection_keys or inspection.get("schemaVersion") != 1:
    raise SystemExit("disaster-recovery release archive inspection schema differs")
archive_sha = inspection.get("releaseArchiveSha256", "")
archive_bytes = inspection.get("releaseArchiveBytes")
repository_tree = inspection.get("repositoryTree", "")
manifest_sha = inspection.get("releaseArchiveContentManifestSha256", "")
if (
    inspection.get("repositoryCommit") != commit
    or not re.fullmatch(r"[0-9a-f]{40}", repository_tree)
    or not re.fullmatch(r"[0-9a-f]{64}", archive_sha)
    or not isinstance(archive_bytes, int)
    or isinstance(archive_bytes, bool)
    or not 1 <= archive_bytes <= 64 * 1024 * 1024
    or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha)
    or inspection.get("releaseArchiveSourceFormat") != "git-archive-tar-v1"
    or inspection.get("containsSecrets") is not False
    or inspection.get("containsSignedUrls") is not False
    or inspection.get("ordinaryDeploymentRequiresCurrentMain") is not True
    or inspection.get("historicalReleaseAdoptionScope") != "clean-target-disaster-recovery-only"
):
    raise SystemExit("disaster-recovery release archive identity differs")
archive_metadata = archive_path.stat(follow_symlinks=False)
if not archive_path.is_file() or archive_path.is_symlink() or archive_metadata.st_uid != 0 or archive_metadata.st_gid != 0 or archive_metadata.st_mode & 0o022:
    raise SystemExit("disaster-recovery release archive is unsafe")
if archive_metadata.st_size != archive_bytes or hashlib.sha256(archive_path.read_bytes()).hexdigest() != archive_sha:
    raise SystemExit("disaster-recovery release archive bytes differ")
for key, expected in (
    ("repositoryTree", repository_tree),
    ("releaseArchiveSha256", archive_sha),
    ("releaseArchiveBytes", archive_bytes),
    ("releaseArchiveContentManifestSha256", manifest_sha),
):
    if release.get(key) != expected:
        raise SystemExit(f"disaster-recovery release evidence {key} differs")
archive_key = f"backups/recovery-releases/archives/{archive_sha}.tar"
authority = {
    "schemaVersion": 1,
    "repository": "Mochirii-Wushu/Mochirii-Forums",
    "repositoryCommit": commit,
    "repositoryTree": repository_tree,
    "productionConfigurationSha256": configuration,
    "releaseArchiveSha256": archive_sha,
    "releaseArchiveBytes": archive_bytes,
    "releaseArchiveContentManifestSha256": manifest_sha,
    "releaseArchiveObjectKey": archive_key,
    "releaseArchiveSourceFormat": "git-archive-tar-v1",
    "containsSecrets": False,
    "containsSignedUrls": False,
    "ordinaryDeploymentRequiresCurrentMain": True,
    "historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
}
authority_payload = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
authority_sha = hashlib.sha256(authority_payload).hexdigest()
document = {
    "schemaVersion": 2,
    "backupLastModified": backup.get("lastModified"),
    "repositoryCommit": commit,
    "repositoryTree": repository_tree,
    "productionConfigurationSha256": configuration,
    "backupFilename": backup.get("filename"),
    "backupSize": backup.get("size"),
    "backupSha256": backup.get("sha256"),
    "backupEvidenceCoreSha256": hashlib.sha256(backup_path.read_bytes()).hexdigest(),
    "normalUploadInventoryCount": backup.get("normalUploadInventoryCount"),
    "normalUploadInventorySha256": backup.get("normalUploadInventorySha256"),
    "releaseEvidenceFile": backup.get("releaseEvidenceFile"),
    "releaseEvidenceSha256": backup.get("releaseEvidenceSha256"),
    "releaseArchiveSha256": archive_sha,
    "releaseArchiveBytes": archive_bytes,
    "releaseArchiveContentManifestSha256": manifest_sha,
    "releaseArchiveObjectKey": archive_key,
    "releaseArchiveSourceFormat": "git-archive-tar-v1",
    "releaseSourceAuthorityObjectKey": f"backups/recovery-releases/authorities/{authority_sha}.json",
    "releaseSourceAuthoritySha256": authority_sha,
    "restoreConfigurationSha256": backup.get("restoreConfigurationSha256"),
    "themeArchiveSha256": backup.get("themeArchiveSha256"),
    "mailMetadataPluginSha256": backup.get("mailMetadataPluginSha256"),
    "discourseDockerRevision": backup.get("discourseDockerRevision"),
    "discourseRevision": backup.get("discourseRevision"),
    "dockerManagerRevision": backup.get("dockerManagerRevision"),
    "baseImageDigest": backup.get("baseImageDigest"),
    "discourseConnectEnabled": backup.get("discourseConnectEnabled"),
    "memberRolloutMarkerFile": backup.get("memberRolloutMarkerFile"),
    "memberRolloutMarkerSha256": backup.get("memberRolloutMarkerSha256"),
    "anonymousRetrievalDenied": backup.get("anonymousRetrievalDenied"),
    "anonymousCdnRetrievalDenied": backup.get("anonymousCdnRetrievalDenied"),
    "recoveryUploadIncluded": backup.get("recoveryUploadIncluded"),
    "recoveryUploadState": backup.get("recoveryUploadState"),
    "recoveryUploadStateSha256": backup.get("recoveryUploadStateSha256"),
    "recoveryUploadDeletedAfterBackup": backup.get("recoveryUploadDeletedAfterBackup"),
    "cleanHostAdoptionRequiresEmptyPersistentData": True,
    "containsSecrets": False,
    "containsSignedUrls": False,
    "releaseArchiveContainsSecrets": False,
    "ordinaryDeploymentRequiresCurrentMain": True,
    "historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
}
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
with output.open("wb") as target:
    target.write(payload)
    target.flush()
    os.fsync(target.fileno())
os.chmod(output, 0o600, follow_symlinks=False)
PY
dr_payload_base64="$(base64 --wrap=0 -- "${dr_payload}")"
[[ ${#dr_payload_base64} -le 65536 && ${dr_payload_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Disaster-recovery evidence encoding is malformed."
dr_result="$(mktemp "${evidence_root}/.disaster-recovery-result-${commit}-${configuration}.XXXXXXXX.json")"
if ! run_container_command publish-recovery-evidence 600 "publish-disaster-recovery-evidence.rb" "${dr_result}" bash -lc 'export MOCHIRII_DR_EVIDENCE_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/publish-disaster-recovery-evidence.rb"' bash "${dr_payload_base64}"; then
  fail "Disaster-recovery evidence publication failed; raw runtime output was suppressed."
fi
python3 -B - "${candidate}" "${dr_payload}" "${dr_result}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys

backup_path = pathlib.Path(sys.argv[1])
payload_path = pathlib.Path(sys.argv[2])
result_path = pathlib.Path(sys.argv[3])
backup = json.loads(backup_path.read_text(encoding="utf-8"))
payload = json.loads(payload_path.read_text(encoding="utf-8"))
result = json.loads(result_path.read_text(encoding="utf-8"))
required = {
    "schemaVersion", "evidenceObjectKey", "evidenceObjectSha256",
    "pointerObjectKey", "pointerObjectSha256", "releaseArchiveObjectKey",
    "releaseArchiveSha256", "releaseArchiveBytes", "releaseSourceAuthorityObjectKey",
    "releaseSourceAuthoritySha256", "immutableEvidencePublished",
    "immutableReleaseArchivePublished", "immutableReleaseSourceAuthorityPublished",
    "pointerSelected", "privateAclPassed",
}
if set(result) != required or result.get("schemaVersion") != 2:
    raise SystemExit("disaster-recovery publication result schema differs")
evidence_sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
if result.get("evidenceObjectKey") != f"backups/recovery-evidence/records/{evidence_sha}.json":
    raise SystemExit("disaster-recovery evidence object key differs")
if result.get("evidenceObjectSha256") != evidence_sha:
    raise SystemExit("disaster-recovery evidence object digest differs")
if result.get("pointerObjectKey") != "backups/recovery-evidence/current.json":
    raise SystemExit("disaster-recovery pointer object key differs")
pointer = {
    "schemaVersion": 2,
    "repositoryCommit": payload["repositoryCommit"],
    "repositoryTree": payload["repositoryTree"],
    "productionConfigurationSha256": payload["productionConfigurationSha256"],
    "backupFilename": payload["backupFilename"],
    "backupSha256": payload["backupSha256"],
    "evidenceObjectKey": result["evidenceObjectKey"],
    "evidenceObjectSha256": evidence_sha,
    "releaseArchiveObjectKey": result["releaseArchiveObjectKey"],
    "releaseArchiveSha256": result["releaseArchiveSha256"],
    "releaseArchiveBytes": result["releaseArchiveBytes"],
    "releaseArchiveContentManifestSha256": payload["releaseArchiveContentManifestSha256"],
    "releaseSourceAuthorityObjectKey": result["releaseSourceAuthorityObjectKey"],
    "releaseSourceAuthoritySha256": result["releaseSourceAuthoritySha256"],
}
pointer_bytes = json.dumps(pointer, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if result.get("pointerObjectSha256") != hashlib.sha256(pointer_bytes).hexdigest():
    raise SystemExit("disaster-recovery pointer object digest differs")
if (
    result.get("releaseArchiveObjectKey") != payload["releaseArchiveObjectKey"]
    or result.get("releaseArchiveSha256") != payload["releaseArchiveSha256"]
    or result.get("releaseArchiveBytes") != payload["releaseArchiveBytes"]
    or result.get("releaseSourceAuthorityObjectKey") != payload["releaseSourceAuthorityObjectKey"]
    or result.get("releaseSourceAuthoritySha256") != payload["releaseSourceAuthoritySha256"]
):
    raise SystemExit("disaster-recovery release publication identity differs")
if not all(result.get(key) is True for key in (
    "immutableEvidencePublished", "immutableReleaseArchivePublished",
    "immutableReleaseSourceAuthorityPublished", "pointerSelected", "privateAclPassed",
)):
    raise SystemExit("disaster-recovery publication proof is incomplete")
backup.update(
    {
        "disasterRecoveryEvidencePublished": True,
        "disasterRecoveryEvidenceObjectKey": result["evidenceObjectKey"],
        "disasterRecoveryEvidenceObjectSha256": evidence_sha,
        "disasterRecoveryPointerSelected": True,
        "disasterRecoveryPointerObjectKey": result["pointerObjectKey"],
        "disasterRecoveryPointerObjectSha256": result["pointerObjectSha256"],
        "disasterRecoveryPrivateAclPassed": True,
        "disasterRecoveryRepositoryTree": payload["repositoryTree"],
        "disasterRecoveryReleaseArchivePublished": True,
        "disasterRecoveryReleaseArchiveObjectKey": result["releaseArchiveObjectKey"],
        "disasterRecoveryReleaseArchiveSha256": result["releaseArchiveSha256"],
        "disasterRecoveryReleaseArchiveBytes": result["releaseArchiveBytes"],
        "disasterRecoveryReleaseArchiveContentManifestSha256": payload["releaseArchiveContentManifestSha256"],
        "disasterRecoveryReleaseArchiveSourceFormat": payload["releaseArchiveSourceFormat"],
        "disasterRecoveryReleaseSourceAuthorityPublished": True,
        "disasterRecoveryReleaseSourceAuthorityObjectKey": result["releaseSourceAuthorityObjectKey"],
        "disasterRecoveryReleaseSourceAuthoritySha256": result["releaseSourceAuthoritySha256"],
        "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain": True,
        "disasterRecoveryHistoricalReleaseAdoptionScope": payload["historicalReleaseAdoptionScope"],
    }
)
backup_path.write_text(json.dumps(backup, sort_keys=True, indent=2) + "\n", encoding="utf-8")
descriptor = os.open(backup_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
rm -f -- "${dr_payload}" "${dr_result}"
dr_payload=""
dr_result=""
[[ -z ${recovery_upload_state} || ! -f ${recovery_upload_state} ]] || rm -f -- "${recovery_upload_state}"
recovery_upload_state=""
python3 -B - "${candidate}" "${evidence}" <<'PY'
import os
import pathlib
import sys

candidate = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2])
candidate.chmod(0o600)
metadata = candidate.stat(follow_symlinks=False)
if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077:
    raise SystemExit("backup evidence candidate is unsafe")
descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.link(candidate, evidence, follow_symlinks=False)
directory = os.open(evidence.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
    candidate.unlink()
    os.fsync(directory)
finally:
    os.close(directory)
PY
candidate=""
readarray -t backup_transaction_contract < <(backup_transaction_command inspect)
[[ ${#backup_transaction_contract[@]} -eq 19 ]] || fail "Terminal backup runtime contract is malformed."
runtime_operation_phase="${backup_transaction_contract[16]}"
runtime_operation_label="${backup_transaction_contract[17]}"
runtime_operation_token="${backup_transaction_contract[18]}"
restore_original_runtime_state || fail "Protected backup could not restore its exact original runtime state."
finish_backup_transaction "${backup_transaction_phase}" "${evidence}" || fail "Protected terminal backup publication could not be completed."
backup_success=true
printf '%s\n' "Mochirii Forums protected backup verified."
