#!/usr/bin/env bash
set -euo pipefail
umask 077
set +x
export HISTFILE=/dev/null

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Administrator recovery verification must run as root through the distinct operator boundary."
[[ $# -eq 3 ]] || fail "Usage: mochirii-forums-break-glass-admin EXPECTED_COMMIT verify|send 'VERIFY MOCHIRII FORUMS ADMIN RECOVERY'"
commit="$1"
action="$2"
confirmation="$3"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Expected commit is malformed."
[[ ${action} == verify || ${action} == send ]] || fail "Administrator recovery action is malformed."
[[ ${confirmation} == "VERIFY MOCHIRII FORUMS ADMIN RECOVERY" ]] || fail "Exact administrator recovery confirmation is required."
[[ -t 0 && -t 1 && -t 2 ]] || fail "Administrator recovery requires an interactive operator console."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
active_operation_pid=""
operation_armed=false
operation_token=""

break_glass_runner_absent() {
  local token="$1"
  [[ ${token} =~ ^[0-9a-f]{32}$ ]] || return 1
  timeout --signal=TERM --kill-after=5s 30 docker exec app ruby -e '
    marker = "MOCHIRII_BREAK_GLASS_OPERATION_TOKEN=#{ARGV.fetch(0)}"
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

stop_app_safely() {
  local state inventory
  timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
  if state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)"; then
    [[ ${state} == false ]]
    return
  fi
  if inventory="$(timeout --signal=TERM --kill-after=5s 15 docker ps -a --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)"; then
    [[ -z ${inventory} ]]
    return
  fi
  return 1
}

terminate_active_group() {
  local pid="${active_operation_pid:-}"
  [[ ${pid} =~ ^[1-9][0-9]*$ ]] || return 0
  kill -TERM -- "-${pid}" >/dev/null 2>&1 || true
  local deadline=$(( $(date +%s) + 45 ))
  while kill -0 "${pid}" >/dev/null 2>&1 && (( $(date +%s) < deadline )); do
    sleep 1
  done
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill -KILL -- "-${pid}" >/dev/null 2>&1 || true
  fi
  wait "${pid}" >/dev/null 2>&1 || true
  active_operation_pid=""
  ! kill -0 "${pid}" >/dev/null 2>&1
}

handle_recovery_signal() {
  trap - HUP INT TERM
  terminate_active_group || true
  if [[ ${operation_armed} == true ]]; then
    if stop_app_safely; then
      printf '%s\n' "Mochirii Forums administrator recovery was interrupted; the application was stopped." >&2
      exit 124
    fi
    printf '%s\n' "CRITICAL: interrupted administrator recovery could not prove application containment." >&2
    exit 125
  fi
  exit 124
}

trap handle_recovery_signal HUP INT TERM

state_root=/var/lib/mochirii/forums
for active_transaction in \
  "${state_root}/deployment-mutation.json" \
  "${state_root}/deployment-transaction.json" \
  "${state_root}/backup-transaction.json" \
  "${state_root}/restore-transaction.json"; do
  [[ ! -e ${active_transaction} && ! -L ${active_transaction} ]] || fail "Administrator recovery refuses an active protected host transaction."
done
[[ -z "$(find "${state_root}/evidence" -maxdepth 1 \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) -print -quit 2>/dev/null || true)" ]] || fail "Administrator recovery refuses unresolved hosted-storage cleanup."
current_evidence=/var/lib/mochirii/forums/current-release.json
[[ -f ${current_evidence} && ! -L ${current_evidence} ]] || fail "Current release evidence is absent."
[[ "$(stat -c '%U:%G %a' "${current_evidence}")" == "root:root 600" ]] || fail "Current release evidence permissions differ."

readarray -t contract < <(python3 -B - "${current_evidence}" "${commit}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
expected_keys = {
    "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
    "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
if set(document) != expected_keys or document.get("repositoryCommit") != sys.argv[2]:
    raise SystemExit("current release identity differs")
configuration = document.get("productionConfigurationSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", configuration):
    raise SystemExit("configuration identity is malformed")
record_name = f"{sys.argv[2]}-{configuration}-release.json"
record = path.parent / "evidence" / record_name
if document.get("releaseEvidenceFile") != record_name or not record.is_file() or record.is_symlink():
    raise SystemExit("release evidence reference differs")
if record.stat().st_uid != 0 or record.stat().st_mode & 0o077:
    raise SystemExit("release evidence permissions differ")
if hashlib.sha256(record.read_bytes()).hexdigest() != document.get("releaseEvidenceSha256"):
    raise SystemExit("release evidence digest differs")
connect = document.get("discourseConnectEnabled")
if not isinstance(connect, bool):
    raise SystemExit("central login evidence is malformed")
print(configuration)
print("true" if connect else "false")
PY
)
[[ ${#contract[@]} -eq 2 ]] || fail "Current release evidence is malformed."
configuration="${contract[0]}"
discourse_connect="${contract[1]}"
release_dir="/opt/mochirii/forums/releases/${commit}"
app_config="/var/discourse/containers/releases/${commit}/${configuration}/app.yml"
[[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "Sealed recovery release is absent."
[[ -f ${app_config} && ! -L ${app_config} ]] || fail "Versioned production configuration is absent."
[[ -L /var/discourse/containers/app.yml && "$(readlink -f -- /var/discourse/containers/app.yml)" == "${app_config}" ]] || fail "Administrator recovery requires the exact production configuration."
bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh" >/dev/null 2>&1 || fail "Administrator recovery refuses an unsealed deployment checkout."
bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Administrator recovery refuses runtime-asset drift."
timeout --signal=TERM --kill-after=30s 600 bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" >/dev/null 2>&1 || fail "Administrator recovery preflight failed."
running_connect="$(timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'case "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" in true|false) printf "%s" "$DISCOURSE_ENABLE_DISCOURSE_CONNECT";; *) exit 1;; esac' 2>/dev/null)" || fail "Running central-login state is malformed."
[[ ${running_connect} == "${discourse_connect}" ]] || fail "Running central-login state differs from protected evidence."

printf '%s' "Recovery administrator email (input is hidden): " >&2
IFS= read -r -s recovery_email
printf '\n' >&2
[[ -n ${recovery_email} && ${#recovery_email} -le 254 && ${recovery_email} != *$'\n'* && ${recovery_email} != *$'\r'* ]] || fail "Recovery administrator input is malformed."
operation_status=0
operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ ${operation_token} =~ ^[0-9a-f]{32}$ ]] || fail "Administrator recovery operation identity could not be generated."
operation_armed=true
(
  exec 200>&- 201>&-
  exec setsid timeout --signal=TERM --kill-after=10s 70s \
    docker exec -i -e MOCHIRII_BREAK_GLASS_OPERATION_TOKEN="${operation_token}" app \
    timeout --signal=TERM --kill-after=10s 55s bash -lc \
    '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-break-glass-admin.rb" "$1"' \
    bash "${action}"
) <<<"${recovery_email}" >/dev/null 2>&1 &
active_operation_pid=$!
[[ "$(ps -o pgid= -p "${active_operation_pid}" | tr -d ' ')" == "${active_operation_pid}" ]] || {
  terminate_active_group || true
  unset recovery_email
  if ! stop_app_safely; then
    fail "CRITICAL: administrator recovery process-group isolation and application containment could not be proved."
  fi
  fail "Administrator recovery process-group isolation was unproved; the application was stopped."
}
wait "${active_operation_pid}" || operation_status=$?
active_operation_pid=""
unset recovery_email
if ! break_glass_runner_absent "${operation_token}"; then
  if ! stop_app_safely; then
    fail "CRITICAL: administrator recovery process termination and application containment could not be proved."
  fi
  fail "Administrator recovery process termination was unproved; the application was stopped."
fi
(( operation_status == 0 )) || fail "Recovery administrator operation failed without exposing the identity or token."
if ! timeout --signal=TERM --kill-after=30s 600 bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" >/dev/null 2>&1; then
  if ! stop_app_safely; then
    fail "CRITICAL: administrator recovery post-verification failed and application containment is unproved."
  fi
  fail "Administrator recovery post-verification failed; the application was stopped."
fi
operation_armed=false
operation_token=""
if [[ ${action} == send ]]; then
  printf '%s\n' "Mochirii Forums one-time administrator recovery email was queued; ordinary login remains closed."
else
  printf '%s\n' "Mochirii Forums recovery administrator and closed-login boundary verified."
fi
