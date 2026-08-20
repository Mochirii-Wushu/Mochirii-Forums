#!/usr/bin/env bash
# Shared bounded process and DNS-01 transaction boundary for media certificate work.

media_fail() {
  printf '%s\n' "$1" >&2
  return 1
}

media_boundary_initialize() {
  local operation_budget="$1"
  local cleanup_reserve="$2"
  [[ ${operation_budget} =~ ^[1-9][0-9]{2,4}$ ]] || media_fail "Certificate operation budget is malformed."
  [[ ${cleanup_reserve} =~ ^[1-9][0-9]{1,3}$ ]] || media_fail "Certificate cleanup reserve is malformed."
  (( cleanup_reserve < operation_budget )) || media_fail "Certificate cleanup reserve exceeds its operation budget."
  readonly MEDIA_OPERATION_STARTED_EPOCH="$(date +%s)"
  readonly MEDIA_OPERATION_BUDGET_SECONDS="${operation_budget}"
  readonly MEDIA_CLEANUP_RESERVE_SECONDS="${cleanup_reserve}"
  readonly MEDIA_ACME_JOURNAL="/var/lib/mochirii/forums/acme-challenge-transaction.json"
  readonly MEDIA_EVENT_LOG="/var/lib/mochirii/forums/logs/media-certificate-events.log"
  MEDIA_ACTIVE_PID=""
  MEDIA_ACTIVE_LABEL=""
  MEDIA_SIGNAL_HANDLING=false
  install -d -m 0700 -o root -g root /var/lib/mochirii/forums/logs
  [[ -x /usr/local/libexec/mochirii-forums/durable-event.py && ! -L /usr/local/libexec/mochirii-forums/durable-event.py ]] || media_fail "Durable certificate event helper is absent."
}

media_record_event() {
  local operation="$1"
  local status="$2"
  [[ ${operation} =~ ^[a-z-]{1,40}$ ]] || return 1
  [[ ${status} == started || ${status} == passed || ${status} == failed || ${status} == blocked ]] || return 1
  python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
    --path "${MEDIA_EVENT_LOG}" --operation "${operation}" --status "${status}" >/dev/null
}

media_remaining_seconds() {
  local requested="$1"
  local reserve="${2:-${MEDIA_CLEANUP_RESERVE_SECONDS}}"
  [[ ${requested} =~ ^[1-9][0-9]{0,4}$ && ${reserve} =~ ^[0-9]{1,4}$ ]] || return 1
  local elapsed remaining
  elapsed=$(( $(date +%s) - MEDIA_OPERATION_STARTED_EPOCH ))
  remaining=$(( MEDIA_OPERATION_BUDGET_SECONDS - elapsed - reserve ))
  (( remaining > 0 )) || return 1
  if (( requested < remaining )); then
    printf '%s\n' "${requested}"
  else
    printf '%s\n' "${remaining}"
  fi
}

media_cleanup_seconds() {
  local elapsed remaining
  elapsed=$(( $(date +%s) - MEDIA_OPERATION_STARTED_EPOCH ))
  remaining=$(( MEDIA_OPERATION_BUDGET_SECONDS - elapsed ))
  (( remaining > 0 )) || return 1
  if (( remaining < MEDIA_CLEANUP_RESERVE_SECONDS )); then
    printf '%s\n' "${remaining}"
  else
    printf '%s\n' "${MEDIA_CLEANUP_RESERVE_SECONDS}"
  fi
}

media_terminate_active_group() {
  local pid="${MEDIA_ACTIVE_PID:-}"
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
  if kill -0 "${pid}" >/dev/null 2>&1; then
    return 1
  fi
  MEDIA_ACTIVE_PID=""
  MEDIA_ACTIVE_LABEL=""
}

media_run_bounded() {
  local label="$1"
  local requested="$2"
  shift 2
  [[ ${label} =~ ^[a-z-]{1,40}$ ]] || return 1
  local seconds status
  seconds="$(media_remaining_seconds "${requested}")" || return 1
  media_record_event "${label}" started || return 1
  # Command output is intentionally discarded. Certbot, package managers, and
  # provider clients may emit credentials or provider payloads; no raw
  # transcript may survive a crash, SIGKILL, or host restart.
  (exec 200>&- 201>&-; exec setsid timeout --signal=TERM --kill-after=30s "${seconds}s" "$@") >/dev/null 2>&1 &
  MEDIA_ACTIVE_PID=$!
  MEDIA_ACTIVE_LABEL="${label}"
  set +e
  wait "${MEDIA_ACTIVE_PID}"
  status=$?
  set -e
  MEDIA_ACTIVE_PID=""
  MEDIA_ACTIVE_LABEL=""
  if (( status != 0 )); then
    media_record_event "${label}" failed || true
    return 1
  fi
  media_record_event "${label}" passed
}

media_run_cleanup_bounded() {
  local label="$1"
  shift
  local seconds status
  seconds="$(media_cleanup_seconds)" || return 1
  (( seconds >= 30 )) || return 1
  (exec 200>&- 201>&-; exec setsid timeout --signal=TERM --kill-after=20s "${seconds}s" "$@") >/dev/null 2>&1 &
  MEDIA_ACTIVE_PID=$!
  MEDIA_ACTIVE_LABEL="${label}"
  set +e
  wait "${MEDIA_ACTIVE_PID}"
  status=$?
  set -e
  MEDIA_ACTIVE_PID=""
  MEDIA_ACTIVE_LABEL=""
  (( status == 0 ))
}

media_reconcile_acme() {
  local helper="$1"
  local credentials="$2"
  [[ -e ${MEDIA_ACME_JOURNAL} || -L ${MEDIA_ACME_JOURNAL} ]] || return 0
  if ! media_run_cleanup_bounded acme-reconcile python3 -B "${helper}" --credentials "${credentials}" --action reconcile; then
    media_record_event acme-cleanup blocked || true
    return 1
  fi
  [[ ! -e ${MEDIA_ACME_JOURNAL} && ! -L ${MEDIA_ACME_JOURNAL} ]]
}

media_run_certbot_dns_transaction() {
  local helper="$1"
  local credentials="$2"
  local requested="$3"
  shift 3
  media_reconcile_acme "${helper}" "${credentials}" || return 1
  media_run_bounded acme-prepare 90 python3 -B "${helper}" --credentials "${credentials}" --action start || return 1
  [[ -f ${MEDIA_ACME_JOURNAL} && ! -L ${MEDIA_ACME_JOURNAL} ]] || return 1
  local command_status=0 cleanup_status=0
  media_run_bounded certbot-dns "${requested}" "$@" || command_status=$?
  media_reconcile_acme "${helper}" "${credentials}" || cleanup_status=$?
  if (( cleanup_status != 0 )); then
    media_record_event certbot-dns blocked || true
    return 1
  fi
  (( command_status == 0 ))
}

media_handle_signal() {
  if [[ ${MEDIA_SIGNAL_HANDLING:-false} == true ]]; then
    exit 125
  fi
  MEDIA_SIGNAL_HANDLING=true
  trap - HUP INT TERM
  local helper="${MEDIA_ACME_HELPER:-}"
  local credentials="${MEDIA_ACME_CREDENTIALS:-}"
  if ! media_terminate_active_group; then
    media_record_event certificate-operation blocked || true
    printf '%s\n' "Mochirii Forums certificate operation interruption could not terminate its bounded process group." >&2
    exit 125
  fi
  if [[ -n ${helper} && -n ${credentials} && ( -e ${MEDIA_ACME_JOURNAL} || -L ${MEDIA_ACME_JOURNAL} ) ]]; then
    if ! media_reconcile_acme "${helper}" "${credentials}"; then
      media_record_event certificate-operation blocked || true
      printf '%s\n' "Mochirii Forums certificate operation interrupted; DNS cleanup is blocked and the sealed recovery journal was retained." >&2
      exit 125
    fi
  fi
  media_record_event certificate-operation failed || true
  printf '%s\n' "Mochirii Forums certificate operation interrupted and reconciled." >&2
  exit 125
}

media_install_signal_traps() {
  trap media_handle_signal HUP INT TERM
}
