#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

readonly deploy_user="mochirii-forums-deploy"
readonly deploy_group="mochirii-forums-deploy"
readonly operator_user="mochirii-forums-operator"
readonly operator_group="mochirii-forums-operator"
readonly state_root="/var/lib/mochirii/forums"
readonly ssh_generator_parent="/etc/systemd/system-generators"
readonly ssh_generator_mask="/etc/systemd/system-generators/sshd-socket-generator"
readonly canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"
readonly deployment_source_commit="ed9f680b0df1de28f062de1769d89d22b2644d1b"
readonly deployment_source_tree="588498dffbea91592fd4e2f10166bc11c8fe7a61"
readonly operation_started_epoch="$(date +%s)"
readonly operation_budget_seconds=2400
readonly containment_reserve_seconds=300
active_operation_pid=""
install_signal_received=false

fail() { printf '%s\n' "$1" >&2; exit 1; }

remaining_operation_seconds() {
  local requested="$1" elapsed remaining
  [[ ${requested} =~ ^[1-9][0-9]{0,3}$ ]] || return 1
  elapsed=$(( $(date +%s) - operation_started_epoch ))
  remaining=$(( operation_budget_seconds - elapsed - containment_reserve_seconds ))
  (( remaining >= 30 )) || return 1
  (( requested < remaining )) && printf '%s\n' "${requested}" || printf '%s\n' "${remaining}"
}

cleanup_operation_seconds() {
  local elapsed remaining
  elapsed=$(( $(date +%s) - operation_started_epoch ))
  remaining=$(( operation_budget_seconds - elapsed ))
  (( remaining >= 30 )) || return 1
  (( remaining < containment_reserve_seconds )) && printf '%s\n' "${remaining}" || printf '%s\n' "${containment_reserve_seconds}"
}

terminate_active_operation() {
  local pid="${active_operation_pid:-}" deadline
  [[ ${pid} =~ ^[1-9][0-9]*$ ]] || return 0
  kill -TERM -- "-${pid}" >/dev/null 2>&1 || true
  deadline=$(( $(date +%s) + 60 ))
  while kill -0 "${pid}" >/dev/null 2>&1 && (( $(date +%s) < deadline )); do sleep 1; done
  kill -0 "${pid}" >/dev/null 2>&1 && kill -KILL -- "-${pid}" >/dev/null 2>&1 || true
  wait "${pid}" >/dev/null 2>&1 || true
  ! kill -0 "${pid}" >/dev/null 2>&1
}

handle_install_signal() {
  install_signal_received=true
  [[ -n ${active_operation_pid:-} ]] || exit 124
  terminate_active_operation || true
}

run_bounded_host_operation() {
  local requested="$1" seconds status=0 pgid
  shift
  seconds="$(remaining_operation_seconds "${requested}")" || return 1
  install_signal_received=false
  (exec 200>&- 201>&-; exec setsid timeout --signal=TERM --kill-after=30s "${seconds}s" "$@") >/dev/null 2>&1 &
  active_operation_pid=$!
  pgid="$(ps -o pgid= -p "${active_operation_pid}" 2>/dev/null | tr -d ' ')" || pgid=""
  if [[ ${pgid} != "${active_operation_pid}" ]]; then terminate_active_operation || true; active_operation_pid=""; return 1; fi
  wait "${active_operation_pid}" || status=$?
  active_operation_pid=""
  [[ ${install_signal_received} == false && ${status} -eq 0 ]]
}

run_bounded_host_cleanup() {
  local seconds status=0 pgid
  seconds="$(cleanup_operation_seconds)" || return 1
  install_signal_received=false
  (exec 200>&- 201>&-; exec setsid timeout --signal=TERM --kill-after=30s "${seconds}s" "$@") >/dev/null 2>&1 &
  active_operation_pid=$!
  pgid="$(ps -o pgid= -p "${active_operation_pid}" 2>/dev/null | tr -d ' ')" || pgid=""
  if [[ ${pgid} != "${active_operation_pid}" ]]; then terminate_active_operation || true; active_operation_pid=""; return 1; fi
  wait "${active_operation_pid}" || status=$?
  active_operation_pid=""
  [[ ${status} -eq 0 ]]
}

trap handle_install_signal HUP INT TERM

atomic_install() {
  local source="$1" target="$2" mode="$3"
  python3 -B - "${source}" "${target}" "${mode}" <<'PY'
import os, pathlib, stat, tempfile, sys
source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
mode = int(sys.argv[3], 8)
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("publication source is not regular")
target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
descriptor, candidate = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
try:
    os.fchmod(descriptor, mode)
    with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
        descriptor = -1
        while chunk := reader.read(1024 * 1024): writer.write(chunk)
        writer.flush(); os.fsync(writer.fileno())
    os.chown(candidate, 0, 0); os.replace(candidate, target)
    parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)
finally:
    if descriptor >= 0: os.close(descriptor)
    try: os.unlink(candidate)
    except FileNotFoundError: pass
PY
}

retain_exact_file() {
  local source="$1" target="$2"
  if [[ -e ${target} || -L ${target} ]]; then
    [[ -f ${target} && ! -L ${target} && "$(stat -c '%U:%G %a' "${target}")" == "root:root 600" ]] || return 1
    cmp -s -- "${source}" "${target}" || return 1
  else
    atomic_install "${source}" "${target}" 0600
  fi
}

retain_disaster_recovery_sources() {
  local root="$1" commit="$2" repository_archive deployment_archive repository_tree inspection
  repository_archive="$(mktemp "${state_root}/.host-control-release-${commit}.XXXXXXXX.tar")" || return 1
  deployment_archive="$(mktemp "${state_root}/.deployment-source-${deployment_source_commit}.XXXXXXXX.tar")" || { rm -f -- "${repository_archive}"; return 1; }
  repository_tree="$(git -C "${root}" rev-parse --verify "${commit}^{tree}")" || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  [[ ${repository_tree} =~ ^[0-9a-f]{40}$ ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  git -c tar.umask=0002 -C "${root}" archive --format=tar --output="${repository_archive}" "${commit}" >/dev/null 2>&1 || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  inspection="$(python3 -B "${root}/scripts/historical-release-disaster-recovery.py" inspect --archive "${repository_archive}" --expected-commit "${commit}")" || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  (( ${#inspection} <= 4096 )) || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  python3 -B - "${inspection}" "${commit}" "${repository_tree}" <<'PY' >/dev/null || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
import json, sys
document = json.loads(sys.argv[1])
if document.get("repositoryCommit") != sys.argv[2] or document.get("repositoryTree") != sys.argv[3]:
    raise SystemExit("retained host-control archive differs from the exact Git commit tree")
PY
  [[ -d /var/discourse/.git && ! -L /var/discourse/.git ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse rev-parse --verify HEAD^{commit})" == "${deployment_source_commit}" ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse rev-parse --verify HEAD^{tree})" == "${deployment_source_tree}" ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  [[ -z "$(git -c core.fsmonitor=false -C /var/discourse status --porcelain=v1 --untracked-files=all)" ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse config --local --get remote.origin.url)" == https://github.com/discourse/discourse_docker.git ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse config --local --get remote.origin.pushurl)" == no_push://mochirii-forums-upstream ]] || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  git -c tar.umask=0002 -C /var/discourse archive --format=tar --output="${deployment_archive}" "${deployment_source_commit}" >/dev/null 2>&1 || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  install -d -m 0700 -o root -g root "/opt/mochirii/forums/host-control-releases/${commit}" /opt/mochirii/forums/deployment-source
  retain_exact_file "${repository_archive}" "/opt/mochirii/forums/host-control-releases/${commit}/mochirii-release.tar" || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  retain_exact_file "${deployment_archive}" "/opt/mochirii/forums/deployment-source/${deployment_source_commit}.tar" || { rm -f -- "${repository_archive}" "${deployment_archive}"; return 1; }
  rm -f -- "${repository_archive}" "${deployment_archive}"
}

durable_remove() {
  python3 -B - "$1" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
try: path.unlink()
except FileNotFoundError: raise SystemExit(0)
parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try: os.fsync(parent)
finally: os.close(parent)
PY
}

systemd_unit_state() {
  local verb="$1" unit="$2" output
  output="$(timeout --signal=TERM --kill-after=5s 15s systemctl "${verb}" "${unit}" 2>/dev/null || true)"
  (( ${#output} <= 32 )) || return 1
  printf '%s\n' "${output}"
}

ssh_generator_mask_is_exact() {
  [[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]] || return 1
  [[ "$(stat -c '%U:%G %a' -- "${ssh_generator_parent}")" == "root:root 755" ]] || return 1
  [[ -L ${ssh_generator_mask} && "$(readlink -- "${ssh_generator_mask}")" == /dev/null ]] || return 1
  [[ "$(stat -c '%U:%G' -- "${ssh_generator_mask}")" == root:root ]]
}

ssh_service_activation_is_exact() {
  ssh_generator_mask_is_exact || return 1
  [[ "$(systemd_unit_state is-enabled ssh.service)" == enabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.service)" == active ]] || return 1
  [[ "$(systemd_unit_state is-enabled ssh.socket)" == disabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.socket)" == inactive ]]
}

ssh_socket_activation_is_exact_predecessor() {
  [[ ! -e ${ssh_generator_mask} && ! -L ${ssh_generator_mask} ]] || return 1
  [[ "$(systemd_unit_state is-enabled ssh.service)" == disabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.service)" == active ]] || return 1
  [[ "$(systemd_unit_state is-enabled ssh.socket)" == enabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.socket)" == active ]]
}

publish_ssh_generator_mask() {
  local staging
  if [[ -e ${ssh_generator_parent} || -L ${ssh_generator_parent} ]]; then
    [[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]] || return 1
    [[ "$(stat -c '%U:%G %a' -- "${ssh_generator_parent}")" == "root:root 755" ]] || return 1
  else
    install -d -m 0755 -o root -g root "${ssh_generator_parent}" || return 1
  fi
  [[ ! -e ${ssh_generator_mask} && ! -L ${ssh_generator_mask} ]] || return 1
  staging="$(mktemp -d "${ssh_generator_parent}/.sshd-socket-generator.XXXXXXXX")" || return 1
  chmod 0700 "${staging}" || { rmdir -- "${staging}"; return 1; }
  ln -s /dev/null "${staging}/mask" || { rmdir -- "${staging}"; return 1; }
  mv -T -- "${staging}/mask" "${ssh_generator_mask}" || { rm -f -- "${staging}/mask"; rmdir -- "${staging}"; return 1; }
  rmdir -- "${staging}" || return 1
  sync -d "${ssh_generator_parent}" 2>/dev/null || true
  ssh_generator_mask_is_exact
}

restore_ssh_socket_activation_predecessor() {
  [[ "$(timeout --signal=TERM --kill-after=5s 15s systemctl show ssh.service -p KillMode --value 2>/dev/null)" == process ]] || return 1
  run_bounded_host_cleanup systemctl disable ssh.service || return 1
  durable_remove "${ssh_generator_mask}" || return 1
  run_bounded_host_cleanup systemctl daemon-reload || return 1
  run_bounded_host_cleanup systemctl enable ssh.socket || return 1
  run_bounded_host_cleanup systemctl stop ssh.service || return 1
  run_bounded_host_cleanup systemctl start ssh.socket || return 1
  run_bounded_host_cleanup systemctl start ssh.service || return 1
  ssh_socket_activation_is_exact_predecessor
}

ensure_ssh_service_activation() {
  ssh_service_activation_is_exact && return 0
  ssh_socket_activation_is_exact_predecessor || return 1
  publish_ssh_generator_mask || return 1
  if run_bounded_host_operation 60 systemctl daemon-reload &&
    run_bounded_host_operation 60 systemctl disable --now ssh.socket &&
    run_bounded_host_operation 60 systemctl enable --now ssh.service &&
    ssh_service_activation_is_exact; then
    return 0
  fi
  restore_ssh_socket_activation_predecessor || fail "OpenSSH service-activation conversion failed and exact rollback is blocked."
  fail "OpenSSH service-activation conversion failed; the exact socket-activated predecessor was restored."
}

manifest_records() {
  python3 -B - "$1" <<'PY'
import hashlib, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
document = json.loads((root / "config/host-control-manifest.v1.json").read_text(encoding="utf-8"))
if set(document) != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"} or document.get("schemaVersion") != 1:
    raise SystemExit("host-control manifest schema differs")
targets, sources = set(), set()
for group in ("coreTargets", "hostPolicyTargets", "certificateTargets"):
    rows = document.get(group)
    if not isinstance(rows, list) or not rows: raise SystemExit("host-control manifest group is empty")
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"source", "target", "mode"}: raise SystemExit("host-control target row differs")
        source, target, mode = row["source"], row["target"], row["mode"]
        if not re.fullmatch(r"(?:config|scripts)/[A-Za-z0-9._-]+", source): raise SystemExit("host-control source path differs")
        if not isinstance(target, str) or not target.startswith(("/etc/", "/usr/local/")) or ".." in pathlib.PurePosixPath(target).parts: raise SystemExit("host-control target path differs")
        if mode not in {"0440", "0644", "0755"} or source in sources or target in targets: raise SystemExit("host-control target duplicate or mode differs")
        source_path = root / source
        if not source_path.is_file() or source_path.is_symlink(): raise SystemExit("host-control source is absent or linked")
        print("\t".join((group, mode, source, target, hashlib.sha256(source_path.read_bytes()).hexdigest())))
        sources.add(source); targets.add(target)
historical_recovery = {
    "source": "scripts/historical-release-disaster-recovery.py",
    "target": "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
    "mode": "0755",
}
if historical_recovery not in document["coreTargets"]:
    raise SystemExit("host-control manifest omitted the historical disaster-recovery authority")
required_historical = {
    ("scripts/historical-recovery-scratch-reader.sh", "/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh", "0755"),
    ("scripts/host-historical-disaster-recovery.sh", "/usr/local/sbin/mochirii-forums-historical-disaster-recovery", "0755"),
    ("scripts/host-operation-lock.py", "/usr/local/libexec/mochirii-forums/host-operation-lock.py", "0755"),
}
actual_historical = {(row["source"], row["target"], row["mode"]) for row in document["coreTargets"]}
if not required_historical.issubset(actual_historical):
    raise SystemExit("host-control manifest omitted an executable historical recovery entrypoint")
PY
}

validate_repository_binding() {
  local repository_root="$1" expected_commit="$2" remote_output
  [[ ${expected_commit} =~ ^[0-9a-f]{40}$ && -d ${repository_root}/.git && ! -L ${repository_root}/.git ]] || return 1
  [[ "$(git -C "${repository_root}" rev-parse --verify HEAD^{commit})" == "${expected_commit}" ]] || return 1
  [[ "$(git -C "${repository_root}" symbolic-ref --short -q HEAD)" == main ]] || return 1
  [[ -z "$(git -c core.fsmonitor=false -C "${repository_root}" status --porcelain=v1 --untracked-files=all)" ]] || return 1
  [[ "$(git -C "${repository_root}" remote get-url origin)" == "${canonical_repository}" ]] || return 1
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
  unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
  export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0
  remote_output="$(timeout --signal=TERM --kill-after=10s 120s git -c credential.helper= -c core.askPass= \
    -c protocol.allow=never -c protocol.https.allow=always -c http.followRedirects=false \
    ls-remote --refs "${canonical_repository}" refs/heads/main 2>/dev/null)" || return 1
  [[ ${remote_output} == "${expected_commit}"$'\trefs/heads/main' ]] || return 1
  manifest_records "${repository_root}" >/dev/null
}

effective_value() { awk -v setting="$2" '$1 == setting { found=$2 } END { print found }' <<<"$1"; }
effective_allow_users() { awk '$1 == "allowusers" { for (i = 2; i <= NF; i++) { found = found (found == "" ? "" : " ") $i } } END { print found }' <<<"$1"; }

validate_user_ssh() {
  local user="$1" phase="$2" effective expected_keys expected_force expected_tty
  effective="$(timeout --signal=TERM --kill-after=5s 15s sshd -T -C "user=${user},host=forums.mochirii.com,addr=127.0.0.1")" || return 1
  [[ "$(effective_value "${effective}" authorizedkeyscommand)" == none ]] || return 1
  [[ "$(effective_value "${effective}" authorizedkeyscommanduser)" == nobody ]] || return 1
  [[ "$(effective_value "${effective}" trustedusercakeys)" == none ]] || return 1
  [[ "$(effective_value "${effective}" authorizedprincipalsfile)" == none ]] || return 1
  [[ "$(effective_value "${effective}" authorizedprincipalscommand)" == none ]] || return 1
  [[ "$(effective_value "${effective}" authorizedprincipalscommanduser)" == nobody ]] || return 1
  [[ "$(effective_value "${effective}" permituserenvironment)" == no ]] || return 1
  [[ "$(effective_value "${effective}" permituserrc)" == no ]] || return 1
  case "${user}" in
    "${operator_user}") expected_keys="${state_root}/operator/.ssh/authorized_keys"; expected_force=none; expected_tty=yes ;;
    "${deploy_user}") expected_keys="${state_root}/deploy/.ssh/authorized_keys"; expected_force=/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py; expected_tty=no ;;
    root) expected_keys=none; expected_force=none; expected_tty=no ;;
    *) return 1 ;;
  esac
  [[ "$(effective_value "${effective}" authorizedkeysfile)" == "${expected_keys}" ]] || return 1
  [[ "$(effective_value "${effective}" forcecommand)" == "${expected_force}" ]] || return 1
  [[ "$(effective_value "${effective}" disableforwarding)" == yes && "$(effective_value "${effective}" permittty)" == "${expected_tty}" ]] || return 1
  if [[ ${phase} == hardened ]]; then
    [[ "$(effective_value "${effective}" passwordauthentication)" == no ]] || return 1
    [[ "$(effective_value "${effective}" kbdinteractiveauthentication)" == no ]] || return 1
    [[ "$(effective_value "${effective}" pubkeyauthentication)" == yes ]] || return 1
    [[ "$(effective_value "${effective}" authenticationmethods)" == publickey ]] || return 1
    [[ "$(effective_allow_users "${effective}")" == "${operator_user} ${deploy_user}" ]] || return 1
    [[ ${user} != root || "$(effective_value "${effective}" permitrootlogin)" == no ]] || return 1
  else
    [[ ${user} != root && "$(effective_value "${effective}" authenticationmethods)" == publickey ]] || return 1
  fi
}

validate_prepared_ssh() { validate_user_ssh "${operator_user}" prepared && validate_user_ssh "${deploy_user}" prepared; }
validate_hardened_ssh() { validate_user_ssh root hardened && validate_user_ssh "${operator_user}" hardened && validate_user_ssh "${deploy_user}" hardened; }

install_sshd_policy() {
  local source="$1" validator="$2" target=/etc/ssh/sshd_config.d/00-00-mochirii-forums.conf
  local backup_root path index=0 valid=true
  local -a managed=("${target}" /etc/ssh/sshd_config.d/50-mochirii-forums-hardening.conf /etc/ssh/sshd_config.d/60-mochirii-forums.conf)
  local -a present=() backups=()
  backup_root="$(mktemp -d /etc/ssh/sshd_config.d/.mochirii-forums-policy.XXXXXXXX)"; chmod 0700 "${backup_root}"
  for path in "${managed[@]}"; do
    if [[ -e ${path} || -L ${path} ]]; then
      [[ -f ${path} && ! -L ${path} && "$(stat -c '%U:%G %a' "${path}")" == "root:root 644" ]] || fail "Managed SSH fragment is unsafe."
      install -m 0600 -o root -g root -- "${path}" "${backup_root}/${index}"
      present+=("${path}"); backups+=("${backup_root}/${index}"); index=$((index + 1))
    fi
  done
  atomic_install "${source}" "${target}" 0644
  for path in /etc/ssh/sshd_config.d/50-mochirii-forums-hardening.conf /etc/ssh/sshd_config.d/60-mochirii-forums.conf; do durable_remove "${path}"; done
  if ! timeout --signal=TERM --kill-after=5s 15s sshd -t >/dev/null 2>&1 || ! "${validator}"; then valid=false
  elif ! run_bounded_host_operation 60 systemctl reload ssh; then valid=false
  elif ! "${validator}"; then valid=false; fi
  if [[ ${valid} != true ]]; then
    for path in "${managed[@]}"; do durable_remove "${path}" || true; done
    for index in "${!present[@]}"; do atomic_install "${backups[$index]}" "${present[$index]}" 0644; done
    rm -rf -- "${backup_root}"
    timeout --signal=TERM --kill-after=5s 15s sshd -t >/dev/null 2>&1 || fail "SSH policy rollback did not restore valid configuration."
    run_bounded_host_cleanup systemctl reload ssh || fail "SSH policy rollback could not be reloaded."
    fail "Candidate SSH policy was rejected and the exact prior fragments were restored."
  fi
  rm -rf -- "${backup_root}"
}

verify_account() {
  local user="$1" group="$2" home="$3" record password_status
  record="$(getent passwd "${user}")" || return 1
  IFS=: read -r account password uid gid gecos actual_home shell <<<"${record}"
  [[ ${account} == "${user}" && ${password} == x && ${uid} =~ ^[0-9]+$ && ${gid} =~ ^[0-9]+$ ]] || return 1
  [[ ${gecos} == "" && ${actual_home} == "${home}" && ${shell} == /bin/bash ]] || return 1
  [[ "$(getent group "${group}" | cut -d: -f3)" == "${gid}" ]] || return 1
  [[ "$(id -gn "${user}")" == "${group}" && "$(id -Gn "${user}")" == "${group}" ]] || return 1
  [[ -z "$(getent group "${group}" | cut -d: -f4)" ]] || return 1
  password_status="$(passwd -S "${user}")" || return 1
  [[ "$(awk '{print $1 " " $2}' <<<"${password_status}")" == "${user} L" ]]
}

write_access_journal() {
  local commit="$1" manifest_sha="$2" deploy_sha="$3" operator_sha="$4"
  python3 -B - "${state_root}/host-access-install.pending.json" "${commit}" "${manifest_sha}" "${deploy_sha}" "${operator_sha}" <<'PY'
import json, os, pathlib, stat, tempfile, sys
path = pathlib.Path(sys.argv[1])
document = {"schemaVersion": 1, "operation": "initial-host-access-install", "phase": "installing",
    "repositoryCommit": sys.argv[2], "manifestSha256": sys.argv[3],
    "deployAuthorizedKeysSha256": sys.argv[4], "operatorAuthorizedKeysSha256": sys.argv[5]}
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("access journal is unsafe")
    if json.loads(path.read_text(encoding="utf-8")) != document: raise SystemExit("access journal tuple differs")
    raise SystemExit(0)
descriptor, candidate = tempfile.mkstemp(prefix=".host-access-install.", suffix=".json", dir=path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        descriptor = -1; json.dump(document, target, sort_keys=True, separators=(",", ":")); target.write("\n"); target.flush(); os.fsync(target.fileno())
    os.chown(candidate, 0, 0); os.link(candidate, path, follow_symlinks=False)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)
finally:
    if descriptor >= 0: os.close(descriptor)
    try: os.unlink(candidate)
    except FileNotFoundError: pass
PY
}

write_prepared_state() {
  python3 -B - "${state_root}/host-control-prepared.json" "$1" "$2" "$3" "$4" <<'PY'
import json, os, pathlib, tempfile, sys
path = pathlib.Path(sys.argv[1])
document = {"schemaVersion": 1, "phase": "prepared", "repositoryCommit": sys.argv[2],
    "manifestSha256": sys.argv[3], "deployAuthorizedKeysSha256": sys.argv[4], "operatorAuthorizedKeysSha256": sys.argv[5]}
descriptor, candidate = tempfile.mkstemp(prefix=".host-control-prepared.", suffix=".json", dir=path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        descriptor = -1; json.dump(document, target, sort_keys=True, separators=(",", ":")); target.write("\n"); target.flush(); os.fsync(target.fileno())
    os.chown(candidate, 0, 0); os.replace(candidate, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)
finally:
    if descriptor >= 0: os.close(descriptor)
    try: os.unlink(candidate)
    except FileNotFoundError: pass
PY
}

validate_operator_proof() {
  local proof_path="$1"
  python3 -B - "${proof_path}" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
try:
    descriptor = os.open(path, flags)
except OSError:
    raise SystemExit(1)
try:
    metadata = os.fstat(descriptor)
    expected = b"operatorSshAndSudoVerified=true\n"
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or os.read(descriptor, len(expected) + 1) != expected
        or os.read(descriptor, 1) != b""
    ):
        raise SystemExit(1)
finally:
    os.close(descriptor)
PY
}

[[ ${EUID} -eq 0 ]] || fail "Host control installation must run as root."
[[ $# -ge 1 ]] || fail "Usage: install-host-control.sh prepare EXPECTED_COMMIT DEPLOY_AUTHORIZED_KEY OPERATOR_AUTHORIZED_KEY | harden 'HARDEN MOCHIRII FORUMS SSH'"
phase="$1"; shift
script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_root}/.." && pwd)"
lock_helper="${repository_root}/scripts/host-operation-lock.py"
if python3 -B "${lock_helper}" assert-held --locks primary,media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary,media -- /bin/bash "$0" "${phase}" "$@"
fi
[[ ! -e ${state_root}/deployment-mutation.json && ! -L ${state_root}/deployment-mutation.json ]] || fail "Host-control installation refuses an active deployment mutation."

if [[ ${phase} == harden ]]; then
  [[ $# -eq 1 && $1 == "HARDEN MOCHIRII FORUMS SSH" ]] || fail "Exact SSH-hardening confirmation is required."
  [[ ${SUDO_USER:-} == "${operator_user}" && -n ${SSH_CONNECTION:-} ]] || fail "SSH hardening must be invoked through sudo from the separately authenticated operator SSH session."
  prepared="${state_root}/host-control-prepared.json"
  [[ -f ${prepared} && ! -L ${prepared} && "$(stat -c '%U:%G %a' "${prepared}")" == "root:root 600" ]] || fail "Prepared host-control evidence is absent or unsafe."
  readarray -t prepared_state < <(python3 -B - "${prepared}" "${repository_root}/config/host-control-manifest.v1.json" "${state_root}/deploy/.ssh/authorized_keys" "${state_root}/operator/.ssh/authorized_keys" <<'PY'
import hashlib, json, pathlib, re, sys
path, manifest, deploy, operator = map(pathlib.Path, sys.argv[1:])
document = json.loads(path.read_text(encoding="utf-8"))
if set(document) != {"schemaVersion", "phase", "repositoryCommit", "manifestSha256", "deployAuthorizedKeysSha256", "operatorAuthorizedKeysSha256"}:
    raise SystemExit("prepared state keys differ")
if document.get("schemaVersion") != 1 or document.get("phase") != "prepared" or not re.fullmatch(r"[0-9a-f]{40}", str(document.get("repositoryCommit", ""))):
    raise SystemExit("prepared state differs")
if document.get("manifestSha256") != hashlib.sha256(manifest.read_bytes()).hexdigest(): raise SystemExit("prepared manifest differs")
if document.get("deployAuthorizedKeysSha256") != hashlib.sha256(deploy.read_bytes()).hexdigest(): raise SystemExit("prepared deploy key differs")
if document.get("operatorAuthorizedKeysSha256") != hashlib.sha256(operator.read_bytes()).hexdigest(): raise SystemExit("prepared operator key differs")
print(document["repositoryCommit"])
PY
  )
  [[ ${#prepared_state[@]} -eq 1 ]] || fail "Prepared host-control evidence is malformed."
  expected_commit="${prepared_state[0]}"
  validate_repository_binding "${repository_root}" "${expected_commit}" || fail "Hardening source is not exact clean canonical main."
  verify_account "${deploy_user}" "${deploy_group}" "${state_root}/deploy" || fail "Deploy account tuple differs before hardening."
  verify_account "${operator_user}" "${operator_group}" "${state_root}/operator" || fail "Operator account tuple differs before hardening."
  sudo -u "${operator_user}" sudo -n /usr/bin/true || fail "Operator maintenance sudo is unavailable."
  proof="${state_root}/operator-ssh-proved"
  if [[ -e ${proof} || -L ${proof} ]]; then
    validate_operator_proof "${proof}" || fail "Existing operator SSH proof is unsafe."
  else
    proof_candidate="$(mktemp "${state_root}/.operator-ssh-proved.XXXXXXXX")"
    printf '%s\n' operatorSshAndSudoVerified=true >"${proof_candidate}"
    atomic_install "${proof_candidate}" "${proof}" 0600
    rm -f -- "${proof_candidate}"
  fi
  install_sshd_policy "${repository_root}/config/sshd-forums.conf" validate_hardened_ssh
  ensure_ssh_service_activation || fail "OpenSSH could not be converted from socket activation to the reviewed service contract."
  validate_hardened_ssh || fail "Effective SSH authentication settings differ after reload."
  /usr/local/libexec/mochirii-forums/host-control-evidence.py seal-access >/dev/null
  /usr/local/libexec/mochirii-forums/host-control-evidence.py seal-control --operation initial-install \
    --commit "${expected_commit}" --source-root "${repository_root}" >/dev/null
  bash "${repository_root}/scripts/verify-host-security.sh" "${expected_commit}" "${repository_root}" >/dev/null 2>&1 || fail "Terminal hardened host-security verification failed."
  printf '%s\n' "Mochirii Forums SSH hardening completed from the verified operator session."
  exit 0
fi

[[ ${phase} == prepare && $# -eq 3 ]] || fail "Usage: install-host-control.sh prepare EXPECTED_COMMIT DEPLOY_AUTHORIZED_KEY OPERATOR_AUTHORIZED_KEY"
expected_commit="$1"; authorized_keys_source="$2"; operator_keys_source="$3"
[[ ${expected_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Expected host-control commit is malformed."
validate_repository_binding "${repository_root}" "${expected_commit}" || fail "Host-control source is not exact clean canonical main."
for hardened_record in "${state_root}/current-host-access.json" "${state_root}/current-host-control.json"; do
  if [[ -e ${hardened_record} || -L ${hardened_record} ]]; then
    fail "Prepared installation cannot replace an already hardened host; use the governed host-control upgrade procedure."
  fi
done
proof="${state_root}/operator-ssh-proved"
if [[ -e ${proof} || -L ${proof} ]]; then
  validate_operator_proof "${proof}" || fail "Existing operator SSH proof is unsafe."
fi
for source in "${authorized_keys_source}" "${operator_keys_source}"; do
  [[ -f ${source} && ! -L ${source} ]] || fail "Authorized-key source must be one regular file."
  [[ "$(stat -c '%U %a' "${source}")" =~ ^root\ (400|600)$ ]] || fail "Authorized-key source must be root-owned mode 0400 or 0600."
done
python3 -B - "${authorized_keys_source}" "${operator_keys_source}" <<'PY' >/dev/null
import pathlib, re, sys
pattern = re.compile(r"(ssh-ed25519|sk-ssh-ed25519@openssh[.]com) ([A-Za-z0-9+/=]+)(?: ([^\x00-\x1f\x7f]+))?")
materials = []
for name in sys.argv[1:]:
    raw = pathlib.Path(name).read_bytes()
    try: text = raw.decode("ascii")
    except UnicodeDecodeError: raise SystemExit("authorized key is not ASCII")
    lines = text.splitlines(); match = pattern.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None: raise SystemExit("authorized key file must contain exactly one plain Ed25519 record")
    materials.append(match.group(2))
if materials[0] == materials[1]: raise SystemExit("deploy and operator keys must be distinct")
PY
ssh-keygen -l -f "${authorized_keys_source}" >/dev/null 2>&1 || fail "Deploy authorized key is invalid."
ssh-keygen -l -f "${operator_keys_source}" >/dev/null 2>&1 || fail "Operator authorized key is invalid."

. /etc/os-release
[[ ${ID} == ubuntu && ${VERSION_ID} == 24.04 ]] || fail "Host operating system differs from Ubuntu 24.04."
for required in docker git python3 sshd visudo; do command -v "${required}" >/dev/null || fail "Required host command is absent: ${required}."; done
docker_platform="$(timeout --signal=TERM --kill-after=5s 30s docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null)" || fail "Docker Engine server readback is unavailable."
[[ ${docker_platform} == linux/amd64 ]] || fail "Docker Engine server platform differs from linux/amd64."
[[ "$(timeout --signal=TERM --kill-after=5s 15s systemctl is-enabled docker 2>/dev/null)" == enabled ]] || fail "Docker Engine service is not enabled."
[[ "$(timeout --signal=TERM --kill-after=5s 15s systemctl is-active docker 2>/dev/null)" == active ]] || fail "Docker Engine service is not active."
docker_version="$(timeout --signal=TERM --kill-after=5s 15s docker version --format '{{.Server.Version}}' 2>/dev/null)" || fail "Docker Engine version readback is unavailable."
git_version="$(timeout --signal=TERM --kill-after=5s 15s git --version 2>/dev/null)" || fail "Git version readback is unavailable."
python_version="$(timeout --signal=TERM --kill-after=5s 15s python3 --version 2>/dev/null)" || fail "Python 3 version readback is unavailable."
[[ ${docker_version} =~ ^[0-9]+[.][0-9]+[.][0-9]+([+-][A-Za-z0-9._-]+)?$ ]] || fail "Docker Engine version readback is malformed."
[[ ${git_version} =~ ^git\ version\ [0-9]+[.][0-9]+[.][0-9]+ ]] || fail "Git version readback is malformed."
[[ ${python_version} =~ ^Python\ 3[.][0-9]+[.][0-9]+ ]] || fail "Python 3 version readback is malformed."

install -d -m 0755 -o root -g root /var/lib/mochirii "${state_root}" /opt/mochirii /opt/mochirii/forums /opt/mochirii/forums/releases
install -d -m 0700 -o root -g root "${state_root}/evidence" "${state_root}/logs" "${state_root}/operator-evidence" "${state_root}/quarantine" /etc/mochirii
[[ "$(stat -c '%U:%G %a' "${state_root}")" == "root:root 755" ]] || fail "Host-control state root mode differs."
python3 -B - "${state_root}/evidence/host-prerequisites.json" "${docker_platform}" "${docker_version}" "${git_version}" "${python_version}" <<'PY'
import datetime, json, os, pathlib, tempfile, sys
path = pathlib.Path(sys.argv[1])
document = {"schemaVersion": 1, "observedAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "operatingSystem": "Ubuntu 24.04", "dockerServerPlatform": sys.argv[2], "dockerServerVersion": sys.argv[3],
    "dockerServiceEnabled": True, "gitVersion": sys.argv[4], "pythonVersion": sys.argv[5]}
descriptor, candidate = tempfile.mkstemp(prefix=".host-prerequisites.", suffix=".json", dir=path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        descriptor = -1; json.dump(document, target, sort_keys=True, separators=(",", ":")); target.write("\n"); target.flush(); os.fsync(target.fileno())
    os.chown(candidate, 0, 0); os.replace(candidate, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)
finally:
    if descriptor >= 0: os.close(descriptor)
    try: os.unlink(candidate)
    except FileNotFoundError: pass
PY

export DEBIAN_FRONTEND=noninteractive
run_bounded_host_operation 600 apt-get update || fail "Host package index refresh failed within its bounded operation."
run_bounded_host_operation 900 apt-get install -y fail2ban unattended-upgrades ufw || fail "Host security package installation failed within its bounded operation."
getent group "${deploy_group}" >/dev/null || groupadd --system "${deploy_group}"
getent group "${operator_group}" >/dev/null || groupadd --system "${operator_group}"
if id "${deploy_user}" >/dev/null 2>&1; then [[ "$(id -gn "${deploy_user}")" == "${deploy_group}" ]] || fail "Existing deploy user has an unexpected primary group."
else useradd --no-create-home --home-dir "${state_root}/deploy" --shell /bin/bash --gid "${deploy_group}" --system "${deploy_user}"; fi
if id "${operator_user}" >/dev/null 2>&1; then [[ "$(id -gn "${operator_user}")" == "${operator_group}" ]] || fail "Existing operator user has an unexpected primary group."
else useradd --no-create-home --home-dir "${state_root}/operator" --shell /bin/bash --gid "${operator_group}" --system "${operator_user}"; fi
passwd -l "${deploy_user}" >/dev/null; passwd -l "${operator_user}" >/dev/null
verify_account "${deploy_user}" "${deploy_group}" "${state_root}/deploy" || fail "Deploy account tuple differs."
verify_account "${operator_user}" "${operator_group}" "${state_root}/operator" || fail "Operator account tuple differs."

install -d -m 0755 -o root -g root "${state_root}/deploy" "${state_root}/operator"
install -d -m 0755 -o root -g root "${state_root}/deploy/.ssh" "${state_root}/operator/.ssh"
install -d -m 0700 -o "${deploy_user}" -g "${deploy_group}" "${state_root}/incoming"
install -d -m 0755 -o root -g root /opt/mochirii/forums/runtime-assets /usr/local/libexec/mochirii-forums
install -d -m 0700 -o root -g root /var/discourse/containers/releases
for home in deploy operator; do
  mapfile -t existing < <(find "${state_root}/${home}/.ssh" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
  if (( ${#existing[@]} > 0 )) && [[ ! ( ${#existing[@]} -eq 1 && ${existing[0]} == authorized_keys ) ]]; then fail "${home} SSH tree contains an alternate key or user-rc source."; fi
done

deploy_key_candidate="$(mktemp "${state_root}/.deploy-authorized-key.XXXXXXXX")"
python3 -B - "${authorized_keys_source}" "${deploy_key_candidate}" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").rstrip("\n")
pathlib.Path(sys.argv[2]).write_text("restrict " + source + "\n", encoding="ascii")
PY
operator_key_candidate="$(mktemp "${state_root}/.operator-authorized-key.XXXXXXXX")"
install -m 0600 -o root -g root "${operator_keys_source}" "${operator_key_candidate}"
deploy_key_sha="$(sha256sum -- "${deploy_key_candidate}" | awk '{print $1}')"
operator_key_sha="$(sha256sum -- "${operator_key_candidate}" | awk '{print $1}')"
manifest_sha="$(sha256sum -- "${repository_root}/config/host-control-manifest.v1.json" | awk '{print $1}')"
write_access_journal "${expected_commit}" "${manifest_sha}" "${deploy_key_sha}" "${operator_key_sha}"
for pair in "${deploy_key_candidate}:${state_root}/deploy/.ssh/authorized_keys:${deploy_key_sha}" "${operator_key_candidate}:${state_root}/operator/.ssh/authorized_keys:${operator_key_sha}"; do
  IFS=: read -r candidate target expected_sha <<<"${pair}"
  if [[ -e ${target} || -L ${target} ]]; then
    [[ -f ${target} && ! -L ${target} && "$(stat -c '%U:%G %a' "${target}")" =~ ^root:root\ (600|644)$ ]] || fail "Existing authorized key target is unsafe."
    [[ "$(sha256sum -- "${target}" | awk '{print $1}')" == "${expected_sha}" ]] || fail "Existing authorized key differs from the journaled initial key."
  fi
  atomic_install "${candidate}" "${target}" 0644
done
rm -f -- "${deploy_key_candidate}" "${operator_key_candidate}"
sudo -u "${deploy_user}" test -r "${state_root}/deploy/.ssh/authorized_keys" || fail "Deploy authorized key is unreadable after privilege drop."
sudo -u "${operator_user}" test -r "${state_root}/operator/.ssh/authorized_keys" || fail "Operator authorized key is unreadable after privilege drop."

mapfile -t control_records < <(manifest_records "${repository_root}") || fail "Host-control manifest validation failed."
for record in "${control_records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  if [[ ${group} == coreTargets || ( ${group} == hostPolicyTargets && ${target} != /etc/ssh/sshd_config.d/00-00-mochirii-forums.conf ) ]]; then
    atomic_install "${repository_root}/${relative}" "${target}" "${mode}"
    [[ "$(sha256sum -- "${target}" | awk '{print $1}')" == "${digest}" ]] || fail "Installed host-control target digest differs."
  fi
done
retain_disaster_recovery_sources "${repository_root}" "${expected_commit}" || fail "Exact C1 and official deployment-source recovery archives could not be retained."
timeout --signal=TERM --kill-after=5s 20s visudo -cf /etc/sudoers.d/mochirii-forums >/dev/null 2>&1 || fail "Deploy sudoers policy is invalid."
timeout --signal=TERM --kill-after=5s 20s visudo -cf /etc/sudoers.d/mochirii-forums-operator >/dev/null 2>&1 || fail "Operator sudoers policy is invalid."
sudo -u "${operator_user}" sudo -n /usr/bin/true || fail "Operator maintenance sudo failed before SSH hardening."
for forbidden in /usr/local/sbin/mochirii-forums-finalize-member-rollout /usr/local/sbin/mochirii-forums-break-glass-admin \
  /usr/local/sbin/mochirii-forums-stop-pending-activation /usr/local/sbin/mochirii-forums-finalize-authentication \
  /usr/local/sbin/mochirii-forums-upgrade-host-control /usr/local/sbin/mochirii-forums-historical-disaster-recovery \
  /usr/local/libexec/mochirii-forums/host-operation-lock.py; do
  sudo -l -U "${deploy_user}" "${forbidden}" >/dev/null 2>&1 && fail "Deploy automation unexpectedly has operator-only authority."
done
sudo -u "${deploy_user}" test ! -w "${state_root}" || fail "Deploy automation can alter protected rollout state."

install_sshd_policy "${repository_root}/config/sshd-forums-prepared.conf" validate_prepared_ssh
validate_prepared_ssh || fail "Prepared SSH confinement differs after reload."

if [[ ! -e /swapfile ]]; then fallocate -l 2G /swapfile; chmod 0600 /swapfile; mkswap /swapfile >/dev/null; fi
[[ "$(stat -c '%U:%G %a %s' /swapfile)" == "root:root 600 2147483648" ]] || fail "Swap file differs from the reviewed 2 GiB boundary."
swap_names="$(timeout --signal=TERM --kill-after=5s 15s swapon --show=NAME --noheadings)" || fail "Swap readback failed."
grep -Fx /swapfile <<<"${swap_names}" >/dev/null || swapon /swapfile
[[ "$(grep -Ec '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0$' /etc/fstab)" -le 1 ]] || fail "Duplicate swap persistence entries exist."
grep -Eq '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0$' /etc/fstab || printf '%s\n' '/swapfile none swap sw 0 0' >>/etc/fstab
[[ "$(awk -F= '$1 == "IPV6" { print $2 }' /etc/default/ufw)" == yes ]] || fail "UFW must enforce both IPv4 and IPv6 on the fresh host."

run_bounded_host_operation 120 systemctl restart docker || fail "Docker restart failed within its bounded operation."
run_bounded_host_operation 120 systemctl enable --now fail2ban unattended-upgrades apt-daily.timer apt-daily-upgrade.timer || fail "Host security service activation failed within its bounded operation."
run_bounded_host_operation 60 ufw --force reset || fail "Firewall reset failed."
run_bounded_host_operation 60 ufw default deny incoming || fail "Firewall inbound default failed."
run_bounded_host_operation 60 ufw default allow outgoing || fail "Firewall outbound default failed."
run_bounded_host_operation 60 ufw default deny routed || fail "Firewall routed default failed."
run_bounded_host_operation 60 ufw allow 22/tcp || fail "Firewall SSH rule failed."
run_bounded_host_operation 60 ufw allow 80/tcp || fail "Firewall HTTP rule failed."
run_bounded_host_operation 60 ufw allow 443/tcp || fail "Firewall HTTPS rule failed."
run_bounded_host_operation 90 ufw --force enable || fail "Firewall activation failed."
[[ "$(nproc)" -eq 1 ]] || fail "Host does not expose exactly one CPU."
memory_mib="$(awk '/MemTotal/ { print int($2 / 1024) }' /proc/meminfo)"
[[ ${memory_mib} -ge 1900 && ${memory_mib} -le 2300 ]] || fail "Host memory is outside the reviewed 2 GiB class."

write_prepared_state "${expected_commit}" "${manifest_sha}" "${deploy_key_sha}" "${operator_key_sha}"
durable_remove "${state_root}/host-access-install.pending.json"
printf '%s\n' "Mochirii Forums host control prepared; verify a separate operator SSH session before the harden phase."
