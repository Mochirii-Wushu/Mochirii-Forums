#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

readonly canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"
readonly deployment_source_commit="ed9f680b0df1de28f062de1769d89d22b2644d1b"
readonly deployment_source_tree="588498dffbea91592fd4e2f10166bc11c8fe7a61"
readonly state_root="/var/lib/mochirii/forums"
readonly evidence_root="${state_root}/evidence"
readonly upgrades_root="${state_root}/control-upgrades"
readonly pending_journal="${state_root}/control-upgrade.pending.json"
readonly control_pointer="${state_root}/current-host-control.json"
active_transaction=""
upgrade_complete=false

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

bounded() {
  timeout --signal=TERM --kill-after=10s "$@"
}

durable_remove() {
  python3 -B - "$1" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
try:
    path.unlink()
except FileNotFoundError:
    raise SystemExit(0)
parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}

durable_remove_workdir() {
  python3 -B - "$1" "${upgrades_root}" <<'PY'
import os
import pathlib
import re
import shutil
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
if path.parent != root or not (
    re.fullmatch(r"[0-9a-f]{40}-[0-9a-f]{64}", path.name)
    or re.fullmatch(r"[.]staging-[0-9a-f]{40}[.][A-Za-z0-9]{8}", path.name)
):
    raise SystemExit("host-control work directory identity differs")
metadata = path.lstat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("host-control work directory is unsafe")
shutil.rmtree(path)
parent = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}

reconcile_unjournaled_workdirs() {
  local path
  [[ ! -e ${pending_journal} && ! -L ${pending_journal} ]] || return 0
  while IFS= read -r -d '' path; do
    durable_remove_workdir "${path}" || return 1
  done < <(find "${upgrades_root}" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  [[ -z "$(find "${upgrades_root}" -mindepth 1 -maxdepth 1 -print -quit)" ]]
}

atomic_install() {
  local source="$1" target="$2" mode="$3"
  python3 -B - "${source}" "${target}" "${mode}" <<'PY'
import os
import pathlib
import stat
import tempfile
import sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
mode = int(sys.argv[3], 8)
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("source is not regular")
target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
descriptor, candidate = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
try:
    os.fchmod(descriptor, mode)
    with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
        descriptor = -1
        while chunk := reader.read(1024 * 1024):
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    os.chown(candidate, 0, 0)
    os.replace(candidate, target)
    parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(candidate)
    except FileNotFoundError:
        pass
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
  local repository_archive="$1" commit="$2" source_root="$3" expected_tree="$4" deployment_archive inspection
  deployment_archive="$(mktemp "${state_root}/.deployment-source-${deployment_source_commit}.XXXXXXXX.tar")" || return 1
  [[ -d /var/discourse/.git && ! -L /var/discourse/.git ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse rev-parse --verify HEAD^{commit})" == "${deployment_source_commit}" ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse rev-parse --verify HEAD^{tree})" == "${deployment_source_tree}" ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ -z "$(git -c core.fsmonitor=false -C /var/discourse status --porcelain=v1 --untracked-files=all)" ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse config --local --get remote.origin.url)" == https://github.com/discourse/discourse_docker.git ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse config --local --get remote.origin.pushurl)" == no_push://mochirii-forums-upstream ]] || { rm -f -- "${deployment_archive}"; return 1; }
  git -c tar.umask=0002 -C /var/discourse archive --format=tar --output="${deployment_archive}" "${deployment_source_commit}" >/dev/null 2>&1 || { rm -f -- "${deployment_archive}"; return 1; }
  inspection="$(python3 -B "${source_root}/scripts/historical-release-disaster-recovery.py" inspect --archive "${repository_archive}" --expected-commit "${commit}")" || { rm -f -- "${deployment_archive}"; return 1; }
  (( ${#inspection} <= 4096 )) || { rm -f -- "${deployment_archive}"; return 1; }
  python3 -B - "${inspection}" "${commit}" "${expected_tree}" <<'PY' >/dev/null || { rm -f -- "${deployment_archive}"; return 1; }
import json, sys
document = json.loads(sys.argv[1])
if document.get("repositoryCommit") != sys.argv[2] or document.get("repositoryTree") != sys.argv[3]:
    raise SystemExit("retained host-control archive differs from the exact Git commit tree")
PY
  install -d -m 0700 -o root -g root "/opt/mochirii/forums/host-control-releases/${commit}" /opt/mochirii/forums/deployment-source
  retain_exact_file "${repository_archive}" "/opt/mochirii/forums/host-control-releases/${commit}/mochirii-release.tar" || { rm -f -- "${deployment_archive}"; return 1; }
  retain_exact_file "${deployment_archive}" "/opt/mochirii/forums/deployment-source/${deployment_source_commit}.tar" || { rm -f -- "${deployment_archive}"; return 1; }
  rm -f -- "${deployment_archive}"
}

manifest_records() {
  local source_root="$1"
  python3 -B - "${source_root}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1])
path = root / "config/host-control-manifest.v1.json"
document = json.loads(path.read_text(encoding="utf-8"))
if set(document) != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"} or document.get("schemaVersion") != 1:
    raise SystemExit("manifest schema differs")
targets = set()
sources = set()
required_core = {
    "/usr/local/libexec/mochirii-forums/durable-event.py",
    "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
    "/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh",
    "/usr/local/libexec/mochirii-forums/host-operation-lock.py",
    "/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
    "/usr/local/libexec/mochirii-forums/verify-host-security.sh",
    "/usr/local/sbin/mochirii-forums-deploy",
    "/usr/local/sbin/mochirii-forums-verify",
    "/usr/local/sbin/mochirii-forums-backup",
    "/usr/local/sbin/mochirii-forums-restore",
    "/usr/local/sbin/mochirii-forums-upgrade-host-control",
    "/usr/local/sbin/mochirii-forums-historical-disaster-recovery",
}
for group in ("coreTargets", "hostPolicyTargets", "certificateTargets"):
    rows = document.get(group)
    if not isinstance(rows, list) or not rows:
        raise SystemExit("manifest group is empty")
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"source", "target", "mode"}:
            raise SystemExit("manifest target row differs")
        source, target, mode = row["source"], row["target"], row["mode"]
        if not re.fullmatch(r"(?:config|scripts)/[A-Za-z0-9._-]+", source):
            raise SystemExit("manifest source differs")
        if not isinstance(target, str) or not target.startswith(("/etc/", "/usr/local/")) or ".." in pathlib.PurePosixPath(target).parts:
            raise SystemExit("manifest target differs")
        if mode not in {"0440", "0644", "0755"} or source in sources or target in targets:
            raise SystemExit("manifest target duplicate or mode differs")
        source_path = root / source
        if not source_path.is_file() or source_path.is_symlink() or source_path.stat().st_size > 2 * 1024 * 1024:
            raise SystemExit("manifest source is unsafe")
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        print("\t".join((group, mode, source, target, digest)))
        sources.add(source)
        targets.add(target)
if not required_core.issubset({row["target"] for row in document["coreTargets"]}):
    raise SystemExit("manifest omitted an indispensable control target")
historical_recovery = {
    "source": "scripts/historical-release-disaster-recovery.py",
    "target": "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
    "mode": "0755",
}
if historical_recovery not in document["coreTargets"]:
    raise SystemExit("manifest historical disaster-recovery authority differs")
PY
}

seal_control_state() {
  local operation="$1" commit="$2" source_root="$3" previous_sha="$4"
  /usr/local/libexec/mochirii-forums/host-control-evidence.py seal-control \
    --operation "${operation}" --commit "${commit}" --source-root "${source_root}" \
    --previous-evidence-sha256 "${previous_sha}"
}

post_install_readback() {
  local source_root="$1" certificate_installed="$2" timer_enabled="$3" timer_active="$4"
  [[ -d ${source_root} && ! -L ${source_root} ]] || return 1
  bounded 20s visudo -cf /etc/sudoers.d/mochirii-forums >/dev/null 2>&1 || return 1
  bounded 20s visudo -cf /etc/sudoers.d/mochirii-forums-operator >/dev/null 2>&1 || return 1
  bounded 20s sshd -t >/dev/null 2>&1 || return 1
  bounded 30s systemctl reload ssh >/dev/null 2>&1 || return 1
  validate_effective_hardened_ssh || return 1
  bounded 30s systemctl restart fail2ban >/dev/null 2>&1 || return 1
  bounded 30s systemctl restart unattended-upgrades >/dev/null 2>&1 || return 1
  bounded 90s systemctl restart docker >/dev/null 2>&1 || return 1
  [[ "$(bounded 20s systemctl is-active fail2ban 2>/dev/null)" == active ]] || return 1
  [[ "$(bounded 20s systemctl is-active unattended-upgrades 2>/dev/null)" == active ]] || return 1
  [[ "$(bounded 20s systemctl is-active docker 2>/dev/null)" == active ]] || return 1
  if [[ ${certificate_installed} == true ]]; then
    bounded 30s systemctl daemon-reload >/dev/null 2>&1 || return 1
    if [[ ${timer_enabled} == true ]]; then
      bounded 30s systemctl enable mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    else
      bounded 30s systemctl disable mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    fi
    if [[ ${timer_active} == true ]]; then
      bounded 30s systemctl start mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    else
      bounded 30s systemctl stop mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    fi
    [[ "$(bounded 20s systemctl is-enabled mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == "$([[ ${timer_enabled} == true ]] && printf enabled || printf disabled)" ]] || return 1
    [[ "$(bounded 20s systemctl is-active mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == "$([[ ${timer_active} == true ]] && printf active || printf inactive)" ]] || return 1
  fi
  bounded 20s sshd -t >/dev/null 2>&1
}

clear_transaction() {
  local transaction="$1"
  durable_remove "${pending_journal}"
  [[ ${transaction} =~ ^${upgrades_root}/[0-9a-f]{40}-[0-9a-f]{64}$ ]] || return 1
  durable_remove_workdir "${transaction}"
}

rollback_transaction() {
  local transaction="$1"
  python3 -B - "${pending_journal}" "${transaction}" "${control_pointer}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import sys
journal_path = pathlib.Path(sys.argv[1])
transaction = pathlib.Path(sys.argv[2])
pointer_path = pathlib.Path(sys.argv[3])
journal = json.loads(journal_path.read_text(encoding="utf-8"))
for row in journal["targets"]:
    target = pathlib.Path(row["target"])
    if row["oldPresent"]:
        backup = transaction / row["backup"]
        if hashlib.sha256(backup.read_bytes()).hexdigest() != row["oldSha256"]:
            raise SystemExit("control rollback backup differs")
        descriptor, candidate = tempfile.mkstemp(prefix=f".{target.name}.rollback.", dir=target.parent)
        try:
            os.fchmod(descriptor, int(row["oldMode"], 8))
            with backup.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
                descriptor = -1
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            os.chown(candidate, 0, 0)
            os.replace(candidate, target)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(candidate)
            except FileNotFoundError:
                pass
    else:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
    parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
pointer_backup = transaction / "backup/current-host-control.json"
descriptor, candidate = tempfile.mkstemp(prefix=".current-host-control.rollback.", dir=pointer_path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with pointer_backup.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
        descriptor = -1
        writer.write(reader.read())
        writer.flush()
        os.fsync(writer.fileno())
    os.chown(candidate, 0, 0)
    os.replace(candidate, pointer_path)
    parent = os.open(pointer_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(candidate)
    except FileNotFoundError:
        pass
PY
}

read_journal() {
  python3 -B - "${pending_journal}" "${upgrades_root}" <<'PY'
import json
import pathlib
import re
import stat
import sys
path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("control journal permissions differ")
document = json.loads(path.read_text(encoding="utf-8"))
keys = {
    "schemaVersion", "operation", "phase", "repositoryCommit", "manifestSha256",
    "transactionDirectory", "certificateAutomationInstalled", "certificateTimerEnabled",
    "certificateTimerActive", "previousControlEvidenceSha256", "targets",
}
if set(document) != keys or document.get("schemaVersion") != 1 or document.get("operation") != "host-control-upgrade" or document.get("phase") != "installing":
    raise SystemExit("control journal schema differs")
commit = document.get("repositoryCommit", "")
manifest = document.get("manifestSha256", "")
expected = root / f"{commit}-{manifest}"
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", manifest) or pathlib.Path(document.get("transactionDirectory", "")) != expected:
    raise SystemExit("control journal transaction binding differs")
for key in ("certificateAutomationInstalled", "certificateTimerEnabled", "certificateTimerActive"):
    if not isinstance(document.get(key), bool):
        raise SystemExit("control journal service state differs")
if document["certificateAutomationInstalled"] is False and (document["certificateTimerEnabled"] or document["certificateTimerActive"]):
    raise SystemExit("control journal certificate state differs")
previous = document.get("previousControlEvidenceSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", previous):
    raise SystemExit("control journal predecessor differs")
rows = document.get("targets")
if not isinstance(rows, list) or not rows:
    raise SystemExit("control journal target inventory differs")
for row in rows:
    if not isinstance(row, dict) or set(row) != {"source", "target", "newMode", "newSha256", "oldPresent", "oldMode", "oldSha256", "backup"}:
        raise SystemExit("control journal target row differs")
print(commit)
print(manifest)
print(expected)
print("true" if document["certificateAutomationInstalled"] else "false")
print("true" if document["certificateTimerEnabled"] else "false")
print("true" if document["certificateTimerActive"] else "false")
print(previous)
PY
}

targets_are_new() {
  python3 -B - "${pending_journal}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for row in document["targets"]:
    path = pathlib.Path(row["target"])
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise SystemExit(1)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != int(row["newMode"], 8):
        raise SystemExit(1)
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["newSha256"]:
        raise SystemExit(1)
PY
}

reconcile_pending() {
  local requested_commit="$1"
  readarray -t state < <(read_journal) || fail "Pending host-control upgrade journal is invalid."
  [[ ${#state[@]} -eq 7 ]] || fail "Pending host-control upgrade state is malformed."
  local commit="${state[0]}" transaction="${state[2]}" certificate="${state[3]}" timer_enabled="${state[4]}" timer_active="${state[5]}" previous_sha="${state[6]}"
  [[ ${commit} == "${requested_commit}" ]] || fail "Pending host-control upgrade belongs to another exact canonical commit."
  local candidate="${transaction}/source"
  if targets_are_new; then
    if ! post_install_readback "${candidate}" "${certificate}" "${timer_enabled}" "${timer_active}"; then
      rollback_transaction "${transaction}" || fail "Host-control commit-forward failed and exact rollback is blocked."
      post_install_readback /opt/mochirii/forums/releases/"$(python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["repositoryCommit"])' "${control_pointer}")" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "Host-control rollback service readback failed."
      clear_transaction "${transaction}" || fail "Rolled-back host-control journal could not be cleared."
      fail "Host-control upgrade failed post-install verification and restored the exact prior controls."
    fi
    seal_control_state upgrade "${commit}" "${candidate}" "${previous_sha}" || fail "Host-control commit evidence could not be sealed."
    if ! bash "${candidate}/scripts/verify-host-security.sh" "${commit}" "${candidate}" --upgrade-transaction >/dev/null 2>&1; then
      rollback_transaction "${transaction}" || fail "Committed host controls failed terminal verification and exact rollback is blocked."
      previous_commit="$(python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["repositoryCommit"])' "${control_pointer}")" || fail "Restored host-control pointer is invalid."
      previous_source="/opt/mochirii/forums/releases/${previous_commit}"
      post_install_readback "${previous_source}" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "Terminal host-control rollback service readback failed."
      bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-transaction >/dev/null 2>&1 || fail "Terminal host-control rollback verification failed."
      clear_transaction "${transaction}" || fail "Terminally rolled-back host-control journal could not be cleared."
      fail "Committed host controls failed terminal verification; the exact prior controls were restored."
    fi
    clear_transaction "${transaction}" || fail "Completed host-control journal could not be cleared."
    printf '%s\n' "Interrupted Mochirii Forums host-control upgrade was committed forward and verified."
    return 0
  fi
  rollback_transaction "${transaction}" || fail "Interrupted host-control upgrade is mixed and exact rollback is blocked."
  previous_commit="$(python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["repositoryCommit"])' "${control_pointer}")" || fail "Restored host-control pointer is invalid."
  previous_source="/opt/mochirii/forums/releases/${previous_commit}"
  post_install_readback "${previous_source}" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "Interrupted host-control rollback service readback failed."
  bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-transaction >/dev/null 2>&1 || fail "Interrupted host-control rollback failed terminal security verification."
  clear_transaction "${transaction}" || fail "Rolled-back host-control journal could not be cleared."
  fail "Interrupted host-control upgrade was rolled back exactly; rerun the approved upgrade."
}

handle_signal() {
  trap - HUP INT TERM
  if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
    reconcile_pending "${expected_commit:-invalid}" || true
  fi
  exit 125
}

[[ ${EUID} -eq 0 ]] || fail "Host-control upgrade must run as root."
[[ $# -eq 2 ]] || fail "Usage: mochirii-forums-upgrade-host-control EXPECTED_COMMIT 'UPGRADE MOCHIRII FORUMS CONTROL'"
expected_commit="$1"
confirmation="$2"
[[ ${expected_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Host-control upgrade commit is malformed."
[[ ${confirmation} == "UPGRADE MOCHIRII FORUMS CONTROL" ]] || fail "Exact host-control upgrade confirmation is required."
[[ ${SUDO_USER:-} == mochirii-forums-operator && -n ${SSH_CONNECTION:-} ]] || fail "Host-control upgrade requires the separately authenticated operator SSH session."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if python3 -B "${lock_helper}" assert-held --locks primary,media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary,media -- /bin/bash "$0" "$@"
fi
[[ ! -e ${state_root}/deployment-mutation.json && ! -L ${state_root}/deployment-mutation.json ]] || fail "Host-control upgrade refuses an active deployment mutation."
trap handle_signal HUP INT TERM

install -d -m 0755 -o root -g root /var/lib/mochirii "${state_root}"
install -d -m 0700 -o root -g root "${evidence_root}" "${upgrades_root}"
[[ "$(stat -c '%U:%G %a' "${state_root}")" == "root:root 755" ]] || fail "Host-control state root mode differs."
reconcile_unjournaled_workdirs || fail "An unjournaled host-control work directory is unsafe or could not be durably removed."
for unresolved in \
  "${state_root}/media-certificate-install.pending.json" \
  "${state_root}/media-certificate-preparation.pending.json" \
  "${state_root}/media-certificate-rotation.pending.json" \
  "${state_root}/acme-challenge-transaction.json"; do
  [[ ! -e ${unresolved} && ! -L ${unresolved} ]] || fail "A certificate recovery transaction blocks host-control upgrade."
done
[[ -z "$(find "${evidence_root}" -maxdepth 1 \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) -print -quit)" ]] || fail "A hosted storage recovery transaction blocks host-control upgrade."

app_inventory="$(bounded 20s docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || fail "Application containment readback failed or timed out."
if [[ -n ${app_inventory} ]]; then
  [[ ${app_inventory} == app ]] || fail "Application container inventory differs."
  [[ "$(bounded 20s docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || fail "Host-control upgrade requires the application to be proved stopped."
fi

if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
  reconcile_pending "${expected_commit}"
  exit 0
fi

[[ -f ${control_pointer} && ! -L ${control_pointer} && "$(stat -c '%U:%G %a' "${control_pointer}")" == "root:root 600" ]] || fail "Current host-control evidence is absent or unsafe."
readarray -t previous_state < <(python3 -B - "${control_pointer}" <<'PY'
import json
import pathlib
import re
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(document) != {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}:
    raise SystemExit("control pointer keys differ")
if document.get("schemaVersion") != 1 or document.get("phase") != "hardened":
    raise SystemExit("control pointer phase differs")
if not re.fullmatch(r"[0-9a-f]{40}", str(document.get("repositoryCommit", ""))) or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("controlEvidenceSha256", ""))):
    raise SystemExit("control pointer identity differs")
print(document["repositoryCommit"])
print(document["controlEvidenceSha256"])
PY
)
[[ ${#previous_state[@]} -eq 2 ]] || fail "Current host-control evidence is malformed."
previous_commit="${previous_state[0]}"
previous_evidence_sha="${previous_state[1]}"
previous_source="/opt/mochirii/forums/releases/${previous_commit}"
[[ -d ${previous_source} && ! -L ${previous_source} ]] || fail "Current trusted host-control source release is absent."
bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" >/dev/null 2>&1 || fail "Current host controls failed the pre-upgrade security gate."

trusted_git_options=(
  -c credential.helper=
  -c core.askPass=
  -c init.templateDir=
  -c protocol.allow=never
  -c protocol.https.allow=always
  -c http.followRedirects=false
)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0

staging="$(mktemp -d "${upgrades_root}/.staging-${expected_commit}.XXXXXXXX")"
cleanup_staging() {
  [[ -z ${staging:-} || ! -d ${staging} ]] || rm -rf -- "${staging}"
}
trap cleanup_staging EXIT
bare="${staging}/trusted.git"
archive="${staging}/source.tar"
candidate="${staging}/source"
mkdir -m 0700 -- "${candidate}"
git "${trusted_git_options[@]}" init --bare "${bare}" >/dev/null 2>&1 || fail "Canonical host-control verifier initialization failed."
git "${trusted_git_options[@]}" -C "${bare}" remote add origin "${canonical_repository}" >/dev/null 2>&1 || fail "Canonical host-control remote initialization failed."
bounded 120s git "${trusted_git_options[@]}" -c protocol.version=2 -C "${bare}" fetch --no-tags --depth=1 --refmap= origin refs/heads/main >/dev/null 2>&1 || fail "Canonical host-control main could not be read."
trusted_commit="$(git "${trusted_git_options[@]}" -C "${bare}" rev-parse --verify FETCH_HEAD^{commit})" || fail "Canonical host-control main did not resolve to one commit."
[[ ${trusted_commit} == "${expected_commit}" ]] || fail "Approved host-control commit is not exact current canonical main."
trusted_tree="$(git "${trusted_git_options[@]}" -C "${bare}" rev-parse --verify "${trusted_commit}^{tree}")" || fail "Canonical host-control main tree did not resolve."
[[ ${trusted_tree} =~ ^[0-9a-f]{40}$ ]] || fail "Canonical host-control main tree is malformed."
git "${trusted_git_options[@]}" -c tar.umask=0002 -C "${bare}" archive --format=tar --output="${archive}" "${trusted_commit}" >/dev/null 2>&1 || fail "Canonical host-control archive construction failed."
tar -xf "${archive}" -C "${candidate}" || fail "Canonical host-control archive extraction failed."
bounded 300s python3 -B "${candidate}/scripts/validate-repository.py" --archive-root "${candidate}" >/dev/null 2>&1 || fail "Canonical host-control repository validation failed."
mapfile -t records < <(manifest_records "${candidate}") || fail "Canonical host-control manifest validation failed."
[[ ${#records[@]} -ge 20 ]] || fail "Canonical host-control target inventory is incomplete."
retain_disaster_recovery_sources "${archive}" "${expected_commit}" "${candidate}" "${trusted_tree}" || fail "Exact C1 and official deployment-source recovery archives could not be retained."

for record in "${records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  case "${relative}" in
    *.sh) bash -n "${candidate}/${relative}" || fail "Candidate shell control failed syntax validation." ;;
    *.py) python3 -B - "${candidate}/${relative}" <<'PY' >/dev/null || fail "Candidate Python control failed syntax validation."
import ast
import pathlib
import sys
ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), filename=sys.argv[1])
PY
      ;;
  esac
done
bounded 20s visudo -cf "${candidate}/config/sudoers-forums" >/dev/null 2>&1 || fail "Candidate deploy sudoers policy is invalid."
bounded 20s visudo -cf "${candidate}/config/sudoers-forums-operator" >/dev/null 2>&1 || fail "Candidate operator sudoers policy is invalid."

certificate_count=0
certificate_present=0
for record in "${records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  [[ ${group} == certificateTargets ]] || continue
  certificate_count=$((certificate_count + 1))
  [[ ! -e ${target} && ! -L ${target} ]] || certificate_present=$((certificate_present + 1))
done
(( certificate_present == 0 || certificate_present == certificate_count )) || fail "Installed certificate automation target set is partial."
certificate_installed=false
timer_enabled=false
timer_active=false
if (( certificate_present == certificate_count )); then
  certificate_installed=true
  [[ "$(bounded 20s systemctl is-enabled mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == enabled ]] || fail "Certificate timer is not enabled before control upgrade."
  [[ "$(bounded 20s systemctl is-active mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == active ]] || fail "Certificate timer is not active before control upgrade."
  timer_enabled=true
  timer_active=true
fi

manifest_sha="$(sha256sum -- "${candidate}/config/host-control-manifest.v1.json" | awk '{print $1}')"
transaction="${upgrades_root}/${expected_commit}-${manifest_sha}"
[[ ! -e ${transaction} && ! -L ${transaction} ]] || fail "A host-control staging directory already exists without a journal."
mv -- "${staging}" "${transaction}"
staging=""
candidate="${transaction}/source"
install -d -m 0700 -o root -g root "${transaction}/backup"
install -m 0600 -o root -g root "${control_pointer}" "${transaction}/backup/current-host-control.json"
sync -d "${transaction}/backup" 2>/dev/null || true

python3 -B - "${candidate}" "${transaction}" "${pending_journal}" "${expected_commit}" "${manifest_sha}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" "${previous_evidence_sha}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import sys
root = pathlib.Path(sys.argv[1])
transaction = pathlib.Path(sys.argv[2])
journal_path = pathlib.Path(sys.argv[3])
commit, manifest_sha = sys.argv[4:6]
certificate, timer_enabled, timer_active = (value == "true" for value in sys.argv[6:9])
previous = sys.argv[9]
manifest = json.loads((root / "config/host-control-manifest.v1.json").read_text(encoding="utf-8"))
rows = []
index = 0
for group in ("coreTargets", "hostPolicyTargets", "certificateTargets"):
    if group == "certificateTargets" and not certificate:
        continue
    for item in manifest[group]:
        source = root / item["source"]
        target = pathlib.Path(item["target"])
        backup_name = f"backup/{index:03d}"
        old_present = target.exists() or target.is_symlink()
        old_mode = None
        old_sha = None
        if old_present:
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0:
                raise SystemExit("existing control target is unsafe")
            old_mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            old_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            backup = transaction / backup_name
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with target.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
        rows.append({
            "source": item["source"], "target": item["target"], "newMode": item["mode"],
            "newSha256": hashlib.sha256(source.read_bytes()).hexdigest(), "oldPresent": old_present,
            "oldMode": old_mode, "oldSha256": old_sha, "backup": backup_name if old_present else None,
        })
        index += 1
backup_parent = os.open(transaction / "backup", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(backup_parent)
finally:
    os.close(backup_parent)
document = {
    "schemaVersion": 1, "operation": "host-control-upgrade", "phase": "installing",
    "repositoryCommit": commit, "manifestSha256": manifest_sha,
    "transactionDirectory": str(transaction), "certificateAutomationInstalled": certificate,
    "certificateTimerEnabled": timer_enabled, "certificateTimerActive": timer_active,
    "previousControlEvidenceSha256": previous, "targets": rows,
}
descriptor, candidate = tempfile.mkstemp(prefix=".control-upgrade.", suffix=".json", dir=journal_path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        descriptor = -1
        json.dump(document, target, sort_keys=True, separators=(",", ":"))
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.chown(candidate, 0, 0)
    os.link(candidate, journal_path, follow_symlinks=False)
    parent = os.open(journal_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(candidate)
    except FileNotFoundError:
        pass
PY

active_transaction="${transaction}"
if [[ ${certificate_installed} == true ]]; then
  bounded 30s systemctl stop mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || fail "Certificate timer could not be stopped after the durable control-upgrade journal was armed."
fi
for record in "${records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  if [[ ${group} == certificateTargets && ${certificate_installed} == false ]]; then
    continue
  fi
  atomic_install "${candidate}/${relative}" "${target}" "${mode}" || fail "Host-control target publication failed; the durable journal was retained."
  [[ "$(sha256sum -- "${target}" | awk '{print $1}')" == "${digest}" ]] || fail "Published host-control target digest differs; the durable journal was retained."
done

post_install_readback "${candidate}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || {
  rollback_transaction "${transaction}" || fail "Host-control post-install readback failed and rollback is blocked."
  post_install_readback "${previous_source}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || fail "Host-control rollback service readback failed."
  clear_transaction "${transaction}" || fail "Rolled-back host-control journal could not be cleared."
  fail "Host-control post-install readback failed; the exact prior controls were restored."
}
seal_control_state upgrade "${expected_commit}" "${candidate}" "${previous_evidence_sha}" || fail "Host-control evidence commit failed; the durable journal was retained."
if ! bash "${candidate}/scripts/verify-host-security.sh" "${expected_commit}" "${candidate}" --upgrade-transaction >/dev/null 2>&1; then
  rollback_transaction "${transaction}" || fail "Upgraded host controls failed terminal verification and exact rollback is blocked."
  post_install_readback "${previous_source}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || fail "Terminal host-control rollback service readback failed."
  bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-transaction >/dev/null 2>&1 || fail "Terminal host-control rollback verification failed."
  clear_transaction "${transaction}" || fail "Terminally rolled-back host-control journal could not be cleared."
  fail "Upgraded host controls failed terminal verification; the exact prior controls were restored."
fi
clear_transaction "${transaction}" || fail "Completed host-control journal could not be cleared."
active_transaction=""
upgrade_complete=true
trap - EXIT HUP INT TERM
printf '%s\n' "Mochirii Forums host controls upgraded to exact canonical main and verified."
