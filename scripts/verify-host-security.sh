#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

bounded() {
  timeout --signal=TERM --kill-after=5s "$@"
}

[[ ${EUID} -eq 0 ]] || fail "Host-security verification must run as root."
[[ $# -eq 2 || ( $# -eq 3 && ( $3 == --upgrade-transaction || $3 == --socket-activation-recovery || $3 == --upgrade-socket-activation-recovery ) ) ]] || fail "Usage: verify-host-security.sh EXPECTED_COMMIT TRUSTED_SOURCE_ROOT [--upgrade-transaction|--socket-activation-recovery|--upgrade-socket-activation-recovery]"
expected_commit="$1"
source_root="$2"
transaction_mode=false
socket_activation_recovery=false
[[ ${3:-} != --upgrade-transaction && ${3:-} != --upgrade-socket-activation-recovery ]] || transaction_mode=true
[[ ${3:-} != --socket-activation-recovery && ${3:-} != --upgrade-socket-activation-recovery ]] || socket_activation_recovery=true
[[ ${expected_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Expected host-control commit is malformed."
[[ -d ${source_root} && ! -L ${source_root} ]] || fail "Trusted host-control source root is absent or linked."
source_root="$(readlink -f -- "${source_root}")"
manifest="${source_root}/config/host-control-manifest.v1.json"
[[ -f ${manifest} && ! -L ${manifest} ]] || fail "Host-control target manifest is absent or linked."

state_root=/var/lib/mochirii/forums
evidence_root="${state_root}/evidence"
access_pointer="${state_root}/current-host-access.json"
control_pointer="${state_root}/current-host-control.json"
policy=/etc/ssh/sshd_config.d/00-00-mochirii-forums.conf
operator_proof="${state_root}/operator-ssh-proved"
upgrades_root="${state_root}/control-upgrades"
pending_upgrade="${state_root}/control-upgrade.pending.json"
lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py

[[ -x ${lock_helper} && ! -L ${lock_helper} && "$(stat -c '%U:%G %a' "${lock_helper}")" == "root:root 755" ]] || fail "Installed host operation lock helper is unsafe."
"${lock_helper}" verify-namespace --locks primary,media || fail "Host operation lock namespace is unsafe."

[[ "$(stat -c '%U:%G %a' "${state_root}")" == "root:root 755" ]] || fail "Host-control state root must remain root:root mode 0755 for account traversal."
for directory in evidence logs operator-evidence quarantine; do
  path="${state_root}/${directory}"
  [[ -d ${path} && ! -L ${path} && "$(stat -c '%U:%G %a' "${path}")" == "root:root 700" ]] || fail "Sensitive host-control directory ${directory} is unsafe."
done
if [[ ${transaction_mode} == true ]]; then
  python3 -B - "${pending_upgrade}" "${upgrades_root}" "${source_root}" "${expected_commit}" "${control_pointer}" <<'PY' >/dev/null
import json
import pathlib
import re
import stat
import sys

journal_path = pathlib.Path(sys.argv[1])
upgrades_root = pathlib.Path(sys.argv[2])
source_root = pathlib.Path(sys.argv[3])
expected_commit = sys.argv[4]
pointer_path = pathlib.Path(sys.argv[5])
for path, mode in ((journal_path, 0o600), (upgrades_root, 0o700)):
    metadata = path.lstat()
    expected_type = stat.S_ISREG if path == journal_path else stat.S_ISDIR
    if not expected_type(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise SystemExit("host-control upgrade verification boundary is unsafe")
if journal_path.stat().st_size > 1024 * 1024:
    raise SystemExit("host-control upgrade journal exceeds its bound")
document = json.loads(journal_path.read_text(encoding="utf-8"))
keys = {
    "schemaVersion", "operation", "phase", "repositoryCommit", "manifestSha256",
    "transactionDirectory", "certificateAutomationInstalled", "certificateTimerEnabled",
    "certificateTimerActive", "previousControlEvidenceSha256", "sshActivationPredecessor", "targets",
}
if set(document) != keys or document.get("schemaVersion") != 1 or document.get("operation") != "host-control-upgrade" or document.get("phase") != "installing":
    raise SystemExit("host-control upgrade journal schema differs")
commit = document.get("repositoryCommit", "")
manifest_sha = document.get("manifestSha256", "")
transaction = pathlib.Path(document.get("transactionDirectory", ""))
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha) or transaction != upgrades_root / f"{commit}-{manifest_sha}":
    raise SystemExit("host-control upgrade journal identity differs")
if document.get("sshActivationPredecessor") not in {"service", "socket"}:
    raise SystemExit("host-control upgrade SSH activation predecessor differs")
metadata = transaction.lstat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("host-control upgrade transaction directory is unsafe")
if {entry.name for entry in upgrades_root.iterdir()} != {transaction.name}:
    raise SystemExit("host-control upgrade work-directory inventory differs")
candidate_source = transaction / "source"
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
forward_source = source_root == candidate_source and expected_commit == commit
rollback_pointer = transaction / "backup/current-host-control.json"
try:
    rollback_metadata = rollback_pointer.lstat()
    rollback_pointer_safe = (
        stat.S_ISREG(rollback_metadata.st_mode)
        and not stat.S_ISLNK(rollback_metadata.st_mode)
        and rollback_metadata.st_uid == 0
        and rollback_metadata.st_gid == 0
        and stat.S_IMODE(rollback_metadata.st_mode) == 0o600
    )
except FileNotFoundError:
    rollback_pointer_safe = False
rollback_source = (
    rollback_pointer_safe
    and pointer_path.read_bytes() == rollback_pointer.read_bytes()
    and pointer.get("repositoryCommit") == expected_commit
)
if not forward_source and not rollback_source:
    raise SystemExit("host-control upgrade verification source is not the exact forward or rollback state")
PY
else
  [[ ! -e ${pending_upgrade} && ! -L ${pending_upgrade} ]] || fail "A host-control upgrade transaction is incomplete."
  if [[ -e ${upgrades_root} || -L ${upgrades_root} ]]; then
    [[ -d ${upgrades_root} && ! -L ${upgrades_root} && "$(stat -c '%U:%G %a' "${upgrades_root}")" == "root:root 700" ]] || fail "Host-control upgrade work root is unsafe."
    [[ -z "$(find "${upgrades_root}" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail "An unjournaled host-control upgrade work directory remains."
  fi
fi

verify_account() {
  local user="$1" group="$2" home="$3" record password_status
  record="$(getent passwd "${user}")" || return 1
  IFS=: read -r account password uid gid gecos actual_home shell <<<"${record}"
  [[ ${account} == "${user}" && ${password} == x && ${uid} =~ ^[0-9]+$ && ${gid} =~ ^[0-9]+$ ]] || return 1
  [[ ${gecos} == "" && ${actual_home} == "${home}" && ${shell} == /bin/bash ]] || return 1
  [[ "$(getent group "${group}" | cut -d: -f3)" == "${gid}" ]] || return 1
  [[ "$(id -gn "${user}")" == "${group}" && "$(id -Gn "${user}")" == "${group}" ]] || return 1
  [[ "$(getent group "${group}" | cut -d: -f4)" == "" ]] || return 1
  password_status="$(passwd -S "${user}")" || return 1
  [[ "$(awk '{print $1 " " $2}' <<<"${password_status}")" == "${user} L" ]]
}

verify_account mochirii-forums-deploy mochirii-forums-deploy "${state_root}/deploy" || fail "Deploy account tuple, lock, or group inventory differs."
verify_account mochirii-forums-operator mochirii-forums-operator "${state_root}/operator" || fail "Operator account tuple, lock, or group inventory differs."
sudo -l -U mochirii-forums-deploy /usr/local/sbin/mochirii-forums-historical-disaster-recovery >/dev/null 2>&1 && fail "Deploy automation unexpectedly has historical disaster-recovery authority."
sudo -l -U mochirii-forums-deploy /usr/local/libexec/mochirii-forums/host-operation-lock.py >/dev/null 2>&1 && fail "Deploy automation unexpectedly has direct host-lock authority."
grep -Fq -- mochirii-forums-historical-disaster-recovery /etc/sudoers.d/mochirii-forums && fail "Deploy sudoers exposes historical disaster recovery."
grep -Fq -- historical /usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py && fail "Deploy SSH dispatch exposes a historical recovery verb."

for home in deploy operator; do
  [[ -d ${state_root}/${home} && ! -L ${state_root}/${home} && "$(stat -c '%U:%G %a' "${state_root}/${home}")" == "root:root 755" ]] || fail "${home} home ownership or mode differs."
  [[ -d ${state_root}/${home}/.ssh && ! -L ${state_root}/${home}/.ssh && "$(stat -c '%U:%G %a' "${state_root}/${home}/.ssh")" == "root:root 755" ]] || fail "${home} SSH tree ownership or mode differs."
  mapfile -t ssh_inventory < <(find "${state_root}/${home}/.ssh" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
  [[ ${#ssh_inventory[@]} -eq 1 && ${ssh_inventory[0]} == authorized_keys ]] || fail "${home} SSH tree contains an alternate key or user-rc source."
  key_file="${state_root}/${home}/.ssh/authorized_keys"
  [[ -f ${key_file} && ! -L ${key_file} && "$(stat -c '%U:%G %a' "${key_file}")" == "root:root 644" ]] || fail "${home} authorized key ownership or mode differs."
  sudo -u "mochirii-forums-${home}" test -r "${key_file}" || fail "${home} authorized key is unreadable after privilege drop."
done

[[ -f ${operator_proof} && ! -L ${operator_proof} && "$(stat -c '%U:%G %a' "${operator_proof}")" == "root:root 600" ]] || fail "Operator SSH proof is absent or unsafe."
[[ "$(cat -- "${operator_proof}")" == operatorSshAndSudoVerified=true ]] || fail "Operator SSH proof content differs."
[[ -f ${access_pointer} && ! -L ${access_pointer} && "$(stat -c '%U:%G %a' "${access_pointer}")" == "root:root 600" ]] || fail "Current host-access evidence is absent or unsafe."
python3 -B - "${access_pointer}" "${evidence_root}" \
  "${state_root}/deploy/.ssh/authorized_keys" "${state_root}/operator/.ssh/authorized_keys" \
  "${operator_proof}" <<'PY' >/dev/null
import hashlib
import json
import pathlib
import re
import stat
import sys

pointer_path, evidence_root, deploy_key, operator_key, proof = map(pathlib.Path, sys.argv[1:])
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
if set(pointer) != {"schemaVersion", "phase", "accessEvidenceFile", "accessEvidenceSha256"}:
    raise SystemExit("host-access pointer keys differ")
if pointer.get("schemaVersion") != 1 or pointer.get("phase") != "hardened":
    raise SystemExit("host-access state is not hardened")
name = pointer.get("accessEvidenceFile", "")
if not re.fullmatch(r"host-access-hardened-[0-9a-f]{64}[.]json", name):
    raise SystemExit("host-access evidence name differs")
record_path = evidence_root / name
metadata = record_path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("host-access evidence permissions differ")
raw = record_path.read_bytes()
if pointer.get("accessEvidenceSha256") != hashlib.sha256(raw).hexdigest():
    raise SystemExit("host-access evidence digest differs")
record = json.loads(raw)
expected_keys = {
    "schemaVersion", "recordedAt", "phase", "deployAuthorizedKeysSha256",
    "operatorAuthorizedKeysSha256", "operatorProofSha256",
}
if set(record) != expected_keys or record.get("schemaVersion") != 1 or record.get("phase") != "hardened":
    raise SystemExit("host-access evidence schema differs")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(record.get("recordedAt", ""))):
    raise SystemExit("host-access evidence timestamp differs")
for field, path in (
    ("deployAuthorizedKeysSha256", deploy_key),
    ("operatorAuthorizedKeysSha256", operator_key),
    ("operatorProofSha256", proof),
):
    if record.get(field) != hashlib.sha256(path.read_bytes()).hexdigest():
        raise SystemExit(f"{field} differs")
deploy_raw = deploy_key.read_bytes()
operator_raw = operator_key.read_bytes()
if len(deploy_raw) > 16384 or len(operator_raw) > 16384:
    raise SystemExit("authorized key exceeds its byte boundary")
try:
    deploy_text = deploy_raw.decode("ascii").splitlines()
    operator_text = operator_raw.decode("ascii").splitlines()
except UnicodeDecodeError:
    raise SystemExit("authorized key is not ASCII")
key = r"(ssh-ed25519|sk-ssh-ed25519@openssh[.]com) ([A-Za-z0-9+/=]+)(?: ([^\x00-\x1f\x7f]+))?"
deploy_match = re.fullmatch(r"restrict " + key, deploy_text[0]) if len(deploy_text) == 1 else None
operator_match = re.fullmatch(key, operator_text[0]) if len(operator_text) == 1 else None
if deploy_match is None or operator_match is None or deploy_match.group(2) == operator_match.group(2):
    raise SystemExit("authorized key syntax, restriction, or separation differs")
PY

[[ -f ${policy} && ! -L ${policy} && "$(stat -c '%U:%G %a' "${policy}")" == "root:root 644" ]] || fail "Managed SSH policy permissions differ."
for obsolete in /etc/ssh/sshd_config.d/50-mochirii-forums-hardening.conf /etc/ssh/sshd_config.d/60-mochirii-forums.conf; do
  [[ ! -e ${obsolete} && ! -L ${obsolete} ]] || fail "An obsolete managed SSH policy fragment remains."
done
bounded 15s sshd -t >/dev/null 2>&1 || fail "OpenSSH configuration validation failed or timed out."

effective_value() {
  local text="$1" setting="$2"
  awk -v setting="${setting}" '$1 == setting { found=$2 } END { print found }' <<<"${text}"
}

for user in root mochirii-forums-operator mochirii-forums-deploy; do
  effective="$(bounded 15s sshd -T -C "user=${user},host=forums.mochirii.com,addr=127.0.0.1")" || fail "Effective SSH readback for ${user} failed or timed out."
  [[ "$(effective_value "${effective}" passwordauthentication)" == no ]] || fail "SSH password authentication remains enabled for ${user}."
  [[ "$(effective_value "${effective}" kbdinteractiveauthentication)" == no ]] || fail "SSH keyboard-interactive authentication remains enabled for ${user}."
  [[ "$(effective_value "${effective}" pubkeyauthentication)" == yes ]] || fail "SSH public-key authentication differs for ${user}."
  [[ "$(effective_value "${effective}" authenticationmethods)" == publickey ]] || fail "SSH authentication methods differ for ${user}."
  [[ "$(effective_value "${effective}" authorizedkeyscommand)" == none ]] || fail "An SSH authorized-keys command is enabled for ${user}."
  [[ "$(effective_value "${effective}" authorizedkeyscommanduser)" == nobody ]] || fail "SSH authorized-keys command identity differs for ${user}."
  [[ "$(effective_value "${effective}" trustedusercakeys)" == none ]] || fail "An SSH user CA is enabled for ${user}."
  [[ "$(effective_value "${effective}" authorizedprincipalsfile)" == none ]] || fail "An SSH authorized-principals file is enabled for ${user}."
  [[ "$(effective_value "${effective}" authorizedprincipalscommand)" == none ]] || fail "An SSH authorized-principals command is enabled for ${user}."
  [[ "$(effective_value "${effective}" authorizedprincipalscommanduser)" == nobody ]] || fail "SSH authorized-principals command identity differs for ${user}."
  [[ "$(effective_value "${effective}" permituserenvironment)" == no ]] || fail "SSH user environment remains enabled for ${user}."
  [[ "$(effective_value "${effective}" permituserrc)" == no ]] || fail "SSH user rc remains enabled for ${user}."
  allow_users="$(awk '$1 == "allowusers" { for (i = 2; i <= NF; i++) { found = found (found == "" ? "" : " ") $i } } END { print found }' <<<"${effective}")"
  [[ ${allow_users} == "mochirii-forums-operator mochirii-forums-deploy" ]] || fail "SSH AllowUsers differs for ${user}."
  case "${user}" in
    root)
      [[ "$(effective_value "${effective}" permitrootlogin)" == no ]] || fail "SSH root login remains enabled."
      [[ "$(effective_value "${effective}" authorizedkeysfile)" == none ]] || fail "SSH root authorized-key source differs."
      [[ "$(effective_value "${effective}" forcecommand)" == none ]] || fail "SSH root force command differs."
      [[ "$(effective_value "${effective}" disableforwarding)" == yes && "$(effective_value "${effective}" permittty)" == no ]] || fail "SSH root confinement differs."
      ;;
    mochirii-forums-operator)
      [[ "$(effective_value "${effective}" authorizedkeysfile)" == "${state_root}/operator/.ssh/authorized_keys" ]] || fail "Operator authorized-key source differs."
      [[ "$(effective_value "${effective}" forcecommand)" == none ]] || fail "Operator account lost interactive command authority."
      [[ "$(effective_value "${effective}" disableforwarding)" == yes && "$(effective_value "${effective}" permittty)" == yes ]] || fail "Operator SSH session boundary differs."
      ;;
    mochirii-forums-deploy)
      [[ "$(effective_value "${effective}" authorizedkeysfile)" == "${state_root}/deploy/.ssh/authorized_keys" ]] || fail "Deploy authorized-key source differs."
      [[ "$(effective_value "${effective}" forcecommand)" == /usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py ]] || fail "Deploy daemon ForceCommand differs."
      [[ "$(effective_value "${effective}" disableforwarding)" == yes && "$(effective_value "${effective}" permittty)" == no ]] || fail "Deploy SSH confinement differs."
      ;;
  esac
done

[[ -f ${control_pointer} && ! -L ${control_pointer} && "$(stat -c '%U:%G %a' "${control_pointer}")" == "root:root 600" ]] || fail "Current host-control evidence is absent or unsafe."
[[ "$(stat -c '%s' "${control_pointer}")" =~ ^[1-9][0-9]*$ ]] || fail "Current host-control evidence is empty or unreadable."
(( $(stat -c '%s' "${control_pointer}") <= 65536 )) || fail "Current host-control evidence exceeds its byte boundary."
python3 -B - "${manifest}" "${source_root}" "${control_pointer}" "${evidence_root}" "${expected_commit}" <<'PY' >/dev/null
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

manifest_path = pathlib.Path(sys.argv[1])
source_root = pathlib.Path(sys.argv[2])
pointer_path = pathlib.Path(sys.argv[3])
evidence_root = pathlib.Path(sys.argv[4])
commit = sys.argv[5]
MAX_JSON_BYTES = 65_536
MAX_ARCHIVE_BYTES = 67_108_864


def bounded_read(path: pathlib.Path, maximum: int, label: str) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if not raw or len(raw) > maximum:
        raise SystemExit(f"{label} size differs")
    return raw


manifest_raw = manifest_path.read_bytes()
manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
manifest = json.loads(manifest_raw)
if set(manifest) != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"} or manifest.get("schemaVersion") != 1:
    raise SystemExit("host-control manifest schema differs")

groups = {}
all_targets = set()
all_sources = set()
for group in ("coreTargets", "hostPolicyTargets", "certificateTargets"):
    rows = manifest.get(group)
    if not isinstance(rows, list) or not rows:
        raise SystemExit("host-control target group is empty")
    parsed = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"source", "target", "mode"}:
            raise SystemExit("host-control target row differs")
        relative, target, mode = row["source"], row["target"], row["mode"]
        if not re.fullmatch(r"(?:config|scripts)/[A-Za-z0-9._-]+", relative):
            raise SystemExit("host-control source path differs")
        if not isinstance(target, str) or not target.startswith(("/etc/", "/usr/local/")) or ".." in pathlib.PurePosixPath(target).parts:
            raise SystemExit("host-control target path differs")
        if mode not in {"0440", "0644", "0755"} or target in all_targets or relative in all_sources:
            raise SystemExit("host-control target row duplicates or mode differs")
        source = source_root / relative
        if not source.is_file() or source.is_symlink():
            raise SystemExit("host-control source is absent or linked")
        parsed.append((target, mode, hashlib.sha256(source.read_bytes()).hexdigest()))
        all_targets.add(target)
        all_sources.add(relative)
    groups[group] = parsed

historical_recovery = {
    "source": "scripts/historical-release-disaster-recovery.py",
    "target": "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
    "mode": "0755",
}
if historical_recovery not in manifest["coreTargets"]:
    raise SystemExit("historical disaster-recovery host-control authority is absent")
required_historical = {
    ("scripts/historical-recovery-scratch-reader.sh", "/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh", "0755"),
    ("scripts/host-historical-disaster-recovery.sh", "/usr/local/sbin/mochirii-forums-historical-disaster-recovery", "0755"),
    ("scripts/host-operation-lock.py", "/usr/local/libexec/mochirii-forums/host-operation-lock.py", "0755"),
}
if not required_historical.issubset({(row["source"], row["target"], row["mode"]) for row in manifest["coreTargets"]}):
    raise SystemExit("historical disaster-recovery executable entrypoint is absent")

pointer_metadata = pointer_path.lstat()
if (
    not stat.S_ISREG(pointer_metadata.st_mode)
    or stat.S_ISLNK(pointer_metadata.st_mode)
    or pointer_metadata.st_uid != 0
    or pointer_metadata.st_gid != 0
    or stat.S_IMODE(pointer_metadata.st_mode) != 0o600
    or not 1 <= pointer_metadata.st_size <= MAX_JSON_BYTES
):
    raise SystemExit("host-control pointer permissions or size differ")
pointer = json.loads(bounded_read(pointer_path, MAX_JSON_BYTES, "host-control pointer"))
pointer_keys = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256", "targetSetSha256",
    "controlEvidenceFile", "controlEvidenceSha256", "releaseArchiveFile", "releaseArchiveSha256",
    "releaseArchiveBytes", "releaseArchiveContentManifestSha256", "deploymentSourceRevision",
    "deploymentSourceTree", "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256",
    "deploymentSourceArchiveBytes", "deploymentSourceContentManifestSha256",
}
if set(pointer) != pointer_keys or pointer.get("schemaVersion") != 1 or pointer.get("phase") != "hardened":
    raise SystemExit("host-control pointer schema or phase differs")
if pointer.get("repositoryCommit") != commit or pointer.get("manifestSha256") != manifest_sha:
    raise SystemExit("host-control pointer release binding differs")
name = pointer.get("controlEvidenceFile", "")
if not re.fullmatch(rf"{commit}-[0-9a-f]{{64}}-host-control[.]json", name):
    raise SystemExit("host-control evidence name differs")
record_path = evidence_root / name
metadata = record_path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or not 1 <= metadata.st_size <= MAX_JSON_BYTES
):
    raise SystemExit("host-control evidence permissions or size differ")
record_raw = bounded_read(record_path, MAX_JSON_BYTES, "host-control evidence")
if pointer.get("controlEvidenceSha256") != hashlib.sha256(record_raw).hexdigest():
    raise SystemExit("host-control evidence digest differs")
record = json.loads(record_raw)
record_keys = {
    "schemaVersion", "recordedAt", "operation", "phase", "repositoryCommit",
    "manifestSha256", "targetSetSha256", "previousControlEvidenceSha256", "targets",
    "repositoryTree", "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(record) != record_keys or record.get("schemaVersion") != 1 or record.get("phase") != "hardened":
    raise SystemExit("host-control evidence schema differs")
if record.get("operation") not in {"initial-install", "upgrade", "certificate-install"} or record.get("repositoryCommit") != commit or record.get("manifestSha256") != manifest_sha:
    raise SystemExit("host-control evidence binding differs")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(record.get("recordedAt", ""))):
    raise SystemExit("host-control evidence timestamp differs")
if record.get("previousControlEvidenceSha256") is not None and not re.fullmatch(r"[0-9a-f]{64}", str(record.get("previousControlEvidenceSha256"))):
    raise SystemExit("host-control predecessor digest differs")
archive_keys = pointer_keys - {
    "schemaVersion", "phase", "repositoryCommit", "manifestSha256", "targetSetSha256",
    "controlEvidenceFile", "controlEvidenceSha256",
}
for key in archive_keys:
    if pointer.get(key) != record.get(key):
        raise SystemExit("host-control retained archive binding differs")
for path_key, sha_key, bytes_key in (
    ("releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes"),
    ("deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes"),
):
    path = pathlib.Path(str(pointer.get(path_key, "")))
    expected_bytes = pointer.get(bytes_key)
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or not 1 <= expected_bytes <= MAX_ARCHIVE_BYTES:
        raise SystemExit("retained recovery archive byte identity is malformed")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != expected_bytes
    ):
        raise SystemExit("retained recovery archive permissions or size differ")
    raw = bounded_read(path, MAX_ARCHIVE_BYTES, "retained recovery archive")
    if hashlib.sha256(raw).hexdigest() != pointer.get(sha_key) or len(raw) != expected_bytes:
        raise SystemExit("retained recovery archive bytes differ")
if pointer.get("releaseArchiveFile") != f"/opt/mochirii/forums/host-control-releases/{commit}/mochirii-release.tar":
    raise SystemExit("retained host-control archive path differs")
if pointer.get("deploymentSourceRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b" or pointer.get("deploymentSourceTree") != "588498dffbea91592fd4e2f10166bc11c8fe7a61":
    raise SystemExit("retained deployment-source pin differs")
if pointer.get("deploymentSourceArchiveFile") != "/opt/mochirii/forums/deployment-source/ed9f680b0df1de28f062de1769d89d22b2644d1b.tar":
    raise SystemExit("retained deployment-source archive path differs")
for key in ("repositoryTree", "releaseArchiveSha256", "releaseArchiveContentManifestSha256", "deploymentSourceArchiveSha256", "deploymentSourceContentManifestSha256"):
    pattern = r"[0-9a-f]{40}" if key == "repositoryTree" else r"[0-9a-f]{64}"
    if re.fullmatch(pattern, str(pointer.get(key, ""))) is None:
        raise SystemExit("retained recovery archive identity is malformed")
evidence_targets = record.get("targets")
if not isinstance(evidence_targets, dict):
    raise SystemExit("host-control target evidence differs")
certificate_presence = [pathlib.Path(target).exists() or pathlib.Path(target).is_symlink() for target, _, _ in groups["certificateTargets"]]
if any(certificate_presence) and not all(certificate_presence):
    raise SystemExit("certificate automation target set is partial")
expected_evidence_targets = {
    target
    for group in ("coreTargets", "hostPolicyTargets")
    for target, _, _ in groups[group]
}
if all(certificate_presence):
    expected_evidence_targets.update(target for target, _, _ in groups["certificateTargets"])
if set(evidence_targets) != expected_evidence_targets:
    raise SystemExit("host-control evidence target inventory differs")
records = []
for target, item in sorted(evidence_targets.items()):
    if not isinstance(item, dict) or set(item) != {"mode", "sha256"} or item["mode"] not in {"0440", "0644", "0755"} or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
        raise SystemExit("host-control target evidence row differs")
    path = pathlib.Path(target)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != int(item["mode"], 8):
        raise SystemExit("host-control evidenced target permissions differ")
    if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
        raise SystemExit("host-control evidenced target bytes differ")
    records.append(f"{target}\0{item['mode']}\0{item['sha256']}\n".encode())
target_set_sha = hashlib.sha256(b"".join(records)).hexdigest()
if record.get("targetSetSha256") != target_set_sha or pointer.get("targetSetSha256") != target_set_sha:
    raise SystemExit("host-control target-set digest differs")

for group in ("coreTargets", "hostPolicyTargets"):
    for target, mode, expected_sha in groups[group]:
        path = pathlib.Path(target)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != int(mode, 8):
            raise SystemExit("required host-control target permissions differ")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
            raise SystemExit("required host-control target differs from trusted source")

if all(certificate_presence):
    for target, mode, expected_sha in groups["certificateTargets"]:
        path = pathlib.Path(target)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != int(mode, 8):
            raise SystemExit("certificate automation target permissions differ")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
            raise SystemExit("certificate automation differs from trusted source")
PY

release_archive_inspection="$(python3 -B "${source_root}/scripts/historical-release-disaster-recovery.py" inspect \
  --archive "/opt/mochirii/forums/host-control-releases/${expected_commit}/mochirii-release.tar" \
  --expected-commit "${expected_commit}")" || fail "Retained host-control recovery archive inspection failed."
python3 -B - "${control_pointer}" "${release_archive_inspection}" <<'PY' >/dev/null || fail "Retained host-control recovery archive binding differs."
import json
import pathlib
import sys
pointer = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
inspection = json.loads(sys.argv[2])
bindings = {
    "repositoryTree": "repositoryTree",
    "releaseArchiveSha256": "releaseArchiveSha256",
    "releaseArchiveBytes": "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256": "releaseArchiveContentManifestSha256",
}
if any(pointer.get(target) != inspection.get(source) for target, source in bindings.items()):
    raise SystemExit("retained host-control archive inspection differs")
PY
deployment_archive_candidate="$(mktemp "${state_root}/.verify-deployment-source.XXXXXXXX.tar")"
git -c tar.umask=0002 -C /var/discourse archive --format=tar --output="${deployment_archive_candidate}" ed9f680b0df1de28f062de1769d89d22b2644d1b >/dev/null 2>&1 || {
  rm -f -- "${deployment_archive_candidate}"
  fail "Official deployment-source archive reconstruction failed."
}
cmp -s -- "${deployment_archive_candidate}" /opt/mochirii/forums/deployment-source/ed9f680b0df1de28f062de1769d89d22b2644d1b.tar || {
  rm -f -- "${deployment_archive_candidate}"
  fail "Retained official deployment-source archive differs from the pinned checkout."
}
rm -f -- "${deployment_archive_candidate}"

service_state() {
  local unit="$1"
  [[ "$(bounded 15s systemctl is-enabled "${unit}" 2>/dev/null)" == enabled ]] || return 1
  [[ "$(bounded 15s systemctl is-active "${unit}" 2>/dev/null)" == active ]]
}

ssh_generator_parent=/etc/systemd/system-generators
ssh_generator_mask=/etc/systemd/system-generators/sshd-socket-generator
if [[ ${socket_activation_recovery} == true ]]; then
  if [[ -e ${ssh_generator_parent} || -L ${ssh_generator_parent} ]]; then
    [[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} && "$(stat -c '%U:%G %a' -- "${ssh_generator_parent}")" == "root:root 755" ]] || fail "OpenSSH socket-generator parent is unsafe."
  fi
  [[ ! -e ${ssh_generator_mask} && ! -L ${ssh_generator_mask} ]] || fail "OpenSSH socket-activation recovery mask state differs."
  [[ "$(bounded 15s systemctl is-enabled ssh.service 2>/dev/null || true)" == disabled ]] || fail "OpenSSH socket-activation recovery service-enable state differs."
  [[ "$(bounded 15s systemctl is-active ssh.service 2>/dev/null || true)" == active ]] || fail "OpenSSH socket-activation recovery service-active state differs."
  [[ "$(bounded 15s systemctl is-enabled ssh.socket 2>/dev/null || true)" == enabled ]] || fail "OpenSSH socket-activation recovery socket-enable state differs."
  [[ "$(bounded 15s systemctl is-active ssh.socket 2>/dev/null || true)" == active ]] || fail "OpenSSH socket-activation recovery socket-active state differs."
else
  [[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} && "$(stat -c '%U:%G %a' -- "${ssh_generator_parent}")" == "root:root 755" ]] || fail "OpenSSH socket-generator parent is unsafe."
  [[ -L ${ssh_generator_mask} && "$(readlink -- "${ssh_generator_mask}")" == /dev/null ]] || fail "OpenSSH socket generator is not exactly masked."
  [[ "$(stat -c '%U:%G' -- "${ssh_generator_mask}")" == root:root ]] || fail "OpenSSH socket-generator mask ownership differs."
  service_state ssh.service || fail "OpenSSH service is not enabled and active."
  [[ "$(bounded 15s systemctl is-enabled ssh.socket 2>/dev/null || true)" == disabled ]] || fail "OpenSSH socket remains enabled."
  [[ "$(bounded 15s systemctl is-active ssh.socket 2>/dev/null || true)" == inactive ]] || fail "OpenSSH socket remains active."
fi
service_state docker || fail "Docker service is not enabled and active."
service_state fail2ban || fail "fail2ban service is not enabled and active."
service_state unattended-upgrades || fail "Unattended-upgrades service is not enabled and active."
service_state apt-daily.timer || fail "APT daily timer is not enabled and active."
service_state apt-daily-upgrade.timer || fail "APT unattended-upgrade timer is not enabled and active."
if [[ -e /etc/systemd/system/mochirii-forums-media-certificate-renew.timer || -L /etc/systemd/system/mochirii-forums-media-certificate-renew.timer ]]; then
  service_state mochirii-forums-media-certificate-renew.timer || fail "Media certificate renewal timer is not enabled and active."
fi
bounded 20s fail2ban-client status sshd >/dev/null 2>&1 || fail "fail2ban SSH jail is not active."
[[ "$(bounded 20s docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null)" == linux/amd64 ]] || fail "Docker server platform differs or readback timed out."

. /etc/os-release
[[ ${ID} == ubuntu && ${VERSION_ID} == 24.04 ]] || fail "Host operating system differs from Ubuntu 24.04."
[[ "$(nproc)" -eq 1 ]] || fail "Host does not expose exactly one CPU."
memory_mib="$(awk '/MemTotal/ { print int($2 / 1024) }' /proc/meminfo)"
[[ ${memory_mib} -ge 1900 && ${memory_mib} -le 2300 ]] || fail "Host memory is outside the reviewed 2 GiB class."
[[ -f /swapfile && ! -L /swapfile && "$(stat -c '%U:%G %a %s' /swapfile)" == "root:root 600 2147483648" ]] || fail "Swap file differs from the exact 2 GiB boundary."
swap_names="$(bounded 15s swapon --show=NAME --noheadings)" || fail "Active swap inventory failed or timed out."
grep -Fx /swapfile <<<"${swap_names}" >/dev/null || fail "Reviewed swap file is not active."
[[ "$(grep -Ec '^/swapfile[[:space:]]+none[[:space:]]+swap[[:space:]]+sw[[:space:]]+0[[:space:]]+0$' /etc/fstab)" -eq 1 ]] || fail "Persistent swap entry differs."

[[ -f /etc/default/ufw && "$(awk -F= '$1 == "IPV6" { print $2 }' /etc/default/ufw)" == yes ]] || fail "UFW IPv6 enforcement differs."
ufw_readback="$(mktemp "${state_root}/logs/.ufw.XXXXXXXX")"
listeners_readback="$(mktemp "${state_root}/logs/.listeners.XXXXXXXX")"
trap 'rm -f -- "${ufw_readback}" "${listeners_readback}"' EXIT
chmod 0600 "${ufw_readback}" "${listeners_readback}"
bounded 20s ufw status verbose >"${ufw_readback}" 2>/dev/null || fail "UFW readback failed or timed out."
python3 -B - "${ufw_readback}" <<'PY' >/dev/null
import pathlib
import re
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if "Status: active" not in text:
    raise SystemExit("UFW is inactive")
default = next((line for line in text.splitlines() if line.startswith("Default:")), "")
if not re.fullmatch(r"Default: deny \(incoming\), allow \(outgoing\), (?:disabled|deny) \(routed\)", default):
    raise SystemExit("UFW defaults differ")
rules = set()
for line in text.splitlines():
    compact = " ".join(line.split())
    if re.match(r"^(22|80|443)/tcp(?: \(v6\))? ", compact):
        rules.add(compact)
    elif " ALLOW " in f" {compact} " or " DENY " in f" {compact} " or " REJECT " in f" {compact} ":
        raise SystemExit("unexpected UFW rule")
expected = {
    "22/tcp ALLOW IN Anywhere", "80/tcp ALLOW IN Anywhere", "443/tcp ALLOW IN Anywhere",
    "22/tcp (v6) ALLOW IN Anywhere (v6)", "80/tcp (v6) ALLOW IN Anywhere (v6)",
    "443/tcp (v6) ALLOW IN Anywhere (v6)",
}
if rules != expected:
    raise SystemExit("UFW allowlist differs")
PY

bounded 15s ss -H -ltn >"${listeners_readback}" 2>/dev/null || fail "Host listener readback failed or timed out."
python3 -B - "${listeners_readback}" <<'PY' >/dev/null
import pathlib
import sys
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) < 4:
        raise SystemExit("listener row is malformed")
    local = fields[3]
    host, separator, port = local.rpartition(":")
    if not separator or not port.isdigit():
        raise SystemExit("listener endpoint is malformed")
    number = int(port)
    if number in {5432, 6379}:
        raise SystemExit("database or cache listener is exposed")
    normalized = host.strip("[]")
    if normalized in {"", "*", "0.0.0.0", "::"} and number not in {22, 80, 443}:
        raise SystemExit("unexpected public listener")
PY

rm -f -- "${ufw_readback}" "${listeners_readback}"
trap - EXIT
printf '%s\n' "Mochirii Forums host-security verification passed."
