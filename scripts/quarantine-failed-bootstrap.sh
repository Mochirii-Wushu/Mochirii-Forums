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

readonly canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"
readonly source_root="/root/Mochirii-Forums"
readonly state_root="/var/lib/mochirii/forums"
readonly evidence_root="${state_root}/evidence"
readonly deployment_journal="${state_root}/deployment-mutation.json"
readonly pending_journal="${state_root}/failed-bootstrap-quarantine.pending.json"
readonly shared_root="/var/discourse/shared"
readonly standalone_root="${shared_root}/standalone"
readonly recovery_root="${shared_root}/.mochirii-forums-failed-bootstrap"
readonly reviewed_failed_bootstrap_recovery_commit="1d741eb75d08a226984935aa18e989ee324a0773"

validate_source_lineage() {
  local current="$1" failed="$2" status_output remote_output
  local -a actual_paths expected_paths=(
    .github/workflows/deploy-forums.yml
    config/host-control-manifest.v1.json
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  [[ -d ${source_root}/.git && ! -L ${source_root}/.git ]] || return 1
  [[ "$(git -C "${source_root}" rev-parse --verify HEAD^{commit} 2>/dev/null)" == "${current}" ]] || return 1
  [[ "$(git -C "${source_root}" symbolic-ref --short -q HEAD 2>/dev/null)" == main ]] || return 1
  [[ "$(git -C "${source_root}" rev-parse --verify "${current}^1" 2>/dev/null)" == "${reviewed_failed_bootstrap_recovery_commit}" ]] || return 1
  [[ "$(git -C "${source_root}" rev-list --parents -n 1 "${current}" 2>/dev/null)" == "${current} ${reviewed_failed_bootstrap_recovery_commit}" ]] || return 1
  [[ "$(git -C "${source_root}" rev-parse --verify "${reviewed_failed_bootstrap_recovery_commit}^1" 2>/dev/null)" == "${failed}" ]] || return 1
  [[ "$(git -C "${source_root}" rev-list --parents -n 1 "${reviewed_failed_bootstrap_recovery_commit}" 2>/dev/null)" == "${reviewed_failed_bootstrap_recovery_commit} ${failed}" ]] || return 1
  status_output="$(git -c core.fsmonitor=false -C "${source_root}" status --porcelain=v1 --untracked-files=all 2>/dev/null)" || return 1
  (( ${#status_output} <= 262144 )) || return 1
  [[ -z ${status_output} ]] || return 1
  [[ "$(git -C "${source_root}" remote get-url origin 2>/dev/null)" == "${canonical_repository}" ]] || return 1
  remote_output="$(bounded 120s git -c credential.helper= -c core.askPass= -c protocol.allow=never -c protocol.https.allow=always -c http.followRedirects=false ls-remote --refs "${canonical_repository}" refs/heads/main 2>/dev/null)" || return 1
  (( ${#remote_output} <= 256 )) || return 1
  [[ ${remote_output} == "${current}"$'\trefs/heads/main' ]] || return 1
  mapfile -t actual_paths < <(git -C "${source_root}" diff-tree --no-commit-id --name-only -r "${failed}" "${current}") || return 1
  [[ ${#actual_paths[@]} -eq ${#expected_paths[@]} ]] || return 1
  for index in "${!expected_paths[@]}"; do
    [[ ${actual_paths[$index]} == "${expected_paths[$index]}" ]] || return 1
  done
}

read_mutation_identity() {
  python3 -B - "${deployment_journal}" <<'PY'
import hashlib
import json
import itertools
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_nlink != 1
    or metadata.st_size <= 0
    or metadata.st_size > 65_536
):
    raise SystemExit("failed bootstrap journal is unsafe")
raw = path.read_bytes()

def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

try:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit("failed bootstrap journal is malformed") from error
keys = {
    "schemaVersion", "phase", "recordedAt", "updatedAt", "deploymentMode",
    "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
    "requestedDiscourseConnect", "targetAppConfigurationFile",
    "targetAppConfigurationSha256", "targetRestoreConfigurationFile",
    "targetRestoreConfigurationSha256", "targetActivationConfigurationFile",
    "targetActivationConfigurationSha256", "previousRepositoryCommit",
    "previousProductionConfigurationSha256", "previousCurrentReleaseSha256",
    "previousAppConfigurationFile", "previousAppConfigurationSha256",
    "previousCurrentTarget", "activeConfigurationFile", "activeConfigurationSha256",
    "launcherOperationToken", "launcherPreviousImageId", "launcherCommand",
    "databaseMutationPossible", "applicationStopped",
}
canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
previous = (
    "previousRepositoryCommit", "previousProductionConfigurationSha256",
    "previousCurrentReleaseSha256", "previousAppConfigurationFile",
    "previousAppConfigurationSha256", "previousCurrentTarget",
)
if (
    not isinstance(document, dict)
    or set(document) != keys
    or raw != canonical
    or document.get("schemaVersion") != 1
    or document.get("phase") != "runtime-contained"
    or document.get("deploymentMode") != "bootstrap"
    or re.fullmatch(r"[0-9a-f]{40}", str(document.get("repositoryCommit", ""))) is None
    or re.fullmatch(r"[0-9a-f]{64}", str(document.get("productionConfigurationSha256", ""))) is None
    or re.fullmatch(r"[0-9a-f]{64}", str(document.get("releaseArchiveSha256", ""))) is None
    or document.get("requestedDiscourseConnect") is not False
    or any(document.get(key) is not None for key in previous)
    or document.get("targetActivationConfigurationFile") is not None
    or document.get("targetActivationConfigurationSha256") is not None
    or document.get("activeConfigurationFile") != document.get("targetAppConfigurationFile")
    or document.get("activeConfigurationSha256") != document.get("targetAppConfigurationSha256")
    or document.get("launcherOperationToken") is not None
    or document.get("launcherPreviousImageId") is not None
    or document.get("launcherCommand") is not None
    or document.get("databaseMutationPossible") is not True
    or document.get("applicationStopped") is not True
):
    raise SystemExit("failed bootstrap journal tuple differs")
print(document["repositoryCommit"])
print(document["productionConfigurationSha256"])
print(document["releaseArchiveSha256"])
print(document["targetAppConfigurationFile"])
print(hashlib.sha256(raw).hexdigest())
PY
}

validate_quarantine_environment() {
  local app_inventory cleanup_inventory
  [[ -d ${state_root} && ! -L ${state_root} && "$(stat -c '%U:%G %a' -- "${state_root}")" == "root:root 755" ]] || return 1
  [[ -d ${evidence_root} && ! -L ${evidence_root} && "$(stat -c '%U:%G %a' -- "${evidence_root}")" == "root:root 700" ]] || return 1
  [[ -d ${shared_root} && ! -L ${shared_root} ]] || return 1
  if [[ -e ${recovery_root} || -L ${recovery_root} ]]; then
    [[ -d ${recovery_root} && ! -L ${recovery_root} && "$(stat -c '%U:%G %a' -- "${recovery_root}")" == "root:root 700" ]] || return 1
  fi
  [[ ! -e /var/lib/mochirii/forums/current-release.json && ! -L /var/lib/mochirii/forums/current-release.json ]] || return 1
  [[ ! -e /opt/mochirii/forums/current && ! -L /opt/mochirii/forums/current ]] || return 1
  [[ ! -e /var/discourse/containers/app.yml && ! -L /var/discourse/containers/app.yml ]] || return 1
  app_inventory="$(bounded 20s docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || return 1
  (( ${#app_inventory} <= 64 )) || return 1
  [[ -z ${app_inventory} ]] || return 1
  for path in \
    "${state_root}/deployment-transaction.json" \
    "${state_root}/deployment-forward-fix-required.json" \
    "${state_root}/current-deployment.json" \
    "${state_root}/backup-transaction.json" \
    "${state_root}/restore-transaction.json" \
    "${state_root}/media-certificate-install.pending.json" \
    "${state_root}/media-certificate-preparation.pending.json" \
    "${state_root}/media-certificate-rotation.pending.json" \
    "${state_root}/acme-challenge-transaction.json"; do
    [[ ! -e ${path} && ! -L ${path} ]] || return 1
  done
  cleanup_inventory="$(bounded 10s find "${evidence_root}" -maxdepth 1 \
    \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) \
    -print -quit 2>/dev/null)" || return 1
  (( ${#cleanup_inventory} <= 4096 )) || return 1
  [[ -z ${cleanup_inventory} ]]
}

read_quarantine_identity() {
  local kind="$1" current="$2" failed="$3"
  python3 -B - "${kind}" "${pending_journal}" "${evidence_root}" "${current}" "${failed}" <<'PY'
import json
import pathlib
import re
import stat
import sys

kind, pending_name, evidence_name, current, failed = sys.argv[1:6]
pending = pathlib.Path(pending_name)
evidence = pathlib.Path(evidence_name)
sha_pattern = r"[0-9a-f]{64}"
timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
base_keys = {
    "schemaVersion", "operation", "phase", "recordedAt", "updatedAt",
    "currentControlCommit", "failedReleaseCommit", "mutationSha256",
    "standalonePath", "quarantinePath", "mutationEvidencePath",
    "standaloneUid", "standaloneGid", "standaloneMode", "sslPresent",
}

def reject_duplicate(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document

def read_exact(path):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery evidence is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > 65_536
    ):
        raise SystemExit("failed-bootstrap recovery evidence is unsafe")
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit("failed-bootstrap recovery evidence is malformed") from error
    canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if raw != canonical:
        raise SystemExit("failed-bootstrap recovery evidence is noncanonical")
    return document

def valid_base(document, phases):
    mode = document.get("standaloneMode")
    uid = document.get("standaloneUid")
    gid = document.get("standaloneGid")
    return (
        document.get("schemaVersion") == 1
        and document.get("operation") == "failed-bootstrap-quarantine"
        and document.get("phase") in phases
        and document.get("currentControlCommit") == current
        and document.get("failedReleaseCommit") == failed
        and re.fullmatch(sha_pattern, str(document.get("mutationSha256", ""))) is not None
        and timestamp_pattern.fullmatch(str(document.get("recordedAt", ""))) is not None
        and timestamp_pattern.fullmatch(str(document.get("updatedAt", ""))) is not None
        and type(uid) is int and 0 <= uid <= 2_147_483_647
        and type(gid) is int and 0 <= gid <= 2_147_483_647
        and type(mode) is int and 0 <= mode <= 0o777
        and mode & 0o700 == 0o700 and mode & 0o002 == 0
        and type(document.get("sslPresent")) is bool
    )

if kind == "pending":
    document = read_exact(pending)
    if set(document) != base_keys or not valid_base(document, {"prepared", "runtime-quarantined", "clean-boundary", "authority-retired"}):
        raise SystemExit("failed-bootstrap pending identity differs")
elif kind == "terminal":
    try:
        metadata = evidence.lstat()
        entries = list(itertools.islice(evidence.iterdir(), 4097))
    except OSError as error:
        raise SystemExit("failed-bootstrap terminal inventory is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or len(entries) > 4096
    ):
        raise SystemExit("failed-bootstrap terminal inventory is unsafe")
    name_pattern = re.compile(rf"{re.escape(failed)}-({sha_pattern})-failed-bootstrap-quarantine\.json")
    matches = [entry for entry in entries if name_pattern.fullmatch(entry.name)]
    if len(matches) != 1:
        raise SystemExit("failed-bootstrap terminal identity is ambiguous")
    document = read_exact(matches[0])
    if (
        set(document) != base_keys | {"completedAt", "sslRestored"}
        or not valid_base(document, {"complete"})
        or timestamp_pattern.fullmatch(str(document.get("completedAt", ""))) is None
        or document.get("sslRestored") is not document.get("sslPresent")
        or name_pattern.fullmatch(matches[0].name).group(1) != document.get("mutationSha256")
    ):
        raise SystemExit("failed-bootstrap terminal identity differs")
else:
    raise SystemExit("failed-bootstrap recovery identity kind differs")

print(document["currentControlCommit"])
print(document["failedReleaseCommit"])
print(document["mutationSha256"])
PY
}

validate_failed_bootstrap_state() {
  local current="$1" failed configuration archive_sha target_app journal_sha release_helper
  local -a identity inspection
  readarray -t identity < <(read_mutation_identity) || return 1
  [[ ${#identity[@]} -eq 5 ]] || return 1
  failed="${identity[0]}"
  configuration="${identity[1]}"
  archive_sha="${identity[2]}"
  target_app="${identity[3]}"
  journal_sha="${identity[4]}"
  validate_source_lineage "${current}" "${failed}" || return 1
  release_helper="/opt/mochirii/forums/releases/${failed}/scripts/deployment-mutation.py"
  [[ -f ${release_helper} && ! -L ${release_helper} ]] || return 1
  readarray -t inspection < <(python3 -B "${release_helper}" inspect --path "${deployment_journal}" \
    --mode bootstrap --commit "${failed}" --configuration "${configuration}" \
    --archive-sha "${archive_sha}" --requested-connect false) || return 1
  [[ ${#inspection[@]} -eq 14 ]] || return 1
  [[ ${inspection[0]} == runtime-contained && ${inspection[7]} == "${target_app}" && ${inspection[8]} == "${configuration}" ]] || return 1
  for index in 1 2 3 4 5 6 9 10 11; do [[ ${inspection[$index]} == - ]] || return 1; done
  [[ ${inspection[12]} == true && ${inspection[13]} == true ]] || return 1
  validate_quarantine_environment || return 1
  [[ -d ${standalone_root} && ! -L ${standalone_root} ]] || return 1
  [[ -d ${standalone_root}/postgres_data && ! -L ${standalone_root}/postgres_data ]] || return 1
  [[ ! -e ${standalone_root}/ssl || ( -d ${standalone_root}/ssl && ! -L ${standalone_root}/ssl ) ]] || return 1
  [[ ! -e ${pending_journal} && ! -L ${pending_journal} ]] || return 1
  for path in \
    "${recovery_root}/${failed}-${journal_sha}" \
    "${evidence_root}/${failed}-${journal_sha}-deployment-mutation.json" \
    "${evidence_root}/${failed}-${journal_sha}-failed-bootstrap-quarantine.json"; do
    [[ ! -e ${path} && ! -L ${path} ]] || return 1
  done
  printf '%s\n%s\n' "${failed}" "${journal_sha}"
}

[[ ${EUID} -eq 0 ]] || fail "Failed-bootstrap quarantine must run as root."
if [[ ${1:-} == --upgrade-preflight ]]; then
  [[ $# -eq 2 && $2 =~ ^[0-9a-f]{40}$ ]] || fail "Failed-bootstrap upgrade preflight arguments differ."
  readarray -t preflight < <(validate_failed_bootstrap_state "$2") || fail "Failed-bootstrap upgrade preflight rejected the retained state."
  [[ ${#preflight[@]} -eq 2 ]] || fail "Failed-bootstrap upgrade preflight output differs."
  printf '%s\n' "${preflight[0]}"
  exit 0
fi

[[ $# -eq 3 ]] || fail "Usage: mochirii-forums-quarantine-failed-bootstrap CURRENT_COMMIT FAILED_COMMIT 'QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP'"
current_commit="$1"
failed_commit="$2"
confirmation="$3"
[[ ${current_commit} =~ ^[0-9a-f]{40}$ && ${failed_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Failed-bootstrap quarantine commit is malformed."
[[ ${confirmation} == "QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP" ]] || fail "Exact failed-bootstrap quarantine confirmation is required."
[[ ${SUDO_USER:-} == mochirii-forums-operator && -n ${SSH_CONNECTION:-} ]] || fail "Failed-bootstrap quarantine requires the separately authenticated operator SSH session."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if python3 -B "${lock_helper}" assert-held --locks primary,media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary,media -- /bin/bash "$0" "$@"
fi

if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
  readarray -t recovery_identity < <(read_quarantine_identity pending "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap pending recovery identity was rejected."
  [[ ${#recovery_identity[@]} -eq 3 && ${recovery_identity[0]} == "${current_commit}" && ${recovery_identity[1]} == "${failed_commit}" && ${recovery_identity[2]} =~ ^[0-9a-f]{64}$ ]] || fail "Failed-bootstrap pending recovery tuple differs."
  preflight=("${failed_commit}" "${recovery_identity[2]}")
  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs."
elif [[ -e ${deployment_journal} || -L ${deployment_journal} ]]; then
  readarray -t preflight < <(validate_failed_bootstrap_state "${current_commit}") || fail "Failed-bootstrap quarantine rejected the retained state."
else
  readarray -t recovery_identity < <(read_quarantine_identity terminal "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap terminal recovery identity was rejected."
  [[ ${#recovery_identity[@]} -eq 3 && ${recovery_identity[0]} == "${current_commit}" && ${recovery_identity[1]} == "${failed_commit}" && ${recovery_identity[2]} =~ ^[0-9a-f]{64}$ ]] || fail "Failed-bootstrap terminal recovery tuple differs."
  preflight=("${failed_commit}" "${recovery_identity[2]}")
  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs."
fi
[[ ${#preflight[@]} -eq 2 && ${preflight[0]} == "${failed_commit}" && ${preflight[1]} =~ ^[0-9a-f]{64}$ ]] || fail "Failed-bootstrap quarantine tuple differs."
validate_quarantine_environment || fail "Failed-bootstrap quarantine environment differs."
bash "${source_root}/scripts/verify-host-security.sh" "${current_commit}" "${source_root}" >/dev/null 2>&1 || fail "Current host controls failed before failed-bootstrap quarantine."
[[ "$(bounded 20s systemctl is-enabled mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == enabled ]] || fail "Certificate renewal timer is not enabled before failed-bootstrap quarantine."
[[ "$(bounded 20s systemctl is-active mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == active ]] || fail "Certificate renewal timer is not active before failed-bootstrap quarantine."

python3 -B - "${pending_journal}" "${deployment_journal}" "${evidence_root}" "${shared_root}" \
  "${standalone_root}" "${recovery_root}" "${current_commit}" "${failed_commit}" "${preflight[1]}" <<'PY'
# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION
import datetime as dt
import hashlib
import itertools
import json
import os
import pathlib
import re
import stat
import sys
import tempfile

pending, mutation, evidence_root, shared_root, standalone, recovery_root = map(pathlib.Path, sys.argv[1:7])
current, failed, mutation_sha = sys.argv[7:10]
if not re.fullmatch(r"[0-9a-f]{40}", current) or not re.fullmatch(r"[0-9a-f]{40}", failed) or not re.fullmatch(r"[0-9a-f]{64}", mutation_sha):
    raise SystemExit("failed-bootstrap quarantine identity is malformed")
quarantine = recovery_root / f"{failed}-{mutation_sha}"
mutation_evidence = evidence_root / f"{failed}-{mutation_sha}-deployment-mutation.json"
terminal = evidence_root / f"{failed}-{mutation_sha}-failed-bootstrap-quarantine.json"
phase_order = {"prepared": 0, "runtime-quarantined": 1, "clean-boundary": 2, "authority-retired": 3}

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def exact_directory(path, label):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"{label} is unsafe")
    return metadata

def exact_regular(path, label, expected_sha=None):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_size <= 0
        or metadata.st_size > 65_536
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise SystemExit(f"{label} is unsafe")
    raw = path.read_bytes()
    if expected_sha is not None and hashlib.sha256(raw).hexdigest() != expected_sha:
        raise SystemExit(f"{label} digest differs")
    return raw

def exact_inventory(path, maximum, label):
    try:
        entries = list(itertools.islice(path.iterdir(), maximum + 1))
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if len(entries) > maximum:
        raise SystemExit(f"{label} exceeds its bounded inventory")
    return {entry.name for entry in entries}

def canonical(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

def reject_duplicate(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document

def decode_canonical(path, label, expected_sha=None):
    raw = exact_regular(path, label, expected_sha)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"{label} is malformed") from error
    if raw != canonical(document):
        raise SystemExit(f"{label} is not canonical")
    return raw, document

base_keys = {
    "schemaVersion", "operation", "phase", "recordedAt", "updatedAt",
    "currentControlCommit", "failedReleaseCommit", "mutationSha256",
    "standalonePath", "quarantinePath", "mutationEvidencePath",
    "standaloneUid", "standaloneGid", "standaloneMode", "sslPresent",
}
timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")

def validate_state(document, phases, terminal_state=False):
    mode = document.get("standaloneMode")
    uid = document.get("standaloneUid")
    gid = document.get("standaloneGid")
    expected_keys = base_keys | ({"completedAt", "sslRestored"} if terminal_state else set())
    if (
        not isinstance(document, dict)
        or set(document) != expected_keys
        or document.get("schemaVersion") != 1
        or document.get("operation") != "failed-bootstrap-quarantine"
        or document.get("phase") not in phases
        or document.get("currentControlCommit") != current
        or document.get("failedReleaseCommit") != failed
        or document.get("mutationSha256") != mutation_sha
        or document.get("standalonePath") != str(standalone)
        or document.get("quarantinePath") != str(quarantine)
        or document.get("mutationEvidencePath") != str(mutation_evidence)
        or timestamp_pattern.fullmatch(str(document.get("recordedAt", ""))) is None
        or timestamp_pattern.fullmatch(str(document.get("updatedAt", ""))) is None
        or type(uid) is not int or not 0 <= uid <= 2_147_483_647
        or type(gid) is not int or not 0 <= gid <= 2_147_483_647
        or type(mode) is not int or not 0 <= mode <= 0o777
        or mode & 0o700 != 0o700 or mode & 0o002 != 0
        or type(document.get("sslPresent")) is not bool
    ):
        raise SystemExit("failed-bootstrap quarantine journal tuple differs")
    if terminal_state and (
        timestamp_pattern.fullmatch(str(document.get("completedAt", ""))) is None
        or document.get("sslRestored") is not document.get("sslPresent")
    ):
        raise SystemExit("failed-bootstrap terminal evidence tuple differs")

def publish(path, document, create):
    raw = canonical(document)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb") as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        if create:
            os.link(temporary, path, follow_symlinks=False)
            fsync_directory(path.parent)
            temporary.unlink()
            fsync_directory(path.parent)
        else:
            os.replace(temporary, path)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

exact_directory(shared_root, "shared runtime root")
evidence_metadata = exact_directory(evidence_root, "evidence root")
if evidence_metadata.st_uid != 0 or evidence_metadata.st_gid != 0 or stat.S_IMODE(evidence_metadata.st_mode) != 0o700:
    raise SystemExit("evidence root permissions differ")
if recovery_root.exists() or recovery_root.is_symlink():
    recovery_metadata = exact_directory(recovery_root, "failed-bootstrap recovery root")
    if recovery_metadata.st_uid != 0 or recovery_metadata.st_gid != 0 or stat.S_IMODE(recovery_metadata.st_mode) != 0o700:
        raise SystemExit("failed-bootstrap recovery root permissions differ")
else:
    recovery_root.mkdir(mode=0o700)
    os.chown(recovery_root, 0, 0)
    fsync_directory(recovery_root.parent)

if terminal.exists() or terminal.is_symlink():
    _, document = decode_canonical(terminal, "failed-bootstrap terminal evidence")
    validate_state(document, {"complete"}, terminal_state=True)
    if mutation.exists() or mutation.is_symlink():
        raise SystemExit("failed-bootstrap terminal evidence conflicts with active authority")
    decode_canonical(mutation_evidence, "deployment mutation evidence", mutation_sha)
    quarantine_metadata = exact_directory(quarantine, "failed-bootstrap quarantine")
    if quarantine_metadata.st_uid != 0 or quarantine_metadata.st_gid != 0 or stat.S_IMODE(quarantine_metadata.st_mode) != 0o700:
        raise SystemExit("failed-bootstrap quarantine permissions differ")
    clean_metadata = exact_directory(standalone, "clean standalone root")
    if (
        clean_metadata.st_uid != document["standaloneUid"]
        or clean_metadata.st_gid != document["standaloneGid"]
        or stat.S_IMODE(clean_metadata.st_mode) != document["standaloneMode"]
    ):
        raise SystemExit("clean standalone metadata differs")
    allowed = {"ssl"} if document.get("sslRestored") else set()
    if exact_inventory(standalone, 1, "clean standalone inventory") != allowed:
        raise SystemExit("clean standalone inventory differs")
    if document["sslRestored"]:
        exact_directory(standalone / "ssl", "restored SSL directory")
    if (quarantine / "ssl").exists() or (quarantine / "ssl").is_symlink():
        raise SystemExit("quarantined SSL authority was not retired")
    if pending.exists() or pending.is_symlink():
        _, pending_document = decode_canonical(pending, "failed-bootstrap pending journal")
        validate_state(pending_document, {"authority-retired"})
        expected_pending = {key: document[key] for key in base_keys}
        expected_pending["phase"] = "authority-retired"
        if pending_document != expected_pending:
            raise SystemExit("failed-bootstrap terminal and pending journals differ")
        pending.unlink()
        fsync_directory(pending.parent)
    raise SystemExit(0)

if pending.exists() or pending.is_symlink():
    _, state = decode_canonical(pending, "failed-bootstrap pending journal")
    validate_state(state, set(phase_order))
else:
    mutation_raw, _ = decode_canonical(mutation, "deployment mutation journal", mutation_sha)
    standalone_metadata = exact_directory(standalone, "standalone root")
    if quarantine.exists() or quarantine.is_symlink() or mutation_evidence.exists() or mutation_evidence.is_symlink():
        raise SystemExit("failed-bootstrap recovery target already exists")
    ssl_path = standalone / "ssl"
    ssl_present = ssl_path.exists() or ssl_path.is_symlink()
    if ssl_present:
        exact_directory(ssl_path, "standalone SSL directory")
    stamp = now()
    state = {
        "schemaVersion": 1,
        "operation": "failed-bootstrap-quarantine",
        "phase": "prepared",
        "recordedAt": stamp,
        "updatedAt": stamp,
        "currentControlCommit": current,
        "failedReleaseCommit": failed,
        "mutationSha256": hashlib.sha256(mutation_raw).hexdigest(),
        "standalonePath": str(standalone),
        "quarantinePath": str(quarantine),
        "mutationEvidencePath": str(mutation_evidence),
        "standaloneUid": standalone_metadata.st_uid,
        "standaloneGid": standalone_metadata.st_gid,
        "standaloneMode": stat.S_IMODE(standalone_metadata.st_mode),
        "sslPresent": ssl_present,
    }
    validate_state(state, {"prepared"})
    publish(pending, state, True)

def advance(phase):
    state["phase"] = phase
    state["updatedAt"] = now()
    validate_state(state, {phase})
    publish(pending, state, False)

if phase_order[state["phase"]] <= phase_order["prepared"]:
    source_exists = standalone.exists() or standalone.is_symlink()
    target_exists = quarantine.exists() or quarantine.is_symlink()
    if source_exists and not target_exists:
        exact_directory(standalone, "standalone root")
        os.rename(standalone, quarantine)
        fsync_directory(shared_root)
    elif not source_exists and target_exists:
        exact_directory(quarantine, "failed-bootstrap quarantine")
    else:
        raise SystemExit("failed-bootstrap runtime quarantine state is ambiguous")
    os.chown(quarantine, 0, 0)
    os.chmod(quarantine, 0o700)
    fsync_directory(recovery_root)
    advance("runtime-quarantined")

if phase_order[state["phase"]] <= phase_order["runtime-quarantined"]:
    if not standalone.exists() and not standalone.is_symlink():
        standalone.mkdir(mode=state["standaloneMode"])
    old_ssl = quarantine / "ssl"
    new_ssl = standalone / "ssl"
    partial_inventory = exact_inventory(standalone, 1, "clean standalone partial inventory")
    old_ssl_exists = old_ssl.exists() or old_ssl.is_symlink()
    new_ssl_exists = new_ssl.exists() or new_ssl.is_symlink()
    if state["sslPresent"]:
        if old_ssl_exists and not new_ssl_exists:
            exact_directory(old_ssl, "quarantined SSL directory")
            expected_partial_inventory = set()
        elif not old_ssl_exists and new_ssl_exists:
            exact_directory(new_ssl, "restored SSL directory")
            expected_partial_inventory = {"ssl"}
        else:
            raise SystemExit("failed-bootstrap SSL recovery state is ambiguous")
    else:
        if old_ssl_exists or new_ssl_exists:
            raise SystemExit("unexpected SSL directory appeared during failed-bootstrap quarantine")
        expected_partial_inventory = set()
    if partial_inventory != expected_partial_inventory:
        raise SystemExit("clean standalone partial inventory differs")
    os.chown(standalone, state["standaloneUid"], state["standaloneGid"])
    os.chmod(standalone, state["standaloneMode"])
    fsync_directory(shared_root)
    clean_metadata = exact_directory(standalone, "clean standalone root")
    if (
        clean_metadata.st_uid != state["standaloneUid"]
        or clean_metadata.st_gid != state["standaloneGid"]
        or stat.S_IMODE(clean_metadata.st_mode) != state["standaloneMode"]
    ):
        raise SystemExit("clean standalone metadata differs")
    if state["sslPresent"]:
        if (old_ssl.exists() or old_ssl.is_symlink()) and not (new_ssl.exists() or new_ssl.is_symlink()):
            exact_directory(old_ssl, "quarantined SSL directory")
            os.rename(old_ssl, new_ssl)
            fsync_directory(quarantine)
            fsync_directory(standalone)
        elif not (old_ssl.exists() or old_ssl.is_symlink()) and (new_ssl.exists() or new_ssl.is_symlink()):
            exact_directory(new_ssl, "restored SSL directory")
        else:
            raise SystemExit("failed-bootstrap SSL recovery state is ambiguous")
    elif old_ssl.exists() or old_ssl.is_symlink() or new_ssl.exists() or new_ssl.is_symlink():
        raise SystemExit("unexpected SSL directory appeared during failed-bootstrap quarantine")
    expected_inventory = {"ssl"} if state["sslPresent"] else set()
    if exact_inventory(standalone, 1, "clean standalone inventory") != expected_inventory:
        raise SystemExit("clean standalone inventory differs")
    advance("clean-boundary")

if phase_order[state["phase"]] <= phase_order["clean-boundary"]:
    mutation_exists = mutation.exists() or mutation.is_symlink()
    evidence_exists = mutation_evidence.exists() or mutation_evidence.is_symlink()
    if mutation_exists and not evidence_exists:
        decode_canonical(mutation, "deployment mutation journal", mutation_sha)
        os.rename(mutation, mutation_evidence)
        fsync_directory(mutation.parent)
        fsync_directory(mutation_evidence.parent)
    elif not mutation_exists and evidence_exists:
        decode_canonical(mutation_evidence, "deployment mutation evidence", mutation_sha)
    else:
        raise SystemExit("failed-bootstrap journal retirement state is ambiguous")
    advance("authority-retired")

decode_canonical(mutation_evidence, "deployment mutation evidence", mutation_sha)
quarantine_metadata = exact_directory(quarantine, "failed-bootstrap quarantine")
if quarantine_metadata.st_uid != 0 or quarantine_metadata.st_gid != 0 or stat.S_IMODE(quarantine_metadata.st_mode) != 0o700:
    raise SystemExit("failed-bootstrap quarantine permissions differ")
clean_metadata = exact_directory(standalone, "clean standalone root")
if (
    clean_metadata.st_uid != state["standaloneUid"]
    or clean_metadata.st_gid != state["standaloneGid"]
    or stat.S_IMODE(clean_metadata.st_mode) != state["standaloneMode"]
):
    raise SystemExit("clean standalone metadata differs")
expected_inventory = {"ssl"} if state["sslPresent"] else set()
if exact_inventory(standalone, 1, "clean standalone inventory") != expected_inventory:
    raise SystemExit("clean standalone inventory differs")
if (quarantine / "ssl").exists() or (quarantine / "ssl").is_symlink():
    raise SystemExit("quarantined SSL authority was not retired")
terminal_document = {
    **state,
    "phase": "complete",
    "completedAt": now(),
    "sslRestored": state["sslPresent"],
}
validate_state(terminal_document, {"complete"}, terminal_state=True)
publish(terminal, terminal_document, True)
pending.unlink()
fsync_directory(pending.parent)
# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION
PY

[[ ! -e ${deployment_journal} && ! -L ${deployment_journal} ]] || fail "Failed-bootstrap mutation authority was not retired."
[[ -d ${standalone_root} && ! -L ${standalone_root} && ! -e ${standalone_root}/postgres_data && ! -L ${standalone_root}/postgres_data ]] || fail "Clean standalone boundary was not established."
bash "${source_root}/scripts/verify-host-security.sh" "${current_commit}" "${source_root}" >/dev/null 2>&1 || fail "Current host controls failed after failed-bootstrap quarantine."
printf '%s\n' "Mochirii Forums failed bootstrap was quarantined without deleting retained runtime evidence."
