#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Historical disaster recovery must run as root through the operator boundary."
[[ ${SUDO_USER:-root} != mochirii-forums-deploy ]] || fail "The deploy principal may not invoke historical disaster recovery."

fixture_root="${MOCHIRII_HISTORICAL_FIXTURE_ROOT:-}"
if [[ -n ${fixture_root} ]]; then
  [[ ${MOCHIRII_HISTORICAL_FIXTURE_MODE:-} == source-only-hostile-fixture ]] || fail "Historical fixture root requires its exact source-only fixture mode."
  fixture_root="$(readlink -f -- "${fixture_root}")"
  [[ ${fixture_root} == /tmp/* && ${fixture_root} != /tmp ]] || fail "Historical fixture root must be one exact child of /tmp."
  state_root="${fixture_root}/var/lib/mochirii/forums"
  stage_root="${state_root}/historical-recovery"
  shared_root="${fixture_root}/var/discourse/shared/standalone"
  runtime_json="${fixture_root}/etc/mochirii/forums.runtime.json"
  containers_root="${fixture_root}/var/discourse/containers/historical-recovery"
  releases_root="${fixture_root}/opt/mochirii/forums/recovery-releases"
  host_control_releases_root="${fixture_root}/opt/mochirii/forums/host-control-releases"
  deployment_source_root="${fixture_root}/opt/mochirii/forums/deployment-source"
  archives_root="${state_root}/recovery-release-archives"
  incoming_root="${state_root}/incoming"
  helper="${MOCHIRII_HISTORICAL_HELPER:-${fixture_root}/bin/historical-release-disaster-recovery.py}"
  scratch_reader="${MOCHIRII_HISTORICAL_SCRATCH_READER:-${fixture_root}/bin/historical-recovery-scratch-reader.sh}"
  deployer="${MOCHIRII_HISTORICAL_DEPLOYER:-${fixture_root}/bin/mochirii-forums-deploy}"
  restorer="${MOCHIRII_HISTORICAL_RESTORER:-${fixture_root}/bin/mochirii-forums-restore}"
  producer_probe="${MOCHIRII_HISTORICAL_PRODUCER_PROBE:-${fixture_root}/bin/probe-website-forums-producer.py}"
  main_probe="${MOCHIRII_HISTORICAL_MAIN_PROBE:-${fixture_root}/bin/probe-canonical-main}"
  lock_file="${fixture_root}/run/lock/mochirii-forums/historical-controller.lock"
else
  state_root=/var/lib/mochirii/forums
  stage_root="${state_root}/historical-recovery"
  shared_root=/var/discourse/shared/standalone
  runtime_json=/etc/mochirii/forums.runtime.json
  containers_root=/var/discourse/containers/historical-recovery
  releases_root=/opt/mochirii/forums/recovery-releases
  host_control_releases_root=/opt/mochirii/forums/host-control-releases
  deployment_source_root=/opt/mochirii/forums/deployment-source
  archives_root="${state_root}/recovery-release-archives"
  incoming_root="${state_root}/incoming"
  helper=/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py
  scratch_reader=/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh
  deployer=/usr/local/sbin/mochirii-forums-deploy
  restorer=/usr/local/sbin/mochirii-forums-restore
  producer_probe=/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py
  main_probe=""
  lock_file=/run/lock/mochirii-forums/historical-controller.lock
fi

readonly state_root stage_root shared_root runtime_json containers_root releases_root host_control_releases_root deployment_source_root archives_root incoming_root
readonly helper scratch_reader deployer restorer producer_probe main_probe lock_file
readonly reader_journal="${state_root}/historical-reader.json"
readonly adoption_journal="${state_root}/historical-release-adoption.json"
readonly host_control="${state_root}/current-host-control.json"
readonly receipt="${stage_root}/fetched-recovery-receipt.json"
readonly fetched_archive="${stage_root}/fetched-release.tar"
readonly scratch_absence="${stage_root}/scratch-reader-absence.json"
readonly reader_confirmation="BEGIN CURRENT-MAIN MOCHIRII FORUMS RECOVERY READER"
readonly prepare_confirmation="PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"
readonly recover_confirmation="RECOVER HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"

lock_directory="$(dirname -- "${lock_file}")"
if [[ -n ${fixture_root} ]]; then
  install -d -m 0700 -o root -g root "$(dirname -- "${lock_directory}")"
else
  [[ ${lock_directory} == /run/lock/mochirii-forums ]] || fail "Historical controller lock directory differs."
  [[ -d /run/lock && ! -L /run/lock && "$(stat -c '%u:%g' -- /run/lock)" == 0:0 ]] ||
    fail "System lock parent is unsafe."
fi
if [[ ! -e ${lock_directory} && ! -L ${lock_directory} ]]; then
  mkdir -m 0700 -- "${lock_directory}" || fail "Historical controller lock directory could not be created safely."
fi
[[ -d ${lock_directory} && ! -L ${lock_directory} && "$(stat -c '%u:%g:%a' -- "${lock_directory}")" == 0:0:700 ]] ||
  fail "Historical controller lock directory ownership or mode is unsafe."
if [[ -e ${lock_file} || -L ${lock_file} ]]; then
  [[ -f ${lock_file} && ! -L ${lock_file} && "$(stat -c '%u:%g' -- "${lock_file}")" == 0:0 ]] ||
    fail "Historical controller lock file is unsafe."
fi
exec 8>"${lock_file}"
chmod 0600 -- "${lock_file}"
flock -n 8 || fail "Another historical disaster-recovery controller is active."

protected_regular() {
  local path="$1" label="$2" maximum="$3"
  [[ -f ${path} && ! -L ${path} ]] || fail "${label} is absent or linked."
  if [[ -z ${fixture_root} ]]; then
    [[ "$(stat -c '%U:%G %a' "${path}")" == root:root\ 600 ]] || fail "${label} has unsafe ownership or mode."
  fi
  [[ "$(stat -c '%s' "${path}")" =~ ^[1-9][0-9]*$ ]] || fail "${label} is empty or unreadable."
  (( $(stat -c '%s' "${path}") <= maximum )) || fail "${label} exceeds its byte boundary."
}

trusted_entrypoint() {
  local path="$1"
  [[ -f ${path} && ! -L ${path} ]] || return 1
  if [[ -n ${fixture_root} ]]; then
    # CI deliberately mounts /tmp noexec. Fixture-only Python/Bash entrypoints
    # are interpreted explicitly, so validate their protected source mode
    # instead of asking access(2) for filesystem execute permission.
    [[ "$(stat -c '%u:%g:%a' -- "${path}")" == 0:0:755 ]]
  else
    [[ -x ${path} ]]
  fi
}

operation_process_absent() {
  local operation_id="$1"
  python3 -B - "${operation_id}" <<'PY'
import pathlib
import sys

marker = f"MOCHIRII_HISTORICAL_READER_OPERATION_ID={sys.argv[1]}".encode("ascii")
for path in pathlib.Path("/proc").glob("[0-9]*/environ"):
    try:
        if marker in path.read_bytes().split(b"\0"):
            raise SystemExit(1)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
PY
}

reader_container_absent() {
  local operation_id="$1" inventory
  if [[ -n ${fixture_root} ]]; then
    inventory="${MOCHIRII_HISTORICAL_FAKE_CONTAINER_INVENTORY:-}"
  else
    inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
      --filter "label=mochirii.forums.historical-reader=${operation_id}" --format '{{.ID}}' 2>/dev/null)" || return 1
  fi
  [[ -z ${inventory} ]]
}

reader_runtime_absent() {
  local operation_id="$1" evidence_path="${2:-}" label_inventory name_inventory image_inventory image_label_inventory image_id_inventory="" evidence_identity=""
  if [[ -n ${fixture_root} ]]; then
    label_inventory="${MOCHIRII_HISTORICAL_FAKE_CONTAINER_INVENTORY:-}"
    name_inventory="${MOCHIRII_HISTORICAL_FAKE_NAMED_CONTAINER_INVENTORY:-}"
    image_inventory="${MOCHIRII_HISTORICAL_FAKE_IMAGE_INVENTORY:-}"
    image_label_inventory="${MOCHIRII_HISTORICAL_FAKE_IMAGE_LABEL_INVENTORY:-}"
    image_id_inventory="${MOCHIRII_HISTORICAL_FAKE_IMAGE_ID_INVENTORY:-}"
  else
    label_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
      --filter "label=mochirii.forums.historical-reader=${operation_id}" --format '{{.ID}}' 2>/dev/null)" || return 1
    name_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
      --filter "name=^/mochirii-dr-reader-${operation_id}$" --format '{{.ID}}' 2>/dev/null)" || return 1
    image_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --no-trunc \
      --filter "reference=local_discourse/mochirii-dr-reader-${operation_id}" --format '{{.ID}}' 2>/dev/null)" || return 1
    image_label_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --all --no-trunc --quiet 2>/dev/null | sort -u | while IFS= read -r identity; do
      [[ -z ${identity} ]] && continue
      [[ ${identity} =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
      label="$(timeout --signal=TERM --kill-after=5s 15 docker image inspect --format '{{index .Config.Labels "mochirii.forums.historical-reader"}}' "${identity}" 2>/dev/null)" || exit 1
      [[ ${label} == "${operation_id}" ]] && printf '%s\n' "${identity}"
    done)" || return 1
  fi
  if [[ -n ${evidence_path} ]]; then
    [[ -f ${evidence_path} && ! -L ${evidence_path} ]] || return 1
    evidence_identity="$(python3 -B - "${evidence_path}" "${operation_id}" <<'PY'
import json
import pathlib
import re
import stat
import sys
path = pathlib.Path(sys.argv[1])
operation = sys.argv[2]
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
    raise SystemExit(1)
document = json.loads(path.read_text(encoding="utf-8"))
values = document.get("operationImageIds", document.get("readerOperationImageIds"))
label = document.get("operationImageLabel", document.get("readerOperationImageLabel"))
if (
    not isinstance(values, list)
    or values != sorted(set(values))
    or len(values) != 1
    or any(not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in values)
    or label != f"mochirii.forums.historical-reader={operation}"
):
    raise SystemExit(1)
print(label)
print("\n".join(values))
PY
    )" || return 1
    [[ ${evidence_identity%%$'\n'*} == "mochirii.forums.historical-reader=${operation_id}" ]] || return 1
    evidence_identity="${evidence_identity#*$'\n'}"
    if [[ -n ${fixture_root} ]]; then
      [[ -z ${image_id_inventory} ]] || return 1
    else
      while IFS= read -r identity; do
        [[ -z ${identity} ]] && continue
        if timeout --signal=TERM --kill-after=5s 15 docker image inspect "${identity}" >/dev/null 2>&1; then
          return 1
        fi
      done <<<"${evidence_identity}"
    fi
  fi
  [[ -z ${label_inventory} && -z ${name_inventory} && -z ${image_inventory} && -z ${image_label_inventory} ]] &&
    operation_process_absent "${operation_id}"
}

begin_reader() {
  local bootstrap_commit="$1" operation_id="$2" confirmation="$3"
  [[ ${confirmation} == "${reader_confirmation}" ]] || fail "Exact current-main reader confirmation is required."
  [[ ${bootstrap_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Current-main reader commit is malformed."
  [[ ${operation_id} =~ ^[0-9a-f]{32}$ ]] || fail "Current-main reader operation identifier is malformed."
  [[ ! -e ${adoption_journal} && ! -L ${adoption_journal} ]] || fail "Historical adoption already exists."
  protected_regular "${host_control}" "Current host-control evidence" 65536
  [[ ! -e ${reader_journal} && ! -L ${reader_journal} ]] || fail "A historical recovery reader is already active."
  [[ ! -e ${scratch_absence} && ! -L ${scratch_absence} ]] || fail "Stale scratch-absence evidence must be reviewed."
  reader_container_absent "${operation_id}" || fail "A historical reader container already exists."
  operation_process_absent "${operation_id}" || fail "A historical reader process already exists."

  install -d -m 0755 -o root -g root "${state_root}"
  install -d -m 0700 -o root -g root "${stage_root}"
  [[ ! -e ${shared_root} && ! -L ${shared_root} ]] || fail "Historical recovery requires the real persistent target to be absent before the reader guard is armed."

  python3 -B - "${host_control}" "${reader_journal}" "${bootstrap_commit}" "${operation_id}" \
    "${state_root}/historical-reader/${operation_id}" "${shared_root}" \
    "${host_control_releases_root}/${bootstrap_commit}/mochirii-release.tar" \
    "${deployment_source_root}/ed9f680b0df1de28f062de1769d89d22b2644d1b.tar" \
    "$([[ -n ${fixture_root} ]] && printf fixture || printf production)" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

control = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
operation = sys.argv[4]
scratch = pathlib.Path(sys.argv[5])
shared = pathlib.Path(sys.argv[6])
release_archive = pathlib.Path(sys.argv[7])
deployment_archive = pathlib.Path(sys.argv[8])
fixture_mode = sys.argv[9] == "fixture"
control_raw = control.read_bytes()
document = json.loads(control_raw)
if fixture_mode:
    deployment_archive = pathlib.Path(str(document.get("deploymentSourceArchiveFile", "")))
required = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(document) != required or document.get("schemaVersion") != 1 or document.get("phase") != "hardened":
    raise SystemExit("current host-control pointer schema differs")
if document.get("repositoryCommit") != commit:
    raise SystemExit("current host-control commit differs from the reader bootstrap")
for key in ("manifestSha256", "targetSetSha256", "controlEvidenceSha256"):
    if re.fullmatch(r"[0-9a-f]{64}", str(document.get(key, ""))) is None:
        raise SystemExit("current host-control digest is malformed")
evidence_name = document.get("controlEvidenceFile", "")
if re.fullmatch(rf"{commit}-[0-9a-f]{{64}}-host-control[.]json", str(evidence_name)) is None:
    raise SystemExit("current host-control immutable evidence name differs")
evidence_path = control.parent / "evidence" / evidence_name
evidence_metadata = evidence_path.lstat()
if (
    not stat.S_ISREG(evidence_metadata.st_mode)
    or stat.S_ISLNK(evidence_metadata.st_mode)
    or not 1 <= evidence_metadata.st_size <= 65536
    or (not fixture_mode and (evidence_metadata.st_uid != 0 or evidence_metadata.st_gid != 0 or stat.S_IMODE(evidence_metadata.st_mode) != 0o600))
):
    raise SystemExit("current host-control immutable evidence is unsafe")
evidence_raw = evidence_path.read_bytes()
if len(evidence_raw) != evidence_metadata.st_size:
    raise SystemExit("current host-control immutable evidence changed while reading")
if hashlib.sha256(evidence_raw).hexdigest() != document.get("controlEvidenceSha256"):
    raise SystemExit("current host-control immutable evidence digest differs")
evidence = json.loads(evidence_raw)
evidence_keys = {
    "schemaVersion", "recordedAt", "operation", "phase", "repositoryCommit", "repositoryTree",
    "manifestSha256", "targetSetSha256", "previousControlEvidenceSha256", "targets",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(evidence) != evidence_keys or evidence.get("schemaVersion") != 1 or evidence.get("phase") != "hardened" or evidence.get("repositoryCommit") != commit:
    raise SystemExit("current host-control immutable evidence schema differs")
for key in required - {"schemaVersion", "phase", "controlEvidenceFile", "controlEvidenceSha256"}:
    if key in evidence and evidence.get(key) != document.get(key):
        raise SystemExit("current host-control pointer differs from immutable evidence")
for path, file_key, sha_key, bytes_key in (
    (release_archive, "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes"),
    (deployment_archive, "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes"),
):
    metadata = path.lstat()
    expected_bytes = document.get(bytes_key)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or not 1 <= expected_bytes <= 67108864
        or metadata.st_size != expected_bytes
        or (not fixture_mode and (metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600))
    ):
        raise SystemExit("current host-control retained archive is unsafe")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise SystemExit("current host-control retained archive changed while reading")
    if document.get(file_key) != str(path) or document.get(sha_key) != hashlib.sha256(raw).hexdigest() or document.get(bytes_key) != len(raw):
        raise SystemExit("current host-control retained archive binding differs")
if (
    (not fixture_mode and document.get("deploymentSourceRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b")
    or (fixture_mode and re.fullmatch(r"[0-9a-f]{40}", str(document.get("deploymentSourceRevision", ""))) is None)
    or (not fixture_mode and document.get("deploymentSourceTree") != "588498dffbea91592fd4e2f10166bc11c8fe7a61")
):
    raise SystemExit("current host-control deployment-source pin differs")
for key in ("repositoryTree", "releaseArchiveSha256", "releaseArchiveContentManifestSha256", "deploymentSourceArchiveSha256", "deploymentSourceContentManifestSha256"):
    pattern = r"[0-9a-f]{40}" if key == "repositoryTree" else r"[0-9a-f]{64}"
    if re.fullmatch(pattern, str(document.get(key, ""))) is None:
        raise SystemExit("current host-control retained archive identity is malformed")
if shared.exists() or shared.is_symlink():
    raise SystemExit("real persistent target exists before reader arming")
timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
intent = {
    "schemaVersion": 1,
    "operation": "current-main-historical-recovery-reader",
    "phase": "reader-armed",
    "recordedAt": timestamp,
    "bootstrapRepositoryCommit": commit,
    "readerOperationId": operation,
    "scratchRoot": str(scratch),
    "currentHostControlFile": str(control),
    "currentHostControlSha256": hashlib.sha256(control_raw).hexdigest(),
    "realPersistentTarget": str(shared),
    "realPersistentTargetInitiallyAbsent": True,
}
candidate = output.parent / f".{output.name}.partial"
if candidate.exists() or candidate.is_symlink():
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_size > 65536:
        raise SystemExit("reader intent partial is unsafe")
    candidate.unlink()
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    target.write(json.dumps(intent, sort_keys=True, indent=2) + "\n")
    target.flush()
    os.fsync(target.fileno())
os.replace(candidate, output)
if os.name != "nt":
    descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
  printf '%s\n' "Current-main recovery reader guard armed; keep all reader state under ${state_root}/historical-reader/${operation_id}."
}

prove_canonical_main() {
  local bootstrap_commit="$1" observed=""
  if [[ -n ${fixture_root} ]]; then
    trusted_entrypoint "${main_probe}" || return 1
    observed="$(python3 -B "${main_probe}" refs/heads/main)" || return 1
    [[ ${observed} == "${bootstrap_commit}" ]]
    return
  fi
  (
    local verifier="" trusted_urls=() trusted_options=()
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
    unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
    export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0
    trusted_options=(
      -c credential.helper=
      -c core.askPass=
      -c init.templateDir=
      -c protocol.allow=never
      -c protocol.https.allow=always
      -c http.followRedirects=false
    )
    verifier="$(mktemp -d "${stage_root}/.canonical-main.XXXXXXXX")" || exit 1
    trap 'rm -rf -- "${verifier}"' EXIT
    git "${trusted_options[@]}" -C "${verifier}" init --bare >/dev/null 2>&1 || exit 1
    git "${trusted_options[@]}" -C "${verifier}" remote add origin \
      https://github.com/Mochirii-Wushu/Mochirii-Forums.git >/dev/null 2>&1 || exit 1
    readarray -t trusted_urls < <(git "${trusted_options[@]}" -C "${verifier}" remote get-url --all origin) || exit 1
    [[ ${#trusted_urls[@]} -eq 1 && ${trusted_urls[0]} == https://github.com/Mochirii-Wushu/Mochirii-Forums.git ]] || exit 1
    timeout --signal=TERM --kill-after=10s 120 git "${trusted_options[@]}" -c protocol.version=2 \
      -C "${verifier}" fetch --no-tags --depth=1 --refmap= origin refs/heads/main >/dev/null 2>&1 || exit 1
    observed="$(git "${trusted_options[@]}" -C "${verifier}" rev-parse --verify FETCH_HEAD^{commit})" || exit 1
    [[ ${observed} == "${bootstrap_commit}" ]]
  )
}

run_current_main_reader() {
  local bootstrap_commit="$1" operation_id="$2"
  local scratch_root="${state_root}/historical-reader/${operation_id}"
  local scratch_transaction="${stage_root}/historical-reader-${operation_id}.transaction.json"
  trusted_entrypoint "${scratch_reader}" || fail "Installed historical scratch reader is absent, linked, or not executable authority."
  [[ ! -e ${shared_root} && ! -L ${shared_root} ]] || fail "Historical reader refuses an existing real persistent target."
  prove_canonical_main "${bootstrap_commit}" || fail "Canonical public main no longer equals the exact C1 reader authority; the reader journal was retained."

  if [[ ! -e ${scratch_transaction} && ! -L ${scratch_transaction} && -f ${scratch_absence} && ! -L ${scratch_absence} ]]; then
    protected_regular "${scratch_absence}" "Scratch-reader absence evidence" 65536
    protected_regular "${receipt}" "Fetched historical recovery receipt" 65536
    protected_regular "${fetched_archive}" "Fetched historical release archive" 67108864
    [[ ! -e ${scratch_root} && ! -L ${scratch_root} ]] || fail "Historical reader scratch root survived its durable absence handoff."
    reader_runtime_absent "${operation_id}" "${scratch_absence}" || fail "Historical reader runtime survived its durable absence handoff."
    return 0
  fi

  if [[ ! -e ${scratch_transaction} && ! -L ${scratch_transaction} ]]; then
    [[ ! -e ${scratch_root} && ! -L ${scratch_root} ]] || fail "Unowned historical reader scratch root exists before the helper call."
    [[ ! -e ${receipt} && ! -L ${receipt} && ! -e ${fetched_archive} && ! -L ${fetched_archive} ]] ||
      fail "Historical reader outputs lack a transaction or durable controller absence handoff."
    reader_runtime_absent "${operation_id}" || fail "Unowned historical reader runtime exists before the helper call."
  else
    protected_regular "${scratch_transaction}" "Historical scratch-reader transaction" 65536
  fi

  local reader_status=0
  if [[ -n ${fixture_root} ]]; then
    readarray -t fixture_deployment < <(python3 -B - "${host_control}" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(document["deploymentSourceRevision"])
print(document["deploymentSourceTree"])
PY
    ) || fail "Historical scratch fixture deployment authority is malformed."
    [[ ${#fixture_deployment[@]} -eq 2 ]] || fail "Historical scratch fixture deployment authority is incomplete."
    MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_ROOT="${fixture_root}" \
      MOCHIRII_HISTORICAL_SCRATCH_MODE=source-only-hostile-fixture \
      MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_DEPLOYMENT_REVISION="${fixture_deployment[0]}" \
      MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_DEPLOYMENT_TREE="${fixture_deployment[1]}" \
      bash "${scratch_reader}" "${bootstrap_commit}" "${operation_id}" \
        "FETCH HISTORICAL MOCHIRII FORUMS RECOVERY SOURCE" || reader_status=$?
  else
    "${scratch_reader}" "${bootstrap_commit}" "${operation_id}" \
      "FETCH HISTORICAL MOCHIRII FORUMS RECOVERY SOURCE" || reader_status=$?
  fi

  if (( reader_status != 0 )); then
    [[ ! -e ${shared_root} && ! -L ${shared_root} ]] ||
      fail "Historical scratch reader failed after touching the real persistent target."
    fail "Historical scratch reader failed; its own containment contract must retain the reader journal."
  fi
  protected_regular "${receipt}" "Fetched historical recovery receipt" 65536
  protected_regular "${fetched_archive}" "Fetched historical release archive" 67108864
  protected_regular "${scratch_transaction}" "Terminal historical scratch-reader transaction" 65536
  python3 -B - "${scratch_transaction}" "${reader_journal}" "${host_control}" "${receipt}" \
    "${fetched_archive}" "${bootstrap_commit}" "${operation_id}" "${scratch_root}" "${shared_root}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

transaction_path, intent_path, control_path, receipt_path, archive_path, scratch, shared = (
    pathlib.Path(value) for value in (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[8], sys.argv[9])
)
commit, operation = sys.argv[6], sys.argv[7]
transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
keys = {
    "schemaVersion", "operation", "phase", "bootstrapRepositoryCommit", "readerOperationId",
    "readerIntentFile", "readerIntentSha256", "currentHostControlFile", "currentHostControlSha256",
    "scratchRoot", "realPersistentTarget", "receiptCandidateFile", "receiptOutputFile",
    "archiveCandidateFile", "archiveOutputFile", "receiptSha256", "receiptBytes",
    "releaseArchiveSha256", "releaseArchiveBytes", "preexistingImageIds",
    "operationImageIds", "operationImageLabel", "cleanupProved",
}
intent_raw = intent_path.read_bytes()
control_raw = control_path.read_bytes()
receipt_raw = receipt_path.read_bytes()
archive_metadata = archive_path.lstat()
if (
    set(transaction) != keys
    or transaction.get("schemaVersion") != 1
    or transaction.get("operation") != "current-main-historical-recovery-scratch-reader"
    or transaction.get("phase") != "outputs-published"
    or transaction.get("bootstrapRepositoryCommit") != commit
    or transaction.get("readerOperationId") != operation
    or transaction.get("readerIntentFile") != str(intent_path)
    or transaction.get("readerIntentSha256") != hashlib.sha256(intent_raw).hexdigest()
    or transaction.get("currentHostControlFile") != str(control_path)
    or transaction.get("currentHostControlSha256") != hashlib.sha256(control_raw).hexdigest()
    or transaction.get("scratchRoot") != str(scratch)
    or transaction.get("realPersistentTarget") != str(shared)
    or transaction.get("receiptCandidateFile") != str(receipt_path.parent / f".fetched-recovery-receipt.{operation}.partial")
    or transaction.get("receiptOutputFile") != str(receipt_path)
    or transaction.get("archiveCandidateFile") != str(archive_path.parent / f".fetched-release.{operation}.partial")
    or transaction.get("archiveOutputFile") != str(archive_path)
    or transaction.get("receiptSha256") != hashlib.sha256(receipt_raw).hexdigest()
    or transaction.get("receiptBytes") != len(receipt_raw)
    or transaction.get("releaseArchiveSha256") != hashlib.sha256(archive_path.read_bytes()).hexdigest()
    or transaction.get("releaseArchiveBytes") != archive_metadata.st_size
    or not isinstance(transaction.get("preexistingImageIds"), list)
    or transaction["preexistingImageIds"] != sorted(set(transaction["preexistingImageIds"]))
    or any(not isinstance(value, str) or __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in transaction["preexistingImageIds"])
    or transaction.get("operationImageIds") != sorted(set(transaction.get("operationImageIds", [])))
    or len(transaction.get("operationImageIds", [])) != 1
    or any(not isinstance(value, str) or __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in transaction.get("operationImageIds", []))
    or set(transaction["preexistingImageIds"]) & set(transaction["operationImageIds"])
    or transaction.get("operationImageLabel") != f"mochirii.forums.historical-reader={operation}"
    or transaction.get("cleanupProved") is not True
):
    raise SystemExit("terminal historical scratch-reader transaction differs")
for candidate in (pathlib.Path(transaction["receiptCandidateFile"]), pathlib.Path(transaction["archiveCandidateFile"])):
    if candidate.exists() or candidate.is_symlink():
        raise SystemExit("historical scratch-reader candidate survived terminal publication")
PY
  [[ ! -e ${scratch_root} && ! -L ${scratch_root} ]] || fail "Historical reader scratch root survived its helper."
  reader_runtime_absent "${operation_id}" "${scratch_transaction}" || fail "Historical reader runtime survived its helper."
  [[ ! -e ${shared_root} && ! -L ${shared_root} ]] || fail "Historical scratch reader touched the real persistent target."
}

prepare_release() {
  local bootstrap_commit="$1" operation_id="$2" confirmation="$3" reader_operation_id=""
  [[ ${confirmation} == "${prepare_confirmation}" ]] || fail "Exact historical release preparation confirmation is required."
  [[ ${bootstrap_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Historical bootstrap commit is malformed."
  [[ ${operation_id} =~ ^[0-9a-f]{32}$ ]] || fail "Historical reader operation identifier is malformed."
  if [[ ! -e ${reader_journal} && ! -L ${reader_journal} ]]; then
    if [[ -e ${adoption_journal} || -L ${adoption_journal} ]]; then
      protected_regular "${adoption_journal}" "Historical adoption journal" 65536
      protected_regular "${receipt}" "Fetched historical recovery receipt" 65536
      trusted_entrypoint "${helper}" || fail "Installed historical recovery helper is absent, linked, or not executable authority."
      reader_operation_id="$(python3 -B - "${adoption_journal}" "${bootstrap_commit}" "${operation_id}" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if (
    document.get("phase") != "configuration-authorized"
    or document.get("bootstrapRepositoryCommit") != sys.argv[2]
    or document.get("readerOperationId") != sys.argv[3]
):
    raise SystemExit("existing historical preparation tuple differs")
print(document["readerOperationId"])
PY
      )" || fail "Existing historical preparation tuple is malformed."
      MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" verify \
        --receipt "${receipt}" --journal "${adoption_journal}" --require-phase configuration-authorized
      [[ ${reader_operation_id} == "${operation_id}" ]] || fail "Existing historical preparation operation differs."
      [[ ! -e ${stage_root}/historical-reader-${operation_id}.transaction.json && ! -L ${stage_root}/historical-reader-${operation_id}.transaction.json ]] ||
        fail "Existing historical preparation retains a scratch transaction."
      [[ ! -e ${state_root}/historical-reader/${operation_id} && ! -L ${state_root}/historical-reader/${operation_id} ]] ||
        fail "Existing historical preparation retains scratch state."
      reader_runtime_absent "${operation_id}" "${scratch_absence}" || fail "Existing historical preparation retains scratch runtime."
      [[ ! -e ${shared_root} && ! -L ${shared_root} ]] || fail "Existing historical preparation no longer has an absent persistent target."
      printf '%s\n' "Historical C0 source and configurations were already authorized with exact terminal preparation evidence."
      return 0
    fi
    begin_reader "${bootstrap_commit}" "${operation_id}" "${reader_confirmation}"
  fi
  protected_regular "${reader_journal}" "Historical reader intent" 65536
  protected_regular "${host_control}" "Current host-control evidence" 65536
  run_current_main_reader "${bootstrap_commit}" "${operation_id}"
  protected_regular "${receipt}" "Fetched historical recovery receipt" 65536
  protected_regular "${fetched_archive}" "Fetched historical release archive" 67108864
  protected_regular "${runtime_json}" "Protected Forums runtime JSON" 1048576
  trusted_entrypoint "${helper}" || fail "Installed historical recovery helper is absent, linked, or not executable authority."

  readarray -t release_identity < <(python3 -B - "${reader_journal}" "${host_control}" "${receipt}" \
    "${fetched_archive}" "${bootstrap_commit}" "${operation_id}" "${shared_root}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

intent_path = pathlib.Path(sys.argv[1])
control_path = pathlib.Path(sys.argv[2])
receipt_path = pathlib.Path(sys.argv[3])
archive_path = pathlib.Path(sys.argv[4])
commit = sys.argv[5]
operation = sys.argv[6]
shared = pathlib.Path(sys.argv[7])
intent = json.loads(intent_path.read_text(encoding="utf-8"))
required_intent = {
    "schemaVersion", "operation", "phase", "recordedAt", "bootstrapRepositoryCommit",
    "readerOperationId", "scratchRoot", "currentHostControlFile", "currentHostControlSha256",
    "realPersistentTarget", "realPersistentTargetInitiallyAbsent",
}
if set(intent) != required_intent or intent.get("schemaVersion") != 1 or intent.get("operation") != "current-main-historical-recovery-reader" or intent.get("phase") != "reader-armed":
    raise SystemExit("historical reader intent schema differs")
if intent.get("bootstrapRepositoryCommit") != commit or intent.get("readerOperationId") != operation:
    raise SystemExit("historical reader intent identity differs")
control_raw = control_path.read_bytes()
if intent.get("currentHostControlFile") != str(control_path) or intent.get("currentHostControlSha256") != hashlib.sha256(control_raw).hexdigest():
    raise SystemExit("current host-control evidence changed during the reader")
control = json.loads(control_raw)
if control.get("repositoryCommit") != commit or control.get("phase") != "hardened":
    raise SystemExit("current host-control release changed during the reader")
if intent.get("realPersistentTarget") != str(shared) or intent.get("realPersistentTargetInitiallyAbsent") is not True:
    raise SystemExit("real persistent target authority differs")
if shared.exists() or shared.is_symlink():
    raise SystemExit("the current-main reader touched the real persistent target")
receipt_raw = receipt_path.read_bytes()
receipt = json.loads(receipt_raw)
c0 = receipt.get("repositoryCommit", "")
archive_sha = receipt.get("disasterRecoveryReleaseArchiveSha256", "")
archive_bytes = receipt.get("disasterRecoveryReleaseArchiveBytes")
if (
    receipt.get("schemaVersion") != 3
    or receipt.get("disasterRecoveryFetchMode") != "clean-target-historical"
    or receipt.get("disasterRecoveryBootstrapCommit") != commit
    or receipt.get("disasterRecoveryOrdinaryDeploymentRequiresCurrentMain") is not True
    or receipt.get("disasterRecoveryHistoricalReleaseAdoptionScope") != "clean-target-disaster-recovery-only"
    or receipt.get("disasterRecoveryPrivateAclPassed") is not True
    or not isinstance(c0, str)
    or re.fullmatch(r"[0-9a-f]{40}", c0) is None
    or c0 == commit
    or not isinstance(archive_sha, str)
    or re.fullmatch(r"[0-9a-f]{64}", archive_sha) is None
    or not isinstance(archive_bytes, int)
    or isinstance(archive_bytes, bool)
    or not 1 <= archive_bytes <= 67108864
):
    raise SystemExit("fetched historical receipt authority differs")
archive_raw = archive_path.read_bytes()
if len(archive_raw) != archive_bytes or hashlib.sha256(archive_raw).hexdigest() != archive_sha:
    raise SystemExit("fetched historical archive differs from its receipt")
print(c0)
print(archive_sha)
print(archive_bytes)
print(intent["scratchRoot"])
print(hashlib.sha256(receipt_raw).hexdigest())
PY
  ) || fail "Historical reader output differs from its exact prearmed authority."
  [[ ${#release_identity[@]} -eq 5 ]] || fail "Historical reader output identity is incomplete."
  local recovered_commit="${release_identity[0]}" archive_sha="${release_identity[1]}" archive_bytes="${release_identity[2]}"
  local scratch_root="${release_identity[3]}" receipt_sha="${release_identity[4]}"
  [[ ${scratch_root} == "${state_root}/historical-reader/${operation_id}" ]] || fail "Historical reader scratch root differs."
  [[ ! -e ${scratch_root} && ! -L ${scratch_root} ]] || fail "Historical reader scratch state survived."
  [[ ! -e ${stage_root}/reader-${operation_id}.cid && ! -L ${stage_root}/reader-${operation_id}.cid ]] || fail "Historical reader launcher state survived."
  reader_container_absent "${operation_id}" || fail "Historical reader container survived."
  operation_process_absent "${operation_id}" || fail "Historical reader process survived."

  local terminal_reader_transaction="${stage_root}/historical-reader-${operation_id}.transaction.json" runtime_identity_evidence=""
  if [[ ! -e ${terminal_reader_transaction} && ! -L ${terminal_reader_transaction} ]]; then
    protected_regular "${scratch_absence}" "Durable scratch-reader absence handoff" 65536
    runtime_identity_evidence="${scratch_absence}"
  else
    protected_regular "${terminal_reader_transaction}" "Terminal historical scratch-reader transaction" 65536
    runtime_identity_evidence="${terminal_reader_transaction}"
  fi
  reader_runtime_absent "${operation_id}" "${runtime_identity_evidence}" ||
    fail "Historical reader immutable runtime identity survived before absence handoff."
  python3 -B - "${reader_journal}" "${scratch_absence}" "${receipt}" "${fetched_archive}" \
    "${host_control}" "${bootstrap_commit}" "${operation_id}" "${terminal_reader_transaction}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import stat
import sys

intent_path, output, receipt_path, archive_path, control_path = map(pathlib.Path, sys.argv[1:6])
commit, operation = sys.argv[6:8]
transaction_path = pathlib.Path(sys.argv[8])
intent_raw = intent_path.read_bytes()
intent = json.loads(intent_raw)
receipt_raw = receipt_path.read_bytes()
archive_raw = archive_path.read_bytes()
control_raw = control_path.read_bytes()
if transaction_path.exists() or transaction_path.is_symlink():
    transaction_raw = transaction_path.read_bytes()
    transaction = json.loads(transaction_raw)
    operation_image_ids = transaction.get("operationImageIds")
    operation_image_label = transaction.get("operationImageLabel")
    if (
        transaction.get("phase") != "outputs-published"
        or transaction.get("cleanupProved") is not True
        or not isinstance(operation_image_ids, list)
        or operation_image_ids != sorted(set(operation_image_ids))
        or len(operation_image_ids) != 1
        or any(not isinstance(value, str) or __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in operation_image_ids)
        or operation_image_label != f"mochirii.forums.historical-reader={operation}"
    ):
        raise SystemExit("terminal historical scratch-reader transaction differs")
    terminal_transaction_sha = hashlib.sha256(transaction_raw).hexdigest()
else:
    existing_handoff = json.loads(output.read_text(encoding="utf-8"))
    terminal_transaction_sha = existing_handoff.get("terminalReaderTransactionSha256", "")
    operation_image_ids = existing_handoff.get("readerOperationImageIds")
    operation_image_label = existing_handoff.get("readerOperationImageLabel")
stable = {
    "schemaVersion": 1,
    "operation": "current-main-historical-recovery-reader",
    "phase": "scratch-absence-proved",
    "bootstrapRepositoryCommit": commit,
    "readerOperationId": operation,
    "readerIntentSha256": hashlib.sha256(intent_raw).hexdigest(),
    "terminalReaderTransactionPhase": "outputs-published",
    "terminalReaderTransactionSha256": terminal_transaction_sha,
    "currentHostControlFile": str(control_path),
    "currentHostControlSha256": hashlib.sha256(control_raw).hexdigest(),
    "disasterRecoveryReceiptFile": str(receipt_path),
    "disasterRecoveryReceiptSha256": hashlib.sha256(receipt_raw).hexdigest(),
    "releaseArchiveFile": str(archive_path),
    "releaseArchiveSha256": hashlib.sha256(archive_raw).hexdigest(),
    "scratchRoot": intent["scratchRoot"],
    "scratchDirectoryAbsent": True,
    "readerContainerAbsent": True,
    "readerOperationImageIds": operation_image_ids,
    "readerOperationImageLabel": operation_image_label,
    "readerOperationImagesAbsent": True,
    "readerProcessAbsent": True,
    "readerLauncherStateAbsent": True,
    "realPersistentTargetAbsent": True,
}
if not isinstance(terminal_transaction_sha, str) or len(terminal_transaction_sha) != 64 or any(character not in "0123456789abcdef" for character in terminal_transaction_sha):
    raise SystemExit("terminal historical scratch-reader transaction digest differs")
if (
    not isinstance(operation_image_ids, list)
    or operation_image_ids != sorted(set(operation_image_ids))
    or len(operation_image_ids) != 1
    or any(not isinstance(value, str) or __import__("re").fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in operation_image_ids)
    or operation_image_label != f"mochirii.forums.historical-reader={operation}"
):
    raise SystemExit("terminal historical scratch-reader image evidence differs")
if output.exists() or output.is_symlink():
    metadata = output.lstat()
    existing = json.loads(output.read_text(encoding="utf-8"))
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_size > 65536:
        raise SystemExit("existing scratch-absence evidence is unsafe")
    if set(existing) != set(stable) | {"recordedAt"} or not isinstance(existing.get("recordedAt"), str):
        raise SystemExit("existing scratch-absence evidence schema differs")
    for key, value in stable.items():
        if existing.get(key) != value:
            raise SystemExit("existing scratch-absence evidence differs")
else:
    document = {**stable, "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}
    descriptor, name = __import__("tempfile").mkstemp(prefix=f".{output.name}.", suffix=".partial", dir=output.parent)
    candidate = pathlib.Path(name)
    try:
        os.chmod(candidate, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(candidate, output)
        if os.name != "nt":
            directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if candidate.exists():
            candidate.unlink()
PY

  local scratch_transaction="${terminal_reader_transaction}"
  if [[ -e ${scratch_transaction} || -L ${scratch_transaction} ]]; then
    protected_regular "${scratch_transaction}" "Terminal historical scratch-reader transaction" 65536
    python3 -B - "${scratch_transaction}" "${scratch_absence}" "${receipt}" "${fetched_archive}" \
      "${bootstrap_commit}" "${operation_id}" "${shared_root}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

transaction, absence, receipt, archive, shared = map(
    pathlib.Path, (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[7])
)
commit, operation = sys.argv[5], sys.argv[6]
document = json.loads(transaction.read_text(encoding="utf-8"))
absence_document = json.loads(absence.read_text(encoding="utf-8"))
receipt_raw = receipt.read_bytes()
archive_raw = archive.read_bytes()
if (
    document.get("phase") != "outputs-published"
    or document.get("bootstrapRepositoryCommit") != commit
    or document.get("readerOperationId") != operation
    or document.get("cleanupProved") is not True
    or document.get("receiptSha256") != hashlib.sha256(receipt_raw).hexdigest()
    or document.get("receiptBytes") != len(receipt_raw)
    or document.get("releaseArchiveSha256") != hashlib.sha256(archive_raw).hexdigest()
    or document.get("releaseArchiveBytes") != len(archive_raw)
    or absence_document.get("bootstrapRepositoryCommit") != commit
    or absence_document.get("readerOperationId") != operation
    or absence_document.get("terminalReaderTransactionPhase") != "outputs-published"
    or absence_document.get("terminalReaderTransactionSha256") != hashlib.sha256(transaction.read_bytes()).hexdigest()
    or absence_document.get("readerOperationImageIds") != document.get("operationImageIds")
    or absence_document.get("readerOperationImageLabel") != document.get("operationImageLabel")
    or absence_document.get("readerOperationImagesAbsent") is not True
    or absence_document.get("disasterRecoveryReceiptSha256") != hashlib.sha256(receipt_raw).hexdigest()
    or absence_document.get("releaseArchiveSha256") != hashlib.sha256(archive_raw).hexdigest()
    or shared.exists()
    or shared.is_symlink()
):
    raise SystemExit("terminal historical scratch-reader retirement authority differs")
transaction.unlink()
if os.name != "nt":
    descriptor = os.open(transaction.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
  fi

  install -d -m 0700 -o root -g root "${archives_root}" "${releases_root}" "${containers_root}"
  local sealed_archive="${archives_root}/${recovered_commit}-${archive_sha}.tar"
  local source_dir="${releases_root}/${recovered_commit}"
  MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" prepare \
    --receipt "${receipt}" --archive "${fetched_archive}" --bootstrap-commit "${bootstrap_commit}" \
    --sealed-archive "${sealed_archive}" --source-dir "${source_dir}" --journal "${adoption_journal}" \
    --current-host-control "${host_control}" --scratch-absence "${scratch_absence}" \
    --confirmation "${prepare_confirmation}"

  local config_candidate config_root production_config restore_config
  config_candidate="$(mktemp -d "${containers_root}/.candidate-${recovered_commit}.XXXXXXXX")"
  trap 'rm -rf -- "${config_candidate:-}"' RETURN
  python3 -B "${source_dir}/scripts/render-app-config.py" --mode production --runtime-json "${runtime_json}" \
    --repository-commit "${recovered_commit}" --output "${config_candidate}/app.yml"
  python3 -B "${source_dir}/scripts/render-app-config.py" --mode disposable-restore --runtime-json "${runtime_json}" \
    --repository-commit "${recovered_commit}" --output "${config_candidate}/restore.yml"
  config_root="${containers_root}/${recovered_commit}"
  install -d -m 0700 -o root -g root "${config_root}"
  production_config="${config_root}/app.yml"
  restore_config="${config_root}/restore.yml"
  for pair in "${config_candidate}/app.yml:${production_config}" "${config_candidate}/restore.yml:${restore_config}"; do
    source_file="${pair%%:*}"
    target_file="${pair#*:}"
    if [[ -e ${target_file} || -L ${target_file} ]]; then
      [[ -f ${target_file} && ! -L ${target_file} ]] || fail "Authorized historical configuration is unsafe."
      cmp -s -- "${source_file}" "${target_file}" || fail "Authorized historical configuration changed on retry."
    else
      install -m 0600 -o root -g root "${source_file}" "${target_file}"
    fi
  done
  rm -rf -- "${config_candidate}"
  config_candidate=""
  trap - RETURN

  MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" authorize \
    --receipt "${receipt}" --journal "${adoption_journal}" \
    --production-config "${production_config}" --restore-config "${restore_config}" \
    --confirmation "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"

  if [[ -n ${fixture_root} && ${MOCHIRII_HISTORICAL_FIXTURE_CRASH_AFTER:-} == configuration-authorized-before-reader-retirement ]]; then
    fail "Historical fixture stopped after configuration authorization and before reader-intent retirement."
  fi

  python3 -B - "${reader_journal}" "${shared_root}" <<'PY'
import os
import pathlib
import sys

journal, shared = map(pathlib.Path, sys.argv[1:])
if shared.exists() or shared.is_symlink():
    raise SystemExit("real persistent target appeared before reader retirement")
journal.unlink()
if os.name != "nt":
    descriptor = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
  printf '%s\n' "Historical C0 source and configurations are authorized; run the exact recovery continuation."
}

contain_failure() {
  if [[ -n ${fixture_root} ]]; then
    if [[ -n ${MOCHIRII_HISTORICAL_FAKE_CONTAINMENT_LOG:-} ]]; then
      printf '%s\n' contained >>"${MOCHIRII_HISTORICAL_FAKE_CONTAINMENT_LOG}"
    fi
    return 0
  fi
  timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
  state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null || true)"
  [[ -z ${state} || ${state} == false ]]
}

completed_recovery() {
  [[ -f ${receipt} && ! -L ${receipt} && ! -e ${adoption_journal} && ! -L ${adoption_journal} ]] || return 1
  protected_regular "${receipt}" "Fetched historical recovery receipt" 65536 || return 1
  python3 -B - "${receipt}" "${state_root}" "$([[ -n ${fixture_root} ]] && printf fixture || printf production)" <<'PY' >/dev/null
import hashlib
import json
import pathlib
import re
import stat
import sys

receipt_path = pathlib.Path(sys.argv[1])
state = pathlib.Path(sys.argv[2])
fixture_mode = sys.argv[3] == "fixture"

def protected(path, maximum):
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not 1 <= metadata.st_size <= maximum
        or (not fixture_mode and (metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600))
    ):
        raise SystemExit(1)
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) != metadata.st_size or len(raw) > maximum:
        raise SystemExit(1)
    return raw

receipt_raw = protected(receipt_path, 65536)
receipt = json.loads(receipt_raw)
commit = receipt.get("repositoryCommit", "")
configuration = receipt.get("productionConfigurationSha256", "")
if re.fullmatch(r"[0-9a-f]{40}", str(commit)) is None or re.fullmatch(r"[0-9a-f]{64}", str(configuration)) is None:
    raise SystemExit(1)
completion = state / "evidence" / f"{commit}-{configuration}-historical-recovery-complete.json"
current = state / "current-release.json"
terminal = state / "current-restore.json"
pointer = state / "latest-backup-evidence"
completion_raw = protected(completion, 65536)
current_raw = protected(current, 65536)
terminal_raw = protected(terminal, 65536)
pointer_raw = protected(pointer, 65536)
record = json.loads(completion_raw)
required = {
    "schemaVersion", "phase", "operation", "bootstrapRepositoryCommit", "recoveredRepositoryCommit",
    "readerOperationId", "disasterRecoveryReceiptFile", "disasterRecoveryReceiptSha256",
    "originalReleaseEvidenceSha256", "regeneratedReleaseEvidenceFile", "regeneratedReleaseEvidenceSha256",
    "restoreTerminalEvidenceFile", "restoreTerminalEvidenceSha256", "cleanBackupEvidenceFile",
    "cleanBackupEvidenceSha256", "recordedAt",
}
if set(record) != required or record.get("schemaVersion") != 1 or record.get("phase") != "complete" or record.get("operation") != "historical-release-clean-target-adoption":
    raise SystemExit(1)
if record.get("recoveredRepositoryCommit") != commit or record.get("disasterRecoveryReceiptFile") != str(receipt_path) or record.get("disasterRecoveryReceiptSha256") != hashlib.sha256(receipt_raw).hexdigest() or record.get("originalReleaseEvidenceSha256") != receipt.get("releaseEvidenceSha256"):
    raise SystemExit(1)
current_doc = json.loads(current_raw)
expected_release_name = f"{commit}-{configuration}-release.json"
if current_doc.get("releaseEvidenceFile") != expected_release_name:
    raise SystemExit(1)
release = state / "evidence" / expected_release_name
if current_doc.get("repositoryCommit") != commit or current_doc.get("productionConfigurationSha256") != configuration or current_doc.get("discourseConnectEnabled") is not False:
    raise SystemExit(1)
release_raw = protected(release, 65536)
if record.get("regeneratedReleaseEvidenceFile") != str(release) or record.get("regeneratedReleaseEvidenceSha256") != hashlib.sha256(release_raw).hexdigest():
    raise SystemExit(1)
terminal_doc = json.loads(terminal_raw)
clean = pathlib.Path(record.get("cleanBackupEvidenceFile", ""))
if clean.parent != state / "evidence" or re.fullmatch(rf"{commit}-{configuration}-[0-9]{{8}}T[0-9]{{6}}Z-backup[.]json", clean.name) is None:
    raise SystemExit(1)
clean_raw = protected(clean, 65536)
clean_doc = json.loads(clean_raw)
if record.get("restoreTerminalEvidenceFile") != str(terminal) or record.get("restoreTerminalEvidenceSha256") != hashlib.sha256(terminal_raw).hexdigest():
    raise SystemExit(1)
if terminal_doc.get("phase") != "complete" or terminal_doc.get("restoreMode") != "clean-target-disaster" or terminal_doc.get("repositoryCommit") != commit or terminal_doc.get("productionConfigurationSha256") != configuration:
    raise SystemExit(1)
if terminal_doc.get("cleanBackupEvidenceFile") != str(clean) or terminal_doc.get("cleanBackupEvidenceSha256") != hashlib.sha256(clean_raw).hexdigest() or record.get("cleanBackupEvidenceSha256") != hashlib.sha256(clean_raw).hexdigest():
    raise SystemExit(1)
if pointer_raw != (str(clean) + "\n").encode("utf-8") or clean_doc.get("finalCleanAfterRestore") is not True or clean_doc.get("repositoryCommit") != commit or clean_doc.get("productionConfigurationSha256") != configuration:
    raise SystemExit(1)
PY
}

resume_recovery() {
  local confirmation="$1" status=0 reader_operation_id=""
  [[ ${confirmation} == "${recover_confirmation}" ]] || fail "Exact historical recovery confirmation is required."
  if [[ ! -e ${adoption_journal} && ! -L ${adoption_journal} ]]; then
    completed_recovery && {
      printf '%s\n' "Historical Mochirii Forums disaster recovery was already completed with exact terminal evidence."
      return 0
    }
    fail "Historical adoption journal is absent and no exact terminal completion is proved."
  fi
  protected_regular "${adoption_journal}" "Historical adoption journal" 65536
  protected_regular "${receipt}" "Fetched historical recovery receipt" 65536
  trusted_entrypoint "${helper}" && trusted_entrypoint "${deployer}" &&
    trusted_entrypoint "${restorer}" && trusted_entrypoint "${producer_probe}" ||
    fail "Historical host-control entrypoint is absent or unsafe."
  if [[ -e ${reader_journal} || -L ${reader_journal} ]]; then
    protected_regular "${reader_journal}" "Historical reader intent pending retirement" 65536
    protected_regular "${scratch_absence}" "Scratch-reader absence evidence" 65536
    MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" verify \
      --receipt "${receipt}" --journal "${adoption_journal}" --require-phase configuration-authorized
    reader_operation_id="$(python3 -B - "${reader_journal}" "${adoption_journal}" "${scratch_absence}" "${host_control}" "${shared_root}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
intent_path, adoption_path, absence_path, control_path, shared = map(pathlib.Path, sys.argv[1:])
intent_raw = intent_path.read_bytes()
intent = json.loads(intent_raw)
adoption = json.loads(adoption_path.read_text(encoding="utf-8"))
absence = json.loads(absence_path.read_text(encoding="utf-8"))
control_raw = control_path.read_bytes()
required = {
    "schemaVersion", "operation", "phase", "recordedAt", "bootstrapRepositoryCommit",
    "readerOperationId", "scratchRoot", "currentHostControlFile", "currentHostControlSha256",
    "realPersistentTarget", "realPersistentTargetInitiallyAbsent",
}
operation = intent.get("readerOperationId", "")
if (
    set(intent) != required
    or intent.get("schemaVersion") != 1
    or intent.get("operation") != "current-main-historical-recovery-reader"
    or intent.get("phase") != "reader-armed"
    or adoption.get("phase") != "configuration-authorized"
    or adoption.get("bootstrapRepositoryCommit") != intent.get("bootstrapRepositoryCommit")
    or adoption.get("readerOperationId") != operation
    or re.fullmatch(r"[0-9a-f]{32}", str(operation)) is None
    or intent.get("currentHostControlFile") != str(control_path)
    or intent.get("currentHostControlSha256") != hashlib.sha256(control_raw).hexdigest()
    or intent.get("realPersistentTarget") != str(shared)
    or intent.get("realPersistentTargetInitiallyAbsent") is not True
    or absence.get("readerOperationId") != operation
    or absence.get("bootstrapRepositoryCommit") != intent.get("bootstrapRepositoryCommit")
    or absence.get("readerIntentSha256") != hashlib.sha256(intent_raw).hexdigest()
    or any(absence.get(key) is not True for key in (
        "scratchDirectoryAbsent", "readerContainerAbsent", "readerOperationImagesAbsent", "readerProcessAbsent",
        "readerLauncherStateAbsent", "realPersistentTargetAbsent",
    ))
    or absence.get("readerOperationImageIds") != sorted(set(absence.get("readerOperationImageIds", [])))
    or len(absence.get("readerOperationImageIds", [])) != 1
    or any(not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in absence.get("readerOperationImageIds", []))
    or absence.get("readerOperationImageLabel") != f"mochirii.forums.historical-reader={operation}"
    or shared.exists()
    or shared.is_symlink()
):
    raise SystemExit("pending historical reader retirement authority differs")
print(operation)
PY
    )" || fail "Historical reader retirement authority is malformed."
    [[ ${reader_operation_id} =~ ^[0-9a-f]{32}$ ]] || fail "Historical reader retirement operation is malformed."
    [[ ! -e ${stage_root}/historical-reader-${reader_operation_id}.transaction.json && ! -L ${stage_root}/historical-reader-${reader_operation_id}.transaction.json ]] ||
      fail "Historical reader retirement refuses an active scratch transaction."
    [[ ! -e ${state_root}/historical-reader/${reader_operation_id} && ! -L ${state_root}/historical-reader/${reader_operation_id} ]] ||
      fail "Historical reader retirement refuses surviving scratch state."
    reader_runtime_absent "${reader_operation_id}" "${scratch_absence}" || fail "Historical reader retirement refuses surviving scratch runtime."
    python3 -B - "${reader_journal}" "${shared_root}" <<'PY'
import os
import pathlib
import sys
journal, shared = map(pathlib.Path, sys.argv[1:])
if shared.exists() or shared.is_symlink():
    raise SystemExit("real persistent target appeared before reader retirement")
journal.unlink()
descriptor = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  fi
  [[ ! -e ${reader_journal} && ! -L ${reader_journal} ]] || fail "Historical reader intent was not retired before recovery continuation."
  readarray -t adoption < <(python3 -B - "${adoption_journal}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
document = json.loads(raw)
phase = document.get("phase", "")
if phase not in {"configuration-authorized", "bootstrap-started", "bootstrap-complete", "restore-started", "restore-complete"}:
    raise SystemExit("historical adoption phase is not resumable")
commit = document.get("recoveredRepositoryCommit", "")
operation = document.get("readerOperationId", "")
archive = document.get("releaseArchiveFile", "")
archive_sha = document.get("releaseArchiveSha256", "")
archive_bytes = document.get("releaseArchiveBytes")
if re.fullmatch(r"[0-9a-f]{40}", str(commit)) is None or re.fullmatch(r"[0-9a-f]{32}", str(operation)) is None or re.fullmatch(r"[0-9a-f]{64}", str(archive_sha)) is None or not isinstance(archive_bytes, int):
    raise SystemExit("historical adoption release identity is malformed")
print(phase)
print(commit)
print(archive)
print(archive_sha)
print(archive_bytes)
print(hashlib.sha256(raw).hexdigest())
print(operation)
PY
  ) || fail "Historical adoption journal is malformed."
  [[ ${#adoption[@]} -eq 7 ]] || fail "Historical adoption journal is incomplete."
  local phase="${adoption[0]}" recovered_commit="${adoption[1]}" sealed_archive="${adoption[2]}"
  local archive_sha="${adoption[3]}" archive_bytes="${adoption[4]}" journal_sha="${adoption[5]}"
  local operation_id="${adoption[6]}"
  [[ ! -e ${stage_root}/historical-reader-${operation_id}.transaction.json && ! -L ${stage_root}/historical-reader-${operation_id}.transaction.json ]] ||
    fail "Historical recovery continuation refuses an unretired scratch-reader transaction."
  [[ ! -e ${state_root}/historical-reader/${operation_id} && ! -L ${state_root}/historical-reader/${operation_id} ]] ||
    fail "Historical recovery continuation refuses surviving scratch-reader state."
  reader_runtime_absent "${operation_id}" "${scratch_absence}" || fail "Historical recovery continuation refuses surviving scratch-reader runtime."
  protected_regular "${sealed_archive}" "Sealed historical release archive" 67108864
  [[ "$(sha256sum -- "${sealed_archive}" | awk '{print $1}')" == "${archive_sha}" ]] || fail "Sealed historical archive changed."
  MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" verify \
    --receipt "${receipt}" --journal "${adoption_journal}" --require-phase "${phase}"
  timeout --signal=TERM --kill-after=5s 45 python3 -B "${producer_probe}" disabled >/dev/null 2>&1 || fail "Historical recovery requires the Website Forums producer to remain disabled."
  if [[ ${phase} == configuration-authorized ]]; then
    [[ ! -e ${shared_root} && ! -L ${shared_root} ]] || fail "Historical bootstrap requires the real persistent target to remain absent."
  elif [[ ${phase} == bootstrap-started ]]; then
    if [[ -e ${shared_root} || -L ${shared_root} ]]; then
      [[ -d ${shared_root} && ! -L ${shared_root} ]] || fail "Interrupted historical bootstrap left an unsafe persistent target."
      protected_regular "${state_root}/deployment-mutation.json" "Interrupted historical bootstrap mutation journal" 65536
    fi
  else
    [[ -d ${shared_root} && ! -L ${shared_root} ]] || fail "Historical restore continuation requires the exact C0 persistent target."
    protected_regular "${state_root}/current-release.json" "Recovered C0 current-release evidence" 65536
  fi

  if [[ ${phase} == configuration-authorized ]]; then
    MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" begin-bootstrap \
      --receipt "${receipt}" --journal "${adoption_journal}" \
      --confirmation "BEGIN HISTORICAL MOCHIRII FORUMS BOOTSTRAP"
    journal_sha="$(sha256sum -- "${adoption_journal}" | awk '{print $1}')"
    phase=bootstrap-started
  fi

  local reconcile_bootstrap=false
  if [[ ${phase} == bootstrap-complete && ( -e ${state_root}/deployment-mutation.json || -L ${state_root}/deployment-mutation.json ) ]]; then
    protected_regular "${state_root}/deployment-mutation.json" "Committed historical bootstrap mutation journal" 65536
    reconcile_bootstrap=true
  fi

  if [[ ${phase} == bootstrap-started || ${reconcile_bootstrap} == true ]]; then
    MOCHIRII_HISTORICAL_BOUNDARY_ROOT="${fixture_root}" python3 -B "${helper}" verify \
      --receipt "${receipt}" --journal "${adoption_journal}" --require-phase "${phase}"
    journal_sha="$(sha256sum -- "${adoption_journal}" | awk '{print $1}')"
    install -d -m 0700 -o root -g root "${incoming_root}"
    incoming="${incoming_root}/${recovered_commit}.tar"
    if [[ -e ${incoming} || -L ${incoming} ]]; then
      [[ -f ${incoming} && ! -L ${incoming} ]] || fail "Historical incoming archive is unsafe."
      cmp -s -- "${sealed_archive}" "${incoming}" || fail "Historical incoming archive differs on retry."
    else
      install -m 0600 -o root -g root "${sealed_archive}" "${incoming}"
    fi
    set +e
    if [[ -n ${fixture_root} ]]; then
      python3 -B "${deployer}" "${incoming}" "${recovered_commit}" "${archive_sha}" "${archive_bytes}" \
        historical-bootstrap "${adoption_journal}" "${journal_sha}"
    else
      "${deployer}" "${incoming}" "${recovered_commit}" "${archive_sha}" "${archive_bytes}" \
        historical-bootstrap "${adoption_journal}" "${journal_sha}"
    fi
    status=$?
    set -e
    if (( status != 0 )); then
      contain_failure || printf '%s\n' "CRITICAL: historical bootstrap failure containment is unproved." >&2
      return "${status}"
    fi
    phase="$(python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["phase"])' "${adoption_journal}")"
  fi

  [[ ${phase} == bootstrap-complete || ${phase} == restore-started || ${phase} == restore-complete ]] || fail "Historical bootstrap did not commit its exact terminal authority."
  set +e
  if [[ -n ${fixture_root} ]]; then
    python3 -B "${restorer}" "${recovered_commit}" "RESTORE CLEAN TARGET MOCHIRII FORUMS"
  else
    "${restorer}" "${recovered_commit}" "RESTORE CLEAN TARGET MOCHIRII FORUMS"
  fi
  status=$?
  set -e
  if (( status != 0 )); then
    contain_failure || printf '%s\n' "CRITICAL: historical restore failure containment is unproved." >&2
    return "${status}"
  fi
  [[ ! -e ${adoption_journal} && ! -L ${adoption_journal} ]] || fail "Historical restore returned without retiring its terminal adoption journal."
  printf '%s\n' "Historical Mochirii Forums disaster recovery completed and retired its active journal."
}

[[ $# -ge 1 ]] || fail "Usage: host-historical-disaster-recovery.sh begin-reader|prepare|resume ..."
command_name="$1"
shift
case "${command_name}" in
  begin-reader)
    [[ $# -eq 3 ]] || fail "Usage: ... begin-reader CURRENT_MAIN_COMMIT OPERATION_ID CONFIRMATION"
    begin_reader "$@"
    ;;
  prepare)
    [[ $# -eq 3 ]] || fail "Usage: ... prepare CURRENT_MAIN_COMMIT OPERATION_ID CONFIRMATION"
    prepare_release "$@"
    ;;
  resume)
    [[ $# -eq 1 ]] || fail "Usage: ... resume CONFIRMATION"
    resume_recovery "$1"
    ;;
  *) fail "Historical disaster-recovery command differs." ;;
esac
