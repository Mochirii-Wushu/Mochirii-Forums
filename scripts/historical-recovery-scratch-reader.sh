#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

readonly pinned_deployment_revision="ed9f680b0df1de28f062de1769d89d22b2644d1b"
readonly pinned_deployment_tree="588498dffbea91592fd4e2f10166bc11c8fe7a61"
readonly confirmation_text="FETCH HISTORICAL MOCHIRII FORUMS RECOVERY SOURCE"
readonly max_document_bytes=65536
readonly max_archive_bytes=67108864

[[ ${EUID} -eq 0 ]] || fail "Historical recovery scratch reader must run as root."
[[ ${SUDO_USER:-root} != mochirii-forums-deploy ]] || fail "The deploy principal may not invoke historical recovery."
[[ $# -eq 3 ]] || fail "Usage: historical-recovery-scratch-reader.sh CURRENT_MAIN_COMMIT OPERATION_ID CONFIRMATION"
readonly bootstrap_commit="$1"
readonly operation_id="$2"
readonly confirmation="$3"
[[ ${bootstrap_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Current-main reader commit is malformed."
[[ ${operation_id} =~ ^[0-9a-f]{32}$ ]] || fail "Historical reader operation identifier is malformed."
[[ ${confirmation} == "${confirmation_text}" ]] || fail "Exact historical reader confirmation is required."

fixture_root="${MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_ROOT:-}"
fixture_mode=false
deployment_revision="${pinned_deployment_revision}"
deployment_tree="${pinned_deployment_tree}"
if [[ -n ${fixture_root} ]]; then
  [[ ${MOCHIRII_HISTORICAL_SCRATCH_MODE:-} == source-only-hostile-fixture ]] || fail "Scratch fixture root requires its exact source-only fixture mode."
  fixture_root="$(readlink -f -- "${fixture_root}")"
  [[ ${fixture_root} == /tmp/* && ${fixture_root} != /tmp ]] || fail "Scratch fixture root must be one exact child of /tmp."
  fixture_mode=true
  deployment_revision="${MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_DEPLOYMENT_REVISION:-}"
  deployment_tree="${MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_DEPLOYMENT_TREE:-}"
  [[ ${deployment_revision} =~ ^[0-9a-f]{40}$ && ${deployment_tree} =~ ^[0-9a-f]{40}$ ]] || fail "Scratch fixture deployment identity is malformed."
  state_root="${fixture_root}/var/lib/mochirii/forums"
  stage_root="${state_root}/historical-recovery"
  runtime_json="${fixture_root}/etc/mochirii/forums.runtime.json"
  real_shared="${fixture_root}/var/discourse/shared/standalone"
  source_archive="${fixture_root}/opt/mochirii/forums/host-control-releases/${bootstrap_commit}/mochirii-release.tar"
  deployment_archive="${fixture_root}/opt/mochirii/forums/deployment-source/${deployment_revision}.tar"
  adapter="${fixture_root}/adapter.py"
  lock_file="${fixture_root}/run/lock/mochirii-forums/historical-reader.lock"
else
  state_root=/var/lib/mochirii/forums
  stage_root="${state_root}/historical-recovery"
  runtime_json=/etc/mochirii/forums.runtime.json
  real_shared=/var/discourse/shared/standalone
  source_archive="/opt/mochirii/forums/host-control-releases/${bootstrap_commit}/mochirii-release.tar"
  deployment_archive="/opt/mochirii/forums/deployment-source/${deployment_revision}.tar"
  adapter=""
  lock_file=/run/lock/mochirii-forums/historical-reader.lock
fi

readonly fixture_root fixture_mode state_root stage_root runtime_json real_shared
readonly deployment_revision deployment_tree source_archive deployment_archive adapter lock_file
readonly host_control="${state_root}/current-host-control.json"
readonly reader_intent="${state_root}/historical-reader.json"
readonly scratch_parent="${state_root}/historical-reader"
readonly scratch_root="${scratch_parent}/${operation_id}"
readonly receipt_output="${stage_root}/fetched-recovery-receipt.json"
readonly archive_output="${stage_root}/fetched-release.tar"
readonly receipt_candidate="${stage_root}/.fetched-recovery-receipt.${operation_id}.partial"
readonly archive_candidate="${stage_root}/.fetched-release.${operation_id}.partial"
readonly transaction_file="${stage_root}/historical-reader-${operation_id}.transaction.json"
readonly app_name="mochirii-dr-reader-${operation_id}"
readonly image_name="local_discourse/${app_name}"

for command_name in base64 chmod flock install mkdir python3 readlink setsid stat timeout; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "Required historical reader command is absent."
done
if [[ ${fixture_mode} == false ]]; then
  command -v docker >/dev/null 2>&1 || fail "Docker is absent from the historical reader host."
else
  [[ -f ${adapter} && ! -L ${adapter} && "$(stat -c '%u:%g:%a' -- "${adapter}")" == 0:0:600 ]] || fail "Historical reader fixture adapter is unsafe."
fi

lock_directory="$(dirname -- "${lock_file}")"
if [[ ${fixture_mode} == true ]]; then
  install -d -m 0700 -o root -g root "$(dirname -- "${lock_directory}")"
else
  [[ ${lock_directory} == /run/lock/mochirii-forums ]] || fail "Historical reader lock directory differs."
  [[ -d /run/lock && ! -L /run/lock && "$(stat -c '%u:%g' -- /run/lock)" == 0:0 ]] ||
    fail "System lock parent is unsafe."
fi
if [[ ! -e ${lock_directory} && ! -L ${lock_directory} ]]; then
  mkdir -m 0700 -- "${lock_directory}" || fail "Historical reader lock directory could not be created safely."
fi
[[ -d ${lock_directory} && ! -L ${lock_directory} && "$(stat -c '%u:%g:%a' -- "${lock_directory}")" == 0:0:700 ]] ||
  fail "Historical reader lock directory ownership or mode is unsafe."
if [[ -e ${lock_file} || -L ${lock_file} ]]; then
  [[ -f ${lock_file} && ! -L ${lock_file} && "$(stat -c '%u:%g' -- "${lock_file}")" == 0:0 ]] ||
    fail "Historical reader lock file is unsafe."
fi
exec 8>"${lock_file}"
chmod 0600 -- "${lock_file}"
flock -n 8 || fail "Another historical recovery scratch reader is active."

protected_regular() {
  local path="$1" label="$2" maximum="$3"
  local metadata
  [[ -f ${path} && ! -L ${path} ]] || fail "${label} is absent or linked."
  metadata="$(stat -c '%u:%g:%a:%s' -- "${path}")" || fail "${label} metadata is unreadable."
  [[ ${metadata} =~ ^0:0:600:([1-9][0-9]*)$ ]] || fail "${label} ownership, mode, or size is unsafe."
  (( ${BASH_REMATCH[1]} <= maximum )) || fail "${label} exceeds its byte boundary."
}

protected_directory() {
  local path="$1" label="$2" expected_mode="$3"
  [[ -d ${path} && ! -L ${path} ]] || fail "${label} is absent or linked."
  [[ "$(stat -c '%u:%g:%a' -- "${path}")" == "0:0:${expected_mode}" ]] || fail "${label} ownership or mode is unsafe."
}

load_or_create_transaction() {
  local preexisting_image_ids="$1"
  python3 -B - "${transaction_file}" "${host_control}" "${reader_intent}" \
    "${bootstrap_commit}" "${operation_id}" "${scratch_root}" "${real_shared}" \
    "${receipt_candidate}" "${receipt_output}" "${archive_candidate}" "${archive_output}" \
    "${preexisting_image_ids}" "mochirii.forums.historical-reader=${operation_id}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile

(
    transaction, control, intent, commit, operation, scratch, shared,
    receipt_candidate, receipt_output, archive_candidate, archive_output,
    preexisting_image_text, image_label,
) = (pathlib.Path(value) if index in {0, 1, 2, 5, 6, 7, 8, 9, 10} else value for index, value in enumerate(sys.argv[1:]))
HEX64 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
KEYS = {
    "schemaVersion", "operation", "phase", "bootstrapRepositoryCommit", "readerOperationId",
    "readerIntentFile", "readerIntentSha256", "currentHostControlFile", "currentHostControlSha256",
    "scratchRoot", "realPersistentTarget", "receiptCandidateFile", "receiptOutputFile",
    "archiveCandidateFile", "archiveOutputFile", "receiptSha256", "receiptBytes",
    "releaseArchiveSha256", "releaseArchiveBytes", "preexistingImageIds",
    "operationImageIds", "operationImageLabel", "cleanupProved",
}
PHASES = {"armed", "receipt-fetched", "archive-fetched", "cleanup-proved", "receipt-published", "outputs-published"}

def protected(path, label):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
        raise SystemExit(f"{label} is unsafe")
    return path.read_bytes()

control_raw = protected(control, "current host-control evidence")
intent_raw = protected(intent, "historical reader intent")
try:
    control_document = json.loads(control_raw)
    intent_document = json.loads(intent_raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("historical reader authority is malformed")
control_keys = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
intent_keys = {
    "schemaVersion", "operation", "phase", "recordedAt", "bootstrapRepositoryCommit",
    "readerOperationId", "scratchRoot", "currentHostControlFile", "currentHostControlSha256",
    "realPersistentTarget", "realPersistentTargetInitiallyAbsent",
}
if (
    not isinstance(control_document, dict)
    or set(control_document) != control_keys
    or control_document.get("schemaVersion") != 1
    or control_document.get("phase") != "hardened"
    or control_document.get("repositoryCommit") != commit
):
    raise SystemExit("current host-control authority differs before reconciliation")
if (
    not isinstance(intent_document, dict)
    or set(intent_document) != intent_keys
    or intent_document.get("schemaVersion") != 1
    or intent_document.get("operation") != "current-main-historical-recovery-reader"
    or intent_document.get("phase") != "reader-armed"
    or intent_document.get("bootstrapRepositoryCommit") != commit
    or intent_document.get("readerOperationId") != operation
    or intent_document.get("scratchRoot") != str(scratch)
    or intent_document.get("currentHostControlFile") != str(control)
    or intent_document.get("currentHostControlSha256") != hashlib.sha256(control_raw).hexdigest()
    or intent_document.get("realPersistentTarget") != str(shared)
    or intent_document.get("realPersistentTargetInitiallyAbsent") is not True
):
    raise SystemExit("historical reader intent differs before reconciliation")
stable = {
    "schemaVersion": 1,
    "operation": "current-main-historical-recovery-scratch-reader",
    "bootstrapRepositoryCommit": commit,
    "readerOperationId": operation,
    "readerIntentFile": str(intent),
    "readerIntentSha256": hashlib.sha256(intent_raw).hexdigest(),
    "currentHostControlFile": str(control),
    "currentHostControlSha256": hashlib.sha256(control_raw).hexdigest(),
    "scratchRoot": str(scratch),
    "realPersistentTarget": str(shared),
    "receiptCandidateFile": str(receipt_candidate),
    "receiptOutputFile": str(receipt_output),
    "archiveCandidateFile": str(archive_candidate),
    "archiveOutputFile": str(archive_output),
    "operationImageLabel": image_label,
}
preexisting_images = sorted(set(filter(None, preexisting_image_text.splitlines())))
if any(IMAGE_ID.fullmatch(value) is None for value in preexisting_images):
    raise SystemExit("historical reader preexisting image inventory is malformed")
if transaction.exists() or transaction.is_symlink():
    raw = protected(transaction, "historical reader transaction")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("historical reader transaction is malformed")
    if not isinstance(document, dict) or set(document) != KEYS or any(document.get(key) != value for key, value in stable.items()):
        raise SystemExit("historical reader transaction authority differs")
    if (
        not isinstance(document.get("preexistingImageIds"), list)
        or document["preexistingImageIds"] != sorted(set(document["preexistingImageIds"]))
        or any(not isinstance(value, str) or IMAGE_ID.fullmatch(value) is None for value in document["preexistingImageIds"])
        or not isinstance(document.get("operationImageIds"), list)
        or document["operationImageIds"] != sorted(set(document["operationImageIds"]))
        or any(not isinstance(value, str) or IMAGE_ID.fullmatch(value) is None for value in document["operationImageIds"])
        or set(document["preexistingImageIds"]) & set(document["operationImageIds"])
    ):
        raise SystemExit("historical reader transaction image identity differs")
    phase = document.get("phase")
    if phase not in PHASES:
        raise SystemExit("historical reader transaction phase differs")
else:
    for path in (receipt_candidate, receipt_output, archive_candidate, archive_output):
        if path.exists() or path.is_symlink():
            raise SystemExit("unowned historical reader output already exists")
    document = {
        **stable,
        "phase": "armed",
        "receiptSha256": None,
        "receiptBytes": None,
        "releaseArchiveSha256": None,
        "releaseArchiveBytes": None,
        "preexistingImageIds": preexisting_images,
        "operationImageIds": [],
        "cleanupProved": False,
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{transaction.name}.", suffix=".partial", dir=transaction.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, transaction)
        descriptor = os.open(transaction, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        descriptor = os.open(transaction.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()

phase = document["phase"]
receipt_sha = document.get("receiptSha256")
receipt_bytes = document.get("receiptBytes")
archive_sha = document.get("releaseArchiveSha256")
archive_bytes = document.get("releaseArchiveBytes")
if phase == "armed":
    if any(value is not None for value in (receipt_sha, receipt_bytes, archive_sha, archive_bytes)) or document.get("cleanupProved") is not False:
        raise SystemExit("armed historical reader transaction retained output identity")
else:
    if HEX64.fullmatch(str(receipt_sha or "")) is None or not isinstance(receipt_bytes, int) or isinstance(receipt_bytes, bool) or not 1 <= receipt_bytes <= 65536:
        raise SystemExit("historical reader receipt identity is malformed")
    if phase == "receipt-fetched":
        if archive_sha is not None or archive_bytes is not None or document.get("cleanupProved") is not False:
            raise SystemExit("receipt-fetched transaction retained later identity")
    else:
        if HEX64.fullmatch(str(archive_sha or "")) is None or not isinstance(archive_bytes, int) or isinstance(archive_bytes, bool) or not 1 <= archive_bytes <= 67108864:
            raise SystemExit("historical reader archive identity is malformed")
        if document.get("cleanupProved") is not (phase in {"cleanup-proved", "receipt-published", "outputs-published"}):
            raise SystemExit("historical reader cleanup proof phase differs")
if phase in {"cleanup-proved", "receipt-published", "outputs-published"} and len(document["operationImageIds"]) != 1:
    raise SystemExit("historical reader terminal image identity differs")
print(phase)
print(receipt_sha or "-")
print(receipt_bytes if receipt_bytes is not None else "-")
print(archive_sha or "-")
print(archive_bytes if archive_bytes is not None else "-")
print(hashlib.sha256((json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")).hexdigest())
PY
}

transition_transaction() {
  local expected_phase="$1" next_phase="$2" expected_sha="$3" receipt_sha="$4" receipt_bytes="$5" archive_sha="$6" archive_bytes="$7" cleanup_proved="$8"
  python3 -B - "${transaction_file}" "${expected_phase}" "${next_phase}" "${expected_sha}" \
    "${receipt_sha}" "${receipt_bytes}" "${archive_sha}" "${archive_bytes}" "${cleanup_proved}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
expected_phase, next_phase, expected_sha = sys.argv[2:5]
receipt_sha, receipt_bytes, archive_sha, archive_bytes, cleanup_text = sys.argv[5:10]
allowed = {
    ("armed", "receipt-fetched"),
    ("receipt-fetched", "archive-fetched"),
    ("archive-fetched", "cleanup-proved"),
    ("cleanup-proved", "receipt-published"),
    ("receipt-published", "outputs-published"),
}
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
    raise SystemExit("historical reader transaction is unsafe")
raw = path.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected_sha:
    raise SystemExit("historical reader transaction changed")
document = json.loads(raw)
if document.get("phase") != expected_phase or (expected_phase, next_phase) not in allowed:
    raise SystemExit("historical reader transaction transition differs")
document["phase"] = next_phase
document["receiptSha256"] = None if receipt_sha == "-" else receipt_sha
document["receiptBytes"] = None if receipt_bytes == "-" else int(receipt_bytes)
document["releaseArchiveSha256"] = None if archive_sha == "-" else archive_sha
document["releaseArchiveBytes"] = None if archive_bytes == "-" else int(archive_bytes)
document["cleanupProved"] = cleanup_text == "true"
payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
temporary = pathlib.Path(temporary_name)
try:
    os.chmod(temporary, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    if temporary.exists():
        temporary.unlink()
print(hashlib.sha256(payload).hexdigest())
PY
}

bind_operation_image_ids() {
  local inventory result_label
  local -a result
  inventory="$(docker_all_image_authority)" || return 1
  readarray -t result < <(python3 -B - "${transaction_file}" "${transaction_sha}" "${inventory}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
expected_sha = sys.argv[2]
inventory_text = sys.argv[3]
image_pattern = re.compile(r"sha256:[0-9a-f]{64}")
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or not 1 <= metadata.st_size <= 65536
):
    raise SystemExit("historical reader transaction is unsafe before image binding")
raw = path.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected_sha:
    raise SystemExit("historical reader transaction changed before image binding")
document = json.loads(raw)
preexisting = document.get("preexistingImageIds")
operation_images = document.get("operationImageIds")
expected_label = document.get("operationImageLabel")
if (
    not isinstance(preexisting, list)
    or preexisting != sorted(set(preexisting))
    or any(not isinstance(value, str) or image_pattern.fullmatch(value) is None for value in preexisting)
    or not isinstance(operation_images, list)
    or operation_images != sorted(set(operation_images))
    or any(not isinstance(value, str) or image_pattern.fullmatch(value) is None for value in operation_images)
    or not isinstance(expected_label, str)
):
    raise SystemExit("historical reader transaction image authority differs")
current = {}
for line in filter(None, inventory_text.splitlines()):
    try:
        identity, label = line.split(" ", 1)
    except ValueError:
        raise SystemExit("historical reader image inventory is malformed")
    if image_pattern.fullmatch(identity) is None or identity in current:
        raise SystemExit("historical reader image inventory identity differs")
    current[identity] = label
created = sorted(set(operation_images) | (set(current) - set(preexisting)))
label_ok = all(current.get(identity, expected_label) == expected_label for identity in created if identity in current)
if len(created) > 1 or (document.get("phase") != "armed" and len(created) != 1):
    raise SystemExit("historical reader operation image inventory is ambiguous")
if not label_ok:
    raise SystemExit("historical reader operation image label differs")
document["operationImageIds"] = created
payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
temporary = pathlib.Path(name)
try:
    os.chmod(temporary, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    if temporary.exists():
        temporary.unlink()
print(hashlib.sha256(payload).hexdigest())
print("true" if label_ok else "false")
PY
  ) || return 1
  [[ ${#result[@]} -eq 2 && ${result[0]} =~ ^[0-9a-f]{64}$ ]] || return 1
  transaction_sha="${result[0]}"
  result_label="${result[1]}"
  [[ ${result_label} == true ]]
}

transaction_operation_image_ids() {
  python3 -B - "${transaction_file}" <<'PY'
import json
import pathlib
import re
import stat
import sys
path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
    raise SystemExit("historical reader transaction is unsafe during cleanup")
document = json.loads(path.read_text(encoding="utf-8"))
values = document.get("operationImageIds")
if not isinstance(values, list) or values != sorted(set(values)) or any(not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in values):
    raise SystemExit("historical reader operation image identity differs")
print("\n".join(values))
PY
}

crash_point() {
  local name="$1"
  if [[ ${fixture_mode} == true && ${MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_CRASH_AFTER:-} == "${name}" ]]; then
    kill -KILL "$$"
  fi
}

failure_point() {
  local name="$1"
  if [[ ${fixture_mode} == true && ${MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_FAIL_AFTER:-} == "${name}" ]]; then
    fail "Historical reader hostile fixture injected an ordinary failure."
  fi
}

operation_process_absent() {
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

terminate_operation_processes() {
  python3 -B - "${operation_id}" <<'PY'
import os
import pathlib
import signal
import sys
import time

marker = f"MOCHIRII_HISTORICAL_READER_OPERATION_ID={sys.argv[1]}".encode("ascii")
self_chain = set()
pid = os.getpid()
while pid > 1:
    self_chain.add(pid)
    try:
        fields = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        pid = int(fields[3])
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        break

def marked():
    result = []
    for path in pathlib.Path("/proc").glob("[0-9]*/environ"):
        try:
            candidate = int(path.parent.name)
            if candidate not in self_chain and marker in path.read_bytes().split(b"\0"):
                result.append(candidate)
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            pass
    return result

for candidate in marked():
    try:
        os.kill(candidate, signal.SIGTERM)
    except ProcessLookupError:
        pass
for _ in range(30):
    if not marked():
        raise SystemExit(0)
    time.sleep(0.1)
for candidate in marked():
    try:
        os.kill(candidate, signal.SIGKILL)
    except ProcessLookupError:
        pass
for _ in range(20):
    if not marked():
        raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit(1)
PY
}

external() {
  local stage="$1"
  shift
  if [[ ${fixture_mode} == true ]]; then
    MOCHIRII_HISTORICAL_READER_OPERATION_ID="${operation_id}" \
      MOCHIRII_HISTORICAL_SCRATCH_ROOT="${scratch_root}" \
      python3 -B "${adapter}" "${stage}" -- "$@"
  else
    MOCHIRII_HISTORICAL_READER_OPERATION_ID="${operation_id}" "$@"
  fi
}

docker_inventory_by_label() {
  external inventory timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
    --filter "label=mochirii.forums.historical-reader=${operation_id}" --format '{{.ID}}'
}

docker_inventory_by_name() {
  external inventory timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
    --filter "name=^/${app_name}$" --format '{{.ID}} {{index .Labels "mochirii.forums.historical-reader"}}'
}

docker_image_inventory() {
  external inventory timeout --signal=TERM --kill-after=5s 15 docker image ls --no-trunc \
    --filter "reference=${image_name}" --format '{{.ID}}'
}

docker_all_image_inventory() {
  external inventory timeout --signal=TERM --kill-after=5s 15 docker image ls --all --no-trunc \
    --format '{{.ID}}' | sort -u
}

docker_image_id_state() {
  local target="$1" inventory identity state=absent
  [[ ${target} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  inventory="$(docker_all_image_inventory)" || return 1
  while IFS= read -r identity; do
    [[ -z ${identity} ]] && continue
    [[ ${identity} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    if [[ ${identity} == "${target}" ]]; then
      state=present
    fi
  done <<<"${inventory}"
  printf '%s\n' "${state}"
}

docker_all_image_authority() {
  local identity label inventory
  inventory="$(docker_all_image_inventory)" || return 1
  while IFS= read -r identity; do
    [[ -z ${identity} ]] && continue
    [[ ${identity} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    label="$(external inventory timeout --signal=TERM --kill-after=5s 15 docker image inspect \
      --format '{{index .Config.Labels "mochirii.forums.historical-reader"}}' "${identity}")" || return 1
    [[ ${label} != *$'\n'* && ${label} != *' '* ]] || return 1
    if [[ -n ${label} && ${label} != '<no value>' ]]; then
      label="mochirii.forums.historical-reader=${label}"
    else
      label=-
    fi
    printf '%s %s\n' "${identity}" "${label}"
  done <<<"${inventory}"
}

docker_operation_image_inventory() {
  local authority identity label
  authority="$(docker_all_image_authority)" || return 1
  while IFS=' ' read -r identity label; do
    [[ -z ${identity} ]] && continue
    [[ ${label} == "mochirii.forums.historical-reader=${operation_id}" ]] && printf '%s\n' "${identity}"
  done <<<"${authority}"
}

active_bounded_pid=""
run_quiet() {
  local stage="$1" seconds="$2"
  shift 2
  local status=0
  if [[ ${fixture_mode} == true ]]; then
    setsid env MOCHIRII_HISTORICAL_READER_OPERATION_ID="${operation_id}" \
      MOCHIRII_HISTORICAL_SCRATCH_ROOT="${scratch_root}" \
      python3 -B "${adapter}" "${stage}" -- "$@" >/dev/null 2>&1 &
  else
    setsid env MOCHIRII_HISTORICAL_READER_OPERATION_ID="${operation_id}" \
      timeout --signal=TERM --kill-after=30s "${seconds}" "$@" >/dev/null 2>&1 &
  fi
  active_bounded_pid=$!
  if [[ ${stage} == launcher-bootstrap ]]; then
    while kill -0 "${active_bounded_pid}" >/dev/null 2>&1; do
      if ! bind_operation_image_ids; then
        kill -TERM -- "-${active_bounded_pid}" >/dev/null 2>&1 || true
        sleep 1
        kill -KILL -- "-${active_bounded_pid}" >/dev/null 2>&1 || true
        status=1
        break
      fi
      sleep 0.1
    done
  fi
  wait "${active_bounded_pid}" || status=$?
  active_bounded_pid=""
  if [[ ${stage} == launcher-bootstrap ]] && ! bind_operation_image_ids; then
    status=1
  fi
  operation_process_absent || return 1
  (( status == 0 ))
}

run_capture() {
  local stage="$1" seconds="$2" blocks="$3" output="$4"
  shift 4
  local status=0
  [[ ! -e ${output} && ! -L ${output} ]] || return 1
  if [[ ${fixture_mode} == true ]]; then
    setsid env MOCHIRII_HISTORICAL_READER_OPERATION_ID="${operation_id}" \
      MOCHIRII_HISTORICAL_SCRATCH_ROOT="${scratch_root}" \
      python3 -B "${adapter}" "${stage}" -- "$@" >"${output}" 2>/dev/null &
  else
    setsid env MOCHIRII_HISTORICAL_READER_OPERATION_ID="${operation_id}" \
      timeout --signal=TERM --kill-after=30s "${seconds}" \
      bash -c 'ulimit -f "$1"; shift; exec "$@"' bash "${blocks}" "$@" >"${output}" 2>/dev/null &
  fi
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || status=$?
  active_bounded_pid=""
  operation_process_absent || return 1
  (( status == 0 ))
}

operation_armed=false
cleanup_complete=false
published=false
publishing=false

safe_remove_candidate() {
  local path="$1"
  [[ -e ${path} || -L ${path} ]] || return 0
  [[ -f ${path} && ! -L ${path} && "$(stat -c '%u:%g' -- "${path}")" == 0:0 ]] || return 1
  rm -f -- "${path}"
}

cleanup_operation() {
  local status=0 inventory line container_id container_label image_id operation_image_ids
  if [[ -n ${active_bounded_pid} ]]; then
    kill -TERM -- "-${active_bounded_pid}" >/dev/null 2>&1 || true
    sleep 1
    kill -KILL -- "-${active_bounded_pid}" >/dev/null 2>&1 || true
    wait "${active_bounded_pid}" >/dev/null 2>&1 || true
    active_bounded_pid=""
  fi
  terminate_operation_processes || status=1

  inventory="$(docker_inventory_by_label 2>/dev/null)" || status=1
  while IFS= read -r container_id; do
    [[ -z ${container_id} ]] && continue
    if [[ ${container_id} =~ ^[0-9a-f]{64}$ ]]; then
      external cleanup timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 "${container_id}" >/dev/null 2>&1 || true
      external cleanup timeout --signal=TERM --kill-after=5s 30 docker rm --force "${container_id}" >/dev/null 2>&1 || status=1
    else
      status=1
    fi
  done <<<"${inventory}"

  inventory="$(docker_inventory_by_name 2>/dev/null)" || status=1
  while IFS= read -r line; do
    [[ -z ${line} ]] && continue
    container_id="${line%% *}"
    container_label="${line#* }"
    if [[ ${container_id} =~ ^[0-9a-f]{64}$ && ${container_label} == "${operation_id}" ]]; then
      external cleanup timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 "${container_id}" >/dev/null 2>&1 || true
      external cleanup timeout --signal=TERM --kill-after=5s 30 docker rm --force "${container_id}" >/dev/null 2>&1 || status=1
    else
      status=1
    fi
  done <<<"${inventory}"

  bind_operation_image_ids || return 1
  operation_image_ids="$(transaction_operation_image_ids 2>/dev/null)" || return 1
  while IFS= read -r image_id; do
    [[ -z ${image_id} ]] && continue
    if [[ ${image_id} =~ ^sha256:[0-9a-f]{64}$ ]]; then
      local image_state=""
      # The immutable ID is durable before the tag can disappear.  A crash
      # after this untag is therefore reconciled by ID on exact retry.
      external cleanup timeout --signal=TERM --kill-after=5s 45 docker image rm "${image_name}" >/dev/null 2>&1 || true
      crash_point after-reader-image-untag
      if ! image_state="$(docker_image_id_state "${image_id}")"; then
        status=1
      elif [[ ${image_state} == present ]]; then
        if external cleanup timeout --signal=TERM --kill-after=5s 45 docker image rm --force "${image_id}" >/dev/null 2>&1; then
          crash_point after-reader-image-delete
        else
          status=1
        fi
      elif [[ ${image_state} != absent ]]; then
        status=1
      fi
      if ! image_state="$(docker_image_id_state "${image_id}")"; then
        status=1
      elif [[ ${image_state} != absent ]]; then
        status=1
      fi
    else
      status=1
    fi
  done <<<"${operation_image_ids}"

  terminate_operation_processes || status=1
  [[ -z "$(docker_inventory_by_label 2>/dev/null)" ]] || status=1
  [[ -z "$(docker_inventory_by_name 2>/dev/null)" ]] || status=1
  [[ -z "$(docker_image_inventory 2>/dev/null)" ]] || status=1
  [[ -z "$(docker_operation_image_inventory 2>/dev/null)" ]] || status=1
  inventory="$(docker_all_image_inventory 2>/dev/null)" || status=1
  while IFS= read -r image_id; do
    [[ -z ${image_id} ]] && continue
    [[ ${image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || status=1
    if grep -Fqx -- "${image_id}" <<<"${operation_image_ids}"; then
      status=1
    fi
  done <<<"${inventory}"
  operation_process_absent || status=1
  [[ ! -e ${real_shared} && ! -L ${real_shared} ]] || status=1

  if (( status == 0 )) && [[ ${operation_armed} == true && ( -e ${scratch_root} || -L ${scratch_root} ) ]]; then
    [[ -d ${scratch_root} && ! -L ${scratch_root} && "$(readlink -f -- "${scratch_root}")" == "${scratch_root}" ]] || status=1
    if (( status == 0 )); then
      rm -rf -- "${scratch_root}" || status=1
    fi
  fi
  [[ ! -e ${scratch_root} && ! -L ${scratch_root} ]] || status=1
  (( status == 0 ))
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ ${cleanup_complete} != true ]]; then
    cleanup_operation || status=1
  fi
  if (( status != 0 )); then
    printf '%s\n' "Historical recovery scratch reader failed closed; no fetched source was authorized." >&2
  fi
  exit "${status}"
}
trap on_exit EXIT
trap 'exit 1' HUP INT TERM

protected_regular "${host_control}" "Current host-control evidence" "${max_document_bytes}"
protected_regular "${reader_intent}" "Historical reader intent" "${max_document_bytes}"
protected_regular "${runtime_json}" "Protected Forums runtime JSON" 1048576
protected_regular "${source_archive}" "Sealed current-main Forums archive" "${max_archive_bytes}"
protected_regular "${deployment_archive}" "Sealed deployment-source archive" "${max_archive_bytes}"
protected_directory "${state_root}" "Forums state root" 755
protected_directory "${stage_root}" "Historical recovery staging root" 700
[[ ! -e ${real_shared} && ! -L ${real_shared} ]] || fail "Historical reader refuses an existing real persistent target."
install -d -m 0700 -o root -g root "${scratch_parent}"
protected_directory "${scratch_parent}" "Historical reader scratch parent" 700
preexisting_image_ids="$(docker_all_image_inventory)" || fail "Historical reader preexisting image inventory is unavailable."
readarray -t transaction_identity < <(load_or_create_transaction "${preexisting_image_ids}") || fail "Historical reader transaction authority is invalid."
[[ ${#transaction_identity[@]} -eq 6 ]] || fail "Historical reader transaction identity is incomplete."
transaction_phase="${transaction_identity[0]}"
transaction_receipt_sha="${transaction_identity[1]}"
transaction_receipt_bytes="${transaction_identity[2]}"
transaction_archive_sha="${transaction_identity[3]}"
transaction_archive_bytes="${transaction_identity[4]}"
transaction_sha="${transaction_identity[5]}"
operation_armed=true
cleanup_operation || fail "Historical reader retry reconciliation could not prove containment."

exact_file() {
  local path="$1" expected_sha="$2" expected_bytes="$3" maximum="$4" label="$5"
  protected_regular "${path}" "${label}" "${maximum}"
  [[ "$(stat -c '%s' -- "${path}")" == "${expected_bytes}" ]] || fail "${label} size differs from the reader transaction."
  [[ "$(sha256sum -- "${path}" | awk '{print $1}')" == "${expected_sha}" ]] || fail "${label} digest differs from the reader transaction."
}

require_absent() {
  local path="$1" label="$2"
  [[ ! -e ${path} && ! -L ${path} ]] || fail "${label} exists outside its transaction phase."
}

advance_transaction() {
  local expected="$1" next="$2" receipt_sha="$3" receipt_bytes="$4" archive_sha="$5" archive_bytes="$6" cleanup="$7"
  transaction_sha="$(transition_transaction "${expected}" "${next}" "${transaction_sha}" \
    "${receipt_sha}" "${receipt_bytes}" "${archive_sha}" "${archive_bytes}" "${cleanup}")" \
    || fail "Historical reader transaction transition failed."
  transaction_phase="${next}"
  transaction_receipt_sha="${receipt_sha}"
  transaction_receipt_bytes="${receipt_bytes}"
  transaction_archive_sha="${archive_sha}"
  transaction_archive_bytes="${archive_bytes}"
}

case "${transaction_phase}" in
  armed)
    require_absent "${receipt_output}" "Fetched receipt output"
    require_absent "${archive_output}" "Fetched archive output"
    safe_remove_candidate "${receipt_candidate}" || fail "Uncommitted receipt partial is unsafe."
    safe_remove_candidate "${archive_candidate}" || fail "Uncommitted archive partial is unsafe."
    ;;
  receipt-fetched)
    exact_file "${receipt_candidate}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Transaction-bound fetched receipt"
    require_absent "${receipt_output}" "Fetched receipt output"
    require_absent "${archive_output}" "Fetched archive output"
    safe_remove_candidate "${archive_candidate}" || fail "Uncommitted archive partial is unsafe."
    ;;
  archive-fetched)
    exact_file "${receipt_candidate}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Transaction-bound fetched receipt"
    exact_file "${archive_candidate}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Transaction-bound fetched archive"
    require_absent "${receipt_output}" "Fetched receipt output"
    require_absent "${archive_output}" "Fetched archive output"
    ;;
  cleanup-proved)
    if [[ -f ${receipt_candidate} && ! -L ${receipt_candidate} && -f ${archive_candidate} && ! -L ${archive_candidate} ]]; then
      exact_file "${receipt_candidate}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Transaction-bound fetched receipt"
      exact_file "${archive_candidate}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Transaction-bound fetched archive"
      require_absent "${receipt_output}" "Fetched receipt output"
      require_absent "${archive_output}" "Fetched archive output"
    elif [[ -f ${receipt_output} && ! -L ${receipt_output} && -f ${archive_candidate} && ! -L ${archive_candidate} ]]; then
      require_absent "${receipt_candidate}" "Fetched receipt candidate"
      require_absent "${archive_output}" "Fetched archive output"
      exact_file "${receipt_output}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Published fetched receipt"
      exact_file "${archive_candidate}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Transaction-bound fetched archive"
      advance_transaction cleanup-proved receipt-published "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
    elif [[ -f ${receipt_output} && ! -L ${receipt_output} && -f ${archive_output} && ! -L ${archive_output} ]]; then
      require_absent "${receipt_candidate}" "Fetched receipt candidate"
      require_absent "${archive_candidate}" "Fetched archive candidate"
      exact_file "${receipt_output}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Published fetched receipt"
      exact_file "${archive_output}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Published fetched archive"
      advance_transaction cleanup-proved receipt-published "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
      advance_transaction receipt-published outputs-published "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
    else
      fail "Cleanup-proved historical reader transaction has an incomplete output pair."
    fi
    cleanup_complete=true
    ;;
  receipt-published)
    require_absent "${receipt_candidate}" "Fetched receipt candidate"
    exact_file "${receipt_output}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Published fetched receipt"
    if [[ -f ${archive_candidate} && ! -L ${archive_candidate} ]]; then
      require_absent "${archive_output}" "Fetched archive output"
      exact_file "${archive_candidate}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Transaction-bound fetched archive"
    elif [[ -f ${archive_output} && ! -L ${archive_output} ]]; then
      require_absent "${archive_candidate}" "Fetched archive candidate"
      exact_file "${archive_output}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Published fetched archive"
      advance_transaction receipt-published outputs-published "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
    else
      fail "Receipt-published historical reader transaction lost its archive."
    fi
    cleanup_complete=true
    ;;
  outputs-published)
    require_absent "${receipt_candidate}" "Fetched receipt candidate"
    require_absent "${archive_candidate}" "Fetched archive candidate"
    exact_file "${receipt_output}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Published fetched receipt"
    exact_file "${archive_output}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Published fetched archive"
    cleanup_complete=true
    ;;
  *) fail "Historical reader transaction phase differs." ;;
esac

if [[ ${transaction_phase} == armed || ${transaction_phase} == receipt-fetched ]]; then
  install -d -m 0700 -o root -g root "${scratch_root}"

python3 -B - "${host_control}" "${reader_intent}" "${source_archive}" "${deployment_archive}" \
  "${bootstrap_commit}" "${operation_id}" "${scratch_root}" "${real_shared}" \
  "${deployment_revision}" "${deployment_tree}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import tarfile

(
    control_path,
    intent_path,
    source_archive,
    deployment_archive,
    commit,
    operation,
    scratch_root,
    real_shared,
    deployment_revision,
    deployment_tree,
) = (pathlib.Path(value) if index in {0, 1, 2, 3, 6, 7} else value for index, value in enumerate(sys.argv[1:]))
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 192 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_MEMBERS = 8192
CONTROL_KEYS = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceArchiveFile",
    "deploymentSourceRevision", "deploymentSourceTree", "deploymentSourceArchiveSha256",
    "deploymentSourceArchiveBytes", "deploymentSourceContentManifestSha256",
}
INTENT_KEYS = {
    "schemaVersion", "operation", "phase", "recordedAt", "bootstrapRepositoryCommit",
    "readerOperationId", "scratchRoot", "currentHostControlFile", "currentHostControlSha256",
    "realPersistentTarget", "realPersistentTargetInitiallyAbsent",
}

def abort(message):
    raise SystemExit(message)

def protected(path, maximum):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        abort("protected archive authority is non-regular")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        abort("protected archive authority permissions differ")
    if not 1 <= metadata.st_size <= maximum:
        abort("protected archive authority size differs")
    return path.read_bytes()

control_raw = protected(control_path, 65536)
intent_raw = protected(intent_path, 65536)
try:
    control = json.loads(control_raw)
    intent = json.loads(intent_raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    abort("historical reader authority is malformed")
if not isinstance(control, dict) or set(control) != CONTROL_KEYS:
    abort("current host-control schema differs")
if control.get("schemaVersion") != 1 or control.get("phase") != "hardened" or control.get("repositoryCommit") != commit:
    abort("current host-control release differs")
for key in (
    "repositoryTree", "manifestSha256", "targetSetSha256", "controlEvidenceSha256",
    "releaseArchiveSha256", "releaseArchiveContentManifestSha256",
    "deploymentSourceArchiveSha256", "deploymentSourceContentManifestSha256",
):
    if HEX64.fullmatch(str(control.get(key, ""))) is None and key != "repositoryTree":
        abort("current host-control digest is malformed")
if HEX40.fullmatch(str(control.get("repositoryTree", ""))) is None:
    abort("current host-control repository tree is malformed")
for key in ("releaseArchiveBytes", "deploymentSourceArchiveBytes"):
    value = control.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ARCHIVE:
        abort("current host-control archive size is malformed")
if control.get("releaseArchiveFile") != str(source_archive):
    abort("current host-control Forums archive path differs")
if control.get("deploymentSourceArchiveFile") != str(deployment_archive):
    abort("current host-control deployment archive path differs")
if control.get("deploymentSourceRevision") != deployment_revision or control.get("deploymentSourceTree") != deployment_tree:
    abort("current host-control deployment source differs")
if not isinstance(intent, dict) or set(intent) != INTENT_KEYS:
    abort("historical reader intent schema differs")
if (
    intent.get("schemaVersion") != 1
    or intent.get("operation") != "current-main-historical-recovery-reader"
    or intent.get("phase") != "reader-armed"
    or intent.get("bootstrapRepositoryCommit") != commit
    or intent.get("readerOperationId") != operation
    or intent.get("scratchRoot") != str(scratch_root)
    or intent.get("currentHostControlFile") != str(control_path)
    or intent.get("currentHostControlSha256") != hashlib.sha256(control_raw).hexdigest()
    or intent.get("realPersistentTarget") != str(real_shared)
    or intent.get("realPersistentTargetInitiallyAbsent") is not True
):
    abort("historical reader intent authority differs")
if real_shared.exists() or real_shared.is_symlink():
    abort("real persistent target appeared before scratch extraction")

class Node:
    def __init__(self):
        self.files = {}
        self.directories = {}

def git_object(kind, payload):
    return hashlib.sha1(kind + b" " + str(len(payload)).encode("ascii") + b"\0" + payload).digest()

def tree_digest(node):
    rows = []
    for name, (executable, blob) in node.files.items():
        encoded = name.encode("ascii")
        mode = b"100755" if executable else b"100644"
        rows.append((encoded + b"\0", mode + b" " + encoded + b"\0" + blob))
    for name, child in node.directories.items():
        encoded = name.encode("ascii")
        rows.append((encoded + b"/", b"40000 " + encoded + b"\0" + tree_digest(child)))
    return git_object(b"tree", b"".join(row for _key, row in sorted(rows, key=lambda item: item[0])))

def identities(files):
    root = Node()
    for path, payload, executable in files:
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            if part in node.files:
                abort("archive path conflicts with a file")
            node = node.directories.setdefault(part, Node())
        name = parts[-1]
        if name in node.files or name in node.directories:
            abort("archive path conflicts with another member")
        node.files[name] = (executable, git_object(b"blob", payload))
    manifest = hashlib.sha256()
    for path, payload, executable in sorted(files, key=lambda item: item[0].encode("ascii")):
        manifest.update(path.encode("ascii"))
        manifest.update(b"\0")
        manifest.update(str(len(payload)).encode("ascii"))
        manifest.update(b"\0")
        manifest.update(b"100755" if executable else b"100644")
        manifest.update(b"\0")
        manifest.update(hashlib.sha256(payload).hexdigest().encode("ascii"))
        manifest.update(b"\n")
    return tree_digest(root).hex(), manifest.hexdigest()

def inspect_extract(archive, destination, expected_commit, expected_tree, expected_sha, expected_size, expected_manifest, required):
    raw = protected(archive, MAX_ARCHIVE)
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha:
        abort("sealed archive bytes differ from host-control authority")
    files = []
    directories = set()
    seen = set()
    expanded = 0
    with tarfile.open(archive, mode="r:") as source:
        if set(source.pax_headers) != {"comment"} or source.pax_headers.get("comment") != expected_commit:
            abort("sealed archive commit authority differs")
        members = source.getmembers()
        if not 1 <= len(members) <= MAX_MEMBERS:
            abort("sealed archive member count differs")
        for member in members:
            raw_name = member.name
            if not raw_name or not raw_name.isascii() or raw_name.startswith("/") or "\\" in raw_name:
                abort("sealed archive member path is unsafe")
            if any(ord(character) < 32 or ord(character) == 127 for character in raw_name):
                abort("sealed archive member path contains a control byte")
            normalized = raw_name.rstrip("/")
            parts = pathlib.PurePosixPath(normalized).parts
            if not parts or any(part in {"", ".", ".."} or ":" in part for part in parts):
                abort("sealed archive path component is unsafe")
            normalized = "/".join(parts)
            if normalized in seen:
                abort("sealed archive contains a duplicate member")
            seen.add(normalized)
            if member.isdir():
                if member.mode & ~0o777 or member.mode & 0o002:
                    abort("sealed archive directory mode is unsafe")
                directories.add(normalized)
                continue
            # `git archive --format=tar` represents tracked non-executable and
            # executable files as 0664 and 0775 respectively.  Some tar
            # producers normalize away the group-write bit, so accept exactly
            # those two Git mode families and normalize them back to the Git
            # tree's 100644/100755 identity.  Special or world-writable modes
            # remain outside the sealed-source boundary.
            if not member.isfile() or member.mode not in {0o644, 0o664, 0o755, 0o775}:
                abort("sealed archive member type or mode is unsafe")
            if not 0 <= member.size <= MAX_MEMBER:
                abort("sealed archive member size differs")
            expanded += member.size
            if expanded > MAX_EXPANDED:
                abort("sealed archive expansion exceeds its bound")
            stream = source.extractfile(member)
            if stream is None:
                abort("sealed archive member bytes are unavailable")
            payload = stream.read(MAX_MEMBER + 1)
            if len(payload) != member.size:
                abort("sealed archive member bytes differ from its header")
            files.append((normalized, payload, bool(member.mode & 0o111)))
    paths = {entry[0] for entry in files}
    if not required.issubset(paths):
        abort("sealed archive lacks required recovery source")
    tree, manifest = identities(files)
    if tree != expected_tree or manifest != expected_manifest:
        abort("sealed archive tree or manifest differs from host-control authority")
    if destination.exists() or destination.is_symlink():
        abort("scratch extraction target already exists")
    destination.mkdir(mode=0o700)
    for directory in sorted(directories, key=lambda value: (value.count("/"), value.encode("ascii"))):
        target = destination.joinpath(*directory.split("/"))
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(0o755)
    for path, payload, executable in files:
        target = destination.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        target.chmod(0o755 if executable else 0o644)
    for directory in sorted((item for item in destination.rglob("*") if item.is_dir()), key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o755)
    destination.chmod(0o700)

source_required = {
    "AGENTS.md", "config/app.yml.example", "scripts/render-app-config.py",
    "scripts/build-theme-archive.py", "scripts/configure-site.rb",
    "scripts/fetch-disaster-recovery-evidence.rb", "scripts/fetch-disaster-recovery-release.rb",
    "plugins/mochirii_email_metadata/plugin.rb",
}
deployment_required = {"launcher", "templates/web.template.yml", "templates/postgres.template.yml", "templates/redis.template.yml"}
inspect_extract(
    source_archive, scratch_root / "source", commit, control["repositoryTree"],
    control["releaseArchiveSha256"], control["releaseArchiveBytes"],
    control["releaseArchiveContentManifestSha256"], source_required,
)
inspect_extract(
    deployment_archive, scratch_root / "discourse", deployment_revision, deployment_tree,
    control["deploymentSourceArchiveSha256"], control["deploymentSourceArchiveBytes"],
    control["deploymentSourceContentManifestSha256"], deployment_required,
)
if real_shared.exists() or real_shared.is_symlink():
    abort("real persistent target appeared during scratch extraction")
PY

readonly source_root="${scratch_root}/source"
readonly discourse_root="${scratch_root}/discourse"
readonly assets_root="${scratch_root}/runtime-assets"
readonly scratch_shared="${scratch_root}/shared/standalone"
readonly config_path="${discourse_root}/containers/${app_name}.yml"
readonly raw_config="${scratch_root}/rendered-restore.yml"
install -d -m 0700 -o root -g root "${assets_root}" "${scratch_shared}/log/var-log" "${discourse_root}/containers" "${discourse_root}/cids"
install -m 0644 -o root -g root "${source_root}/plugins/mochirii_email_metadata/plugin.rb" "${assets_root}/mochirii-email-metadata-plugin.rb"
for script_name in configure-site.rb fetch-disaster-recovery-evidence.rb fetch-disaster-recovery-release.rb; do
  install -m 0644 -o root -g root "${source_root}/scripts/${script_name}" "${assets_root}/${script_name}"
done
python3 -B "${source_root}/scripts/build-theme-archive.py" --output "${assets_root}/mochirii-theme.zip" >/dev/null 2>&1 || fail "Scratch theme asset construction failed."
python3 -B "${source_root}/scripts/render-app-config.py" --mode disposable-restore \
  --runtime-json "${runtime_json}" --repository-commit "${bootstrap_commit}" --output "${raw_config}" \
  >/dev/null 2>&1 || fail "Scratch recovery configuration rendering failed."

python3 -B - "${raw_config}" "${config_path}" "${bootstrap_commit}" "${scratch_shared}" "${assets_root}" "${real_shared}" <<'PY'
import os
import pathlib
import stat
import sys

source, output = map(pathlib.Path, sys.argv[1:3])
commit, shared, assets, real_shared = sys.argv[3:]
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 1024 * 1024:
    raise SystemExit("raw scratch configuration is unsafe")
text = source.read_text(encoding="utf-8")
replacements = {
    'expose:\n  - "127.0.0.1:18080:80"\n\nparams:': 'expose: []\n\nparams:',
    '      host: /var/discourse/shared/standalone\n      guest: /shared': f'      host: {shared}\n      guest: /shared',
    '      host: /var/discourse/shared/standalone/log/var-log\n      guest: /var/log': f'      host: {shared}/log/var-log\n      guest: /var/log',
    f'      host: /opt/mochirii/forums/runtime-assets/{commit}\n      guest: /opt/mochirii-release:ro': f'      host: {assets}\n      guest: /opt/mochirii-release:ro',
}
for old, new in replacements.items():
    if text.count(old) != 1:
        raise SystemExit("scratch configuration isolation source differs")
    text = text.replace(old, new)
for forbidden in (real_shared, "/var/discourse/shared/standalone", "/opt/mochirii/forums/runtime-assets/", ' - "80:80"', ' - "443:443"', "127.0.0.1:18080:80"):
    if forbidden in text:
        raise SystemExit("scratch configuration retained a production mount or listener")
if text.count(f"      host: {shared}\n") != 1 or text.count(f"      host: {shared}/log/var-log\n") != 1 or text.count(f"      host: {assets}\n") != 1:
    raise SystemExit("scratch configuration mount inventory differs")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(output, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    target.write(text)
    target.flush()
    os.fsync(target.fileno())
PY
rm -f -- "${raw_config}"
[[ ! -e ${real_shared} && ! -L ${real_shared} ]] || fail "Real persistent target appeared before scratch bootstrap."

readonly docker_args="--label=mochirii.forums.historical-reader=${operation_id} --cpuset-cpus=0 --memory=2g --memory-swap=4g"
launcher_command=(bash -c 'cd -- "$1" && exec ./launcher "$2" "$3" --skip-prereqs --docker-args "$4"' bash "${discourse_root}" bootstrap "${app_name}" "${docker_args}")
run_quiet launcher-bootstrap 2400 "${launcher_command[@]}" || fail "Scratch Discourse bootstrap failed or exceeded its bound."
[[ ! -e ${real_shared} && ! -L ${real_shared} ]] || fail "Real persistent target appeared during scratch bootstrap."
launcher_command=(bash -c 'cd -- "$1" && exec ./launcher "$2" "$3" --skip-prereqs --docker-args "$4"' bash "${discourse_root}" start "${app_name}" "${docker_args}")
run_quiet launcher-start 300 "${launcher_command[@]}" || fail "Scratch Discourse start failed or exceeded its bound."

mounts_file="${scratch_root}/mounts.json"
ports_file="${scratch_root}/ports.json"
label_file="${scratch_root}/label.txt"
running_file="${scratch_root}/running.txt"
run_capture inspect-mounts 30 128 "${mounts_file}" timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{json .Mounts}}' "${app_name}" || fail "Scratch container mount inspection failed."
run_capture inspect-ports 30 128 "${ports_file}" timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{json .HostConfig.PortBindings}}' "${app_name}" || fail "Scratch container port inspection failed."
run_capture inspect-label 30 128 "${label_file}" timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{index .Config.Labels "mochirii.forums.historical-reader"}}' "${app_name}" || fail "Scratch container label inspection failed."
run_capture inspect-running 30 128 "${running_file}" timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' "${app_name}" || fail "Scratch container state inspection failed."
python3 -B - "${mounts_file}" "${ports_file}" "${label_file}" "${running_file}" "${scratch_shared}" "${assets_root}" "${operation_id}" "${real_shared}" <<'PY'
import json
import pathlib
import sys

mounts_file, ports_file, label_file, running_file = map(pathlib.Path, sys.argv[1:5])
shared, assets, operation, real_shared = sys.argv[5:]
mounts = json.loads(mounts_file.read_text(encoding="utf-8"))
ports = json.loads(ports_file.read_text(encoding="utf-8"))
expected = {
    (shared, "/shared", False),
    (f"{shared}/log/var-log", "/var/log", False),
    (assets, "/opt/mochirii-release", True),
}
actual = set()
if not isinstance(mounts, list) or len(mounts) != 3:
    raise SystemExit("scratch container mount count differs")
for mount in mounts:
    if not isinstance(mount, dict):
        raise SystemExit("scratch container mount is malformed")
    source = mount.get("Source")
    destination = mount.get("Destination")
    readonly = not bool(mount.get("RW"))
    if mount.get("Type") != "bind" or not isinstance(source, str) or real_shared in source or "/var/discourse/shared/standalone" in source:
        raise SystemExit("scratch container retained a forbidden mount")
    actual.add((source, destination, readonly))
if actual != expected:
    raise SystemExit("scratch container mount identity differs")
if ports not in ({}, None):
    raise SystemExit("scratch container unexpectedly publishes a port")
if label_file.read_text(encoding="utf-8").strip() != operation:
    raise SystemExit("scratch container operation label differs")
if running_file.read_text(encoding="utf-8").strip() != "true":
    raise SystemExit("scratch container is not running")
PY
fi

if [[ ${transaction_phase} == armed ]]; then
  fetch_evidence_command=(docker exec -i \
    -e "MOCHIRII_HISTORICAL_READER_OPERATION_ID=${operation_id}" \
    -e MOCHIRII_DR_FETCH_MODE=clean-target-historical \
    -e "MOCHIRII_DR_BOOTSTRAP_COMMIT=${bootstrap_commit}" \
    "${app_name}" timeout --signal=TERM --kill-after=10s 150 bash -lc \
    '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/fetch-disaster-recovery-evidence.rb"')
  run_capture fetch-evidence 180 128 "${receipt_candidate}" "${fetch_evidence_command[@]}" || fail "Historical recovery evidence fetch failed or exceeded its bound."
  protected_regular "${receipt_candidate}" "Fetched historical recovery receipt" "${max_document_bytes}"
fi

if [[ ${transaction_phase} == armed || ${transaction_phase} == receipt-fetched ]]; then
  readarray -t receipt_identity < <(python3 -B - "${receipt_candidate}" "${bootstrap_commit}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
bootstrap = sys.argv[2]
raw = path.read_bytes()
try:
    document = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("historical recovery receipt is malformed")
required = {
    "schemaVersion", "repositoryCommit", "productionConfigurationSha256",
    "disasterRecoveryImported", "disasterRecoveryFetchMode", "disasterRecoveryBootstrapCommit",
    "disasterRecoveryReleaseArchiveSha256", "disasterRecoveryReleaseArchiveBytes",
    "disasterRecoveryReleaseArchiveContentManifestSha256",
    "disasterRecoveryReleaseSourceAuthoritySha256",
    "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain",
    "disasterRecoveryHistoricalReleaseAdoptionScope", "disasterRecoveryPrivateAclPassed",
}
if not isinstance(document, dict) or not required.issubset(document):
    raise SystemExit("historical recovery receipt lacks its authority")
c0 = document.get("repositoryCommit")
archive_sha = document.get("disasterRecoveryReleaseArchiveSha256")
archive_bytes = document.get("disasterRecoveryReleaseArchiveBytes")
if (
    document.get("schemaVersion") != 3
    or re.fullmatch(r"[0-9a-f]{40}", str(c0)) is None
    or c0 == bootstrap
    or re.fullmatch(r"[0-9a-f]{64}", str(document.get("productionConfigurationSha256", ""))) is None
    or document.get("disasterRecoveryImported") is not True
    or document.get("disasterRecoveryFetchMode") != "clean-target-historical"
    or document.get("disasterRecoveryBootstrapCommit") != bootstrap
    or re.fullmatch(r"[0-9a-f]{64}", str(archive_sha)) is None
    or not isinstance(archive_bytes, int) or isinstance(archive_bytes, bool) or not 1 <= archive_bytes <= 67108864
    or re.fullmatch(r"[0-9a-f]{64}", str(document.get("disasterRecoveryReleaseArchiveContentManifestSha256", ""))) is None
    or re.fullmatch(r"[0-9a-f]{64}", str(document.get("disasterRecoveryReleaseSourceAuthoritySha256", ""))) is None
    or document.get("disasterRecoveryOrdinaryDeploymentRequiresCurrentMain") is not True
    or document.get("disasterRecoveryHistoricalReleaseAdoptionScope") != "clean-target-disaster-recovery-only"
    or document.get("disasterRecoveryPrivateAclPassed") is not True
):
    raise SystemExit("historical recovery receipt authority differs")
print(archive_sha)
print(archive_bytes)
print(hashlib.sha256(raw).hexdigest())
print(len(raw))
PY
) || fail "Fetched historical recovery receipt validation failed."
  [[ ${#receipt_identity[@]} -eq 4 ]] || fail "Fetched historical recovery receipt identity is incomplete."
  fetched_archive_sha="${receipt_identity[0]}"
  fetched_archive_bytes="${receipt_identity[1]}"
  fetched_receipt_sha="${receipt_identity[2]}"
  fetched_receipt_bytes="${receipt_identity[3]}"
  if [[ ${transaction_phase} == armed ]]; then
    advance_transaction armed receipt-fetched "${fetched_receipt_sha}" "${fetched_receipt_bytes}" - - false
    crash_point after-receipt-fetch
  else
    [[ ${fetched_receipt_sha} == "${transaction_receipt_sha}" && ${fetched_receipt_bytes} == "${transaction_receipt_bytes}" ]] || fail "Fetched receipt changed after its durable transition."
  fi
  receipt_base64="$(base64 -w 0 -- "${receipt_candidate}")" || fail "Historical recovery receipt encoding failed."
  (( ${#receipt_base64} <= 131072 )) || fail "Historical recovery receipt encoding exceeds its bound."

  fetch_release_command=(docker exec -i \
    -e "MOCHIRII_HISTORICAL_READER_OPERATION_ID=${operation_id}" \
    -e "MOCHIRII_DR_FETCH_RECEIPT_BASE64=${receipt_base64}" \
    "${app_name}" timeout --signal=TERM --kill-after=10s 180 bash -lc \
    '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/fetch-disaster-recovery-release.rb"')
  run_capture fetch-release 210 131072 "${archive_candidate}" "${fetch_release_command[@]}" || fail "Historical release archive fetch failed or exceeded its bound."
  protected_regular "${archive_candidate}" "Fetched historical release archive" "${max_archive_bytes}"
  [[ "$(stat -c '%s' -- "${archive_candidate}")" == "${fetched_archive_bytes}" ]] || fail "Fetched historical release archive size differs."
  [[ "$(sha256sum -- "${archive_candidate}" | awk '{print $1}')" == "${fetched_archive_sha}" ]] || fail "Fetched historical release archive digest differs."
  [[ ! -e ${real_shared} && ! -L ${real_shared} ]] || fail "Real persistent target appeared during historical source fetch."
  advance_transaction receipt-fetched archive-fetched "${fetched_receipt_sha}" "${fetched_receipt_bytes}" "${fetched_archive_sha}" "${fetched_archive_bytes}" false
  crash_point after-archive-fetch
fi

if [[ ${transaction_phase} == archive-fetched ]]; then
  cleanup_operation || fail "Historical reader cleanup or absence proof failed."
  cleanup_complete=true
  [[ ! -e ${real_shared} && ! -L ${real_shared} ]] || fail "Real persistent target appeared after historical reader cleanup."
  exact_file "${receipt_candidate}" "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${max_document_bytes}" "Transaction-bound fetched receipt"
  exact_file "${archive_candidate}" "${transaction_archive_sha}" "${transaction_archive_bytes}" "${max_archive_bytes}" "Transaction-bound fetched archive"
  advance_transaction archive-fetched cleanup-proved "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
  crash_point after-cleanup-proof
fi

if [[ ${transaction_phase} == cleanup-proved ]]; then
  publishing=true
  mv -- "${receipt_candidate}" "${receipt_output}"
  python3 -B - "${stage_root}" <<'PY'
import os
import pathlib
import sys
descriptor = os.open(pathlib.Path(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  crash_point after-first-rename
  failure_point after-first-rename
  advance_transaction cleanup-proved receipt-published "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
fi

if [[ ${transaction_phase} == receipt-published ]]; then
  mv -- "${archive_candidate}" "${archive_output}"
  python3 -B - "${stage_root}" <<'PY'
import os
import pathlib
import sys
descriptor = os.open(pathlib.Path(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  crash_point after-second-rename
  failure_point after-second-rename
  advance_transaction receipt-published outputs-published "${transaction_receipt_sha}" "${transaction_receipt_bytes}" "${transaction_archive_sha}" "${transaction_archive_bytes}" true
fi

[[ ${transaction_phase} == outputs-published ]] || fail "Historical reader did not reach its terminal publication phase."
python3 -B - "${stage_root}" "${receipt_output}" "${archive_output}" "${transaction_receipt_sha}" "${transaction_archive_sha}" "${transaction_archive_bytes}" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

directory, receipt, archive = map(pathlib.Path, sys.argv[1:4])
receipt_sha, archive_sha, archive_bytes = sys.argv[4], sys.argv[5], int(sys.argv[6])
for path, expected_sha, maximum in ((receipt, receipt_sha, 65536), (archive, archive_sha, 67108864)):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("published historical reader output permissions differ")
    if not 1 <= metadata.st_size <= maximum or hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
        raise SystemExit("published historical reader output identity differs")
if archive.stat().st_size != archive_bytes:
    raise SystemExit("published historical archive size differs")
descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
published=true
printf '%s\n' "Historical recovery receipt and exact prior-release source were fetched through an isolated current-main reader; terminal transaction awaits controller readback."
