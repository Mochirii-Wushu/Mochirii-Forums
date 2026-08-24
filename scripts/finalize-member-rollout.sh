#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Member-rollout finalization must run as root."
[[ $# -eq 2 ]] || fail "Usage: finalize-member-rollout.sh COMMIT 'FINALIZE MOCHIRII FORUMS MEMBER ROLLOUT'"
commit="$1"
confirmation="$2"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Release commit is malformed."
[[ ${confirmation} == "FINALIZE MOCHIRII FORUMS MEMBER ROLLOUT" ]] || fail "Exact member-rollout confirmation is required."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if python3 -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
state_root="/var/lib/mochirii/forums"
evidence_root="${state_root}/evidence"
marker="${state_root}/member-rollout-enabled"
current_evidence="${state_root}/current-release.json"
restore_terminal="${state_root}/current-restore.json"
[[ ! -e ${state_root}/deployment-transaction.json && ! -L ${state_root}/deployment-transaction.json ]] || fail "Member rollout refuses an active deployment transaction."
[[ ! -e ${state_root}/deployment-mutation.json && ! -L ${state_root}/deployment-mutation.json ]] || fail "Member rollout refuses an active deployment mutation."
[[ ! -e ${state_root}/restore-transaction.json && ! -L ${state_root}/restore-transaction.json ]] || fail "Member rollout refuses an active nonterminal restore transaction."
[[ ! -e ${state_root}/backup-transaction.json && ! -L ${state_root}/backup-transaction.json ]] || fail "Member rollout refuses an unresolved backup transaction."
[[ -z "$(find "${evidence_root}" -maxdepth 1 \( -name '*-backup-upload-cleanup-required.json' -o -name '*-storage-cleanup-required.json' \) -print -quit 2>/dev/null || true)" ]] || fail "Member rollout refuses an unresolved storage cleanup transaction."
[[ -f ${current_evidence} && ! -L ${current_evidence} ]] || fail "Current release evidence is absent."
[[ "$(stat -c '%U:%G %a' "${current_evidence}")" == "root:root 600" ]] || fail "Current release evidence has unsafe ownership or mode."
[[ -f ${restore_terminal} && ! -L ${restore_terminal} ]] || fail "Completed restore state is absent."
[[ "$(stat -c '%U:%G %a' "${restore_terminal}")" == "root:root 600" ]] || fail "Completed restore state has unsafe ownership or mode."

readarray -t current_contract < <(python3 - "${current_evidence}" "${evidence_root}" "${commit}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "repositoryCommit",
    "productionConfigurationSha256",
    "releaseEvidenceFile",
    "releaseEvidenceSha256",
    "discourseConnectEnabled",
    "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
if set(document) != required:
    raise SystemExit("current evidence keys differ")
if document.get("repositoryCommit") != sys.argv[3]:
    raise SystemExit("current release differs")
configuration = document.get("productionConfigurationSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", configuration):
    raise SystemExit("configuration digest is malformed")
expected = f"{sys.argv[3]}-{configuration}-release.json"
record = root / expected
if document.get("releaseEvidenceFile") != expected or not record.is_file() or record.is_symlink():
    raise SystemExit("release evidence reference differs")
if record.stat().st_uid != 0 or record.stat().st_mode & 0o077:
    raise SystemExit("release evidence permissions are unsafe")
record_sha = hashlib.sha256(record.read_bytes()).hexdigest()
if document.get("releaseEvidenceSha256") != record_sha:
    raise SystemExit("release evidence digest differs")
if document.get("discourseConnectEnabled") is not False:
    raise SystemExit("central login must remain disabled until finalization")
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if (marker_file is None) != (marker_sha is None):
    raise SystemExit("member-rollout evidence is incomplete")
if marker_file is not None and (
    marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)
):
    raise SystemExit("member-rollout evidence is malformed")
print(configuration)
print(expected)
print(record_sha)
print(marker_file or "-")
print(marker_sha or "-")
PY
)
[[ ${#current_contract[@]} -eq 5 ]] || fail "Current release evidence is malformed."
configuration="${current_contract[0]}"
release_record_name="${current_contract[1]}"
release_record_sha="${current_contract[2]}"
current_marker_file="${current_contract[3]}"
current_marker_sha="${current_contract[4]}"
[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "/var/discourse/containers/releases/${commit}/${configuration}/app.yml" ]] || fail "Production configuration is not active."
timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = false' >/dev/null 2>&1 || fail "Central login must remain disabled until after finalization."

readarray -t restore_contract < <(python3 - "${evidence_root}" "${restore_terminal}" "${commit}" "${configuration}" <<'PY'
import base64
import hashlib
import json
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
terminal_path = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
configuration = sys.argv[4]

def regular_root_file(path, maximum=262_144):
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise SystemExit(f"unsafe protected evidence file: {path.name}")
    return path.read_bytes()

root_metadata = root.lstat()
if (
    not stat.S_ISDIR(root_metadata.st_mode)
    or stat.S_ISLNK(root_metadata.st_mode)
    or root_metadata.st_uid != 0
    or root_metadata.st_gid != 0
    or stat.S_IMODE(root_metadata.st_mode) != 0o700
):
    raise SystemExit("restore evidence directory is unsafe")
terminal_bytes = regular_root_file(terminal_path, 65_536)
terminal = json.loads(terminal_bytes)
terminal_keys = {
    "schemaVersion", "phase", "restoreMode", "repositoryCommit", "productionConfigurationSha256",
    "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "cleanBackupEvidenceFile",
    "cleanBackupEvidenceSha256", "cleanBackupFilename", "cleanBackupSha256",
    "restoreEvidenceFile", "restoreEvidenceSha256",
}
if set(terminal) != terminal_keys or terminal.get("schemaVersion") != 1 or terminal.get("phase") != "complete":
    raise SystemExit("completed restore state schema differs")
if terminal.get("restoreMode") != "disposable-rehearsal":
    raise SystemExit("member rollout requires the disposable restore rehearsal")
if terminal.get("repositoryCommit") != commit or terminal.get("productionConfigurationSha256") != configuration:
    raise SystemExit("completed restore state tuple differs")

def bound_evidence(field, digest_field, suffix):
    value = terminal.get(field)
    digest = terminal.get(digest_field)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise SystemExit(f"{field} binding is malformed")
    candidate = pathlib.Path(value)
    if not candidate.is_absolute() or candidate.parent != root:
        raise SystemExit(f"{field} escapes the evidence directory")
    if not re.fullmatch(rf"{commit}-{configuration}-[0-9]{{8}}T[0-9]{{6}}Z-{suffix}[.]json", candidate.name):
        raise SystemExit(f"{field} filename differs")
    payload = regular_root_file(candidate)
    if hashlib.sha256(payload).hexdigest() != digest:
        raise SystemExit(f"{field} digest differs")
    return candidate, payload, json.loads(payload)

tested_path, tested_bytes, tested = bound_evidence("testedBackupEvidenceFile", "testedBackupEvidenceSha256", "backup")
clean_path, clean_bytes, clean = bound_evidence("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256", "backup")
record, record_bytes, document = bound_evidence("restoreEvidenceFile", "restoreEvidenceSha256", "restore")

if terminal.get("cleanBackupFilename") != clean.get("filename") or terminal.get("cleanBackupSha256") != clean.get("sha256"):
    raise SystemExit("completed restore clean-backup identity differs")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", str(terminal.get("cleanBackupFilename"))) or ".." in terminal["cleanBackupFilename"]:
    raise SystemExit("completed restore clean-backup filename is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(terminal.get("cleanBackupSha256"))):
    raise SystemExit("completed restore clean-backup digest is malformed")

if tested.get("schemaVersion") != 3 or tested.get("repositoryCommit") != commit or tested.get("productionConfigurationSha256") != configuration:
    raise SystemExit("tested backup release tuple differs")
if tested.get("anonymousRetrievalDenied") is not True or tested.get("anonymousCdnRetrievalDenied") is not True:
    raise SystemExit("tested backup anonymous retrieval denial is incomplete")
if tested.get("privateAdminRetrievalUrlPresent") is not True or tested.get("backupPrefix") != "backups/":
    raise SystemExit("tested backup protected retrieval contract differs")
if tested.get("recoveryUploadIncluded") is not True or tested.get("recoveryUploadDeletedAfterBackup") is not True:
    raise SystemExit("tested backup lacks the deleted recovery-upload fixture")
state = tested.get("recoveryUploadState")
state_keys = {
    "schemaVersion", "repositoryCommit", "uploadId", "uploadSha1", "originalFilename",
    "objectPath", "tombstonePath", "contentSha256", "publicUrlSha256",
}
if not isinstance(state, dict) or set(state) != state_keys or state.get("schemaVersion") != 1 or state.get("repositoryCommit") != commit:
    raise SystemExit("tested recovery-upload state schema differs")
if type(state.get("uploadId")) is not int or state["uploadId"] <= 0:
    raise SystemExit("tested recovery-upload identifier is malformed")
marker_base = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==", validate=True)
marker_comment = f"mochirii-recovery-{commit}".encode("ascii")
marker_bytes = marker_base[:-1] + b"!\xfe" + bytes([len(marker_comment)]) + marker_comment + b"\x00;"
expected_sha1 = hashlib.sha1(marker_bytes).hexdigest()
if state.get("uploadSha1") != expected_sha1 or state.get("contentSha256") != hashlib.sha256(marker_bytes).hexdigest():
    raise SystemExit("tested recovery-upload content identity differs")
if state.get("originalFilename") != f"mochirii-recovery-{commit[:12]}.gif":
    raise SystemExit("tested recovery-upload filename differs")
object_path = state.get("objectPath", "")
if not re.fullmatch(rf"original/[1-9][0-9]*X/(?:[0-9a-f]/)*{expected_sha1}[.]gif", object_path):
    raise SystemExit("tested recovery-upload object path differs")
if state.get("tombstonePath") != f"tombstone/{object_path}" or not re.fullmatch(r"[0-9a-f]{64}", str(state.get("publicUrlSha256"))):
    raise SystemExit("tested recovery-upload private identity differs")
state_bytes = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
state_sha = hashlib.sha256(state_bytes).hexdigest()
if tested.get("recoveryUploadStateSha256") != state_sha:
    raise SystemExit("tested recovery-upload state digest differs")
tested_inventory_count = tested.get("normalUploadInventoryCount")
tested_inventory_sha = tested.get("normalUploadInventorySha256")
if type(tested_inventory_count) is not int or not 0 <= tested_inventory_count <= 10_000:
    raise SystemExit("tested normal-upload inventory count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(tested_inventory_sha)):
    raise SystemExit("tested normal-upload inventory digest is malformed")

required = {
    "schemaVersion": 3,
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "anonymousBackupRetrievalDenied": True,
    "anonymousBackupCdnRetrievalDenied": True,
    "outboundMailSuppressed": True,
    "allMailDisabledDuringRestore": True,
    "databaseIntegrityPassed": True,
    "normalUploadRestorePassed": True,
    "recoveryUploadCleanupPassed": True,
    "finalCleanBackupMarkerAbsent": True,
    "sidekiqJobProcessingPassed": True,
    "restartPassed": True,
    "rebuildPassed": True,
    "productionVerificationPassed": True,
}
if any(document.get(key) != value for key, value in required.items()):
    raise SystemExit("restore evidence is incomplete")
if document.get("recoveryUploadIncluded") is not True or document.get("recoveryUploadStateSha256") != state_sha:
    raise SystemExit("restore evidence does not bind the tested recovery upload")
if document.get("testedNormalUploadInventoryCount") != tested_inventory_count or document.get("testedNormalUploadInventorySha256") != tested_inventory_sha:
    raise SystemExit("restore evidence does not bind the tested normal-upload inventory")
if document.get("cleanTargetDisasterRestore") is not False:
    raise SystemExit("member rollout requires a disposable restore rehearsal")
if document.get("memberRolloutMarkerFile") is not None or document.get("memberRolloutMarkerSha256") is not None:
    raise SystemExit("restore evidence unexpectedly contains a preexisting member marker")
if document.get("backupFilename") != tested.get("filename") or document.get("backupSha256") != tested.get("sha256"):
    raise SystemExit("restore evidence tested-backup identity differs")
if document.get("finalCleanBackupEvidenceFile") != clean_path.name or document.get("finalCleanBackupEvidenceSha256") != hashlib.sha256(clean_bytes).hexdigest():
    raise SystemExit("restore evidence final-clean evidence binding differs")
if document.get("finalCleanBackupFilename") != clean.get("filename") or document.get("finalCleanBackupSha256") != clean.get("sha256"):
    raise SystemExit("restore evidence final-clean object identity differs")
if clean.get("schemaVersion") != 3 or clean.get("repositoryCommit") != commit or clean.get("productionConfigurationSha256") != configuration:
    raise SystemExit("final clean backup release tuple differs")
if clean.get("finalCleanAfterRestore") is not True or clean.get("recoveryUploadIncluded") is not False or clean.get("recoveryUploadState") is not None:
    raise SystemExit("final clean backup evidence retains the recovery fixture")
if clean.get("recoveryUploadStateSha256") is not None or clean.get("recoveryUploadDeletedAfterBackup") is not False:
    raise SystemExit("final clean backup retains recovery-upload cleanup state")
if clean.get("memberRolloutMarkerFile") is not None or clean.get("memberRolloutMarkerSha256") is not None or clean.get("discourseConnectEnabled") is not False:
    raise SystemExit("final clean backup activation state differs")
if clean.get("anonymousRetrievalDenied") is not True or clean.get("anonymousCdnRetrievalDenied") is not True:
    raise SystemExit("final clean backup anonymous retrieval denial is incomplete")
inventory_count = clean.get("normalUploadInventoryCount")
inventory_sha = clean.get("normalUploadInventorySha256")
if type(inventory_count) is not int or not 0 <= inventory_count <= 10_000 or not re.fullmatch(r"[0-9a-f]{64}", str(inventory_sha)):
    raise SystemExit("final clean backup normal-upload inventory is malformed")
if document.get("finalCleanNormalUploadInventoryCount") != inventory_count or document.get("finalCleanNormalUploadInventorySha256") != inventory_sha:
    raise SystemExit("restore evidence final-clean normal-upload inventory differs")
if not all(clean.get(key) is True for key in (
    "disasterRecoveryEvidencePublished", "disasterRecoveryPointerSelected", "disasterRecoveryPrivateAclPassed",
    "disasterRecoveryReleaseArchivePublished", "disasterRecoveryReleaseSourceAuthorityPublished",
    "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain",
)):
    raise SystemExit("final clean disaster-recovery publication is incomplete")
dr_evidence_sha = clean.get("disasterRecoveryEvidenceObjectSha256")
if not re.fullmatch(r"[0-9a-f]{64}", str(dr_evidence_sha)) or clean.get("disasterRecoveryEvidenceObjectKey") != f"backups/recovery-evidence/records/{dr_evidence_sha}.json":
    raise SystemExit("final clean disaster-recovery evidence identity is malformed")
if clean.get("disasterRecoveryPointerObjectKey") != "backups/recovery-evidence/current.json" or not re.fullmatch(r"[0-9a-f]{64}", str(clean.get("disasterRecoveryPointerObjectSha256"))):
    raise SystemExit("final clean disaster-recovery pointer identity is malformed")
archive_sha = clean.get("disasterRecoveryReleaseArchiveSha256")
authority_sha = clean.get("disasterRecoveryReleaseSourceAuthoritySha256")
if (
    not re.fullmatch(r"[0-9a-f]{40}", str(clean.get("disasterRecoveryRepositoryTree", "")))
    or not re.fullmatch(r"[0-9a-f]{64}", str(archive_sha))
    or clean.get("disasterRecoveryReleaseArchiveObjectKey") != f"backups/recovery-releases/archives/{archive_sha}.tar"
    or type(clean.get("disasterRecoveryReleaseArchiveBytes")) is not int
    or not 1 <= clean["disasterRecoveryReleaseArchiveBytes"] <= 64 * 1024 * 1024
    or not re.fullmatch(r"[0-9a-f]{64}", str(clean.get("disasterRecoveryReleaseArchiveContentManifestSha256", "")))
    or clean.get("disasterRecoveryReleaseArchiveSourceFormat") != "git-archive-tar-v1"
    or not re.fullmatch(r"[0-9a-f]{64}", str(authority_sha))
    or clean.get("disasterRecoveryReleaseSourceAuthorityObjectKey") != f"backups/recovery-releases/authorities/{authority_sha}.json"
    or clean.get("disasterRecoveryHistoricalReleaseAdoptionScope") != "clean-target-disaster-recovery-only"
):
    raise SystemExit("final clean disaster-recovery release authority is malformed")
pointer = root.parent / "latest-backup-evidence"
pointer_bytes = regular_root_file(pointer, 4096)
if pointer_bytes != (str(clean_path) + "\n").encode("utf-8"):
    raise SystemExit("latest backup pointer does not name the final clean backup")
if pathlib.Path(terminal.get("restoreEvidenceFile")) != record or hashlib.sha256(record_bytes).hexdigest() != terminal.get("restoreEvidenceSha256"):
    raise SystemExit("completed restore does not bind exact restore evidence")
if document.get("finalCleanBackupMarkerAbsent") is not True:
    raise SystemExit("restore evidence does not prove the final clean marker absent")
if document.get("finalCleanBackupEvidenceSha256") != terminal.get("cleanBackupEvidenceSha256"):
    raise SystemExit("completed restore clean evidence digest differs")
if document.get("finalCleanBackupFilename") != terminal.get("cleanBackupFilename") or document.get("finalCleanBackupSha256") != terminal.get("cleanBackupSha256"):
    raise SystemExit("completed restore clean backup identity differs")
if tested_path == clean_path:
    raise SystemExit("tested and final clean backups must be distinct")
if not pointer.is_file() or pointer.is_symlink():
    raise SystemExit("latest backup pointer is unsafe")
print(record.name)
print(hashlib.sha256(record_bytes).hexdigest())
PY
)
[[ ${#restore_contract[@]} -eq 2 ]] || fail "Disposable-restore evidence is malformed."
restore_record_name="${restore_contract[0]}"
restore_record_sha="${restore_contract[1]}"

python3 - "${marker}" "${commit}" "${configuration}" "${restore_record_name}" "${restore_record_sha}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
expected = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "restoreEvidenceFile": sys.argv[4],
    "restoreEvidenceSha256": sys.argv[5],
    "destructiveRestorePermanentlyDisabled": True,
}
def discard_safe_partial():
    if not candidate.exists() and not candidate.is_symlink():
        return
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit("member-rollout marker partial is unsafe")
    candidate.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

if path.exists() or path.is_symlink():
    if not path.is_file() or path.is_symlink():
        raise SystemExit("member-rollout marker is not one regular file")
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        raise SystemExit("member-rollout marker permissions are unsafe")
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != set(expected) | {"finalizedAt"}:
        raise SystemExit("member-rollout marker keys differ")
    if any(document.get(key) != value for key, value in expected.items()):
        raise SystemExit("member-rollout marker differs from exact restore evidence")
    if not isinstance(document.get("finalizedAt"), str) or not document["finalizedAt"].endswith("Z"):
        raise SystemExit("member-rollout marker timestamp is malformed")
    discard_safe_partial()
else:
    discard_safe_partial()
    document = dict(expected)
    document["finalizedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(json.dumps(document, sort_keys=True) + "\n")
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
[[ "$(stat -c '%U:%G %a' "${marker}")" == "root:root 600" ]] || fail "Member-rollout marker has unsafe ownership or mode."
marker_sha="$(sha256sum -- "${marker}" | awk '{print $1}')"
[[ ${marker_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Member-rollout marker digest is malformed."
if [[ ${current_marker_file} != - || ${current_marker_sha} != - ]]; then
  [[ ${current_marker_file} == member-rollout-enabled && ${current_marker_sha} == "${marker_sha}" ]] || fail "Current release evidence differs from the permanent member-rollout marker."
fi

# Atomically reseal the current release contract with the permanent marker.
# This does not mutate the immutable pre-activation release record or its tuple.
python3 - "${current_evidence}" "${commit}" "${configuration}" "${release_record_name}" "${release_record_sha}" "${marker_sha}" <<'PY'
import json
import os
import pathlib
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
document = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "releaseEvidenceFile": sys.argv[4],
    "releaseEvidenceSha256": sys.argv[5],
    "discourseConnectEnabled": False,
    "memberRolloutMarkerFile": "member-rollout-enabled",
    "memberRolloutMarkerSha256": sys.argv[6],
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
[[ "$(stat -c '%U:%G %a' "${current_evidence}")" == "root:root 600" ]] || fail "Resealed current evidence has unsafe ownership or mode."
python3 - "${current_evidence}" "${commit}" "${configuration}" "${release_record_name}" "${release_record_sha}" "${marker_sha}" <<'PY' >/dev/null
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "releaseEvidenceFile": sys.argv[4],
    "releaseEvidenceSha256": sys.argv[5],
    "discourseConnectEnabled": False,
    "memberRolloutMarkerFile": "member-rollout-enabled",
    "memberRolloutMarkerSha256": sys.argv[6],
}
if document != expected:
    raise SystemExit("resealed current evidence differs")
PY
python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
  --path "${state_root}/logs/events.log" --operation member-rollout --status passed \
  --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
  --field "evidence_sha256=${marker_sha}" >/dev/null || fail "Member-rollout completion event could not be committed durably."
printf '%s\n' "Mochirii Forums destructive restore permanently disabled for member rollout."
