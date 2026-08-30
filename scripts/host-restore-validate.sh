#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly launcher_bootstrap_cid="/var/discourse/cids/app_bootstrap.cid"
readonly launcher_timeout_seconds=7200
readonly launcher_cumulative_budget_seconds=12600
readonly operation_started_epoch="$(date +%s)"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Disposable restore validation must run as root."
[[ $# -eq 2 ]] || fail "Usage: host-restore-validate.sh COMMIT CONFIRMATION"
commit="$1"
confirmation="$2"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Expected commit is malformed."
disaster_restore=false
case "${confirmation}" in
  "RESTORE DISPOSABLE MOCHIRII FORUMS") ;;
  "RESTORE CLEAN TARGET MOCHIRII FORUMS") disaster_restore=true ;;
  *) fail "Exact destructive restore confirmation is required." ;;
esac

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
historical_adoption=false
historical_journal="/var/lib/mochirii/forums/historical-release-adoption.json"
historical_receipt="/var/lib/mochirii/forums/historical-recovery/fetched-recovery-receipt.json"
historical_helper="/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py"
historical_bootstrap_commit=""
historical_restore_phase=""
if [[ -e ${historical_journal} || -L ${historical_journal} ]]; then
  [[ ${disaster_restore} == true ]] || fail "An active historical adoption refuses disposable restore."
  [[ -f ${historical_journal} && ! -L ${historical_journal} ]] || fail "Historical adoption journal is absent or linked."
  [[ "$(stat -c '%U:%G %a' "${historical_journal}")" == "root:root 600" ]] || fail "Historical adoption journal has unsafe ownership or mode."
  [[ -f ${historical_receipt} && ! -L ${historical_receipt} ]] || fail "Historical recovery receipt is absent or linked."
  [[ -x ${historical_helper} && ! -L ${historical_helper} ]] || fail "Installed historical recovery helper is absent or linked."
  readarray -t historical_restore_contract < <(python3 -B - "${historical_journal}" "${commit}" <<'PY'
import json
import pathlib
import re
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
phase = document.get("phase")
if phase not in {"bootstrap-complete", "restore-started", "restore-complete"}:
    raise SystemExit("historical adoption is not restore-ready")
if document.get("recoveredRepositoryCommit") != sys.argv[2]:
    raise SystemExit("historical adoption commit differs")
bootstrap = document.get("bootstrapRepositoryCommit", "")
if re.fullmatch(r"[0-9a-f]{40}", str(bootstrap)) is None or bootstrap == sys.argv[2]:
    raise SystemExit("historical bootstrap commit is malformed")
print(phase)
print(bootstrap)
PY
  ) || fail "Historical adoption restore authority is malformed."
  [[ ${#historical_restore_contract[@]} -eq 2 ]] || fail "Historical adoption restore authority is incomplete."
  historical_adoption=true
  historical_restore_phase="${historical_restore_contract[0]}"
  historical_bootstrap_commit="${historical_restore_contract[1]}"
  python3 -B "${historical_helper}" verify --receipt "${historical_receipt}" \
    --journal "${historical_journal}" --require-phase "${historical_restore_contract[0]}" >/dev/null
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
if document.get("releaseEvidenceSha256") != hashlib.sha256(record.read_bytes()).hexdigest():
    raise SystemExit("release evidence digest differs")
if document.get("discourseConnectEnabled") is not False:
    raise SystemExit("restore validation requires central login disabled")
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if (marker_file is None) != (marker_sha is None):
    raise SystemExit("current member-rollout evidence is incomplete")
if marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)):
    raise SystemExit("current member-rollout evidence is malformed")
print(value)
print(marker_file or "-")
print(marker_sha or "-")
PY
) || fail "Current release evidence is malformed."
[[ ${#current_contract[@]} -eq 3 ]] || fail "Current release evidence is incomplete."
configuration="${current_contract[0]}"
current_member_marker_file="${current_contract[1]}"
current_member_marker_sha="${current_contract[2]}"
release_dir="/opt/mochirii/forums/releases/${commit}"
production_config="/var/discourse/containers/releases/${commit}/${configuration}/app.yml"
restore_config="/var/discourse/containers/releases/${commit}/${configuration}/restore.yml"
release_record="/var/lib/mochirii/forums/evidence/${commit}-${configuration}-release.json"
release_archive="/opt/mochirii/forums/runtime-assets/${commit}/mochirii-release.tar"
state_root="/var/lib/mochirii/forums"
evidence_root="${state_root}/evidence"
logs_root="${state_root}/logs"
restore_journal="${state_root}/restore-transaction.json"
restore_terminal="${state_root}/current-restore.json"
restore_phase=""
completed_restore_resume=false
clean_backup_evidence=""
clean_backup_evidence_sha256=""
clean_backup_filename=""
clean_backup_sha256=""
restore_evidence=""
restore_evidence_sha256=""
launcher_operation_token=""
launcher_previous_image_id=""
launcher_replacement_image_id=""
launcher_operation_command=""
launcher_configuration_file=""
launcher_configuration_sha256=""
launcher_restore_phase=""
if [[ ${historical_adoption} == true && ${historical_restore_phase} == restore-complete ]]; then
  [[ ! -e ${state_root}/backup-transaction.json && ! -L ${state_root}/backup-transaction.json ]] || fail "Historical terminal reconciliation refuses an active backup transaction."
  [[ ! -e ${state_root}/deployment-transaction.json && ! -L ${state_root}/deployment-transaction.json ]] || fail "Historical terminal reconciliation refuses an active deployment transaction."
  [[ ! -e ${state_root}/deployment-mutation.json && ! -L ${state_root}/deployment-mutation.json ]] || fail "Historical terminal reconciliation refuses an active deployment mutation."
  [[ ! -e ${restore_journal} && ! -L ${restore_journal} ]] || fail "Historical terminal reconciliation refuses an active restore transaction."
  readarray -t historical_terminal_contract < <(python3 -B - "${historical_journal}" "${restore_terminal}" "${state_root}/latest-backup-evidence" <<'PY'
import json
import pathlib
import sys
journal, terminal, pointer = map(pathlib.Path, sys.argv[1:])
document = json.loads(journal.read_text(encoding="utf-8"))
if document.get("phase") != "restore-complete" or document.get("restoreTerminalEvidenceFile") != str(terminal):
    raise SystemExit("historical terminal reconciliation tuple differs")
clean = pathlib.Path(str(document.get("cleanBackupEvidenceFile", "")))
if clean.parent != journal.parent / "evidence" or pointer.read_bytes() != (str(clean) + "\n").encode("utf-8"):
    raise SystemExit("historical terminal clean-backup pointer differs")
print(clean)
PY
  ) || fail "Historical terminal-only reconciliation authority is malformed."
  [[ ${#historical_terminal_contract[@]} -eq 1 ]] || fail "Historical terminal-only reconciliation authority is incomplete."
  python3 -B "${historical_helper}" complete --receipt "${historical_receipt}" \
    --journal "${historical_journal}" --current-release "${current_evidence}" \
    --restore-terminal "${restore_terminal}" --clean-backup "${historical_terminal_contract[0]}" \
    --backup-pointer "${state_root}/latest-backup-evidence" \
    --confirmation "COMPLETE HISTORICAL MOCHIRII FORUMS RECOVERY"
  [[ ! -e ${historical_journal} && ! -L ${historical_journal} ]] || fail "Terminal historical adoption journal was not retired."
  printf '%s\n' "Mochirii Forums historical restore terminal evidence reconciled."
  exit 0
fi
[[ ! -e ${state_root}/backup-transaction.json && ! -L ${state_root}/backup-transaction.json ]] || fail "Restore refuses an active backup transaction; only the protected backup command may reconcile it."
[[ ! -e ${state_root}/deployment-transaction.json && ! -L ${state_root}/deployment-transaction.json ]] || fail "Restore refuses an active deployment transaction; only the protected deploy command may reconcile it."
[[ ! -e ${state_root}/deployment-mutation.json && ! -L ${state_root}/deployment-mutation.json ]] || fail "Restore refuses an active deployment mutation; only the protected deploy command may reconcile it."
[[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "Immutable release is absent."
[[ -f ${production_config} && -f ${restore_config} && -f ${release_record} && -f ${release_archive} ]] || fail "Versioned production, restore, archive, and release evidence are required."
[[ ! -L ${production_config} && ! -L ${restore_config} && ! -L ${release_record} && ! -L ${release_archive} ]] || fail "Versioned configuration, archive, or evidence may not be a symbolic link."
[[ "$(stat -c '%U:%G %a' "${release_record}")" == "root:root 600" ]] || fail "Release evidence has unsafe ownership or mode."
bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Restore refuses runtime assets that differ from the sealed release."
backup_transaction_helper="${release_dir}/scripts/backup-transaction.py"
[[ -f ${backup_transaction_helper} && ! -L ${backup_transaction_helper} ]] || fail "Protected backup transaction helper is absent."

current_backup="${state_root}/current-backup.json"
if [[ -e ${current_backup} || -L ${current_backup} ]]; then
  restore_retirement_sha="$(python3 -B - "${commit}" "${configuration}" <<'PY'
import hashlib
import sys
print(hashlib.sha256(f"mochirii-restore-backup-retirement-v1\0{sys.argv[1]}\0{sys.argv[2]}".encode("ascii")).hexdigest())
PY
)" || fail "Restore backup-retirement identity could not be derived."
  [[ ${restore_retirement_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Restore backup-retirement identity is malformed."
  backup_helper_arguments=(
    --state-root "${state_root}"
    --evidence-root "${evidence_root}"
    --transaction "${state_root}/backup-transaction.json"
    --current "${current_backup}"
    --pointer "${state_root}/latest-backup-evidence"
    --commit "${commit}"
    --configuration "${configuration}"
    --operation-sha "${restore_retirement_sha}"
  )
  readarray -t current_backup_contract < <(python3 -B "${backup_transaction_helper}" inspect-current "${backup_helper_arguments[@]}") || fail "Terminal backup state could not be inspected before restore."
  [[ ${#current_backup_contract[@]} -eq 5 && ${current_backup_contract[0]} == "${commit}" && ${current_backup_contract[1]} == "${configuration}" && ${current_backup_contract[4]} == event-committed ]] || fail "Restore refuses a nonterminal or different-tuple current backup."
  python3 -B "${backup_transaction_helper}" retire-current "${backup_helper_arguments[@]}" || fail "Terminal current-backup state could not be retired durably before restore."
  [[ ! -e ${current_backup} && ! -L ${current_backup} ]] || fail "Terminal current-backup retirement could not be proved."
fi

if [[ -e ${restore_journal} || -L ${restore_journal} ]]; then
  readarray -t resume_contract < <(python3 -B - "${restore_journal}" "${commit}" "${configuration}" "${production_config}" "${restore_config}" "${release_record}" "${disaster_restore}" <<'PY'
import datetime
import hashlib
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
meta = path.lstat()
if not stat.S_ISREG(meta.st_mode) or stat.S_ISLNK(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_size > 65536:
    raise SystemExit("restore journal is unsafe")
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "schemaVersion", "phase", "restoreMode", "recordedAt", "updatedAt", "repositoryCommit",
    "productionConfigurationSha256", "productionConfigurationFile", "productionConfigurationFileSha256",
    "restoreConfigurationFile", "restoreConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256",
    "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "recoveryUploadIncluded",
    "recoveryUploadStateSha256", "normalUploadInventoryCount", "normalUploadInventorySha256",
    "cleanBackupIntentAt",
    "cleanBackupEvidenceFile", "cleanBackupEvidenceSha256", "cleanBackupFilename", "cleanBackupSha256",
    "restoreEvidenceFile", "restoreEvidenceSha256",
    "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
    "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
}
if set(document) != required or document.get("schemaVersion") != 1:
    raise SystemExit("restore journal keys differ")
phases = {
    "prepared", "isolating", "isolated", "restoring", "data-restored", "verified-restored",
    "cleaning-fixture", "fixture-cleaned", "member-marker-committed", "production-reopening", "production-reopened",
    "clean-backup-creating", "clean-backup-committed", "pointer-committed",
    "restore-evidence-committed", "event-committed",
}
if document.get("phase") not in phases or document.get("repositoryCommit") != sys.argv[2] or document.get("productionConfigurationSha256") != sys.argv[3]:
    raise SystemExit("restore journal tuple differs")
clean_phases = {
    "clean-backup-creating", "clean-backup-committed", "pointer-committed",
    "production-reopening", "production-reopened", "restore-evidence-committed", "event-committed",
}
clean_intent = document.get("cleanBackupIntentAt")
if (document["phase"] in clean_phases) != isinstance(clean_intent, str):
    raise SystemExit("clean backup intent timestamp is incomplete")
if clean_intent is not None:
    try:
        parsed_intent = datetime.datetime.fromisoformat(clean_intent.replace("Z", "+00:00"))
    except ValueError as error:
        raise SystemExit("clean backup intent timestamp is malformed") from error
    if parsed_intent.tzinfo is None:
        raise SystemExit("clean backup intent timestamp lacks a time zone")
expected_mode = "clean-target-disaster" if sys.argv[7] == "true" else "disposable-rehearsal"
if document.get("restoreMode") != expected_mode:
    raise SystemExit("restore journal mode differs")
def exact_file(field, digest_field, expected=None):
    value = document.get(field)
    digest = document.get(digest_field)
    if not isinstance(value, str) or not value.startswith("/") or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise SystemExit(f"{field} binding is malformed")
    candidate = pathlib.Path(value)
    if expected is not None and candidate != pathlib.Path(expected):
        raise SystemExit(f"{field} path differs")
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise SystemExit(f"{field} permissions differ")
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"{field} digest differs")
    return value
production_file = exact_file("productionConfigurationFile", "productionConfigurationFileSha256", sys.argv[4])
restore_file = exact_file("restoreConfigurationFile", "restoreConfigurationSha256", sys.argv[5])
exact_file("releaseEvidenceFile", "releaseEvidenceSha256", sys.argv[6])
tested = exact_file("testedBackupEvidenceFile", "testedBackupEvidenceSha256")
launcher_token = document.get("launcherOperationToken")
launcher_image = document.get("launcherPreviousImageId")
launcher_replacement_image = document.get("launcherReplacementImageId")
launcher_command = document.get("launcherCommand")
launcher_file = document.get("launcherConfigurationFile")
launcher_sha = document.get("launcherConfigurationSha256")
launcher_phase = document.get("launcherRestorePhase")
launcher_values = (launcher_token, launcher_image, launcher_replacement_image, launcher_command, launcher_file, launcher_sha, launcher_phase)
if launcher_token is None:
    if any(value is not None for value in launcher_values):
        raise SystemExit("restore launcher journal binding is incomplete")
else:
    allowed_configurations = {
        production_file: document["productionConfigurationFileSha256"],
        restore_file: document["restoreConfigurationSha256"],
    }
    if (
        re.fullmatch(r"[0-9a-f]{32}", str(launcher_token)) is None
        or (launcher_image != "-" and re.fullmatch(r"sha256:[0-9a-f]{64}", str(launcher_image)) is None)
        or (launcher_replacement_image is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", str(launcher_replacement_image)) is None)
        or launcher_replacement_image == launcher_image
        or launcher_command not in {"bootstrap", "start", "restart", "rebuild", "destroy"}
        or allowed_configurations.get(launcher_file) != launcher_sha
        or launcher_phase != document["phase"]
    ):
        raise SystemExit("restore launcher journal binding differs")
recovery_included = document.get("recoveryUploadIncluded")
recovery_sha = document.get("recoveryUploadStateSha256")
if not isinstance(recovery_included, bool) or recovery_included != (recovery_sha is not None):
    raise SystemExit("recovery-upload journal binding is incomplete")
if recovery_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", str(recovery_sha)):
    raise SystemExit("recovery-upload journal digest is malformed")
inventory_count = document.get("normalUploadInventoryCount")
inventory_sha = document.get("normalUploadInventorySha256")
if not isinstance(inventory_count, int) or isinstance(inventory_count, bool) or not 0 <= inventory_count <= 10000:
    raise SystemExit("normal-upload journal count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(inventory_sha)):
    raise SystemExit("normal-upload journal digest is malformed")
optional_pairs = (
    ("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256"),
    ("restoreEvidenceFile", "restoreEvidenceSha256"),
)
for field, digest_field in optional_pairs:
    value = document.get(field)
    digest = document.get(digest_field)
    if (value is None) != (digest is None):
        raise SystemExit(f"{field} binding is incomplete")
    if value is not None:
        exact_file(field, digest_field)
for field in ("cleanBackupFilename", "cleanBackupSha256"):
    value = document.get(field)
    if value is not None and not isinstance(value, str):
        raise SystemExit(f"{field} is malformed")
if (document.get("cleanBackupFilename") is None) != (document.get("cleanBackupSha256") is None):
    raise SystemExit("clean backup tuple is incomplete")
if document.get("cleanBackupFilename") is not None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", document["cleanBackupFilename"]) or ".." in document["cleanBackupFilename"] or not re.fullmatch(r"[0-9a-f]{64}", document["cleanBackupSha256"]):
        raise SystemExit("clean backup tuple is malformed")
print(document["phase"])
print(tested)
print(document.get("cleanBackupEvidenceFile") or "-")
print(document.get("cleanBackupEvidenceSha256") or "-")
print(document.get("cleanBackupFilename") or "-")
print(document.get("cleanBackupSha256") or "-")
print(document.get("restoreEvidenceFile") or "-")
print(document.get("restoreEvidenceSha256") or "-")
print(launcher_token or "-")
print(launcher_image or "-")
print(launcher_replacement_image or "-")
print(launcher_command or "-")
print(launcher_file or "-")
print(launcher_sha or "-")
print(launcher_phase or "-")
PY
  ) || fail "Existing restore transaction journal is malformed."
  [[ ${#resume_contract[@]} -eq 15 ]] || fail "Existing restore transaction journal is incomplete."
  restore_phase="${resume_contract[0]}"
  backup_evidence="${resume_contract[1]}"
  [[ ${resume_contract[2]} == - ]] || clean_backup_evidence="${resume_contract[2]}"
  [[ ${resume_contract[3]} == - ]] || clean_backup_evidence_sha256="${resume_contract[3]}"
  [[ ${resume_contract[4]} == - ]] || clean_backup_filename="${resume_contract[4]}"
  [[ ${resume_contract[5]} == - ]] || clean_backup_sha256="${resume_contract[5]}"
  [[ ${resume_contract[6]} == - ]] || restore_evidence="${resume_contract[6]}"
  [[ ${resume_contract[7]} == - ]] || restore_evidence_sha256="${resume_contract[7]}"
  if [[ ${resume_contract[8]} != - ]]; then
    launcher_operation_token="${resume_contract[8]}"
    launcher_previous_image_id="${resume_contract[9]}"
    [[ ${resume_contract[10]} == - ]] || launcher_replacement_image_id="${resume_contract[10]}"
    launcher_operation_command="${resume_contract[11]}"
    launcher_configuration_file="${resume_contract[12]}"
    launcher_configuration_sha256="${resume_contract[13]}"
    launcher_restore_phase="${resume_contract[14]}"
  fi
  active_config="$(readlink -f -- /var/discourse/containers/app.yml)" || fail "Active restore configuration cannot be resolved."
  [[ ${active_config} == "${production_config}" || ${active_config} == "${restore_config}" ]] || fail "Restore journal does not authorize the active configuration."
else
  [[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${production_config}" ]] || fail "A new restore must begin from the exact production configuration."
  backup_pointer="${state_root}/latest-backup-evidence"
  if [[ -f ${restore_terminal} && ! -L ${restore_terminal} && -f ${backup_pointer} && ! -L ${backup_pointer} ]]; then
    readarray -t completed_contract < <(python3 -B - "${restore_terminal}" "${backup_pointer}" "${commit}" "${configuration}" "${disaster_restore}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

record = pathlib.Path(sys.argv[1])
pointer = pathlib.Path(sys.argv[2])
for path in (record, pointer):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("completed restore pointer is unsafe")
document = json.loads(record.read_text(encoding="utf-8"))
required = {
    "schemaVersion", "phase", "restoreMode", "repositoryCommit", "productionConfigurationSha256",
    "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "cleanBackupEvidenceFile",
    "cleanBackupEvidenceSha256", "cleanBackupFilename", "cleanBackupSha256",
    "restoreEvidenceFile", "restoreEvidenceSha256",
}
expected_mode = "clean-target-disaster" if sys.argv[5] == "true" else "disposable-rehearsal"
if set(document) != required or document.get("schemaVersion") != 1 or document.get("phase") != "complete" or document.get("restoreMode") not in {"clean-target-disaster", "disposable-rehearsal"} or document.get("repositoryCommit") != sys.argv[3] or document.get("productionConfigurationSha256") != sys.argv[4]:
    raise SystemExit("completed restore tuple differs")
def validate(field, digest_field):
    value = document.get(field)
    digest = document.get(digest_field)
    if not isinstance(value, str) or not value.startswith("/") or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise SystemExit("completed restore file binding is malformed")
    path = pathlib.Path(value)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit("completed restore file binding differs")
    return value
tested = validate("testedBackupEvidenceFile", "testedBackupEvidenceSha256")
clean = validate("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256")
restored = validate("restoreEvidenceFile", "restoreEvidenceSha256")
if pointer.read_text(encoding="utf-8") != clean + "\n":
    print("NEW")
    raise SystemExit(0)
if document.get("restoreMode") != expected_mode:
    raise SystemExit("completed restore mode differs")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", str(document.get("cleanBackupFilename"))) or ".." in document["cleanBackupFilename"] or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("cleanBackupSha256"))):
    raise SystemExit("completed restore backup tuple is malformed")
print("RESUME")
print(tested)
print(clean)
print(document["cleanBackupEvidenceSha256"])
print(document["cleanBackupFilename"])
print(document["cleanBackupSha256"])
print(restored)
print(document["restoreEvidenceSha256"])
PY
    ) || fail "Completed restore state is malformed."
    if [[ ${completed_contract[0]:-} == RESUME ]]; then
      [[ ${#completed_contract[@]} -eq 8 ]] || fail "Completed restore state is incomplete."
      restore_phase=event-committed
      backup_evidence="${completed_contract[1]}"
      clean_backup_evidence="${completed_contract[2]}"
      clean_backup_evidence_sha256="${completed_contract[3]}"
      clean_backup_filename="${completed_contract[4]}"
      clean_backup_sha256="${completed_contract[5]}"
      restore_evidence="${completed_contract[6]}"
      restore_evidence_sha256="${completed_contract[7]}"
      completed_restore_resume=true
    elif [[ ${#completed_contract[@]} -ne 1 || ${completed_contract[0]} != NEW ]]; then
      fail "Completed restore state discriminator is malformed."
    fi
  elif [[ -e ${restore_terminal} || -L ${restore_terminal} ]]; then
    fail "Completed restore state is unsafe."
  fi
fi

if [[ ${disaster_restore} == true && -z ${backup_evidence:-} ]]; then
  [[ ! -e ${restore_journal} && ! -L ${restore_journal} ]] || fail "A clean-target disaster restore refuses an unrelated active restore journal."
  timeout --signal=TERM --kill-after=5s 45 python3 -B "${release_dir}/scripts/probe-website-forums-producer.py" disabled >/dev/null 2>&1 || fail "Clean-target disaster restore requires the Website Forums producer to be exactly disabled."
  disaster_operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${disaster_operation_token} =~ ^[0-9a-f]{32}$ ]] || fail "Clean-target guard token generation failed."
  timeout --signal=TERM --kill-after=10s 360 docker exec -e MOCHIRII_OPERATION_TOKEN="${disaster_operation_token}" app \
    timeout --signal=TERM --kill-after=10s 330 bash -lc \
      '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-clean-disaster-target.rb"' >/dev/null 2>&1 || {
        timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
        fail "Clean-target disaster restore guard failed; the application was contained."
      }
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
  ' "${disaster_operation_token}" >/dev/null 2>&1 || {
    timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
    fail "Clean-target guard process termination is unproved; the application was contained."
  }
  disaster_candidate="$(mktemp "${evidence_root}/.disaster-recovery-evidence.XXXXXXXX.json")"
  chmod 0600 "${disaster_candidate}"
  disaster_operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${disaster_operation_token} =~ ^[0-9a-f]{32}$ ]] || fail "Recovery fetch token generation failed."
  historical_fetch_environment=()
  if [[ ${historical_adoption} == true ]]; then
    historical_fetch_environment=(
      -e MOCHIRII_DR_FETCH_MODE=clean-target-historical
      -e "MOCHIRII_DR_BOOTSTRAP_COMMIT=${historical_bootstrap_commit}"
    )
  fi
  if ! (ulimit -f 128; exec timeout --signal=TERM --kill-after=10s 360 docker exec \
      -e MOCHIRII_OPERATION_TOKEN="${disaster_operation_token}" \
      -e MOCHIRII_PRODUCTION_CONFIGURATION_SHA256="${configuration}" \
      "${historical_fetch_environment[@]}" app \
      timeout --signal=TERM --kill-after=10s 330 bash -lc \
      '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/fetch-disaster-recovery-evidence.rb"') \
      >"${disaster_candidate}" 2>/dev/null; then
    rm -f -- "${disaster_candidate}"
    timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
    fail "Private off-host recovery evidence fetch failed; the application was contained."
  fi
  if [[ ${historical_adoption} == true ]]; then
    cmp -s -- "${disaster_candidate}" "${historical_receipt}" || {
      rm -f -- "${disaster_candidate}"
      timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
      fail "Historical recovery receipt changed when re-read through the recovered C0 application."
    }
  fi
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
  ' "${disaster_operation_token}" >/dev/null 2>&1 || {
    rm -f -- "${disaster_candidate}"
    timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
    fail "Recovery evidence fetch termination is unproved; the application was contained."
  }
  disaster_timestamp="$(python3 -B - "${disaster_candidate}" "${commit}" "${configuration}" <<'PY'
import datetime
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("repositoryCommit") != sys.argv[2] or document.get("productionConfigurationSha256") != sys.argv[3]:
    raise SystemExit("fetched recovery evidence tuple differs")
try:
    modified = datetime.datetime.fromisoformat(str(document["lastModified"]).replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("fetched recovery evidence timestamp is malformed") from error
if modified.tzinfo is None:
    raise SystemExit("fetched recovery evidence timestamp lacks a time zone")
print(modified.astimezone(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
PY
)" || fail "Fetched recovery evidence identity could not be derived."
  [[ ${disaster_timestamp} =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail "Fetched recovery evidence timestamp is malformed."
  backup_evidence="${evidence_root}/${commit}-${configuration}-${disaster_timestamp}-backup.json"
  python3 -B - "${disaster_candidate}" "${backup_evidence}" "${backup_pointer}" <<'PY'
import os
import pathlib
import stat
import sys

candidate = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2])
pointer = pathlib.Path(sys.argv[3])
metadata = candidate.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
    raise SystemExit("fetched recovery evidence is unsafe")
if evidence.exists() or evidence.is_symlink():
    evidence_meta = evidence.lstat()
    if not stat.S_ISREG(evidence_meta.st_mode) or stat.S_ISLNK(evidence_meta.st_mode) or evidence_meta.st_uid != 0 or stat.S_IMODE(evidence_meta.st_mode) != 0o600 or evidence.read_bytes() != candidate.read_bytes():
        raise SystemExit("existing fetched recovery evidence differs")
    candidate.unlink()
else:
    os.link(candidate, evidence, follow_symlinks=False)
directory = os.open(evidence.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
    if candidate.exists():
        candidate.unlink()
    os.fsync(directory)
finally:
    os.close(directory)
partial = pointer.parent / f".{pointer.name}.disaster-partial"
if partial.exists() or partial.is_symlink():
    partial_meta = partial.lstat()
    if not stat.S_ISREG(partial_meta.st_mode) or stat.S_ISLNK(partial_meta.st_mode) or partial_meta.st_uid != 0 or stat.S_IMODE(partial_meta.st_mode) != 0o600 or partial_meta.st_size > 65536:
        raise SystemExit("disaster pointer partial is unsafe")
    partial.unlink()
descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    target.write(str(evidence) + "\n")
    target.flush()
    os.fsync(target.fileno())
os.replace(partial, pointer)
descriptor = os.open(pointer, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(pointer.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
fi

if [[ -z ${backup_evidence:-} ]]; then
  backup_pointer="/var/lib/mochirii/forums/latest-backup-evidence"
  [[ -f ${backup_pointer} && ! -L ${backup_pointer} ]] || fail "Protected latest-backup pointer is absent."
  [[ "$(stat -c '%U:%G %a' "${backup_pointer}")" == "root:root 600" ]] || fail "Protected latest-backup pointer has unsafe ownership or mode."
  IFS= read -r backup_evidence < "${backup_pointer}"
  [[ ${backup_evidence} =~ ^/var/lib/mochirii/forums/evidence/${commit}-${configuration}-[0-9]{8}T[0-9]{6}Z-backup[.]json$ ]] || fail "Latest backup evidence is not bound to the exact release and configuration."
  [[ -f ${backup_evidence} && ! -L ${backup_evidence} ]] || fail "Protected backup evidence is absent."
else
  backup_pointer="/var/lib/mochirii/forums/latest-backup-evidence"
fi

readarray -t backup_contract < <(python3 - "${backup_evidence}" "${commit}" "${configuration}" "${release_record}" "${restore_config}" "/opt/mochirii/forums/runtime-assets/${commit}/mochirii-theme.zip" "/opt/mochirii/forums/runtime-assets/${commit}/mochirii-email-metadata-plugin.rb" "${historical_adoption}" <<'PY'
import json
import base64
import hashlib
import pathlib
import re
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("repositoryCommit") != sys.argv[2]:
    raise SystemExit("backup release mismatch")
if document.get("productionConfigurationSha256") != sys.argv[3]:
    raise SystemExit("backup configuration mismatch")
if document.get("anonymousRetrievalDenied") is not True or document.get("anonymousCdnRetrievalDenied") is not True:
    raise SystemExit("backup privacy evidence missing")
filename = document.get("filename", "")
if not isinstance(filename, str) or len(filename.encode("ascii", "strict")) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}\.t?gz", filename) or ".." in filename:
    raise SystemExit("backup filename invalid")
sha256 = document.get("sha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", sha256):
    raise SystemExit("backup digest invalid")
if document.get("schemaVersion") != 3:
    raise SystemExit("backup evidence schema differs")
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
release_path = pathlib.Path(sys.argv[4])
historical = sys.argv[8] == "true"
if document.get("releaseEvidenceFile") != release_path.name:
    raise SystemExit("backup release evidence filename differs")
if document.get("releaseEvidenceSha256") != digest(release_path):
    if not historical:
        raise SystemExit("backup release evidence differs")
    release = json.loads(release_path.read_text(encoding="utf-8"))
    historical_bindings = {
        "repositoryCommit": document.get("repositoryCommit"),
        "repositoryTree": document.get("disasterRecoveryRepositoryTree"),
        "releaseArchiveSha256": document.get("disasterRecoveryReleaseArchiveSha256"),
        "releaseArchiveBytes": document.get("disasterRecoveryReleaseArchiveBytes"),
        "releaseArchiveContentManifestSha256": document.get("disasterRecoveryReleaseArchiveContentManifestSha256"),
        "productionConfigurationSha256": document.get("productionConfigurationSha256"),
        "restoreConfigurationSha256": document.get("restoreConfigurationSha256"),
        "themeArchiveSha256": document.get("themeArchiveSha256"),
        "mailMetadataPluginSha256": document.get("mailMetadataPluginSha256"),
        "discourseDockerRevision": document.get("discourseDockerRevision"),
        "discourseRevision": document.get("discourseRevision"),
        "dockerManagerRevision": document.get("dockerManagerRevision"),
        "baseImageDigest": document.get("baseImageDigest"),
    }
    if (
        release.get("schemaVersion") != 2
        or any(release.get(key) != value for key, value in historical_bindings.items())
        or release.get("discourseConnectEnabled") is not False
        or release.get("activationPhase") != "consumer-disabled"
        or release.get("containedActivationPassed") is not False
        or release.get("memberRolloutMarkerFile") is not None
        or release.get("memberRolloutMarkerSha256") is not None
        or any(release.get(key) is not True for key in (
            "hostVerificationPassed", "hostedStoragePassed", "storageRestartPersistencePassed",
            "storageRebuildPersistencePassed", "storageCleanupPassed",
        ))
    ):
        raise SystemExit("regenerated historical release evidence is not semantically equal to the private C0 receipt")
if document.get("restoreConfigurationSha256") != digest(sys.argv[5]) or document.get("themeArchiveSha256") != digest(sys.argv[6]) or document.get("mailMetadataPluginSha256") != digest(sys.argv[7]):
    raise SystemExit("backup runtime asset binding differs")
expected_pins = {
    "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
    "discourseRevision": "badad7b0456a628e578bc48b9f8c1259422b5d58",
    "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
    "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
}
if any(document.get(key) != value for key, value in expected_pins.items()):
    raise SystemExit("backup source pin binding differs")
inventory_count = document.get("normalUploadInventoryCount")
inventory_sha = document.get("normalUploadInventorySha256")
if not isinstance(inventory_count, int) or isinstance(inventory_count, bool) or not 0 <= inventory_count <= 10000:
    raise SystemExit("backup normal-upload inventory count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(inventory_sha)):
    raise SystemExit("backup normal-upload inventory digest is malformed")
inventory_bytes = json.dumps(
    {"normalUploadInventoryCount": inventory_count, "normalUploadInventorySha256": inventory_sha},
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8") + b"\n"
state = document.get("recoveryUploadState")
required_state = {
    "schemaVersion", "repositoryCommit", "uploadId", "uploadSha1", "originalFilename",
    "objectPath", "tombstonePath", "contentSha256", "publicUrlSha256",
}
if document.get("recoveryUploadIncluded") is True:
    if document.get("recoveryUploadDeletedAfterBackup") is not True:
        raise SystemExit("backup recovery upload was not deleted after backup")
    if not isinstance(state, dict) or set(state) != required_state or state.get("schemaVersion") != 1 or state.get("repositoryCommit") != sys.argv[2]:
        raise SystemExit("backup recovery-upload state differs")
    state_bytes = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    state_sha = hashlib.sha256(state_bytes).hexdigest()
    if document.get("recoveryUploadStateSha256") != state_sha:
        raise SystemExit("backup recovery-upload state digest differs")
    state_encoding = base64.b64encode(state_bytes).decode("ascii")
elif document.get("recoveryUploadIncluded") is False:
    if state is not None or document.get("recoveryUploadStateSha256") is not None or document.get("recoveryUploadDeletedAfterBackup") is not False:
        raise SystemExit("clean backup retained recovery-upload identity")
    state_encoding = "-"
    state_sha = "-"
else:
    raise SystemExit("backup recovery-upload inclusion flag is malformed")
print(filename)
print(sha256)
print(state_encoding)
print(state_sha)
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if (marker_file is None) != (marker_sha is None):
    raise SystemExit("backup member-rollout binding is incomplete")
if marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)):
    raise SystemExit("backup member-rollout binding is malformed")
print(marker_file or "-")
print(marker_sha or "-")
print(inventory_count)
print(inventory_sha)
print(base64.b64encode(inventory_bytes).decode("ascii"))
PY
)
[[ ${#backup_contract[@]} -eq 9 ]] || fail "Backup evidence contract is malformed."
backup_filename="${backup_contract[0]}"
backup_sha256="${backup_contract[1]}"
recovery_upload_state_base64="${backup_contract[2]}"
recovery_upload_state_sha256="${backup_contract[3]}"
source_member_rollout_file="${backup_contract[4]}"
source_member_rollout_sha="${backup_contract[5]}"
normal_upload_inventory_count="${backup_contract[6]}"
normal_upload_inventory_sha256="${backup_contract[7]}"
normal_upload_inventory_base64="${backup_contract[8]}"
[[ ${#backup_filename} -le 200 && ${backup_filename} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz$ && ${backup_filename} != *..* ]] || fail "Backup filename is malformed."
[[ ${backup_sha256} =~ ^[0-9a-f]{64}$ ]] || fail "Backup digest is malformed."
if [[ ${recovery_upload_state_base64} == - && ${recovery_upload_state_sha256} == - ]]; then
  recovery_upload_fixture=false
  [[ ${disaster_restore} == true ]] || fail "A fixture-free backup is accepted only for clean-target disaster recovery."
else
  recovery_upload_fixture=true
  [[ ${#recovery_upload_state_base64} -le 8192 && ${recovery_upload_state_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Recovery-upload state encoding is malformed."
  [[ ${recovery_upload_state_sha256} =~ ^[0-9a-f]{64}$ ]] || fail "Recovery-upload state digest is malformed."
fi
[[ ${normal_upload_inventory_count} =~ ^(0|[1-9][0-9]{0,4})$ ]] || fail "Normal-upload inventory count is malformed."
(( normal_upload_inventory_count <= 10000 )) || fail "Normal-upload inventory count exceeds its bound."
[[ ${normal_upload_inventory_sha256} =~ ^[0-9a-f]{64}$ ]] || fail "Normal-upload inventory digest is malformed."
[[ ${#normal_upload_inventory_base64} -le 4096 && ${normal_upload_inventory_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Normal-upload inventory encoding is malformed."
if [[ ${source_member_rollout_file} == - && ${source_member_rollout_sha} == - ]]; then
  source_member_rollout=false
elif [[ ${disaster_restore} == true && ${source_member_rollout_file} == member-rollout-enabled && ${source_member_rollout_sha} =~ ^[0-9a-f]{64}$ ]]; then
  source_member_rollout=true
else
  fail "Only clean-target disaster recovery may adopt member-rollout backup evidence."
fi
member_marker="${state_root}/member-rollout-enabled"
if [[ ${source_member_rollout} == false ]]; then
  [[ ${current_member_marker_file} == - && ${current_member_marker_sha} == - && ! -e ${member_marker} && ! -L ${member_marker} ]] || fail "Restore is forbidden while member-rollout evidence exists."
else
  if [[ ${current_member_marker_file} == - && ${current_member_marker_sha} == - && ! -e ${member_marker} && ! -L ${member_marker} ]]; then
    :
  elif [[ ${current_member_marker_file} == member-rollout-enabled && ${current_member_marker_sha} =~ ^[0-9a-f]{64}$ && -f ${member_marker} && ! -L ${member_marker} ]]; then
    [[ "$(sha256sum -- "${member_marker}" | awk '{print $1}')" == "${current_member_marker_sha}" ]] || fail "Recovered member-rollout marker digest differs."
  else
    fail "Recovered member-rollout marker state is incomplete."
  fi
fi

install -d -m 0700 -o root -g root "${evidence_root}" "${logs_root}"
isolated=false
restore_success=false
runtime_survivor_unproved=false
active_bounded_pid=""
active_operation_token=""
active_operation_kind=""
clean_backup_candidate=""
clean_inventory_candidate=""
clean_inventory_after_candidate=""
clean_dr_payload=""
clean_dr_result=""

phase_number() {
  case "$1" in
    prepared) printf '10\n' ;;
    isolating) printf '20\n' ;;
    isolated) printf '30\n' ;;
    restoring) printf '40\n' ;;
    data-restored) printf '50\n' ;;
    verified-restored) printf '60\n' ;;
    cleaning-fixture) printf '70\n' ;;
    fixture-cleaned) printf '80\n' ;;
    member-marker-committed) printf '90\n' ;;
    clean-backup-creating) printf '100\n' ;;
    clean-backup-committed) printf '110\n' ;;
    pointer-committed) printf '120\n' ;;
    production-reopening) printf '130\n' ;;
    production-reopened) printf '140\n' ;;
    restore-evidence-committed) printf '150\n' ;;
    event-committed) printf '160\n' ;;
    *) return 1 ;;
  esac
}

phase_before() {
  local current target
  current="$(phase_number "${restore_phase}")" || return 1
  target="$(phase_number "$1")" || return 1
  (( current < target ))
}

write_restore_journal() {
  local next_phase="$1"
  local clean_evidence="${2:--}"
  local clean_evidence_sha="${3:--}"
  local clean_filename="${4:--}"
  local clean_sha="${5:--}"
  local restore_record="${6:--}"
  local restore_record_sha="${7:--}"
  python3 -B - "${restore_journal}" "${next_phase}" "${commit}" "${configuration}" \
    "${production_config}" "${restore_config}" "${release_record}" "${backup_evidence}" \
    "${recovery_upload_state_sha256}" "${clean_evidence}" "${clean_evidence_sha}" \
    "${clean_filename}" "${clean_sha}" "${restore_record}" "${restore_record_sha}" "${disaster_restore}" \
    "${recovery_upload_fixture}" "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" \
    "${launcher_operation_token:--}" "${launcher_previous_image_id:--}" "${launcher_replacement_image_id:--}" "${launcher_operation_command:--}" \
    "${launcher_configuration_file:--}" "${launcher_configuration_sha256:--}" "${launcher_restore_phase:--}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
phase = sys.argv[2]
order = {
    "prepared": 10, "isolating": 20, "isolated": 30, "restoring": 40,
    "data-restored": 50, "verified-restored": 60, "cleaning-fixture": 70,
    "fixture-cleaned": 80, "member-marker-committed": 90, "clean-backup-creating": 100,
    "clean-backup-committed": 110, "pointer-committed": 120, "production-reopening": 130,
    "production-reopened": 140, "restore-evidence-committed": 150, "event-committed": 160,
}
required = {
    "schemaVersion", "phase", "restoreMode", "recordedAt", "updatedAt", "repositoryCommit",
    "productionConfigurationSha256", "productionConfigurationFile", "productionConfigurationFileSha256",
    "restoreConfigurationFile", "restoreConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256",
    "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "recoveryUploadIncluded",
    "recoveryUploadStateSha256", "normalUploadInventoryCount", "normalUploadInventorySha256",
    "cleanBackupIntentAt", "cleanBackupEvidenceFile", "cleanBackupEvidenceSha256",
    "cleanBackupFilename", "cleanBackupSha256", "restoreEvidenceFile", "restoreEvidenceSha256",
    "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
    "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
}
if phase not in order:
    raise SystemExit("restore phase is invalid")
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
def bound_file(value, expected_sha=None):
    candidate = pathlib.Path(value)
    metadata = candidate.lstat()
    if not candidate.is_absolute() or not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise SystemExit("restore journal input file is unsafe")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if expected_sha not in (None, "-") and digest != expected_sha:
        raise SystemExit("restore journal input digest differs")
    return str(candidate), digest
production_file, production_sha = bound_file(sys.argv[5])
restore_file, restore_sha = bound_file(sys.argv[6])
release_file, release_sha = bound_file(sys.argv[7])
tested_file, tested_sha = bound_file(sys.argv[8])
if not re.fullmatch(r"[0-9a-f]{40}", sys.argv[3]) or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[4]):
    raise SystemExit("restore journal identity is malformed")
recovery_included = {"true": True, "false": False}.get(sys.argv[17])
recovery_sha = None if sys.argv[9] == "-" else sys.argv[9]
if recovery_included is None or recovery_included != (recovery_sha is not None):
    raise SystemExit("restore journal recovery-upload binding is malformed")
if recovery_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", recovery_sha):
    raise SystemExit("restore journal recovery-upload digest is malformed")
if not re.fullmatch(r"(?:0|[1-9][0-9]{0,4})", sys.argv[18]) or int(sys.argv[18]) > 10000:
    raise SystemExit("restore journal normal-upload count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", sys.argv[19]):
    raise SystemExit("restore journal normal-upload digest is malformed")
allowed_launcher_configurations = {
    production_file: production_sha,
    restore_file: restore_sha,
}
def validate_launcher(values):
    token, image, replacement_image, command, configuration_file, configuration_sha, restore_phase = values
    if token is None:
        if any(value is not None for value in values):
            raise SystemExit("restore launcher journal binding is incomplete")
        return None
    if (
        re.fullmatch(r"[0-9a-f]{32}", str(token)) is None
        or (image != "-" and re.fullmatch(r"sha256:[0-9a-f]{64}", str(image)) is None)
        or (replacement_image is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", str(replacement_image)) is None)
        or replacement_image == image
        or command not in {"bootstrap", "start", "restart", "rebuild", "destroy"}
        or allowed_launcher_configurations.get(configuration_file) != configuration_sha
        or restore_phase != phase
    ):
        raise SystemExit("restore launcher journal binding differs")
    return values
if sys.argv[20] == "-":
    if any(value != "-" for value in sys.argv[21:27]):
        raise SystemExit("restore launcher journal arguments are incomplete")
    incoming_launcher = validate_launcher((None, None, None, None, None, None, None))
else:
    incoming_launcher = validate_launcher((sys.argv[20], sys.argv[21], None if sys.argv[22] == "-" else sys.argv[22], *sys.argv[23:27]))
def optional_file(value, digest):
    if value == "-" and digest == "-":
        return None, None
    if value == "-" or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("restore optional file binding is malformed")
    return bound_file(value, digest)
clean_file, clean_file_sha = optional_file(sys.argv[10], sys.argv[11])
restore_record, restore_record_sha = optional_file(sys.argv[14], sys.argv[15])
clean_filename = None if sys.argv[12] == "-" else sys.argv[12]
clean_sha = None if sys.argv[13] == "-" else sys.argv[13]
if (clean_filename is None) != (clean_sha is None):
    raise SystemExit("clean backup identity is incomplete")
if clean_filename is not None and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", clean_filename) or ".." in clean_filename or not re.fullmatch(r"[0-9a-f]{64}", clean_sha)):
    raise SystemExit("clean backup identity is malformed")
existing = None
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("restore journal is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != required or existing.get("schemaVersion") != 1:
        raise SystemExit("restore journal keys differ")
    if existing.get("phase") not in order or order[phase] < order[existing["phase"]]:
        raise SystemExit("restore journal phase cannot move backward")
    existing_launcher = validate_launcher(tuple(existing.get(key) for key in (
        "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
        "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
    )))
    if existing_launcher is not None:
        if phase != existing["phase"]:
            raise SystemExit("restore journal cannot advance while a launcher is armed")
        if incoming_launcher is not None:
            if incoming_launcher[:2] != existing_launcher[:2] or incoming_launcher[3:] != existing_launcher[3:]:
                raise SystemExit("restore journal armed launcher identity cannot change")
            if existing_launcher[2] is not None and incoming_launcher[2] != existing_launcher[2]:
                raise SystemExit("restore journal replacement image identity cannot change")
    elif incoming_launcher is not None and phase != existing["phase"]:
        raise SystemExit("restore journal must arm a launcher within its current phase")
elif incoming_launcher is not None:
    raise SystemExit("restore journal must exist before a launcher can be armed")
clean_intent = existing.get("cleanBackupIntentAt") if existing else None
if order[phase] >= order["clean-backup-creating"] and clean_intent is None:
    clean_intent = now
if order[phase] < order["clean-backup-creating"] and clean_intent is not None:
    raise SystemExit("clean backup intent appeared before its phase")
stable = {
    "schemaVersion": 1,
    "restoreMode": "clean-target-disaster" if sys.argv[16] == "true" else "disposable-rehearsal",
    "repositoryCommit": sys.argv[3],
    "productionConfigurationSha256": sys.argv[4],
    "productionConfigurationFile": production_file,
    "productionConfigurationFileSha256": production_sha,
    "restoreConfigurationFile": restore_file,
    "restoreConfigurationSha256": restore_sha,
    "releaseEvidenceFile": release_file,
    "releaseEvidenceSha256": release_sha,
    "testedBackupEvidenceFile": tested_file,
    "testedBackupEvidenceSha256": tested_sha,
    "recoveryUploadIncluded": recovery_included,
    "recoveryUploadStateSha256": recovery_sha,
    "normalUploadInventoryCount": int(sys.argv[18]),
    "normalUploadInventorySha256": sys.argv[19],
}
if existing is not None:
    for key, value in stable.items():
        if existing.get(key) != value:
            raise SystemExit(f"restore journal stable field differs: {key}")
    if existing.get("cleanBackupEvidenceFile") is not None and clean_file != existing.get("cleanBackupEvidenceFile"):
        raise SystemExit("clean backup evidence cannot change")
    if existing.get("cleanBackupFilename") is not None and (
        clean_filename != existing.get("cleanBackupFilename") or clean_sha != existing.get("cleanBackupSha256")
    ):
        raise SystemExit("clean backup object identity cannot change")
    if existing.get("restoreEvidenceFile") is not None and restore_record != existing.get("restoreEvidenceFile"):
        raise SystemExit("restore evidence cannot change")
    if existing_launcher is not None or incoming_launcher is not None:
        launcher_only_fields = {
            "cleanBackupEvidenceFile": clean_file,
            "cleanBackupEvidenceSha256": clean_file_sha,
            "cleanBackupFilename": clean_filename,
            "cleanBackupSha256": clean_sha,
            "restoreEvidenceFile": restore_record,
            "restoreEvidenceSha256": restore_record_sha,
        }
        for key, value in launcher_only_fields.items():
            if existing.get(key) != value:
                raise SystemExit("restore journal launcher transition changed unrelated evidence")
document = {
    **stable,
    "phase": phase,
    "recordedAt": existing.get("recordedAt", now) if existing else now,
    "updatedAt": now,
    "cleanBackupIntentAt": clean_intent,
    "cleanBackupEvidenceFile": clean_file,
    "cleanBackupEvidenceSha256": clean_file_sha,
    "cleanBackupFilename": clean_filename,
    "cleanBackupSha256": clean_sha,
    "restoreEvidenceFile": restore_record,
    "restoreEvidenceSha256": restore_record_sha,
    "launcherOperationToken": None if incoming_launcher is None else incoming_launcher[0],
    "launcherPreviousImageId": None if incoming_launcher is None else incoming_launcher[1],
    "launcherReplacementImageId": None if incoming_launcher is None else incoming_launcher[2],
    "launcherCommand": None if incoming_launcher is None else incoming_launcher[3],
    "launcherConfigurationFile": None if incoming_launcher is None else incoming_launcher[4],
    "launcherConfigurationSha256": None if incoming_launcher is None else incoming_launcher[5],
    "launcherRestorePhase": None if incoming_launcher is None else incoming_launcher[6],
}
with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False, encoding="utf-8") as target:
    json.dump(document, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
    temporary = pathlib.Path(target.name)
temporary.chmod(0o600)
os.replace(temporary, path)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  restore_phase="${next_phase}"
}

launcher_journal_unarmed() {
  [[ -z ${launcher_operation_token} && -z ${launcher_previous_image_id} && -z ${launcher_replacement_image_id} && -z ${launcher_operation_command} &&
     -z ${launcher_configuration_file} && -z ${launcher_configuration_sha256} && -z ${launcher_restore_phase} ]]
}

prove_launcher_selected_config() {
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ ${launcher_configuration_file} == "${production_config}" || ${launcher_configuration_file} == "${restore_config}" ]] || return 1
  [[ ${launcher_configuration_sha256} =~ ^[0-9a-f]{64}$ && ${launcher_restore_phase} == "${restore_phase}" ]] || return 1
  [[ -L /var/discourse/containers/app.yml ]] || return 1
  [[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${launcher_configuration_file}" ]] || return 1
  [[ "$(sha256sum -- "${launcher_configuration_file}" | awk '{print $1}')" == "${launcher_configuration_sha256}" ]]
}

arm_launcher_journal() {
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ ${launcher_previous_image_id} == - || ${launcher_previous_image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ -z ${launcher_replacement_image_id} ]] || return 1
  [[ ${launcher_operation_command} == bootstrap || ${launcher_operation_command} == start || ${launcher_operation_command} == restart || ${launcher_operation_command} == rebuild || ${launcher_operation_command} == destroy ]] || return 1
  [[ -z ${launcher_configuration_file} && -z ${launcher_configuration_sha256} && -z ${launcher_restore_phase} ]] || return 1
  launcher_configuration_file="$(readlink -f -- /var/discourse/containers/app.yml)" || return 1
  [[ ${launcher_configuration_file} == "${production_config}" || ${launcher_configuration_file} == "${restore_config}" ]] || return 1
  launcher_configuration_sha256="$(sha256sum -- "${launcher_configuration_file}" | awk '{print $1}')" || return 1
  [[ ${launcher_configuration_sha256} =~ ^[0-9a-f]{64}$ ]] || return 1
  launcher_restore_phase="${restore_phase}"
  write_restore_journal "${restore_phase}" \
    "${clean_backup_evidence:--}" "${clean_backup_evidence_sha256:--}" \
    "${clean_backup_filename:--}" "${clean_backup_sha256:--}" \
    "${restore_evidence:--}" "${restore_evidence_sha256:--}"
}

bind_launcher_replacement_image() {
  local replacement="$1"
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ ${replacement} =~ ^sha256:[0-9a-f]{64}$ && ${replacement} != "${launcher_previous_image_id}" ]] || return 1
  if [[ -n ${launcher_replacement_image_id} ]]; then
    [[ ${launcher_replacement_image_id} == "${replacement}" ]]
    return
  fi
  launcher_replacement_image_id="${replacement}"
  if ! write_restore_journal "${restore_phase}" \
      "${clean_backup_evidence:--}" "${clean_backup_evidence_sha256:--}" \
      "${clean_backup_filename:--}" "${clean_backup_sha256:--}" \
      "${restore_evidence:--}" "${restore_evidence_sha256:--}"; then
    launcher_replacement_image_id=""
    return 1
  fi
}

retire_launcher_journal() {
  local retained_token="${launcher_operation_token}"
  local retained_image="${launcher_previous_image_id}"
  local retained_replacement_image="${launcher_replacement_image_id}"
  local retained_command="${launcher_operation_command}"
  local retained_configuration="${launcher_configuration_file}"
  local retained_configuration_sha="${launcher_configuration_sha256}"
  local retained_phase="${launcher_restore_phase}"
  launcher_marked_processes_absent || return 1
  launcher_processes_absent || return 1
  prove_launcher_selected_config || return 1
  launcher_operation_token=""
  launcher_previous_image_id=""
  launcher_replacement_image_id=""
  launcher_operation_command=""
  launcher_configuration_file=""
  launcher_configuration_sha256=""
  launcher_restore_phase=""
  if ! write_restore_journal "${restore_phase}" \
      "${clean_backup_evidence:--}" "${clean_backup_evidence_sha256:--}" \
      "${clean_backup_filename:--}" "${clean_backup_sha256:--}" \
      "${restore_evidence:--}" "${restore_evidence_sha256:--}"; then
    launcher_operation_token="${retained_token}"
    launcher_previous_image_id="${retained_image}"
    launcher_replacement_image_id="${retained_replacement_image}"
    launcher_operation_command="${retained_command}"
    launcher_configuration_file="${retained_configuration}"
    launcher_configuration_sha256="${retained_configuration_sha}"
    launcher_restore_phase="${retained_phase}"
    return 1
  fi
}

advance_restore_phase() {
  launcher_journal_unarmed || return 1
  write_restore_journal "$1" \
    "${clean_backup_evidence:--}" "${clean_backup_evidence_sha256:--}" \
    "${clean_backup_filename:--}" "${clean_backup_sha256:--}" \
    "${restore_evidence:--}" "${restore_evidence_sha256:--}"
}

ensure_recovered_member_marker() {
  if [[ ${source_member_rollout} == false ]]; then
    [[ ${current_member_marker_file} == - && ${current_member_marker_sha} == - && ! -e ${member_marker} && ! -L ${member_marker} ]]
    return
  fi
  readarray -t marker_contract < <(python3 -B - "${member_marker}" "${current_evidence}" "${backup_evidence}" "${commit}" "${configuration}" "${source_member_rollout_sha}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import sys

marker = pathlib.Path(sys.argv[1])
current_path = pathlib.Path(sys.argv[2])
backup_path = pathlib.Path(sys.argv[3])
commit = sys.argv[4]
configuration = sys.argv[5]
source_marker_sha = sys.argv[6]
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", configuration) or not re.fullmatch(r"[0-9a-f]{64}", source_marker_sha):
    raise SystemExit("disaster member marker identity is malformed")
backup_meta = backup_path.lstat()
if not stat.S_ISREG(backup_meta.st_mode) or stat.S_ISLNK(backup_meta.st_mode) or backup_meta.st_uid != 0 or backup_meta.st_mode & 0o077:
    raise SystemExit("disaster backup evidence is unsafe")
backup_sha = hashlib.sha256(backup_path.read_bytes()).hexdigest()
stable = {
    "repositoryCommit": commit,
    "productionConfigurationSha256": configuration,
    "disasterRecoveryBackupEvidenceFile": backup_path.name,
    "disasterRecoveryBackupEvidenceSha256": backup_sha,
    "sourceMemberRolloutMarkerSha256": source_marker_sha,
    "destructiveRestorePermanentlyDisabled": True,
}
candidate = marker.parent / f".{marker.name}.disaster-partial"
if marker.exists() or marker.is_symlink():
    metadata = marker.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("recovered member marker is unsafe")
    document = json.loads(marker.read_text(encoding="utf-8"))
    if set(document) != set(stable) | {"finalizedAt"} or any(document.get(key) != value for key, value in stable.items()) or not isinstance(document.get("finalizedAt"), str) or not document["finalizedAt"].endswith("Z"):
        raise SystemExit("recovered member marker differs")
else:
    if candidate.exists() or candidate.is_symlink():
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
            raise SystemExit("recovered member marker partial is unsafe")
        candidate.unlink()
    document = dict(stable)
    document["finalizedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(document, target, sort_keys=True)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.link(candidate, marker, follow_symlinks=False)
    directory = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        candidate.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)
marker_sha = hashlib.sha256(marker.read_bytes()).hexdigest()
current = json.loads(current_path.read_text(encoding="utf-8"))
if current.get("repositoryCommit") != commit or current.get("productionConfigurationSha256") != configuration or current.get("discourseConnectEnabled") is not False:
    raise SystemExit("current release differs during member marker recovery")
existing_file = current.get("memberRolloutMarkerFile")
existing_sha = current.get("memberRolloutMarkerSha256")
if (existing_file, existing_sha) not in {(None, None), ("member-rollout-enabled", marker_sha)}:
    raise SystemExit("current member marker binding conflicts")
current["memberRolloutMarkerFile"] = "member-rollout-enabled"
current["memberRolloutMarkerSha256"] = marker_sha
with tempfile.NamedTemporaryFile("w", dir=current_path.parent, prefix=f".{current_path.name}.", delete=False, encoding="utf-8") as target:
    json.dump(current, target, sort_keys=True)
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
    temporary = pathlib.Path(target.name)
temporary.chmod(0o600)
os.replace(temporary, current_path)
descriptor = os.open(current_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(current_path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(marker_sha)
PY
  ) || return 1
  [[ ${#marker_contract[@]} -eq 1 && ${marker_contract[0]} =~ ^[0-9a-f]{64}$ ]] || return 1
  current_member_marker_file=member-rollout-enabled
  current_member_marker_sha="${marker_contract[0]}"
}

clear_restore_journal() {
  [[ ${restore_phase} == event-committed ]] && launcher_journal_unarmed || return 1
  python3 -B - "${restore_journal}" <<'PY'
import json
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
if document.get("phase") != "event-committed" or any(document.get(key) is not None for key in (
    "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
    "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
)):
    raise SystemExit("restore journal still has an active launcher authority")
path.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

publish_restore_terminal() {
  python3 -B - "${restore_terminal}" "${commit}" "${configuration}" "${backup_evidence}" \
    "${clean_backup_evidence}" "${clean_backup_evidence_sha256}" "${clean_backup_filename}" \
    "${clean_backup_sha256}" "${restore_evidence}" "${restore_evidence_sha256}" "${disaster_restore}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
def bind(value, expected):
    candidate = pathlib.Path(value)
    metadata = candidate.lstat()
    if not candidate.is_absolute() or not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise SystemExit("completed restore input is unsafe")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if expected is not None and digest != expected:
        raise SystemExit("completed restore input digest differs")
    return str(candidate), digest
tested_file, tested_sha = bind(sys.argv[4], None)
clean_file, clean_sha = bind(sys.argv[5], sys.argv[6])
restore_file, restore_sha = bind(sys.argv[9], sys.argv[10])
if not re.fullmatch(r"[0-9a-f]{40}", sys.argv[2]) or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[3]) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", sys.argv[7]) or ".." in sys.argv[7] or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[8]):
    raise SystemExit("completed restore identity is malformed")
document = {
    "schemaVersion": 1,
    "phase": "complete",
    "restoreMode": "clean-target-disaster" if sys.argv[11] == "true" else "disposable-rehearsal",
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "testedBackupEvidenceFile": tested_file,
    "testedBackupEvidenceSha256": tested_sha,
    "cleanBackupEvidenceFile": clean_file,
    "cleanBackupEvidenceSha256": clean_sha,
    "cleanBackupFilename": sys.argv[7],
    "cleanBackupSha256": sys.argv[8],
    "restoreEvidenceFile": restore_file,
    "restoreEvidenceSha256": restore_sha,
}
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536:
        raise SystemExit("completed restore record is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if existing == document:
        raise SystemExit(0)
with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False, encoding="utf-8") as target:
    json.dump(document, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
    temporary = pathlib.Path(target.name)
temporary.chmod(0o600)
os.replace(temporary, path)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

record_event() {
  local status="$1"
  local evidence_sha="${2:--}"
  [[ ${status} == started || ${status} == passed || ${status} == failed ]] || return 1
  [[ ${evidence_sha} == - || ${evidence_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
    --path "${logs_root}/events.log" --operation restore-rehearsal --status "${status}" \
    --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
    --field "evidence_sha256=${evidence_sha}" >/dev/null
}
record_event started || fail "Protected restore event evidence could not be initialized."
if [[ -z ${restore_phase} ]]; then
  write_restore_journal prepared || fail "Restore transaction could not be durably pre-armed."
fi
if [[ ${historical_adoption} == true ]]; then
  python3 -B "${historical_helper}" begin-restore --receipt "${historical_receipt}" \
    --journal "${historical_journal}" \
    --confirmation "BEGIN HISTORICAL MOCHIRII FORUMS RESTORE"
  python3 -B "${historical_helper}" verify --receipt "${historical_receipt}" \
    --journal "${historical_journal}" --require-phase restore-started >/dev/null
fi

remaining_operation_seconds() {
  local requested="$1"
  local now
  local remaining
  [[ ${requested} =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  now="$(date +%s)"
  remaining=$((operation_started_epoch + launcher_cumulative_budget_seconds - now))
  (( remaining >= 60 )) || return 1
  (( requested <= remaining )) || requested="${remaining}"
  printf '%s\n' "${requested}"
}

activate_config() {
  local target="$1"
  launcher_journal_unarmed || return 1
  ln -sfn -- "${target}" /var/discourse/containers/app.yml.next
  mv -Tf -- /var/discourse/containers/app.yml.next /var/discourse/containers/app.yml
  python3 -B - /var/discourse/containers <<'PY'
import os
import sys
descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

run_launcher() {
  local label="$1"
  local launcher_status=0
  local bounded_seconds
  local candidate_operation_token
  local candidate_previous_image_id
  local preexisting_operation_inventory
  local requested_command
  shift
  [[ $# -eq 2 && ${2:-} == app ]] || return 1
  if [[ -n ${launcher_operation_token} ]]; then
    reconcile_launcher_failure || return 1
  elif ! launcher_journal_unarmed; then
    runtime_survivor_unproved=true
    printf '%s\n' "CRITICAL: Restore launcher journal state is incomplete." >&2
    return 1
  elif [[ -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ]] || ! launcher_processes_absent; then
    runtime_survivor_unproved=true
    printf '%s\n' "CRITICAL: Restore found launcher residue without a durable operation identity." >&2
    return 1
  fi
  [[ ! -e ${launcher_bootstrap_cid} && ! -L ${launcher_bootstrap_cid} ]] || return 1
  launcher_processes_absent || return 1
  requested_command="${1:-}"
  [[ ${requested_command} == bootstrap || ${requested_command} == start || ${requested_command} == restart || ${requested_command} == rebuild || ${requested_command} == destroy ]] || return 1
  if ! timeout --signal=TERM --kill-after=5s 90 bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums restore launcher refused drifted runtime assets." >&2
    return 1
  fi
  if ! timeout --signal=TERM --kill-after=5s 90 bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh" >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums restore launcher refused unsealed deployment source." >&2
    reconcile_launcher_failure || true
    return 1
  fi
  candidate_operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${candidate_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  candidate_previous_image_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
  [[ -z ${candidate_previous_image_id} || ${candidate_previous_image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ -n ${candidate_previous_image_id} ]] || candidate_previous_image_id=-
  preexisting_operation_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
    --filter "label=mochirii.forums.operation=${candidate_operation_token}" --format '{{.ID}}' 2>/dev/null)" || return 1
  [[ -z ${preexisting_operation_inventory} ]] || return 1
  bounded_seconds="$(remaining_operation_seconds "${launcher_timeout_seconds}")" || {
    printf '%s\n' "Mochirii Forums cumulative restore launcher budget is exhausted." >&2
    reconcile_launcher_failure || true
    return 1
  }
  launcher_operation_token="${candidate_operation_token}"
  launcher_previous_image_id="${candidate_previous_image_id}"
  launcher_operation_command="${requested_command}"
  active_operation_kind="launcher"
  if ! arm_launcher_journal; then
    printf '%s\n' "Mochirii Forums restore launcher authority could not be durably armed." >&2
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  (exec 200>&- 201>&-; exec env "MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=${launcher_operation_token}" \
    timeout --signal=TERM --kill-after=30s "${bounded_seconds}" \
    bash -c 'cd /var/discourse && exec ./launcher "$@"' bash "$@" \
      --docker-args "--label=mochirii.forums.operation=${launcher_operation_token}") >/dev/null 2>&1 &
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || launcher_status=$?
  active_bounded_pid=""
  if (( launcher_status != 0 )); then
    printf '%s\n' "Mochirii Forums restore launcher operation failed; raw launcher output was suppressed." >&2
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  if ! reconcile_launcher_operation success; then
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  if ! bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1; then
    printf '%s\n' "Mochirii Forums restore launcher produced an untrusted runtime-asset mount." >&2
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  if ! retire_launcher_journal; then
    printf '%s\n' "Mochirii Forums restore launcher terminal proof could not retire its durable authority." >&2
    reconcile_launcher_failure || true
    active_operation_kind=""
    return 1
  fi
  active_operation_kind=""
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

run_container_command() {
  local label="$1"
  local inner_seconds="$2"
  local process_marker="$3"
  local command_status=0
  local operation_token
  local outer_seconds
  local output=/dev/null
  shift 3
  [[ ${label} =~ ^[a-z-]{1,32}$ && ${inner_seconds} =~ ^[1-9][0-9]{0,4}$ && ${process_marker} != *$'\n'* ]] || return 1
  if [[ ${1:-} == --output ]]; then
    [[ $# -ge 3 ]] || return 1
    output="$2"
    shift 2
    [[ ${output} == "${evidence_root}/"* && -f ${output} && ! -L ${output} && "$(stat -c '%U:%G %a' "${output}")" == "root:root 600" ]] || return 1
  fi
  outer_seconds="$(remaining_operation_seconds "$((inner_seconds + 30))")" || return 1
  if (( outer_seconds < inner_seconds + 30 )); then
    inner_seconds=$((outer_seconds - 30))
  fi
  operation_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  [[ ${operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  active_operation_token="${operation_token}"
  active_operation_kind="container"
  (exec 200>&- 201>&-; exec timeout --signal=TERM --kill-after=10s "${outer_seconds}" docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app \
    timeout --signal=TERM --kill-after=15s "${inner_seconds}" "$@" \
    >"${output}" 2>/dev/null) &
  active_bounded_pid=$!
  wait "${active_bounded_pid}" || command_status=$?
  active_bounded_pid=""
  if ! container_operation_absent "${operation_token}"; then
    active_operation_token=""
    if ! stop_app_safely; then
      runtime_survivor_unproved=true
      printf '%s\n' "CRITICAL: Restore in-container process termination could not be verified." >&2
    fi
    active_operation_kind=""
    return 1
  fi
  active_operation_token=""
  if (( command_status == 124 || command_status == 137 || command_status == 143 )); then
    if ! stop_app_safely; then
      runtime_survivor_unproved=true
      printf '%s\n' "CRITICAL: Timed-out restore operation could not prove an application stop." >&2
    fi
    active_operation_kind=""
    return 1
  fi
  active_operation_kind=""
  (( command_status == 0 ))
}

disable_restore_safely() {
  run_container_command disable-restore 300 "discourse disable_restore" discourse disable_restore &&
    run_container_command verify-restore-disabled 300 "SiteSetting.allow_restore" bash -lc \
      '/usr/local/bin/rails runner "raise unless SiteSetting.allow_restore == false"'
}

prove_restore_containment() {
  local port_bindings
  [[ -L /var/discourse/containers/app.yml ]] || return 1
  [[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${restore_config}" ]] || return 1
  port_bindings="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{json .HostConfig.PortBindings}}' app 2>/dev/null)" || return 1
  [[ ${port_bindings} == '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]}' ]] || return 1
  if run_container_command verify-restore-environment 300 "MOCHIRII_REPOSITORY_COMMIT" bash -lc \
      'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1" && test "$DISCOURSE_DISABLE_EMAILS" = yes && test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = false' \
      bash "${commit}" &&
    run_container_command verify-restore-setting 300 "SiteSetting.allow_restore" bash -lc \
      '/usr/local/bin/rails runner "raise unless SiteSetting.allow_restore == false"'; then
    return 0
  fi
  return 1
}

stop_app_safely() {
  local inventory
  local running
  timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app >/dev/null 2>&1 || true
  if running="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --format '{{.State.Running}}' app 2>/dev/null)"; then
    [[ ${running} == false ]]
    return
  fi
  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || return 1
  [[ -z ${inventory} ]]
}

remove_launcher_cid_safely() {
  local bootstrap_id=""
  local bootstrap_inventory=""
  local bootstrap_token=""
  [[ -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ]] || return 0
  if [[ ! -f ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} || "$(stat -c '%U:%G %a' "${launcher_bootstrap_cid}" 2>/dev/null)" != "root:root 600" || "$(stat -c '%s' "${launcher_bootstrap_cid}" 2>/dev/null)" -gt 128 ]]; then
    return 1
  fi
  IFS= read -r bootstrap_id <"${launcher_bootstrap_cid}" || true
  if [[ -n ${bootstrap_id} ]]; then
    [[ ${bootstrap_id} =~ ^[0-9a-f]{64}$ ]] || return 1
    bootstrap_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc --filter "id=${bootstrap_id}" --format '{{.ID}}' 2>/dev/null)" || return 1
    [[ -z ${bootstrap_inventory} || ${bootstrap_inventory} == "${bootstrap_id}" ]] || return 1
    if [[ -n ${bootstrap_inventory} ]]; then
      bootstrap_token="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{ index .Config.Labels "mochirii.forums.operation" }}' "${bootstrap_id}" 2>/dev/null)" || return 1
      [[ ${bootstrap_token} == "${launcher_operation_token}" ]] || return 1
      timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 "${bootstrap_id}" >/dev/null 2>&1 || true
      timeout --signal=TERM --kill-after=5s 45 docker rm --force "${bootstrap_id}" >/dev/null 2>&1 || true
      bootstrap_inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc --filter "id=${bootstrap_id}" --format '{{.ID}}' 2>/dev/null)" || return 1
      [[ -z ${bootstrap_inventory} ]] || return 1
    fi
  fi
  python3 -B - "${launcher_bootstrap_cid}" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

launcher_processes_absent() {
  timeout --signal=TERM --kill-after=5s 15 bash -c \
    'ps -eo args 2>/dev/null | awk '\''index($0, "." "/launcher") || index($0, "app_bootstrap" ".cid") { found = 1 } END { exit(found ? 1 : 0) }'\'' >/dev/null'
}

control_launcher_marked_processes() {
  local mode="$1"
  [[ ${mode} == absent || ${mode} == terminate ]] || return 1
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  timeout --signal=TERM --kill-after=5s 15 python3 -B - "${mode}" "${launcher_operation_token}" <<'PY'
import os
import pathlib
import re
import signal
import sys
import time

mode, token = sys.argv[1:]
if mode not in {"absent", "terminate"} or re.fullmatch(r"[0-9a-f]{32}", token) is None:
    raise SystemExit(2)
marker = b"MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=" + token.encode("ascii")


def parent_pid(pid):
    try:
        fields = pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
    except (FileNotFoundError, ProcessLookupError):
        return 0
    for field in fields:
        if field.startswith("PPid:"):
            value = field.split()
            if len(value) == 2 and value[1].isdigit():
                return int(value[1])
            break
    raise RuntimeError(f"could not resolve parent process {pid}")


safe_processes = set()
candidate = os.getpid()
while candidate > 0 and candidate not in safe_processes:
    safe_processes.add(candidate)
    candidate = parent_pid(candidate)


def is_marked(pid):
    try:
        fields = pathlib.Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    except (FileNotFoundError, ProcessLookupError):
        return False
    return marker in fields


def marked_processes():
    result = []
    for entry in pathlib.Path("/proc").iterdir():
        if entry.name.isdigit():
            pid = int(entry.name)
            if pid not in safe_processes and is_marked(pid):
                result.append(pid)
    return sorted(result)


def signal_marked(processes, operation_signal):
    for pid in processes:
        if pid in safe_processes or not is_marked(pid):
            continue
        try:
            os.kill(pid, operation_signal)
        except ProcessLookupError:
            pass


if mode == "absent":
    raise SystemExit(1 if marked_processes() else 0)

for operation_signal, duration in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 3.0)):
    deadline = time.monotonic() + duration
    stable_absence = 0
    while time.monotonic() < deadline:
        processes = marked_processes()
        if processes:
            stable_absence = 0
            signal_marked(processes, operation_signal)
        else:
            stable_absence += 1
            if stable_absence >= 5:
                raise SystemExit(0)
        time.sleep(0.1)
raise SystemExit(1 if marked_processes() else 0)
PY
}

launcher_marked_processes_absent() {
  control_launcher_marked_processes absent
}

terminate_launcher_marked_processes() {
  control_launcher_marked_processes terminate && launcher_marked_processes_absent
}

launcher_image_id_absent() {
  local target="$1"
  local inventory=""
  local identity=""
  [[ ${target} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --all --quiet --no-trunc 2>/dev/null)" || return 1
  while IFS= read -r identity; do
    [[ -n ${identity} ]] || continue
    [[ ${identity} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    [[ ${identity} != "${target}" ]] || return 1
  done <<<"${inventory}"
}

reconcile_launcher_image() {
  local expected_id="${launcher_previous_image_id}"
  local current_id=""
  local durable_replacement=""
  local stable=0
  local attempts=0
  [[ ${expected_id} == - ]] && expected_id=""
  [[ -z ${expected_id} || ${expected_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  while (( attempts < 30 && stable < 5 )); do
    current_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
    [[ -z ${current_id} || ${current_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    durable_replacement="${launcher_replacement_image_id}"
    [[ -z ${durable_replacement} || ( ${durable_replacement} =~ ^sha256:[0-9a-f]{64}$ && ${durable_replacement} != "${expected_id}" ) ]] || return 1
    if [[ -n ${current_id} && ${current_id} != "${expected_id}" ]]; then
      if [[ -z ${durable_replacement} ]]; then
        bind_launcher_replacement_image "${current_id}" || return 1
        durable_replacement="${launcher_replacement_image_id}"
      fi
      [[ ${current_id} == "${durable_replacement}" ]] || return 1
      timeout --signal=TERM --kill-after=5s 30 docker image rm --force local_discourse/app >/dev/null 2>&1 || return 1
      current_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
      [[ -z ${current_id} ]] || return 1
    fi
    if [[ -n ${durable_replacement} ]] && ! launcher_image_id_absent "${durable_replacement}"; then
      timeout --signal=TERM --kill-after=5s 30 docker image rm --force "${durable_replacement}" >/dev/null 2>&1 || return 1
      launcher_image_id_absent "${durable_replacement}" || return 1
    fi
    current_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
    [[ -z ${current_id} || ${current_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    if [[ -n ${expected_id} && -z ${current_id} ]]; then
      timeout --signal=TERM --kill-after=5s 30 docker image inspect "${expected_id}" >/dev/null 2>&1 || return 1
      timeout --signal=TERM --kill-after=5s 30 docker image tag "${expected_id}" local_discourse/app >/dev/null 2>&1 || return 1
      current_id="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
    fi
    if [[ ${current_id} == "${expected_id}" ]] && { [[ -z ${durable_replacement} ]] || launcher_image_id_absent "${durable_replacement}"; }; then
      stable=$((stable + 1))
    else
      stable=0
    fi
    attempts=$((attempts + 1))
    (( stable >= 5 )) || sleep 1
  done
  (( stable >= 5 ))
}

reconcile_launcher_operation() {
  local outcome="$1"
  local inventory=""
  local app_state=""
  local app_image=""
  local current_image=""
  local container_id=""
  local container_name=""
  local stable=0
  local attempts=0
  [[ ${outcome} == success || ${outcome} == failure ]] || return 1
  [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ ${launcher_previous_image_id} == - || ${launcher_previous_image_id} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ ${launcher_operation_command} == bootstrap || ${launcher_operation_command} == start || ${launcher_operation_command} == restart || ${launcher_operation_command} == rebuild || ${launcher_operation_command} == destroy ]] || return 1
  if [[ ${outcome} == failure ]]; then
    terminate_launcher_marked_processes || return 1
  fi
  launcher_marked_processes_absent || return 1
  launcher_processes_absent || return 1
  prove_launcher_selected_config || return 1
  if [[ ${outcome} == success && ( -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ) ]]; then
    return 1
  fi
  if [[ ${outcome} == failure ]]; then
    remove_launcher_cid_safely || return 1
    inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
      --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}} {{.Names}}' 2>/dev/null)" || return 1
    while IFS=' ' read -r container_id container_name; do
      [[ -n ${container_id} ]] || continue
      [[ ${container_id} =~ ^[0-9a-f]{64}$ && ${container_name} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || return 1
      timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 "${container_id}" >/dev/null 2>&1 || true
      timeout --signal=TERM --kill-after=5s 45 docker rm --force "${container_id}" >/dev/null 2>&1 || true
    done <<<"${inventory}"
    while (( attempts < 30 && stable < 5 )); do
      inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
        --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}}' 2>/dev/null)" || return 1
      if [[ -z ${inventory} ]]; then stable=$((stable + 1)); else stable=0; fi
      attempts=$((attempts + 1))
      (( stable >= 5 )) || sleep 1
    done
    (( stable >= 5 )) || return 1
    reconcile_launcher_image || return 1
    launcher_marked_processes_absent || return 1
    launcher_processes_absent
    return
  fi
  inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --no-trunc \
    --filter "label=mochirii.forums.operation=${launcher_operation_token}" --format '{{.ID}} {{.Names}}' 2>/dev/null)" || return 1
  case "${launcher_operation_command}" in
    start|rebuild) [[ ${inventory} =~ ^[0-9a-f]{64}[[:space:]]app$ ]] || return 1 ;;
    bootstrap|restart|destroy) [[ -z ${inventory} ]] || return 1 ;;
    *) return 1 ;;
  esac
  if [[ ${launcher_operation_command} == start || ${launcher_operation_command} == rebuild || ${launcher_operation_command} == restart ]]; then
    app_state="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" || return 1
    [[ ${app_state} == true ]] || return 1
  elif [[ ${launcher_operation_command} == destroy ]]; then
    inventory="$(timeout --signal=TERM --kill-after=5s 15 docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || return 1
    [[ -z ${inventory} ]] || return 1
  fi
  current_image="$(timeout --signal=TERM --kill-after=5s 15 docker image ls --quiet --no-trunc local_discourse/app 2>/dev/null)" || return 1
  [[ -z ${current_image} || ${current_image} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  case "${launcher_operation_command}" in
    bootstrap|rebuild) [[ ${current_image} =~ ^sha256:[0-9a-f]{64}$ ]] || return 1 ;;
    start|restart|destroy)
      if [[ ${launcher_previous_image_id} == - ]]; then
        [[ -z ${current_image} ]] || return 1
      else
        [[ ${current_image} == "${launcher_previous_image_id}" ]] || return 1
      fi
      ;;
  esac
  if [[ ${launcher_operation_command} == start || ${launcher_operation_command} == rebuild || ${launcher_operation_command} == restart ]]; then
    app_image="$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.Image}}' app 2>/dev/null)" || return 1
    [[ ${app_image} == "${current_image}" ]] || return 1
  fi
  launcher_marked_processes_absent || return 1
  launcher_processes_absent
}

reconcile_launcher_failure() {
  if [[ ${launcher_operation_token} =~ ^[0-9a-f]{32}$ ]]; then
    if ! reconcile_launcher_operation failure; then
      runtime_survivor_unproved=true
      printf '%s\n' "CRITICAL: Restore launcher container, process, or image reconciliation is unproved." >&2
      return 1
    fi
  else
    launcher_journal_unarmed && [[ ! -e ${launcher_bootstrap_cid} && ! -L ${launcher_bootstrap_cid} ]] || { runtime_survivor_unproved=true; return 1; }
    launcher_processes_absent || { runtime_survivor_unproved=true; return 1; }
  fi
  if ! stop_app_safely; then
    runtime_survivor_unproved=true
    return 1
  fi
  if [[ -n ${launcher_operation_token} ]] && ! retire_launcher_journal; then
    runtime_survivor_unproved=true
    printf '%s\n' "CRITICAL: Restore launcher terminal reconciliation could not retire its durable authority." >&2
    return 1
  fi
  return 0
}

on_exit() {
  local status=$?
  local failure_state_proved=false
  trap - EXIT
  [[ -z ${clean_backup_candidate} || ! -f ${clean_backup_candidate} ]] || rm -f -- "${clean_backup_candidate}"
  [[ -z ${clean_inventory_candidate} || ! -f ${clean_inventory_candidate} ]] || rm -f -- "${clean_inventory_candidate}"
  [[ -z ${clean_inventory_after_candidate} || ! -f ${clean_inventory_after_candidate} ]] || rm -f -- "${clean_inventory_after_candidate}"
  [[ -z ${clean_dr_payload} || ! -f ${clean_dr_payload} ]] || rm -f -- "${clean_dr_payload}"
  [[ -z ${clean_dr_result} || ! -f ${clean_dr_result} ]] || rm -f -- "${clean_dr_result}"
  if [[ ${status} -ne 0 && ${isolated} == true && ${restore_success} == false ]]; then
    if [[ ${runtime_survivor_unproved} == true ]]; then
      printf '%s\n' "CRITICAL: Restore process termination is unproved; disablement, rebuild, and public reopen are blocked." >&2
    else
      disable_restore_safely || printf '%s\n' "Restore disablement failed before containment; raw output was discarded." >&2
      if activate_config "${restore_config}" &&
        run_launcher containment rebuild app &&
        disable_restore_safely &&
        prove_restore_containment; then
        failure_state_proved=true
        printf '%s\n' "Restore containment is active and verified." >&2
      else
        if stop_app_safely; then
          failure_state_proved=true
          printf '%s\n' "Restore containment could not be proved; the application was stopped." >&2
        else
          printf '%s\n' "CRITICAL: Restore containment and application stop could not be verified; public ingress must remain closed." >&2
        fi
      fi
    fi
    if [[ ${failure_state_proved} == true ]]; then
      printf '%s\n' "Restore failed; exact containment or an application stop was verified." >&2
    else
      printf '%s\n' "CRITICAL: Restore failed without a proved containment state; public ingress must remain externally closed." >&2
    fi
  fi
  if [[ ${status} -ne 0 && ${restore_success} == false ]]; then
    record_event failed || true
  fi
  exit "${status}"
}
trap on_exit EXIT

handle_operation_signal() {
  local kind="${active_operation_kind}"
  trap - HUP INT TERM
  terminate_active_group
  if [[ ${kind} == launcher ]]; then
    reconcile_launcher_failure || true
  elif [[ ${kind} == container ]]; then
    if ! stop_app_safely; then
      runtime_survivor_unproved=true
      printf '%s\n' "CRITICAL: Interrupted restore operation could not prove an application stop." >&2
    fi
  fi
  exit 124
}
trap handle_operation_signal HUP INT TERM

isolated=true
if [[ -n ${launcher_operation_token} ]]; then
  reconcile_launcher_failure || fail "Interrupted restore launcher state could not be reconciled from its durable journal; the journal was retained."
  [[ -z ${launcher_operation_token} ]] || fail "Interrupted restore launcher authority survived terminal reconciliation."
fi
if phase_before production-reopening; then
  if phase_before isolating; then
    advance_restore_phase isolating || fail "Restore isolation intent could not be committed."
  fi
  activate_config "${restore_config}"
  run_launcher restore-resume rebuild app || fail "Restore containment rebuild failed."
  disable_restore_safely || fail "Disposable restore did not begin with restore disabled."
  prove_restore_containment || fail "Disposable restore containment did not match the exact loopback, full-mail, login, and restore-state contract."
  if phase_before isolated; then
    advance_restore_phase isolated || fail "Verified restore isolation could not be committed."
  fi

  if phase_before data-restored; then
    if phase_before restoring; then
      advance_restore_phase restoring || fail "Destructive restore intent could not be committed."
    fi
    # Re-read the exact remote object through the application immediately before
    # the destructive restore and bind both origin and CDN denial to protected evidence.
    run_container_command verify-backup-object 1800 "verify-backup.rb" bash -lc \
      'export MOCHIRII_EXPECTED_BACKUP_FILENAME="$1" MOCHIRII_EXPECTED_BACKUP_SHA256="$2" MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_BASE64="$3"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"' \
      bash "${backup_filename}" "${backup_sha256}" "${normal_upload_inventory_base64}" || fail "The remote backup object or its normal-upload inventory changed before restore."
    run_container_command enable-restore 300 "discourse enable_restore" discourse enable_restore || fail "Restore enablement failed; raw runtime output was suppressed."
    run_container_command restore-backup 5400 "discourse restore --location s3" discourse restore --location s3 "${backup_filename}" || fail "Application restore failed; raw runtime output was suppressed."
    disable_restore_safely || fail "Restore disablement failed; raw runtime output was discarded."
    advance_restore_phase data-restored || fail "Restored-data commit point could not be sealed."
  fi

  if phase_before verified-restored; then
    run_container_command verify-restored-data 900 "verify-restored-backup.rb" bash -lc 'if [[ "$1" != - ]]; then export MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256="$1"; fi; export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2" MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-restored-backup.rb"' bash "${recovery_upload_state_sha256}" "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" || fail "Restored data validation failed."
    run_launcher restored-restart restart app || fail "Restored restart failed."
    run_container_command verify-restored-restart 900 "verify-restored-backup.rb" bash -lc 'if [[ "$1" != - ]]; then export MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256="$1"; fi; export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2" MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-restored-backup.rb"' bash "${recovery_upload_state_sha256}" "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" || fail "Restored restart validation failed."
    run_launcher restored-rebuild rebuild app || fail "Restored rebuild failed."
    run_container_command verify-restored-rebuild 900 "verify-restored-backup.rb" bash -lc 'if [[ "$1" != - ]]; then export MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256="$1"; fi; export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2" MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-restored-backup.rb"' bash "${recovery_upload_state_sha256}" "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" || fail "Restored rebuild validation failed."
    disable_restore_safely || fail "Restore disablement failed after rebuild."
    prove_restore_containment || fail "Restore containment changed after the supported rebuild."
    advance_restore_phase verified-restored || fail "Restored runtime verification could not be committed."
  fi

  if phase_before fixture-cleaned; then
    if phase_before cleaning-fixture; then
      advance_restore_phase cleaning-fixture || fail "Restored fixture cleanup intent could not be committed."
    fi
    if [[ ${recovery_upload_fixture} == true ]]; then
      run_container_command cleanup-restored-upload 600 "prepare-backup-marker.rb cleanup" bash -lc 'export MOCHIRII_RECOVERY_UPLOAD_ACTION=cleanup MOCHIRII_RECOVERY_UPLOAD_STATE_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-backup-marker.rb"' bash "${recovery_upload_state_base64}" || fail "Restored recovery-upload cleanup failed."
      run_container_command verify-clean-upload-contained 600 "prepare-backup-marker.rb verify-clean" bash -lc 'export MOCHIRII_RECOVERY_UPLOAD_ACTION=verify-clean MOCHIRII_RECOVERY_UPLOAD_STATE_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-backup-marker.rb"' bash "${recovery_upload_state_base64}" || fail "Restored recovery-upload absence could not be proved."
    else
      run_container_command verify-clean-upload-contained 600 "verify-restored-backup.rb" bash -lc 'export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$1" MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$2"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-restored-backup.rb"' bash "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" || fail "Fixture-free restored upload identity could not be re-proved."
    fi
    advance_restore_phase fixture-cleaned || fail "Restored fixture cleanup could not be committed."
  fi
fi

ensure_recovered_member_marker || fail "Recovered member-rollout safety marker could not be proved."
if phase_before member-marker-committed; then
  advance_restore_phase member-marker-committed || fail "Recovered member-rollout safety boundary could not be committed."
fi

if phase_before clean-backup-committed; then
  if phase_before clean-backup-creating; then
    advance_restore_phase clean-backup-creating || fail "Final clean backup intent could not be committed."
  fi
  if [[ ${recovery_upload_fixture} == true ]]; then
    run_container_command verify-clean-upload 600 "prepare-backup-marker.rb verify-clean" bash -lc 'export MOCHIRII_RECOVERY_UPLOAD_ACTION=verify-clean MOCHIRII_RECOVERY_UPLOAD_STATE_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-backup-marker.rb"' bash "${recovery_upload_state_base64}" || fail "Recovery-upload cleanup could not be re-proved before the final clean backup."
  fi
  clean_inventory_candidate="$(mktemp "${evidence_root}/.clean-upload-inventory-${commit}-${configuration}.XXXXXXXX.json")"
  chmod 0600 "${clean_inventory_candidate}"
  run_container_command capture-clean-upload-inventory 600 "verify-backup.rb inventory" --output "${clean_inventory_candidate}" bash -lc 'export MOCHIRII_BACKUP_INVENTORY_ONLY=true; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"' || fail "Final clean normal-upload inventory could not be captured."
  clean_inventory_base64="$(python3 -B - "${clean_inventory_candidate}" <<'PY'
import base64
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_bytes()
if not 1 <= len(payload) <= 2048:
    raise SystemExit("clean inventory output exceeds its bound")
document = json.loads(payload)
if set(document) != {"normalUploadInventoryCount", "normalUploadInventorySha256"}:
    raise SystemExit("clean inventory schema differs")
count = document["normalUploadInventoryCount"]
digest = document["normalUploadInventorySha256"]
if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 10000:
    raise SystemExit("clean inventory count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
    raise SystemExit("clean inventory digest is malformed")
canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
if payload != canonical:
    raise SystemExit("clean inventory output is not canonical")
print(base64.b64encode(canonical).decode("ascii"))
PY
)" || fail "Final clean normal-upload inventory is malformed."
  [[ ${#clean_inventory_base64} -le 4096 && ${clean_inventory_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Final clean normal-upload inventory encoding is malformed."
  clean_backup_candidate="$(mktemp "${evidence_root}/.clean-backup-${commit}-${configuration}.XXXXXXXX.json")"
  chmod 0600 "${clean_backup_candidate}"
  run_container_command inspect-clean-backup 600 "verify-backup.rb" --output "${clean_backup_candidate}" bash -lc 'export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"' bash "${clean_inventory_base64}" || fail "Latest backup inspection failed before the final clean backup."
  clean_backup_disposition="$(python3 -B - "${clean_backup_candidate}" "${restore_journal}" "${backup_filename}" "${backup_sha256}" "${clean_backup_filename:--}" "${clean_backup_sha256:--}" <<'PY'
import datetime
import json
import pathlib
import re
import sys

candidate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
journal = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
filename = candidate.get("filename")
digest = candidate.get("sha256")
if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", filename) or ".." in filename:
    raise SystemExit("latest backup filename is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
    raise SystemExit("latest backup digest is malformed")
expected_name = None if sys.argv[5] == "-" else sys.argv[5]
expected_sha = None if sys.argv[6] == "-" else sys.argv[6]
if (expected_name is None) != (expected_sha is None):
    raise SystemExit("recorded clean backup identity is incomplete")
if expected_name is not None and (filename != expected_name or digest != expected_sha):
    raise SystemExit("recorded clean backup identity changed")
if filename == sys.argv[3]:
    if expected_name is not None:
        raise SystemExit("recorded clean backup still names the tested backup")
    if digest != sys.argv[4]:
        raise SystemExit("tested backup object was replaced")
    print("CREATE")
    raise SystemExit(0)
if journal.get("phase") != "clean-backup-creating":
    raise SystemExit("clean backup adoption requires the exact intent phase")
try:
    intent = datetime.datetime.fromisoformat(str(journal["cleanBackupIntentAt"]).replace("Z", "+00:00"))
    modified = datetime.datetime.fromisoformat(str(candidate["lastModified"]).replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("clean backup adoption timestamp is malformed") from error
now = datetime.datetime.now(datetime.timezone.utc)
if intent.tzinfo is None or modified.tzinfo is None or modified < intent.replace(microsecond=0) or modified > now + datetime.timedelta(minutes=5):
    raise SystemExit("latest backup is outside the exact clean-backup transaction window")
print("ADOPT")
PY
)" || fail "Final clean backup recovery disposition is ambiguous."
  if [[ ${clean_backup_disposition} == CREATE ]]; then
    run_container_command create-clean-backup 2400 "discourse backup" discourse backup || fail "Final clean application backup failed; raw runtime output was suppressed."
    run_container_command verify-clean-backup 600 "verify-backup.rb" --output "${clean_backup_candidate}" bash -lc 'export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"' bash "${clean_inventory_base64}" || fail "Final clean backup validation failed; raw runtime output was suppressed."
    python3 -B - "${clean_backup_candidate}" "${restore_journal}" "${backup_filename}" <<'PY'
import datetime
import json
import pathlib
import re
import sys

candidate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
journal = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
filename = candidate.get("filename")
digest = candidate.get("sha256")
if filename == sys.argv[3] or not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", filename) or ".." in filename:
    raise SystemExit("clean backup did not advance the remote object identity")
if not re.fullmatch(r"[0-9a-f]{64}", str(digest)) or journal.get("phase") != "clean-backup-creating":
    raise SystemExit("clean backup transaction binding differs")
intent = datetime.datetime.fromisoformat(str(journal["cleanBackupIntentAt"]).replace("Z", "+00:00"))
modified = datetime.datetime.fromisoformat(str(candidate["lastModified"]).replace("Z", "+00:00"))
now = datetime.datetime.now(datetime.timezone.utc)
if intent.tzinfo is None or modified.tzinfo is None or modified < intent.replace(microsecond=0) or modified > now + datetime.timedelta(minutes=5):
    raise SystemExit("clean backup is outside the exact transaction window")
PY
  elif [[ ${clean_backup_disposition} != ADOPT ]]; then
    fail "Final clean backup recovery discriminator is malformed."
  fi
  clean_inventory_after_candidate="$(mktemp "${evidence_root}/.clean-upload-inventory-after-${commit}-${configuration}.XXXXXXXX.json")"
  chmod 0600 "${clean_inventory_after_candidate}"
  run_container_command reverify-clean-inventory 600 "verify-backup.rb inventory" --output "${clean_inventory_after_candidate}" bash -lc 'export MOCHIRII_BACKUP_INVENTORY_ONLY=true; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-backup.rb"' || fail "Final backup normal-upload inventory could not be re-read."
  cmp --silent -- "${clean_inventory_candidate}" "${clean_inventory_after_candidate}" || fail "Final backup changed the bounded normal-upload inventory."
  if [[ ${recovery_upload_fixture} == true ]]; then
    run_container_command reverify-clean-upload 600 "prepare-backup-marker.rb verify-clean" bash -lc 'export MOCHIRII_RECOVERY_UPLOAD_ACTION=verify-clean MOCHIRII_RECOVERY_UPLOAD_STATE_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-backup-marker.rb"' bash "${recovery_upload_state_base64}" || fail "Final backup did not preserve recovery-upload cleanup."
  else
    run_container_command reverify-clean-upload 600 "verify-restored-backup.rb" bash -lc 'export MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$1" MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$2"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-restored-backup.rb"' bash "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" || fail "Final backup did not preserve fixture-free restored upload identity."
  fi
  readarray -t clean_remote_contract < <(python3 -B - "${clean_backup_candidate}" <<'PY'
import datetime
import json
import pathlib
import re
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
filename = document.get("filename")
digest = document.get("sha256")
if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz", filename) or ".." in filename:
    raise SystemExit("clean backup filename is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
    raise SystemExit("clean backup digest is malformed")
try:
    modified = datetime.datetime.fromisoformat(str(document["lastModified"]).replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("clean backup timestamp is malformed") from error
if modified.tzinfo is None:
    raise SystemExit("clean backup timestamp lacks a time zone")
print(filename)
print(digest)
print(modified.astimezone(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
PY
  ) || fail "Final clean backup identity is malformed."
  [[ ${#clean_remote_contract[@]} -eq 3 ]] || fail "Final clean backup identity is incomplete."
  clean_backup_filename="${clean_remote_contract[0]}"
  clean_backup_sha256="${clean_remote_contract[1]}"
  clean_timestamp="${clean_remote_contract[2]}"
  advance_restore_phase clean-backup-creating || fail "Final clean backup object identity could not be committed before evidence publication."
  clean_backup_evidence="${evidence_root}/${commit}-${configuration}-${clean_timestamp}-backup.json"
  readarray -t clean_backup_contract < <(python3 -B - "${clean_backup_candidate}" "${clean_backup_evidence}" "${commit}" "${configuration}" "${production_config}" "${restore_config}" "/opt/mochirii/forums/runtime-assets/${commit}/mochirii-theme.zip" "/opt/mochirii/forums/runtime-assets/${commit}/mochirii-email-metadata-plugin.rb" "${release_record}" "${current_member_marker_file}" "${current_member_marker_sha}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys

candidate = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2])
document = json.loads(candidate.read_text(encoding="utf-8"))
if document.get("repositoryCommit") != sys.argv[3]:
    raise SystemExit("clean backup release differs")
if document.get("privateAdminRetrievalUrlPresent") is not True or document.get("anonymousRetrievalDenied") is not True or document.get("anonymousCdnRetrievalDenied") is not True or document.get("backupPrefix") != "backups/":
    raise SystemExit("clean backup privacy evidence differs")
if document.get("size", 0) <= 0 or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("sha256", ""))):
    raise SystemExit("clean backup integrity evidence differs")
inventory_count = document.get("normalUploadInventoryCount")
inventory_sha = document.get("normalUploadInventorySha256")
if not isinstance(inventory_count, int) or isinstance(inventory_count, bool) or not 0 <= inventory_count <= 10000:
    raise SystemExit("clean backup normal-upload count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(inventory_sha)):
    raise SystemExit("clean backup normal-upload digest is malformed")
def digest(value):
    return hashlib.sha256(pathlib.Path(value).read_bytes()).hexdigest()
release = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
if release.get("repositoryCommit") != sys.argv[3] or release.get("productionConfigurationSha256") != sys.argv[4]:
    raise SystemExit("clean backup release evidence differs")
marker_file = None if sys.argv[10] == "-" else sys.argv[10]
marker_sha = None if sys.argv[11] == "-" else sys.argv[11]
if (marker_file is None) != (marker_sha is None) or (marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha))):
    raise SystemExit("clean backup member marker binding differs")
document.update(
    {
        "schemaVersion": 3,
        "productionConfigurationSha256": sys.argv[4],
        "restoreConfigurationSha256": digest(sys.argv[6]),
        "themeArchiveSha256": digest(sys.argv[7]),
        "mailMetadataPluginSha256": digest(sys.argv[8]),
        "releaseEvidenceFile": pathlib.Path(sys.argv[9]).name,
        "releaseEvidenceSha256": digest(sys.argv[9]),
        "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
        "discourseRevision": "badad7b0456a628e578bc48b9f8c1259422b5d58",
        "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
        "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
        "discourseConnectEnabled": False,
        "memberRolloutMarkerFile": marker_file,
        "memberRolloutMarkerSha256": marker_sha,
        "recoveryUploadIncluded": False,
        "recoveryUploadState": None,
        "recoveryUploadStateSha256": None,
        "recoveryUploadDeletedAfterBackup": False,
    }
)
candidate.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
candidate.chmod(0o600)
descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
print(document["filename"])
print(document["sha256"])
PY
) || fail "Final clean backup evidence could not be published."
[[ ${#clean_backup_contract[@]} -eq 2 ]] || fail "Final clean backup evidence is malformed."
[[ ${clean_backup_contract[0]} == "${clean_backup_filename}" && ${clean_backup_contract[1]} == "${clean_backup_sha256}" ]] || fail "Final clean backup evidence identity changed during publication."
[[ ${clean_backup_filename} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz$ && ${clean_backup_filename} != *..* ]] || fail "Final clean backup filename is malformed."
[[ ${clean_backup_sha256} =~ ^[0-9a-f]{64}$ ]] || fail "Final clean backup digest is malformed."
  clean_release_archive_inspection="$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
    "${release_dir}/scripts/historical-release-disaster-recovery.py" inspect \
    --archive "${release_archive}" --expected-commit "${commit}")" || fail "Final clean release archive identity inspection failed."
  [[ ${#clean_release_archive_inspection} -le 4096 ]] || fail "Final clean release archive identity exceeds its byte boundary."
  clean_dr_payload="$(mktemp "${evidence_root}/.clean-disaster-recovery-payload-${commit}-${configuration}.XXXXXXXX.json")"
  chmod 0600 "${clean_dr_payload}"
  python3 -B - "${clean_backup_candidate}" "${release_record}" "${release_archive}" "${clean_release_archive_inspection}" "${clean_dr_payload}" <<'PY'
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
    raise SystemExit("clean disaster-recovery release tuple is malformed")
if release.get("repositoryCommit") != commit or release.get("productionConfigurationSha256") != configuration:
    raise SystemExit("clean disaster-recovery release evidence tuple differs")
inspection_keys = {
    "schemaVersion", "repositoryCommit", "repositoryTree", "releaseArchiveSha256",
    "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
    "releaseArchiveSourceFormat", "containsSecrets", "containsSignedUrls",
    "ordinaryDeploymentRequiresCurrentMain", "historicalReleaseAdoptionScope",
}
if set(inspection) != inspection_keys or inspection.get("schemaVersion") != 1:
    raise SystemExit("clean disaster-recovery release archive inspection schema differs")
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
    raise SystemExit("clean disaster-recovery release archive identity differs")
archive_metadata = archive_path.stat(follow_symlinks=False)
if not archive_path.is_file() or archive_path.is_symlink() or archive_metadata.st_uid != 0 or archive_metadata.st_gid != 0 or archive_metadata.st_mode & 0o022:
    raise SystemExit("clean disaster-recovery release archive is unsafe")
if archive_metadata.st_size != archive_bytes or hashlib.sha256(archive_path.read_bytes()).hexdigest() != archive_sha:
    raise SystemExit("clean disaster-recovery release archive bytes differ")
for key, expected in (
    ("repositoryTree", repository_tree),
    ("releaseArchiveSha256", archive_sha),
    ("releaseArchiveBytes", archive_bytes),
    ("releaseArchiveContentManifestSha256", manifest_sha),
):
    if release.get(key) != expected:
        raise SystemExit(f"clean disaster-recovery release evidence {key} differs")
inventory_count = backup.get("normalUploadInventoryCount")
inventory_sha = backup.get("normalUploadInventorySha256")
if not isinstance(inventory_count, int) or isinstance(inventory_count, bool) or not 0 <= inventory_count <= 10000:
    raise SystemExit("clean disaster-recovery upload count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(inventory_sha)):
    raise SystemExit("clean disaster-recovery upload digest is malformed")
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
    "normalUploadInventoryCount": inventory_count,
    "normalUploadInventorySha256": inventory_sha,
    "releaseEvidenceFile": backup.get("releaseEvidenceFile"),
    "releaseEvidenceSha256": backup.get("releaseEvidenceSha256"),
    "releaseArchiveSha256": archive_sha,
    "releaseArchiveBytes": archive_bytes,
    "releaseArchiveContentManifestSha256": manifest_sha,
    "releaseArchiveObjectKey": f"backups/recovery-releases/archives/{archive_sha}.tar",
    "releaseArchiveSourceFormat": "git-archive-tar-v1",
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
authority = {
    "schemaVersion": 1,
    "repository": "Mochirii-Wushu/Mochirii-Forums",
    "repositoryCommit": commit,
    "repositoryTree": repository_tree,
    "productionConfigurationSha256": configuration,
    "releaseArchiveSha256": archive_sha,
    "releaseArchiveBytes": archive_bytes,
    "releaseArchiveContentManifestSha256": manifest_sha,
    "releaseArchiveObjectKey": document["releaseArchiveObjectKey"],
    "releaseArchiveSourceFormat": "git-archive-tar-v1",
    "containsSecrets": False,
    "containsSignedUrls": False,
    "ordinaryDeploymentRequiresCurrentMain": True,
    "historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
}
authority_payload = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
authority_sha = hashlib.sha256(authority_payload).hexdigest()
document["releaseSourceAuthorityObjectKey"] = f"backups/recovery-releases/authorities/{authority_sha}.json"
document["releaseSourceAuthoritySha256"] = authority_sha
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
with output.open("wb") as target:
    target.write(payload)
    target.flush()
    os.fsync(target.fileno())
os.chmod(output, 0o600, follow_symlinks=False)
PY
  clean_dr_payload_base64="$(base64 --wrap=0 -- "${clean_dr_payload}")"
  [[ ${#clean_dr_payload_base64} -le 65536 && ${clean_dr_payload_base64} =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail "Clean disaster-recovery evidence encoding is malformed."
  clean_dr_result="$(mktemp "${evidence_root}/.clean-disaster-recovery-result-${commit}-${configuration}.XXXXXXXX.json")"
  chmod 0600 "${clean_dr_result}"
  run_container_command publish-clean-recovery 600 "publish-disaster-recovery-evidence.rb" --output "${clean_dr_result}" bash -lc 'export MOCHIRII_DR_EVIDENCE_BASE64="$1"; /usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/publish-disaster-recovery-evidence.rb"' bash "${clean_dr_payload_base64}" || fail "Final clean disaster-recovery evidence publication failed."
  clean_backup_evidence_sha256="$(python3 -B - "${clean_backup_candidate}" "${clean_dr_payload}" "${clean_dr_result}" "${clean_backup_evidence}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys

backup_path = pathlib.Path(sys.argv[1])
payload_path = pathlib.Path(sys.argv[2])
result_path = pathlib.Path(sys.argv[3])
evidence = pathlib.Path(sys.argv[4])
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
    raise SystemExit("clean disaster-recovery publication result schema differs")
evidence_sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
if result.get("evidenceObjectKey") != f"backups/recovery-evidence/records/{evidence_sha}.json" or result.get("evidenceObjectSha256") != evidence_sha:
    raise SystemExit("clean disaster-recovery evidence object binding differs")
if result.get("pointerObjectKey") != "backups/recovery-evidence/current.json":
    raise SystemExit("clean disaster-recovery pointer object key differs")
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
    raise SystemExit("clean disaster-recovery pointer object digest differs")
if (
    result.get("releaseArchiveObjectKey") != payload["releaseArchiveObjectKey"]
    or result.get("releaseArchiveSha256") != payload["releaseArchiveSha256"]
    or result.get("releaseArchiveBytes") != payload["releaseArchiveBytes"]
    or result.get("releaseSourceAuthorityObjectKey") != payload["releaseSourceAuthorityObjectKey"]
    or result.get("releaseSourceAuthoritySha256") != payload["releaseSourceAuthoritySha256"]
):
    raise SystemExit("clean disaster-recovery release publication identity differs")
if not all(result.get(key) is True for key in (
    "immutableEvidencePublished", "immutableReleaseArchivePublished",
    "immutableReleaseSourceAuthorityPublished", "pointerSelected", "privateAclPassed",
)):
    raise SystemExit("clean disaster-recovery publication proof is incomplete")
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
        "finalCleanAfterRestore": True,
    }
)
backup_path.write_text(json.dumps(backup, sort_keys=True, indent=2) + "\n", encoding="utf-8")
backup_path.chmod(0o600)
descriptor = os.open(backup_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if evidence.exists() or evidence.is_symlink():
    metadata = evidence.lstat()
    if not evidence.is_file() or evidence.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or evidence.read_bytes() != backup_path.read_bytes():
        raise SystemExit("existing clean backup evidence differs")
    backup_path.unlink()
else:
    os.link(backup_path, evidence, follow_symlinks=False)
directory = os.open(evidence.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
    if backup_path.exists():
        backup_path.unlink()
    os.fsync(directory)
finally:
    os.close(directory)
print(hashlib.sha256(evidence.read_bytes()).hexdigest())
PY
)" || fail "Final clean local and off-host recovery evidence could not be committed."
  rm -f -- "${clean_dr_payload}" "${clean_dr_result}"
  clean_dr_payload=""
  clean_dr_result=""
  clean_backup_candidate=""
  [[ ${clean_backup_evidence_sha256} =~ ^[0-9a-f]{64}$ ]] || fail "Final clean backup evidence digest is malformed."
  advance_restore_phase clean-backup-committed || fail "Final clean backup commit point could not be sealed."
fi

if phase_before pointer-committed; then
python3 -B - "${backup_pointer}" "${clean_backup_evidence}" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2])
candidate = path.parent / f".{path.name}.partial"
if not evidence.is_file() or evidence.is_symlink():
    raise SystemExit("final clean backup evidence is unsafe")
if candidate.exists() or candidate.is_symlink():
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit("latest backup pointer partial is unsafe")
    candidate.unlink()
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    target.write(str(evidence) + "\n")
    target.flush()
    os.fsync(target.fileno())
os.replace(candidate, path)
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY

  advance_restore_phase pointer-committed || fail "Final clean backup pointer commit point could not be sealed."
fi

if phase_before production-reopened; then
  if phase_before production-reopening; then
    advance_restore_phase production-reopening || fail "Production reopen intent could not be committed."
  fi
  if [[ ${disaster_restore} == true ]]; then
    timeout --signal=TERM --kill-after=5s 45 python3 -B "${release_dir}/scripts/probe-website-forums-producer.py" disabled >/dev/null 2>&1 || fail "Website producer disablement changed before disaster-recovery reopen."
  fi
  activate_config "${production_config}"
  run_launcher production-reopen rebuild app || fail "Production reopen rebuild failed."
  verification_seconds="$(remaining_operation_seconds 600)" || fail "Production verification exceeded the cumulative restore deadline."
  timeout --signal=TERM --kill-after=10s "${verification_seconds}" bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" --restore-transaction >/dev/null 2>&1 || fail "Production verification after restore failed."
  advance_restore_phase production-reopened || fail "Production reopen could not be committed."
fi

if phase_before restore-evidence-committed; then
  readarray -t restore_identity < <(python3 -B - "${restore_journal}" "${clean_backup_evidence}" "${commit}" "${configuration}" <<'PY'
import datetime
import json
import pathlib
import re
import sys

journal = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
clean_name = pathlib.Path(sys.argv[2]).name
match = re.fullmatch(rf"{re.escape(sys.argv[3])}-{re.escape(sys.argv[4])}-([0-9]{{8}}T[0-9]{{6}}Z)-backup[.]json", clean_name)
if match is None:
    raise SystemExit("clean backup evidence filename is malformed")
try:
    recorded = datetime.datetime.fromisoformat(str(journal["recordedAt"]).replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("restore transaction timestamp is malformed") from error
if recorded.tzinfo is None:
    raise SystemExit("restore transaction timestamp lacks a time zone")
print(match.group(1))
print(recorded.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))
PY
  ) || fail "Restore evidence identity could not be derived durably."
  [[ ${#restore_identity[@]} -eq 2 ]] || fail "Restore evidence identity is incomplete."
  restore_evidence="${evidence_root}/${commit}-${configuration}-${restore_identity[0]}-restore.json"
  bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Runtime assets changed during restore verification."
  python3 - "${restore_evidence}" "${backup_evidence}" "${commit}" "${configuration}" "${production_config}" "${restore_config}" "/opt/mochirii/forums/runtime-assets/${commit}/mochirii-theme.zip" "/opt/mochirii/forums/runtime-assets/${commit}/mochirii-email-metadata-plugin.rb" "${release_record}" "${recovery_upload_state_sha256}" "${clean_backup_evidence}" "${clean_backup_evidence_sha256}" "${clean_backup_filename}" "${clean_backup_sha256}" "${current_member_marker_file}" "${current_member_marker_sha}" "${disaster_restore}" "${recovery_upload_fixture}" "${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}" "${restore_identity[1]}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import tempfile
import sys

backup = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
if digest(sys.argv[5]) != sys.argv[4]:
    raise SystemExit("Production configuration digest changed")
clean_evidence = pathlib.Path(sys.argv[11])
if not clean_evidence.is_file() or clean_evidence.is_symlink() or digest(clean_evidence) != sys.argv[12]:
    raise SystemExit("Final clean backup evidence differs")
clean_backup = json.loads(clean_evidence.read_text(encoding="utf-8"))
if clean_backup.get("filename") != sys.argv[13] or clean_backup.get("sha256") != sys.argv[14] or clean_backup.get("finalCleanAfterRestore") is not True:
    raise SystemExit("Final clean backup tuple differs")
recovery_fixture = {"true": True, "false": False}.get(sys.argv[18])
if recovery_fixture is None or backup.get("recoveryUploadIncluded") is not recovery_fixture:
    raise SystemExit("Tested backup recovery-upload mode differs")
recovery_sha = None if sys.argv[10] == "-" else sys.argv[10]
if recovery_fixture != (recovery_sha is not None):
    raise SystemExit("Restore recovery-upload binding is incomplete")
if backup.get("recoveryUploadStateSha256") != recovery_sha:
    raise SystemExit("Tested backup recovery-upload digest differs")
try:
    expected_inventory_count = int(sys.argv[19])
except ValueError as error:
    raise SystemExit("Tested normal-upload count is malformed") from error
expected_inventory_sha = sys.argv[20]
if backup.get("normalUploadInventoryCount") != expected_inventory_count or backup.get("normalUploadInventorySha256") != expected_inventory_sha:
    raise SystemExit("Tested normal-upload inventory differs")
clean_inventory_count = clean_backup.get("normalUploadInventoryCount")
clean_inventory_sha = clean_backup.get("normalUploadInventorySha256")
if not isinstance(clean_inventory_count, int) or isinstance(clean_inventory_count, bool) or not 0 <= clean_inventory_count <= 10000:
    raise SystemExit("Final clean normal-upload count is malformed")
if not re.fullmatch(r"[0-9a-f]{64}", str(clean_inventory_sha)):
    raise SystemExit("Final clean normal-upload digest is malformed")
if clean_backup.get("recoveryUploadIncluded") is not False or clean_backup.get("recoveryUploadState") is not None or clean_backup.get("recoveryUploadStateSha256") is not None:
    raise SystemExit("Final clean backup retained the recovery-upload fixture")
marker_file = None if sys.argv[15] == "-" else sys.argv[15]
marker_sha = None if sys.argv[16] == "-" else sys.argv[16]
if (marker_file is None) != (marker_sha is None):
    raise SystemExit("Restore member marker binding is incomplete")
if marker_file is not None and (marker_file != "member-rollout-enabled" or len(marker_sha) != 64):
    raise SystemExit("Restore member marker binding is malformed")
document = {
    "schemaVersion": 3,
    "recordedAt": sys.argv[21],
    "repositoryCommit": sys.argv[3],
    "productionConfigurationSha256": sys.argv[4],
    "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
    "discourseRevision": "badad7b0456a628e578bc48b9f8c1259422b5d58",
    "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
    "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
    "backupFilename": backup["filename"],
    "backupSha256": backup["sha256"],
    "releaseArchiveSha256": json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))["releaseArchiveSha256"],
    "restoreConfigurationSha256": digest(sys.argv[6]),
    "themeArchiveSha256": digest(sys.argv[7]),
    "mailMetadataPluginSha256": digest(sys.argv[8]),
    "releaseEvidenceFile": pathlib.Path(sys.argv[9]).name,
    "releaseEvidenceSha256": digest(sys.argv[9]),
    "discourseConnectEnabled": False,
    "memberRolloutMarkerFile": marker_file,
    "memberRolloutMarkerSha256": marker_sha,
    "anonymousBackupRetrievalDenied": True,
    "anonymousBackupCdnRetrievalDenied": True,
    "outboundMailSuppressed": True,
    "allMailDisabledDuringRestore": True,
    "databaseIntegrityPassed": True,
    "normalUploadRestorePassed": True,
    "recoveryUploadIncluded": recovery_fixture,
    "recoveryUploadStateSha256": recovery_sha,
    "testedNormalUploadInventoryCount": expected_inventory_count,
    "testedNormalUploadInventorySha256": expected_inventory_sha,
    "recoveryUploadCleanupPassed": True,
    "finalCleanBackupEvidenceFile": clean_evidence.name,
    "finalCleanBackupEvidenceSha256": sys.argv[12],
    "finalCleanBackupFilename": sys.argv[13],
    "finalCleanBackupSha256": sys.argv[14],
    "finalCleanNormalUploadInventoryCount": clean_inventory_count,
    "finalCleanNormalUploadInventorySha256": clean_inventory_sha,
    "finalCleanBackupMarkerAbsent": True,
    "sidekiqJobProcessingPassed": True,
    "restartPassed": True,
    "rebuildPassed": True,
    "productionVerificationPassed": True,
    "cleanTargetDisasterRestore": sys.argv[17] == "true",
}
path = pathlib.Path(sys.argv[1])
with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as target:
    target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
    target.flush()
    os.fsync(target.fileno())
    temporary = pathlib.Path(target.name)
temporary.chmod(0o600)
if path.exists() or path.is_symlink():
    metadata = path.lstat()
    if not path.is_file() or path.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or path.read_bytes() != temporary.read_bytes():
        raise SystemExit("existing restore evidence differs")
    temporary.unlink()
else:
    os.link(temporary, path, follow_symlinks=False)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
    if temporary.exists():
        temporary.unlink()
    os.fsync(directory)
finally:
    os.close(directory)
PY
  restore_evidence_sha256="$(sha256sum -- "${restore_evidence}" | awk '{print $1}')"
  [[ ${restore_evidence_sha256} =~ ^[0-9a-f]{64}$ ]] || fail "Restore evidence digest is malformed."
  advance_restore_phase restore-evidence-committed || fail "Restore evidence commit point could not be sealed."
fi

record_event passed "${restore_evidence_sha256}" || fail "Protected restore event evidence could not be completed."
if phase_before event-committed; then
  advance_restore_phase event-committed || fail "Restore terminal event commit point could not be sealed."
fi
publish_restore_terminal || fail "Completed restore state could not be durably published."
if [[ -e ${restore_journal} || -L ${restore_journal} ]]; then
  clear_restore_journal || fail "Completed restore transaction journal could not be retired."
fi
if [[ ${historical_adoption} == true ]]; then
  python3 -B "${historical_helper}" complete --receipt "${historical_receipt}" \
    --journal "${historical_journal}" --current-release "${current_evidence}" \
    --restore-terminal "${restore_terminal}" --clean-backup "${clean_backup_evidence}" \
    --backup-pointer "${backup_pointer}" \
    --confirmation "COMPLETE HISTORICAL MOCHIRII FORUMS RECOVERY"
  [[ ! -e ${historical_journal} && ! -L ${historical_journal} ]] || fail "Terminal historical adoption journal was not retired."
fi
restore_success=true
printf '%s\n' "Mochirii Forums disposable restore verified."
