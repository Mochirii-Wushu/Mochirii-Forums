#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "The stable verification wrapper must run as root."
[[ $# -eq 1 && $1 =~ ^[0-9a-f]{40}$ ]] || fail "Usage: mochirii-forums-verify EXPECTED_COMMIT"
commit="$1"
lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
pending_storage_cleanup="$(find /var/lib/mochirii/forums/evidence -maxdepth 1 -name '*-storage-cleanup-required.json' -print -quit 2>/dev/null || true)"
[[ -z ${pending_storage_cleanup} ]] || fail "Hosted storage cleanup remains blocked; runtime verification cannot pass."
current_evidence="/var/lib/mochirii/forums/current-release.json"
[[ -f ${current_evidence} && ! -L ${current_evidence} ]] || fail "Current release evidence is absent."
[[ "$(stat -c '%U:%G %a' "${current_evidence}")" == "root:root 600" ]] || fail "Current release evidence has unsafe ownership or mode."
readarray -t current_contract < <(python3 - "${current_evidence}" "${commit}" <<'PY'
import hashlib
import json
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
connect = document.get("discourseConnectEnabled")
marker_file = document.get("memberRolloutMarkerFile")
marker_sha = document.get("memberRolloutMarkerSha256")
if not isinstance(connect, bool) or (marker_file is None) != (marker_sha is None):
    raise SystemExit("activation evidence is malformed")
if marker_file is not None and (marker_file != "member-rollout-enabled" or not re.fullmatch(r"[0-9a-f]{64}", marker_sha)):
    raise SystemExit("member-rollout evidence is malformed")
release = json.loads(record.read_text(encoding="utf-8"))
release_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "repositoryTree",
    "releaseArchiveSha256", "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
    "discourseDockerRevision", "discourseRevision", "dockerManagerRevision",
    "baseImageDigest", "productionConfigurationSha256", "restoreConfigurationSha256",
    "containedActivationConfigurationSha256", "containedActivationPassed", "activationPhase",
    "themeArchiveSha256", "mailMetadataPluginSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256", "hostVerificationPassed", "storageEvidenceFile",
    "storageEvidenceSha256", "hostedStoragePassed", "storageRestartPersistencePassed",
    "storageRebuildPersistencePassed", "storageCleanupPassed",
}
if set(release) != release_keys or release.get("schemaVersion") != 2:
    raise SystemExit("release evidence schema differs")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(release.get("recordedAt", ""))):
    raise SystemExit("release evidence timestamp is malformed")
if (
    not re.fullmatch(r"[0-9a-f]{40}", str(release.get("repositoryTree", "")))
    or not isinstance(release.get("releaseArchiveBytes"), int)
    or isinstance(release.get("releaseArchiveBytes"), bool)
    or not 1 <= release["releaseArchiveBytes"] <= 67108864
    or not re.fullmatch(r"[0-9a-f]{64}", str(release.get("releaseArchiveContentManifestSha256", "")))
):
    raise SystemExit("release archive authority is malformed")
marker_transition_allowed = (
    marker_file == "member-rollout-enabled"
    and release.get("memberRolloutMarkerFile") is None
    and release.get("memberRolloutMarkerSha256") is None
)
if (
    release.get("repositoryCommit") != sys.argv[2]
    or release.get("productionConfigurationSha256") != value
    or release.get("discourseDockerRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b"
    or release.get("discourseRevision") != "cbf996f65aae3da1843224aa624bcd9a225931ac"
    or release.get("dockerManagerRevision") != "c008c3ca7fcc44775215843992e88190adb7b3bf"
    or release.get("baseImageDigest") != "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
    or release.get("discourseConnectEnabled") is not connect
    or (not marker_transition_allowed and release.get("memberRolloutMarkerFile") != marker_file)
    or (not marker_transition_allowed and release.get("memberRolloutMarkerSha256") != marker_sha)
):
    raise SystemExit("release evidence tuple differs")
if marker_transition_allowed:
    marker = path.parent / "member-rollout-enabled"
    if not marker.is_file() or marker.is_symlink() or marker.stat().st_uid != 0 or marker.stat().st_mode & 0o077 or hashlib.sha256(marker.read_bytes()).hexdigest() != marker_sha:
        raise SystemExit("member-rollout marker transition is unsafe")
    marker_document = json.loads(marker.read_text(encoding="utf-8"))
    common = {
        "repositoryCommit", "productionConfigurationSha256", "finalizedAt",
        "destructiveRestorePermanentlyDisabled",
    }
    if marker_document.get("repositoryCommit") != sys.argv[2] or marker_document.get("productionConfigurationSha256") != value or marker_document.get("destructiveRestorePermanentlyDisabled") is not True or not isinstance(marker_document.get("finalizedAt"), str) or not marker_document["finalizedAt"].endswith("Z"):
        raise SystemExit("member-rollout marker transition identity differs")
    standard = common | {"restoreEvidenceFile", "restoreEvidenceSha256"}
    disaster = common | {
        "disasterRecoveryBackupEvidenceFile", "disasterRecoveryBackupEvidenceSha256",
        "sourceMemberRolloutMarkerSha256",
    }
    if set(marker_document) == standard:
        evidence_name = marker_document.get("restoreEvidenceFile", "")
        evidence_sha = marker_document.get("restoreEvidenceSha256", "")
        expected_pattern = rf"{sys.argv[2]}-{value}-[0-9]{{8}}T[0-9]{{6}}Z-restore[.]json"
    elif set(marker_document) == disaster:
        evidence_name = marker_document.get("disasterRecoveryBackupEvidenceFile", "")
        evidence_sha = marker_document.get("disasterRecoveryBackupEvidenceSha256", "")
        expected_pattern = rf"{sys.argv[2]}-{value}-[0-9]{{8}}T[0-9]{{6}}Z-backup[.]json"
        if not re.fullmatch(r"[0-9a-f]{64}", str(marker_document.get("sourceMemberRolloutMarkerSha256", ""))):
            raise SystemExit("disaster member-rollout source marker is malformed")
    else:
        raise SystemExit("member-rollout marker transition schema differs")
    evidence_path = path.parent / "evidence" / evidence_name
    if not re.fullmatch(expected_pattern, evidence_name) or not evidence_path.is_file() or evidence_path.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", str(evidence_sha)) or hashlib.sha256(evidence_path.read_bytes()).hexdigest() != evidence_sha:
        raise SystemExit("member-rollout marker transition evidence differs")
expected_phase = "consumer-public-producer-pending" if connect else "consumer-disabled"
if release.get("containedActivationPassed") is not connect or release.get("activationPhase") != expected_phase:
    raise SystemExit("release activation phase differs")
if not re.fullmatch(r"[0-9a-f]{64}", str(release.get("releaseArchiveSha256", ""))):
    raise SystemExit("release archive digest is malformed")
activation_sha = release.get("containedActivationConfigurationSha256")
if connect:
    if not re.fullmatch(r"[0-9a-f]{64}", str(activation_sha or "")):
        raise SystemExit("contained activation configuration digest is malformed")
elif activation_sha is not None:
    raise SystemExit("disabled consumer retains contained activation evidence")
for key in ("restoreConfigurationSha256", "themeArchiveSha256", "mailMetadataPluginSha256", "storageEvidenceSha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", str(release.get(key, ""))):
        raise SystemExit("release evidence digest is malformed")
for key in (
    "hostVerificationPassed", "hostedStoragePassed", "storageRestartPersistencePassed",
    "storageRebuildPersistencePassed", "storageCleanupPassed",
):
    if release.get(key) is not True:
        raise SystemExit("release gate is not passed")
storage_name = f"{sys.argv[2]}-{value}-storage.json"
storage = path.parent / "evidence" / storage_name
if release.get("storageEvidenceFile") != storage_name or not storage.is_file() or storage.is_symlink():
    raise SystemExit("hosted storage evidence reference differs")
if storage.stat().st_uid != 0 or storage.stat().st_mode & 0o077:
    raise SystemExit("hosted storage evidence permissions are unsafe")
if hashlib.sha256(storage.read_bytes()).hexdigest() != release.get("storageEvidenceSha256"):
    raise SystemExit("hosted storage evidence digest differs")
storage_document = json.loads(storage.read_text(encoding="utf-8"))
storage_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "objectWriteReadPassed", "optimizedVariantPassed", "customHostnameOnlyPassed",
    "anonymousDirectRetrievalPassed", "anonymousListingDenied", "publicAclPassed",
    "restartPersistencePassed", "rebuildPersistencePassed", "databaseRowsDeleted",
    "primaryObjectsDeleted", "tombstonesDeleted",
}
if set(storage_document) != storage_keys or storage_document.get("schemaVersion") != 1:
    raise SystemExit("hosted storage evidence schema differs")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(storage_document.get("recordedAt", ""))):
    raise SystemExit("hosted storage evidence timestamp is malformed")
if storage_document.get("repositoryCommit") != sys.argv[2] or storage_document.get("productionConfigurationSha256") != value:
    raise SystemExit("hosted storage evidence tuple differs")
for key in storage_keys - {"schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256"}:
    if storage_document.get(key) is not True:
        raise SystemExit("hosted storage gate is not passed")
print(value)
print("true" if connect else "false")
print(marker_file or "-")
print(marker_sha or "-")
print(expected)
print(document.get("releaseEvidenceSha256"))
print(hashlib.sha256(path.read_bytes()).hexdigest())
PY
)
[[ ${#current_contract[@]} -eq 7 ]] || fail "Current release evidence is malformed."
configuration="${current_contract[0]}"
discourse_connect="${current_contract[1]}"
marker_file="${current_contract[2]}"
marker_sha="${current_contract[3]}"
release_record_name="${current_contract[4]}"
release_record_sha="${current_contract[5]}"
current_release_sha="${current_contract[6]}"
[[ ${release_record_sha} =~ ^[0-9a-f]{64}$ && ${current_release_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Current release evidence digest is malformed."
[[ ${marker_file} != - ]] || marker_file=""
[[ ${marker_sha} != - ]] || marker_sha=""
running_discourse_connect="$(timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'case "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" in true|false) printf "%s" "$DISCOURSE_ENABLE_DISCOURSE_CONNECT";; *) exit 1;; esac' 2>/dev/null)" || fail "Running DiscourseConnect flag is malformed."
[[ ${running_discourse_connect} == "${discourse_connect}" ]] || fail "Current activation evidence differs from the running container."
rollout_marker="/var/lib/mochirii/forums/member-rollout-enabled"
if [[ -n ${marker_file} ]]; then
  [[ -f ${rollout_marker} && ! -L ${rollout_marker} ]] || fail "Member-rollout marker referenced by current evidence is absent."
  [[ "$(stat -c '%U:%G %a' "${rollout_marker}")" == "root:root 600" ]] || fail "Member-rollout marker has unsafe ownership or mode."
  [[ "$(sha256sum -- "${rollout_marker}" | awk '{print $1}')" == "${marker_sha}" ]] || fail "Member-rollout marker digest differs from current evidence."
else
  [[ ! -e ${rollout_marker} ]] || fail "Unrecorded member-rollout marker is present."
fi
authentication_evidence_sha="-"
current_authentication=/var/lib/mochirii/forums/current-authentication.json
if [[ ${discourse_connect} == true ]]; then
  [[ -f ${current_authentication} && ! -L ${current_authentication} ]] || fail "Completed Website authentication evidence is absent."
  [[ "$(stat -c '%U:%G %a' "${current_authentication}")" == "root:root 600" ]] || fail "Current authentication evidence has unsafe ownership or mode."
  authentication_evidence_sha="$(python3 -B - "${current_authentication}" /var/lib/mochirii/forums/evidence /var/lib/mochirii/forums/operator-evidence "${commit}" "${configuration}" "${release_record_name}" "${release_record_sha}" "${current_release_sha}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

pointer_path = pathlib.Path(sys.argv[1])
evidence_root = pathlib.Path(sys.argv[2])
operator_root = pathlib.Path(sys.argv[3])
commit = sys.argv[4]
configuration = sys.argv[5]
release_name = sys.argv[6]
release_sha = sys.argv[7]
current_release_sha = sys.argv[8]
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
pointer_keys = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}
if set(pointer) != pointer_keys:
    raise SystemExit("current authentication evidence schema differs")
expected_name = f"{commit}-{configuration}-authentication-complete.json"
if (
    pointer.get("repositoryCommit") != commit
    or pointer.get("productionConfigurationSha256") != configuration
    or pointer.get("authenticationEvidenceFile") != expected_name
    or pointer.get("activationPhase") != "complete"
):
    raise SystemExit("authentication activation is not complete for the current release")
record_path = evidence_root / expected_name
if not record_path.is_file() or record_path.is_symlink():
    raise SystemExit("authentication evidence record is absent")
record_stat = record_path.stat()
if record_stat.st_uid != 0 or record_stat.st_mode & 0o077 or record_stat.st_size > 65536:
    raise SystemExit("authentication evidence record permissions are unsafe")
record_sha = hashlib.sha256(record_path.read_bytes()).hexdigest()
if pointer.get("authenticationEvidenceSha256") != record_sha:
    raise SystemExit("authentication evidence record digest differs")
record = json.loads(record_path.read_text(encoding="utf-8"))
record_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "releaseEvidenceFile", "releaseEvidenceSha256", "currentReleaseSha256",
    "pendingAuthenticationEvidenceFile", "pendingAuthenticationEvidenceSha256",
    "websiteEvidenceFile", "websiteEvidenceSha256", "websiteRepositoryCommit",
    "activationPhase", "websiteProducerEnabled", "producerFailClosedBeforeEnablePassed",
    "activeMemberAllowed", "inactiveMemberDenied", "unverifiedMemberDenied",
    "invalidSignatureDenied", "malformedRequestDenied", "expiredRequestDenied",
    "replayDenied", "alternateLoginDisabled", "callbackLogRedactionPassed",
    "callbackBrowserQueryScrubPassed", "callbackBrowserPrivateResponsePassed",
    "terminalHostVerificationPassed",
}
if set(record) != record_keys or record.get("schemaVersion") != 1:
    raise SystemExit("authentication evidence schema differs")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", str(record.get("recordedAt", ""))):
    raise SystemExit("authentication evidence timestamp is malformed")
if (
    record.get("repositoryCommit") != commit
    or record.get("productionConfigurationSha256") != configuration
    or record.get("releaseEvidenceFile") != release_name
    or record.get("releaseEvidenceSha256") != release_sha
    or record.get("currentReleaseSha256") != current_release_sha
    or record.get("activationPhase") != "complete"
    or not re.fullmatch(r"[0-9a-f]{40}", str(record.get("websiteRepositoryCommit", "")))
):
    raise SystemExit("authentication evidence tuple differs")
for key in {
    "websiteProducerEnabled", "producerFailClosedBeforeEnablePassed", "activeMemberAllowed",
    "inactiveMemberDenied", "unverifiedMemberDenied", "invalidSignatureDenied",
    "malformedRequestDenied", "expiredRequestDenied", "replayDenied",
    "alternateLoginDisabled", "callbackLogRedactionPassed",
    "callbackBrowserQueryScrubPassed", "callbackBrowserPrivateResponsePassed",
    "terminalHostVerificationPassed",
}:
    if record.get(key) is not True:
        raise SystemExit("authentication evidence contains an unpassed gate")
pending_name = f"{commit}-{configuration}-authentication-pending.json"
pending_path = evidence_root / pending_name
if (
    record.get("pendingAuthenticationEvidenceFile") != pending_name
    or not pending_path.is_file()
    or pending_path.is_symlink()
):
    raise SystemExit("protected pending authentication evidence reference differs")
pending_stat = pending_path.stat()
if pending_stat.st_uid != 0 or pending_stat.st_mode & 0o077 or pending_stat.st_size > 65536:
    raise SystemExit("protected pending authentication evidence permissions or size are unsafe")
pending_sha = hashlib.sha256(pending_path.read_bytes()).hexdigest()
if record.get("pendingAuthenticationEvidenceSha256") != pending_sha:
    raise SystemExit("protected pending authentication evidence digest differs")
pending = json.loads(pending_path.read_text(encoding="utf-8"))
pending_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "releaseEvidenceFile", "releaseEvidenceSha256", "currentReleaseSha256",
    "activationPhase", "websiteProducerDisabledProved", "containedActivationPassed",
    "publicForumsVerificationPassed",
}
if set(pending) != pending_keys or pending.get("schemaVersion") != 1:
    raise SystemExit("protected pending authentication evidence schema differs")
if (
    pending.get("repositoryCommit") != commit
    or pending.get("productionConfigurationSha256") != configuration
    or pending.get("releaseEvidenceFile") != release_name
    or pending.get("releaseEvidenceSha256") != release_sha
    or pending.get("currentReleaseSha256") != current_release_sha
    or pending.get("activationPhase") != "consumer-public-producer-pending"
):
    raise SystemExit("protected pending authentication evidence tuple differs")
for key in ("websiteProducerDisabledProved", "containedActivationPassed", "publicForumsVerificationPassed"):
    if pending.get(key) is not True:
        raise SystemExit("protected pending authentication evidence contains an unpassed gate")

website_name = f"{commit}-{configuration}-website-authentication.json"
website_path = operator_root / website_name
if record.get("websiteEvidenceFile") != website_name or not website_path.is_file() or website_path.is_symlink():
    raise SystemExit("protected Website evidence reference differs")
website_stat = website_path.stat()
if website_stat.st_uid != 0 or website_stat.st_mode & 0o077 or website_stat.st_size > 65536:
    raise SystemExit("protected Website evidence permissions or size are unsafe")
website_sha = hashlib.sha256(website_path.read_bytes()).hexdigest()
if record.get("websiteEvidenceSha256") != website_sha:
    raise SystemExit("protected Website evidence digest differs")
website = json.loads(website_path.read_text(encoding="utf-8"))
website_keys = {
    "schemaVersion", "recordedAt", "websiteRepositoryCommit", "forumsRepositoryCommit",
    "forumsProductionConfigurationSha256", "websiteProducerEnabled",
    "producerFailClosedBeforeEnablePassed", "activeMemberAllowed", "inactiveMemberDenied",
    "unverifiedMemberDenied", "invalidSignatureDenied", "malformedRequestDenied",
    "expiredRequestDenied", "replayDenied", "alternateLoginDisabled",
    "callbackLogRedactionPassed", "callbackBrowserQueryScrubPassed",
    "callbackBrowserPrivateResponsePassed",
}
if set(website) != website_keys or website.get("schemaVersion") != 1:
    raise SystemExit("protected Website evidence schema differs")
if (
    website.get("websiteRepositoryCommit") != record.get("websiteRepositoryCommit")
    or website.get("forumsRepositoryCommit") != commit
    or website.get("forumsProductionConfigurationSha256") != configuration
):
    raise SystemExit("protected Website evidence tuple differs")
for key in website_keys - {
    "schemaVersion", "recordedAt", "websiteRepositoryCommit", "forumsRepositoryCommit",
    "forumsProductionConfigurationSha256",
}:
    if website.get(key) is not True:
        raise SystemExit("protected Website evidence contains an unpassed gate")
print(record_sha)
PY
)" || fail "Completed Website authentication evidence is invalid."
  [[ ${authentication_evidence_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Completed Website authentication evidence digest is malformed."
  timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py enabled >/dev/null 2>&1 || fail "The Website authentication producer is not currently enabled."
elif [[ -e ${current_authentication} || -L ${current_authentication} ]]; then
  [[ -f ${current_authentication} && ! -L ${current_authentication} && "$(stat -c '%U:%G %a' "${current_authentication}")" == "root:root 600" ]] || fail "Stale authentication evidence is unsafe."
  python3 -B - "${current_authentication}" "${commit}" "${configuration}" <<'PY' >/dev/null
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(document) != {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}:
    raise SystemExit("stale authentication evidence schema differs")
if document.get("repositoryCommit") == sys.argv[2] and document.get("productionConfigurationSha256") == sys.argv[3]:
    raise SystemExit("disabled consumer retains matching authentication evidence")
PY
fi
release_dir="/opt/mochirii/forums/releases/${commit}"
[[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "Verified release directory is absent."
[[ "$(stat -c '%U:%G' "${release_dir}")" == "root:root" ]] || fail "Release ownership is invalid."
logs_root="/var/lib/mochirii/forums/logs"
install -d -m 0700 -o root -g root "${logs_root}"
record_event() {
  local status="$1"
  local evidence_sha="${authentication_evidence_sha:--}"
  [[ ${status} == started || ${status} == passed || ${status} == failed ]] || return 1
  [[ ${evidence_sha} == - || ${evidence_sha} =~ ^[0-9a-f]{64}$ ]] || return 1
  python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
    --path "${logs_root}/events.log" --operation verify --status "${status}" \
    --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
    --field "evidence_sha256=${evidence_sha}" >/dev/null
}
verify_success=false
on_exit() {
  local status=$?
  trap - EXIT
  if [[ ${status} -ne 0 && ${verify_success} == false ]]; then
    record_event failed || true
  fi
  exit "${status}"
}
trap on_exit EXIT
record_event started || fail "Protected verification event evidence could not be initialized."
if ! timeout --signal=TERM --kill-after=30s 480 bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" >/dev/null 2>&1; then
  fail "Mochirii Forums host verification failed; raw runtime output was suppressed."
fi
record_event passed || fail "Protected verification event evidence could not be completed."
verify_success=true
printf '%s\n' "Mochirii Forums protected host verification passed."
