#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Authentication finalization must run as root through the distinct operator boundary."
if [[ -n ${SUDO_USER:-} && ${SUDO_USER} != mochirii-forums-operator ]]; then
  fail "Authentication finalization is restricted to the distinct operator or provider console."
fi
[[ $# -eq 4 ]] || fail "Usage: mochirii-forums-finalize-authentication COMMIT CONFIGURATION_SHA256 WEBSITE_EVIDENCE_SHA256 'FINALIZE MOCHIRII FORUMS AUTHENTICATION'"
commit="$1"
configuration="$2"
website_evidence_sha="$3"
confirmation="$4"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Authentication finalization commit is malformed."
[[ ${configuration} =~ ^[0-9a-f]{64}$ ]] || fail "Authentication finalization configuration is malformed."
[[ ${website_evidence_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Website authentication evidence digest is malformed."
[[ ${confirmation} == "FINALIZE MOCHIRII FORUMS AUTHENTICATION" ]] || fail "Exact authentication finalization confirmation is required."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if python3 -B "${lock_helper}" assert-held --locks primary 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary -- /bin/bash "$0" "$@"
fi
state_root=/var/lib/mochirii/forums
evidence_root="${state_root}/evidence"
operator_evidence_root="${state_root}/operator-evidence"
for active_transaction in \
  "${state_root}/deployment-mutation.json" \
  "${state_root}/deployment-transaction.json" \
  "${state_root}/backup-transaction.json" \
  "${state_root}/restore-transaction.json"; do
  [[ ! -e ${active_transaction} && ! -L ${active_transaction} ]] || fail "Authentication finalization refuses an active protected host transaction."
done
[[ -z "$(find "${evidence_root}" -maxdepth 1 \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) -print -quit 2>/dev/null || true)" ]] || fail "Authentication finalization refuses unresolved hosted-storage cleanup."
current_release="${state_root}/current-release.json"
current_authentication="${state_root}/current-authentication.json"
website_evidence="${operator_evidence_root}/${commit}-${configuration}-website-authentication.json"
release_dir="/opt/mochirii/forums/releases/${commit}"
production_config="/var/discourse/containers/releases/${commit}/${configuration}/app.yml"
authentication_record="${evidence_root}/${commit}-${configuration}-authentication-complete.json"

for directory in "${evidence_root}" "${operator_evidence_root}"; do
  [[ -d ${directory} && ! -L ${directory} ]] || fail "Protected authentication evidence directory is absent."
  [[ "$(stat -c '%U:%G %a' "${directory}")" == "root:root 700" ]] || fail "Protected authentication evidence directory permissions differ."
done
[[ -d ${state_root} && ! -L ${state_root} && "$(stat -c '%U:%G %a' "${state_root}")" == "root:root 755" ]] || fail "Protected state-root traversal permissions differ."
for protected in "${current_release}" "${current_authentication}" "${website_evidence}"; do
  [[ -f ${protected} && ! -L ${protected} ]] || fail "Protected authentication evidence is absent."
  [[ "$(stat -c '%U:%G %a' "${protected}")" == "root:root 600" ]] || fail "Protected authentication evidence permissions differ."
  [[ "$(stat -c '%s' "${protected}")" -le 65536 ]] || fail "Protected authentication evidence exceeds its byte boundary."
done
[[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "The sealed Forums release is absent."
[[ -f ${production_config} && ! -L ${production_config} ]] || fail "The exact production configuration is absent."

readarray -t authentication_contract < <(python3 -B - "${current_release}" "${current_authentication}" "${website_evidence}" "${website_evidence_sha}" "${commit}" "${configuration}" "${authentication_record}" <<'PY'
import hashlib
import datetime
import json
import pathlib
import re
import sys

current_path = pathlib.Path(sys.argv[1])
authentication_pointer_path = pathlib.Path(sys.argv[2])
website_path = pathlib.Path(sys.argv[3])
expected_website_sha = sys.argv[4]
commit = sys.argv[5]
configuration = sys.argv[6]
complete_path = pathlib.Path(sys.argv[7])
current_bytes = current_path.read_bytes()
current = json.loads(current_bytes)
current_keys = {
    "repositoryCommit", "productionConfigurationSha256", "releaseEvidenceFile",
    "releaseEvidenceSha256", "discourseConnectEnabled", "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
if set(current) != current_keys:
    raise SystemExit("current release evidence schema differs")
if current.get("repositoryCommit") != commit or current.get("productionConfigurationSha256") != configuration:
    raise SystemExit("current release identity differs")
if current.get("discourseConnectEnabled") is not True:
    raise SystemExit("the central-login consumer is not enabled")
if current.get("memberRolloutMarkerFile") != "member-rollout-enabled" or not re.fullmatch(
    r"[0-9a-f]{64}", str(current.get("memberRolloutMarkerSha256", ""))
):
    raise SystemExit("member rollout evidence is incomplete")

release_name = current.get("releaseEvidenceFile", "")
if release_name != f"{commit}-{configuration}-release.json":
    raise SystemExit("release evidence filename differs")
release_path = current_path.parent / "evidence" / release_name
if not release_path.is_file() or release_path.is_symlink():
    raise SystemExit("release evidence is absent")
release_stat = release_path.stat()
if release_stat.st_uid != 0 or release_stat.st_mode & 0o077:
    raise SystemExit("release evidence permissions are unsafe")
release_sha = hashlib.sha256(release_path.read_bytes()).hexdigest()
if current.get("releaseEvidenceSha256") != release_sha:
    raise SystemExit("release evidence digest differs")
release = json.loads(release_path.read_text(encoding="utf-8"))
release_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "repositoryTree",
    "releaseArchiveSha256", "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
    "discourseDockerRevision", "discourseRevision", "dockerManagerRevision", "baseImageDigest",
    "productionConfigurationSha256", "restoreConfigurationSha256",
    "containedActivationConfigurationSha256", "containedActivationPassed", "activationPhase",
    "themeArchiveSha256", "mailMetadataPluginSha256", "discourseConnectEnabled",
    "memberRolloutMarkerFile", "memberRolloutMarkerSha256", "hostVerificationPassed",
    "storageEvidenceFile", "storageEvidenceSha256", "hostedStoragePassed",
    "storageRestartPersistencePassed", "storageRebuildPersistencePassed", "storageCleanupPassed",
}
if (
    set(release) != release_keys
    or release.get("schemaVersion") != 2
    or not re.fullmatch(r"[0-9a-f]{40}", str(release.get("repositoryTree", "")))
    or not re.fullmatch(r"[0-9a-f]{64}", str(release.get("releaseArchiveSha256", "")))
    or not isinstance(release.get("releaseArchiveBytes"), int)
    or isinstance(release.get("releaseArchiveBytes"), bool)
    or not 1 <= release["releaseArchiveBytes"] <= 67108864
    or not re.fullmatch(r"[0-9a-f]{64}", str(release.get("releaseArchiveContentManifestSha256", "")))
    or release.get("repositoryCommit") != commit
    or release.get("productionConfigurationSha256") != configuration
    or release.get("discourseConnectEnabled") is not True
    or release.get("containedActivationPassed") is not True
    or release.get("activationPhase") != "consumer-public-producer-pending"
):
    raise SystemExit("release is not awaiting protected Website authentication evidence")

pointer = json.loads(authentication_pointer_path.read_text(encoding="utf-8"))
pointer_keys = {
    "repositoryCommit", "productionConfigurationSha256", "authenticationEvidenceFile",
    "authenticationEvidenceSha256", "activationPhase",
}
pending_name = f"{commit}-{configuration}-authentication-pending.json"
if set(pointer) != pointer_keys or (
    pointer.get("repositoryCommit") != commit
    or pointer.get("productionConfigurationSha256") != configuration
    or pointer.get("activationPhase") not in {"consumer-public-producer-pending", "complete"}
):
    raise SystemExit("current authentication state is not an exact finalizable phase")
pointer_complete = pointer.get("activationPhase") == "complete"
if not pointer_complete and pointer.get("authenticationEvidenceFile") != pending_name:
    raise SystemExit("pending authentication pointer filename differs")
pending_path = current_path.parent / "evidence" / pending_name
if not pending_path.is_file() or pending_path.is_symlink():
    raise SystemExit("pending authentication evidence is absent")
pending_stat = pending_path.stat()
if pending_stat.st_uid != 0 or pending_stat.st_mode & 0o077 or pending_stat.st_size > 65536:
    raise SystemExit("pending authentication evidence permissions are unsafe")
pending_sha = hashlib.sha256(pending_path.read_bytes()).hexdigest()
if not pointer_complete and pointer.get("authenticationEvidenceSha256") != pending_sha:
    raise SystemExit("pending authentication evidence digest differs")
pending = json.loads(pending_path.read_text(encoding="utf-8"))
pending_keys = {
    "schemaVersion", "recordedAt", "repositoryCommit", "productionConfigurationSha256",
    "releaseEvidenceFile", "releaseEvidenceSha256", "currentReleaseSha256",
    "activationPhase", "websiteProducerDisabledProved", "containedActivationPassed",
    "publicForumsVerificationPassed",
}
if set(pending) != pending_keys or pending.get("schemaVersion") != 1:
    raise SystemExit("pending authentication evidence schema differs")
if (
    pending.get("repositoryCommit") != commit
    or pending.get("productionConfigurationSha256") != configuration
    or pending.get("releaseEvidenceFile") != release_name
    or pending.get("releaseEvidenceSha256") != release_sha
    or pending.get("currentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()
    or pending.get("activationPhase") != "consumer-public-producer-pending"
):
    raise SystemExit("pending authentication evidence tuple differs")
for key in ("websiteProducerDisabledProved", "containedActivationPassed", "publicForumsVerificationPassed"):
    if pending.get(key) is not True:
        raise SystemExit("pending authentication evidence contains an unpassed gate")

resume_complete = False
complete = None
if complete_path.exists() or complete_path.is_symlink():
    if not complete_path.is_file() or complete_path.is_symlink():
        raise SystemExit("existing authentication evidence is unsafe")
    complete_stat = complete_path.stat()
    if complete_stat.st_uid != 0 or complete_stat.st_mode & 0o077 or complete_stat.st_size > 65536:
        raise SystemExit("existing authentication evidence permissions are unsafe")
    complete = json.loads(complete_path.read_text(encoding="utf-8"))
    complete_keys = {
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
    if set(complete) != complete_keys or complete.get("schemaVersion") != 1:
        raise SystemExit("existing authentication evidence schema differs")
    expected_complete = {
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "releaseEvidenceFile": release_name,
        "releaseEvidenceSha256": release_sha,
        "currentReleaseSha256": hashlib.sha256(current_bytes).hexdigest(),
        "pendingAuthenticationEvidenceFile": pending_name,
        "pendingAuthenticationEvidenceSha256": pending_sha,
        "websiteEvidenceFile": website_path.name,
        "websiteEvidenceSha256": expected_website_sha,
        "activationPhase": "complete",
    }
    if any(complete.get(key) != value for key, value in expected_complete.items()):
        raise SystemExit("existing authentication evidence tuple differs")
    if not isinstance(complete.get("recordedAt"), str) or not complete["recordedAt"].endswith("Z"):
        raise SystemExit("existing authentication evidence timestamp is malformed")
    for key in complete_keys - set(expected_complete) - {"schemaVersion", "recordedAt", "websiteRepositoryCommit"}:
        if complete.get(key) is not True:
            raise SystemExit("existing authentication evidence contains an unpassed gate")
    resume_complete = True
    complete_sha = hashlib.sha256(complete_path.read_bytes()).hexdigest()
    if pointer_complete and (
        pointer.get("authenticationEvidenceFile") != complete_path.name
        or pointer.get("authenticationEvidenceSha256") != complete_sha
    ):
        raise SystemExit("completed authentication pointer differs from its sealed record")

if pointer_complete and not resume_complete:
    raise SystemExit("completed authentication pointer lacks its sealed record")

website_bytes = website_path.read_bytes()
if hashlib.sha256(website_bytes).hexdigest() != expected_website_sha:
    raise SystemExit("Website authentication evidence digest differs")
website = json.loads(website_bytes)
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
    raise SystemExit("Website authentication evidence schema differs")
recorded_text = str(website.get("recordedAt", ""))
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z", recorded_text):
    raise SystemExit("Website authentication evidence timestamp is malformed")
try:
    recorded = datetime.datetime.fromisoformat(recorded_text.removesuffix("Z") + "+00:00")
except ValueError as error:
    raise SystemExit("Website authentication evidence timestamp is invalid") from error
now = datetime.datetime.now(datetime.timezone.utc)
if not resume_complete and (recorded < now - datetime.timedelta(minutes=15) or recorded > now + datetime.timedelta(minutes=2)):
    raise SystemExit("Website authentication evidence is stale or future-dated")
if not re.fullmatch(r"[0-9a-f]{40}", str(website.get("websiteRepositoryCommit", ""))):
    raise SystemExit("Website authentication source commit is malformed")
if website.get("forumsRepositoryCommit") != commit or website.get("forumsProductionConfigurationSha256") != configuration:
    raise SystemExit("Website authentication evidence targets another Forums release")
if resume_complete and complete.get("websiteRepositoryCommit") != website.get("websiteRepositoryCommit"):
    raise SystemExit("existing authentication evidence Website source differs")
for key in website_keys - {
    "schemaVersion", "recordedAt", "websiteRepositoryCommit", "forumsRepositoryCommit",
    "forumsProductionConfigurationSha256",
}:
    if website.get(key) is not True:
        raise SystemExit("Website authentication evidence contains an unpassed gate")

print(release_name)
print(release_sha)
print(hashlib.sha256(current_bytes).hexdigest())
print(website.get("websiteRepositoryCommit"))
print(pending_name)
print(pending_sha)
if pointer_complete:
    print("resume-pointer-complete")
elif resume_complete:
    print("resume-complete")
else:
    print("create-complete")
PY
)
[[ ${#authentication_contract[@]} -eq 7 ]] || fail "Protected authentication evidence is malformed."
release_record_name="${authentication_contract[0]}"
release_record_sha="${authentication_contract[1]}"
current_release_sha="${authentication_contract[2]}"
website_commit="${authentication_contract[3]}"
pending_record_name="${authentication_contract[4]}"
pending_record_sha="${authentication_contract[5]}"
authentication_publication_mode="${authentication_contract[6]}"
for digest in "${release_record_sha}" "${current_release_sha}" "${pending_record_sha}"; do
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || fail "Protected authentication tuple contains a malformed digest."
done
[[ ${website_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Protected Website commit is malformed."
[[ ${authentication_publication_mode} == create-complete || ${authentication_publication_mode} == resume-complete || ${authentication_publication_mode} == resume-pointer-complete ]] || fail "Authentication publication mode is malformed."

[[ -L /var/discourse/containers/app.yml ]] || fail "The active Forums configuration is not versioned."
[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${production_config}" ]] || fail "The exact public production configuration is not active."
[[ "$(timeout --signal=TERM --kill-after=5s 15 docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == true ]] || fail "The Forums application is not running."
timeout --signal=TERM --kill-after=5s 30 docker exec app bash -lc 'test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = true && test "$DISCOURSE_DISABLE_EMAILS" = no' >/dev/null 2>&1 || fail "The running public authentication state differs."
timeout --signal=TERM --kill-after=5s 90 bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Runtime assets differ before authentication finalization."
timeout --signal=TERM --kill-after=30s 600 bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" >/dev/null 2>&1 || fail "Terminal host verification failed before authentication finalization."
timeout --signal=TERM --kill-after=5s 90 bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Runtime assets changed during authentication finalization."
timeout --signal=TERM --kill-after=5s 30 /usr/local/libexec/mochirii-forums/probe-website-forums-producer.py enabled >/dev/null 2>&1 || fail "The Website authentication producer is not in the exact enabled state."

python3 -B - "${authentication_record}" "${commit}" "${configuration}" "${release_record_name}" "${release_record_sha}" "${current_release_sha}" "${pending_record_name}" "${pending_record_sha}" "$(basename -- "${website_evidence}")" "${website_evidence_sha}" "${website_commit}" <<'PY'
import datetime
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
document = {
    "schemaVersion": 1,
    "recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "releaseEvidenceFile": sys.argv[4],
    "releaseEvidenceSha256": sys.argv[5],
    "currentReleaseSha256": sys.argv[6],
    "pendingAuthenticationEvidenceFile": sys.argv[7],
    "pendingAuthenticationEvidenceSha256": sys.argv[8],
    "websiteEvidenceFile": sys.argv[9],
    "websiteEvidenceSha256": sys.argv[10],
    "websiteRepositoryCommit": sys.argv[11],
    "activationPhase": "complete",
    "websiteProducerEnabled": True,
    "producerFailClosedBeforeEnablePassed": True,
    "activeMemberAllowed": True,
    "inactiveMemberDenied": True,
    "unverifiedMemberDenied": True,
    "invalidSignatureDenied": True,
    "malformedRequestDenied": True,
    "expiredRequestDenied": True,
    "replayDenied": True,
    "alternateLoginDisabled": True,
    "callbackLogRedactionPassed": True,
    "callbackBrowserQueryScrubPassed": True,
    "callbackBrowserPrivateResponsePassed": True,
    "terminalHostVerificationPassed": True,
}
def discard_safe_partial():
    if not candidate.exists() and not candidate.is_symlink():
        return
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit("authentication evidence partial is unsafe")
    candidate.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

if path.exists() or path.is_symlink():
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise SystemExit("existing authentication evidence is unsafe")
    existing = json.loads(path.read_text(encoding="utf-8"))
    if set(existing) != set(document):
        raise SystemExit("existing authentication evidence schema differs")
    for key, value in document.items():
        if key != "recordedAt" and existing.get(key) != value:
            raise SystemExit("existing authentication evidence tuple differs")
    discard_safe_partial()
else:
    discard_safe_partial()
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
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
[[ "$(stat -c '%U:%G %a' "${authentication_record}")" == "root:root 600" ]] || fail "Authentication evidence permissions differ."
authentication_sha="$(sha256sum -- "${authentication_record}" | awk '{print $1}')"
[[ ${authentication_sha} =~ ^[0-9a-f]{64}$ ]] || fail "Authentication evidence digest is malformed."

python3 -B - "${current_authentication}" "${commit}" "${configuration}" "$(basename -- "${authentication_record}")" "${authentication_sha}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
candidate = path.parent / f".{path.name}.partial"
document = {
    "repositoryCommit": sys.argv[2],
    "productionConfigurationSha256": sys.argv[3],
    "authenticationEvidenceFile": sys.argv[4],
    "authenticationEvidenceSha256": sys.argv[5],
    "activationPhase": "complete",
}
if candidate.exists() or candidate.is_symlink():
    metadata = candidate.lstat()
    if not candidate.is_file() or candidate.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit("current authentication partial is unsafe")
    candidate.unlink()
descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    json.dump(document, target, sort_keys=True)
    target.write("\n")
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
[[ "$(stat -c '%U:%G %a' "${current_authentication}")" == "root:root 600" ]] || fail "Current authentication evidence permissions differ."

python3 -B /usr/local/libexec/mochirii-forums/durable-event.py \
  --path "${state_root}/logs/events.log" --operation authentication-e2e --status passed \
  --field "repository_commit=${commit}" --field "configuration_sha256=${configuration}" \
  --field "evidence_sha256=${authentication_sha}" >/dev/null || fail "Authentication completion event could not be committed durably."
printf '%s\n' "Mochirii Forums authentication activation was finalized from protected Website evidence."
