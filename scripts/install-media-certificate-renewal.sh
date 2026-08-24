#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Media certificate renewal installation must run as root."
[[ $# -eq 4 ]] || fail "Usage: install-media-certificate-renewal.sh RUNTIME_JSON CERTBOT_CONFIG DNS_CREDENTIALS 'INSTALL MOCHIRII FORUMS MEDIA CERTIFICATE'"
runtime_source="$1"
certbot_source="$2"
dns_source="$3"
confirmation="$4"
[[ ${confirmation} == "INSTALL MOCHIRII FORUMS MEDIA CERTIFICATE" ]] || fail "Exact certificate installation confirmation is required."
for source in "${runtime_source}" "${certbot_source}" "${dns_source}"; do
  [[ -f ${source} && ! -L ${source} ]] || fail "Certificate input must be one regular file."
  [[ "$(stat -c '%U:%G %a' "${source}")" == "root:root 600" ]] || fail "Certificate input must be root:root mode 0600."
done

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_root}/.." && pwd)"
common="${script_root}/media-certificate-operation.sh"
acme_helper="${script_root}/reconcile-acme-dns.py"
[[ -f ${common} && ! -L ${common} && -f ${acme_helper} && ! -L ${acme_helper} ]] || fail "Certificate operation helpers are absent."
# shellcheck source=media-certificate-operation.sh
source "${common}"
lock_helper="${script_root}/host-operation-lock.py"
if python3 -B "${lock_helper}" assert-held --locks primary,media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks primary,media -- /bin/bash "$0" "$@"
fi
[[ ! -e /var/lib/mochirii/forums/deployment-mutation.json && ! -L /var/lib/mochirii/forums/deployment-mutation.json ]] || fail "Certificate installation refuses an active deployment mutation."
media_boundary_initialize 900 120 || fail "Certificate installation boundary initialization failed."
MEDIA_ACME_HELPER="${acme_helper}"
MEDIA_ACME_CREDENTIALS="${dns_source}"
media_install_signal_traps

python3 - "${runtime_source}" <<'PY' >/dev/null
import json
import pathlib
import re
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(document) != {"providerApiToken", "cdnEndpointId", "cdnOrigin"}:
    raise SystemExit("runtime keys differ")
if not re.fullmatch(r"[0-9a-f-]{36}", document.get("cdnEndpointId", "")):
    raise SystemExit("endpoint id invalid")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9][.]sgp1[.]digitaloceanspaces[.]com", document.get("cdnOrigin", "")):
    raise SystemExit("origin invalid")
token = document.get("providerApiToken")
if not isinstance(token, str) or not 32 <= len(token) <= 512 or any(c in token for c in "\r\n\x00"):
    raise SystemExit("token invalid")
PY
python3 - "${certbot_source}" <<'PY' >/dev/null
import pathlib
import re
import sys
lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
if len(lines) != 6:
    raise SystemExit("certbot config line count differs")
expected = {
    "agree-tos": "true",
    "non-interactive": "true",
    "authenticator": "dns-cloudflare",
    "dns-cloudflare-credentials": "/etc/letsencrypt/mochirii-cloudflare.ini",
    "dns-cloudflare-propagation-seconds": "30",
}
parsed = {}
for line in lines:
    if " = " not in line:
        raise SystemExit("certbot config is malformed")
    key, value = line.split(" = ", 1)
    if key in parsed or any(c in value for c in "\r\n\x00"):
        raise SystemExit("certbot config is malformed")
    parsed[key] = value
email = parsed.pop("email", "")
if not re.fullmatch(r"[^@\s]+@(?:[A-Za-z0-9-]+[.])+[A-Za-z]{2,63}", email):
    raise SystemExit("ACME contact email is malformed")
if parsed != expected:
    raise SystemExit("certbot config differs from the exact allowlist")
PY
python3 - "${dns_source}" <<'PY' >/dev/null
import pathlib
import re
import sys
value = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
if not re.fullmatch(r"dns_cloudflare_api_token = [A-Za-z0-9_-]{20,512}", value):
    raise SystemExit("DNS credential file differs from the exact token-only form")
PY

log_root="/var/lib/mochirii/forums/logs"
install_journal="/var/lib/mochirii/forums/media-certificate-install.pending.json"
preparation_journal="/var/lib/mochirii/forums/media-certificate-preparation.pending.json"
control_pointer="/var/lib/mochirii/forums/current-host-control.json"
control_evidence_root="/var/lib/mochirii/forums/evidence"
control_evidence_helper="/usr/local/libexec/mochirii-forums/host-control-evidence.py"
host_security_verifier="/usr/local/libexec/mochirii-forums/verify-host-security.sh"
prepared_certbot="/etc/letsencrypt/mochirii-media.ini"
prepared_dns="/etc/letsencrypt/mochirii-cloudflare.ini"
lineage="/etc/letsencrypt/live/media-forums.mochirii.com"
install -d -m 0700 -o root -g root "${log_root}" /usr/local/libexec/mochirii-forums /etc/mochirii /etc/letsencrypt
[[ ! -e ${preparation_journal} && ! -L ${preparation_journal} ]] || fail "Certificate preparation remains incomplete or unproved."
validate_prepared_input() {
  local source="$1"
  local prepared="$2"
  [[ -f ${prepared} && ! -L ${prepared} ]] || return 1
  [[ "$(stat -c '%U:%G %a' "${prepared}")" == "root:root 600" ]] || return 1
  cmp -s -- "${source}" "${prepared}"
}
validate_prepared_input "${certbot_source}" "${prepared_certbot}" || fail "Prepared Certbot configuration differs from the exact installation input."
validate_prepared_input "${dns_source}" "${prepared_dns}" || fail "Prepared DNS credential differs from the exact installation input."

install_targets=(
  /usr/local/libexec/mochirii-forums/media-certificate-operation.sh
  /usr/local/libexec/mochirii-forums/reconcile-acme-dns.py
  /usr/local/libexec/mochirii-forums/rotate-media-certificate.py
  /usr/local/sbin/mochirii-forums-rotate-media-certificate
  /usr/local/sbin/mochirii-forums-renew-media-certificate
  /etc/mochirii/forums-media-certificate.json
  /etc/systemd/system/mochirii-forums-media-certificate-renew.service
  /etc/systemd/system/mochirii-forums-media-certificate-renew.timer
)

read_current_control_binding() {
  python3 -B - "${control_pointer}" "${control_evidence_root}" "${repository_root}/config/host-control-manifest.v1.json" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

pointer_path = pathlib.Path(sys.argv[1])
evidence_root = pathlib.Path(sys.argv[2])
manifest_path = pathlib.Path(sys.argv[3])
for path, kind, mode in (
    (pointer_path, stat.S_ISREG, 0o600),
    (evidence_root, stat.S_ISDIR, 0o700),
):
    metadata = path.lstat()
    if not kind(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise SystemExit("current control evidence boundary is unsafe")
if pointer_path.stat().st_size > 65536:
    raise SystemExit("current control pointer exceeds its bound")
if not manifest_path.is_file() or manifest_path.is_symlink():
    raise SystemExit("trusted host-control manifest is absent or linked")
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
pointer_keys = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(pointer) != pointer_keys or pointer.get("schemaVersion") != 1 or pointer.get("phase") != "hardened":
    raise SystemExit("current control pointer schema differs")
commit = pointer.get("repositoryCommit", "")
manifest_sha = pointer.get("manifestSha256", "")
target_set_sha = pointer.get("targetSetSha256", "")
evidence_sha = pointer.get("controlEvidenceSha256", "")
if not all(re.fullmatch(pattern, str(value)) for pattern, value in (
    (r"[0-9a-f]{40}", commit), (r"[0-9a-f]{64}", manifest_sha),
    (r"[0-9a-f]{64}", target_set_sha), (r"[0-9a-f]{64}", evidence_sha),
)):
    raise SystemExit("current control pointer identity differs")
archive_bindings = {
    "repositoryTree", "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if (
    not re.fullmatch(r"[0-9a-f]{40}", str(pointer.get("repositoryTree", "")))
    or pointer.get("releaseArchiveFile") != f"/opt/mochirii/forums/host-control-releases/{commit}/mochirii-release.tar"
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("releaseArchiveSha256", "")))
    or not isinstance(pointer.get("releaseArchiveBytes"), int)
    or isinstance(pointer.get("releaseArchiveBytes"), bool)
    or not 1 <= pointer["releaseArchiveBytes"] <= 64 * 1024 * 1024
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("releaseArchiveContentManifestSha256", "")))
    or pointer.get("deploymentSourceRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b"
    or pointer.get("deploymentSourceTree") != "588498dffbea91592fd4e2f10166bc11c8fe7a61"
    or pointer.get("deploymentSourceArchiveFile") != "/opt/mochirii/forums/deployment-source/ed9f680b0df1de28f062de1769d89d22b2644d1b.tar"
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("deploymentSourceArchiveSha256", "")))
    or not isinstance(pointer.get("deploymentSourceArchiveBytes"), int)
    or isinstance(pointer.get("deploymentSourceArchiveBytes"), bool)
    or not 1 <= pointer["deploymentSourceArchiveBytes"] <= 64 * 1024 * 1024
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("deploymentSourceContentManifestSha256", "")))
):
    raise SystemExit("current control retained-source authority differs")
if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != manifest_sha:
    raise SystemExit("certificate installer source differs from current host controls")
name = pointer.get("controlEvidenceFile", "")
if name != f"{commit}-{target_set_sha}-host-control.json":
    raise SystemExit("current control evidence name differs")
record_path = evidence_root / name
metadata = record_path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
    raise SystemExit("current control evidence is unsafe")
raw = record_path.read_bytes()
if hashlib.sha256(raw).hexdigest() != evidence_sha:
    raise SystemExit("current control evidence digest differs")
record = json.loads(raw)
record_keys = {
    "schemaVersion", "recordedAt", "operation", "phase", "repositoryCommit", "repositoryTree",
    "manifestSha256", "targetSetSha256", "previousControlEvidenceSha256", "targets",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(record) != record_keys or record.get("schemaVersion") != 1 or record.get("phase") != "hardened":
    raise SystemExit("current control evidence schema differs")
if record.get("operation") not in {"initial-install", "upgrade", "certificate-install"}:
    raise SystemExit("current control evidence operation differs")
if any(record.get(key) != pointer[key] for key in ("repositoryCommit", "manifestSha256", "targetSetSha256")):
    raise SystemExit("current control evidence binding differs")
if any(record.get(key) != pointer.get(key) for key in archive_bindings):
    raise SystemExit("current control retained-source evidence binding differs")
print(f"{commit}\t{manifest_sha}\t{evidence_sha}")
PY
}

validate_installed_automation_bytes() {
  local source target mode
  while IFS=$'\t' read -r source target mode; do
    [[ -f ${target} && ! -L ${target} ]] || return 1
    [[ "$(stat -c '%U:%G %a' "${target}")" == "root:root ${mode}" ]] || return 1
    cmp -s -- "${source}" "${target}" || return 1
  done <<EOF
${script_root}/media-certificate-operation.sh	/usr/local/libexec/mochirii-forums/media-certificate-operation.sh	644
${script_root}/reconcile-acme-dns.py	/usr/local/libexec/mochirii-forums/reconcile-acme-dns.py	755
${script_root}/rotate-media-certificate.py	/usr/local/libexec/mochirii-forums/rotate-media-certificate.py	755
${script_root}/rotate-media-certificate.sh	/usr/local/sbin/mochirii-forums-rotate-media-certificate	755
${script_root}/run-media-certificate-renewal.sh	/usr/local/sbin/mochirii-forums-renew-media-certificate	755
${runtime_source}	/etc/mochirii/forums-media-certificate.json	600
${repository_root}/config/mochirii-forums-media-certificate-renew.service	/etc/systemd/system/mochirii-forums-media-certificate-renew.service	644
${repository_root}/config/mochirii-forums-media-certificate-renew.timer	/etc/systemd/system/mochirii-forums-media-certificate-renew.timer	644
EOF
}

seal_certificate_control_state() {
  [[ -f ${control_evidence_helper} && ! -L ${control_evidence_helper} ]] || return 1
  [[ "$(stat -c '%U:%G %a' "${control_evidence_helper}")" == "root:root 755" ]] || return 1
  timeout --signal=TERM --kill-after=5s 30s python3 -B "${control_evidence_helper}" seal-control \
    --operation certificate-install \
    --commit "${control_repository_commit}" \
    --source-root "${repository_root}" \
    --previous-evidence-sha256 "${previous_control_evidence_sha}" >/dev/null 2>&1
}

verify_certificate_control_state() {
  python3 -B - "${control_pointer}" "${control_evidence_root}" "${control_repository_commit}" "${control_manifest_sha}" "${previous_control_evidence_sha}" <<'PY'
import hashlib
import json
import pathlib
import re
import stat
import sys

pointer_path = pathlib.Path(sys.argv[1])
evidence_root = pathlib.Path(sys.argv[2])
commit, manifest_sha, predecessor = sys.argv[3:6]
pointer_metadata = pointer_path.lstat()
if not stat.S_ISREG(pointer_metadata.st_mode) or stat.S_ISLNK(pointer_metadata.st_mode) or pointer_metadata.st_uid != 0 or pointer_metadata.st_gid != 0 or stat.S_IMODE(pointer_metadata.st_mode) != 0o600 or not 1 <= pointer_metadata.st_size <= 65536:
    raise SystemExit("certificate control pointer is unsafe")
pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
pointer_keys = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(pointer) != pointer_keys or pointer.get("schemaVersion") != 1 or pointer.get("phase") != "hardened":
    raise SystemExit("certificate control pointer schema differs")
name = pointer.get("controlEvidenceFile", "")
if pointer.get("repositoryCommit") != commit or pointer.get("manifestSha256") != manifest_sha or not re.fullmatch(rf"{commit}-[0-9a-f]{{64}}-host-control[.]json", name):
    raise SystemExit("certificate control pointer identity differs")
archive_bindings = {
    "repositoryTree", "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if (
    not re.fullmatch(r"[0-9a-f]{40}", str(pointer.get("repositoryTree", "")))
    or pointer.get("releaseArchiveFile") != f"/opt/mochirii/forums/host-control-releases/{commit}/mochirii-release.tar"
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("releaseArchiveSha256", "")))
    or not isinstance(pointer.get("releaseArchiveBytes"), int)
    or isinstance(pointer.get("releaseArchiveBytes"), bool)
    or not 1 <= pointer["releaseArchiveBytes"] <= 64 * 1024 * 1024
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("releaseArchiveContentManifestSha256", "")))
    or pointer.get("deploymentSourceRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b"
    or pointer.get("deploymentSourceTree") != "588498dffbea91592fd4e2f10166bc11c8fe7a61"
    or pointer.get("deploymentSourceArchiveFile") != "/opt/mochirii/forums/deployment-source/ed9f680b0df1de28f062de1769d89d22b2644d1b.tar"
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("deploymentSourceArchiveSha256", "")))
    or not isinstance(pointer.get("deploymentSourceArchiveBytes"), int)
    or isinstance(pointer.get("deploymentSourceArchiveBytes"), bool)
    or not 1 <= pointer["deploymentSourceArchiveBytes"] <= 64 * 1024 * 1024
    or not re.fullmatch(r"[0-9a-f]{64}", str(pointer.get("deploymentSourceContentManifestSha256", "")))
):
    raise SystemExit("certificate control retained-source authority differs")
record_path = evidence_root / name
metadata = record_path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 1 <= metadata.st_size <= 65536:
    raise SystemExit("certificate control evidence is unsafe")
raw = record_path.read_bytes()
if pointer.get("controlEvidenceSha256") != hashlib.sha256(raw).hexdigest():
    raise SystemExit("certificate control evidence digest differs")
record = json.loads(raw)
record_keys = {
    "schemaVersion", "recordedAt", "operation", "phase", "repositoryCommit", "repositoryTree",
    "manifestSha256", "targetSetSha256", "previousControlEvidenceSha256", "targets",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}
if set(record) != record_keys or record.get("schemaVersion") != 1 or record.get("phase") != "hardened":
    raise SystemExit("certificate control evidence schema differs")
if record.get("operation") != "certificate-install" or record.get("repositoryCommit") != commit or record.get("previousControlEvidenceSha256") != predecessor:
    raise SystemExit("certificate control evidence predecessor differs")
if pointer.get("targetSetSha256") != record.get("targetSetSha256") or pointer.get("manifestSha256") != record.get("manifestSha256"):
    raise SystemExit("certificate control evidence binding differs")
if any(record.get(key) != pointer.get(key) for key in archive_bindings):
    raise SystemExit("certificate control retained-source evidence binding differs")
PY
  [[ -f ${host_security_verifier} && ! -L ${host_security_verifier} ]] || return 1
  [[ "$(stat -c '%U:%G %a' "${host_security_verifier}")" == "root:root 755" ]] || return 1
  timeout --signal=TERM --kill-after=10s 180s bash "${host_security_verifier}" \
    "${control_repository_commit}" "${repository_root}" >/dev/null 2>&1
}

write_install_journal() {
  local phase="$1"
  python3 -B - "${install_journal}" "${phase}" "${control_repository_commit}" "${control_manifest_sha}" "${previous_control_evidence_sha}" <<'PY'
import json
import os
import pathlib
import re
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
phase = sys.argv[2]
commit = sys.argv[3]
manifest_sha = sys.argv[4]
predecessor = sys.argv[5]
if phase not in {"installing", "committed"}:
    raise SystemExit("installation phase differs")
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha) or not re.fullmatch(r"[0-9a-f]{64}", predecessor):
    raise SystemExit("installation control binding differs")
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
descriptor, candidate = tempfile.mkstemp(prefix=".media-certificate-install.", suffix=".json", dir=path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(
            {
                "schemaVersion": 1,
                "operation": "initial-media-certificate-renewal-install",
                "preexistingManagedTimerEnabled": False,
                "preexistingManagedTimerActive": False,
                "repositoryCommit": commit,
                "manifestSha256": manifest_sha,
                "previousControlEvidenceSha256": predecessor,
                "phase": phase,
            },
            target,
            sort_keys=True,
        )
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    descriptor = -1
    os.replace(candidate, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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

clear_install_journal() {
  python3 -B - "${install_journal}" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("journal is not regular")
if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("journal permissions differ")
path.unlink()
parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}

validate_install_journal() {
  python3 -B - "${install_journal}" <<'PY'
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("journal is not regular")
if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("journal permissions differ")
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "schemaVersion": 1,
    "operation": "initial-media-certificate-renewal-install",
    "preexistingManagedTimerEnabled": False,
    "preexistingManagedTimerActive": False,
}
if set(document) != set(required) | {"phase", "repositoryCommit", "manifestSha256", "previousControlEvidenceSha256"} or any(document.get(key) != value for key, value in required.items()) or document.get("phase") not in {"installing", "committed"}:
    raise SystemExit("journal differs")
if not re.fullmatch(r"[0-9a-f]{40}", str(document.get("repositoryCommit", ""))) or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("manifestSha256", ""))) or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("previousControlEvidenceSha256", ""))):
    raise SystemExit("journal control binding differs")
print("\t".join((document["phase"], document["repositoryCommit"], document["manifestSha256"], document["previousControlEvidenceSha256"])))
PY
}

installation_success=false
cleanup_installation() {
  [[ -e ${install_journal} || -L ${install_journal} ]] || return 0
  local state phase commit manifest_sha predecessor current_binding current_commit current_manifest current_sha
  state="$(validate_install_journal)" || return 1
  IFS=$'\t' read -r phase commit manifest_sha predecessor <<<"${state}"
  [[ ${phase} == installing ]] || return 1
  current_binding="$(read_current_control_binding)" || return 1
  IFS=$'\t' read -r current_commit current_manifest current_sha <<<"${current_binding}"
  [[ ${current_commit} == "${commit}" && ${current_manifest} == "${manifest_sha}" && ${current_sha} == "${predecessor}" ]] || return 1
  media_run_cleanup_bounded install-timer-stop systemctl disable --now mochirii-forums-media-certificate-renew.timer || true
  local target
  for target in "${install_targets[@]}"; do
    [[ ! -e ${target} && ! -L ${target} ]] || rm -f -- "${target}" || return 1
  done
  media_run_cleanup_bounded install-daemon-reload systemctl daemon-reload || return 1
  timeout --signal=TERM --kill-after=5s 15 systemctl is-enabled --quiet mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 && return 1
  timeout --signal=TERM --kill-after=5s 15 systemctl is-active --quiet mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 && return 1
  clear_install_journal || return 1
}

on_exit() {
  local status=$?
  trap - EXIT
  if [[ ${installation_success} != true ]]; then
    journal_state=""
    journal_phase=""
    if [[ -e ${install_journal} || -L ${install_journal} ]]; then
      journal_state="$(validate_install_journal 2>/dev/null || true)"
      journal_phase="${journal_state%%$'\t'*}"
    fi
    if [[ ${journal_phase} == committed ]]; then
      media_record_event certificate-install blocked || true
      printf '%s\n' "Mochirii Forums certificate installation is committed; rerun the exact installer to reconcile terminal evidence." >&2
      exit 1
    fi
    if ! cleanup_installation; then
      media_record_event certificate-install blocked || true
      printf '%s\n' "Mochirii Forums certificate installation cleanup is blocked; the sealed root recovery journal was retained." >&2
      exit 1
    fi
  fi
  exit "${status}"
}
trap on_exit EXIT

if [[ -e ${install_journal} || -L ${install_journal} ]]; then
  prior_install_state="$(validate_install_journal)" || fail "A prior certificate installation journal is malformed."
  IFS=$'\t' read -r prior_install_phase control_repository_commit control_manifest_sha previous_control_evidence_sha <<<"${prior_install_state}"
  if [[ ${prior_install_phase} == committed ]]; then
    current_control_binding="$(read_current_control_binding)" || fail "Committed certificate installation lost its exact control-evidence binding."
    IFS=$'\t' read -r current_control_commit current_manifest_sha current_control_sha <<<"${current_control_binding}"
    [[ ${current_control_commit} == "${control_repository_commit}" && ${current_manifest_sha} == "${control_manifest_sha}" ]] || fail "Committed certificate installation source differs from its sealed control tuple."
    validate_installed_automation_bytes || fail "Committed certificate automation bytes, ownership, or modes differ."
    media_run_bounded install-resume-enabled 30 systemctl is-enabled --quiet mochirii-forums-media-certificate-renew.timer || fail "Committed certificate timer is not enabled."
    media_run_bounded install-resume-active 30 systemctl is-active --quiet mochirii-forums-media-certificate-renew.timer || fail "Committed certificate timer is not active."
    media_run_bounded install-resume-preflight 120 /usr/local/libexec/mochirii-forums/rotate-media-certificate.py \
      --runtime-json /etc/mochirii/forums-media-certificate.json \
      --certificate "${lineage}/cert.pem" --chain "${lineage}/chain.pem" \
      --private-key "${lineage}/privkey.pem" --preflight-only || fail "Committed certificate automation preflight differs."
    [[ ! -e ${MEDIA_ACME_JOURNAL} && ! -L ${MEDIA_ACME_JOURNAL} ]] || fail "Committed certificate install retains unresolved DNS state."
    seal_certificate_control_state || fail "Committed certificate control evidence could not be sealed or adopted."
    verify_certificate_control_state || fail "Committed certificate control evidence failed terminal verification."
    media_record_event certificate-install passed || fail "Committed certificate installation event could not be reconciled."
    clear_install_journal || fail "Committed certificate installation journal could not be cleared durably."
    installation_success=true
    printf '%s\n' "Mochirii Forums automatic media certificate renewal installation was already committed and is verified."
    exit 0
  fi
  cleanup_installation || fail "A prior certificate installation could not be reconciled."
fi

current_control_binding="$(read_current_control_binding)" || fail "Current host-control evidence is absent, unsafe, or differs from this certificate source."
IFS=$'\t' read -r control_repository_commit control_manifest_sha previous_control_evidence_sha <<<"${current_control_binding}"
[[ -f ${host_security_verifier} && ! -L ${host_security_verifier} && "$(stat -c '%U:%G %a' "${host_security_verifier}")" == "root:root 755" ]] || fail "Installed host-security verifier is absent or unsafe."
timeout --signal=TERM --kill-after=10s 180s bash "${host_security_verifier}" \
  "${control_repository_commit}" "${repository_root}" >/dev/null 2>&1 || fail "Current host controls failed verification before certificate installation."

for target in "${install_targets[@]}"; do
  [[ ! -e ${target} && ! -L ${target} ]] || fail "A managed certificate automation target already exists outside the initial installation transaction."
done
timeout --signal=TERM --kill-after=5s 15s systemctl is-enabled --quiet mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 && fail "The managed certificate timer is already enabled outside the initial installation transaction."
timeout --signal=TERM --kill-after=5s 15s systemctl is-active --quiet mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 && fail "The managed certificate timer is already active outside the initial installation transaction."
export DEBIAN_FRONTEND=noninteractive
media_run_bounded package-index 240 apt-get update || fail "Certificate package index update failed within its bounded operation."
media_run_bounded package-install 360 apt-get install -y certbot python3-certbot-dns-cloudflare || fail "Certificate package installation failed within its bounded operation."
write_install_journal installing || fail "Certificate installation recovery journal could not be sealed."
media_record_event certificate-install started || fail "Certificate installation event evidence could not be sealed."

install -m 0644 -o root -g root "${script_root}/media-certificate-operation.sh" /usr/local/libexec/mochirii-forums/media-certificate-operation.sh
install -m 0755 -o root -g root "${script_root}/reconcile-acme-dns.py" /usr/local/libexec/mochirii-forums/reconcile-acme-dns.py
install -m 0755 -o root -g root "${script_root}/rotate-media-certificate.py" /usr/local/libexec/mochirii-forums/rotate-media-certificate.py
install -m 0755 -o root -g root "${script_root}/rotate-media-certificate.sh" /usr/local/sbin/mochirii-forums-rotate-media-certificate
install -m 0755 -o root -g root "${script_root}/run-media-certificate-renewal.sh" /usr/local/sbin/mochirii-forums-renew-media-certificate
install -m 0600 -o root -g root "${runtime_source}" /etc/mochirii/forums-media-certificate.json
install -m 0644 -o root -g root "${repository_root}/config/mochirii-forums-media-certificate-renew.service" /etc/systemd/system/mochirii-forums-media-certificate-renew.service
install -m 0644 -o root -g root "${repository_root}/config/mochirii-forums-media-certificate-renew.timer" /etc/systemd/system/mochirii-forums-media-certificate-renew.timer
media_run_bounded install-daemon-reload 30 systemctl daemon-reload || fail "Certificate unit daemon reload failed within its bounded operation."

for required in cert.pem chain.pem privkey.pem; do
  [[ -e "${lineage}/${required}" ]] || fail "The separately issued and bound media certificate lineage is absent."
done
if ! media_run_bounded certificate-preflight 120 /usr/local/libexec/mochirii-forums/rotate-media-certificate.py \
  --runtime-json /etc/mochirii/forums-media-certificate.json \
  --certificate "${lineage}/cert.pem" \
  --chain "${lineage}/chain.pem" \
  --private-key "${lineage}/privkey.pem" \
  --preflight-only; then
  fail "The pre-bound media certificate failed bounded automation preflight."
fi
media_run_bounded install-timer-enable 30 systemctl enable --now mochirii-forums-media-certificate-renew.timer || fail "Media certificate renewal timer activation failed within its bounded operation."
media_run_bounded install-timer-enabled-readback 30 systemctl is-enabled --quiet mochirii-forums-media-certificate-renew.timer || fail "Media certificate renewal timer is not enabled."
media_run_bounded install-timer-active-readback 30 systemctl is-active --quiet mochirii-forums-media-certificate-renew.timer || fail "Media certificate renewal timer is not active."
[[ ! -e ${MEDIA_ACME_JOURNAL} && ! -L ${MEDIA_ACME_JOURNAL} ]] || fail "Certificate installation found an unresolved DNS mutation journal."
validate_installed_automation_bytes || fail "Installed certificate automation bytes, ownership, or modes differ."
write_install_journal committed || fail "Certificate installation commit point could not be sealed."
seal_certificate_control_state || fail "Certificate control evidence could not be sealed."
verify_certificate_control_state || fail "Certificate control evidence failed terminal verification."
media_record_event certificate-install passed || fail "Certificate installation event evidence could not be sealed."
clear_install_journal || fail "Committed certificate installation journal could not be cleared durably."
installation_success=true
printf '%s\n' "Mochirii Forums automatic media certificate renewal installed and verified."
