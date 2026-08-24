#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Initial media certificate preparation must run as root."
[[ $# -eq 3 ]] || fail "Usage: prepare-media-certificate.sh CERTBOT_CONFIG DNS_CREDENTIALS 'PREPARE MOCHIRII FORUMS MEDIA CERTIFICATE'"
certbot_source="$1"
dns_source="$2"
confirmation="$3"
[[ ${confirmation} == "PREPARE MOCHIRII FORUMS MEDIA CERTIFICATE" ]] || fail "Exact certificate preparation confirmation is required."
for source in "${certbot_source}" "${dns_source}"; do
  [[ -f ${source} && ! -L ${source} ]] || fail "Certificate input must be one regular file."
  [[ "$(stat -c '%U:%G %a' "${source}")" == "root:root 600" ]] || fail "Certificate input must be root:root mode 0600."
done

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
common="${script_root}/media-certificate-operation.sh"
acme_helper="${script_root}/reconcile-acme-dns.py"
[[ -f ${common} && ! -L ${common} && -f ${acme_helper} && ! -L ${acme_helper} ]] || fail "Certificate operation helpers are absent."
# shellcheck source=media-certificate-operation.sh
source "${common}"
lock_helper="${script_root}/host-operation-lock.py"
if python3 -B "${lock_helper}" assert-held --locks media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec python3 -B "${lock_helper}" run --locks media -- /bin/bash "$0" "$@"
fi
[[ ! -e /var/lib/mochirii/forums/deployment-mutation.json && ! -L /var/lib/mochirii/forums/deployment-mutation.json ]] || fail "Certificate preparation refuses an active deployment mutation."
media_boundary_initialize 1200 180 || fail "Certificate operation boundary initialization failed."
MEDIA_ACME_HELPER="${acme_helper}"
MEDIA_ACME_CREDENTIALS="${dns_source}"
media_install_signal_traps

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
    if key in parsed or any(character in value for character in "\r\n\x00"):
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
preparation_journal="/var/lib/mochirii/forums/media-certificate-preparation.pending.json"
lineage="/etc/letsencrypt/live/media-forums.mochirii.com"
renewal="/etc/letsencrypt/renewal/media-forums.mochirii.com.conf"
archive="/etc/letsencrypt/archive/media-forums.mochirii.com"
install -d -m 0700 -o root -g root "${log_root}" /etc/letsencrypt

validate_lineage() {
  python3 -B - "${lineage}" "${renewal}" "${archive}" <<'PY' >/dev/null || return 1
import os
import pathlib
import stat
import sys

live = pathlib.Path(sys.argv[1])
renewal = pathlib.Path(sys.argv[2])
archive = pathlib.Path(sys.argv[3])
for directory in (live, archive):
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SystemExit("lineage directory metadata differs")
renewal_metadata = renewal.lstat()
if not stat.S_ISREG(renewal_metadata.st_mode) or stat.S_ISLNK(renewal_metadata.st_mode) or renewal_metadata.st_uid != 0 or stat.S_IMODE(renewal_metadata.st_mode) & 0o022:
    raise SystemExit("renewal metadata differs")

names = {"cert", "chain", "fullchain", "privkey"}
live_entries = {entry.name for entry in live.iterdir()}
if live_entries not in ({f"{name}.pem" for name in names}, {f"{name}.pem" for name in names} | {"README"}):
    raise SystemExit("live lineage inventory differs")
archive_entries = {entry.name for entry in archive.iterdir()}
if archive_entries != {f"{name}1.pem" for name in names}:
    raise SystemExit("archive lineage inventory differs")
for name in names:
    link = live / f"{name}.pem"
    metadata = link.lstat()
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0:
        raise SystemExit("live lineage link metadata differs")
    expected = archive / f"{name}1.pem"
    if link.resolve(strict=True) != expected.resolve(strict=True):
        raise SystemExit("live lineage link target differs")
    target_metadata = expected.lstat()
    if not stat.S_ISREG(target_metadata.st_mode) or stat.S_ISLNK(target_metadata.st_mode) or target_metadata.st_uid != 0:
        raise SystemExit("archive lineage file metadata differs")
    mode = stat.S_IMODE(target_metadata.st_mode)
    if mode & 0o022 or (name == "privkey" and mode & 0o077):
        raise SystemExit("archive lineage file permissions differ")
PY
  local cert_key key_key
  cert_key="$(openssl x509 -in "${lineage}/cert.pem" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" || return 1
  key_key="$(openssl pkey -in "${lineage}/privkey.pem" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" || return 1
  [[ ${cert_key} =~ ^[0-9a-f]{64}$ && ${cert_key} == "${key_key}" ]] || return 1
  openssl x509 -in "${lineage}/cert.pem" -checkhost media-forums.mochirii.com -noout >/dev/null 2>&1 || return 1
  openssl x509 -in "${lineage}/cert.pem" -checkend 604800 -noout >/dev/null 2>&1 || return 1
  local san_names
  san_names="$(openssl x509 -in "${lineage}/cert.pem" -noout -ext subjectAltName 2>/dev/null | grep -oE 'DNS:[^,[:space:]]+' | LC_ALL=C sort -u)" || return 1
  [[ ${san_names} == "DNS:media-forums.mochirii.com" ]] || return 1
}

discard_incomplete_transaction_lineage() {
  python3 -B - "${lineage}" "${renewal}" "${archive}" <<'PY' >/dev/null || return 1
import os
import pathlib
import re
import stat
import sys

live = pathlib.Path(sys.argv[1])
renewal = pathlib.Path(sys.argv[2])
archive = pathlib.Path(sys.argv[3])

def safe_parent(path):
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise SystemExit("certificate transaction parent is unsafe")

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

base = live.parent.parent
if base != renewal.parent.parent or base != archive.parent.parent or str(base) != "/etc/letsencrypt":
    raise SystemExit("certificate transaction roots differ")
safe_parent(base)
for target in (live, renewal, archive):
    parent = target.parent
    if parent.exists() or parent.is_symlink():
        safe_parent(parent)
    elif target.exists() or target.is_symlink():
        raise SystemExit("certificate transaction parent is absent")

if renewal.exists() or renewal.is_symlink():
    metadata = renewal.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size > 65_536
    ):
        raise SystemExit("partial renewal record is unsafe")

if live.exists() or live.is_symlink():
    metadata = live.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise SystemExit("partial live lineage is unsafe")
    for entry in live.iterdir():
        metadata = entry.lstat()
        if entry.name == "README":
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_size > 65_536
            ):
                raise SystemExit("partial live README is unsafe")
            continue
        match = re.fullmatch(r"(cert|chain|fullchain|privkey)[.]pem", entry.name)
        if match is None or not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0:
            raise SystemExit("partial live lineage inventory differs")
        target = os.readlink(entry)
        if os.path.isabs(target) or "\x00" in target:
            raise SystemExit("partial live lineage link is unsafe")
        normalized = pathlib.Path(os.path.normpath(os.path.join(entry.parent, target)))
        if normalized.parent != archive or re.fullmatch(rf"{match.group(1)}[1-9][0-9]{{0,5}}[.]pem", normalized.name) is None:
            raise SystemExit("partial live lineage link target differs")

if archive.exists() or archive.is_symlink():
    metadata = archive.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise SystemExit("partial archive lineage is unsafe")
    for entry in archive.iterdir():
        metadata = entry.lstat()
        if (
            re.fullmatch(r"(?:cert|chain|fullchain|privkey)[1-9][0-9]{0,5}[.]pem", entry.name) is None
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > 1_048_576
        ):
            raise SystemExit("partial archive lineage inventory differs")

if renewal.exists():
    renewal.unlink()
    fsync_directory(renewal.parent)
if live.exists():
    for entry in live.iterdir():
        entry.unlink()
    live.rmdir()
    fsync_directory(live.parent)
if archive.exists():
    for entry in archive.iterdir():
        entry.unlink()
    archive.rmdir()
    fsync_directory(archive.parent)
if any(path.exists() or path.is_symlink() for path in (live, renewal, archive)):
    raise SystemExit("partial certificate lineage cleanup is unproved")
PY
}

write_preparation_journal() {
  local phase="$1"
  python3 -B - "${preparation_journal}" "${phase}" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
phase = sys.argv[2]
if phase not in {"prepared", "issued", "committed"}:
    raise SystemExit("phase differs")
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
descriptor, candidate = tempfile.mkstemp(prefix=".media-certificate-preparation.", suffix=".json", dir=path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(
            {
                "schemaVersion": 1,
                "certificateName": "media-forums.mochirii.com",
                "preexistingLineage": False,
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

clear_preparation_journal() {
  python3 -B - "${preparation_journal}" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("journal is not regular")
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("journal permissions differ")
path.unlink()
parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}

read_preparation_phase() {
  python3 -B - "${preparation_journal}" <<'PY'
import json
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("journal is not regular")
if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("journal permissions differ")
document = json.loads(path.read_text(encoding="utf-8"))
if set(document) != {"schemaVersion", "certificateName", "preexistingLineage", "phase"}:
    raise SystemExit("journal keys differ")
if (
    document["schemaVersion"] != 1
    or document["certificateName"] != "media-forums.mochirii.com"
    or document["preexistingLineage"] is not False
    or document["phase"] not in {"prepared", "issued", "committed"}
):
    raise SystemExit("journal values differ")
print(document["phase"])
PY
}

export DEBIAN_FRONTEND=noninteractive
media_run_bounded package-index 300 apt-get update || fail "Certificate package index update failed within its bounded operation."
media_run_bounded package-install 420 apt-get install -y certbot python3-certbot-dns-cloudflare || fail "Certificate package installation failed within its bounded operation."
install_preparation_input() {
  local source="$1"
  local target="$2"
  if [[ "$(readlink -f -- "${source}")" == "${target}" ]]; then
    [[ -f ${target} && ! -L ${target} && "$(stat -c '%U:%G %a' "${target}")" == "root:root 600" ]] || return 1
  elif [[ -e ${target} || -L ${target} ]]; then
    [[ -f ${target} && ! -L ${target} && "$(stat -c '%U:%G %a' "${target}")" == "root:root 600" ]] || return 1
  else
    install -m 0600 -o root -g root "${source}" "${target}" || return 1
  fi
  cmp -s -- "${source}" "${target}"
}
install_preparation_input "${certbot_source}" /etc/letsencrypt/mochirii-media.ini || fail "Prepared Certbot configuration could not be installed exactly."
install_preparation_input "${dns_source}" /etc/letsencrypt/mochirii-cloudflare.ini || fail "Prepared DNS credential could not be installed exactly."
MEDIA_ACME_CREDENTIALS=/etc/letsencrypt/mochirii-cloudflare.ini

if [[ -e ${preparation_journal} || -L ${preparation_journal} ]]; then
  phase="$(read_preparation_phase)" || fail "Initial certificate preparation journal is malformed."
  if [[ ${phase} == issued || ${phase} == committed ]]; then
    validate_lineage || fail "Committed certificate journal no longer matches the exact lineage."
    if [[ ${phase} == issued ]]; then
      write_preparation_journal committed || fail "Certificate preparation commit point could not be sealed."
    fi
    media_record_event initial-certificate passed || fail "Certificate event evidence could not be sealed."
    clear_preparation_journal || fail "Committed certificate preparation journal could not be cleared durably."
    printf '%s\n' "Initial Mochirii Forums media certificate prepared for separate exact CDN binding."
    exit 0
  fi
  media_reconcile_acme "${acme_helper}" /etc/letsencrypt/mochirii-cloudflare.ini || fail "Interrupted certificate preparation DNS cleanup remains unproved."
  if [[ -e ${lineage} || -L ${lineage} || -e ${renewal} || -L ${renewal} || -e ${archive} || -L ${archive} ]]; then
    if validate_lineage; then
      write_preparation_journal issued || fail "Recovered certificate preparation evidence could not be committed forward."
      validate_lineage || fail "Recovered certificate lineage changed before completion."
      write_preparation_journal committed || fail "Recovered certificate preparation commit point could not be sealed."
      media_record_event initial-certificate passed || fail "Certificate event evidence could not be sealed."
      clear_preparation_journal || fail "Recovered certificate preparation journal could not be cleared durably."
      printf '%s\n' "Initial Mochirii Forums media certificate prepared for separate exact CDN binding."
      exit 0
    fi
    discard_incomplete_transaction_lineage || fail "Interrupted certificate preparation has unsafe or ambiguous partial lineage state; the root recovery journal was retained."
  fi
else
  [[ ! -e ${lineage} && ! -L ${lineage} && ! -e ${renewal} && ! -L ${renewal} && ! -e ${archive} && ! -L ${archive} ]] || fail "A pre-existing media certificate lineage is outside this initial preparation transaction."
  write_preparation_journal prepared || fail "Initial certificate preparation journal could not be sealed."
fi

media_record_event initial-certificate started || fail "Certificate event evidence could not be sealed."
if ! media_run_certbot_dns_transaction \
  "${acme_helper}" \
  /etc/letsencrypt/mochirii-cloudflare.ini \
  420 \
  certbot certonly \
    --config /etc/letsencrypt/mochirii-media.ini \
    --cert-name media-forums.mochirii.com \
    --domain media-forums.mochirii.com; then
  media_record_event initial-certificate blocked || true
  fail "Initial media certificate issuance or exact DNS cleanup failed; the root recovery journal was retained."
fi
validate_lineage || fail "Initial media certificate lineage or key binding is incomplete."
write_preparation_journal issued || fail "Issued certificate preparation evidence could not be sealed."
validate_lineage || fail "Initial media certificate lineage changed before completion."
write_preparation_journal committed || fail "Initial certificate preparation commit point could not be sealed."
media_record_event initial-certificate passed || fail "Certificate event evidence could not be sealed."
clear_preparation_journal || fail "Committed certificate preparation journal could not be cleared durably."
printf '%s\n' "Initial Mochirii Forums media certificate prepared for separate exact CDN binding."
