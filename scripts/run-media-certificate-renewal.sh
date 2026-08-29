#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Media certificate renewal must run as root."
common=/usr/local/libexec/mochirii-forums/media-certificate-operation.sh
acme_helper=/usr/local/libexec/mochirii-forums/reconcile-acme-dns.py
credentials=/etc/letsencrypt/mochirii-cloudflare.ini
[[ -f ${common} && ! -L ${common} && -f ${acme_helper} && ! -L ${acme_helper} ]] || fail "Installed media certificate operation helpers are absent."
lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks media -- /bin/bash "$0" "$@"
fi
# shellcheck source=media-certificate-operation.sh
source "${common}"
[[ ! -e /var/lib/mochirii/forums/deployment-mutation.json && ! -L /var/lib/mochirii/forums/deployment-mutation.json ]] || fail "Certificate renewal refuses an active deployment mutation."
media_boundary_initialize 1140 180 || fail "Media certificate renewal boundary initialization failed."
MEDIA_ACME_HELPER="${acme_helper}"
MEDIA_ACME_CREDENTIALS="${credentials}"
media_install_signal_traps
lineage="/etc/letsencrypt/live/media-forums.mochirii.com"
rotation=(
  /usr/local/libexec/mochirii-forums/rotate-media-certificate.py
  --runtime-json /etc/mochirii/forums-media-certificate.json
  --certificate "${lineage}/cert.pem"
  --chain "${lineage}/chain.pem"
  --private-key "${lineage}/privkey.pem"
)

media_record_event certificate-renewal started || fail "Certificate renewal event evidence could not be sealed."
media_run_bounded certificate-reconcile 120 "${rotation[@]}" --reconcile-only || fail "Mochirii Forums media certificate reconciliation is blocked; protected recovery evidence was retained."
if ! media_run_certbot_dns_transaction \
  "${acme_helper}" \
  "${credentials}" \
  700 \
  certbot renew \
    --cert-name media-forums.mochirii.com \
    --quiet \
    --deploy-hook /usr/local/sbin/mochirii-forums-rotate-media-certificate; then
  media_record_event certificate-renewal blocked || true
  fail "Mochirii Forums media certificate renewal or exact DNS cleanup failed; protected recovery evidence was retained."
fi
media_run_bounded certificate-preflight 120 "${rotation[@]}" --preflight-only || fail "Mochirii Forums media certificate renewal did not preserve the exact custom-host binding."
[[ ! -e ${MEDIA_ACME_JOURNAL} && ! -L ${MEDIA_ACME_JOURNAL} ]] || fail "Mochirii Forums media certificate renewal left a DNS cleanup journal."
media_record_event certificate-renewal passed || fail "Certificate renewal event evidence could not be sealed."
printf '%s\n' "Mochirii Forums media certificate renewal completed."
