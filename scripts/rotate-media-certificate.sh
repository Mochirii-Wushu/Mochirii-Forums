#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || exit 1
[[ ${RENEWED_DOMAINS:-} == "media-forums.mochirii.com" ]] || exit 1
[[ ${RENEWED_LINEAGE:-} == "/etc/letsencrypt/live/media-forums.mochirii.com" ]] || exit 1
[[ ! -e /var/lib/mochirii/forums/deployment-mutation.json && ! -L /var/lib/mochirii/forums/deployment-mutation.json ]] || exit 1

exec /usr/local/libexec/mochirii-forums/rotate-media-certificate.py \
  --runtime-json /etc/mochirii/forums-media-certificate.json \
  --certificate "${RENEWED_LINEAGE}/cert.pem" \
  --chain "${RENEWED_LINEAGE}/chain.pem" \
  --private-key "${RENEWED_LINEAGE}/privkey.pem"
