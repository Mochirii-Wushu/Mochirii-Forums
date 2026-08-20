#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Contained activation verification must run as root."
[[ $# -eq 2 ]] || fail "Usage: verify-contained-activation.sh EXPECTED_COMMIT EXPECTED_PRODUCTION_CONFIGURATION_SHA256"
commit="$1"
configuration="$2"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Contained activation commit is malformed."
[[ ${configuration} =~ ^[0-9a-f]{64}$ ]] || fail "Contained activation configuration identity is malformed."
release_dir="/opt/mochirii/forums/releases/${commit}"
contained_config="/var/discourse/containers/releases/${commit}/${configuration}/activation.yml"

[[ -f ${contained_config} && ! -L ${contained_config} ]] || fail "Contained activation configuration is absent."
[[ -L /var/discourse/containers/app.yml ]] || fail "Active configuration is not versioned."
[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${contained_config}" ]] || fail "The active configuration is not the exact contained activation."
bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh" >/dev/null 2>&1 || fail "Contained activation refuses an unsealed deployment checkout."
bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Contained activation runtime assets differ."
[[ "$(docker inspect --format '{{.State.Running}}' app 2>/dev/null)" == true ]] || fail "Contained activation container is not running."
port_bindings="$(docker inspect --format '{{json .HostConfig.PortBindings}}' app 2>/dev/null)" || fail "Contained activation port readback failed."
python3 -B - "${port_bindings}" <<'PY' >/dev/null
import json
import sys
bindings = json.loads(sys.argv[1])
if set(bindings) != {"80/tcp"}:
    raise SystemExit("contained port inventory differs")
rows = bindings["80/tcp"]
if rows != [{"HostIp": "127.0.0.1", "HostPort": "18080"}]:
    raise SystemExit("contained loopback binding differs")
PY
docker exec app bash -lc '
  test "$MOCHIRII_REPOSITORY_COMMIT" = "$1"
  test "$DISCOURSE_ENABLE_DISCOURSE_CONNECT" = true
  test "$DISCOURSE_DISABLE_EMAILS" = non-staff
  test "$MOCHIRII_STAGE4_FIXTURE" = false
  test "$MOCHIRII_STAGE4_CONNECT_FIXTURE" = false
' bash "${commit}" >/dev/null 2>&1 || fail "Contained activation runtime flags differ."
docker exec app bash -lc 'cd /var/www/discourse && bundle exec rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-site.rb"' >/dev/null 2>&1 || fail "Contained activation site-setting verification failed."

python3 -B - <<'PY' >/dev/null
import http.client
import re
import subprocess
import urllib.parse

FORBIDDEN = re.compile(rb"(?:digitaloceanspaces[.]com|amazonaws[.]com|discourse[.](?:org|com)|powered\s+by\s+discourse)", re.I)

def request(path: str, cookie: str | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=15)
    headers = {"Host": "forums.mochirii.com", "User-Agent": "MochiriiActivationVerifier/1"}
    if cookie:
        headers["Cookie"] = cookie
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read(65537)
    if len(body) > 65536:
        raise RuntimeError("contained response exceeded its bound")
    result = response.status, dict(response.getheaders()), body
    connection.close()
    return result

status, headers, body = request("/session/sso")
if status != 302 or len(body) > 65536:
    raise RuntimeError("contained consumer did not issue one bounded redirect")
location = headers.get("Location") or headers.get("location")
cookie_header = headers.get("Set-Cookie") or headers.get("set-cookie")
if not isinstance(location, str) or len(location) > 8192 or not cookie_header:
    raise RuntimeError("contained consumer response boundary differs")
parsed = urllib.parse.urlsplit(location)
if parsed.scheme != "https" or parsed.netloc != "mochirii.com" or parsed.path != "/forums/connect" or parsed.fragment:
    raise RuntimeError("contained consumer escaped the exact producer origin")
query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
if set(query) != {"sso", "sig"} or any(len(values) != 1 for values in query.values()):
    raise RuntimeError("contained consumer request fields differ")
completed = subprocess.run(
    [
        "timeout", "45", "docker", "exec", "-i", "app", "timeout",
        "--signal=TERM", "--kill-after=10s", "30s", "bash", "-lc",
        'cd /var/www/discourse && bundle exec rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-contained-discourse-connect.rb"',
    ],
    input=location.encode("utf-8"),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    timeout=50,
    check=False,
)
if completed.returncode != 0:
    raise RuntimeError("contained consumer signature verification failed")
cookie = cookie_header.split(";", 1)[0]
for hostile in (
    "/session/sso_login?sso=Zm9v&sig=" + "0" * 64,
    "/session/sso_login?sso=Zm9v&sso=YmFy&sig=" + "0" * 64,
    "/session/sso_login?sso=%25&sig=malformed",
):
    hostile_status, hostile_headers, hostile_body = request(hostile, cookie)
    cache = (hostile_headers.get("Cache-Control") or hostile_headers.get("cache-control") or "").lower()
    referrer = (hostile_headers.get("Referrer-Policy") or hostile_headers.get("referrer-policy") or "").lower()
    if hostile_status != 419 or "no-store" not in cache or referrer != "no-referrer" or b"Mochirii" not in hostile_body or FORBIDDEN.search(hostile_body):
        raise RuntimeError("contained consumer hostile response escaped its private Mochirii boundary")
PY

bash "${release_dir}/scripts/verify-runtime-assets.sh" "${commit}" --require-container >/dev/null 2>&1 || fail "Contained activation assets changed during verification."
printf '%s\n' "Mochirii Forums contained consumer activation verified."
