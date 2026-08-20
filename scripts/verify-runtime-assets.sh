#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "Runtime-asset verification must run as root."
[[ $# -eq 1 || ( $# -eq 2 && $2 == --require-container ) ]] || fail "Usage: verify-runtime-assets.sh COMMIT [--require-container]"
commit="$1"
require_container="${2:-}"
[[ ${commit} =~ ^[0-9a-f]{40}$ ]] || fail "Runtime-asset release commit is malformed."

release_dir="/opt/mochirii/forums/releases/${commit}"
asset_dir="/opt/mochirii/forums/runtime-assets/${commit}"
guest_dir="/opt/mochirii-release"
[[ -d ${release_dir} && ! -L ${release_dir} ]] || fail "Sealed release source is absent."
[[ -d ${asset_dir} && ! -L ${asset_dir} ]] || fail "Versioned runtime assets are absent."
[[ "$(stat -c '%U:%G %a' "${asset_dir}")" == "root:root 755" ]] || fail "Runtime-asset directory permissions differ."

runtime_assets=(
  acme-sh-3.0.6.gz.b64
  backup-transaction.py
  backup-url-boundary.rb
  configure-site.rb
  expire-discourse-connect-nonce.rb
  fetch-disaster-recovery-evidence.rb
  fetch-disaster-recovery-release.rb
  mochirii-release.tar
  mochirii-email-metadata-plugin.rb
  mochirii-theme.zip
  normal-upload-inventory.rb
  prepare-admin-recovery-fixture.rb
  prepare-backup-marker.rb
  publish-disaster-recovery-evidence.rb
  render-branding-email.rb
  storage-response-boundary.rb
  verify-break-glass-admin.rb
  verify-clean-disaster-target.rb
  verify-contained-discourse-connect.rb
  verify-backup.rb
  verify-discourse-connect-fixture.rb
  verify-sensitive-log-redaction.rb
  verify-restored-backup.rb
  verify-site.rb
  verify-storage-fixture.rb
  verify-zero-secure-uploads.rb
)

python3 - "${asset_dir}" "${runtime_assets[@]}" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
expected = set(sys.argv[2:])
observed = set()
for entry in root.iterdir():
    metadata = entry.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("Runtime-asset inventory contains a linked or non-regular entry.")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise SystemExit("Runtime-asset file permissions differ.")
    observed.add(entry.name)
if observed != expected:
    raise SystemExit("Runtime-asset inventory differs from the exact allowlist.")
PY

for script in backup-transaction.py backup-url-boundary.rb configure-site.rb expire-discourse-connect-nonce.rb fetch-disaster-recovery-evidence.rb fetch-disaster-recovery-release.rb normal-upload-inventory.rb prepare-admin-recovery-fixture.rb prepare-backup-marker.rb publish-disaster-recovery-evidence.rb render-branding-email.rb storage-response-boundary.rb verify-backup.rb verify-break-glass-admin.rb verify-clean-disaster-target.rb verify-contained-discourse-connect.rb verify-discourse-connect-fixture.rb verify-restored-backup.rb verify-sensitive-log-redaction.rb verify-site.rb verify-storage-fixture.rb verify-zero-secure-uploads.rb; do
  cmp -s -- "${release_dir}/scripts/${script}" "${asset_dir}/${script}" || fail "Runtime script differs from sealed release source."
done
cmp -s -- "${release_dir}/plugins/mochirii_email_metadata/plugin.rb" "${asset_dir}/mochirii-email-metadata-plugin.rb" || fail "Mail metadata component differs from sealed release source."
cmp -s -- "${release_dir}/config/acme-sh-3.0.6.gz.b64" "${asset_dir}/acme-sh-3.0.6.gz.b64" || fail "Immutable ACME client payload differs from sealed release source."
[[ "$(base64 --decode "${asset_dir}/acme-sh-3.0.6.gz.b64" | sha256sum | awk '{print $1}')" == "a42ebbbddb439b989272e97d9e8f1d354311d48f3b56543583a3b345fac0492c" ]] || fail "Immutable ACME client payload digest differs."

theme_candidate="$(mktemp /tmp/mochirii-theme-verify.XXXXXXXX.zip)"
inspect_candidate=""
cleanup() {
  [[ ! -f ${theme_candidate} ]] || rm -f -- "${theme_candidate}"
  [[ -z ${inspect_candidate} || ! -f ${inspect_candidate} ]] || rm -f -- "${inspect_candidate}"
}
trap cleanup EXIT
PYTHONDONTWRITEBYTECODE=1 python3 "${release_dir}/scripts/build-theme-archive.py" --output "${theme_candidate}" >/dev/null
cmp -s -- "${theme_candidate}" "${asset_dir}/mochirii-theme.zip" || fail "Theme archive differs from the deterministic sealed release build."

PYTHONDONTWRITEBYTECODE=1 python3 -B - \
  "${release_dir}/scripts/historical-release-disaster-recovery.py" \
  "${asset_dir}/mochirii-release.tar" "${release_dir}" "${commit}" <<'PY'
import importlib.util
import pathlib
import sys

helper_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
release_root = pathlib.Path(sys.argv[3])
commit = sys.argv[4]
specification = importlib.util.spec_from_file_location("mochirii_runtime_release_identity", helper_path)
if specification is None or specification.loader is None:
    raise SystemExit("Historical release identity helper could not be loaded.")
helper = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = helper
specification.loader.exec_module(helper)
identity = helper.inspect_archive(archive_path, commit)
source_tree, source_manifest = helper.source_identity(release_root)
if identity.repository_tree != source_tree:
    raise SystemExit("Runtime release archive tree differs from the sealed release source.")
if identity.content_manifest_sha256 != source_manifest:
    raise SystemExit("Runtime release archive manifest differs from the sealed release source.")
inspection = helper.inspect_document(identity)
expected_keys = {
    "schemaVersion", "repositoryCommit", "repositoryTree", "releaseArchiveSha256",
    "releaseArchiveBytes", "releaseArchiveContentManifestSha256",
    "releaseArchiveSourceFormat", "containsSecrets", "containsSignedUrls",
    "ordinaryDeploymentRequiresCurrentMain", "historicalReleaseAdoptionScope",
}
if set(inspection) != expected_keys or inspection.get("schemaVersion") != 1:
    raise SystemExit("Runtime release archive inspection schema differs.")
if (
    inspection.get("containsSecrets") is not False
    or inspection.get("containsSignedUrls") is not False
    or inspection.get("ordinaryDeploymentRequiresCurrentMain") is not True
    or inspection.get("historicalReleaseAdoptionScope") != "clean-target-disaster-recovery-only"
    or inspection.get("releaseArchiveSourceFormat") != "git-archive-tar-v1"
):
    raise SystemExit("Runtime release archive recovery boundary differs.")
PY

if [[ ${require_container} == --require-container ]]; then
  inspect_candidate="$(mktemp /tmp/mochirii-asset-mount-inspect.XXXXXXXX.json)"
  timeout 30 docker inspect app >"${inspect_candidate}" 2>/dev/null || fail "Application mount readback failed."
  python3 - "${inspect_candidate}" "${asset_dir}" "${guest_dir}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
    raise SystemExit("Application inspection shape differs.")
expected_source = sys.argv[2]
expected_destination = sys.argv[3]
mounts = document[0].get("Mounts")
if not isinstance(mounts, list):
    raise SystemExit("Application mount inventory is absent.")
exact = []
for mount in mounts:
    if not isinstance(mount, dict):
        raise SystemExit("Application mount entry is malformed.")
    source = mount.get("Source")
    destination = mount.get("Destination")
    writable = mount.get("RW")
    if not isinstance(source, str) or not isinstance(destination, str) or not isinstance(writable, bool):
        raise SystemExit("Application mount fields are malformed.")
    source_reaches_assets = source == expected_source or expected_source.startswith(source.rstrip("/") + "/")
    destination_reaches_guest = destination == expected_destination or expected_destination.startswith(destination.rstrip("/") + "/")
    if source == expected_source and destination == expected_destination:
        exact.append(mount)
    elif source_reaches_assets or destination_reaches_guest:
        raise SystemExit("A second application mount can reach the protected runtime assets.")
if len(exact) != 1 or exact[0].get("Type") != "bind" or exact[0].get("RW") is not False:
    raise SystemExit("Protected runtime assets are not mounted exactly once read-only.")
PY
fi

printf '%s\n' "Mochirii Forums runtime assets verified."
