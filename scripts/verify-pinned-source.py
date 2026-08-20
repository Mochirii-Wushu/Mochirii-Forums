#!/usr/bin/env python3
"""Verify exact upstream bytes and pin-specific semantic contracts."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKER_REPOSITORY = "discourse/discourse_docker"
CORE_REPOSITORY = "discourse/discourse"
MANAGER_REPOSITORY = "discourse/docker_manager"
ACME_REPOSITORY = "acmesh-official/acme.sh"


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        return None


OFFICIAL_OPENER = urllib.request.build_opener(NoRedirectHandler())


def validate_official_url(url: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.netloc != parsed.hostname
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RuntimeError("Official source URL is outside an exact HTTPS authority.")
    if parsed.hostname == "api.github.com":
        allowed_path = re.fullmatch(
            r"/repos/discourse/(?:discourse|discourse_docker|docker_manager)/(?:git/commits/[0-9a-f]{40}|git/tags/[0-9a-f]{40})",
            parsed.path,
        ) or re.fullmatch(
            r"/repos/acmesh-official/acme[.]sh/git/commits/[0-9a-f]{40}",
            parsed.path,
        ) or re.fullmatch(
            r"/repos/discourse/discourse_docker/(?:git/ref/heads/main|compare/[0-9a-f]{40}[.][.][.][0-9a-f]{40})",
            parsed.path,
        )
        if not allowed_path or parsed.query:
            raise RuntimeError("GitHub API URL is outside the exact source allowlist.")
    elif parsed.hostname == "raw.githubusercontent.com":
        decoded_path = urllib.parse.unquote(parsed.path, errors="strict")
        match = re.fullmatch(
            r"/discourse/(discourse|discourse_docker|docker_manager)/[0-9a-f]{40}/(.+)",
            decoded_path,
        ) or re.fullmatch(
            r"/acmesh-official/(acme[.]sh)/[0-9a-f]{40}/(.+)",
            decoded_path,
        )
        if (
            match is None
            or parsed.query
            or any(component in {"", ".", ".."} for component in match.group(2).split("/"))
        ):
            raise RuntimeError("Raw GitHub URL is outside the exact source allowlist.")
    elif parsed.hostname == "auth.docker.io":
        try:
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as error:
            raise RuntimeError("Registry authorization URL is malformed.") from error
        if parsed.path != "/token" or query != [
            ("service", "registry.docker.io"),
            ("scope", "repository:discourse/base:pull"),
        ]:
            raise RuntimeError("Registry authorization URL is outside the exact allowlist.")
    elif parsed.hostname == "registry-1.docker.io":
        if (
            not re.fullmatch(
                r"/v2/discourse/base/manifests/(?:[A-Za-z0-9_.-]{1,128}|sha256:[0-9a-f]{64})",
                parsed.path,
            )
            or parsed.query
        ):
            raise RuntimeError("Registry manifest URL is outside the exact allowlist.")
    else:
        raise RuntimeError("Official source URL hostname is not allowlisted.")
    return parsed


def request(url: str, *, headers: dict[str, str] | None = None, limit: int = 2 * 1024 * 1024) -> tuple[bytes, object]:
    parsed = validate_official_url(url)
    combined = {"User-Agent": "Mochirii-Forums-Pin-Verification/1", "Accept-Encoding": "identity"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and parsed.hostname == "api.github.com":
        combined["Authorization"] = f"Bearer {token}"
    if headers:
        combined.update(headers)
    error: Exception | None = None
    for attempt in range(3):
        try:
            with OFFICIAL_OPENER.open(urllib.request.Request(url, headers=combined), timeout=25) as response:
                if response.geturl() != url or response.status != 200:
                    raise RuntimeError("Official source response changed URL or status.")
                length = response.headers.get("Content-Length")
                if length and int(length) > limit:
                    raise RuntimeError(f"Remote response exceeds bound: {url}")
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise RuntimeError(f"Remote response exceeded bound: {url}")
                return body, response.headers
        except urllib.error.HTTPError as caught:
            if 300 <= caught.code < 400:
                raise RuntimeError("Official source redirect was blocked.") from None
            error = caught
            if attempt < 2:
                time.sleep(attempt + 1)
        except (OSError, urllib.error.URLError) as caught:
            error = caught
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError(f"Unable to verify official source URL: {url}") from error


def verified_file(repository: str, revision: str, entry: dict) -> bytes:
    path = urllib.parse.quote(entry["path"], safe="/")
    url = f"https://raw.githubusercontent.com/{repository}/{revision}/{path}"
    body, _ = request(url, limit=int(entry["bytes"]))
    if len(body) != entry["bytes"] or hashlib.sha256(body).hexdigest() != entry["sha256"]:
        raise RuntimeError(f"Official bytes changed: {repository}@{revision}:{entry['path']}")
    return body


def verify_commit(repository: str, revision: str, tree: str, verified: bool, reason: str) -> None:
    body, _ = request(f"https://api.github.com/repos/{repository}/git/commits/{revision}", limit=256 * 1024)
    document = json.loads(body)
    if (
        document.get("sha") != revision
        or document.get("tree", {}).get("sha") != tree
        or document.get("verification", {}).get("verified") is not verified
        or document.get("verification", {}).get("reason") != reason
    ):
        raise RuntimeError(f"Official commit identity changed: {repository}@{revision}")


def verify_current_main(provenance: dict) -> None:
    observation = provenance.get("driftObservation")
    expected_observation_keys = {
        "observedAt",
        "mainRevision",
        "mainTree",
        "mainCommitSignatureVerified",
        "mainCommitSignatureReason",
        "comparisonStatus",
        "commitsAheadOfPin",
        "commitsBehindPin",
        "totalCommits",
        "baseRevision",
        "mergeBaseRevision",
        "pinIsAncestor",
        "selectedForRuntime",
        "automaticPinUpdateAllowed",
        "changedPathInventoryComplete",
        "compatibilityReviewComplete",
        "reviewStatus",
        "changedPaths",
        "materialChangeScope",
        "rangeCommits",
    }
    if not isinstance(observation, dict) or set(observation) != expected_observation_keys:
        raise RuntimeError("Recorded deployment-source drift observation is malformed.")
    revision = observation.get("mainRevision")
    tree = observation.get("mainTree")
    pinned = provenance["upstream"]["revision"]
    if not isinstance(revision, str) or not isinstance(tree, str):
        raise RuntimeError("Recorded deployment-source main identity is malformed.")
    if not all(len(value) == 40 and value == value.lower() and all(character in "0123456789abcdef" for character in value) for value in (revision, tree)):
        raise RuntimeError("Recorded deployment-source main identity is malformed.")
    if (
        observation.get("observedAt") != "2026-08-20"
        or observation.get("comparisonStatus") != "ahead"
        or observation.get("baseRevision") != pinned
        or observation.get("mergeBaseRevision") != pinned
        or observation.get("pinIsAncestor") is not True
        or observation.get("selectedForRuntime") is not False
        or observation.get("automaticPinUpdateAllowed") is not False
        or observation.get("changedPathInventoryComplete") is not True
        or observation.get("compatibilityReviewComplete") is not False
        or observation.get("reviewStatus") != "drift-detected-separate-review-required"
    ):
        raise RuntimeError("Recorded deployment-source drift disposition changed.")
    counts = (
        observation.get("commitsAheadOfPin"),
        observation.get("commitsBehindPin"),
        observation.get("totalCommits"),
    )
    if any(type(value) is not int or value < 0 for value in counts) or counts != (10, 0, 10):
        raise RuntimeError("Recorded deployment-source comparison counts changed.")

    commits = observation.get("rangeCommits")
    material = observation.get("materialChangeScope")
    changed_paths = observation.get("changedPaths")
    if not isinstance(commits, list) or len(commits) != counts[2]:
        raise RuntimeError("Recorded deployment-source commit range is incomplete.")
    if not isinstance(material, list) or len(material) != len(commits):
        raise RuntimeError("Recorded deployment-source material-change scope is incomplete.")
    if (
        not isinstance(changed_paths, list)
        or changed_paths != sorted(changed_paths)
        or len(changed_paths) != len(set(changed_paths))
        or any(not isinstance(path, str) or not path or path.startswith(("/", ".")) or "\\" in path for path in changed_paths)
    ):
        raise RuntimeError("Recorded deployment-source changed-path inventory is malformed.")
    revisions: list[str] = []
    for entry in commits:
        if not isinstance(entry, dict) or set(entry) != {"revision", "tree", "signatureVerified", "signatureReason", "subject"}:
            raise RuntimeError("Recorded deployment-source range commit is malformed.")
        if type(entry["signatureVerified"]) is not bool or entry["signatureReason"] not in {"valid", "unsigned"}:
            raise RuntimeError("Recorded deployment-source range signature is malformed.")
        for key in ("revision", "tree"):
            value = entry.get(key)
            if not isinstance(value, str) or len(value) != 40 or value != value.lower() or any(character not in "0123456789abcdef" for character in value):
                raise RuntimeError("Recorded deployment-source range identity is malformed.")
        if not isinstance(entry.get("subject"), str) or not entry["subject"] or "\n" in entry["subject"]:
            raise RuntimeError("Recorded deployment-source range subject is malformed.")
        revisions.append(entry["revision"])
    if len(revisions) != len(set(revisions)) or revisions[-1] != revision:
        raise RuntimeError("Recorded deployment-source range order is malformed.")
    material_revisions: list[str] = []
    for entry in material:
        if not isinstance(entry, dict) or set(entry) != {"revision", "classification", "selectedForRuntime"}:
            raise RuntimeError("Recorded deployment-source material-change entry is malformed.")
        if entry.get("selectedForRuntime") is not False:
            raise RuntimeError("Observed upstream drift was selected without a compatibility change.")
        classification = entry.get("classification")
        if not isinstance(classification, str) or not classification or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in classification):
            raise RuntimeError("Recorded deployment-source material classification is malformed.")
        material_revisions.append(entry.get("revision"))
    if material_revisions != revisions:
        raise RuntimeError("Recorded deployment-source material scope does not bind the exact range.")

    ref_body, ref_headers = request(
        f"https://api.github.com/repos/{DOCKER_REPOSITORY}/git/ref/heads/main",
        limit=256 * 1024,
    )
    try:
        ref = json.loads(ref_body)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Official deployment-source main reference is malformed.") from error
    if not isinstance(ref, dict):
        raise RuntimeError("Official deployment-source main reference is ambiguous.")
    ref_object = ref.get("object")
    if (
        ref.get("ref") != "refs/heads/main"
        or not isinstance(ref_object, dict)
        or ref_object.get("type") != "commit"
        or ref_object.get("sha") != revision
        or ref_headers.get("Link") is not None
    ):
        raise RuntimeError("Official deployment-source main moved or returned an ambiguous reference.")

    verify_commit(
        DOCKER_REPOSITORY,
        revision,
        tree,
        observation["mainCommitSignatureVerified"],
        observation["mainCommitSignatureReason"],
    )
    compare_body, compare_headers = request(
        f"https://api.github.com/repos/{DOCKER_REPOSITORY}/compare/{pinned}...{revision}",
        limit=2 * 1024 * 1024,
    )
    try:
        comparison = json.loads(compare_body)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Official deployment-source comparison is malformed.") from error
    if not isinstance(comparison, dict) or compare_headers.get("Link") is not None:
        raise RuntimeError("Official deployment-source comparison is ambiguous or paginated.")
    if (
        comparison.get("status") != observation["comparisonStatus"]
        or comparison.get("ahead_by") != counts[0]
        or comparison.get("behind_by") != counts[1]
        or comparison.get("total_commits") != counts[2]
        or comparison.get("base_commit", {}).get("sha") != observation["baseRevision"]
        or comparison.get("merge_base_commit", {}).get("sha") != observation["mergeBaseRevision"]
    ):
        raise RuntimeError("Official deployment-source comparison moved after review.")
    actual_commits = comparison.get("commits")
    if not isinstance(actual_commits, list) or len(actual_commits) != len(commits):
        raise RuntimeError("Official deployment-source comparison range is incomplete.")
    for expected, actual in zip(commits, actual_commits, strict=True):
        actual_document = actual if isinstance(actual, dict) else {}
        commit = actual_document.get("commit", {})
        verification = commit.get("verification", {}) if isinstance(commit, dict) else {}
        message = commit.get("message") if isinstance(commit, dict) else None
        subject = message.splitlines()[0] if isinstance(message, str) and message else None
        if (
            actual_document.get("sha") != expected["revision"]
            or commit.get("tree", {}).get("sha") != expected["tree"]
            or verification.get("verified") is not expected["signatureVerified"]
            or verification.get("reason") != expected["signatureReason"]
            or subject != expected["subject"]
        ):
            raise RuntimeError("Official deployment-source comparison commit changed after review.")
    actual_paths = [entry.get("filename") for entry in comparison.get("files", []) if isinstance(entry, dict)]
    if actual_paths != changed_paths:
        raise RuntimeError("Official deployment-source changed-path inventory moved after review.")


def verify_registry(provenance: dict) -> None:
    token_body, _ = request(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:discourse/base:pull",
        limit=64 * 1024,
    )
    token = json.loads(token_body).get("token")
    if not token:
        raise RuntimeError("Registry did not issue a bounded pull token.")
    accept = ", ".join(
        (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
    )
    tag = provenance["baseImage"]["tag"].split(":", 1)[1]
    body, headers = request(
        f"https://registry-1.docker.io/v2/discourse/base/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": accept},
        limit=4 * 1024 * 1024,
    )
    if headers.get("Docker-Content-Digest") != provenance["baseImage"]["registryIndexDigestObservedAtReview"]:
        raise RuntimeError("Mutable base tag no longer resolves to the reviewed index digest.")
    index = json.loads(body)
    matches = [
        item
        for item in index.get("manifests", [])
        if item.get("platform", {}).get("os") == "linux" and item.get("platform", {}).get("architecture") == "amd64"
    ]
    expected = provenance["baseImage"]["linuxAmd64Digest"]
    if len(matches) != 1 or matches[0].get("digest") != expected:
        raise RuntimeError("Base index does not bind exactly one reviewed Linux AMD64 manifest.")
    _, manifest_headers = request(
        f"https://registry-1.docker.io/v2/discourse/base/manifests/{expected}",
        headers={"Authorization": f"Bearer {token}", "Accept": accept},
        limit=4 * 1024 * 1024,
    )
    if manifest_headers.get("Docker-Content-Digest") != expected:
        raise RuntimeError("Linux AMD64 base manifest digest changed.")


def require(source: dict[str, bytes], path: str, snippets: tuple[bytes, ...]) -> None:
    body = source[path]
    for snippet in snippets:
        if snippet not in body:
            raise RuntimeError(f"Pinned semantic contract changed: {path}: {snippet!r}")


def verify_semantics(docker: dict[str, bytes], core: dict[str, bytes]) -> None:
    require(
        docker,
        "templates/web.template.yml",
        (
            b"bundle install --jobs $(nproc --ignore=1) --retry 3",
            b"grep -q 'outlets/discourse' /etc/nginx/conf.d/discourse.conf",
            b"path: /usr/local/bin/rails",
            b'(cd /var/www/discourse && RAILS_ENV=production sudo -H -E -u discourse bundle exec script/rails "$@")',
            b"path: /usr/local/bin/discourse",
            b'(cd /var/www/discourse && RAILS_ENV=production sudo -H -E -u discourse bundle exec script/discourse "$@")',
        ),
    )
    if b"bundle install --jobs $(($(nproc) - 1)) --retry 3" in docker["templates/web.template.yml"]:
        raise RuntimeError("The one-core zero-job command returned.")
    require(
        docker,
        "launcher",
        (
            b"base_image=`cat $config_file",
            b"image=$base_image",
            b"pull_image",
            b"YAML.load(STDIN.readlines.join)['base_image']",
        ),
    )
    require(core, "app/models/translation_override.rb", (b"def self.upsert!(locale, key, value)",))
    require(
        core,
        "lib/tasks/themes.rake",
        (b'task "themes:install:archive" => :environment', b'filename = ENV["THEME_ARCHIVE"]', b"RemoteTheme.update_zipped_theme"),
    )
    require(
        core,
        "app/models/remote_theme.rb",
        (b'def self.update_zipped_theme(', b'theme_info["assets"]&.each', b"theme_id:"),
    )
    require(core, "app/models/theme.rb", (b"has_many :upload_fields", b"def set_default!"))
    require(core, "config/nginx.sample.conf", (b"include conf.d/outlets/discourse/*.conf;",))
    require(
        core,
        "app/views/layouts/_head.html.erb",
        (b'<meta name="generator" content="Discourse <%= Discourse::VERSION::STRING %> - https://github.com/discourse/discourse version <%= Discourse.git_version %>">',),
    )
    require(core, "app/views/metadata/opensearch.xml.erb", (b"<Tags>discourse forum</Tags>",))
    require(
        core,
        "lib/file_store/s3_store.rb",
        (b'list_missing(Upload.by_users, "original/")', b'list_missing(OptimizedImage, "optimized/")', b"presigned_get_url"),
    )
    require(core, "lib/s3_helper.rb", (b"return if !SiteSetting.s3_configure_tombstone_policy",))
    require(
        core,
        "config/routes.rb",
        (
            b'get "session/email-login/:token" => "session#email_login_info"',
            b'post "session/email-login/:token" => "session#email_login"',
            b'get "#{root_path}/admin-login" => "users#admin_login"',
            b'put "#{root_path}/admin-login" => "users#admin_login"',
        ),
    )
    require(
        core,
        "app/controllers/users_controller.rb",
        (
            b"def admin_login",
            b"User.real.admins.with_email(params[:email]).first",
            b"scope: EmailToken.scopes[:email_login]",
            b"Jobs.enqueue(:critical_user_email, type: \"admin_login\"",
        ),
    )
    require(
        core,
        "app/controllers/session_controller.rb",
        (
            b"def email_login_info",
            b"def email_login",
            b"check_local_login_allowed(user: user, check_login_via_email: true)",
            b"# admin-login can get around enabled SSO/disabled local logins",
            b"return if user&.admin?",
        ),
    )
    region = core["app/models/s3_region_site_setting.rb"]
    if b"whatever" in region or b"def self.valid_value?" not in region:
        raise RuntimeError("The pinned region enum no longer requires environment-only compatibility override.")
    settings = core["config/site_settings.yml"]
    for setting in (
        b"login_required:",
        b"allow_new_registrations:",
        b"discourse_connect_csrf_protection:",
        b"verbose_discourse_connect_logging:",
        b"secure_uploads:",
        b"enable_direct_s3_uploads:",
        b"s3_configure_tombstone_policy:",
        b"include_s3_uploads_in_backups:",
        b"allow_staff_to_upload_any_file_in_pm:",
        b"allow_all_attachments_for_group_messages:",
    ):
        if setting not in settings:
            raise RuntimeError(f"Pinned site setting disappeared: {setting!r}")
    plugin_settings = {
        "plugins/discourse-apple-auth/config/settings.yml": b"sign_in_with_apple_enabled:",
        "plugins/discourse-login-with-amazon/config/settings.yml": b"enable_login_with_amazon:",
        "plugins/discourse-microsoft-auth/config/settings.yml": b"microsoft_auth_enabled:",
        "plugins/discourse-oauth2-basic/config/settings.yml": b"oauth2_enabled:",
        "plugins/discourse-openid-connect/config/settings.yml": b"openid_connect_enabled:",
    }
    for path, setting in plugin_settings.items():
        require(core, path, (setting, b"default: false"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--require-current-main", action="store_true")
    args = parser.parse_args()

    if args.require_current_main and not args.online:
        parser.error("--require-current-main requires --online")

    provenance = load("docs/operations/upstream-provenance.v1.json")
    components = load("docs/operations/third-party-components.v1.json")
    identity = load("docs/operations/forum-central-identity.consumer.v1.json")
    if not args.online:
        print("Pinned-source manifest structure passed; online bytes were not requested.")
        return 0

    docker_revision = provenance["upstream"]["revision"]
    core_revision = components["application"]["revision"]
    manager = components["defaultStandaloneComponent"]
    vendored = components["vendoredRuntimeComponents"]
    if not isinstance(vendored, list) or len(vendored) != 1 or not isinstance(vendored[0], dict):
        raise RuntimeError("Vendored runtime component inventory differs.")
    acme = vendored[0]
    docker_source = {
        entry["path"]: verified_file(DOCKER_REPOSITORY, docker_revision, entry)
        for entry in provenance["files"]
    }
    core_entries: dict[str, dict] = {}
    for group in (components["application"]["evidenceFiles"], components["application"]["semanticEvidenceFiles"], identity["pinnedConsumerEvidence"]["evidenceFiles"]):
        for entry in group:
            core_entries[entry["path"]] = entry
    core_source = {
        path: verified_file(CORE_REPOSITORY, core_revision, entry)
        for path, entry in sorted(core_entries.items())
    }
    for entry in manager["evidenceFiles"]:
        verified_file(MANAGER_REPOSITORY, manager["revision"], entry)
    acme_source = verified_file(ACME_REPOSITORY, acme["revision"], acme["source"])
    acme_license = verified_file(
        ACME_REPOSITORY,
        acme["revision"],
        {
            "path": acme["license"]["upstreamPath"],
            "bytes": acme["license"]["bytes"],
            "sha256": acme["license"]["sha256"],
        },
    )
    encoded_text = (ROOT / acme["encodedSource"]["path"]).read_text(encoding="ascii")
    encoded_lines = encoded_text.splitlines()
    if (
        not encoded_text.endswith("\n")
        or not encoded_lines
        or any(not 1 <= len(line) <= 76 for line in encoded_lines)
        or any(len(line) != 76 for line in encoded_lines[:-1])
        or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded_lines[-1])
        or any(not re.fullmatch(r"[A-Za-z0-9+/]{76}", line) for line in encoded_lines[:-1])
    ):
        raise RuntimeError("Vendored immutable ACME encoding is malformed.")
    encoded = base64.b64decode("".join(encoded_lines), validate=True)
    if (
        len(encoded) != acme["encodedSource"]["compressedBytes"]
        or hashlib.sha256(encoded).hexdigest() != acme["encodedSource"]["compressedSha256"]
        or gzip.decompress(encoded) != acme_source
        or (ROOT / acme["license"]["repositoryPath"]).read_bytes() != acme_license
    ):
        raise RuntimeError("Vendored immutable ACME bytes differ from exact upstream evidence.")

    verify_commit(
        DOCKER_REPOSITORY,
        docker_revision,
        provenance["upstream"]["revisionTree"],
        provenance["upstream"]["revisionCommitSignatureVerified"],
        provenance["upstream"]["revisionCommitSignatureReason"],
    )
    verify_commit(CORE_REPOSITORY, core_revision, components["application"]["revisionTree"], False, "unsigned")
    verify_commit(
        MANAGER_REPOSITORY,
        manager["revision"],
        manager["revisionTree"],
        manager["revisionCommitSignatureVerified"],
        manager["revisionCommitSignatureReason"],
    )
    verify_commit(
        ACME_REPOSITORY,
        acme["revision"],
        acme["revisionTree"],
        acme["revisionCommitSignatureVerified"],
        acme["revisionCommitSignatureReason"],
    )
    tag_body, _ = request(
        f"https://api.github.com/repos/{CORE_REPOSITORY}/git/tags/{components['application']['tagObjectSha1']}",
        limit=256 * 1024,
    )
    tag = json.loads(tag_body)
    if tag.get("tag") != components["application"]["release"] or tag.get("object", {}).get("sha") != core_revision:
        raise RuntimeError("Discourse annotated release tag changed.")

    verify_semantics(docker_source, core_source)
    verify_registry(provenance)
    if args.require_current_main:
        verify_current_main(provenance)
        print("Recorded official deployment-source main observation is still exact.")
    print("Exact upstream bytes, APIs, revisions, and base-image digests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
