#!/usr/bin/env python3
"""Materialize the sanitized standalone template without exposing values."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "config" / "app.yml.example"
TLS_FRAGMENT = ROOT / "config" / "immutable-letsencrypt.fragment.yml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+)$")
HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
USER = re.compile(r"^[^\r\n\x00]{1,256}$")
ALLOWED_AUTH = {"plain", "login", "cram_md5"}
PRODUCTION_KEYS = {
    "FORUMS_ACTIVATION_ENABLED",
    "FORUMS_DEVELOPER_EMAILS",
    "FORUMS_DISCOURSE_CONNECT_ENABLED",
    "FORUMS_DISCOURSE_CONNECT_SECRET",
    "FORUMS_NOTIFICATION_EMAIL",
    "FORUMS_S3_ACCESS_KEY_ID",
    "FORUMS_S3_SECRET_ACCESS_KEY",
    "FORUMS_SMTP_ADDRESS",
    "FORUMS_SMTP_AUTHENTICATION",
    "FORUMS_SMTP_PASSWORD",
    "FORUMS_SMTP_PORT",
    "FORUMS_SMTP_USER_NAME",
}


class RenderError(RuntimeError):
    pass


def tls_fragment_section(name: str) -> str:
    if name not in {"ENV", "HOOKS", "RUN"}:
        raise RenderError("Immutable TLS fragment section is outside the exact allowlist.")
    text = TLS_FRAGMENT.read_text(encoding="utf-8")
    begin = f"# MOCHIRII TLS {name} BEGIN\n"
    end = f"# MOCHIRII TLS {name} END\n"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise RenderError("Immutable TLS fragment markers differ from the exact contract.")
    before, remainder = text.split(begin, 1)
    section, after = remainder.split(end, 1)
    if name == "ENV" and before:
        raise RenderError("Immutable TLS fragment has bytes before its first section.")
    if not section or "# MOCHIRII TLS" in section:
        raise RenderError("Immutable TLS fragment section is empty or nested.")
    del after
    return section.rstrip("\n")


def runtime(name: str, *, secret: bool = False) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RenderError(f"Required runtime variable is absent: {name}")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise RenderError(f"Runtime variable must be a single line: {name}")
    if len(value) > (8192 if secret else 512):
        raise RenderError(f"Runtime variable exceeds its bound: {name}")
    return value


def protected(values: dict[str, str], name: str, *, secret: bool = False, allow_empty: bool = False) -> str:
    value = values.get(name)
    if not isinstance(value, str) or (not value and not allow_empty):
        raise RenderError(f"Required protected runtime field is absent: {name}")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise RenderError(f"Protected runtime field must be a literal single line: {name}")
    if len(value) > (8192 if secret else 512):
        raise RenderError(f"Protected runtime field exceeds its bound: {name}")
    return value


def load_protected_runtime(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise RenderError("Protected runtime JSON must be one regular file.")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RenderError("Protected runtime JSON must be mode 0600.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RenderError("Protected runtime JSON is invalid.") from error
    if not isinstance(document, dict) or set(document) != PRODUCTION_KEYS:
        raise RenderError("Protected runtime JSON keys differ from the exact allowlist.")
    if any(not isinstance(value, str) for value in document.values()):
        raise RenderError("Every protected runtime JSON value must be a literal string.")
    return document


def scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def valid_email(value: str) -> bool:
    if len(value) > 254:
        return False
    match = EMAIL.fullmatch(value)
    if not match:
        return False
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return bool(HOST.fullmatch(domain))


def fixture_values(*, connect: bool = False) -> dict[str, str]:
    commit = os.environ.get("FORUMS_REPOSITORY_COMMIT", "0" * 40)
    if not SHA40.fullmatch(commit):
        raise RenderError("FORUMS_REPOSITORY_COMMIT must be one lowercase full commit when supplied.")
    connect_secret = runtime("FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET", secret=True) if connect else ""
    if connect and not HEX64.fullmatch(connect_secret):
        raise RenderError(
            "FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET must be exactly 64 lowercase hex characters."
        )
    return {
        "__MOCHIRII_TLS_TEMPLATES__": "  # TLS is disabled only in the loopback fixture.",
        "__MOCHIRII_TLS_ENV__": "  # Public TLS is disabled only in the loopback fixture.",
        "__MOCHIRII_TLS_HOOKS__": "  # No public TLS lifecycle hook is installed in the loopback fixture.",
        "__MOCHIRII_TLS_RUN__": "  # No public TLS client is installed in the loopback fixture.",
        "__MOCHIRII_EXPOSE__": '  - "127.0.0.1:18080:80"',
        "__MOCHIRII_DEVELOPER_EMAILS__": scalar("stage4-fixture@forums.mochirii.com"),
        "__MOCHIRII_SMTP_ADDRESS__": scalar("127.0.0.1"),
        "__MOCHIRII_SMTP_PORT__": scalar("1"),
        "__MOCHIRII_SMTP_USER_NAME__": scalar("fixture"),
        "__MOCHIRII_SMTP_PASSWORD__": scalar("fixture-not-a-secret"),
        "__MOCHIRII_SMTP_AUTHENTICATION__": scalar("plain"),
        "__MOCHIRII_ENABLE_DISCOURSE_CONNECT__": '"true"' if connect else '"false"',
        "__MOCHIRII_DISCOURSE_CONNECT_SECRET__": scalar(connect_secret),
        "__MOCHIRII_ENABLE_S3_UPLOADS__": '"false"',
        "__MOCHIRII_S3_ACCESS_KEY_ID__": scalar("fixture"),
        "__MOCHIRII_S3_SECRET_ACCESS_KEY__": scalar("fixture-not-a-secret"),
        "__MOCHIRII_BACKUP_LOCATION__": '"local"',
        "__MOCHIRII_STAGE4_FIXTURE__": '"true"',
        "__MOCHIRII_STAGE4_CONNECT_FIXTURE__": '"true"' if connect else '"false"',
        "__MOCHIRII_NOTIFICATION_EMAIL__": scalar("notifications@fixture.invalid"),
        "__MOCHIRII_CONTACT_EMAIL__": scalar("notifications@fixture.invalid"),
        "__MOCHIRII_EXPECTED_NOTIFICATION_EMAIL__": scalar("notifications@fixture.invalid"),
        "__MOCHIRII_REPOSITORY_COMMIT__": scalar(commit),
        "__MOCHIRII_RELEASE_ASSET_HOST__": f"/opt/mochirii/forums/runtime-assets/{commit}",
        "__MOCHIRII_RELEASE_ASSET_ROOT__": scalar("/opt/mochirii-release"),
        "__MOCHIRII_DISABLE_EMAILS__": scalar("non-staff"),
    }


def production_values(
    values: dict[str, str],
    repository_commit: str,
    *,
    disposable_restore: bool = False,
    contained_activation: bool = False,
) -> dict[str, str]:
    if values.get("FORUMS_ACTIVATION_ENABLED") != "true":
        raise RenderError(
            "Production rendering is disabled unless FORUMS_ACTIVATION_ENABLED=true exactly."
        )

    if not SHA40.fullmatch(repository_commit):
        raise RenderError("Repository commit must be one lowercase full commit.")

    emails = protected(values, "FORUMS_DEVELOPER_EMAILS")
    email_list = emails.split(",")
    if not 1 <= len(email_list) <= 20 or any(not valid_email(email) for email in email_list):
        raise RenderError("FORUMS_DEVELOPER_EMAILS is not a bounded email list.")

    commit = repository_commit
    address = protected(values, "FORUMS_SMTP_ADDRESS")
    if not HOST.fullmatch(address):
        raise RenderError("FORUMS_SMTP_ADDRESS must be one DNS hostname.")
    port = protected(values, "FORUMS_SMTP_PORT")
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise RenderError("FORUMS_SMTP_PORT must be an integer from 1 through 65535.")
    username = protected(values, "FORUMS_SMTP_USER_NAME")
    if not USER.fullmatch(username):
        raise RenderError("FORUMS_SMTP_USER_NAME is malformed.")
    authentication = protected(values, "FORUMS_SMTP_AUTHENTICATION")
    if authentication not in ALLOWED_AUTH:
        raise RenderError("FORUMS_SMTP_AUTHENTICATION is outside the reviewed values.")

    notification_email = protected(values, "FORUMS_NOTIFICATION_EMAIL")
    email_match = EMAIL.fullmatch(notification_email)
    if not valid_email(notification_email) or email_match is None:
        raise RenderError("FORUMS_NOTIFICATION_EMAIL must be one bounded email address.")
    email_domain = email_match.group(1).lower()
    if email_domain != "mochirii.com" and not email_domain.endswith(".mochirii.com"):
        raise RenderError("FORUMS_NOTIFICATION_EMAIL must use a Mochirii-owned domain.")

    connect_flag = protected(values, "FORUMS_DISCOURSE_CONNECT_ENABLED")
    if connect_flag not in {"true", "false"}:
        raise RenderError("FORUMS_DISCOURSE_CONNECT_ENABLED must be true or false exactly.")
    connect = connect_flag == "true" and not disposable_restore
    if contained_activation and not connect:
        raise RenderError("Contained activation requires the built-in consumer to be enabled.")
    supplied_connect_secret = protected(
        values, "FORUMS_DISCOURSE_CONNECT_SECRET", secret=True, allow_empty=True
    )
    connect_secret = supplied_connect_secret if connect else ""
    if connect and not HEX64.fullmatch(connect_secret):
        raise RenderError("FORUMS_DISCOURSE_CONNECT_SECRET must be exactly 64 lowercase hex characters.")
    if connect_flag == "false" and supplied_connect_secret:
        raise RenderError("A disabled DiscourseConnect consumer may not retain a runtime secret.")

    tls_enabled = not disposable_restore and not contained_activation
    return {
        "__MOCHIRII_TLS_TEMPLATES__": (
            "  # TLS is intentionally absent while the runtime is isolated on loopback."
            if not tls_enabled
            else '  - "templates/web.ssl.template.yml"'
        ),
        "__MOCHIRII_TLS_ENV__": (
            tls_fragment_section("ENV") if tls_enabled
            else "  # Public TLS is intentionally absent while the runtime is isolated on loopback."
        ),
        "__MOCHIRII_TLS_HOOKS__": (
            tls_fragment_section("HOOKS") if tls_enabled
            else "  # No public TLS lifecycle hook is installed in loopback containment."
        ),
        "__MOCHIRII_TLS_RUN__": (
            tls_fragment_section("RUN") if tls_enabled
            else "  # No public TLS client is installed in loopback containment."
        ),
        "__MOCHIRII_EXPOSE__": (
            '  - "127.0.0.1:18080:80"'
            if disposable_restore or contained_activation
            else '  - "80:80"\n  - "443:443"'
        ),
        "__MOCHIRII_DEVELOPER_EMAILS__": scalar(emails),
        "__MOCHIRII_SMTP_ADDRESS__": scalar(address),
        "__MOCHIRII_SMTP_PORT__": scalar(port),
        "__MOCHIRII_SMTP_USER_NAME__": scalar(username),
        "__MOCHIRII_SMTP_PASSWORD__": scalar(protected(values, "FORUMS_SMTP_PASSWORD", secret=True)),
        "__MOCHIRII_SMTP_AUTHENTICATION__": scalar(authentication),
        "__MOCHIRII_ENABLE_DISCOURSE_CONNECT__": '"true"' if connect else '"false"',
        "__MOCHIRII_DISCOURSE_CONNECT_SECRET__": scalar(connect_secret),
        "__MOCHIRII_ENABLE_S3_UPLOADS__": '"true"',
        "__MOCHIRII_S3_ACCESS_KEY_ID__": scalar(protected(values, "FORUMS_S3_ACCESS_KEY_ID", secret=True)),
        "__MOCHIRII_S3_SECRET_ACCESS_KEY__": scalar(protected(values, "FORUMS_S3_SECRET_ACCESS_KEY", secret=True)),
        "__MOCHIRII_BACKUP_LOCATION__": '"s3"',
        "__MOCHIRII_STAGE4_FIXTURE__": '"false"',
        "__MOCHIRII_STAGE4_CONNECT_FIXTURE__": '"false"',
        "__MOCHIRII_NOTIFICATION_EMAIL__": scalar(notification_email),
        "__MOCHIRII_CONTACT_EMAIL__": scalar(notification_email),
        "__MOCHIRII_EXPECTED_NOTIFICATION_EMAIL__": scalar(notification_email),
        "__MOCHIRII_REPOSITORY_COMMIT__": scalar(commit),
        "__MOCHIRII_RELEASE_ASSET_HOST__": f"/opt/mochirii/forums/runtime-assets/{commit}",
        "__MOCHIRII_RELEASE_ASSET_ROOT__": scalar("/opt/mochirii-release"),
        "__MOCHIRII_DISABLE_EMAILS__": scalar(
            "yes" if disposable_restore else ("non-staff" if contained_activation else "no")
        ),
    }


def render(
    mode: str,
    output: Path,
    *,
    runtime_values: dict[str, str] | None = None,
    repository_commit: str | None = None,
) -> None:
    if mode in {"stage4-fixture", "stage4-connect-fixture"}:
        if runtime_values is not None or repository_commit is not None:
            raise RenderError("Fixture rendering may not consume production runtime JSON.")
        values = fixture_values(connect=mode == "stage4-connect-fixture")
    else:
        if runtime_values is None or repository_commit is None:
            raise RenderError("Production rendering requires protected runtime JSON and an exact commit.")
        values = production_values(
            runtime_values,
            repository_commit,
            disposable_restore=mode == "disposable-restore",
            contained_activation=mode == "contained-activation",
        )
    rendered = TEMPLATE.read_text(encoding="utf-8")
    for token, value in values.items():
        count = rendered.count(token)
        if count != 1:
            raise RenderError(f"Expected exactly one template token {token}; found {count}.")
        rendered = rendered.replace(token, value)
    remaining = sorted(set(re.findall(r"__MOCHIRII_[A-Z0-9_]+__", rendered)))
    if remaining:
        raise RenderError("Unresolved template tokens remain: " + ", ".join(remaining))
    if output.resolve() == TEMPLATE.resolve():
        raise RenderError("The sanitized template may not be overwritten.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8", newline="\n")
    output.chmod(stat.S_IRUSR | stat.S_IWUSR)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=(
            "stage4-fixture",
            "stage4-connect-fixture",
            "production",
            "disposable-restore",
            "contained-activation",
        ),
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-json", type=Path)
    parser.add_argument("--repository-commit")
    args = parser.parse_args()
    protected_runtime = None
    if args.runtime_json is not None:
        protected_runtime = load_protected_runtime(args.runtime_json)
    render(
        args.mode,
        args.output.resolve(),
        runtime_values=protected_runtime,
        repository_commit=args.repository_commit,
    )
    print(f"Rendered {args.mode} configuration with values redacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
