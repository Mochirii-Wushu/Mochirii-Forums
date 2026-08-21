#!/usr/bin/env python3
"""Exercise the pinned built-in consumer over the loopback HTTP boundary."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import subprocess
import tempfile
from http.cookies import SimpleCookie
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse


MAX_BYTES = 2 * 1024 * 1024
FORBIDDEN = (
    re.compile(rb'<meta\s+name=["\']generator["\']\s+content=["\']Discourse', re.I),
    re.compile(rb'>\s*Powered by Discourse\s*<', re.I),
    re.compile(rb'https?://(?:[^/]+\.)?discourse\.(?:org|com)', re.I),
    re.compile(rb'digitaloceanspaces\.com', re.I),
    re.compile(rb'amazonaws\.com', re.I),
)
VALUE_FORBIDDEN = (
    re.compile(rb"\bdiscobot\b", re.I),
    re.compile(rb"\bDiscourse(?:Connect)?\b", re.I),
    re.compile(rb"(?:^|[./])discourse\.(?:org|com)", re.I),
    re.compile(rb"digitaloceanspaces\.com", re.I),
    re.compile(rb"amazonaws\.com", re.I),
)
VISIBLE_UPSTREAM = re.compile(rb"\bDiscourse(?:Connect)?\b", re.I)
CALLBACK_LOG_MARKERS: set[bytes] = {
    b"mochirii-stage4-consumer-fixture",
    b"stage4-fixture@forums.mochirii.com",
    b"mochirii-s4-test",
    b"Mochirii Stage 4 Fixture",
    b"stage4-fixture%40forums.mochirii.com",
    b"Mochirii%20Stage%204%20Fixture",
    b"Mochirii+Stage+4+Fixture",
}
FORBIDDEN_RESPONSE_METADATA = re.compile(
    r"(?:\bdiscourse\b|(?:^|[./-])discourse(?:[./-]|$)|digitalocean(?:spaces)?|amazonaws)",
    re.I,
)


class VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "template"}:
            self.hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "template"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def register_sensitive_marker(value: str | bytes) -> None:
    marker = value.encode("ascii") if isinstance(value, str) else value
    if 16 <= len(marker) <= 16_384:
        CALLBACK_LOG_MARKERS.add(marker)


def register_admin_recovery_markers(tokens: tuple[bytes, ...]) -> None:
    for token in tokens:
        encoded = quote(token.decode("ascii"), safe="").encode("ascii")
        register_sensitive_marker(token)
        register_sensitive_marker(encoded)
        register_sensitive_marker(b"/session/email-login/" + encoded)


def sensitive_marker_reached(content: bytes, markers: list[bytes] | tuple[bytes, ...]) -> bool:
    return any(marker in content for marker in markers)


class Session:
    def __init__(self, port: int) -> None:
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, list[str]], bytes]:
        headers = {
            "Host": "forums.mochirii.com",
            "Accept-Encoding": "identity",
            "User-Agent": "Mochirii-Forums-DiscourseConnect-Fixture/1",
        }
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        if extra_headers:
            headers.update(extra_headers)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            values: dict[str, list[str]] = {}
            for name, value in response.getheaders():
                if FORBIDDEN_RESPONSE_METADATA.search(name) or FORBIDDEN_RESPONSE_METADATA.search(value):
                    raise RuntimeError("A member-facing response header exposed prohibited identity.")
                values.setdefault(name.lower(), []).append(value)
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise RuntimeError("DiscourseConnect fixture response exceeded its byte bound.")
            for raw_cookie in values.get("set-cookie", []):
                parsed = SimpleCookie()
                parsed.load(raw_cookie)
                for name, morsel in parsed.items():
                    self.cookies[name] = morsel.value
            return response.status, values, body
        finally:
            connection.close()

    def get(self, path: str) -> tuple[int, dict[str, list[str]], bytes]:
        return self.request("GET", path)

    def post_form(
        self, path: str, fields: dict[str, str], csrf: str
    ) -> tuple[int, dict[str, list[str]], bytes]:
        encoded = urlencode(fields).encode("ascii")
        return self.request(
            "POST",
            path,
            body=encoded,
            extra_headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(encoded)),
                "X-CSRF-Token": csrf,
                "X-Requested-With": "XMLHttpRequest",
            },
        )


def exactly_one(values: dict[str, list[str]], name: str) -> str:
    entries = values.get(name, [])
    if len(entries) != 1:
        raise RuntimeError(f"Expected exactly one {name} header.")
    return entries[0]


def request_nonce(session: Session, secret: bytes) -> str:
    status, headers, _body = session.get("/session/sso?return_path=%2Flatest")
    if status != 302:
        raise RuntimeError("Built-in consumer did not issue its signed producer request.")
    location = exactly_one(headers, "location")
    parsed = urlparse(location)
    if (parsed.scheme, parsed.netloc, parsed.path) != ("https", "mochirii.com", "/forums/connect"):
        raise RuntimeError("Consumer request escaped the exact Mochirii producer URL.")
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if set(query) != {"sso", "sig"} or any(len(values) != 1 for values in query.values()):
        raise RuntimeError("Consumer request query is not canonical.")
    encoded = query["sso"][0]
    expected = hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, query["sig"][0]):
        raise RuntimeError("Consumer request signature is invalid.")
    try:
        unsigned = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("Consumer request payload is malformed.") from error
    fields = parse_qs(unsigned, keep_blank_values=True, strict_parsing=True)
    if len(fields.get("nonce", [])) != 1:
        raise RuntimeError("Consumer request nonce is not canonical.")
    if fields.get("return_sso_url") != ["https://forums.mochirii.com/session/sso_login"]:
        raise RuntimeError("Consumer callback URL changed.")
    nonce = fields["nonce"][0]
    register_sensitive_marker(nonce)
    return nonce


def callback(nonce: str, secret: bytes) -> tuple[str, str]:
    unsigned = urlencode(
        {
            "nonce": nonce,
            "external_id": "mochirii-stage4-consumer-fixture",
            "email": "stage4-fixture@forums.mochirii.com",
            "username": "mochirii-s4-test",
            "name": "Mochirii Stage 4 Fixture",
            "suppress_welcome_message": "true",
        }
    )
    encoded = base64.b64encode(unsigned.encode("utf-8")).decode("ascii")
    signature = hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return encoded, signature


def callback_path(encoded: str, signature: str) -> str:
    encoded_query = quote(encoded, safe="")
    signature_query = quote(signature, safe="")
    for value in (
        encoded,
        signature,
        encoded_query,
        signature_query,
        "sso=" + encoded_query,
        "sig=" + signature_query,
    ):
        register_sensitive_marker(value)
    return "/session/sso_login?" + urlencode({"sso": encoded, "sig": signature})


def assert_branded_error(status: int, body: bytes, expected: int) -> None:
    if status != expected:
        raise RuntimeError(f"Hostile consumer fixture returned HTTP {status}, expected {expected}.")
    if b"Mochirii" not in body:
        raise RuntimeError("Hostile consumer response is not Mochirii-branded.")
    if any(pattern.search(body) for pattern in FORBIDDEN):
        raise RuntimeError("Hostile consumer response exposed prohibited branding.")
    parser = VisibleText()
    parser.feed(body.decode("utf-8"))
    if VISIBLE_UPSTREAM.search("\n".join(parser.parts).encode("utf-8")):
        raise RuntimeError("Hostile consumer response retained upstream identity.")


def stop_fixture_app() -> None:
    subprocess.run(
        ["timeout", "45", "sudo", "docker", "stop", "--time", "30", "app"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=50,
        check=False,
    )
    inspect = subprocess.run(
        ["timeout", "15", "sudo", "docker", "inspect", "--type", "container", "--format", "{{.State.Running}}", "app"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
    if inspect.returncode == 0 and inspect.stdout.strip() == b"false":
        return
    inventory = subprocess.run(
        ["timeout", "15", "sudo", "docker", "container", "ls", "--all", "--filter", "name=^/app$", "--format", "{{.Names}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
    if inventory.returncode == 0 and not inventory.stdout.strip():
        return
    raise RuntimeError("CRITICAL: disposable application containment could not be proved.")


def container_operation_absent(token: str) -> bool:
    probe = subprocess.run(
        [
            "timeout", "35", "sudo", "docker", "exec", "app", "timeout",
            "--signal=TERM", "--kill-after=5s", "25s", "ruby", "-e",
            (
                'marker = "MOCHIRII_OPERATION_TOKEN=#{ARGV.fetch(0)}"; '
                'found = Dir.glob("/proc/[0-9]*/environ").any? do |path|; '
                'begin; File.binread(path).split("\\0", -1).include?(marker); '
                'rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH; false; end; end; '
                'exit(found ? 1 : 0)'
            ),
            token,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=40,
        check=False,
    )
    return probe.returncode == 0


def run_container_runner(
    script: str,
    *,
    arguments: tuple[str, ...] = (),
    input_bytes: bytes | None = None,
    capture_stdout: bool = False,
) -> bytes:
    token = secrets.token_hex(16)
    command = [
        "sudo", "docker", "exec", "-i", "-e", f"MOCHIRII_OPERATION_TOKEN={token}",
        "app", "timeout", "--signal=TERM", "--kill-after=10s", "45s",
        "bash", "-lc", script, "bash", *arguments,
    ]
    completed: subprocess.CompletedProcess[bytes] | None = None
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    if not container_operation_absent(token):
        stop_fixture_app()
        raise RuntimeError("A disposable in-container fixture survived its operation boundary.")
    if timed_out or completed is None or completed.returncode != 0:
        raise RuntimeError("A disposable in-container fixture failed within its bounded operation.")
    output = completed.stdout or b""
    if len(output) > 16_384:
        raise RuntimeError("A disposable in-container fixture exceeded its output boundary.")
    return output.strip()


def expire_nonce(nonce: str) -> None:
    run_container_runner(
        '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/expire-discourse-connect-nonce.rb"',
        input_bytes=(nonce + "\n").encode("ascii"),
    )


def verify_fixture_user() -> None:
    run_container_runner(
        '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-discourse-connect-fixture.rb"',
    )


def admin_recovery_fixture(action: str) -> bytes:
    if action not in {"issue", "cleanup"}:
        raise RuntimeError("Admin recovery fixture action is malformed.")
    return run_container_runner(
        '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/prepare-admin-recovery-fixture.rb" "$1"',
        arguments=(action,),
        capture_stdout=True,
    )


def assert_admin_login_form_denied(session: Session) -> None:
    for path in (
        "/u/admin-login",
        "/u/admin-login/",
        "/u/admin-login?fixture=1",
        "/u/admin-login.json",
        "/users/admin-login",
        "/users/admin-login/",
        "/users/admin-login?fixture=1",
        "/users/admin-login.json",
    ):
        for method in ("GET", "PUT"):
            encoded = b"email=fixture%40example.invalid" if method == "PUT" else None
            headers = (
                {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(encoded))}
                if encoded is not None
                else None
            )
            status, response_headers, body = session.request(
                method,
                path,
                body=encoded,
                extra_headers=headers,
            )
            cache_control = ",".join(response_headers.get("cache-control", [])).lower()
            content_type = ",".join(response_headers.get("content-type", [])).lower()
            if status != 404 or "private" not in cache_control or "no-store" not in cache_control:
                raise RuntimeError("A public administrator recovery alias escaped its private denial boundary.")
            if "text/html" not in content_type or b"Mochirii Forums" not in body:
                raise RuntimeError("An administrator recovery denial is not Mochirii-branded HTML.")
            if any(pattern.search(body) for pattern in FORBIDDEN) or VISIBLE_UPSTREAM.search(body):
                raise RuntimeError("An administrator recovery denial exposed prohibited identity.")


def assert_local_login_denied(session: Session) -> None:
    csrf_status, _csrf_headers, csrf_body = session.get("/session/csrf.json")
    csrf = json_object(csrf_body, "local-login CSRF").get("csrf") if csrf_status == 200 else None
    if not isinstance(csrf, str) or len(csrf) < 32:
        raise RuntimeError("Local-login denial fixture did not obtain a CSRF token.")
    status, _headers, body = session.post_form(
        "/session.json",
        {"login": "mochirii-closed-login-fixture", "password": "fixture-not-a-password"},
        csrf,
    )
    if status != 403 or any(pattern.search(body) for pattern in FORBIDDEN) or VISIBLE_UPSTREAM.search(body):
        raise RuntimeError("Ordinary local password login was not explicitly denied.")
    current_status, _current_headers, _current_body = session.get("/session/current.json")
    if current_status != 404:
        raise RuntimeError("Denied ordinary local login unexpectedly authenticated.")


def verify_admin_email_recovery(port: int) -> None:
    superseded_token = b""
    token = b""
    try:
        superseded_token = admin_recovery_fixture("issue")
        token = admin_recovery_fixture("issue")
        if not re.fullmatch(rb"[A-Za-z0-9_-]{20,256}", token) or not re.fullmatch(
            rb"[A-Za-z0-9_-]{20,256}", superseded_token
        ):
            raise RuntimeError("Admin recovery fixture token is malformed.")
        if token == superseded_token:
            raise RuntimeError("Repeated administrator recovery reused a prior token.")
        register_admin_recovery_markers((superseded_token, token))
        superseded_path = "/session/email-login/" + quote(superseded_token.decode("ascii"), safe="")
        obsolete = Session(port)
        obsolete_status, _obsolete_headers, _obsolete_body = obsolete.get(superseded_path)
        if obsolete_status not in {403, 404}:
            raise RuntimeError("A superseded administrator recovery token remained valid.")
        path = "/session/email-login/" + quote(token.decode("ascii"), safe="")
        recovered = Session(port)
        csrf_status, _csrf_headers, csrf_body = recovered.get("/session/csrf.json")
        csrf = json_object(csrf_body, "admin recovery CSRF").get("csrf") if csrf_status == 200 else None
        if not isinstance(csrf, str) or len(csrf) < 32:
            raise RuntimeError("Admin recovery fixture did not obtain a CSRF token.")
        info_status, _info_headers, info_body = recovered.get(path)
        info = json_object(info_body, "admin recovery token") if info_status == 200 else {}
        if info.get("can_login") is not True or info.get("token_email") != "stage4-fixture@forums.mochirii.com":
            raise RuntimeError("Pinned admin email-login bypass did not accept the exact fixture administrator.")
        status, _headers, body = recovered.post_form(path, {}, csrf)
        result = json_object(body, "admin recovery login") if status == 200 else {}
        if result.get("error") or result.get("success") != "OK":
            raise RuntimeError("Pinned admin email-login did not establish a session.")
        current_status, _current_headers, current_body = recovered.get("/session/current.json")
        current = json_object(current_body, "recovered admin session") if current_status == 200 else {}
        if current.get("username") != "mochirii-s4-test" or current.get("admin") is not True:
            raise RuntimeError("Pinned admin email-login established the wrong session.")
        replay = Session(port)
        replay_status, _replay_headers, _replay_body = replay.get(path)
        if replay_status not in {403, 404}:
            raise RuntimeError("Consumed admin recovery token remained reusable.")
        assert_local_login_denied(Session(port))
        assert_admin_login_form_denied(recovered)
    finally:
        admin_recovery_fixture("cleanup")


def json_object(body: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} response is not valid JSON.") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} response is not one JSON object.")
    return value


def string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for child in value for item in string_values(child)]
    if isinstance(value, dict):
        return [item for child in value.values() for item in string_values(child)]
    return []


def assert_member_values(value: object, label: str) -> None:
    visible = "\n".join(string_values(value)).encode("utf-8")
    if any(pattern.search(visible) for pattern in VALUE_FORBIDDEN):
        raise RuntimeError(f"{label} exposed prohibited member-facing branding.")


def verify_member_branding(session: Session) -> None:
    status, _headers, body = session.get("/u/discobot.json")
    if status != 404 or any(pattern.search(body) for pattern in FORBIDDEN):
        raise RuntimeError("The retired narrative-bot profile remains member-addressable.")

    status, _headers, body = session.get("/u/mochirii-guide.json")
    profile = json_object(body, "Mochirii Guide profile") if status == 200 else {}
    assert_member_values(profile, "Mochirii Guide profile")
    user = profile.get("user")
    if not isinstance(user, dict) or user.get("username") != "mochirii-guide" or user.get("name") != "Mochirii Guide":
        raise RuntimeError("The Mochirii Guide profile identity changed.")
    avatar = user.get("avatar_template")
    if not isinstance(avatar, str) or not avatar:
        raise RuntimeError("The Mochirii Guide avatar URL is absent.")
    avatar = avatar.replace("{size}", "240")
    parsed_avatar = urlparse(avatar)
    if parsed_avatar.fragment or parsed_avatar.username or parsed_avatar.password:
        raise RuntimeError("The disposable Mochirii Guide avatar URL is not canonical.")
    if parsed_avatar.netloc:
        if (
            parsed_avatar.scheme not in {"http", "https"}
            or parsed_avatar.hostname != "forums.mochirii.com"
            or parsed_avatar.port not in {None, 80, 443}
        ):
            raise RuntimeError("The disposable Mochirii Guide avatar escaped the Forums origin.")
    elif parsed_avatar.scheme or not parsed_avatar.path.startswith("/"):
        raise RuntimeError("The disposable Mochirii Guide avatar URL is not an origin-relative path.")
    avatar_path = parsed_avatar.path + (("?" + parsed_avatar.query) if parsed_avatar.query else "")
    avatar_status, avatar_headers, avatar_body = session.get(avatar_path)
    avatar_type = "".join(avatar_headers.get("content-type", [])).lower()
    if avatar_status != 200 or not avatar_type.startswith("image/") or not avatar_body:
        raise RuntimeError("The Mochirii Guide avatar did not render as an image.")

    status, _headers, body = session.get("/about.json")
    about = json_object(body, "about") if status == 200 else {}
    assert_member_values(about, "about")
    if "Mochirii" not in "\n".join(string_values(about)):
        raise RuntimeError("The signed-in about payload omitted Mochirii identity.")

    status, _headers, body = session.get("/guidelines")
    if status != 200:
        raise RuntimeError("The signed-in guidelines route did not render.")
    parser = VisibleText()
    parser.feed(body.decode("utf-8"))
    guidelines = "\n".join(parser.parts).encode("utf-8")
    if b"Mochirii Forums provides tools" not in guidelines or b"civilized public discussion" not in guidelines or any(
        pattern.search(guidelines) for pattern in VALUE_FORBIDDEN
    ):
        raise RuntimeError("The signed-in guidelines presentation changed.")

    expected_badges = {
        1: "Granted all essential Mochirii community functions",
        2: "Granted invitations, group messaging, and more participation in Mochirii Forums",
        3: "Granted topic organization, wiki editing, and more participation tools",
        4: "Granted global organization and moderation tools in Mochirii Forums",
    }
    status, _headers, body = session.get("/badges.json")
    badges = json_object(body, "badges") if status == 200 else {}
    assert_member_values(badges, "badges")
    badge_rows = badges.get("badges")
    if not isinstance(badge_rows, list):
        raise RuntimeError("The badge serializer payload is absent.")
    serialized = {
        badge.get("id"): badge.get("description")
        for badge in badge_rows
        if isinstance(badge, dict) and badge.get("id") in expected_badges
    }
    if serialized != expected_badges:
        raise RuntimeError("The four trust-badge descriptions changed.")
    for badge_id in expected_badges:
        badge_status, _badge_headers, badge_body = session.get(f"/badges/{badge_id}.json")
        badge = json_object(badge_body, f"badge {badge_id}") if badge_status == 200 else {}
        assert_member_values(badge, f"badge {badge_id}")
        if expected_badges[badge_id] not in string_values(badge):
            raise RuntimeError(f"Badge route {badge_id} omitted its Mochirii description.")

    for feed_path in (
        "/latest.rss",
        "/latest.atom",
        "/latest.RSS",
        "/latest.r%73s",
        "/latest?format=rss",
        "/latest?format=ATOM",
        "/t/1.rss",
        "/posts/1.rss",
        "/badges/1.rss",
        "/badges.rss",
    ):
        feed_status, feed_headers, feed_body = session.get(feed_path)
        feed_type = ",".join(feed_headers.get("content-type", [])).lower()
        cache_control = ",".join(feed_headers.get("cache-control", [])).lower()
        if feed_status != 404 or "text/html" not in feed_type:
            raise RuntimeError("An authenticated feed alias escaped the Mochirii HTML denial boundary.")
        if "private" not in cache_control or "no-store" not in cache_control:
            raise RuntimeError("An authenticated feed denial omitted private no-store caching.")
        if b"Mochirii Forums" not in feed_body:
            raise RuntimeError("An authenticated feed denial omitted Mochirii identity.")
        if re.search(rb"<(?:rss|feed)\b|xmlns(?::\w+)?=", feed_body, re.I):
            raise RuntimeError("An authenticated feed alias returned XML metadata.")
        if any(pattern.search(feed_body) for pattern in FORBIDDEN) or VISIBLE_UPSTREAM.search(feed_body):
            raise RuntimeError("An authenticated feed denial exposed prohibited identity.")


def assert_callback_logs_redacted() -> None:
    markers = sorted(CALLBACK_LOG_MARKERS)
    if not markers or len(markers) > 64 or any(len(marker) < 16 or len(marker) > 16_384 for marker in markers):
        raise RuntimeError("Sensitive callback marker inventory is malformed.")
    run_container_runner(
        '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-sensitive-log-redaction.rb"',
        input_bytes=b"\n".join(markers) + b"\n",
    )
    with tempfile.TemporaryFile() as transcript:
        completed = subprocess.run(
            ["timeout", "35", "sudo", "docker", "logs", "--since", "30m", "app"],
            stdin=subprocess.DEVNULL,
            stdout=transcript,
            stderr=subprocess.DEVNULL,
            timeout=40,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("Disposable container log readback failed.")
        size = os.fstat(transcript.fileno()).st_size
        if size > 128 * 1024 * 1024:
            raise RuntimeError("Disposable container log readback exceeded its byte boundary.")
        transcript.seek(0)
        content = transcript.read()
        if sensitive_marker_reached(content, markers):
            raise RuntimeError("A callback secret or member marker reached the container log boundary.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        raise RuntimeError("Loopback fixture port is invalid.")
    mode = args.secret_file.stat().st_mode & 0o777
    if mode != 0o600:
        raise RuntimeError("Fixture key file must be mode 0600.")
    secret_text = args.secret_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", secret_text):
        raise RuntimeError("Fixture key must be exactly 64 lowercase hex characters.")
    secret = secret_text.encode("ascii")

    signed_out = Session(args.port)
    status, _headers, body = signed_out.get("/login")
    if status != 200 or b"Mochirii" not in body or any(pattern.search(body) for pattern in FORBIDDEN):
        raise RuntimeError("Signed-out login presentation failed the consumer fixture gate.")
    signed_out_visible = VisibleText()
    signed_out_visible.feed(body.decode("utf-8"))
    if VISIBLE_UPSTREAM.search("\n".join(signed_out_visible.parts).encode("utf-8")):
        raise RuntimeError("Signed-out login retained upstream identity.")
    assert_admin_login_form_denied(signed_out)
    assert_local_login_denied(Session(args.port))
    csrf_status, _csrf_headers, csrf_body = signed_out.get("/session/csrf.json")
    csrf = json_object(csrf_body, "CSRF").get("csrf") if csrf_status == 200 else None
    if not isinstance(csrf, str) or len(csrf) < 32:
        raise RuntimeError("A valid same-session CSRF token was not issued.")
    local_status, _local_headers, local_body = signed_out.post_form(
        "/session/login-code.json",
        {"email": "stage4-fixture@forums.mochirii.com"},
        csrf,
    )
    if local_status != 404 or any(pattern.search(local_body) for pattern in FORBIDDEN) or VISIBLE_UPSTREAM.search(local_body):
        raise RuntimeError("Disabled local email-code login was not hidden by the pinned not-found boundary.")
    current_status, _current_headers, _current_body = signed_out.get("/session/current.json")
    if current_status != 404:
        raise RuntimeError("The denied local-login session unexpectedly authenticated.")

    valid = Session(args.port)
    encoded, signature = callback(request_nonce(valid, secret), secret)
    status, headers, _body = valid.get(callback_path(encoded, signature))
    return_location = urlparse(exactly_one(headers, "location"))
    referrer_policy = ",".join(headers.get("referrer-policy", [])).lower()
    cache_control = {
        token.strip().lower()
        for value in headers.get("cache-control", [])
        for token in value.split(",")
    }
    if (
        status != 302
        or return_location.path != "/latest"
        or return_location.query
        or return_location.fragment
        or referrer_policy != "no-referrer"
        or not {"private", "no-store", "max-age=0"}.issubset(cache_control)
        or ",".join(headers.get("pragma", [])).lower() != "no-cache"
        or ",".join(headers.get("expires", [])).strip() != "0"
    ):
        raise RuntimeError("Valid same-session consumer callback did not return through its private query-scrubbed boundary.")
    current_status, _current_headers, current_body = valid.get("/session/current.json")
    current = json_object(current_body, "current session") if current_status == 200 else {}
    if current.get("username") != "mochirii-s4-test":
        raise RuntimeError("Valid consumer callback did not establish the exact fixture session.")
    verify_fixture_user()
    verify_member_branding(valid)
    status, _headers, body = valid.get(callback_path(encoded, signature))
    assert_branded_error(status, body, 419)

    cross_source = Session(args.port)
    cross_encoded, cross_signature = callback(request_nonce(cross_source, secret), secret)
    status, _headers, body = Session(args.port).get(callback_path(cross_encoded, cross_signature))
    assert_branded_error(status, body, 419)

    invalid = Session(args.port)
    invalid_encoded, _valid_signature = callback(request_nonce(invalid, secret), secret)
    status, _headers, body = invalid.get(callback_path(invalid_encoded, "0" * 64))
    assert_branded_error(status, body, 422)

    malformed = Session(args.port)
    request_nonce(malformed, secret)
    malformed_value = "<"
    malformed_signature = hmac.new(secret, malformed_value.encode("ascii"), hashlib.sha256).hexdigest()
    status, _headers, body = malformed.get(callback_path(malformed_value, malformed_signature))
    assert_branded_error(status, body, 422)

    duplicated = Session(args.port)
    duplicate_encoded, duplicate_signature = callback(request_nonce(duplicated, secret), secret)
    duplicate_query = (
        "/session/sso_login?"
        + urlencode({"sso": duplicate_encoded})
        + "&sso=%3C&"
        + urlencode({"sig": duplicate_signature})
    )
    callback_path(duplicate_encoded, duplicate_signature)
    status, _headers, body = duplicated.get(duplicate_query)
    assert_branded_error(status, body, 422)

    expired = Session(args.port)
    expired_nonce = request_nonce(expired, secret)
    expired_encoded, expired_signature = callback(expired_nonce, secret)
    expire_nonce(expired_nonce)
    status, _headers, body = expired.get(callback_path(expired_encoded, expired_signature))
    assert_branded_error(status, body, 419)

    unexpected_payload = base64.b64encode(("mochirii-stage4-unexpected-error-" + secrets.token_hex(16)).encode("ascii")).decode("ascii")
    unexpected_signature = hmac.new(secret, unexpected_payload.encode("ascii"), hashlib.sha256).hexdigest()
    unexpected_path = callback_path(unexpected_payload, unexpected_signature).replace(
        "/session/sso_login", "/SESSION/SSO_LOGIN", 1
    )
    unexpected_status, _unexpected_headers, _unexpected_body = Session(args.port).request("PUT", unexpected_path)
    if unexpected_status in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
        raise RuntimeError("Unexpected callback method or normalized-case route did not fail closed.")

    verify_admin_email_recovery(args.port)
    assert_callback_logs_redacted()

    print("Built-in DiscourseConnect consumer fixtures passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
