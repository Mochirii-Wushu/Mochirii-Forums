#!/usr/bin/env python3
"""Verify public Mochirii presentation without accepting upstream marks."""

from __future__ import annotations

import argparse
import http.client
import html
import json
import re
import ssl
from html.parser import HTMLParser
from urllib.parse import unquote, urlparse


MAX_BYTES = 2 * 1024 * 1024
FORBIDDEN = (
    re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']Discourse', re.I),
    re.compile(r">\s*Powered by Discourse\s*<", re.I),
    re.compile(r"https?://(?:[^/]+\.)?discourse\.(?:org|com)", re.I),
    re.compile(r"digitaloceanspaces\.com", re.I),
    re.compile(r"amazonaws\.com", re.I),
)
VISIBLE_UPSTREAM = re.compile(r"\bDiscourse\b", re.I)
FORBIDDEN_RESPONSE_METADATA = re.compile(
    r"(?:\bdiscourse\b|(?:^|[./-])discourse(?:[./-]|$)|digitalocean(?:spaces)?|amazonaws)",
    re.I,
)
SIGNED_CREDENTIAL_MARKER = re.compile(
    r"(?:"
    r"x-amz-(?:algorithm|credential|date|expires|security-token|signature|signedheaders)"
    r"|awsaccesskeyid"
    r"|authorization\s*[=:]\s*aws4-hmac-sha256"
    r"|(?:^|[?&;\s])signature\s*="
    r")",
    re.I,
)
JSON_ASCII_ESCAPE = re.compile(r"\\u00([0-7][0-9a-f])", re.I)


def exposes_signed_credential(value: str) -> bool:
    """Reject raw and bounded encoded spellings without decoding arbitrary bytes."""

    views = {value}
    frontier = {value}
    for _ in range(2):
        expanded: set[str] = set()
        for candidate in frontier:
            expanded.add(unquote(candidate))
            expanded.add(html.unescape(candidate))
            expanded.add(
                JSON_ASCII_ESCAPE.sub(
                    lambda match: chr(int(match.group(1), 16)), candidate
                )
            )
        expanded -= views
        views.update(expanded)
        frontier = expanded
    return any(SIGNED_CREDENTIAL_MARKER.search(candidate) for candidate in views)


class VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "template"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "template"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.hidden_depth == 0 and data.strip():
            self.parts.append(data)


def fetch(
    base_url: str,
    host_header: str,
    path: str,
    *,
    user_agent: str = "Mochirii-Forums-Validation/1",
) -> tuple[int, str, dict[str, list[str]], bytes]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("Base URL must be an explicit HTTP or HTTPS origin.")
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    kwargs: dict[str, object] = {"timeout": 20}
    if parsed.scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    connection = connection_type(parsed.hostname, parsed.port, **kwargs)
    try:
        connection.request(
            "GET",
            path,
            headers={"Host": host_header, "Accept-Encoding": "identity", "User-Agent": user_agent},
        )
        response = connection.getresponse()
        response_headers: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            response_headers.setdefault(name.lower(), []).append(value)
            if FORBIDDEN_RESPONSE_METADATA.search(name) or FORBIDDEN_RESPONSE_METADATA.search(value):
                raise RuntimeError(f"Public response metadata exposed prohibited identity: {path}")
            if exposes_signed_credential(name) or exposes_signed_credential(value):
                raise RuntimeError(f"Public response metadata exposed a signed retrieval credential: {path}")
        content_type = response.getheader("Content-Type", "")
        content_length = response.getheader("Content-Length")
        if content_length and int(content_length) > MAX_BYTES:
            raise RuntimeError(f"Response is too large: {path}")
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise RuntimeError(f"Response exceeded byte bound: {path}")
        if any(
            marker in content_type.lower()
            for marker in ("text/", "json", "xml", "javascript", "webmanifest")
        ) and exposes_signed_credential(body.decode("utf-8", errors="replace")):
            raise RuntimeError(f"Public rendered content exposed a signed retrieval credential: {path}")
        return response.status, content_type, response_headers, body
    finally:
        connection.close()


def text_body(path: str, body: bytes) -> str:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"Response is not UTF-8: {path}") from error


def verify_image(base_url: str, source: str) -> None:
    if source.startswith("//"):
        raise RuntimeError("A scheme-relative identity image URL is forbidden.")
    source_url = urlparse(source)
    base = urlparse(base_url)
    if source_url.username or source_url.password or source_url.fragment or source_url.query:
        raise RuntimeError("A public identity image URL contains non-canonical authority data.")
    if source_url.scheme:
        if source_url.scheme not in {"http", "https"} or source_url.hostname not in {
            "forums.mochirii.com",
            "media-forums.mochirii.com",
        }:
            raise RuntimeError("A public identity image escaped the Mochirii hostname boundary.")
        if source_url.port is not None:
            raise RuntimeError("A public identity image URL contains an unexpected explicit port.")
        if source_url.hostname == "media-forums.mochirii.com":
            if source_url.scheme != "https":
                raise RuntimeError("The Mochirii media hostname must use HTTPS.")
            request_base = f"{source_url.scheme}://{source_url.netloc}"
            host = "media-forums.mochirii.com"
        else:
            if source_url.scheme != base.scheme:
                raise RuntimeError("The Forums identity image scheme differs from the verified origin.")
            request_base = base_url
            host = "forums.mochirii.com"
        path = source_url.path
    else:
        if source_url.netloc or not source_url.path.startswith("/"):
            raise RuntimeError("A relative identity image URL is not origin-absolute.")
        request_base = base_url
        host = "forums.mochirii.com"
        path = source_url.path
    status, content_type, _headers, body = fetch(request_base, host, path)
    if status != 200 or not content_type.lower().startswith("image/") or not body:
        raise RuntimeError("A Mochirii identity image failed its HTTP and media-type gate.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--host-header", default="forums.mochirii.com")
    args = parser.parse_args()

    responses: dict[str, tuple[str, str]] = {}
    for path in (
        "/login",
        "/403.html",
        "/404.html",
        "/422.html",
        "/500.html",
        "/503.html",
        "/manifest.webmanifest",
        "/opensearch.xml",
    ):
        status, content_type, _headers, body = fetch(args.base_url, args.host_header, path)
        if status != 200:
            raise RuntimeError(f"Unexpected HTTP {status} for {path}")
        text = text_body(path, body)
        if "Mochirii" not in text:
            raise RuntimeError(f"Mochirii branding is missing from {path}")
        if "html" in content_type.lower():
            visible = VisibleText()
            visible.feed(text)
            if VISIBLE_UPSTREAM.search("\n".join(visible.parts)):
                raise RuntimeError(f"Member-visible upstream identity remains in {path}")
        elif VISIBLE_UPSTREAM.search(text):
            raise RuntimeError(f"Public metadata retains upstream identity in {path}")
        for pattern in FORBIDDEN:
            if pattern.search(text):
                raise RuntimeError(f"Prohibited public branding in {path}: {pattern.pattern}")
        responses[path] = (content_type, text)

    login = responses["/login"][1]
    if not re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Mochirii Forums["\']', login, re.I):
        raise RuntimeError("The exact Mochirii generator metadata was not served.")
    if "Page not found · Mochirii Forums" not in responses["/404.html"][1]:
        raise RuntimeError("The reviewed 404 page was not served.")
    if "Access unavailable · Mochirii Forums" not in responses["/403.html"][1]:
        raise RuntimeError("The reviewed 403 page was not served.")
    if "Request unavailable · Mochirii Forums" not in responses["/422.html"][1]:
        raise RuntimeError("The reviewed 422 page was not served.")
    if "We could not complete that request" not in responses["/500.html"][1]:
        raise RuntimeError("The reviewed 500 page was not served.")
    if "Temporarily unavailable · Mochirii Forums" not in responses["/503.html"][1]:
        raise RuntimeError("The reviewed 503 page was not served.")

    for recovery_path in (
        "/u/admin-login",
        "/u/admin-login/",
        "/u/admin-login?fixture=1",
        "/u/admin-login.json",
        "/users/admin-login",
        "/users/admin-login/",
        "/users/admin-login?fixture=1",
        "/users/admin-login.json",
    ):
        recovery_status, recovery_type, recovery_headers, recovery_body = fetch(
            args.base_url, args.host_header, recovery_path
        )
        recovery_cache = ",".join(recovery_headers.get("cache-control", [])).lower()
        recovery_text = text_body(recovery_path, recovery_body)
        if (
            recovery_status != 404
            or "text/html" not in recovery_type.lower()
            or "private" not in recovery_cache
            or "no-store" not in recovery_cache
            or "Mochirii Forums" not in recovery_text
        ):
            raise RuntimeError(
                "A public administrator recovery alias is not denied with private Mochirii HTML: "
                f"path={recovery_path!r} status={recovery_status} media_type={recovery_type!r}."
            )
        recovery_visible = VisibleText()
        recovery_visible.feed(recovery_text)
        if VISIBLE_UPSTREAM.search("\n".join(recovery_visible.parts)) or any(
            pattern.search(recovery_text) for pattern in FORBIDDEN
        ):
            raise RuntimeError("An administrator recovery denial exposed prohibited identity.")

    manifest = json.loads(responses["/manifest.webmanifest"][1])
    if manifest.get("name") != "Mochirii Forums" or manifest.get("short_name") != "Mochirii":
        raise RuntimeError("PWA identity differs from the reviewed Mochirii values.")
    icons = manifest.get("icons")
    if not isinstance(icons, list) or not icons:
        raise RuntimeError("PWA icons are absent.")
    if not any(isinstance(icon, dict) and icon.get("sizes") == "512x512" for icon in icons):
        raise RuntimeError("PWA manifest omitted the reviewed 512x512 icon.")
    for icon in icons:
        if not isinstance(icon, dict) or not isinstance(icon.get("src"), str):
            raise RuntimeError("PWA manifest icon entry is malformed.")
        verify_image(args.base_url, icon["src"])

    info_status, _info_type, _info_headers, info_body = fetch(
        args.base_url, args.host_header, "/site/basic-info.json"
    )
    info = json.loads(text_body("/site/basic-info.json", info_body)) if info_status == 200 else {}
    if info.get("title") != "Mochirii Forums" or info.get("login_required") is not True:
        raise RuntimeError("Public site identity or login boundary changed.")
    for key in ("logo_url", "logo_small_url", "mobile_logo_url", "apple_touch_icon_url", "favicon_url"):
        source = info.get(key)
        if not isinstance(source, str) or not source:
            raise RuntimeError(f"Public identity image is absent: {key}")
        verify_image(args.base_url, source)

    opensearch_type, opensearch = responses["/opensearch.xml"]
    if opensearch_type.split(";", 1)[0].strip().lower() != "application/xml":
        raise RuntimeError("OpenSearch metadata did not use the pinned XML response type.")
    if "<Tags>Mochirii Forums</Tags>" not in opensearch or "<Tags>discourse forum</Tags>" in opensearch:
        raise RuntimeError("OpenSearch metadata was not replaced exactly.")

    legacy_status, _legacy_type, _legacy_headers, legacy_body = fetch(
        args.base_url,
        args.host_header,
        "/login",
        user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)",
    )
    legacy = text_body("unsupported-browser login", legacy_body)
    if legacy_status != 200 or "Your browser is unsupported" not in legacy or "Mochirii Forums" not in legacy:
        raise RuntimeError("The unsupported-browser presentation did not use its Mochirii override.")
    for pattern in FORBIDDEN:
        if pattern.search(legacy):
            raise RuntimeError("The unsupported-browser presentation exposed prohibited branding.")
    legacy_visible = VisibleText()
    legacy_visible.feed(legacy)
    if VISIBLE_UPSTREAM.search("\n".join(legacy_visible.parts)):
        raise RuntimeError("The unsupported-browser presentation retained upstream identity.")

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
        feed_status, feed_type, feed_headers, feed_body = fetch(
            args.base_url, args.host_header, feed_path
        )
        feed_text = text_body(feed_path, feed_body)
        cache_control = ",".join(feed_headers.get("cache-control", [])).lower()
        if feed_status != 404 or "text/html" not in feed_type.lower():
            raise RuntimeError(f"Feed alias was not denied by the Mochirii HTML boundary: {feed_path}")
        if "private" not in cache_control or "no-store" not in cache_control:
            raise RuntimeError(f"Feed denial omitted its private no-store policy: {feed_path}")
        if "Mochirii Forums" not in feed_text:
            raise RuntimeError(f"Feed denial omitted Mochirii branding: {feed_path}")
        if re.search(r"<(?:rss|feed)\b|xmlns(?::\w+)?=", feed_text, re.I):
            raise RuntimeError(f"Feed alias returned XML metadata: {feed_path}")
        if VISIBLE_UPSTREAM.search(feed_text) or any(pattern.search(feed_text) for pattern in FORBIDDEN):
            raise RuntimeError(f"Feed denial exposed prohibited identity: {feed_path}")

    print("Mochirii public branding passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
