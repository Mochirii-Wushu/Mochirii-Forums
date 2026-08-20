#!/usr/bin/env python3
"""Prove the secret-free Website Forums producer state without redirects."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl


HOST = "mochirii.com"
PATH = "/api/forums/discourse-connect"
MAX_BODY_BYTES = 64 * 1024
FORBIDDEN = re.compile(
    r"(?:\bdiscourse\b|digitalocean(?:spaces)?|amazonaws|cloudflare|(?:^|[./-])discourse(?:[./-]|$))",
    re.IGNORECASE,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state", choices=("enabled", "disabled"))
    args = parser.parse_args()
    expected_status = 400 if args.state == "enabled" else 503
    expected_code = "invalid_request" if args.state == "enabled" else "unavailable"
    expected_error = (
        "This Mōchirīī Forums sign-in request is invalid."
        if args.state == "enabled"
        else "Mōchirīī Forums sign-in is unavailable."
    )
    body = b"{}"
    connection = http.client.HTTPSConnection(
        HOST,
        443,
        timeout=20,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "POST",
            PATH,
            body=body,
            headers={
                "Host": HOST,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "User-Agent": "Mochirii-Forums-Producer-State/1",
            },
        )
        response = connection.getresponse()
        headers: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            headers.setdefault(name.lower(), []).append(value)
            if FORBIDDEN.search(name) or FORBIDDEN.search(value):
                raise RuntimeError("Website producer response metadata exposed an unapproved identity.")
        if response.status != expected_status:
            raise RuntimeError("Website producer state does not match the required activation phase.")
        if headers.get("location") or headers.get("set-cookie"):
            raise RuntimeError("Website producer state probe redirected or created browser state.")
        content_type = ",".join(headers.get("content-type", [])).lower()
        cache_control = {token.strip().lower() for value in headers.get("cache-control", []) for token in value.split(",")}
        if "application/json" not in content_type or not {"private", "no-store", "max-age=0"}.issubset(cache_control):
            raise RuntimeError("Website producer state probe omitted its private JSON boundary.")
        exact_headers = {
            "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            "expires": "0",
            "pragma": "no-cache",
            "referrer-policy": "no-referrer",
            "x-content-type-options": "nosniff",
            "x-frame-options": "deny",
        }
        for name, expected in exact_headers.items():
            values = headers.get(name, [])
            if len(values) != 1 or values[0].strip().lower() != expected:
                raise RuntimeError("Website producer response security headers differ.")
        vary = {token.strip().lower() for value in headers.get("vary", []) for token in value.split(",")}
        if not {"origin", "authorization"}.issubset(vary):
            raise RuntimeError("Website producer response Vary boundary differs.")
        content_length = headers.get("content-length", [])
        if content_length:
            if len(content_length) != 1 or not content_length[0].isdigit() or int(content_length[0]) > MAX_BODY_BYTES:
                raise RuntimeError("Website producer response length is malformed or excessive.")
        response_body = response.read(MAX_BODY_BYTES + 1)
        if len(response_body) > MAX_BODY_BYTES:
            raise RuntimeError("Website producer response exceeded its byte boundary.")
        try:
            document = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Website producer response is not one JSON document.") from error
        if document != {"ok": False, "code": expected_code, "error": expected_error}:
            raise RuntimeError("Website producer response contract differs.")
        if FORBIDDEN.search(response_body.decode("utf-8")):
            raise RuntimeError("Website producer response body exposed an unapproved identity.")
    finally:
        connection.close()
    print(f"Mochirii Forums Website producer {args.state} state verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
