#!/usr/bin/env python3
"""Own and reconcile the one exact DNS-01 challenge transaction."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


API_ORIGIN = "https://api.cloudflare.com"
ZONE_NAME = "mochirii.com"
CHALLENGE_NAME = "_acme-challenge.media-forums.mochirii.com"
JOURNAL = Path("/var/lib/mochirii/forums/acme-challenge-transaction.json")
ID = re.compile(r"[0-9a-f]{32}")
CREDENTIAL_RECORD = re.compile(r"dns_cloudflare_api_token = ([A-Za-z0-9_-]{20,512})")
MAX_RESPONSE_BYTES = 1024 * 1024
TOTAL_DEADLINE_SECONDS = 60


class ReconcileError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def protected_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ReconcileError("Protected ACME input is not one regular file.")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ReconcileError("Protected ACME input permissions differ.")


def token_from(path: Path) -> str:
    protected_file(path)
    match = CREDENTIAL_RECORD.fullmatch(path.read_text(encoding="utf-8").strip())
    if match is None:
        raise ReconcileError("DNS credential differs from the exact token-only form.")
    return match.group(1)


def request(token: str, method: str, path: str) -> dict:
    if method not in {"GET", "DELETE"} or not path.startswith("/client/v4/"):
        raise ReconcileError("ACME reconciliation request is outside the exact API allowlist.")
    url = API_ORIGIN + path
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "api.cloudflare.com" or parsed.fragment:
        raise ReconcileError("ACME reconciliation API authority differs.")
    outbound = urllib.request.Request(
        url,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    opener = urllib.request.build_opener(NoRedirect)
    started = time.monotonic()
    try:
        response = opener.open(outbound, timeout=30)
        with response:
            if response.geturl() != url or not 200 <= response.status < 300:
                raise ReconcileError("ACME reconciliation response origin or status differs.")
            body = bytearray()
            while True:
                if time.monotonic() - started > TOTAL_DEADLINE_SECONDS:
                    raise ReconcileError("ACME reconciliation response exceeded its total deadline.")
                block = response.read(min(65536, MAX_RESPONSE_BYTES + 1 - len(body)))
                if not block:
                    break
                body.extend(block)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ReconcileError("ACME reconciliation response exceeded its byte bound.")
    except urllib.error.HTTPError as error:
        raise ReconcileError("ACME reconciliation API rejected the request.") from error
    except urllib.error.URLError as error:
        raise ReconcileError("ACME reconciliation API outcome is unavailable.") from error
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReconcileError("ACME reconciliation response is malformed.") from error
    if not isinstance(document, dict) or document.get("success") is not True:
        raise ReconcileError("ACME reconciliation response did not confirm success.")
    return document


def zone_id(token: str) -> str:
    query = urllib.parse.urlencode({"name": ZONE_NAME, "status": "active", "page": 1, "per_page": 2})
    document = request(token, "GET", f"/client/v4/zones?{query}")
    rows = document.get("result")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ReconcileError("DNS zone lookup did not return one exact zone.")
    identifier = rows[0].get("id")
    if not isinstance(identifier, str) or ID.fullmatch(identifier) is None or rows[0].get("name") != ZONE_NAME:
        raise ReconcileError("DNS zone identity differs.")
    return identifier


def records(token: str, zone: str) -> list[str]:
    query = urllib.parse.urlencode(
        {"type": "TXT", "name": CHALLENGE_NAME, "page": 1, "per_page": 20, "order": "name"}
    )
    document = request(token, "GET", f"/client/v4/zones/{zone}/dns_records?{query}")
    rows = document.get("result")
    info = document.get("result_info")
    if not isinstance(rows, list) or len(rows) > 20 or not isinstance(info, dict) or info.get("total_count") != len(rows):
        raise ReconcileError("DNS challenge inventory is incomplete or unbounded.")
    identifiers: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != "TXT" or row.get("name") != CHALLENGE_NAME:
            raise ReconcileError("DNS challenge inventory contains an unexpected record.")
        identifier = row.get("id")
        if not isinstance(identifier, str) or ID.fullmatch(identifier) is None or identifier in identifiers:
            raise ReconcileError("DNS challenge record identity is malformed or duplicated.")
        identifiers.append(identifier)
    return identifiers


def load_journal() -> dict:
    protected_file(JOURNAL)
    document = json.loads(JOURNAL.read_text(encoding="utf-8"))
    if set(document) != {"schemaVersion", "transactionId", "challengeName", "zoneId", "phase"}:
        raise ReconcileError("ACME challenge journal keys differ.")
    if (
        document.get("schemaVersion") != 1
        or not isinstance(document.get("transactionId"), str)
        or re.fullmatch(r"[0-9a-f]{32}", document["transactionId"]) is None
        or document.get("challengeName") != CHALLENGE_NAME
        or not isinstance(document.get("zoneId"), str)
        or ID.fullmatch(document["zoneId"]) is None
        or document.get("phase") != "prepared-clear"
    ):
        raise ReconcileError("ACME challenge journal values differ.")
    return document


def write_journal(document: dict) -> None:
    JOURNAL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".acme-challenge.", suffix=".json", dir=JOURNAL.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(document, target, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        descriptor = -1
        os.replace(name, JOURNAL)
        parent_descriptor = os.open(JOURNAL.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def start(token: str) -> None:
    if JOURNAL.exists() or JOURNAL.is_symlink():
        raise ReconcileError("A prior ACME challenge transaction requires reconciliation.")
    zone = zone_id(token)
    if records(token, zone):
        raise ReconcileError("The exact ACME challenge name is not clear before mutation.")
    write_journal(
        {
            "schemaVersion": 1,
            "transactionId": os.urandom(16).hex(),
            "challengeName": CHALLENGE_NAME,
            "zoneId": zone,
            "phase": "prepared-clear",
        }
    )


def reconcile(token: str) -> None:
    journal = load_journal()
    if zone_id(token) != journal["zoneId"]:
        raise ReconcileError("ACME challenge journal zone no longer matches provider readback.")
    for identifier in records(token, journal["zoneId"]):
        request(token, "DELETE", f"/client/v4/zones/{journal['zoneId']}/dns_records/{identifier}")
    for attempt in range(3):
        if not records(token, journal["zoneId"]):
            JOURNAL.unlink()
            parent_descriptor = os.open(JOURNAL.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            return
        if attempt < 2:
            time.sleep(5)
    raise ReconcileError("ACME challenge cleanup could not be proved; the sealed journal was retained.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--action", choices=("start", "reconcile"), required=True)
    args = parser.parse_args()
    token = token_from(args.credentials)
    if args.action == "start":
        start(token)
    else:
        reconcile(token)
    print("Mochirii Forums ACME challenge boundary completed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReconcileError, json.JSONDecodeError, UnicodeDecodeError):
        print("Mochirii Forums ACME challenge boundary blocked.", file=os.sys.stderr)
        raise SystemExit(1) from None
