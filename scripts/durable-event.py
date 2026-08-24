#!/usr/bin/env python3
"""Append one bounded, durable, idempotent host-operation event."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import NoReturn


FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
EVENT_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}")
FIELD_VALUE = re.compile(r"[ -~]{1,256}")
MAX_EVENT_BYTES = 4 * 1024 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def parse_field(value: str) -> tuple[str, str]:
    name, separator, field_value = value.partition("=")
    if (
        separator != "="
        or FIELD_NAME.fullmatch(name) is None
        or FIELD_VALUE.fullmatch(field_value) is None
        or any(character in field_value for character in "\r\n\0")
    ):
        fail("event field is outside the reviewed boundary")
    return name, field_value


def validate_parent(path: Path) -> None:
    parent = path.parent
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("event parent is not one protected directory")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("event parent permissions differ")


def validate_file(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("event log is not one protected regular file")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("event log permissions differ")
    if metadata.st_size > MAX_EVENT_BYTES:
        fail("event log exceeds its reviewed byte boundary")
    content = path.read_bytes()
    if len(content) != metadata.st_size or (content and not content.endswith(b"\n")):
        fail("event log is incomplete")
    return content


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--field", action="append", default=[])
    args = parser.parse_args()

    if os.geteuid() != 0:
        fail("durable event append must run as root")
    if args.path.name not in {"events.log", "media-certificate-events.log"} or not args.path.is_absolute():
        fail("event log path differs from the exact host boundary")
    if EVENT_PATTERN.fullmatch(args.operation) is None or EVENT_PATTERN.fullmatch(args.status) is None:
        fail("event identity is malformed")
    fields = dict(parse_field(value) for value in args.field)
    if len(fields) != len(args.field) or set(fields) & {"operation", "status", "event_key", "recorded_at"}:
        fail("event fields are duplicated or reserved")

    validate_parent(args.path)
    created = False
    try:
        content = validate_file(args.path)
    except FileNotFoundError:
        content = b""
        created = True

    identity: dict[str, str] = {
        "operation": args.operation,
        "status": args.status,
        **dict(sorted(fields.items())),
    }
    canonical_identity = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")
    event_key = hashlib.sha256(canonical_identity).hexdigest()

    for raw_line in content.splitlines():
        if len(raw_line) > 4096:
            fail("event log contains an oversized line")
        try:
            existing = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Bounded legacy records remain readable evidence. New records are
            # canonical JSON and are the only records eligible for idempotence.
            continue
        if not isinstance(existing, dict) or existing.get("eventKey") != event_key:
            continue
        if any(existing.get(key) != value for key, value in identity.items()):
            fail("event key conflicts with existing evidence")
        return 0

    event: dict[str, str] = {
        "eventKey": event_key,
        "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        **identity,
    }
    encoded = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(content) + len(encoded) > MAX_EVENT_BYTES:
        fail("event log cannot accept another bounded record")

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    descriptor = os.open(args.path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail("opened event log permissions differ")
        if metadata.st_size != len(content):
            fail("event log changed during append")
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            fail("event append was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(args.path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if created:
        validate_file(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
