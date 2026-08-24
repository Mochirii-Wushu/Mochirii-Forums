#!/usr/bin/env python3
"""Rotate the exact external-DNS Spaces CDN certificate without logging secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


API_ROOT = "https://api.digitalocean.com/v2"
MEDIA_HOST = "media-forums.mochirii.com"
CERTIFICATE_NAME_PREFIX = "mochirii-media-forums-"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ORIGIN = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9][.]sgp1[.]digitaloceanspaces[.]com$")
TRANSACTION_NAME = re.compile(r"^mochirii-media-forums-[0-9a-f]{12}-[0-9a-f]{12}$")
JOURNAL = Path("/var/lib/mochirii/forums/evidence/media-certificate-rotation.pending.json")
EVENT_LOG = Path("/var/lib/mochirii/forums/logs/media-certificate-events.log")
MAX_CERTIFICATES = 200
MAX_PRE_MUTATION_CERTIFICATES = 190
RECONCILIATION_SETTLE_SECONDS = 600
MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024
PROVIDER_TOTAL_DEADLINE_SECONDS = 60


class RotationError(RuntimeError):
    pass


class ProviderHTTPError(RotationError):
    """The provider returned an explicit HTTP rejection."""

    def __init__(self, status: int):
        self.status = status
        super().__init__(f"Provider API returned HTTP {status}.")


class ProviderResponseUncertain(RotationError):
    """The request may have reached the provider but no final response was proved."""


class CreationCleanedError(RotationError):
    """A malformed create result was found and its exact object was removed."""


class RetirementSettlementPending(RotationError):
    """Old-certificate absence has not yet been proved twice over time."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        return None


PROVIDER_OPENER = urllib.request.build_opener(NoRedirectHandler())


def read_bounded_response(response, limit: int, deadline: float) -> bytes:
    if not 1 <= limit <= MAX_PROVIDER_RESPONSE_BYTES or deadline <= time.monotonic():
        raise RotationError("Provider response boundary is malformed or expired.")
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise ProviderResponseUncertain("Provider API total response deadline expired.")
        chunk = response.read(min(64 * 1024, limit + 1 - total))
        if not isinstance(chunk, bytes):
            raise RotationError("Provider API returned a non-byte response body.")
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RotationError("Provider API response exceeded its byte bound.")
        chunks.append(chunk)
        if time.monotonic() >= deadline:
            raise ProviderResponseUncertain("Provider API total response deadline expired.")
    return b"".join(chunks)


def fixed_event(status: str) -> None:
    if status not in {"started", "passed", "blocked"}:
        raise RotationError("Certificate event status is malformed.")
    EVENT_LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = EVENT_LOG.parent
    if parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o077:
        raise RotationError("Certificate event boundary is not root-only.")
    descriptor = os.open(EVENT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise RotationError("Certificate event log is not root-only.")
        marker = f"{int(time.time())} operation=media-certificate status={status}\n".encode("ascii")
        os.write(descriptor, marker)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def protected_parent(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_uid != 0 or path.parent.stat().st_mode & 0o077:
        raise RotationError("Certificate journal boundary is not root-only.")


def write_journal(document: dict[str, object]) -> None:
    protected_parent(JOURNAL)
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 64 * 1024:
        raise RotationError("Certificate journal exceeds its byte bound.")
    temporary = JOURNAL.with_name(f".{JOURNAL.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, JOURNAL)
    directory = os.open(JOURNAL.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_journal(endpoint_id: str, origin: str) -> dict[str, object] | None:
    if not JOURNAL.exists():
        return None
    if JOURNAL.is_symlink() or not JOURNAL.is_file() or JOURNAL.stat().st_uid != 0 or JOURNAL.stat().st_mode & 0o077:
        raise RotationError("Certificate journal is not one root-only regular file.")
    if JOURNAL.stat().st_size > 64 * 1024:
        raise RotationError("Certificate journal exceeds its byte bound.")
    try:
        document = json.loads(JOURNAL.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RotationError("Certificate journal is malformed.") from error
    expected = {
        "schemaVersion", "endpointId", "cdnOrigin", "customDomain", "transactionName",
        "priorCertificateIds", "oldCertificateId", "oldTlsSha256", "newCertificateSha256",
        "newCertificateId", "ttl", "phase", "createdAt", "absenceObservations", "lastAbsenceAt",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise RotationError("Certificate journal keys differ from the exact schema.")
    prior = document["priorCertificateIds"]
    if (
        document["schemaVersion"] != 1
        or document["endpointId"] != endpoint_id
        or document["cdnOrigin"] != origin
        or document["customDomain"] != MEDIA_HOST
        or not isinstance(document["transactionName"], str)
        or not TRANSACTION_NAME.fullmatch(document["transactionName"])
        or not isinstance(prior, list)
        or len(prior) > MAX_PRE_MUTATION_CERTIFICATES
        or not all(isinstance(item, str) and UUID.fullmatch(item) for item in prior)
        or prior != sorted(set(prior))
        or document["oldCertificateId"] not in prior
        or not isinstance(document["oldCertificateId"], str)
        or not UUID.fullmatch(document["oldCertificateId"])
        or not isinstance(document["oldTlsSha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", document["oldTlsSha256"])
        or not isinstance(document["newCertificateSha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", document["newCertificateSha256"])
        or (document["newCertificateId"] is not None and (not isinstance(document["newCertificateId"], str) or not UUID.fullmatch(document["newCertificateId"])))
        or document["newCertificateId"] in prior
        or not isinstance(document["ttl"], int)
        or document["ttl"] <= 0
        or document["phase"] not in {"prepared", "created", "bound", "retiring-old"}
        or not isinstance(document["createdAt"], int)
        or document["createdAt"] <= 0
        or not isinstance(document["absenceObservations"], int)
        or not 0 <= document["absenceObservations"] <= 100
        or (document["lastAbsenceAt"] is not None and (not isinstance(document["lastAbsenceAt"], int) or document["lastAbsenceAt"] < document["createdAt"]))
    ):
        raise RotationError("Certificate journal values are malformed.")
    if document["phase"] in {"created", "bound", "retiring-old"} and document["newCertificateId"] is None:
        raise RotationError("Certificate journal phase is missing its new identifier.")
    return document


def clear_journal() -> None:
    if JOURNAL.exists():
        if JOURNAL.is_symlink() or not JOURNAL.is_file() or JOURNAL.stat().st_uid != 0 or JOURNAL.stat().st_mode & 0o077:
            raise RotationError("Certificate journal cannot be cleared safely.")
        JOURNAL.unlink()
        directory = os.open(JOURNAL.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def protected_runtime(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise RotationError("Certificate runtime JSON must be one root-only regular file.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RotationError("Certificate runtime JSON is invalid.") from error
    expected = {"providerApiToken", "cdnEndpointId", "cdnOrigin"}
    if not isinstance(document, dict) or set(document) != expected:
        raise RotationError("Certificate runtime JSON keys differ from the exact allowlist.")
    if any(
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(character in value for character in "\r\n\x00")
        for value in document.values()
    ):
        raise RotationError("Certificate runtime JSON contains a malformed literal value.")
    return document


def api(token: str, method: str, path: str, payload: dict[str, object] | None = None) -> object:
    endpoint_match = re.fullmatch(r"/cdn/endpoints/([^/?#]+)", path)
    certificate_match = re.fullmatch(r"/certificates/([^/?#]+)", path)
    allowed = (
        (method == "GET" and endpoint_match is not None and UUID.fullmatch(endpoint_match.group(1))),
        (method == "PUT" and endpoint_match is not None and UUID.fullmatch(endpoint_match.group(1))),
        (method == "GET" and path == f"/certificates?per_page={MAX_CERTIFICATES}"),
        (method == "GET" and certificate_match is not None and UUID.fullmatch(certificate_match.group(1))),
        (method == "POST" and path == "/certificates"),
        (method == "DELETE" and certificate_match is not None and UUID.fullmatch(certificate_match.group(1))),
    )
    if not any(allowed):
        raise RotationError("Provider API method or path is outside the exact allowlist.")
    url = API_ROOT + path
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.digitalocean.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.netloc != "api.digitalocean.com"
        or not parsed.path.startswith("/v2/")
    ):
        raise RotationError("Provider API URL is outside the exact HTTPS authority.")
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mochirii-Forums-Media-Certificate-Renewal/1",
        },
    )
    started = time.monotonic()
    deadline = started + PROVIDER_TOTAL_DEADLINE_SECONDS
    try:
        with PROVIDER_OPENER.open(request, timeout=min(30, PROVIDER_TOTAL_DEADLINE_SECONDS)) as response:
            if response.geturl() != url or response.status not in {200, 201, 202, 204}:
                raise RotationError("Provider API response changed URL or status.")
            data = read_bounded_response(response, MAX_PROVIDER_RESPONSE_BYTES, deadline)
            if response.status == 204:
                return None
            return json.loads(data)
    except urllib.error.HTTPError as error:
        try:
            read_bounded_response(error, 64 * 1024, deadline)
        except (RotationError, OSError):
            pass
        if 300 <= error.code < 400:
            raise RotationError("Provider API redirect was blocked.") from None
        raise ProviderHTTPError(error.code) from None
    except (urllib.error.URLError, TimeoutError, socket.timeout) as error:
        raise ProviderResponseUncertain("Provider API response outcome is uncertain.") from error
    except json.JSONDecodeError as error:
        raise RotationError("Provider API request failed or returned invalid JSON.") from error


def object_field(document: object, name: str) -> dict[str, object]:
    if not isinstance(document, dict) or not isinstance(document.get(name), dict):
        raise RotationError(f"Provider API omitted the expected {name} object.")
    return document[name]


def endpoint(token: str, endpoint_id: str) -> dict[str, object]:
    return object_field(api(token, "GET", f"/cdn/endpoints/{endpoint_id}"), "endpoint")


def certificate_inventory(token: str) -> list[dict[str, str]]:
    document = api(token, "GET", f"/certificates?per_page={MAX_CERTIFICATES}")
    if not isinstance(document, dict) or not isinstance(document.get("certificates"), list):
        raise RotationError("Provider API omitted the bounded certificate inventory.")
    links = document.get("links", {})
    if not isinstance(links, dict):
        raise RotationError("Provider certificate inventory links are malformed.")
    pages = links.get("pages", {})
    if pages is not None and not isinstance(pages, dict):
        raise RotationError("Provider certificate inventory pages are malformed.")
    if isinstance(pages, dict) and pages.get("next"):
        raise RotationError("Provider certificate inventory exceeded the reviewed 200-object bound.")
    rows: list[dict[str, str]] = []
    for item in document["certificates"]:
        if not isinstance(item, dict):
            raise RotationError("Provider certificate inventory contains a malformed row.")
        identifier = item.get("id")
        name = item.get("name")
        if (
            not isinstance(identifier, str)
            or not UUID.fullmatch(identifier)
            or not isinstance(name, str)
            or not 1 <= len(name) <= 255
        ):
            raise RotationError("Provider certificate inventory contains malformed identity data.")
        rows.append({"id": identifier, "name": name})
    if len(rows) > MAX_CERTIFICATES or len({row["id"] for row in rows}) != len(rows):
        raise RotationError("Provider certificate inventory is outside the reviewed bound.")
    return rows


def pre_mutation_inventory(token: str) -> list[dict[str, str]]:
    rows = certificate_inventory(token)
    if len(rows) > MAX_PRE_MUTATION_CERTIFICATES:
        raise RotationError("Provider certificate inventory lacks the reserved cleanup capacity.")
    return rows


def transaction_certificates(token: str, name: str, prior_ids: set[str]) -> list[str]:
    return [
        row["id"]
        for row in certificate_inventory(token)
        if row["name"] == name and row["id"] not in prior_ids
    ]


def delete_transaction_certificate(token: str, identifier: str, name: str, prior_ids: set[str]) -> None:
    if identifier in prior_ids or not UUID.fullmatch(identifier):
        raise RotationError("Certificate cleanup refused a pre-existing or malformed identifier.")
    api(token, "DELETE", f"/certificates/{identifier}")
    if identifier in transaction_certificates(token, name, prior_ids):
        raise RotationError("Replacement certificate cleanup readback failed.")


def update_journal(document: dict[str, object], **changes: object) -> dict[str, object]:
    updated = dict(document)
    updated.update(changes)
    write_journal(updated)
    return updated


def record_retirement_absence(document: dict[str, object]) -> tuple[dict[str, object], bool]:
    now = int(time.time())
    previous = document["lastAbsenceAt"]
    observations = int(document["absenceObservations"])
    if previous is None:
        return update_journal(document, absenceObservations=1, lastAbsenceAt=now), False
    if now - int(previous) < 60:
        return document, False
    observations = max(2, observations + 1)
    updated = update_journal(
        document,
        absenceObservations=observations,
        lastAbsenceAt=now,
    )
    return updated, observations >= 2


def observe_transaction_certificates(
    token: str,
    name: str,
    prior_ids: set[str],
    *,
    attempts: int = 4,
    delay: float = 2.0,
) -> list[str]:
    if not 1 <= attempts <= 10 or not 0 <= delay <= 30:
        raise RotationError("Certificate reconciliation polling parameters are malformed.")
    last: list[str] = []
    for attempt in range(attempts):
        last = transaction_certificates(token, name, prior_ids)
        if last:
            return last
        if attempt + 1 < attempts:
            time.sleep(delay)
    return last


def reconcile_journal(token: str, endpoint_id: str, expected_origin: str) -> bool:
    journal = load_journal(endpoint_id, expected_origin)
    if journal is None:
        return False
    name = str(journal["transactionName"])
    prior_ids = set(journal["priorCertificateIds"])
    old_id = str(journal["oldCertificateId"])
    current = endpoint(token, endpoint_id)
    if current.get("id") != endpoint_id or current.get("origin") != expected_origin:
        raise RotationError("Pending certificate reconciliation found endpoint identity drift.")
    if current.get("ttl") != journal["ttl"] or current.get("custom_domain") != MEDIA_HOST:
        raise RotationError("Pending certificate reconciliation found endpoint policy drift.")

    discovered = observe_transaction_certificates(token, name, prior_ids)
    known_new = journal["newCertificateId"]
    identity_mismatch = known_new is not None and bool(discovered) and known_new not in discovered
    if len(discovered) > 1:
        # The random exact transaction name was proved absent before creation;
        # every matching non-prior ID belongs to this transaction. They remain
        # safe to remove, but multiple creation results are still a blocked
        # provider invariant after cleanup.
        multiple_results = True
    else:
        multiple_results = False

    current_certificate = current.get("certificate_id")
    if journal["phase"] == "retiring-old":
        # TLS was proved on the new binding before this phase was sealed. From
        # here recovery is commit-forward only: the prior certificate may have
        # been deleted even when its DELETE response or inventory readback was
        # lost, so rebinding it is never safe.
        if not isinstance(known_new, str) or not UUID.fullmatch(known_new):
            raise RotationError("Committed certificate journal lost its new identifier.")
        if current_certificate != known_new:
            raise RotationError("Committed certificate binding changed during reconciliation.")
        if discovered != [known_new]:
            raise RotationError("Committed certificate inventory is absent or ambiguous.")
        wait_for_tls(str(journal["newCertificateSha256"]))
        before_retirement = {row["id"] for row in certificate_inventory(token)}
        if known_new not in before_retirement:
            raise RotationError("Committed replacement certificate is absent from inventory.")
        try:
            # Always issue the idempotent retirement request. Inventory can
            # transiently omit an object that still exists, including after a
            # crash just after sealing this phase but before the first DELETE.
            api(token, "DELETE", f"/certificates/{old_id}")
        except ProviderHTTPError as error:
            if error.status != 404:
                raise
        except ProviderResponseUncertain:
            pass
        after_retirement = {row["id"] for row in certificate_inventory(token)}
        if old_id in after_retirement or known_new not in after_retirement:
            raise RotationError("Committed old-certificate retirement remains uncertain.")
        journal, settled = record_retirement_absence(journal)
        if not settled:
            raise RetirementSettlementPending("Committed old-certificate absence awaits a time-separated observation.")
        latest = endpoint(token, endpoint_id)
        if (
            latest.get("id") != endpoint_id
            or latest.get("origin") != expected_origin
            or latest.get("ttl") != journal["ttl"]
            or latest.get("custom_domain") != MEDIA_HOST
            or latest.get("certificate_id") != known_new
        ):
            raise RotationError("Committed certificate binding changed during retirement.")
        wait_for_tls(str(journal["newCertificateSha256"]))
        clear_journal()
        return True

    if discovered:
        if current_certificate in discovered:
            api(
                token,
                "PUT",
                f"/cdn/endpoints/{endpoint_id}",
                {"ttl": journal["ttl"], "certificate_id": old_id, "custom_domain": MEDIA_HOST},
            )
            rolled_back = endpoint(token, endpoint_id)
            if (
                rolled_back.get("id") != endpoint_id
                or rolled_back.get("origin") != expected_origin
                or rolled_back.get("ttl") != journal["ttl"]
                or rolled_back.get("custom_domain") != MEDIA_HOST
                or rolled_back.get("certificate_id") != old_id
            ):
                raise RotationError("Pending certificate reconciliation rollback readback failed.")
            wait_for_tls(str(journal["oldTlsSha256"]))
            current = rolled_back
        elif current_certificate != old_id:
            for identifier in discovered:
                delete_transaction_certificate(token, identifier, name, prior_ids)
            raise RotationError("Pending certificate reconciliation preserved endpoint drift after owned cleanup.")

        for identifier in discovered:
            if identifier in transaction_certificates(token, name, prior_ids):
                delete_transaction_certificate(token, identifier, name, prior_ids)
        if observe_transaction_certificates(token, name, prior_ids, attempts=2, delay=1.0):
            raise RotationError("Pending certificate reconciliation could not prove replacement absence.")
        readback = endpoint(token, endpoint_id)
        if (
            readback.get("id") != endpoint_id
            or readback.get("origin") != expected_origin
            or readback.get("ttl") != journal["ttl"]
            or readback.get("custom_domain") != MEDIA_HOST
            or readback.get("certificate_id") != old_id
        ):
            raise RotationError("Pending certificate reconciliation did not restore the prior exact binding.")
        if multiple_results or identity_mismatch:
            raise RotationError("Pending certificate reconciliation removed ambiguous transaction objects but remains blocked.")
        clear_journal()
        return True

    if current_certificate != old_id:
        raise RotationError("Pending certificate reconciliation cannot prove the prior exact binding.")
    now = int(time.time())
    previous_observed_at = journal["lastAbsenceAt"]
    observations = int(journal["absenceObservations"]) + 1
    journal = update_journal(
        journal,
        absenceObservations=observations,
        lastAbsenceAt=now,
    )
    settled = (
        previous_observed_at is not None
        and now - int(previous_observed_at) >= 60
        and now - int(journal["createdAt"]) >= RECONCILIATION_SETTLE_SECONDS
        and observations >= 2
    )
    if settled:
        clear_journal()
        return True
    raise RotationError("Certificate creation outcome remains uncertain; protected reconciliation evidence was retained.")


def create_transaction_certificate(
    token: str,
    name: str,
    payload: dict[str, object],
    prior_ids: set[str],
) -> str:
    try:
        created = object_field(api(token, "POST", "/certificates", payload), "certificate")
        response_identifier = created.get("id")
        discovered = transaction_certificates(token, name, prior_ids)
        if (
            not isinstance(response_identifier, str)
            or not UUID.fullmatch(response_identifier)
            or discovered != [response_identifier]
        ):
            raise RotationError("New certificate identity readback is malformed or ambiguous.")
        return response_identifier
    except Exception as error:
        # The transaction name is random, exact, and proved absent from the
        # pre-mutation inventory. Delete every newly observed exact-name row so
        # malformed create responses cannot strand an uploaded certificate.
        discovered = transaction_certificates(token, name, prior_ids)
        for identifier in list(discovered):
            delete_transaction_certificate(token, identifier, name, prior_ids)
        if discovered:
            if transaction_certificates(token, name, prior_ids):
                raise RotationError("Malformed certificate creation cleanup remained incomplete.") from error
            raise CreationCleanedError("Malformed certificate creation was removed and remains blocked.") from error
        raise


def certificate_der(path: Path) -> bytes:
    result = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-outform", "DER"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    if not result.stdout:
        raise RotationError("Leaf certificate could not be decoded.")
    return result.stdout


def validate_certificate(certificate: Path, chain: Path, private_key: Path) -> str:
    for path in (certificate, chain, private_key):
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_uid != 0:
            raise RotationError("Certificate input must resolve to one root-owned regular file.")
        if not resolved.is_relative_to(Path("/etc/letsencrypt/archive/media-forums.mochirii.com")):
            raise RotationError("Certificate input escaped the exact ACME archive boundary.")
    if private_key.resolve().stat().st_mode & 0o077:
        raise RotationError("Certificate private key permissions are too broad.")
    commands = (
        ["openssl", "x509", "-in", str(certificate), "-checkhost", MEDIA_HOST, "-noout"],
        ["openssl", "x509", "-in", str(certificate), "-checkend", "2592000", "-noout"],
        ["openssl", "pkey", "-in", str(private_key), "-check", "-noout"],
    )
    for command in commands:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    leaf_key = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    ).stdout
    private_public_key = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    ).stdout
    if not leaf_key or not hashlib.sha256(leaf_key).digest() == hashlib.sha256(private_public_key).digest():
        raise RotationError("Certificate and private key do not match.")
    return hashlib.sha256(certificate_der(certificate)).hexdigest()


def served_tls_fingerprint() -> str:
    context = ssl.create_default_context()
    with socket.create_connection((MEDIA_HOST, 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=MEDIA_HOST) as secured:
            served = secured.getpeercert(binary_form=True)
    return hashlib.sha256(served).hexdigest()


def wait_for_tls(expected_fingerprint: str) -> None:
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            if served_tls_fingerprint() == expected_fingerprint:
                return
        except (OSError, ssl.SSLError):
            pass
        time.sleep(10)
    raise RotationError("The custom media hostname did not serve the new trusted certificate.")


def bounded_pem(path: Path) -> str:
    resolved = path.resolve(strict=True)
    data = resolved.read_bytes()
    if not 1 <= len(data) <= 256 * 1024:
        raise RotationError("Certificate input exceeds its byte boundary.")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as error:
        raise RotationError("Certificate input is not ASCII PEM data.") from error


def main() -> int:
    if os.geteuid() != 0:
        raise RotationError("Certificate rotation must run as root.")
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--chain", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--runtime-json", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--reconcile-only", action="store_true")
    args = parser.parse_args()
    if args.preflight_only and args.reconcile_only:
        raise RotationError("Certificate modes are mutually exclusive.")

    runtime = protected_runtime(args.runtime_json)
    token = runtime["providerApiToken"]
    endpoint_id = runtime["cdnEndpointId"]
    expected_origin = runtime["cdnOrigin"]
    if not UUID.fullmatch(endpoint_id) or str(uuid.UUID(endpoint_id)) != endpoint_id:
        raise RotationError("CDN endpoint identifier is malformed.")
    if not ORIGIN.fullmatch(expected_origin):
        raise RotationError("CDN origin differs from the exact SGP1 Spaces form.")
    fixed_event("started")
    reconcile_journal(token, endpoint_id, expected_origin)
    if args.reconcile_only:
        fixed_event("passed")
        print("Mochirii Forums media certificate reconciliation passed.")
        return 0
    fingerprint = validate_certificate(args.certificate, args.chain, args.private_key)

    current = endpoint(token, endpoint_id)
    if current.get("id") != endpoint_id or current.get("origin") != expected_origin:
        raise RotationError("CDN endpoint readback differs from the exact configured resource.")
    if current.get("custom_domain") != MEDIA_HOST:
        raise RotationError("CDN endpoint is not already bound to the exact custom hostname.")
    old_certificate_id = current.get("certificate_id")
    if not isinstance(old_certificate_id, str) or not UUID.fullmatch(old_certificate_id):
        raise RotationError("CDN endpoint certificate readback is malformed.")
    old_certificate = object_field(api(token, "GET", f"/certificates/{old_certificate_id}"), "certificate")
    if old_certificate.get("id") != old_certificate_id or not str(old_certificate.get("name", "")).startswith(
        CERTIFICATE_NAME_PREFIX
    ):
        raise RotationError("The bound certificate is not owned by this exact renewal contract.")
    try:
        old_tls_fingerprint = served_tls_fingerprint()
    except (OSError, ssl.SSLError) as error:
        raise RotationError("The prior custom-host certificate was not trusted before rotation.") from error
    ttl = current.get("ttl")
    if not isinstance(ttl, int) or ttl <= 0:
        raise RotationError("CDN endpoint TTL readback is malformed.")
    if args.preflight_only:
        if old_tls_fingerprint != fingerprint:
            raise RotationError("The bound custom-host certificate differs from the protected ACME lineage.")
        fixed_event("passed")
        print("Mochirii Forums media certificate automation preflight passed.")
        return 0

    prior_inventory = pre_mutation_inventory(token)
    prior_certificate_ids = {row["id"] for row in prior_inventory}
    if old_certificate_id not in prior_certificate_ids:
        raise RotationError("The bound prior certificate is absent from the reserved inventory.")
    certificate_name = CERTIFICATE_NAME_PREFIX + fingerprint[:12] + "-" + uuid.uuid4().hex[:12]
    private_key_pem = bounded_pem(args.private_key)
    leaf_certificate_pem = bounded_pem(args.certificate)
    certificate_chain_pem = bounded_pem(args.chain)
    new_certificate_id: str | None = None
    journal: dict[str, object] = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": expected_origin,
        "customDomain": MEDIA_HOST,
        "transactionName": certificate_name,
        "priorCertificateIds": sorted(prior_certificate_ids),
        "oldCertificateId": old_certificate_id,
        "oldTlsSha256": old_tls_fingerprint,
        "newCertificateSha256": fingerprint,
        "newCertificateId": None,
        "ttl": ttl,
        "phase": "prepared",
        "createdAt": int(time.time()),
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    if JOURNAL.exists():
        raise RotationError("A certificate journal survived reconciliation; no new mutation is allowed.")
    write_journal(journal)
    try:
        new_certificate_id = create_transaction_certificate(
            token,
            certificate_name,
            {
                "name": certificate_name,
                "type": "custom",
                "private_key": private_key_pem,
                "leaf_certificate": leaf_certificate_pem,
                "certificate_chain": certificate_chain_pem,
            },
            prior_certificate_ids,
        )
        journal = update_journal(journal, phase="created", newCertificateId=new_certificate_id)
        api(
            token,
            "PUT",
            f"/cdn/endpoints/{endpoint_id}",
            {"ttl": ttl, "certificate_id": new_certificate_id, "custom_domain": MEDIA_HOST},
        )
        rebound = endpoint(token, endpoint_id)
        if (
            rebound.get("id") != endpoint_id
            or rebound.get("origin") != expected_origin
            or rebound.get("ttl") != ttl
            or rebound.get("custom_domain") != MEDIA_HOST
            or rebound.get("certificate_id") != new_certificate_id
        ):
            raise RotationError("CDN certificate rotation readback failed.")
        journal = update_journal(journal, phase="bound")
        wait_for_tls(fingerprint)
        journal = update_journal(journal, phase="retiring-old")
        try:
            reconcile_journal(token, endpoint_id, expected_origin)
        except RetirementSettlementPending:
            time.sleep(60)
            if not reconcile_journal(token, endpoint_id, expected_origin):
                raise RotationError("Certificate retirement journal disappeared before settlement.")
    except CreationCleanedError:
        latest = endpoint(token, endpoint_id)
        if latest.get("certificate_id") != old_certificate_id or transaction_certificates(token, certificate_name, prior_certificate_ids):
            raise RotationError("Cleaned certificate creation did not preserve the exact prior binding.")
        clear_journal()
        raise
    except Exception as error:
        try:
            reconcile_journal(token, endpoint_id, expected_origin)
        except Exception as reconciliation_error:
            raise reconciliation_error from error
        raise

    fixed_event("passed")
    print("Mochirii Forums media certificate rotated and verified.")
    return 0


if __name__ == "__main__":
    try:
        result = main()
    except BaseException:
        try:
            if os.geteuid() == 0:
                fixed_event("blocked")
        except Exception:
            pass
        raise
    raise SystemExit(result)
