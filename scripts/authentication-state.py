#!/usr/bin/env python3
"""Validate the sealed Forums authentication activation state machine."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z")
POINTER_KEYS = {
    "repositoryCommit",
    "productionConfigurationSha256",
    "authenticationEvidenceFile",
    "authenticationEvidenceSha256",
    "activationPhase",
}
COMMON_RECORD_KEYS = {
    "schemaVersion",
    "recordedAt",
    "repositoryCommit",
    "productionConfigurationSha256",
    "releaseEvidenceFile",
    "releaseEvidenceSha256",
    "currentReleaseSha256",
    "activationPhase",
}
PHASE_SUFFIXES = {
    "consumer-public-producer-pending": "authentication-pending",
    "complete": "authentication-complete",
    "contained-after-e2e-failure": "authentication-contained",
    "contained-producer-state-unproved": "authentication-containment-unproved",
    "activation-deploy-failed": "authentication-activation-failed",
    "activation-deploy-failed-producer-unproved": "authentication-activation-failed-unproved",
}
PENDING_GATES = {
    "websiteProducerDisabledProved",
    "containedActivationPassed",
    "publicForumsVerificationPassed",
}
COMPLETE_REFERENCES = {
    "pendingAuthenticationEvidenceFile",
    "pendingAuthenticationEvidenceSha256",
    "websiteEvidenceFile",
    "websiteEvidenceSha256",
    "websiteRepositoryCommit",
}
COMPLETE_GATES = {
    "websiteProducerEnabled",
    "producerFailClosedBeforeEnablePassed",
    "activeMemberAllowed",
    "inactiveMemberDenied",
    "unverifiedMemberDenied",
    "invalidSignatureDenied",
    "malformedRequestDenied",
    "expiredRequestDenied",
    "replayDenied",
    "alternateLoginDisabled",
    "callbackLogRedactionPassed",
    "callbackBrowserQueryScrubPassed",
    "callbackBrowserPrivateResponsePassed",
    "terminalHostVerificationPassed",
}
CONTAINMENT_FIELDS = {
    "pendingAuthenticationEvidenceFile",
    "pendingAuthenticationEvidenceSha256",
    "websiteProducerDisabledProved",
    "applicationStopped",
}
ACTIVATION_FAILURE_FIELDS = {
    "schemaVersion",
    "recordedAt",
    "repositoryCommit",
    "productionConfigurationSha256",
    "previousRepositoryCommit",
    "previousProductionConfigurationSha256",
    "releaseEvidenceFile",
    "releaseEvidenceSha256",
    "currentReleaseSha256",
    "activationPhase",
    "websiteProducerDisabledProved",
    "applicationStopped",
}
PHASE_KEYS = {
    "consumer-public-producer-pending": COMMON_RECORD_KEYS | PENDING_GATES,
    "complete": COMMON_RECORD_KEYS | COMPLETE_REFERENCES | COMPLETE_GATES,
    "contained-after-e2e-failure": COMMON_RECORD_KEYS | CONTAINMENT_FIELDS,
    "contained-producer-state-unproved": COMMON_RECORD_KEYS | CONTAINMENT_FIELDS,
    "activation-deploy-failed": ACTIVATION_FAILURE_FIELDS,
    "activation-deploy-failed-producer-unproved": ACTIVATION_FAILURE_FIELDS,
}
CURRENT_RELEASE_KEYS = {
    "repositoryCommit",
    "productionConfigurationSha256",
    "releaseEvidenceFile",
    "releaseEvidenceSha256",
    "discourseConnectEnabled",
    "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
}
RELEASE_RECORD_KEYS = {
    "schemaVersion",
    "recordedAt",
    "repositoryCommit",
    "repositoryTree",
    "releaseArchiveSha256",
    "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256",
    "discourseDockerRevision",
    "discourseRevision",
    "dockerManagerRevision",
    "baseImageDigest",
    "productionConfigurationSha256",
    "restoreConfigurationSha256",
    "containedActivationConfigurationSha256",
    "containedActivationPassed",
    "activationPhase",
    "themeArchiveSha256",
    "mailMetadataPluginSha256",
    "discourseConnectEnabled",
    "memberRolloutMarkerFile",
    "memberRolloutMarkerSha256",
    "hostVerificationPassed",
    "storageEvidenceFile",
    "storageEvidenceSha256",
    "hostedStoragePassed",
    "storageRestartPersistencePassed",
    "storageRebuildPersistencePassed",
    "storageCleanupPassed",
}
WEBSITE_IDENTITY_KEYS = {
    "schemaVersion",
    "recordedAt",
    "websiteRepositoryCommit",
    "forumsRepositoryCommit",
    "forumsProductionConfigurationSha256",
}
WEBSITE_GATE_KEYS = {
    "websiteProducerEnabled",
    "producerFailClosedBeforeEnablePassed",
    "activeMemberAllowed",
    "inactiveMemberDenied",
    "unverifiedMemberDenied",
    "invalidSignatureDenied",
    "malformedRequestDenied",
    "expiredRequestDenied",
    "replayDenied",
    "alternateLoginDisabled",
    "callbackLogRedactionPassed",
    "callbackBrowserQueryScrubPassed",
    "callbackBrowserPrivateResponsePassed",
}


class AuthenticationStateError(RuntimeError):
    pass


def _exact_hex(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_documents(pointer: object, record: object) -> str:
    if not isinstance(pointer, dict) or set(pointer) != POINTER_KEYS:
        raise AuthenticationStateError("Current authentication evidence schema differs.")
    commit = pointer.get("repositoryCommit")
    configuration = pointer.get("productionConfigurationSha256")
    digest = pointer.get("authenticationEvidenceSha256")
    phase = pointer.get("activationPhase")
    if not _exact_hex(commit, HEX40) or not _exact_hex(configuration, HEX64) or not _exact_hex(digest, HEX64):
        raise AuthenticationStateError("Current authentication evidence identity is malformed.")
    if phase not in PHASE_SUFFIXES:
        raise AuthenticationStateError("Current authentication phase is outside the exact state machine.")
    expected_name = f"{commit}-{configuration}-{PHASE_SUFFIXES[phase]}.json"
    if pointer.get("authenticationEvidenceFile") != expected_name:
        raise AuthenticationStateError("Current authentication evidence filename differs.")
    if not isinstance(record, dict) or set(record) != PHASE_KEYS[phase] or record.get("schemaVersion") != 1:
        raise AuthenticationStateError("Current authentication evidence record schema differs.")
    if phase in {"activation-deploy-failed", "activation-deploy-failed-producer-unproved"}:
        previous_commit = record.get("previousRepositoryCommit")
        previous_configuration = record.get("previousProductionConfigurationSha256")
        expected_producer_state = phase == "activation-deploy-failed"
        if (
            record.get("repositoryCommit") != commit
            or record.get("productionConfigurationSha256") != configuration
            or not _exact_hex(previous_commit, HEX40)
            or not _exact_hex(previous_configuration, HEX64)
            or record.get("releaseEvidenceFile") != f"{previous_commit}-{previous_configuration}-release.json"
            or not _exact_hex(record.get("releaseEvidenceSha256"), HEX64)
            or not _exact_hex(record.get("currentReleaseSha256"), HEX64)
            or record.get("activationPhase") != phase
            or record.get("applicationStopped") is not True
            or record.get("websiteProducerDisabledProved") is not expected_producer_state
            or not isinstance(record.get("recordedAt"), str)
            or TIMESTAMP.fullmatch(record["recordedAt"]) is None
        ):
            raise AuthenticationStateError("Activation deployment failure evidence differs.")
        return phase
    if (
        record.get("repositoryCommit") != commit
        or record.get("productionConfigurationSha256") != configuration
        or record.get("releaseEvidenceFile") != f"{commit}-{configuration}-release.json"
        or not _exact_hex(record.get("releaseEvidenceSha256"), HEX64)
        or not _exact_hex(record.get("currentReleaseSha256"), HEX64)
        or record.get("activationPhase") != phase
        or not isinstance(record.get("recordedAt"), str)
        or TIMESTAMP.fullmatch(record["recordedAt"]) is None
    ):
        raise AuthenticationStateError("Current authentication evidence record tuple differs.")
    pending_name = f"{commit}-{configuration}-authentication-pending.json"
    if phase == "consumer-public-producer-pending":
        if any(record.get(key) is not True for key in PENDING_GATES):
            raise AuthenticationStateError("Pending authentication evidence contains an unpassed gate.")
    elif phase == "complete":
        if (
            record.get("pendingAuthenticationEvidenceFile") != pending_name
            or not _exact_hex(record.get("pendingAuthenticationEvidenceSha256"), HEX64)
            or record.get("websiteEvidenceFile") != f"{commit}-{configuration}-website-authentication.json"
            or not _exact_hex(record.get("websiteEvidenceSha256"), HEX64)
            or not _exact_hex(record.get("websiteRepositoryCommit"), HEX40)
            or any(record.get(key) is not True for key in COMPLETE_GATES)
        ):
            raise AuthenticationStateError("Completed authentication evidence differs.")
    else:
        expected_producer_state = phase == "contained-after-e2e-failure"
        if (
            record.get("pendingAuthenticationEvidenceFile") != pending_name
            or not _exact_hex(record.get("pendingAuthenticationEvidenceSha256"), HEX64)
            or record.get("applicationStopped") is not True
            or record.get("websiteProducerDisabledProved") is not expected_producer_state
        ):
            raise AuthenticationStateError("Authentication containment evidence differs.")
    return phase


def _read_protected(path: Path, label: str) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AuthenticationStateError(f"{label} is not one protected regular file.")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65_536:
        raise AuthenticationStateError(f"{label} permissions or size are unsafe.")
    return path.read_bytes()


def _decode_object(content: bytes, label: str) -> dict[str, object]:
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthenticationStateError(f"{label} is not valid JSON.") from error
    if not isinstance(document, dict):
        raise AuthenticationStateError(f"{label} is not one JSON object.")
    return document


def _canonical_object_bytes(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")


def _validate_release_record(
    release: dict[str, object],
    commit: str,
    configuration: str,
    discourse_connect: bool,
    label: str,
) -> None:
    expected_phase = "consumer-public-producer-pending" if discourse_connect else "consumer-disabled"
    contained_configuration = release.get("containedActivationConfigurationSha256")
    marker_file = release.get("memberRolloutMarkerFile")
    marker_sha = release.get("memberRolloutMarkerSha256")
    if (
        set(release) != RELEASE_RECORD_KEYS
        or release.get("schemaVersion") != 2
        or not isinstance(release.get("recordedAt"), str)
        or TIMESTAMP.fullmatch(str(release["recordedAt"])) is None
        or release.get("repositoryCommit") != commit
        or release.get("productionConfigurationSha256") != configuration
        or release.get("discourseDockerRevision") != "ed9f680b0df1de28f062de1769d89d22b2644d1b"
        or release.get("discourseRevision") != "badad7b0456a628e578bc48b9f8c1259422b5d58"
        or release.get("dockerManagerRevision") != "c008c3ca7fcc44775215843992e88190adb7b3bf"
        or release.get("baseImageDigest")
        != "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
        or not _exact_hex(release.get("repositoryTree"), HEX40)
        or not _exact_hex(release.get("releaseArchiveSha256"), HEX64)
        or not isinstance(release.get("releaseArchiveBytes"), int)
        or isinstance(release.get("releaseArchiveBytes"), bool)
        or not 1 <= int(release["releaseArchiveBytes"]) <= 67_108_864
        or not _exact_hex(release.get("releaseArchiveContentManifestSha256"), HEX64)
        or not _exact_hex(release.get("restoreConfigurationSha256"), HEX64)
        or not _exact_hex(release.get("themeArchiveSha256"), HEX64)
        or not _exact_hex(release.get("mailMetadataPluginSha256"), HEX64)
        or release.get("discourseConnectEnabled") is not discourse_connect
        or release.get("activationPhase") != expected_phase
        or release.get("containedActivationPassed") is not discourse_connect
        or (
            discourse_connect
            and not _exact_hex(contained_configuration, HEX64)
        )
        or (not discourse_connect and contained_configuration is not None)
        or any(
            release.get(gate) is not True
            for gate in (
                "hostVerificationPassed",
                "hostedStoragePassed",
                "storageRestartPersistencePassed",
                "storageRebuildPersistencePassed",
                "storageCleanupPassed",
            )
        )
        or release.get("storageEvidenceFile") != f"{commit}-{configuration}-storage.json"
        or not _exact_hex(release.get("storageEvidenceSha256"), HEX64)
        or (marker_file is None) != (marker_sha is None)
        or (
            marker_file is not None
            and (marker_file != "member-rollout-enabled" or not _exact_hex(marker_sha, HEX64))
        )
    ):
        raise AuthenticationStateError(f"{label} contract differs.")


def _validate_member_marker(
    state_root: Path,
    marker_file: object,
    marker_sha: object,
    label: str,
) -> None:
    if marker_file is None and marker_sha is None:
        return
    if marker_file != "member-rollout-enabled" or not _exact_hex(marker_sha, HEX64):
        raise AuthenticationStateError(f"{label} identity differs.")
    marker_bytes = _read_protected(state_root / marker_file, label)
    if hashlib.sha256(marker_bytes).hexdigest() != marker_sha:
        raise AuthenticationStateError(f"{label} digest differs.")


def _validate_reference_chain(
    pointer_path: Path,
    pointer: dict[str, object],
    record: dict[str, object],
    expected_commit: str,
    expected_configuration: str,
) -> None:
    state_root = pointer_path.parent
    evidence_root = state_root / "evidence"
    commit = str(pointer["repositoryCommit"])
    configuration = str(pointer["productionConfigurationSha256"])

    phase = str(pointer["activationPhase"])
    if phase in {"activation-deploy-failed", "activation-deploy-failed-producer-unproved"}:
        previous_commit = str(record["previousRepositoryCommit"])
        previous_configuration = str(record["previousProductionConfigurationSha256"])
        release_name = f"{previous_commit}-{previous_configuration}-release.json"
        live_current_bytes = _read_protected(state_root / "current-release.json", "Current release pointer")
        live_current = _decode_object(live_current_bytes, "Current release pointer")
        release_bytes = _read_protected(evidence_root / release_name, "Prior immutable release record")
        release_sha = hashlib.sha256(release_bytes).hexdigest()
        release = _decode_object(release_bytes, "Prior immutable release record")
        live_matches_prior = (
            set(live_current) == CURRENT_RELEASE_KEYS
            and live_current.get("repositoryCommit") == previous_commit
            and live_current.get("productionConfigurationSha256") == previous_configuration
            and live_current.get("releaseEvidenceFile") == release_name
            and live_current.get("discourseConnectEnabled") is False
        )
        if live_matches_prior:
            reference_current = live_current
            reference_current_bytes = live_current_bytes
        else:
            target_release_name = f"{commit}-{configuration}-release.json"
            if (
                phase != "activation-deploy-failed"
                or commit != expected_commit
                or configuration != expected_configuration
                or set(live_current) != CURRENT_RELEASE_KEYS
                or live_current.get("repositoryCommit") != commit
                or live_current.get("productionConfigurationSha256") != configuration
                or live_current.get("releaseEvidenceFile") != target_release_name
                or live_current.get("discourseConnectEnabled") is not True
            ):
                raise AuthenticationStateError(
                    "Stopped activation retry does not name the exact prior or verified target release."
                )
            target_release_bytes = _read_protected(
                evidence_root / target_release_name,
                "Stopped activation retry target release",
            )
            target_release_sha = hashlib.sha256(target_release_bytes).hexdigest()
            target_release = _decode_object(target_release_bytes, "Stopped activation retry target release")
            _validate_release_record(
                target_release,
                commit,
                configuration,
                True,
                "Stopped activation retry target release",
            )
            if (
                live_current.get("releaseEvidenceSha256") != target_release_sha
                or live_current.get("memberRolloutMarkerFile") != target_release.get("memberRolloutMarkerFile")
                or live_current.get("memberRolloutMarkerSha256") != target_release.get("memberRolloutMarkerSha256")
            ):
                raise AuthenticationStateError("Stopped activation retry target release chain differs.")
            _validate_member_marker(
                state_root,
                target_release.get("memberRolloutMarkerFile"),
                target_release.get("memberRolloutMarkerSha256"),
                "Stopped activation retry target member-rollout marker",
            )
            reference_current = {
                "repositoryCommit": previous_commit,
                "productionConfigurationSha256": previous_configuration,
                "releaseEvidenceFile": release_name,
                "releaseEvidenceSha256": release_sha,
                "discourseConnectEnabled": False,
                "memberRolloutMarkerFile": release.get("memberRolloutMarkerFile"),
                "memberRolloutMarkerSha256": release.get("memberRolloutMarkerSha256"),
            }
            reference_current_bytes = _canonical_object_bytes(reference_current)
        if (
            reference_current.get("releaseEvidenceSha256") != release_sha
            or record.get("releaseEvidenceFile") != release_name
            or record.get("releaseEvidenceSha256") != release_sha
            or record.get("currentReleaseSha256") != hashlib.sha256(reference_current_bytes).hexdigest()
            or set(release) != RELEASE_RECORD_KEYS
            or release.get("schemaVersion") != 2
            or release.get("repositoryCommit") != previous_commit
            or not _exact_hex(release.get("repositoryTree"), HEX40)
            or not _exact_hex(release.get("releaseArchiveSha256"), HEX64)
            or not isinstance(release.get("releaseArchiveBytes"), int)
            or isinstance(release.get("releaseArchiveBytes"), bool)
            or not 1 <= int(release["releaseArchiveBytes"]) <= 67_108_864
            or not _exact_hex(release.get("releaseArchiveContentManifestSha256"), HEX64)
            or release.get("productionConfigurationSha256") != previous_configuration
            or release.get("discourseConnectEnabled") is not False
            or release.get("activationPhase") != "consumer-disabled"
            or release.get("containedActivationPassed") is not False
            or release.get("containedActivationConfigurationSha256") is not None
            or any(
                release.get(gate) is not True
                for gate in (
                    "hostVerificationPassed",
                    "hostedStoragePassed",
                    "storageRestartPersistencePassed",
                    "storageRebuildPersistencePassed",
                    "storageCleanupPassed",
                )
            )
            or reference_current.get("memberRolloutMarkerFile") != release.get("memberRolloutMarkerFile")
            or reference_current.get("memberRolloutMarkerSha256") != release.get("memberRolloutMarkerSha256")
        ):
            raise AuthenticationStateError("Stopped activation retry release evidence chain differs.")
        marker_file = reference_current.get("memberRolloutMarkerFile")
        marker_sha = reference_current.get("memberRolloutMarkerSha256")
        if marker_file != "member-rollout-enabled" or not _exact_hex(marker_sha, HEX64):
            raise AuthenticationStateError("Stopped activation retry lacks the exact permanent member-rollout marker.")
        marker_bytes = _read_protected(state_root / marker_file, "Member-rollout marker")
        if hashlib.sha256(marker_bytes).hexdigest() != marker_sha:
            raise AuthenticationStateError("Stopped activation retry member-rollout marker digest differs.")
        return

    live_current_bytes = _read_protected(state_root / "current-release.json", "Current release pointer")
    live_current = _decode_object(live_current_bytes, "Current release pointer")
    release_name = f"{commit}-{configuration}-release.json"
    release_bytes = _read_protected(evidence_root / release_name, "Immutable release record")
    release_sha = hashlib.sha256(release_bytes).hexdigest()
    release = _decode_object(release_bytes, "Immutable release record")
    _validate_release_record(release, commit, configuration, True, "Authentication release evidence")

    live_matches_authentication = (
        set(live_current) == CURRENT_RELEASE_KEYS
        and live_current.get("repositoryCommit") == commit
        and live_current.get("productionConfigurationSha256") == configuration
        and live_current.get("releaseEvidenceFile") == release_name
        and live_current.get("discourseConnectEnabled") is True
    )
    if live_matches_authentication:
        reference_current = live_current
        reference_current_bytes = live_current_bytes
    else:
        target_release_name = f"{expected_commit}-{expected_configuration}-release.json"
        target_release_path = evidence_root / target_release_name
        if (
            phase != "complete"
            or (commit == expected_commit and configuration == expected_configuration)
            or set(live_current) != CURRENT_RELEASE_KEYS
            or live_current.get("repositoryCommit") != expected_commit
            or live_current.get("productionConfigurationSha256") != expected_configuration
            or live_current.get("releaseEvidenceFile") != target_release_name
            or live_current.get("discourseConnectEnabled") is not False
        ):
            raise AuthenticationStateError("Current release authentication tuple differs.")
        target_release_bytes = _read_protected(target_release_path, "Authentication advance target release")
        target_release_sha = hashlib.sha256(target_release_bytes).hexdigest()
        target_release = _decode_object(target_release_bytes, "Authentication advance target release")
        _validate_release_record(
            target_release,
            expected_commit,
            expected_configuration,
            False,
            "Authentication advance target release",
        )
        if (
            live_current.get("releaseEvidenceSha256") != target_release_sha
            or live_current.get("memberRolloutMarkerFile") != target_release.get("memberRolloutMarkerFile")
            or live_current.get("memberRolloutMarkerSha256") != target_release.get("memberRolloutMarkerSha256")
        ):
            raise AuthenticationStateError("Authentication advance target release chain differs.")
        _validate_member_marker(
            state_root,
            target_release.get("memberRolloutMarkerFile"),
            target_release.get("memberRolloutMarkerSha256"),
            "Authentication advance target member-rollout marker",
        )
        reference_current = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "releaseEvidenceFile": release_name,
            "releaseEvidenceSha256": release_sha,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": release.get("memberRolloutMarkerFile"),
            "memberRolloutMarkerSha256": release.get("memberRolloutMarkerSha256"),
        }
        reference_current_bytes = _canonical_object_bytes(reference_current)

    if (
        reference_current.get("releaseEvidenceSha256") != release_sha
        or record.get("releaseEvidenceFile") != release_name
        or record.get("releaseEvidenceSha256") != release_sha
        or record.get("currentReleaseSha256") != hashlib.sha256(reference_current_bytes).hexdigest()
        or reference_current.get("memberRolloutMarkerFile") != release.get("memberRolloutMarkerFile")
        or reference_current.get("memberRolloutMarkerSha256") != release.get("memberRolloutMarkerSha256")
    ):
        raise AuthenticationStateError("Authentication release evidence chain differs.")
    _validate_member_marker(
        state_root,
        release.get("memberRolloutMarkerFile"),
        release.get("memberRolloutMarkerSha256"),
        "Authentication member-rollout marker",
    )

    if phase in {"complete", "contained-after-e2e-failure", "contained-producer-state-unproved"}:
        pending_name = f"{commit}-{configuration}-authentication-pending.json"
        pending_bytes = _read_protected(evidence_root / pending_name, "Pending authentication record")
        pending_sha = hashlib.sha256(pending_bytes).hexdigest()
        if (
            record.get("pendingAuthenticationEvidenceFile") != pending_name
            or record.get("pendingAuthenticationEvidenceSha256") != pending_sha
        ):
            raise AuthenticationStateError("Pending authentication evidence chain differs.")
        pending = _decode_object(pending_bytes, "Pending authentication record")
        pending_pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": pending_name,
            "authenticationEvidenceSha256": pending_sha,
            "activationPhase": "consumer-public-producer-pending",
        }
        validate_documents(pending_pointer, pending)
        if (
            pending.get("releaseEvidenceSha256") != release_sha
            or pending.get("currentReleaseSha256") != hashlib.sha256(reference_current_bytes).hexdigest()
        ):
            raise AuthenticationStateError("Pending authentication release chain differs.")

    if phase == "complete":
        website_name = f"{commit}-{configuration}-website-authentication.json"
        website_bytes = _read_protected(state_root / "operator-evidence" / website_name, "Website authentication record")
        if (
            record.get("websiteEvidenceFile") != website_name
            or record.get("websiteEvidenceSha256") != hashlib.sha256(website_bytes).hexdigest()
        ):
            raise AuthenticationStateError("Website authentication evidence chain differs.")
        website = _decode_object(website_bytes, "Website authentication record")
        if (
            set(website) != WEBSITE_IDENTITY_KEYS | WEBSITE_GATE_KEYS
            or website.get("schemaVersion") != 1
            or not isinstance(website.get("recordedAt"), str)
            or TIMESTAMP.fullmatch(str(website["recordedAt"])) is None
            or not _exact_hex(website.get("websiteRepositoryCommit"), HEX40)
            or website.get("websiteRepositoryCommit") != record.get("websiteRepositoryCommit")
            or website.get("forumsRepositoryCommit") != commit
            or website.get("forumsProductionConfigurationSha256") != configuration
            or any(website.get(key) is not True for key in WEBSITE_GATE_KEYS)
        ):
            raise AuthenticationStateError("Website authentication evidence differs.")


def evaluate(pointer_path: Path, expected_commit: str, expected_configuration: str) -> str:
    pointer_bytes = _read_protected(pointer_path, "Current authentication pointer")
    pointer = _decode_object(pointer_bytes, "Current authentication pointer")
    phase = pointer.get("activationPhase")
    if phase not in PHASE_SUFFIXES:
        raise AuthenticationStateError("Current authentication phase is outside the exact state machine.")
    record_name = pointer.get("authenticationEvidenceFile")
    if not isinstance(record_name, str) or Path(record_name).name != record_name:
        raise AuthenticationStateError("Current authentication record filename is unsafe.")
    record_path = pointer_path.parent / "evidence" / record_name
    record_bytes = _read_protected(record_path, "Current authentication record")
    if hashlib.sha256(record_bytes).hexdigest() != pointer.get("authenticationEvidenceSha256"):
        raise AuthenticationStateError("Current authentication record digest differs.")
    record = _decode_object(record_bytes, "Current authentication record")
    validated_phase = validate_documents(pointer, record)
    _validate_reference_chain(pointer_path, pointer, record, expected_commit, expected_configuration)
    if pointer.get("repositoryCommit") == expected_commit and pointer.get("productionConfigurationSha256") == expected_configuration:
        return validated_phase
    return "stale-other-tuple"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-configuration", required=True)
    args = parser.parse_args()
    if not HEX40.fullmatch(args.expected_commit) or not HEX64.fullmatch(args.expected_configuration):
        raise AuthenticationStateError("Expected authentication tuple is malformed.")
    print(evaluate(args.pointer, args.expected_commit, args.expected_configuration))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
