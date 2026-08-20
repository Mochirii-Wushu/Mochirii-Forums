#!/usr/bin/env python3
"""Focused source contracts for backup and hosted-storage crash recovery."""

from __future__ import annotations

import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def ordered(body: str, *needles: str) -> None:
    positions = []
    for needle in needles:
        position = body.find(needle)
        if position < 0:
            raise RuntimeError(f"Missing transaction contract: {needle}")
        positions.append(position)
    if positions != sorted(positions):
        raise RuntimeError(f"Transaction ordering changed: {needles}")


def main() -> None:
    backup = source("scripts/host-backup.sh")
    backup_ruby = source("scripts/prepare-backup-marker.rb")
    deploy = source("scripts/host-deploy.sh")
    storage_ruby = source("scripts/verify-storage-fixture.rb")
    member = source("scripts/finalize-member-rollout.sh")
    publisher = source("scripts/publish-disaster-recovery-evidence.rb")
    backup_terminal = source("scripts/backup-transaction.py")
    backup_terminal_test = source("scripts/test-backup-transaction.py")
    inventory = source("scripts/normal-upload-inventory.rb")
    verify_backup = source("scripts/verify-backup.rb")
    verify_restored = source("scripts/verify-restored-backup.rb")

    backup_transaction = backup[backup.index("if [[ -z ${marker_file} ]]") :]
    ordered(
        backup_transaction,
        'create_backup_upload_journal "${backup_upload_transaction}"',
        "MOCHIRII_RECOVERY_UPLOAD_ACTION=prepare",
        "MOCHIRII_BACKUP_INVENTORY_ONLY=true",
        "discourse backup",
        "MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_BASE64",
        'reconcile_backup_upload_journal "${backup_upload_journal}"',
        "recovery_upload_deleted=true",
    )
    for required in (
        "os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW",
        "os.fsync(target.fileno())",
        "os.fsync(directory)",
        "*-backup-upload-cleanup-required.json",
        'expected = {"recoveryUploadCleanupPassed": True}',
        "recovery-upload terminal absence proof differs",
        "Backup refuses an active nonterminal restore transaction.",
        "Backup refuses an active deployment transaction.",
        "Backup refuses an unresolved hosted-storage cleanup transaction.",
        "BACKUP_OPERATION_SHA256",
        "backup_operation_sha256=",
        '"backupOperationSha256": operation_sha',
        'backup_runtime_recovery_command bind-cleanup',
        'backup_runtime_recovery_command complete-cleanup',
        'backup_runtime_recovery_command resume-runtime',
        "inspect-current",
        "adopt-current",
        "retire-current",
    ):
        if required not in backup:
            raise RuntimeError(f"Backup journal durability contract is absent: {required}")
    backup_journal_publish = backup[
        backup.index("create_backup_upload_journal()") : backup.index(
            "reconcile_backup_upload_journal_partial()"
        )
    ]
    ordered(
        backup_journal_publish,
        'partial = root / ".backup-upload-cleanup-journal.partial"',
        "descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW",
        "target.write(payload)",
        "os.fsync(target.fileno())",
        "os.link(partial, path, follow_symlinks=False)",
        "partial.unlink()",
    )
    if (
        backup_journal_publish.count("os.fsync(directory)") != 2
        or "os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL" in backup_journal_publish
    ):
        raise RuntimeError("Backup upload journal can expose an un-fsynced final authority.")
    backup_partial_reconcile = backup[
        backup.index("reconcile_backup_upload_journal_partial()") : backup.index(
            "clear_backup_upload_journal()"
        )
    ]
    for required in (
        "metadata.st_nlink != 2",
        "candidate_metadata.st_ino == metadata.st_ino",
        "linked backup upload journal identity differs",
        "uncommitted backup upload journal partial has hidden links",
        "partial.unlink()",
        "os.fsync(directory)",
    ):
        if required not in backup_partial_reconcile:
            raise RuntimeError(
                f"Backup upload partial reconciliation contract is absent: {required}"
            )
    ordered(
        backup,
        "reconcile_backup_upload_journal_partial || fail",
        "pending_backup_upload_journals",
        'create_backup_upload_journal "${backup_upload_transaction}"',
        "MOCHIRII_RECOVERY_UPLOAD_ACTION=prepare",
    )
    backup_prepare = backup_ruby[backup_ruby.index('if action == "prepare"') :]
    ordered(
        backup_prepare,
        "write_transaction_state!(prearmed)",
        "recover_transaction_state!(journal",
        "arm_upload_identity_callback!",
        "UploadCreator.new(",
        "PluginStore.set(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY",
    )
    ordered(
        backup_ruby[backup_ruby.index("def cleanup_transaction!") :],
        "upload.destroy!",
        "bounded_absent!",
        "PluginStore.remove(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)",
        "PluginStore.remove(RECOVERY_NAMESPACE, key)",
    )
    backup_cleanup = backup_ruby[
        backup_ruby.index("def cleanup_transaction!") : backup_ruby.index("def safe_state!")
    ]
    if "upload.content" in backup_cleanup:
        raise RuntimeError(
            "Recovery cleanup still requires an object read before deleting a partial row."
        )
    if "origin: transaction.fetch(\"uploadOrigin\")" not in backup_ruby:
        raise RuntimeError("Recovery upload lacks transaction-owned row identity.")
    terminal_flow = backup[backup.index('if [[ -e ${backup_transaction}') :]
    ordered(
        terminal_flow,
        'finish_backup_transaction "${backup_transaction_phase}" "${evidence}"',
        'printf \'%s\\n\' "Mochirii Forums terminal backup publication reconciled."',
        "record_event started",
        "create_backup_upload_journal",
        "discourse backup",
    )
    finish = backup[backup.index("finish_backup_transaction()") : backup.index("validate_backup_upload_journal()")]
    ordered(
        finish,
        "evidence-sha",
        "select-pointer",
        "publish-phase --phase pointer-committed",
        'record_event passed "${evidence_sha}"',
        "publish-phase --phase event-committed",
        "backup_transaction_command clear",
    )
    for required in (
        "previousLatestPointerSha256",
        '"phase": "prepared"',
        '"pointer-committed"',
        '"event-committed"',
        "latest-backup pointer changed outside this transaction",
        "backup evidence changed after its commit point",
        'partial = path.with_name(f".{path.name}.partial")',
        "os.link(partial, path, follow_symlinks=False)",
        "reconcile_exclusive_partial(args.transaction)",
        "transaction prearm partial differs from its final authority",
        "os.fsync(directory)",
        "backupOperationSha256",
        "current-backup cannot be retired by its own operation",
        "terminal current-backup must be retired before a new transaction",
    ):
        if required not in backup_terminal:
            raise RuntimeError(f"Terminal backup crash contract is absent: {required}")
    for required in (
        "Same-operation terminal backup was not adopted.",
        "different operation retired an intervened pointer",
        "New backup transaction did not bind its caller operation.",
    ):
        if required not in backup_terminal_test:
            raise RuntimeError(f"Terminal backup operation-key fixture is absent: {required}")

    ordered(
        verify_backup,
        "MochiriiNormalUploadInventory.compute!",
        'inventory_only == "true"',
        "BackupRestore::BackupStore.create",
    )
    for required in (
        "Upload.where(secure: false)",
        "MAX_UPLOADS = 10_000",
        "relation.find_each(batch_size: BATCH_SIZE)",
        "store.get_path_for_upload(upload)",
        "object.load",
        "object.size",
        "object.etag",
        '"id" => upload_id',
        '"sha1" => sha1',
        '"filesize" => filesize',
        '"objectPath" => path',
        '"objectSize" => object_size',
        '"objectEtag" => object_etag',
    ):
        if required not in inventory:
            raise RuntimeError(f"Normal-upload inventory contract is absent: {required}")
    for required in (
        "MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT",
        "MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256",
        "MochiriiNormalUploadInventory.compute!",
        "normal_upload_inventory: normal_upload_inventory_matches",
    ):
        if required not in verify_restored:
            raise RuntimeError(f"Restored normal-upload inventory contract is absent: {required}")

    storage_flow = deploy[deploy.index("# Exercise the real hosted object-store path") :]
    ordered(
        storage_flow,
        'create_storage_cleanup_journal "${storage_transaction_id}"',
        "storage_fixture_created=true",
        'run_storage_fixture create "${storage_create_result}" "${storage_cleanup_journal}"',
        'promote_storage_state "${storage_create_result}" "${storage_state}"',
        'run_storage_fixture delete "${storage_delete_result}" "${storage_state}"',
        'validate_storage_terminal_result delete "${storage_delete_result}"',
        'clear_storage_cleanup_journal "${storage_cleanup_journal}"',
        "storage_fixture_deleted=true",
    )
    for required in (
        "pluginStoreNamespace",
        "fixture-transaction:",
        "validate_storage_cleanup_journal",
        "validate_storage_terminal_result",
        "os.replace(source, destination)",
        "the pre-armed exact root-only retry journal was retained",
    ):
        if required not in deploy:
            raise RuntimeError(f"Hosted-storage journal contract is absent: {required}")
    storage_journal_publish = deploy[
        deploy.index("create_storage_cleanup_journal()") : deploy.index(
            "reconcile_storage_cleanup_journal_partial()"
        )
    ]
    ordered(
        storage_journal_publish,
        'partial = root / ".storage-cleanup-journal.partial"',
        "descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW",
        "target.write(payload)",
        "os.fsync(target.fileno())",
        "os.link(partial, path, follow_symlinks=False)",
        "partial.unlink()",
    )
    if (
        storage_journal_publish.count("os.fsync(directory)") != 2
        or "os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL" in storage_journal_publish
    ):
        raise RuntimeError("Hosted-storage journal can expose an un-fsynced final authority.")
    storage_partial_reconcile = deploy[
        deploy.index("reconcile_storage_cleanup_journal_partial()") : deploy.index(
            "validate_storage_cleanup_journal()"
        )
    ]
    for required in (
        "metadata.st_nlink != 2",
        "candidate_metadata.st_ino == metadata.st_ino",
        "linked storage cleanup journal identity differs",
        "uncommitted storage cleanup journal partial has hidden links",
        "partial.unlink()",
        "os.fsync(directory)",
    ):
        if required not in storage_partial_reconcile:
            raise RuntimeError(
                f"Hosted-storage partial reconciliation contract is absent: {required}"
            )
    ordered(
        deploy,
        "reconcile_storage_cleanup_journal_partial || fail",
        "pending_cleanup_candidates=",
        'create_storage_cleanup_journal "${storage_transaction_id}"',
        "storage_fixture_created=true",
    )
    create = storage_ruby[storage_ruby.index('when "create"') : storage_ruby.index('when "verify"')]
    ordered(
        create,
        "write_transaction_state!(initial_transaction_state(journal))",
        "arm_upload_identity_callback!(journal)",
        "UploadCreator.new(",
        "arm_optimized_identity_callback!(journal, upload)",
        "OptimizedImage.create_for",
        "puts JSON.generate(state.sort.to_h)",
    )
    if "puts JSON.generate(recovery.sort.to_h)" in create:
        raise RuntimeError("Hosted-storage recovery still depends on untrusted stdout identity.")
    cleanup = storage_ruby[storage_ruby.index("def cleanup_transaction_fixture!") : storage_ruby.index("def cleanup_owned_fixture!")]
    ordered(
        cleanup,
        "upload.destroy!",
        "transaction owned upload survived cleanup",
        "transaction primary object survived cleanup",
        "PluginStore.remove(TRANSACTION_NAMESPACE",
    )

    if (
        "*-backup-upload-cleanup-required.json" not in member
        or "*-storage-cleanup-required.json" not in member
        or "backup-transaction.json" not in member
        or "deployment-transaction.json" not in member
        or "normalUploadInventoryCount" not in member
        or "normalUploadInventorySha256" not in member
    ):
        raise RuntimeError("Member rollout can bypass an unresolved storage transaction.")
    for forbidden in ("presigned", "signed_url", "source:"):
        if forbidden in publisher.lower():
            raise RuntimeError(f"Disaster-recovery publisher contains forbidden URL material: {forbidden}")
    ordered(
        publisher,
        "immutable evidence object bytes differ",
        "evidence_key = upload_exact!",
        "pointer_key = upload_exact!",
        '"pointerSelected" => true',
    )
    for required in ("acl: \"private\"", "private_object!", "containsSecrets", "containsSignedUrls"):
        if required not in publisher:
            raise RuntimeError(f"Disaster-recovery privacy contract is absent: {required}")
    for required in (
        "recovery_marker_bytes",
        "recovery upload state content digest differs",
        "recovery upload state filename differs",
        "recovery upload state object path differs",
        "recovery upload state tombstone path differs",
        "anonymousCdnRetrievalDenied",
        "normalUploadInventoryCount",
        "normalUploadInventorySha256",
    ):
        if required not in publisher:
            raise RuntimeError(f"Disaster-recovery deep binding is absent: {required}")

    print("Storage transaction durability checks passed.")


if __name__ == "__main__":
    main()
