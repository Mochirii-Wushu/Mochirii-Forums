# Forums storage contract

Mochirii Forums uses one dedicated SGP1 Standard Spaces bucket. Ordinary
uploads use Discourse's `original/`, `optimized/`, and `tombstone/` key
families. Private application backups use the non-overlapping `backups/`
prefix in that same bucket. No second backup bucket or storage subscription is
allowed.

The source template names `mochirii-forums`. If that name is unavailable, stop
and review the nearest unambiguous name as an exact source/configuration change
before deployment; never override the immutable template ad hoc.

## Required runtime settings

The sanitized template fixes these values:

| Setting | Required value |
| --- | --- |
| `enable_s3_uploads` | `true` |
| `s3_region` | `whatever`, environment override only |
| `s3_endpoint` | `https://sgp1.digitaloceanspaces.com` |
| `s3_upload_bucket` | `mochirii-forums` |
| `s3_backup_bucket` | `mochirii-forums/backups` |
| `s3_cdn_url` | `https://media-forums.mochirii.com` |
| `s3_use_cdn_url_for_all_uploads` | `true` |
| `s3_use_acls` | `true` |
| `s3_install_cors_rule` | `false` |
| `enable_direct_s3_uploads` | `false` |
| `s3_configure_tombstone_policy` | `false` |
| `secure_uploads` | `false` |
| `backup_location` | `s3` |
| `include_s3_uploads_in_backups` | `true` |

The region value remains an `app.yml` environment override. Do not persist
`whatever` through the admin/database setter because the selected core's region
setting does not accept it.

Static Discourse assets stay on the Droplet. Do not add `s3:upload_assets`, an
application CDN setting, direct browser uploads, automatic CORS installation,
or another CDN/storage provider.

## Access and privacy

- Create one provider-limited read/write/delete key restricted to the Forums
  bucket. Never use a full-account key, Social key, AWS identity, ARN, role, or
  bucket-wide policy.
- Keep bucket listing restricted and static website hosting disabled.
- Do not apply a bucket-wide public-read policy.
- Ordinary uploads receive public object ACLs because
  `secure_uploads=false`; anyone with a direct URL may retrieve them.
- Backups keep private ACLs and are retrievable only through the application or
  a protected operator path.
- Keep direct browser upload, automatic CORS installation, and automatic
  tombstone lifecycle mutation disabled.
- A deleted upload may be copied under `tombstone/` before its active object is
  removed. Delete every disposable test object and its tombstone without
  widening the runtime key.

Secure/private uploads are unsupported by this public-media architecture. The
stable hosted verifier runs the exact release-versioned zero-secure-upload
check through `MOCHIRII_RELEASE_ASSET_ROOT`. Any `secure=true` object before
an import or upload migration is a hard stop; never convert or expose it.

## File boundary

Only `jpg`, `jpeg`, `png`, `gif`, and `webp` are accepted. Staff has no extra
extension list, and staff-private-message and group-message bypasses are
disabled. Documents, archives, source, executables, audio, and video must fail.

The composer notice must remain visible:

> Direct upload URLs may be accessed without a forum session. Do not upload confidential material.

## Included-CDN stop gate

The only approved delivery path is the bucket's included CDN using
`media-forums.mochirii.com`. Before member rollout, use a disposable image and
prove all of the following:

1. application write, optimized variants, and delete succeed;
2. rendered ordinary-image URLs use only `media-forums.mochirii.com`;
3. anonymous direct retrieval succeeds while anonymous bucket listing fails;
4. raw provider hostnames are absent from member-facing URLs;
5. restart and supported rebuild preserve objects and URLs;
6. private backup creation, list/retrieve, integrity, and supported restore
   pass; and
7. deletion cleans the active and disposable tombstone objects.

The stable deploy wrapper executes these checks through the immutable
`verify-storage-fixture.rb` release asset. Before the first Rails mutation it
durably creates and directory-syncs a root-owned mode `0600`, digest-named
`*-storage-cleanup-required.json` journal containing a random transaction ID
and its exact transaction-specific `PluginStore` key. The Rails fixture writes
that key before `UploadCreator` runs, binds the upload through a transaction-
specific `origin`, and uses row-creation callbacks to persist the exact upload
and optimized-image IDs and object keys in the same database transactions,
before either external object PUT. Runner stdout is therefore not cleanup
authority. Successful stdout is bounded, file-synced, and atomically promoted
to transient host state only for restart/rebuild verification.

The cleanup journal is first written and file-synced as a fixed root-only
`.partial`, then hard-linked no-replace to its digest-named final path. The
wrapper parent-fsyncs before removing the partial and parent-fsyncing again.
Startup may remove an unlinked protected partial because mutation cannot have
begun; a linked partial is removed only after its inode, canonical bytes,
digest, and final name all agree. Ambiguous or hidden links fail closed.

Cleanup reconstructs identity from the pre-armed journal plus the database
record, accepts rows or objects already removed by a cascade or interrupted
attempt, deletes only the transaction-owned row, optimized row, objects, and
tombstones, and proves all of them absent. It removes the transaction
`PluginStore` key only after that proof; the host removes and directory-syncs
the journal only after the runner returns the terminal proof. A lost or
partial runner response therefore leaves the original journal reusable. If
cleanup cannot finish, the wrapper emits only a fixed blocked event, fails
deployment, and refuses a later fixture until the exact state is reconciled.
The stable verifier, backup wrapper, and member-rollout finalizer also refuse
unresolved storage journals. Until reconciliation, failure handling keeps the
loopback-only, mail-contained, DiscourseConnect-disabled restore configuration
active; it never reopens the prior public release. If containment cannot be
proved, the application is stopped.

Anonymous provider/CDN responses are streamed through a hard byte limit;
declared or cumulative chunked oversize fails before the body can grow beyond
that limit while the pre-armed cleanup identity remains active. Successful
release evidence contains booleans and immutable hashes only, never object
keys, URLs, credentials, or provider responses. Verified backup evidence is
also projected into one sanitized, private, digest-addressed recovery record
under `backups/recovery-evidence/records/`; a single private
`backups/recovery-evidence/current.json` object selects it only after exact
readback. Those objects contain no credential or signed URL. Their exact keys
and SHA-256 digests are bound back into the root-only host backup evidence.
Before backup work begins, the wrapper also fsyncs a root-owned mode `0600`
`/var/lib/mochirii/forums/backup-transaction.json`. It binds the intended
timestamped evidence file, the previously selected local backup pointer, and
an opaque lowercase SHA-256 supplied by the protected workflow for that stable
caller operation. The same operation digest may adopt only its exact terminal
receipt. A distinct operation must exact-validate the prior event-committed
evidence and still-selected pointer, then unlink `current-backup.json` and
fsync its parent directory before it may pre-arm another transaction.
This transaction uses the same file-fsynced partial, no-replace hard-link, and
double parent-fsync publication rule, so SIGKILL cannot strand a malformed
final transaction filename.
After evidence publication, the local pointer may change only from that exact
prior value to the new evidence. An atomically replaced and fsynced
`current-backup.json` then advances through `pointer-committed` and
`event-committed`. The transaction is removed and its parent directory fsynced
only after the idempotent protected passed event. A retry with already-sealed
evidence adopts these terminal files and completes the event without creating
another backup or disposable upload; changed evidence or an intervening
pointer remains blocked for review.

Every hosted backup is also bracketed by the same bounded normal-upload
inventory before backup creation and during backup verification. The inventory
walks at most 10,000 nonsecure `Upload` rows in primary-key order, derives each
exact row identity from its ID, SHA-1, filesize, and application object path,
and performs an S3 HEAD readback for exact object size and ETag. Only the total
count and one domain-separated aggregate SHA-256 leave the container; member
filenames, paths, ETags, URLs, and other row data are never emitted. Backup and
sanitized disaster-recovery evidence retain those two values. Restore,
restart, and supported rebuild verification recompute and exactly compare the
same inventory, including post-member backups for which the disposable
recovery upload is intentionally absent.

The public-branding boundary applies to rendered URLs, response bodies, forum
UI, Open Graph/PWA metadata, and email. The approved DNS-only direct Spaces CDN
unavoidably emits non-rendered transport metadata, so the verifier admits only
the currently reviewed bounded grammar: exact header-name/count/byte limits;
safe values for the direct-CDN UUID/request ID, cache result, ray, object type,
dates, lengths, ranges, caching, and TLS fields; and `Server: cloudflare`.
An optional Cloudflare `__cf_bm` transport cookie is accepted only with a
URL-safe opaque value of at most 4096 total header bytes, the exact request-host
domain, `/` path, valid IMF date, `SameSite=None`, `Secure`, and `HttpOnly`.
Its opaque value is never logged, persisted, or compared. Every other cookie,
header name, control byte, redirect/location, signed URL or signature field,
provider hostname in a rendered URL/body, and upstream identity in a body
fails closed. This is a packet-consistency inference for unavoidable protocol
metadata; it does not authorize a proxy layer or an architecture/provider
change.

If any item fails, stop. Do not add another CDN/provider, enable secure
uploads, broaden credentials, expose backups, or patch core.

## Primary references

- [Official Discourse S3-compatible storage guidance](https://meta.discourse.org/t/configure-an-s3-compatible-object-storage-provider-for-uploads/148916)
- [Official Spaces CDN guidance](https://docs.digitalocean.com/products/spaces/how-to/customize-cdn-endpoint/)
- [Official Spaces pricing and included CDN](https://docs.digitalocean.com/products/spaces/details/pricing/)
