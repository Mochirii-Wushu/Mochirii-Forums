# Backup, restore, and rollback

Use Discourse application backups with uploads included. Normal uploads and
private backups occupy non-overlapping prefixes in the same dedicated bucket.
An application backup does not replace the root-owned runtime configuration,
release source, host recovery key, or provider/DNS evidence.

## Protected evidence boundary

Raw backup, launcher, restore, and verification output is discarded or held
only in an ephemeral root-owned mode `0600` file that is unlinked before the
command returns. Durable `/var/lib/mochirii/forums/logs` and
`/var/lib/mochirii/forums/evidence` records contain only fixed allowlisted
status markers and sanitized immutable evidence. Do not place a backup, member
data, signed retrieval URL, raw command output, secret, provider identifier, or
host-private path in Git, workflow artifacts, or public logs.

The stable wrappers serialize operations through the installed host-lock
helper. It traverses only the real root-owned `/run/lock`, safely creates the
ephemeral root-owned mode-`0700` `/run/lock/mochirii-forums` directory, opens
only fixed root-owned regular mode-`0600` lock files with `O_NOFOLLOW` directory
descriptors, and enforces primary-before-media acquisition. It never
uses `/var/lock` or a caller-supplied path. The lock descriptors survive for
the wrapper lifetime, while deliberately detached bounded children close them
before exec so a killed wrapper has one exact supported retry boundary.
After an ephemeral reboot, namespace verification accepts a missing unused
lock file only after validating the private directory and every existing node;
it never creates the missing sibling. The first operation that needs that lock
creates it with the same no-follow, root-owned, single-link contract.
Workflows receive only fixed success or failure messages.

## Create and verify a backup

Dispatch `.github/workflows/backup-forums.yml` from exact current `main`, with
the exact running commit and confirmation `BACKUP MOCHIRII FORUMS`. It invokes:

```text
/usr/local/sbin/mochirii-forums-backup <exact-commit> <workflow-operation-sha256>
```

The protected workflow derives the opaque lowercase SHA-256 from its stable
GitHub run identity without transmitting or recording that raw identity. A
rerun of the same workflow operation reuses the digest and may adopt its exact
terminal backup; a different workflow run has a different digest and must
exact-validate and durably retire the prior terminal before pre-arming a new
backup transaction.

The root wrapper refuses a non-production or mismatched configuration. It
creates the application backup, verifies that the exact object is under
`backups/`, proves anonymous retrieval denial and protected administrator
retrieval, and records a positive size and lowercase SHA-256. Before member
rollout, it first creates one bounded ordinary GIF upload through Discourse's
supported `UploadCreator` and external S3 store. Root-only state binds the
exact row, SHA-1, original object and tombstone paths, content SHA-256, and
custom-host URL SHA-256. The wrapper proves those bytes exist at the expected
normal-upload object, creates and verifies the backup, then deletes the exact
disposable row, object, tombstone, and marker and proves their absence. A
retry adopts only the exact matching marker; conflicting or partially proved
state fails closed. The schema-3 backup evidence retains only the bounded
fixture identity required for the isolated restore and is durably published
before the wrapper atomically updates the root-owned mode `0600`
`/var/lib/mochirii/forums/latest-backup-evidence` pointer.

Before any fixture or backup mutation, the wrapper durably pre-arms
`/var/lib/mochirii/forums/backup-transaction.json` and, when a disposable
upload is required, one digest-bound
`*-backup-upload-cleanup-required.json` journal. Rails also stores the exact
transaction identity under `normal_upload_transaction:<transaction-id>`
before `UploadCreator`, then seals its row-derived object key through a row-
creation callback in the same database transaction and before the external
PUT. This is the recovery authority if the root wrapper loses its transient
output. Cleanup accepts an already-cascaded
row only when the durable journal and Rails transaction state bind the exact
row and object keys, removes whatever remains, proves the row, object,
tombstone, and both PluginStore markers absent, and only then unlinks and
parent-fsyncs the journal. Deploy, restore, and member finalization refuse an
unresolved backup or upload-cleanup transaction.

Neither pre-arm exposes its final filename while bytes are incomplete. The
wrapper file-fsyncs a fixed root-only `.partial`, hard-links it no-replace to
the final authority, parent-fsyncs, removes the partial, and parent-fsyncs
again. On retry, an unlinked protected partial is known to precede mutation
and may be retired; a linked partial is retired only when its inode, canonical
bytes, and exact final identity agree. Any other link or metadata is retained
and blocks the operation.

The backup transaction binds the prior latest-backup pointer before mutation.
It advances only through `prepared`, `pointer-committed`, and
`event-committed`; a retry exact-validates the immutable backup evidence and
latest pointer, reconciles the idempotent durable event, and returns success
without creating another backup. Evidence files, mutable pointers, transaction
records, and their parent directories are fsynced at their commit points.
The terminal `current-backup.json` is bound to the workflow operation digest.
The restore wrapper may retire it only after the helper proves the exact
event-committed evidence and still-selected latest pointer; retirement is
parent-directory-fsynced before restore can replace that pointer.

Every backup durably binds its original running or stopped state and the exact
release, selected production configuration, core and Docker Manager revisions,
container image, runtime environment, port bindings, and workflow-operation
digest before a command that could stop the app. Each such command is separately
pre-armed with an immutable operation token. A retry may reconcile an armed
command only after proving that token's process and container absent and the
entire bound runtime tuple unchanged. The backup journal is the sole bounded
restart and containment owner through terminal success, including after upload
cleanup and for post-rollout backups that never create a fixture journal.
For a stopped-origin backup, failure containment first fsyncs
`temporary-stop-authorized`, then stops and proves the exact app, and only then
advances to `initial-stopped`. A crash after the stop but before that second
transition therefore retains an exact retry owner instead of producing an
unowned `idle` plus stopped state.

Fixture cleanup retains its narrower ordered transition from `cleanup-pending`
through restart authorization, cleanup proof, and explicit resume. Later
timeouts, signals, or uncertain survivors remain owned by the enclosing backup
transaction: retry re-proves the exact tuple, reconciles the command identity,
and either resumes the same operation or keeps the app stopped. Terminal
success idempotently restores the exact original running or stopped state before
the transaction may retire. A prepared transaction cannot use a journal-free
retirement escape, and no other operation can reuse its restart authority.
Deploy and restore continue to refuse every active backup transaction.

Backups created after the permanent member-rollout marker do not create a
disposable upload. They must prove that no recovery-upload marker is present
and bind a bounded, sanitized aggregate of the current non-secure Upload rows
to exact object HEAD readback. Only the row count and aggregate SHA-256 enter
evidence; filenames, keys, row identifiers, object metadata, and member data
do not. A clean-target restore recomputes the same aggregate after restore,
restart, and rebuild.

Every verified backup also publishes a sanitized private disaster-recovery
record at `backups/recovery-evidence/records/<record-sha256>.json` and
atomically selects it through `backups/recovery-evidence/current.json`. The
private record binds the exact backup, core local-evidence digest, release and
runtime pins, member-rollout marker digest, recovery-upload state (or the
exact post-rollout null tuple), aggregate upload proof, and both origin and
custom-CDN anonymous denial results. It contains no secret, member datum,
signed URL, or provider response. Both objects must retain private ACLs.

Before that selector advances, the same transaction also publishes the exact
secret-free Git release archive at
`backups/recovery-releases/archives/<archive-sha256>.tar` and a canonical
source-authority record at
`backups/recovery-releases/authorities/<authority-sha256>.json`. The authority
binds the repository commit and tree, production-configuration digest, archive
size and SHA-256, normalized content-manifest SHA-256, fixed Git-archive
format, `ordinaryDeploymentRequiresCurrentMain=true`, and the sole historical
scope `clean-target-disaster-recovery-only`. Archive, authority, evidence, and
selector are all exact-private owner-only objects; immutable collisions must
be byte-identical. Publication or private readback failure prevents the local
backup transaction from reaching its terminal pointer.

The application-provided signed retrieval URL is untrusted input. Verification
requires HTTPS with peer and hostname validation, the exact dedicated
bucket/region authority on port 443, the exact `backups/default/<filename>`
object path, a bounded complete signature query, and the same bounded safe
archive basename later supplied to the restore CLI. Wrong authority, userinfo,
alternate ports, path drift, fragments, missing or duplicate signature fields,
leading-option names, and dot segments fail without printing the URL or query.

Record the repository commit, exact upstream tuple, base-image digest, rendered
production and restore configuration digests, theme digest, backup filename,
size, SHA-256, and private-access result in the protected release evidence.

## Supported pre-rollout restore rehearsal

Restore overwrites destination data. It is authorized on this host only while
the installation is still disposable and
`/var/lib/mochirii/forums/member-rollout-enabled` does not exist.
DiscourseConnect must remain disabled.

Dispatch `.github/workflows/restore-forums.yml` from exact current `main`, with
the exact running commit and confirmation:

```text
RESTORE DISPOSABLE MOCHIRII FORUMS
```

The stable root restore wrapper performs the complete guarded sequence:

1. load the root-owned latest-backup pointer and bind it to the same release;
2. atomically select the versioned disposable-restore configuration;
3. rebuild with HTTP bound to `127.0.0.1:18080`, no public HTTPS ingress,
   all outbound mail disabled, and DiscourseConnect disabled;
4. re-read the exact remote backup object through the application and compare
   its filename and SHA-256 with protected evidence immediately before restore;
5. use the supported container command `discourse restore --location s3` for
   that exact filename;
6. prove that the database marker and the exact disposable normal-upload row,
   original object bytes, content digest, custom-host identity, and absent
   tombstone were recreated by the backup; independently enqueue and observe
   completion of the bounded first-party Sidekiq probe job;
7. verify a restart and a supported rebuild while still isolated;
8. delete the exact recovery-upload row, original object, tombstone, and
   marker, prove every identity absent, capture the bounded normal-upload
   inventory, create and verify a subsequent clean backup, re-read the same
   inventory, commit the member marker, privately publish the clean backup's
   immutable disaster-recovery record and selector, and atomically point
   `latest-backup-evidence` at that clean backup while ingress and mail remain
   contained;
9. atomically restore the versioned production configuration, rebuild, and run
   the full hosted verifier while it owns and exact-validates only this restore
   journal; and
10. durably publish root-owned mode `0600` restore evidence that binds the
    tested backup, recovery-upload state digest, upload-inventory proof,
    cleanup, and final clean backup, then commit the durable passed event,
    terminal restore record, and journal removal in that order.

If restore fails after isolation begins, the wrapper keeps the restore
configuration active and rebuilds into containment. Public ingress and member
mail remain disabled. Use the distinct operator key or provider console to
inspect protected evidence; never bypass containment to make the site appear
healthy.

The restore wrapper pre-arms a root-owned mode `0600`
`restore-transaction.json` before selecting the isolated configuration. Each
configuration switch, destructive restore, verification, fixture cleanup,
member-marker adoption, clean-backup intent and publication, off-host selector,
latest-pointer replacement, production reopen, restore-evidence publication,
and terminal event has an ordered durable phase. The clean-backup intent has a
stable timestamp and sealed remote-object identity, so a retry adopts only the
exact post-intent backup instead of creating a duplicate. A retry accepts only
the exact same release, configs, tested backup, recovery identity, normal-upload
aggregate, and mode; it resumes or safely repeats the one phase whose intent
was already committed. Ambiguity remains contained.
Before every launcher invocation, that same journal atomically and durably binds
an operation token, the prior immutable image ID or explicit absence, exact
launcher command, selected configuration path and digest, and current restore
phase. Before an altered image tag is removed, its replacement image ID is
monotonically fsynced into the same journal. Startup reconciles any armed token,
labeled anonymous container, CID loss, image swap, or untagged replacement image
before the launcher may run again. The exact token is also inherited by the
host launcher process tree. Failure and retry scan actual NUL-delimited
`/proc/<pid>/environ`, boundedly terminate even detached or renamed marked
descendants, and prove both token-marked and generic launcher processes absent.
The launcher identity fields clear only after the process, container, replacement image, configuration,
and stopped-or-success terminal state are proved; a phase or configuration
cannot advance while they remain armed.
After `event-committed`, the wrapper publishes `current-restore.json`, then
unlinks and parent-fsyncs the active journal. A retry after that boundary
validates the terminal record and live state and returns success without
restoring again.

## Irreversible member-rollout marker

Only after a supported restore record for the exact release passes may the
human operator run:

```sh
sudo /usr/local/sbin/mochirii-forums-finalize-member-rollout \
  <exact-commit> 'FINALIZE MOCHIRII FORUMS MEMBER ROLLOUT'
```

The finalizer requires the production configuration, a running container with
DiscourseConnect still disabled, complete schema-3 restore evidence, and a
`latest-backup-evidence` pointer that names the bound final clean backup with
the disposable upload absent. It creates
`/var/lib/mochirii/forums/member-rollout-enabled` atomically with mode `0600`.
The marker is intentionally one-way: never remove it, edit it, or restore over
member-serving data in place. After this boundary, install the same protected
64-lowercase-hex secret with the Website flag still off, rebuild the consumer
in loopback containment, and pass the exact signed-outbound and
hostile-callback fixture. Disposable CI and later fresh Website end-to-end
evidence own valid inbound, expiry, cross-session, and replay proof.
Only then may the reviewed public Forums config run while the producer remains
fail-closed `503`; enable the Website producer last and retain public ingress
only after the real member allow/deny/expiry/replay fixture passes. Any failure
turns the producer off and returns Forums to proved loopback containment or a
proved stopped state.

After a producer-pending public rebuild has returned, any later Website
authentication failure, or a stopped first-activation failure whose producer
disablement could not be proved automatically, must use the exact operator-only
`mochirii-forums-stop-pending-activation` command documented in
[DEPLOYMENT.md](DEPLOYMENT.md). It binds the protected current commit and
configuration, validates either the pending chain or the target-to-prior
activation-failure chain, proves the app stopped, retries the producer-disabled
probe, and records only a fixed blocked event; the GitHub deploy key cannot
invoke it. Repeated probe failure leaves the exact unproved record in place.

A successful retry must recreate the exact producer-pending pointer after a
fresh loopback consumer fixture and disabled-producer probe. It then follows
the protected Website evidence and operator-only
`mochirii-forums-finalize-authentication` procedure in
[DEPLOYMENT.md](DEPLOYMENT.md). Do not reuse an older Website record: the
finalizer accepts only the current commit/configuration tuple and a timestamp
within its narrow freshness window. The Website record must attest callback
log redaction, browser query scrubbing, and private no-store callback responses
as booleans without retaining the canary values or any member data.

After the marker exists, recovery requiring a restore must use a separately
approved clean target at the exact compatible revisions. Never repurpose the
pre-rollout restore workflow for production member data.

## Clean-host disaster recovery

Loss of the original Droplet does not authorize an in-place or stale-version
restore. Provisioning, DNS, provider, secret, and public-ingress changes remain
separate approval-gated operations. On an explicitly approved empty Ubuntu
target, first install and verify the exact reviewed host-control release, then
restore the protected runtime JSON and operator keys through the private
recovery boundary. The target must have no member-rollout marker and the
clean-target verifier must prove there are no positive-id users, posts,
topics, uploads, API keys, recovery marker, or existing PostgreSQL data.

The private selector may name release `C0` after canonical public `main` has
advanced to `C1`. Never bootstrap `C1` against the real recovery PostgreSQL
path merely to read the selector: a newer migration would turn the subsequent
`C0` restore into an unsafe downgrade. Use only the exact current-main
host-control code and a disposable current-main recovery reader whose database,
Redis, uploads, configuration, and launcher state are isolated from
`/var/discourse/shared/standalone`. Fetch the selector with mode
`clean-target-historical`, then destroy that scratch reader and prove its
entire state absent before the recovered release touches the real persistent
path.

The installed `C1` host-control evidence must bind two retained root-owned,
mode `0600` Git archives before recovery starts:

- `/opt/mochirii/forums/host-control-releases/<C1>/mochirii-release.tar`, from
  the exact clean canonical-main checkout used to install or upgrade control;
- `/opt/mochirii/forums/deployment-source/ed9f680b0df1de28f062de1769d89d22b2644d1b.tar`,
  from the exact clean official `/var/discourse` checkout and tree recorded by
  the deployment-source pin.

The immutable host-control record and `current-host-control.json` bind each
archive path, byte count, SHA-256, reconstructed Git tree, and normalized
content-manifest digest. `verify-host-security.sh` re-inspects both. Do not use
a surviving unsealed checkout as recovery authority.

Choose a new random 32-lowercase-hex operation identifier. With canonical
public `main` still exactly `C1`, the distinct human operator runs the complete
preparation entrypoint:

```sh
sudo /usr/local/sbin/mochirii-forums-historical-disaster-recovery \
  prepare <exact-C1-commit> <32-hex-operation-id> \
  'PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE'
```

There is no manual fetch or materialization step. Before executing any `C1`
archive-owned code, the controller durably arms `historical-reader.json` and
independently re-reads canonical public `main`. It then invokes the installed
scratch-reader helper. That helper reconstructs the sealed `C1` and official
deployment archives under its operation-bound scratch root, renders a
scratch-only Discourse configuration, runs both historical fetchers with
`MOCHIRII_DR_FETCH_MODE=clean-target-historical` and the exact `C1` bootstrap
commit, and passes the bounded base64 receipt into the release fetch. It stops
and destroys its exact process, container, configuration, source, launcher, and
scratch state before publishing the mode `0600` receipt and archive. Before the
image can be built or tagged, the transaction binds all pre-existing image IDs,
the exact operation label, and then the immutable operation-created image ID.
Cleanup and retry reconcile that ID and label even after an untag. If deletion
already completed before a crash, retry inventories the immutable ID, accepts
only its proved absence, and does not repeat the failing removal; malformed or
ambiguous identity remains fatal. Both ID and label must be proved absent. The
controller validates the retained `outputs-published` transaction,
records its SHA-256 plus the same immutable image identity and absence proof in
`scratch-reader-absence.json`, re-proves the real persistent target absent, and
only then durably retires the scratch transaction. Altered or missing image-ID
evidence blocks adoption.

The controller validates the fetched Git archive, recomputes its `C0` tree and
manifest, seals and extracts only bounded reviewed source, renders both `C0`
configurations, and grants `configuration-authorized` only when their digests
equal the private receipt. It then retires the reader intent. An exact retry of
the same `prepare` command adopts only the same terminal evidence. A crash
after configuration authorization is also retryable: the controller accepts
and retires the stale reader intent only when the adoption, intent, scratch
absence, transaction absence, runtime absence, `C1`, and operation identifier
all still match.

After the Website producer is proved disabled, continue only through:

```sh
sudo /usr/local/sbin/mochirii-forums-historical-disaster-recovery \
  resume 'RECOVER HISTORICAL MOCHIRII FORUMS DISASTER RELEASE'
```

The controller prearms the monotonic adoption journal before the internal
historical bootstrap can mutate the real `C0` persistent path. That internal
seven-argument deploy contract is accepted only from this operator recovery
flow, with the exact journal path and digest. It is absent from forced SSH
verbs and deploy-principal sudo authority, and ordinary deployment refuses an
active historical adoption. A `bootstrap-complete` retry may only reconcile
the same committed deployment transaction; it cannot rerun launcher or runtime
mutation.

The restore consumes only `bootstrap-complete`, moves monotonically through
`restore-started` and `restore-complete`, and contains the app on every failure.
Terminal retirement requires the exact current release, restore terminal,
final clean backup, and `latest-backup-evidence` pointer. A crash after the
durable `restore-complete` transition is terminal reconciliation only: active
backup, deployment, deployment-mutation, or restore transactions make it fail
closed, and it never reruns destructive restore work. The adoption journal is
retained on every nonterminal failure and removed only after immutable
completion evidence is published and re-read. Retry the same `resume` command;
do not delete or edit journals by hand.

The deploy key cannot invoke either historical controller confirmation. The
restore command reads only the privately validated selector receipt,
reconstructs the exact schema-3
local evidence, and checks its pre-publication core digest. It never creates or
prints a signed URL. The command then uses the same full-mail, loopback-only
restore journal described above. A pre-rollout backup proves its disposable
upload directly. A post-rollout backup instead requires the source
member-marker digest and exact normal-upload aggregate to match after restore,
restart, and rebuild. A sanitized fixture-free backup is accepted only by this
clean-target mode; ordinary in-place rehearsal still requires the exact
disposable recovery upload.

Before any public reopen, the command re-proves the Website producer disabled,
atomically recreates the irreversible member-rollout marker when the source
backup carried one, and reseals `current-release.json`. That recovered marker
binds the private disaster evidence and original marker digest; it never
authorizes destructive in-place restore. The command then verifies the exact
host/source/runtime tree, creates a clean final backup, privately publishes and
locally selects its exact recovery evidence before public reopen, commits the
terminal restore record, and re-proves the producer disabled. Re-enable the Website producer
and authenticate members only through the normal protected activation and
finalization procedure. Keep ingress closed and the restore journal intact on
any uncertainty.

## Configuration recovery

Recovery requires all of these in addition to the application backup:

- exact reviewed repository commit, tree, and release archive digest;
- exact Discourse Docker, core, Docker Manager, and base-image revisions;
- the protected literal runtime JSON and its rendered configuration digests;
- the exact theme and release-versioned runtime assets;
- bucket, private backup prefix, CDN, DNS, and certificate readback;
- the distinct operator recovery key and provider-console access; and
- the recovery-stored administrator identity outside Git.

Production must not depend on this workstation or a private recovery folder.

## Operator-only administrator recovery

Ordinary native login, email login, login codes, passkeys, and every alternate
provider remain disabled. The public `GET` and `PUT` `/u/admin-login` and
`/users/admin-login` aliases, including trailing-slash, query, and format
forms, are denied by the reviewed nginx outlet with a private, no-store,
Mochirii-only `404`. Administrator recovery is instead initiated on the host
by the distinct human operator; the GitHub deploy credential has no sudo or
forced-command route to this wrapper.

The pinned core explicitly permits an existing administrator to consume an
`email_login` token even while DiscourseConnect owns ordinary login and local
login is disabled. The repository exercises that exact one-time path in the
disposable built-in-consumer fixture, including token consumption and replay
denial. Use only an already-authorized SMTP authority and the recovery-stored
administrator email that is also present in the protected developer-email
runtime list. Do not add a mail provider or DNS record.

From the distinct operator SSH session or provider console:

1. Run the read-only identity/settings preflight. Enter the recovery email only
   at the hidden prompt; it never enters arguments, environment, output, or an
   evidence record.

   ```sh
   sudo /usr/local/sbin/mochirii-forums-break-glass-admin \
     <exact-running-commit> verify \
     'VERIFY MOCHIRII FORUMS ADMIN RECOVERY'
   ```

2. If the recovery identity does not yet exist as the exact active, approved,
   confirmed administrator, first repeat the preflight to prove the sealed
   checkout and closed-login runtime, then use the pinned official host-console
   procedure. Disable terminal recording, set `HISTFILE=/dev/null`, run
   `cd /var/discourse && ./launcher enter app`, and inside the container run
   `HISTFILE=/dev/null bundle exec rake admin:create`. Supply only the
   recovery-stored identity and password at the task's private interactive
   prompts, exit the container, and rerun step 1. No local-login setting is
   enabled by this procedure.

3. Initiate exactly one recovery email from the host. This creates an
   `email_login` token and enqueues the pinned critical mail job without
   printing the identity or token.

   ```sh
   sudo /usr/local/sbin/mochirii-forums-break-glass-admin \
     <exact-running-commit> send \
     'VERIFY MOCHIRII FORUMS ADMIN RECOVERY'
   ```

4. Open only the one-time link delivered to the protected recovery mailbox.
   The link targets `/session/email-login/<token>`; the public initiation form
   remains blocked. After access is recovered, rerun step 1. It must prove the
   exact current release, read-only runtime assets, protected evidence,
   DiscourseConnect state, disabled local/alternate login settings, and full
   hosted verifier before the incident is considered closed.

If any wrapper or delivery check fails, do not enable a public login form or
change an authentication setting. Keep the current service unchanged, use the
provider console to inspect only protected fixed evidence, and resolve the
already-authorized SMTP or recovery-identity condition. The wrapper emits only
fixed success/failure text and never returns a recovery token.

## Rollback rule

Discourse does not support downgrade across migrations. Before a rebuild,
create and validate a backup at the current version. On failure:

1. close public/member traffic if authorization or data integrity is uncertain;
2. if no migration or data mutation occurred, use the stable deployer to
   restore and verify the exact prior same-version release/configuration;
3. otherwise use an approved forward fix or restore the verified same-version
   backup into a clean exact-revision installation; and
4. rerun the entire validation ledger before reopening.

Never infer that reverting Git reverses a database migration. Never destroy
pre-existing or imported data when cleaning up a failed empty/disposable
Forums deployment.

Every target configuration or launcher mutation is pre-armed in
`/var/lib/mochirii/forums/deployment-mutation.json`. Do not delete or edit that
journal, `app_bootstrap.cid`, the selected configuration, an app container, or
`local_discourse/app` by hand. Rerun only the exact same canonical commit,
configuration, archive digest, and mode through the protected deployment
workflow. The retry validates the prior/current chain, reconciles the durable
launcher label and image snapshot, proves a stopped state, and replays the
target forward. If the journal records `databaseMutationPossible=true`, old
code must not be launched even when the prior configuration is still selected.
Other backup, restore, authentication, member-rollout, certificate, and
host-control operations refuse this journal. The only separate operator
exception is the pending-activation stop command for an exact
`activation-deploy-failed-producer-unproved` record bound to the same
`runtime-contained` journal, stopped app, selected prior configuration, prior
current-release digest, and prior release symlink; it proves the producer off
and leaves deployment ownership intact. Retry validates the journal's sealed
prior current-release bytes and `/opt/mochirii/forums/current` target before
any stop, cleanup, configuration, or launcher action. An orphan hosted-storage
cleanup journal is never mutation authority. It is cleared only after the
runtime reaches `verified` and the separate deployment terminal
transaction is fully adopted. A same-version/no-target-migration rollback uses
the narrowly scoped prior-rollout verifier; cross-version or
`databaseMutationPossible=true` recovery remains stopped for forward-fix or a
clean restore.

## Primary references

- [Official Discourse backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
- [Official automatic backup guidance](https://meta.discourse.org/t/configure-automatic-backups-for-discourse/14855)
- [Official administrator creation from the host console](https://meta.discourse.org/t/create-an-admin-account-from-the-console/17274)
