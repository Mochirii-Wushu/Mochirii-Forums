# Validation Gates

Validation is split deliberately between source evidence, a disposable
standalone build, and protected hosted readback. A result in one lane does not
prove another lane.

## Source gate

Run from a clean checkout of the exact candidate commit:

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1 -Online
git diff --check
```

The source gate checks the repository allowlist, JSON contracts, sanitized
runtime template, exact upstream bytes, one-core command, immutable action
pins, theme archive determinism, hostile renderer inputs, upload policy,
branding source, and credential-like material. It must not render production
configuration or contact a runtime/provider account.

The offline Python contract has no host Ruby dependency. The eight standalone
Ruby hostile fixtures and seven Python fault/recovery fixtures run only in the
exact pinned
`discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48`
container after that digest is pulled explicitly. Their container uses
`--pull=never`, no network, a read-only root filesystem, a read-only repository
mount, a private 16-MiB no-exec `/tmp` tmpfs, no capabilities,
`no-new-privileges`, and fixed process/memory bounds.
Changing that image or isolation tuple is a reviewed source-contract change.

The pinned Linux lock fixture creates an empty boot-like `/run/lock`, safely
recreates only the private Forums directory, and rejects a malicious parent or
lock-file symlink, nonregular or multiply linked node, unsafe owner or mode,
reverse primary/media ordering, and every `/var/lock` alias. Contention and
SIGKILL cases prove exact inherited-descriptor exclusion, explicit
close-before-exec behavior, and successful same-root retry without truncating
an attacker-selected victim. Static recurrence checks require every primary or
media controller to use the one installed helper and reject any direct
predictable open in the shared mode-`1777` `/run/lock` directory.
The clean-boot case also acquires only the primary lock, verifies the complete
namespace with the unused media file absent, and proves that verification did
not create that sibling. Literal, quoted, and variable-computed descriptor
opens are hostile static fixtures.

The historical-recovery fixtures use genuine deterministic `git archive`
inputs rather than hand-built lookalikes. One drives the installed controller,
the actual isolated scratch-reader, and the actual adoption helper through a
C0-backup/C1-main/lost-host state machine with bounded boundary adapters. It
proves that C1 never creates or mounts the real persistent path, C0 source and
configuration remain bound to private recovery provenance, bootstrap and
restore are prearmed, crashes before and after their durable transitions are
exactly resumable, and the adoption journal retires only after terminal restore
and clean-backup evidence. The other injects timeout, tamper, forbidden mount,
actual NUL-delimited marked-process, and publication crash windows into the C1
reader. These are executable source-boundary tests; they do not claim that a
real provider backup was fetched or that production Discourse was restored.
The Python matrix also executes backup-wide post-cleanup and post-rollout
timeout/SIGKILL recovery plus the stopped-origin crash after stop proof but
before phase advance, historical scratch crashes after image untag and after
immutable-ID deletion but before absence proof, disposable launcher
post-CID-unlink/final-rm-failure with a misleading exit zero plus mismatched
tagged and running rebuild images, and restore launcher kill-after-arm,
post-CID-unlink, image-swap/untag, pre-phase-advance, and detached changed-argv
marked-process windows. These fixtures
require exact operation tokens, immutable container and image IDs, labels,
selected configuration digests, and durable retry/retirement proof.

## Disposable standalone gate

Dispatch `.github/workflows/disposable-bootstrap.yml` at the exact candidate
commit. The workflow has read-only repository permission, uses fixture-only
values, binds HTTP to loopback, and creates no provider resource. It must prove:

- the exact platform image digest is accepted by the official launcher;
- every launcher call is pre-armed by the disposable guard with its exact
  operation label and pre-existing container/image IDs, then proves every
  operation-created container and image absent or the one terminal app image
  adopted; start, restart, and rebuild additionally require the named running
  app's immutable image ID to equal the exact tagged app image. Launcher exit
  zero alone is not completion evidence;
- the selected deployment source builds with one effective CPU;
- the exact application and Docker Manager revisions are installed;
- the exact current-main repository archive is retained, tree/digest/size/
  normalized-manifest verified, and mounted with the historical private-release
  fetcher;
- the private archive-authority publication/fetch chain rejects altered bytes,
  and the historical C0/C1/lost-host and isolated-reader hostile fixtures pass;
- the theme archive imports, its uploads become logo/icon settings, and the
  composer upload-notice connector is compiled;
- site settings, translation overrides, static error pages, generator and
  OpenSearch replacements, PWA metadata, and non-delivered mail presentation
  use Mochirii branding; the OpenSearch filter is bound to the pinned
  controller's `application/xml` response and its runtime media type is checked;
  automatic external Gravatar downloads are disabled
  before the narrative system user is saved, and fixed identity, profile,
  active-avatar, and no-Gravatar subchecks remain true after Sidekiq processing;
- the system-owned staff Admin Quick Start topic is revised only from the exact
  pinned upstream seed after the pinned `TextCleaner` and `PostCreator`
  whitespace/`rstrip` storage transformation to the exact reviewed Mochirii
  guide; source-file and stored-post digests are independently bound, the exact
  successor is idempotent, and any unexpected staff edit fails closed without
  overwrite;
- the administrator recovery mail contains only the exact fixture-token path
  at the mode-bound Forums origin: HTTP is accepted solely for the explicit
  loopback fixture, while non-fixture verification requires HTTPS; and the
  separate administrator-confirmation presentation uses a
  route-valid deterministic administrator-confirmation fixture token
  rather than a real Redis-backed privilege token; the digest uses the pinned `site_digest_logo_url` accessor
  and a rollback-only age adjustment of the exact controlled seed topics
  (welcome, guidelines, and Admin Quick Start), requires all three in the
  rendered message, and restores every original timestamp so Discourse's real
  digest query produces a real `Mail::Message` without retaining fixture state;
- one local application backup is created in the fixture, a protected marker is
  changed, the exact local backup is destructively restored with
  `--location local`, and the restored marker is verified; and
- PostgreSQL, Redis, a registered Sidekiq process plus one exact bounded
  first-party probe job, and persistent `/shared` data survive one supported
  restart and `launcher rebuild app` after that local restore. The job uses one
  private namespaced Redis lease, an exact no-argument JID binding, and a
  60-second post-enqueue observation window. Atomic same-JID transitions retain
  the lease expiry, concurrent and stale generations cannot interfere, and
  terminal cleanup removes only the caller-owned state or accepts its expiry.

A successful disposable job is required for the Stage 4 candidate. Its result
proves local fixture backup, destructive local restore, restart, and rebuild
only for the exact candidate commit. It does not prove DNS, TLS, SMTP delivery,
production object storage, the private `backups/` prefix, S3 ACL/list/retrieval
behavior, `discourse restore --location s3`, cost, or production health. The
production S3 backup and isolated S3 restore remain mandatory hosted gates.

## Pre-creation and hosted gates

Stage 5 must stop before any paid resource is created unless protected,
time-bounded evidence passes `scripts/verify-cost-evidence.py` and an already
authorized SMTP authority with the verified Mochirii sender is ready. Repository
placeholders are not SMTP evidence.

The protected deployment, backup, and hosted-verification workflows are
operator entrypoints only. Their presence grants no deployment authority. For
an authorized exact release they must record, without secrets:

- no active deployment-mutation, deployment-promotion, backup, or restore
  transaction for standalone verification; the deploy owner may name only its
  exact mutation journal or its exact mutation-plus-promotion pair, and the
  prior-rollback owner may name only a mutation-only exact sealed prior tuple;
  the restore owner may name only its restore journal. Mutation plus promotion
  requires mutation phase `verified`; verified mutation alone is limited to
  exact completed-terminal adoption and full published-state validation. Their schema, phase,
  commit/configuration tuple, protected configuration/evidence, launcher
  identity, irreversible-mutation flag, marker, upload inventory, and
  authentication action are revalidated. Deployment verification also binds
  the exact `/opt/mochirii/forums/current` symlink target;
- an exact completed-deployment record when present, bound to current-release,
  immutable release/archive evidence, the physical member marker, and the
  protected authentication record. Only the later absent-to-member-marker and
  producer-pending-to-complete transitions are accepted without rewriting that
  terminal record;

- the exact locked account/home/shell/primary-and-supplementary-group tuples,
  root-owned key trees and key bytes, sole effective SSH authorization sources,
  deploy daemon `ForceCommand`, operator interactive boundary, and valid sshd
  configuration for root, operator, and deploy;
- active exact-default-deny IPv4/IPv6 UFW rules for only 22, 80, and 443;
  enabled and active SSH, Docker, fail2ban, unattended-upgrades, and apt timers;
  the active fail2ban SSH jail; exact Docker daemon log policy; exact 2 GiB
  persistent swap; and no unexpected public listener;
- the exact installed stable wrapper, libexec, host-policy, and complete-or-
  absent certificate-automation bytes/modes from the host-control manifest,
  their immutable target-set digest and predecessor chain, and an enabled,
  active certificate timer whenever that automation is installed;
- the exact current-main Forums archive and pinned deployment-source archive
  retained by host control, including bounded size, digest, repository-tree,
  normalized-manifest, protected path, and immutable-evidence equality;
- the full sealed detached `discourse_docker` checkout, including clean tracked
  and untracked state, exact critical source bytes, canonical pull-only remote,
  running Discourse core and Docker Manager tracked-byte cleanliness, and the
  running container/local image identity;

- repository, deployment, application, Docker Manager, base-image,
  configuration, and theme identities;
- valid HTTPS plus PostgreSQL, Redis, a registered Sidekiq process plus an exact
  completed bounded probe job, private service ports, restart, and rebuild
  results;
- closed native registration, the sole built-in DiscourseConnect path,
  session-bound nonce protection, and hostile member-access results;
- zero secure uploads before storage use, image-only upload/write/variant/read/
  delete behavior, public object ACLs, custom media URLs, anonymous listing
  denial, persistence after the exact restart and rebuild, tombstone cleanup,
  digest-bound retry state on any incomplete cleanup, and private backup
  retrieval;
- a supported application backup and integrity check followed by an isolated
  `--location s3` restore while the installation is still disposable. The
  hosted backup creates one exact ordinary normal-upload fixture through the
  supported Discourse/S3 path, deletes its live row and object after backup,
  and the restore must recreate the exact row, original bytes, content digest,
  custom-host identity, and database marker. The wrapper then exactly removes
  that fixture, proves its row/object/tombstone/marker absent, and creates a
  verified final clean backup before member-rollout finalization;
- every off-host recovery pointer publishes the exact secret-free immutable
  release archive and private source authority before its terminal pointer. On
  a lost clean host, only the operator-only historical controller may run C1 in
  a separate scratch root to fetch that C0 authority; it must destroy and prove
  all C1 scratch state absent before journal-scoped C0 bootstrap touches the
  real target. Ordinary deploy remains exact current-main-only, the deploy SSH
  principal has no historical verb, and restore may retire the adoption journal
  only after exact terminal restore, final-clean-backup, and pointer evidence;
- every potentially app-stopping backup command remains under its exact durable
  transaction owner through terminal restoration of the original running or
  stopped state, including post-upload-cleanup, post-rollout, and
  stopped-origin post-stop/pre-phase-advance failure windows;
  and each restore launcher invocation is journal-armed with its token, prior
  image ID, command, selected configuration, and phase before execution, then
  durably binds any replacement ID before untag or deletion. That token is
  inherited by the host process tree and actual NUL-delimited environment scans
  must terminate and prove detached or changed-argv descendants absent; and
- public HTML, errors, metadata, PWA, footer, icons, mail, upload notice, cost,
  and resource-scope results.

If the included object-storage CDN exposes the provider origin or fails any
upload, variant, deletion, restart, or rebuild check, the deployment stops. No
alternate provider or weaker public-media contract is permitted.

## Evidence rule

Complete the redacted release-evidence contract for the exact reviewed commit.
Record pass, fail, and not-run distinctly. Do not describe CI, deployment,
backup, restore, provider state, or production health as successful without a
current immutable reference to the corresponding result.
