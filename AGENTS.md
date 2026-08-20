# Mochirii Forums Repository Guidance

This repository is the canonical deployment-control source for Mochirii
Forums. It owns only the reviewed configuration, theme, validation, release,
backup, restore, and rollback material needed to operate the official
Discourse Docker standalone installation. Discourse core and
`discourse/discourse_docker` remain external upstream projects and are never
vendored or forked here.

## Required workflow

- Start with `git status --short --branch` and preserve every existing worktree.
- Never edit `main` directly. Use one focused branch and protected pull request.
- Read the current authority packet and the nearest `AGENTS.md` before changes.
- Run `pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1 -Online`
  before handoff.
- Record the exact base, reviewed head, Discourse revision, deployment-source
  revision, Docker Manager revision, rendered configuration digest, and theme
  digest in release evidence.
- Keep commits, pull requests, public copy, and deployment authority
  Mochirii-owned. Preserve required upstream license and copyright notices.

## Runtime architecture

- Use only the official `discourse_docker` standalone layout with persistent
  host data under `/var/discourse/shared/standalone` mounted at `/shared`.
- Keep the selected exact revisions in
  `docs/operations/upstream-provenance.v1.json` and
  `docs/operations/third-party-components.v1.json`. Never deploy a moving tag
  or branch.
- Keep `discourse/discourse_docker` as the sole pull-only upstream remote. Its
  push URL is `disabled://upstream-push`; `origin` is the push default.
- Do not vendor upstream core, add a core fork, patch core, or install optional
  plugins. Docker Manager is allowed only because the official standalone
  template includes it, and its exact resolved revision is pinned. The
  repository-owned `mochirii_email_metadata` component is mandatory, is bound
  to the exact Forums commit, and only removes the pinned recipient-visible
  application headers that violate the Mochirii branding contract.
- Use the supported Mochirii theme and site settings for public presentation.
  Configuration overlays may replace exact pinned public metadata and static
  error pages only when validation fails closed on upstream revision drift.

## Fixed product and storage contract

- Hostname: `forums.mochirii.com`.
- Media hostname: `media-forums.mochirii.com`.
- One dedicated SGP1 Spaces bucket named `mochirii-forums`, or the approved
  nearest unambiguous available name materialized only at runtime.
- Normal image uploads are public by direct URL; backups under `backups/` are
  private. Anonymous bucket listing and anonymous backup retrieval are denied.
- `login_required=true`, `secure_uploads=false`, native registration closed,
  local login disabled, and built-in DiscourseConnect is the sole planned
  member login path.
- Browser-direct object-store uploads and automatic CORS installation are
  disabled. ACLs are enabled. Static application assets remain on the Droplet;
  never add an `s3:upload_assets` hook or application CDN setting.
- Permit only `jpg`, `jpeg`, `png`, `gif`, and `webp`, including staff and
  private/group-message paths. No documents, archives, source, executables,
  audio, or video.
- Do not create or depend on an AWS account, ARN, endpoint, bucket, key,
  CloudFront distribution, or any additional storage provider.
- Secure uploads are intentionally unsupported by this architecture. If a
  secure upload exists before any import or migration, stop; never convert or
  expose it.

## Identity and mail

- Use only Discourse's built-in DiscourseConnect consumer. Website owns the
  producer. No custom authentication plugin or additional login provider is
  allowed.
- Keep the shared secret server-only and enable the consumer only after the
  Website producer and hostile fixtures pass end to end.
- Mail settings and the Mochirii-owned sender address are provider-neutral
  runtime inputs. Stage 4 does not select a mail subdomain or provider.
- Do not name, create, or activate an SMTP provider from repository source.
  Production rendering fails closed unless an already authorized SMTP path is
  supplied through the protected runtime boundary.

## Security and provider boundary

- Never commit credentials, tokens, private keys, runtime `.env` files,
  `app.yml`, databases, uploads, backups, archives, generated runtime state,
  host identifiers, or member data.
- `config/app.yml.example` is sanitized and non-secret. Only
  `scripts/render-app-config.py` may materialize root-owned runtime
  `/var/discourse/containers/app.yml` from protected runtime values.
- Provider mutations, DNS, TLS, certificates, secret creation, public
  activation, deployment, rollback, and paid resources require the exact
  stage-specific authorization. Source validation never grants that authority.
- Stage 4 creates no Droplet, bucket, key, CDN endpoint, certificate, DNS record,
  SMTP account, or cost.
- Keep production independent of this workstation and private recovery files.

## Validation and release

- Run the static repository, configuration, theme, storage-policy, secret, and
  exact upstream-byte checks locally.
- The isolated bootstrap workflow must use the secret-free loopback fixture,
  the exact one-core-compatible deployment pin, and no provider access.
- Before production, prove one-core bootstrap/rebuild, PostgreSQL, Redis,
  Sidekiq, login policy, upload policy, media hostname, private backup prefix,
  backup integrity, restore, branding, TLS, restart, and workstation
  independence.
- If the included object-storage CDN does not pass real upload, variant,
  delete, custom-hostname, and rebuild tests, stop. Do not substitute another
  provider or weaken the hostname requirement.
- Downgrade across migrations is not a rollback. Use a same-version verified
  backup restore or an approved forward fix.
