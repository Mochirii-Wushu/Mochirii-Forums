# ADR 0004: Authorized standalone deployment source

- Status: Accepted for Stage 4 source preparation
- Date: 2026-08-14

## Context

The replacement Social and Forums authority packet authorizes the governance
seed to become the canonical source and deployment-control repository for
Mochirii Forums. Stage 4 permits non-secret source preparation only. Provider,
DNS, TLS, credential, SMTP, public-deployment, and paid-resource changes remain
prohibited until the final cost-incurring stage.

The previously reviewed `discourse_docker` commit
`a3028747c5b7774f49a3b110221d96ca2b3f340d` runs
`bundle install --jobs $(($(nproc) - 1))`. On the authorized one-vCPU host that
becomes `--jobs 0`, so the old pin cannot satisfy a clean supported bootstrap.
Official commit `ed9f680b0df1de28f062de1769d89d22b2644d1b` is the first upstream
fix and uses `nproc --ignore=1`.

## Decision

1. Keep Discourse core and `discourse_docker` external. This repository owns
   only configuration, a supported theme, operations, and validation.
2. Select Discourse `v2026.7.1` at exact application commit
   `cbf996f65aae3da1843224aa624bcd9a225931ac`.
3. Select exact deployment commit
   `ed9f680b0df1de28f062de1769d89d22b2644d1b`, including its required Ruby,
   base-image, PostgreSQL 18, disk-calculation, and one-core commits. This is a
   new empty installation; it does not perform a PostgreSQL upgrade or import.
4. Pin Docker Manager at
   `c008c3ca7fcc44775215843992e88190adb7b3bf`, the exact official revision
   resolved before the selected deployment commit. It is the only included
   upstream component and is not an optional Mochirii addition.
5. Use one official standalone container with PostgreSQL, Redis, Rails,
   Sidekiq, Nginx, and persistent `/shared` data on the dedicated host.
6. Use one dedicated Spaces bucket through the built-in S3-compatible storage
   settings. Normal uploads are public, backups are private under `backups/`,
   direct browser uploads and CORS installation are disabled, and static
   application assets remain local.
7. Use the built-in DiscourseConnect consumer, closed registration,
   `login_required=true`, and `secure_uploads=false`. No optional authentication
   provider or custom core plugin is allowed.
8. Use a supported Mochirii theme plus exact configuration overlays for public
   metadata and static error pages. Use one mandatory, dependency-free,
   repository-owned delivery interceptor solely to remove the exact pinned
   recipient-visible application headers before SMTP. It is bound to the exact
   Forums commit, does not rewrite member content, and is not an optional
   third-party plugin or core patch. Preserve all upstream notices internally.
9. Keep SMTP provider-neutral. Production rendering requires an already
   authorized runtime SMTP authority and a verified Mochirii sender.
10. Apply public-brand neutrality to rendered URLs/body/UI/OG/PWA/email. The
    DNS-only direct Spaces CDN's unavoidable, non-rendered protocol fields are
    accepted only through the repository's exact bounded current-provider
    header and optional `__cf_bm` grammar; their opaque values are never
    persisted, logged, or compared. This inference does not add a proxy or
    change the approved provider architecture.

## Consequences

- The repository can produce one exact sanitized deployment configuration and
  deterministic theme archive without storing secrets.
- The old one-core-incompatible deployment pin is retained as rejected evidence,
  not silently advanced to moving upstream.
- The included object-storage CDN remains an end-to-end deployment stop gate;
  source preparation does not claim it works before the real media test.
- No provider resource, runtime, DNS record, certificate, SMTP account, or cost
  is created by accepting this decision.

## Primary references

- [Official Docker-only installation requirements](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL.md)
- [Official cloud standalone procedure](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL-cloud.md)
- [Official one-core correction](https://github.com/discourse/discourse_docker/commit/ed9f680b0df1de28f062de1769d89d22b2644d1b)
- [Official S3-compatible storage guidance](https://meta.discourse.org/t/configure-an-s3-compatible-object-storage-provider-for-uploads/148916)
- [Official backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
