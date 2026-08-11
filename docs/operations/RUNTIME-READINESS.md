# Runtime Readiness Gates

This checklist defines evidence required before Mōchirīī Forums can gain
runnable source or provider configuration. It is not an installation or
deployment runbook, and it creates no runtime or recurring cost.

The source-only contracts in `SOURCE-INTRODUCTION-READINESS.md` define and test
the fail-closed inputs for this checklist. They do not mark any operational gate
complete.

## Current supported baseline

Verified against official sources on 2026-08-11:

| Contract | Official baseline | Mōchirīī gate |
| --- | --- | --- |
| Installation | Docker on 64-bit Linux with SSH access | Official standalone `discourse_docker` only |
| CPU | 1 modern core minimum; 2 recommended | Selected host must prove at least the minimum |
| Memory | 1 GiB minimum with swap; 2 GiB recommended | Selected host and clean rebuild must pass |
| Swap | Required with the 1 GiB minimum | At least 2 GiB, persistent across reboot |
| Disk | 10 GiB minimum; 20 GiB recommended | Capacity and rebuild headroom must be measured |

The supported single-container layout uses the upstream
`samples/standalone.yml` template, a host runtime configuration at
`/var/discourse/containers/app.yml`, persistent host data under
`/var/discourse/shared/standalone`, and the container mount `/shared`. The
runtime configuration is secret-bearing host state and must never be committed
to this repository.

The current official one-line entrypoint is `install-discourse`. Its exact
reviewed source is recorded in `upstream-provenance.v1.json`, but execution
remains blocked: the script follows moving branches, can invoke a network-fetched
Docker installer, and the setup wizard names a mutable image tag. A later
approved packet must bind every transitive input and image digest; piping a
network response directly to a privileged shell is not an approved method.

The current unselected `discourse_docker` drift includes a PostgreSQL 18
dump/restore migration that can temporarily require the old database, new
database, and dump (roughly three database sizes of free space), changes locale
to builtin `C.UTF-8`, and retains the old data under
`/shared/postgres_data_old`. Before selecting that deployment revision, measure
the actual database and upload footprint, size disk with rebuild/backup
headroom, verify cleanup/retention behavior, and rehearse the exact upgrade plus
restore. The generic 10 GiB minimum is not production capacity evidence.

## Architecture and cost

- Record the supported Discourse topology, exact upstream revision, operating
  system, container engine, data volumes, mail path, ingress boundary, and
  network trust zones.
- Record the responsible owner, monthly cost ceiling, capacity assumptions,
  data residency, retention, and an approved shutdown path.
- Keep production independent of workstations and private recovery folders.
- Prove the service, jobs, scheduled backups, restore, and post-reboot health
  with this workstation powered off.
- Require an inventory of every plugin, theme, integration, external service,
  license, and update owner. The current inventory is intentionally empty in
  [customizations.v1.json](customizations.v1.json).

## Time contract

- Mōchirīī Forums civil dates, business-calendar boundaries, wall-clock
  schedules, labels, and human-facing date/time displays use the sole IANA zone
  `Asia/Singapore`.
- Derive the displayed offset and abbreviation from IANA data for the exact
  instant being rendered. Never substitute a fixed-offset zone or a manually
  maintained offset/label, including for historical instants.
- Database storage, protocol and API timestamps, audit records, logs, cache
  validators, signatures, and duration arithmetic remain unambiguous UTC
  instants. Relative elapsed-time displays remain duration based.
- The future runtime must verify the effective application, scheduler, and
  display zones after configuration and again after rebuild/restart. Source
  defaults or a host operating-system zone do not constitute runtime proof.
- Pinned core does not provide one authoritative site-wide display zone:
  local-date rendering can use the browser or user option, Calendar can fall
  back to the browser zone, and built-in local-dates settings default email to
  `Etc/UTC` while suggesting non-Singapore zones. Rails remaining in UTC is the
  correct storage baseline, not proof of the human-facing contract.
- A setting, host zone, theme-only change, or `moment` monkeypatch cannot satisfy
  this full contract. The lean future design first requires an upstream,
  default-preserving central display-zone resolver on the selected supported
  release. Only then may one separately approved, isolated Mōchirīī plugin under
  GPL-2.0-or-later select `Asia/Singapore`, normalize or reject conflicting user
  zone writes, and bind core, Local Dates, Calendar, Chat, email, and job-facing
  displays to that resolver. Do not fork core or introduce manual offsets.
- That plugin is a design gate, not approved source in this packet. Inventory
  and license-review the exact revision, then browser/email-test anonymous and
  authenticated users, conflicting browser/user zones, all named surfaces,
  current instants, and a historical Singapore instant with a different offset.
  Also prove UTC storage/wire/audit values remain unchanged. Every corresponding
  runtime field and activation gate stays false until that evidence passes. The
  runtime tzdb version and evidence also remain unresolved; the moving IANA
  source link below is not a selected runtime release.
- Any provider cron or external schedule must be reconciled to the same
  Singapore wall-clock contract before jobs are enabled. Historical records
  are not automatically rewritten or re-bucketed.

## Identity, secrets, and network controls

- Require least-privilege operator access, MFA, named break-glass ownership,
  and periodic access review.
- Store runtime secrets only in an approved provider secret store; keep the
  private recovery copy inside its separately governed credential boundary.
- Never place secrets in Git, images, logs, backups, browser bundles, workflow
  output, or evidence records.
- Document TLS termination, firewall allowlists, administrative access,
  outbound egress, rate limiting, denial-of-service protections, and log
  redaction before exposure.
- Verify mail authentication, bounce handling, complaint handling, abuse
  controls, and a no-send staging mode before enabling outbound email.
- Mōchirīī launch requires an approved SMTP path. The current official installer
  can instead use Discourse ID when SMTP is skipped, but that would add a new
  identity/vendor contract and is not approved by this packet.

## Central identity

- Use Discourse's built-in DiscourseConnect consumer. Do not implement or patch
  a custom core authentication plugin.
- `Mochirii-Wushu/Mochirii-Website` remains the producer and owner of shared
  identity. Forums owns only consumer configuration and compatibility evidence.
- The producer must validate the inbound lowercase-hex HMAC-SHA256 signature,
  bind and return the nonce, enforce the exact HTTPS return URL, issue a stable
  opaque `external_id`, require a verified email and current guild entitlement,
  and keep username/name values bounded. No role, group, moderator, or admin
  grant is implicit.
- Both directions use exactly one `sso` and one `sig` query value and reject
  duplicates or extra query keys. The `sso` value is a percent-encoded, strict
  standard-Base64 encoding of an `application/x-www-form-urlencoded` payload;
  `sig` authenticates the exact Base64 string. Strict encoding is a Website
  producer requirement. The pinned consumer filters and decodes Base64
  leniently, so this packet does not claim strict consumer decoding.
- The shared secret remains server-only. Request/response payloads and query
  strings may contain personal data and must not be logged. Keep verbose SSO
  logging off outside an explicitly approved redacted incident procedure.
- Website's inbound signature comparison must be constant-time. The observed
  pinned Discourse consumer compares the response HMAC with ordinary Ruby
  inequality, so the consumer contract does not claim constant-time comparison.
  It also emits SSO diagnostics on a generic user lookup/creation failure even
  when verbose logging is off; activation requires an explicit privacy review
  and supported mitigation or documented acceptance of that residual risk.
- Keep an approved break-glass administrator and a tested disable/rollback path
  before activation. Revocation and logout reconciliation require cross-repo
  evidence.
- Require explicit entitlement-loss session revocation, logout reconciliation,
  consumer/proxy query-log privacy mitigation, and break-glass test evidence.
  Their source fields remain null and their activation gates remain false.
- `forum-central-identity.consumer.v1.json` is only a versioned fail-closed
  proposal. Website's current registry entry is unversioned and lacks the
  producer artifact, tests, shared fixture, and rollback window, so activation
  remains blocked.

## Backup and restore

- Use Discourse application backups with uploads enabled, and preserve the
  reviewed host runtime configuration plus required encryption-key references.
- Define encrypted storage, least-privilege access, geographic placement,
  retention, immutability, and deletion rules.
- Prove scheduled backup creation and independent monitoring.
- Keep an encrypted off-host backup destination separate from any uploads
  bucket. The default local standalone backup path
  `/var/discourse/shared/standalone/backups/default` is not off-host protection.
- Complete an isolated restore rehearsal at the same application version and
  verify integrity, member access boundaries, uploads, and email suppression.
- Record recovery point and recovery time objectives from measured evidence.
- Never claim backup readiness from file creation alone; a successful isolated
  restore is required.

Official Discourse guidance warns that restores overwrite destination data and
that restored environments suppress ordinary user email until explicitly
re-enabled. The exact approved runtime packet must translate that guidance into
environment-specific, rollback-safe commands.

## Upgrade and rollback

- Review upstream changes and security notices before changing a pin.
- Capture a verified pre-change backup, current source revision, configuration
  digest, image digest, and health baseline.
- Rehearse the upgrade and rollback in an isolated environment.
- Use only the supported admin upgrader or a reviewed `launcher rebuild app`
  path, with an exact supported core revision, deployment revision, image
  digest, and plugin compatibility decision.
- Never claim that selecting a prior source/image reverses database migrations;
  Discourse does not support downgrade across migrations. A version-changing
  failure requires a supported forward fix or a clean same-version restore from
  the verified pre-change backup, with its exact deployment/configuration
  evidence.
- Use a bounded maintenance window, explicit stop conditions, post-change
  functional checks, and a named rollback operator.
- Retain immutable release evidence using the
  [release evidence template](release-evidence.v1.example.json).

## Monitoring and incident response

- Monitor bounded HTTP readiness, database and job health, storage capacity,
  certificate expiry, mail delivery, backup freshness, security events, and
  resource saturation without collecting unnecessary member content.
- Define alert ownership, severity, acknowledgement targets, escalation,
  evidence preservation, containment, recovery, and member-notification
  decision paths.
- Test loss of a container, database unavailability, full disk, mail failure,
  expired certificate, compromised operator credential, and restore failure.
- Keep security reports private under `SECURITY.md`; publish incident details
  only through an approved disclosure process.

## Launch acceptance

Runnable source or provider configuration remains blocked until all gates above
have accountable owners, exact evidence, rollback instructions, security and
privacy review, cost authorization, and a reviewed release decision.

## Primary references

- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [Pinned installation and minimum requirements](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL.md)
- [Pinned cloud installation and standalone layout](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL-cloud.md)
- [Official Discourse release support index](https://releases.discourse.org/)
- [Official Discourse backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
- [Official automatic-backup guidance](https://meta.discourse.org/t/configure-automatic-backups-for-discourse/14855)
- [Official self-hosted plugin guidance](https://meta.discourse.org/t/install-plugins-on-a-self-hosted-site/19157)
- [Official theme and component guidance](https://meta.discourse.org/t/installing-a-theme-or-theme-component/63682)
- [Pinned security guidance](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/SECURITY.md)
- [Official DiscourseConnect consumer setup](https://meta.discourse.org/t/setup-discourseconnect-official-single-sign-on-for-discourse-sso/13045)
- [Pinned local-date formatter](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/plugins/discourse-local-dates/assets/javascripts/lib/format-local-date.js)
- [Pinned local-date composer](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/plugins/discourse-local-dates/assets/javascripts/discourse/components/modal/local-dates-create.gjs)
- [Pinned Calendar event-date display](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/plugins/discourse-calendar/assets/javascripts/discourse/components/event-date.gjs)
- [Pinned local-dates settings](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/plugins/discourse-local-dates/config/settings.yml)
- [Pinned Discourse plugin API source](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/frontend/discourse/app/lib/plugin-api.gjs)
- [Official versioned client plugin API guidance](https://meta.discourse.org/t/a-versioned-api-for-client-side-plugins/40051)
- [Official theme-component versus plugin guidance](https://meta.discourse.org/t/theme-component-v-plugin-whats-the-difference/153951/3)
- [Official IANA tzdb Asia source](https://data.iana.org/time-zones/tzdb/asia)
- [Official Discourse downgrade/restore guidance](https://meta.discourse.org/t/how-do-i-revert-from-an-existing-version-to-an-older-version/252025)
- [GitHub repository security quickstart](https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository)
- [Current DigitalOcean Droplet pricing](https://www.digitalocean.com/pricing/droplets)
