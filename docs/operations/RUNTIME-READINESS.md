# Runtime readiness gates

This ledger separates source validation from live/provider proof. A source or
CI result cannot mark a runtime, provider, DNS, TLS, SMTP, cost, backup, or
member-access gate complete.

Stage 4 is source-only. No provider resource, configuration, credential,
certificate, DNS record, public deployment, or paid cost is created by this
repository state.

## Selected supported baseline

The only selected installation is the official single-container standalone
layout with persistent `/shared` data:

| Component | Exact selection |
| --- | --- |
| Discourse Docker | `ed9f680b0df1de28f062de1769d89d22b2644d1b` |
| Discourse core | `v2026.8.0` / `badad7b0456a628e578bc48b9f8c1259422b5d58` |
| Docker Manager | `c008c3ca7fcc44775215843992e88190adb7b3bf` |
| Linux AMD64 base | `sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48` |
| Host | Ubuntu 24.04 LTS, SGP1, 1 vCPU, 2 GiB RAM, 50 GiB disk, 2 GiB swap |

The rejected `a3028747...` deployment candidate is evidence only; its build
command resolves to zero Bundler jobs on one CPU. No optional plugin, core
fork, raw-source installation, moving revision, managed database, managed
cache, volume, load balancer, or second deployment authority is allowed.
The one mandatory first-party operational component is release-bound. It
removes the exact pinned recipient-visible application headers and owns the
bounded Sidekiq execution probe; it is not an optional feature. The probe
separately proves a registered Sidekiq process and execution of one exact
harmless default-queue job through one namespaced, expiring Redis lease. The
caller claims a private preparing nonce, enqueues without a correlation
argument, binds the returned JID, and accepts only the same JID's completed
state. Compare-and-swap transitions retain the original lease expiry; same-JID
retry resumes a started state, while an old JID cannot mutate a new owner. The
probe observes for 60 seconds after enqueue and conditionally deletes only its
own state. Its fixed verifier output never contains the nonce, JID, arguments,
raw exception, process identity, queue contents, or logs. A not-started state
does not claim to distinguish backlog from failure before job execution.

## Stage 4 source gate

All of the following must pass at the same exact repository commit:

- repository and secret scans, sanitized configuration parsing, exact upstream
  byte and digest checks, and deterministic theme construction;
- hostile renderer, storage-policy, branding, mail-rendering, and
  DiscourseConnect fixtures;
- the loopback-only official standalone bootstrap with one effective CPU;
- exact core and Docker Manager revision readback;
- PostgreSQL, Redis, a registered Sidekiq process plus an exact completed probe
  job, persistent data, restart, and supported rebuild in the disposable
  fixture; and
- a clean worktree/commit review with immutable release evidence.

No item in this section proves production. A failure outputs `BLOCKED` and no
provider stage begins.

## Stage 5 pre-creation gate

Before any paid creation:

1. Social remains successfully cut over and healthy.
2. The exact Forums source gate and required CI are green.
3. An existing, already authorized SMTP authority and Mochirii-owned sender
   pass mandatory STARTTLS with peer certificate verification, sender
   authorization, authenticated submission, and branded test delivery. No new
   mail provider/account, mail DNS record, or fixed mail cost is within scope.
4. Protected live evidence no older than the validator limit passes
   `scripts/verify-cost-evidence.py`: the SGP1 plan is available at `$12.00`,
   weekly backups are 20 percent (`$2.40`), the existing Spaces subscription is
   active, the additional bucket is within its included fixed cost, aggregate
   usage is reviewed, no second subscription/resource is required, and the
   aggregate incremental fixed monthly total is exactly `$14.40`.
5. The exact capacity, bucket quota, and limited-key interface are available.

The gate uses current plan, pricing, subscription, quota, and aggregate-usage
readback. Any higher fixed total, unavailable dependency, second subscription,
or additional paid resource stops before creation.

## Provisioning boundary

Only these resources may be created:

- one SGP1 Basic `s-1vcpu-2gb` Ubuntu 24.04 LTS Droplet with weekly backups;
- one SGP1 Standard Spaces bucket named `mochirii-forums`, or the nearest
  unambiguous available name after an exact source/config update and validation;
- one bucket-scoped read/write/delete object key;
- the included bucket CDN with `media-forums.mochirii.com`; and
- the exact `forums.mochirii.com` and `media-forums.mochirii.com` DNS/TLS
  configuration.

The provider and DNS procedure is
[PROVIDER-DNS-TLS.md](PROVIDER-DNS-TLS.md). It must preserve all unrelated DNS
and provider resources.

## Host and runtime gate

Before public access, record current evidence that:

- the distinct deploy and operator keys work, root/password SSH is disabled,
  and provider-console recovery remains available;
- firewall, fail2ban, unattended security updates, Docker log rotation, 2 GiB
  persistent swap, and one-CPU resource bounds are active;
- the official deployment checkout and running application match the exact
  release tuple and repository commit;
- `/etc/mochirii/forums.runtime.json` is a literal root-owned mode `0600` JSON
  file with exactly the reviewed keys, and rendered configuration is an
  immutable versioned release artifact;
- only SSH, HTTP, and HTTPS are host-reachable; PostgreSQL and Redis are not
  public;
- HTTPS, PostgreSQL, Redis, a registered Sidekiq process plus an exact completed
  probe job, restart, and supported rebuild pass; and
- all launcher, backup, restore, certificate, and provider details remain in
  root-only protected logs and evidence.

## Product and identity gate

The exact runtime must prove:

- `login_required=true`, `secure_uploads=false`, native registration closed,
  local login disabled, every additional login provider disabled, and
  `automatically_download_gravatars=false` before narrative-user branding;
- the built-in DiscourseConnect consumer is the sole member login path;
- valid active/verified members pass while anonymous, inactive, unverified,
  malformed, expired, replayed, and cross-session requests fail;
- the shared secret is exactly 64 lowercase hexadecimal characters, server
  only, and absent while the consumer is disabled;
- the recovery administrator is available through host-console procedure, not
  a standing public local-login form; its one-time link is bound to the exact
  Forums origin and token path, with HTTP permitted only in the explicit
  loopback fixture and HTTPS required for every non-fixture runtime; and
- public/member HTML, metadata, PWA assets, emails, errors, logos, footer, and
  upload notice are Mochirii-branded while required legal notices remain
  preserved internally; the narrative system user retains the exact Mochirii
  active avatar with no asynchronously downloaded Gravatar after Sidekiq runs.

DiscourseConnect stays disabled through backup and disposable restore. After
the irreversible marker exists, provision the same secret while the Website
producer remains off, rebuild the consumer in loopback containment, and pass
the local signed-outbound and hostile-callback fixture. Disposable CI and the
later fresh Website end-to-end evidence own valid inbound, expiry,
cross-session, and replay proof. Next prove the reviewed public config is
still closed behind `login_required` while the producer returns `503`; enable
the Website producer last and retain public ingress only after the live member
allow/deny/expiry/replay fixture passes. Failure turns the producer off and
returns Forums to proved loopback containment or a proved stopped state.

## Storage, backup, and restore gate

Before member rollout:

- prove the database contains zero `secure=true` uploads;
- prove one disposable image write, optimized variants, custom-host retrieval,
  anonymous direct retrieval, anonymous listing denial, deletion, and cleanup;
- reject all non-image extensions and any provider hostname in member-facing
  media URLs;
- create an application backup under the same bucket's private `backups/`
  prefix, prove anonymous denial, application list/retrieve, size, and SHA-256;
- restore the exact re-read object using the isolated loopback configuration
  with member mail suppressed, then prove database integrity, uploads, jobs,
  restart, rebuild, and production reopen; and
- from the distinct operator account, create the one-way
  `member-rollout-enabled` marker. Once it exists, destructive restore on the
  member-serving host is permanently refused.

See [STORAGE.md](STORAGE.md) and [RECOVERY.md](RECOVERY.md).

## Final acceptance

Public/member activation is allowed only when one evidence set binds the final
repository commit, upstream tuple, release archive digest, rendered
configuration digests, theme and mail-metadata-component digests, cost readback, provider resource class,
SMTP readback, hosted verification, storage test, backup, restore, and
member-rollout marker. Pass, fail, and not-run must remain distinct.

If any live gate fails, keep access closed. Remove only newly created empty or
disposable Forums resources needed to stop billing, report incurred cost, and
preserve sanitized evidence. Never destroy imported or pre-existing data.

## Primary references

- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [Pinned installation requirements](https://github.com/discourse/discourse/blob/badad7b0456a628e578bc48b9f8c1259422b5d58/docs/INSTALL.md)
- [Pinned cloud standalone layout](https://github.com/discourse/discourse/blob/badad7b0456a628e578bc48b9f8c1259422b5d58/docs/INSTALL-cloud.md)
- [Official S3-compatible storage guidance](https://meta.discourse.org/t/configure-an-s3-compatible-object-storage-provider-for-uploads/148916)
- [Official Discourse backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
- [Official Droplet backup pricing](https://docs.digitalocean.com/products/backups/details/pricing/)
- [Official Spaces pricing](https://docs.digitalocean.com/products/spaces/details/pricing/)
