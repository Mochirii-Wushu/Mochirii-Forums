# Runtime secret names

Repository source contains names and placeholders only. Runtime values are
literal JSON strings in root-owned protected files. Never use a shell `.env`
file as the host runtime source, source secret material as code, place it in
Git, pass values on a command line, or print it.

## Application runtime JSON

Production values live in `/etc/mochirii/forums.runtime.json`. The file must be
one non-symlink regular file owned by `root:root`, mode `0600`, containing
exactly these keys and no others:

| Key | Contract |
| --- | --- |
| `FORUMS_ACTIVATION_ENABLED` | Must be literal `true` for production rendering |
| `FORUMS_DEVELOPER_EMAILS` | Bounded approved recovery-administrator email list |
| `FORUMS_DISCOURSE_CONNECT_ENABLED` | Literal `true` or `false`; keep `false` through restore rehearsal |
| `FORUMS_DISCOURSE_CONNECT_SECRET` | Empty while disabled; exactly 64 lowercase hexadecimal characters when enabled |
| `FORUMS_NOTIFICATION_EMAIL` | One existing authorized sender on `mochirii.com` or an already authorized subdomain |
| `FORUMS_S3_ACCESS_KEY_ID` | Dedicated bucket-limited runtime key identifier |
| `FORUMS_S3_SECRET_ACCESS_KEY` | Dedicated bucket-limited runtime key secret |
| `FORUMS_SMTP_ADDRESS` | Existing authorized SMTP DNS hostname |
| `FORUMS_SMTP_AUTHENTICATION` | Reviewed `plain`, `login`, or `cram_md5` value |
| `FORUMS_SMTP_PASSWORD` | Runtime-only SMTP credential |
| `FORUMS_SMTP_PORT` | Existing implicit-TLS SMTP submission port |
| `FORUMS_SMTP_USER_NAME` | Runtime SMTP identity |

The exact repository commit is a separate validated deploy argument, not a
runtime JSON field. Rendered configuration is immutable by its SHA-256 under
the exact source commit. After the member-rollout marker, the operator may
atomically replace the protected runtime JSON from DiscourseConnect `false`
with an empty secret to `true` with the exact secret, then rebuild the same
reviewed current-`main` source commit. This creates a new configuration-digest
tuple for that commit; it never changes the stored pre-activation tuple. TLS
transport policy is fixed in the sanitized template: forced TLS, STARTTLS
disabled, peer verification enabled, and SMTP HELO domain
`forums.mochirii.com`. There is no
runtime switch that can weaken those settings.

No SMTP provider or mail DNS change is selected or authorized by this
repository. If the existing SMTP authority and Mochirii-owned sender cannot be
verified before paid creation, stop. Only the Forums web and media hostnames
are within the later DNS scope. Skipping email or enabling another identity
service is forbidden.

## Media-certificate runtime files

External-DNS certificate preparation first uses two root-owned mode `0600`
non-symlink files:

- `/etc/letsencrypt/mochirii-media.ini`, containing the ACME contact and exact
  non-interactive DNS-01 options; and
- `/etc/letsencrypt/mochirii-cloudflare.ini`, containing only the restricted
  `dns_cloudflare_api_token` entry.

Only after the issued lineage has been separately uploaded, bound to the exact
CDN endpoint, and verified does renewal automation add:

- `/etc/mochirii/forums-media-certificate.json`, with exactly
  `providerApiToken`, `cdnEndpointId`, and the exact SGP1 `cdnOrigin`.

Start from the matching sanitized files under `config/`. The provider token is
limited to certificate create/read/delete, CDN read/update, and the documented
prerequisite read scopes listed in [PROVIDER-DNS-TLS.md](PROVIDER-DNS-TLS.md).
The DNS token uses only `Zone:DNS:Edit` for the single `mochirii.com` zone; a
global API key is forbidden.

Certificate private keys and lineages stay under `/etc/letsencrypt`, root-only.
They never enter repository releases, deployment workflows, backups, or public
evidence.

## Deployment transport

The protected GitHub `forums-production` environment may contain only the
restricted SSH host, deploy username, deploy private key, and pinned known-host
value needed by the workflows. The deploy account accepts one distinct
Ed25519 key. Its authorized-key entry is rewritten with OpenSSH `restrict` and
one root-installed forced-command dispatcher. That dispatcher accepts only a
bounded digest-bound release stream and the stable deploy, verify, backup, and
pre-rollout restore verbs; it rejects shell, SFTP/subsystems, extra arguments,
forwarding, tunnels, agents, X11, and TTY access.

The human operator uses a separate Ed25519 key and provider-console recovery.
Do not put the operator key in the deployment environment or reuse the deploy
key. Runtime application, object-storage, SMTP, DNS, certificate, and provider
API secrets never traverse the GitHub deployment workflow.

The deploy key has no sudo or dispatcher route to the host-operation lock
helper and cannot choose a lock path. Root controllers alone request the fixed
primary or media identities; the helper never accepts `/var/lock`, a pathname,
or a mode/owner repair from deployment input.

## Evidence and recovery

Raw launcher, Rails, backup, and restore transcripts are never retained: the
official launcher can trace secret-bearing environment arguments. Such output
is discarded or captured only in an ephemeral root-owned mode `0600` file that
is unlinked before return. Durable host logs contain only fixed allowlisted
operation/status/hash markers. Certificate and package command output remains
inside the protected host boundary and must never include credentials.
Public evidence records only exact source and artifact hashes, pass/fail
states, resource classes, and redacted references. It never records secret
values, query payloads, member identifiers, signed URLs, provider tokens,
private keys, object keys, or raw logs.

The root-owned mode `0600` `current-release.json` is protected state, not a
secret store. It contains exactly seven non-secret evidence fields:
`repositoryCommit`, `productionConfigurationSha256`, `releaseEvidenceFile`,
`releaseEvidenceSha256`, `discourseConnectEnabled`,
`memberRolloutMarkerFile`, and `memberRolloutMarkerSha256`. The host writes it
with a same-directory temporary file, `fsync`, atomic replace, and directory
`fsync`; operators never edit it directly.

The approved private recovery boundary may hold the governed recovery copy.
Production never depends on this workstation or that folder. Rotation records
may name a secret and timestamp, but never its value.
