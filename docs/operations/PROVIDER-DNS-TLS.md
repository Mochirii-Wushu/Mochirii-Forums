# Provider, DNS, and TLS runbook

This runbook is inert Stage 4 source. It documents the later, explicitly
authorized Stage 5 operations but performs none of them. At this checkpoint no
Droplet, bucket, key, CDN endpoint, certificate, DNS record, runtime secret, or
paid cost has been created or changed.

## Pre-creation gate

Do not create a paid resource until all of these pass in the same protected
operator session:

1. Social remains at its successful terminal gate.
2. The exact current Forums `main` commit passes source CI and the official
   one-effective-CPU disposable bootstrap.
3. An existing, already authorized SMTP authority and Mochirii-owned sender
   pass mandatory STARTTLS with peer certificate verification, authenticated
   submission, and branded test delivery at no new fixed cost. Creating a mail
   provider/account, selecting a mail hostname, or changing mail DNS is outside
   scope.
4. Current provider readback proves SGP1 capacity and passes
   `scripts/verify-cost-evidence.py` with an observation within its maximum age:
   `s-1vcpu-2gb` at `$12.00` monthly, weekly Basic backups at 20 percent or
   `$2.40`, an active existing Spaces subscription, the additional Standard
   bucket within that subscription at `$0.00` incremental fixed, aggregate
   usage reviewed, no second subscription, no additional paid resource, and
   exactly `$14.40` aggregate incremental fixed monthly cost.
5. The account can create one bucket-scoped read/write/delete key, the included
   CDN, and the exact two authorized DNS records.

The pricing gate is based on live plan, backup, subscription, quota, and usage
readback. If any fixed total is higher, capacity is unavailable, a second
subscription/resource is required, or SMTP is not already ready, create
nothing and stop.

Official pricing references:

- [Droplet backup pricing](https://docs.digitalocean.com/products/backups/details/pricing/)
- [Spaces subscription, bucket, and included-CDN pricing](https://docs.digitalocean.com/products/spaces/details/pricing/)

## Exact provider resources

Create only:

- one SGP1 Basic Droplet, slug `s-1vcpu-2gb`, Ubuntu 24.04 LTS,
  1 vCPU, 2 GiB RAM, 50 GiB local disk, weekly Droplet backups, and included
  monitoring; and
- one SGP1 Standard Spaces bucket named `mochirii-forums`.

If the bucket name is unavailable, stop. Select the nearest unambiguous name
only through an exact reviewed source/configuration update and rerun all gates
before creating it.

Do not create a volume, managed database, managed cache, load balancer,
Kubernetes cluster, App Platform app, second Droplet, second bucket,
second Spaces subscription, external CDN, or another provider resource.

Create exactly one limited Spaces key through the provider's bucket-limited
interface. Restrict it to read, write, and delete object operations on only the
Forums bucket. Never use a full-account key, Social key, public bucket policy,
AWS credential, IAM role, ARN, or lifecycle-policy authority. Keep bucket
listing private, backups private, and static website hosting disabled.

## Host bootstrap

Use SSH keys only. Run the exact host-control installer in two phases. First,
while retaining the original privileged bootstrap session, run its `prepare`
phase with two distinct root-owned key files:

```text
<exact-reviewed-installer> prepare <exact-current-main-commit> <deploy-key-file> <operator-key-file>
```

- the automation deploy key, restricted to the stable wrappers; and
- the human operator recovery key, separately stored and tested with
  maintenance sudo.

The prepare phase creates both users, installs the stable wrappers and narrow
deploy sudoers rule, configures the deploy-user SSH restrictions, UFW,
fail2ban, unattended security updates, 2 GiB persistent swap, Docker log
rotation, and private container services. It deliberately leaves root/password
SSH policy unchanged.

Open a new, separate SSH connection authenticated as
`mochirii-forums-operator`. From that connection, prove its maintenance sudo
and invoke the same reviewed installer through sudo with:

```text
sudo <exact-reviewed-installer> harden 'HARDEN MOCHIRII FORUMS SSH'
```

The harden phase requires the operator `SUDO_USER` plus a live SSH connection,
creates the root-only operator proof, disables root/password/keyboard-
interactive SSH, validates the effective daemon configuration, and reloads
SSH. Prove the operator session remains usable before closing the bootstrap
session. Keep provider-console access available for SSH/firewall recovery.
Preserve package and installer output only in protected root logs.

The prepared and hardened phases pin the exact account tuple, absolute sole
authorized-key sources, root-owned home/key trees, daemon forced command,
disabled alternate key/CA/principals sources, firewall allowlist, security
services, Docker policy, swap, and installed control digests. Future control or
certificate-automation source changes use only the operator-only transactional
upgrade command in [DEPLOYMENT.md](DEPLOYMENT.md); never rerun `prepare` over a
hardened host.

Install `discourse/discourse_docker` at detached commit
`ed9f680b0df1de28f062de1769d89d22b2644d1b` under `/var/discourse` and verify
exact `HEAD`. Do not use the moving one-line installer or update the checkout
from a branch.

## DNS records

Cloudflare remains the DNS authority, not a second media CDN. Preserve every
unrelated zone setting and record. Create only:

- a DNS-only `A` record for `forums.mochirii.com` pointing to the dedicated
  Droplet IPv4 address; and
- a DNS-only `CNAME` for `media-forums.mochirii.com` pointing to the exact
  included Spaces CDN endpoint hostname.

Do not proxy either record through another CDN. Do not create or change a mail
record. Read back the exact record names, types, values, and DNS-only state
before continuing.

## Media CDN and external-DNS TLS

Enable the bucket's included CDN and bind only
`media-forums.mochirii.com`. A Standard bucket is required; Cold Storage does
not support the required CDN/custom endpoint. Because DNS is external to the
storage provider, use a bring-your-own certificate. Official guidance requires
a certificate for a custom CDN subdomain and identifies an uploaded
certificate as the external-DNS path:

- [Enable the Spaces CDN and custom subdomain](https://docs.digitalocean.com/products/spaces/how-to/customize-cdn-endpoint/)
- [Manage the Spaces CDN endpoint](https://docs.digitalocean.com/products/spaces/how-to/manage-cdn-cache/)
- [Manage uploaded certificates](https://docs.digitalocean.com/platform/teams/how-to/manage-certificates/)

Create two narrowly scoped automation tokens:

- a provider token with only `certificate:create`, `certificate:read`,
  `certificate:delete`, `cdn:read`, `cdn:update`, `spaces:read`, and the
  documented `regions:read`, `sizes:read`, and `actions:read` prerequisites;
  do not grant global `api:write`, Droplet mutation, domain mutation, CDN
  create/delete, bucket mutation, or unrelated provider scopes; and
- a Cloudflare API token with only `Zone:DNS:Edit`, restricted to the single
  `mochirii.com` zone. Do not use a Global API Key or an all-zones token.

DigitalOcean documents per-resource token scopes, and the Certbot Cloudflare
plugin recommends a zone-restricted DNS-edit token:

- [DigitalOcean API token scopes](https://docs.digitalocean.com/reference/api/scopes/)
- [Certbot Cloudflare DNS plugin credentials](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)

Initial issuance/binding and recurring renewal are deliberately separate:

1. Materialize root-owned mode `0600` protected inputs from
   `config/certbot-cli.ini.example` and `config/certbot-dns.ini.example`.
   They may be staged at any operator-only paths; do not overwrite unrelated
   files under `/etc/letsencrypt`.
2. Under explicit certificate/DNS authorization, run
   `scripts/prepare-media-certificate.sh` with confirmation
   `PREPARE MOCHIRII FORUMS MEDIA CERTIFICATE`. It validates the two inputs,
   installs the DNS plugin, and issues only the
   `media-forums.mochirii.com` ACME lineage and materializes the exact inputs
   as `/etc/letsencrypt/mochirii-media.ini` and
   `/etc/letsencrypt/mochirii-cloudflare.ini`. It does not upload a provider
   certificate, bind a CDN endpoint, install rotation automation, or enable a
   timer.
   Preparation durably records that the exact lineage paths were absent before
   invoking Certbot. On retry it first reconciles the ACME DNS journal. A fully
   valid transaction-owned lineage is committed forward; an incomplete lineage
   is removed only after exact root ownership, inventory, symlink-target, mode,
   and size checks, with each parent directory fsynced, and issuance is retried.
   Any unexpected entry or ambiguous path retains the journal and fails closed.
3. Through the separately authorized provider operation, upload that exact
   leaf/key/chain as a custom certificate whose name begins
   `mochirii-media-forums-`, bind it and only
   `media-forums.mochirii.com` to the exact included CDN endpoint, create/read
   back the DNS-only CNAME, and prove the trusted served certificate
   fingerprint equals the protected ACME lineage. Do not call renewal
   automation against an unbound endpoint.
4. Materialize `config/media-certificate.runtime.json.example` as root-owned
   mode `0600` `/etc/mochirii/forums-media-certificate.json`, with the exact
   already-bound CDN endpoint ID, exact
   `<bucket>.sgp1.digitaloceanspaces.com` origin, and restricted provider
   token.
5. Run `scripts/install-media-certificate-renewal.sh` with confirmation
   `INSTALL MOCHIRII FORUMS MEDIA CERTIFICATE`. It installs the reviewed
   scripts and units, requires the separately issued lineage, and exact-validates
   and adopts the two preparation-owned root-only configurations without
   recreating or deleting them. A mismatch, symlink, unsafe mode, incomplete
   preparation journal, or partially installed automation fails closed. Its
   transaction cleanup removes only automation created by the installer. It
   performs a read-only preflight before enabling the persistent daily timer. The
   preflight refuses an absent/untrusted custom hostname, missing certificate
   ID, certificate outside the `mochirii-media-forums-` ownership prefix, or a
   served fingerprint that differs from the protected lineage.

The certificate installer keeps the root-only configuration and log
directories at mode `0700`, but `/usr/local/libexec/mochirii-forums` is the
shared executable traversal boundary and must remain a non-link, root-owned
mode-`0755` directory. Installation and terminal host verification prove both
that directory tuple and execution of the forced-command dispatcher by the
unprivileged deploy principal. Never collapse the shared executable parent to
the private-directory mode; an ownership, link, mode, or traversal mismatch
fails closed.

Run the installer only from the exact source whose manifest digest is already
bound by `current-host-control.json`. It takes the primary host lock before the
media lock through the installed no-follow helper. The helper accepts only its
fixed root-owned mode-`0700` `/run/lock/mochirii-forums` namespace and fixed
root-owned regular mode-`0600` files; `/var/lock`, linked nodes, and unsafe
ownership or modes fail closed. The installer verifies the existing host controls, and writes the exact
repository commit, manifest digest, and current control-evidence digest into
the root-only installation journal before publishing automation. After exact
script, wrapper, runtime, unit, timer-enabled, timer-active, and provider
preflight readback, it commits the journal, seals a new `certificate-install`
host-control record whose predecessor is that original evidence digest, and
runs the full host-security verifier. Only then may it record the terminal
passed event and durably clear the journal. A committed retry must adopt that
same immutable record; it cannot invent a new predecessor or report success
from a mixed control tuple.

Only a later successful Certbot renewal invokes the deploy hook. Rotation
validates the new certificate, creates the replacement uploaded certificate,
updates and reads back the exact existing endpoint, verifies the served TLS
fingerprint, and then deletes only the previously bound owned certificate. If
creation, binding, or pre-TLS verification fails, it restores the exact prior
certificate ID and custom hostname and removes the unused replacement. After
the new served TLS fingerprint passes, a sealed `retiring-old` phase is
commit-forward only: recovery must keep the exact new binding, idempotently
issue retirement for the prior owned certificate even if inventory omits it,
and never attempt to rebind a prior ID that may already have been deleted.
Every DELETE outcome, including a successful response, retains the journal
until at least two absence observations separated by 60 seconds pass while the
exact new endpoint binding, inventory, and served TLS remain valid. There is no
unproven null-certificate or empty-custom-host rollback path.

Before the first provider mutation the rotator reserves cleanup headroom in a
bounded certificate inventory and writes a root-owned mode `0600` transaction
journal containing only the exact endpoint, prior IDs, random transaction name,
phase, and fingerprints. A timeout, malformed response, or stale inventory
retains that journal and emits a fixed blocked marker. Every later timer or hook
must reconcile the journal before creating anything else; it deletes only
transaction-owned IDs and clears the journal only after endpoint, TLS, and
inventory readback converge. Never bypass the capacity gate or delete an
unrelated certificate to make room.

All issuance, renewal, and provider output remains under root-owned protected
logs. Never print tokens, private keys, certificate bodies, provider payloads,
or identifiers into workflow/public evidence. Verify the systemd timer is
enabled, exercise a protected renewal dry run or due-renewal procedure, and
monitor certificate expiry without exposing secret state.

## Forums HTTPS

Point `forums.mochirii.com` to the Droplet only after the host is ready. The
rendered production configuration keeps the official Discourse Docker web SSL
template but replaces its floating Let's Encrypt downloader with the
repository-owned immutable integration. It decodes vendored acme.sh `3.1.4`
commit `3661fd86b6304115e42f43910e6dd452ab9866d6`, verifies exact compressed and
decoded SHA-256 values before execution, and installs exact hash-verifying
wrappers for the client and curl. Every install, configuration, issuance,
certificate installation, and renewal invocation starts from an empty
environment; curl resolves only to the reviewed wrapper and receives `-q` as
its first option, disabling ambient curl configuration. Wget selection,
insecure TLS, custom CA paths, and custom CA bundles are rejected after retained
account and CA configuration loads. The client and wrapper must be root-owned,
mode-0755, one-link ordinary files, and the installed client is normalized and
verified after the production mode-077 install. The integration persists
`AUTO_UPGRADE=0`. Bootstrap and renewal never fetch or upgrade executable client
source. A client update requires a separate source, license, digest,
disposable-bootstrap, hosted-renewal, and rollback review.
Rollback uses the prior exact Forums release/configuration and its still-pinned
client while preserving `/shared/letsencrypt` certificate/account data. Prove
valid issuance and the hash-verifying automatic renewal path through the exact
hosted release. Do not terminate Forums TLS at a load balancer or second CDN.

Keep public ingress closed until the member-independent bootstrap, storage,
backup, disposable restore, restart, rebuild, branding, mail, and authentication
gates all pass. The restore configuration deliberately has no public TLS
template and binds HTTP to loopback only.

## Provider readback and evidence

Before member rollout, record a sanitized evidence reference for:

- one exact Droplet class, region, operating system, disk, and weekly-backup
  policy;
- one exact Standard bucket, one limited key, and the active existing Spaces
  subscription;
- the included CDN's exact origin class, Mochirii custom hostname, and trusted
  certificate result;
- the exact DNS-only web and media records;
- valid HTTPS on both Mochirii hostnames;
- the `$14.40` incremental fixed monthly total and no other paid resource; and
- proof that no unrelated DNS/provider setting changed.

Identifiers, tokens, IPs not intended for public disclosure, certificate
material, and raw provider responses remain in the protected evidence
boundary.

## Failure cleanup

If the final deployment cannot complete safely, close public access and remove
only newly created empty or disposable Forums resources necessary to stop
unnecessary billing. Revoke newly created limited credentials and remove the
two newly created DNS records only when they are still exclusively disposable.
Report any cost already incurred and retain sanitized evidence.

Never delete imported/member data or any pre-existing resource. If an object
or backup is no longer disposable, stop and preserve it for explicit recovery
direction.
