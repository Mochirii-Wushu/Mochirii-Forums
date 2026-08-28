# Forums deployment procedure

This is the source-controlled procedure for the official Discourse Docker
standalone installation. Stage 4 prepares and validates source only. It does
not create a host, bucket, key, CDN endpoint, certificate, DNS record, SMTP
account, runtime secret, public deployment, or cost.

## Exact release tuple

Every deployment must bind one reviewed full repository commit to all of these
immutable upstream inputs:

- `discourse_docker`:
  `ed9f680b0df1de28f062de1769d89d22b2644d1b`;
- Discourse core `v2026.7.1`:
  `cbf996f65aae3da1843224aa624bcd9a225931ac`;
- Docker Manager, included by the official standalone template:
  `c008c3ca7fcc44775215843992e88190adb7b3bf`; and
- Linux AMD64 base image:
  `sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48`.

Never replace a revision or digest with a tag, branch, or provider default.
Rerun the online source gate immediately before the first bootstrap or any
rebuild.

The live release identity is this upstream tuple plus one exact Forums source
commit and the SHA-256 of its rendered production configuration. Runtime-only
activation changes create a new configuration digest without changing or
duplicating the source commit.

## Stage 5 order and stop gates

Perform the following steps in order. A failed item stops the deployment.

1. Confirm the Social terminal gate remains complete and healthy.
2. Require the exact Forums `main` commit to pass repository CI and the
   loopback-only, one-effective-CPU disposable bootstrap.
3. Freeze the reviewed repository commit and release archive.
4. Before any paid creation, verify an existing, already authorized SMTP path:
   a Mochirii-owned sender on `mochirii.com` or an already authorized
   subdomain, mandatory STARTTLS with peer certificate verification,
   authenticated submission, branded test delivery, and no new provider,
   account, subscription, or mail DNS change.
5. Immediately before creation, collect protected live provider readback and
   pass `scripts/verify-cost-evidence.py`. It must prove SGP1 availability, the
   exact `$12.00` plan, weekly backups at 20 percent (`$2.40`), an active
   existing Spaces subscription, the additional bucket within that
   subscription at `$0.00` fixed, and `$14.40` aggregate incremental fixed
   monthly cost. A higher price, second subscription, or additional paid
   resource is a hard stop.
6. Create only the one authorized Droplet and one Standard bucket, then finish
   the provider, DNS, and TLS procedure in
   [PROVIDER-DNS-TLS.md](PROVIDER-DNS-TLS.md).
7. Install the exact host controls, exact upstream deployment source, protected
   runtime state, and exact release. Keep DiscourseConnect disabled.
8. Prove runtime, storage, private backup, disposable restore, restart, rebuild,
   mail, HTTPS, and branding behavior while no member rollout has occurred.
9. From the distinct operator account, create the irreversible member-rollout
   marker only after the supported restore evidence passes.
10. Materialize the same exact 64-lowercase-hex shared secret in both protected
    runtimes while the Website producer activation flag remains off. Rebuild
    Forums with the consumer on only in the reviewed loopback-contained
    configuration, then prove the exact signed outbound producer request and
    callback target plus private Mochirii denial for invalid, duplicate, and
    malformed callbacks. Disposable CI already proves the pinned consumer's
    local valid, expired, cross-session, and replay behavior; later fresh
    Website end-to-end evidence must prove those cases across the real producer
    boundary before finalization.
11. Switch to the exact reviewed public Forums configuration while the Website
    producer still returns fail-closed `503`. Prove `login_required=true`, no
    member content is exposed, ordinary/local/alternate login remains off, and
    the producer really is unavailable.
12. Enable the Website producer, then run the real Website-to-Forums active
    member allow, inactive/unverified deny, malformed/expired deny, and replay
    fixtures. Retain public ingress only when all of them pass.
13. On any activation failure, turn the Website producer off first and return
    Forums to the exact prior consumer-disabled release or stop the container.
    The deployer first attempts an exact verified rollback. If that cannot
    complete, it stops the app, canonically restores the prior release/config
    pointers without starting it, and atomically seals either
    `activation-deploy-failed` or the fail-closed
    `activation-deploy-failed-producer-unproved` retry state. Prove the stop and
    producer disablement before another activation. Keep the same reviewed
    current-`main` source commit;
    every contained or public runtime is a new immutable configuration-digest
    tuple and never alters the stored pre-activation configuration.
14. Open member access only after every hosted gate passes and the final runtime
    evidence binds the exact repository commit, configuration digest, and
    activation result.

The Forums deploy release intentionally records
`activationPhase=consumer-public-producer-pending`; green Forums deployment is
not evidence that Website authentication is complete. Before enabling the
producer, keep the exact commit and configuration digest from protected
current-release evidence. If the later Website end-to-end fixture fails, turn
the Website flag off first, then use the distinct operator SSH session or
provider console to invoke the stable stop boundary:

```sh
sudo /usr/local/sbin/mochirii-forums-stop-pending-activation \
  <exact-current-commit> <exact-current-configuration-sha256> \
  'STOP MOCHIRII FORUMS PENDING ACTIVATION'
```

The command accepts only the exact protected producer-pending tuple, its exact
unproved containment transition, or an exact
`activation-deploy-failed-producer-unproved` tuple whose current-release chain
names the sealed prior consumer-disabled release. It takes the shared primary
host lock through the no-follow private lock helper,
proves the app stopped through daemon readback, retries the exact Website
producer-disabled probe, and atomically advances to the corresponding proved
stopped state. Repeated probe failure preserves the unproved state and fails.
Every ordinary host operation refuses an active deployment-mutation journal.
The sole exception is this stop command while reconciling that exact
`activation-deploy-failed-producer-unproved` record: it additionally requires a
root-owned mode `0600` `runtime-contained` mutation journal whose target, prior
release, current-release digest, selected prior configuration, stopped state,
and release symlink all match the failure record. It advances only the
authentication containment record and leaves the mutation journal for the
same-tuple deploy retry.
The deploy credential cannot invoke it. Do not restart public Forums until the
producer is off and a fresh contained consumer fixture plus Website end-to-end
fixture can be completed. An exact deploy retry may consume only the proved
`activation-deploy-failed` state; it derives the prior consumer flag from the
sealed release evidence while the app remains stopped, rebuilds the target first
in loopback containment, and repeats the producer-disabled proof before any
public config is activated. Final authentication evidence is a separate
protected readback and must never be inferred from the producer-pending release
record.

On a successful Website end-to-end run, transfer only its secret-free JSON
result through the distinct operator channel. The file must be root-owned,
mode `0600`, at
`/var/lib/mochirii/forums/operator-evidence/<commit>-<configuration>-website-authentication.json`.
It has exactly these fields: `schemaVersion`, `recordedAt`,
`websiteRepositoryCommit`, `forumsRepositoryCommit`,
`forumsProductionConfigurationSha256`, `websiteProducerEnabled`,
`producerFailClosedBeforeEnablePassed`, `activeMemberAllowed`,
`inactiveMemberDenied`, `unverifiedMemberDenied`, `invalidSignatureDenied`,
`malformedRequestDenied`, `expiredRequestDenied`, `replayDenied`,
`alternateLoginDisabled`, `callbackLogRedactionPassed`,
`callbackBrowserQueryScrubPassed`, and
`callbackBrowserPrivateResponsePassed`. Every gate is Boolean `true`; the record
contains no member identity, nonce, payload, signature, cookie, URL query, or
log excerpt. Within 15 minutes of its UTC `recordedAt` timestamp, compute its
SHA-256 privately and invoke:

```sh
sudo /usr/local/sbin/mochirii-forums-finalize-authentication \
  <exact-current-commit> <exact-current-configuration-sha256> \
  <exact-website-evidence-sha256> \
  'FINALIZE MOCHIRII FORUMS AUTHENTICATION'
```

The operator-only finalizer revalidates the pending evidence chain, repeats
the no-secret Website producer-enabled probe and terminal host verification,
then atomically records `activationPhase=complete`. The deploy key cannot
invoke it. The hosted verifier accepts a consumer-enabled release only in that
complete phase and repeats the producer-enabled probe; a pending, contained,
unproved, stale, or additive evidence record is not terminal success.

## Host baseline and access recovery

The only authorized host class is Ubuntu 24.04 LTS in SGP1 with one vCPU,
2 GiB RAM, 50 GiB local disk, weekly Droplet backups, and a persistent 2 GiB
swap file.

### Fresh Ubuntu 24.04 prerequisites

On the new host, follow the then-current official
[Docker Engine Ubuntu apt repository procedure](https://docs.docker.com/engine/install/ubuntu/).
Do not pipe the moving convenience installer into a
shell and do not invent a Docker package-version pin. First inspect Docker's
documented conflicting packages:

```sh
for package in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  dpkg-query -W -f='${binary:Package}\n' "$package" 2>/dev/null || true
done
```

This is a new dedicated host. If any result reflects unexpected operator data
or another workload, stop instead of removing it. Otherwise remove only the
reported conflicting packages, then install the repository prerequisites plus
Git and Python 3:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl --fail --show-error --silent --location \
  https://download.docker.com/linux/ubuntu/gpg \
  --output /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
docker_suite="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
docker_arch="$(dpkg --print-architecture)"
printf '%s\n' \
  'Types: deb' \
  'URIs: https://download.docker.com/linux/ubuntu' \
  "Suites: ${docker_suite}" \
  'Components: stable' \
  "Architectures: ${docker_arch}" \
  'Signed-By: /etc/apt/keyrings/docker.asc' | \
  sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

Immediately record protected readback before host-control mutation:

```sh
docker version --format '{{.Server.Os}}/{{.Server.Arch}} {{.Server.Version}}'
systemctl is-enabled docker
git --version
python3 --version
```

Require a reachable Docker server on exactly `linux/amd64`, an enabled Docker
service, Git, and Python 3. `scripts/install-host-control.sh prepare` repeats
those gates and seals their non-secret versions in root-only prerequisite
evidence before installing packages or host policy. Do not use `hello-world`;
the exact pinned standalone bootstrap later proves daemon, image, cgroup, CPU,
memory, and swap compatibility without introducing a moving image test.

If the conflict-package inventory is empty, no removal command is needed. If
it contains only the documented packages on this still-empty host and their
removal has been reviewed, remove only those fixed names and reread the
inventory before adding Docker's repository:

```sh
for package in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'ok installed' || continue
  sudo apt-get remove -y "$package"
done
```

Provide two distinct root-owned, mode `0400` or `0600`, single-key Ed25519
files to the `prepare` phase of `scripts/install-host-control.sh`: one
automation deploy key and one human break-glass operator key. The prepare phase
creates:

```text
<exact-reviewed-installer> prepare <exact-current-main-commit> <deploy-key-file> <operator-key-file>
```

- `mochirii-forums-deploy`, restricted to the four stable deploy, verify,
  backup, and pre-rollout restore wrappers through one forced-command
  dispatcher; and
- `mochirii-forums-operator`, with the separately held maintenance key needed
  for recovery and member-rollout finalization.

Keep the original privileged bootstrap session open after `prepare` returns.
Open a separate SSH connection with the operator key, prove non-interactive
maintenance sudo from that authenticated session, and only then invoke the
same reviewed installer as:

```text
sudo <exact-reviewed-installer> harden 'HARDEN MOCHIRII FORUMS SSH'
```

The operator-only sudoers policy preserves exactly `SSH_CONNECTION` for this
locked principal because Ubuntu `sudo` otherwise removes that sshd-provided
session evidence. Do not widen the preserved environment or synthesize the
value; both initial hardening and later governed control upgrades require the
real operator SSH context to reach the root-owned verifier.

The `harden` phase refuses a root/bootstrap invocation: it requires
`SUDO_USER=mochirii-forums-operator` and a live SSH connection, writes a
root-owned mode `0600` operator proof, disables root/password/keyboard-
interactive SSH, validates the effective daemon configuration, and reloads
SSH. Confirm the operator session still works before closing the bootstrap
session. Preserve the provider console as the recovery path if SSH
configuration or both accounts fail. Never use the automation key as the
operator key.

If hardening fails after the exact operator proof is published but before the
root-owned hardened access/control records are sealed, keep the proof as
evidence. A reviewed newer canonical-main repair may rerun `prepare` only while
both hardened records remain absent and the proof is one unlinked regular
`root:root` mode-`0600` file containing exactly
`operatorSshAndSudoVerified=true` plus its final line feed. An unsafe proof,
either hardened record, or a missing live operator SSH/sudo context remains a
hard stop. Never delete, rewrite, or synthesize the proof to bypass recovery.

Both accounts have exact root-owned mode-`0755` homes, root-owned mode-`0755`
`.ssh` directories, root-owned mode-`0644` single `authorized_keys` files,
`/bin/bash`, locked passwords, their matching primary group, and no
supplementary group. The public-key sources remain immutable to both principals
but are readable after sshd drops privileges; the installer and terminal host
verifier execute that exact dropped-privilege read gate. `/var/lib/mochirii/forums`
remains root-owned mode `0755` so sshd can traverse to those keys; `evidence`,
`operator-evidence`, `logs`, `quarantine`, and control-upgrade work remain
root-owned mode `0700`.

The effective daemon contract is stricter than the key files alone. Root has
no key source and cannot log in. Operator and deploy use only their one exact
absolute `AuthorizedKeysFile`; `AuthorizedKeysCommand`, trusted user CAs, and
authorized-principals files or commands are all disabled. The operator retains
an interactive TTY but no forwarding or user rc. Deploy has no TTY, forwarding,
user rc, shell-selected command, or privilege group, and the daemon itself
forces the installed dispatcher. Any `authorized_keys2`, `rc`, extra `.ssh`
entry, alternate daemon source, account/group drift, or effective-setting drift
fails hosted verification.

The installer also configures the host firewall, fail2ban, unattended security
updates, 2 GiB swap, and Docker log rotation. PostgreSQL, Redis, and application
service ports remain private to the standalone container. Only SSH, HTTP, and
HTTPS are host-accessible.

### Governed host-control upgrades

Do not rerun `prepare` or replace the hardened SSH fragment manually to update
stable wrappers, host policy, or installed certificate automation. From a
separately authenticated `mochirii-forums-operator` SSH session, after proving
the application is absent or stopped and reviewing the exact current public
canonical `main` commit, run:

```sh
sudo /usr/local/sbin/mochirii-forums-upgrade-host-control \
  <exact-current-canonical-main-commit> \
  'UPGRADE MOCHIRII FORUMS CONTROL'
```

The operator-only wrapper takes the private primary and media locks in that
order through `/usr/local/libexec/mochirii-forums/host-operation-lock.py`, refuses
active storage, backup, restore, or certificate recovery journals, verifies
the currently installed controls, and fetches only public canonical `main`
with credentials and alternate Git protocols disabled. It validates the
candidate repository and exact `config/host-control-manifest.v1.json` target
inventory before any installed byte changes. Candidate extraction discards
archive ownership and permission grants under the script's restrictive umask,
yielding mode-`0700` directories and mode-`0600` ordinary files before
validation. The predecessor archive authority is bound at that exact
mode-`0600` candidate boundary; published host targets still receive only
their reviewed manifest modes. The archive validator therefore cannot receive
group- or other-writable source paths from the trusted Git archive.

The predecessor source is not inferred from the application-release tree. The
current root-owned control pointer must select the exact retained
`/opt/mochirii/forums/host-control-releases/<commit>/mochirii-release.tar`
ordinary file and bind its commit, Git tree, byte count, SHA-256, and expanded
content-manifest SHA-256. The upgrade reuses the bounded historical Git-archive
inspector and no-link extractor to copy that archive to
`previous-release.tar` and materialize `previous-source/<commit>` inside the
mode-`0700` staging tree. Both move atomically with the staging tree into the
transaction. A missing, linked, multiply linked, misowned, mis-moded,
off-boundary, oversized, changed, malformed, duplicate-key, tree-mismatched,
or manifest-mismatched predecessor fails before any installed target or SSH
activation change.

A root-owned mode-`0600` journal and root-owned mode-`0700` transaction tree
contain the exact old bytes, modes, new digests, current control pointer, and
certificate-timer state. It also records exactly one OpenSSH activation
predecessor: the reviewed service state, or the one-time Ubuntu 24.04 socket
state in which `ssh.service` is disabled/active, `ssh.socket` is
enabled/active, and the socket generator is unmasked. No mixed activation
state is accepted. The journal is directory-fsynced before the timer is
stopped, any target is atomically replaced, or OpenSSH activation changes.

Ubuntu's packaged socket-to-service conversion procedure is made explicit: the
upgrade publishes an exact `/dev/null` mask at
`/etc/systemd/system-generators/sshd-socket-generator`, reloads systemd,
disables and stops `ssh.socket`, then enables and starts `ssh.service`.
Terminal verification requires that exact mask, `ssh.service`
enabled/active, and `ssh.socket` disabled/inactive. A failed or interrupted
conversion restores the journaled predecessor before clearing the
transaction. Socket-predecessor restoration first proves Ubuntu's
`ssh.service` uses `KillMode=process`, disables the service without stopping
the retained sessions, removes the generator mask, reloads systemd, and enables
the socket without starting it. It then stops only the listener process, starts
`ssh.socket`, and starts `ssh.service` through that socket before requiring the
exact predecessor tuple. This ordering keeps the already authenticated
operator/recovery children alive while preventing the still-active listener
from blocking socket activation. Keep a verified privileged recovery session
open throughout the one-time conversion. Do not edit units manually or retry
unchanged failing bytes.

An invocation from the same exact canonical commit commits forward only when
every target is already the exact new root-owned byte/mode tuple; otherwise it
restores every exact old target, pointer, and activation predecessor, then exits
without an automatic unchanged-byte attempt. A changed
canonical-main repair may adopt a pending journal only when its locally clean
`main` checkout and a bounded credential-free remote read both prove current
canonical `main`, and the journal commit is that successor's direct Git parent.
That path always restores and verifies the exact predecessor, clears the old
journal, and continues the newly approved upgrade in the same locked process;
it never commits the older candidate forward or requires an identical-byte
second invocation. Both recovery paths rerun bounded sshd
syntax/effective-setting checks, service readback, installed target digests,
and the full host-security verifier. Unjournaled pre-journal staging is
accepted only under the exact protected state-root naming/mode contract and is
durably removed during recovery. The deploy SSH principal has no dispatcher or sudo
route to this operation.

Interrupted recovery derives the predecessor only from the transaction's
backed-up pointer, sealed archive, and extracted source, and verifies their
evidence digest before classifying installed targets. For the first upgrade of
the upgrade control itself, retain the exact canonical-main checkout and the
privileged recovery channel until completion. If a pending journal survives an
abrupt stop before the installed wrapper is replaced, resume with either the
exact canonical-main `scripts/upgrade-host-control.sh` that created the
transaction or a reviewed direct canonical successor carrying the bounded
recovery contract above. Never invoke an older installed wrapper, skip the
direct-parent/current-main proof, or reconstruct an application release as a
workaround.

The initial host-control installer safely creates and validates the ephemeral
private lock namespace before publishing controls. The certificate-automation
installer uses the same primary-then-media order. Both refuse a linked,
nonregular, multiply linked, non-root-owned, or writable lock node rather than
repairing or following it. The certificate installer records the current host-control evidence digest as
its immutable predecessor, exact-validates the installed certificate-control
bytes and unit/timer state, reseals the complete control inventory, and passes
the full host-security verifier before its terminal event or journal removal.
One governed direct successor may correct the exact historical certificate-
installer defect that changed `/usr/local/libexec/mochirii-forums` from its
root-owned mode-`0755` executable-boundary contract to mode `0700`. Only after
the existing predecessor passes its full verifier, the upgrade requires the
current directory to be a non-link owned by `root:root`, requires either mode
`0755` or that exact mode-`0700` defect, and binds the old combined installer
line plus the successor's reviewed split mode-`0700` private-directory and
mode-`0755` shared-directory lines. It changes only that exact `0700` mode to
`0755`, syncs the directory and its parent, and proves the deploy principal can
execute the forced-command dispatcher. Mode `0755` is idempotently accepted;
every other mode, owner, link, source, or traversal state fails closed. The
socket-activation recovery branch does not perform this repair.
After a host-control source upgrade, deploy that same reviewed commit through
the ordinary release path before using its release-owned certificate installer
or declaring the hosted release tuple complete.

## Exact upstream installation

Install `discourse/discourse_docker` at the pinned detached revision under
`/var/discourse`. The checkout must have exact `HEAD`
`ed9f680b0df1de28f062de1769d89d22b2644d1b`; do not run an installer or
launcher path that follows moving `main`.

Initialize the empty root-owned path, add only canonical public fetch URL
`https://github.com/discourse/discourse_docker.git`, fetch the exact commit,
check it out detached, and set the sole local push URL to
`no_push://mochirii-forums-upstream`. Do not configure credentials. Before
every launcher invocation the sealed verifier requires that exact detached
commit and tree, a clean tracked/untracked worktree, the sole canonical fetch
remote and disabled push URL, exact launcher/standalone/web/PostgreSQL-template
sizes and SHA-256 values, and the exact Linux-AMD64 base-image digest in the
active configuration. Any drift stops before launcher execution.

Persistent application data stays under
`/var/discourse/shared/standalone`, mounted at `/shared`. Repository releases
are immutable under `/opt/mochirii/forums/releases/<commit>`, and their
versioned runtime assets are addressed through the in-container
`MOCHIRII_RELEASE_ASSET_ROOT` value. Operators must not use an unversioned
fixed asset path.

## Protected runtime materialization

Create `/etc/mochirii/forums.runtime.json` from
`config/runtime.json.example`. It must be one regular `root:root` mode `0600`
JSON file containing exactly the literal-string allowlist documented in
[SECRETS.md](SECRETS.md). Do not source it as shell code, place the repository
commit in it, pass its values on a command line, or print it.

Production rendering is performed only inside the root-owned deploy wrapper.
The wrapper receives the exact repository commit separately, renders
production and isolated-restore configurations, validates them, hashes the
rendered production configuration, and stores the pair under
`/var/discourse/containers/releases/<commit>/<configuration-sha256>/`. It then
atomically points `/var/discourse/containers/app.yml` at the reviewed
production configuration. Multiple configuration digests may exist for the
same immutable source commit; an existing commit/digest tuple is accepted only
when both rendered files are byte-identical. Raw launcher, Rails, backup, and
restore output is discarded or held only in an ephemeral root-only file that
is unlinked before return; it is never retained because the official launcher
traces secret-bearing environment arguments. The durable root-only event log
contains only fixed allowlisted operation/status/hash markers. Workflows
receive only fixed success or failure messages.

The deployer atomically maintains root-owned mode `0600`
`/var/lib/mochirii/forums/current-release.json`. Its exact seven fields are:

- `repositoryCommit`;
- `productionConfigurationSha256`;
- `releaseEvidenceFile`;
- `releaseEvidenceSha256`;
- `discourseConnectEnabled`;
- `memberRolloutMarkerFile`; and
- `memberRolloutMarkerSha256`.

The file is written through a same-directory temporary file, file `fsync`,
atomic replace, and directory `fsync`. Every stable wrapper verifies this
record, the referenced root-only release evidence, the active configuration
symlink/digest, the running DiscourseConnect flag, and the marker state before
acting.

Before the first target configuration symlink or launcher mutation, the
deployer also publishes root-owned mode `0600`
`/var/lib/mochirii/forums/deployment-mutation.json`. Its exact immutable tuple
binds the deployment mode, commit/configuration/archive identity, every target
configuration and digest, and either the complete prior release/current/config
chain or an exact bootstrap absence tuple. Publication uses a fixed protected
partial, file `fsync`, atomic no-replace hard link, parent-directory `fsync`,
partial unlink, and a second parent `fsync`. Each configuration selection is
recorded before the symlink swap. Each launcher command records its random
operation label, prior image ID, active configuration, and irreversible
database-mutation boundary before the launcher process starts. The active
phases are `prepared`, `config-armed`, `launcher-armed`, `runtime-active`,
`runtime-contained`, and `verified`.

The sealed prior tuple includes the SHA-256 of the exact current-release bytes
and the exact `/opt/mochirii/forums/current` symlink target. A retry validates
both before stopping a container, selecting a configuration, reconciling a
launcher, or performing storage cleanup. Bootstrap absence also means no
current-release record and no `/opt/mochirii/forums/current` entry, in addition
to no application container, database, or selected configuration. A retained
storage-cleanup journal without its exact same-tuple deployment-mutation
authority is an orphan and is refused before any configuration or launcher
mutation.

After an uncatchable interruption, only the exact same canonical release tuple
may adopt this journal. It reconciles a populated, empty, or already-unlinked
launcher CID by the durable operation label, proves launcher processes and
operation-labelled containers absent, restores the recorded image boundary
when reconciliation failed, independently stops the app, and validates that
the selected configuration is either the sealed prior configuration or the
recorded target configuration. Bootstrap retry may accept only its exact
target container/configuration and retained database; it removes the stopped
target container without deleting persistent data before replay. Rebuild retry
continues forward with the exact target, so a possible migration is never
followed by an automatic old-code launch. Ambiguous bytes, identities, Docker
readback, or survivor state retain the journal and fail closed.

Deployment terminal promotion is additionally guarded by root-owned mode `0600`
`/var/lib/mochirii/forums/deployment-transaction.json`. Its immutable tuple
binds the deployment mode, commit, configuration digest, release-archive and
release-evidence digests, DiscourseConnect state, member marker, authentication
action, and any forward-fix evidence. The only active phases are `prepared`,
`state-committed`, and `event-committed`. The deployer durably pre-arms
`prepared` before changing the current release or authentication pointers,
records `state-committed` only after exact hosted readback, commits the durable
deployment event before `event-committed`, then publishes the exact
`current-deployment.json` terminal record with phase `complete` before
directory-fsyncing removal of the journal. The mutation journal first advances
to `verified`, and failure containment is conservatively armed before the
`prepared` transaction is published. It remains present through this complete
terminal transaction, and
is removed with a parent-directory `fsync` only after terminal adoption
succeeds. Retry adoption occurs before any
bootstrap or hosted-storage side effect and accepts only the same complete
tuple, marker, and authentication action.

The hosted verifier normally accepts no active deployment mutation,
deployment promotion, backup, or restore journal. Only the owning deploy or
restore wrapper supplies its exact internal transaction-owner flag. The deploy
owner accepts exactly the mutation journal alone during runtime verification,
or the mutation plus promotion journals during terminal publication; the
prior-rollback owner accepts only a mutation-only `rebuild` journal whose
runtime, selected configuration, current-release bytes, and release symlink are
the exact sealed prior tuple; the restore owner accepts only its restore
journal. Mutation plus promotion is accepted only when mutation phase is
`verified`. A verified mutation without a promotion journal is accepted only
for exact terminal adoption and must revalidate the complete published state.
Every other active-journal inventory is rejected. A completed deployment record is
bound to current-release and immutable release evidence. It may remain
unchanged when later operator procedures advance only the member marker from
absent to its exact digest or authentication from producer-pending to complete;
commit, configuration, archive, evidence, or any other marker/authentication
drift fails closed.

## Stable operation entrypoints

Use the protected workflows on exact current `main`; do not invoke the launcher
directly as an ordinary operator procedure:

| Operation | Workflow | Stable root wrapper |
| --- | --- | --- |
| Bootstrap or rebuild | `deploy-forums.yml` | `/usr/local/sbin/mochirii-forums-deploy` |
| Runtime verification | `verify-forums.yml` | `/usr/local/sbin/mochirii-forums-verify` |
| Application backup | `backup-forums.yml` | `/usr/local/sbin/mochirii-forums-backup` |
| Pre-rollout restore rehearsal | `restore-forums.yml` | `/usr/local/sbin/mochirii-forums-restore` |

The deployment workflow creates a secret-free `git archive`, records its
SHA-256 and byte size, and sends it to the exact protected incoming filename.
Both transfer sessions use OpenSSH protocol keepalives every 30 seconds, allow
at most ten unanswered keepalives, and retain TCP keepalive. A broken or
unresponsive transport therefore reaches the existing dispatcher containment
boundary instead of silently abandoning a long root operation.
The deploy authorized-key record uses OpenSSH `restrict` plus the exact
root-installed `ssh-deploy-dispatch.py` forced command. It has no shell, SFTP,
subsystem, forwarding, tunnel, agent, X11, or TTY surface. The dispatcher
accepts only a 64-MiB-bounded, digest-bound archive stream and the exact
`deploy`, `verify`, `backup`, and pre-rollout `restore` verbs. A deploy-owned
nonblocking lock serializes intake/operations and archive reads have a fixed
deadline. Intake uses one exact `.receive.partial` slot. HUP, INT, TERM, and
deadline exits remove and directory-fsync that slot; an uncatchable interruption
can leave only that bounded owned regular file, and the next exact `receive`
validates, removes, and directory-fsyncs it before accepting bytes. An
idempotent retry with the complete target already present hashes and discards
the exact incoming stream without creating a second on-disk archive. Every
other `SSH_ORIGINAL_COMMAND` is rejected without evaluation.

The deploy SSH key is therefore transport-only. Before executing any uploaded
Python, Ruby, shell, or configuration, the root deployer fetches only the exact
public canonical `refs/heads/main` through HTTPS with system/global Git configuration,
credential helpers, alternate protocols, and prompts disabled. It requires
that fetched commit to equal the requested commit, derives a fresh deterministic
`git archive` itself, and byte-compares that root-owned archive with the
quarantined upload. It then enforces the 64 MiB transport limit, validates
bounded safe tar members before extraction, reruns repository and online pin
checks, and rejects same-commit source byte drift.

After the launcher and ordinary host checks pass, the deployer uses the real
application upload path to create one deterministic disposable PNG, an
optimized variant, and public object ACLs. It proves custom-host anonymous
retrieval and anonymous listing denial, then repeats the read proof after a
supported restart and rebuild. It removes the exact database rows, objects,
and tombstones before promotion. Exact keys/IDs exist only in transient
root-only state. If any partial-create cleanup fails, a digest-named mode-0600
retry record is retained, deployment remains failed, and a later exact deploy
must reconcile it before another fixture. While that state exists, the stable
verifier refuses a green result and failure handling must keep the exact
loopback-only restore configuration active with non-staff mail and
DiscourseConnect disabled; it must not reopen the prior public release. If
containment cannot be proved, stop the container. The release-evidence tuple binds the
sanitized hosted-storage result, source/configuration, restore configuration,
and theme digests.

For the first deployment use `bootstrap`; without its exact mutation journal it
refuses an existing container, database, active configuration, current-release
record, or `/opt/mochirii/forums/current` target. Use `rebuild`
only after a verified backup; without exact mutation-retry authority it refuses
an absent or mismatched current-release record. Before target mutation, ordinary
failures leave the prior release unchanged. Once the mutation journal is armed,
failure stops the app and retains exact forward-retry authority. A prior
same-version rollback is admissible only while absence of target database
mutation is proved, and its distinct verification owner must re-prove the
running prior configuration, prior current-release bytes, prior release chain,
and prior `/opt/mochirii/forums/current` target. In all cases, cross-version or mutation-possible failures never launch
old code. A failed bootstrap retains
persistent state and its exact journal for
bounded replay or explicit disposal review; it never silently deletes shared
data.

If an exact bootstrap replay is prevented by a proved deployment-transport
defect, one reviewed canonical recovery commit may install only the bounded
transport repair and the governed failed-bootstrap quarantine control while the
failed release journal remains `runtime-contained`. The source-mode correction
is one exact sole-parent child of reviewed recovery commit
`1d741eb75d08a226984935aa18e989ee324a0773`; that reviewed commit must itself
have failed release `b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f` as its sole parent. The
cumulative diff from the failed release must still contain exactly the reviewed
workflow, host-control, quarantine, validation, and runbook paths. The
host-control upgrader accepts that pinned two-commit exception only when the
journal is one canonical root-owned bootstrap tuple, the application and all
publication pointers are absent, the app is stopped, PostgreSQL state is
present, and every unrelated operation journal is absent. The upgrade must
leave the mutation journal and failed runtime bytes unchanged.

The later usable-swap verifier incident has a separate, non-interchangeable
two-commit recovery chain. Failed bootstrap commit
`26e793aada31faeaa8b56308625288164430647c` is the sole parent of reviewed
usable-swap repair commit `6e2f1b5c831b992c3222c015836fa180cd591e3e`;
the recovery source must be one exact sole-parent child of that repair and the
current canonical `main`. Its cumulative diff from the failed release is
exactly `docs/operations/DEPLOYMENT.md`, `docs/operations/RECOVERY.md`,
`scripts/quarantine-failed-bootstrap.sh`, `scripts/test-contracts.py`,
`scripts/upgrade-host-control.sh`, `scripts/validate-repository.py`, and
`scripts/verify-host.sh`. The historical transport exception and this
usable-swap exception are selected only by their exact failed commit; neither
authorizes another lineage or changed-path set. The same stopped/absent
publication, retained-journal, root-owned-state, and unrelated-journal
exclusion rules apply, and the upgrade must leave the failed journal and
runtime bytes unchanged.

The primary-certificate bootstrap incident has a third, non-interchangeable
two-commit recovery chain. Failed bootstrap commit
`f564d62a82adf79b8f012a25949826e2b447681d` is the sole parent of reviewed
ACME installed-byte repair commit
`85e12f1ce27e1462e7c82e59e1dbf01c190327b9`; the recovery source must be one
exact sole-parent child of that repair and the current canonical `main`. Its
cumulative diff from the failed release is exactly
`config/immutable-letsencrypt.fragment.yml`,
`docs/operations/DEPLOYMENT.md`, `docs/operations/RECOVERY.md`,
`scripts/quarantine-failed-bootstrap.sh`, `scripts/test-contracts.py`,
`scripts/upgrade-host-control.sh`, and `scripts/validate-repository.py`.
Selection remains by exact failed commit, so this exception cannot substitute
for either earlier lineage or authorize another path set. The same retained
journal/runtime, stopped/absent publication, root-owned-state, and unrelated-
journal exclusion rules apply.

The later c2f bootstrap incident has a fourth, non-interchangeable recovery
chain. Failed bootstrap commit
`c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306` is the sole parent of reviewed
quarantine-output control repair commit
`8eea740795f0536468e48c5e8cda2ded29b1e51e`; the recovery source must be one
exact sole-parent child of that repair and the current canonical `main`. Its
cumulative diff from the failed release is exactly
`docs/operations/DEPLOYMENT.md`, `docs/operations/RECOVERY.md`,
`scripts/quarantine-failed-bootstrap.sh`, `scripts/test-contracts.py`,
`scripts/upgrade-host-control.sh`, and `scripts/validate-repository.py`.
Selection remains by exact failed commit, so this exception cannot substitute
for any earlier lineage or authorize another path set. The reviewed recovery
hardens journal validation and atomic diagnostic output; it does not claim to
identify or correct the retained c2f launcher/bootstrap cause. The same
retained-journal/runtime, stopped/absent publication, root-owned-state, and
unrelated-journal exclusion rules apply.

The later bootstrap at exact release
`fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d` is retained as a separate failed
runtime and must not be retried with identical bytes. Bounded dual-lock evidence
proved that RSA issuance and installation completed, the configured runit
`nginx` reload failed while bootstrap had only the directly started ACME nginx
master, and ECC issuance never began. The source repair uses the same absolute
`nginx -c /etc/nginx/letsencrypt.conf -s reload` signal path for initial
issuance and later renewal, instead of addressing a not-yet-running runit
service. It also creates and retains the ACME account and log as root-owned
mode-`0600` ordinary single-link files and makes terminal host verification
fail closed on metadata drift. The repair itself does not authorize a replay:
its exact commit must first be protected-merged and followed by a separate
sole-parent current-main control/quarantine lineage binding before the retained
`fae3770f...` runtime can be quarantined and a changed-byte bootstrap considered.

That fae bootstrap incident has a fifth, non-interchangeable recovery chain.
Failed bootstrap commit `fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d` is the
sole parent of reviewed ACME reload/private-state repair commit
`f51c2e8deaf39293c9b97f3aab797b882c3dc628`. Exact recovery child
`591d96484369ae29a8fa4e61219b325997f4b679` is its sole-parent child, exact
launcher-settlement child `a71bbe8070ca6dadeff3c4966e81bd97fee83cf7` is
the recovery child's sole-parent child, and the recovery source must be one
exact sole-parent child of that launcher-settlement commit and the current
canonical `main`. Its cumulative diff from the failed release is exactly
`config/immutable-letsencrypt.fragment.yml`, `docs/operations/DEPLOYMENT.md`,
`docs/operations/RECOVERY.md`, `scripts/disposable-launcher-guard.py`,
`scripts/quarantine-failed-bootstrap.sh`, `scripts/test-contracts.py`,
`scripts/test-disposable-launcher-guard.py`, `scripts/upgrade-host-control.sh`,
`scripts/validate-repository.py`, and `scripts/verify-host.sh`. Selection remains
by exact failed commit, so this exception cannot substitute for an earlier
lineage, admit another descendant, or authorize another path set. The reviewed
repair corrects the proved ACME reload and private-state metadata boundaries;
the launcher settlement corrects only the proved post-restore named-application
transition. Neither authorizes an identical-byte retry or identifies any
additional retained-runtime cause. The same retained-journal/runtime,
stopped/absent publication, root-owned-state, and unrelated-journal exclusion
rules apply.

The later bootstrap at exact release
`9110568e09bda4d572eaf2c27a768b9c053048f9` has a sixth,
non-interchangeable recovery chain for the proved ACME webroot traversal
boundary. That failed release is the sole parent of reviewed webroot repair
commit `bb891aa65ebe8470fa04cdd639185afdad7372f7`; the recovery source must be
one exact sole-parent child of that repair and the current canonical `main`.
Its cumulative diff from the failed release is exactly
`config/immutable-letsencrypt.fragment.yml`, `docs/operations/DEPLOYMENT.md`,
`docs/operations/RECOVERY.md`, `scripts/quarantine-failed-bootstrap.sh`,
`scripts/test-contracts.py`, `scripts/upgrade-host-control.sh`, and
`scripts/validate-repository.py`. Selection remains by exact failed commit, so
this exception cannot substitute for an earlier lineage, admit another
descendant or merge commit, or authorize another path set. The reviewed repair
creates and verifies only the public ACME challenge directories before the
bootstrap Nginx process; it does not authorize an identical-byte retry or
identify any additional retained-runtime cause. The same retained journal and
runtime, stopped/absent publication, root-owned state, unrelated-journal
exclusion, and evidence-preserving quarantine rules apply.

The later bootstrap at exact release
`81e5226e54246686ce0ef80051d4df2cd1b64c5e` has a seventh,
non-interchangeable recovery chain for the proved ACME certificate-material
validation boundary. That failed release is the sole parent of reviewed
material repair commit `64e12c2344fbc04d44b10c495cf9651cac5ac0b8`; exact reviewed
source-authority commit `af3540426051c94bf26e9661ac68ce8ee720f977` is the material
repair's sole-parent child; and the recovery source must be one exact
sole-parent child of that source-authority commit and the current canonical
`main`. The three exact path segments are independently bound: the material
repair changes only `config/immutable-letsencrypt.fragment.yml`,
`scripts/test-contracts.py`, and `scripts/validate-repository.py`; the reviewed
source-authority commit changes only `.gitattributes`, `.github/CODEOWNERS`,
`.github/workflows/open-reviewed-source-pr.yml`, `CONTRIBUTING.md`,
`docs/adr/0001-clean-initialization-and-canonical-ownership.md`,
`scripts/test-contracts.py`, and `scripts/validate-repository.py`; and the final
recovery child changes only the eleven reviewed recovery-control paths. Its
cumulative diff from the failed release is exactly `.gitattributes`,
`.github/CODEOWNERS`, `.github/workflows/open-reviewed-source-pr.yml`,
`.github/workflows/validate-repository.yml`, `CONTRIBUTING.md`,
`config/immutable-letsencrypt.fragment.yml`, `docs/operations/DEPLOYMENT.md`,
`docs/adr/0001-clean-initialization-and-canonical-ownership.md`,
`docs/operations/RECOVERY.md`, `scripts/check-repository.ps1`,
`scripts/check-source-introduction.ps1`, `scripts/host-deploy.sh`,
`scripts/quarantine-failed-bootstrap.sh`, `scripts/test-contracts.py`,
`scripts/test-source-introduction.ps1`, `scripts/upgrade-host-control.sh`, and
`scripts/validate-repository.py`. Selection remains by exact failed commit, so
this exception cannot substitute for an earlier lineage, admit another
descendant or merge commit, or authorize another path set. The reviewed repair
removes automatic forced reissuance and enforces a one-way
issue-validate-install sequence for RSA and then ECC, with ordered cumulative
chain, exact public-key algorithm, private diagnostic, and certificate/key
identity validation. It neither authorizes an identical-byte retry nor claims
another retained-runtime cause. The same retained journal and runtime,
stopped/absent publication, root-owned state, unrelated-journal exclusion, and
evidence-preserving quarantine rules apply.

The later bootstrap at exact release
`637a7c315574840156ac46615beb4417074088ed` has an eighth,
non-interchangeable recovery chain for the proved ACME stage-evidence boundary.
That failed release is the sole parent of reviewed stage-evidence repair commit
`9683e62abd3d0f41c41fc2a126a49eb33216c265`; the recovery source must be one
exact sole-parent child of that repair and the current canonical `main`. The
two exact path segments are independently bound: the stage-evidence repair
changes only `.github/workflows/validate-repository.yml`,
`config/immutable-letsencrypt.fragment.yml`, `scripts/check-repository.ps1`,
`scripts/check-source-introduction.ps1`, `scripts/host-deploy.sh`,
`scripts/test-contracts.py`, `scripts/test-source-introduction.ps1`,
`scripts/validate-repository.py`, and `scripts/verify-host.sh`; the final
recovery child changes only `.github/workflows/validate-repository.yml`, this
document, `docs/operations/RECOVERY.md`, `scripts/check-repository.ps1`,
`scripts/check-source-introduction.ps1`, `scripts/host-deploy.sh`,
`scripts/quarantine-failed-bootstrap.sh`, `scripts/test-contracts.py`,
`scripts/test-source-introduction.ps1`, `scripts/upgrade-host-control.sh`, and
`scripts/validate-repository.py`. The cumulative diff from the failed release
is exactly those thirteen unique paths, including the unchanged accepted stage
fragment and host verifier. Selection remains by exact failed commit, so this
exception cannot substitute for an earlier lineage, admit another descendant
or merge commit, or authorize another path set. The reviewed repair adds
durable fixed stage evidence and descriptor-held installed-material identity
validation around the unchanged RSA-then-ECC issuance order. It neither
authorizes an identical-byte retry nor claims an unproved retained-runtime
cause. The same retained journal and runtime, stopped/absent publication,
root-owned state, unrelated-journal exclusion, and evidence-preserving
quarantine rules apply.

Every direct acceptance launcher pins the exact validator or hostile-fixture
bytes before execution and invokes Python with `-I -S -B`. Both entrypoints
also reject ambiguous import paths and incompatible startup flags before any
shadowable import. The required repository workflow repeats the exact digest
binding and runs the complete hostile fixture as root in isolated, site-free
Linux, so Windows-only or non-root success cannot skip the real quarantine
transaction contract.

After that exact upgrade, use the separately authenticated operator session:

```sh
sudo /usr/local/sbin/mochirii-forums-quarantine-failed-bootstrap \
  <exact-current-main> <exact-failed-journal-commit> \
  'QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP'
```

The command takes the primary and media locks, revalidates canonical lineage,
the complete journal tuple, stopped/absent publication state, certificate
timer, and host controls, then journals its own work. It atomically renames the
complete failed `shared/standalone` tree into the root-only sibling recovery
boundary, recreates the clean standalone directory with its exact metadata,
restores only the exact ordinary `ssl` directory when present, and moves the
original mutation journal to digest-named protected evidence. It never deletes
the database, uploads, logs, certificate material, release, configuration, or
journal bytes. Crash recovery accepts only the same pending tuple and exact
partial filesystem state. Only after terminal evidence and active-journal
retirement may the keepalive-protected workflow bootstrap exact current `main`.
That deployment has a changed canonical commit, archive, installed control, and
clean runtime boundary; it is not an identical-byte retry.
An exact consumer-enabled tuple whose authentication state is already
`complete` may use the same rebuild entrypoint: the deployer deep-validates the
immutable pending/Website/complete chain, repeats the live producer-enabled
probe, preserves the complete pointer, and never rewrites pending evidence. If
the app was already proved stopped after an interrupted rebuild, the consumer
flag is derived from that sealed complete release rather than an unavailable
container before the exact public rebuild.

## Member-rollout boundary

The destructive restore rehearsal is allowed only while the root-owned
`member-rollout-enabled` marker does not exist. It must run with loopback-only
ingress, member mail suppressed, and DiscourseConnect disabled. After verified
backup, restore, restart, rebuild, and production reopen evidence exists, the
operator may run the installed stable finalizer with the exact confirmation
string documented in [RECOVERY.md](RECOVERY.md).

The finalizer creates the marker atomically, mode `0600`, and never removes it.
All later restores require a clean, separately approved recovery target; never
delete or bypass the marker on the member-serving host.

For the first `false` to `true` DiscourseConnect transition, atomically replace
the protected runtime JSON with the exact flag and shared secret, keep the
repository commit unchanged, and dispatch a `rebuild`. The deployer requires a
verified backup of the prior commit/configuration tuple and proves that the
marker names the restored pre-activation commit/configuration before accepting
the new configuration digest. It records a new immutable release-evidence file
and reseals the seven-field current-release record with the same marker digest.

## Failure and cleanup

If deployment cannot finish safely, close public/member access. Remove only
newly created empty or disposable Forums resources needed to stop unnecessary
billing, record any cost already incurred, and retain sanitized evidence.
Never delete pre-existing or imported data. Do not substitute another CDN,
storage provider, managed database, cache, volume, load balancer, or identity
provider.
