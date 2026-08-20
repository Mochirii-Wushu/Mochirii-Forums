# Contributing

## Current repository boundary

This public repository owns the reviewed Mochirii Forums configuration, theme,
declared plugin, CI, host-control, deployment, backup, restore, verification,
and upgrade source for the dedicated Discourse host. Discourse core and
`discourse_docker` remain pinned external upstream projects; do not vendor or
fork them here.

Source review or merge does not authorize a live deployment, provider change,
DNS/TLS mutation, secret operation, paid resource, or public release. Those
actions retain the explicit approval gates in `AGENTS.md` and the operations
runbooks.

## Change discipline

1. Read `AGENTS.md`, `docs/operations/CURRENT-STATE.md`, and the runbook for the
   affected operation.
2. Start from current protected `main` and create one focused branch. Never edit
   `main` directly.
3. Preserve the exact supported upstream revisions, base-image digest,
   authentication boundary, persistent `/shared` data, and public/private
   storage split unless the change explicitly reviews that contract.
4. Add or update hostile contract coverage for every new source file, runtime
   asset, state field, command, failure transition, or authorization surface.
5. Update deployment, recovery, validation, security, and provenance
   documentation whenever their executable contract changes.
6. Run the repository source gate and inspect the complete diff:

   ```powershell
   pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1
   git diff --check
   ```

   Add `-Online` when upstream or current-main provenance is in scope.
   The disposable standalone workflow remains required for runtime-affecting changes.
7. Open a pull request that records scope, risk, exact checks, deployment and
   rollback ordering, and every unverified live gate. Obtain accountable human
   review of the final exact head before merge.

For upstream evidence changes, also follow
`docs/operations/SOURCE-PROVENANCE.md`. Monthly/manual inspection is read-only:
upstream drift is never merged or promoted automatically. Record the exact
official revision and bytes, review its source/license/security impact, update
all coordinated pins, and rerun the disposable runtime gate.

## Security-sensitive and operational changes

Changes to SSH, sudo, host control, authentication, signed-request handling,
storage ACLs, backup/restore, destructive operations, certificate automation,
or durable evidence must remain fail closed. Bind every mutation to an exact
reviewed tuple, pre-arm recovery state before side effects, bound external
processes, verify durable readback, and cover interrupted/adversarial cases.

Public copy, branding, hostnames, or member-facing behavior may be changed only
when the issue or request explicitly places it in scope. A pull request may
change source and documentation, but it may not operate the live host or a
provider.

## Exact-head review boundary

Do not assume a CODEOWNERS entry, plan feature, or repository visibility alone
enforces review. Immediately before merge, re-check the base, exact head SHA,
required CI, branch protections, and accountable human approval. Do not bypass
protections, force-push a reviewed head, or merge a different commit.

## Prohibited contributions

Do not submit credentials, tokens, private keys, cookies, member data,
databases, uploads, backups, signed URLs, provider-private identifiers,
materialized runtime JSON, `.env` files, generated `app.yml`, raw logs, recovery
artifacts, release archives, binaries, or generated evidence. Do not vendor
Discourse core, float an upstream tag/branch/image, add a general SSH shell, or
weaken authorization, privacy, containment, recovery, and exact-digest gates.

Security findings belong in the private reporting path described in
`SECURITY.md`, never in a public issue or pull-request discussion.
