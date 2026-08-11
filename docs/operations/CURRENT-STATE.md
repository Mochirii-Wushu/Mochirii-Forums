# Current State

- Recorded: 2026-08-11
- Repository: `Mochirii-Wushu/Mochirii-Forums`
- Visibility target: Private
- Runtime state: None
- Provider state: Unchanged
- Deployment state: None

## Verified local scope

This branch contains only repository governance, documentation, validation, and
reviewed source-provenance evidence. It intentionally contains no runnable
Discourse source, vendored upstream core, plugin, theme, `app.yml`, hostname,
public copy, provider setting, secret, database, archive, binary, deployment, or
paid resource.

The validation workflow uses read-only repository permission, fetches and verifies
the exact event head, persists no credentials, and invokes the fail-closed local
contract. The upstream workflow uses `actions/checkout` v7.0.1 at immutable
commit `3d3c42e5aac5ba805825da76410c181273ba90b1` with persisted credentials
disabled.

ADR 0002 records the official `discourse/discourse_docker` repository as a
pull-only upstream. This local clone now fetches only official `main`, follows
no tags, has exactly one inert `disabled://upstream-push`, uses `origin` as its
push default, and permits only fast-forward pulls. The exact evidence manifest pins revision
`a3028747c5b7774f49a3b110221d96ca2b3f340d` and five file hashes without
copying upstream bytes. Local tests prove the remote
policy rejects pushes, URL rewrites, and extra remotes in an isolated fixture.
The monthly/manual inspection workflow has no write permission and reports
upstream drift without promoting it. Its native timezone-aware schedule requests
22:17 on day 3 in IANA `Asia/Singapore` (`17 22 3 * *`); no manual offset is an
authority, and provider delivery is not an exact-time SLA.

Read-only GitHub readback on 2026-08-11 confirmed that the origin is private,
its Git repository is empty, its configured default-branch name is `main`, no
`refs/heads/main` default-branch ref exists, and it belongs to the Free
organization plan. Consequently the checked-in monthly workflow is a future
contract and cannot run until an explicitly authorized empty-main bootstrap
places it on `main`. Both the classic branch-protection and rulesets API
readbacks returned 403 with the plan-upgrade/public message. Private branch
protection, private rulesets,
protected-environment approval, CODEOWNERS enforcement, and required review are
therefore not claimed. Exact-head CI and accountable human review remain
procedural gates; `repository-capabilities.v1.json` keeps bootstrap and paid-plan
approvals false. GitHub Free currently includes 2,000 Actions minutes per month
and 500 MB artifact storage. These workflows publish no artifact/cache, but
private push, pull-request, Dependabot-triggered, manual, and scheduled runs all
consume the organization's shared Actions minutes; without billing/budget
readback, the packet does not claim guaranteed zero incremental cost.

ADR 0003 adds a cost-neutral source-introduction proposal. Its redacted runtime,
backup, isolated-restore, and rollback contracts remain non-runnable and fail
closed. No upstream source, executable configuration, host, hostname, provider,
secret, public surface, or recurring cost has been introduced.

The current `backup-restore-contract.v1.json` bytes were pre-existing,
user-owned working-copy work when this Forums source repair began; this lane did
not edit them. Root review accepted SHA-256
`797227459ba5c6072ef35df5187f8288e8eb53bc468323e1bdf492031222b877` as a
separate prerequisite because its standalone topology, off-host/digest/freshness,
clean-host/same-revision, post-reboot/workstation-off, and rollback gates are
causal to online readiness. The checker binds those exact bytes. Any later
commit approval must name their inclusion separately from this lane's authored
changes.

The runtime contract now records the supported standalone layout, persistent
`/shared` boundary, current official minimum resources, 2 GiB swap gate,
SMTP/no-send requirements, supported upgrade paths, health evidence, and
workstation-off acceptance. The official installer checksum is recorded, but
execution stays blocked because its transitive inputs and setup-wizard image
are not immutable in this packet.

The third-party inventory distinguishes the official GPL-2.0-or-later
application from the pinned MIT deployment tooling. It records no approved
plugin, theme, integration or public upstream mark. The compatible application
revision, complete dependency graph, SBOM, notice artifact, license review and
trademark review remain unresolved release gates rather than inferred facts.
The official release index identified `v2026.7.1` as a supported ESR released
2026-07-31 with planned end of support 2027-03-30. The unsigned annotated tag
object is `11c70a765e46c3229d66e108883fa2d33f5d0b81`; it peels to the separate
unsigned commit `cbf996f65aae3da1843224aa624bcd9a225931ac` and tree
`0aeceebe79c4d2da8cf0fab213514335c201bfa7`. Exact license, copyright, and
README byte hashes are recorded. This observation is deliberately not selected
for runtime.

The deployment pin remains byte-valid at
`a3028747c5b7774f49a3b110221d96ca2b3f340d`; GitHub reports its commit
signature verified with reason `valid`. A read-only fetch on 2026-08-11
observed official `discourse_docker` main at
`e6d7b508b43f9610950166f53cb1be1bd78435a9`, 11 commits ahead and zero behind
the pin; GitHub reports that commit signature verified with reason `valid` too.
The recorded material-change list is deliberately notable rather than all 11
commit subjects. It includes base-image and Debian trixie changes, PostgreSQL 18
dump/restore plus free-space and all-database fixes, the single-core CPU fix,
distro Redis/nginx changes, and Redis log-directory handling. The PostgreSQL 18
path changes locale to
builtin `C.UTF-8`, temporarily needs the old database, new database, and dump,
checks roughly three database sizes of free space, and retains old files under
`/shared/postgres_data_old`. Therefore the generic 10 GiB upstream minimum is
not production sizing evidence; exact data-size capacity and an isolated
restore/upgrade rehearsal remain gates. Drift is recorded for review and is not
an automatic pin advance or runtime selection.

The permanent repository ownership model is configuration and isolated overlays
only; Discourse core and `discourse_docker` stay external and are never vendored.
The built-in DiscourseConnect consumer is the supported central-identity path.
Website remains the shared-identity producer. The versioned consumer proposal
records the unresolved Website handback gaps and keeps endpoints,
secret references, compatibility evidence, rollback window, activation, public
exposure, and provider mutation unresolved or false. No custom core plugin is
allowed.

The intended contract requires every Mōchirīī business date, calendar boundary,
display, and schedule to use the sole IANA authority `Asia/Singapore`, with the
displayed offset derived for the specific instant. Storage, protocol, wire,
audit, and log timestamps remain UTC. No fixed-offset or manually maintained
display authority remains in the source-only contract.

That intended display contract is not implemented or proven by this packet.
Pinned Discourse core can choose browser- or user-selected zones for local-date
rendering, Calendar can fall back to the browser zone, and the built-in
local-dates settings contain non-Singapore human-facing defaults. A host zone or
the Rails UTC baseline does not close this gap. A theme-only change or monkeypatch
cannot cover server, email, jobs, and all client surfaces. Activation remains
blocked pending a supported upstream central resolver, followed by a separately
approved and inventoried GPL-2.0-or-later Mōchirīī plugin that selects only
`Asia/Singapore`, normalizes conflicting user zone writes, and is tested across
core, Local Dates, Calendar, Chat, email, current, conflicting-user, and
historical paths without changing UTC storage/wire/audit instants. No plugin or
runtime source is introduced here.

## Review boundary

CODEOWNERS has no matching rule because no existing user or team has been approved.
Current private-Free readback does not expose enforceable private-repository
rulesets. Exact-head CI and accountable human review are therefore required
procedural gates before any merge.

## Remaining separately approved decisions

Before introducing runnable forum configuration, approve the exact external
core/deployment revisions and configuration/overlay boundary proposed by ADR
0003. Website must first deliver the versioned producer artifact and tests in a
separate repository change. Before adding runtime or provider configuration,
close every gate in `RUNTIME-READINESS.md`, including
ownership, cost, security, secrets, email, backup, isolated restore proof,
upgrade, rollback, monitoring, and incident response.

This state record does not authorize a commit, push, pull request, GitHub setting
change, source import, deployment, or provider mutation.

## Current provider references

- [GitHub included usage by plan](https://docs.github.com/en/billing/reference/product-usage-included)
- [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
