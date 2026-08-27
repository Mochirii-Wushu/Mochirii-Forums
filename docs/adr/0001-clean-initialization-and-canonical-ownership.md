# ADR 0001: Clean initialization and canonical ownership

- Status: Accepted for the local governance seed
- Date: 2026-07-29

## Context

The public `Mochirii-Wushu/Mochirii-Forums` repository is the intended canonical
source boundary for future Mōchirīī forum customizations and controlled upstream
tracking. No approved forum-source migration, provider configuration, hostname,
runtime, or deployment belongs in this initial change.

Starting with governance only avoids accidentally copying stale prototypes,
runtime state, provider details, credentials, user data, or an upstream project
without preserving its license and history correctly.

## Decision

Initialize the repository with documentation, contribution and security policy,
GitHub Actions-only dependency update configuration, and a fail-closed repository
contract. The seed contains no runnable Discourse distribution, vendored upstream
core, plugin, theme, container, `app.yml`, database, archive, binary, public copy,
or provider configuration.

The repository contract uses an explicit initial-file allowlist. Introducing a
new source category requires a focused change that updates the contract and the
relevant decision record. GitHub Actions validates the exact pull-request head
with read-only contents permission and no third-party actions.

The existing repository owner `@xartaiusx` is the code owner for every tracked
path, including CODEOWNERS and workflows. This decision requires, but does not
itself activate, protected-`main` provider settings for one fresh code-owner
approval, stale-approval dismissal, approval of the most recent reviewable push,
and no administrator bypass. Those gates remain pending until post-bootstrap
provider readback proves them. A default-branch `repository_dispatch` workflow
can create a fresh bot branch whose sole commit has current `main` as its parent
and is tree-identical to an exact reviewed source commit, then open a pull
request. It has no review, merge, ref-update, or `main`-update operation. Exact-
head CI and provider readback remain mandatory before merge.

## Future import gate

Before forum source is introduced, approve and document:

1. the canonical upstream and license;
2. whether history is preserved, mirrored, or reconstructed;
3. ownership boundaries between upstream core and Mōchirīī customizations;
4. dependency and security-update policy;
5. secret, data, and provider boundaries;
6. build, test, backup, restore, rollback, and deployment contracts; and
7. the exact provider and cost effects, if any.

## Consequences

- The repository is reviewable and safe to initialize but is not runnable.
- Passing validation proves only the source contract, not production readiness.
- No deployment or provider action follows from accepting this ADR.
- Future source work cannot silently bypass an ownership or provenance decision.
