# ADR 0001: Clean initialization and canonical ownership

- Status: Accepted for the local governance seed
- Date: 2026-07-29

## Context

The private `Mochirii-Wushu/Mochirii-Forums` repository is the intended canonical
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

CODEOWNERS remains comment-only until an existing GitHub user or team is approved.
No nonexistent team or organization placeholder is treated as an owner. Because
enforceable private-repository rulesets are not currently assumed, exact-head CI
and accountable human review are procedural merge gates.

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
