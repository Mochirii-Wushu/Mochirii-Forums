# Current State

- Recorded: 2026-07-29
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
contract. No third-party GitHub Action is used.

ADR 0002 records the official `discourse/discourse_docker` repository as a
future pull-only upstream. The exact evidence manifest pins one revision and
four file hashes without copying upstream bytes. Local tests prove the remote
policy rejects pushes, URL rewrites, and extra remotes in an isolated fixture.
The manual inspection workflow has no schedule or write permission and reports
upstream drift without promoting it.

## Review boundary

CODEOWNERS has no matching rule because no existing user or team has been approved.
Private-plan ruleset enforcement is not assumed. Exact-head CI and accountable
human review are therefore required procedural gates before any merge.

## Remaining separately approved decisions

Before introducing forum software, approve the exact history-preservation and
source-introduction packet described by ADR 0002. Before adding runtime or
provider configuration, close every gate in `RUNTIME-READINESS.md`, including
architecture, ownership, cost, security, secrets, email, backup, isolated
restore proof, upgrade, rollback, monitoring, and incident response.

This state record does not authorize a commit, push, pull request, GitHub setting
change, source import, deployment, or provider mutation.
