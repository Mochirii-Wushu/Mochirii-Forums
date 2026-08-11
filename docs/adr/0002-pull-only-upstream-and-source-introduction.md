# ADR 0002: Pull-only upstream and deferred source introduction

- Status: Accepted for the governance scaffold
- Date: 2026-07-29

## Context

Mōchirīī Forums needs a durable way to inspect the officially supported
Discourse self-hosting source without copying an unreviewed runtime into this
repository or allowing an accidental upstream push. The official Discourse
installation documentation supports Docker-based self-hosting, and the
`discourse/discourse_docker` repository is the upstream owner of that deployment
source.

The governance seed is not an installation packet. It must remain free of
runnable forum source, containers, provider settings, hostnames, secrets, user
data, and public copy.

## Decision

Use `https://github.com/discourse/discourse_docker.git` as the only configured
Git upstream and deployment-source remote. Discourse core remains a separate
immutable evidence reference, not another configured remote. A future authorized
working clone may configure the deployment source as a pull-only `upstream`
remote with:

- the exact HTTPS fetch URL;
- the nonfunctional push sentinel `disabled://upstream-push`;
- no Git URL rewrite that can transform either URL; and
- a locally verified `origin` of
  `https://github.com/Mochirii-Wushu/Mochirii-Forums.git`.

The repository records a reviewed upstream revision and hashes for a small set
of official source files. Those hashes are evidence, not vendored source and
not approval to install or execute anything. A low-frequency monthly and
manually dispatched read-only workflow may verify that exact evidence and report
upstream drift. It may not update a pin or create a branch, commit, pull request,
release, deployment, or provider change.

The local clone has exactly `origin` and `upstream`: `origin` is the push
default, `pull.ff=only`, and `upstream` uses the official HTTPS fetch URL plus
exactly one `disabled://upstream-push` push URL. Automatic tag following is
disabled and the fetch refspec maps only official `main`; exact tags are
inspected directly without importing them. This is an
accident-prevention control; authorization and review remain separate.

Any future source introduction requires a separate reviewed ADR and change that
defines the history-preservation method, exact upstream revision, license
handling, customization boundaries, runtime architecture, data and secret
ownership, backup and restore proof, rollback, security review, operating cost,
and deployment authorization.

## Consequences

- The official upstream can be inspected without becoming repository-owned
  source.
- Accidental pushes are blocked by policy and tested in an isolated fixture.
- Upstream movement is visible and requires review instead of being silently
  consumed.
- No forum runtime, provider state, cost, hostname, or public experience is
  created by this decision.

## Primary references

- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [Pinned Discourse installation documentation](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL.md)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
