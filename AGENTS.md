# Mochirii Forums Repository Guidance

This private repository is the future canonical source owner for Mōchirīī forum
customizations and controlled upstream tracking. It currently contains only a
governance seed. It does not contain a runnable forum, a deployment, or provider
configuration.

## Required workflow

- One bootstrap exception exists for the live repository while it has no
  `main` ref: this exact reviewed governance seed may be first-pushed to empty
  `main` only under an explicit bootstrap authorization. This file does not
  grant that authorization. After `main` exists, every change uses a focused
  branch and pull request.
- Start with `git status --short --branch` and preserve all existing work.
- Use one focused branch and pull request per causal change.
- Run `pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1` before handoff.
- Record the exact base and head SHA before review and again before merge.
- Require accountable human review of the final exact head. Repository rulesets
  are not assumed to be enforceable on the current private-repository plan.
- Keep commits, pull requests, documentation, and source Mōchirīī-owned. Git
  author identity may remain only in Git and GitHub audit metadata.

## Hard boundaries

- Never commit credentials, tokens, private keys, environment files, database
  exports, user content, archives, binaries, generated runtime state, or logs.
- Do not add runnable Discourse source, vendored upstream core, `app.yml`,
  containers, plugins, themes, provider settings, hostnames, or public copy until
  a separately reviewed ownership and implementation packet authorizes them.
- Source-only ADRs, redacted non-runnable examples, validation contracts, and
  backup/restore/rollback evidence schemas are allowed when every activation,
  provider, secret, public-exposure, mail, and paid-resource field fails closed.
- The only remotes are canonical `origin` and the pull-only official
  `discourse/discourse_docker` upstream documented by ADR 0002. The upstream
  fetch URL remains enabled for official `main` only, automatic tag following
  is disabled, its sole push URL is `disabled://upstream-push`, `origin` is the
  push default, and pulls are fast-forward-only. Never add a Git URL rewrite,
  automatic pin update, or vendored upstream bytes.
- Keep upstream inspection read-only. The approved low-frequency monthly
  schedule and manual dispatch may report drift, but may never update a pin,
  create a branch or pull request, promote a release, or mutate a provider.
- Do not deploy, publish, create paid resources, or mutate GitHub or any provider
  from this repository without exact authorization.
- Keep production independent of any workstation and private recovery folder.
- Do not weaken the repository contract to make an unrelated change pass.

## Future source introduction

Discourse core and `discourse_docker` are permanent external upstream owners;
this repository remains configuration/overlay-only and never imports or vendors
their source trees. Before adding runnable Mōchirīī configuration, a theme, or
another customization, update the ownership ADR and repository contract in a
focused reviewed pull request. Record origin, license, exact immutable revision,
update policy, rollback boundary, and validation. Close the architecture,
security, identity, cost, backup, isolated restore, monitoring,
incident-response, and release-evidence gates in `docs/operations` before adding
runtime or provider configuration.

ADR 0003 and its source-only contracts prepare that review packet but do not
authorize source import, installation, provider configuration, or billing.
