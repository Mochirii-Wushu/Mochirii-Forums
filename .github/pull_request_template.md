## Stage 4 source boundary

- [ ] This pull request changes reviewed Mochirii Forums source only; it does not authorize or claim a live deployment, provider mutation, DNS/TLS change, credential or SMTP operation, paid resource, or public activation.
- [ ] The diff contains no credential, private value, member data, database, upload, backup, certificate, runtime environment, generated `app.yml`, release archive, or provider-private evidence.
- [ ] Discourse core and `discourse_docker` remain exact external upstream references; no upstream tree, optional plugin, second deployment authority, or unsupported runtime architecture was introduced.
- [ ] Public copy, behavior, authorization, storage, recovery, and provider scope changed only where this pull request explicitly documents and tests that contract.

## Selected immutable tuple and inventory

- [ ] Forums base commit: `<full protected main SHA>`
- [ ] Candidate head commit: `<full pull request head SHA>`
- [ ] Discourse Docker: `ed9f680b0df1de28f062de1769d89d22b2644d1b`
- [ ] Discourse application: `cbf996f65aae3da1843224aa624bcd9a225931ac`
- [ ] Docker Manager: `c008c3ca7fcc44775215843992e88190adb7b3bf`
- [ ] Linux AMD64 base image: `sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48`
- [ ] The complete repository file inventory remains allowlisted; every added, removed, or renamed path is intentional and reflected in validation.
- [ ] Any upstream-drift evidence remains pull-only, binds one exact observed revision/tree/range/path inventory, and does not advance the selected runtime pin.

## Source gates for this exact head

- [ ] `pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1`
- [ ] `pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1 -Online` when upstream evidence is in scope
- [ ] `git diff --check`
- [ ] Repository allowlist, JSON shape, secret, runtime-template, theme, branding, authentication, storage, backup/restore, host-control, and hostile contract checks pass.
- [ ] Required pull-request CI is green for the candidate head commit above; links and exact result identifiers are recorded below.

Source validation result: `<PASS/FAIL and immutable run reference>`

## Disposable standalone evidence

- [ ] `.github/workflows/disposable-bootstrap.yml` passed at the candidate head commit above for every runtime-affecting change.
- [ ] The disposable result binds the exact selected tuple, one effective CPU, fixture-only loopback configuration, backup/restore, restart, rebuild, PostgreSQL, Redis, Sidekiq, theme, branding, authentication, and persistent `/shared` checks.
- [ ] The disposable job created no provider resource and is not represented as hosted or production proof.

Disposable result: `<PASS/NOT REQUIRED with reason, immutable run reference, and exact head SHA>`

## Exact-head review and merge gate

- [ ] After the final push, an accountable human reviewed this exact candidate head, its complete diff, required CI, and the current base/head relationship.
- [ ] Current branch protection or ruleset enforcement was read back; procedural review is not represented as provider-enforced protection when enforcement is absent.
- [ ] No reviewed commit was replaced, force-pushed, or merged under a different head.
- [ ] Deployment and rollback ordering, fail-closed behavior, and affected runbooks/evidence contracts are recorded for every operational change.

Exact-head review evidence: `<reviewer, exact head SHA, approval reference, and protection readback>`

## Live and provider evidence remains unverified

Record every item as `PASS`, `FAIL`, or `NOT RUN`; do not infer one lane from another.

- Hosted runtime verification: `<NOT RUN or immutable evidence reference>`
- Provider resource and scope readback: `<NOT RUN or immutable evidence reference>`
- Current pricing, subscription, quota, and fixed-cost gate: `<NOT RUN or immutable evidence reference>`
- SMTP authority and branded delivery: `<NOT RUN or immutable evidence reference>`
- DNS and TLS: `<NOT RUN or immutable evidence reference>`
- Production Spaces upload/CDN/private-backup behavior: `<NOT RUN or immutable evidence reference>`
- Production backup, isolated restore, restart, rebuild, and member rollout: `<NOT RUN or immutable evidence reference>`
- Mochirii authentication and hostile live fixtures: `<NOT RUN or immutable evidence reference>`

Unverified or failed live gates keep activation closed. Merging this source pull request grants no provider, deployment, secret, cost, DNS/TLS, SMTP, or public-release authority.
