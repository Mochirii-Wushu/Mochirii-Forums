# Source Introduction Readiness

This is the cost-neutral, source-only handoff for a future supported Mōchirīī
Forums implementation. It intentionally contains no executable forum
configuration, secrets, hostnames, provider settings, user data, or deployment
commands.

## Prepared contracts

- ADR 0003 fixes the ownership and supported-topology decision boundary.
- `source-introduction.v1.json` pins the reviewed upstream evidence and records
  the permanent reviewed external-reference/no-import method that applies before
  repository-owned configuration or isolated overlays are introduced.
- `runtime-config.v1.example.json` is a redacted, fail-closed input contract.
  Every operational switch is disabled and all provider, identity, secret,
  artifact, and cost fields are unresolved. It records the official standalone
  layout, current minimum resources, persistent `/shared` boundary, SMTP,
  supported upgrade methods, health evidence, and workstation-independence
  requirements without creating a runtime. It also makes IANA
  `Asia/Singapore` the sole future business/calendar/display/scheduler authority,
  requires offsets to be derived for the rendered instant, preserves UTC
  storage/protocol/audit instants, and leaves effective runtime verification
  false. Pinned core does not itself enforce a universal display zone, so no
  supported implementation or browser proof is claimed by this packet.
- `backup-restore-contract.v1.json` requires encrypted backups, independent
  freshness monitoring, same-version isolated restore, suppressed mail, data
  integrity, measured recovery objectives, and rehearsed rollback.
- `third-party-components.v1.json` separates the GPL-2.0-or-later application
  from the MIT deployment tooling, keeps the compatible core revision unset,
  records the supported `v2026.7.1` ESR annotated tag object, peeled commit,
  commit tree, unsigned status, and exact notice hashes as an observation rather
  than a runtime selection, records no approved plugin, theme or integration,
  and requires a complete dependency SBOM, license review and release notice
  artifact.
- `upstream-provenance.v1.json` pins the official one-line installer, setup
  wizard, launcher, standalone sample, and license. The installer remains
  non-executable because its transitive inputs and setup-wizard image are not
  immutable in this packet.
- `forum-central-identity.consumer.v1.json` fixes the supported built-in
  DiscourseConnect consumer architecture and Website producer handback. Every
  endpoint, secret, compatibility result, rollback field, and activation gate
  remains unresolved or false; no custom core plugin is allowed.
- `repository-capabilities.v1.json` records the private, empty, Free-plan origin
  and does not claim unavailable private rulesets, protected environments,
  CODEOWNERS enforcement, or review enforcement.
- `check-source-introduction.ps1` rejects any attempt to turn these proposal
  records into an activated or secret-bearing configuration.

## Still blocked by accountable decisions

1. Select compatible supported core and deployment revisions under the permanent
   external-reference/configuration-overlay boundary; complete license and
   trademark review without weakening the recorded upstream notices.
2. Approve named runtime, backup, incident, and release owners.
3. Approve a provider, region, hostname, SMTP path, selected capacity meeting
   the minimum resource and 2 GiB swap contract, and monthly cost ceiling.
4. Approve a secret store and administrative access model with MFA and
   least-privilege controls.
5. Approve any plugin, theme, integration, or public copy before it is added.
   Plugin revisions and compatibility must be reviewed; theme source must
   remain isolated and separately updatable through the supported theme model.
6. Approve an isolated candidate environment for image, backup, restore,
   upgrade, rollback, security, accessibility, recovery, and effective
   application/scheduler timezone verification.
7. Approve production only from an immutable reviewed release after all evidence
   fields are complete.
8. Complete the Website-owned versioned DiscourseConnect producer artifact,
   producer tests, cross-repository fixture, consumer tests, rollback window,
   and exact merge/deployment order before enabling central identity.
9. Wait for a supported upstream default-preserving central display-zone hook,
   then separately approve, inventory, and license-review one isolated
   Mōchirīī GPL-2.0-or-later plugin that selects only `Asia/Singapore` and binds
   core, Local Dates, Calendar, Chat, email, and jobs. A host zone, setting,
   theme-only change, monkeypatch, or core UTC baseline is insufficient. Prove
   conflicting browser/user zones, anonymous/authenticated paths, current and
   historical instants, and unchanged UTC storage/wire/audit values.

## Release sequence after approval

1. Introduce only exact reviewed configuration/overlay boundaries in a focused
   pull request; never vendor Discourse core or `discourse_docker`.
2. Bind the installer, setup-wizard image, deployment source, core source, and
   every plugin to immutable reviewed revisions and digests.
3. Build an immutable image with an SBOM and provenance; record its digest.
4. Create an unpublished candidate with outbound mail and public exposure off.
5. Complete the isolated backup/restore and rollback rehearsals.
6. Run functional, authorization, accessibility, security, recovery, and
   observation checks.
7. Present a separate production packet with exact commands, readback, stop
   conditions, cost, and rollback.

No step in this document authorizes a GitHub or provider mutation.
