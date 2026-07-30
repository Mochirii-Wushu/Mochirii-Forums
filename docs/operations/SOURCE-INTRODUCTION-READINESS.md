# Source Introduction Readiness

This is the cost-neutral, source-only handoff for a future supported Mōchirīī
Forums implementation. It intentionally contains no executable forum
configuration, secrets, hostnames, provider settings, user data, or deployment
commands.

## Prepared contracts

- ADR 0003 fixes the ownership and supported-topology decision boundary.
- `source-introduction.v1.json` pins the reviewed upstream evidence and requires
  a separately reviewed history-preservation method before source is imported.
- `runtime-config.v1.example.json` is a redacted, fail-closed input contract.
  Every operational switch is disabled and all provider, identity, secret,
  artifact, and cost fields are unresolved.
- `backup-restore-contract.v1.json` requires encrypted backups, independent
  freshness monitoring, same-version isolated restore, suppressed mail, data
  integrity, measured recovery objectives, and rehearsed rollback.
- `check-source-introduction.ps1` rejects any attempt to turn these proposal
  records into an activated or secret-bearing configuration.

## Still blocked by accountable decisions

1. Select the exact history-preservation method and review the upstream license
   and source boundary.
2. Approve named runtime, backup, incident, and release owners.
3. Approve a provider, region, hostname, email path, and monthly cost ceiling.
4. Approve a secret store and administrative access model with MFA and
   least-privilege controls.
5. Approve any plugin, theme, integration, or public copy before it is added.
6. Approve an isolated candidate environment for image, backup, restore,
   upgrade, rollback, security, accessibility, and recovery verification.
7. Approve production only from an immutable reviewed release after all evidence
   fields are complete.

## Release sequence after approval

1. Introduce only the exact reviewed source and customization boundaries in a
   focused pull request.
2. Build an immutable image with an SBOM and provenance; record its digest.
3. Create an unpublished candidate with outbound mail and public exposure off.
4. Complete the isolated backup/restore and rollback rehearsals.
5. Run functional, authorization, accessibility, security, recovery, and
   observation checks.
6. Present a separate production packet with exact commands, readback, stop
   conditions, cost, and rollback.

No step in this document authorizes a GitHub or provider mutation.
