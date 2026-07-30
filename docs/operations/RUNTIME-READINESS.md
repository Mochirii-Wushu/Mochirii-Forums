# Runtime Readiness Gates

This checklist defines evidence required before Mōchirīī Forums can gain
runnable source or provider configuration. It is not an installation or
deployment runbook, and it creates no runtime or recurring cost.

## Architecture and cost

- Record the supported Discourse topology, exact upstream revision, operating
  system, container engine, data volumes, mail path, ingress boundary, and
  network trust zones.
- Record the responsible owner, monthly cost ceiling, capacity assumptions,
  data residency, retention, and an approved shutdown path.
- Keep production independent of workstations and private recovery folders.
- Require an inventory of every plugin, theme, integration, external service,
  license, and update owner. The current inventory is intentionally empty in
  [customizations.v1.json](customizations.v1.json).

## Identity, secrets, and network controls

- Require least-privilege operator access, MFA, named break-glass ownership,
  and periodic access review.
- Store runtime secrets only in an approved provider secret store; keep the
  private recovery copy inside its separately governed credential boundary.
- Never place secrets in Git, images, logs, backups, browser bundles, workflow
  output, or evidence records.
- Document TLS termination, firewall allowlists, administrative access,
  outbound egress, rate limiting, denial-of-service protections, and log
  redaction before exposure.
- Verify mail authentication, bounce handling, complaint handling, abuse
  controls, and a no-send staging mode before enabling outbound email.

## Backup and restore

- Define database, uploads, configuration, and encryption-key backup scope.
- Define encrypted storage, least-privilege access, geographic placement,
  retention, immutability, and deletion rules.
- Prove scheduled backup creation and independent monitoring.
- Complete an isolated restore rehearsal at the same application version and
  verify integrity, member access boundaries, uploads, and email suppression.
- Record recovery point and recovery time objectives from measured evidence.
- Never claim backup readiness from file creation alone; a successful isolated
  restore is required.

Official Discourse guidance warns that restores overwrite destination data and
that restored environments suppress ordinary user email until explicitly
re-enabled. The exact approved runtime packet must translate that guidance into
environment-specific, rollback-safe commands.

## Upgrade and rollback

- Review upstream changes and security notices before changing a pin.
- Capture a verified pre-change backup, current source revision, configuration
  digest, image digest, and health baseline.
- Rehearse the upgrade and rollback in an isolated environment.
- Define database migration compatibility and the point after which rollback
  requires restore instead of image reversal.
- Use a bounded maintenance window, explicit stop conditions, post-change
  functional checks, and a named rollback operator.
- Retain immutable release evidence using the
  [release evidence template](release-evidence.v1.example.json).

## Monitoring and incident response

- Monitor bounded HTTP readiness, database and job health, storage capacity,
  certificate expiry, mail delivery, backup freshness, security events, and
  resource saturation without collecting unnecessary member content.
- Define alert ownership, severity, acknowledgement targets, escalation,
  evidence preservation, containment, recovery, and member-notification
  decision paths.
- Test loss of a container, database unavailability, full disk, mail failure,
  expired certificate, compromised operator credential, and restore failure.
- Keep security reports private under `SECURITY.md`; publish incident details
  only through an approved disclosure process.

## Launch acceptance

Runnable source or provider configuration remains blocked until all gates above
have accountable owners, exact evidence, rollback instructions, security and
privacy review, cost authorization, and a reviewed release decision.

## Primary references

- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [Official Discourse backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
- [GitHub repository security quickstart](https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository)
