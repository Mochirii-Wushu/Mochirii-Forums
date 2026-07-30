# ADR 0003: Supported source-introduction packet

- Status: Proposed; source-only and not authorized for execution
- Date: 2026-07-30

## Context

ADR 0002 established a pull-only relationship with the official deployment
source and prohibited an unreviewed runtime import. The remaining cost-free work
is to define exactly how a future reviewed source introduction would be owned,
validated, operated, restored, and rolled back without creating a host or
making this workstation part of production.

## Decision

Prepare a source-only implementation packet with these boundaries:

1. The only upstream is the exact revision recorded in
   `upstream-provenance.v1.json`. No moving branch or mutable image tag is an
   acceptable release input.
2. Upstream application and deployment source is not vendored into this
   repository by this packet. A later reviewed change must choose and document
   a history-preserving import method before adding source bytes.
3. Repository-owned customizations must remain isolated from upstream core and
   enumerated in `customizations.v1.json` before they can be enabled.
4. Runtime configuration is represented only by the redacted, non-runnable
   contract in `runtime-config.v1.example.json`. Secrets remain null and all
   mail, public exposure, jobs, and deployment switches remain disabled.
5. A release cannot become runtime-ready until its exact source commit, tree,
   upstream revision, image digest, SBOM, provenance, configuration digest,
   backup, isolated restore, and rollback evidence are complete.
6. The future supported production topology is a dedicated single-host
   installation following the official cloud-install model. It requires a
   separately approved provider, cost ceiling, hostname, email path, backup
   destination, monitoring owner, and incident-response owner.
7. Production must run independently of local workstations and private recovery
   folders. Provider secret stores are the runtime source; private recovery
   material remains outside Git and is never read by repository checks.

## Rejected alternatives

- Tracking a moving upstream branch as a release input.
- Vendoring the entire upstream history without an approved preservation plan.
- Committing an executable `app.yml`, hostname, email credentials, database
  dump, or provider-specific bootstrap command before the operating packet is
  approved.
- Treating backup creation as restore proof.
- Using a local workstation as a production service, scheduler, queue, backup,
  or recovery dependency.

## Consequences

This packet closes the architecture and evidence-design work that can be done
without cost or provider mutation. It does not install forum software, create a
Droplet, configure email or DNS, publish a site, or authorize secrets. Those
remain explicit review and billing gates.

## Primary references

- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [Official cloud installation guidance](https://github.com/discourse/discourse/blob/main/docs/INSTALL-cloud.md)
- [Official backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
