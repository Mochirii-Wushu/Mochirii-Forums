# Security Policy

## Supported source

| Source line | Security status |
| --- | --- |
| Current protected `main` with the exact upstream revisions and image digest recorded in the repository | Supported for security fixes and source validation |
| Older commits, moving upstream refs, locally modified runtime assets, or unreviewed images | Unsupported |

This repository contains supported runtime, host-control, deployment, backup,
restore, and recovery source.
A green source or disposable-runtime check does not claim that a production
host exists, is patched, or is healthy; current hosted readback and a separately
authorized operation are required for those claims.

## Reporting a vulnerability

Use the repository Security tab's private vulnerability-reporting or security-
advisory workflow. If that private path is unavailable, do not open a public
issue with details: notify a repository owner without exploit material and ask
for a private channel.

Include only the minimum information needed to assess the issue: affected exact
revision, impact, prerequisites, and a safe proof of concept. Remove tokens,
cookies, member or personal data, signed URLs, provider identifiers, private
hostnames/addresses, production payloads, raw logs, backups, and recovery
material. Never test against production or a provider without explicit
target-specific authorization.

## Response targets and boundary

- Critical reports target acknowledgement within 24 hours and an immediate
  containment/coordination decision.
- High-severity reports target acknowledgement within three business days.
- Other reports are triaged as maintainer capacity permits.

These are response targets, not a promise of public disclosure or deployment.
Maintainers validate reports in an isolated environment with least privilege,
classify affected exact source/runtime tuples, and prepare a focused reviewed
change with hostile regression coverage. Emergency provider, secret, data,
host, DNS, or production actions still require explicit authority and protected
readback. Never print or copy a secret into an issue, commit, command line, CI
log, evidence record, or chat; rotate through the owning protected provider and
private recovery procedures when separately authorized.

Public disclosure occurs only after remediation and an explicit coordinated-
disclosure decision. The security record must distinguish
source validation, CI/disposable evidence, hosted verification,
provider readback, and production remediation.

## Security scope

Reports are in scope when they affect repository-owned configuration, themes or
plugins, CI provenance, forced-command SSH, account/sudo policy, host controls,
authentication and signed requests, storage/privacy boundaries, certificate
automation, deployment, backup/restore, destructive containment, or durable
evidence. Discourse core and `discourse_docker` vulnerabilities should also be
reported to their upstream security process; report the Mochirii impact here
privately when the pinned tuple is affected.

The monthly/manual upstream inspection is read-only. A notice or new upstream
revision is untrusted review input: do not execute it, move a pin, rebuild,
deploy, or mutate a provider automatically. Verify official bytes and advisory
scope, review license and compatibility, update coordinated pins in one focused
pull request, and pass the full source plus disposable-runtime gates before any
separately approved rollout.
