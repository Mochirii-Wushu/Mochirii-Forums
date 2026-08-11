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

1. The only configured Git upstream-source remote is official
   `discourse/discourse_docker`; it fetches moving `main` only for reviewed drift
   observation. The deployment-tooling evidence/runtime-candidate pin is the
   exact revision recorded in `upstream-provenance.v1.json`. The application
   source is the official Discourse core repository recorded in
   `third-party-components.v1.json`; its compatible exact runtime selection
   remains deliberately null until reviewed. The supported `v2026.7.1` ESR
   annotated tag object and its separately recorded peeled commit are current
   evidence, not a runtime selection. No moving branch or mutable image tag is
   an acceptable release input.
2. Upstream application and deployment source is never vendored into this
   repository. The permanent ownership model is Mōchirīī configuration and
   isolated overlays only, with immutable external upstream references and
   preserved license/notice evidence.
3. Repository-owned customizations must remain isolated from upstream core and
   enumerated in `customizations.v1.json` before they can be enabled.
4. Runtime configuration is represented only by the redacted, non-runnable
   contract in `runtime-config.v1.example.json`. It references the supported
   standalone `containers/app.yml` and persistent `/shared` layout without
   committing runtime YAML. Secrets remain null and all mail, public exposure,
   jobs, and deployment switches remain disabled.
5. A release cannot become runtime-ready until its exact source commit, tree,
   upstream revision, image digest, SBOM, provenance, configuration digest,
   backup, isolated restore, and rollback evidence are complete.
6. Central identity uses Discourse's built-in DiscourseConnect consumer. The
   Website repository remains the shared-identity producer. This repository
   owns only a versioned fail-closed consumer contract; it does not duplicate
   the producer, introduce a custom core plugin, or activate identity settings.
7. The future supported production topology is a dedicated single-host
   installation following the official cloud-install model. It requires a
   separately approved provider, cost ceiling, hostname, email path, backup
   destination, monitoring owner, and incident-response owner. The current
   minimum gate is one CPU core, 1 GiB memory with 2 GiB swap, and 10 GiB disk;
   final capacity must also pass clean rebuild, restore, reboot, and load
   evidence.
8. Production must run independently of local workstations and private recovery
   folders. Provider secret stores are the runtime source; private recovery
   material remains outside Git and is never read by repository checks.
9. The application and deployment repositories retain their GPL-2.0-or-later
   and MIT license boundaries. Every plugin, theme, integration and complete
   dependency graph must be inventoried with license and notice evidence before
   it can enter a release. Official Discourse marks remain unused unless a
   separate trademark review approves their exact public presentation.
10. The reviewed `install-discourse` checksum is evidence only. Direct
   network-to-privileged-shell execution remains prohibited, and its moving
   Git branch, Docker installer, and setup-wizard image must be independently
   pinned before any installation can be approved.
11. `Asia/Singapore` is the sole future business/calendar/display/scheduling
    authority while storage, protocol and audit instants remain UTC. Pinned core
    does not itself expose one supported site-wide display-zone hook. A setting,
    theme-only change, host zone, or monkeypatch is insufficient. Activation
    therefore waits for an upstream default-preserving central resolver and then
    a separately approved, isolated GPL-2.0-or-later Mōchirīī plugin that selects
    only `Asia/Singapore`, normalizes conflicting user writes, binds core/Local
    Dates/Calendar/Chat/email/jobs, and passes current, user-conflict, historical,
    and unchanged-UTC evidence. No such plugin is introduced by this packet.

## Rejected alternatives

- Tracking a moving upstream branch as a release input.
- Vendoring or forking upstream core in the Mōchirīī repository.
- Implementing central identity as a custom Discourse core plugin.
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

- [Pinned official Discourse Docker source](https://github.com/discourse/discourse_docker/tree/a3028747c5b7774f49a3b110221d96ca2b3f340d)
- [Observed Discourse v2026.7.1 GPL license](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/LICENSE.txt)
- [Observed Discourse v2026.7.1 copyright and registered-mark notice](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/README.md#copyright--license)
- [Official release support index](https://releases.discourse.org/)
- [Pinned cloud installation guidance](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL-cloud.md)
- [Official Discourse brand guidance](https://www.discourse.org/brand)
- [Pinned Discourse plugin API source](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/frontend/discourse/app/lib/plugin-api.gjs)
- [Official versioned client plugin API guidance](https://meta.discourse.org/t/a-versioned-api-for-client-side-plugins/40051)
- [Official theme-component versus plugin guidance](https://meta.discourse.org/t/theme-component-v-plugin-whats-the-difference/153951/3)
- [Official backup and restore guidance](https://meta.discourse.org/t/create-download-and-restore-a-backup-of-your-discourse-database/122710)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
