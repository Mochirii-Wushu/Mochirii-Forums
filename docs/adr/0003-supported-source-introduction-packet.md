# ADR 0003: Supported source-introduction packet

- Status: Superseded by ADR 0004
- Date: 2026-07-30
- Superseded: 2026-08-14

## Historical context

This proposal described the evidence and ownership gates that existed before a
runnable release was selected. It deliberately did not authorize installation,
provider state, credentials, DNS, SMTP, public exposure, or paid resources.

ADR 0004 and the current operations contracts supersede every runtime choice in
this proposal. Do not use this document as an installation, pin, plugin,
storage, identity, capacity, or provider procedure.

## Preserved decisions

The following repository boundaries remain current:

- Discourse core and `discourse/discourse_docker` stay external and pull-only;
- this repository owns only reviewed configuration, theme, validation,
  deployment control, backup, restore, rollback, and provenance;
- no moving branch, mutable tag, vendored core, raw-source installation, or
  workstation dependency is a release input;
- secrets, rendered runtime configuration, databases, uploads, backups, and
  private recovery material remain outside Git; and
- required upstream license and copyright evidence remains preserved.

## Current authority

Use [ADR 0004](0004-authorized-standalone-deployment.md) and the manifests in
`docs/operations` for the exact selected Discourse Docker, core, Docker Manager,
and base-image revisions. The current architecture permits no optional plugin,
uses one bucket with a private `backups/` prefix, and remains provider-free
until the explicit Stage 5 gates pass.

## Historical references

- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [Pinned Discourse license](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/LICENSE.txt)
- [Pinned Discourse copyright notice](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/README.md#copyright--license)
- [Official cloud installation guidance](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/INSTALL-cloud.md)
