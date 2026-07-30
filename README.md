# Mōchirīī Forums

Private canonical repository for the future Mōchirīī forums source boundary.

This state contains governance and a fail-closed source-introduction proposal.
It intentionally has no runnable forum software, public experience, hostname,
provider integration, deployment configuration, database, secret, binary, or
vendored upstream core.

## Current contents

- repository contribution and security boundaries;
- clean-initialization and pull-only upstream ownership decisions;
- a fail-closed source contract;
- exact upstream provenance and empty customization manifests;
- cost-neutral runtime-readiness and release-evidence gates;
- least-privilege GitHub Actions validation;
- an unscheduled, read-only upstream inspection workflow; and
- GitHub Actions-only dependency update configuration.

See [the current state](docs/operations/CURRENT-STATE.md) and
[ADR 0001](docs/adr/0001-clean-initialization-and-canonical-ownership.md) before
[ADR 0002](docs/adr/0002-pull-only-upstream-and-source-introduction.md)
before adding source. The [source-provenance policy](docs/operations/SOURCE-PROVENANCE.md)
and [runtime-readiness gates](docs/operations/RUNTIME-READINESS.md) define what
must be reviewed first. The
[source-introduction packet](docs/operations/SOURCE-INTRODUCTION-READINESS.md)
records the remaining decisions without creating a runtime or cost.

## Validate locally

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1
```

Passing local validation does not authorize a merge, deployment, provider
change, or public release.

The `inspect-forums-upstream` workflow is manual-only. It verifies the pinned
official bytes and fails when upstream `main` moves; it never updates the pin
or writes repository/provider state.
