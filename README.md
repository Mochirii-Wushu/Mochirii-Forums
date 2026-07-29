# Mōchirīī Forums

Private canonical repository for the future Mōchirīī forums source boundary.

This initial state contains governance and validation only. It intentionally has
no runnable forum software, public experience, hostname, provider integration,
deployment configuration, database, secret, binary, or vendored upstream core.

## Current contents

- repository contribution and security boundaries;
- a clean-initialization ownership decision;
- a fail-closed source contract;
- least-privilege GitHub Actions validation; and
- GitHub Actions-only dependency update configuration.

See [the current state](docs/operations/CURRENT-STATE.md) and
[ADR 0001](docs/adr/0001-clean-initialization-and-canonical-ownership.md) before
adding source.

## Validate locally

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1
```

Passing local validation does not authorize a merge, deployment, provider
change, or public release.
