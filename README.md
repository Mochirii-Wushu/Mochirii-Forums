# Mochirii Forums

Canonical deployment-control repository for `forums.mochirii.com`.

This repository contains the minimum non-secret configuration, immutable
upstream references, Mochirii theme, validation, deployment, backup, restore,
and rollback procedures for the officially supported Discourse Docker
standalone architecture. It does not vendor Discourse core, store runtime
secrets, or create provider resources.

## Selected release

- Discourse application: `v2026.8.0`, commit
  `badad7b0456a628e578bc48b9f8c1259422b5d58`.
- Discourse Docker: commit
  `ed9f680b0df1de28f062de1769d89d22b2644d1b`.
- Docker Manager, included by the official standalone template: commit
  `c008c3ca7fcc44775215843992e88190adb7b3bf`.

The earlier reviewed Discourse Docker commit `a3028747...` is not deployable on
the authorized one-vCPU host because its official build command evaluates to
zero Bundler jobs. The selected commit is the first official correction and is
reviewed with its five required transitive new-install commits.

## Validate

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1 -Online
```

The manual disposable-bootstrap workflow performs the official standalone
bootstrap against a loopback-only, secret-free fixture. Static validation alone
does not prove a bootstrap, deployment, provider configuration, or production
health.

## Operate

- [Deployment procedure](docs/operations/DEPLOYMENT.md)
- [Storage contract](docs/operations/STORAGE.md)
- [Validation gates](docs/operations/VALIDATION.md)
- [Backup, restore, and rollback](docs/operations/RECOVERY.md)
- [Runtime secret names](docs/operations/SECRETS.md)
- [Third-party notices](docs/operations/THIRD-PARTY-NOTICES.md)

No command in this repository authorizes provider creation or production
activation outside the current stage-specific authority packet.
