# Current State

- Recorded: 2026-08-20
- Repository: `Mochirii-Wushu/Mochirii-Forums`
- Visibility: Public
- Default branch: `main`
- Runtime state: Not created by Stage 4
- Provider state: Unchanged by Stage 4
- Deployment state: Inactive

## Source boundary

This repository is the canonical deployment-control source for Mochirii
Forums. It contains the exact external upstream pins, sanitized official
standalone template, deterministic Mochirii theme, runtime contract, validation
tools, and deployment/recovery procedures. It does not vendor or fork upstream
core and contains no runtime secret, rendered `app.yml`, database, upload,
backup, certificate, private key, or member data.

The selected empty-install baseline is:

- application `v2026.7.1` at
  `cbf996f65aae3da1843224aa624bcd9a225931ac`;
- deployment source at
  `ed9f680b0df1de28f062de1769d89d22b2644d1b`;
- Docker Manager, the sole official standalone component, at
  `c008c3ca7fcc44775215843992e88190adb7b3bf`; and
- Linux AMD64 base image at
  `sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48`.

The old deployment candidate `a3028747...` is retained only as rejected
evidence because its one-core Bundler command resolves to zero jobs. The
selected replacement includes reviewed Ruby, base-image, PostgreSQL 18, disk,
and one-core changes and is valid only for this new empty installation.
Official deployment-source `main` was separately observed on 2026-08-20 at
`ccb3ea007204c683f7177258f1f509e2fb36f82b`, ten commits ahead of the pin.
That drift is recorded but not selected; its compatibility review remains
incomplete, and the monthly/manual read-only gate stops when the observation
moves.

## Unpassed boundaries

Source files do not prove the manual disposable bootstrap, production cost,
SMTP authority, provider capacity, DNS, TLS, object-storage CDN behavior,
backup restore, authentication, or public runtime. Those remain separate
fail-closed gates in [VALIDATION.md](VALIDATION.md).

No commit, push, pull request, provider mutation, paid resource, DNS change,
certificate, credential, SMTP account, or production activation is authorized
by this state record.
