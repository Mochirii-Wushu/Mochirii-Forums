# Source Provenance and Remote Policy

## Ownership boundary

`Mochirii-Wushu/Mochirii-Forums` owns only Mochirii configuration, theme,
validation, and operations material. Official application and deployment
source remain external; this repository neither vendors nor forks them.

The immutable selections are recorded in
`upstream-provenance.v1.json` and `third-party-components.v1.json`:

| Component | Exact selection |
| --- | --- |
| Application | `cbf996f65aae3da1843224aa624bcd9a225931ac` |
| Deployment source | `ed9f680b0df1de28f062de1769d89d22b2644d1b` |
| Docker Manager | `c008c3ca7fcc44775215843992e88190adb7b3bf` |
| Base image, Linux AMD64 | `sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48` |
| Vendored acme.sh | `3.0.6`, commit `b7caf7a0165d80dd1556b16057a06bb32025066d`, source SHA-256 `400d1a96ef72a1f27fe79c7f0e6d4e4f600c0509c0cd787db00931b9258c54da` |
| Required first-party mail metadata component | exact `plugins/mochirii_email_metadata/plugin.rb` bytes in the Forums commit |

The selected deployment revision is the first official correction for the
one-core Bundler path. It is six commits after the rejected candidate and also
selects reviewed Ruby, base-image, PostgreSQL 18, and disk-calculation changes.
It is approved only for a new empty installation; it is not evidence that a
database upgrade or import is safe.

## Pull-only upstream

The only deployment-source remote is
`https://github.com/discourse/discourse_docker.git`. In a reviewed local clone,
`upstream` fetches official `main` for drift observation, follows no tags, and
has the single inert push URL `disabled://upstream-push`. `origin` remains the
push default and pulls are fast-forward only.

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/configure-upstream.ps1 -Apply
pwsh -NoLogo -NoProfile -File ./scripts/verify-upstream-policy.ps1 -RequireReachable
pwsh -NoLogo -NoProfile -File ./scripts/verify-upstream-provenance.ps1 -Online -RequireCurrentMain
```

The sentinel prevents accidents; it does not replace GitHub authorization or
review. The read-only inspection workflow may report drift but cannot update a
pin, commit, branch, pull request, release, deployment, or provider resource.

The repository-owned mail metadata component is not an optional third-party
plugin or a core fork. It uses the supported delivery-interceptor boundary to
remove only the exact pinned application identity headers before SMTP. Its
source and runtime bytes are bound to the exact Forums release commit and
recorded digest, and it never rewrites member-authored subjects or bodies.

The one deliberate vendored utility is the exact reviewed acme.sh client used
for Forums HTTPS. Its compressed repository payload, decoded source, upstream
commit/tree/signature, and GPL license are independently bound in the
third-party manifest and online gate. The local immutable TLS integration
never downloads executable source during bootstrap, disables acme.sh automatic
updates, and requires a separate compatibility review to change any byte or
revision.

The 2026-08-20 bounded observation records official `main` at
`ccb3ea007204c683f7177258f1f509e2fb36f82b`, ten commits ahead of the
selected revision with no commits behind it. The manifest binds the exact main
tree, commit signatures, comparison counts, ordered range, and complete changed
path inventory. That range includes deployment launcher/template, PostgreSQL,
Redis, Debian base, browser-key, mutable base-image, development-image
PostgreSQL 15, and web-template ownership-optimization changes across the same
20 paths. None of those ten commits is selected for this runtime, and
compatibility review remains a separate incomplete change. The monthly/manual
inspection fails closed if the official reference or any recorded comparison
evidence moves; it never advances the selected revision.

## Pin-change procedure

Any pin change is a separate compatibility change. Verify exact official
bytes, commit/tree identity, action and image digests, license/notice effects,
template semantics, application/plugin compatibility, one-core bootstrap,
rebuild, backup restore, and public branding before selection. Never promote a
moving branch or tag because drift exists.

## Primary references

- [Selected deployment source](https://github.com/discourse/discourse_docker/tree/ed9f680b0df1de28f062de1769d89d22b2644d1b)
- [Selected application source](https://github.com/discourse/discourse/tree/cbf996f65aae3da1843224aa624bcd9a225931ac)
- [Official one-core correction](https://github.com/discourse/discourse_docker/commit/ed9f680b0df1de28f062de1769d89d22b2644d1b)
- [Official release support index](https://releases.discourse.org/)
