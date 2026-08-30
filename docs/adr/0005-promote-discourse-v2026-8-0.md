# ADR 0005: Promote Discourse core to v2026.8.0

- Status: Accepted for exact-source deployment
- Date: 2026-08-30

## Context

Discourse `v2026.8.0` is the current official monthly `release`. The
previously selected `v2026.7.1` belongs to the supported `2026.7` ESR line,
whose current patch as of this ADR date is `v2026.7.2`. Discourse's deprecated
`stable` alias points to `esr`, not to the monthly `release` channel, so
`v2026.7.1` no longer satisfies the requirement to deploy the current monthly
release.

The application core is external and immutable in this repository. Promotion
therefore requires an exact annotated tag, commit, tree, byte manifest, and
semantic review rather than a moving branch or vendored source import.

## Decision

1. Select official annotated tag `v2026.8.0`, tag object
   `ac9de1e10018989468ded7fe40d71fe009d97632`, application commit
   `badad7b0456a628e578bc48b9f8c1259422b5d58`, and tree
   `81f61aa5bf0c84fb305ea26910d15d37da7967bb`.
2. Keep the reviewed Discourse Docker commit
   `ed9f680b0df1de28f062de1769d89d22b2644d1b`, Docker Manager commit
   `c008c3ca7fcc44775215843992e88190adb7b3bf`, and pinned base image unchanged.
3. Update every current release, runtime, verification, and source-evidence
   consumer to the new exact application identity.
4. Preserve `theme/mochirii/about.json` at minimum version `2026.7.1`; that
   value is a compatibility floor, not the deployed release identity.
5. Preserve historical ADRs and historical backup-name test fixtures as
   immutable evidence of earlier reviewed releases.

## Verification

The complete 48-file application evidence union was revalidated at the new
commit. Fourteen files changed identity. The existing exact semantic checks
for DiscourseConnect, authentication, email and digest production, themes,
topic seeds and normalization, restore, storage, Gravatar, routes, metadata,
and optional authentication providers remain valid after updating only the
corresponding whole-file tuples.

The DiscourseConnect signature comparison is strengthened upstream to a
constant-time comparison. Its consumer nonce, replay, expiry, and session
binding model remains unchanged. New provider-only behavior does not affect
Mochirii's consumer-only configuration.

## Consequences

- A production build can use the current monthly exact application release
  without changing the deployment architecture or adding an upstream fork.
- Deployment still requires protected merge, exact-main hosted validation,
  the documented host control flow, backup and restore evidence, and live
  verification. Source acceptance alone does not claim production activation.

## Primary references

- [Official supported versions](https://github.com/discourse/discourse/blob/main/versions.json)
- [Official v2026.8.0 commit](https://github.com/discourse/discourse/commit/badad7b0456a628e578bc48b9f8c1259422b5d58)
- [Pinned installation requirements](https://github.com/discourse/discourse/blob/badad7b0456a628e578bc48b9f8c1259422b5d58/docs/INSTALL.md)
- [Pinned cloud standalone procedure](https://github.com/discourse/discourse/blob/badad7b0456a628e578bc48b9f8c1259422b5d58/docs/INSTALL-cloud.md)
