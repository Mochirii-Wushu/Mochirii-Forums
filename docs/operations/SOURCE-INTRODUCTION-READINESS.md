# Source Introduction Readiness

Stage 4 introduces only repository-owned configuration, theme, validation, and
operations source around immutable external upstream revisions. Upstream core
and deployment source remain external and their required licenses and notices
remain preserved.

## Prepared

- Exact application, deployment, Docker Manager, and base-image identities.
- Sanitized official standalone template with persistent `/shared` data.
- Closed native registration, login-required access, built-in
  DiscourseConnect consumer, nonce/session protection, and no alternate login
  provider.
- Public image-only uploads, private backup prefix, no direct browser upload,
  no automatic CORS or lifecycle mutation, and no application-asset CDN.
- Deterministic Mochirii theme, public metadata/error overlays, and a mandatory
  warning that direct upload URLs are public.
- Provider-neutral fail-closed SMTP inputs and Mochirii sender identity.
- Exact deployment, hosted verification, backup, restore, and rollback
  procedures whose execution remains separately protected.

## Stage 4 gate

The exact candidate must pass local/CI source checks and the manual disposable
one-core bootstrap described in [VALIDATION.md](VALIDATION.md). No provider or
paid resource may exist as a consequence of that gate. A missing or failed
check blocks later provisioning.

## Still external to source readiness

Live pricing, account quota, SMTP authorization, DNS, TLS, storage/CDN
behavior, provider-scoped credentials, authentication fixtures, backup restore,
and production health require current protected readback in Stage 5. The
included object-storage CDN is explicitly unproven until its real custom-host
upload lifecycle passes end to end.

This document grants no GitHub, provider, secret, deployment, or billing
authority.
