# Release evidence contract

Every runtime/provider release produces one immutable, redacted record based
on `release-evidence.v2.example.json`. The completed record belongs in the
approved protected evidence boundary, not automatically in public Git.

The legacy `release-evidence.v1.example.json` is a machine-readable supersession
pointer only and must not be used for a new release.

## Required binding

One record must bind:

- the exact repository commit/tree and release archive digest/size plus its
  normalized content-manifest digest;
- exact Discourse Docker, core, Docker Manager, and base-image revisions;
- rendered production, consumer-on loopback-containment, and isolated-restore
  configuration digests plus theme and required first-party
  mail-metadata-component digests;
- exact CI, disposable one-core bootstrap, secret, and source validation
  results;
- protected live cost and existing-SMTP evidence references without values;
- the authorized provider resource classes and final fixed monthly cost;
- hosted HTTPS, runtime, storage, backup, restore, authentication, branding,
  restart, and rebuild readbacks;
- the irreversible member-rollout marker reference and final DiscourseConnect
  activation result, including the immutable pending record, fresh protected
  Website end-to-end record, callback-log-redaction, browser-query-scrub, and
  private no-store callback-response gates, and operator-finalized `complete`
  authentication record;
- operator, approval, start/completion times, stop conditions, cleanup, and
  actual outcome; and
- unresolved risks with named owners and due dates.

The root host deploy wrapper writes a narrower schema-2 record, while the
backup and restore wrappers write narrower schema-3
records in `/var/lib/mochirii/forums/evidence`. Reference those protected
records by immutable digest; do not copy their raw contents or host-private
paths into public evidence. The deploy record includes the exact hosted-storage
evidence filename/digest and pass flags for write/read, optimized variant,
custom hostname, public ACL, anonymous listing denial, restart/rebuild
persistence, row/object deletion, and tombstone cleanup.

Before member rollout, schema-3 backup evidence binds the exact disposable
normal-upload row/object/content/custom-host identity that was present in the
tested backup and its proved live cleanup. Schema-3 restore evidence binds
that upload's exact recreation from the backup, the completed Sidekiq job
probe, exact post-restore cleanup, and a subsequent clean backup whose evidence
and current pointer prove the fixture absent. The irreversible rollout marker
may reference only that complete restore chain.

Hashes prove byte identity, not safety, approval, or successful deployment. A
release record is valid only when source, artifacts, approval, cost, provider
state, deployment, restore, member-rollout marker, and final readback all bind
to the same final reviewed release.

The example uses explicit `null`, `false`, and empty placeholders so incomplete
evidence fails visibly. Never replace them with invented values or infer a
provider/runtime pass from source validation.
