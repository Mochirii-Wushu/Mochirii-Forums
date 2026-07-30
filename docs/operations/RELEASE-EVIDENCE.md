# Release Evidence Contract

Every future source, runtime, or provider release must produce one immutable,
redacted record based on `release-evidence.v1.example.json`. The completed
record belongs in an approved evidence boundary, not automatically in public
Git.

## Required binding

- repository, base, reviewed head commit, and tree;
- upstream revision and reviewed manifest digest;
- source package or image digest and software bill of materials digest;
- exact CI and security results at the reviewed head;
- approved customization inventory digest;
- pre-change backup and restore-rehearsal references;
- deployment target class without secrets or sensitive identifiers;
- operator, approval reference, start and completion times;
- health, functional, accessibility, and security readbacks;
- rollback target, stop conditions, and actual outcome; and
- unresolved risks with named owners and due dates.

Hashes prove byte identity, not safety or approval. A release record is valid
only when the source, artifact, approval, deployment, and readback all bind to
the same reviewed revision.

The example uses explicit `null` placeholders so incomplete evidence fails
visibly. Never replace them with invented values.
