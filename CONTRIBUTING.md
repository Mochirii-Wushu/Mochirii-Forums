# Contributing

## Change discipline

The live repository currently has no `main` ref. Its exact reviewed governance
seed may be first-pushed to empty `main` only under a separate explicit
bootstrap authorization. This document is not that authorization. Once `main`
exists, the workflow below applies without exception.

1. Read `AGENTS.md` and `docs/operations/CURRENT-STATE.md`.
2. Start from the current default branch and create one focused branch.
3. Keep the change inside the repository's approved ownership boundary.
4. Add or update contract coverage for every new allowed file type or behavior.
5. Run the repository contract and inspect the complete diff.
6. Open a pull request that records scope, risk, tests, and remaining gates.
7. Obtain accountable human review of the final exact head before merge.

## Exact-head review boundary

No GitHub user or team is currently approved for CODEOWNERS, and private-plan
ruleset enforcement is not assumed. A comment-only CODEOWNERS file is therefore
intentional. Do not invent a team or use an organization handle as a substitute.
Until an existing owner identity and enforceable ruleset are separately approved,
the operator must verify the base, head SHA, required CI, and human review again
immediately before merge.

## Prohibited contributions

Do not submit credentials, user data, databases, environment files, generated
artifacts, binaries, archives, runnable forum software, vendored upstream core,
provider configuration, hostnames, deployment code, or public-facing copy in
this governance phase.

Security-sensitive findings belong in a private GitHub security advisory, not a
public issue or pull-request discussion. See `SECURITY.md`.
