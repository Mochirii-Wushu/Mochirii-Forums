## Purpose

Describe the single causal change and why it belongs in this repository.

## Scope

- [ ] The diff is source-only and contains no credentials, private values, databases, archives, or generated binaries.
- [ ] No provider, runtime, deployment, cost, hostname, or public-copy change is included.
- [ ] Any future upstream-source introduction is covered by an approved ownership and history decision.

## Verification

- [ ] `pwsh -NoLogo -NoProfile -File ./scripts/check-repository.ps1`
- [ ] PowerShell parsing, YAML parsing when available, and `git diff --check` pass.
- [ ] Required CI is successful for this exact pull-request head.

## Review and release boundary

- [ ] An accountable human reviewed the exact head after the final push.
- [ ] The base branch and exact head SHA are recorded before merge.
- [ ] This pull request does not authorize a deployment or provider mutation.
