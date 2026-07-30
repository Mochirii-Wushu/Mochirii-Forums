# Source Provenance and Remote Policy

## Ownership boundary

`Mochirii-Wushu/Mochirii-Forums` is the canonical owner of reviewed Mōchirīī
forum customizations and governance. It is not a fork, mirror, or vendor copy of
Discourse core. The official `discourse/discourse_docker` repository remains
the owner of the referenced self-hosting source and license.

The checked-in [upstream evidence](upstream-provenance.v1.json) pins one exact
revision and hashes only four official files. It must never be treated as a
floating dependency or an installation approval.

## Approved remote topology

| Remote | Fetch | Push |
| --- | --- | --- |
| `origin` | `https://github.com/Mochirii-Wushu/Mochirii-Forums.git` | same URL |
| `upstream` | `https://github.com/discourse/discourse_docker.git` | `disabled://upstream-push` |

No additional remote or URL rewrite is allowed in the reviewed topology. The
repository does not store Git credentials. Authentication remains the operator
and GitHub credential manager's responsibility.

The push sentinel is a local accident-prevention control, not an authorization
boundary against a compromised workstation. GitHub access, least-privilege
roles, review, and protected-branch controls remain authoritative.

## Safe local setup

After the repository has an approved `main` and only in a disposable or
reviewed working clone:

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/configure-upstream.ps1 -Apply
pwsh -NoLogo -NoProfile -File ./scripts/verify-upstream-policy.ps1
```

`configure-upstream.ps1` refuses to modify an unexpected origin or unexpected
existing upstream. It changes only the local clone's `upstream` remote. If its
post-change verification fails, it restores the prior local remote state.

To prove read access without updating local refs:

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/verify-upstream-policy.ps1 -RequireReachable
```

## Upstream review procedure

1. Run the manual `inspect-upstream` workflow or the provenance verifier with
   `-Online -RequireCurrentMain`.
2. If upstream `main` moved, do not update the pin automatically.
3. Review the upstream diff, license, release notes, security notices, runtime
   requirements, and configuration changes.
4. Update the evidence manifest in one focused pull request only after its
   exact revision and bytes are independently verified.
5. Run repository validation and obtain accountable human review of the exact
   head.
6. Keep source introduction and any runtime/provider change in later,
   separately authorized pull requests.

The manual workflow is deliberately unscheduled and read-only. A failed drift
check is a review signal, not permission for automated promotion.
