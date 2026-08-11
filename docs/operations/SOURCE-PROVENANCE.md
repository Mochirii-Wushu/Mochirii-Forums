# Source Provenance and Remote Policy

## Ownership boundary

`Mochirii-Wushu/Mochirii-Forums` is the canonical owner of reviewed Mōchirīī
forum configuration, isolated overlays, and governance. It is permanently not a
fork, mirror, or vendor copy of Discourse core or `discourse_docker`. Those
official repositories remain the owners of their source and licenses.

The checked-in [upstream evidence](upstream-provenance.v1.json) pins
`discourse_docker` revision
`a3028747c5b7774f49a3b110221d96ca2b3f340d` and hashes only five official
files: the license, one-line installer, setup wizard, launcher, and standalone
sample. It must never be treated as a floating dependency or an installation
approval.

The reviewed pin remains selected only as source evidence. On 2026-08-11,
read-only fetch observed `main` at
`e6d7b508b43f9610950166f53cb1be1bd78435a9`, 11 commits ahead and zero behind
the pin. GitHub reports verified commit signatures with reason `valid` for both
the pin and observed main; the online verifier binds those results and both
commit trees. The manifest records notable compatibility gates, including the
PostgreSQL 18 base change and its free-space, one-core, and all-database
companions plus Redis log-directory handling; it does not claim the list is an
exhaustive changelog. That observation is recorded but not selected or promoted.

## Approved remote topology

| Remote | Fetch | Push |
| --- | --- | --- |
| `origin` | `https://github.com/Mochirii-Wushu/Mochirii-Forums.git` | same URL |
| `upstream` | `https://github.com/discourse/discourse_docker.git` | `disabled://upstream-push` |

No additional remote or URL rewrite is allowed in the reviewed topology. The
repository does not store Git credentials. Authentication remains the operator
and GitHub credential manager's responsibility.

Local configuration must also set `remote.pushDefault=origin` and
`pull.ff=only`. The upstream fetch refspec maps only official `main` to
`refs/remotes/upstream/main`,
`remote.upstream.tagOpt=--no-tags` prevents auto-following reachable tags, and
exactly one upstream push URL is permitted: the inert sentinel shown above.

The push sentinel is a local accident-prevention control, not an authorization
boundary against a compromised workstation. GitHub access, least-privilege
roles, review, and protected-branch controls remain authoritative.

## Safe local setup

Only in a disposable or reviewed working clone:

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/configure-upstream.ps1 -Apply
pwsh -NoLogo -NoProfile -File ./scripts/verify-upstream-policy.ps1
```

`configure-upstream.ps1` refuses to modify an unexpected origin or unexpected
existing upstream. It changes only the approved upstream and local pull/push
defaults. If its post-change verification fails, it restores the prior local
remote state.

To prove read access without updating local refs:

```powershell
pwsh -NoLogo -NoProfile -File ./scripts/verify-upstream-policy.ps1 -RequireReachable
```

## Upstream review procedure

1. Run the monthly/manual `inspect-forums-upstream` workflow or the provenance verifier with
   `-Online -RequireCurrentMain`.
2. If upstream `main` moved beyond the recorded drift observation, do not update
   the observation or pin automatically.
3. Review the upstream diff, license, release notes, security notices, runtime
   requirements, installer transitive inputs, mutable setup-wizard image,
   plugin compatibility, and configuration changes.
4. Update the evidence manifest in one focused pull request only after its
   exact revision and bytes are independently verified.
5. Run repository validation and obtain accountable human review of the exact
   head.
6. Keep configuration introduction and any runtime/provider change in later,
   separately authorized pull requests.

Once an explicitly authorized empty-main bootstrap places the workflow on
`main`, it has a monthly schedule requesting 22:17 on day 3 with native IANA
`Asia/Singapore` scheduling (`17 22 3 * *`); the empty origin makes it inert
today. GitHub may delay or drop scheduled runs under high load, so this is a
drift-alert cadence rather than an exact-time SLA. Manual dispatch is then
available.
The workflow is read-only, uses immutable action
pins, persists no checkout credentials, and cannot update a pin, create a
branch/PR, publish an artifact, or promote a runtime. A failed drift check is a
review signal, not permission for automated promotion.

## Release-tag evidence

The 2026-08-11 release observation deliberately distinguishes Git object types:

- unsigned annotated tag object
  `11c70a765e46c3229d66e108883fa2d33f5d0b81`;
- peeled unsigned commit
  `cbf996f65aae3da1843224aa624bcd9a225931ac`;
- commit tree `0aeceebe79c4d2da8cf0fab213514335c201bfa7`.

`third-party-components.v1.json` also binds exact SHA-256 evidence for the
release's GPL license, copyright notice, README, security/version files, and
the pinned local-date/Calendar behavior that prevents this packet from claiming
universal `Asia/Singapore` display authority. The central-identity contract
separately binds the pinned DiscourseConnect parser, nonce/session model,
controller, and site settings. The official release index
reports `v2026.7.1` as a supported ESR released 2026-07-31 with planned end of
support 2027-03-30. None of that selects it for runtime.

## Primary references

- [Official Discourse release index](https://releases.discourse.org/)
- [Official v2026.7.1 changelog](https://releases.discourse.org/changelog/v2026.7.1/)
- [Pinned v2026.7.1 license](https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/LICENSE.txt)
- [Official Discourse Docker repository](https://github.com/discourse/discourse_docker)
- [PostgreSQL 18 dump/restore change](https://github.com/discourse/discourse_docker/commit/09493049db7e4873f3dcff1356249ccf879ca6ec)
- [GitHub Actions timezone-aware schedule syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onschedule)
- [GitHub Actions schedule delivery behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [Pinned actions/checkout v7.0.1 release](https://github.com/actions/checkout/releases/tag/v7.0.1)
- [Dependabot schedule timezone option](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#scheduletimezone)
