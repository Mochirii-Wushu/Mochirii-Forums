# Security Policy

## Reporting a vulnerability

Use this private repository's GitHub security-advisory workflow to report a
suspected vulnerability. Do not disclose exploit details, credentials, private
member information, or reproduction artifacts in an issue, discussion, commit,
pull request, or chat log.

Include only the minimum information needed to reproduce and assess the issue:
affected revision, impact, prerequisites, and a safe proof of concept. Remove
tokens, cookies, personal data, infrastructure identifiers, and production
payloads.

## Response boundary

- Maintainers validate the report in an isolated environment.
- Access follows least privilege and is limited to the people handling the case.
- Remediation uses a focused reviewed pull request and exact-head CI.
- Provider, secret, data, and production changes require separate authorization.
- Public disclosure occurs only after remediation and an explicit coordinated
  disclosure decision.

This repository currently contains governance source only and has no supported
runtime release.

## Upstream and dependency response

The manual upstream inspection workflow may identify a new official revision,
security notice, or dependency change. Treat that result as untrusted input for
review: do not execute it, update the reviewed pin automatically, or introduce
runnable source in the same change. Assess impact and license, verify official
bytes, document the decision, and use a focused exact-head pull request.

Once runtime source exists under separate approval, define severity targets,
supported versions, dependency inventory, coordinated disclosure, emergency
change review, rollback, and post-incident evidence before declaring a
supported release.
