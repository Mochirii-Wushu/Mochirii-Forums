# Third-party notices

Mochirii Forums preserves upstream licenses and attribution while keeping
member-facing product presentation Mochirii-only.

## Discourse core

- Source: <https://github.com/discourse/discourse>
- Selected revision: `badad7b0456a628e578bc48b9f8c1259422b5d58`
- License: GPL-2.0-or-later
- License: <https://github.com/discourse/discourse/blob/badad7b0456a628e578bc48b9f8c1259422b5d58/LICENSE.txt>
- Copyright notice: <https://github.com/discourse/discourse/blob/badad7b0456a628e578bc48b9f8c1259422b5d58/COPYRIGHT.md>

## Discourse Docker

- Source: <https://github.com/discourse/discourse_docker>
- Selected revision: `ed9f680b0df1de28f062de1769d89d22b2644d1b`
- License: MIT
- License: <https://github.com/discourse/discourse_docker/blob/ed9f680b0df1de28f062de1769d89d22b2644d1b/LICENSE>

## Docker Manager

- Source: <https://github.com/discourse/docker_manager>
- Selected revision: `c008c3ca7fcc44775215843992e88190adb7b3bf`
- License: MIT
- License: <https://github.com/discourse/docker_manager/blob/c008c3ca7fcc44775215843992e88190adb7b3bf/LICENSE>

Docker Manager is present only because the official standalone template
includes it. No optional third-party plugin is added. The mandatory
repository-owned `mochirii_email_metadata` component is a first-party branding
control bound to the exact Forums commit; it does not modify or redistribute
upstream core source.

## acme.sh

- Source: <https://github.com/acmesh-official/acme.sh>
- Selected release: `3.1.4`
- Exact revision: `3661fd86b6304115e42f43910e6dd452ab9866d6`
- License: GPL-3.0-or-later
- Included license: `config/acme-sh-3.1.4.LICENSE.md`

The exact reviewed `acme.sh` bytes are stored as the deterministic
base64-encoded gzip payload `config/acme-sh-3.1.4.gz.b64`. Production bootstrap
decodes and verifies its recorded SHA-256 before execution. Automatic updates
are disabled; no tag/branch URL or online installer executes on the host. One
exact local transport hardening transformation selects the repository-owned
absolute curl wrapper; it does not remove or replace upstream attribution or
license terms.

## Mochirii theme

The repository-owned theme is MIT licensed in `theme/mochirii/LICENSE.txt`.
Its three public brand assets are copied from the canonical Mochirii Website
public asset boundary and bound to exact SHA-256 digests by the theme builder.

These notices remain available to operators and source recipients. Public
upstream or infrastructure-provider promotion is not required to preserve the
licenses above.
