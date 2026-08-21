#!/usr/bin/env python3
"""Hostile fixture tests for rendering and deterministic theme packaging."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

LOCALIZED_ERROR_COPY_BLOCK = '''        - |-
          for status in 403 422 500 503; do
            source="public/${status}.html"
            [ -f "$source" ] && [ ! -L "$source" ] || exit 1
            set -- "public/${status}".*.html
            [ "$#" -eq 48 ] || exit 1
            for target; do
              [ -f "$target" ] && [ ! -L "$target" ] || exit 1
              cp -- "$source" "$target" || exit 1
              cmp -s -- "$source" "$target" || exit 1
            done
          done'''
LOCALIZED_ERROR_COPY_COMMAND = "\n".join(
    line[10:] for line in LOCALIZED_ERROR_COPY_BLOCK.splitlines()[1:]
)
NGINX_LOG_DIRECTORY_BLOCK = '''        - >-
          test ! -L /var/log/nginx &&
          install -d -m 0755 -o root -g adm /var/log/nginx &&
          nginx -t'''


def module_from(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RENDER = module_from("scripts/render-app-config.py", "render_app_config")
THEME = module_from("scripts/build-theme-archive.py", "build_theme_archive")
ROTATE = module_from("scripts/rotate-media-certificate.py", "rotate_media_certificate")
UPSTREAM = module_from("scripts/verify-pinned-source.py", "verify_pinned_source")
VALIDATOR = module_from("scripts/validate-repository.py", "validate_repository")
AUTHENTICATION = module_from("scripts/authentication-state.py", "authentication_state")
CONNECT_FIXTURE = module_from("scripts/verify-discourse-connect.py", "verify_discourse_connect")
PRODUCER_PROBE = module_from("scripts/probe-website-forums-producer.py", "probe_website_forums_producer")
PUBLIC_BRANDING = module_from("scripts/verify-public-branding.py", "verify_public_branding")


@contextlib.contextmanager
def environment(values: dict[str, str]):
    previous = os.environ.copy()
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def expect_render_error(
    values: dict[str, str],
    mutation: tuple[str, str] | None = None,
    *,
    repository_commit: str = "1" * 40,
) -> None:
    candidate = dict(values)
    if mutation:
        candidate[mutation[0]] = mutation[1]
    with tempfile.TemporaryDirectory(prefix="mochirii-render-reject-") as directory:
        try:
            RENDER.render(
                "production",
                Path(directory) / "app.yml",
                runtime_values=candidate,
                repository_commit=repository_commit,
            )
        except RENDER.RenderError:
            return
    raise RuntimeError(f"Production renderer accepted hostile input: {mutation}")


def test_renderer() -> None:
    commit = "a" * 40
    production = {
        "FORUMS_ACTIVATION_ENABLED": "true",
        "FORUMS_DEVELOPER_EMAILS": "operator@example.invalid",
        "FORUMS_DISCOURSE_CONNECT_ENABLED": "true",
        "FORUMS_DISCOURSE_CONNECT_SECRET": "a" * 64,
        "FORUMS_S3_ACCESS_KEY_ID": "fixture-key-not-real",
        "FORUMS_S3_SECRET_ACCESS_KEY": "fixture-storage-secret-not-real",
        "FORUMS_SMTP_ADDRESS": "smtp.example.invalid",
        "FORUMS_SMTP_PORT": "465",
        "FORUMS_SMTP_USER_NAME": "fixture-user",
        "FORUMS_SMTP_PASSWORD": "fixture-password-#-$-not-real",
        "FORUMS_SMTP_AUTHENTICATION": "plain",
        "FORUMS_NOTIFICATION_EMAIL": "notifications@mochirii.com",
    }

    expect_render_error({})
    for required in (
        "FORUMS_DEVELOPER_EMAILS",
        "FORUMS_S3_ACCESS_KEY_ID",
        "FORUMS_S3_SECRET_ACCESS_KEY",
        "FORUMS_SMTP_ADDRESS",
        "FORUMS_SMTP_PORT",
        "FORUMS_SMTP_USER_NAME",
        "FORUMS_SMTP_PASSWORD",
        "FORUMS_SMTP_AUTHENTICATION",
        "FORUMS_NOTIFICATION_EMAIL",
        "FORUMS_DISCOURSE_CONNECT_SECRET",
    ):
        candidate = dict(production)
        candidate.pop(required)
        expect_render_error(candidate)

    hostile = (
        ("FORUMS_DEVELOPER_EMAILS", "a@example.invalid\nb@example.invalid"),
        ("FORUMS_SMTP_ADDRESS", "127.0.0.1"),
        ("FORUMS_SMTP_ADDRESS", "smtp.example.invalid\nDISCOURSE_SKIP_EMAIL_SETUP=1"),
        ("FORUMS_SMTP_PORT", "0"),
        ("FORUMS_SMTP_PORT", "65536"),
        ("FORUMS_SMTP_AUTHENTICATION", "none"),
        ("FORUMS_S3_SECRET_ACCESS_KEY", "bad\nvalue"),
        ("FORUMS_DISCOURSE_CONNECT_SECRET", "a" * 63),
        ("FORUMS_DISCOURSE_CONNECT_SECRET", "A" * 64),
        ("FORUMS_DISCOURSE_CONNECT_SECRET", "g" * 64),
        ("FORUMS_NOTIFICATION_EMAIL", "notifications@example.invalid"),
    )
    for mutation in hostile:
        expect_render_error(production, mutation)

    with tempfile.TemporaryDirectory(prefix="mochirii-render-pass-") as directory:
        output = Path(directory) / "app.yml"
        RENDER.render("production", output, runtime_values=production, repository_commit=commit)
        rendered = output.read_text(encoding="utf-8")
        if "__MOCHIRII_" in rendered or commit not in rendered:
            raise RuntimeError("Production rendering did not resolve and bind every token.")
        if 'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "true"' not in rendered:
            raise RuntimeError("Explicit DiscourseConnect activation was lost.")
        if 'fixture-password-#-$-not-real' not in rendered:
            raise RuntimeError("Quoted SMTP fixture did not survive exact rendering.")
        tls_required = (
            '  - "templates/web.ssl.template.yml"',
            "acme-sh-3.0.6.gz.b64",
            "400d1a96ef72a1f27fe79c7f0e6d4e4f600c0509c0cd787db00931b9258c54da",
            "--auto-upgrade 0",
            "/usr/local/bin/mochirii-acme-cron",
        )
        if any(value not in rendered for value in tls_required):
            raise RuntimeError("Production rendering lost the immutable TLS integration.")
        if "web.letsencrypt.ssl.template.yml" in rendered or "curl " in rendered or "--upgrade" in rendered:
            raise RuntimeError("Production rendering reintroduced floating TLS client source.")
        if os.name != "nt" and stat.S_IMODE(output.stat().st_mode) != 0o600:
            raise RuntimeError("Rendered runtime configuration is not mode 0600.")

    with tempfile.TemporaryDirectory(prefix="mochirii-render-restore-") as directory:
        output = Path(directory) / "app.yml"
        RENDER.render("disposable-restore", output, runtime_values=production, repository_commit=commit)
        rendered = output.read_text(encoding="utf-8")
        required = (
            '127.0.0.1:18080:80',
            'DISCOURSE_DISABLE_EMAILS: "yes"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "false"',
            'DISCOURSE_ENABLE_S3_UPLOADS: "true"',
        )
        if any(value not in rendered for value in required):
            raise RuntimeError("Disposable restore rendering did not fail closed.")
        if any(value in rendered for value in ("acme-sh-3.0.6", "mochirii-acme-cron", "DISCOURSE_FORCE_HTTPS")):
            raise RuntimeError("Disposable restore rendering activated the public TLS client.")

    expect_render_error(production, repository_commit="ABC")
    disabled_with_secret = dict(production)
    disabled_with_secret["FORUMS_DISCOURSE_CONNECT_ENABLED"] = "false"
    expect_render_error(disabled_with_secret)
    with tempfile.TemporaryDirectory(prefix="mochirii-runtime-json-") as directory:
        runtime_json = Path(directory) / "runtime.json"
        runtime_json.write_text(json.dumps(production), encoding="utf-8")
        if os.name != "nt":
            runtime_json.chmod(0o600)
        loaded = RENDER.load_protected_runtime(runtime_json)
        if loaded != production:
            raise RuntimeError("Protected literal runtime JSON changed during parsing.")
        runtime_json.write_text(json.dumps({**production, "PATH": "/hostile"}), encoding="utf-8")
        if os.name != "nt":
            runtime_json.chmod(0o600)
        try:
            RENDER.load_protected_runtime(runtime_json)
        except RENDER.RenderError:
            pass
        else:
            raise RuntimeError("Protected runtime JSON accepted an arbitrary environment name.")

        symlink = Path(directory) / "runtime-link.json"
        try:
            symlink.symlink_to(runtime_json)
        except OSError:
            if os.name != "nt":
                raise
        else:
            try:
                RENDER.load_protected_runtime(symlink)
            except RENDER.RenderError as error:
                if "regular file" not in str(error):
                    raise RuntimeError("Renderer rejected a symlink for the wrong reason.") from error
            else:
                raise RuntimeError("Renderer followed a protected runtime JSON symlink.")

    with tempfile.TemporaryDirectory(prefix="mochirii-rotation-symlink-") as directory:
        target = Path(directory) / "runtime.json"
        target.write_text(
            json.dumps(
                {
                    "providerApiToken": "fixture-provider-token-not-real-00000000",
                    "cdnEndpointId": "00000000-0000-4000-8000-000000000000",
                    "cdnOrigin": "mochirii-forums.sgp1.digitaloceanspaces.com",
                }
            ),
            encoding="utf-8",
        )
        if os.name != "nt":
            target.chmod(0o600)
        symlink = Path(directory) / "runtime-link.json"
        try:
            symlink.symlink_to(target)
        except OSError:
            if os.name != "nt":
                raise
        else:
            try:
                ROTATE.protected_runtime(symlink)
            except ROTATE.RotationError as error:
                if "regular file" not in str(error):
                    raise RuntimeError("Rotation rejected a symlink for the wrong reason.") from error
            else:
                raise RuntimeError("Rotation followed a protected runtime JSON symlink.")

    with tempfile.TemporaryDirectory(prefix="mochirii-render-fixture-") as directory:
        output = Path(directory) / "app.yml"
        with environment({"FORUMS_REPOSITORY_COMMIT": commit}):
            RENDER.render("stage4-fixture", output)
        rendered = output.read_text(encoding="utf-8")
        required = (
            '127.0.0.1:18080:80',
            'MOCHIRII_STAGE4_FIXTURE: "true"',
            'DISCOURSE_ENABLE_S3_UPLOADS: "false"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "false"',
            commit,
        )
        if any(value not in rendered for value in required):
            raise RuntimeError("Stage 4 fixture is not loopback-only and externally inactive.")
        if (
            rendered.count(LOCALIZED_ERROR_COPY_BLOCK) != 1
            or rendered.count("for status in 403 422 500 503; do") != 1
        ):
            raise RuntimeError("Rendered localized error-page copy lost its exact literal shell contract.")
        if rendered.count(NGINX_LOG_DIRECTORY_BLOCK) != 1:
            raise RuntimeError("Rendered Nginx validation lost its exact persistent log-directory contract.")

    if os.name != "nt":
        localized_names = [
            "locale space",
            "line\nbreak",
            "-leading-dash",
            *(f"locale-{index:02d}" for index in range(3, 48)),
        ]

        def prepare_error_pages(directory: str) -> tuple[Path, list[tuple[Path, Path]]]:
            public = Path(directory) / "public"
            public.mkdir()
            pairs: list[tuple[Path, Path]] = []
            for status in (403, 422, 500, 503):
                source = public / f"{status}.html"
                source.write_bytes(f"branded-{status}\n".encode("ascii"))
                source.chmod(0o644)
                for index, locale in enumerate(localized_names):
                    target = public / f"{status}.{locale}.html"
                    target.write_bytes(b"upstream-content\n")
                    target.chmod(0o600 if index == 0 else 0o644)
                    pairs.append((source, target))
            return public, pairs

        def run_error_page_copy(directory: str, *, path: str | None = None) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["sh", "-c", LOCALIZED_ERROR_COPY_COMMAND],
                cwd=directory,
                env={"LC_ALL": "C", "PATH": path or os.environ.get("PATH", "/usr/bin:/bin")},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )

        with tempfile.TemporaryDirectory(prefix="mochirii-error-pages-pass-") as directory:
            public, pairs = prepare_error_pages(directory)
            identities = {
                target: (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode))
                for _, target in pairs
            }
            result = run_error_page_copy(directory)
            if result.returncode != 0:
                raise RuntimeError("Localized error-page copy rejected its exact safe inventory.")
            if len(list(public.glob("*.html"))) != 196:
                raise RuntimeError("Localized error-page copy changed the exact inventory.")
            for source, target in pairs:
                identity = (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode))
                if target.read_bytes() != source.read_bytes() or identity != identities[target]:
                    raise RuntimeError("Localized error-page copy changed content or file identity incorrectly.")

        for scenario in ("missing", "extra", "symlink", "false-success"):
            with tempfile.TemporaryDirectory(prefix=f"mochirii-error-pages-{scenario}-") as directory:
                public, pairs = prepare_error_pages(directory)
                path = None
                if scenario == "missing":
                    pairs[0][1].unlink()
                elif scenario == "extra":
                    (public / "403.extra.html").write_bytes(b"unexpected\n")
                elif scenario == "symlink":
                    victim = Path(directory) / "victim"
                    victim.write_bytes(b"victim-must-survive\n")
                    pairs[0][1].unlink()
                    pairs[0][1].symlink_to(victim)
                else:
                    fake_bin = Path(directory) / "bin"
                    fake_bin.mkdir()
                    fake_cp = fake_bin / "cp"
                    true_command = shutil.which("true")
                    if true_command is None:
                        raise RuntimeError("Localized error-page hostile fixture cannot locate true(1).")
                    fake_cp.symlink_to(true_command)
                    path = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
                result = run_error_page_copy(directory, path=path)
                if result.returncode == 0:
                    raise RuntimeError(f"Localized error-page copy accepted hostile {scenario} state.")
                if scenario == "symlink" and (Path(directory) / "victim").read_bytes() != b"victim-must-survive\n":
                    raise RuntimeError("Localized error-page copy followed a hostile symlink.")

    connect_fixture = "b" * 64
    with tempfile.TemporaryDirectory(prefix="mochirii-render-connect-fixture-") as directory:
        output = Path(directory) / "app.yml"
        values = {
            "FORUMS_REPOSITORY_COMMIT": commit,
            "FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET": connect_fixture,
        }
        with environment(values):
            RENDER.render("stage4-connect-fixture", output)
        rendered = output.read_text(encoding="utf-8")
        required = (
            '127.0.0.1:18080:80',
            'MOCHIRII_STAGE4_FIXTURE: "true"',
            'MOCHIRII_STAGE4_CONNECT_FIXTURE: "true"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "true"',
            connect_fixture,
        )
        if any(value not in rendered for value in required):
            raise RuntimeError("Stage 4 DiscourseConnect fixture lost its exact loopback contract.")

    with tempfile.TemporaryDirectory(prefix="mochirii-render-connect-reject-") as directory:
        with environment(
            {
                "FORUMS_REPOSITORY_COMMIT": commit,
                "FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET": "B" * 64,
            }
        ):
            try:
                RENDER.render("stage4-connect-fixture", Path(directory) / "app.yml")
            except RENDER.RenderError:
                pass
            else:
                raise RuntimeError("Stage 4 DiscourseConnect fixture accepted a non-lowercase key.")


def test_theme_archive() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-theme-test-") as directory:
        first = Path(directory) / "one.zip"
        second = Path(directory) / "two.zip"
        THEME.build(first)
        THEME.build(second)
        first_bytes = first.read_bytes()
        if first_bytes != second.read_bytes():
            raise RuntimeError("Theme archive is not deterministic.")
        with zipfile.ZipFile(first) as archive:
            names = archive.namelist()
            if names != sorted(names) or "about.json" not in names:
                raise RuntimeError("Theme archive inventory is malformed.")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise RuntimeError("Theme archive contains an unsafe path.")
        if not hashlib.sha256(first_bytes).hexdigest():
            raise RuntimeError("Theme archive digest could not be calculated.")
    verifier = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_theme_runtime_verifier(verifier)
    hostile_replacements = (
        ('].all? { |value| value&.id == emblem_id }', '].all? { |value| value == emblem_id }'),
        ('].all? { |value| value&.id == icon_id }', '].all? { |value| value == icon_id }'),
        ('].all? { |value| value&.id == social_card_id }', '].all? { |value| value == social_card_id }'),
        (
            '"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":',
            '"discourse/connectors/composer-fields-below/mochirii-upload-notice":',
        ),
        ('checks["theme_logo_settings"] =\n    [', 'checks["theme_logo_settings"] = true ||\n    ['),
        (
            '].all? { |value| value&.id == emblem_id } &&',
            '].all? { |value| value&.id == emblem_id } ||',
        ),
        (
            '].all? { |value| value&.id == icon_id } &&',
            '].all? { |value| value&.id == icon_id } ||',
        ),
        (
            """compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":') &&""",
            """compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":') ||""",
        ),
    )
    for current, stale in hostile_replacements:
        hostile = verifier.replace(current, stale, 1)
        if hostile == verifier:
            raise RuntimeError("Runtime theme verifier hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_theme_runtime_verifier(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Runtime theme verifier accepted a stale pinned-semantic mutation.")
    decoy_hostiles = (
        verifier.replace(
            '].all? { |value| value&.id == emblem_id }',
            '].all? { true } # ].all? { |value| value&.id == emblem_id }',
            1,
        ),
        verifier.replace(
            """compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":')""",
            """compiled_theme.include?('"discourse/' 'connectors/composer-fields-below/mochirii-upload-notice":') # "discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":""",
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'checks["theme_logo_settings"] = true\n'
            'checks["upload_notice_connector_compiled"] = true\n'
            'checks["repository_revision"] =',
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'results = checks\n'
            'results["theme_logo_settings"] = true\n'
            'results["upload_notice_connector_compiled"] = true\n'
            'checks["repository_revision"] =',
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'checks.merge!("theme_logo_settings" => true, "upload_notice_connector_compiled" => true)\n'
            'checks["repository_revision"] =',
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'checks["theme_logo_" + "settings"] = true\n'
            'checks["upload_notice_" + "connector_compiled"] = true\n'
            'checks["repository_revision"] =',
            1,
        ),
    )
    for hostile in decoy_hostiles:
        if hostile == verifier:
            raise RuntimeError("Runtime theme verifier decoy hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_theme_runtime_verifier(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Runtime theme verifier accepted a decoy pinned-semantic mutation.")


def test_narrative_avatar_contract() -> None:
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    configure = (ROOT / "scripts/configure-site.rb").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_narrative_avatar_contract(template, configure, verifier)
    components = json.loads(
        (ROOT / "docs/operations/third-party-components.v1.json").read_text(encoding="utf-8")
    )
    gravatar_paths = {entry["path"] for entry in VALIDATOR.PINNED_GRAVATAR_EVIDENCE}
    gravatar_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in gravatar_paths
    ]
    if gravatar_evidence != VALIDATOR.PINNED_GRAVATAR_EVIDENCE:
        raise RuntimeError("Pinned automatic Gravatar lifecycle evidence differs.")
    upstream = (ROOT / "scripts/verify-pinned-source.py").read_text(encoding="utf-8")
    VALIDATOR.validate_pinned_source_verifier(upstream)
    for canary in (
        "PINNED_GRAVATAR_EVIDENCE = {",
        "PINNED_USER_GRAVATAR_SCHEDULE_BLOCK = b'''",
        "def verify_gravatar_semantics(core: dict[str, bytes]) -> None:",
        'verify_gravatar_semantics(core)',
        'settings.count(b"  automatically_download_gravatars: true\\n") != 1',
    ):
        if upstream.count(canary) != 1:
            raise RuntimeError("Pinned automatic Gravatar semantic gate differs.")
    fixture = (ROOT / "scripts/test-narrative-avatar.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_narrative_avatar_fixture(fixture)
    fixture_hostiles = (
        fixture.replace("  .sub(avatar_write_order, reordered_avatar_write_order)\n", "", 1),
        fixture.replace(
            'assert_fixture(method_source.scan(avatar_write_order).length == 1, "avatar write-order anchor differed")\n',
            "",
            1,
        ),
        fixture.replace("app_setting: :false, gravatar_response: :success", "app_setting: :true, gravatar_response: :success", 1),
        fixture.replace("app_setting: :omitted, gravatar_response: :success", "app_setting: :false, gravatar_response: :success", 1),
        fixture.replace("Jobs.drain_update_gravatar!\n", "", 1),
    )
    for hostile_fixture in fixture_hostiles:
        if hostile_fixture == fixture:
            raise RuntimeError("Narrative avatar fixture hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_narrative_avatar_fixture(hostile_fixture)
        except RuntimeError:
            continue
        raise RuntimeError("Narrative avatar fixture hostile mutation was accepted.")
    workflow = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    VALIDATOR.validate_narrative_avatar_workflow(workflow)
    preflight_start = "      - name: Prove one-effective-CPU command path\n"
    bootstrap_start = "      - name: Bootstrap exact standalone under one effective CPU\n"
    inert_step = '''      - name: Inert narrative fixture decoy
        if: ${{ false }}
        shell: bash
        run: |
''' + VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL
    workflow_hostiles = (
        workflow.replace(VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL, "", 1).replace(
            bootstrap_start,
            inert_step + bootstrap_start,
            1,
        ),
        workflow.replace(
            preflight_start,
            preflight_start + "        if: ${{ false }}\n",
            1,
        ),
        workflow.replace(
            VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL,
            "          if false; then\n" + VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL + "          fi\n",
            1,
        ),
    )
    for hostile_workflow in workflow_hostiles:
        try:
            VALIDATOR.validate_narrative_avatar_workflow(hostile_workflow)
        except RuntimeError:
            continue
        raise RuntimeError("Narrative avatar workflow hostile mutation was accepted.")

    environment_block = '''  DISCOURSE_ALLOW_EMAIL_INVITES: "false"
  DISCOURSE_DISCOURSE_NARRATIVE_BOT_ENABLED: "false"
  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"

  DISCOURSE_LOGIN_REQUIRED: "true"'''
    hostile_cases = (
        (
            template.replace(
                'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"',
                'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                environment_block,
                environment_block.replace(
                    '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"\n',
                    "",
                ),
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                environment_block,
                environment_block.replace(
                    '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"\n\n',
                    "",
                ) + '\n  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS : "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                '  "DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS": "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                "  'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS': \"true\"",
                1,
            ),
            configure,
            verifier,
        ),
        (
            template,
            configure.replace(
                "  automatically_download_gravatars: false,",
                "  automatically_download_gravatars: true,",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure.replace("\nconfigure_narrative_system_user!(icon_upload)\n", "\n", 1),
            verifier,
        ),
        (
            template,
            configure.replace(
                "  bot.user_avatar.update!(custom_upload_id: icon_upload.id, gravatar_upload_id: nil)",
                "  bot.user_avatar.update!(custom_upload_id: icon_upload.id)",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure,
            verifier.replace(
                'ENV["DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"] == "false" &&',
                'ENV["DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"] == "true" &&',
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                "SiteSetting.automatically_download_gravatars == false",
                "SiteSetting.automatically_download_gravatars == true",
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                'checks["narrative_system_user_gravatar_absent"] =\n',
                'checks["narrative_system_user_gravatar_absent"] = true ||\n',
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                'checks["narrative_system_user_branded"] =\n  checks.values_at(',
                'checks["narrative_system_user_branded"] = true ||\n  checks.values_at(',
                1,
            ),
        ),
    )
    for hostile_template, hostile_configure, hostile_verifier in hostile_cases:
        try:
            VALIDATOR.validate_narrative_avatar_contract(
                hostile_template,
                hostile_configure,
                hostile_verifier,
            )
        except RuntimeError:
            continue
        raise RuntimeError("Narrative avatar hostile mutation was accepted.")


def test_branding_email_renderer_contract() -> None:
    renderer = (ROOT / "scripts/render-branding-email.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_branding_email_renderer(renderer)
    hostile_replacements = (
        ("Email.extract_parts(mail.encoded)", "Email.extract_body(mail)"),
        ("Email.extract_parts(digest.encoded)", "Email.extract_body(digest)"),
        ("Email.extract_parts(mail.encoded)", "Email.extract_parts(mail)"),
        ("Email.extract_parts(digest.encoded)", "Email.extract_parts(digest)"),
        ("Email.extract_parts(mail.encoded)", "Email.extract_parts(mail.to_s)"),
        (
            'puts "Mochirii mail presentation passed."',
            'puts body\nputs "Mochirii mail presentation passed."',
        ),
        (
            'puts "Mochirii mail presentation passed."',
            'warn expected_address\nputs "Mochirii mail presentation passed."',
        ),
        ('stage4_fixture == "true" &&', 'stage4_fixture == "true" ||'),
        (
            'expected_scheme = allow_fixture_http ? "http" : "https"',
            'expected_scheme = "http"',
        ),
        (
            'expected_path = "/session/email-login/mochirii-fixture-admin-login-token"',
            'expected_path = "/session/email-login/wrong-token"',
        ),
        (
            "Somebody asked to log in to your account on [Mochirii Forums](#{expected_base_url}).",
            "Somebody asked to log in to your account on a different site.",
        ),
        (
            'normalized_text = text_part.to_s.gsub("\\r\\n", "\\n").strip',
            "normalized_text = text_part.to_s.strip",
        ),
        (
            "  unless html_part.nil? &&",
            "  unless true &&",
        ),
        (
            "      normalized_text == expected_text",
            "      normalized_text.include?(expected_link)",
        ),
        ("      expected.query.nil? &&", "      true &&"),
        ("      expected.fragment.nil?", "      true"),
        (
            'admin_confirmation_fixture_token = "0123456789abcdef" * 2',
            'admin_confirmation_fixture_token = "fixture-token"',
        ),
        (
            "unless admin_confirmation_fixture_token.match?(/\\A[0-9a-f]+\\z/) && admin_confirmation_fixture_token.length == 32",
            "unless true",
        ),
        (
            "      admin_confirmation_fixture_token,",
            '      "fixture-token",',
        ),
        ("SiteSetting.site_digest_logo_url", "SiteSetting.digest_logo_url"),
        ("def materialize(delivery, label:)", "def materialize(delivery)"),
        ("mail.is_a?(Mail::Message)", "mail.respond_to?(:header)"),
        ("topic.id != SiteSetting.welcome_topic_id", "false"),
        ("Topic.transaction(requires_new: true)", "Topic.transaction"),
        ("topic.update_columns(created_at: 2.days.ago)", "topic.update_columns(created_at: 2.minutes.ago)"),
        ("since: 3.days.ago", "since: 1.day.ago"),
        ("raise ActiveRecord::Rollback", "next"),
        (
            'deliveries["digest"] = render_stage4_digest!(user: bot, topic: post.topic)',
            'deliveries["digest"] = UserNotifications.digest(bot, since: 30.days.ago, skip_unsubscribe_links: true)',
        ),
    )
    for current, stale in hostile_replacements:
        hostile = renderer.replace(current, stale, 1)
        if hostile == renderer:
            raise RuntimeError("Branding email renderer hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_branding_email_renderer(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Branding email renderer accepted a stale API or output mutation.")

    components = json.loads(
        (ROOT / "docs/operations/third-party-components.v1.json").read_text(encoding="utf-8")
    )
    email_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") == "lib/email.rb"
    ]
    if email_evidence != [VALIDATOR.PINNED_EMAIL_EVIDENCE]:
        raise RuntimeError("Pinned email extraction API evidence differs.")
    mail_rendering_paths = {entry["path"] for entry in VALIDATOR.PINNED_MAIL_RENDERING_EVIDENCE}
    mail_rendering_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in mail_rendering_paths
    ]
    if mail_rendering_evidence != VALIDATOR.PINNED_MAIL_RENDERING_EVIDENCE:
        raise RuntimeError("Pinned administrator-mail and digest-logo evidence differs.")

    fixture = (ROOT / "scripts/test-admin-login-link.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_admin_login_link_fixture(fixture)
    fixture_hostiles = (
        fixture.replace('fixture_base = "http://forums.mochirii.com"', 'fixture_base = "https://forums.mochirii.com"', 1),
        fixture.replace('"production HTTP mode",', '"production HTTP mode removed",', 1),
        fixture.replace('"foreign host" =>', '"foreign host removed" =>', 1),
        fixture.replace('"wrong token" =>', '"wrong token removed" =>', 1),
        fixture.replace('"query" =>', '"query removed" =>', 1),
        fixture.replace('"mixed-case foreign URL" =>', '"mixed-case foreign URL removed" =>', 1),
        fixture.replace('"duplicate recovery link" =>', '"duplicate recovery link removed" =>', 1),
        fixture.replace('"entity-encoded HTML anchor" =>', '"entity-encoded HTML anchor removed" =>', 1),
        fixture.replace('"entity-encoded Markdown link" =>', '"entity-encoded Markdown link removed" =>', 1),
        fixture.replace(
            '"transport CRLF normalization changed the exact mail"',
            '"transport CRLF normalization case removed"',
            1,
        ),
        fixture.replace(
            '"unexpected pre-delivery HTML part",',
            '"unexpected pre-delivery HTML part removed",',
            1,
        ),
        fixture.replace('assert_fixture(error.cause.nil?, "#{label} retained an exception cause")', '', 1),
        fixture.replace('source.scan("SiteSetting.site_digest_logo_url").length == 1', 'true', 1),
        fixture.replace(
            'source.scan(\'admin_confirmation_fixture_token = "0123456789abcdef" * 2\').length == 1',
            "true",
            1,
        ),
        fixture.replace('source.scan("SecureRandom").empty?', "true", 1),
        fixture.replace(
            '"encoded-separator administrator confirmation token" =>',
            '"encoded-separator administrator confirmation token removed" =>',
            1,
        ),
    )
    for hostile_fixture in fixture_hostiles:
        if hostile_fixture == fixture:
            raise RuntimeError("Administrator recovery-link fixture hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_admin_login_link_fixture(hostile_fixture)
        except RuntimeError:
            continue
        raise RuntimeError("Administrator recovery-link fixture hostile mutation was accepted.")
    upstream = (ROOT / "scripts/verify-pinned-source.py").read_text(encoding="utf-8")
    VALIDATOR.validate_pinned_source_verifier(upstream)
    for canary in (
        "PINNED_EMAIL_EXTRACT_PARTS_BLOCK = b'''  def self.extract_parts(raw)",
        "PINNED_ADMIN_LOGIN_METHOD_BLOCK = b'''",
        "PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE = b'''",
        "PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK = b'''",
        "PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK = b'''",
        "PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX = b'''",
        "PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX = b'''",
        "PINNED_BUILD_EMAIL_HELPER_SOURCE = b'''",
        "PINNED_BASE_PROTOCOL_BLOCK = b'''",
        "PINNED_ADMIN_LOGIN_LOCALE_BLOCK = b'''",
        "PINNED_DIGEST_LOGO_METHOD_BLOCK = b'''",
        "def verify_email_extract_parts_method(source: bytes) -> None:",
        "def verify_email_semantics(source: bytes) -> None:",
        "def verify_mail_evidence_manifest(components: dict) -> None:",
        "def verify_mail_semantics(core: dict[str, bytes]) -> None:",
        'hashlib.sha256(source).hexdigest() != PINNED_EMAIL_SHA256',
        'verify_email_semantics(core["lib/email.rb"])',
        "verify_mail_evidence_manifest(components)",
        "verify_mail_semantics(core)",
    ):
        if upstream.count(canary) != 1:
            raise RuntimeError("Pinned email extraction semantic gate differs.")

    baseline_email = (
        b"module Email\n"
        + UPSTREAM.PINNED_EMAIL_EXTRACT_PARTS_BLOCK
        + b"  def self.site_title\n    nil\n  end\nend\n"
    )
    UPSTREAM.verify_email_extract_parts_method(baseline_email)
    hostile_email_methods = (
        baseline_email.replace(b"[text&.decoded, html&.decoded]", b"[raw.to_s, nil]", 1),
        baseline_email.replace(b"text = mail.text_part", b"text = mail.html_part", 1),
        baseline_email.replace(b"def self.extract_parts(raw)", b"def self.extract_body(raw)", 1),
        baseline_email.replace(
            UPSTREAM.PINNED_EMAIL_EXTRACT_PARTS_BLOCK,
            b"  # mail = Mail.new(raw)\n"
            b"  # if mail.multipart?\n"
            b"  # [text&.decoded, html&.decoded]\n"
            b"  def self.extract_parts(raw)\n"
            b"    [raw.to_s, nil]\n"
            b"  end\n\n",
            1,
        ),
    )
    for hostile in hostile_email_methods:
        try:
            UPSTREAM.verify_email_extract_parts_method(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Pinned email semantic gate accepted a wrong implementation.")

    synthetic_mail_core = {
        "app/mailers/user_notifications.rb":
            UPSTREAM.PINNED_ADMIN_LOGIN_METHOD_BLOCK
            + b"  def account_created(user, opts = {})\n  end\n\n"
            + UPSTREAM.PINNED_EMAIL_LOGIN_HELPER_BLOCK
            + b"  def build_summary_for(user)\n  end\n",
        "app/mailers/admin_confirmation_mailer.rb": UPSTREAM.PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE,
        "lib/admin_confirmation.rb":
            UPSTREAM.PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK
            + b"  def email_confirmed!\n  end\n",
        "config/routes.rb": UPSTREAM.PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK,
        "lib/email/message_builder.rb":
            UPSTREAM.PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX
            + b"      if @opts[:recipient_user].present?\n      end\n"
            + UPSTREAM.PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX
            + b"      if @template_args[:unsubscribe_instructions].present?\n      end\n"
            + UPSTREAM.PINNED_MESSAGE_BUILDER_BODY_BLOCK
            + b"    def build_args\n    end\n",
        "lib/email/build_email_helper.rb": UPSTREAM.PINNED_BUILD_EMAIL_HELPER_SOURCE,
        "lib/discourse.rb":
            UPSTREAM.PINNED_BASE_PROTOCOL_BLOCK
            + b"  def self.current_hostname_with_port\n  end\n",
        "config/locales/server.en.yml":
            UPSTREAM.PINNED_ADMIN_LOGIN_LOCALE_BLOCK
            + b"    account_created:\n      title: fixture\n",
        "app/helpers/user_notifications_helper.rb":
            UPSTREAM.PINNED_DIGEST_LOGO_METHOD_BLOCK
            + b"  def html_site_link\n  end\n",
    }

    def synthetic_evidence(core: dict[str, bytes]) -> dict[str, tuple[int, str]]:
        return {
            path: (len(body), hashlib.sha256(body).hexdigest())
            for path, body in core.items()
        }

    original_mail_evidence = UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE
    try:
        UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE = synthetic_evidence(synthetic_mail_core)
        UPSTREAM.verify_mail_semantics(synthetic_mail_core)
        mail_hostiles = (
            (
                "app/mailers/user_notifications.rb",
                b"opts[:email_token]",
                b"nil",
            ),
            (
                "app/mailers/user_notifications.rb",
                b"email_token: email_token",
                b"email_token: nil",
            ),
            (
                "app/mailers/admin_confirmation_mailer.rb",
                b"confirm_admin_url(token: token, host: Discourse.base_url)",
                b"confirm_admin_url(token: nil, host: Discourse.base_url)",
            ),
            (
                "lib/admin_confirmation.rb",
                b"@token = SecureRandom.hex",
                b'@token = "invalid-token"',
            ),
            (
                "config/routes.rb",
                b"token: /[0-9a-f]+/",
                b"token: /[^/]+/",
            ),
            (
                "lib/email/message_builder.rb",
                b"base_url: Discourse.base_url",
                b'base_url: "http://fixture.invalid"',
            ),
            (
                "lib/email/message_builder.rb",
                b'.text_body_template", augmented_template_args)',
                b'.html_body_template", augmented_template_args)',
            ),
            (
                "lib/email/message_builder.rb",
                b"return unless html_override = @opts[:html_override]",
                b"html_override = @opts[:html_override]",
            ),
            (
                "lib/email/build_email_helper.rb",
                b"if message && h = builder.html_part",
                b"if message && h = builder.body",
            ),
            (
                "lib/discourse.rb",
                b'SiteSetting.force_https? ? "https" : "http"',
                b'"https"',
            ),
            (
                "config/locales/server.en.yml",
                b"%{base_url}/session/email-login/%{email_token}",
                b"%{base_url}/session/email-login/fixed-token",
            ),
            (
                "app/helpers/user_notifications_helper.rb",
                b"SiteSetting.site_digest_logo_url",
                b"SiteSetting.digest_logo_url",
            ),
        )
        for path, current, stale in mail_hostiles:
            hostile_core = dict(synthetic_mail_core)
            hostile_core[path] = hostile_core[path].replace(current, stale, 1)
            if hostile_core[path] == synthetic_mail_core[path]:
                raise RuntimeError("Pinned mail semantic hostile mutation anchor is absent.")
            UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE = synthetic_evidence(hostile_core)
            try:
                UPSTREAM.verify_mail_semantics(hostile_core)
            except RuntimeError:
                continue
            raise RuntimeError("Pinned mail semantic gate accepted a hostile implementation.")
    finally:
        UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE = original_mail_evidence

    verifier_hostiles = (
        upstream.replace(
            '    verify_email_semantics(core["lib/email.rb"])\n',
            '    if False:\n        verify_email_semantics(core["lib/email.rb"])\n',
            1,
        ),
        upstream.replace(
            '    verify_email_semantics(core["lib/email.rb"])\n',
            '    # verify_email_semantics(core["lib/email.rb"])\n',
            1,
        ),
        upstream.replace(
            "    verify_mail_semantics(core)\n",
            "    if False:\n        verify_mail_semantics(core)\n",
            1,
        ),
        upstream.replace(
            "    verify_mail_evidence_manifest(components)\n",
            "    if False:\n        verify_mail_evidence_manifest(components)\n",
            1,
        ),
    )
    for hostile in verifier_hostiles:
        if hostile == upstream:
            raise RuntimeError("Pinned-source verifier hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_pinned_source_verifier(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Pinned-source verifier accepted a disabled email semantic gate.")


def test_certificate_create_cleanup() -> None:
    old_identifier = "00000000-0000-4000-8000-000000000001"
    new_identifier = "00000000-0000-4000-8000-000000000002"
    name = "mochirii-media-forums-fixture-transaction"
    inventory = [{"id": old_identifier, "name": "mochirii-media-forums-old"}]
    calls: list[tuple[str, str]] = []
    original_api = ROTATE.api

    def hostile_api(token: str, method: str, path: str, payload=None):
        del token, payload
        calls.append((method, path))
        if method == "POST" and path == "/certificates":
            inventory.append({"id": new_identifier, "name": name})
            return {"certificate": {"id": "malformed", "name": name}}
        if method == "GET" and path == "/certificates?per_page=200":
            return {"certificates": list(inventory), "links": {"pages": {}}}
        if method == "DELETE" and path == f"/certificates/{new_identifier}":
            inventory[:] = [row for row in inventory if row["id"] != new_identifier]
            return None
        raise RuntimeError(f"Unexpected mocked provider operation: {method} {path}")

    ROTATE.api = hostile_api
    try:
        try:
            ROTATE.create_transaction_certificate(
                "fixture-token",
                name,
                {"name": name, "type": "custom"},
                {old_identifier},
            )
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Malformed certificate creation readback did not fail closed.")
    finally:
        ROTATE.api = original_api
    if inventory != [{"id": old_identifier, "name": "mochirii-media-forums-old"}]:
        raise RuntimeError("Malformed certificate creation left a provider-side orphan.")
    if ("DELETE", f"/certificates/{new_identifier}") not in calls:
        raise RuntimeError("Malformed certificate creation did not delete the exact new object.")


def test_certificate_identity_read_allowlist() -> None:
    identifier = "00000000-0000-4000-8000-000000000001"

    class FixtureResponse:
        status = 200

        def __init__(self, url: str):
            self.url = url
            self.body = json.dumps({"certificate": {"id": identifier, "name": "mochirii-media-forums-old"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return self.url

        def read(self, limit: int):
            result, self.body = self.body[:limit], self.body[limit:]
            return result

    class FixtureOpener:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        def open(self, request, timeout):
            del timeout
            self.calls.append((request.method, request.full_url))
            return FixtureResponse(request.full_url)

    original = ROTATE.PROVIDER_OPENER
    opener = FixtureOpener()
    ROTATE.PROVIDER_OPENER = opener
    try:
        document = ROTATE.api("fixture-provider-token", "GET", f"/certificates/{identifier}")
        if document != {"certificate": {"id": identifier, "name": "mochirii-media-forums-old"}}:
            raise RuntimeError("Exact certificate identity readback changed.")
        allowed_calls = len(opener.calls)
        for method, path in (
            ("PUT", f"/certificates/{identifier}"),
            ("POST", f"/certificates/{identifier}"),
            ("GET", "/certificates/not-a-uuid"),
            ("GET", f"/certificates/{identifier}?extra=1"),
            ("DELETE", f"/certificates/{identifier}/extra"),
        ):
            try:
                ROTATE.api("fixture-provider-token", method, path)
            except ROTATE.RotationError:
                pass
            else:
                raise RuntimeError("Hostile certificate identity method or path was accepted.")
        if len(opener.calls) != allowed_calls:
            raise RuntimeError("Rejected certificate identity path reached the provider opener.")
    finally:
        ROTATE.PROVIDER_OPENER = original


def test_http_redirect_boundaries() -> None:
    request = urllib.request.Request("https://api.digitalocean.com/v2/certificates")
    for target in (
        "https://example.invalid/capture",
        "https://api.digitalocean.com/v2/certificates/redirected",
    ):
        if ROTATE.NoRedirectHandler().redirect_request(request, None, 302, "fixture", {}, target) is not None:
            raise RuntimeError("Provider no-redirect handler accepted a redirect.")
    github_request = urllib.request.Request(
        "https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/main"
    )
    for target in (
        "https://example.invalid/capture",
        "https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/other",
    ):
        if UPSTREAM.NoRedirectHandler().redirect_request(github_request, None, 302, "fixture", {}, target) is not None:
            raise RuntimeError("Official-source no-redirect handler accepted a redirect.")

    class RedirectOpener:
        def __init__(self, location: str):
            self.location = location
            self.calls = 0

        def open(self, requested, timeout):
            del timeout
            self.calls += 1
            raise urllib.error.HTTPError(
                requested.full_url,
                302,
                "fixture redirect",
                {"Location": self.location},
                io.BytesIO(b"fixture"),
            )

    original_provider_opener = ROTATE.PROVIDER_OPENER
    provider_redirect = RedirectOpener("https://example.invalid/capture")
    ROTATE.PROVIDER_OPENER = provider_redirect
    try:
        try:
            ROTATE.api("fixture-provider-token", "GET", "/certificates?per_page=200")
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Provider API followed a cross-authority redirect.")
    finally:
        ROTATE.PROVIDER_OPENER = original_provider_opener
    if provider_redirect.calls != 1:
        raise RuntimeError("Provider redirect caused a second request.")

    original_official_opener = UPSTREAM.OFFICIAL_OPENER
    for url, headers, location in (
        (
            "https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/main",
            None,
            "https://example.invalid/capture",
        ),
        (
            "https://registry-1.docker.io/v2/discourse/base/manifests/sha256:" + "a" * 64,
            {"Authorization": "Bearer fixture-registry-token"},
            "https://registry-1.docker.io/v2/discourse/base/manifests/other",
        ),
    ):
        redirect = RedirectOpener(location)
        UPSTREAM.OFFICIAL_OPENER = redirect
        try:
            with environment({**os.environ, "GITHUB_TOKEN": "fixture-github-token"}):
                try:
                    UPSTREAM.request(url, headers=headers, limit=1024)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("Official-source request followed a redirect.")
        finally:
            UPSTREAM.OFFICIAL_OPENER = original_official_opener
        if redirect.calls != 1:
            raise RuntimeError("Official-source redirect caused a second request.")

    class DriftResponse:
        status = 200
        headers: dict[str, str] = {}

        def __init__(self, url: str):
            self.url = url
            self.complete = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return self.url

        def read(self, _limit):
            if self.complete:
                return b""
            self.complete = True
            return b"{}"

    class DriftOpener:
        def __init__(self, url: str):
            self.response = DriftResponse(url)
            self.calls = 0

        def open(self, _request, timeout):
            del timeout
            self.calls += 1
            return self.response

    drift = DriftOpener("https://example.invalid/provider-response")
    ROTATE.PROVIDER_OPENER = drift
    try:
        try:
            ROTATE.api("fixture-provider-token", "GET", "/certificates?per_page=200")
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Provider response URL drift was accepted.")
    finally:
        ROTATE.PROVIDER_OPENER = original_provider_opener
    official_drift = DriftOpener("https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/other")
    UPSTREAM.OFFICIAL_OPENER = official_drift
    try:
        try:
            UPSTREAM.request("https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/main")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Official-source response URL drift was accepted.")
    finally:
        UPSTREAM.OFFICIAL_OPENER = original_official_opener

    hostile_urls = (
        "https://api.github.com.example.invalid/repos/discourse/discourse/git/commits/" + "a" * 40,
        "https://user@api.github.com/repos/discourse/discourse/git/commits/" + "a" * 40,
        "https://api.github.com:444/repos/discourse/discourse/git/commits/" + "a" * 40,
        "https://registry-1.docker.io/v2/discourse/base/manifests/" + "a" * 129,
    )
    for url in hostile_urls:
        expect_validation_failure(lambda url=url: UPSTREAM.validate_official_url(url), "hostile official URL")

    class SlowResponse:
        def read(self, _limit):
            return b"fixture"

    original_monotonic = ROTATE.time.monotonic
    ticks = iter((0.0, 0.0, 61.0))
    ROTATE.time.monotonic = lambda: next(ticks)
    try:
        try:
            ROTATE.read_bounded_response(SlowResponse(), 1024, 60.0)
        except ROTATE.ProviderResponseUncertain:
            pass
        else:
            raise RuntimeError("Provider total response deadline was treated as an inactivity timeout.")
    finally:
        ROTATE.time.monotonic = original_monotonic


def test_certificate_inventory_capacity() -> None:
    inventory = [
        {"id": f"00000000-0000-4000-8000-{index:012x}", "name": f"fixture-{index}"}
        for index in range(200)
    ]
    calls: list[tuple[str, str]] = []
    original_api = ROTATE.api

    def full_inventory_api(token: str, method: str, path: str, payload=None):
        del token, payload
        calls.append((method, path))
        if method == "GET" and path == "/certificates?per_page=200":
            return {"certificates": list(inventory), "links": {"pages": {}}}
        if method == "POST":
            inventory.append(
                {"id": "00000000-0000-4000-8000-000000000200", "name": "forbidden-201st-object"}
            )
            return {"certificate": inventory[-1]}
        raise RuntimeError(f"Unexpected mocked provider operation: {method} {path}")

    ROTATE.api = full_inventory_api
    try:
        try:
            ROTATE.pre_mutation_inventory("fixture-token")
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Full certificate inventory did not stop before mutation.")
    finally:
        ROTATE.api = original_api
    if any(method == "POST" for method, _ in calls) or len(inventory) != 200:
        raise RuntimeError("Capacity gate allowed a 201st certificate mutation.")


def test_certificate_preparation_recovery_contract() -> None:
    prepare = (ROOT / "scripts/prepare-media-certificate.sh").read_text(encoding="utf-8")
    installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    prepared_branch = prepare[prepare.index("if [[ -e ${preparation_journal}") : prepare.index("media_record_event initial-certificate started")]
    recovery_start = prepared_branch.index(
        'media_reconcile_acme "${acme_helper}" /etc/letsencrypt/mochirii-cloudflare.ini'
    )
    prepared_recovery = prepared_branch[recovery_start:]
    prepared_order = (
        'media_reconcile_acme "${acme_helper}" /etc/letsencrypt/mochirii-cloudflare.ini',
        'if [[ -e ${lineage}',
        "if validate_lineage; then",
        "write_preparation_journal issued",
        'validate_lineage || fail "Recovered certificate lineage changed before completion.',
        "clear_preparation_journal",
    )
    positions = [prepared_recovery.index(value) for value in prepared_order]
    if positions != sorted(positions):
        raise RuntimeError("Prepared-phase certificate recovery can adopt a lineage before ACME reconciliation or exact validation.")
    issuance = prepare[prepare.index("media_run_certbot_dns_transaction") :]
    if issuance.index("validate_lineage") > issuance.index("write_preparation_journal issued"):
        raise RuntimeError("Initial certificate issuance can commit an unvalidated lineage.")
    for required in (
        'archive_entries != {f"{name}1.pem" for name in names}',
        'link.resolve(strict=True) != expected.resolve(strict=True)',
        'openssl x509 -in "${lineage}/cert.pem" -checkhost media-forums.mochirii.com',
        '[[ ${san_names} == "DNS:media-forums.mochirii.com" ]]',
        'document["preexistingLineage"] is not False',
        "discard_incomplete_transaction_lineage()",
        'str(base) != "/etc/letsencrypt"',
        're.fullmatch(r"(?:cert|chain|fullchain|privkey)[1-9][0-9]{0,5}[.]pem", entry.name)',
        'not stat.S_ISLNK(metadata.st_mode)',
        'normalized.parent != archive',
        "fsync_directory(live.parent)",
        "fsync_directory(archive.parent)",
        'discard_incomplete_transaction_lineage || fail "Interrupted certificate preparation has unsafe or ambiguous partial lineage state;',
    ):
        if required not in prepare:
            raise RuntimeError("Recovered certificate lineage lost an exact ownership, path, key, or SAN invariant.")
    cleanup_start = prepared_recovery.index("discard_incomplete_transaction_lineage || fail")
    if cleanup_start < prepared_recovery.index("if validate_lineage; then"):
        raise RuntimeError("Prepared certificate recovery can discard a fully valid lineage before commit-forward adoption.")
    if any(value in prepare for value in ("shutil.rmtree", "rm -rf -- \"${lineage}\"", "find ${lineage} -delete")):
        raise RuntimeError("Prepared certificate recovery broadened beyond the exact journal-owned lineage inventory.")

    prepared_validation = installer[installer.index("validate_prepared_input()") : installer.index("export DEBIAN_FRONTEND")]
    if any(value not in prepared_validation for value in ('[[ -f ${prepared} && ! -L ${prepared} ]]', 'root:root 600', 'cmp -s -- "${source}" "${prepared}"')):
        raise RuntimeError("Certificate installer does not exactly validate preparation-owned inputs before adoption.")
    targets = installer[installer.index("install_targets=(") : installer.index("write_install_journal()")]
    if "/etc/letsencrypt/mochirii-media.ini" in targets or "/etc/letsencrypt/mochirii-cloudflare.ini" in targets:
        raise RuntimeError("Certificate installer can delete or recreate preparation-owned issuance inputs.")
    cleanup = installer[installer.index("cleanup_installation() {") : installer.index("on_exit() {")]
    if 'for target in "${install_targets[@]}"' not in cleanup or "prepared_certbot" in cleanup or "prepared_dns" in cleanup:
        raise RuntimeError("Partial certificate installation cleanup crosses the adopted preparation boundary.")
    if installer.index('validate_prepared_input "${dns_source}"') > installer.index("write_install_journal"):
        raise RuntimeError("Certificate installation journals a mutation before validating prepared input bytes.")


def test_certificate_control_evidence_adoption_contract() -> None:
    installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    evidence = (ROOT / "scripts/host-control-evidence.py").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    required = (
        'assert-held --locks primary,media',
        'run --locks primary,media',
        'read_current_control_binding()',
        '"manifestSha256": manifest_sha',
        '"previousControlEvidenceSha256": predecessor',
        '[[ ${current_commit} == "${commit}" && ${current_manifest} == "${manifest_sha}" && ${current_sha} == "${predecessor}" ]]',
        'validate_installed_automation_bytes()',
        'seal_certificate_control_state()',
        '--operation certificate-install',
        'verify_certificate_control_state()',
        'record.get("previousControlEvidenceSha256") != predecessor',
        'timeout --signal=TERM --kill-after=10s 180s bash "${host_security_verifier}"',
    )
    if any(value not in installer for value in required):
        raise RuntimeError("Certificate install lost its journaled predecessor, exact-byte readback, or terminal control reseal boundary.")
    if "--locks media,primary" in installer:
        raise RuntimeError("Certificate install lock ordering can deadlock the governed host-control upgrade.")

    recovery_start = installer.index('if [[ ${prior_install_phase} == committed ]]')
    recovery_end = installer.index('cleanup_installation || fail', recovery_start)
    recovery = installer[recovery_start:recovery_end]
    recovery_order = (
        'validate_installed_automation_bytes || fail',
        'media_run_bounded install-resume-enabled',
        'media_run_bounded install-resume-active',
        'media_run_bounded install-resume-preflight',
        'seal_certificate_control_state || fail',
        'verify_certificate_control_state || fail',
        'media_record_event certificate-install passed',
        'clear_install_journal',
    )
    recovery_positions = [recovery.index(value) for value in recovery_order]
    if recovery_positions != sorted(recovery_positions):
        raise RuntimeError("Committed certificate retry can report success before adopting and verifying its control record.")

    install = installer[installer.index('write_install_journal installing'):]
    install_order = (
        'write_install_journal installing',
        'media_record_event certificate-install started',
        'media_run_bounded install-timer-enabled-readback',
        'media_run_bounded install-timer-active-readback',
        'validate_installed_automation_bytes || fail',
        'write_install_journal committed',
        'seal_certificate_control_state || fail',
        'verify_certificate_control_state || fail',
        'media_record_event certificate-install passed',
        'clear_install_journal',
    )
    install_positions = [install.index(value) for value in install_order]
    if install_positions != sorted(install_positions):
        raise RuntimeError("Certificate install can clear or report success before exact readback, reseal, and terminal verification.")
    if 'if path.exists() or path.is_symlink():' not in evidence or 'set(document) - {"recordedAt"}' not in evidence:
        raise RuntimeError("Immutable host-control evidence lost exact idempotent retry adoption.")
    for source in (evidence, verifier):
        if '"certificate-install"' not in source:
            raise RuntimeError("Certificate-authored host-control evidence is rejected by a stable control component.")


def test_certificate_commit_forward_retirement() -> None:
    endpoint_id = "00000000-0000-4000-8000-000000000010"
    old_identifier = "00000000-0000-4000-8000-000000000011"
    new_identifier = "00000000-0000-4000-8000-000000000012"
    origin = "mochirii-forums.sgp1.digitaloceanspaces.com"
    name = "mochirii-media-forums-fixture-commit-forward"
    inventory = {
        old_identifier: "mochirii-media-forums-old",
        new_identifier: name,
    }
    journal = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": origin,
        "customDomain": ROTATE.MEDIA_HOST,
        "transactionName": name,
        "priorCertificateIds": [old_identifier],
        "oldCertificateId": old_identifier,
        "oldTlsSha256": "a" * 64,
        "newCertificateSha256": "b" * 64,
        "newCertificateId": new_identifier,
        "ttl": 3600,
        "phase": "retiring-old",
        "createdAt": 1,
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    calls: list[tuple[str, str]] = []
    cleared = False
    stale_inventory_reads = 0
    originals = {
        "load_journal": ROTATE.load_journal,
        "endpoint": ROTATE.endpoint,
        "observe": ROTATE.observe_transaction_certificates,
        "inventory": ROTATE.certificate_inventory,
        "api": ROTATE.api,
        "wait": ROTATE.wait_for_tls,
        "clear": ROTATE.clear_journal,
        "update": ROTATE.update_journal,
        "time": ROTATE.time.time,
    }

    def fixture_endpoint(token: str, requested: str):
        del token
        if requested != endpoint_id:
            raise RuntimeError("Unexpected endpoint identity.")
        return {
            "id": endpoint_id,
            "origin": origin,
            "ttl": 3600,
            "custom_domain": ROTATE.MEDIA_HOST,
            "certificate_id": new_identifier,
        }

    def fixture_inventory(token: str):
        nonlocal stale_inventory_reads
        del token
        if stale_inventory_reads:
            stale_inventory_reads -= 1
            return [
                {"id": old_identifier, "name": "mochirii-media-forums-old"},
                {"id": new_identifier, "name": name},
            ]
        return [{"id": identifier, "name": value} for identifier, value in inventory.items()]

    def response_loss_api(token: str, method: str, path: str, payload=None):
        nonlocal stale_inventory_reads
        del token, payload
        calls.append((method, path))
        if method == "DELETE" and path == f"/certificates/{old_identifier}":
            existed = old_identifier in inventory
            inventory.pop(old_identifier, None)
            if existed:
                stale_inventory_reads = 1
            raise ROTATE.ProviderResponseUncertain("Fixture lost the successful DELETE response.")
        if method == "PUT":
            raise RuntimeError("Commit-forward reconciliation attempted a forbidden rollback.")
        raise RuntimeError(f"Unexpected mocked provider operation: {method} {path}")

    def clear_fixture_journal() -> None:
        nonlocal cleared
        cleared = True

    def update_fixture_journal(document: dict[str, object], **changes: object):
        del document
        journal.update(changes)
        return dict(journal)

    observed_times = iter((100, 161))

    ROTATE.load_journal = lambda requested, requested_origin: journal
    ROTATE.endpoint = fixture_endpoint
    ROTATE.observe_transaction_certificates = lambda *_args, **_kwargs: [new_identifier]
    ROTATE.certificate_inventory = fixture_inventory
    ROTATE.api = response_loss_api
    ROTATE.wait_for_tls = lambda fingerprint: None
    ROTATE.clear_journal = clear_fixture_journal
    ROTATE.update_journal = update_fixture_journal
    ROTATE.time.time = lambda: next(observed_times)
    try:
        for expected_failure in ("stale inventory", "first absence observation"):
            try:
                ROTATE.reconcile_journal("fixture-token", endpoint_id, origin)
            except ROTATE.RotationError:
                pass
            else:
                raise RuntimeError(f"Uncertain retirement passed during {expected_failure}.")
            if cleared:
                raise RuntimeError("Uncertain retirement cleared its recovery journal prematurely.")
        if not ROTATE.reconcile_journal("fixture-token", endpoint_id, origin):
            raise RuntimeError("Commit-forward certificate reconciliation did not complete.")
    finally:
        ROTATE.load_journal = originals["load_journal"]
        ROTATE.endpoint = originals["endpoint"]
        ROTATE.observe_transaction_certificates = originals["observe"]
        ROTATE.certificate_inventory = originals["inventory"]
        ROTATE.api = originals["api"]
        ROTATE.wait_for_tls = originals["wait"]
        ROTATE.clear_journal = originals["clear"]
        ROTATE.update_journal = originals["update"]
        ROTATE.time.time = originals["time"]
    if not cleared or old_identifier in inventory or new_identifier not in inventory:
        raise RuntimeError("Commit-forward retirement did not preserve only the new certificate.")
    if any(method == "PUT" for method, _ in calls):
        raise RuntimeError("Commit-forward retirement attempted to rebind the old certificate.")
    if sum(method == "DELETE" for method, _ in calls) != 3:
        raise RuntimeError("Commit-forward retirement did not retry the exact idempotent deletion.")


def test_certificate_commit_forward_ignores_stale_absence() -> None:
    endpoint_id = "00000000-0000-4000-8000-000000000020"
    old_identifier = "00000000-0000-4000-8000-000000000021"
    new_identifier = "00000000-0000-4000-8000-000000000022"
    origin = "mochirii-forums.sgp1.digitaloceanspaces.com"
    name = "mochirii-media-forums-fixture-stale-absence"
    delete_attempts = 0
    cleared = False
    journal = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": origin,
        "customDomain": ROTATE.MEDIA_HOST,
        "transactionName": name,
        "priorCertificateIds": [old_identifier],
        "oldCertificateId": old_identifier,
        "oldTlsSha256": "c" * 64,
        "newCertificateSha256": "d" * 64,
        "newCertificateId": new_identifier,
        "ttl": 3600,
        "phase": "retiring-old",
        "createdAt": 1,
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    originals = {
        "load_journal": ROTATE.load_journal,
        "endpoint": ROTATE.endpoint,
        "observe": ROTATE.observe_transaction_certificates,
        "inventory": ROTATE.certificate_inventory,
        "api": ROTATE.api,
        "wait": ROTATE.wait_for_tls,
        "clear": ROTATE.clear_journal,
        "update": ROTATE.update_journal,
        "time": ROTATE.time.time,
    }

    def fixture_endpoint(_token: str, _requested: str):
        return {
            "id": endpoint_id,
            "origin": origin,
            "ttl": 3600,
            "custom_domain": ROTATE.MEDIA_HOST,
            "certificate_id": new_identifier,
        }

    def delete_despite_stale_absence(_token: str, method: str, path: str, payload=None):
        nonlocal delete_attempts
        del payload
        if method != "DELETE" or path != f"/certificates/{old_identifier}":
            raise RuntimeError("Unexpected stale-absence fixture operation.")
        delete_attempts += 1
        return None

    def clear_fixture_journal() -> None:
        nonlocal cleared
        cleared = True

    def update_fixture_journal(document: dict[str, object], **changes: object):
        del document
        journal.update(changes)
        return dict(journal)

    ROTATE.load_journal = lambda *_args: journal
    ROTATE.endpoint = fixture_endpoint
    ROTATE.observe_transaction_certificates = lambda *_args, **_kwargs: [new_identifier]
    ROTATE.certificate_inventory = lambda _token: [{"id": new_identifier, "name": name}]
    ROTATE.api = delete_despite_stale_absence
    ROTATE.wait_for_tls = lambda _fingerprint: None
    ROTATE.clear_journal = clear_fixture_journal
    ROTATE.update_journal = update_fixture_journal
    observed_times = iter((100, 161))
    ROTATE.time.time = lambda: next(observed_times)
    try:
        try:
            ROTATE.reconcile_journal("fixture-token", endpoint_id, origin)
        except ROTATE.RetirementSettlementPending:
            pass
        else:
            raise RuntimeError("A successful DELETE plus one immediate absence cleared the journal.")
        if cleared or journal["absenceObservations"] != 1 or journal["lastAbsenceAt"] != 100:
            raise RuntimeError("First successful-DELETE absence was not retained in the sealed journal.")
        if not ROTATE.reconcile_journal("fixture-token", endpoint_id, origin):
            raise RuntimeError("Time-separated successful-DELETE retirement did not complete.")
    finally:
        ROTATE.load_journal = originals["load_journal"]
        ROTATE.endpoint = originals["endpoint"]
        ROTATE.observe_transaction_certificates = originals["observe"]
        ROTATE.certificate_inventory = originals["inventory"]
        ROTATE.api = originals["api"]
        ROTATE.wait_for_tls = originals["wait"]
        ROTATE.clear_journal = originals["clear"]
        ROTATE.update_journal = originals["update"]
        ROTATE.time.time = originals["time"]
    if delete_attempts != 2 or not cleared:
        raise RuntimeError("Time-separated successful-DELETE retirement did not finish safely.")


def test_certificate_rejected_retirement_remains_blocked() -> None:
    endpoint_id = "00000000-0000-4000-8000-000000000030"
    old_identifier = "00000000-0000-4000-8000-000000000031"
    new_identifier = "00000000-0000-4000-8000-000000000032"
    origin = "mochirii-forums.sgp1.digitaloceanspaces.com"
    name = "mochirii-media-forums-fixture-hard-rejection"
    journal = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": origin,
        "customDomain": ROTATE.MEDIA_HOST,
        "transactionName": name,
        "priorCertificateIds": [old_identifier],
        "oldCertificateId": old_identifier,
        "oldTlsSha256": "e" * 64,
        "newCertificateSha256": "f" * 64,
        "newCertificateId": new_identifier,
        "ttl": 3600,
        "phase": "retiring-old",
        "createdAt": 1,
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    calls: list[tuple[str, str]] = []
    cleared = False
    originals = {
        "load_journal": ROTATE.load_journal,
        "endpoint": ROTATE.endpoint,
        "observe": ROTATE.observe_transaction_certificates,
        "inventory": ROTATE.certificate_inventory,
        "api": ROTATE.api,
        "wait": ROTATE.wait_for_tls,
        "clear": ROTATE.clear_journal,
        "update": ROTATE.update_journal,
    }

    ROTATE.load_journal = lambda *_args: journal
    ROTATE.endpoint = lambda *_args: {
        "id": endpoint_id,
        "origin": origin,
        "ttl": 3600,
        "custom_domain": ROTATE.MEDIA_HOST,
        "certificate_id": new_identifier,
    }
    ROTATE.observe_transaction_certificates = lambda *_args, **_kwargs: [new_identifier]
    ROTATE.certificate_inventory = lambda _token: [{"id": new_identifier, "name": name}]

    def rejected_delete(_token: str, method: str, path: str, payload=None):
        del payload
        calls.append((method, path))
        raise ROTATE.ProviderHTTPError(403)

    ROTATE.api = rejected_delete
    ROTATE.wait_for_tls = lambda _fingerprint: None

    def forbidden_clear() -> None:
        nonlocal cleared
        cleared = True

    ROTATE.clear_journal = forbidden_clear
    ROTATE.update_journal = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("Explicitly rejected DELETE advanced absence evidence.")
    )
    try:
        for _ in range(2):
            try:
                ROTATE.reconcile_journal("fixture-token", endpoint_id, origin)
            except ROTATE.ProviderHTTPError as error:
                if error.status != 403:
                    raise
            else:
                raise RuntimeError("Explicitly rejected certificate retirement was accepted.")
    finally:
        ROTATE.load_journal = originals["load_journal"]
        ROTATE.endpoint = originals["endpoint"]
        ROTATE.observe_transaction_certificates = originals["observe"]
        ROTATE.certificate_inventory = originals["inventory"]
        ROTATE.api = originals["api"]
        ROTATE.wait_for_tls = originals["wait"]
        ROTATE.clear_journal = originals["clear"]
        ROTATE.update_journal = originals["update"]
    if cleared or journal["absenceObservations"] != 0 or len(calls) != 2:
        raise RuntimeError("Explicitly rejected retirement did not retain the sealed journal.")


def test_storage_response_boundary() -> None:
    host_deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    prearmed = host_deploy.index(
        'readarray -t storage_journal_contract < <(create_storage_cleanup_journal "${storage_transaction_id}")'
    )
    armed = host_deploy.index("storage_fixture_created=true", prearmed)
    create = host_deploy.index("run_storage_fixture create", armed)
    failure_state = host_deploy.index('promote_storage_state "${storage_create_result}" "${storage_state}"', create)
    if not prearmed < armed < create < failure_state:
        raise RuntimeError("Hosted storage cleanup state is not armed before the untrusted streamed response.")

    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    required_isolation = (
        "image=discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
        "ruby_fixture_container=(--rm --pull=never --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --memory-swap 256m)",
        'docker pull "$image"',
        'docker image inspect "$image"',
    )
    if any(value not in disposable for value in required_isolation):
        raise RuntimeError("Disposable Ruby fixtures lost their exact pinned isolated container boundary.")
    for fixture in (
        "test-storage-response-boundary.rb",
        "test-backup-url-boundary.rb",
        "test-normal-upload-inventory.rb",
        "test-admin-login-link.rb",
        "test-narrative-avatar.rb",
        "test-sidekiq-processing-probe.rb",
    ):
        pattern = re.compile(
            r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+ruby /repo/scripts/'
            + re.escape(fixture)
            + r" >/dev/null"
        )
        if len(pattern.findall(disposable)) != 1:
            raise RuntimeError(f"Disposable Ruby fixture is not contained in the pinned image: {fixture}")
    normal_upload_fixture = (ROOT / "scripts/test-normal-upload-inventory.rb").read_text(encoding="utf-8")
    for canary in (
        'assert(inventory.keys.length == 2, "normal upload inventory leaked raw identity")',
        'assert_failure("object path is malformed")',
        'assert_failure("object size differs from its row")',
        'assert_failure("object ETag is malformed")',
        'assert_failure("object is absent")',
        'assert_failure("row count exceeds its bound")',
        'assert_failure("external S3 upload storage is inactive")',
        '"schemaVersion" => 2',
        '"repositoryTree" => "9" * 40',
        '"releaseArchiveBytes" => 512',
        'publisher_validator.source_authority(clean_document)',
        '"releaseArchiveContainsSecrets" => false',
        '"ordinaryDeploymentRequiresCurrentMain" => true',
        '"historicalReleaseAdoptionScope" => "clean-target-disaster-recovery-only"',
        'fetcher_source.split("\\nfetch_mode = ENV.fetch", 2)',
    ):
        if canary not in normal_upload_fixture:
            raise RuntimeError("Normal-upload inventory hostile fixture coverage differs.")

    # These hostile Ruby fixtures execute only in the exact pinned, isolated
    # disposable-bootstrap image asserted above. The offline Python contract
    # intentionally has no host Ruby or floating container dependency.


def test_ssh_dispatch_contract() -> None:
    source = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")
    backup_workflow = (ROOT / ".github/workflows/backup-forums.yml").read_text(encoding="utf-8")
    required = (
        "fcntl.LOCK_EX | fcntl.LOCK_NB",
        "signal.alarm(MAX_RECEIVE_SECONDS)",
        "MAX_RECEIVE_SECONDS = 300",
        '"/usr/local/sbin/mochirii-forums-deploy"',
        '"/usr/local/sbin/mochirii-forums-verify"',
        '"/usr/local/sbin/mochirii-forums-backup"',
        '"/usr/local/sbin/mochirii-forums-restore"',
        'PARTIAL_NAME = ".receive.partial"',
        "reconcile_partial()",
        "signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM",
        '"backup": re.compile(rf"\\Abackup {COMMIT} {DIGEST}\\Z")',
        '["/usr/local/sbin/mochirii-forums-backup", values[0], values[1]]',
    )
    if any(value not in source for value in required) or "shell=True" in source:
        raise RuntimeError("Forced-command SSH dispatcher lost its bounded non-shell contract.")
    backup_operation_contract = (
        '[[ "$GITHUB_RUN_ID" =~ ^[0-9]{1,32}$ ]]',
        'backup_operation_sha256="$(printf \'%s\' "mochirii-forums-backup-v1:${GITHUB_RUN_ID}" | sha256sum | awk \'{print $1}\')"',
        '[[ "$backup_operation_sha256" =~ ^[0-9a-f]{64}$ ]]',
        '"backup ${RELEASE_COMMIT} ${backup_operation_sha256}"',
    )
    if any(value not in backup_workflow for value in backup_operation_contract):
        raise RuntimeError("Backup workflow lost its stable opaque operation identity.")
    host_deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    canonical_compare = host_deploy.index('cmp -s -- "${trusted_archive}" "${quarantine}"')
    durable_consume = host_deploy.index('consume_incoming_archive || fail', canonical_compare)
    if (
        not canonical_compare < durable_consume
        or "incoming_archive_consumed=false" not in host_deploy
        or 'rm -f -- "${resolved_archive}"' not in host_deploy
        or "os.fsync(descriptor)" not in host_deploy
    ):
        raise RuntimeError("Root deployment does not durably consume its one-slot transport archive.")
    if os.name != "posix":
        return

    import fcntl

    dispatch = module_from("scripts/ssh-deploy-dispatch.py", "ssh_deploy_dispatch")
    commit = "a" * 40
    digest = "b" * 64
    valid = (
        f"receive {commit} {digest} 1",
        f"deploy {commit} {digest} 1 bootstrap",
        f"verify {commit}",
        f"backup {commit} {digest}",
        f"restore {commit}",
    )
    hostile = (
        "bash",
        "internal-sftp",
        f"verify {commit};id",
        f"receive {commit} {digest} 1 extra",
        f"backup {commit}",
        f"backup {commit} {digest} extra",
        f"deploy {commit} {digest} 1 rebuild\nwhoami",
    )
    if any(not any(pattern.fullmatch(value) for pattern in dispatch.COMMANDS.values()) for value in valid):
        raise RuntimeError("Forced-command SSH dispatcher rejected an exact allowed verb.")
    if any(any(pattern.fullmatch(value) for pattern in dispatch.COMMANDS.values()) for value in hostile):
        raise RuntimeError("Forced-command SSH dispatcher accepted a hostile command.")

    with tempfile.TemporaryDirectory(prefix="mochirii-dispatch-lock-") as directory:
        incoming = Path(directory)
        incoming.chmod(0o700)
        original_incoming = dispatch.INCOMING
        dispatch.INCOMING = incoming
        first = dispatch.acquire_dispatch_lock()
        try:
            try:
                dispatch.acquire_dispatch_lock()
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("Concurrent SSH intake did not fail closed.")
        finally:
            fcntl.flock(first, fcntl.LOCK_UN)
            os.close(first)
            dispatch.INCOMING = original_incoming
    with tempfile.TemporaryDirectory(prefix="mochirii-dispatch-inventory-") as directory:
        incoming = Path(directory)
        incoming.chmod(0o700)
        original_incoming = dispatch.INCOMING
        dispatch.INCOMING = incoming
        try:
            first_archive = incoming / f"{commit}.tar"
            first_archive.write_bytes(b"a")
            first_archive.chmod(0o600)
            dispatch.safe_incoming(first_archive)
            second_archive = incoming / f"{'c' * 40}.tar"
            second_archive.write_bytes(b"b")
            second_archive.chmod(0o600)
            try:
                dispatch.safe_incoming(first_archive)
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("A second arbitrary commit escaped the one-slot incoming quota.")
            second_archive.unlink()
            rogue = incoming / "unexpected"
            rogue.write_bytes(b"fixture")
            rogue.chmod(0o600)
            try:
                dispatch.safe_incoming(first_archive)
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("Unexpected incoming inventory was accepted.")
            rogue.unlink()
            partial = incoming / dispatch.PARTIAL_NAME
            partial.write_bytes(b"stranded")
            partial.chmod(0o600)
            dispatch.safe_incoming(first_archive, allow_partial=True)
            dispatch.reconcile_partial()
            if partial.exists():
                raise RuntimeError("A stranded exact partial slot was not reconciled.")
            partial.symlink_to(first_archive)
            try:
                dispatch.safe_incoming(first_archive, allow_partial=True)
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("A hostile partial-slot symlink was accepted.")
            partial.unlink()
            original_read = dispatch.os.read
            try:
                exact_digest = hashlib.sha256(b"a").hexdigest()
                chunks = iter((b"a", b""))
                dispatch.os.read = lambda _descriptor, _size: next(chunks)
                dispatch.receive(commit, exact_digest, "1")
                if first_archive.read_bytes() != b"a" or partial.exists():
                    raise RuntimeError("Idempotent existing-target intake created a second on-disk archive slot.")

                first_archive.unlink()
                calls = 0
                def interrupted_read(_descriptor: int, _size: int) -> bytes:
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        return b"x"
                    dispatch.receive_interrupted(signal.SIGTERM, None)
                    return b""
                dispatch.os.read = interrupted_read
                try:
                    dispatch.receive(commit, hashlib.sha256(b"xy").hexdigest(), "2")
                except dispatch.DispatchError:
                    pass
                else:
                    raise RuntimeError("Interrupted SSH intake did not fail closed.")
                if partial.exists() or first_archive.exists():
                    raise RuntimeError("Interrupted SSH intake stranded a durable partial or target archive.")
            finally:
                dispatch.os.read = original_read
        finally:
            dispatch.INCOMING = original_incoming
    try:
        dispatch.receive_interrupted(signal.SIGALRM, None)
    except dispatch.DispatchError:
        pass
    else:
        raise RuntimeError("Overlong SSH intake deadline did not fail closed.")


def test_current_main_observation() -> None:
    provenance = json.loads((ROOT / "docs/operations/upstream-provenance.v1.json").read_text(encoding="utf-8"))
    observation = provenance["driftObservation"]
    pinned = provenance["upstream"]["revision"]
    expected_new_commits = [
        {
            "revision": "3cdefc992290e6d1376a11c72bada098f7b3cf6a",
            "tree": "8ba8cd9d92578682170da2700b466c2c075348c1",
            "signatureVerified": True,
            "signatureReason": "valid",
            "subject": "FIX: Include PostgreSQL 15 in the dev image (#1114)",
        },
        {
            "revision": "ccb3ea007204c683f7177258f1f509e2fb36f82b",
            "tree": "74c8d88910e156d45e319a97ca884892fcca75d1",
            "signatureVerified": True,
            "signatureReason": "valid",
            "subject": "PERF: Skip chown for files that already have the right ownership (#1115)",
        },
        {
            "revision": "00595119c368c0aef7d7019ec66ffc8fa51cce79",
            "tree": "d5b846bf4e59784c5220c48839d7eb1b45671aae",
            "signatureVerified": True,
            "signatureReason": "valid",
            "subject": "PERF: Refresh Fontconfig cache after package installation (#1117)",
        },
    ]
    if (
        observation["observedAt"] != "2026-08-20"
        or observation["commitsAheadOfPin"] != 11
        or observation["commitsBehindPin"] != 0
        or observation["totalCommits"] != 11
        or len(observation["changedPaths"]) != 20
        or observation["rangeCommits"][-3:] != expected_new_commits
        or [entry["classification"] for entry in observation["materialChangeScope"][-3:]]
        != [
            "dev-image-postgresql-15",
            "web-template-ownership-optimization",
            "base-image-fontconfig-cache-refresh",
        ]
    ):
        raise RuntimeError("The refreshed bounded deployment-source observation changed.")

    def reference_document() -> dict:
        return {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": observation["mainRevision"]},
        }

    def commit_document() -> dict:
        return {
            "sha": observation["mainRevision"],
            "tree": {"sha": observation["mainTree"]},
            "verification": {
                "verified": observation["mainCommitSignatureVerified"],
                "reason": observation["mainCommitSignatureReason"],
            },
        }

    def comparison_document() -> dict:
        return {
            "status": observation["comparisonStatus"],
            "ahead_by": observation["commitsAheadOfPin"],
            "behind_by": observation["commitsBehindPin"],
            "total_commits": observation["totalCommits"],
            "base_commit": {"sha": pinned},
            "merge_base_commit": {"sha": pinned},
            "head_commit": {"sha": observation["mainRevision"]},
            "commits": [
                {
                    "sha": entry["revision"],
                    "commit": {
                        "tree": {"sha": entry["tree"]},
                        "verification": {
                            "verified": entry["signatureVerified"],
                            "reason": entry["signatureReason"],
                        },
                        "message": entry["subject"] + "\n\nfixture body",
                    },
                }
                for entry in observation["rangeCommits"]
            ],
            "files": [{"filename": path} for path in observation["changedPaths"]],
        }

    def exact_request(url: str, **_kwargs):
        if url.endswith("/git/ref/heads/main"):
            return json.dumps(reference_document()).encode(), {}
        if url.endswith("/git/commits/" + observation["mainRevision"]):
            return json.dumps(commit_document()).encode(), {}
        if "/compare/" in url:
            return json.dumps(comparison_document()).encode(), {}
        raise RuntimeError("fixture received an unexpected official-source URL")

    original_request = UPSTREAM.request
    try:
        UPSTREAM.request = exact_request
        UPSTREAM.verify_current_main(provenance)

        hostile_requests = []

        def moved_request(url: str, **kwargs):
            if url.endswith("/git/ref/heads/main"):
                document = reference_document()
                document["object"]["sha"] = "0" * 40
                return json.dumps(document).encode(), {}
            return exact_request(url, **kwargs)

        hostile_requests.append(moved_request)

        def malformed_request(url: str, **kwargs):
            if url.endswith("/git/ref/heads/main"):
                return b"not-json", {}
            return exact_request(url, **kwargs)

        hostile_requests.append(malformed_request)

        def ambiguous_request(url: str, **kwargs):
            if url.endswith("/git/ref/heads/main"):
                return json.dumps([reference_document(), reference_document()]).encode(), {}
            return exact_request(url, **kwargs)

        hostile_requests.append(ambiguous_request)

        def unreachable_request(_url: str, **_kwargs):
            raise RuntimeError("fixture network unavailable")

        hostile_requests.append(unreachable_request)

        def moved_compare_request(url: str, **kwargs):
            if "/compare/" in url:
                document = comparison_document()
                document["ahead_by"] += 1
                return json.dumps(document).encode(), {}
            return exact_request(url, **kwargs)

        hostile_requests.append(moved_compare_request)

        for hostile_request in hostile_requests:
            UPSTREAM.request = hostile_request
            try:
                UPSTREAM.verify_current_main(provenance)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Current-main verifier accepted moved, malformed, ambiguous, or unreachable evidence.")
    finally:
        UPSTREAM.request = original_request


def expect_validation_failure(action, label: str) -> None:
    try:
        action()
    except RuntimeError:
        return
    raise RuntimeError(f"Repository governance accepted hostile fixture: {label}")


def test_repository_governance() -> None:
    allowed = sorted(VALIDATOR.ALLOWED_FILES)
    if len(allowed) != 162:
        raise RuntimeError("The exact Stage 4 repository inventory count changed.")
    if VALIDATOR.validate_inventory_paths(allowed) != allowed:
        raise RuntimeError("The exact Stage 4 repository inventory did not round trip.")
    expect_validation_failure(
        lambda: VALIDATOR.validate_inventory_paths([*allowed, "rogue.py"]),
        "extra untracked source",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_inventory_paths([*allowed, allowed[0]]),
        "duplicate normalized path",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_inventory_paths(
            [*allowed[1:], allowed[0].replace("/", "\\"), allowed[0]],
        ),
        "duplicate slash-normalized path",
    )

    hostile_text = {
        "invalid UTF-8": b"\xff\n",
        "binary control": b"fixture\x01\n",
        "missing EOF newline": b"fixture",
        "blank EOF line": b"fixture\n\n",
        "Git LFS pointer": b"version https://git-lfs.github.com/spec/v1\n",
        "trailing whitespace": b"fixture \n",
        "secret assignment": b"FORUMS_SMTP_PASSWORD=hostile-value\n",
    }
    for label, data in hostile_text.items():
        expect_validation_failure(
            lambda data=data: VALIDATOR.validate_text_contract("fixture.txt", data),
            label,
        )
    VALIDATOR.validate_text_contract(
        ".env.example",
        b"FORUMS_SMTP_PASSWORD=replace-at-runtime\n",
    )
    VALIDATOR.validate_text_contract(
        ".github/workflows/disposable-bootstrap.yml",
        b'FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET="$(<"$secret_file")" \\\n',
    )

    pull_request_template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
    VALIDATOR.validate_stage4_pull_request_template(pull_request_template)
    for required in VALIDATOR.STAGE4_PR_TEMPLATE_REQUIRED:
        expect_validation_failure(
            lambda required=required: VALIDATOR.validate_stage4_pull_request_template(
                pull_request_template.replace(required, "removed-required-contract", 1)
            ),
            f"missing pull-request contract: {required}",
        )
    expect_validation_failure(
        lambda: VALIDATOR.validate_stage4_pull_request_template(
            pull_request_template + "\nAny future upstream-source introduction\n"
        ),
        "retired seed pull-request boundary",
    )

    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    security_policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    contributing_contract = (
        "This public repository owns the reviewed Mochirii Forums configuration",
        "Source review or merge does not authorize a live deployment",
        "Start from current protected `main`",
        "host-control, deployment, backup, restore",
        "Public copy, branding, hostnames, or member-facing behavior",
        "Do not submit credentials, tokens, private keys, cookies, member data",
    )
    security_contract = (
        "Current protected `main` with the exact upstream revisions and image digest",
        "This repository contains supported runtime, host-control, deployment, backup",
        "private vulnerability-reporting or security-",
        "Critical reports target acknowledgement within 24 hours",
        "Never test against production or a provider without explicit",
        "A green source or disposable-runtime check does not claim",
    )
    if any(value not in contributing for value in contributing_contract) or any(
        value in contributing for value in ("currently has no `main` ref", "in this governance phase")
    ):
        raise RuntimeError("Contributing policy regressed to the retired governance seed state.")
    if any(value not in security_policy for value in security_contract) or any(
        value in security_policy for value in ("governance source only", "Once runtime source exists")
    ):
        raise RuntimeError("Security policy regressed to the retired governance seed state.")

    with tempfile.TemporaryDirectory(prefix="mochirii-governance-path-") as directory:
        root = Path(directory)
        regular = root / "regular.txt"
        regular.write_bytes(b"fixture\n")
        if VALIDATOR.validate_path_entry(root, "regular.txt") != b"fixture\n":
            raise RuntimeError("Regular repository file changed during path validation.")
        oversized = root / "oversized.txt"
        oversized.write_bytes(b"a" * (VALIDATOR.MAX_FILE_BYTES + 1))
        expect_validation_failure(
            lambda: VALIDATOR.validate_path_entry(root, "oversized.txt"),
            "oversized file",
        )
        target = root / "target.txt"
        target.write_bytes(b"fixture\n")
        link = root / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            if os.name != "nt":
                raise
        else:
            expect_validation_failure(
                lambda: VALIDATOR.validate_path_entry(root, "link.txt"),
                "symbolic link or reparse point",
            )

    workflow_path = ".github/workflows/validate-repository.yml"
    workflow = (ROOT / workflow_path).read_text(encoding="utf-8")
    VALIDATOR.validate_workflow_contract(workflow_path, workflow)
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            workflow_path,
            workflow.replace("pull_request:", "pull_request_target:", 1),
        ),
        "pull_request_target",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            workflow_path,
            workflow.replace("  contents: read", "  contents: write", 1),
        ),
        "write workflow permission",
    )
    checkout_workflow_path = ".github/workflows/disposable-bootstrap.yml"
    checkout_workflow = (ROOT / checkout_workflow_path).read_text(encoding="utf-8")
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            checkout_workflow_path,
            re.sub(r"actions/checkout@[0-9a-f]{40}", "actions/checkout@main", checkout_workflow, count=1),
        ),
        "moving action reference",
    )

    json_path = "docs/operations/activation.v1.json"
    document = json.loads((ROOT / json_path).read_text(encoding="utf-8"))
    VALIDATOR.validate_json_shape_value(json_path, document)
    additive = json.loads(json.dumps(document))
    additive["deploymentAuthorized"] = True
    expect_validation_failure(
        lambda: VALIDATOR.validate_json_shape_value(json_path, additive),
        "additive JSON property",
    )
    wrong_type = json.loads(json.dumps(document))
    wrong_type["schemaVersion"] = "1"
    expect_validation_failure(
        lambda: VALIDATOR.validate_json_shape_value(json_path, wrong_type),
        "wrong JSON scalar type",
    )
    expect_validation_failure(
        lambda: json.loads('{"schemaVersion":1,"schemaVersion":1}', object_pairs_hook=VALIDATOR._reject_duplicate_json_keys),
        "duplicate JSON property",
    )


def test_extracted_archive_governance() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-archive-governance-") as directory:
        boundary = Path(directory)
        staging = boundary / "staging"
        staging.mkdir()
        for relative in sorted(VALIDATOR.ALLOWED_FILES):
            source = ROOT / relative
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        environment_values = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        subprocess.run(["git", "init", "--quiet", str(staging)], check=True, env=environment_values)
        subprocess.run(
            ["git", "-C", str(staging), "-c", "core.autocrlf=false", "add", "--all"],
            check=True,
            env=environment_values,
        )
        tree = subprocess.run(
            ["git", "-C", str(staging), "write-tree"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
            env=environment_values,
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise RuntimeError("Fixture Git tree identity is malformed.")
        archive = boundary / "release.tar"
        subprocess.run(
            ["git", "-C", str(staging), "archive", "--format=tar", f"--output={archive}", tree],
            check=True,
            env=environment_values,
        )
        clean = boundary / "clean"
        clean.mkdir()
        with tarfile.open(archive, "r:") as source:
            source.extractall(clean, filter="data")

        def archive_validation(root: Path) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [sys.executable, "-B", str(root / "scripts/validate-repository.py"), "--archive-root", str(root)],
                cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        if archive_validation(clean).returncode != 0:
            raise RuntimeError("Exact extracted Git archive failed repository validation.")
        scenarios = {
            "extra": lambda root: (root / "scripts/rogue.py").write_text("fixture\n", encoding="utf-8"),
            "missing": lambda root: (root / "README.md").unlink(),
            "tampered": lambda root: (root / "theme/mochirii/assets/mochirii-icon.png").write_bytes(b"fixture"),
        }
        for label, mutate in scenarios.items():
            hostile = boundary / label
            shutil.copytree(clean, hostile)
            mutate(hostile)
            if archive_validation(hostile).returncode == 0:
                raise RuntimeError(f"Extracted archive validator accepted {label} bytes.")
        linked = boundary / "linked"
        shutil.copytree(clean, linked)
        linked_readme = linked / "README.md"
        linked_readme.unlink()
        try:
            linked_readme.symlink_to(linked / "AGENTS.md")
        except OSError:
            if os.name != "nt":
                raise
        else:
            if archive_validation(linked).returncode == 0:
                raise RuntimeError("Extracted archive validator accepted a linked source entry.")


def test_authentication_state_machine() -> None:
    commit = "1" * 40
    configuration = "2" * 64
    pending_name = f"{commit}-{configuration}-authentication-pending.json"
    common = {
        "schemaVersion": 1,
        "recordedAt": "2026-08-15T12:00:00Z",
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "releaseEvidenceFile": f"{commit}-{configuration}-release.json",
        "releaseEvidenceSha256": "3" * 64,
        "currentReleaseSha256": "4" * 64,
    }
    records = {
        "consumer-public-producer-pending": {
            **common,
            "activationPhase": "consumer-public-producer-pending",
            "websiteProducerDisabledProved": True,
            "containedActivationPassed": True,
            "publicForumsVerificationPassed": True,
        },
        "complete": {
            **common,
            "activationPhase": "complete",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": "5" * 64,
            "websiteEvidenceFile": f"{commit}-{configuration}-website-authentication.json",
            "websiteEvidenceSha256": "6" * 64,
            "websiteRepositoryCommit": "7" * 40,
            **{key: True for key in AUTHENTICATION.COMPLETE_GATES},
        },
        "contained-after-e2e-failure": {
            **common,
            "activationPhase": "contained-after-e2e-failure",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": "5" * 64,
            "websiteProducerDisabledProved": True,
            "applicationStopped": True,
        },
        "contained-producer-state-unproved": {
            **common,
            "activationPhase": "contained-producer-state-unproved",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": "5" * 64,
            "websiteProducerDisabledProved": False,
            "applicationStopped": True,
        },
        "activation-deploy-failed": {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T12:00:00Z",
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "previousRepositoryCommit": "9" * 40,
            "previousProductionConfigurationSha256": "a" * 64,
            "releaseEvidenceFile": f"{'9' * 40}-{'a' * 64}-release.json",
            "releaseEvidenceSha256": "b" * 64,
            "currentReleaseSha256": "c" * 64,
            "activationPhase": "activation-deploy-failed",
            "websiteProducerDisabledProved": True,
            "applicationStopped": True,
        },
        "activation-deploy-failed-producer-unproved": {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T12:00:00Z",
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "previousRepositoryCommit": "9" * 40,
            "previousProductionConfigurationSha256": "a" * 64,
            "releaseEvidenceFile": f"{'9' * 40}-{'a' * 64}-release.json",
            "releaseEvidenceSha256": "b" * 64,
            "currentReleaseSha256": "c" * 64,
            "activationPhase": "activation-deploy-failed-producer-unproved",
            "websiteProducerDisabledProved": False,
            "applicationStopped": True,
        },
    }
    for phase, record in records.items():
        pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": f"{commit}-{configuration}-{AUTHENTICATION.PHASE_SUFFIXES[phase]}.json",
            "authenticationEvidenceSha256": "8" * 64,
            "activationPhase": phase,
        }
        if AUTHENTICATION.validate_documents(pointer, record) != phase:
            raise RuntimeError("Authentication state-machine fixture returned the wrong phase.")

        additive = dict(record)
        additive["unexpected"] = True
        expect_validation_failure(
            lambda pointer=pointer, additive=additive: AUTHENTICATION.validate_documents(pointer, additive),
            f"additive authentication record property in {phase}",
        )

    complete = dict(records["complete"])
    complete["callbackLogRedactionPassed"] = False
    complete_pointer = {
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "authenticationEvidenceFile": f"{commit}-{configuration}-authentication-complete.json",
        "authenticationEvidenceSha256": "8" * 64,
        "activationPhase": "complete",
    }
    expect_validation_failure(
        lambda: AUTHENTICATION.validate_documents(complete_pointer, complete),
        "unpassed callback-log gate",
    )
    unproved = dict(records["contained-producer-state-unproved"])
    unproved["websiteProducerDisabledProved"] = True
    unproved_pointer = {
        **complete_pointer,
        "authenticationEvidenceFile": f"{commit}-{configuration}-authentication-containment-unproved.json",
        "activationPhase": "contained-producer-state-unproved",
    }
    expect_validation_failure(
        lambda: AUTHENTICATION.validate_documents(unproved_pointer, unproved),
        "false producer-disabled proof in unproved containment",
    )
    failed_unproved = dict(records["activation-deploy-failed-producer-unproved"])
    failed_unproved["websiteProducerDisabledProved"] = True
    failed_unproved_pointer = {
        **complete_pointer,
        "authenticationEvidenceFile": f"{commit}-{configuration}-authentication-activation-failed-unproved.json",
        "activationPhase": "activation-deploy-failed-producer-unproved",
    }
    expect_validation_failure(
        lambda: AUTHENTICATION.validate_documents(failed_unproved_pointer, failed_unproved),
        "false producer-disabled proof in activation-deploy failure",
    )

    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    if 'scripts/authentication-state.py"' not in deploy or "contained-producer-state-unproved" not in deploy:
        raise RuntimeError("Host deploy does not execute the exact authentication state evaluator.")
    contained_verification = deploy.index('bash "${release_dir}/scripts/verify-contained-activation.sh"')
    public_activation = deploy.index('activate_config "${config_dir}/app.yml"', contained_verification)
    disabled_probe = "/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled"
    disabled_probes = [match.start() for match in re.finditer(re.escape(disabled_probe), deploy)]
    staged_disabled_probes = [position for position in disabled_probes if position > contained_verification]
    if (
        len(staged_disabled_probes) != 2
        or not contained_verification < staged_disabled_probes[0] < public_activation < staged_disabled_probes[1]
        or deploy[staged_disabled_probes[0]:public_activation].count("activate_config") != 0
    ):
        raise RuntimeError("Public consumer activation can precede its immediate Website producer-disabled proof.")

    stop = (ROOT / "scripts/host-stop-pending-activation.sh").read_text(encoding="utf-8")
    unproved_validation = stop.index('unproved_document.get("activationPhase") != "contained-producer-state-unproved"')
    stopped_readback = stop.index('[[ ${stopped} == true ]]')
    retry_probe = stop.index("/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled", stopped_readback)
    pointer_advance = stop.index("os.replace(temporary, path)")
    if not unproved_validation < stopped_readback < retry_probe < pointer_advance:
        raise RuntimeError("Unproved producer-state containment cannot be reconciled while the app remains stopped.")
    for fragment in (
        '"consumer-public-producer-pending", "contained-producer-state-unproved"',
        'unproved_document.get("pendingAuthenticationEvidenceSha256") != pending_sha',
        'unproved_document.get("websiteProducerDisabledProved") is not False',
        'containment_phase=contained-producer-state-unproved',
        'containment_phase=contained-after-e2e-failure',
        'if path.exists() or path.is_symlink():',
    ):
        if fragment not in stop:
            raise RuntimeError("Pending activation reconciliation lost an exact fail-closed state transition.")
    for fragment in (
        "activation-deploy-failed-producer-unproved",
        "activation-deploy-failed",
        'failure.get("previousRepositoryCommit"',
        'failure.get("currentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()',
        'release.get("discourseConnectEnabled") is not False',
        'containment_phase=activation-deploy-failed',
        'containment_suffix=authentication-activation-failed',
    ):
        if fragment not in stop:
            raise RuntimeError("Operator reconciliation cannot advance an exact stopped activation-deploy failure.")

    transition_sequence = (
        "consumer-public-producer-pending",
        "contained-producer-state-unproved",
        "contained-after-e2e-failure",
        "consumer-public-producer-pending",
        "complete",
    )
    for phase in transition_sequence:
        pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": f"{commit}-{configuration}-{AUTHENTICATION.PHASE_SUFFIXES[phase]}.json",
            "authenticationEvidenceSha256": "8" * 64,
            "activationPhase": phase,
        }
        if AUTHENTICATION.validate_documents(pointer, records[phase]) != phase:
            raise RuntimeError("Authentication retry lifecycle rejected a required exact transition state.")

    failed_transition_sequence = (
        "activation-deploy-failed-producer-unproved",
        "activation-deploy-failed",
        "consumer-public-producer-pending",
        "complete",
    )
    for phase in failed_transition_sequence:
        pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": f"{commit}-{configuration}-{AUTHENTICATION.PHASE_SUFFIXES[phase]}.json",
            "authenticationEvidenceSha256": "8" * 64,
            "activationPhase": phase,
        }
        if AUTHENTICATION.validate_documents(pointer, records[phase]) != phase:
            raise RuntimeError("Activation-deploy recovery lifecycle rejected a required exact transition state.")

    protected_reader = AUTHENTICATION._read_protected
    # The repository fixture runs without host root on both Windows and the
    # Ubuntu CI runner. Static contracts cover root:0600 enforcement; this
    # isolated tree exercises the deep evidence graph without weakening the
    # production reader.
    AUTHENTICATION._read_protected = lambda path, _label: path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="mochirii-activation-failure-state-") as directory:
        state_root = Path(directory)
        evidence_root = state_root / "evidence"
        evidence_root.mkdir()
        prior_commit = "9" * 40
        prior_configuration = "a" * 64
        marker_bytes = b'{"destructiveRestorePermanentlyDisabled":true}\n'
        marker_path = state_root / "member-rollout-enabled"
        marker_path.write_bytes(marker_bytes)
        marker_path.chmod(0o600)
        marker_sha = hashlib.sha256(marker_bytes).hexdigest()
        release_name = f"{prior_commit}-{prior_configuration}-release.json"
        release_path = evidence_root / release_name
        release = {key: None for key in AUTHENTICATION.RELEASE_RECORD_KEYS}
        release.update(
            {
                "schemaVersion": 2,
                "recordedAt": "2026-08-15T11:00:00Z",
                "repositoryCommit": prior_commit,
                "repositoryTree": "7" * 40,
                "releaseArchiveSha256": "1" * 64,
                "releaseArchiveBytes": 1024,
                "releaseArchiveContentManifestSha256": "8" * 64,
                "productionConfigurationSha256": prior_configuration,
                "discourseConnectEnabled": False,
                "activationPhase": "consumer-disabled",
                "containedActivationPassed": False,
                "containedActivationConfigurationSha256": None,
                "memberRolloutMarkerFile": "member-rollout-enabled",
                "memberRolloutMarkerSha256": marker_sha,
                "hostVerificationPassed": True,
                "hostedStoragePassed": True,
                "storageRestartPersistencePassed": True,
                "storageRebuildPersistencePassed": True,
                "storageCleanupPassed": True,
            }
        )
        release_path.write_bytes((json.dumps(release, sort_keys=True) + "\n").encode("utf-8"))
        release_path.chmod(0o600)
        release_sha = hashlib.sha256(release_path.read_bytes()).hexdigest()
        current_path = state_root / "current-release.json"
        current = {
            "repositoryCommit": prior_commit,
            "productionConfigurationSha256": prior_configuration,
            "releaseEvidenceFile": release_name,
            "releaseEvidenceSha256": release_sha,
            "discourseConnectEnabled": False,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path.write_bytes((json.dumps(current, sort_keys=True) + "\n").encode("utf-8"))
        current_path.chmod(0o600)
        failure_name = f"{commit}-{configuration}-authentication-activation-failed.json"
        failure_path = evidence_root / failure_name
        failure = dict(records["activation-deploy-failed"])
        failure.update(
            {
                "previousRepositoryCommit": prior_commit,
                "previousProductionConfigurationSha256": prior_configuration,
                "releaseEvidenceFile": release_name,
                "releaseEvidenceSha256": release_sha,
                "currentReleaseSha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
            }
        )
        failure_path.write_bytes((json.dumps(failure, sort_keys=True) + "\n").encode("utf-8"))
        failure_path.chmod(0o600)
        pointer_path = state_root / "current-authentication.json"
        failure_pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": failure_name,
            "authenticationEvidenceSha256": hashlib.sha256(failure_path.read_bytes()).hexdigest(),
            "activationPhase": "activation-deploy-failed",
        }
        pointer_path.write_bytes((json.dumps(failure_pointer, sort_keys=True) + "\n").encode("utf-8"))
        pointer_path.chmod(0o600)
        if AUTHENTICATION.evaluate(pointer_path, commit, configuration) != "activation-deploy-failed":
            raise RuntimeError("Deep stopped activation-deploy evidence chain was rejected.")
        hostile_current = dict(current)
        hostile_current["discourseConnectEnabled"] = True
        current_path.write_bytes((json.dumps(hostile_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, commit, configuration),
            "consumer-enabled current pointer in stopped activation recovery",
        )
        current_path.write_bytes((json.dumps(current, sort_keys=True) + "\n").encode("utf-8"))
        marker_path.write_bytes(b"hostile\n")
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, commit, configuration),
            "changed member-rollout marker in stopped activation recovery",
        )
        marker_path.write_bytes(marker_bytes)

        target_release_name = f"{commit}-{configuration}-release.json"
        target_release_path = evidence_root / target_release_name
        target_release = {
            "schemaVersion": 2,
            "recordedAt": "2026-08-15T12:30:00Z",
            "repositoryCommit": commit,
            "repositoryTree": "7" * 40,
            "releaseArchiveSha256": "1" * 64,
            "releaseArchiveBytes": 1024,
            "releaseArchiveContentManifestSha256": "8" * 64,
            "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
            "discourseRevision": "cbf996f65aae3da1843224aa624bcd9a225931ac",
            "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
            "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
            "productionConfigurationSha256": configuration,
            "restoreConfigurationSha256": "2" * 64,
            "containedActivationConfigurationSha256": "3" * 64,
            "containedActivationPassed": True,
            "activationPhase": "consumer-public-producer-pending",
            "themeArchiveSha256": "4" * 64,
            "mailMetadataPluginSha256": "5" * 64,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
            "hostVerificationPassed": True,
            "storageEvidenceFile": f"{commit}-{configuration}-storage.json",
            "storageEvidenceSha256": "6" * 64,
            "hostedStoragePassed": True,
            "storageRestartPersistencePassed": True,
            "storageRebuildPersistencePassed": True,
            "storageCleanupPassed": True,
        }
        target_release_path.write_bytes((json.dumps(target_release, sort_keys=True) + "\n").encode("utf-8"))
        target_release_path.chmod(0o600)
        for field, hostile_value in (
            ("repositoryTree", "not-a-tree"),
            ("releaseArchiveBytes", True),
            ("releaseArchiveBytes", 67_108_865),
            ("releaseArchiveContentManifestSha256", "not-a-manifest"),
        ):
            hostile_release = dict(target_release)
            hostile_release[field] = hostile_value
            expect_validation_failure(
                lambda document=hostile_release: AUTHENTICATION._validate_release_record(
                    document,
                    commit,
                    configuration,
                    True,
                    "Hostile immutable release authority",
                ),
                f"malformed immutable release authority {field}",
            )
        target_release_sha = hashlib.sha256(target_release_path.read_bytes()).hexdigest()
        target_current = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "releaseEvidenceFile": target_release_name,
            "releaseEvidenceSha256": target_release_sha,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path.write_bytes((json.dumps(target_current, sort_keys=True) + "\n").encode("utf-8"))
        if AUTHENTICATION.evaluate(pointer_path, commit, configuration) != "activation-deploy-failed":
            raise RuntimeError("Stopped activation retry could not adopt the verified target publication.")
        hostile_target_current = dict(target_current)
        hostile_target_current["discourseConnectEnabled"] = False
        current_path.write_bytes((json.dumps(hostile_target_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, commit, configuration),
            "consumer-disabled target after activation retry",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-authentication-advance-state-") as directory:
        state_root = Path(directory)
        evidence_root = state_root / "evidence"
        operator_root = state_root / "operator-evidence"
        evidence_root.mkdir()
        operator_root.mkdir()
        previous_commit = "8" * 40
        previous_configuration = "c" * 64
        target_commit = "9" * 40
        target_configuration = "d" * 64
        marker_bytes = b'{"destructiveRestorePermanentlyDisabled":true}\n'
        marker_path = state_root / "member-rollout-enabled"
        marker_path.write_bytes(marker_bytes)
        marker_path.chmod(0o600)
        marker_sha = hashlib.sha256(marker_bytes).hexdigest()

        def release_document(release_commit: str, release_configuration: str, connect: bool) -> dict[str, object]:
            return {
                "schemaVersion": 2,
                "recordedAt": "2026-08-15T11:00:00Z",
                "repositoryCommit": release_commit,
                "repositoryTree": "7" * 40,
                "releaseArchiveSha256": "1" * 64,
                "releaseArchiveBytes": 1024,
                "releaseArchiveContentManifestSha256": "8" * 64,
                "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
                "discourseRevision": "cbf996f65aae3da1843224aa624bcd9a225931ac",
                "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
                "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
                "productionConfigurationSha256": release_configuration,
                "restoreConfigurationSha256": "2" * 64,
                "containedActivationConfigurationSha256": "3" * 64 if connect else None,
                "containedActivationPassed": connect,
                "activationPhase": "consumer-public-producer-pending" if connect else "consumer-disabled",
                "themeArchiveSha256": "4" * 64,
                "mailMetadataPluginSha256": "5" * 64,
                "discourseConnectEnabled": connect,
                "memberRolloutMarkerFile": "member-rollout-enabled",
                "memberRolloutMarkerSha256": marker_sha,
                "hostVerificationPassed": True,
                "storageEvidenceFile": f"{release_commit}-{release_configuration}-storage.json",
                "storageEvidenceSha256": "6" * 64,
                "hostedStoragePassed": True,
                "storageRestartPersistencePassed": True,
                "storageRebuildPersistencePassed": True,
                "storageCleanupPassed": True,
            }

        previous_release_name = f"{previous_commit}-{previous_configuration}-release.json"
        previous_release_path = evidence_root / previous_release_name
        previous_release = release_document(previous_commit, previous_configuration, True)
        previous_release_path.write_bytes((json.dumps(previous_release, sort_keys=True) + "\n").encode("utf-8"))
        previous_release_path.chmod(0o600)
        previous_release_sha = hashlib.sha256(previous_release_path.read_bytes()).hexdigest()
        previous_current = {
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "releaseEvidenceFile": previous_release_name,
            "releaseEvidenceSha256": previous_release_sha,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path = state_root / "current-release.json"
        current_path.write_bytes((json.dumps(previous_current, sort_keys=True) + "\n").encode("utf-8"))
        current_path.chmod(0o600)
        previous_current_sha = hashlib.sha256(current_path.read_bytes()).hexdigest()

        pending_name = f"{previous_commit}-{previous_configuration}-authentication-pending.json"
        pending_path = evidence_root / pending_name
        pending = {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T11:30:00Z",
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "releaseEvidenceFile": previous_release_name,
            "releaseEvidenceSha256": previous_release_sha,
            "currentReleaseSha256": previous_current_sha,
            "activationPhase": "consumer-public-producer-pending",
            **{key: True for key in AUTHENTICATION.PENDING_GATES},
        }
        pending_path.write_bytes((json.dumps(pending, sort_keys=True) + "\n").encode("utf-8"))
        pending_path.chmod(0o600)
        pending_sha = hashlib.sha256(pending_path.read_bytes()).hexdigest()

        website_name = f"{previous_commit}-{previous_configuration}-website-authentication.json"
        website_path = operator_root / website_name
        website = {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T11:45:00Z",
            "websiteRepositoryCommit": "7" * 40,
            "forumsRepositoryCommit": previous_commit,
            "forumsProductionConfigurationSha256": previous_configuration,
            **{key: True for key in AUTHENTICATION.WEBSITE_GATE_KEYS},
        }
        website_path.write_bytes((json.dumps(website, sort_keys=True) + "\n").encode("utf-8"))
        website_path.chmod(0o600)
        website_sha = hashlib.sha256(website_path.read_bytes()).hexdigest()

        complete_name = f"{previous_commit}-{previous_configuration}-authentication-complete.json"
        complete_path = evidence_root / complete_name
        complete = {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T12:00:00Z",
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "releaseEvidenceFile": previous_release_name,
            "releaseEvidenceSha256": previous_release_sha,
            "currentReleaseSha256": previous_current_sha,
            "activationPhase": "complete",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": pending_sha,
            "websiteEvidenceFile": website_name,
            "websiteEvidenceSha256": website_sha,
            "websiteRepositoryCommit": "7" * 40,
            **{key: True for key in AUTHENTICATION.COMPLETE_GATES},
        }
        complete_path.write_bytes((json.dumps(complete, sort_keys=True) + "\n").encode("utf-8"))
        complete_path.chmod(0o600)
        pointer_path = state_root / "current-authentication.json"
        complete_pointer = {
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "authenticationEvidenceFile": complete_name,
            "authenticationEvidenceSha256": hashlib.sha256(complete_path.read_bytes()).hexdigest(),
            "activationPhase": "complete",
        }
        pointer_path.write_bytes((json.dumps(complete_pointer, sort_keys=True) + "\n").encode("utf-8"))
        pointer_path.chmod(0o600)

        if AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration) != "stale-other-tuple":
            raise RuntimeError("A completed prior tuple was rejected before the consumer-disabled advance.")

        target_release_name = f"{target_commit}-{target_configuration}-release.json"
        target_release_path = evidence_root / target_release_name
        target_release = release_document(target_commit, target_configuration, False)
        target_release_path.write_bytes((json.dumps(target_release, sort_keys=True) + "\n").encode("utf-8"))
        target_release_path.chmod(0o600)
        target_release_sha = hashlib.sha256(target_release_path.read_bytes()).hexdigest()
        target_current = {
            "repositoryCommit": target_commit,
            "productionConfigurationSha256": target_configuration,
            "releaseEvidenceFile": target_release_name,
            "releaseEvidenceSha256": target_release_sha,
            "discourseConnectEnabled": False,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path.write_bytes((json.dumps(target_current, sort_keys=True) + "\n").encode("utf-8"))
        if AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration) != "stale-other-tuple":
            raise RuntimeError("A completed prior tuple was rejected after consumer-disabled current-release publication.")

        hostile_current = dict(target_current)
        hostile_current["discourseConnectEnabled"] = True
        current_path.write_bytes((json.dumps(hostile_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "consumer-enabled authentication advance target",
        )
        current_path.write_bytes((json.dumps(target_current, sort_keys=True) + "\n").encode("utf-8"))

        hostile_complete = dict(complete)
        hostile_complete["currentReleaseSha256"] = "0" * 64
        complete_path.write_bytes((json.dumps(hostile_complete, sort_keys=True) + "\n").encode("utf-8"))
        complete_pointer["authenticationEvidenceSha256"] = hashlib.sha256(complete_path.read_bytes()).hexdigest()
        pointer_path.write_bytes((json.dumps(complete_pointer, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "historical completed current-release digest mismatch",
        )
        complete_path.write_bytes((json.dumps(complete, sort_keys=True) + "\n").encode("utf-8"))
        complete_pointer["authenticationEvidenceSha256"] = hashlib.sha256(complete_path.read_bytes()).hexdigest()
        pointer_path.write_bytes((json.dumps(complete_pointer, sort_keys=True) + "\n").encode("utf-8"))

        marker_path.write_bytes(b"hostile\n")
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "changed member marker during completed authentication advance",
        )
        marker_path.write_bytes(marker_bytes)

        unrelated_current = dict(target_current)
        unrelated_current["repositoryCommit"] = "a" * 40
        current_path.write_bytes((json.dumps(unrelated_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "unrelated current release during completed authentication advance",
        )
    AUTHENTICATION._read_protected = protected_reader

    activation_exit = deploy[deploy.index("on_exit() {") : deploy.index("trap on_exit EXIT")]
    if "recover_failed_activation" not in activation_exit or activation_exit.index("storage_cleanup_blocked") > activation_exit.index("recover_failed_activation"):
        raise RuntimeError("Activation failure recovery can bypass storage cleanup containment or the stopped retry transition.")
    recovery = deploy[deploy.index("seal_activation_deploy_failure() {") : deploy.index("recover_failed_activation() {")]
    recovery_required = (
        "emergency_stop",
        'activate_config "${previous_config}"',
        'write_current_evidence "${previous_release}"',
        "activation-deploy-failed-producer-unproved",
        "activation-deploy-failed",
        "websiteProducerDisabledProved",
        "applicationStopped",
        "os.link(candidate, path, follow_symlinks=False)",
        "os.replace(candidate, path)",
    )
    if any(value not in recovery for value in recovery_required):
        raise RuntimeError("Activation failure cannot atomically seal an exact stopped prior-release retry state.")
    retry_start = deploy.index("elif [[ ${authentication_retry_state} == activation-deploy-failed ]]")
    retry_branch = deploy[retry_start : deploy.index("elif [[ ${complete_authentication_rebuild}", retry_start)]
    if retry_branch.index("docker inspect --type container") > retry_branch.index('current_discourse_connect="${previous_discourse_connect}"') or "docker exec app" in retry_branch:
        raise RuntimeError("Stopped activation-deploy retry reads target consumer state from an unavailable container.")
    failure_canaries = (
        "Contained DiscourseConnect activation verification failed.",
        "Public consumer activation requires the exact Website producer-disabled state.",
        "Mochirii Forums launcher operation failed",
        "Hosted storage fixture creation failed",
        "Hosted storage fixture did not survive restart",
        "Hosted storage fixture did not survive rebuild",
        "Hosted storage fixture cleanup failed",
        "Deployment terminal transaction could not be reconciled safely.",
        "Deployment terminal state could not be committed or verified.",
    )
    if any(value not in deploy for value in failure_canaries):
        raise RuntimeError("Activation failure hostile boundary inventory changed.")

    installer = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")
    if (
        "stop-pending-activation" in dispatcher
        or "finalize-authentication" in dispatcher
        or '/usr/local/sbin/mochirii-forums-stop-pending-activation' not in installer
        or '/usr/local/sbin/mochirii-forums-finalize-authentication' not in installer
        or 'sudo -l -U "${deploy_user}" "${forbidden}"' not in installer
        or "${SUDO_USER} != mochirii-forums-operator" not in stop
        or "${SUDO_USER} != mochirii-forums-operator" not in (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")
    ):
        raise RuntimeError("The deploy credential gained authentication stop or finalization authority.")


def test_deployment_checkout_configuration_boundary() -> None:
    checkout = (ROOT / "scripts/verify-discourse-docker-checkout.sh").read_text(encoding="utf-8")
    exact_pattern = (
        r"^/var/discourse/containers/releases/[0-9a-f]{40}/[0-9a-f]{64}/"
        r"(app|restore|activation)[.]yml$"
    )
    if exact_pattern not in checkout:
        raise RuntimeError("Versioned activation configuration is absent from the sealed checkout boundary.")
    boundary = re.compile(exact_pattern)
    commit = "a" * 40
    configuration = "2" * 64
    if not boundary.fullmatch(f"/var/discourse/containers/releases/{commit}/{configuration}/activation.yml"):
        raise RuntimeError("Exact versioned activation configuration was rejected.")
    for hostile in (
        f"/var/discourse/containers/releases/{commit}/{configuration}/activation-copy.yml",
        f"/var/discourse/containers/releases/{commit}/{configuration}/activation.yml/child",
        f"/var/discourse/containers/releases/{commit}/../{configuration}/activation.yml",
        f"/var/discourse/containers/releases/{commit.upper()}/{configuration}/activation.yml",
    ):
        if boundary.fullmatch(hostile):
            raise RuntimeError("A hostile versioned activation configuration name was accepted.")
    required_parser_bounds = (
        'docker image inspect "${base_image}"',
        "--pull=never",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        '"${base_image}" ruby -ryaml',
        '<"${resolved_app_config}"',
    )
    if any(value not in checkout for value in required_parser_bounds) or re.search(r"(?m)^ruby\s+-ryaml", checkout):
        raise RuntimeError("Fresh-host source validation regained an unbounded host Ruby dependency.")
    cleanup_match = re.search(r"(?ms)^cleanup_parser\(\) \{.*?^\}", checkout)
    if cleanup_match is None:
        raise RuntimeError("Pinned parser cleanup function is absent.")
    cleanup = cleanup_match.group(0)
    if (
        'docker rm --force "${parser_container}"' not in cleanup
        or 'docker container ls --all --filter "name=^/${parser_container}$"' not in cleanup
        or cleanup.index("docker rm --force") > cleanup.index("docker container ls")
        or "|| return 1" not in cleanup
    ):
        raise RuntimeError("Pinned parser cleanup does not prove the exact named container absent.")
    host_deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    host_cleanup = re.search(r"(?ms)^cleanup_parser_container\(\) \{.*?^\}", host_deploy)
    if host_cleanup is None or 'docker container ls --all --filter "name=^/${name}$"' not in host_cleanup.group(0):
        raise RuntimeError("Secret-bearing rendered-config parser lacks an exact post-run absence readback.")
    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the parser cleanup hostile fixture.")
        harness = cleanup + r'''
parser_container=mochirii-forums-source-verify-123
timeout() {
  while [[ ${1-} == -* ]]; do shift; done
  [[ $# -gt 0 ]] || return 1
  shift
  [[ $# -gt 0 ]] || return 1
  "$@"
}
docker() {
  if [[ $1 == rm ]]; then
    [[ ${MOCK_RM} == success ]]
    return
  fi
  if [[ $1 == container && $2 == ls ]]; then
    case ${MOCK_INVENTORY} in
      empty) return 0 ;;
      remains) printf '%s\n' "$parser_container"; return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 1
}
cleanup_parser
'''
        cases = (
            ({"MOCK_RM": "success", "MOCK_INVENTORY": "empty"}, True),
            ({"MOCK_RM": "failed", "MOCK_INVENTORY": "empty"}, True),
            ({"MOCK_RM": "success", "MOCK_INVENTORY": "remains"}, False),
            ({"MOCK_RM": "failed", "MOCK_INVENTORY": "remains"}, False),
            ({"MOCK_RM": "failed", "MOCK_INVENTORY": "error"}, False),
        )
        for values, expected in cases:
            completed = subprocess.run(
                [bash, "-c", harness],
                env={**os.environ, **values},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if (completed.returncode == 0) is not expected:
                raise RuntimeError("Pinned parser cleanup survivor hostile fixture changed.")


def test_sensitive_callback_markers() -> None:
    original = set(CONNECT_FIXTURE.CALLBACK_LOG_MARKERS)
    try:
        nonce = "nonce-stage4-fixture-0123456789abcdef"
        encoded, signature = CONNECT_FIXTURE.callback(nonce, b"a" * 64)
        path = CONNECT_FIXTURE.callback_path(encoded, signature)
        first_token = b"admin-token-stage4-fixture-111111111111"
        second_token = b"admin-token-stage4-fixture-222222222222"
        CONNECT_FIXTURE.register_admin_recovery_markers((first_token, second_token))
        markers = sorted(CONNECT_FIXTURE.CALLBACK_LOG_MARKERS)
        required = {
            b"mochirii-stage4-consumer-fixture",
            b"stage4-fixture@forums.mochirii.com",
            b"mochirii-s4-test",
            b"Mochirii Stage 4 Fixture",
            b"stage4-fixture%40forums.mochirii.com",
            b"Mochirii%20Stage%204%20Fixture",
            b"Mochirii+Stage+4+Fixture",
            first_token,
            second_token,
            b"/session/email-login/" + first_token,
            b"/session/email-login/" + second_token,
        }
        if not required.issubset(markers) or not encoded or not signature or not path.startswith("/session/sso_login?"):
            raise RuntimeError("Sensitive callback marker fixture omitted an exact identity or recovery credential.")
        if len(markers) > 64 or any(not 16 <= len(marker) <= 16_384 for marker in markers):
            raise RuntimeError("Sensitive callback marker inventory exceeded its exact bound.")
        encoded_marker = next(marker for marker in markers if marker.startswith(b"sso=") and b"%" in marker)
        hostile_request_line = b"GET /session/sso_login?" + encoded_marker + b" HTTP/1.1\n"
        if not CONNECT_FIXTURE.sensitive_marker_reached(hostile_request_line, markers):
            raise RuntimeError("Percent-encoded callback request-line leakage was not detected.")
        scanner = (ROOT / "scripts/verify-sensitive-log-redaction.rb").read_text(encoding="utf-8")
        if r"[\x00-\x1f\x7f]" not in scanner or r"[\x00-\x20]" in scanner:
            raise RuntimeError("Sensitive-log marker validation rejects ordinary display-name spaces.")
        app = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
        exact_route = 'location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$" {'
        denial_route = "location ~* ^/session/email-login/ {"
        recovery_required = (
            "EMAIL_LOGIN_PATH = %r{\\A/session/email-login/[A-Za-z0-9_-]{20,256}\\z}.freeze",
            'FILTERED_EMAIL_LOGIN_PATH = "/session/email-login/[FILTERED]".freeze',
            "Rails.application.config.filter_parameters |= %i[sso sig token]",
            exact_route,
            denial_route,
            "error_page 420 = @mochirii_email_login_denied;",
        )
        if any(value not in app for value in recovery_required) or app.index(exact_route) > app.index(denial_route):
            raise RuntimeError("Administrator email-login token lacks its exact application/Nginx privacy boundary.")
        initializer = app[app.index("module MochiriiSensitiveRequestPathFilter"):app.index("  - file:", app.index("module MochiriiSensitiveRequestPathFilter"))]
        if "PATH_INFO" in initializer or "def path" in initializer or ".*" in initializer:
            raise RuntimeError("Administrator email-login log filter changes routing or became overbroad.")
    finally:
        CONNECT_FIXTURE.CALLBACK_LOG_MARKERS.clear()
        CONNECT_FIXTURE.CALLBACK_LOG_MARKERS.update(original)


def test_website_producer_probe_contract() -> None:
    security_headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "private, no-store, max-age=0"),
        ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        ("Expires", "0"),
        ("Pragma", "no-cache"),
        ("Referrer-Policy", "no-referrer"),
        ("Vary", "Origin, Authorization"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
    ]
    contracts = {
        "disabled": (
            503,
            {"ok": False, "code": "unavailable", "error": "Mōchirīī Forums sign-in is unavailable."},
        ),
        "enabled": (
            400,
            {"ok": False, "code": "invalid_request", "error": "This Mōchirīī Forums sign-in request is invalid."},
        ),
    }

    class Response:
        def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
            self.status = status
            self._headers = headers
            self._body = body

        def getheaders(self):
            return self._headers

        def read(self, maximum: int) -> bytes:
            return self._body[:maximum]

    class Connection:
        response: Response
        last_request: tuple[object, ...] | None = None

        def __init__(self, host: str, port: int, *, timeout: int, context) -> None:
            if host != "mochirii.com" or port != 443 or timeout != 20 or context is None:
                raise RuntimeError("Website producer probe connection boundary changed.")

        def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
            Connection.last_request = (method, path, body, headers)

        def getresponse(self) -> Response:
            return Connection.response

        def close(self) -> None:
            return None

    original_connection = PRODUCER_PROBE.http.client.HTTPSConnection
    original_argv = sys.argv[:]
    try:
        PRODUCER_PROBE.http.client.HTTPSConnection = Connection
        for state, (status, document) in contracts.items():
            body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            Connection.response = Response(status, [*security_headers, ("Content-Length", str(len(body)))], body)
            sys.argv = ["probe-website-forums-producer.py", state]
            with contextlib.redirect_stdout(io.StringIO()):
                if PRODUCER_PROBE.main() != 0:
                    raise RuntimeError("Exact Website producer probe fixture failed.")
            method, path, request_body, headers = Connection.last_request or (None, None, None, {})
            if (
                method != "POST"
                or path != "/api/forums/discourse-connect"
                or request_body != b"{}"
                or "Origin" in headers
                or headers.get("Host") != "mochirii.com"
            ):
                raise RuntimeError("Website producer probe sent a member-bearing or noncanonical request.")

        hostile_responses = [
            Response(503, [*security_headers, ("Location", "https://example.invalid/")], json.dumps(contracts["disabled"][1], ensure_ascii=False).encode()),
            Response(503, [(name, "default-src 'none'") if name == "Content-Security-Policy" else (name, value) for name, value in security_headers], json.dumps(contracts["disabled"][1], ensure_ascii=False).encode()),
            Response(503, [*security_headers, ("Server", "cloudflare")], json.dumps(contracts["disabled"][1], ensure_ascii=False).encode()),
            Response(503, security_headers, b'{"ok":false,"code":"unavailable","error":"wrong"}'),
        ]
        for response in hostile_responses:
            Connection.response = response
            sys.argv = ["probe-website-forums-producer.py", "disabled"]
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    PRODUCER_PROBE.main()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Website producer probe accepted a hostile state response.")
    finally:
        PRODUCER_PROBE.http.client.HTTPSConnection = original_connection
        sys.argv = original_argv


def test_restore_stop_boundary() -> None:
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    match = re.search(r"(?ms)^stop_app_safely\(\) \{.*?^\}", restore)
    if match is None:
        raise RuntimeError("Disposable restore stop boundary is absent.")
    function = match.group(0)
    required = (
        "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
        "docker inspect --format '{{.State.Running}}' app",
        "docker container ls --all --filter 'name=^/app$'",
        "|| return 1",
    )
    if any(value not in function for value in required) or "|| printf false" in function:
        raise RuntimeError("Disposable restore stop boundary can convert daemon failure into a stopped state.")
    if "CRITICAL: Restore containment and application stop could not be verified" not in restore:
        raise RuntimeError("Disposable restore lacks a distinct critical unknown-stop marker.")
    if os.name != "posix":
        return
    bash = shutil.which("bash")
    if bash is None:
        raise RuntimeError("Bash is required for the restore stop hostile fixture.")
    harness = (
        function
        + "\n"
        + r'''
timeout() {
  while [[ ${1-} == -* ]]; do shift; done
  [[ $# -gt 0 ]] || return 1
  shift
  [[ $# -gt 0 ]] || return 1
  if [[ $1 == docker && ${2-} == stop ]]; then
    return 1
  fi
  "$@"
}
docker() {
  if [[ $1 == inspect ]]; then
    case ${MOCK_INSPECT} in
      false|true) printf '%s\n' "${MOCK_INSPECT}"; return 0 ;;
      *) return 1 ;;
    esac
  fi
  if [[ $1 == container && $2 == ls ]]; then
    case ${MOCK_INVENTORY} in
      empty) return 0 ;;
      app) printf '%s\n' app; return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 1
}
stop_app_safely
'''
    )
    cases = (
        ({"MOCK_INSPECT": "error", "MOCK_INVENTORY": "error"}, False),
        ({"MOCK_INSPECT": "error", "MOCK_INVENTORY": "app"}, False),
        ({"MOCK_INSPECT": "true", "MOCK_INVENTORY": "empty"}, False),
        ({"MOCK_INSPECT": "false", "MOCK_INVENTORY": "app"}, True),
        ({"MOCK_INSPECT": "error", "MOCK_INVENTORY": "empty"}, True),
    )
    for values, expected in cases:
        completed = subprocess.run(
            [bash, "-c", harness],
            env={**os.environ, **values},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if (completed.returncode == 0) is not expected:
            raise RuntimeError("Disposable restore hostile stop-state fixture changed.")


def test_host_containment_contract() -> None:
    import ast

    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/host-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    host_verify = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    break_glass = (ROOT / "scripts/host-break-glass-admin.sh").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    connect_verifier = (ROOT / "scripts/verify-discourse-connect.py").read_text(encoding="utf-8")
    survivor_fixture = (ROOT / "scripts/test-operation-survivor.rb").read_text(encoding="utf-8")
    nul_scan = r'File.binread(path).split("\0", -1).include?(marker)'
    literal_backslash_scan = r'File.binread(path).split("\\0", -1).include?(marker)'
    for source, expected, label in (
        (deploy, 1, "deploy"),
        (backup, 1, "backup"),
        (restore, 3, "restore"),
        (break_glass, 1, "break-glass"),
        (disposable, 1, "disposable"),
    ):
        if source.count(nul_scan) != expected or literal_backslash_scan in source:
            raise RuntimeError(f"{label} process-survivor scan no longer splits real NUL-delimited environ bytes.")
    generated_scans = [
        node.value
        for node in ast.walk(ast.parse(connect_verifier))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and '/proc/[0-9]*/environ' in node.value
    ]
    if len(generated_scans) != 1 or generated_scans[0].count(nul_scan) != 1 or literal_backslash_scan in generated_scans[0]:
        raise RuntimeError("DiscourseConnect process-survivor command no longer emits a real-NUL Ruby scan.")
    survivor_required = (
        'File.binwrite(marked, ["PATH=/usr/bin", marker, "HOME=/var/www/discourse", ""].join("\\0"))',
        'File.binread(path).split("\\0", -1).include?(marker)',
        'File.binread(marked).split("\\\\0", -1).include?(marker)',
        '"scripts/host-deploy.sh" => 1',
        '"scripts/host-backup.sh" => 1',
        '"scripts/host-restore-validate.sh" => 3',
        '"scripts/host-break-glass-admin.sh" => 1',
        '".github/workflows/disposable-bootstrap.yml" => 1',
        '"scripts/verify-discourse-connect.py" => 1',
    )
    if any(value not in survivor_fixture for value in survivor_required):
        raise RuntimeError("Executable survivor fixture lost its actual-NUL, marked-process, or three-host binding.")
    if "timeout --foreground" in deploy:
        raise RuntimeError("Hosted storage runner uses foreground timeout, which does not contain child processes.")
    function = deploy[deploy.index("run_storage_fixture() {") : deploy.index("activate_config() {")]
    runner_probe = function.index("container_operation_absent")
    status_gate = function.index("(( runner_status == 0 ))")
    stop_gate = function.index("emergency_stop")
    if not (runner_probe < stop_gate < status_gate):
        raise RuntimeError("Hosted storage cleanup can race a surviving Rails runner.")
    if "|| printf false" in function or "docker stop --time 30 app" in function:
        raise RuntimeError("Hosted storage runner uses an unproved direct stop fallback.")
    required_stop = (
        "stop_app_safely()",
        "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
        "docker inspect --format '{{.State.Running}}' app",
        "docker container ls --all --filter 'name=^/app$'",
        "emergency_stop()",
        "CRITICAL: Mochirii Forums application stop could not be verified.",
        "timeout --signal=TERM --kill-after=30s",
        "launcher_bootstrap_cid",
        "reconcile_launcher_failure()",
        "runtime_survivor_unproved=true",
        "cleanup, rebuild, and public rollback are blocked",
        'MOCHIRII_OPERATION_TOKEN="${operation_token}"',
        "remaining_mutation_seconds",
        "launcher_cumulative_budget_seconds=7800",
        'active_operation_kind="launcher"',
        'reconcile_launcher_failure || true',
        'verify-runtime-assets.sh" "${release}" --require-container',
    )
    if any(value not in deploy for value in required_stop):
        raise RuntimeError("Independent application-stop readback boundary changed.")
    deploy_exit = deploy[deploy.index("on_exit() {") : deploy.index("trap on_exit EXIT")]
    if deploy_exit.count("emergency_stop") < 3:
        raise RuntimeError("A failed containment, sealed rollback, or bootstrap destroy can leave a running app.")
    forbidden_recovery = (
        "run_launcher storage-containment-stop stop app",
        "run_launcher storage-recovery-stop stop app",
        "run_launcher cleanup-reconciled-stop stop app",
        "Failed initial container was stopped",
    )
    if any(value in deploy for value in forbidden_recovery):
        raise RuntimeError("Launcher-dependent recovery still claims an unproved application stop.")
    rollback_failure = deploy_exit[deploy_exit.index("if restore_previous_release; then") : deploy_exit.index("else\n      run_launcher failed-bootstrap-cleanup")]
    if "emergency_stop" not in rollback_failure:
        raise RuntimeError("Checkout-seal or launcher rollback failure does not independently stop the app.")
    destroy_failure = deploy_exit[deploy_exit.index("run_launcher failed-bootstrap-cleanup destroy app") :]
    if destroy_failure.index("emergency_stop") > destroy_failure.index("rm -f -- \"${app_config}\""):
        raise RuntimeError("Bootstrap cleanup removes evidence before proving the app stopped.")

    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    required = (
        "prove_restore_containment()",
        '[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${restore_config}" ]]',
        "DISCOURSE_DISABLE_EMAILS\" = yes",
        "DISCOURSE_ENABLE_DISCOURSE_CONNECT\" = false",
        "SiteSetting.allow_restore == false",
        "stop_app_safely()",
        "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
        "docker inspect --format '{{.State.Running}}' app",
        "docker container ls --all --filter 'name=^/app$'",
        "run_container_command()",
        "timeout --signal=TERM --kill-after=15s",
        'MOCHIRII_OPERATION_TOKEN="${operation_token}"',
        "container_operation_absent",
        "remaining_operation_seconds",
        "reconcile_launcher_failure()",
        "Restore process termination is unproved",
    )
    if any(value not in restore for value in required):
        raise RuntimeError("Disposable restore containment lost an exact runtime or stop invariant.")
    exit_body = restore[restore.index("on_exit() {") : restore.index("trap on_exit EXIT")]
    if exit_body.index("activate_config") > exit_body.index("prove_restore_containment"):
        raise RuntimeError("Restore failure containment is verified before the exact isolated config is activated.")
    if exit_body.index("prove_restore_containment") > exit_body.index("stop_app_safely"):
        raise RuntimeError("Restore failure does not stop the app after containment proof fails.")
    if exit_body.index("runtime_survivor_unproved") > exit_body.index("disable_restore_safely"):
        raise RuntimeError("Restore failure can run cleanup before checking for an unproved survivor.")
    restore_runner = restore[restore.index("run_container_command() {") : restore.index("disable_restore_safely() {")]
    if any(
        value not in restore_runner
        for value in (
            'timeout --signal=TERM --kill-after=10s "${outer_seconds}" docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app',
            "timeout --signal=TERM --kill-after=15s",
            "container_operation_absent",
            "stop_app_safely",
            "runtime_survivor_unproved=true",
        )
    ):
        raise RuntimeError("Restore in-container timeout or survivor containment changed.")
    if not all(
        value in restore
        for value in (
            "run_container_command restore-backup 5400",
            'discourse restore --location s3 "${backup_filename}"',
            "run_container_command verify-restored-data 900",
            "run_container_command verify-restored-restart 900",
            "run_container_command verify-restored-rebuild 900",
        )
    ):
        raise RuntimeError("Destructive restore or its readbacks escaped the bounded in-container runner.")

    backup_transaction = (ROOT / "scripts/backup-transaction.py").read_text(encoding="utf-8")
    if "timeout --foreground" in backup:
        raise RuntimeError("Backup runner uses foreground timeout, which does not contain child processes.")
    for value in (
        "mutation_budget_seconds=4500",
        "remaining_mutation_seconds",
        'MOCHIRII_OPERATION_TOKEN="${operation_token}"',
        "container_operation_absent",
        "contain_failed_container_operation",
        "verify-runtime-assets.sh",
        "backup_runtime_recovery_command",
        "start_app_for_backup_recovery",
        "docker start app",
        "cleanup-pending",
        "restart-authorized",
        "cleanup-proved",
        "Backup refuses an active deployment transaction.",
        "Backup refuses an active nonterminal restore transaction.",
    ):
        if value not in backup:
            raise RuntimeError("Backup cumulative lifetime or runtime-asset boundary changed.")

    recovery_functions = backup[
        backup.index("prove_production_selection() {") :
        backup.index("finish_backup_transaction() {")
    ]
    start_function = backup[
        backup.index("start_app_for_backup_recovery() {") :
        backup.index("finish_backup_transaction() {")
    ]
    if any(value not in recovery_functions for value in (
        'timeout --signal=TERM --kill-after=5s 45 docker start app',
        '[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${production_config}" ]]',
        '[[ "$(readlink -f -- /opt/mochirii/forums/current)" == "${release_dir}" ]]',
        'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1"',
        'test "$DISCOURSE_DISABLE_EMAILS" = no',
        'stop_app_safely || runtime_survivor_unproved=true',
    )):
        raise RuntimeError("Stopped backup recovery lost its bounded exact-production identity or timeout containment.")
    operation_runner = backup[backup.index("run_container_command() {") : backup.index("record_event() {")]
    runner_order = (
        "prove_running_backup_identity",
        'backup_runtime_operation_command arm-operation "${label}" "${operation_token}"',
        'docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app',
        'container_operation_absent "${operation_token}"',
        'backup_runtime_operation_command complete-operation "${label}" "${operation_token}"',
    )
    if [operation_runner.index(value) for value in runner_order] != sorted(operation_runner.index(value) for value in runner_order):
        raise RuntimeError("Backup container mutation is not durably armed and absence-proved before completion.")
    runtime_reconciliation = backup[
        backup.index("reconcile_bound_runtime_ownership() {") : backup.index("restore_original_runtime_state() {")
    ]
    operation_recovery = runtime_reconciliation[
        runtime_reconciliation.index("operation-armed)") : runtime_reconciliation.index("idle)", runtime_reconciliation.index("operation-armed)"))
    ]
    recovery_order = (
        "contain_failed_container_operation",
        "prove_stopped_backup_identity",
        "prove-operation-absent",
        "authorize-restart",
        "start_app_for_backup_recovery",
        "complete-restart",
    )
    if [operation_recovery.index(value) for value in recovery_order] != sorted(operation_recovery.index(value) for value in recovery_order):
        raise RuntimeError("Stopped backup recovery can restart before exact operation absence and durable authority.")
    original_restoration = backup[
        backup.index("restore_original_runtime_state() {") : backup.index("contain_temporary_runtime_on_failure() {")
    ]
    if any(value not in original_restoration for value in (
        '[[ ${original_runtime_state} == running ]]',
        "complete-original-state --observed-runtime-state running",
        "authorize-original-stop",
        "runtime_operation_phase=original-stop-authorized",
        "reconcile_bound_runtime_ownership",
    )):
        raise RuntimeError("Backup terminal path no longer restores its exact original running/stopped state.")
    if "backup_transaction_command retire-prepared" in backup or 'fail("prepared backup ownership cannot retire before terminal runtime restoration")' not in backup_transaction:
        raise RuntimeError("Prepared backup ownership regained a journal-free retirement escape.")
    cleanup_function = backup[backup.index("cleanup() {") : backup.index("trap cleanup EXIT")]
    if "contain_temporary_runtime_on_failure" not in cleanup_function or "CRITICAL: Backup could not restore its stopped-origin containment state." not in cleanup_function:
        raise RuntimeError("A failed stopped-origin backup can escape without fail-closed containment ownership.")
    containment_function = backup[
        backup.index("contain_temporary_runtime_on_failure() {") : backup.index("finish_backup_transaction() {")
    ]
    containment_order = (
        "backup_transaction_command contain-temporary-runtime",
        "runtime_operation_phase=temporary-stop-authorized",
        "stop_app_safely",
        "prove_stopped_backup_identity",
        "backup_transaction_command contain-temporary-runtime",
        "runtime_operation_phase=initial-stopped",
    )
    cursor = 0
    for value in containment_order:
        position = containment_function.index(value, cursor)
        cursor = position + len(value)
    backup_fixture = (ROOT / "scripts/test-backup-transaction.py").read_text(encoding="utf-8")
    for value in (
        "assert_host_containment_sigkill",
        "assert_host_containment_retry",
        "Host containment stop was not durably pre-authorized.",
        "Post-stop SIGKILL reverted to unowned idle state.",
        '"temporary-stop-authorized"',
    ):
        if value not in backup_fixture:
            raise RuntimeError("Backup hostile fixture lost the stopped-origin post-stop crash window.")
    for value in (
        '"originalRuntimeState"', '"runtimeIdentitySha256"', '"currentReleaseSha256"',
        '"discourseRevision"', '"dockerManagerRevision"', '"runtimeEnvironmentSha256"',
        '"runtimePortBindingsSha256"', '"runtimeContainerImage"', '"runtimeOperationPhase"',
        '"arm-operation"', '"complete-operation"', '"prove-operation-absent"',
        '"authorize-restart"', '"complete-restart"', '"authorize-initial-start"',
        '"complete-initial-start"', '"contain-temporary-runtime"',
        '"authorize-original-stop"', '"complete-original-state"',
    ):
        if value not in backup_transaction:
            raise RuntimeError("Backup transaction lost its exact runtime recovery authority inventory.")
    for source, refusal, label in (
        (
            deploy,
            "Deployment refuses an active backup transaction; only the protected backup command may reconcile it.",
            "deploy",
        ),
        (
            restore,
            "Restore refuses an active backup transaction; only the protected backup command may reconcile it.",
            "restore",
        ),
    ):
        if refusal not in source:
            raise RuntimeError(f"{label} gained a bypass around protected stopped-backup recovery.")

    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    disposable_guard = (ROOT / "scripts/disposable-launcher-guard.py").read_text(encoding="utf-8")
    disposable_guard_fixture = (ROOT / "scripts/test-disposable-launcher-guard.py").read_text(encoding="utf-8")
    docker_manager_readback = (
        "sudo docker exec -u discourse app git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD"
    )
    if (
        disposable.count(docker_manager_readback) != 4
        or disposable.count("plugins/docker_manager rev-parse HEAD") != 4
        or "sudo docker exec app git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD" in disposable
        or "safe.directory" in disposable
    ):
        raise RuntimeError("Disposable Docker Manager readback does not execute as its repository owner.")
    backup_identity = re.search(r"(?ms)^prove_running_backup_identity\(\) \{.*?^\}", backup)
    if backup_identity is None:
        raise RuntimeError("Backup running-identity proof is absent.")
    backup_identity_source = backup_identity.group(0)
    if (
        backup_identity_source.count("docker exec -u discourse app bash -lc") != 1
        or backup_identity_source.count("git -C /var/www/discourse rev-parse HEAD") != 1
        or backup_identity_source.count("git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD") != 1
        or "docker exec app bash -lc" in backup_identity_source
        or "safe.directory" in backup
    ):
        raise RuntimeError("Backup runtime Git proof is not bound to the repository owner.")
    hosted_core_readback = "timeout --signal=TERM --kill-after=5s 30s docker exec -u discourse app bash -lc 'test \"$(cd /var/www/discourse && git rev-parse HEAD)\" = cbf996f65aae3da1843224aa624bcd9a225931ac'"
    hosted_manager_readback = "timeout --signal=TERM --kill-after=5s 30s docker exec -u discourse app bash -lc 'test \"$(cd /var/www/discourse/plugins/docker_manager && git rev-parse HEAD)\" = c008c3ca7fcc44775215843992e88190adb7b3bf'"
    hosted_source_block = '''timeout --signal=TERM --kill-after=10s 60s docker exec -u discourse app bash -lc '
  set -e
  export GIT_OPTIONAL_LOCKS=0
  git -C /var/www/discourse diff --no-ext-diff --quiet HEAD --
  git -C /var/www/discourse diff --no-ext-diff --cached --quiet
  test -z "$(git -c core.fsmonitor=false -C /var/www/discourse status --porcelain=v1 --untracked-files=all)"
  git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --quiet HEAD --
  git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --cached --quiet
  test -z "$(git -c core.fsmonitor=false -C /var/www/discourse/plugins/docker_manager status --porcelain=v1 --untracked-files=all)"
  cmp -s /var/www/discourse/plugins/mochirii_email_metadata/plugin.rb /opt/mochirii-release/mochirii-email-metadata-plugin.rb
' || fail "Running core, Docker Manager, or mandatory mail component bytes differ."'''
    if (
        host_verify.count(hosted_core_readback) != 1
        or host_verify.count(hosted_manager_readback) != 1
        or host_verify.count(hosted_source_block) != 1
        or "docker exec app bash -lc 'test \"$(cd /var/www/discourse" in host_verify
        or "safe.directory" in host_verify
    ):
        raise RuntimeError("Hosted Git proof is not exactly owner-scoped and mutation-free.")
    for value in (
        "Disposable named application image differs from the exact tagged application image.",
        "allowed_images.add(tagged)",
    ):
        if value not in disposable_guard:
            raise RuntimeError("Disposable launcher can retire mismatched tagged and running app images.")
    for value in (
        '"rebuild-mismatched-created-images"',
        '"rebuild-mismatched-preexisting-tag"',
        "Matching rebuild did not adopt exactly one terminal app image.",
        "def nginx_log_directory_fixture() -> None:",
        "NGINX_LOG_DIRECTORY_PREFIX = (",
        "Pinned Nginx log directory symlink guard changed its target.",
        "def nginx_outlet_syntax_fixture() -> None:",
        "Pinned Nginx accepted the hostile unquoted bounded recovery regex.",
    ):
        if value not in disposable_guard_fixture:
            raise RuntimeError("Disposable hostile fixture lost terminal image-equality or Nginx syntax coverage.")
    if (
        disposable.count("--tmpfs /var/log:rw,nosuid,nodev,size=4m,mode=0755,uid=0,gid=0 --group-add adm") != 1
    ):
        raise RuntimeError("Disposable hostile fixture lost its isolated root:adm Nginx log boundary.")
    if "timeout --foreground" in disposable:
        raise RuntimeError("Disposable restore uses foreground timeout, which can leave a spawned child alive.")
    for value in ("MOCHIRII_OPERATION_TOKEN", "container_operation_absent", "terminate_active_group"):
        if value not in disposable:
            raise RuntimeError("Disposable restore lost its descendant containment boundary.")


def test_process_group_timeout() -> None:
    if os.name != "posix":
        return
    timeout_command = shutil.which("timeout")
    bash = shutil.which("bash")
    if timeout_command is None or bash is None:
        raise RuntimeError("GNU timeout and Bash are required for the process-group hostile fixture.")
    with tempfile.TemporaryDirectory(prefix="mochirii-process-group-") as directory:
        pid_path = Path(directory) / "child.pid"
        completed = subprocess.run(
            [
                timeout_command,
                "--signal=TERM",
                "--kill-after=1s",
                "1s",
                bash,
                "-c",
                'sleep 300 & child=$!; printf "%s" "$child" >"$1"; wait "$child"',
                "bash",
                str(pid_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if completed.returncode not in {124, 137} or not pid_path.is_file():
            raise RuntimeError("Process-group hostile fixture did not reach its bounded timeout.")
        child_pid = int(pid_path.read_text(encoding="ascii"))
        for _ in range(20):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("A differently named spawned child survived the process-group timeout.")


def test_sidekiq_processing_contract() -> None:
    plugin = (ROOT / "plugins/mochirii_email_metadata/plugin.rb").read_text(encoding="utf-8")
    site = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    restored = (ROOT / "scripts/verify-restored-backup.rb").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-sidekiq-processing-probe.rb").read_text(encoding="utf-8")
    required = (
        'HEALTH_STATE_KEY = "mochirii-runtime-health-sidekiq-probe".freeze',
        "HEALTH_LEASE_GRACE_SECONDS = 30",
        "HEALTH_JOB_BIND_SECONDS = 5",
        "HEALTH_NONCE_PATTERN = /\\A[0-9a-f]{32}\\z/",
        "HEALTH_JID_PATTERN = /\\A[0-9a-f]{24}\\z/",
        "HEALTH_PREPARING_PATTERN = /\\Apreparing:[0-9a-f]{32}\\z/",
        "HEALTH_TRANSITION_SCRIPT",
        "HEALTH_DELETE_SCRIPT",
        'redis.call("set", KEYS[1], ARGV[2], "XX", "KEEPTTL")',
        'for index = 1, #ARGV do',
        "class SidekiqProbeError < StandardError",
        "class SidekiqProbeJobError < StandardError",
        "redis.namespace_key(HEALTH_STATE_KEY)",
        "redis.without_namespace",
        "nx: true, ex: lease_seconds",
        "Jobs.run_later?",
        "DB.transaction_open?",
        'Jobs.enqueue(:mochirii_sidekiq_processing_probe, queue: "default")',
        "jid.is_a?(String) && jid.match?(HEALTH_JID_PATTERN)",
        'raise SidekiqProbeError.new("marker-mismatch")',
        'raise SidekiqProbeError.new("job-reported-failure")',
        "return true if classify_health_probe_timeout(jid) == :completed",
        "ensure\n      clear_health_probe!(token, jid) if health_probe_owned",
        "state == started",
        "return unless state == pending",
        "transition_health_probe(started, completed)",
        "transition_health_probe(started, failed)",
        "raise MochiriiEmailMetadata::SidekiqProbeJobError.new, cause: nil",
    )
    if any(value not in plugin for value in required):
        raise RuntimeError("Leased Sidekiq processing probe lost an enqueue, state, retry, or cleanup invariant.")
    expected_states = {
        "cleanup-failed",
        "enqueue-rejected",
        "job-not-started-before-timeout",
        "job-reported-failure",
        "job-started-without-completion",
        "marker-mismatch",
        "probe-already-running",
        "probe-internal-failure",
        "run-mode-invalid",
        "transaction-open",
    }
    state_block = re.search(r"HEALTH_FAILURE_STATES\s*=\s*%w\[(.*?)\][.]freeze", plugin, re.S)
    if state_block is None or set(state_block.group(1).split()) != expected_states:
        raise RuntimeError("Sidekiq processing probe fixed-state vocabulary differs.")
    verifier_method = plugin[
        plugin.index("def self.verify_sidekiq_processing!") : plugin.index("module ::Jobs")
    ]
    verifier_order = (
        'raise SidekiqProbeError.new("run-mode-invalid")',
        'raise SidekiqProbeError.new("transaction-open")',
        "claim_health_probe!(token, timeout_seconds + HEALTH_LEASE_GRACE_SECONDS)",
        "health_probe_owned = true",
        'Jobs.enqueue(:mochirii_sidekiq_processing_probe, queue: "default")',
        "jid.is_a?(String) && jid.match?(HEALTH_JID_PATTERN)",
        'health_state_value("pending", jid)',
        "transition_health_probe(preparing, pending) == 1",
    )
    verifier_positions = [verifier_method.index(value) for value in verifier_order]
    if verifier_positions != sorted(verifier_positions):
        raise RuntimeError("Sidekiq lease claim, enqueue, JID binding, and observation ordering differs.")
    transition_block = plugin[plugin.index("def self.transition_health_probe") : plugin.index("def self.claim_health_probe!")]
    cleanup_block = plugin[plugin.index("def self.clear_health_probe!") : plugin.index("def self.expected_health_phase")]
    if ".to_i" in transition_block or ".to_i" in cleanup_block:
        raise RuntimeError("Sidekiq Lua outcomes regained Ruby truthiness coercion.")
    if "health_probe_state" in cleanup_block:
        raise RuntimeError("Sidekiq cleanup regained a post-delete global-read race.")
    if plugin.count("redis.without_namespace") != 2:
        raise RuntimeError("Sidekiq Lua operations are not bound to the physical namespaced key.")
    if any(value in plugin for value in ('redis.call("set", KEYS[1], ARGV[2], "EX"', "Discourse.redis.del")):
        raise RuntimeError("Sidekiq transitions can extend the lease or delete without ownership.")
    expected_lua = {
        "HEALTH_TRANSITION_SCRIPT": """local current = redis.call(\"get\", KEYS[1])
if not current then
  return 0
end
if current ~= ARGV[1] then
  return -1
end
if redis.call(\"ttl\", KEYS[1]) <= 0 then
  return -2
end
redis.call(\"set\", KEYS[1], ARGV[2], \"XX\", \"KEEPTTL\")
return 1""",
        "HEALTH_DELETE_SCRIPT": """local current = redis.call(\"get\", KEYS[1])
if not current then
  return 0
end
for index = 1, #ARGV do
  if current == ARGV[index] then
    redis.call(\"del\", KEYS[1])
    return 1
  end
end
return -1""",
    }
    for constant, expected_script in expected_lua.items():
        script_match = re.search(
            rf"{constant}\s*=\s*DiscourseRedis::EvalHelper[.]new\(<<~LUA\)\n(.*?)\n\s+LUA",
            plugin,
            re.S,
        )
        if script_match is None:
            raise RuntimeError(f"{constant} is absent from the Sidekiq probe.")
        actual_script = "\n".join(
            line[8:] if line.startswith(" " * 8) else line for line in script_match.group(1).splitlines()
        )
        if actual_script != expected_script:
            raise RuntimeError(f"{constant} differs from its exact fail-closed Lua body.")
    job = plugin[plugin.index("class MochiriiSidekiqProcessingProbe") :]
    if not (
        job.index("state == started") < job.index("return unless state == pending")
        and job.index("transition_health_probe(pending, started)") < job.index("transition_health_probe(started, completed)")
        and job.index("rescue StandardError") < job.index("transition_health_probe(started, failed)")
    ):
        raise RuntimeError("Sidekiq same-JID resume, completion, or fixed retry ordering differs.")
    for unsafe in (
        "Sidekiq::Queue",
        "Sidekiq::RetrySet",
        "Sidekiq::DeadSet",
        "Sidekiq::WorkSet",
        "Sidekiq::ProcessSet",
        "DistributedMutex",
        "PluginStore",
        '"#{token}"',
        '"#{jid}"',
        '"#{arguments}"',
        "error.message",
        "backtrace",
    ):
        if unsafe in plugin:
            raise RuntimeError("Sidekiq processing diagnostics inspect or emit an unsafe value.")
    fixture_canaries = (
        "spawn_worker_before_bind: true",
        "ProbeHarness.redis.expiry_history.uniq == [90.0]",
        '"direct NX claim did not expire and replace the ambiguous owner"',
        'expect_probe_state("run-mode-invalid")',
        'expect_probe_state("transaction-open")',
        'expect_probe_state("enqueue-rejected")',
        'expect_probe_state("probe-internal-failure")',
        'expect_probe_state("probe-already-running")',
        "enqueue_hold: true",
        '"expired pre-bind caller did not fail closed"',
        "lease_seconds: 1",
        'ProbeHarness.reset(mode: :missing_state)',
        'ProbeHarness.reset(mode: :wrong_state)',
        'expect_probe_state("job-not-started-before-timeout")',
        'expect_probe_state("job-started-without-completion")',
        'expect_probe_state("job-reported-failure")',
        'ProbeHarness.redis.force_state("started:" + ProbeHarness::VALID_JID)',
        'ProbeHarness.redis.force_state("pending:" + ProbeHarness::SECOND_JID)',
        'ProbeHarness.redis.force_state("preparing:" + ProbeHarness::FIXED_NONCE)',
        "ProbeHarness.delete_override = :nil",
        "ProbeHarness.delete_override = :raise",
        "takeover_after_delete: true",
        '"old cleanup changed the immediately acquired generation"',
        'expect_probe_state("cleanup-failed")',
        'ProbeHarness::RAW_WORKER_ERROR',
        'ProbeHarness::RAW_ENQUEUE_ERROR',
        'ProbeHarness::RAW_CLAIM_ERROR',
        "error.cause.nil?",
        "error.full_message.include?(value)",
        'puts "Sidekiq processing probe hostile fixture passed."',
    )
    if any(value not in fixture for value in fixture_canaries):
        raise RuntimeError("Sidekiq processing hostile fixture lost a state, retry, cleanup, or redaction case.")
    fake_redis_set = fixture[
        fixture.index("def set(key, value, nx:, ex:)") : fixture.index("def transition(key, arguments)")
    ]
    if (
        fake_redis_set.count("expire_if_needed(canonical)") != 1
        or fake_redis_set.index("expire_if_needed(canonical)")
        > fake_redis_set.index("return nil if nx && @store.key?(canonical)")
    ):
        raise RuntimeError("Sidekiq hostile Redis model does not expire a due key before its NX claim.")
    sidekiq_doc_requirements = {
        "docs/operations/RECOVERY.md": (
            "60-second post-enqueue observation window",
            "same-JID pending, started, failed,",
            "conditional Lua delete",
            "does not distinguish backlog from a",
        ),
        "docs/operations/RUNTIME-READINESS.md": (
            "one namespaced, expiring Redis lease",
            "enqueues without a correlation",
            "Compare-and-swap transitions retain the original lease expiry",
            "does not claim to distinguish backlog",
        ),
        "docs/operations/VALIDATION.md": (
            "private namespaced Redis lease",
            "exact no-argument JID binding",
            "60-second post-enqueue observation window",
            "terminal cleanup removes only the caller-owned state",
        ),
    }
    for document, required_values in sidekiq_doc_requirements.items():
        source = (ROOT / document).read_text(encoding="utf-8")
        if any(value not in source for value in required_values):
            raise RuntimeError(f"Sidekiq processing operations documentation differs in {document}.")
    for verifier in (site, restored):
        required_verifier = (
            "Sidekiq::ProcessSet.new.any?",
            "MochiriiEmailMetadata.verify_sidekiq_processing!",
            "rescue MochiriiEmailMetadata::SidekiqProbeError => error",
            'sidekiq_probe_state = "completed"',
            "sidekiq_probe_state = error.state",
            "sidekiqProbeState: sidekiq_probe_state",
        )
        if any(value not in verifier for value in required_verifier):
            raise RuntimeError("Runtime verification no longer proves and safely reports Sidekiq execution.")
        if any(value in verifier for value in ("error.message", "error.backtrace", "error.inspect")):
            raise RuntimeError("Runtime Sidekiq verification emits unsafe exception detail.")


def test_backup_restore_normal_upload_contract() -> None:
    marker = (ROOT / "scripts/prepare-backup-marker.rb").read_text(encoding="utf-8")
    restored = (ROOT / "scripts/verify-restored-backup.rb").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/host-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    finalizer = (ROOT / "scripts/finalize-member-rollout.sh").read_text(encoding="utf-8")
    publisher = (ROOT / "scripts/publish-disaster-recovery-evidence.rb").read_text(encoding="utf-8")
    fetcher = (ROOT / "scripts/fetch-disaster-recovery-evidence.rb").read_text(encoding="utf-8")
    release_fetcher = (ROOT / "scripts/fetch-disaster-recovery-release.rb").read_text(encoding="utf-8")
    historical_release = (ROOT / "scripts/historical-release-disaster-recovery.py").read_text(encoding="utf-8")
    clean_target = (ROOT / "scripts/verify-clean-disaster-target.rb").read_text(encoding="utf-8")
    runtime_assets = (ROOT / "scripts/verify-runtime-assets.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    backup_transaction = (ROOT / "scripts/backup-transaction.py").read_text(encoding="utf-8")
    backup_transaction_fixture = (ROOT / "scripts/test-backup-transaction.py").read_text(encoding="utf-8")

    marker_required = (
        'STATE_KEYS = %w[',
        'backupOperationSha256',
        "UploadCreator.new(",
        'origin: transaction.fetch("uploadOrigin")',
        ").create_for(Discourse.system_user.id)",
        'upload.user_id == Discourse.system_user.id',
        'upload.secure == false',
        'upload.content == expected_bytes',
        'store.get_path_for_upload(upload) == state.fetch("objectPath")',
        'public_uri.host == "media-forums.mochirii.com"',
        'store.object_from_path(state.fetch("objectPath")).exists?',
        'store.object_from_path(state.fetch("tombstonePath")).exists?',
        'store.delete_file(state.fetch("objectPath"))',
        'store.delete_file(state.fetch("tombstonePath"))',
        'PluginStore.remove(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)',
        'bounded_absent!(store, state)',
    )
    if any(value not in marker for value in marker_required):
        raise RuntimeError("Normal-upload recovery fixture lost an exact row, object, content, host, or cleanup invariant.")
    if any(value in marker for value in ("delete_all", "delete_matching", "objects.each", "clear_bucket")):
        raise RuntimeError("Normal-upload recovery cleanup broadened beyond the exact disposable identity.")

    restored_required = (
        'ENV.fetch("MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256")',
        'Digest::SHA256.hexdigest(canonical + "\\n") == expected_state_sha',
        'Upload.find_by(id: state["uploadId"])',
        'upload.content == expected_bytes',
        'store.get_path_for_upload(upload) == state["objectPath"]',
        'public_uri.host == "media-forums.mochirii.com"',
        'store.object_from_path(state["objectPath"]).exists?',
        'store.object_from_path(state["tombstonePath"]).exists?',
    )
    if any(value not in restored for value in restored_required):
        raise RuntimeError("Restored normal-upload proof lost an exact state, row, byte, path, or custom-host check.")

    backup_order = (
        "MOCHIRII_RECOVERY_UPLOAD_ACTION=prepare",
        "run_container_command create-backup",
        "run_container_command verify-backup",
    )
    backup_positions = [backup.index(value) for value in backup_order]
    cleanup_position = backup.index(
        'if ! reconcile_backup_upload_journal "${backup_upload_journal}"; then',
        backup_positions[-1],
    )
    backup_positions.extend(
        backup.index(value, cleanup_position)
        for value in (
            '"recoveryUploadDeletedAfterBackup": recovery_deleted',
            "os.link(candidate, evidence, follow_symlinks=False)",
            'finish_backup_transaction "${backup_transaction_phase}" "${evidence}"',
        )
    )
    backup_positions.insert(3, cleanup_position)
    if backup_positions != sorted(backup_positions):
        raise RuntimeError("Backup evidence can publish before the exact recovery upload is backed up and cleaned.")
    restore_backup_fixture = (
        'document.get("schemaVersion") != 3',
        'document.get("recoveryUploadIncluded") is True',
        'document.get("recoveryUploadDeletedAfterBackup") is not True',
        'inventory_count = document.get("normalUploadInventoryCount")',
        'inventory_sha = document.get("normalUploadInventorySha256")',
    )
    if any(value not in restore for value in restore_backup_fixture):
        raise RuntimeError("Disposable restore accepts backup evidence without the tested normal-upload fixture.")

    restore_journal_keys = {
        "schemaVersion", "phase", "restoreMode", "recordedAt", "updatedAt", "repositoryCommit",
        "productionConfigurationSha256", "productionConfigurationFile", "productionConfigurationFileSha256",
        "restoreConfigurationFile", "restoreConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256",
        "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "recoveryUploadIncluded",
        "recoveryUploadStateSha256", "normalUploadInventoryCount", "normalUploadInventorySha256",
        "cleanBackupIntentAt", "cleanBackupEvidenceFile", "cleanBackupEvidenceSha256",
        "cleanBackupFilename", "cleanBackupSha256", "restoreEvidenceFile", "restoreEvidenceSha256",
        "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
        "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
    }
    resume_start = restore.index("readarray -t resume_contract")
    resume_end = restore.index('print(document["phase"])', resume_start)
    resume_contract = restore[resume_start:resume_end]
    keys_match = re.search(r"required = \{(?P<body>.*?)\}\nif set\(document\) != required", resume_contract, re.S)
    if keys_match is None or set(re.findall(r'"([A-Za-z][A-Za-z0-9]+)"', keys_match.group("body"))) != restore_journal_keys:
        raise RuntimeError("Restore journal no longer validates its exact field inventory.")
    restore_launcher_fixture = (ROOT / "scripts/test-host-restore-launcher-journal.py").read_text(encoding="utf-8")
    for value in (
        'bind_launcher_replacement_image',
        'launcher_image_id_absent',
        '"launcherReplacementImageId"',
        'docker image rm --force "${durable_replacement}"',
        'restore journal replacement image identity cannot change',
        'env "MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=${launcher_operation_token}"',
        'fields = pathlib.Path(f"/proc/{pid}/environ").read_bytes().split(b"\\0")',
        'terminate_launcher_marked_processes',
        'launcher_marked_processes_absent',
    ):
        if value not in restore:
            raise RuntimeError("Restore launcher lost its durable replacement-image reconciliation.")
    for value in (
        'post-image-swap replacement ID was not durably bound',
        'crash_action=post-delete',
        'post-CID-unlink or image-reconciliation crash changed launcher authority',
        'harmless-detached',
        'setsid bash -c',
        'if launcher_marked_processes_absent; then exit 60; fi',
        'if retire_launcher_journal; then exit 61; fi',
    ):
        if value not in restore_launcher_fixture:
            raise RuntimeError("Restore launcher immutable-set hostile fixture coverage differs.")
    journal_intent_contract = (
        'clean_phases = {',
        '(document["phase"] in clean_phases) != isinstance(clean_intent, str)',
        'clean_intent = existing.get("cleanBackupIntentAt") if existing else None',
        'if order[phase] >= order["clean-backup-creating"] and clean_intent is None:',
        'if order[phase] < order["clean-backup-creating"] and clean_intent is not None:',
        '"cleanBackupIntentAt": clean_intent',
        'journal.get("phase") != "clean-backup-creating"',
        'journal["cleanBackupIntentAt"]',
        'modified < intent.replace(microsecond=0)',
    )
    if any(value not in restore for value in journal_intent_contract):
        raise RuntimeError("Restore clean-backup intent is not stable, phase-bound, and adoption-bound.")

    fixtureless_start = restore.index(
        'if [[ ${recovery_upload_state_base64} == - && ${recovery_upload_state_sha256} == - ]]; then'
    )
    fixtureless_end = restore.index("\nfi\n", fixtureless_start)
    fixtureless_contract = restore[fixtureless_start:fixtureless_end]
    if (
        "recovery_upload_fixture=false" not in fixtureless_contract
        or '[[ ${disaster_restore} == true ]] || fail "A fixture-free backup is accepted only for clean-target disaster recovery."'
        not in fixtureless_contract
    ):
        raise RuntimeError("Fixture-less backup evidence is no longer restricted to a clean-target disaster restore.")

    retirement_start = restore.index('current_backup="${state_root}/current-backup.json"')
    retirement_end = restore.index('if [[ -e ${restore_journal} || -L ${restore_journal} ]]; then', retirement_start)
    retirement = restore[retirement_start:retirement_end]
    retirement_contract = (
        'mochirii-restore-backup-retirement-v1\\0{sys.argv[1]}\\0{sys.argv[2]}',
        '--operation-sha "${restore_retirement_sha}"',
        'backup_transaction_helper}" inspect-current',
        '${current_backup_contract[4]} == event-committed',
        'backup_transaction_helper}" retire-current',
        '[[ ! -e ${current_backup} && ! -L ${current_backup} ]]',
    )
    if any(value not in retirement for value in retirement_contract):
        raise RuntimeError("Restore no longer retires only an exact event-committed current-backup through its helper.")
    retirement_positions = [retirement.index(value) for value in retirement_contract[2:]]
    if retirement_positions != sorted(retirement_positions):
        raise RuntimeError("Restore can retire terminal backup state before exact inspection or omit absence proof.")

    restore_runtime = restore[restore.index("isolated=true") :]
    restored_environment = (
        'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2"',
        'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"',
        '"${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}"',
    )
    for operation in ("verify-restored-data", "verify-restored-restart", "verify-restored-rebuild"):
        matching_lines = [line for line in restore_runtime.splitlines() if f"run_container_command {operation} " in line]
        if len(matching_lines) != 1 or any(value not in matching_lines[0] for value in restored_environment):
            raise RuntimeError(f"{operation} lost its exact normal-upload inventory environment binding.")
    restore_order = (
        'discourse restore --location s3 "${backup_filename}"',
        "run_container_command verify-restored-data",
        "run_container_command verify-restored-restart",
        "run_container_command verify-restored-rebuild",
        "run_container_command cleanup-restored-upload",
        "advance_restore_phase clean-backup-creating",
        "run_container_command verify-clean-upload 600",
        "run_container_command capture-clean-upload-inventory",
        "run_container_command inspect-clean-backup",
        "run_container_command create-clean-backup",
        "run_container_command verify-clean-backup",
        "run_container_command reverify-clean-inventory",
        "run_container_command reverify-clean-upload",
        "run_container_command publish-clean-recovery",
        "os.link(backup_path, evidence, follow_symlinks=False)",
        "advance_restore_phase clean-backup-committed",
        'python3 -B - "${backup_pointer}" "${clean_backup_evidence}"',
        "advance_restore_phase pointer-committed",
        "advance_restore_phase production-reopening",
        'activate_config "${production_config}"',
        "run_launcher production-reopen rebuild app",
        'bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" --restore-transaction',
        "advance_restore_phase production-reopened",
        '"normalUploadRestorePassed": True',
        '"finalCleanBackupMarkerAbsent": True',
        "advance_restore_phase restore-evidence-committed",
        'record_event passed "${restore_evidence_sha256}"',
        "advance_restore_phase event-committed",
    )
    restore_positions = [restore_runtime.index(value) for value in restore_order]
    if restore_positions != sorted(restore_positions):
        raise RuntimeError("Restore cleanup, final clean backup, evidence, or pointer ordering changed.")

    finalizer_required = (
        'restore_terminal="${state_root}/current-restore.json"',
        'restore-transaction.json && ! -L ${state_root}/restore-transaction.json',
        '[[ "$(stat -c \'%U:%G %a\' "${restore_terminal}")" == "root:root 600" ]]',
        'set(terminal) != terminal_keys',
        'terminal.get("restoreMode") != "disposable-rehearsal"',
        'bound_evidence("testedBackupEvidenceFile", "testedBackupEvidenceSha256", "backup")',
        'bound_evidence("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256", "backup")',
        'bound_evidence("restoreEvidenceFile", "restoreEvidenceSha256", "restore")',
        '"schemaVersion": 3',
        '"normalUploadRestorePassed": True',
        '"recoveryUploadCleanupPassed": True',
        '"finalCleanBackupMarkerAbsent": True',
        'tested.get("recoveryUploadIncluded") is not True',
        'tested.get("recoveryUploadStateSha256") != state_sha',
        'document.get("recoveryUploadIncluded") is not True',
        'document.get("recoveryUploadStateSha256") != state_sha',
        'document.get("testedNormalUploadInventoryCount") != tested_inventory_count',
        'clean.get("recoveryUploadIncluded") is not False',
        'document.get("finalCleanNormalUploadInventoryCount") != inventory_count',
        '"disasterRecoveryEvidencePublished", "disasterRecoveryPointerSelected", "disasterRecoveryPrivateAclPassed"',
        'backups/recovery-evidence/records/{dr_evidence_sha}.json',
        'clean.get("disasterRecoveryPointerObjectKey") != "backups/recovery-evidence/current.json"',
        'pointer_bytes != (str(clean_path) + "\\n").encode("utf-8")',
    )
    if any(value not in finalizer for value in finalizer_required):
        raise RuntimeError("Member rollout no longer requires the exact disposable terminal, restored upload, inventory, and final clean publication chain.")
    if any(value in finalizer for value in ('glob("*-restore.json")', "rglob(", "latest_restore", "latest-restore")):
        raise RuntimeError("Member rollout scans for a restore record instead of requiring the exact current-restore terminal.")

    for runtime_script in (
        "fetch-disaster-recovery-evidence.rb",
        "publish-disaster-recovery-evidence.rb",
        "verify-clean-disaster-target.rb",
    ):
        if deploy.count(runtime_script) != 2 or runtime_assets.count(runtime_script) != 2 or disposable.count(runtime_script) != 1:
            raise RuntimeError(f"Disaster-recovery runtime asset inventory differs: {runtime_script}")
    if deploy.count("fetch-disaster-recovery-release.rb") != 2 or runtime_assets.count("fetch-disaster-recovery-release.rb") != 2 or disposable.count("fetch-disaster-recovery-release.rb") != 3:
        raise RuntimeError("Historical release fetcher runtime asset or pinned fixture inventory differs.")
    for value in (
        "mochirii-release.tar",
        "test-disaster-recovery-release-chain.rb",
        "test-historical-recovery-scratch-reader.py",
        "test-historical-release-disaster-recovery.py",
        "test-disposable-launcher-guard.py",
        "test-host-restore-launcher-journal.py",
        "test-host-operation-lock.py",
    ):
        if value not in disposable:
            raise RuntimeError(f"Historical release disposable fixture registration differs: {value}")
    for value in ("mochirii-release.tar", "repositoryTree", "releaseArchiveBytes", "releaseArchiveContentManifestSha256"):
        if value not in deploy or value not in runtime_assets:
            raise RuntimeError(f"Immutable release runtime authority differs: {value}")
    for operation in (backup, restore):
        required_release_publication = (
            '"schemaVersion": 2', '"repositoryTree"', '"releaseArchiveBytes"',
            '"releaseArchiveContentManifestSha256"', '"releaseArchiveContainsSecrets": False',
            '"ordinaryDeploymentRequiresCurrentMain": True',
            '"historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only"',
            'result.get("schemaVersion") != 2',
        )
        if any(value not in operation for value in required_release_publication):
            raise RuntimeError("Backup/restore immutable release publication contract differs.")
    for consumer_name in (
        "authentication-state.py", "host-finalize-authentication.sh",
        "host-verify-wrapper.sh", "verify-host.sh",
    ):
        consumer = (ROOT / "scripts" / consumer_name).read_text(encoding="utf-8")
        if any(value not in consumer for value in ("repositoryTree", "releaseArchiveBytes", "releaseArchiveContentManifestSha256")):
            raise RuntimeError(f"Release evidence consumer lacks immutable archive authority: {consumer_name}")
    if "Ordinary deployment refuses an active historical disaster-recovery adoption." not in deploy:
        raise RuntimeError("Ordinary deployment can overlap historical disaster-recovery adoption.")
    if deploy.count("backup-transaction.py") != 2 or runtime_assets.count("backup-transaction.py") != 2 or disposable.count("backup-transaction.py") != 2:
        raise RuntimeError("Durable backup transaction helper or hostile fixture registration differs.")
    if deploy.count("normal-upload-inventory.rb") != 2 or runtime_assets.count("normal-upload-inventory.rb") != 2 or disposable.count("normal-upload-inventory.rb") != 2:
        raise RuntimeError("Normal-upload inventory runtime asset registration differs.")
    private_publication = (
        'S3Helper.build_from_config(for_backup: true)',
        'relative_evidence_key = "recovery-evidence/records/#{evidence_sha}.json"',
        'acl: "private"',
        'cache_control: "no-store"',
        'private_object!(object)',
        'document["containsSecrets"] == false',
        'document["containsSignedUrls"] == false',
        'bounded_read(object) == payload',
        'document["schemaVersion"] == 2',
        'releaseArchiveContainsSecrets',
        'ordinaryDeploymentRequiresCurrentMain',
        'historicalReleaseAdoptionScope',
        'recovery-releases/archives/',
        'recovery-releases/authorities/',
        '"schemaVersion" => 2',
    )
    if any(value not in publisher for value in private_publication):
        raise RuntimeError("Private off-host recovery evidence publication boundary differs.")
    private_fetch = (
        'MAX_DOCUMENT_BYTES = 32 * 1024',
        'private_object!(pointer_object)',
        'private_object!(evidence_object)',
        'grants.length == 1',
        'grants.first.permission == "FULL_CONTROL"',
        'grants.first.grantee&.type == "CanonicalUser"',
        'grants.first.grantee&.id.to_s == owner_id',
        'fail_fetch("object ACL is not exact private owner-only") unless exact_private',
        'Digest::SHA256.hexdigest(evidence_bytes) == pointer["evidenceObjectSha256"]',
        'source["cleanHostAdoptionRequiresEmptyPersistentData"] == true',
        'source["containsSecrets"] == false',
        'source["containsSignedUrls"] == false',
        '"normalUploadInventoryCount" => source["normalUploadInventoryCount"]',
        '"normalUploadInventorySha256" => source["normalUploadInventorySha256"]',
        'Digest::SHA256.hexdigest(core_bytes) == source["backupEvidenceCoreSha256"]',
        '"disasterRecoveryImported" => true',
        '"disasterRecoveryPrivateAclPassed" => true',
        'fetch_mode = ENV.fetch("MOCHIRII_DR_FETCH_MODE", "current-release")',
        '"disasterRecoveryBootstrapCommit" => bootstrap_commit',
        '"disasterRecoveryRepositoryTree" => source["repositoryTree"]',
        '"disasterRecoveryReleaseArchiveContentManifestSha256" => source["releaseArchiveContentManifestSha256"]',
    )
    if any(value not in fetcher for value in private_fetch):
        raise RuntimeError("Private off-host recovery evidence fetch boundary differs.")
    release_fetch_required = (
        'private_object!(pointer_object)',
        'private_object!(authority_object)',
        'private_object!(archive_object)',
        'fail_release_fetch("object ACL is not exact private owner-only")',
        'MAX_RELEASE_ARCHIVE_BYTES = 64 * 1024 * 1024',
        'receipt["disasterRecoveryFetchMode"] == "clean-target-historical"',
        'bootstrap_commit != commit',
        'ordinaryDeploymentRequiresCurrentMain',
        'historicalReleaseAdoptionScope',
        'digest.hexdigest == archive_sha',
    )
    if any(value not in release_fetcher for value in release_fetch_required):
        raise RuntimeError("Private immutable historical release fetch boundary differs.")
    historical_required = (
        'ARCHIVE_FORMAT = "git-archive-tar-v1"',
        'ADOPTION_SCOPE = "clean-target-disaster-recovery-only"',
        'ordinaryDeploymentRequiresCurrentMain',
        'historical-release-adoption.json',
        '"phase": "source-prepared"',
        '"phase": "configuration-authorized"',
        'tree != identity.repository_tree or manifest != identity.content_manifest_sha256',
        'PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE',
        'AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE',
    )
    if any(value not in historical_release for value in historical_required):
        raise RuntimeError("Provenance-bound historical release adoption contract differs.")
    fetch_core_order = (
        '"normalUploadInventoryCount" => source["normalUploadInventoryCount"]',
        '"normalUploadInventorySha256" => source["normalUploadInventorySha256"]',
        "core_bytes = JSON.pretty_generate(core_document.sort.to_h)",
        'Digest::SHA256.hexdigest(core_bytes) == source["backupEvidenceCoreSha256"]',
        '"disasterRecoveryImported" => true',
    )
    if [fetcher.index(value) for value in fetch_core_order] != sorted(fetcher.index(value) for value in fetch_core_order):
        raise RuntimeError("Fetched disaster-recovery inventory is not reconstructed into the pre-publication core digest.")
    clean_checks = (
        'User.where("id > 0").none?', 'Post.where("user_id > 0").none?',
        'Topic.where("user_id > 0").none?', 'Upload.none?', 'ApiKey.none?',
        'UserApiKey.none?', 'PluginStore.get("mochirii-recovery", "repository_commit").nil?',
        'PluginStore.get("mochirii-recovery", "normal_upload_marker").nil?',
    )
    if any(value not in clean_target for value in clean_checks):
        raise RuntimeError("Clean-target disaster restore guard differs.")
    clean_position = restore.index('verify-clean-disaster-target.rb')
    fetch_position = restore.index('fetch-disaster-recovery-evidence.rb', clean_position)
    restore_position = restore.index('discourse restore --location s3 "${backup_filename}"', fetch_position)
    if not clean_position < fetch_position < restore_position:
        raise RuntimeError("Private recovery evidence can be fetched or restored before the clean-target guard.")

    backup_publish = backup[backup.index('python3 -B - "${candidate}" "${evidence}"') : backup.index('candidate=""', backup.index('python3 -B - "${candidate}" "${evidence}"'))]
    publish_order = (
        "os.fsync(descriptor)",
        "os.link(candidate, evidence, follow_symlinks=False)",
        "os.fsync(directory)",
        "candidate.unlink()",
    )
    positions = [backup_publish.index(value) for value in publish_order]
    if positions != sorted(positions):
        raise RuntimeError("Backup evidence can report success without durable no-replace file and parent commits.")

    terminal = backup[backup.index("finish_backup_transaction() {") : backup.index("validate_backup_upload_journal()")]
    terminal_order = (
        "backup_transaction_command evidence-sha",
        "backup_transaction_command select-pointer",
        "backup_transaction_command publish-phase --phase pointer-committed",
        'record_event passed "${evidence_sha}"',
        "backup_transaction_command publish-phase --phase event-committed",
        "backup_transaction_command clear",
    )
    terminal_positions = [terminal.index(value) for value in terminal_order]
    if terminal_positions != sorted(terminal_positions):
        raise RuntimeError("Backup pointer, passed event, terminal record, or journal clearance ordering differs.")
    helper_required = (
        "backupOperationSha256",
        "previousLatestEvidenceFile", "previousLatestPointerSha256",
        'if current_file == evidence.name and current_sha == target_sha:',
        'fail("latest-backup pointer changed outside this transaction")',
        'atomic_write(args.pointer, target_payload, replace=current_file is not None)',
        'if transaction["phase"] != "event-committed":',
        'if args.current.exists() or args.current.is_symlink():',
        'fail("terminal current-backup must be retired before a new transaction")',
        'document["backupOperationSha256"] != args.operation_sha',
        'validate_terminal_current(',
        'if document["backupOperationSha256"] == args.operation_sha:',
        'fail("current-backup cannot be retired by its own operation")',
        "args.transaction.unlink()", "os.fsync(directory)",
        '"runtimeRecoveryPhase"',
        '"cleanup-pending"', '"restart-authorized"', '"cleanup-proved"',
        "validate_backup_upload_journal(",
        "action_bind_cleanup", "action_authorize_restart",
        "action_complete_cleanup", "action_resume_runtime", "action_retire_prepared",
        'fail("backup runtime cannot resume before cleanup journal retirement")',
        'fail("prepared backup ownership cannot retire before terminal runtime restoration")',
        '"originalRuntimeState"', '"runtimeIdentitySha256"', '"currentReleaseSha256"',
        '"discourseRevision"', '"dockerManagerRevision"', '"runtimeEnvironmentSha256"',
        '"runtimePortBindingsSha256"', '"runtimeContainerImage"', '"runtimeOperationPhase"',
        "action_arm_operation", "action_complete_operation", "action_prove_operation_absent",
        "action_complete_restart", "action_authorize_initial_start", "action_complete_initial_start",
        "action_contain_temporary_runtime", "action_authorize_original_stop", "action_complete_original_state",
    )
    if any(value not in backup_transaction for value in helper_required):
        raise RuntimeError("Durable backup transaction lost operation identity, predecessor, adoption, retirement, terminal-phase, or parent-fsync enforcement.")

    host_backup_operation = (
        '[[ $# -eq 2 ]] || fail "Usage: host-backup.sh EXPECTED_COMMIT BACKUP_OPERATION_SHA256"',
        '[[ ${backup_operation_sha} =~ ^[0-9a-f]{64}$ ]]',
        '--operation-sha "${backup_operation_sha}"',
        'backup_transaction_command inspect-current',
        'if [[ ${current_backup_operation} == "${backup_operation_sha}" ]]; then',
        'backup_transaction_command adopt-current',
        '[[ ${current_backup_phase} == event-committed ]]',
        'backup_transaction_command retire-current',
        'backup_transaction_command create',
        'backup_runtime_recovery_command bind-cleanup',
        'backup_runtime_recovery_command complete-cleanup',
        'backup_runtime_recovery_command resume-runtime',
        'backup_runtime_operation_command arm-operation',
        'backup_runtime_operation_command complete-operation',
        'backup_runtime_operation_command prove-operation-absent',
        'backup_runtime_operation_command complete-restart',
        'restore_original_runtime_state',
        'start_app_for_backup_recovery',
    )
    if any(value not in backup for value in host_backup_operation):
        raise RuntimeError("Protected backup caller identity adoption/retirement contract differs.")
    operation_flow = backup[backup.index('if [[ -e ${current_backup} || -L ${current_backup} ]]; then') :]
    operation_positions = [operation_flow.index(value) for value in (
        'backup_transaction_command inspect-current',
        'backup_transaction_command adopt-current',
        'backup_transaction_command retire-current',
        'backup_transaction_command create',
    )]
    if operation_positions != sorted(operation_positions):
        raise RuntimeError("Backup can create a new transaction before terminal operation adoption or retirement.")
    operation_fixture_required = (
        "Same-operation terminal backup was not adopted.",
        "different operation retired an intervened pointer",
        "New backup transaction did not bind its caller operation.",
        "current receipt advanced two commit points",
        "same operation retired its terminal receipt",
        "new operation prearmed before terminal receipt retirement",
        "stopped recovery accepted a changed operation token",
        "crash-recovered backup resumed before journal retirement",
        "Stopped upload-cleanup recovery did not resume exactly.",
        "Post-cleanup SIGKILL lost exact runtime ownership.",
        "post-cleanup recovery accepted changed ports",
        "Post-rollout timeout lost journal-free operation ownership.",
        "idle journal-free backup gained generic restart authority",
        "Stopped-origin runtime was not durably restored.",
    )
    if any(value not in backup_transaction_fixture for value in operation_fixture_required):
        raise RuntimeError("Backup operation-identity hostile fixtures differ.")

    restore_evidence_start = restore.index('python3 - "${restore_evidence}" "${backup_evidence}"')
    restore_evidence = restore[restore_evidence_start : restore.index('  restore_evidence_sha256=', restore_evidence_start)]
    if restore_evidence.index("os.link(temporary, path, follow_symlinks=False)") > restore_evidence.index("os.fsync(directory)"):
        raise RuntimeError("Restore evidence parent fsync precedes its no-replace publication.")
    deterministic_identity = restore[
        restore.index('readarray -t restore_identity < <(python3 -B - "${restore_journal}"') : restore_evidence_start
    ]
    deterministic_required = (
        'clean_name = pathlib.Path(sys.argv[2]).name',
        'journal["recordedAt"]',
        'print(match.group(1))',
        'restore_evidence="${evidence_root}/${commit}-${configuration}-${restore_identity[0]}-restore.json"',
    )
    if any(value not in deterministic_identity for value in deterministic_required):
        raise RuntimeError("Restore evidence identity is no longer derived deterministically from durable journal and clean-backup state.")
    adoption_required = (
        'if path.exists() or path.is_symlink():',
        'path.read_bytes() != temporary.read_bytes()',
        'raise SystemExit("existing restore evidence differs")',
        'os.link(temporary, path, follow_symlinks=False)',
        'if temporary.exists():',
        'temporary.unlink()',
    )
    if any(value not in restore_evidence for value in adoption_required):
        raise RuntimeError("Restore evidence retry does not exact-adopt only deterministic existing bytes.")


def test_public_branding_signed_credential_boundary() -> None:
    hostile = (
        "X-Amz-Credential=fixture/20260815/sgp1/s3/aws4_request",
        "x-aMz-SiGnAtUrE=deadbeef",
        "X-AMZ-SECURITY-TOKEN=fixture",
        "AWSAccessKeyId=fixture",
        "Signature=deadbeef",
        "X%2dAmz%2dCredential%3dfixture",
        "x&#45;amz&#45;signature=deadbeef",
        r'{"X\u002dAmz\u002dSecurity\u002dToken":"fixture"}',
        "X%26%2345%3BAmz%26%2345%3BCredential=fixture",
    )
    for value in hostile:
        if not PUBLIC_BRANDING.exposes_signed_credential(value):
            raise RuntimeError(f"Public branding accepted an encoded signed credential marker: {value}")
    accepted = (
        "x-amz-request-id: fixture-request-id",
        "X-AMZ-REQUEST-ID=fixture-request-id",
        "x%2damz%2drequest%2did=fixture-request-id",
    )
    if any(PUBLIC_BRANDING.exposes_signed_credential(value) for value in accepted):
        raise RuntimeError("Public branding rejected neutral x-amz-request-id transport metadata.")


def test_atomic_operator_evidence_publication_contract() -> None:
    member = (ROOT / "scripts/finalize-member-rollout.sh").read_text(encoding="utf-8")
    authentication = (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")
    stop = (ROOT / "scripts/host-stop-pending-activation.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    for label, source in (
        ("member-rollout marker", member),
        ("authentication complete record", authentication),
        ("operator containment record", stop),
        ("deployment immutable evidence", deploy),
    ):
        if "os.link(candidate, path, follow_symlinks=False)" not in source:
            raise RuntimeError(f"{label} is visible at its final name before a complete fsynced no-replace publication.")
        if "partial is unsafe" not in source or "os.fsync(directory)" not in source:
            raise RuntimeError(f"{label} lacks bounded stale-partial reconciliation or parent durability.")
        direct_final_writes = list(
            re.finditer(r"os[.]open\(path, os[.]O_WRONLY[^\n]*os[.]O_EXCL", source)
        )
        if direct_final_writes:
            if label != "deployment immutable evidence" or len(direct_final_writes) != 1:
                raise RuntimeError(f"{label} still writes directly into a final immutable filename.")
            prefix = source[max(0, direct_final_writes[0].start() - 250) : direct_final_writes[0].start()]
            if "storage-cleanup-required.json" not in prefix:
                raise RuntimeError("Deployment evidence gained an unreviewed direct-final publication.")
    if deploy.count("os.link(candidate, path, follow_symlinks=False)") < 4:
        raise RuntimeError("Storage, release, pending-authentication, or activation-failure evidence escaped atomic no-replace publication.")
    if stop.count("os.link(candidate, path, follow_symlinks=False)") < 2:
        raise RuntimeError("One operator containment transition still exposes a partial final-name record.")

    member_publish = member[member.index("candidate = path.parent / f\".{path.name}.partial\"") : member.index("[[ \"$(stat -c", member.index("candidate = path.parent / f\".{path.name}.partial\""))]
    for value in (
        "discard_safe_partial()",
        "if path.exists() or path.is_symlink():",
        'set(document) != set(expected) | {"finalizedAt"}',
        "any(document.get(key) != value for key, value in expected.items())",
        "os.fsync(target.fileno())",
        "os.link(candidate, path, follow_symlinks=False)",
        "candidate.unlink()",
    ):
        if value not in member_publish:
            raise RuntimeError("Member-rollout crash recovery lost exact-existing or partial-publication handling.")

    complete_validation = authentication[authentication.index("resume_complete = False") : authentication.index("print(release_name)")]
    if (
        complete_validation.index("if complete_path.exists() or complete_path.is_symlink():")
        > complete_validation.index("if not resume_complete and")
        or 'expected_complete = {' not in complete_validation
        or 'complete.get("websiteRepositoryCommit") != website.get("websiteRepositoryCommit")' not in complete_validation
    ):
        raise RuntimeError("Authentication record-created/pointer-pending resume still depends on fresh or conflicting Website evidence.")
    complete_publish = authentication[authentication.index('python3 -B - "${authentication_record}"') : authentication.index('[[ "$(stat -c', authentication.index('python3 -B - "${authentication_record}"'))]
    if "if path.exists() or path.is_symlink():" not in complete_publish or "os.link(candidate, path, follow_symlinks=False)" not in complete_publish:
        raise RuntimeError("Authentication complete evidence is not exact-existing idempotent after record-before-pointer interruption.")
    break_glass = (ROOT / "scripts/host-break-glass-admin.sh").read_text(encoding="utf-8")
    verify_wrapper = (ROOT / "scripts/host-verify-wrapper.sh").read_text(encoding="utf-8")
    bounded_reads = {
        "member rollout": (member, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
        "authentication finalization": (authentication, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
        "administrator recovery": (break_glass, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
        "stable host verification": (verify_wrapper, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
    }
    for label, (source, required) in bounded_reads.items():
        direct_reads = [line.strip() for line in source.splitlines() if "docker exec app bash -lc" in line]
        if not direct_reads or any(required not in line for line in direct_reads):
            raise RuntimeError(f"{label} holds the global lock across an unbounded Docker readback.")
    deployment_reads = [line.strip() for line in deploy.splitlines() if "docker exec app bash -lc" in line]
    if not deployment_reads or any(
        "timeout --signal=TERM --kill-after=" not in line for line in deployment_reads
    ):
        raise RuntimeError("Deployment recovery holds the global lock across an unbounded Docker readback.")


def test_deployment_terminal_transaction_contract() -> None:
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/host-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    wrapper = (ROOT / "scripts/host-verify-wrapper.sh").read_text(encoding="utf-8")
    authentication = (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")
    stop = (ROOT / "scripts/host-stop-pending-activation.sh").read_text(encoding="utf-8")
    break_glass = (ROOT / "scripts/host-break-glass-admin.sh").read_text(encoding="utf-8")

    deploy_required = (
        'readonly deployment_transaction="/var/lib/mochirii/forums/deployment-transaction.json"',
        'readonly deployment_terminal="/var/lib/mochirii/forums/current-deployment.json"',
        'order = {"prepared": 10, "state-committed": 20, "event-committed": 30}',
        'phase not in {"prepared", "state-committed", "event-committed"}',
        'source.get("phase") != "event-committed"',
        'document["phase"] = "complete"',
        'an active deployment transaction belongs to another exact operation',
        'deployment transaction stable field differs: {key}',
        'deployment member marker binding differs',
        'deployment authentication binding differs',
        'Active deployment transaction authentication state differs from its exact retry contract.',
        'run_release_verification "${previous_release}" "${previous_configuration}" --deployment-prior-rollback || return 1',
    )
    if any(value not in deploy for value in deploy_required):
        raise RuntimeError("Deployment terminal schema, exact-tuple adoption, or fail-closed retry contract differs.")

    mutation_verified = deploy.rindex("mark_deployment_mutation_verified")
    prearm = deploy.rindex("write_deployment_transaction prepared")
    armed = deploy.rindex("deployment_commit_armed=true", 0, prearm)
    completion_call = deploy.index("complete_deployment_commit prepared", prearm)
    if not mutation_verified < armed < prearm < completion_call:
        raise RuntimeError("Deployment publication is not conservatively armed before its durable prepared transaction.")
    completion = deploy[deploy.index("complete_deployment_commit() {") : deploy.index("seal_activation_deploy_failure() {")]
    completion_order = (
        'ln -sfn -- "${release_dir}" /opt/mochirii/forums/current.next',
        'write_current_evidence "${commit}" "${configuration_id}"',
        'finish_deployment_authentication "${authentication_action}"',
        'run_release_verification "${commit}" "${configuration_id}" --deployment-transaction',
        'write_deployment_transaction state-committed',
        'record_event deployment passed',
        'write_deployment_transaction event-committed',
        "publish_deployment_terminal",
        "clear_deployment_transaction",
    )
    completion_positions = [completion.index(value) for value in completion_order]
    if completion_positions != sorted(completion_positions):
        raise RuntimeError("Deployment state, durable event, terminal record, or journal clearance ordering differs.")
    for required in (
        '<<\'PY\' >/dev/null || return 1',
        'ln -sfn -- "${release_dir}" /opt/mochirii/forums/current.next || return 1',
        'mv -Tf -- /opt/mochirii/forums/current.next /opt/mochirii/forums/current || return 1',
        'fsync_directory /opt/mochirii/forums || return 1',
        '"${requested_discourse_connect}" "${marker_file_for_evidence}" "${marker_sha_for_evidence}" || return 1',
    ):
        if required not in completion:
            raise RuntimeError("Deployment terminal publication can mask a durable mutation failure.")
    forward_fix_publication = deploy[
        deploy.index("seal_forward_fix_required() {") : deploy.index("validate_forward_fix_retry() {")
    ]
    for required in (
        'activate_config "${config_dir}/app.yml" || return 1',
        'current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk \'{print $1}\')" || return 1',
        "<<'PY' || return 1",
        "return 0",
    ):
        if required not in forward_fix_publication:
            raise RuntimeError("Forward-fix containment can mask its durable journal publication failure.")
    activation_failure_publication = deploy[
        deploy.index("seal_activation_deploy_failure() {") : deploy.index("recover_failed_activation() {")
    ]
    for required in (
        'activate_config "${previous_config}" || return 1',
        'record_sha="$(sha256sum -- "${record}" | awk \'{print $1}\')" || return 1',
        "<<'PY' || return 1",
        "return 0",
    ):
        if required not in activation_failure_publication:
            raise RuntimeError("Activation containment can mask its durable evidence or pointer publication failure.")
    terminal_retry = completion.index('if [[ ${phase} == complete ]]')
    terminal_verify = completion.index('run_release_verification "${commit}" "${configuration_id}" || return 1', terminal_retry)
    active_verify = completion.index('run_release_verification "${commit}" "${configuration_id}" --deployment-transaction', terminal_verify)
    if not terminal_retry < terminal_verify < active_verify:
        raise RuntimeError("Completed deployment adoption incorrectly claims ownership of a retired transaction journal.")

    adoption = deploy.index("readarray -t deployment_resume < <(deployment_state_contract)")
    bootstrap_precondition = deploy.index('if [[ ${mode} == bootstrap ]]; then', adoption)
    storage_fixture = deploy.index("run_storage_fixture create", bootstrap_precondition)
    if not adoption < bootstrap_precondition < storage_fixture:
        raise RuntimeError("Deployment retry adoption occurs after bootstrap or hosted-storage side effects.")

    deployment_docs = (ROOT / "docs/operations/DEPLOYMENT.md").read_text(encoding="utf-8")
    recovery_docs = (ROOT / "docs/operations/RECOVERY.md").read_text(encoding="utf-8")
    validation_docs = (ROOT / "docs/operations/VALIDATION.md").read_text(encoding="utf-8")
    documentation_required = {
        "deployment": (
            deployment_docs,
            (
                "leaves the mutation journal for the",
                "SHA-256 of the exact current-release bytes",
                "without its exact same-tuple deployment-mutation",
                "failure containment is conservatively armed before the",
                "prior-rollback owner accepts only a mutation-only `rebuild` journal",
                "refuses an existing container, database, active configuration, current-release",
            ),
        ),
        "recovery": (
            recovery_docs,
            (
                "leaves deployment ownership intact",
                "An orphan hosted-storage",
                "cleanup journal is never mutation authority.",
                "same-version/no-target-migration rollback",
            ),
        ),
        "validation": (
            validation_docs,
            (
                "prior-rollback owner may name only a mutation-only exact sealed prior tuple",
                "Mutation plus promotion",
                "exact `/opt/mochirii/forums/current` symlink target",
            ),
        ),
    }
    for label, (document, required_fragments) in documentation_required.items():
        if any(fragment not in document for fragment in required_fragments):
            raise RuntimeError(f"Deployment mutation {label} documentation differs.")

    cross_refusals = {
        "deployment": (deploy, "backup-transaction.json", "restore-transaction.json"),
        "backup": (backup, "deployment-transaction.json", "restore-transaction.json"),
        "restore": (restore, "deployment-transaction.json", "backup-transaction.json"),
    }
    for label, (source, first, second) in cross_refusals.items():
        if first not in source or second not in source or "deployment-mutation.json" not in source:
            raise RuntimeError(f"{label} lost an active cross-operation transaction refusal.")
    for label, source in (
        ("authentication finalization", authentication),
        ("administrator recovery", break_glass),
    ):
        if any(name not in source for name in ("deployment-transaction.json", "deployment-mutation.json", "backup-transaction.json", "restore-transaction.json")):
            raise RuntimeError(f"{label} no longer refuses every active protected host transaction.")
    for value in (
        "deployment-transaction.json",
        "backup-transaction.json",
        "restore-transaction.json",
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved && ${deployment_mutation_active} != true ]]; then',
        "Activation failure producer reconciliation requires its exact deployment mutation journal.",
        'if [[ ${deployment_mutation_active} == true && ${authentication_phase} != activation-deploy-failed-producer-unproved ]]; then',
        "deployment mutation stopped retry tuple differs",
        'mutation.get("phase") != "runtime-contained"',
        'mutation.get("activeConfigurationFile") != str(previous_app)',
        'mutation.get("previousCurrentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()',
        'validate_mutation(pathlib.Path(mutation_argument))',
    ):
        if value not in stop:
            raise RuntimeError("Pending activation containment lost its exact mutation-bound recovery exception.")
    mutation_required = stop.index(
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved && ${deployment_mutation_active} != true ]]; then'
    )
    failed_activation_branch = stop.index(
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then', mutation_required
    )
    exact_mutation_argument = stop.index(
        '"${configuration}" "${deployment_mutation}" <<\'PY\'', failed_activation_branch
    )
    unconditional_mutation_validation = stop.index(
        "validate_mutation(pathlib.Path(mutation_argument))", exact_mutation_argument
    )
    failed_activation_cardinality = stop.index(
        '[[ ${#evidence[@]} -eq 6', unconditional_mutation_validation
    )
    first_failed_activation_stop = stop.index('docker stop --time 30 app', failed_activation_cardinality)
    if not (
        mutation_required
        < failed_activation_branch
        < exact_mutation_argument
        < unconditional_mutation_validation
        < failed_activation_cardinality
        < first_failed_activation_stop
    ):
        raise RuntimeError("Activation failure producer reconciliation can bypass exact mutation validation before containment.")

    verifier_required = (
        '[--deployment-transaction|--deployment-prior-rollback|--restore-transaction]',
        '"standalone": {frozenset()}',
        'frozenset({"deployment-mutation"})',
        'frozenset({"deployment", "deployment-mutation"})',
        '"--deployment-prior-rollback": {frozenset({"deployment-mutation"})}',
        '"--restore-transaction": {frozenset({"restore"})}',
        'active host-operation transaction inventory differs from the verifier owner',
        'deployment mutation journal tuple, schema, path, or phase differs',
        'deployment mutation launcher identity is incomplete',
        'deployment mutation launcher token or command differs',
        'deployment prior-rollback owner differs from the mutation journal',
        'deployment prior-rollback runtime state differs',
        'deployment promotion requires a verified mutation journal',
        'verified deployment mutation lacks its completed terminal record',
        'completed_terminal_matches_expected = (',
        'active["deployment"] or mutation_phase != "verified"',
        'published current release target differs from the verifier owner',
        'deployment transaction tuple or phase differs',
        'restore transaction tuple or phase differs',
        '"cleanBackupIntentAt"',
        'restore transaction clean-backup intent differs',
        'completed deployment record schema or identity differs',
        'completed deployment release evidence differs',
        'completed deployment differs from current release evidence',
        'completed deployment member marker transition differs',
        'current member-rollout marker differs',
        'current authentication evidence record differs',
        'completed deployment authentication transition differs',
        'completed deployment authentication release binding differs',
        'marker_transition = (',
        'allow_authentication_transition and action == "pending"',
        'set(release_document) != release_keys',
        'require_disabled_authentication_absent=True',
    )
    if any(value not in verifier for value in verifier_required):
        raise RuntimeError("Hosted verification transaction owner, terminal, marker, or authentication boundary differs.")
    if '--deployment-transaction' in wrapper or '--restore-transaction' in wrapper:
        raise RuntimeError("Stable standalone host verification can adopt another operation's active journal.")
    if 'bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" --restore-transaction' not in restore:
        raise RuntimeError("Restore does not identify its exact active journal to hosted verification.")


def test_deployment_runtime_mutation_contract() -> None:
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    helper = (ROOT / "scripts/deployment-mutation.py").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-deployment-mutation.py").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    deployment_docs = (ROOT / "docs/operations/DEPLOYMENT.md").read_text(encoding="utf-8")
    recovery_docs = (ROOT / "docs/operations/RECOVERY.md").read_text(encoding="utf-8")
    validation_docs = (ROOT / "docs/operations/VALIDATION.md").read_text(encoding="utf-8")

    required_deploy = (
        'readonly deployment_mutation_journal="/var/lib/mochirii/forums/deployment-mutation.json"',
        'create_deployment_mutation || fail "Deployment runtime mutation journal could not be durably pre-armed."',
        'deployment_mutation set-config --path "${deployment_mutation_journal}"',
        'deployment_mutation arm-launcher --path "${deployment_mutation_journal}"',
        'deployment_mutation finish-launcher --path "${deployment_mutation_journal}"',
        'readarray -t deployment_mutation_contract < <(inspect_deployment_mutation)',
        'mark_deployment_mutation_contained',
        'mark_deployment_mutation_verified',
        'clear_deployment_mutation',
        'Deployment terminal publication exists without a verified runtime-mutation journal.',
        'Interrupted launcher mutation could not be reconciled safely.',
        'deployment_mutation mark-contained --path "${deployment_mutation_journal}" || return 1',
        'deployment_mutation mark-verified --path "${deployment_mutation_journal}" || return 1',
        'Deployment mutation prior current-release bytes differ from their sealed digest.',
        'Pending hosted storage cleanup lacks its exact deployment mutation authority.',
        'Bootstrap mode refuses existing current-release evidence.',
        'Bootstrap mode refuses an existing current-release target.',
    )
    if any(value not in deploy for value in required_deploy):
        raise RuntimeError("Deployment runtime mutation journal integration differs.")
    prearm = deploy.index('create_deployment_mutation || fail "Deployment runtime mutation journal could not be durably pre-armed."')
    first_target_switch = deploy.index('activate_config "${config_dir}/activation.yml"', prearm)
    terminal_prearm = deploy.rindex("write_deployment_transaction prepared")
    mutation_verified = deploy.rindex("mark_deployment_mutation_verified")
    terminal_armed = deploy.rindex("deployment_commit_armed=true", 0, terminal_prearm)
    mutation_clear = deploy.rindex("clear_deployment_mutation")
    terminal_complete = deploy.rindex("complete_deployment_commit prepared")
    if not prearm < first_target_switch < mutation_verified < terminal_armed < terminal_prearm < terminal_complete < mutation_clear:
        raise RuntimeError("Deployment mutation, verification, and terminal publication ordering differs.")
    activate = deploy[deploy.index("activate_config() {") : deploy.index("write_current_evidence() {")]
    if activate.index("deployment_mutation set-config") > activate.index('ln -sfn -- "${target}"') or any(
        fragment not in activate
        for fragment in (
            '--configuration-file "${target}" || return 1',
            'ln -sfn -- "${target}" "${app_config}.next" || return 1',
            'mv -Tf -- "${app_config}.next" "${app_config}" || return 1',
            'fsync_directory "$(dirname -- "${app_config}")" || return 1',
        )
    ):
        raise RuntimeError("Deployment configuration can switch before its mutation journal is armed.")

    create_wrapper = deploy[deploy.index("create_deployment_mutation() {") : deploy.index("remaining_mutation_seconds() {")]
    for required in (
        '--previous-app-sha "${prior_config_sha}" --previous-current-target "${prior_target}" || return 1',
        'deployment_mutation mark-contained --path "${deployment_mutation_journal}" || return 1',
        'deployment_mutation mark-verified --path "${deployment_mutation_journal}" || return 1',
        '--commit "${commit}" --configuration "${configuration_id}" --archive-sha "${expected_archive_sha}" || return 1',
    ):
        if required not in create_wrapper:
            raise RuntimeError("Deployment mutation wrapper can mask a protected helper failure.")

    adoption = deploy.index("readarray -t deployment_resume < <(deployment_state_contract)")
    prior_digest = deploy.index("Deployment mutation prior current-release bytes differ from their sealed digest.", adoption)
    actual_config = deploy.index('actual_mutation_config="-"', adoption)
    launcher_reconcile = deploy.index('reconcile_launcher_failure || fail "Interrupted launcher mutation could not be reconciled safely."', adoption)
    if not prior_digest < actual_config < launcher_reconcile:
        raise RuntimeError("Deployment mutation retry can mutate runtime state before validating prior current-release bytes.")

    cleanup_start = deploy.index('if [[ ${pending_cleanup_present} == true ]]; then')
    cleanup_end = deploy.index('[[ -z "$(find "${evidence_root}" -maxdepth 1 -name \'*-storage-cleanup-required.json\' -print -quit)" ]]', cleanup_start)
    cleanup = deploy[cleanup_start:cleanup_end]
    cleanup_authority = cleanup.index('Pending hosted storage cleanup lacks its exact deployment mutation authority.')
    cleanup_switch = cleanup.index('activate_config "${config_dir}/restore.yml"')
    cleanup_launcher = cleanup.index('run_launcher storage-cleanup-resume rebuild app')
    if not cleanup_authority < cleanup_switch < cleanup_launcher:
        raise RuntimeError("Hosted storage orphan cleanup can mutate configuration before proving deployment authority.")

    bootstrap_start = deploy.index('if [[ ${mode} == bootstrap ]]; then', cleanup_end)
    bootstrap = deploy[bootstrap_start : deploy.index('else\n  if [[ ${deployment_mutation_resume} == false ]]; then', bootstrap_start)]
    if any(value not in bootstrap for value in (
        'Bootstrap mode refuses existing current-release evidence.',
        'Bootstrap mode refuses an existing current-release target.',
    )):
        raise RuntimeError("Bootstrap mutation can overwrite an existing durable release publication.")

    for source, label, token_fragment in (
        (deploy, "deploy", 'launcher_operation_token="$(od -An -N16 -tx1 /dev/urandom'),
        (restore, "restore", 'candidate_operation_token="$(od -An -N16 -tx1 /dev/urandom'),
    ):
        launcher = source[source.index("run_launcher() {") : source.index("container_operation_absent() {")]
        stale = launcher.index('if [[ -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ]]')
        token = launcher.index(token_fragment)
        if stale > token:
            raise RuntimeError(f"{label} launcher creates a new identity before stale CID reconciliation.")

    helper_required = (
        'candidate = path.parent / f".{path.name}.{\'partial\' if create else \'update\'}"',
        'os.link(candidate, path, follow_symlinks=False)',
        "os.fsync(target.fileno())",
        "fsync_directory(path.parent)",
        '"launcherOperationToken"',
        '"launcherPreviousImageId"',
        '"launcherCommand"',
        '"databaseMutationPossible"',
        'if document["databaseMutationPossible"] and not updated["databaseMutationPossible"]:',
        'if document["phase"] != "verified":',
        'bootstrap deployment mutation requires complete prior-publication absence',
        'deployment mutation prior current-release bytes differ',
        'deployment mutation prior current-release target differs',
    )
    if any(value not in helper for value in helper_required):
        raise RuntimeError("Deployment mutation helper lost an atomicity or monotonicity invariant.")
    fixture_required = (
        "linked deployment mutation partial survived reconciliation",
        "unlinked deployment mutation update survived reconciliation",
        "launcher mutation was not durably armed before the migration boundary",
        "unsafe deployment mutation orphan was silently removed",
    )
    if any(value not in fixture for value in fixture_required):
        raise RuntimeError("Deployment mutation hostile fixture coverage differs.")
    fixture_pattern = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-deployment-mutation[.]py >/dev/null'
    )
    if len(fixture_pattern.findall(disposable)) != 1:
        raise RuntimeError("Deployment mutation hostile fixture escaped the pinned root container.")
    if any(value not in deployment_docs for value in (
        "`/var/lib/mochirii/forums/deployment-mutation.json`",
        "atomic no-replace hard link",
        "cross-version or mutation-possible failures never launch",
    )):
        raise RuntimeError("Deployment mutation procedure documentation differs.")
    if "`databaseMutationPossible=true`" not in recovery_docs or "exact mutation-plus-promotion pair" not in validation_docs:
        raise RuntimeError("Deployment mutation recovery or validation documentation differs.")


def test_historical_disaster_recovery_entrypoint_contract() -> None:
    helper = (ROOT / "scripts/historical-release-disaster-recovery.py").read_text(encoding="utf-8")
    controller = (ROOT / "scripts/host-historical-disaster-recovery.sh").read_text(encoding="utf-8")
    scratch = (ROOT / "scripts/historical-recovery-scratch-reader.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-historical-release-disaster-recovery.py").read_text(encoding="utf-8")
    scratch_fixture = (ROOT / "scripts/test-historical-recovery-scratch-reader.py").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    certificate_installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    install_control = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    upgrade_control = (ROOT / "scripts/upgrade-host-control.sh").read_text(encoding="utf-8")
    deploy_workflow = (ROOT / ".github/workflows/deploy-forums.yml").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")

    helper_required = (
        'ARCHIVE_FORMAT = "git-archive-tar-v1"',
        'ADOPTION_SCOPE = "clean-target-disaster-recovery-only"',
        '"phase": "source-prepared"', '"phase": "configuration-authorized"',
        '"bootstrap-started"', '"bootstrap-complete"', '"restore-started"', '"restore-complete"',
        'complete_bootstrap = subcommands.add_parser("complete-bootstrap")',
        'begin_restore = subcommands.add_parser("begin-restore")',
        'complete = subcommands.add_parser("complete")',
        'Restore terminal evidence does not complete the exact historical recovery tuple.',
    )
    if any(value not in helper for value in helper_required):
        raise RuntimeError("Historical adoption helper lost its provenance or monotonic bootstrap/restore state machine.")

    controller_required = (
        'lock_file=/run/lock/mochirii-forums/historical-controller.lock',
        'install -d -m 0755 -o root -g root "${state_root}"',
        'install -d -m 0700 -o root -g root "${stage_root}"',
        'CI deliberately mounts /tmp noexec.',
        'trusted_entrypoint "${main_probe}"',
        'python3 -B "${main_probe}" refs/heads/main',
        'bash "${scratch_reader}" "${bootstrap_commit}"',
        'python3 -B "${deployer}"',
        'python3 -B "${restorer}"',
        'prove_canonical_main "${bootstrap_commit}"',
        'MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_ROOT',
        'terminalReaderTransactionPhase', 'terminalReaderTransactionSha256',
        'readerOperationImageIds', 'readerOperationImageLabel', 'readerOperationImagesAbsent',
        'terminal historical scratch-reader retirement authority differs',
        'pending historical reader retirement authority differs',
        'Historical reader retirement refuses an active scratch transaction.',
        '--require-phase configuration-authorized',
        'begin-bootstrap', 'historical-bootstrap',
        'Historical reader intent was not retired before recovery continuation.',
        'Historical Mochirii Forums disaster recovery completed and retired its active journal.',
    )
    if any(value not in controller for value in controller_required):
        raise RuntimeError("Operator-only historical controller lost a current-main, scratch, retry, or retirement boundary.")
    if controller.index('prove_canonical_main "${bootstrap_commit}"') > controller.index('"${scratch_reader}" "${bootstrap_commit}"'):
        raise RuntimeError("C1 scratch execution can precede the exact canonical-main proof.")
    if controller.index('--confirmation "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"') > controller.index('journal.unlink()', controller.index('--confirmation "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"')):
        raise RuntimeError("Reader intent can retire before durable C0 configuration authorization.")
    retirement = controller.index('pending historical reader retirement authority differs')
    producer_gate = controller.index('Historical recovery requires the Website Forums producer to remain disabled.', retirement)
    if retirement > producer_gate:
        raise RuntimeError("A stale exact reader journal can survive into C0 mutation authority.")

    scratch_required = (
        'PHASES = {"armed", "receipt-fetched", "archive-fetched", "cleanup-proved", "receipt-published", "outputs-published"}',
        'path.read_bytes().split(b"\\0")',
        'member.mode not in {0o644, 0o664, 0o755, 0o775}',
        'scratch container retained a forbidden mount',
        'MOCHIRII_DR_FETCH_MODE=clean-target-historical',
        'MOCHIRII_DR_BOOTSTRAP_COMMIT=',
        '"preexistingImageIds"', '"operationImageIds"', '"operationImageLabel"',
        'docker image rm --force "${image_id}"',
        'crash_point after-reader-image-untag',
        'docker_image_id_state "${image_id}"',
        'crash_point after-reader-image-delete',
        'terminal transaction awaits controller readback',
    )
    if any(value not in scratch for value in scratch_required):
        raise RuntimeError("C1 scratch reader lost its durable transaction, actual-NUL scan, Git-tar, mount, or fetch boundary.")
    scratch_fixture = (ROOT / "scripts/test-historical-recovery-scratch-reader.py").read_text(encoding="utf-8")
    for value in (
        '"after-reader-image-delete"',
        "post-ID-delete retry repeated or omitted immutable image deletion",
        "fixture adapter unrealistically accepted removal of an absent image ID",
        'damaged_operation_image_identity_fixture("missing")',
        'damaged_operation_image_identity_fixture("altered")',
    ):
        if value not in scratch_fixture:
            raise RuntimeError("Scratch hostile fixture lost post-delete retry or damaged image-ID refusal coverage.")

    deploy_required = (
        'The deploy principal may not invoke historical bootstrap.',
        'Ordinary deployment refuses an active historical disaster-recovery adoption.',
        '--require-phase bootstrap-complete',
        'A bootstrap-complete historical journal may only reconcile its same terminal deployment transaction; runtime mutation is forbidden.',
    )
    if any(value not in deploy for value in deploy_required):
        raise RuntimeError("Ordinary/current-main deploy or journal-scoped C0 bootstrap authority differs.")
    restore_required = (
        'An active historical adoption refuses disposable restore.',
        'Historical terminal reconciliation refuses an active backup transaction.',
        'Historical terminal reconciliation refuses an active deployment transaction.',
        'Historical terminal reconciliation refuses an active deployment mutation.',
        'Historical terminal reconciliation refuses an active restore transaction.',
        'regenerated historical release evidence is not semantically equal to the private C0 receipt',
        'begin-restore', '--require-phase restore-started',
        'Terminal historical adoption journal was not retired.',
    )
    if any(value not in restore for value in restore_required):
        raise RuntimeError("Historical C0 restore lost collision gates, provenance equality, phase ownership, or terminal retirement.")
    collision = restore.index('Historical terminal reconciliation refuses an active backup transaction.')
    terminal_complete = restore.index('"${historical_helper}" complete', collision)
    if collision > terminal_complete:
        raise RuntimeError("Historical terminal completion can bypass transaction collision gates.")
    if restore.index('"${historical_helper}" begin-restore') > restore.index('discourse restore --location s3'):
        raise RuntimeError("Historical restore mutation can precede its durable adoption phase.")

    fixture_required = (
        'SCRATCH.git_archive(c0_archive,c0_files,"C0 historical backup")',
        'configuration-authorized-before-reader-retirement',
        'crash_result=controller(crashed,"prepare",C1,OPERATION,PREPARE_CONFIRMATION,passed=False)',
        'MOCHIRII_FIXTURE_DEPLOY_CRASH_ONCE', 'MOCHIRII_FIXTURE_DEPLOY_COMPLETE_CRASH_ONCE',
        'MOCHIRII_FIXTURE_RESTORE_COMPLETE_CRASH_ONCE',
        'C0 mutation was not prearmed.', 'Bootstrap-complete retry was not reconciliation-only.',
        'Restore-complete retry was not terminal-only.',
        'Historical C0 backup / C1 main / lost-host production-entrypoint fixture passed.',
    )
    if any(value not in fixture for value in fixture_required):
        raise RuntimeError("C0/C1/lost-host production-entrypoint crash fixture coverage differs.")
    scratch_fixture_required = (
        '"git", "-c", "core.autocrlf=false", "-c", "core.filemode=true"',
        '"-c", "tar.umask=0002"',
        'actual NUL-delimited marked process survived reconciliation',
        'MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_CRASH_AFTER',
        'scratch container retained a forbidden mount',
    )
    if any(value not in scratch_fixture for value in scratch_fixture_required):
        raise RuntimeError("Real-Git scratch-reader timeout/crash/tamper/survivor fixture coverage differs.")
    for fixture_source in (fixture, scratch_fixture):
        if (
            "/tmp:rw,noexec,nosuid,nodev,size=16m" not in fixture_source
            or re.search(r'"--pids-limit"\s*,\s*"64"', fixture_source) is None
            or re.search(r'"--memory"\s*,\s*"256m"', fixture_source) is None
            or re.search(r'"--memory-swap"\s*,\s*"256m"', fixture_source) is None
        ):
            raise RuntimeError("Historical fixture convenience wrapper differs from the pinned CI noexec isolation tuple.")

    for source, minimum in (
        (install_control, 2), (upgrade_control, 2), (deploy, 1), (verifier, 1),
        (deploy_workflow, 1), (disposable, 1),
    ):
        if source.count("tar.umask=0002") < minimum:
            raise RuntimeError("A retained or consumed Git archive lost deterministic tar-mode construction.")
    bounded_verifier = (
        'MAX_JSON_BYTES = 65_536', 'MAX_ARCHIVE_BYTES = 67_108_864',
        'bounded_read(pointer_path, MAX_JSON_BYTES', 'bounded_read(record_path, MAX_JSON_BYTES',
        'isinstance(expected_bytes, bool)', 'metadata.st_size != expected_bytes',
        'bounded_read(path, MAX_ARCHIVE_BYTES',
    )
    if any(value not in verifier for value in bounded_verifier):
        raise RuntimeError("Host-security retained archive verification regained an unbounded read.")
    certificate_archive_contract = (
        'pointer_keys = {', 'record_keys = {', 'archive_bindings = {',
        'not 1 <= pointer["releaseArchiveBytes"] <= 64 * 1024 * 1024',
        'not 1 <= pointer["deploymentSourceArchiveBytes"] <= 64 * 1024 * 1024',
        'any(record.get(key) != pointer.get(key) for key in archive_bindings)',
    )
    if any(value not in certificate_installer for value in certificate_archive_contract):
        raise RuntimeError("Certificate automation consumes a stale or unbounded host-control archive schema.")


def test_host_operation_lock_contract() -> None:
    helper = (ROOT / "scripts/host-operation-lock.py").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-host-operation-lock.py").read_text(encoding="utf-8")
    service = (ROOT / "config/mochirii-forums-media-certificate-renew.service").read_text(encoding="utf-8")
    sudoers = (ROOT / "config/sudoers-forums").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")

    helper_contract = (
        'LOCK_DIRECTORY = "mochirii-forums"',
        'LOCK_ORDER = ("primary", "media")',
        '"primary": "primary.lock"',
        '"media": "media-certificate.lock"',
        '"primary": 200',
        '"media": 201',
        'CONTEXT_ENV = "MOCHIRII_FORUMS_HOST_LOCK_FDS"',
        'os.O_DIRECTORY',
        'os.O_NOFOLLOW',
        'os.O_CLOEXEC',
        'os.mkdir(LOCK_DIRECTORY, 0o700, dir_fd=lock_fd)',
        'os.open(LOCK_FILES[lock_id], _LOCK_FLAGS, dir_fd=private_fd)',
        '_LOCK_FLAGS | os.O_CREAT | os.O_EXCL',
        'metadata.st_nlink != 1',
        '_directory_mode(metadata) != 0o700',
        'stat.S_IMODE(metadata.st_mode) != 0o600',
        'ubuntu_sticky = mode == 0o1777',
        'fcntl.F_DUPFD_CLOEXEC',
        'fcntl.LOCK_EX | fcntl.LOCK_NB',
        'os.set_inheritable(LOCK_FDS[lock_id], True)',
        'if not command or not os.path.isabs(command[0]):',
        'os.execve(command[0], list(command), child_environment)',
        'def verify_namespace(',
        'if isinstance(cause, OSError) and cause.errno == errno.ENOENT:',
        'if action in {"assert-held", "verify-namespace", "verify-nodes"}:',
    )
    if any(value not in helper for value in helper_contract):
        raise RuntimeError("Host-operation lock helper lost its private no-follow inode, ordering, or inherited-FD boundary.")
    if 'LOCK_ORDER = ("media", "primary")' in helper or 'CANONICAL_ROOT = pathlib.Path("/run/lock")' in helper:
        raise RuntimeError("Host-operation lock helper can reverse order or anchor beneath the attacker-writable lock directory.")

    fixture_contract = (
        'Linked /run parent received a lock artifact.',
        'Linked system lock parent received a lock artifact.',
        'Linked private lock directory received a lock artifact.',
        'Linked lock victim bytes changed.',
        '"directory": lambda path: path.mkdir(mode=0o600)',
        '"fifo": lambda path: os.mkfifo(path, 0o600)',
        '"socket": _create_socket_entry',
        'hardlinked lock file',
        'unsafe private-directory owner',
        'unsafe lock-file owner',
        'absent /run/lock',
        'Clean boot private lock directory metadata differs.',
        'verify-nodes created a missing lock file.',
        'Ubuntu /var/lock alias produced a second lock namespace.',
        'Helper traversed the noncanonical /var/lock alias.',
        'reverse primary/media acquisition',
        'Contending primary acquisition was not blocked:',
        'Contending media acquisition was not blocked:',
        'Primary FD collision clobbered its caller-owned descriptor.',
        'Media FD collision clobbered its caller-owned descriptor.',
        'Parent SIGKILL released a descendant-owned lock.',
        'Retry remained blocked after the last inherited FD closed.',
        'Primary-only clean reboot unexpectedly created the media lock.',
        'Namespace verification created the absent media lock.',
        'Namespace verification changed linked media victim bytes.',
        'nonregular existing media',
        'unsafe existing media mode',
        'unsafe existing media owner',
    )
    if any(value not in fixture for value in fixture_contract):
        raise RuntimeError("Host-operation lock executable hostile inventory differs.")
    if VALIDATOR.BASE_DIGEST not in fixture or '"--network",\n        "none"' not in fixture or '"--read-only"' not in fixture:
        raise RuntimeError("Host-operation lock hostile wrapper differs from the pinned isolated Linux boundary.")

    consumers = {
        "primary": (
            "scripts/finalize-member-rollout.sh",
            "scripts/host-backup.sh",
            "scripts/host-break-glass-admin.sh",
            "scripts/host-deploy.sh",
            "scripts/host-finalize-authentication.sh",
            "scripts/host-restore-validate.sh",
            "scripts/host-stop-pending-activation.sh",
            "scripts/host-verify-wrapper.sh",
        ),
        "media": (
            "scripts/prepare-media-certificate.sh",
            "scripts/run-media-certificate-renewal.sh",
        ),
        "primary,media": (
            "scripts/install-host-control.sh",
            "scripts/install-media-certificate-renewal.sh",
            "scripts/upgrade-host-control.sh",
        ),
    }
    all_consumers = []
    for lock_set, paths in consumers.items():
        for relative in paths:
            source = (ROOT / relative).read_text(encoding="utf-8")
            all_consumers.append((relative, source))
            if (
                f'assert-held --locks {lock_set}' not in source
                or f'run --locks {lock_set}' not in source
                or '[[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."' not in source
            ):
                raise RuntimeError(f"{relative} lost its exact inherited {lock_set} lock wrapper.")
            if "--locks media,primary" in source:
                raise RuntimeError(f"{relative} can acquire the media lock before the primary lock.")

    retired_lock_paths = (
        "/run/lock/mochirii-forums.lock",
        "/run/lock/mochirii-forums-media-certificate.lock",
        "/var/lock/mochirii-forums.lock",
        "/var/lock/mochirii-forums-media-certificate.lock",
        "/run/lock/mochirii-forums/primary.lock",
        "/run/lock/mochirii-forums/media-certificate.lock",
        "/var/lock/mochirii-forums/primary.lock",
        "/var/lock/mochirii-forums/media-certificate.lock",
    )
    descriptor_open = re.compile(r"\bexec\s+\d+\s*(?:<>|>>|>|<)")
    numeric_flock = re.compile(r"\bflock\s+(?:-[^\s]+\s+)*\d+\b")

    def unsafe_open(source: str) -> bool:
        without_reviewed_closes = source.replace("exec 200>&- 201>&-", "")
        return bool(
            any(path in source for path in retired_lock_paths)
            or descriptor_open.search(without_reviewed_closes)
            or numeric_flock.search(source)
        )

    for relative, source in all_consumers:
        if unsafe_open(source):
            raise RuntimeError(f"{relative} regained a direct or variable-computed lock descriptor open.")
    for hostile in (
        'exec 9>/run/lock/mochirii-forums.lock\n',
        'lock_file=/run/lock/mochirii-forums/primary.lock\nexec 9>"${lock_file}"\n',
        'media_lock=/var/lock/mochirii-forums/media-certificate.lock\nexec 8>"${media_lock}"\n',
        'flock -n 9\n',
    ):
        if not unsafe_open(hostile):
            raise RuntimeError("Host-operation recurrence gate missed a literal or variable-computed direct lock open.")

    close_before_exec = {
        "scripts/host-backup.sh": 1,
        "scripts/host-break-glass-admin.sh": 1,
        "scripts/host-deploy.sh": 4,
        "scripts/host-restore-validate.sh": 2,
        "scripts/install-host-control.sh": 2,
        "scripts/media-certificate-operation.sh": 2,
    }
    for relative, minimum in close_before_exec.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        if source.count("exec 200>&- 201>&-") < minimum:
            raise RuntimeError(f"{relative} can leak protected host-lock descriptors into a detached operation.")

    if (
        "ReadWritePaths=/etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/lib/mochirii/forums -/run/lock/mochirii-forums" not in service
        or re.search(r"(?:^|\s)/run/lock(?:\s|$)", service, re.MULTILINE)
    ):
        raise RuntimeError("Media-certificate systemd write authority is not narrowed to the private lock namespace.")
    if "host-operation-lock.py" in sudoers or "host-operation-lock.py" in dispatcher:
        raise RuntimeError("Deploy-key authority gained a direct host-operation lock helper route.")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    if (
        'verify-namespace --locks primary,media' not in verifier
        or 'sudo -l -U mochirii-forums-deploy /usr/local/libexec/mochirii-forums/host-operation-lock.py' not in verifier
    ):
        raise RuntimeError("Host-security verification lost private lock-node or deploy-authority proof.")

    docs = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "docs/operations/DEPLOYMENT.md",
            "docs/operations/PROVIDER-DNS-TLS.md",
            "docs/operations/RECOVERY.md",
            "docs/operations/SECRETS.md",
            "docs/operations/VALIDATION.md",
        )
    )
    for required in (
        "/run/lock/mochirii-forums",
        "mode-`0700`",
        "mode-`0600`",
        "primary-before-media",
        "O_NOFOLLOW",
        "`/var/lock`",
        "deploy key",
    ):
        if required not in docs:
            raise RuntimeError("Host-operation lock documentation is incomplete.")


def test_host_security_control_plane_contract() -> None:
    manifest = json.loads((ROOT / "config/host-control-manifest.v1.json").read_text(encoding="utf-8"))
    if set(manifest) != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"} or manifest.get("schemaVersion") != 1:
        raise RuntimeError("Host-control manifest schema differs.")
    expected = {
        "coreTargets": {
            "/usr/local/libexec/mochirii-forums/durable-event.py",
            "/usr/local/libexec/mochirii-forums/host-control-evidence.py",
            "/usr/local/libexec/mochirii-forums/host-operation-lock.py",
            "/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh",
            "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
            "/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py",
            "/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
            "/usr/local/libexec/mochirii-forums/verify-host-security.sh",
            "/usr/local/sbin/mochirii-forums-backup",
            "/usr/local/sbin/mochirii-forums-break-glass-admin",
            "/usr/local/sbin/mochirii-forums-deploy",
            "/usr/local/sbin/mochirii-forums-finalize-authentication",
            "/usr/local/sbin/mochirii-forums-finalize-member-rollout",
            "/usr/local/sbin/mochirii-forums-historical-disaster-recovery",
            "/usr/local/sbin/mochirii-forums-restore",
            "/usr/local/sbin/mochirii-forums-stop-pending-activation",
            "/usr/local/sbin/mochirii-forums-upgrade-host-control",
            "/usr/local/sbin/mochirii-forums-verify",
        },
        "hostPolicyTargets": {
            "/etc/apt/apt.conf.d/20auto-upgrades", "/etc/docker/daemon.json",
            "/etc/fail2ban/jail.d/mochirii-forums.conf",
            "/etc/ssh/sshd_config.d/00-00-mochirii-forums.conf",
            "/etc/sudoers.d/mochirii-forums", "/etc/sudoers.d/mochirii-forums-operator",
        },
        "certificateTargets": {
            "/etc/systemd/system/mochirii-forums-media-certificate-renew.service",
            "/etc/systemd/system/mochirii-forums-media-certificate-renew.timer",
            "/usr/local/libexec/mochirii-forums/media-certificate-operation.sh",
            "/usr/local/libexec/mochirii-forums/reconcile-acme-dns.py",
            "/usr/local/libexec/mochirii-forums/rotate-media-certificate.py",
            "/usr/local/sbin/mochirii-forums-renew-media-certificate",
            "/usr/local/sbin/mochirii-forums-rotate-media-certificate",
        },
    }
    for group, exact_targets in expected.items():
        rows = manifest.get(group)
        if not isinstance(rows, list) or {row.get("target") for row in rows} != exact_targets:
            raise RuntimeError(f"Host-control {group} exact target inventory differs.")
        for row in rows:
            if set(row) != {"source", "target", "mode"} or row["mode"] not in {"0440", "0644", "0755"}:
                raise RuntimeError(f"Host-control {group} row differs.")
            source = ROOT / row["source"]
            if not source.is_file() or source.is_symlink():
                raise RuntimeError(f"Host-control source is absent or linked: {row['source']}")

    installer = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    hardened = (ROOT / "config/sshd-forums.conf").read_text(encoding="utf-8")
    prepared = (ROOT / "config/sshd-forums-prepared.conf").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    upgrade = (ROOT / "scripts/upgrade-host-control.sh").read_text(encoding="utf-8")
    host_verify = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")
    finalizer = (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")

    if "PermitRootLogin no" in prepared or "AllowUsers " in prepared:
        raise RuntimeError("Prepared SSH policy can lock out bootstrap before operator proof.")
    required_hardening = (
        "AuthorizedKeysCommand none", "TrustedUserCAKeys none", "AuthorizedPrincipalsFile none",
        "AuthorizedKeysCommandUser nobody", "AuthorizedPrincipalsCommand none",
        "AuthorizedPrincipalsCommandUser nobody", "PermitUserEnvironment no",
        "AuthorizedKeysFile /var/lib/mochirii/forums/operator/.ssh/authorized_keys",
        "AuthorizedKeysFile /var/lib/mochirii/forums/deploy/.ssh/authorized_keys",
        "ForceCommand /usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
        "DisableForwarding yes", "PermitUserRC no", "PermitRootLogin no",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no",
    )
    if any(value not in hardened for value in required_hardening):
        raise RuntimeError("Hardened SSH sole-source or confinement policy differs.")
    if "authorized_keys2" in installer + prepared + hardened or 'write_text("restrict " + source + "\\n"' not in installer:
        raise RuntimeError("Authorized-key publication regained a second file or key-owned forced command.")
    if "mochirii-forums-upgrade-host-control" in dispatcher:
        raise RuntimeError("Deploy SSH principal gained host-control upgrade authority.")
    if 'sudo -l -U "${deploy_user}" "${forbidden}"' not in installer or "/usr/local/sbin/mochirii-forums-upgrade-host-control" not in installer:
        raise RuntimeError("Installer does not prove the deploy principal lacks control-upgrade authority.")
    if not all(value in installer for value in (
        'Prepared installation cannot replace an already hardened host',
        'host-access-install.pending.json', 'os.fsync(writer.fileno())',
        'install -d -m 0755 -o root -g root /var/lib/mochirii "${state_root}"',
        'install -d -m 0700 -o root -g root "${state_root}/deploy/.ssh"',
        'timeout --signal=TERM --kill-after=5s 15s sshd -T',
        'authorizedkeyscommanduser', 'authorizedprincipalscommanduser',
        'permituserenvironment',
    )):
        raise RuntimeError("Initial host-control publication or hardened-retry boundary differs.")
    journal_position = upgrade.index('os.link(candidate, journal_path, follow_symlinks=False)')
    timer_stop_position = upgrade.index('systemctl stop mochirii-forums-media-certificate-renew.timer', journal_position)
    first_publication = upgrade.index('atomic_install "${candidate}/${relative}"', timer_stop_position)
    if not journal_position < timer_stop_position < first_publication:
        raise RuntimeError("Control upgrade mutates a timer or target before its durable journal is armed.")
    for required in (
        'fetch --no-tags --depth=1 --refmap= origin refs/heads/main',
        'Host-control upgrade requires the application to be proved stopped.',
        'assert-held --locks primary,media', 'run --locks primary,media', 'rollback_transaction', 'targets_are_new',
        'durable_remove_workdir', 'reconcile_unjournaled_workdirs',
        'validate_effective_hardened_ssh',
        'seal_control_state upgrade', 'verify-host-security.sh',
        '--upgrade-transaction',
        '${SUDO_USER:-} == mochirii-forums-operator',
    ):
        if required not in upgrade:
            raise RuntimeError("Transactional canonical control-upgrade boundary differs.")
    if upgrade.index('fetch --no-tags --depth=1 --refmap= origin refs/heads/main') > upgrade.index('validate-repository.py'):
        raise RuntimeError("Candidate-controlled source can run before canonical-main control binding.")
    clear_start = upgrade.index("clear_transaction() {")
    journal_clear = upgrade.index('durable_remove "${pending_journal}"', clear_start)
    tree_clear = upgrade.index('durable_remove_workdir "${transaction}"', journal_clear)
    orphan_reconcile = upgrade.index('reconcile_unjournaled_workdirs || fail')
    current_control_gate = upgrade.index('Current host-control evidence is absent or unsafe.')
    if not journal_clear < tree_clear or not orphan_reconcile < current_control_gate:
        raise RuntimeError("Host-control completion orphan recovery or durable clearance ordering differs.")

    hostile_host_canaries = (
        "SSH tree contains an alternate key or user-rc source.", "authorizedkeyscommand",
        "authorizedkeyscommanduser", "trustedusercakeys", "authorizedprincipalsfile",
        "authorizedprincipalscommanduser", "permituserenvironment", "Deploy account tuple",
        "service_state fail2ban", "service_state unattended-upgrades", "ufw status verbose",
        "unexpected UFW rule", "unexpected public listener", "Docker service is not enabled and active.",
        "host-control evidenced target bytes differ", "certificate automation target set is partial",
        "host-control evidence target inventory differs",
        "service_state mochirii-forums-media-certificate-renew.timer",
        "An unjournaled host-control upgrade work directory remains.",
        "--upgrade-transaction",
        "timeout --signal=TERM --kill-after=5s",
    )
    if any(value not in verifier for value in hostile_host_canaries):
        raise RuntimeError("Hosted host-security hostile boundary inventory differs.")
    checkout_gate = host_verify.index('verify-discourse-docker-checkout.sh')
    runtime_read = host_verify.index("docker inspect --format '{{.State.Running}}' app")
    if checkout_gate > runtime_read or "diff --no-ext-diff --quiet HEAD --" not in host_verify or host_verify.count("status --porcelain=v1 --untracked-files=all") != 2:
        raise RuntimeError("Hosted verification does not prove sealed deployment and running source bytes first.")
    if host_verify.count('timeout --signal=TERM --kill-after=10s 180s bash "${release_dir}/scripts/verify-runtime-assets.sh"') != 2:
        raise RuntimeError("Hosted runtime-asset verification is not bounded before and after daemon readback.")
    for line in host_verify.splitlines():
        if re.search(r"\bdocker\s+(?:inspect|image inspect|exec)\b", line) and "timeout --signal=TERM --kill-after=" not in line:
            raise RuntimeError("Hosted verification contains an unbounded Docker daemon readback.")
    checkout = (ROOT / "scripts/verify-discourse-docker-checkout.sh").read_text(encoding="utf-8")
    for line in checkout.splitlines():
        if re.search(r"\bdocker\s+(?:image inspect|rm|container ls|run)\b", line) and "timeout --signal=TERM --kill-after=" not in line:
            raise RuntimeError("Sealed deployment checkout contains an unbounded Docker daemon call.")

    required_mode_split = (
        'for directory in "${evidence_root}" "${operator_evidence_root}"; do',
        '[[ "$(stat -c \'%U:%G %a\' "${directory}")" == "root:root 700" ]]',
        '[[ -d ${state_root} && ! -L ${state_root} && "$(stat -c \'%U:%G %a\' "${state_root}")" == "root:root 755" ]]',
    )
    if any(value not in finalizer for value in required_mode_split):
        raise RuntimeError("Authentication finalizer state-root traversal and sensitive-directory modes conflict.")


def test_runtime_rails_execution_contract() -> None:
    expected_wrappers = {
        ".github/workflows/disposable-bootstrap.yml": 14,
        "scripts/host-restore-validate.sh": 19,
        "scripts/host-backup.sh": 5,
        "scripts/verify-discourse-connect.py": 4,
        "scripts/host-deploy.sh": 3,
        "scripts/historical-recovery-scratch-reader.sh": 2,
        "scripts/verify-contained-activation.sh": 2,
        "scripts/verify-host.sh": 2,
        "scripts/host-break-glass-admin.sh": 1,
    }
    sources = {
        relative: (ROOT / relative).read_text(encoding="utf-8")
        for relative in expected_wrappers
    }
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    owner_scoped_build_runner = """su discourse -c 'bundle exec rails runner
          \"$MOCHIRII_RELEASE_ASSET_ROOT/configure-site.rb\"'"""
    owner_probe = """sudo docker exec app /usr/local/bin/rails runner 'require \"etc\"; raise unless Process.euid == Etc.getpwnam(\"discourse\").uid; raise unless GitUtils.git_version == \"cbf996f65aae3da1843224aa624bcd9a225931ac\"; ActiveRecord::Base.connection.execute(\"SELECT 1\")'"""

    def assert_contract(candidate_sources: dict[str, str], candidate_template: str) -> None:
        for relative, expected in expected_wrappers.items():
            source = candidate_sources[relative]
            if (
                "bundle exec rails runner" in source
                or source.count("/usr/local/bin/rails runner") != expected
                or source.count("rails runner") != expected
            ):
                raise RuntimeError(f"Runtime Rails owner-wrapper inventory differs: {relative}")
        if sum(expected_wrappers.values()) != 52:
            raise RuntimeError("Runtime Rails owner-wrapper total differs.")
        if (
            candidate_template.count("bundle exec rails runner") != 1
            or candidate_template.count("rails runner") != 1
            or candidate_template.count(owner_scoped_build_runner) != 1
        ):
            raise RuntimeError("Build-time Rails runner owner scope differs.")
        if candidate_sources[".github/workflows/disposable-bootstrap.yml"].count(owner_probe) != 1:
            raise RuntimeError("Disposable Rails UID/Git/database proof differs.")

    assert_contract(sources, template)

    workflow = sources[".github/workflows/disposable-bootstrap.yml"]
    raw_runtime = dict(sources)
    raw_runtime[".github/workflows/disposable-bootstrap.yml"] = workflow.replace(
        "/usr/local/bin/rails runner", "bundle exec rails runner", 1
    )
    missing_wrapper = dict(sources)
    missing_wrapper[".github/workflows/disposable-bootstrap.yml"] = workflow.replace(
        owner_probe + "\n", "", 1
    )
    extra_wrapper = dict(sources)
    extra_wrapper[".github/workflows/disposable-bootstrap.yml"] = workflow + "\n/usr/local/bin/rails runner\n"
    hostile_cases = (
        (raw_runtime, template),
        (missing_wrapper, template),
        (extra_wrapper, template),
        (sources, template.replace("su discourse -c 'bundle exec rails runner", "bundle exec rails runner", 1)),
    )
    for candidate_sources, candidate_template in hostile_cases:
        try:
            assert_contract(candidate_sources, candidate_template)
        except RuntimeError:
            continue
        raise RuntimeError("Runtime Rails owner-wrapper hostile mutation was accepted.")


def main() -> int:
    test_renderer()
    test_theme_archive()
    test_narrative_avatar_contract()
    test_branding_email_renderer_contract()
    test_certificate_create_cleanup()
    test_certificate_identity_read_allowlist()
    test_http_redirect_boundaries()
    test_certificate_inventory_capacity()
    test_certificate_preparation_recovery_contract()
    test_certificate_control_evidence_adoption_contract()
    test_certificate_commit_forward_retirement()
    test_certificate_commit_forward_ignores_stale_absence()
    test_certificate_rejected_retirement_remains_blocked()
    test_storage_response_boundary()
    test_ssh_dispatch_contract()
    test_current_main_observation()
    test_repository_governance()
    test_extracted_archive_governance()
    test_authentication_state_machine()
    test_deployment_checkout_configuration_boundary()
    test_sensitive_callback_markers()
    test_website_producer_probe_contract()
    test_restore_stop_boundary()
    test_host_containment_contract()
    test_process_group_timeout()
    test_sidekiq_processing_contract()
    test_backup_restore_normal_upload_contract()
    test_public_branding_signed_credential_boundary()
    test_atomic_operator_evidence_publication_contract()
    test_deployment_terminal_transaction_contract()
    test_deployment_runtime_mutation_contract()
    test_historical_disaster_recovery_entrypoint_contract()
    test_host_operation_lock_contract()
    test_host_security_control_plane_contract()
    test_runtime_rails_execution_contract()
    print("Configuration and theme hostile fixtures passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
