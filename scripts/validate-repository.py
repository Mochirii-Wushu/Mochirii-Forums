#!/usr/bin/env python3
"""Fail-closed source, storage, branding, and secret contract validation."""

from __future__ import annotations

import argparse
import ast
import base64
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import symtable
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_MODE = False
DOCKER_REVISION = "ed9f680b0df1de28f062de1769d89d22b2644d1b"
CORE_REVISION = "cbf996f65aae3da1843224aa624bcd9a225931ac"
DOCKER_MANAGER_REVISION = "c008c3ca7fcc44775215843992e88190adb7b3bf"
BASE_DIGEST = "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
ACME_REVISION = "b7caf7a0165d80dd1556b16057a06bb32025066d"
ACME_SOURCE_SHA256 = "400d1a96ef72a1f27fe79c7f0e6d4e4f600c0509c0cd787db00931b9258c54da"
ACME_COMPRESSED_SHA256 = "a42ebbbddb439b989272e97d9e8f1d354311d48f3b56543583a3b345fac0492c"
CONFIGURE_LETSENCRYPT_SHA256 = "069d53abb70100354d0b44bd0d3b132c9d764a952f8abc91f5e7b6d12775cfde"
IMMUTABLE_LETSENCRYPT_FRAGMENT_SHA256 = "1806f1aa5c9e3cc3741a422a8ea82d4dcba7137c60707ef1c186974b0685524e"
OBSERVED_MAIN_REVISION = "00595119c368c0aef7d7019ec66ffc8fa51cce79"
OBSERVED_MAIN_TREE = "d5b846bf4e59784c5220c48839d7eb1b45671aae"
OBSERVED_RANGE = [
    "e071c2c8ebf8a93c1fba4e16fbb7168a2a9201bd",
    "9a064388b76beb41527b7c7b650566a5f94075aa",
    "a4d4cb41aeb6266f8cfc84b88477435629317787",
    "dfdddb8505c71b4b3b5e6a741f4e90e4a9c9e0a7",
    "e6d7b508b43f9610950166f53cb1be1bd78435a9",
    "7a5523773202c7e9b77a61d0d15ac6f514f67c45",
    "a68d4b8707fd653697e8b6b27b336d093dbed5e4",
    "9c35fe8f6f4eb66d399f756e3bae773292e34db2",
    "3cdefc992290e6d1376a11c72bada098f7b3cf6a",
    "ccb3ea007204c683f7177258f1f509e2fb36f82b",
    OBSERVED_MAIN_REVISION,
]
OBSERVED_MATERIAL_CLASSIFICATIONS = [
    "import-template-dependency-installation",
    "postgresql-18-upgrade-template",
    "debian-trixie-base-transition",
    "redis-packaging-transition",
    "redis-runtime-directory",
    "mutable-base-image-default",
    "browser-signing-key-refresh",
    "mutable-base-image-default",
    "dev-image-postgresql-15",
    "web-template-ownership-optimization",
    "base-image-fontconfig-cache-refresh",
]
OBSERVED_CHANGED_PATHS = [
    "image/base/Dockerfile",
    "image/base/install-imagemagick",
    "image/base/install-nginx",
    "image/base/install-redis",
    "image/base/nginx_public_keys.key",
    "image/discourse_dev/Dockerfile",
    "image/discourse_test/Dockerfile",
    "image/discourse_test/install-chrome",
    "image/discourse_test/mozilla-release-key.asc",
    "launcher",
    "templates/import/chrome-dep.template.yml",
    "templates/import/mbox.template.yml",
    "templates/import/mssql-dep.template.yml",
    "templates/import/mysql-dep.template.yml",
    "templates/import/phpbb3.template.yml",
    "templates/import/vanilla.template.yml",
    "templates/postgres.18.template.yml",
    "templates/postgres.template.yml",
    "templates/redis.template.yml",
    "templates/web.template.yml",
]
STAGE4_PR_TEMPLATE_REQUIRED = (
    "## Stage 4 source boundary",
    "does not authorize or claim a live deployment, provider mutation",
    f"Discourse Docker: `{DOCKER_REVISION}`",
    f"Discourse application: `{CORE_REVISION}`",
    f"Docker Manager: `{DOCKER_MANAGER_REVISION}`",
    f"Linux AMD64 base image: `{BASE_DIGEST}`",
    "The complete repository file inventory remains allowlisted",
    "## Source gates for this exact head",
    "./scripts/check-repository.ps1 -Online` when upstream evidence is in scope",
    "## Disposable standalone evidence",
    "one effective CPU, fixture-only loopback configuration",
    "## Exact-head review and merge gate",
    "accountable human reviewed this exact candidate head",
    "## Live and provider evidence remains unverified",
    "Record every item as `PASS`, `FAIL`, or `NOT RUN`",
    "Unverified or failed live gates keep activation closed",
)
THEME_ASSETS = {
    "theme/mochirii/assets/mochirii-emblem.webp": (
        286382,
        "ed9fe4c522bc2b0d1c2072c1c098f241ee52f0ceec0307cb531ce440e730bb60",
    ),
    "theme/mochirii/assets/mochirii-icon.png": (
        58034,
        "742422603499f5033e6b0aadbd25383e3db8814734ae7e5fa5c997050ba71409",
    ),
    "theme/mochirii/assets/mochirii-social-card.png": (
        390912,
        "039a3356756542ed351d87a6756d5f7c769bdaec6a1a0fca58f486149455878b",
    ),
}
THEME_RUNTIME_VERIFIER_BLOCK = '''checks["theme_logo_uploads"] =
  %w[mochirii_emblem mochirii_icon mochirii_social_card].all? { |name| theme_uploads[name]&.upload }
if checks["theme_logo_uploads"]
  emblem_id = theme_uploads.fetch("mochirii_emblem").upload.id
  icon_id = theme_uploads.fetch("mochirii_icon").upload.id
  icon_upload = theme_uploads.fetch("mochirii_icon").upload
  social_card_id = theme_uploads.fetch("mochirii_social_card").upload.id
  checks["theme_logo_settings"] =
    [
      SiteSetting.logo,
      SiteSetting.logo_dark,
      SiteSetting.mobile_logo,
      SiteSetting.mobile_logo_dark,
    ].all? { |value| value&.id == emblem_id } &&
      [
        SiteSetting.logo_small,
        SiteSetting.logo_small_dark,
        SiteSetting.favicon,
        SiteSetting.apple_touch_icon,
      ].all? { |value| value&.id == icon_id } &&
      [
        SiteSetting.digest_logo,
        SiteSetting.large_icon,
        SiteSetting.manifest_icon,
        SiteSetting.opengraph_image,
      ].all? { |value| value&.id == social_card_id }
else
  checks["theme_logo_settings"] = false
end
compiled_theme = theme&.javascript_cache&.content.to_s
checks["upload_notice_connector_compiled"] =
  compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":') &&
    compiled_theme.include?("Direct upload URLs may be accessed without a forum session")
'''
NARRATIVE_CONFIGURATOR_BLOCK = '''def configure_narrative_system_user!(icon_upload)
  bot = User.find_by(id: -2)
  raise "Pinned narrative system user is absent" if bot.nil?
  unless %w[discobot mochirii-guide].include?(bot.username)
    raise "Pinned narrative system user identity is unexpected"
  end
  if bot.username == "discobot"
    changed = UsernameChanger.new(bot, "mochirii-guide", Discourse.system_user).change(asynchronous: false)
    raise "Narrative system user rename failed" unless changed
    bot.reload
  end
  bot.update!(name: "Mochirii Guide", email: "mochirii-guide@forums.mochirii.com")
  bot.create_user_profile! if bot.user_profile.nil?
  bot.user_profile.update!(
    bio_raw: "Mochirii Forums guidance is maintained by the Mochirii moderation team.",
    website: "https://mochirii.com",
    location: "Mochirii",
  )
  bot.create_user_avatar! if bot.user_avatar.nil?
  bot.user_avatar.update!(custom_upload_id: icon_upload.id, gravatar_upload_id: nil)
  bot.update!(uploaded_avatar_id: icon_upload.id)
  raise "Old narrative system username remains" if User.exists?(username_lower: "discobot")
end

configure_narrative_system_user!(icon_upload)
'''
NARRATIVE_RUNTIME_VERIFIER_BLOCK = '''checks["narrative_system_user_identity_branded"] =
  bot&.username == "mochirii-guide" &&
    bot&.name == "Mochirii Guide" &&
    bot&.email == "mochirii-guide@forums.mochirii.com" &&
    User.where(username_lower: "discobot").none?
checks["narrative_system_user_profile_branded"] =
  !bot.nil? &&
    !bot.user_profile.nil? &&
    !bot_profile_text.match?(/discobot|discourse[.]org|meta[.]discourse|blog[.]discourse|digitaloceanspaces|amazonaws/i)
checks["narrative_system_user_active_avatar_branded"] =
  !bot.nil? &&
    !bot.user_avatar.nil? &&
    bot.uploaded_avatar_id == icon_id &&
    bot.user_avatar.custom_upload_id == icon_id &&
    icon_upload.sha1 == "c1fde880bdf518e913d5eeb9a868f886e3e47fa0"
checks["narrative_system_user_gravatar_absent"] =
  !bot.nil? && !bot.user_avatar.nil? && bot.user_avatar.gravatar_upload_id.nil?
checks["narrative_system_user_branded"] =
  checks.values_at(
    "narrative_system_user_identity_branded",
    "narrative_system_user_profile_branded",
    "narrative_system_user_active_avatar_branded",
    "narrative_system_user_gravatar_absent",
  ).all?
'''
ADMIN_QUICK_START_TEMPLATE_SHA256 = "61215146fdcd1c7e3555ca9c98d7a44217f10bc4c9eb5ee81a931a5492d03f5c"
ADMIN_QUICK_START_STORED_TEMPLATE_BYTES = 1305
ADMIN_QUICK_START_STORED_TEMPLATE_SHA256 = "797e8a4616d96ed775fc51b1df92ee3d6bac0ce1b431050ba2af306894bdc766"
RUNTIME_VERIFIER_SHA256 = "8bbef62aa9f74ce8372292a784d30c2ad5b0da9d4061e8a4184b128f499e0896"
RESTORED_BACKUP_VERIFIER_SHA256 = "2804d9bfc738ff083f6a286bfa0fbca6bbe0c986e29d69dd732ab9453f832189"
RESTORED_CHECK_EXIT_CODES = (
    ("repository_revision", 64, "repository-revision"),
    ("recovery_marker", 65, "recovery-marker"),
    ("recovery_normal_upload", 66, "recovery-normal-upload"),
    ("database", 67, "database"),
    ("redis", 68, "redis"),
    ("sidekiq_process_present", 69, "sidekiq-process-present"),
    ("sidekiq_processing", 70, "sidekiq-processing"),
    ("mail_suppression_matches_runtime", 71, "mail-suppression-matches-runtime"),
    ("central_login_matches_runtime", 72, "central-login-matches-runtime"),
    ("secure_uploads_absent", 73, "secure-uploads-absent"),
    ("normal_upload_inventory", 74, "normal-upload-inventory"),
)
CONFIGURE_SITE_SHA256 = "b4c38e0c734ce7b1300756beee970578ee7f1521d10497a0820880808c714dd3"
APP_TEMPLATE_SHA256 = "889de69b3a2f9e82a9d1ca33034d7cf6ec3717a124a767ad9028af3499313ccf"
ADMIN_RECOVERY_FIXTURE_SHA256 = "a9cee13eabafa16cba8bc4f0e2cf6fdef457df229d3157d761e65b936c95e733"
SENSITIVE_LOG_VERIFIER_SHA256 = "dcd105f619674983c42c92eeff2f06dbdc37fca3779aa5e13acdbc8b80ffc09c"
SENSITIVE_LOG_EXECUTABLE_SHA256 = "3e9ca44f8d9f4e2f89463fca323ba63388f2c059664cc4e0d25ebd1c9fcad6fa"
DISCOURSE_CONNECT_VERIFIER_SHA256 = "f12739d6baba4eb4267509fd35b5e6f9ce79be19e5ec63b07e2134140041a360"
CONTAINED_ACTIVATION_VERIFIER_SHA256 = "1ef24d7e9422a007fcc55a88f8c86d06fc618cae8e1ab311b6f91586e3e23bf1"
HOST_NGINX_FILE_VERIFIER_SHA256 = "b7356abad4a80964825cf3a8cf1290ccd7c33d65fe0095c2dd47328f046ce9d9"
HOST_NGINX_FILE_VERIFIER_PREFIX_SHA256 = "363ca993d78a0c3578c8118c3026f2d3410f8ecb876c1f9a12a1b684cca6d74b"
HOST_SENSITIVE_RESPONSE_VERIFIER_SHA256 = "cefc6ba11ee9810f228a9f47048c95d5d441e6de854a60d0a3629de7e6d3a0e7"
HOST_VERIFY_SOURCE_SHA256 = "92e5ef74b22abd395c0c0a80d41d73dee46114c048e21a7cc9978b340b9c193f"
DISPOSABLE_NGINX_HEADER_PROOF_SHA256 = "9aa1279010aac1a5b7c65b6634053792d15c17f788090456660f1a575aa9b98e"
DISPOSABLE_NGINX_OUTLET_EXTRACTOR_RUBY = r"""
require "yaml"

document = YAML.safe_load_file(ARGV.fetch(0), aliases: true)
expected = {
  "/etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc" =>
    File.join(ARGV.fetch(1), "conf.d/outlets/discourse/35-mochirii-public-response-headers.inc"),
  "/etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf" =>
    File.join(ARGV.fetch(1), "conf.d/outlets/discourse/40-mochirii-public-metadata.conf"),
  "/etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf" =>
    File.join(ARGV.fetch(1), "conf.d/outlets/server/35-mochirii-public-response-headers.conf"),
  "/etc/nginx/conf.d/outlets/server/40-mochirii-feed-denial.conf" =>
    File.join(ARGV.fetch(1), "conf.d/outlets/server/40-mochirii-feed-denial.conf"),
}
items = document.fetch("run")
final_commands = items.fetch(-1).fetch("exec").fetch("cmd")
expected_header_include = %q{test "$(grep -Fxc '      include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;' /etc/nginx/conf.d/discourse.conf)" -eq 1}
expected_private_username_log = %q{test "$(grep -Fo '"-" "$upstream_http_x_discourse_trackview"' /etc/nginx/conf.d/discourse.conf | wc -l)" -eq 1}
expected_no_username_log = %q{! grep -Fq '$upstream_http_x_discourse_username' /etc/nginx/conf.d/discourse.conf}
expected_nginx = "test ! -L /var/log/nginx && install -d -m 0755 -o root -g adm /var/log/nginx && nginx -t"
abort "final response-header include command differs" unless final_commands.length == 12 && final_commands.fetch(-5) == expected_header_include
abort "final private username-log command differs" unless final_commands.fetch(-4) == expected_private_username_log
abort "final username-log exclusion command differs" unless final_commands.fetch(-3) == expected_no_username_log
abort "final Nginx command differs" unless final_commands.fetch(-1) == expected_nginx
outlet_directories = [
  "/etc/nginx/conf.d/outlets/discourse",
  "/etc/nginx/conf.d/outlets/server",
]
actual_outlets = items.filter_map do |item|
  file = item["file"]
  next unless file.is_a?(Hash) && file["path"].is_a?(String)
  next unless outlet_directories.include?(File.dirname(file["path"]))
  file["path"]
end
abort "outlet inventory differs" unless actual_outlets.sort == expected.keys.sort
expected.each do |source, destination|
  matches = items.select { |item| item["file"].is_a?(Hash) && item["file"]["path"] == source }
  abort "outlet inventory differs" unless matches.length == 1
  contents = matches.fetch(0).fetch("file").fetch("contents")
  abort "outlet contents differ" unless contents.is_a?(String) && !contents.empty?
  File.binwrite(destination, contents)
end
"""
# Exact normalized server outlet derived from discourse_docker@ed9f680b0df1de28f062de1769d89d22b2644d1b
# templates/web.ssl.template.yml (2,111 bytes; SHA-256 7a3b819e65104c9178e004772b487fa809ce6b421668dfa1adf330221dda552b).
PINNED_WEB_SSL_SERVER_OUTLET = '''listen 443 ssl;
listen [::]:443 ssl;
http2 on;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

ssl_certificate /shared/ssl/ssl.crt;
ssl_certificate_key /shared/ssl/ssl.key;

ssl_session_tickets off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:1m;

add_header Strict-Transport-Security 'max-age=31536000';

if ($http_host != forums.mochirii.com) {
  rewrite (.*) https://forums.mochirii.com$1 permanent;
}'''
MANAGED_WEB_SSL_SERVER_OUTLET = PINNED_WEB_SSL_SERVER_OUTLET.replace(
    "ssl_certificate /shared/ssl/ssl.crt;",
    "ssl_certificate /shared/ssl/forums.mochirii.com.cer;  ssl_certificate /shared/ssl/forums.mochirii.com_ecc.cer;",
).replace(
    "ssl_certificate_key /shared/ssl/ssl.key;",
    "ssl_certificate_key /shared/ssl/forums.mochirii.com.key;   ssl_certificate_key /shared/ssl/forums.mochirii.com_ecc.key;",
)
EXPECTED_SERVER_TLS_SHA256 = tuple(
    hashlib.sha256(value.encode("utf-8")).hexdigest()
    for value in (PINNED_WEB_SSL_SERVER_OUTLET, MANAGED_WEB_SSL_SERVER_OUTLET)
)
OPENSEARCH_FILTER_BLOCK = '''        sub_filter_once off;
        sub_filter '<meta name="generator" content="Discourse 2026.7.1 - https://github.com/discourse/discourse version cbf996f65aae3da1843224aa624bcd9a225931ac">' '<meta name="generator" content="Mochirii Forums">';
        sub_filter '<Tags>discourse forum</Tags>' '<Tags>Mochirii Forums</Tags>';
        # The pinned metadata controller renders formats: [:xml], which Rails
        # serves as application/xml. Bind the replacement to that exact type.
        sub_filter_types application/xml;
'''
NARRATIVE_AVATAR_FIXTURE_SHA256 = "4c3d3945c022ee9c344787f3331367b85bd5602dc071482d3e00a66d8ea6ad0e"
NARRATIVE_AVATAR_WORKFLOW_CALL = '''          docker run "${ruby_fixture_container[@]}" -v "$GITHUB_WORKSPACE:/repo:ro" "$image" \\
            ruby /repo/scripts/test-narrative-avatar.rb >/dev/null
'''
NARRATIVE_AVATAR_WORKFLOW_STEP_SHA256 = "ca9dd9dc65530f75fb8fd301100522b843a33a9b9ae86def99844c155799afe2"
BRANDING_EMAIL_RENDERER_SHA256 = "0b504c71c1de2053585a20848e0515d2507d6d0b2a41c24eb99b83204b88c15c"
PINNED_SOURCE_VERIFIER_SHA256 = "4af86c3f95dc54b1e51790b8c7954c38e7fc0c1ccfc1a4ce607b5b56078927db"
ADMIN_LOGIN_LINK_FIXTURE_SHA256 = "b3d459fdaf0bc78b01a3584c35d4c70f1d28369ffdde17b5debc809f95650dba"
ADMIN_LOGIN_LINK_WORKFLOW_CALL = '''          docker run "${ruby_fixture_container[@]}" -v "$GITHUB_WORKSPACE:/repo:ro" "$image" \\
            ruby /repo/scripts/test-admin-login-link.rb >/dev/null
'''
PINNED_EMAIL_EVIDENCE = {
    "path": "lib/email.rb",
    "bytes": 1549,
    "sha256": "99ebebf096369af5bb765b5105abff94e28f6054be440ae922f0361ce1c1c0c2",
}
PINNED_OPENSEARCH_EVIDENCE = [
    {
        "path": "app/controllers/metadata_controller.rb",
        "bytes": 4914,
        "sha256": "7bf4d3f2034773d7cc5ad5c1ea621b8716caed198cd5f7a4a377bb6a04321de6",
    },
    {
        "path": "app/views/metadata/opensearch.xml.erb",
        "bytes": 926,
        "sha256": "44e583c097b8dacc3a6825e7d9376505ff886c521b6632bd9ad176ea6360cc64",
    },
]
PINNED_MAIL_RENDERING_EVIDENCE = [
    {
        "path": "app/mailers/user_notifications.rb",
        "bytes": 28133,
        "sha256": "eb6a22bb03b0731e81f9f560609bd344be3076fb49c1cffe21c6590f495063d4",
    },
    {
        "path": "app/models/topic.rb",
        "bytes": 78502,
        "sha256": "fd6468dd779edc6767dd8fb380e36c735b0698f6f4a2951a5e8a3b186ea6f056",
    },
    {
        "path": "app/mailers/admin_confirmation_mailer.rb",
        "bytes": 438,
        "sha256": "409f849e00ee2d001c2106e5c2aacdb15c448a9aee246005381b735194347849",
    },
    {
        "path": "lib/admin_confirmation.rb",
        "bytes": 1699,
        "sha256": "d095168b0c36efabf5a74e6e7685865a8c39b4520d444e86470874113b963566",
    },
    {
        "path": "lib/email/message_builder.rb",
        "bytes": 13752,
        "sha256": "6238ba3ecdb9a4003e0cce29938fc481c7c657bf07f392b00c1a2147db2f3502",
    },
    {
        "path": "lib/email/build_email_helper.rb",
        "bytes": 393,
        "sha256": "bb537c8d6dcce21ef12184de53ec32bab64b807e34c6a872f3243686be0c8f7a",
    },
    {
        "path": "lib/discourse.rb",
        "bytes": 39279,
        "sha256": "351e1170f79acb9b321746df618339de5412c95b1ce4c13db2c17e96bf1d0678",
    },
    {
        "path": "config/locales/server.en.yml",
        "bytes": 420250,
        "sha256": "0ff18443abac07e496e27142f21b33e8935242ca3d55fd33531c1ace43a92f50",
    },
    {
        "path": "app/helpers/user_notifications_helper.rb",
        "bytes": 3229,
        "sha256": "8916b4cf739dd589a2d6f8131332b9b59b2de20b9981b210c1bea0b189803aa5",
    },
    {
        "path": "config/routes.rb",
        "bytes": 81601,
        "sha256": "f5b5a641132de5342d78e0e3579783c0dcd0391ec5997e2034dd6a99d8c3078b",
    },
]
PINNED_TOPIC_SEED_EVIDENCE = [
    {
        "path": "db/fixtures/990_topics.rb",
        "bytes": 321,
        "sha256": "e25b129d6c76d27837e1d4a9e187cd7b49bacfe79e3d438e1a7473909e48a5c9",
    },
    {
        "path": "docs/ADMIN-QUICK-START-GUIDE.md",
        "bytes": 1905,
        "sha256": "94d08273429f2e919890201c2d21608595b78d384e4d3d7dc180659918744f50",
    },
    {
        "path": "lib/seed_data/topics.rb",
        "bytes": 7537,
        "sha256": "2e43f4a9f95f19d1e928e5ef6b873ed4f66144d91280f400a63e6e23e9029020",
    },
    {
        "path": "lib/post_creator.rb",
        "bytes": 22044,
        "sha256": "b4cf0a70dde716e8785239498d84a4612fc26f3e9607053abfd64c1edb7a1b52",
    },
    {
        "path": "lib/post_revisor.rb",
        "bytes": 29992,
        "sha256": "f92dfd0ff095b0a72b181e0b5a8d649e331a22cf1a669de98718feecc1a9a2a2",
    },
    {
        "path": "lib/text_cleaner.rb",
        "bytes": 3043,
        "sha256": "79410d0c02c60dff8e368e4308d41b4fdbbbb130afab1b1648c921ff7a4dc67a",
    },
]
PINNED_RESTORE_EVIDENCE = [
    {
        "path": "script/discourse",
        "bytes": 12564,
        "sha256": "417622a3df71fe50f4e0405dc20ba6abf0eeb2bf387ad1c132beb58684649e9e",
    },
    {
        "path": "lib/backup_restore/restorer.rb",
        "bytes": 6291,
        "sha256": "ad002009a0eb446706d8b29a679682f849e506df14fad15f500338b697a5a272",
    },
]
PINNED_GRAVATAR_EVIDENCE = [
    {
        "path": "app/models/user.rb",
        "bytes": 73523,
        "sha256": "79c453b7bf56a69f7919572020ffa5fdf9b32de37255439d0a22c2b73f3ff7ca",
    },
    {
        "path": "app/models/user_avatar.rb",
        "bytes": 7189,
        "sha256": "a53eb92ffe3793ef32c3f48f3e3216133916424a19a2ffea376b22e0b705a5a9",
    },
    {
        "path": "app/jobs/regular/update_gravatar.rb",
        "bytes": 539,
        "sha256": "2757a35e7521b9b6d8a7cdf7d6cf5e5ebf1273132956533dcf3951b27bca397c",
    },
]
ALLOWED_FILES = frozenset(
    {
    ".env.example",
    ".gitattributes",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/workflows/backup-forums.yml",
    ".github/workflows/deploy-forums.yml",
    ".github/workflows/disposable-bootstrap.yml",
    ".github/workflows/inspect-upstream.yml",
    ".github/workflows/restore-forums.yml",
    ".github/workflows/validate-repository.yml",
    ".github/workflows/verify-forums.yml",
    ".gitignore",
    "AGENTS.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    "config/app.yml.example",
    "config/acme-sh-3.0.6.gz.b64",
    "config/acme-sh-3.0.6.LICENSE.md",
    "config/apt-auto-upgrades.conf",
    "config/certbot-cli.ini.example",
    "config/certbot-dns.ini.example",
    "config/docker-daemon-policy.json",
    "config/fail2ban-forums.conf",
    "config/host-control-manifest.v1.json",
    "config/immutable-letsencrypt.fragment.yml",
    "config/media-certificate.runtime.json.example",
    "config/mochirii-forums-media-certificate-renew.service",
    "config/mochirii-forums-media-certificate-renew.timer",
    "config/runtime.json.example",
    "config/sshd-forums-prepared.conf",
    "config/sshd-forums.conf",
    "config/sudoers-forums",
    "config/sudoers-forums-operator",
    "plugins/mochirii_email_metadata/plugin.rb",
    "docs/adr/0001-clean-initialization-and-canonical-ownership.md",
    "docs/adr/0002-pull-only-upstream-and-source-introduction.md",
    "docs/adr/0003-supported-source-introduction-packet.md",
    "docs/adr/0004-authorized-standalone-deployment.md",
    "docs/operations/CURRENT-STATE.md",
    "docs/operations/DEPLOYMENT.md",
    "docs/operations/PROVIDER-DNS-TLS.md",
    "docs/operations/RECOVERY.md",
    "docs/operations/RELEASE-EVIDENCE.md",
    "docs/operations/RUNTIME-READINESS.md",
    "docs/operations/SECRETS.md",
    "docs/operations/SOURCE-INTRODUCTION-READINESS.md",
    "docs/operations/SOURCE-PROVENANCE.md",
    "docs/operations/STORAGE.md",
    "docs/operations/VALIDATION.md",
    "docs/operations/THIRD-PARTY-NOTICES.md",
    "docs/operations/activation.v1.json",
    "docs/operations/backup-restore-contract.v1.json",
    "docs/operations/cost-gate.v1.json",
    "docs/operations/customizations.v1.json",
    "docs/operations/forum-central-identity.consumer.v1.json",
    "docs/operations/release-evidence.v1.example.json",
    "docs/operations/release-evidence.v2.example.json",
    "docs/operations/repository-capabilities.v1.json",
    "docs/operations/runtime-config.v1.example.json",
    "docs/operations/source-introduction.v1.json",
    "docs/operations/storage-policy.v1.json",
    "docs/operations/third-party-components.v1.json",
    "docs/operations/upstream-provenance.v1.json",
    "scripts/authentication-state.py",
    "scripts/backup-transaction.py",
    "scripts/backup-url-boundary.rb",
    "scripts/build-theme-archive.py",
    "scripts/check-repository.ps1",
    "scripts/check-source-introduction.ps1",
    "scripts/configure-site.rb",
    "scripts/configure-upstream.ps1",
    "scripts/expire-discourse-connect-nonce.rb",
    "scripts/fetch-disaster-recovery-evidence.rb",
    "scripts/fetch-disaster-recovery-release.rb",
    "scripts/finalize-member-rollout.sh",
    "scripts/durable-event.py",
    "scripts/deployment-mutation.py",
    "scripts/disposable-launcher-guard.py",
    "scripts/host-backup.sh",
    "scripts/host-break-glass-admin.sh",
    "scripts/host-deploy.sh",
    "scripts/host-finalize-authentication.sh",
    "scripts/host-historical-disaster-recovery.sh",
    "scripts/host-operation-lock.py",
    "scripts/host-restore-validate.sh",
    "scripts/host-stop-pending-activation.sh",
    "scripts/host-verify-wrapper.sh",
    "scripts/host-control-evidence.py",
    "scripts/historical-recovery-scratch-reader.sh",
    "scripts/historical-release-disaster-recovery.py",
    "scripts/install-host-control.sh",
    "scripts/install-media-certificate-renewal.sh",
    "scripts/media-certificate-operation.sh",
    "scripts/normal-upload-inventory.rb",
    "scripts/prepare-backup-marker.rb",
    "scripts/prepare-admin-recovery-fixture.rb",
    "scripts/prepare-media-certificate.sh",
    "scripts/probe-website-forums-producer.py",
    "scripts/publish-disaster-recovery-evidence.rb",
    "scripts/quarantine-failed-bootstrap.sh",
    "scripts/reconcile-acme-dns.py",
    "scripts/render-app-config.py",
    "scripts/render-branding-email.rb",
    "scripts/rotate-media-certificate.py",
    "scripts/rotate-media-certificate.sh",
    "scripts/run-media-certificate-renewal.sh",
    "scripts/ssh-deploy-dispatch.py",
    "scripts/storage-response-boundary.rb",
    "scripts/test-backup-url-boundary.rb",
    "scripts/test-admin-login-link.rb",
    "scripts/test-backup-transaction.py",
    "scripts/test-normal-upload-inventory.rb",
    "scripts/test-narrative-avatar.rb",
    "scripts/test-operation-survivor.rb",
    "scripts/test-sidekiq-processing-probe.rb",
    "scripts/test-contracts.py",
    "scripts/test-deployment-mutation.py",
    "scripts/test-disposable-launcher-guard.py",
    "scripts/test-disaster-recovery-release-chain.rb",
    "scripts/test-historical-recovery-scratch-reader.py",
    "scripts/test-historical-release-disaster-recovery.py",
    "scripts/test-host-restore-launcher-journal.py",
    "scripts/test-host-operation-lock.py",
    "scripts/test-source-introduction.ps1",
    "scripts/test-storage-response-boundary.rb",
    "scripts/test-storage-transaction-durability.py",
    "scripts/test-upstream-policy.ps1",
    "scripts/validate-repository.py",
    "scripts/verify-backup.rb",
    "scripts/verify-break-glass-admin.rb",
    "scripts/verify-clean-disaster-target.rb",
    "scripts/verify-contained-activation.sh",
    "scripts/verify-contained-discourse-connect.rb",
    "scripts/verify-cost-evidence.py",
    "scripts/verify-discourse-connect-fixture.rb",
    "scripts/verify-discourse-connect.py",
    "scripts/verify-discourse-docker-checkout.sh",
    "scripts/verify-host.sh",
    "scripts/verify-host-security.sh",
    "scripts/verify-pinned-source.py",
    "scripts/verify-public-branding.py",
    "scripts/verify-runtime-assets.sh",
    "scripts/verify-restored-backup.rb",
    "scripts/verify-site.rb",
    "scripts/verify-sensitive-log-redaction.rb",
    "scripts/verify-storage-fixture.rb",
    "scripts/verify-upstream-policy.ps1",
    "scripts/verify-upstream-provenance.ps1",
    "scripts/verify-zero-secure-uploads.rb",
    "scripts/upgrade-host-control.sh",
    "theme/mochirii/LICENSE.txt",
    "theme/mochirii/about.json",
    "theme/mochirii/assets/mochirii-emblem.webp",
    "theme/mochirii/assets/mochirii-icon.png",
    "theme/mochirii/assets/mochirii-social-card.png",
    "theme/mochirii/common/common.scss",
    "theme/mochirii/common/footer.html",
    "theme/mochirii/common/head_tag.html",
    "theme/mochirii/javascripts/discourse/connectors/composer-fields-below/mochirii-upload-notice.hbs",
    "theme/mochirii/locales/en.yml",
    }
)
MAX_FILE_BYTES = 1024 * 1024
JSON_SHAPE_SHA256 = {
    "config/docker-daemon-policy.json": "b463d5412575e0b75c225ade0cbc4bffbf61633eeeea956a6621729859e60113",
    "config/host-control-manifest.v1.json": "a3a1f8a8c55afaf4e88774a07e7bdc7414976fbd77390da43b4077229a8e53f0",
    "config/media-certificate.runtime.json.example": "6c5764ec4d954960987f91a8812b8c1fd805cda280bf9c236b500b4aeacf190f",
    "config/runtime.json.example": "5ab0c927fd6c0a85c45b605d2b22a6203a216e823ff61f45e22efc37e05b1238",
    "docs/operations/activation.v1.json": "50fcd14b2495d5f88582652f284d0a6e278fde9d428e983dfb12879a1ff13d3e",
    "docs/operations/backup-restore-contract.v1.json": "cea30f18d0842adfd5712dd05ad52089a276c67fe9e61a9f28c7f779a8652b4c",
    "docs/operations/cost-gate.v1.json": "1ae0eb5cf7f4b32a530575a690952c0d1d82226686b37549e22deefea4619d64",
    "docs/operations/customizations.v1.json": "8028131bf21a3519916c70d049a8c1a1d2c5f737be754accd4fca84b98873c42",
    "docs/operations/forum-central-identity.consumer.v1.json": "7b891ccb1c5b1559b0750dcef4add6c17b6b4fd2f932acf235be9a102238479d",
    "docs/operations/release-evidence.v1.example.json": "99b73f2448df6dfdfe2dea6cebe7c21bd182c036f6e8fb0923681c12100d2e42",
    "docs/operations/release-evidence.v2.example.json": "c2e42a164c118ae5367f7cdc310dbc3c2e15edf8919c6a29905b5475b661a536",
    "docs/operations/repository-capabilities.v1.json": "3382dab28678b9d56e7cb430ffacda4fc3e1f52df94adc0f74b5761433487806",
    "docs/operations/runtime-config.v1.example.json": "3c75090f614add84c67429fc9c66c2551280339f02d6b5a5fae704fdce4c2bae",
    "docs/operations/source-introduction.v1.json": "cb61665e970f3948e3b9f15293e85f4be80ddd0344a7bafdde6e47d9763a2c08",
    "docs/operations/storage-policy.v1.json": "9b4b8c841497133d3fc9a7b2350fc6fbe7b92e90f27fec69b035c2f27031ccab",
    "docs/operations/third-party-components.v1.json": "bdb87c1d4e255ea39e377a16f36ec53f3443713cdcd12c93287d239acfc7e6bc",
    "docs/operations/upstream-provenance.v1.json": "9208d8d87a9dcf86273a10aff3011cbd2ad218000aaaf659547b96d497c4a78b",
    "theme/mochirii/about.json": "0cfcd9a73ccc866ae9f272dfe933ce70cdf2e2f0e4ae16b01d0ce1f3c4ececa3",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def ruby_executable_contract_source(source: str) -> str:
    executable: list[str] = []
    in_block_comment = False
    for line in source.splitlines(keepends=True):
        logical = line.rstrip("\r\n")
        if in_block_comment:
            if re.fullmatch(r"=end(?:[ \t].*)?", logical):
                in_block_comment = False
            continue
        if re.fullmatch(r"=begin(?:[ \t].*)?", logical):
            in_block_comment = True
            continue
        if logical.lstrip(" \t").startswith("#"):
            continue
        executable.append(line)
    if in_block_comment:
        fail("Sensitive-log executable Ruby contract contains an unterminated block comment.")
    return "".join(executable)


def validate_theme_runtime_verifier(source: str) -> None:
    sensitive_parameter_filter = '''checks["discourse_connect_log_parameters_filtered"] =
  Rails.application.config.filter_parameters.include?(:email) &&
    Rails.application.config.filter_parameters.include?(:sso) &&
    Rails.application.config.filter_parameters.include?(:sig) &&
    Rails.application.config.filter_parameters.include?(:token)
'''
    if source.count(sensitive_parameter_filter) != 1:
        fail("Runtime verifier lost the exact member-email and callback parameter filter check.")
    logster_context_filter = '''logster_string_identity_env = {}
logster_symbol_identity_env = {}
logster_control_env = {}
logster_string_identity_result =
  Logster.add_to_env(logster_string_identity_env, "username", "member-identity-probe")
logster_symbol_identity_result =
  Logster.add_to_env(logster_symbol_identity_env, :username, "member-identity-probe")
logster_control_result = Logster.add_to_env(logster_control_env, :job, "runtime-context-probe")
logster_callback_env = Rails.application.env_config.merge(
  Rack::MockRequest.env_for(
    "/session/sso_login?sso=member-identity-probe&sig=member-identity-probe",
  ),
)
logster_callback_request = ActionDispatch::Request.new(logster_callback_env)
logster_callback_context = Logster::Message.populate_from_env(logster_callback_env)
checks["member_identity_omitted_from_logster_context"] =
  defined?(MochiriiSensitiveLogsterEnvironmentFilter) &&
    defined?(MochiriiSensitiveLogsterMessageFilter) &&
    Logster.singleton_class.ancestors.include?(MochiriiSensitiveLogsterEnvironmentFilter) &&
    Logster::Message.singleton_class.ancestors.include?(MochiriiSensitiveLogsterMessageFilter) &&
    logster_string_identity_result.nil? &&
    logster_symbol_identity_result.nil? &&
    logster_string_identity_env.empty? &&
    logster_symbol_identity_env.empty? &&
    logster_control_result == "runtime-context-probe" &&
    logster_control_env == { job: "runtime-context-probe" }
checks["sensitive_request_fields_filtered_from_logster_context"] =
  (!logster_callback_context.key?("params") ||
    logster_callback_context["params"] == logster_callback_request.filtered_parameters) &&
    (!logster_callback_context.key?("REQUEST_URI") ||
      logster_callback_context["REQUEST_URI"] == logster_callback_request.filtered_path) &&
    !JSON.generate(logster_callback_context).include?("member-identity-probe")
'''
    if source.count(logster_context_filter) != 1:
        fail("Runtime verifier lost the exact member-identity Logster omission check.")
    member_log_identity_filter = '''lograge_payload = DiscourseLograge.custom_payload(
  ip: "127.0.0.1",
  username: "member-identity-probe",
  route: "runtime-context-probe",
  omitted: nil,
)
checks["member_identity_omitted_from_request_logs"] =
  defined?(MochiriiSensitiveDiscourseLogragePayloadFilter) &&
    DiscourseLograge.singleton_class.ancestors.include?(MochiriiSensitiveDiscourseLogragePayloadFilter) &&
    lograge_payload == { ip: "127.0.0.1", username: nil, route: "runtime-context-probe" } &&
    !JSON.generate(lograge_payload).include?("member-identity-probe")
'''
    if source.count(member_log_identity_filter) != 1:
        fail("Runtime verifier lost the exact member-identity log omission check.")
    recovery_logster_filter = '''recovery_token = "a" * 32
recovery_logster_env = Rails.application.env_config.merge(
  Rack::MockRequest.env_for("/session/email-login/#{recovery_token}"),
)
recovery_request = ActionDispatch::Request.new(recovery_logster_env)
recovery_logster_context = Logster::Message.populate_from_env(recovery_logster_env)
ordinary_request = ActionDispatch::Request.new(
  Rails.application.env_config.merge(Rack::MockRequest.env_for("/session/email-login/too-short")),
)
checks["admin_recovery_log_path_filtered"] =
  defined?(MochiriiSensitiveRequestPathFilter) &&
    ActionDispatch::Request.ancestors.include?(MochiriiSensitiveRequestPathFilter) &&
    recovery_request.path == "/session/email-login/#{recovery_token}" &&
    recovery_request.filtered_path == "/session/email-login/[FILTERED]" &&
    ordinary_request.filtered_path == "/session/email-login/too-short" &&
    (!recovery_logster_context.key?("REQUEST_URI") ||
      recovery_logster_context["REQUEST_URI"] == "/session/email-login/[FILTERED]") &&
    !JSON.generate(recovery_logster_context).include?(recovery_token)
'''
    if source.count(recovery_logster_filter) != 1:
        fail("Runtime verifier lost the exact administrator recovery Logster omission check.")
    start = 'checks["theme_logo_uploads"] =\n'
    end = 'checks["core_revision"] ='
    if source.count(start) != 1 or source.count(end) != 1:
        fail("Runtime theme verifier block boundary differs.")
    block = source[source.index(start) : source.index(end)]
    if block != THEME_RUNTIME_VERIFIER_BLOCK:
        fail("Runtime theme verifier differs from the exact pinned semantic block.")
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != RUNTIME_VERIFIER_SHA256:
        fail("Runtime verifier differs from the exact reviewed source digest.")


def validate_sidekiq_runtime_verifier(source: str, label: str) -> None:
    processing_marker = "MochiriiEmailMetadata.verify_sidekiq_processing!"
    process_marker = "Sidekiq::ProcessSet.new.any?"
    required = (
        process_marker,
        processing_marker,
        "rescue MochiriiEmailMetadata::SidekiqProbeError => error",
        'sidekiq_probe_state = "completed"',
        "sidekiq_probe_state = error.state",
        "sidekiqProbeState: sidekiq_probe_state",
    )
    if any(source.count(value) != 1 for value in required):
        fail(f"Registered, executing, and fixed-state Sidekiq verification differs in {label}.")
    if source.index(processing_marker) > source.index(process_marker):
        fail(f"Sidekiq registration is sampled before the bounded processing proof in {label}.")
    if any(value in source for value in ("error.message", "error.backtrace", "error.inspect")):
        fail(f"Sidekiq verifier emits an unsafe exception value: {label}")


def validate_restored_mail_suppression_contract(source: str) -> None:
    runtime_binding = 'runtime_mail_suppression = ENV.fetch("DISCOURSE_DISABLE_EMAILS")\n'
    check = '''  mail_suppression_matches_runtime:
    %w[yes non-staff].include?(runtime_mail_suppression) &&
      SiteSetting.disable_emails == runtime_mail_suppression,
'''
    if (
        source.count(runtime_binding) != 1
        or source.count(check) != 1
        or source.count("runtime_mail_suppression") != 3
        or source.count("mail_suppression_matches_runtime") != 2
        or "all_mail_disabled" in source
        or hashlib.sha256(source.encode("utf-8")).hexdigest() != RESTORED_BACKUP_VERIFIER_SHA256
    ):
        fail("Restored-backup mail suppression is not bound to the exact safe runtime setting.")


def validate_restored_central_login_contract(source: str) -> None:
    runtime_binding = '''runtime_central_login =
  case ENV.fetch("DISCOURSE_ENABLE_DISCOURSE_CONNECT")
  when "true" then true
  when "false" then false
  else raise "DiscourseConnect runtime flag is malformed"
  end
'''
    check = '''  central_login_matches_runtime:
    SiteSetting.enable_discourse_connect == runtime_central_login,
'''
    if (
        source.count(runtime_binding) != 1
        or source.count(check) != 1
        or source.count("runtime_central_login") != 2
        or "central_login_disabled" in source
        or "SiteSetting.enable_discourse_connect == false" in source
    ):
        fail("Restored-backup central login is not bound to the exact runtime flag.")


def validate_restored_failure_exit_contract(source: str) -> None:
    expected_check_names = tuple(name for name, _status, _category in RESTORED_CHECK_EXIT_CODES)
    checks_start = "checks = {\n"
    checks_end = "\n}\n\nfailed = checks.select { |_name, passed| !passed }.keys\n"
    mapping = "RESTORED_CHECK_EXIT_CODES = {\n" + "".join(
        f"  {name}: {status},\n" for name, status, _category in RESTORED_CHECK_EXIT_CODES
    ) + "}.freeze\n"
    tail = '''failed = checks.select { |_name, passed| !passed }.keys
puts JSON.generate({ checks: checks, failed: failed, sidekiqProbeState: sidekiq_probe_state })
exit(RESTORED_CHECK_EXIT_CODES.fetch(failed.first)) if failed.any?
'''
    if source.count(checks_start) != 1 or source.count(checks_end) != 1:
        fail("Restored-backup fixed-check boundary differs.")
    checks_block = source[
        source.index(checks_start) + len(checks_start) : source.index(checks_end)
    ]
    observed_check_names = tuple(
        re.findall(r"(?m)^  ([a-z][a-z0-9_]*):", checks_block)
    )
    if (
        source.count(mapping) != 1
        or source.count(tail) != 1
        or observed_check_names != expected_check_names
        or 'raise "Mochirii restored-backup verification failed"' in source
        or len({status for _name, status, _category in RESTORED_CHECK_EXIT_CODES}) != len(RESTORED_CHECK_EXIT_CODES)
        or any(status in {0, 1, 124, 137, 143} for _name, status, _category in RESTORED_CHECK_EXIT_CODES)
    ):
        fail("Restored-backup fixed-check exit mapping differs.")


def validate_narrative_avatar_contract(template: str, configure: str, verifier: str) -> None:
    environment_line = '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"\n'
    environment_block = '''  DISCOURSE_ALLOW_EMAIL_INVITES: "false"
  DISCOURSE_DISCOURSE_NARRATIVE_BOT_ENABLED: "false"
  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"

  DISCOURSE_LOGIN_REQUIRED: "true"'''
    expected_setting = "  automatically_download_gravatars: false,\n"
    runtime_setting = '''checks["automatic_gravatar_downloads_disabled"] =
  ENV["DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"] == "false" &&
    SiteSetting.automatically_download_gravatars == false
'''
    env_start = "\nenv:\n"
    env_end = "\nvolumes:\n"
    if template.count(env_start) != 1 or template.count(env_end) != 1:
        fail("Application environment section boundary differs.")
    environment = template[template.index(env_start) : template.index(env_end)]
    key_pattern = r"(?m)^  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS[ \t]*:"
    if (
        template.count(environment_line) != 1
        or environment.count(environment_line) != 1
        or environment.count(environment_block) != 1
        or len(re.findall(key_pattern, template)) != 1
        or len(re.findall(key_pattern, environment)) != 1
    ):
        fail("Automatic Gravatar downloads are not disabled exactly once in the runtime environment.")
    if hashlib.sha256(template.encode("utf-8")).hexdigest() != APP_TEMPLATE_SHA256:
        fail("Application template differs from the exact reviewed source digest.")
    if configure.count(expected_setting) != 1:
        fail("Site configuration does not fail closed on the automatic Gravatar setting.")
    if configure.count(NARRATIVE_CONFIGURATOR_BLOCK) != 1:
        fail("Narrative system-user configuration differs from the exact reviewed helper and call.")
    if verifier.count(runtime_setting) != 1 or verifier.count(NARRATIVE_RUNTIME_VERIFIER_BLOCK) != 1:
        fail("Narrative runtime verifier lost its environment, setting, or fixed subcheck boundary.")
    admin_templates: list[str] = []
    for source, start, label in (
        (configure, "mochirii_admin_quick_start_template = <<~MARKDOWN\n", "site configurator"),
        (verifier, "expected_admin_quick_start_template = <<~MARKDOWN\n", "runtime verifier"),
    ):
        if source.count(start) != 1:
            fail(f"Administrator quick-start template boundary differs in the {label}.")
        body_start = source.index(start) + len(start)
        body_end = source.find("MARKDOWN\n", body_start)
        if body_end < 0:
            fail(f"Administrator quick-start template is unterminated in the {label}.")
        admin_templates.append(source[body_start:body_end])
    if (
        admin_templates[0] != admin_templates[1]
        or hashlib.sha256(admin_templates[0].encode("utf-8")).hexdigest()
        != ADMIN_QUICK_START_TEMPLATE_SHA256
    ):
        fail("Administrator quick-start replacement differs from the exact reviewed template.")
    runtime_admin_template = textwrap.dedent(admin_templates[0])
    stored_admin_template = runtime_admin_template[:-1]
    if (
        not runtime_admin_template.endswith("\n")
        or runtime_admin_template.endswith("\n\n")
        or len(stored_admin_template.encode("utf-8")) != ADMIN_QUICK_START_STORED_TEMPLATE_BYTES
        or hashlib.sha256(stored_admin_template.encode("utf-8")).hexdigest()
        != ADMIN_QUICK_START_STORED_TEMPLATE_SHA256
    ):
        fail("Administrator quick-start stored replacement differs from the exact reviewed bytes.")
    configurator_contract = (
        'require "digest"\n',
        'mochirii_admin_quick_start =\n'
        '  TextCleaner.normalize_whitespaces(\n'
        '    mochirii_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url),\n'
        '  ).rstrip\n',
        "normalized_upstream_admin_quick_start.bytesize == 1904 &&\n",
        '      "2416035d0c2dedd589a39005285277b181cf1723dd8cbf113e45f9175df12a12"\n',
        "if admin_quick_start.raw == mochirii_admin_quick_start\n",
        "elsif untouched_upstream_admin_quick_start\n",
        "  admin_quick_start.revise(Discourse.system_user, { raw: mochirii_admin_quick_start })\n",
        '  raise "Pinned administrator quick-start content was edited"\n',
        "unless admin_quick_start.raw == mochirii_admin_quick_start\n",
    )
    if any(configure.count(value) != 1 for value in configurator_contract):
        fail("Administrator quick-start configurator lost its exact fail-closed seed revision contract.")
    runtime_contract = (
        'expected_admin_quick_start =\n'
        '  TextCleaner.normalize_whitespaces(\n'
        '    expected_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url),\n'
        '  ).rstrip\n',
        'checks["admin_quick_start_branded"] =\n',
        "    admin_quick_start_topic.category_id == SiteSetting.staff_category_id &&\n",
        "    admin_quick_start.user_id == Discourse::SYSTEM_USER_ID &&\n",
        "    admin_quick_start.last_editor_id == Discourse::SYSTEM_USER_ID &&\n",
        "    admin_quick_start.raw == expected_admin_quick_start &&\n",
        "    !admin_quick_start.raw.match?(/\\bDiscourse\\b|discourse[.](?:org|com)|digitaloceanspaces|amazonaws/i)\n",
    )
    if any(verifier.count(value) != 1 for value in runtime_contract):
        fail("Administrator quick-start runtime verifier lost its exact content and ownership contract.")
    if hashlib.sha256(configure.encode("utf-8")).hexdigest() != CONFIGURE_SITE_SHA256:
        fail("Site configurator differs from the exact reviewed source digest.")
    if hashlib.sha256(verifier.encode("utf-8")).hexdigest() != RUNTIME_VERIFIER_SHA256:
        fail("Runtime verifier differs from the exact reviewed source digest.")
    require_text(
        read("docs/operations/VALIDATION.md"),
        [
            "automatic external Gravatar downloads are disabled",
            "fixed identity, profile,",
            "active-avatar, and no-Gravatar subchecks",
        ],
        "automatic Gravatar validation contract",
    )
    require_text(
        read("docs/operations/RUNTIME-READINESS.md"),
        [
            "`automatically_download_gravatars=false` before narrative-user branding",
            "no asynchronously downloaded Gravatar after Sidekiq runs",
        ],
        "automatic Gravatar runtime-readiness contract",
    )


def validate_branding_email_renderer(source: str) -> None:
    expected_calls = (
        "  text, html = Email.extract_parts(mail.encoded)\n",
        "  _digest_text, digest_html = Email.extract_parts(digest.encoded)\n",
    )
    if any(source.count(call) != 1 for call in expected_calls):
        fail("Branding email renderer does not use the exact pinned raw-message API at both call sites.")
    if source.count("Email.extract_parts(") != 2 or "Email.extract_body" in source:
        fail("Branding email renderer contains an unreviewed email extraction call.")
    if source.count('puts "Mochirii mail presentation passed."') != 1:
        fail("Branding email renderer success output changed.")
    digest_fixture_contract = (
        "def materialize(delivery, label:)\n",
        "  unless mail.is_a?(Mail::Message)\n",
        '    raise "#{label} mail path did not render a Mail::Message"\n',
        "def render_stage4_digest!(user:, welcome_topic:, guidelines_topic:, admin_quick_start_topic:)\n",
        "  topics = [welcome_topic, guidelines_topic, admin_quick_start_topic]\n",
        "    SiteSetting.admin_quick_start_topic_id,\n",
        '    raise "Digest fixture topics are not the exact controlled seed topics"\n',
        '      !admin_quick_start_topic.first_post.raw.start_with?("*Mochirii staff setup guide*")\n',
        "  original_created_at = topics.to_h { |topic| [topic.id, topic.created_at] }\n",
        "  Topic.transaction(requires_new: true) do\n",
        "    topics.each { |topic| topic.update_columns(created_at: aged_created_at) }\n",
        "    delivery = UserNotifications.digest(user, since: 3.days.ago, skip_unsubscribe_links: true)\n",
        '    mail = materialize(delivery, label: "digest")\n',
        '    expected_markers = topics.map(&:title) + ["Mochirii staff setup guide"]\n',
        '      raise "Digest fixture omitted a controlled seed topic"\n',
        "    raise ActiveRecord::Rollback\n",
        "  topics.each(&:reload)\n",
        "  unless topics.all? { |topic| topic.created_at == original_created_at.fetch(topic.id) }\n",
        '    raise "Digest fixture topic ages leaked beyond rollback"\n',
        "  deliveries[\"digest\"] = render_stage4_digest!(\n",
        "    welcome_topic: welcome_topic,\n",
        "    guidelines_topic: guidelines_topic,\n",
        "    admin_quick_start_topic: admin_quick_start_topic,\n",
        "  mail = materialize(delivery, label: label)\n",
        '  digest = materialize(deliveries.fetch("digest"), label: "digest")\n',
    )
    if any(source.count(value) != 1 for value in digest_fixture_contract):
        fail("Branding email renderer lost its rollback-only real-digest fixture contract.")
    digest_start = "def render_stage4_digest!(user:, welcome_topic:, guidelines_topic:, admin_quick_start_topic:)\n"
    digest_end = "def allow_fixture_admin_login_http?(stage4_fixture:, connect_fixture:, expected_address:)\n"
    if source.count(digest_start) != 1 or source.count(digest_end) != 1:
        fail("Branding email renderer digest-fixture method boundary differs.")
    digest_block = source[source.index(digest_start) : source.index(digest_end)]
    ordered_digest_steps = (
        "    topics.each { |topic| topic.update_columns(created_at: aged_created_at) }\n",
        "    delivery = UserNotifications.digest(user, since: 3.days.ago, skip_unsubscribe_links: true)\n",
        '    mail = materialize(delivery, label: "digest")\n',
        "    digest_text, digest_html = render_parts(mail)\n",
        '    expected_markers = topics.map(&:title) + ["Mochirii staff setup guide"]\n',
        "    mail.encoded\n",
        "    raise ActiveRecord::Rollback\n",
        "  topics.each(&:reload)\n",
        "  unless topics.all? { |topic| topic.created_at == original_created_at.fetch(topic.id) }\n",
    )
    if any(digest_block.count(value) != 1 for value in ordered_digest_steps):
        fail("Branding email renderer lost an exact ordered digest-fixture step.")
    ordered_offsets = [digest_block.index(value) for value in ordered_digest_steps]
    if ordered_offsets != sorted(ordered_offsets):
        fail("Branding email renderer does not encode before rollback and prove exact fixture restoration.")
    if any(value in digest_block for value in ("PostCreator", "Topic.create", "Post.create", ".save!", ".destroy!")):
        fail("Branding email renderer persists digest fixture content.")
    admin_login_contract = (
        "def allow_fixture_admin_login_http?(stage4_fixture:, connect_fixture:, expected_address:)\n",
        '  stage4_fixture == "true" &&\n',
        '    connect_fixture == "true" &&\n',
        '    expected_address == "notifications@fixture.invalid"\n',
        "def verify_admin_login_link!(text_part:, html_part:, expected_base_url:, allow_fixture_http:)\n",
        '  expected_scheme = allow_fixture_http ? "http" : "https"\n',
        "  expected_port = allow_fixture_http ? 80 : 443\n",
        '  expected_path = "/session/email-login/mochirii-fixture-admin-login-token"\n',
        "  expected_text =\n",
        "    <<~TEXT.strip\n",
        "      Somebody asked to log in to your account on [Mochirii Forums](#{expected_base_url}).\n",
        "      If you did not make this request, you can safely ignore this email.\n",
        "      Click the following link to log in:\n",
        "      #{expected_link}\n",
        '  normalized_text = text_part.to_s.gsub("\\r\\n", "\\n").strip\n',
        "  unless expected_origin_exact\n",
        "  unless normalized_text.include?(expected_link)\n",
        "  unless html_part.nil? &&\n",
        "      normalized_text == expected_text\n",
        "      allow_fixture_admin_login_http?(\n",
        '        stage4_fixture: ENV["MOCHIRII_STAGE4_FIXTURE"],\n',
        '        connect_fixture: ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"],\n',
        "    verify_admin_login_link!(\n",
        "      text_part: text_part,\n",
        "      html_part: html_part,\n",
        "      expected_base_url: Discourse.base_url,\n",
        "      allow_fixture_http: allow_fixture_http,\n",
        'admin_confirmation_fixture_token = "0123456789abcdef" * 2\n',
        "unless admin_confirmation_fixture_token.match?(/\\A[0-9a-f]+\\z/) && admin_confirmation_fixture_token.length == 32\n",
        '  raise "Administrator confirmation fixture token changed"\n',
        "      admin_confirmation_fixture_token,\n",
        "  digest_logo = SiteSetting.site_digest_logo_url.to_s\n",
    )
    if any(source.count(value) != 1 for value in admin_login_contract):
        fail("Branding email renderer lost its mode-bound recovery-link, confirmation-token, or digest-logo contract.")
    if "SiteSetting.digest_logo_url" in source or "SecureRandom" in source:
        fail("Branding email renderer retained a stale digest API or generated a real confirmation token.")
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != BRANDING_EMAIL_RENDERER_SHA256:
        fail("Branding email renderer differs from the exact reviewed source digest.")
    require_text(
        read("docs/operations/VALIDATION.md"),
        [
            "HTTP is accepted solely for the explicit",
            "non-fixture verification requires HTTPS",
            "route-valid deterministic administrator-confirmation fixture token",
            "pinned `site_digest_logo_url` accessor",
            "rollback-only age adjustment of the exact controlled seed topics",
            "real `Mail::Message`",
        ],
        "mode-bound administrator recovery-mail validation contract",
    )
    require_text(
        read("docs/operations/RUNTIME-READINESS.md"),
        [
            "HTTP permitted only in the explicit",
            "HTTPS required for every non-fixture runtime",
        ],
        "administrator recovery-mail runtime-readiness contract",
    )
    require_text(
        read("docs/operations/RECOVERY.md"),
        [
            "Production requires the exact HTTPS Forums origin",
            "HTTP is accepted only by the explicit",
        ],
        "administrator recovery-mail operator contract",
    )


def validate_admin_login_link_fixture(source: str) -> None:
    required = (
        "class PermissiveNullMailFixture\n",
        'materialize_marker = "def materialize(delivery, label:)\\n"',
        '  materialize(direct_mail, label: "direct").equal?(direct_mail),',
        '  materialize(lazy_delivery, label: "lazy").equal?(lazy_mail),',
        '  materialize(PermissiveNullMailFixture.new, label: "digest")',
        '    error.message == "digest mail path did not render a Mail::Message",',
        '  raise AdminLoginLinkFixtureError, "permissive NullMail canary was accepted"',
        'method_marker = "def allow_fixture_admin_login_http?(stage4_fixture:, connect_fixture:, expected_address:)\\n"',
        '"partial fixture HTTP authorization was accepted"',
        'fixture_base = "http://forums.mochirii.com"',
        'production_base = "https://forums.mochirii.com"',
        '"exact fixture HTTP mail was rejected"',
        '"exact production HTTPS mail was rejected"',
        '"transport CRLF normalization changed the exact mail"',
        '"duplicate recovery link" =>',
        '"duplicate base link" =>',
        '"production HTTP mode",',
        '"fixture HTTPS mode",',
        '"missing recovery link",',
        '"malformed expected origin",',
        '"foreign host" =>',
        '"nondefault port" =>',
        '"userinfo" =>',
        '"wrong token" =>',
        '"wrong path" =>',
        '"query" =>',
        '"fragment" =>',
        '"unrelated foreign URL" =>',
        '"mixed-case foreign URL" =>',
        '"relative wrong-token path" =>',
        '"uppercase relative path" =>',
        '"uppercase scheme-relative path" =>',
        '"dot-segment relative path" =>',
        '"doubled-separator relative path" =>',
        '"encoded mixed-case relative path" =>',
        '"encoded uppercase relative path" =>',
        '"script-prefixed exact URL" =>',
        '"token suffix after punctuation" =>',
        '"foreign query wrapper" =>',
        '"encoded terminal slash" =>',
        '"encoded route slashes" =>',
        '"encoded route hyphen" =>',
        '"fully encoded route" =>',
        '"fully encoded uppercase route" =>',
        '"overencoded recovery route" =>',
        '"raw HTML scheme-relative anchor" =>',
        '"raw HTML relative anchor" =>',
        '"entity-encoded HTML anchor" =>',
        '"Markdown scheme-relative link" =>',
        '"Markdown relative link" =>',
        '"entity-encoded Markdown link" =>',
        '"site-name drift" =>',
        '"unexpected pre-delivery HTML part",',
        'source.scan("SiteSetting.site_digest_logo_url").length == 1',
        'source.scan("SiteSetting.digest_logo_url").empty?',
        'source.scan(\'admin_confirmation_fixture_token = "0123456789abcdef" * 2\').length == 1',
        'source.scan("SecureRandom").empty?',
        'admin_confirmation_route_token = /\\A[0-9a-f]+\\z/',
        '    admin_confirmation_fixture_token.length == 32,\n',
        '"one-character pinned-route token was rejected"',
        '"long pinned-route token was rejected"',
        '"empty administrator confirmation token" =>',
        '"uppercase administrator confirmation token" =>',
        '"hyphenated administrator confirmation token" =>',
        '"nonhex administrator confirmation token" =>',
        '"short administrator confirmation token" =>',
        '"long administrator confirmation token" =>',
        '"slash administrator confirmation token" =>',
        '"encoded-separator administrator confirmation token" =>',
        '"newline administrator confirmation token" =>',
        'assert_fixture(error.cause.nil?, "#{label} retained an exception cause")',
        'puts "Administrator recovery mail link hostile fixture passed."',
    )
    if any(source.count(value) != 1 for value in required):
        fail("Administrator recovery-link hostile fixture inventory differs.")
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != ADMIN_LOGIN_LINK_FIXTURE_SHA256:
        fail("Administrator recovery-link hostile fixture differs from the exact reviewed source digest.")


def validate_narrative_avatar_fixture(source: str) -> None:
    required = {
        'method_marker = "def configure_narrative_system_user!(icon_upload)\\n"': 1,
        'APP_SETTING = "DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"': 1,
        'assert_fixture(method_source.scan(avatar_write_order).length == 1, "avatar write-order anchor differed")': 1,
        '.sub(avatar_write_order, reordered_avatar_write_order)': 1,
        '"reorder hostile did not invert the exact avatar writes"': 1,
        'app_setting: :false, gravatar_response: :success': 1,
        'app_setting: :true, gravatar_response: :success': 1,
        'app_setting: :omitted, gravatar_response: :success': 1,
        'configure_narrative_system_user_reordered!(icon_upload)': 2,
        'app_setting: :true, gravatar_response: :not_found': 1,
        'Jobs.drain_update_gravatar!': 6,
        'puts "Narrative avatar delayed-job fixture passed."': 1,
    }
    if any(source.count(value) != expected for value, expected in required.items()):
        fail("Narrative avatar delayed-writer hostile inventory differs.")
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != NARRATIVE_AVATAR_FIXTURE_SHA256:
        fail("Narrative avatar hostile fixture differs from the exact reviewed source digest.")


def validate_narrative_avatar_workflow(source: str) -> None:
    start = "      - name: Prove one-effective-CPU command path\n"
    end = "      - name: Bootstrap exact standalone under one effective CPU\n"
    if source.count(start) != 1 or source.count(end) != 1:
        fail("Disposable preflight step boundary differs.")
    step = source[source.index(start) : source.index(end)]
    run_marker = "        run: |\n"
    if step.count(run_marker) != 1 or re.search(r"(?m)^        if:", step[: step.index(run_marker)]):
        fail("Disposable preflight step is conditional or malformed.")
    if (
        source.count(NARRATIVE_AVATAR_WORKFLOW_CALL) != 1
        or step.count(NARRATIVE_AVATAR_WORKFLOW_CALL) != 1
        or source.count(ADMIN_LOGIN_LINK_WORKFLOW_CALL) != 1
        or step.count(ADMIN_LOGIN_LINK_WORKFLOW_CALL) != 1
    ):
        fail("Narrative avatar or administrator-link fixture is not executed exactly once in the required preflight step.")
    if hashlib.sha256(step.encode("utf-8")).hexdigest() != NARRATIVE_AVATAR_WORKFLOW_STEP_SHA256:
        fail("Disposable preflight step differs from the exact reviewed executable body.")


def validate_disposable_restore_command_diagnostics(source: str) -> None:
    step_start = "      - name: Prove supported backup and destructive disposable restore\n"
    step_end = "      - name: Remove fixture secret and private logs\n"
    if source.count(step_start) != 1 or source.count(step_end) != 1:
        fail("Disposable restore diagnostic step boundary differs.")
    step = source[source.index(step_start) : source.index(step_end)]
    helper_start = "          run_fixture_command() {\n"
    helper_end = "          }\n          restore_enabled=false\n"
    if step.count(helper_start) != 1 or step.count(helper_end) != 1:
        fail("Disposable restore diagnostic helper boundary differs.")
    helper = step[
        step.index(helper_start) : step.index(helper_end) + len("          }\n")
    ]
    category_helper = '''          restore_failure_category() {
            case "$1" in
''' + "".join(
        f"              {status}) printf '%s\\n' '{category}' ;;\n"
        for _name, status, category in RESTORED_CHECK_EXIT_CODES
    ) + '''              *) return 1 ;;
            esac
          }
'''
    if step.count(category_helper) != 1:
        fail("Disposable restore fixed-check category mapping differs.")
    expected_markers = (
        "discourse-disable-restore-on-exit",
        "prepare-backup-marker",
        "discourse-backup",
        "post-backup-recovery-marker",
        "discourse-enable-restore",
        "discourse-restore-local",
        "discourse-disable-restore",
        "verify-restored-backup-initial",
        "verify-restored-backup-after-restart",
        "verify-restored-backup-after-rebuild",
    )
    markers = tuple(
        re.findall(r"(?m)^[ ]{10,14}run_fixture_command [0-9]+ '([^']+)' ", step)
    )
    if markers != expected_markers or any(
        re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", marker) is None
        for marker in markers
    ):
        fail("Disposable restore categorical marker inventory differs.")
    marker_guard = "[[ ${marker} =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || return 1"
    suppressed_command = '''timeout "${outer_seconds}" sudo docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app \\
              timeout --signal=TERM --kill-after=15s "${inner_seconds}" "$@" \\
              >/dev/null 2>&1 &'''
    restore_failure_output = '''if [[ ${marker} =~ ^verify-restored-backup-(initial|after-restart|after-rebuild)$ ]] &&
                category="$(restore_failure_category "${status}")"; then
                printf 'DISPOSABLE_FIXTURE_COMMAND_FAILED:%s:%s\\n' "${marker}" "${category}" >&2
              else
                printf 'DISPOSABLE_FIXTURE_COMMAND_FAILED:%s\\n' "${marker}" >&2
              fi'''
    categorical_outputs = (
        "printf 'DISPOSABLE_FIXTURE_COMMAND_CONTAINMENT_FAILED:%s\\n' \"${marker}\" >&2",
        "printf 'DISPOSABLE_FIXTURE_COMMAND_TIMEOUT:%s\\n' \"${marker}\" >&2",
        restore_failure_output,
        "printf 'DISPOSABLE_FIXTURE_COMMAND_PASSED:%s\\n' \"${marker}\"",
    )
    required = (marker_guard, suppressed_command, *categorical_outputs)
    if any(helper.count(value) != 1 for value in required):
        fail("Disposable restore categorical diagnostics or raw-output suppression differs.")
    order = [helper.index(value) for value in required]
    if order != sorted(order):
        fail("Disposable restore categorical diagnostics execute out of order.")
    if (
        re.search(r"(?m)^\s*(?:cat|head|tail|tee)\b", helper)
        or re.search(r"printf[^\n]*\$\{status\}", helper)
    ):
        fail("Disposable restore helper can publish raw command output.")


def validate_pinned_source_verifier(source: str) -> None:
    required = (
        'verify_email_semantics(core["lib/email.rb"])',
        "verify_mail_evidence_manifest(components)",
        "verify_topic_seed_evidence_manifest(components)",
        "verify_restore_evidence_manifest(components)",
        "verify_opensearch_evidence_manifest(components)",
        "verify_opensearch_semantics(core)",
        "verify_login_code_denial_semantics(session_controller)",
        "verify_mail_semantics(core)",
        "verify_topic_seed_semantics(core)",
        "verify_restore_semantics(core)",
        "def verify_mail_evidence_manifest(components: dict) -> None:",
        "def verify_topic_seed_evidence_manifest(components: dict) -> None:",
        "def verify_restore_evidence_manifest(components: dict) -> None:",
        "def verify_opensearch_evidence_manifest(components: dict) -> None:",
        "def verify_opensearch_controller_method(source: bytes) -> None:",
        "def verify_opensearch_semantics(core: dict[str, bytes]) -> None:",
        "PINNED_OPENSEARCH_CONTROLLER_BLOCK = b'''",
        "def verify_mail_semantics(core: dict[str, bytes]) -> None:",
        "def verify_topic_seed_semantics(core: dict[str, bytes]) -> None:",
        "def verify_restore_semantics(core: dict[str, bytes]) -> None:",
        "PINNED_TOPIC_SEED_EVIDENCE = {",
        "PINNED_RESTORE_EVIDENCE = {",
        "PINNED_RESTORE_CLI_OPTION_BLOCK = b'''",
        "PINNED_RESTORE_CLI_PASS_THROUGH_BLOCK = b'''",
        "PINNED_RESTORER_INITIALIZER_BLOCK = b'''",
        "PINNED_RESTORER_MAIL_SUPPRESSION_BLOCK = b'''",
        "PINNED_TOPIC_FIXTURE_SOURCE = b'''",
        "PINNED_ADMIN_QUICK_START_TOPIC_BLOCK = b'''",
        "PINNED_TOPIC_CREATE_GUARD_BLOCK = b'''",
        "PINNED_ADMIN_QUICK_START_RAW_BLOCK = b'''",
        "PINNED_POST_CREATOR_RAW_NORMALIZATION_BLOCK = b'''",
        "PINNED_POST_REVISOR_RAW_NORMALIZATION_BLOCK = b'''",
        "PINNED_TEXT_CLEANER_WHITESPACE_BLOCK = b'''",
        "PINNED_ADMIN_QUICK_START_POST_RAW = (",
        "PINNED_USER_NOTIFICATIONS_DIGEST_BLOCK = b'''",
        "PINNED_TOPIC_FOR_DIGEST_BLOCK = b'''",
        '        PINNED_USER_NOTIFICATIONS_DIGEST_BLOCK,',
        '        core["app/models/topic.rb"],',
        '        PINNED_TOPIC_FOR_DIGEST_BLOCK,',
        "PINNED_ADMIN_LOGIN_METHOD_BLOCK = b'''",
        "PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE = b'''",
        "PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK = b'''",
        "PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK = b'''",
        "PINNED_EMAIL_LOGIN_HELPER_BLOCK = b'''",
        "PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX = b'''",
        "PINNED_MESSAGE_BUILDER_BODY_BLOCK = b'''",
        "PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX = b'''",
        "PINNED_BUILD_EMAIL_HELPER_SOURCE = b'''",
        "PINNED_BASE_PROTOCOL_BLOCK = b'''",
        "PINNED_ADMIN_LOGIN_LOCALE_BLOCK = b'''",
        "PINNED_DIGEST_LOGO_METHOD_BLOCK = b'''",
        'if core["app/mailers/admin_confirmation_mailer.rb"] != PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE:',
        'if core["config/routes.rb"].count(PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK) != 1:',
        'if b"SiteSetting.digest_logo_url" in helper:',
    )
    if any(source.count(value) != 1 for value in required):
        fail("Pinned-source verifier does not execute the exact mail, topic-seed, and OpenSearch semantic gates once.")
    if hashlib.sha256(source.encode("utf-8")).hexdigest() != PINNED_SOURCE_VERIFIER_SHA256:
        fail("Pinned-source verifier differs from the exact reviewed source digest.")


def validate_inventory_paths(
    inventory: list[str] | tuple[str, ...],
    allowed: frozenset[str] = ALLOWED_FILES,
) -> list[str]:
    normalized: list[str] = []
    observed: set[str] = set()
    for value in inventory:
        if not isinstance(value, str) or not value:
            fail("Repository inventory contains an empty or non-text path.")
        relative = value.replace("\\", "/")
        if relative in observed:
            fail(f"Duplicate normalized repository path: {relative}")
        observed.add(relative)
        normalized.append(relative)
    missing = sorted(allowed - observed)
    unexpected = sorted(observed - allowed)
    if missing:
        fail("Required repository files are missing: " + ", ".join(missing))
    if unexpected:
        fail("Unexpected repository files are not allowed: " + ", ".join(unexpected))
    return normalized


def validate_tracked_entry_mode(mode: str, relative: str) -> None:
    if mode != "100644":
        fail(f"Tracked repository entry differs from the exact non-executable source boundary: {relative}")


def enumerate_repository_files() -> list[str]:
    if ARCHIVE_MODE:
        allowed_directories = {
            parent.as_posix()
            for relative in ALLOWED_FILES
            for parent in Path(relative).parents
            if parent.as_posix() != "."
        }
        observed_directories: set[str] = set()
        inventory: list[str] = []
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                fail(f"Archive tree contains a linked or special entry: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                if relative not in allowed_directories:
                    fail(f"Archive tree contains an unexpected directory: {relative}")
                observed_directories.add(relative)
                if os.name != "nt" and metadata.st_mode & 0o022:
                    fail(f"Archive directory is group/other writable: {relative}")
                continue
            if os.name != "nt" and (metadata.st_mode & 0o111 or metadata.st_mode & 0o022):
                fail(f"Archive file mode differs from the exact non-executable source boundary: {relative}")
            inventory.append(relative)
        missing_directories = sorted(allowed_directories - observed_directories)
        if missing_directories:
            fail("Archive tree directories are missing: " + ", ".join(missing_directories))
        return validate_inventory_paths(sorted(inventory))

    completed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail("Unable to enumerate the repository file boundary.")
    try:
        decoded = completed.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("Repository inventory paths are not strict UTF-8.") from error
    fields = decoded.split("\0")
    if not fields or fields[-1] != "":
        fail("Repository inventory did not use the expected NUL-delimited format.")
    inventory = validate_inventory_paths(fields[:-1])

    staged = subprocess.run(
        ["git", "ls-files", "-z", "--stage"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if staged.returncode != 0:
        fail("Unable to inspect tracked repository entry modes.")
    try:
        staged_text = staged.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("Tracked repository metadata is not strict UTF-8.") from error
    staged_fields = staged_text.split("\0")
    if not staged_fields or staged_fields[-1] != "":
        fail("Tracked repository metadata was not NUL-delimited.")
    for entry in staged_fields[:-1]:
        match = re.fullmatch(r"(\d{6}) [0-9a-f]{40} 0\t(.+)", entry, re.DOTALL)
        if match is None:
            fail("Tracked repository metadata is malformed or contains a conflict stage.")
        mode, relative = match.groups()
        validate_tracked_entry_mode(mode, relative)
    return inventory


def validate_path_entry(root: Path, relative: str) -> bytes:
    path = root / Path(*relative.split("/"))
    current = root
    for component in relative.split("/"):
        if component in {"", ".", ".."}:
            fail(f"Repository path contains an unsafe component: {relative}")
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise RuntimeError(f"Repository path cannot be inspected: {relative}") from error
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            fail(f"Symbolic links, junctions, and reparse points are forbidden: {relative}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"Repository inventory entry is not a regular file: {relative}")
    if metadata.st_size > MAX_FILE_BYTES:
        fail(f"Repository file exceeds the 1 MiB limit: {relative}")
    return path.read_bytes()


def _safe_secret_assignment_value(relative: str, name: str, value: str) -> bool:
    candidate = value.strip()
    if candidate.endswith(","):
        candidate = candidate[:-1].rstrip()
    if candidate in {"replace-at-runtime", '"replace-at-runtime"', "''", '""'}:
        return candidate not in {"''", '""'} or (
            relative == "config/runtime.json.example" and name == "FORUMS_DISCOURSE_CONNECT_SECRET"
        )
    if re.fullmatch(r"__MOCHIRII_[A-Z0-9_]+__", candidate):
        return True
    if re.fullmatch(r"\$\{\{\s*github[.]token\s*\}\}", candidate):
        return True
    return candidate == '"$(<"$secret_file")" \\'


def validate_text_contract(relative: str, data: bytes) -> str:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"Repository text is not strict UTF-8: {relative}") from error
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        fail(f"Binary control characters are forbidden: {relative}")
    if not text.endswith("\n"):
        fail(f"Text file must end with one newline: {relative}")
    if re.search(r"(?:\r?\n){2}$", text):
        fail(f"Text file must not end with a blank line: {relative}")
    if text.startswith("version https://git-lfs.github.com/spec/v1"):
        fail(f"Git LFS pointers are forbidden: {relative}")
    for number, line in enumerate(text.splitlines(), start=1):
        if re.search(r"[ \t]+$", line):
            fail(f"Trailing whitespace is forbidden: {relative}:{number}")

        assignment = re.fullmatch(
            r"\s*(?:export\s+)?(?P<name>[A-Z0-9_]*(?:API_KEY|CLIENT_SECRET|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)[A-Z0-9_]*)\s*[:=]\s*(?P<value>.+?)\s*",
            line,
        )
        if assignment is None and relative == "config/certbot-dns.ini.example":
            assignment = re.fullmatch(
                r"\s*(?P<name>dns_[a-z0-9_]*(?:api_token|password|private_key|secret|token))\s*=\s*(?P<value>.+?)\s*",
                line,
            )
        if assignment is None and relative in {
            "config/media-certificate.runtime.json.example",
            "config/runtime.json.example",
        }:
            assignment = re.fullmatch(
                r'\s*"(?P<name>(?:[A-Z0-9_]*(?:API_KEY|CLIENT_SECRET|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)[A-Z0-9_]*|providerApiToken))"\s*:\s*(?P<value>.+?)\s*',
                line,
            )
        if assignment is not None and not _safe_secret_assignment_value(
            relative,
            assignment.group("name"),
            assignment.group("value"),
        ):
            fail(f"Secret-like assignment is forbidden: {relative}:{number}")
    return text


def validate_workflow_contract(relative: str, text: str) -> None:
    for reference in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text):
        if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference):
            fail(f"Workflow action is not pinned by full commit: {relative}: {reference}")
    if re.search(r"(?im)^[ \t]*(?:pull_request_target|'pull_request_target'|\"pull_request_target\")[ \t]*:", text):
        fail(f"pull_request_target is forbidden: {relative}")
    if re.search(r"(?im)^[ \t]+(?:permissions|'permissions'|\"permissions\")[ \t]*:", text):
        fail(f"Job-level workflow permissions are forbidden: {relative}")
    lines = text.splitlines()
    headers = [index for index, line in enumerate(lines) if re.fullmatch(r"permissions:\s*", line)]
    if len(headers) != 1:
        fail(f"Workflow must declare one exact top-level permissions block: {relative}")
    permissions: list[str] = []
    for line in lines[headers[0] + 1 :]:
        if line and not line[0].isspace():
            break
        if line.strip() and not line.lstrip().startswith("#"):
            permissions.append(line)
    if permissions != ["  contents: read"]:
        fail(f"Workflow permissions must equal contents read only: {relative}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            fail(f"Duplicate JSON object key is forbidden: {key}")
        value[key] = item
    return value


def json_shape(value: object) -> object:
    if isinstance(value, dict):
        return ["object", [[key, json_shape(value[key])] for key in sorted(value)]]
    if isinstance(value, list):
        return ["array", [json_shape(item) for item in value]]
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean"]
    if isinstance(value, int):
        return ["integer"]
    if isinstance(value, float):
        return ["number"]
    if isinstance(value, str):
        return ["string"]
    fail(f"Unsupported JSON value type: {type(value).__name__}")


def json_shape_sha256(value: object) -> str:
    encoded = json.dumps(json_shape(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_json_shape_value(
    relative: str,
    value: object,
    expected: dict[str, str] = JSON_SHAPE_SHA256,
) -> None:
    if relative not in expected:
        fail(f"JSON contract is not allowlisted: {relative}")
    if json_shape_sha256(value) != expected[relative]:
        fail(f"JSON object properties or value types changed: {relative}")


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def load(relative: str) -> dict[str, object]:
    value = json.loads(read(relative), object_pairs_hook=_reject_duplicate_json_keys)
    if not isinstance(value, dict):
        fail(f"JSON document must be an object: {relative}")
    validate_json_shape_value(relative, value)
    return value


def require_text(text: str, snippets: list[str], label: str) -> None:
    for snippet in snippets:
        if snippet not in text:
            fail(f"Missing reviewed {label} value: {snippet}")


def yaml_executable_file_contents(
    text: str,
    path: str,
    boundary: str = "  - file:\n",
) -> str:
    marker = (
        "  - file:\n"
        f"      path: {path}\n"
        '      chmod: "+x"\n'
        "      contents: |\n"
    )
    if text.count(marker) != 1:
        fail("Immutable TLS executable file boundary differs.")
    remainder = text.split(marker, 1)[1]
    if boundary not in remainder:
        fail("Immutable TLS executable file has no exact terminal boundary.")
    block, _ = remainder.split(boundary, 1)
    if not block.endswith("\n"):
        fail("Immutable TLS executable file is not final-LF terminated.")
    executable: list[str] = []
    for line in block.splitlines(keepends=True):
        if line == "\n":
            executable.append(line)
        elif line.startswith("        ") and line.endswith("\n"):
            executable.append(line[8:])
        else:
            fail("Immutable TLS executable file indentation differs.")
    return "".join(executable)


def validate_immutable_acme_install_contract(tls: str) -> None:
    if hashlib.sha256(tls.encode("utf-8")).hexdigest() != IMMUTABLE_LETSENCRYPT_FRAGMENT_SHA256:
        fail("Immutable TLS fragment differs from the exact active reviewed structure.")
    configure = yaml_executable_file_contents(tls, "/usr/local/bin/configure-letsencrypt")
    cron = yaml_executable_file_contents(tls, "/usr/local/bin/mochirii-acme-cron")
    letsencrypt = yaml_executable_file_contents(
        tls,
        "/usr/local/bin/letsencrypt",
        "# MOCHIRII TLS RUN END\n",
    )
    if hashlib.sha256(configure.encode("utf-8")).hexdigest() != CONFIGURE_LETSENCRYPT_SHA256:
        fail("Immutable ACME configuration executable differs from the exact reviewed source.")
    exact_install = '''AUTO_UPGRADE=0 NO_DETECT_SH=1 LE_WORKING_DIR="${letsencrypt_dir}" ./acme.sh \\
  --install --nocron --noprofile --log "${letsencrypt_dir}/acme.sh.log" --auto-upgrade 0'''
    exact_reload = "/usr/sbin/nginx -c /etc/nginx/letsencrypt.conf -s reload"
    cron_call = '''env AUTO_UPGRADE=0 LE_WORKING_DIR="${letsencrypt_dir}" \\
  "${letsencrypt_dir}/acme.sh" --cron --home "${letsencrypt_dir}"'''
    rsa_install = '''LE_WORKING_DIR="${letsencrypt_dir}" "${letsencrypt_dir}/acme.sh" \\
  --installcert -d "${DISCOURSE_HOSTNAME}" \\
  --fullchainpath "/shared/ssl/${DISCOURSE_HOSTNAME}.cer" \\
  --keypath "/shared/ssl/${DISCOURSE_HOSTNAME}.key"'''
    ecc_install = '''LE_WORKING_DIR="${letsencrypt_dir}" "${letsencrypt_dir}/acme.sh" \\
  --installcert --ecc -d "${DISCOURSE_HOSTNAME}" \\
  --fullchainpath "/shared/ssl/${DISCOURSE_HOSTNAME}_ecc.cer" \\
  --keypath "/shared/ssl/${DISCOURSE_HOSTNAME}_ecc.key"'''
    private_directory_verification = '''test -d "${letsencrypt_dir}"
test ! -L "${letsencrypt_dir}"
test "$(stat -c '%U:%G %a' -- "${letsencrypt_dir}")" = "root:root 755"'''
    private_directory_normalization = '''if test -e "${letsencrypt_dir}" || test -L "${letsencrypt_dir}"; then
  test -d "${letsencrypt_dir}"
  test ! -L "${letsencrypt_dir}"
  chown root:root -- "${letsencrypt_dir}"
  chmod 0755 -- "${letsencrypt_dir}"
else
  install -d -m 0755 -g root -o root "${letsencrypt_dir}"
fi
test -d "${letsencrypt_dir}"
test ! -L "${letsencrypt_dir}"
test "$(stat -c '%U:%G %a' -- "${letsencrypt_dir}")" = "root:root 755"'''
    private_loop = 'for private_path in "${letsencrypt_dir}/account.conf" "${letsencrypt_dir}/acme.sh.log"; do'
    private_regular = 'test -f "${private_path}"'
    private_nonlink = 'test ! -L "${private_path}"'
    private_combined = f"{private_regular} && {private_nonlink}"
    private_single_link = '''test "$(stat -c '%h' -- "${private_path}")" = "1"'''
    private_metadata = '''test "$(stat -c '%U:%G %a %h' -- "${private_path}")" = "root:root 600 1"'''
    private_preflight = '''for private_path in "${letsencrypt_dir}/account.conf" "${letsencrypt_dir}/acme.sh.log"; do
  if test -e "${private_path}" || test -L "${private_path}"; then
    test -f "${private_path}"
    test ! -L "${private_path}"
    test "$(stat -c '%h' -- "${private_path}")" = "1"
    chown root:root -- "${private_path}"
    chmod 0600 -- "${private_path}"
    test "$(stat -c '%U:%G %a %h' -- "${private_path}")" = "root:root 600 1"
  fi
done'''
    private_post_install = '''for private_path in "${letsencrypt_dir}/account.conf" "${letsencrypt_dir}/acme.sh.log"; do
  test -f "${private_path}"
  test ! -L "${private_path}"
  test "$(stat -c '%h' -- "${private_path}")" = "1"
  chown root:root -- "${private_path}"
  chmod 0600 -- "${private_path}"
  test "$(stat -c '%U:%G %a %h' -- "${private_path}")" = "root:root 600 1"
done'''
    private_verification = '''for private_path in "${letsencrypt_dir}/account.conf" "${letsencrypt_dir}/acme.sh.log"; do
  test -f "${private_path}"
  test ! -L "${private_path}"
  test "$(stat -c '%U:%G %a %h' -- "${private_path}")" = "root:root 600 1"
done'''
    terminal = "exec /usr/local/bin/letsencrypt\n"
    initial_stop = "/usr/sbin/nginx -c /etc/nginx/letsencrypt.conf -s stop"
    if (
        configure.count(exact_install) != 1
        or configure.count("./acme.sh") != 1
        or configure.count("--install") != 1
        or configure.count("NO_DETECT_SH") != 1
        or tls.count("NO_DETECT_SH") != 1
        or tls.count("umask 077") != 3
        or tls.count(private_loop) != 7
        or tls.count(private_regular) != 7
        or tls.count(private_nonlink) != 7
        or private_combined in tls
        or tls.count(private_single_link) != 2
        or tls.count(private_metadata) != 7
        or configure.count(private_directory_normalization) != 1
        or configure.count(private_directory_verification) != 1
        or cron.count(private_directory_verification) != 1
        or letsencrypt.count(private_directory_verification) != 1
        or configure.count(private_preflight) != 1
        or configure.count(private_post_install) != 1
        or configure.count(private_verification) != 1
        or cron.count(private_verification) != 2
        or letsencrypt.count(private_verification) != 2
        or tls.count('chown root:root -- "${private_path}"') != 2
        or tls.count('chmod 0600 -- "${private_path}"') != 2
        or cron.count(cron_call) != 1
        or cron.count(exact_reload) != 1
        or cron.count(f"\n{exact_reload}\n") != 1
        or cron.count("set -euo pipefail") != 1
        or "exec env" in cron
        or letsencrypt.count(rsa_install) != 1
        or letsencrypt.count(ecc_install) != 1
        or letsencrypt.count("--installcert") != 2
        or letsencrypt.count(exact_reload) != 1
        or letsencrypt.count(f"\n{exact_reload}\n") != 1
        or letsencrypt.count(initial_stop) != 1
        or letsencrypt.count("set -euo pipefail") != 1
        or tls.count(exact_reload) != 2
        or "sv reload nginx" in tls
        or "--reloadcmd" in tls
        or configure.index("umask 077") >= configure.index(private_directory_normalization)
        or configure.index(private_directory_normalization) >= configure.index(private_preflight)
        or configure.index(private_preflight) >= configure.index(exact_install)
        or configure.index(exact_install) >= configure.index(private_post_install)
        or configure.index(private_post_install) >= configure.index(private_verification)
        or cron.index(private_directory_verification) >= cron.index(private_verification)
        or cron.index(private_verification) >= cron.index(cron_call)
        or cron.index(cron_call) >= cron.index(exact_reload)
        or cron.index(exact_reload) >= cron.rindex(private_verification)
        or not cron.endswith(private_verification + "\n")
        or letsencrypt.index(private_directory_verification) >= letsencrypt.index(private_verification)
        or letsencrypt.index(private_verification) >= letsencrypt.index(rsa_install)
        or letsencrypt.index(rsa_install) >= letsencrypt.index(ecc_install)
        or letsencrypt.index(ecc_install) >= letsencrypt.index(exact_reload)
        or letsencrypt.index(exact_reload) >= letsencrypt.rindex(private_verification)
        or letsencrypt.rindex(private_verification) >= letsencrypt.index(initial_stop)
        or not configure.endswith(terminal)
        or configure.index(exact_install) >= configure.index(terminal)
    ):
        fail("Immutable ACME installation, reload, or private-state contract differs.")


def validate_acme_host_private_state_contract(host_verifier: str) -> None:
    expected = '''private_acme_directory=/var/discourse/shared/standalone/letsencrypt
[[ -d ${private_acme_directory} && ! -L ${private_acme_directory} ]] || fail "Private ACME runtime directory is absent or linked."
[[ "$(stat -c '%U:%G %a' -- "${private_acme_directory}")" == "root:root 755" ]] || fail "Private ACME runtime directory metadata differs."
for private_acme_path in \\
  /var/discourse/shared/standalone/letsencrypt/account.conf \\
  /var/discourse/shared/standalone/letsencrypt/acme.sh.log; do
  [[ -f ${private_acme_path} && ! -L ${private_acme_path} ]] || fail "Private ACME runtime state is absent or linked."
  [[ "$(stat -c '%U:%G %a %h' -- "${private_acme_path}")" == "root:root 600 1" ]] || fail "Private ACME runtime state metadata differs."
done'''
    if host_verifier.count(expected) != 1:
        fail("Host verification does not bind exact root-private ACME runtime state.")


def validate_stage4_pull_request_template(text: str) -> None:
    require_text(text, list(STAGE4_PR_TEMPLATE_REQUIRED), "Stage 4 pull-request template")
    retired_seed_claims = (
        "Any future upstream-source introduction",
        "No provider, runtime, deployment, cost, hostname, or public-copy change is included",
    )
    if any(claim in text for claim in retired_seed_claims):
        fail("Pull-request template regressed to the retired governance seed boundary.")


def validate_manifests() -> None:
    provenance = load("docs/operations/upstream-provenance.v1.json")
    components = load("docs/operations/third-party-components.v1.json")
    storage = load("docs/operations/storage-policy.v1.json")
    activation = load("docs/operations/activation.v1.json")
    source = load("docs/operations/source-introduction.v1.json")
    identity = load("docs/operations/forum-central-identity.consumer.v1.json")
    cost = load("docs/operations/cost-gate.v1.json")

    if provenance.get("schemaVersion") != 2 or provenance["upstream"]["revision"] != DOCKER_REVISION:
        fail("Deployment-source provenance does not bind the selected revision.")
    if provenance["baseImage"]["linuxAmd64Digest"] != BASE_DIGEST:
        fail("Base-image provenance does not bind the selected AMD64 digest.")
    observation = provenance.get("driftObservation")
    if not isinstance(observation, dict):
        fail("Deployment-source provenance lacks the reviewed main observation.")
    if (
        observation.get("observedAt") != "2026-08-20"
        or observation.get("mainRevision") != OBSERVED_MAIN_REVISION
        or observation.get("mainTree") != OBSERVED_MAIN_TREE
        or observation.get("mainCommitSignatureVerified") is not True
        or observation.get("mainCommitSignatureReason") != "valid"
        or observation.get("comparisonStatus") != "ahead"
        or observation.get("commitsAheadOfPin") != 11
        or observation.get("commitsBehindPin") != 0
        or observation.get("totalCommits") != 11
        or observation.get("baseRevision") != DOCKER_REVISION
        or observation.get("mergeBaseRevision") != DOCKER_REVISION
        or observation.get("pinIsAncestor") is not True
        or observation.get("selectedForRuntime") is not False
        or observation.get("automaticPinUpdateAllowed") is not False
        or observation.get("changedPathInventoryComplete") is not True
        or observation.get("compatibilityReviewComplete") is not False
        or observation.get("reviewStatus") != "drift-detected-separate-review-required"
        or observation.get("changedPaths") != OBSERVED_CHANGED_PATHS
    ):
        fail("Deployment-source main observation or fail-closed disposition changed.")
    range_commits = observation.get("rangeCommits")
    material_scope = observation.get("materialChangeScope")
    if (
        not isinstance(range_commits, list)
        or [entry.get("revision") for entry in range_commits if isinstance(entry, dict)] != OBSERVED_RANGE
        or len(range_commits) != len(OBSERVED_RANGE)
        or not isinstance(material_scope, list)
        or [entry.get("revision") for entry in material_scope if isinstance(entry, dict)] != OBSERVED_RANGE
        or len(material_scope) != len(OBSERVED_RANGE)
        or [entry.get("classification") for entry in material_scope if isinstance(entry, dict)]
        != OBSERVED_MATERIAL_CLASSIFICATIONS
        or any(entry.get("selectedForRuntime") is not False for entry in material_scope if isinstance(entry, dict))
    ):
        fail("Deployment-source drift range or material-change scope changed.")
    if components.get("schemaVersion") != 3:
        fail("Third-party component schema changed.")
    if components["application"]["revision"] != CORE_REVISION:
        fail("Application revision changed.")
    if components["deployment"]["revision"] != DOCKER_REVISION:
        fail("Deployment revision changed.")
    if components["defaultStandaloneComponent"]["revision"] != DOCKER_MANAGER_REVISION:
        fail("Docker Manager revision changed.")
    email_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") == PINNED_EMAIL_EVIDENCE["path"]
    ]
    if email_evidence != [PINNED_EMAIL_EVIDENCE]:
        fail("Pinned email extraction API evidence changed.")
    opensearch_paths = {expected["path"] for expected in PINNED_OPENSEARCH_EVIDENCE}
    opensearch_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in opensearch_paths
    ]
    if opensearch_evidence != PINNED_OPENSEARCH_EVIDENCE:
        fail("Pinned OpenSearch controller and template evidence changed.")
    mail_rendering_paths = {expected["path"] for expected in PINNED_MAIL_RENDERING_EVIDENCE}
    mail_rendering_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in mail_rendering_paths
    ]
    if mail_rendering_evidence != PINNED_MAIL_RENDERING_EVIDENCE:
        fail("Pinned administrator-mail and digest-logo rendering evidence changed.")
    topic_seed_paths = {expected["path"] for expected in PINNED_TOPIC_SEED_EVIDENCE}
    topic_seed_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in topic_seed_paths
    ]
    if topic_seed_evidence != PINNED_TOPIC_SEED_EVIDENCE:
        fail("Pinned topic-seed and administrator-guide evidence changed.")
    restore_paths = {expected["path"] for expected in PINNED_RESTORE_EVIDENCE}
    restore_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in restore_paths
    ]
    if restore_evidence != PINNED_RESTORE_EVIDENCE:
        fail("Pinned restore mail-suppression evidence changed.")
    gravatar_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in {expected["path"] for expected in PINNED_GRAVATAR_EVIDENCE}
    ]
    if gravatar_evidence != PINNED_GRAVATAR_EVIDENCE:
        fail("Pinned automatic Gravatar lifecycle evidence changed.")
    vendored = components.get("vendoredRuntimeComponents")
    if (
        not isinstance(vendored, list)
        or len(vendored) != 1
        or vendored[0].get("revision") != ACME_REVISION
        or vendored[0].get("source", {}).get("sha256") != ACME_SOURCE_SHA256
        or vendored[0].get("encodedSource", {}).get("compressedSha256") != ACME_COMPRESSED_SHA256
        or vendored[0].get("automaticUpdateEnabled") is not False
        or vendored[0].get("onlineExactByteGateRequired") is not True
    ):
        fail("Vendored immutable ACME component contract changed.")
    if components.get("optionalPlugins") != []:
        fail("Optional plugins are forbidden.")
    if components.get("providerMutationAuthorized") is not False or components.get("runtimeActivationEnabled") is not False:
        fail("Stage 4 component state overclaims activation or provider authority.")

    expected_keys = ["original/", "optimized/", "tombstone/"]
    if storage.get("normalUploadKeyFamilies") != expected_keys or storage.get("backupPrefix") != "backups/":
        fail("Storage prefixes differ from pinned single-site behavior.")
    configuration = storage["configuration"]
    expected_storage = {
        "enableS3Uploads": True,
        "regionEnvironmentValue": "whatever",
        "endpoint": "https://sgp1.digitaloceanspaces.com",
        "uploadBucketSetting": "mochirii-forums",
        "backupBucketSetting": "mochirii-forums/backups",
        "cdnUrl": "https://media-forums.mochirii.com",
        "useCdnForAllUploads": True,
        "useAcls": True,
        "installCorsRule": False,
        "directBrowserUploads": False,
        "secureUploads": False,
        "configureTombstonePolicy": False,
        "includeUploadsInBackups": True,
        "applicationAssetCdn": False,
        "uploadAssetsHook": False,
    }
    if configuration != expected_storage:
        fail("Storage configuration manifest changed.")
    if storage.get("allowedUploadExtensions") != ["jpg", "jpeg", "png", "gif", "webp"]:
        fail("Image extension allowlist changed.")
    if storage.get("providerMutationAuthorized") is not False:
        fail("Storage manifest overclaims provider authority.")
    if any(value is not False for value in storage["stage5Gates"].values()):
        fail("Unexecuted Stage 5 storage evidence is marked passed.")
    if any(value is not False for value in activation["stage4"].values()):
        fail("Stage 4 activation ledger records a forbidden mutation.")
    if source.get("providerMutationAuthorized") is not False or source.get("paidResourceAuthorized") is not False:
        fail("Source-introduction manifest overclaims provider or cost authority.")

    fixture = identity.get("stage4BuiltInLoopbackFixture")
    expected_fixture = {
        "workflow": ".github/workflows/disposable-bootstrap.yml",
        "runtimeGeneratedSecretIsLowercaseHex64": True,
        "secretPersistedOrLogged": False,
        "sameSessionValidLoginPassedWhenWorkflowGreen": True,
        "differentSessionDeniedWhenWorkflowGreen": True,
        "invalidSignatureDeniedWhenWorkflowGreen": True,
        "malformedAndDuplicateArgumentsDeniedWhenWorkflowGreen": True,
        "expiredNonceDeniedWhenWorkflowGreen": True,
        "replayedNonceDeniedWhenWorkflowGreen": True,
        "alternateLoginDisabledWhenWorkflowGreen": True,
        "currentHostedEvidence": None,
    }
    if fixture != expected_fixture:
        fail("Built-in DiscourseConnect loopback fixture contract changed.")
    if identity.get("consumer", {}).get("settings", {}).get("automatically_download_gravatars") is not False:
        fail("Consumer identity contract does not disable automatic external Gravatar downloads.")
    if any(value is not False for value in identity["activation"].values()):
        fail("Identity activation overclaims hosted or production evidence.")
    if identity.get("providerMutationAuthorized") is not False or identity.get("publicActivationAuthorized") is not False:
        fail("Identity contract overclaims provider or public activation authority.")

    expected_live_cost_keys = {
        "observedAt",
        "sizeApiPlanAvailableInRegion",
        "sizeApiMonthlyPriceConfirmed",
        "weeklyBackupPriceConfirmed",
        "existingSpacesSubscriptionActive",
        "additionalBucketWithinIncludedQuota",
        "aggregateUsageReviewed",
        "aggregateFixedMonthlyUsd",
        "secondSubscriptionRequired",
        "additionalPaidResourceRequired",
    }
    if set(cost["requiredLiveEvidence"]) != expected_live_cost_keys:
        fail("Live cost evidence contract contains an unsupported or missing gate.")
    if cost.get("providerMutationAuthorized") is not False or cost.get("paidResourceCreated") is not False:
        fail("Cost contract overclaims provider or paid-resource state.")

    for entry in provenance["files"]:
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or entry["bytes"] <= 0:
            fail(f"Invalid deployment evidence: {entry['path']}")
    for group in ("evidenceFiles", "semanticEvidenceFiles"):
        for entry in components["application"][group]:
            if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or entry["bytes"] <= 0:
                fail(f"Invalid application evidence: {entry['path']}")


def validate_opensearch_filter_contract(app: str) -> None:
    outlet_start = "      path: /etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf\n"
    outlet_end = "  # Pups replace is a silent no-op when its source is absent, so bind the exact\n"
    if app.count(outlet_start) != 1 or app.count(outlet_end) != 1:
        fail("Public metadata nginx outlet boundary differs.")
    start = app.index(outlet_start)
    end = app.index(outlet_end, start)
    outlet = app[start:end]
    if (
        outlet.count(OPENSEARCH_FILTER_BLOCK) != 1
        or outlet.count("sub_filter_types application/xml;") != 1
        or "application/opensearchdescription+xml" in outlet
    ):
        fail("OpenSearch nginx replacement is not bound to the pinned application/xml response.")


def validate_html_denial_types_contract(app: str) -> None:
    for name in (
        "mochirii_feed_denied",
        "mochirii_admin_recovery_denied",
        "mochirii_email_login_denied",
    ):
        start_marker = f"        location @{name} {{\n"
        if app.count(start_marker) != 1:
            fail(f"Named HTML denial location differs: {name}.")
        start = app.index(start_marker)
        end = app.find("\n        }", start)
        if end < 0:
            fail(f"Named HTML denial location is unterminated: {name}.")
        block = app[start:end]
        expected = start_marker + "          types { }\n          default_type text/html;"
        if not block.startswith(expected) or block.count("types { }") != 1:
            fail(f"Named HTML denial location does not reset inherited MIME mappings: {name}.")


def validate_login_code_denial_contract(verifier: str) -> None:
    expected = (
        '    if local_status != 404 or any(pattern.search(local_body) for pattern in FORBIDDEN) '
        'or VISIBLE_UPSTREAM.search(local_body):\n'
        '        raise RuntimeError("Disabled local email-code login was not hidden by the pinned not-found boundary.")'
    )
    if verifier.count(expected) != 1 or "local_status != 403" in verifier:
        fail("Local email-code denial does not match the pinned not-found controller boundary.")


def validate_sensitive_response_header_contract(app: str, host_verify: str) -> None:
    if hashlib.sha256(host_verify.encode("utf-8")).hexdigest() != HOST_VERIFY_SOURCE_SHA256:
        fail("Hosted verification source differs from the exact reviewed contract.")

    def contains_unquoted_block_delimiter(line: str) -> bool:
        quote: str | None = None
        escaped = False
        for character in line:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif quote is not None:
                if character == quote:
                    quote = None
            elif character in {'"', "'"}:
                quote = character
            elif character == "#":
                break
            elif character in {"{", "}"}:
                return True
        return False

    def nginx_directives(source: str) -> tuple[str, ...]:
        directives: list[str] = []
        current: list[str] = []
        quote: str | None = None
        escaped = False
        comment = False
        for character in source:
            if comment:
                if character in {"\r", "\n"}:
                    comment = False
                    current.append(" ")
            elif escaped:
                current.append(character)
                escaped = False
            elif character == "\\":
                current.append(character)
                escaped = True
            elif quote is not None:
                current.append(character)
                if character == quote:
                    quote = None
            elif character in {'"', "'"}:
                current.append(character)
                quote = character
            elif character == "#":
                comment = True
            elif character == ";":
                directive = "".join(current).strip()
                if directive:
                    directives.append(directive + ";")
                current = []
            elif character == "{":
                directive = "".join(current).strip()
                if directive:
                    directives.append(directive + " {")
                current = []
            elif character == "}":
                current = []
            else:
                current.append(character)
        return tuple(directives)

    def directive_name(directive: str) -> str:
        token = directive.split(None, 1)[0]
        return token.replace('"', "").replace("'", "").replace("\\", "").lower()

    app_directives = nginx_directives(app)
    if any(
        directive_name(directive) == "proxy_pass_header"
        for directive in app_directives
    ):
        fail("Application template can re-enable an upstream response header.")

    shared_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc\n"
        "      contents: |\n"
    )
    shared_end_marker = "  - file:\n      path: /etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf\n"
    server_scope_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf\n"
        "      contents: |\n"
    )
    server_scope_end_marker = "  - file:\n      path: /etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf\n"
    outlet_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf\n"
        "      contents: |\n"
    )
    outlet_end_marker = "  # Pups replace is a silent no-op when its source is absent, so bind the exact\n"
    avatar_precondition = '''  # Pups replace is a silent no-op when its source is absent, so bind the exact
  # pinned core anchors before applying the two reviewed substitutions.
  - exec:
      cmd:
        - |-
          python3 - <<'PY'
          from pathlib import Path
          source = Path("/etc/nginx/conf.d/discourse.conf").read_text(encoding="utf-8")
          cache_anchor = \'\'\'      proxy_hide_header "Set-Cookie";
                proxy_hide_header "X-Discourse-Username";
                proxy_hide_header "X-Runtime";\'\'\'
          username_log_fragment = \'\'\'"$upstream_http_x_discourse_username" "$upstream_http_x_discourse_trackview"\'\'\'
          if source.count(cache_anchor) != 1:
              raise SystemExit("Pinned cache response-header anchor differs.")
          if source.count(username_log_fragment) != 1:
              raise SystemExit("Pinned nginx username log anchor differs.")
          PY
'''
    avatar_replacement = '''  - replace:
      filename: /etc/nginx/conf.d/discourse.conf
      from: |2-
              proxy_hide_header "Set-Cookie";
              proxy_hide_header "X-Discourse-Username";
              proxy_hide_header "X-Runtime";
      to: |2-
              proxy_hide_header "Set-Cookie";
              proxy_hide_header "X-Discourse-Username";
              proxy_hide_header "X-Runtime";
              include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;
  - replace:
      filename: /etc/nginx/conf.d/discourse.conf
      from: |-
        "$upstream_http_x_discourse_username" "$upstream_http_x_discourse_trackview"
      to: |-
        "-" "$upstream_http_x_discourse_trackview"
'''
    avatar_postcondition = '''  # Prove both replacements took effect before any later run item can continue.
  - exec:
      cmd:
        - |-
          python3 - <<'PY'
          from pathlib import Path
          source = Path("/etc/nginx/conf.d/discourse.conf").read_text(encoding="utf-8")
          cache_anchor = \'\'\'      proxy_hide_header "Set-Cookie";
                proxy_hide_header "X-Discourse-Username";
                proxy_hide_header "X-Runtime";
                include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;\'\'\'
          private_log_fragment = \'\'\'"-" "$upstream_http_x_discourse_trackview"\'\'\'
          if source.count(cache_anchor) != 1:
              raise SystemExit("Pinned cache response-header replacement differs.")
          if source.count(private_log_fragment) != 1 or "$upstream_http_x_discourse_username" in source:
              raise SystemExit("Pinned nginx username log replacement differs.")
          PY
'''
    avatar_build_assertion = '''        - >-
          test "$(grep -Fxc '      include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;'
          /etc/nginx/conf.d/discourse.conf)" -eq 1
        - >-
          test "$(grep -Fo '"-" "$upstream_http_x_discourse_trackview"'
          /etc/nginx/conf.d/discourse.conf | wc -l)" -eq 1
        - >-
          ! grep -Fq '$upstream_http_x_discourse_username'
          /etc/nginx/conf.d/discourse.conf
'''
    if (
        app.count(shared_start_marker) != 1
        or app.count(shared_end_marker) != 1
        or app.count(server_scope_start_marker) != 1
        or app.count(server_scope_end_marker) != 1
        or app.count(outlet_start_marker) != 1
        or app.count(outlet_end_marker) != 1
        or app.count(avatar_precondition) != 1
        or app.count(avatar_replacement) != 1
        or app.count(avatar_postcondition) != 1
        or app.count(avatar_build_assertion) != 1
    ):
        fail("Shared response-header source boundary differs.")
    shared_start = app.index(shared_start_marker) + len(shared_start_marker)
    shared_end = app.index(shared_end_marker, shared_start)
    shared_directives = nginx_directives(app[shared_start:shared_end])
    public_response_headers = {
        "X-Discourse-Route",
        "X-Discourse-Username",
        "X-Discourse-Crawler-View",
        "Discourse-No-Onebox",
        "Discourse-Rate-Limit-Error-Code",
        "Discourse-Xhr-Redirect",
        "Discourse-Actions-Remaining",
        "Discourse-Actions-Max",
        "Discourse-Logged-Out",
        "Discourse-Track-View-Session-Id-Placeholder",
        "X-Discourse-TrackView",
        "X-Discourse-BrowserPageView",
        "X-Discourse-Cached",
    }
    shared_required = {f"proxy_hide_header {name};" for name in public_response_headers}
    if len(shared_directives) != len(shared_required) or set(shared_directives) != shared_required:
        fail("Shared response-header denylist differs from the exact reviewed contract.")
    server_scope_start = app.index(server_scope_start_marker) + len(server_scope_start_marker)
    server_scope_end = app.index(server_scope_end_marker, server_scope_start)
    server_scope_directives = nginx_directives(app[server_scope_start:server_scope_end])
    shared_include = "include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;"
    if server_scope_directives != (shared_include,):
        fail("Server-scope response-header inheritance differs from the exact reviewed contract.")
    outlet_start = app.index(outlet_start_marker) + len(outlet_start_marker)
    outlet_end = app.index(outlet_end_marker, outlet_start)
    outlet_directives = nginx_directives(app[outlet_start:outlet_end])
    outlet_required = {
        shared_include,
        "sub_filter_once off;",
        "sub_filter '<meta name=\"generator\" content=\"Discourse 2026.7.1 - https://github.com/discourse/discourse version cbf996f65aae3da1843224aa624bcd9a225931ac\">' '<meta name=\"generator\" content=\"Mochirii Forums\">';",
        "sub_filter '<Tags>discourse forum</Tags>' '<Tags>Mochirii Forums</Tags>';",
        "sub_filter_types application/xml;",
    }
    if len(outlet_directives) != len(outlet_required) or set(outlet_directives) != outlet_required:
        fail("Discourse outlet source directives differ from the exact reviewed contract.")

    markers = (
        "        location ~* ^/session/sso_login(?:\\.[A-Za-z0-9]+)?/?$ {\n",
        '        location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$" {\n',
    )
    blocks: list[tuple[str, ...]] = []
    for marker in markers:
        if app.count(marker) != 1:
            fail("Sensitive identity location is absent or duplicated.")
        start = app.index(marker)
        end = app.find("\n        }", start)
        if end < 0:
            fail("Sensitive identity location is unterminated.")
        if any(
            contains_unquoted_block_delimiter(line)
            for line in app[start + len(marker):end].splitlines()
        ):
            fail("Sensitive identity location contains a nested block.")
        directives = nginx_directives(app[start + len(marker):end])
        blocks.append(directives)
    exact_headers = {
        "Cache-Control": 'add_header Cache-Control "private, no-store, max-age=0" always;',
        "Pragma": 'add_header Pragma "no-cache" always;',
        "Expires": 'add_header Expires "0" always;',
        "Referrer-Policy": 'add_header Referrer-Policy "no-referrer" always;',
    }
    exact_response_directives = {
        *(f"proxy_hide_header {name};" for name in exact_headers),
        *exact_headers.values(),
    }
    exact_location_directives = {
        "access_log off;",
        "log_not_found off;",
        "error_log /dev/null emerg;",
        *exact_response_directives,
        "expires off;",
        "include conf.d/outlets/discourse/*.conf;",
        "proxy_set_header Host $http_host;",
        'proxy_set_header X-Request-Start "t=${msec}";',
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header X-Forwarded-Proto $thescheme;",
        'proxy_set_header X-Sendfile-Type "";',
        'proxy_set_header X-Accel-Mapping "";',
        'proxy_set_header Client-Ip "";',
        "proxy_pass http://discourse;",
    }
    for index, directives in enumerate(blocks):
        allowed = set(exact_location_directives)
        if index == 1:
            allowed.add('add_header X-Content-Type-Options "nosniff" always;')
        if len(directives) != len(allowed) or set(directives) != allowed:
            fail("Sensitive identity route directives differ from the exact private proxy contract.")
    for name, replacement in exact_headers.items():
        hide = f"proxy_hide_header {name};"
        if (
            app.count(hide) != len(markers)
            or any(
                directives.count(hide) != 1
                or directives.count(replacement) != 1
                or directives.index(hide) > directives.index(replacement)
                or any(
                    directive not in {hide, replacement, "expires off;"}
                    and name.lower() in directive.lower()
                    for directive in directives
                )
                for directives in blocks
            )
        ):
            fail(f"Sensitive identity routes do not exactly replace upstream {name} metadata.")
    file_start_marker = (
        "timeout --signal=TERM --kill-after=5s 60s docker exec -i app python3 -B - "
        "<<'PY_NGINX_FILES' >/dev/null || fail \"Active nginx configuration files differ "
        "from the exact reviewed inventory.\"\n"
    )
    if host_verify.count(file_start_marker) != 1:
        fail("Hosted nginx file verifier is absent or duplicated.")
    file_start = host_verify.index(file_start_marker) + len(file_start_marker)
    file_end = host_verify.find("\nPY_NGINX_FILES\n", file_start)
    if file_end < 0:
        fail("Hosted nginx file verifier is unterminated.")
    try:
        file_source = host_verify[file_start:file_end]
        file_tree = ast.parse(file_source)
    except SyntaxError as error:
        fail(f"Hosted nginx file verifier is not valid Python: {error}")

    def literal_assignment(name: str) -> object:
        assignments = [
            node
            for node in file_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        if len(assignments) != 1:
            fail(f"Hosted nginx file verifier assignment differs: {name}.")
        try:
            return ast.literal_eval(assignments[0].value)
        except (TypeError, ValueError) as error:
            fail(f"Hosted nginx file verifier assignment is not literal: {name}: {error}")

    expected_directories = {
        "/etc/nginx/conf.d": ("discourse.conf", "outlets"),
        "/etc/nginx/conf.d/outlets": ("before-server", "discourse", "server"),
        "/etc/nginx/conf.d/outlets/before-server": (
            "20-redirect-http-to-https.conf",
            "30-ratelimited.conf",
        ),
        "/etc/nginx/conf.d/outlets/discourse": (
            "20-https.conf",
            "30-ratelimited.conf",
            "35-mochirii-public-response-headers.inc",
            "40-mochirii-public-metadata.conf",
        ),
        "/etc/nginx/conf.d/outlets/server": (
            "10-http.conf",
            "20-https.conf",
            "30-offline-page.conf",
            "35-mochirii-public-response-headers.conf",
            "40-mochirii-feed-denial.conf",
        ),
        "/etc/nginx/modules-enabled": (),
        "/etc/nginx/sites-enabled": (),
    }
    expected_files = {
        "/etc/nginx/nginx.conf": (
            "942f01a5cce65339d54ef67df4427768473f26b89e348926c8e65929b7863952",
        ),
        "/etc/nginx/mime.types": (
            "d2404914bf644ebde13c987081c3259bdd40e2e31985b90a77c08e42f64efe4e",
        ),
        "/etc/nginx/conf.d/discourse.conf": (
            "fe954577f31a53e71e6dca29eea779e00744969834d1b5301873cddee77295dc",
        ),
        "/etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc": (
            "27d523e877de6bf78fe392fefa47d9f37efe5586716c745848c6c4e9cb880fd4",
        ),
        "/etc/nginx/conf.d/outlets/before-server/20-redirect-http-to-https.conf": (
            "7bb5588965b9122d7dba2a9cf7ff1c5fd9e933b278eacaf0f88176aa8fd72312",
        ),
        "/etc/nginx/conf.d/outlets/before-server/30-ratelimited.conf": (
            "13a8adb310d300c3e1a4525421c0d28c218617316014baabd583394e10cafd52",
        ),
        "/etc/nginx/conf.d/outlets/discourse/20-https.conf": (
            "cfc7898c735f0ca38c2acaeab9165bcceebe3519db1a19593628d368f5fbba09",
        ),
        "/etc/nginx/conf.d/outlets/discourse/30-ratelimited.conf": (
            "855b446d8b3d803097b970fd14f5696f0395e01464d8518dba152a200d51bfa2",
        ),
        "/etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf": (
            "12bb9c934b236c6885b02f3dbf59d809ce66a5ea75b8522f76f9f59cc626df2e",
        ),
        "/etc/nginx/conf.d/outlets/server/10-http.conf": (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        "/etc/nginx/conf.d/outlets/server/20-https.conf": (
            *EXPECTED_SERVER_TLS_SHA256,
        ),
        "/etc/nginx/conf.d/outlets/server/30-offline-page.conf": (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        "/etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf": (
            "2c5be5f9dc56632ddd56e6af8ca2f08028f515e41179be90c5cfa31ec8cbc566",
        ),
        "/etc/nginx/conf.d/outlets/server/40-mochirii-feed-denial.conf": (
            "c82653d574f1747c7ed0822d1423833af8acc982e8d01df96b9072d2bd8b0c87",
        ),
    }
    if (
        hashlib.sha256(file_source.encode("utf-8")).hexdigest()
        != HOST_NGINX_FILE_VERIFIER_SHA256
        or hashlib.sha256(host_verify[:file_start].encode("utf-8")).hexdigest()
        != HOST_NGINX_FILE_VERIFIER_PREFIX_SHA256
        or literal_assignment("MAX_CONFIG_BYTES") != 1_048_576
        or literal_assignment("MAX_DIRECTORY_ENTRIES") != 32
        or literal_assignment("PINNED_DISCOURSE_USERNAME_LOG_FRAGMENT")
        != '"$upstream_http_x_discourse_username" "$upstream_http_x_discourse_trackview"'
        or literal_assignment("PRIVATE_DISCOURSE_USERNAME_LOG_FRAGMENT")
        != '"-" "$upstream_http_x_discourse_trackview"'
        or literal_assignment("EXPECTED_DIRECTORY_CHILDREN") != expected_directories
        or literal_assignment("EXPECTED_FILE_SHA256") != expected_files
        or file_start > host_verify.index('nginx_log="$(mktemp ')
    ):
        fail("Hosted verification does not bind the exact active nginx file inventory.")
    host_start_marker = 'python3 -B - "${nginx_log}" <<\'PY\' >/dev/null\n'
    if host_verify.count(host_start_marker) != 1:
        fail("Hosted sensitive-location verifier is absent or duplicated.")
    host_start = host_verify.index(host_start_marker) + len(host_start_marker)
    host_end = host_verify.find("\nPY\n", host_start)
    if host_end < 0:
        fail("Hosted sensitive-location verifier is unterminated.")
    try:
        host_source = host_verify[host_start:host_end]
        host_tree = ast.parse(host_source)
    except SyntaxError as error:
        fail(f"Hosted sensitive-location verifier is not valid Python: {error}")
    required_assignments = [
        node
        for node in host_tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "required"
    ]
    expected_required = {
        "access_log off;",
        "log_not_found off;",
        "error_log /dev/null emerg;",
        *(f"proxy_hide_header {name};" for name in exact_headers),
        *exact_headers.values(),
        "expires off;",
        "include conf.d/outlets/discourse/*.conf;",
        "proxy_pass http://discourse;",
        "proxy_set_header Host $http_host;",
        'proxy_set_header X-Request-Start "t=${msec}";',
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header X-Forwarded-Proto $thescheme;",
        'proxy_set_header X-Sendfile-Type "";',
        'proxy_set_header X-Accel-Mapping "";',
        'proxy_set_header Client-Ip "";',
    }
    avatar_assignments = [
        node
        for node in host_tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "avatar_required"
    ]
    log_boundary_assignments = {
        name: [
            node
            for node in host_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        for name in ("private_username_log_fragment", "username_log_variable")
    }
    expected_avatar_required = {
        "brotli_comp_level 6;",
        'proxy_ignore_headers "Set-Cookie";',
        'proxy_hide_header "Set-Cookie";',
        'proxy_hide_header "X-Discourse-Username";',
        'proxy_hide_header "X-Runtime";',
        "include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;",
        "proxy_cache one;",
        'proxy_cache_key "$scheme,$host,$request_uri";',
        "proxy_cache_valid 200 301 302 7d;",
        "proxy_cache_bypass $bypass_cache;",
        "proxy_pass http://discourse;",
        "break;",
    }
    expected_calls = ast.parse(
        'verify_sensitive_location(location_body(callback_marker, "sensitive callback"), "sensitive callback")\n'
        'verify_sensitive_location(\n'
        '    location_body(email_marker, "administrator recovery privacy"),\n'
        '    "administrator recovery",\n'
        '    {\'add_header X-Content-Type-Options "nosniff" always;\'},\n'
        ')\n'
    ).body
    actual_calls = [
        node
        for node in host_tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "verify_sensitive_location"
    ]
    if (
        hashlib.sha256(host_source.encode("utf-8")).hexdigest()
        != HOST_SENSITIVE_RESPONSE_VERIFIER_SHA256
        or len(required_assignments) != 1
        or not isinstance(required_assignments[0].value, ast.Set)
        or ast.literal_eval(required_assignments[0].value) != expected_required
        or len(avatar_assignments) != 1
        or not isinstance(avatar_assignments[0].value, ast.Set)
        or ast.literal_eval(avatar_assignments[0].value) != expected_avatar_required
        or len(log_boundary_assignments["private_username_log_fragment"]) != 1
        or ast.literal_eval(log_boundary_assignments["private_username_log_fragment"][0].value)
        != '"-" "$upstream_http_x_discourse_trackview"'
        or len(log_boundary_assignments["username_log_variable"]) != 1
        or ast.literal_eval(log_boundary_assignments["username_log_variable"][0].value)
        != "$upstream_http_x_discourse_username"
        or [ast.dump(node, include_attributes=False) for node in actual_calls]
        != [ast.dump(node, include_attributes=False) for node in expected_calls]
    ):
        fail("Hosted verification does not reach both exact sensitive response-header contracts.")


def validate_disposable_nginx_response_header_proof(workflow: str) -> None:
    start = "      - name: Verify imported theme, settings, metadata, and mail\n"
    end = "\n      - name: Prove persistent database and supported rebuild\n"
    if workflow.count(start) != 1 or workflow.count(end) != 1:
        fail("Disposable rendered nginx response-header proof boundary differs.")
    proof_start = workflow.index(start)
    proof_end = workflow.index(end, proof_start)
    proof = workflow[proof_start:proof_end]
    required = (
        "set -euo pipefail",
        'Upload.exists?(sha1: "0000000000000000000000000000000000000000")',
        "sudo docker exec app nginx -T",
        "MAX_TRANSCRIPT_BYTES = 4_194_304",
        'directive_name(item) == "proxy_pass_header"',
        'sections("/etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc")',
        'sections("/etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf")',
        'avatar_marker = r"location ~ ^/(svg-sprite/|letter_avatar/|letter_avatar_proxy/|user_avatar|',
        "len(avatar_directives) != len(avatar_required)",
        "rendered nginx cache-accelerated response-header boundary differs",
        "MAX_HEADER_BYTES = 65_536",
        'http.client.HTTPConnection("127.0.0.1", 3000, timeout=10)',
        'routes != ["uploads/show_short"]',
        "--write-out '%{http_code}'",
        "http://127.0.0.1:18080/uploads/short-url/0",
        '[[ "$proxied_status" == "404" ]]',
        "direct inherited proxy response exposed prohibited identity metadata",
    )
    if (
        any(proof.count(value) != 1 for value in required)
        or hashlib.sha256(proof.encode("utf-8")).hexdigest()
        != DISPOSABLE_NGINX_HEADER_PROOF_SHA256
    ):
        fail("Disposable rendered nginx response-header proof differs from the exact reviewed body.")


def validate_disposable_nginx_fixture_final_command_contract(source: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        fail("Disposable Nginx fixture is not valid Python source.")
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "nginx_outlet_syntax_fixture"
    ]
    if len(functions) != 1:
        fail("Disposable Nginx fixture function boundary differs.")
    function = functions[0]
    extractor_assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "extractor"
    ]
    expected_run = ast.parse(
        'subprocess.run([ruby, "-e", extractor, str(rendered), str(prefix)], '
        'stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, '
        'timeout=10, check=False)',
        mode="eval",
    ).body
    extracted_assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "extracted"
    ]
    expected_failure = ast.parse(
        'if extracted.returncode != 0:\n'
        '    raise RuntimeError("Pinned Nginx fixture could not extract the exact outlet inventory.")'
    ).body[0]
    failure_checks = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.If)
        and ast.dump(node, include_attributes=False)
        == ast.dump(expected_failure, include_attributes=False)
    ]
    bound_names: dict[str, list[ast.Name]] = {}
    if len(extractor_assignments) == 1 and len(extracted_assignments) == 1:
        bound_names = {
            name.id: [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Name)
                and node.id == name.id
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ]
            for name in (
                extractor_assignments[0].targets[0],
                extracted_assignments[0].targets[0],
            )
        }
    execution_sequences = 0
    if (
        len(extractor_assignments) == 1
        and len(extracted_assignments) == 1
        and len(failure_checks) == 1
    ):
        for node in ast.walk(function):
            body = getattr(node, "body", None)
            if not isinstance(body, list):
                continue
            execution_sequences += sum(
                body[index] is extractor_assignments[0]
                and body[index + 1] is extracted_assignments[0]
                and body[index + 2] is failure_checks[0]
                for index in range(max(0, len(body) - 2))
            )
    if (
        len(extractor_assignments) != 1
        or not isinstance(extractor_assignments[0].value, ast.Constant)
        or extractor_assignments[0].value.value != DISPOSABLE_NGINX_OUTLET_EXTRACTOR_RUBY
        or len(extracted_assignments) != 1
        or ast.dump(extracted_assignments[0].value, include_attributes=False)
        != ast.dump(expected_run, include_attributes=False)
        or len(failure_checks) != 1
        or len(bound_names.get("extractor", ())) != 1
        or len(bound_names.get("extracted", ())) != 1
        or execution_sequences != 1
    ):
        fail("Disposable Nginx fixture final-command contract differs from the exact executed source.")


def validate_https_consumer_fixture_contract(verifier: str) -> None:
    required = (
        "import atexit",
        "import signal",
        '            "X-Forwarded-Proto": "https",',
        "def read_fixture_force_https() -> bool:",
        "def set_fixture_force_https(enabled: bool) -> None:",
        "class FixtureForceHttpsRestorer:",
        "set_fixture_force_https(self.original)",
        "def fixture_interrupted(signum: int, _frame: object) -> None:",
        "raise SystemExit(128 + signum)",
        "def run_with_fixture_force_https(operation: Callable[[], None]) -> None:",
        "original_force_https = read_fixture_force_https()",
        "restore_force_https = FixtureForceHttpsRestorer(original_force_https)",
        "atexit.register(restore_force_https)",
        "signal.signal(signum, fixture_interrupted)",
        "set_fixture_force_https(True)",
        "restore_force_https()",
        "atexit.unregister(restore_force_https)",
        "signal.signal(signum, handler)",
        '["https://forums.mochirii.com/session/sso_login"]',
        'arguments=("true" if enabled else "false",)',
        "run_with_fixture_force_https(lambda: verify_fixture(args, secret))",
        'print("Built-in DiscourseConnect consumer fixtures passed.")',
    )
    if any(verifier.count(value) != 1 for value in required):
        fail("DiscourseConnect fixture does not bind and restore the production HTTPS callback scheme.")
    if (
        verifier.count('ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"') != 2
        or verifier.count('ARGV.fetch(0) == "true"\' "$1"') != 1
        or verifier.count(
            "    finally:\n"
            "        absence_error: BaseException | None = None\n"
            "        try:\n"
            "            absent = container_operation_absent(token)\n"
            "        except BaseException as error:\n"
            "            absence_error = error\n"
            "            absent = False\n"
            "        if not absent:\n"
            "            stop_fixture_app()\n"
            "            if absence_error is not None:\n"
            "                raise RuntimeError(\n"
            '                    "A disposable in-container fixture absence proof failed."\n'
            "                ) from absence_error"
        )
        != 1
        or verifier.count(
            "        set_fixture_force_https(True)\n"
            "        operation()\n"
            "    finally:\n"
            "        try:\n"
            "            restore_force_https()\n"
            "        finally:"
        )
        != 1
    ):
        fail("DiscourseConnect fixture mutation guard or interrupted survivor proof differs.")
    try:
        tree = ast.parse(verifier)
    except SyntaxError as error:
        fail(f"DiscourseConnect fixture is not valid Python: {error}")

    protected_global_names = {
        "assert_callback_logs_redacted",
        "run_container_runner",
    }
    dynamic_namespace_names = {
        "__builtins__",
        "__import__",
        "compile",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "setattr",
        "vars",
    }
    dynamic_namespace_attributes = {
        "__code__",
        "__dict__",
        "__globals__",
        "__setattr__",
        "f_globals",
    }
    expected_instance_attribute_stores = [
        "cookies",
        "hidden",
        "hidden",
        "hidden",
        "original",
        "parts",
        "pending",
        "pending",
        "port",
    ]
    instance_attribute_stores = [
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ]
    if (
        any(isinstance(node, (ast.Global, ast.Nonlocal)) for node in ast.walk(tree))
        or any(
            isinstance(node, ast.Name) and node.id in dynamic_namespace_names
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.Attribute)
            and (
                node.attr in dynamic_namespace_attributes
                or (
                    node.attr in protected_global_names
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                )
            )
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and not (
                isinstance(node.value, ast.Name)
                and node.value.id == "self"
            )
            for node in ast.walk(tree)
        )
        or sorted(instance_attribute_stores) != expected_instance_attribute_stores
    ):
        fail("DiscourseConnect fixture can mutate a protected global call target.")

    expected_runner_function = ast.parse(
        '''def run_container_runner(
    script: str,
    *,
    arguments: tuple[str, ...] = (),
    input_bytes: bytes | None = None,
    capture_stdout: bool = False,
    classify_sensitive_log_failure: bool = False,
) -> bytes:
    token = secrets.token_hex(16)
    command = [
        "sudo", "docker", "exec", "-i", "-e", f"MOCHIRII_OPERATION_TOKEN={token}",
        "app", "timeout", "--signal=TERM", "--kill-after=10s", "45s",
        "bash", "-lc", script, "bash", *arguments,
    ]
    completed: subprocess.CompletedProcess[bytes] | None = None
    timed_out = False
    try:
        try:
            completed = subprocess.run(
                command,
                input=input_bytes,
                stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        absence_error: BaseException | None = None
        try:
            absent = container_operation_absent(token)
        except BaseException as error:
            absence_error = error
            absent = False
        if not absent:
            stop_fixture_app()
            if absence_error is not None:
                raise RuntimeError(
                    "A disposable in-container fixture absence proof failed."
                ) from absence_error
            raise RuntimeError("A disposable in-container fixture survived its operation boundary.")
    if timed_out or completed is None:
        raise RuntimeError("A disposable in-container fixture failed within its bounded operation.")
    if completed.returncode != 0:
        if classify_sensitive_log_failure:
            category = {
                40: "input",
                41: "identity",
                42: "authenticated-session",
                43: "authentication-audit-shape",
                44: "authentication-audit-marker",
                45: "log-inventory",
                46: "application-log-marker",
                47: "logster-shape",
                48: "logster-marker",
                49: "application-log-identity-marker",
                50: "application-log-callback-marker",
                51: "application-log-recovery-marker",
                52: "application-log-identity-marker-1",
                53: "application-log-identity-marker-2",
                54: "application-log-identity-marker-3",
                55: "application-log-identity-marker-4",
                56: "application-log-identity-marker-5",
                57: "application-log-identity-marker-6",
                58: "application-log-identity-marker-7",
            }.get(completed.returncode)
            if category is not None:
                raise RuntimeError(
                    f"A disposable sensitive-log audit failed closed [category={category}]."
                )
        raise RuntimeError("A disposable in-container fixture failed within its bounded operation.")
    output = completed.stdout or b""
    if len(output) > 16_384:
        raise RuntimeError("A disposable in-container fixture exceeded its output boundary.")
    return output.strip()
'''
    ).body[0]
    expected_sensitive_log_function = ast.parse(
        '''def assert_callback_logs_redacted() -> None:
    marker_records = sorted(CALLBACK_LOG_MARKER_CATEGORIES.items())
    markers = [marker for marker, _category in marker_records]
    if (
        not markers
        or len(markers) > 64
        or set(markers) != CALLBACK_LOG_MARKERS
        or any(len(marker) < 16 or len(marker) > 16_384 for marker in markers)
        or any(category not in {"identity", "callback", "recovery"} for _marker, category in marker_records)
    ):
        raise RuntimeError("Sensitive callback marker inventory is malformed.")
    run_container_runner(
        '/usr/local/bin/rails runner "$MOCHIRII_RELEASE_ASSET_ROOT/verify-sensitive-log-redaction.rb"',
        input_bytes=b"".join(
            category.encode("ascii") + b"\\t" + marker + b"\\n"
            for marker, category in marker_records
        ),
        classify_sensitive_log_failure=True,
    )
    with tempfile.TemporaryFile() as transcript:
        completed = subprocess.run(
            ["timeout", "35", "sudo", "docker", "logs", "--since", "30m", "app"],
            stdin=subprocess.DEVNULL,
            stdout=transcript,
            stderr=subprocess.DEVNULL,
            timeout=40,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("Disposable container log readback failed.")
        size = os.fstat(transcript.fileno()).st_size
        if size > 128 * 1024 * 1024:
            raise RuntimeError("Disposable container log readback exceeded its byte boundary.")
        transcript.seek(0)
        content = transcript.read()
        if sensitive_marker_reached(content, markers):
            raise RuntimeError("A callback secret or member marker reached the container log boundary.")
'''
    ).body[0]
    expected_register_marker_function = ast.parse(
        '''def register_sensitive_marker(value: str | bytes, category: str = "callback") -> None:
    marker = value.encode("ascii") if isinstance(value, str) else value
    existing = CALLBACK_LOG_MARKER_CATEGORIES.get(marker)
    if (
        category not in {"identity", "callback", "recovery"}
        or not 16 <= len(marker) <= 16_384
        or (existing is not None and existing != category)
    ):
        raise RuntimeError("Sensitive callback marker category is malformed.")
    CALLBACK_LOG_MARKERS.add(marker)
    CALLBACK_LOG_MARKER_CATEGORIES[marker] = category
'''
    ).body[0]
    expected_register_recovery_markers_function = ast.parse(
        '''def register_admin_recovery_markers(tokens: tuple[bytes, ...]) -> None:
    for token in tokens:
        encoded = quote(token.decode("ascii"), safe="").encode("ascii")
        register_sensitive_marker(token, "recovery")
        register_sensitive_marker(encoded, "recovery")
        register_sensitive_marker(b"/session/email-login/" + encoded, "recovery")
'''
    ).body[0]
    runner_functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "run_container_runner"
    ]
    sensitive_log_functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "assert_callback_logs_redacted"
    ]
    register_marker_functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "register_sensitive_marker"
    ]
    register_recovery_markers_functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "register_admin_recovery_markers"
    ]
    if (
        len(runner_functions) != 1
        or len(sensitive_log_functions) != 1
        or len(register_marker_functions) != 1
        or len(register_recovery_markers_functions) != 1
    ):
        fail("Sensitive-log failure classification function binding differs.")
    try:
        symbol_root = symtable.symtable(verifier, "verify-discourse-connect.py", "exec")
    except SyntaxError as error:
        fail(f"DiscourseConnect fixture symbol table is invalid: {error}")
    sensitive_log_symbol_tables = [
        table
        for table in symbol_root.get_children()
        if table.get_type() == "function"
        and table.get_name() == "assert_callback_logs_redacted"
        and table.get_lineno() == sensitive_log_functions[0].lineno
    ]
    if len(sensitive_log_symbol_tables) != 1:
        fail("Sensitive-log audit function symbol table differs.")
    runner_symbol = sensitive_log_symbol_tables[0].lookup("run_container_runner")
    marker_category_stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and isinstance(node.value, ast.Name)
        and node.value.id == "CALLBACK_LOG_MARKER_CATEGORIES"
    ]
    marker_inventory_mutations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"CALLBACK_LOG_MARKERS", "CALLBACK_LOG_MARKER_CATEGORIES"}
        and node.func.attr in {"add", "clear", "discard", "pop", "popitem", "remove", "setdefault", "update"}
    ]
    if (
        ast.dump(runner_functions[0], include_attributes=False)
        != ast.dump(expected_runner_function, include_attributes=False)
        or ast.dump(sensitive_log_functions[0], include_attributes=False)
        != ast.dump(expected_sensitive_log_function, include_attributes=False)
        or ast.dump(register_marker_functions[0], include_attributes=False)
        != ast.dump(expected_register_marker_function, include_attributes=False)
        or ast.dump(register_recovery_markers_functions[0], include_attributes=False)
        != ast.dump(expected_register_recovery_markers_function, include_attributes=False)
        or len(marker_category_stores) != 1
        or len(marker_inventory_mutations) != 1
        or marker_inventory_mutations[0].func.attr != "add"
        or marker_inventory_mutations[0].func.value.id != "CALLBACK_LOG_MARKERS"
        or not runner_symbol.is_global()
        or runner_symbol.is_assigned()
        or runner_symbol.is_imported()
        or runner_symbol.is_parameter()
        or runner_symbol.is_nonlocal()
        or runner_symbol.is_free()
    ):
        fail("Sensitive-log failure classification executable Python sequence differs.")
    expected_imports = ast.parse(
        "from __future__ import annotations\n"
        "import argparse\n"
        "import atexit\n"
        "import base64\n"
        "import hashlib\n"
        "import hmac\n"
        "import http.client\n"
        "import json\n"
        "import os\n"
        "import re\n"
        "import secrets\n"
        "import signal\n"
        "import subprocess\n"
        "import tempfile\n"
        "import time\n"
        "from collections.abc import Callable\n"
        "from http.cookies import SimpleCookie\n"
        "from html.parser import HTMLParser\n"
        "from pathlib import Path\n"
        "from urllib.parse import parse_qs, quote, urlencode, urlparse\n"
    ).body
    actual_imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    module_assignments = [
        node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
    ]
    assignment_targets: list[str] = []
    assignment_values: dict[str, ast.expr] = {}
    for node in module_assignments:
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                fail("DiscourseConnect fixture module assignment target differs.")
            assignment_targets.append(node.targets[0].id)
            assignment_values[node.targets[0].id] = node.value
            value = node.value
        else:
            if not isinstance(node.target, ast.Name) or node.value is None:
                fail("DiscourseConnect fixture annotated module assignment differs.")
            assignment_targets.append(node.target.id)
            assignment_values[node.target.id] = node.value
            value = node.value
        for call in (child for child in ast.walk(value) if isinstance(child, ast.Call)):
            if not (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "re"
                and call.func.attr == "compile"
            ):
                fail("DiscourseConnect fixture module constant executes an unexpected call.")
    expected_marker_categories = {
        b"mochirii-stage4-consumer-fixture": "identity",
        b"stage4-fixture@forums.mochirii.com": "identity",
        b"mochirii-s4-test": "identity",
        b"Mochirii Stage 4 Fixture": "identity",
        b"stage4-fixture%40forums.mochirii.com": "identity",
        b"Mochirii%20Stage%204%20Fixture": "identity",
        b"Mochirii+Stage+4+Fixture": "identity",
    }
    try:
        marker_categories = ast.literal_eval(assignment_values["CALLBACK_LOG_MARKER_CATEGORIES"])
        marker_inventory = ast.literal_eval(assignment_values["CALLBACK_LOG_MARKERS"])
    except (KeyError, ValueError, TypeError, SyntaxError) as error:
        raise RuntimeError("Sensitive callback marker constants are not exact literals.") from error
    if marker_categories != expected_marker_categories or marker_inventory != set(expected_marker_categories):
        fail("Sensitive callback marker categories or inventory differ.")
    expected_definition_shape = [
        ("function", "forbidden_response_header_name_category"),
        ("class", "VisibleText"),
        ("function", "register_sensitive_marker"),
        ("function", "register_admin_recovery_markers"),
        ("function", "sensitive_marker_reached"),
        ("class", "Session"),
        ("function", "exactly_one"),
        ("function", "request_nonce"),
        ("function", "callback"),
        ("function", "callback_path"),
        ("function", "assert_branded_error"),
        ("function", "stop_fixture_app"),
        ("function", "container_operation_absent"),
        ("function", "run_container_runner"),
        ("function", "read_fixture_force_https"),
        ("function", "set_fixture_force_https"),
        ("class", "FixtureForceHttpsRestorer"),
        ("function", "fixture_interrupted"),
        ("function", "run_with_fixture_force_https"),
        ("function", "expire_nonce"),
        ("function", "verify_fixture_user"),
        ("function", "admin_recovery_fixture"),
        ("function", "assert_admin_login_form_denied"),
        ("function", "assert_local_login_denied"),
        ("function", "assert_admin_recovery_token_invalid"),
        ("function", "verify_admin_email_recovery"),
        ("function", "json_object"),
        ("function", "verify_exact_fixture_session"),
        ("function", "string_values"),
        ("function", "assert_member_values"),
        ("function", "verify_member_branding"),
        ("function", "assert_callback_logs_redacted"),
        ("function", "verify_fixture"),
        ("function", "main"),
    ]
    actual_definition_shape = [
        ("function" if isinstance(node, ast.FunctionDef) else "class", node.name)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    ]
    expected_top_level_types = (
        [ast.Expr]
        + [type(node) for node in expected_imports]
        + [ast.Assign, ast.Assign, ast.Assign, ast.Assign, ast.Assign, ast.AnnAssign, ast.AnnAssign, ast.Assign]
        + [ast.FunctionDef if kind == "function" else ast.ClassDef
           for kind, _name in expected_definition_shape]
        + [ast.If]
    )
    if (
        not tree.body
        or not isinstance(tree.body[0], ast.Expr)
        or not isinstance(tree.body[0].value, ast.Constant)
        or not isinstance(tree.body[0].value.value, str)
        or [ast.dump(node, include_attributes=False) for node in actual_imports]
        != [ast.dump(node, include_attributes=False) for node in expected_imports]
        or assignment_targets
        != [
            "MAX_BYTES",
            "REQUEST_INTERVAL_SECONDS",
            "FORBIDDEN",
            "VALUE_FORBIDDEN",
            "VISIBLE_UPSTREAM",
            "CALLBACK_LOG_MARKER_CATEGORIES",
            "CALLBACK_LOG_MARKERS",
            "FORBIDDEN_RESPONSE_METADATA",
        ]
        or actual_definition_shape != expected_definition_shape
        or [type(node) for node in tree.body] != expected_top_level_types
        or any(
            not isinstance(
                node,
                (
                    ast.Expr,
                    ast.Import,
                    ast.ImportFrom,
                    ast.Assign,
                    ast.AnnAssign,
                    ast.FunctionDef,
                    ast.ClassDef,
                    ast.If,
                ),
            )
            for node in tree.body
        )
        or any(
            node.decorator_list
            or any(
                isinstance(call, ast.Call)
                for default in [*node.args.defaults, *node.args.kw_defaults]
                if default is not None
                for call in ast.walk(default)
            )
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        or any(
            node.decorator_list
            or any(
                isinstance(call, ast.Call)
                for expression in [*node.bases, *(keyword.value for keyword in node.keywords)]
                for call in ast.walk(expression)
            )
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        )
        or any(
            any(not isinstance(statement, ast.FunctionDef) for statement in node.body)
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        )
        or any(
            isinstance(node, ast.Expr) and index != 0
            for index, node in enumerate(tree.body)
        )
        or any(
            isinstance(node, ast.If) and index != len(tree.body) - 1
            for index, node in enumerate(tree.body)
        )
    ):
        fail("DiscourseConnect fixture module-level execution shape differs.")
    session_classes = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Session"
    ]
    expected_json_get_method = ast.parse(
        '''def get_json(self, path: str) -> tuple[int, dict[str, list[str]], bytes]:
    return self.request(
        "GET",
        path,
        extra_headers={
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
'''
    ).body[0]
    json_get_methods = (
        [
            node
            for node in session_classes[0].body
            if isinstance(node, ast.FunctionDef) and node.name == "get_json"
        ]
        if len(session_classes) == 1
        else []
    )
    if (
        len(json_get_methods) != 1
        or ast.dump(json_get_methods[0], include_attributes=False)
        != ast.dump(expected_json_get_method, include_attributes=False)
    ):
        fail("DiscourseConnect fixture JSON GET boundary differs.")
    session_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "verify_exact_fixture_session"
    ]
    expected_session_function = ast.parse(
        "def verify_exact_fixture_session(\n"
        "    status: int,\n"
        "    body: bytes,\n"
        "    label: str,\n"
        "    *,\n"
        "    require_admin: bool,\n"
        ") -> None:\n"
        "    if status != 200:\n"
        "        raise RuntimeError(f\"{label} did not return an authenticated session.\")\n"
        "    document = json_object(body, label)\n"
        "    current = document.get(\"current_user\")\n"
        "    if not isinstance(current, dict):\n"
        "        raise RuntimeError(f\"{label} omitted its authenticated-user envelope.\")\n"
        "    if current.get(\"username\") != \"mochirii-s4-test\":\n"
        "        raise RuntimeError(f\"{label} established the wrong fixture identity.\")\n"
        "    if current.get(\"admin\") is not require_admin:\n"
        "        raise RuntimeError(f\"{label} administrator authority differed.\")\n"
    ).body[0]
    if (
        len(session_functions) != 1
        or ast.dump(session_functions[0], include_attributes=False)
        != ast.dump(expected_session_function, include_attributes=False)
    ):
        fail("DiscourseConnect fixture authenticated-session envelope contract differs.")
    main_functions = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    ]
    if len(main_functions) != 1:
        fail("DiscourseConnect fixture main entry point differs.")
    main_function = main_functions[0]
    wrapper_name = "run_with_fixture_force_https"
    wrapper_functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == wrapper_name
    ]
    wrapper_aliases = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.alias)
        and (node.asname or node.name.split(".", 1)[0]) == wrapper_name
    ]
    if (
        len(wrapper_functions) != 1
        or wrapper_functions[0] not in tree.body
        or wrapper_functions[0].decorator_list
        or any(
            isinstance(node, ast.Name)
            and node.id == wrapper_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef)) and node.name == wrapper_name
            for node in ast.walk(tree)
        )
        or wrapper_aliases
        or any(
            isinstance(node, ast.ExceptHandler) and node.name == wrapper_name
            for node in ast.walk(tree)
        )
        or any(
            (
                isinstance(node, (ast.MatchAs, ast.MatchStar))
                and node.name == wrapper_name
            )
            or (
                isinstance(node, ast.MatchMapping)
                and node.rest == wrapper_name
            )
            for node in ast.walk(tree)
        )
    ):
        fail("DiscourseConnect fixture HTTPS wrapper binding differs or is shadowed.")
    expected_wrapper_function = ast.parse(
        "def run_with_fixture_force_https(operation: Callable[[], None]) -> None:\n"
        "    original_force_https = read_fixture_force_https()\n"
        "    restore_force_https = FixtureForceHttpsRestorer(original_force_https)\n"
        "    atexit.register(restore_force_https)\n"
        "    previous_handlers: dict[int, object] = {}\n"
        "    try:\n"
        "        for signum in (signal.SIGINT, signal.SIGTERM):\n"
        "            previous_handlers[signum] = signal.signal(signum, fixture_interrupted)\n"
        "        set_fixture_force_https(True)\n"
        "        operation()\n"
        "    finally:\n"
        "        try:\n"
        "            restore_force_https()\n"
        "        finally:\n"
        "            for signum, handler in previous_handlers.items():\n"
        "                signal.signal(signum, handler)\n"
        "        atexit.unregister(restore_force_https)\n"
    ).body[0]
    if ast.dump(wrapper_functions[0], include_attributes=False) != ast.dump(
        expected_wrapper_function, include_attributes=False
    ):
        fail("DiscourseConnect fixture HTTPS wrapper control flow differs.")
    symbol_root = symtable.symtable(verifier, "verify-discourse-connect.py", "exec")
    verify_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "verify_fixture"
    ]
    admin_recovery_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "verify_admin_email_recovery"
    ]
    invalid_admin_token_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "assert_admin_recovery_token_invalid"
    ]
    expected_verify_statement_types = (
        "Assign,Assign,If,Assign,Expr,If,Expr,Expr,Assign,Assign,If,Assign,If,Assign,If,"
        "Assign,Assign,Assign,Assign,Assign,Assign,If,Assign,Expr,Expr,Expr,Assign,Expr,"
        "Assign,Assign,Assign,Expr,Assign,Assign,Assign,Expr,Assign,Expr,Assign,Assign,Assign,"
        "Expr,Assign,Assign,Assign,Expr,Assign,Expr,Assign,If,Assign,Assign,Assign,Expr,Assign,Expr,"
        "Assign,Assign,Assign,Assign,If,Expr,Expr"
    ).split(",")
    if len(verify_functions) != 1:
        fail("DiscourseConnect fixture verification function differs.")
    verify_function = verify_functions[0]
    malformed_callback_indices = [
        index
        for index, node in enumerate(verify_function.body)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "malformed"
    ]
    expected_malformed_callback_statements = ast.parse(
        '''def malformed_callback_fixture(args: argparse.Namespace, secret: bytes) -> None:
    malformed = Session(args.port)
    request_nonce(malformed, secret)
    malformed_value = "<" * 16
    malformed_signature = hmac.new(secret, malformed_value.encode("ascii"), hashlib.sha256).hexdigest()
    status, headers, body = malformed.get(callback_path(malformed_value, malformed_signature))
    assert_branded_error(status, headers, body, 422)
'''
    ).body[0].body
    malformed_start = malformed_callback_indices[0] if len(malformed_callback_indices) == 1 else -1
    malformed_actual = verify_function.body[
        malformed_start : malformed_start + len(expected_malformed_callback_statements)
    ]
    if [ast.dump(node, include_attributes=False) for node in malformed_actual] != [
        ast.dump(node, include_attributes=False) for node in expected_malformed_callback_statements
    ]:
        fail("DiscourseConnect malformed callback fixture differs or is unreachable.")
    if len(admin_recovery_functions) != 1:
        fail("DiscourseConnect administrator recovery verification function differs.")
    admin_recovery_function = admin_recovery_functions[0]
    if len(invalid_admin_token_functions) != 1:
        fail("DiscourseConnect invalid administrator recovery token verifier differs.")
    invalid_admin_token_function = invalid_admin_token_functions[0]
    expected_invalid_admin_token_function = ast.parse(
        '''def assert_admin_recovery_token_invalid(session: Session, path: str, message: str) -> None:
    status, headers, body = session.get_json(path)
    if status == 403:
        return
    success_detail = ""
    category = {
        400: "bad-request",
        401: "unauthorized",
        404: "not-found",
        408: "request-timeout",
        419: "private-denial",
        422: "unprocessable",
        429: "rate-limited",
        500: "internal-error",
        502: "bad-gateway",
        503: "unavailable",
        504: "gateway-timeout",
    }.get(status)
    if category is None:
        if 200 <= status < 300:
            category = "unexpected-success"
            status_category = "ok" if status == 200 else "no-content" if status == 204 else "other"
            content_types = headers.get("content-type", [])
            media_type = (
                content_types[0].partition(";")[0].strip(" \\t").lower()
                if len(content_types) == 1
                else ""
            )
            if media_type == "application/json":
                media_category = "json"
            elif media_type in {"application/xhtml+xml", "text/html"}:
                media_category = "html"
            else:
                media_category = "other"

            def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
                value: dict[str, object] = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError
                    value[key] = item
                return value

            def reject_json_constant(_value: str) -> None:
                raise ValueError

            try:
                document = json.loads(
                    body,
                    object_pairs_hook=unique_json_object,
                    parse_constant=reject_json_constant,
                )
            except (UnicodeDecodeError, ValueError, RecursionError):
                envelope_category = "malformed"
            else:
                requested_token = re.fullmatch(
                    r"/session/email-login/([A-Za-z0-9_-]{20,256})",
                    path,
                )
                if (
                    isinstance(document, dict)
                    and requested_token is not None
                    and document.get("can_login") is True
                    and document.get("token") == requested_token.group(1)
                    and document.get("token_email") == "stage4-fixture@forums.mochirii.com"
                ):
                    envelope_category = "requested-token-current"
                elif (
                    isinstance(document, dict)
                    and document.get("can_login") is False
                    and isinstance(document.get("error"), str)
                ):
                    envelope_category = "invalid-token"
                else:
                    envelope_category = "other"
            success_detail = (
                f"; status={status_category}; media={media_category}; envelope={envelope_category}"
            )
        elif 300 <= status < 400:
            category = "unexpected-redirect"
        elif 400 <= status < 500:
            category = "other-client-error"
        elif 500 <= status < 600:
            category = "other-server-error"
        else:
            category = "invalid-status"
    retry_after = "present" if "retry-after" in headers else "absent"
    raise RuntimeError(
        f"{message} [response={category}{success_detail}; retry-after={retry_after}]"
    )
'''
    ).body[0]
    if ast.dump(invalid_admin_token_function, include_attributes=False) != ast.dump(
        expected_invalid_admin_token_function, include_attributes=False
    ):
        fail("DiscourseConnect invalid administrator recovery token control flow differs.")
    expected_admin_recovery_function = ast.parse(
        '''def verify_admin_email_recovery(port: int, member_session: Session) -> None:
    superseded_token = b""
    token = b""
    recovered = Session(port)
    try:
        superseded_token = admin_recovery_fixture("issue")
        token = admin_recovery_fixture("issue")
        if not re.fullmatch(rb"[A-Za-z0-9_-]{20,256}", token) or not re.fullmatch(
            rb"[A-Za-z0-9_-]{20,256}", superseded_token
        ):
            raise RuntimeError("Admin recovery fixture token is malformed.")
        if token == superseded_token:
            raise RuntimeError("Repeated administrator recovery reused a prior token.")
        register_admin_recovery_markers((superseded_token, token))
        superseded_path = "/session/email-login/" + quote(superseded_token.decode("ascii"), safe="")
        obsolete = Session(port)
        assert_admin_recovery_token_invalid(
            obsolete,
            superseded_path,
            "A superseded administrator recovery token remained valid.",
        )
        path = "/session/email-login/" + quote(token.decode("ascii"), safe="")
        csrf_status, _csrf_headers, csrf_body = recovered.get("/session/csrf.json")
        csrf = json_object(csrf_body, "admin recovery CSRF").get("csrf") if csrf_status == 200 else None
        if not isinstance(csrf, str) or len(csrf) < 32:
            raise RuntimeError("Admin recovery fixture did not obtain a CSRF token.")
        info_status, _info_headers, info_body = recovered.get_json(path)
        info = json_object(info_body, "admin recovery token") if info_status == 200 else {}
        if info.get("can_login") is not True or info.get("token_email") != "stage4-fixture@forums.mochirii.com":
            raise RuntimeError("Pinned admin email-login bypass did not accept the exact fixture administrator.")
        status, _headers, body = recovered.post_form(path, {}, csrf)
        result = json_object(body, "admin recovery login") if status == 200 else {}
        if result.get("error") or result.get("success") != "OK":
            raise RuntimeError("Pinned admin email-login did not establish a session.")
        current_status, _current_headers, current_body = recovered.get("/session/current.json")
        verify_exact_fixture_session(
            current_status,
            current_body,
            "Pinned admin email-login",
            require_admin=True,
        )
        replay = Session(port)
        assert_admin_recovery_token_invalid(
            replay,
            path,
            "Consumed admin recovery token remained reusable.",
        )
        assert_local_login_denied(Session(port))
        assert_admin_login_form_denied(recovered)
    finally:
        admin_recovery_fixture("cleanup")
    for closed_session in (recovered, member_session):
        current_status, _current_headers, _current_body = closed_session.get("/session/current.json")
        if current_status != 404:
            raise RuntimeError("Admin recovery fixture cleanup retained an authenticated session.")
'''
    ).body[0]
    if ast.dump(admin_recovery_function, include_attributes=False) != ast.dump(
        expected_admin_recovery_function, include_attributes=False
    ):
        fail("DiscourseConnect administrator recovery control flow differs.")
    expected_member_session_block = ast.parse(
        'current_status, _current_headers, current_body = valid.get("/session/current.json")\n'
        "verify_exact_fixture_session(\n"
        "    current_status,\n"
        "    current_body,\n"
        '    "Valid consumer callback",\n'
        "    require_admin=False,\n"
        ")\n"
    ).body
    expected_admin_recovery_call_block = ast.parse(
        "verify_admin_email_recovery(args.port, valid)\n"
        "assert_callback_logs_redacted()\n"
    ).body
    expected_duplicate_callback_block = ast.parse(
        '''duplicated = Session(args.port)
duplicate_encoded, duplicate_signature = callback(request_nonce(duplicated, secret), secret)
duplicate_query = (
    "/session/sso_login?"
    + urlencode({"sso": duplicate_encoded})
    + "&sso=%3C&"
    + urlencode({"sig": duplicate_signature})
)
callback_path(duplicate_encoded, duplicate_signature)
status, headers, body = duplicated.get(duplicate_query)
assert_branded_error(status, headers, body, 500)
current_status, _current_headers, _current_body = duplicated.get("/session/current.json")
if current_status != 404:
    raise RuntimeError("The denied duplicate consumer callback unexpectedly authenticated.")
'''
    ).body
    member_session_blocks = [
        verify_function.body[index:index + len(expected_member_session_block)]
        for index in range(len(verify_function.body) - len(expected_member_session_block) + 1)
        if [
            ast.dump(node, include_attributes=False)
            for node in verify_function.body[index:index + len(expected_member_session_block)]
        ]
        == [ast.dump(node, include_attributes=False) for node in expected_member_session_block]
    ]
    admin_recovery_call_blocks = [
        verify_function.body[index:index + len(expected_admin_recovery_call_block)]
        for index in range(len(verify_function.body) - len(expected_admin_recovery_call_block) + 1)
        if [
            ast.dump(node, include_attributes=False)
            for node in verify_function.body[index:index + len(expected_admin_recovery_call_block)]
        ]
        == [ast.dump(node, include_attributes=False) for node in expected_admin_recovery_call_block]
    ]
    duplicate_callback_blocks = [
        verify_function.body[index:index + len(expected_duplicate_callback_block)]
        for index in range(len(verify_function.body) - len(expected_duplicate_callback_block) + 1)
        if [
            ast.dump(node, include_attributes=False)
            for node in verify_function.body[index:index + len(expected_duplicate_callback_block)]
        ]
        == [ast.dump(node, include_attributes=False) for node in expected_duplicate_callback_block]
    ]
    if (
        len(member_session_blocks) != 1
        or len(admin_recovery_call_blocks) != 1
        or len(duplicate_callback_blocks) != 1
    ):
        fail("DiscourseConnect fixture session-envelope call-site contract differs.")
    verify_symbol_tables = [
        table
        for table in symbol_root.get_children()
        if table.get_type() == "function"
        and table.get_name() == "verify_fixture"
        and table.get_lineno() == verify_function.lineno
    ]
    if len(verify_symbol_tables) != 1:
        fail("DiscourseConnect fixture verification symbol table differs.")
    verify_symbol_table = verify_symbol_tables[0]
    name_call_counts: dict[str, int] = {}
    attribute_call_counts: dict[str, int] = {}
    for call in (node for node in ast.walk(verify_function) if isinstance(node, ast.Call)):
        if isinstance(call.func, ast.Name):
            name_call_counts[call.func.id] = name_call_counts.get(call.func.id, 0) + 1
        elif isinstance(call.func, ast.Attribute):
            attribute_call_counts[call.func.attr] = attribute_call_counts.get(call.func.attr, 0) + 1
        else:
            fail("DiscourseConnect fixture verification uses a dynamic call target.")
    for call_name in name_call_counts:
        call_symbol = verify_symbol_table.lookup(call_name)
        if (
            not call_symbol.is_global()
            or call_symbol.is_assigned()
            or call_symbol.is_imported()
            or call_symbol.is_parameter()
            or call_symbol.is_nonlocal()
        ):
            fail("DiscourseConnect fixture verification call target is shadowed.")
    if (
        [type(node).__name__ for node in verify_function.body]
        != expected_verify_statement_types
        or ast.dump(verify_function.body[0], include_attributes=False)
        != ast.dump(ast.parse("signed_out = Session(args.port)").body[0], include_attributes=False)
        or [ast.dump(node, include_attributes=False) for node in verify_function.body[-2:]]
        != [
            ast.dump(node, include_attributes=False)
            for node in ast.parse(
                "verify_admin_email_recovery(args.port, valid)\n"
                "assert_callback_logs_redacted()\n"
            ).body
        ]
        or any(
            isinstance(
                node,
                (
                    ast.Return,
                    ast.Yield,
                    ast.YieldFrom,
                    ast.Await,
                    ast.Try,
                    ast.TryStar,
                    ast.With,
                    ast.AsyncWith,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Match,
                    ast.Import,
                    ast.ImportFrom,
                    ast.Global,
                    ast.Nonlocal,
                    ast.Delete,
                    ast.NamedExpr,
                ),
            )
            for node in ast.walk(verify_function)
        )
        or any(
            not (
                isinstance(node.exc, ast.Call)
                and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == "RuntimeError"
            )
            for node in ast.walk(verify_function)
            if isinstance(node, ast.Raise)
        )
        or name_call_counts
        != {
            "RuntimeError": 8,
            "Session": 10,
            "VisibleText": 1,
            "any": 2,
            "assert_admin_login_form_denied": 1,
            "assert_branded_error": 6,
            "assert_callback_logs_redacted": 1,
            "assert_local_login_denied": 1,
            "callback": 5,
            "callback_path": 8,
            "exactly_one": 1,
            "expire_nonce": 1,
            "isinstance": 1,
            "json_object": 1,
            "len": 1,
            "request_nonce": 6,
            "urlencode": 2,
            "urlparse": 1,
            "verify_admin_email_recovery": 1,
            "verify_exact_fixture_session": 1,
            "verify_fixture_user": 1,
            "verify_member_branding": 1,
        }
        or attribute_call_counts
        != {
            "b64encode": 1,
            "decode": 2,
            "encode": 4,
            "feed": 1,
            "get": 17,
            "hexdigest": 2,
            "issubset": 1,
            "join": 4,
            "lower": 3,
            "new": 2,
            "post_form": 1,
            "replace": 1,
            "request": 1,
            "search": 4,
            "split": 1,
            "strip": 2,
            "token_hex": 1,
        }
    ):
        fail("DiscourseConnect fixture verification reachability differs.")
    main_symbol_tables = [
        table
        for table in symbol_root.get_children()
        if table.get_type() == "function"
        and table.get_name() == "main"
        and table.get_lineno() == main_function.lineno
    ]
    if len(main_symbol_tables) != 1:
        fail("DiscourseConnect fixture main symbol table differs.")
    wrapper_symbol = main_symbol_tables[0].lookup(wrapper_name)
    expected_entrypoint = ast.parse(
        'if __name__ == "__main__":\n'
        "    raise SystemExit(main())\n"
    ).body[0]
    if (
        len(tree.body) < 2
        or tree.body[-2] is not main_function
        or ast.dump(tree.body[-1], include_attributes=False)
        != ast.dump(expected_entrypoint, include_attributes=False)
        or main_function.decorator_list
        or symbol_root.lookup("__name__").is_assigned()
        or symbol_root.lookup("__name__").is_imported()
        or symbol_root.lookup("SystemExit").is_assigned()
        or symbol_root.lookup("SystemExit").is_imported()
    ):
        fail("DiscourseConnect fixture module entry point differs or is shadowed.")
    expected_tail = ast.parse(
        'run_with_fixture_force_https(lambda: verify_fixture(args, secret))\n'
        'print("Built-in DiscourseConnect consumer fixtures passed.")\n'
        "return 0\n"
    ).body
    if (
        len(main_function.body) < len(expected_tail)
        or [ast.dump(node, include_attributes=False) for node in main_function.body[-3:]]
        != [ast.dump(node, include_attributes=False) for node in expected_tail]
        or len([node for node in ast.walk(main_function) if isinstance(node, ast.Return)]) != 1
        or not wrapper_symbol.is_global()
        or wrapper_symbol.is_assigned()
        or wrapper_symbol.is_imported()
        or wrapper_symbol.is_parameter()
        or wrapper_symbol.is_nonlocal()
        or len(
            [
                node
                for node in ast.walk(main_function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "verify_fixture"
            ]
        )
        != 1
    ):
        fail("DiscourseConnect fixture main does not structurally bind cleanup before success.")
    order = tuple(
        verifier.index(value)
        for value in (
            "original_force_https = read_fixture_force_https()",
            "restore_force_https = FixtureForceHttpsRestorer(original_force_https)",
            "atexit.register(restore_force_https)",
            "signal.signal(signum, fixture_interrupted)",
            "set_fixture_force_https(True)",
            "operation()",
            "restore_force_https()",
            "signal.signal(signum, handler)",
            "atexit.unregister(restore_force_https)",
        )
    )
    if (
        order != tuple(sorted(order))
        or verifier.index("signed_out = Session(args.port)")
        >= verifier.index("    assert_callback_logs_redacted()")
    ):
        fail("DiscourseConnect fixture HTTPS setup or restoration order differs.")


SMTP_REQUIRED_STARTTLS_INITIALIZER = '''  - file:
      path: /var/www/discourse/config/initializers/mochirii_required_starttls.rb
      contents: |
        # frozen_string_literal: true

        Rails.application.config.after_initialize do
          configured = ActionMailer::Base.smtp_settings
          unless configured.is_a?(Hash) &&
            configured[:enable_starttls_auto] == true &&
            !configured.key?(:enable_starttls) &&
            !configured.key?(:tls) &&
            !configured.key?(:ssl) &&
            configured[:openssl_verify_mode].to_s == "peer"
            raise "SMTP STARTTLS input contract differs"
          end

          required = configured.dup
          required.delete(:enable_starttls_auto)
          required[:enable_starttls] = true
          ActionMailer::Base.smtp_settings = required.freeze
        end
'''
SMTP_RUNTIME_TRANSPORT_VERIFIER = '''smtp_source = GlobalSetting.smtp_settings
smtp = ActionMailer::Base.smtp_settings
checks["smtp_transport_fail_closed"] =
  smtp_source.is_a?(Hash) &&
    smtp_source[:enable_starttls_auto] == true &&
    !smtp_source.key?(:enable_starttls) &&
    !smtp_source.key?(:tls) &&
    !smtp_source.key?(:ssl) &&
    smtp_source[:openssl_verify_mode].to_s == "peer" &&
    smtp.is_a?(Hash) &&
    smtp[:address] == ENV.fetch("DISCOURSE_SMTP_ADDRESS") &&
    smtp[:port] == ENV.fetch("DISCOURSE_SMTP_PORT").to_i &&
    smtp[:domain] == "forums.mochirii.com" &&
    smtp[:authentication].to_s == ENV.fetch("DISCOURSE_SMTP_AUTHENTICATION") &&
    smtp[:enable_starttls] == true &&
    !smtp.key?(:enable_starttls_auto) &&
    !smtp.key?(:tls) &&
    !smtp.key?(:ssl) &&
    smtp[:openssl_verify_mode].to_s == "peer"
'''


def validate_smtp_transport_contract(app: str, runtime_verifier: str) -> None:
    environment_start = "\nenv:\n"
    environment_end = "\nvolumes:\n"
    if app.count(environment_start) != 1 or app.count(environment_end) != 1:
        fail("Application SMTP environment boundary differs.")
    environment = app[
        app.index(environment_start) + len(environment_start) : app.index(environment_end)
    ]
    required_environment = (
        '  DISCOURSE_SMTP_FORCE_TLS: "false"\n',
        '  DISCOURSE_SMTP_ENABLE_START_TLS: "true"\n',
        '  DISCOURSE_SMTP_OPENSSL_VERIFY_MODE: "peer"\n',
    )
    if any(environment.count(value) != 1 for value in required_environment):
        fail("Application SMTP transport flags are not exact singletons.")
    for key in (
        "DISCOURSE_SMTP_FORCE_TLS",
        "DISCOURSE_SMTP_ENABLE_START_TLS",
        "DISCOURSE_SMTP_OPENSSL_VERIFY_MODE",
    ):
        if len(re.findall(rf"(?m)^  {key}[ \t]*:", environment)) != 1:
            fail("Application SMTP transport contains an alternate or duplicate key.")

    initializer_start = (
        "  - file:\n"
        "      path: /var/www/discourse/config/initializers/mochirii_required_starttls.rb\n"
    )
    initializer_end = (
        "  - file:\n"
        "      path: /var/www/discourse/config/initializers/mochirii_sensitive_parameter_filter.rb\n"
    )
    if app.count(initializer_start) != 1 or app.count(initializer_end) != 1:
        fail("Required STARTTLS initializer boundary differs.")
    initializer = app[app.index(initializer_start) : app.index(initializer_end)]
    if initializer != SMTP_REQUIRED_STARTTLS_INITIALIZER:
        fail("Required STARTTLS initializer differs from the reviewed fail-closed source.")

    runtime_start = "smtp_source = GlobalSetting.smtp_settings\n"
    runtime_end = 'checks["notification_sender_runtime_bound"] =\n'
    if (
        runtime_verifier.count(runtime_start) != 1
        or runtime_verifier.count(runtime_end) != 1
        or runtime_verifier.index(runtime_start) >= runtime_verifier.index(runtime_end)
    ):
        fail("Runtime SMTP transport verifier boundary differs.")
    runtime = runtime_verifier[
        runtime_verifier.index(runtime_start) : runtime_verifier.index(runtime_end)
    ]
    if runtime != SMTP_RUNTIME_TRANSPORT_VERIFIER:
        fail("Runtime SMTP transport verifier differs from the reviewed fail-closed source.")

    documentation_contract = {
        "docs/operations/DEPLOYMENT.md": (
            "mandatory STARTTLS with peer certificate verification",
            "authenticated submission, branded test delivery",
        ),
        "docs/operations/PROVIDER-DNS-TLS.md": (
            "mandatory STARTTLS with peer certificate verification",
            "authenticated\n   submission, and branded test delivery",
        ),
        "docs/operations/RUNTIME-READINESS.md": (
            "mandatory STARTTLS with peer certificate verification",
            "authenticated submission, and branded test delivery",
        ),
        "docs/operations/SECRETS.md": (
            "Existing authenticated STARTTLS submission port",
            "STARTTLS required rather than opportunistic",
            "peer verification enabled",
        ),
    }
    for relative, required in documentation_contract.items():
        source = read(relative)
        if any(value not in source for value in required):
            fail(f"Required STARTTLS documentation differs: {relative}")


def validate_template() -> None:
    app = read("config/app.yml.example")
    validate_smtp_transport_contract(app, read("scripts/verify-site.rb"))
    validate_disposable_nginx_fixture_final_command_contract(
        read("scripts/test-disposable-launcher-guard.py")
    )
    validate_html_denial_types_contract(app)
    validate_sensitive_response_header_contract(app, read("scripts/verify-host.sh"))
    require_text(
        app,
        [
            f'base_image: "discourse/base@{BASE_DIGEST}"',
            f'  version: "{CORE_REVISION}"',
            f"git checkout --detach {DOCKER_MANAGER_REVISION}",
            'DISCOURSE_HOSTNAME: "forums.mochirii.com"',
            'DISCOURSE_LOGIN_REQUIRED: "true"',
            'DISCOURSE_ALLOW_USER_LOCALE: "false"',
            'DISCOURSE_SET_LOCALE_FROM_ACCEPT_LANGUAGE_HEADER: "false"',
            'DISCOURSE_ALLOW_NEW_REGISTRATIONS: "false"',
            'DISCOURSE_ENABLE_LOCAL_LOGINS: "false"',
            'DISCOURSE_ENABLE_DISCOURSE_ID: "false"',
            'DISCOURSE_DISCOURSE_CONNECT_CSRF_PROTECTION: "true"',
            'DISCOURSE_VERBOSE_DISCOURSE_CONNECT_LOGGING: "false"',
            'DISCOURSE_DISABLE_EMAILS: __MOCHIRII_DISABLE_EMAILS__',
            'DISCOURSE_SMTP_FORCE_TLS: "false"',
            'DISCOURSE_SMTP_ENABLE_START_TLS: "true"',
            'DISCOURSE_SMTP_DOMAIN: "forums.mochirii.com"',
            'DISCOURSE_SMTP_OPENSSL_VERIFY_MODE: "peer"',
            'DISCOURSE_SIMPLE_EMAIL_SUBJECT: "false"',
            'DISCOURSE_SEND_OLD_CREDENTIAL_REMINDER_DAYS: "0"',
            'DISCOURSE_SECURE_UPLOADS: "false"',
            'DISCOURSE_ENABLE_DIRECT_S3_UPLOADS: "false"',
            'DISCOURSE_S3_REGION: "whatever"',
            'DISCOURSE_S3_ENDPOINT: "https://sgp1.digitaloceanspaces.com"',
            'DISCOURSE_S3_UPLOAD_BUCKET: "mochirii-forums"',
            'DISCOURSE_S3_BACKUP_BUCKET: "mochirii-forums/backups"',
            'DISCOURSE_S3_CDN_URL: "https://media-forums.mochirii.com"',
            'DISCOURSE_S3_USE_CDN_URL_FOR_ALL_UPLOADS: "true"',
            'DISCOURSE_S3_USE_ACLS: "true"',
            'DISCOURSE_S3_INSTALL_CORS_RULE: "false"',
            'DISCOURSE_S3_CONFIGURE_TOMBSTONE_POLICY: "false"',
            'DISCOURSE_INCLUDE_S3_UPLOADS_IN_BACKUPS: "true"',
            'DISCOURSE_AUTHORIZED_EXTENSIONS: "jpg|jpeg|png|gif|webp"',
            'DISCOURSE_AUTHORIZED_EXTENSIONS_FOR_STAFF: ""',
            'DISCOURSE_ALLOW_STAFF_TO_UPLOAD_ANY_FILE_IN_PM: "false"',
            'DISCOURSE_ALLOW_ALL_ATTACHMENTS_FOR_GROUP_MESSAGES: "false"',
            'DISCOURSE_DISCOURSE_NARRATIVE_BOT_ENABLED: "false"',
            'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"',
            'DISCOURSE_SEND_TL2_PROMOTION_MESSAGE: "false"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: __MOCHIRII_ENABLE_DISCOURSE_CONNECT__',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT_PROVIDER: "false"',
            "<meta name=\"generator\" content=\"Mochirii Forums\">",
            "<Tags>Mochirii Forums</Tags>",
            "include conf.d/outlets/discourse/*.conf;",
            'MOCHIRII_RELEASE_ASSET_ROOT: __MOCHIRII_RELEASE_ASSET_ROOT__',
            'host: __MOCHIRII_RELEASE_ASSET_HOST__',
            'guest: /opt/mochirii-release:ro',
            "for status in 403 422 500 503; do",
            "Access unavailable · Mochirii Forums",
            "Request unavailable · Mochirii Forums",
            "Temporarily unavailable · Mochirii Forums",
            "Rails.application.config.filter_parameters |= %i[email sso sig token]",
            "module MochiriiSensitiveDiscourseLogragePayloadFilter",
            "super(ip: ip, username: nil, **extras)",
            "DiscourseLograge.singleton_class.prepend(MochiriiSensitiveDiscourseLogragePayloadFilter)",
            "module MochiriiSensitiveLogsterEnvironmentFilter",
            'return if key == "username" || key == :username',
            "Logster.singleton_class.prepend(MochiriiSensitiveLogsterEnvironmentFilter)",
            "module MochiriiSensitiveLogsterMessageFilter",
            'scrubbed["params"] = filtered_parameters if scrubbed.key?("params")',
            'scrubbed["REQUEST_URI"] = filtered_path if scrubbed.key?("REQUEST_URI")',
            "Logster::Message.singleton_class.prepend(MochiriiSensitiveLogsterMessageFilter)",
            "module MochiriiSensitiveRequestPathFilter",
            "return FILTERED_EMAIL_LOGIN_PATH if path.match?(EMAIL_LOGIN_PATH)",
            "module MochiriiSensitiveUserAuthTokenAuditFilter",
            "super(info.merge(path: MochiriiSensitiveRequestPathFilter::FILTERED_EMAIL_LOGIN_PATH))",
            "UserAuthToken.singleton_class.prepend(MochiriiSensitiveUserAuthTokenAuditFilter)",
            "location ~* ^/session/sso_login(?:\\.[A-Za-z0-9]+)?/?$",
            'location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$"',
            "location ~* ^/session/email-login/ {",
            "error_page 420 = @mochirii_email_login_denied;",
            "access_log off;",
            "error_log /dev/null emerg;",
            'add_header Referrer-Policy "no-referrer" always;',
            "__MOCHIRII_TLS_ENV__",
            "__MOCHIRII_TLS_HOOKS__",
            "__MOCHIRII_TLS_RUN__",
        ],
        "app template",
    )
    sensitive_initializer = r'''  - file:
      path: /var/www/discourse/config/initializers/mochirii_sensitive_parameter_filter.rb
      contents: |
        # frozen_string_literal: true

        # The DiscourseConnect callback carries the signed payload and signature
        # in its query. Local email-login requests carry a member email, and
        # administrator recovery carries its token in one pinned route segment.
        # Preserve PATH_INFO/routing while redacting only that canonical segment
        # from Rails::Rack::Logger's filtered_path.
        module MochiriiSensitiveRequestPathFilter
          EMAIL_LOGIN_PATH = %r{\A/session/email-login/[A-Za-z0-9_-]{20,256}\z}.freeze
          FILTERED_EMAIL_LOGIN_PATH = "/session/email-login/[FILTERED]".freeze

          def filtered_path
            return FILTERED_EMAIL_LOGIN_PATH if path.match?(EMAIL_LOGIN_PATH)

            super
          end
        end

        # The pinned UserAuthToken generate, rotate, and verbose lookup paths all
        # converge on this durable audit writer. Copy and narrow only its exact
        # canonical recovery-path field; never mutate Rack routing/request state.
        module MochiriiSensitiveUserAuthTokenAuditFilter
          def log(info)
            return super unless info.is_a?(Hash)

            audit_path = info[:path]
            return super unless audit_path.is_a?(String) &&
              audit_path.match?(MochiriiSensitiveRequestPathFilter::EMAIL_LOGIN_PATH)

            super(info.merge(path: MochiriiSensitiveRequestPathFilter::FILTERED_EMAIL_LOGIN_PATH))
          end
        end

        # Pinned Discourse adds the authenticated username to Logster's
        # persisted request environment. Omit only that member identifier while
        # preserving every other supported Logster context field.
        module MochiriiSensitiveLogsterEnvironmentFilter
          def add_to_env(env, key, value)
            return if key == "username" || key == :username

            super
          end
        end

        # Logster independently parses request parameters and copies REQUEST_URI
        # when it persists an error. Replace those raw fields with the same Rails
        # filtered views used by the application logger, or omit them if the
        # filter cannot produce a trusted result.
        module MochiriiSensitiveLogsterMessageFilter
          def populate_env_helper(env)
            scrubbed = super
            return scrubbed unless scrubbed.is_a?(Hash)

            scrubbed.delete("username")
            scrubbed.delete(:username)
            return scrubbed unless env.is_a?(Hash) && env.include?("rack.input")

            begin
              request = ActionDispatch::Request.new(env)
              filtered_parameters = request.filtered_parameters
              filtered_path = request.filtered_path
            rescue StandardError
              scrubbed.delete("params")
              scrubbed.delete("REQUEST_URI")
            else
              scrubbed["params"] = filtered_parameters if scrubbed.key?("params")
              scrubbed["REQUEST_URI"] = filtered_path if scrubbed.key?("REQUEST_URI")
            end

            scrubbed
          end
        end

        ActionDispatch::Request.prepend(MochiriiSensitiveRequestPathFilter) unless
          ActionDispatch::Request.ancestors.include?(MochiriiSensitiveRequestPathFilter)
        Logster.singleton_class.prepend(MochiriiSensitiveLogsterEnvironmentFilter) unless
          Logster.singleton_class.ancestors.include?(MochiriiSensitiveLogsterEnvironmentFilter)
        Logster::Message.singleton_class.prepend(MochiriiSensitiveLogsterMessageFilter) unless
          Logster::Message.singleton_class.ancestors.include?(MochiriiSensitiveLogsterMessageFilter)
        Rails.application.reloader.to_prepare do
          UserAuthToken.singleton_class.prepend(MochiriiSensitiveUserAuthTokenAuditFilter) unless
            UserAuthToken.singleton_class.ancestors.include?(MochiriiSensitiveUserAuthTokenAuditFilter)
        end
        # Pinned Discourse Lograge passes current_user.username to this helper
        # whenever its optional logger is enabled. Preserve every other compact
        # payload field while preventing that identifier from being serialized.
        module MochiriiSensitiveDiscourseLogragePayloadFilter
          def custom_payload(ip:, username:, **extras)
            super(ip: ip, username: nil, **extras)
          end
        end

        DiscourseLograge.singleton_class.prepend(MochiriiSensitiveDiscourseLogragePayloadFilter) unless
          DiscourseLograge.singleton_class.ancestors.include?(MochiriiSensitiveDiscourseLogragePayloadFilter)
        Rails.application.config.filter_parameters |= %i[email sso sig token]
'''
    if app.count(sensitive_initializer) != 1:
        fail("Sensitive request and authentication audit filters differ.")
    if app.index('location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$"') > app.index("location ~* ^/session/email-login/ {"):
        fail("Canonical administrator recovery privacy route is shadowed by its denial boundary.")
    localized_error_copy = '''        - |-
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
    if app.count(localized_error_copy) != 1 or app.count("for status in 403 422 500 503; do") != 1:
        fail("Localized error-page copy is not the exact fail-closed literal command.")
    nginx_log_directory = '''        - >-
          test ! -L /var/log/nginx &&
          install -d -m 0755 -o root -g adm /var/log/nginx &&
          nginx -t'''
    if app.count(nginx_log_directory) != 1 or app.count("install -d -m 0755 -o root -g adm /var/log/nginx") != 1:
        fail("Nginx log directory is not materialized under the exact package contract before validation.")
    tokens = set(re.findall(r"__MOCHIRII_[A-Z0-9_]+__", app))
    if not tokens or any(app.count(token) != 1 for token in tokens):
        fail("Every runtime token must occur exactly once.")
    if app.count("git clone --no-tags") != 1 or "discourse/docker_manager.git" not in app:
        fail("Only the pinned default Docker Manager clone is permitted.")
    validate_narrative_avatar_contract(
        app,
        read("scripts/configure-site.rb"),
        read("scripts/verify-site.rb"),
    )
    validate_opensearch_filter_contract(app)

    forbidden = [
        r"(?m)^\s*DISCOURSE_CDN_URL:",
        r"(?m)^\s*DISCOURSE_USE_S3:",
        r"(?m)^\s*DISCOURSE_S3_BUCKET:",
        r"s3:upload_assets",
        r"DISCOURSE_SECURE_UPLOADS:\s*[\"']?true",
        r"DISCOURSE_ENABLE_DIRECT_S3_UPLOADS:\s*[\"']?true",
        r"DISCOURSE_S3_INSTALL_CORS_RULE:\s*[\"']?true",
        r"DISCOURSE_S3_CONFIGURE_TOMBSTONE_POLICY:\s*[\"']?true",
        r"DISCOURSE_S3_USE_IAM_PROFILE:",
        r"DISCOURSE_S3_ROLE_ARN:",
        r"amazonaws\.com",
    ]
    for pattern in forbidden:
        if re.search(pattern, app, re.I):
            fail(f"Forbidden storage or provider configuration matched: {pattern}")

    tls = read("config/immutable-letsencrypt.fragment.yml")
    validate_immutable_acme_install_contract(tls)
    expected_tls_outlet_rewrite = r'''        sed -Ei "s/ssl_certificate .+/ssl_certificate \/shared\/ssl\/${DISCOURSE_HOSTNAME}.cer;\
          ssl_certificate \/shared\/ssl\/${DISCOURSE_HOSTNAME}_ecc.cer;/" \
          /etc/nginx/conf.d/outlets/server/20-https.conf
        sed -Ei "s/ssl_certificate_key .+/ssl_certificate_key \/shared\/ssl\/${DISCOURSE_HOSTNAME}.key; \
          ssl_certificate_key \/shared\/ssl\/${DISCOURSE_HOSTNAME}_ecc.key;/" \
          /etc/nginx/conf.d/outlets/server/20-https.conf'''
    if tls.count(expected_tls_outlet_rewrite) != 1:
        fail("Immutable TLS certificate rewrites differ from the exact reviewed outlet states.")
    require_text(
        tls,
        [
            "acme-sh-3.0.6.gz.b64",
            ACME_SOURCE_SHA256,
            ACME_COMPRESSED_SHA256,
            "--install --nocron --noprofile",
            "--auto-upgrade 0",
            "NO_DETECT_SH=1",
            'grep -Eq "^AUTO_UPGRADE=',
            "/usr/local/bin/mochirii-acme-cron",
        ],
        "immutable Forums TLS integration",
    )
    if "web.letsencrypt.ssl.template.yml" in app or "curl " in tls or "--upgrade" in tls:
        fail("Forums TLS integration reintroduced floating executable source or automatic upgrade.")
    encoded_text = read("config/acme-sh-3.0.6.gz.b64")
    encoded_lines = encoded_text.splitlines()
    if (
        not encoded_text.endswith("\n")
        or not encoded_lines
        or any(not 1 <= len(line) <= 76 for line in encoded_lines)
        or any(len(line) != 76 for line in encoded_lines[:-1])
    ):
        fail("Vendored immutable ACME encoding differs from the exact line boundary.")
    try:
        compressed = base64.b64decode("".join(encoded_lines), validate=True)
        source = gzip.decompress(compressed)
    except (ValueError, gzip.BadGzipFile) as error:
        raise RuntimeError("Vendored immutable ACME payload cannot be decoded exactly.") from error
    if (
        len(compressed) != 50641
        or hashlib.sha256(compressed).hexdigest() != ACME_COMPRESSED_SHA256
        or len(source) != 220764
        or hashlib.sha256(source).hexdigest() != ACME_SOURCE_SHA256
    ):
        fail("Vendored immutable ACME payload bytes differ.")
    license_bytes = (ROOT / "config/acme-sh-3.0.6.LICENSE.md").read_bytes()
    if len(license_bytes) != 35149 or hashlib.sha256(license_bytes).hexdigest() != "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986":
        fail("Vendored ACME license bytes differ.")


def validate_theme_and_public_source() -> None:
    about = load("theme/mochirii/about.json")
    if about.get("name") != "Mochirii Forums" or about.get("minimum_discourse_version") != "2026.7.1":
        fail("Theme metadata changed.")
    if sorted(about.get("assets", {}).values()) != sorted(path.removeprefix("theme/mochirii/") for path in THEME_ASSETS):
        fail("Theme asset allowlist changed.")
    for relative, (expected_bytes, expected_digest) in THEME_ASSETS.items():
        data = (ROOT / relative).read_bytes()
        if len(data) != expected_bytes or hashlib.sha256(data).hexdigest() != expected_digest:
            fail(f"Theme asset digest changed: {relative}")
    notice = read("theme/mochirii/javascripts/discourse/connectors/composer-fields-below/mochirii-upload-notice.hbs")
    expected_notice = "Direct upload URLs may be accessed without a forum session. Do not upload confidential material."
    if expected_notice not in notice:
        fail("The mandatory public-upload notice changed.")
    validate_theme_runtime_verifier(read("scripts/verify-site.rb"))
    validate_branding_email_renderer(read("scripts/render-branding-email.rb"))
    validate_admin_login_link_fixture(read("scripts/test-admin-login-link.rb"))
    for relative in (
        "theme/mochirii/common/head_tag.html",
        "theme/mochirii/common/footer.html",
        "theme/mochirii/common/common.scss",
        "theme/mochirii/locales/en.yml",
        "theme/mochirii/javascripts/discourse/connectors/composer-fields-below/mochirii-upload-notice.hbs",
    ):
        value = read(relative)
        if re.search(r"digitalocean|amazonaws\.com|powered by discourse|discourse\.org", value, re.I):
            fail(f"Public theme source exposes provider or upstream branding: {relative}")

    public_branding = read("scripts/verify-public-branding.py")
    require_text(
        public_branding,
        [
            "def exposes_signed_credential(value: str) -> bool:",
            "unquote(candidate)",
            "html.unescape(candidate)",
            "JSON_ASCII_ESCAPE.sub(",
            "SIGNED_CREDENTIAL_MARKER.search(candidate)",
            "x-amz-(?:algorithm|credential|date|expires|security-token|signature|signedheaders)",
            "awsaccesskeyid",
            "authorization\\s*[=:]\\s*aws4-hmac-sha256",
            'opensearch_type.split(";", 1)[0].strip().lower() != "application/xml"',
            "OpenSearch metadata did not use the pinned XML response type.",
        ],
        "bounded public signed-credential decoding",
    )
    branding_contracts = read("scripts/test-contracts.py")
    require_text(
        branding_contracts,
        [
            "test_public_branding_signed_credential_boundary",
            "X-Amz-Credential=fixture/20260815/sgp1/s3/aws4_request",
            "x-aMz-SiGnAtUrE=deadbeef",
            "X-AMZ-SECURITY-TOKEN=fixture",
            "AWSAccessKeyId=fixture",
            "X%2dAmz%2dCredential%3dfixture",
            "x&#45;amz&#45;signature=deadbeef",
            'X\\u002dAmz\\u002dSecurity\\u002dToken',
            "x-amz-request-id: fixture-request-id",
        ],
        "public signed-credential hostile fixtures",
    )

    operational_plugin = read("plugins/mochirii_email_metadata/plugin.rb")
    require_text(
        operational_plugin,
        [
            'HEALTH_STATE_KEY = "mochirii-runtime-health-sidekiq-probe".freeze',
            "HEALTH_LEASE_GRACE_SECONDS = 30",
            "HEALTH_JOB_BIND_SECONDS = 5",
            "HEALTH_NONCE_PATTERN",
            "HEALTH_JID_PATTERN",
            "HEALTH_PREPARING_PATTERN",
            "HEALTH_FAILURE_STATES",
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
            "Process::CLOCK_MONOTONIC",
            'raise SidekiqProbeError.new("marker-mismatch")',
            'raise SidekiqProbeError.new("job-reported-failure")',
            "return true if classify_health_probe_timeout(jid) == :completed",
            "ensure\n      clear_health_probe!(token, jid) if health_probe_owned",
            "state == started",
            "return unless state == pending",
            "transition_health_probe(started, completed)",
            "transition_health_probe(started, failed)",
            "raise MochiriiEmailMetadata::SidekiqProbeJobError.new, cause: nil",
        ],
        "leased state-only first-party Sidekiq execution probe",
    )
    expected_sidekiq_states = {
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
    state_block = re.search(r"HEALTH_FAILURE_STATES\s*=\s*%w\[(.*?)\][.]freeze", operational_plugin, re.S)
    if state_block is None or set(state_block.group(1).split()) != expected_sidekiq_states:
        fail("Sidekiq processing diagnostics differ from the exact fixed-state allowlist.")
    verifier_method = operational_plugin[
        operational_plugin.index("def self.verify_sidekiq_processing!") : operational_plugin.index("module ::Jobs")
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
    if [verifier_method.index(value) for value in verifier_order] != sorted(
        verifier_method.index(value) for value in verifier_order
    ):
        fail("Sidekiq lease claim, enqueue, JID binding, and observation ordering differs.")
    transition_block = operational_plugin[
        operational_plugin.index("def self.transition_health_probe") : operational_plugin.index("def self.claim_health_probe!")
    ]
    cleanup_block = operational_plugin[
        operational_plugin.index("def self.clear_health_probe!") : operational_plugin.index("def self.expected_health_phase")
    ]
    if ".to_i" in transition_block or ".to_i" in cleanup_block:
        fail("Sidekiq Lua outcomes regained Ruby truthiness coercion.")
    if "health_probe_state" in cleanup_block:
        fail("Sidekiq cleanup regained a post-delete global-read race.")
    if operational_plugin.count("redis.without_namespace") != 2:
        fail("Sidekiq Lua operations are not bound to the exact physical namespaced key.")
    if any(value in operational_plugin for value in ('redis.call("set", KEYS[1], ARGV[2], "EX"', "Discourse.redis.del")):
        fail("Sidekiq state transitions can extend the lease or delete without ownership.")
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
            operational_plugin,
            re.S,
        )
        if script_match is None:
            fail(f"{constant} is absent from the Sidekiq probe.")
        actual_script = "\n".join(
            line[8:] if line.startswith(" " * 8) else line for line in script_match.group(1).splitlines()
        )
        if actual_script != expected_script:
            fail(f"{constant} differs from its exact fail-closed Lua body.")
    job = operational_plugin[operational_plugin.index("class MochiriiSidekiqProcessingProbe") :]
    if not (
        job.index("state == started") < job.index("return unless state == pending")
        and job.index("transition_health_probe(pending, started)") < job.index("transition_health_probe(started, completed)")
        and job.index("rescue StandardError") < job.index("transition_health_probe(started, failed)")
    ):
        fail("Sidekiq same-JID resume, completion, or fixed retry ordering differs.")
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
        if unsafe in operational_plugin:
            fail("Sidekiq processing diagnostics inspect or emit an unsafe value.")
    sidekiq_fixture = read("scripts/test-sidekiq-processing-probe.rb")
    require_text(
        sidekiq_fixture,
        [
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
        ],
        "Sidekiq lease, cleanup, retry, concurrency, and redaction hostile fixture",
    )
    fake_redis_set = sidekiq_fixture[
        sidekiq_fixture.index("def set(key, value, nx:, ex:)") : sidekiq_fixture.index("def transition(key, arguments)")
    ]
    if (
        fake_redis_set.count("expire_if_needed(canonical)") != 1
        or fake_redis_set.index("expire_if_needed(canonical)")
        > fake_redis_set.index("return nil if nx && @store.key?(canonical)")
    ):
        fail("Sidekiq hostile Redis model does not expire a due key before its NX claim.")
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
        require_text(read(document), required_values, f"Sidekiq diagnostic operations contract in {document}")
    for verifier in ("scripts/verify-site.rb", "scripts/verify-restored-backup.rb"):
        validate_sidekiq_runtime_verifier(read(verifier), verifier)


def validate_secrets_and_workflows() -> None:
    relative_files = enumerate_repository_files()
    generated = sorted(
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if "__pycache__" in path.parts or (path.is_file() and path.suffix in {".pyc", ".pyo"})
    )
    if generated:
        fail("Generated Python cache entered the worktree: " + ", ".join(generated))
    json_contracts = {
        relative
        for relative in ALLOWED_FILES
        if relative.endswith(".json") or relative.endswith(".json.example")
    }
    if json_contracts != set(JSON_SHAPE_SHA256):
        fail("The exact JSON-contract inventory and shape allowlist differ.")

    secret_patterns = (
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
        re.compile(rb"AKIA[0-9A-Z]{16}"),
    )
    text_files: dict[str, str] = {}
    for relative in relative_files:
        data = validate_path_entry(ROOT, relative)
        if any(pattern.search(data) for pattern in secret_patterns):
            fail(f"Credential-like material detected: {relative}")
        if relative in THEME_ASSETS:
            expected_bytes, expected_digest = THEME_ASSETS[relative]
            if len(data) != expected_bytes or hashlib.sha256(data).hexdigest() != expected_digest:
                fail(f"Allowlisted binary asset bytes changed: {relative}")
            continue
        text = validate_text_contract(relative, data)
        text_files[relative] = text
        if relative.startswith(".github/workflows/") and relative.endswith((".yml", ".yaml")):
            validate_workflow_contract(relative, text)

    validation_workflow = text_files[".github/workflows/validate-repository.yml"]
    trusted_marker = "  trusted-online-pins:"
    if trusted_marker not in validation_workflow:
        fail("Trusted authenticated online pin gate is absent.")
    pull_controlled, trusted_online = validation_workflow.split(trusted_marker, 1)
    if (
        "GITHUB_TOKEN: ${{ github.token }}" in pull_controlled
        or "run: ./scripts/check-repository.ps1 -Online" in pull_controlled
        or "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" not in trusted_online
        or "GITHUB_TOKEN: ${{ github.token }}" not in trusted_online
        or "run: ./scripts/check-repository.ps1 -Online" not in trusted_online
    ):
        fail("Online pin authentication escaped the exact trusted-main workflow boundary.")
    disposable_workflow = text_files[".github/workflows/disposable-bootstrap.yml"]
    trusted_disposable_marker = "      - name: Validate upstream bytes on trusted main events"
    if trusted_disposable_marker not in disposable_workflow:
        fail("Disposable bootstrap lacks its trusted-main online pin gate.")
    untrusted_disposable, trusted_disposable = disposable_workflow.split(trusted_disposable_marker, 1)
    if (
        "GITHUB_TOKEN: ${{ github.token }}" in untrusted_disposable
        or "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" not in trusted_disposable
        or "GITHUB_TOKEN: ${{ github.token }}" not in trusted_disposable
    ):
        fail("Disposable pull-request source can reach authenticated online verification.")
    for workflow in (".github/workflows/deploy-forums.yml", ".github/workflows/inspect-upstream.yml"):
        if "GITHUB_TOKEN: ${{ github.token }}" not in text_files[workflow]:
            fail(f"Trusted online workflow lacks read-only API authentication: {workflow}")

    env_lines = [line for line in read(".env.example").splitlines() if line and not line.startswith("#")]
    if any(
        "replace-at-runtime" not in line
        and not line.endswith("=false")
        and not line.endswith("=true")
        and not line.endswith("=465")
        and not line.endswith("=plain")
        and "example.invalid" not in line
        and not line.endswith("=" + "0" * 40)
        for line in env_lines
    ):
        fail("Environment example contains a non-placeholder value.")
    all_text = "\n".join(
        text_files[relative]
        for relative in relative_files
        if relative in text_files
    )
    if re.search(r"\bresend\b", all_text, re.I):
        fail("A mail provider was selected in source.")
    private_boundary_name = "Mochi " + "Creds"
    if private_boundary_name in all_text:
        fail("Private recovery-boundary paths entered repository source.")
    validate_stage4_pull_request_template(text_files[".github/pull_request_template.md"])
    contributing = read("CONTRIBUTING.md")
    security_policy = read("SECURITY.md")
    require_text(
        contributing,
        [
            "This public repository owns the reviewed Mochirii Forums configuration",
            "Source review or merge does not authorize a live deployment",
            "Start from current protected `main`",
            "host-control, deployment, backup, restore",
            "Public copy, branding, hostnames, or member-facing behavior",
            "Do not submit credentials, tokens, private keys, cookies, member data",
            "The disposable standalone workflow remains required for runtime-affecting",
        ],
        "Stage 4 contributing policy",
    )
    if "currently has no `main` ref" in contributing or "in this governance phase" in contributing:
        fail("Contributing policy regressed to the retired governance seed state.")
    require_text(
        security_policy,
        [
            "Current protected `main` with the exact upstream revisions and image digest",
            "This repository contains supported runtime, host-control, deployment, backup",
            "private vulnerability-reporting or security-",
            "Critical reports target acknowledgement within 24 hours",
            "Never test against production or a provider without explicit",
            "forced-command SSH",
            "A green source or disposable-runtime check does not claim",
            "source validation, CI/disposable evidence, hosted verification",
        ],
        "Stage 4 security policy",
    )
    if "governance source only" in security_policy or "Once runtime source exists" in security_policy:
        fail("Security policy regressed to the retired governance seed state.")

    production_workflows = {
        "backup-forums.yml": '"backup ${RELEASE_COMMIT} ${backup_operation_sha256}"',
        "restore-forums.yml": '"restore ${RELEASE_COMMIT}"',
        "verify-forums.yml": '"verify ${RELEASE_COMMIT}"',
    }
    for name, dispatcher_command in production_workflows.items():
        workflow_text = read(f".github/workflows/{name}")
        require_text(
            workflow_text,
            [
                "group: forums-production",
                "[[ \"$GITHUB_REF\" == refs/heads/main ]]",
                "refs/heads/main:refs/remotes/origin/main",
                '[[ "$(git rev-parse HEAD)" == "$RELEASE_COMMIT" ]]',
                '[[ "$(git rev-parse refs/remotes/origin/main)" == "$RELEASE_COMMIT" ]]',
                "ssh -T",
                "BatchMode=yes",
                "ClearAllForwardings=yes",
                "IdentitiesOnly=yes",
                "RequestTTY=no",
                "StrictHostKeyChecking=yes",
                dispatcher_command,
            ],
            f"protected workflow {name}",
        )
        if "persist-credentials: false" not in workflow_text:
            fail(f"Protected workflow persists checkout credentials: {name}")
        if re.search(r"(?m)\b(?:scp|sftp|sudo)\b|/usr/local/sbin/mochirii-forums-", workflow_text):
            fail(f"Protected workflow bypasses the forced-command SSH boundary: {name}")
    backup_workflow = read(".github/workflows/backup-forums.yml")
    require_text(
        backup_workflow,
        [
            '[[ "$GITHUB_RUN_ID" =~ ^[0-9]{1,32}$ ]]',
            'backup_operation_sha256="$(printf \'%s\' "mochirii-forums-backup-v1:${GITHUB_RUN_ID}" | sha256sum | awk \'{print $1}\')"',
            '[[ "$backup_operation_sha256" =~ ^[0-9a-f]{64}$ ]]',
            '"backup ${RELEASE_COMMIT} ${backup_operation_sha256}"',
        ],
        "stable opaque backup operation identity",
    )

    deploy_workflow = read(".github/workflows/deploy-forums.yml")
    require_text(
        deploy_workflow,
        [
            "group: forums-production",
            "[[ \"$GITHUB_REF\" == refs/heads/main ]]",
            "refs/heads/main:refs/remotes/origin/main",
            '[[ "$(git rev-parse HEAD)" == "$RELEASE_COMMIT" ]]',
            '[[ "$(git rev-parse refs/remotes/origin/main)" == "$RELEASE_COMMIT" ]]',
            "persist-credentials: false",
            'ssh_options=(-T -i "$key" -o BatchMode=yes -o ClearAllForwardings=yes -o IdentitiesOnly=yes -o RequestTTY=no -o ServerAliveInterval=30 -o ServerAliveCountMax=10 -o TCPKeepAlive=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts")',
            "BatchMode=yes",
            "ClearAllForwardings=yes",
            "IdentitiesOnly=yes",
            "RequestTTY=no",
            "ServerAliveInterval=30",
            "ServerAliveCountMax=10",
            "TCPKeepAlive=yes",
            "StrictHostKeyChecking=yes",
            '"receive ${RELEASE_COMMIT} ${ARCHIVE_DIGEST} ${ARCHIVE_SIZE}"',
            '"deploy ${RELEASE_COMMIT} ${ARCHIVE_DIGEST} ${ARCHIVE_SIZE} ${MODE}"',
        ],
        "protected deploy workflow",
    )
    if (
        deploy_workflow.count("ssh_options=(") != 1
        or deploy_workflow.count('ssh "${ssh_options[@]}" --') != 2
        or re.search(r"(?m)^\s*ssh\s+-T\b", deploy_workflow)
    ):
        fail("Protected deploy workflow does not share one exact keepalive transport tuple.")
    if re.search(r"(?m)\b(?:scp|sftp|sudo)\b|/usr/local/sbin/mochirii-forums-", deploy_workflow):
        fail("Protected deploy workflow bypasses the forced-command SSH boundary.")

    disposable = read(".github/workflows/disposable-bootstrap.yml")
    validate_narrative_avatar_workflow(disposable)
    validate_disposable_nginx_response_header_proof(disposable)
    validate_disposable_restore_command_diagnostics(disposable)
    require_text(
        disposable,
        [
            "pull_request:",
            "push:",
            "--cpuset-cpus=0 --memory=2g --memory-swap=4g",
            "DISCOURSE_CONNECT",
            "verify-discourse-connect.py",
            "include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;",
            "discourse restore --location local",
            "remote set-url --push origin no_push://mochirii-forums-upstream",
            "/usr/local/sbin/mochirii-stage4-launcher",
            "scripts/disposable-launcher-guard.py",
            "test-disposable-launcher-guard.py",
            "test-host-restore-launcher-journal.py",
            "test-host-operation-lock.py",
            "timeout --signal=TERM --kill-after=15s",
            "MOCHIRII_OPERATION_TOKEN",
            "container_operation_absent",
            "/opt/mochirii-release",
            "test-storage-response-boundary.rb",
            "test-backup-url-boundary.rb",
            "test-backup-transaction.py",
            "test-deployment-mutation.py",
            "test-normal-upload-inventory.rb",
            "test-admin-login-link.rb",
            "test-narrative-avatar.rb",
            "test-operation-survivor.rb",
            "test-sidekiq-processing-probe.rb",
            "ruby_fixture_container=(--rm --pull=never --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --memory-swap 256m)",
            "docker pull \"$image\"",
            "docker image inspect \"$image\"",
            "Supported disposable backup, restore, restart, and rebuild passed.",
        ],
        "disposable bootstrap workflow",
    )
    launcher_calls = len(re.findall(r"(?m)^\s*sudo /usr/local/sbin/mochirii-stage4-launcher (?:bootstrap|start|restart|rebuild) ", disposable))
    if launcher_calls != 5 or disposable.count("scripts/disposable-launcher-guard.py /usr/local/sbin/mochirii-stage4-launcher") != 1:
        fail("Disposable launcher calls do not use the exact bounded sealed-checkout helper.")
    docker_manager_readback = (
        "sudo docker exec -u discourse app git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD"
    )
    if (
        disposable.count(docker_manager_readback) != 4
        or disposable.count("plugins/docker_manager rev-parse HEAD") != 4
        or "sudo docker exec app git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD" in disposable
        or "safe.directory" in disposable
    ):
        fail("Disposable Docker Manager readback does not execute as the exact repository owner.")
    disposable_guard = read("scripts/disposable-launcher-guard.py")
    require_text(
        disposable_guard,
        [
            'LABEL_KEY = "mochirii.forums.disposable-operation"',
            '"preexistingContainerIds"', '"preexistingImageIds"',
            '"createdContainerIds"', '"createdImageIds"',
            'document["phase"] = "cleanup-armed"',
            'runtime.remove_container(identity)', 'runtime.remove_image(identity)',
            'stop_marked_processes(token)',
            'runtime.journal.unlink()', 'fsync_directory(runtime.journal.parent)',
            '["bash", str(gate)]',
            'MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_FAIL_AFTER',
            'Disposable named application image differs from the exact tagged application image.',
            'allowed_images.add(tagged)',
        ],
        "durable disposable launcher immutable-ID reconciliation",
    )
    require_text(
        read("scripts/test-disposable-launcher-guard.py"),
        [
            '"rebuild-mismatched-created-images"',
            '"rebuild-mismatched-preexisting-tag"',
            'Matching rebuild did not adopt exactly one terminal app image.',
            'def nginx_log_directory_fixture() -> None:',
            'NGINX_LOG_DIRECTORY_PREFIX = (',
            'Pinned Nginx log directory symlink guard changed its target.',
            'def nginx_outlet_syntax_fixture() -> None:',
            'Pinned Nginx accepted the hostile unquoted bounded recovery regex.',
        ],
        "disposable launcher terminal image-equality and Nginx syntax hostile fixture",
    )
    validate_narrative_avatar_fixture(read("scripts/test-narrative-avatar.rb"))
    validate_admin_login_link_fixture(read("scripts/test-admin-login-link.rb"))
    for fixture in (
        "test-storage-response-boundary.rb",
        "test-backup-url-boundary.rb",
        "test-normal-upload-inventory.rb",
        "test-admin-login-link.rb",
        "test-narrative-avatar.rb",
        "test-operation-survivor.rb",
        "test-sidekiq-processing-probe.rb",
    ):
        pattern = re.compile(
            r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+ruby /repo/scripts/'
            + re.escape(fixture)
            + r" >/dev/null"
        )
        if len(pattern.findall(disposable)) != 1:
            fail(f"Disposable Ruby fixture escaped the pinned image: {fixture}")
    require_text(
        read("scripts/test-normal-upload-inventory.rb"),
        [
            '"schemaVersion" => 2',
            '"repositoryTree" => "9" * 40',
            '"releaseArchiveBytes" => 512',
            'publisher_validator.source_authority(clean_document)',
            '"releaseArchiveContainsSecrets" => false',
            '"ordinaryDeploymentRequiresCurrentMain" => true',
            '"historicalReleaseAdoptionScope" => "clean-target-disaster-recovery-only"',
            'fetcher_source.split("\\nfetch_mode = ENV.fetch", 2)',
        ],
        "schema-2 normal-upload disaster-recovery hostile fixture",
    )
    backup_transaction_fixture = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-backup-transaction[.]py >/dev/null'
    )
    if len(backup_transaction_fixture.findall(disposable)) != 1:
        fail("Disposable backup transaction fixture escaped the pinned root container.")
    deployment_mutation_fixture = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-deployment-mutation[.]py >/dev/null'
    )
    if len(deployment_mutation_fixture.findall(disposable)) != 1:
        fail("Disposable deployment mutation fixture escaped the pinned root container.")
    disposable_launcher_fixture = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" --tmpfs /var/log:rw,nosuid,nodev,size=4m,mode=0755,uid=0,gid=0 --group-add adm -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-disposable-launcher-guard[.]py --inside-linux >/dev/null'
    )
    if len(disposable_launcher_fixture.findall(disposable)) != 1:
        fail("Disposable launcher hostile fixture lost its isolated root:adm Nginx log boundary.")
    restore_launcher_fixture = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-host-restore-launcher-journal[.]py --inside-linux >/dev/null'
    )
    if len(restore_launcher_fixture.findall(disposable)) != 1:
        fail("Restore launcher hostile fixture escaped the pinned root container.")
    host_lock_fixture = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-host-operation-lock[.]py >/dev/null'
    )
    if len(host_lock_fixture.findall(disposable)) != 1:
        fail("Host operation lock hostile fixture escaped the pinned root container.")

    host_deploy = read("scripts/host-deploy.sh")
    host_restore = read("scripts/host-restore-validate.sh")
    host_verify_wrapper = read("scripts/host-verify-wrapper.sh")
    host_authentication_finalizer = read("scripts/host-finalize-authentication.sh")
    host_authentication_stop = read("scripts/host-stop-pending-activation.sh")
    host_break_glass = read("scripts/host-break-glass-admin.sh")
    authentication_state = read("scripts/authentication-state.py")
    producer_probe = read("scripts/probe-website-forums-producer.py")
    render_config = read("scripts/render-app-config.py")
    fixture_developer_binding = (
        '"__MOCHIRII_DEVELOPER_EMAILS__": scalar("stage4-developer@example.invalid"),'
    )
    if (
        render_config.count(fixture_developer_binding) != 1
        or '"__MOCHIRII_DEVELOPER_EMAILS__": scalar("stage4-fixture@forums.mochirii.com"),' in render_config
    ):
        fail("Disposable developer identity collides with the DiscourseConnect member fixture.")
    connect_fixture = read("scripts/verify-discourse-connect.py")
    if hashlib.sha256(connect_fixture.encode("utf-8")).hexdigest() != DISCOURSE_CONNECT_VERIFIER_SHA256:
        fail("DiscourseConnect fixture verifier differs from the exact reviewed source digest.")
    validate_login_code_denial_contract(connect_fixture)
    validate_https_consumer_fixture_contract(connect_fixture)
    contained_activation_fixture = read("scripts/verify-contained-activation.sh")
    if (
        hashlib.sha256(contained_activation_fixture.encode("utf-8")).hexdigest()
        != CONTAINED_ACTIVATION_VERIFIER_SHA256
    ):
        fail("Contained activation fixture differs from the exact reviewed source digest.")
    admin_recovery_fixture = read("scripts/prepare-admin-recovery-fixture.rb")
    sensitive_log_verifier = read("scripts/verify-sensitive-log-redaction.rb")
    if hashlib.sha256(admin_recovery_fixture.encode("utf-8")).hexdigest() != ADMIN_RECOVERY_FIXTURE_SHA256:
        fail("Administrator recovery fixture differs from the exact reviewed source digest.")
    if hashlib.sha256(sensitive_log_verifier.encode("utf-8")).hexdigest() != SENSITIVE_LOG_VERIFIER_SHA256:
        fail("Sensitive-log verifier differs from the exact reviewed source digest.")
    sensitive_log_executable = ruby_executable_contract_source(sensitive_log_verifier)
    if hashlib.sha256(sensitive_log_executable.encode("utf-8")).hexdigest() != SENSITIVE_LOG_EXECUTABLE_SHA256:
        fail("Sensitive-log executable Ruby body differs from the exact reviewed contract.")
    sensitive_log_executable_prefix = '''# frozen_string_literal: true

require "pathname"

SENSITIVE_LOG_AUDIT_EXIT_CODES = {
  input: 40,
  identity: 41,
  authenticated_session: 42,
  authentication_audit_shape: 43,
  authentication_audit_marker: 44,
  log_inventory: 45,
  application_log_marker: 46,
  logster_shape: 47,
  logster_marker: 48,
  application_log_identity_marker: 49,
  application_log_callback_marker: 50,
  application_log_recovery_marker: 51,
  application_log_identity_marker_1: 52,
  application_log_identity_marker_2: 53,
  application_log_identity_marker_3: 54,
  application_log_identity_marker_4: 55,
  application_log_identity_marker_5: 56,
  application_log_identity_marker_6: 57,
  application_log_identity_marker_7: 58,
}.freeze

APPLICATION_LOG_MARKER_CATEGORIES = {
  "identity" => :application_log_identity_marker,
  "callback" => :application_log_callback_marker,
  "recovery" => :application_log_recovery_marker,
}.freeze

APPLICATION_LOG_IDENTITY_MARKER_CATEGORIES = {
  "Mochirii Stage 4 Fixture" => :application_log_identity_marker_1,
  "Mochirii%20Stage%204%20Fixture" => :application_log_identity_marker_2,
  "Mochirii+Stage+4+Fixture" => :application_log_identity_marker_3,
  "mochirii-s4-test" => :application_log_identity_marker_4,
  "mochirii-stage4-consumer-fixture" => :application_log_identity_marker_5,
  "stage4-fixture%40forums.mochirii.com" => :application_log_identity_marker_6,
  "stage4-fixture@forums.mochirii.com" => :application_log_identity_marker_7,
}.freeze

def reject_sensitive_log!(category)
  exit SENSITIVE_LOG_AUDIT_EXIT_CODES.fetch(category)
end

reject_sensitive_log!(:input) unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"

'''
    if (
        not sensitive_log_verifier.startswith(sensitive_log_executable_prefix)
        or "SENSITIVE_LOG_AUDIT_EXIT_CODES" in sensitive_log_verifier[
            len(sensitive_log_executable_prefix):
        ]
        or sensitive_log_verifier.count("def reject_sensitive_log!(category)") != 1
    ):
        fail("Sensitive-log executable Ruby classification contract differs.")
    finalizer = read("scripts/finalize-member-rollout.sh")
    require_text(
        host_deploy,
        [
            'runtime_json="/etc/mochirii/forums.runtime.json"',
            'configuration_id="${production_config_sha}"',
            'current-release.json',
            '"discourseConnectEnabled"',
            '"memberRolloutMarkerSha256"',
            '>/dev/null 2>&1',
            'canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"',
            "fetch --no-tags --depth=1 --refmap= origin refs/heads/main",
            'cmp -s -- "${trusted_archive}" "${quarantine}"',
            'protocol.allow=never',
            'protocol.https.allow=always',
            'http.followRedirects=false',
            'bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh"',
            'storage_cleanup_blocked=true',
            'containment_config="${config_dir}/restore.yml"',
            "loopback-only, non-staff-mail containment is active",
            "storage-cleanup-required.json",
            "backup-url-boundary.rb",
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
            "launcher_cumulative_budget_seconds=7800",
            "remaining_mutation_seconds",
            "MOCHIRII_OPERATION_TOKEN",
            "container_operation_absent",
            "verify-runtime-assets.sh",
            "seal_activation_deploy_failure()",
            "recover_failed_activation()",
            "activation-deploy-failed-producer-unproved",
            "activation-deploy-failed",
            'write_current_evidence "${previous_release}"',
            'assets_root="/opt/mochirii/forums/runtime-assets"',
            '--archive-root "${candidate}"',
            'scripts/authentication-state.py"',
            "probe-website-forums-producer.py disabled",
        ],
        "root deployment boundary",
    )
    forbidden_host_fragments = [
        '. "${runtime_json}"',
        "source /etc/mochirii",
        "./launcher \"$@\" >>",
        "./launcher \"$@\" 2>",
        "timeout --foreground",
        "/var/discourse/shared/standalone/mochirii",
    ]
    if any(fragment in host_deploy for fragment in forbidden_host_fragments):
        fail("Host deployer evaluates runtime secrets or persists raw launcher output.")
    if any(
        fragment in host_deploy
        for fragment in (
            "run_launcher storage-containment-stop stop app",
            "run_launcher storage-recovery-stop stop app",
            "run_launcher cleanup-reconciled-stop stop app",
            "Failed initial container was stopped",
        )
    ):
        fail("Deployment recovery claims or relies on an unproved launcher stop.")
    trust_cmp = host_deploy.index('cmp -s -- "${trusted_archive}" "${quarantine}"')
    candidate_validation = host_deploy.index('python3 "${candidate}/scripts/validate-repository.py"')
    if trust_cmp >= candidate_validation:
        fail("Candidate-controlled source can execute before canonical-main byte comparison.")
    launcher_body = re.search(r"(?ms)^run_launcher\(\) \{.*?^\}", host_deploy)
    if launcher_body is None or launcher_body.group(0).index("verify-discourse-docker-checkout.sh") > launcher_body.group(0).index("bash -c 'cd /var/discourse && exec ./launcher"):
        fail("Host launcher does not seal deployment-source bytes before execution.")
    require_text(
        host_verify_wrapper,
        [
            "*-storage-cleanup-required.json",
            "Hosted storage cleanup remains blocked; runtime verification cannot pass.",
            '"pendingAuthenticationEvidenceFile"',
            '"callbackLogRedactionPassed"',
            '"callbackBrowserQueryScrubPassed"',
            "probe-website-forums-producer.py enabled",
        ],
        "stable verification cleanup gate",
    )
    require_text(
        authentication_state,
        [
            '"consumer-public-producer-pending"',
            '"complete"',
            '"contained-after-e2e-failure"',
            '"contained-producer-state-unproved"',
            '"activation-deploy-failed"',
            '"activation-deploy-failed-producer-unproved"',
            '"previousRepositoryCommit"',
            '"callbackLogRedactionPassed"',
            '"callbackBrowserQueryScrubPassed"',
            "def validate_documents(pointer: object, record: object) -> str:",
            "def evaluate(pointer_path: Path, expected_commit: str, expected_configuration: str) -> str:",
        ],
        "authentication state machine",
    )
    require_text(
        host_authentication_finalizer,
        [
            "FINALIZE MOCHIRII FORUMS AUTHENTICATION",
            '"pendingAuthenticationEvidenceFile"',
            '"callbackLogRedactionPassed": True',
            '"callbackBrowserQueryScrubPassed": True',
            "probe-website-forums-producer.py enabled",
        ],
        "operator authentication finalization",
    )
    require_text(
        host_authentication_stop,
        [
            "STOP MOCHIRII FORUMS PENDING ACTIVATION",
            "probe-website-forums-producer.py disabled",
            "containment_phase=contained-after-e2e-failure",
            "containment_phase=contained-producer-state-unproved",
            "containment_phase=activation-deploy-failed",
            "containment_phase=activation-deploy-failed-producer-unproved",
            'failure.get("previousRepositoryCommit"',
            '"applicationStopped": True',
        ],
        "operator authentication containment",
    )
    require_text(
        producer_probe,
        [
            'HOST = "mochirii.com"',
            'PATH = "/api/forums/discourse-connect"',
            '"default-src \'none\'; frame-ancestors \'none\'; base-uri \'none\'"',
            '"origin", "authorization"',
            '"Mōchirīī Forums sign-in is unavailable."',
            '"This Mōchirīī Forums sign-in request is invalid."',
        ],
        "secret-free Website producer probe",
    )
    require_text(
        connect_fixture,
        [
            'b"mochirii-stage4-consumer-fixture"',
            'b"Mochirii Stage 4 Fixture"',
            'b"Mochirii%20Stage%204%20Fixture"',
            "register_admin_recovery_markers",
            "assert_callback_logs_redacted",
            "MOCHIRII_OPERATION_TOKEN",
        ],
        "consumer callback secrecy fixture",
    )
    require_text(
        sensitive_log_verifier,
        [
            'Pathname.new("/var/log/nginx")',
            'Pathname.new("/shared/log/rails")',
            'redis.scan(cursor, match: "*logster*"',
            'record[1].match?(/[\\x00-\\x1f\\x7f]/)',
            '!raw.end_with?("\\n")',
            'raw.include?("\\r")',
            '"identity" => :application_log_identity_marker',
            '"callback" => :application_log_callback_marker',
            '"recovery" => :application_log_recovery_marker',
            'APPLICATION_LOG_IDENTITY_MARKER_CATEGORIES.fetch(marker_record[1], :input)',
            'UserAuthTokenLog.where(user_id: user.id).order(:id).limit(129).to_a',
            'entry.path == filtered_email_login_path',
            'UserAuthToken.where(user_id: user.id).exists?',
        ],
        "callback log redaction verifier",
    )
    require_text(
        host_restore,
        [
            'discourse restore --location s3 "${backup_filename}"',
            "[A-Za-z0-9][A-Za-z0-9_.-]{0,190}",
            "prove_restore_containment",
            '[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${restore_config}" ]]',
            "DISCOURSE_DISABLE_EMAILS\" = yes",
            "DISCOURSE_ENABLE_DISCOURSE_CONNECT\" = false",
            "SiteSetting.allow_restore == false",
            "stop_app_safely",
            "Restore containment could not be proved; the application was stopped.",
            "run_container_command",
            "timeout --signal=TERM --kill-after=15s",
            "MOCHIRII_OPERATION_TOKEN",
            "container_operation_absent",
            "remaining_operation_seconds",
            "verify-runtime-assets.sh",
            "discourse restore --location s3",
            "runtime_survivor_unproved=true",
            "reconcile_launcher_failure()",
            "Restore process termination is unproved",
            'MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256="$1"',
            "normalUploadRestorePassed",
            "recoveryUploadCleanupPassed",
            "finalCleanBackupEvidenceFile",
            "finalCleanBackupMarkerAbsent",
            "sidekiqJobProcessingPassed",
            "create-clean-backup",
            "verify-clean-upload",
            "reverify-clean-upload",
            '"recoveryUploadIncluded"',
            '"normalUploadInventoryCount"',
            '"normalUploadInventorySha256"',
            '"cleanBackupIntentAt"',
            'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2"',
            'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"',
            'publish-clean-recovery 600',
            'advance_restore_phase production-reopening',
        ],
        "protected restore containment",
    )
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
    restore_resume_start = host_restore.index("readarray -t resume_contract")
    restore_resume_end = host_restore.index('print(document["phase"])', restore_resume_start)
    restore_resume = host_restore[restore_resume_start:restore_resume_end]
    restore_keys_match = re.search(r"required = \{(?P<body>.*?)\}\nif set\(document\) != required", restore_resume, re.S)
    if restore_keys_match is None or set(re.findall(r'"([A-Za-z][A-Za-z0-9]+)"', restore_keys_match.group("body"))) != restore_journal_keys:
        fail("Restore journal exact field inventory differs.")
    require_text(
        host_restore,
        [
            '"launcherReplacementImageId"',
            'bind_launcher_replacement_image',
            'launcher_image_id_absent',
            'docker image rm --force "${durable_replacement}"',
            'restore journal replacement image identity cannot change',
            'restore journal cannot advance while a launcher is armed',
            'reconcile_launcher_failure || fail "Interrupted restore launcher state could not be reconciled from its durable journal; the journal was retained."',
            'env "MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=${launcher_operation_token}"',
            'fields = pathlib.Path(f"/proc/{pid}/environ").read_bytes().split(b"\\0")',
            'terminate_launcher_marked_processes',
            'launcher_marked_processes_absent',
        ],
        "restore launcher immutable image-ID journal",
    )
    restore_launcher_fixture = read("scripts/test-host-restore-launcher-journal.py")
    require_text(
        restore_launcher_fixture,
        [
            'post-image-swap replacement ID was not durably bound',
            'crash_action=post-delete',
            'launcherReplacementImageId',
            'post-CID-unlink or image-reconciliation crash changed launcher authority',
            'harmless-detached',
            'setsid bash -c',
            'if launcher_marked_processes_absent; then exit 60; fi',
            'if retire_launcher_journal; then exit 61; fi',
            'restore launcher journal hostile crash-window tests passed',
        ],
        "restore launcher immutable-set hostile fixture",
    )
    require_text(
        host_restore,
        [
            'clean_phases = {',
            '(document["phase"] in clean_phases) != isinstance(clean_intent, str)',
            'clean_intent = existing.get("cleanBackupIntentAt") if existing else None',
            'if order[phase] >= order["clean-backup-creating"] and clean_intent is None:',
            'if order[phase] < order["clean-backup-creating"] and clean_intent is not None:',
            '"cleanBackupIntentAt": clean_intent',
            'journal.get("phase") != "clean-backup-creating"',
            'journal["cleanBackupIntentAt"]',
            'modified < intent.replace(microsecond=0)',
            '[[ ${disaster_restore} == true ]] || fail "A fixture-free backup is accepted only for clean-target disaster recovery."',
        ],
        "restore journal and clean-target-only fixtureless contract",
    )
    restore_lines = host_restore.splitlines()
    for operation in ("verify-restored-data", "verify-restored-restart", "verify-restored-rebuild"):
        matching = [line for line in restore_lines if f"run_container_command {operation} " in line]
        if len(matching) != 1 or any(
            value not in matching[0]
            for value in (
                'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2"',
                'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"',
                '"${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}"',
            )
        ):
            fail(f"{operation} lost its exact normal-upload inventory binding.")
    restore_retirement_start = host_restore.index('current_backup="${state_root}/current-backup.json"')
    restore_retirement_end = host_restore.index(
        'if [[ -e ${restore_journal} || -L ${restore_journal} ]]; then', restore_retirement_start
    )
    restore_retirement = host_restore[restore_retirement_start:restore_retirement_end]
    restore_retirement_order = (
        'backup_transaction_helper}" inspect-current',
        '${current_backup_contract[4]} == event-committed',
        'backup_transaction_helper}" retire-current',
        '[[ ! -e ${current_backup} && ! -L ${current_backup} ]]',
    )
    if (
        '--operation-sha "${restore_retirement_sha}"' not in restore_retirement
        or [restore_retirement.index(value) for value in restore_retirement_order]
        != sorted(restore_retirement.index(value) for value in restore_retirement_order)
    ):
        fail("Restore does not inspect, exact-validate, durably retire, and prove absence of terminal backup state.")
    restore_runtime = host_restore[host_restore.index("isolated=true") :]
    restore_publication_order = (
        "run_container_command capture-clean-upload-inventory",
        "run_container_command inspect-clean-backup",
        "run_container_command create-clean-backup",
        "run_container_command verify-clean-backup",
        "run_container_command reverify-clean-inventory",
        "run_container_command publish-clean-recovery",
        "os.link(backup_path, evidence, follow_symlinks=False)",
        "advance_restore_phase clean-backup-committed",
        'python3 -B - "${backup_pointer}" "${clean_backup_evidence}"',
        "advance_restore_phase pointer-committed",
        "advance_restore_phase production-reopening",
        'activate_config "${production_config}"',
    )
    restore_publication_positions = [restore_runtime.index(value) for value in restore_publication_order]
    if restore_publication_positions != sorted(restore_publication_positions):
        fail("Final clean inventory, backup, DR evidence, or latest pointer can publish after production reopen begins.")
    restore_launcher_body = re.search(r"(?ms)^run_launcher\(\) \{.*?^\}", host_restore)
    if restore_launcher_body is None or restore_launcher_body.group(0).index("verify-discourse-docker-checkout.sh") > restore_launcher_body.group(0).index("bash -c 'cd /var/discourse && exec ./launcher"):
        fail("Restore launcher does not seal deployment-source bytes before execution.")

    host_backup = read("scripts/host-backup.sh")
    require_text(
        host_backup,
        [
            "run_container_command",
            "timeout --signal=TERM --kill-after=15s",
            "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
            "mutation_budget_seconds=4500",
            "remaining_mutation_seconds",
            "MOCHIRII_OPERATION_TOKEN",
            "container_operation_absent",
            "docker exec -u discourse app bash -lc",
            'git -C /var/www/discourse rev-parse HEAD',
            'git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD',
            "verify-runtime-assets.sh",
            "prepare-backup-marker.rb",
            "discourse backup",
            "verify-backup.rb",
            "MOCHIRII_RECOVERY_UPLOAD_ACTION=prepare",
            "MOCHIRII_RECOVERY_UPLOAD_ACTION=cleanup",
            "recoveryUploadIncluded",
            "recoveryUploadStateSha256",
            "recoveryUploadDeletedAfterBackup",
            "CRITICAL: Backup in-container process termination could not be verified.",
        ],
        "protected backup process boundary",
    )
    backup_identity = re.search(r"(?ms)^prove_running_backup_identity\(\) \{.*?^\}", host_backup)
    if backup_identity is None:
        fail("Backup running-identity proof is absent.")
    backup_identity_source = backup_identity.group(0)
    if (
        backup_identity_source.count("docker exec -u discourse app bash -lc") != 1
        or backup_identity_source.count("git -C /var/www/discourse rev-parse HEAD") != 1
        or backup_identity_source.count("git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD") != 1
        or "docker exec app bash -lc" in backup_identity_source
        or "safe.directory" in host_backup
    ):
        fail("Backup running-identity Git proof is not bound to the exact repository owner.")
    backup_marker = read("scripts/prepare-backup-marker.rb")
    restored_verifier = read("scripts/verify-restored-backup.rb")
    validate_restored_mail_suppression_contract(restored_verifier)
    validate_restored_central_login_contract(restored_verifier)
    validate_restored_failure_exit_contract(restored_verifier)
    require_text(
        backup_marker,
        [
            "UploadCreator.new(",
            'origin: transaction.fetch("uploadOrigin")',
            ").create_for(Discourse.system_user.id)",
            "store.get_path_for_upload(upload)",
            'public_uri.host == "media-forums.mochirii.com"',
            'store.delete_file(state.fetch("objectPath"))',
            'store.delete_file(state.fetch("tombstonePath"))',
            "bounded_absent!(store, state)",
            'PluginStore.remove(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)',
        ],
        "normal-upload backup recovery fixture",
    )
    require_text(
        restored_verifier,
        [
            'PluginStore.get("mochirii-recovery", "normal_upload_marker")',
            "Digest::SHA256.hexdigest(canonical + \"\\n\") == expected_state_sha",
            "upload.content == expected_bytes",
            'public_uri.host == "media-forums.mochirii.com"',
            'store.object_from_path(state["objectPath"]).exists?',
        ],
        "restored normal-upload identity proof",
    )
    disaster_publisher = read("scripts/publish-disaster-recovery-evidence.rb")
    disaster_fetcher = read("scripts/fetch-disaster-recovery-evidence.rb")
    disaster_release_fetcher = read("scripts/fetch-disaster-recovery-release.rb")
    historical_release = read("scripts/historical-release-disaster-recovery.py")
    historical_controller = read("scripts/host-historical-disaster-recovery.sh")
    historical_scratch = read("scripts/historical-recovery-scratch-reader.sh")
    historical_fixture = read("scripts/test-historical-release-disaster-recovery.py")
    historical_scratch_fixture = read("scripts/test-historical-recovery-scratch-reader.py")
    historical_host_security = read("scripts/verify-host-security.sh")
    historical_certificate_installer = read("scripts/install-media-certificate-renewal.sh")
    clean_disaster_target = read("scripts/verify-clean-disaster-target.rb")
    runtime_assets = read("scripts/verify-runtime-assets.sh")
    require_text(
        disaster_publisher,
        [
            'S3Helper.build_from_config(for_backup: true)',
            'EXPECTED_BUCKET = "mochirii-forums"',
            'EXPECTED_FOLDER = "backups"',
            'POINTER_PATH = "recovery-evidence/current.json"',
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
        ],
        "private off-host recovery evidence publication",
    )
    require_text(
        disaster_fetcher,
        [
            'MAX_DOCUMENT_BYTES = 32 * 1024',
            'S3Helper.build_from_config(for_backup: true)',
            'private_object!(pointer_object)',
            'private_object!(evidence_object)',
            'grants.length == 1',
            'grants.first.permission == "FULL_CONTROL"',
            'grants.first.grantee&.type == "CanonicalUser"',
            'grants.first.grantee&.id.to_s == owner_id',
            'fail_fetch("object ACL is not exact private owner-only") unless exact_private',
            'pointer["evidenceObjectKey"] == "#{EXPECTED_FOLDER}/recovery-evidence/records/#{pointer["evidenceObjectSha256"]}.json"',
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
        ],
        "private off-host recovery evidence fetch",
    )
    require_text(
        disaster_release_fetcher,
        [
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
        ],
        "private immutable historical release fetch",
    )
    require_text(
        historical_release,
        [
            'ARCHIVE_FORMAT = "git-archive-tar-v1"',
            'ADOPTION_SCOPE = "clean-target-disaster-recovery-only"',
            'ordinaryDeploymentRequiresCurrentMain',
            'historical-release-adoption.json',
            '"phase": "source-prepared"',
            '"phase": "configuration-authorized"',
            '"bootstrap-started"',
            '"bootstrap-complete"',
            '"restore-started"',
            '"restore-complete"',
            'complete_bootstrap = subcommands.add_parser("complete-bootstrap")',
            'begin_restore = subcommands.add_parser("begin-restore")',
            'complete = subcommands.add_parser("complete")',
            'tree != identity.repository_tree or manifest != identity.content_manifest_sha256',
            'PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE',
            'AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE',
        ],
        "provenance-bound historical release adoption",
    )
    require_text(
        historical_controller,
        [
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
            'terminalReaderTransactionPhase',
            'terminalReaderTransactionSha256',
            'readerOperationImageIds',
            'readerOperationImageLabel',
            'readerOperationImagesAbsent',
            'terminal historical scratch-reader retirement authority differs',
            'pending historical reader retirement authority differs',
            'Historical reader retirement refuses an active scratch transaction.',
            'Historical reader intent was not retired before recovery continuation.',
            'begin-bootstrap',
            'historical-bootstrap',
            'Historical Mochirii Forums disaster recovery completed and retired its active journal.',
        ],
        "operator-only historical recovery controller",
    )
    if historical_controller.index('prove_canonical_main "${bootstrap_commit}"') > historical_controller.index('"${scratch_reader}" "${bootstrap_commit}"'):
        fail("Historical C1 scratch execution can precede the exact current-main proof.")
    authorization = historical_controller.index('--confirmation "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"')
    if authorization > historical_controller.index("journal.unlink()", authorization):
        fail("Historical reader intent can retire before durable C0 configuration authorization.")
    retirement = historical_controller.index("pending historical reader retirement authority differs")
    if retirement > historical_controller.index("Historical recovery requires the Website Forums producer to remain disabled.", retirement):
        fail("A stale exact historical reader journal can survive into C0 mutation authority.")
    require_text(
        historical_scratch,
        [
            'PHASES = {"armed", "receipt-fetched", "archive-fetched", "cleanup-proved", "receipt-published", "outputs-published"}',
            'path.read_bytes().split(b"\\0")',
            'member.mode not in {0o644, 0o664, 0o755, 0o775}',
            'scratch container retained a forbidden mount',
            'MOCHIRII_DR_FETCH_MODE=clean-target-historical',
            'MOCHIRII_DR_BOOTSTRAP_COMMIT=',
            '"preexistingImageIds"',
            '"operationImageIds"',
            '"operationImageLabel"',
            'docker image rm --force "${image_id}"',
            'crash_point after-reader-image-untag',
            'docker_image_id_state "${image_id}"',
            'crash_point after-reader-image-delete',
            'terminal transaction awaits controller readback',
        ],
        "isolated C1 historical recovery reader",
    )
    require_text(
        host_deploy,
        [
            'The deploy principal may not invoke historical bootstrap.',
            'Ordinary deployment refuses an active historical disaster-recovery adoption.',
            '--require-phase bootstrap-complete',
            'A bootstrap-complete historical journal may only reconcile its same terminal deployment transaction; runtime mutation is forbidden.',
        ],
        "journal-scoped historical C0 bootstrap",
    )
    require_text(
        host_restore,
        [
            'An active historical adoption refuses disposable restore.',
            'Historical terminal reconciliation refuses an active backup transaction.',
            'Historical terminal reconciliation refuses an active deployment transaction.',
            'Historical terminal reconciliation refuses an active deployment mutation.',
            'Historical terminal reconciliation refuses an active restore transaction.',
            'regenerated historical release evidence is not semantically equal to the private C0 receipt',
            'begin-restore',
            '--require-phase restore-started',
            'Terminal historical adoption journal was not retired.',
        ],
        "historical C0 restore and terminal retirement",
    )
    collision = host_restore.index("Historical terminal reconciliation refuses an active backup transaction.")
    if collision > host_restore.index('"${historical_helper}" complete', collision):
        fail("Historical restore terminal completion can bypass transaction collision gates.")
    if host_restore.index('"${historical_helper}" begin-restore') > host_restore.index('discourse restore --location s3'):
        fail("Historical restore mutation can precede its durable adoption phase.")
    require_text(
        historical_fixture,
        [
            'SCRATCH.git_archive(c0_archive,c0_files,"C0 historical backup")',
            'configuration-authorized-before-reader-retirement',
            'crash_result=controller(crashed,"prepare",C1,OPERATION,PREPARE_CONFIRMATION,passed=False)',
            'MOCHIRII_FIXTURE_DEPLOY_CRASH_ONCE',
            'MOCHIRII_FIXTURE_DEPLOY_COMPLETE_CRASH_ONCE',
            'MOCHIRII_FIXTURE_RESTORE_COMPLETE_CRASH_ONCE',
            'C0 mutation was not prearmed.',
            'Bootstrap-complete retry was not reconciliation-only.',
            'Restore-complete retry was not terminal-only.',
            'Historical C0 backup / C1 main / lost-host production-entrypoint fixture passed.',
        ],
        "C0 backup, C1 main, lost-host production-entrypoint fixture",
    )
    require_text(
        historical_scratch_fixture,
        [
            '"git", "-c", "core.autocrlf=false", "-c", "core.filemode=true"',
            '"-c", "tar.umask=0002"',
            'actual NUL-delimited marked process survived reconciliation',
            'MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_CRASH_AFTER',
            'scratch container retained a forbidden mount',
        ],
        "real-Git C1 scratch hostile fixture",
    )
    for fixture_source in (historical_fixture, historical_scratch_fixture):
        if (
            "/tmp:rw,noexec,nosuid,nodev,size=16m" not in fixture_source
            or re.search(r'"--pids-limit"\s*,\s*"64"', fixture_source) is None
            or re.search(r'"--memory"\s*,\s*"256m"', fixture_source) is None
            or re.search(r'"--memory-swap"\s*,\s*"256m"', fixture_source) is None
        ):
            fail("Historical fixture convenience wrapper differs from the pinned CI noexec isolation tuple.")
    for source, minimum in (
        (read("scripts/install-host-control.sh"), 2),
        (read("scripts/upgrade-host-control.sh"), 2),
        (host_deploy, 1),
        (historical_host_security, 1),
        (read(".github/workflows/deploy-forums.yml"), 1),
        (disposable, 1),
    ):
        if source.count("tar.umask=0002") < minimum:
            fail("A retained or consumed Git archive lost deterministic tar-mode construction.")
    require_text(
        historical_host_security,
        [
            'MAX_JSON_BYTES = 65_536',
            'MAX_ARCHIVE_BYTES = 67_108_864',
            'bounded_read(pointer_path, MAX_JSON_BYTES',
            'bounded_read(record_path, MAX_JSON_BYTES',
            'isinstance(expected_bytes, bool)',
            'metadata.st_size != expected_bytes',
            'bounded_read(path, MAX_ARCHIVE_BYTES',
        ],
        "bounded retained host-control archive verification",
    )
    require_text(
        historical_certificate_installer,
        [
            'pointer_keys = {',
            'record_keys = {',
            'archive_bindings = {',
            'not 1 <= pointer["releaseArchiveBytes"] <= 64 * 1024 * 1024',
            'not 1 <= pointer["deploymentSourceArchiveBytes"] <= 64 * 1024 * 1024',
            'any(record.get(key) != pointer.get(key) for key in archive_bindings)',
        ],
        "certificate host-control archive schema consumption",
    )
    fetch_core_order = (
        '"normalUploadInventoryCount" => source["normalUploadInventoryCount"]',
        '"normalUploadInventorySha256" => source["normalUploadInventorySha256"]',
        "core_bytes = JSON.pretty_generate(core_document.sort.to_h)",
        'Digest::SHA256.hexdigest(core_bytes) == source["backupEvidenceCoreSha256"]',
        '"disasterRecoveryImported" => true',
    )
    fetch_core_positions = [disaster_fetcher.index(value) for value in fetch_core_order]
    if fetch_core_positions != sorted(fetch_core_positions):
        fail("Fetched disaster-recovery inventory is not part of the validated pre-publication core digest.")
    require_text(
        clean_disaster_target,
        [
            'User.where("id > 0").none?',
            'Post.where("user_id > 0").none?',
            'Topic.where("user_id > 0").none?',
            'Upload.none?',
            'ApiKey.none?',
            'UserApiKey.none?',
            'PluginStore.get("mochirii-recovery", "repository_commit").nil?',
            'PluginStore.get("mochirii-recovery", "normal_upload_marker").nil?',
        ],
        "clean-target disaster restore guard",
    )
    require_text(
        host_backup,
        [
            'publish-recovery-evidence 600',
            'MOCHIRII_DR_EVIDENCE_BASE64',
            'publish-disaster-recovery-evidence.rb',
            'backups/recovery-evidence/current.json',
            'privateAclPassed',
        ],
        "bounded disaster-recovery evidence publisher",
    )
    require_text(
        host_restore,
        [
            'probe-website-forums-producer.py" disabled',
            'verify-clean-disaster-target.rb',
            'fetch-disaster-recovery-evidence.rb',
            'ulimit -f 128',
            'Private off-host recovery evidence fetch failed; the application was contained.',
        ],
        "clean-target private disaster recovery",
    )
    for runtime_script in (
        "fetch-disaster-recovery-evidence.rb",
        "publish-disaster-recovery-evidence.rb",
        "verify-clean-disaster-target.rb",
    ):
        if host_deploy.count(runtime_script) != 2 or runtime_assets.count(runtime_script) != 2 or disposable.count(runtime_script) != 1:
            fail(f"Disaster-recovery runtime asset inventory differs: {runtime_script}")
    if host_deploy.count("fetch-disaster-recovery-release.rb") != 2 or runtime_assets.count("fetch-disaster-recovery-release.rb") != 2 or disposable.count("fetch-disaster-recovery-release.rb") != 3:
        fail("Historical release fetcher runtime asset or pinned fixture inventory differs.")
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
            fail(f"Historical release disposable fixture registration differs: {value}")
    for value in ("mochirii-release.tar", "repositoryTree", "releaseArchiveBytes", "releaseArchiveContentManifestSha256"):
        if value not in host_deploy or value not in runtime_assets:
            fail(f"Immutable release runtime authority differs: {value}")
    for operation in (host_backup, host_restore):
        for value in (
            '"schemaVersion": 2',
            '"repositoryTree"',
            '"releaseArchiveBytes"',
            '"releaseArchiveContentManifestSha256"',
            '"releaseArchiveContainsSecrets": False',
            '"ordinaryDeploymentRequiresCurrentMain": True',
            '"historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only"',
            'result.get("schemaVersion") != 2',
        ):
            if value not in operation:
                fail(f"Backup/restore immutable release publication contract differs: {value}")
    for consumer_path in (
        "scripts/authentication-state.py",
        "scripts/host-finalize-authentication.sh",
        "scripts/host-verify-wrapper.sh",
        "scripts/verify-host.sh",
    ):
        consumer = read(consumer_path)
        for value in ("repositoryTree", "releaseArchiveBytes", "releaseArchiveContentManifestSha256"):
            if value not in consumer:
                fail(f"Release evidence consumer lacks immutable archive authority: {consumer_path}: {value}")
    if "Ordinary deployment refuses an active historical disaster-recovery adoption." not in host_deploy:
        fail("Ordinary deployment can overlap historical disaster-recovery adoption.")
    if host_deploy.count("backup-transaction.py") != 2 or runtime_assets.count("backup-transaction.py") != 2 or disposable.count("backup-transaction.py") != 2:
        fail("Durable backup transaction helper or hostile fixture inventory differs.")
    if host_deploy.count("normal-upload-inventory.rb") != 2 or runtime_assets.count("normal-upload-inventory.rb") != 2 or disposable.count("normal-upload-inventory.rb") != 2:
        fail("Normal-upload inventory runtime asset registration differs.")
    backup_transaction = read("scripts/backup-transaction.py")
    backup_transaction_test = read("scripts/test-backup-transaction.py")
    require_text(
        backup_transaction,
        [
            'backupOperationSha256',
            'previousLatestEvidenceFile',
            'previousLatestPointerSha256',
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
            'args.transaction.unlink()',
            'os.fsync(directory)',
            '"originalRuntimeState"',
            '"runtimeIdentitySha256"',
            '"currentReleaseSha256"',
            '"discourseRevision"',
            '"dockerManagerRevision"',
            '"runtimeEnvironmentSha256"',
            '"runtimePortBindingsSha256"',
            '"runtimeContainerImage"',
            '"runtimeOperationPhase"',
            'action_arm_operation',
            'action_complete_operation',
            'action_prove_operation_absent',
            'action_authorize_restart',
            'action_complete_restart',
            'action_authorize_initial_start',
            'action_complete_initial_start',
            'action_contain_temporary_runtime',
            'action_authorize_original_stop',
            'action_complete_original_state',
            'document.get("discourseRevision") != transaction["discourseRevision"]',
            'document.get("dockerManagerRevision") != transaction["dockerManagerRevision"]',
            'fail("prepared backup ownership cannot retire before terminal runtime restoration")',
        ],
        "durable backup caller identity and terminal transaction",
    )
    require_text(
        host_backup,
        [
            '[[ $# -eq 2 ]] || fail "Usage: host-backup.sh EXPECTED_COMMIT BACKUP_OPERATION_SHA256"',
            '[[ ${backup_operation_sha} =~ ^[0-9a-f]{64}$ ]]',
            '--operation-sha "${backup_operation_sha}"',
            'backup_transaction_command inspect-current',
            'if [[ ${current_backup_operation} == "${backup_operation_sha}" ]]; then',
            'backup_transaction_command adopt-current',
            '[[ ${current_backup_phase} == event-committed ]]',
            'backup_transaction_command retire-current',
            'backup_transaction_command create',
            'backup_runtime_operation_command arm-operation',
            'backup_runtime_operation_command complete-operation',
            'backup_runtime_operation_command prove-operation-absent',
            'reconcile_bound_runtime_ownership',
            'restore_original_runtime_state',
            '(ulimit -f 128; exec 200>&- 201>&-; exec timeout',
        ],
        "protected backup operation identity",
    )
    backup_operation_flow = host_backup[host_backup.index('if [[ -e ${current_backup} || -L ${current_backup} ]]; then') :]
    backup_operation_order = (
        'backup_transaction_command inspect-current',
        'backup_transaction_command adopt-current',
        'backup_transaction_command retire-current',
        'backup_transaction_command create',
    )
    backup_operation_positions = [backup_operation_flow.index(value) for value in backup_operation_order]
    if backup_operation_positions != sorted(backup_operation_positions):
        fail("Backup creation can precede same-operation adoption or different-operation retirement.")
    if "backup_transaction_command retire-prepared" in host_backup:
        fail("Host backup regained a journal-free prepared-transaction retirement path.")
    require_text(
        backup_transaction_test,
        [
            'Hostile backup transaction was accepted: {label}',
            'intervening latest pointer',
            'clear before durable passed event',
            'evidence changed after pointer commit',
            'Terminal backup transaction was not cleared exactly once.',
            'Same-operation terminal backup was not adopted.',
            'same operation retired its terminal receipt',
            'new operation prearmed before terminal receipt retirement',
            'different operation retired an intervened pointer',
            'New backup transaction did not bind its caller operation.',
            'Post-cleanup SIGKILL lost exact runtime ownership.',
            'Post-rollout timeout lost journal-free operation ownership.',
            'terminal evidence contradicted the prepared Discourse revision',
            'terminal evidence contradicted the prepared Docker Manager revision',
            'C1 operation did not retire the self-validated C0 terminal receipt.',
            'Stopped-origin unbound journal was not durably adopted.',
            '(exec 9>&-; exec sleep 30)',
        ],
        "backup terminal and caller-identity transaction fault fixtures",
    )
    if "timeout --foreground" in host_restore or "timeout --foreground" in host_backup or "timeout --foreground" in disposable:
        fail("A bounded in-container operation uses foreground timeout and can leave child processes alive.")
    restore_evidence_start = host_restore.index('python3 - "${restore_evidence}" "${backup_evidence}"')
    restore_identity_start = host_restore.index(
        'readarray -t restore_identity < <(python3 -B - "${restore_journal}"', 0, restore_evidence_start
    )
    restore_identity = host_restore[restore_identity_start:restore_evidence_start]
    require_text(
        restore_identity,
        [
            'clean_name = pathlib.Path(sys.argv[2]).name',
            'journal["recordedAt"]',
            'print(match.group(1))',
            'restore_evidence="${evidence_root}/${commit}-${configuration}-${restore_identity[0]}-restore.json"',
        ],
        "deterministic restore evidence identity",
    )
    restore_evidence_publication = host_restore[
        restore_evidence_start : host_restore.index('  restore_evidence_sha256=', restore_evidence_start)
    ]
    require_text(
        restore_evidence_publication,
        [
            'if path.exists() or path.is_symlink():',
            'path.read_bytes() != temporary.read_bytes()',
            'raise SystemExit("existing restore evidence differs")',
            'os.link(temporary, path, follow_symlinks=False)',
            'if temporary.exists():',
            'temporary.unlink()',
            'os.fsync(directory)',
        ],
        "deterministic restore evidence adoption",
    )
    require_text(
        finalizer,
        [
            'member-rollout-enabled',
            'restore_terminal="${state_root}/current-restore.json"',
            'restore-transaction.json && ! -L ${state_root}/restore-transaction.json',
            '[[ "$(stat -c \'%U:%G %a\' "${restore_terminal}")" == "root:root 600" ]]',
            'set(terminal) != terminal_keys',
            'terminal.get("restoreMode") != "disposable-rehearsal"',
            'bound_evidence("testedBackupEvidenceFile", "testedBackupEvidenceSha256", "backup")',
            'bound_evidence("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256", "backup")',
            'bound_evidence("restoreEvidenceFile", "restoreEvidenceSha256", "restore")',
            '"discourseConnectEnabled": False',
            'os.replace(temporary, path)',
            '"normalUploadRestorePassed": True',
            '"recoveryUploadCleanupPassed": True',
            '"finalCleanBackupMarkerAbsent": True',
            'tested.get("recoveryUploadIncluded") is not True',
            'tested.get("recoveryUploadStateSha256") != state_sha',
            'document.get("recoveryUploadIncluded") is not True',
            'document.get("recoveryUploadStateSha256") != state_sha',
            'document.get("testedNormalUploadInventoryCount") != tested_inventory_count',
            'document.get("finalCleanNormalUploadInventoryCount") != inventory_count',
            '"disasterRecoveryEvidencePublished", "disasterRecoveryPointerSelected", "disasterRecoveryPrivateAclPassed"',
            'backups/recovery-evidence/records/{dr_evidence_sha}.json',
            'clean.get("disasterRecoveryPointerObjectKey") != "backups/recovery-evidence/current.json"',
            'pointer_bytes != (str(clean_path) + "\\n").encode("utf-8")',
            'latest backup pointer does not name the final clean backup',
        ],
        "irreversible member-rollout terminal and recovery-evidence finalizer",
    )
    if any(value in finalizer for value in ('glob("*-restore.json")', "rglob(", "latest_restore", "latest-restore")):
        fail("Member rollout scans for restore evidence instead of requiring exact current-restore terminal state.")

    dispatcher = read("scripts/ssh-deploy-dispatch.py")
    require_text(
        dispatcher,
        [
            "MAX_ARCHIVE_BYTES = 64 * 1024 * 1024",
            "MAX_RECEIVE_SECONDS = 300",
            "fcntl.LOCK_EX | fcntl.LOCK_NB",
            "signal.alarm(MAX_RECEIVE_SECONDS)",
            '"receive": re.compile',
            '"deploy": re.compile',
            '"verify": re.compile',
            '"backup": re.compile',
            '"restore": re.compile',
            '"/usr/local/sbin/mochirii-forums-deploy"',
            '"/usr/local/sbin/mochirii-forums-verify"',
            '"/usr/local/sbin/mochirii-forums-backup"',
            '"/usr/local/sbin/mochirii-forums-restore"',
            "stdin=subprocess.DEVNULL",
            "stdout=subprocess.DEVNULL",
            "stderr=subprocess.DEVNULL",
            "ROOT_CONTAINMENT_GRACE_SECONDS = 300",
            '"backup": 4800',
            '"restore": 13200',
            '"deploy": 8400',
            '"backup": re.compile(rf"\\Abackup {COMMIT} {DIGEST}\\Z")',
            '["/usr/local/sbin/mochirii-forums-backup", values[0], values[1]]',
        ],
        "forced-command SSH dispatcher",
    )
    if any(value in dispatcher for value in ("shell=True", "os.system(", "shell=True", "/bin/bash", "internal-sftp")):
        fail("Forced-command SSH dispatcher gained a general command or transfer surface.")
    installer = read("scripts/install-host-control.sh")
    hardened_ssh = read("config/sshd-forums.conf")
    prepared_ssh = read("config/sshd-forums-prepared.conf")
    operator_sudoers = read("config/sudoers-forums-operator")
    host_security = read("scripts/verify-host-security.sh")
    host_verify = read("scripts/verify-host.sh")
    validate_acme_host_private_state_contract(host_verify)
    deployment_checkout = read("scripts/verify-discourse-docker-checkout.sh")
    control_upgrade = read("scripts/upgrade-host-control.sh")
    failed_bootstrap_quarantine = read("scripts/quarantine-failed-bootstrap.sh")
    control_evidence = read("scripts/host-control-evidence.py")
    operation_lock = read("scripts/host-operation-lock.py")
    operation_lock_fixture = read("scripts/test-host-operation-lock.py")
    if operator_sudoers.splitlines() != [
        'Defaults:mochirii-forums-operator env_keep += "SSH_CONNECTION"',
        "mochirii-forums-operator ALL=(ALL:ALL) NOPASSWD: ALL",
    ]:
        fail("Operator sudoers does not preserve only the live SSH session evidence.")
    require_text(
        operation_lock,
        [
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
        ],
        "race-safe host-operation lock helper",
    )
    require_text(
        operation_lock_fixture,
        [
            BASE_DIGEST,
            'Linked /run parent received a lock artifact.',
            'Linked system lock parent received a lock artifact.',
            'Linked private lock directory received a lock artifact.',
            'Linked lock victim bytes changed.',
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
        ],
        "host-operation lock hostile fixture",
    )
    if '"--network",\n        "none"' not in operation_lock_fixture or '"--read-only"' not in operation_lock_fixture:
        fail("Host-operation lock hostile wrapper differs from the pinned isolated Linux boundary.")

    lock_consumers = {
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
            "scripts/quarantine-failed-bootstrap.sh",
            "scripts/upgrade-host-control.sh",
        ),
    }
    lock_sources: dict[str, str] = {}
    for lock_set, paths in lock_consumers.items():
        for relative in paths:
            source = read(relative)
            lock_sources[relative] = source
            require_text(
                source,
                [
                    f"assert-held --locks {lock_set}",
                    f"run --locks {lock_set}",
                    '[[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."',
                ],
                f"{relative} host-operation lock wrapper",
            )
            if "--locks media,primary" in source:
                fail(f"{relative} can acquire the media lock before the primary lock.")
    if len(lock_sources) != 14:
        fail("The complete primary/media lock-consumer inventory differs.")
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
    for relative, source in lock_sources.items():
        without_reviewed_closes = source.replace("exec 200>&- 201>&-", "")
        if (
            any(path in source for path in retired_lock_paths)
            or descriptor_open.search(without_reviewed_closes)
            or numeric_flock.search(source)
        ):
            fail(f"{relative} regained a direct or variable-computed lock descriptor open.")
    for relative, minimum in {
        "scripts/host-backup.sh": 1,
        "scripts/host-break-glass-admin.sh": 1,
        "scripts/host-deploy.sh": 4,
        "scripts/host-restore-validate.sh": 2,
        "scripts/install-host-control.sh": 2,
        "scripts/media-certificate-operation.sh": 2,
    }.items():
        if read(relative).count("exec 200>&- 201>&-") < minimum:
            fail(f"{relative} can leak protected host-lock descriptors into a detached operation.")
    lock_service = read("config/mochirii-forums-media-certificate-renew.service")
    if (
        "ReadWritePaths=/etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/lib/mochirii/forums -/run/lock/mochirii-forums"
        not in lock_service
        or re.search(r"(?:^|\s)/run/lock(?:\s|$)", lock_service, re.MULTILINE)
    ):
        fail("Media-certificate systemd write authority is not narrowed to the private lock namespace.")
    if "host-operation-lock.py" in read("config/sudoers-forums") or "host-operation-lock.py" in dispatcher:
        fail("Deploy-key authority gained a direct host-operation lock helper route.")
    require_text(
        host_security,
        [
            'verify-namespace --locks primary,media',
            'sudo -l -U mochirii-forums-deploy /usr/local/libexec/mochirii-forums/host-operation-lock.py',
        ],
        "host-security lock-node and deploy-authority proof",
    )
    require_text(
        host_deploy,
        [
            'readonly deployment_transaction="/var/lib/mochirii/forums/deployment-transaction.json"',
            'readonly deployment_terminal="/var/lib/mochirii/forums/current-deployment.json"',
            'order = {"prepared": 10, "state-committed": 20, "event-committed": 30}',
            'document["phase"] = "complete"',
            'an active deployment transaction belongs to another exact operation',
            'deployment transaction stable field differs: {key}',
            'deployment member marker binding differs',
            'deployment authentication binding differs',
            'Active deployment transaction authentication state differs from its exact retry contract.',
            'run_release_verification "${previous_release}" "${previous_configuration}" --deployment-prior-rollback || return 1',
            'Deployment mutation prior current-release bytes differ from their sealed digest.',
            'Pending hosted storage cleanup lacks its exact deployment mutation authority.',
            'Bootstrap mode refuses existing current-release evidence.',
            'Bootstrap mode refuses an existing current-release target.',
        ],
        "deployment terminal transaction",
    )
    deployment_verified = host_deploy.rindex("mark_deployment_mutation_verified")
    deployment_prearm = host_deploy.rindex("write_deployment_transaction prepared")
    deployment_armed = host_deploy.rindex("deployment_commit_armed=true", 0, deployment_prearm)
    deployment_completion_call = host_deploy.index("complete_deployment_commit prepared", deployment_prearm)
    if not deployment_verified < deployment_armed < deployment_prearm < deployment_completion_call:
        fail("Deployment publication is not conservatively armed before its durable prepared transaction.")
    deployment_completion = host_deploy[
        host_deploy.index("complete_deployment_commit() {") : host_deploy.index("seal_activation_deploy_failure() {")
    ]
    deployment_completion_order = (
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
    deployment_completion_positions = [deployment_completion.index(value) for value in deployment_completion_order]
    if deployment_completion_positions != sorted(deployment_completion_positions):
        fail("Deployment state, durable event, terminal record, or journal clearance ordering differs.")
    for required in (
        '<<\'PY\' >/dev/null || return 1',
        'ln -sfn -- "${release_dir}" /opt/mochirii/forums/current.next || return 1',
        'mv -Tf -- /opt/mochirii/forums/current.next /opt/mochirii/forums/current || return 1',
        'fsync_directory /opt/mochirii/forums || return 1',
        '"${requested_discourse_connect}" "${marker_file_for_evidence}" "${marker_sha_for_evidence}" || return 1',
    ):
        if required not in deployment_completion:
            fail("Deployment terminal publication can mask a durable mutation failure.")
    forward_fix_publication = host_deploy[
        host_deploy.index("seal_forward_fix_required() {") : host_deploy.index("validate_forward_fix_retry() {")
    ]
    for required in (
        'activate_config "${config_dir}/app.yml" || return 1',
        'current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk \'{print $1}\')" || return 1',
        "<<'PY' || return 1",
        "return 0",
    ):
        if required not in forward_fix_publication:
            fail("Forward-fix containment can mask its durable journal publication failure.")
    activation_failure_publication = host_deploy[
        host_deploy.index("seal_activation_deploy_failure() {") : host_deploy.index("recover_failed_activation() {")
    ]
    for required in (
        'activate_config "${previous_config}" || return 1',
        'record_sha="$(sha256sum -- "${record}" | awk \'{print $1}\')" || return 1',
        "<<'PY' || return 1",
        "return 0",
    ):
        if required not in activation_failure_publication:
            fail("Activation containment can mask its durable evidence or pointer publication failure.")
    deployment_terminal_retry = deployment_completion.index('if [[ ${phase} == complete ]]')
    deployment_terminal_verify = deployment_completion.index(
        'run_release_verification "${commit}" "${configuration_id}" || return 1', deployment_terminal_retry
    )
    deployment_active_verify = deployment_completion.index(
        'run_release_verification "${commit}" "${configuration_id}" --deployment-transaction', deployment_terminal_verify
    )
    if not deployment_terminal_retry < deployment_terminal_verify < deployment_active_verify:
        fail("Completed deployment adoption incorrectly claims an active verifier journal.")
    deployment_adoption = host_deploy.index("readarray -t deployment_resume < <(deployment_state_contract)")
    deployment_bootstrap = host_deploy.index('if [[ ${mode} == bootstrap ]]; then', deployment_adoption)
    deployment_storage = host_deploy.index("run_storage_fixture create", deployment_bootstrap)
    if not deployment_adoption < deployment_bootstrap < deployment_storage:
        fail("Deployment retry adoption occurs after bootstrap or hosted-storage side effects.")
    deployment_docs = read("docs/operations/DEPLOYMENT.md")
    recovery_docs = read("docs/operations/RECOVERY.md")
    validation_docs = read("docs/operations/VALIDATION.md")
    require_text(
        deployment_docs,
        [
            "leaves the mutation journal for the",
            "SHA-256 of the exact current-release bytes",
            "without its exact same-tuple deployment-mutation",
            "failure containment is conservatively armed before the",
            "prior-rollback owner accepts only a mutation-only `rebuild` journal",
            "refuses an existing container, database, active configuration, current-release",
        ],
        "deployment mutation lifecycle documentation",
    )
    require_text(
        deployment_docs,
        [
            "`KillMode=process`",
            "direct Git parent",
            "continues the newly approved upgrade in the same locked process",
            "identical-byte",
            "exact historical certificate-",
            "root-owned mode-`0755` executable-boundary contract",
            "exact mode-`0700` defect",
            "syncs the directory and its parent",
            "socket-activation recovery branch does not perform this repair",
            "Both transfer sessions use OpenSSH protocol keepalives every 30 seconds",
            "failed release journal remains `runtime-contained`",
            "`1d741eb75d08a226984935aa18e989ee324a0773`",
            "`b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f`",
            "`591d96484369ae29a8fa4e61219b325997f4b679`",
            "`a71bbe8070ca6dadeff3c4966e81bd97fee83cf7`",
            "cumulative diff from the failed release",
            "mochirii-forums-quarantine-failed-bootstrap",
            "Crash recovery accepts only the same pending tuple",
        ],
        "host-control changed-successor recovery documentation",
    )
    require_text(
        recovery_docs,
        [
            "leaves deployment ownership intact",
            "An orphan hosted-storage",
            "cleanup journal is never mutation authority.",
            "same-version/no-target-migration rollback",
            "bootstrap-only exception",
            "source-mode correction may upgrade",
            "`1d741eb75d08a226984935aa18e989ee324a0773`",
            "`b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f`",
            "`591d96484369ae29a8fa4e61219b325997f4b679`",
            "`a71bbe8070ca6dadeff3c4966e81bd97fee83cf7`",
            "complete failed standalone tree",
            "A crash resumes only through its own exact",
        ],
        "deployment mutation recovery documentation",
    )
    require_text(
        validation_docs,
        [
            "prior-rollback owner may name only a mutation-only exact sealed prior tuple",
            "Mutation plus promotion",
            "exact `/opt/mochirii/forums/current` symlink target",
        ],
        "deployment mutation verifier documentation",
    )
    for label, source, first, second in (
        ("deployment", host_deploy, "backup-transaction.json", "restore-transaction.json"),
        ("backup", host_backup, "deployment-transaction.json", "restore-transaction.json"),
        ("restore", host_restore, "deployment-transaction.json", "backup-transaction.json"),
    ):
        if first not in source or second not in source or "deployment-mutation.json" not in source:
            fail(f"Protected {label} lost an active cross-operation transaction refusal.")
    for label, source in (
        ("authentication finalization", host_authentication_finalizer),
        ("administrator recovery", host_break_glass),
    ):
        if any(name not in source for name in ("deployment-transaction.json", "deployment-mutation.json", "backup-transaction.json", "restore-transaction.json")):
            fail(f"{label} no longer refuses every active protected host transaction.")
    require_text(
        host_authentication_stop,
        [
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
        ],
        "mutation-bound pending activation containment exception",
    )
    mutation_required = host_authentication_stop.index(
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved && ${deployment_mutation_active} != true ]]; then'
    )
    failed_activation_branch = host_authentication_stop.index(
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then', mutation_required
    )
    exact_mutation_argument = host_authentication_stop.index(
        '"${configuration}" "${deployment_mutation}" <<\'PY\'', failed_activation_branch
    )
    unconditional_mutation_validation = host_authentication_stop.index(
        "validate_mutation(pathlib.Path(mutation_argument))", exact_mutation_argument
    )
    failed_activation_cardinality = host_authentication_stop.index(
        '[[ ${#evidence[@]} -eq 6', unconditional_mutation_validation
    )
    first_failed_activation_stop = host_authentication_stop.index(
        'docker stop --time 30 app', failed_activation_cardinality
    )
    if not (
        mutation_required
        < failed_activation_branch
        < exact_mutation_argument
        < unconditional_mutation_validation
        < failed_activation_cardinality
        < first_failed_activation_stop
    ):
        fail("Activation failure producer reconciliation can bypass exact mutation validation before containment.")
    require_text(
        host_verify,
        [
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
        ],
        "host verifier transaction and terminal ownership",
    )
    if "--deployment-transaction" in host_verify_wrapper or "--restore-transaction" in host_verify_wrapper:
        fail("Stable standalone host verification can adopt another operation's journal.")
    require_text(
        host_restore,
        ['bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" --restore-transaction'],
        "restore-owned host verification",
    )
    require_text(
        installer,
        [
            'write_text("restrict " + source + "\\n"',
            'config/sshd-forums-prepared.conf',
            'config/sshd-forums.conf',
            'Prepared installation cannot replace an already hardened host',
            'for hardened_record in "${state_root}/current-host-access.json" "${state_root}/current-host-control.json"',
            'validate_operator_proof() {',
            'getattr(os, "O_NOFOLLOW", 0)',
            'getattr(os, "O_NONBLOCK", 0)',
            'stat.S_IMODE(metadata.st_mode) != 0o600',
            'metadata.st_nlink != 1',
            'expected = b"operatorSshAndSudoVerified=true\\n"',
            'validate_operator_proof "${proof}" || fail "Existing operator SSH proof is unsafe."',
            'install -d -m 0755 -o root -g root /var/lib/mochirii "${state_root}"',
            'install -d -m 0755 -o root -g root "${state_root}/deploy/.ssh"',
            'atomic_install "${candidate}" "${target}" 0644',
            'sudo -u "${deploy_user}" test -r "${state_root}/deploy/.ssh/authorized_keys"',
            'sudo -u "${operator_user}" test -r "${state_root}/operator/.ssh/authorized_keys"',
            'sudo -l -U "${deploy_user}" "${forbidden}"',
            '/usr/local/sbin/mochirii-forums-upgrade-host-control',
            'host-access-install.pending.json',
            'host-control-evidence.py seal-access',
            'host-control-evidence.py seal-control',
            'ls-remote --refs "${canonical_repository}" refs/heads/main',
            'timeout --signal=TERM --kill-after=5s 15s sshd -T',
            'run_bounded_host_operation 60 systemctl reload ssh',
            'readonly ssh_generator_parent="/etc/systemd/system-generators"',
            'readonly ssh_generator_mask="/etc/systemd/system-generators/sshd-socket-generator"',
            '[[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]]',
            'stat -c \'%U:%G %a\' -- "${ssh_generator_parent}")" == "root:root 755"',
            'ln -s /dev/null "${staging}/mask"',
            'restore_ssh_socket_activation_predecessor()',
            'ensure_ssh_service_activation()',
            'run_bounded_host_operation 60 systemctl disable --now ssh.socket',
            'run_bounded_host_operation 60 systemctl enable --now ssh.service',
            'authorizedkeyscommanduser',
            'authorizedprincipalscommanduser',
            'permituserenvironment',
        ],
        "host SSH boundary",
    )
    if installer.count('validate_operator_proof "${proof}" || fail "Existing operator SSH proof is unsafe."') != 2:
        fail("Host SSH boundary does not bind both partial-proof recovery consumers.")
    require_text(
        hardened_ssh,
        [
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "AllowUsers mochirii-forums-operator mochirii-forums-deploy",
            "AuthorizedKeysCommand none",
            "TrustedUserCAKeys none",
            "AuthorizedPrincipalsFile none",
            "AuthorizedPrincipalsCommand none",
            "AuthorizedKeysFile /var/lib/mochirii/forums/operator/.ssh/authorized_keys",
            "AuthorizedKeysFile /var/lib/mochirii/forums/deploy/.ssh/authorized_keys",
            "ForceCommand /usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
            "DisableForwarding yes",
            "PermitUserRC no",
        ],
        "hardened SSH policy",
    )
    if "PermitRootLogin no" in prepared_ssh or "AllowUsers " in prepared_ssh:
        fail("Prepared SSH policy can lock out the retained bootstrap session before operator proof.")
    if 'install -d -m 0700 -o root -g root "${state_root}/deploy/.ssh"' in installer:
        fail("Host SSH source restored an unreadable privilege-dropped key directory.")
    require_text(
        prepared_ssh,
        [
            "AuthorizedKeysCommand none",
            "TrustedUserCAKeys none",
            "AuthorizedPrincipalsFile none",
            "ForceCommand /usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
            "DisableForwarding yes",
            "PermitUserRC no",
        ],
        "prepared SSH policy",
    )
    if "authorized_keys2" in installer + hardened_ssh + prepared_ssh or "AuthorizedKeysCommand " not in hardened_ssh:
        fail("Host SSH source policy regained an alternate key source.")
    allow_users_program = (
        '$1 == "allowusers" { for (i = 2; i <= NF; i++) { '
        'found = found (found == "" ? "" : " ") $i } } END { print found }'
    )
    if installer.count(f"awk '{allow_users_program}'") != 1 or host_security.count(
        f"awk '{allow_users_program}'"
    ) != 1:
        fail("Host SSH consumers do not share the exact multi-row AllowUsers parser.")
    if 'found=$0' in installer + host_security:
        fail("Host SSH source retains only one emitted AllowUsers row.")
    require_text(
        host_security,
        [
            '"root:root 755"',
            '"root:root 644"',
            'sudo -u "mochirii-forums-${home}" test -r "${key_file}"',
            'Sensitive host-control directory',
            'SSH tree contains an alternate key or user-rc source.',
            'authorizedkeyscommand',
            'authorizedkeyscommanduser',
            'trustedusercakeys',
            'authorizedprincipalsfile',
            'authorizedprincipalscommanduser',
            'permituserenvironment',
            'forcecommand',
            'for group in ("coreTargets", "hostPolicyTargets"):',
            'service_state fail2ban',
            'service_state unattended-upgrades',
            'fail2ban-client status sshd',
            'docker version --format',
            'ufw status verbose',
            'unexpected public listener',
            'host-control target-set digest differs',
            'host-control evidence target inventory differs',
            'certificate automation target set is partial',
            'service_state mochirii-forums-media-certificate-renew.timer',
            'libexec_root=/usr/local/libexec/mochirii-forums',
            'deploy_dispatcher="${libexec_root}/ssh-deploy-dispatch.py"',
            '"$(stat -c \'%U:%G %a\' "${libexec_root}")" == "root:root 755"',
            'sudo -u mochirii-forums-deploy test -x "${deploy_dispatcher}"',
            '--upgrade-transaction',
            '--socket-activation-recovery',
            '--upgrade-socket-activation-recovery',
            'ssh_generator_parent=/etc/systemd/system-generators',
            'OpenSSH socket-generator parent is unsafe.',
            'ssh_generator_mask=/etc/systemd/system-generators/sshd-socket-generator',
            'OpenSSH socket-activation recovery service-enable state differs.',
            'OpenSSH socket-activation recovery socket-active state differs.',
            'service_state ssh.service || fail "OpenSSH service is not enabled and active."',
            'OpenSSH socket remains enabled.',
            'OpenSSH socket remains active.',
        ],
        "hosted host-security verification",
    )
    if 'service_state ssh.socket || fail "OpenSSH service is not enabled and active."' in host_security:
        fail("Hosted host-security verification permits socket activation as a terminal state.")
    require_text(
        control_upgrade,
        [
            'canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"',
            'fetch --no-tags --depth=1 --refmap= origin refs/heads/main',
            'tar --no-same-owner --no-same-permissions -xf "${archive}" -C "${candidate}"',
            'Host-control upgrade requires the application to be proved stopped.',
            'assert-held --locks primary,media',
            'run --locks primary,media',
            'control-upgrade.pending.json',
            'readonly libexec_root="/usr/local/libexec/mochirii-forums"',
            'reconcile_shared_libexec_traversal() {',
            '[[ ${current_mode} == 700 ]]',
            'chmod 0755 -- "${libexec_root}"',
            'sync -d "${libexec_root}"',
            'sudo -u mochirii-forums-deploy test -x "${libexec_root}/ssh-deploy-dispatch.py"',
            'reconcile_shared_libexec_traversal "${previous_source}" "${candidate}"',
            'os.fsync(writer.fileno())',
            'os.replace(candidate, target)',
            'rollback_transaction',
            'targets_are_new',
            'durable_remove_workdir',
            'reconcile_unjournaled_workdirs',
            'validate_effective_hardened_ssh',
            'seal_control_state upgrade',
            'verify-host-security.sh',
            '--upgrade-transaction',
            '--socket-activation-recovery',
            '--upgrade-socket-activation-recovery',
            'readonly ssh_generator_parent="/etc/systemd/system-generators"',
            'readonly ssh_generator_mask="/etc/systemd/system-generators/sshd-socket-generator"',
            '[[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]]',
            'stat -c \'%U:%G %a\' -- "${ssh_generator_parent}")" == "root:root 755"',
            'ssh_activation_predecessor()',
            'restore_ssh_activation_predecessor()',
            'verify_previous_host_controls()',
            'bounded 15s systemctl show ssh.service -p KillMode --value',
            'bounded 60s systemctl enable ssh.socket',
            'bounded 60s systemctl stop ssh.service',
            'bounded 60s systemctl start ssh.socket',
            'validate_effective_hardened_ssh() {',
            'validate_effective_hardened_ssh || return 1',
            '"sshActivationPredecessor"',
            '.control-upgrade-staging-${expected_commit}.XXXXXXXX',
            'bounded 60s systemctl disable --now ssh.socket',
            'bounded 60s systemctl enable --now ssh.service',
            'bash "${candidate_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-transaction',
            'bash "${candidate_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-socket-activation-recovery',
            'bash "${candidate}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --socket-activation-recovery',
            'readonly host_control_releases_root="/opt/mochirii/forums/host-control-releases"',
            'bind_previous_source() {',
            'json.loads(raw_pointer.decode("utf-8"), object_pairs_hook=strict_object)',
            'document.get("releaseArchiveFile") != str(archive)',
            'exact_regular(helper_path, 0o600, 2 * 1024 * 1024, "Candidate archive authority")',
            'module.inspect_archive(sealed_archive, commit)',
            'module.extract_exact(sealed_archive, identity, source_root)',
            'module.source_identity(source_root)',
            'bind_previous_source "${transaction}/backup/current-host-control.json" "${transaction}" "${candidate}" verify',
            'if ! predecessor_output="$(',
            'readarray -t predecessor_state <<<"${predecessor_output}"',
            '[[ ${previous_evidence_sha} == "${previous_sha}" ]]',
            'bind_previous_source "${control_pointer}" "${staging}" "${candidate}" prepare',
            'if ! previous_state_output="$(',
            'readarray -t previous_state <<<"${previous_state_output}"',
            'previous_source="${transaction}/previous-source/${previous_commit}"',
            'bind_invoked_canonical_successor() {',
            '[[ -f $0 && ! -L $0 ]]',
            'invocation_source_root="$(dirname -- "$(dirname -- "${invocation_script}")")"',
            'rev-parse --verify "${requested_commit}^1"',
            'ls-remote --refs "${canonical_repository}" refs/heads/main',
            'bind_invoked_canonical_successor "${requested_commit}" "${commit}"',
            'successor_recovery=true',
            'recovery_continue=true',
            '[[ ${recovery_continue} == true ]] || exit 0',
            'unchanged bytes must not be retried',
            '${SUDO_USER:-} == mochirii-forums-operator',
        ],
        "transactional host-control upgrade",
    )
    require_text(
        control_upgrade,
        [
            "validate_failed_bootstrap_upgrade_exception() {",
            "select_reviewed_failed_bootstrap_recovery_commit() {",
            "validate_reviewed_failed_bootstrap_successor_paths() {",
            'readonly reviewed_legacy_failed_bootstrap_commit="b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f"',
            'readonly reviewed_failed_bootstrap_recovery_commit="1d741eb75d08a226984935aa18e989ee324a0773"',
            'readonly reviewed_active_swap_failed_bootstrap_commit="26e793aada31faeaa8b56308625288164430647c"',
            'readonly reviewed_active_swap_recovery_commit="6e2f1b5c831b992c3222c015836fa180cd591e3e"',
            'readonly reviewed_acme_failed_bootstrap_commit="f564d62a82adf79b8f012a25949826e2b447681d"',
            'readonly reviewed_acme_recovery_commit="85e12f1ce27e1462e7c82e59e1dbf01c190327b9"',
            'readonly reviewed_quarantine_output_failed_bootstrap_commit="c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306"',
            'readonly reviewed_quarantine_output_recovery_commit="8eea740795f0536468e48c5e8cda2ded29b1e51e"',
            'readonly reviewed_acme_reload_privacy_failed_bootstrap_commit="fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d"',
            'readonly reviewed_acme_reload_privacy_recovery_commit="f51c2e8deaf39293c9b97f3aab797b882c3dc628"',
            'readonly reviewed_acme_reload_privacy_recovery_child_commit="591d96484369ae29a8fa4e61219b325997f4b679"',
            'readonly reviewed_acme_reload_privacy_launcher_child_commit="a71bbe8070ca6dadeff3c4966e81bd97fee83cf7"',
            'rev-parse --verify "${requested_commit}^1"',
            'rev-list --parents -n 1 "${requested_commit}"',
            'rev-parse --verify "${reviewed_acme_reload_privacy_launcher_child_commit}^1"',
            'rev-list --parents -n 1 "${reviewed_acme_reload_privacy_launcher_child_commit}"',
            'rev-parse --verify "${reviewed_acme_reload_privacy_recovery_child_commit}^1"',
            'rev-list --parents -n 1 "${reviewed_acme_reload_privacy_recovery_child_commit}"',
            'rev-parse --verify "${reviewed_recovery_commit}^1"',
            'rev-list --parents -n 1 "${reviewed_recovery_commit}"',
            'diff-tree --no-commit-id --name-only -r "${pending_commit}" "${requested_commit}"',
            '[[ -f ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh && ! -L ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh && ! -x ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh ]]',
            'scripts/quarantine-failed-bootstrap.sh" --upgrade-preflight',
            'bind_invoked_canonical_successor "${requested_commit}" "${state[0]}"',
            "deployment_recovery_upgrade=false",
            'validate_failed_bootstrap_upgrade_exception "${expected_commit}"',
            'terminal_recovery_output="$(bash "${candidate}/scripts/quarantine-failed-bootstrap.sh" --upgrade-preflight',
            '[[ ${terminal_recovery_passed} != true ]] || ! bash "${candidate}/scripts/verify-host-security.sh"',
        ],
        "failed-bootstrap pinned-successor host-control exception",
    )
    require_text(
        failed_bootstrap_quarantine,
        [
            'readonly pending_journal="${state_root}/failed-bootstrap-quarantine.pending.json"',
            'readonly recovery_root="${shared_root}/.mochirii-forums-failed-bootstrap"',
            'readonly reviewed_legacy_failed_bootstrap_commit="b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f"',
            'readonly reviewed_failed_bootstrap_recovery_commit="1d741eb75d08a226984935aa18e989ee324a0773"',
            'readonly reviewed_active_swap_failed_bootstrap_commit="26e793aada31faeaa8b56308625288164430647c"',
            'readonly reviewed_active_swap_recovery_commit="6e2f1b5c831b992c3222c015836fa180cd591e3e"',
            'readonly reviewed_acme_failed_bootstrap_commit="f564d62a82adf79b8f012a25949826e2b447681d"',
            'readonly reviewed_acme_recovery_commit="85e12f1ce27e1462e7c82e59e1dbf01c190327b9"',
            'readonly reviewed_quarantine_output_failed_bootstrap_commit="c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306"',
            'readonly reviewed_quarantine_output_recovery_commit="8eea740795f0536468e48c5e8cda2ded29b1e51e"',
            'readonly reviewed_acme_reload_privacy_failed_bootstrap_commit="fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d"',
            'readonly reviewed_acme_reload_privacy_recovery_commit="f51c2e8deaf39293c9b97f3aab797b882c3dc628"',
            'readonly reviewed_acme_reload_privacy_recovery_child_commit="591d96484369ae29a8fa4e61219b325997f4b679"',
            'readonly reviewed_acme_reload_privacy_launcher_child_commit="a71bbe8070ca6dadeff3c4966e81bd97fee83cf7"',
            'rev-parse --verify "${current}^1"',
            'rev-list --parents -n 1 "${current}"',
            'rev-parse --verify "${reviewed_acme_reload_privacy_launcher_child_commit}^1"',
            'rev-list --parents -n 1 "${reviewed_acme_reload_privacy_launcher_child_commit}"',
            'rev-parse --verify "${reviewed_acme_reload_privacy_recovery_child_commit}^1"',
            'rev-list --parents -n 1 "${reviewed_acme_reload_privacy_recovery_child_commit}"',
            'rev-parse --verify "${reviewed_recovery_commit}^1"',
            'rev-list --parents -n 1 "${reviewed_recovery_commit}"',
            'legacy_expected_paths=(',
            ".github/workflows/deploy-forums.yml",
            "config/host-control-manifest.v1.json",
            "docs/operations/DEPLOYMENT.md",
            "docs/operations/RECOVERY.md",
            "scripts/quarantine-failed-bootstrap.sh",
            "scripts/test-contracts.py",
            "scripts/upgrade-host-control.sh",
            "scripts/validate-repository.py",
            'active_swap_expected_paths=(',
            "scripts/verify-host.sh",
            'acme_expected_paths=(',
            "config/immutable-letsencrypt.fragment.yml",
            'quarantine_output_expected_paths=(',
            'acme_reload_privacy_expected_paths=(',
            'object_pairs_hook=reject_duplicate',
            'metadata.st_uid != 0',
            'metadata.st_gid != 0',
            'metadata.st_nlink != 1',
            "list(itertools.islice(evidence.iterdir(), 4097))",
            "validate_quarantine_environment() {",
            "read_quarantine_identity() {",
            'if [[ ${1:-} == --upgrade-preflight ]]',
            "QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP",
            "assert-held --locks primary,media",
            "run --locks primary,media",
            "# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION",
            'phase_order = {"prepared": 0, "runtime-quarantined": 1, "clean-boundary": 2, "authority-retired": 3}',
            "decode_canonical(pending, \"failed-bootstrap pending journal\")",
            "def exact_inventory(path, maximum, label):",
            "list(itertools.islice(path.iterdir(), maximum + 1))",
            "decode_canonical(mutation, \"deployment mutation journal\", mutation_sha)",
            "os.rename(standalone, quarantine)",
            "os.rename(old_ssl, new_ssl)",
            "os.rename(mutation, mutation_evidence)",
            'expected_inventory = {"ssl"} if state["sslPresent"] else set()',
            'validate_state(state, {"prepared"})',
            "validate_state(state, {phase})",
            'validate_state(terminal_document, {"complete"}, terminal_state=True)',
            "publish(terminal, terminal_document, True)",
            "pending.unlink()",
            "# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION",
            'verify-host-security.sh" "${current_commit}"',
            "mochirii-forums-media-certificate-renew.timer",
            '[[ ! -e ${deployment_journal} && ! -L ${deployment_journal} ]]',
        ],
        "failed-bootstrap reversible quarantine transaction",
    )
    if any(
        value in failed_bootstrap_quarantine
        for value in (
            "shutil.rmtree",
            "rm -rf",
            "find ${quarantine} -delete",
            "mutation.unlink()",
            "mutation_evidence.unlink()",
            "quarantine.rmdir()",
        )
    ):
        fail("Failed-bootstrap quarantine gained a destructive retained-evidence path.")
    if "{entry.name for entry in standalone.iterdir()}" in failed_bootstrap_quarantine:
        fail("Failed-bootstrap clean-boundary inventory is not bounded.")
    if (
        failed_bootstrap_quarantine.count("# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION") != 1
        or failed_bootstrap_quarantine.count("# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION") != 1
        or failed_bootstrap_quarantine.count("pending.unlink()") != 2
    ):
        fail("Failed-bootstrap quarantine transaction or exact journal retirement count differs.")
    quarantine_order = tuple(
        failed_bootstrap_quarantine.index(value)
        for value in (
            "# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION",
            "publish(pending, state, True)",
            "os.rename(standalone, quarantine)",
            "standalone.mkdir(mode=state[\"standaloneMode\"])",
            "os.rename(mutation, mutation_evidence)",
            "publish(terminal, terminal_document, True)",
            "# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION",
        )
    )
    if quarantine_order != tuple(sorted(quarantine_order)):
        fail("Failed-bootstrap quarantine can retire authority before durable runtime preservation.")
    upgrade_exception_gate = control_upgrade.index(
        'if [[ -e ${state_root}/deployment-mutation.json || -L ${state_root}/deployment-mutation.json ]]'
    )
    upgrade_first_mutation = control_upgrade.index('install -d -m 0755 -o root -g root /var/lib/mochirii', upgrade_exception_gate)
    upgrade_seal = control_upgrade.index('seal_control_state upgrade "${expected_commit}"')
    upgrade_recovery_readback = control_upgrade.index('terminal_recovery_output="$(bash "${candidate}/scripts/quarantine-failed-bootstrap.sh"', upgrade_seal)
    upgrade_terminal_verifier = control_upgrade.index(
        'bash "${candidate}/scripts/verify-host-security.sh" "${expected_commit}" "${candidate}" --upgrade-transaction',
        upgrade_recovery_readback,
    )
    if not upgrade_exception_gate < upgrade_first_mutation < upgrade_seal < upgrade_recovery_readback < upgrade_terminal_verifier:
        fail("Failed-bootstrap host-control exception can bypass pre-mutation or terminal verification.")
    candidate_validation = control_upgrade.index(
        'bounded 300s python3 -B "${candidate}/scripts/validate-repository.py"'
    )
    predecessor_binding = control_upgrade.index(
        'bind_previous_source "${control_pointer}" "${staging}" "${candidate}" prepare',
        candidate_validation,
    )
    predecessor_gate = control_upgrade.index(
        'ssh_predecessor="$(ssh_activation_predecessor)"', predecessor_binding
    )
    predecessor_verifier = control_upgrade.index(
        'bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}"',
        predecessor_gate,
    )
    traversal_repair = control_upgrade.index(
        'reconcile_shared_libexec_traversal "${previous_source}" "${candidate}"',
        predecessor_verifier,
    )
    recovery_gate = control_upgrade.index('--socket-activation-recovery', traversal_repair)
    retained_archives = control_upgrade.index(
        'retain_disaster_recovery_sources "${archive}"', recovery_gate
    )
    transaction_move = control_upgrade.index('mv -- "${staging}" "${transaction}"', retained_archives)
    moved_predecessor = control_upgrade.index(
        'previous_source="${transaction}/previous-source/${previous_commit}"', transaction_move
    )
    journal_position = control_upgrade.index(
        'os.link(candidate, journal_path, follow_symlinks=False)', moved_predecessor
    )
    first_publication = control_upgrade.index(
        'atomic_install "${candidate}/${relative}"', journal_position
    )
    activation_commit = control_upgrade.index(
        'ensure_ssh_service_activation || {', first_publication
    )
    first_readback = control_upgrade.index(
        'post_install_readback "${candidate}"', activation_commit
    )
    terminal_verification = control_upgrade.index(
        'bash "${candidate}/scripts/verify-host-security.sh" "${expected_commit}" "${candidate}" --upgrade-transaction',
        first_readback,
    )
    if not (
        candidate_validation
        < predecessor_binding
        < predecessor_gate
        < predecessor_verifier
        < traversal_repair
        < recovery_gate
        < retained_archives
        < transaction_move
        < moved_predecessor
        < journal_position
        < first_publication
        < activation_commit
        < first_readback
        < terminal_verification
    ):
        fail("SSH service activation can bypass validation, journaling, publication, readback, or terminal verification.")
    traversal_function_start = control_upgrade.index("reconcile_shared_libexec_traversal() {")
    traversal_function_end = control_upgrade.index("\n}\n", traversal_function_start)
    traversal_function = control_upgrade[traversal_function_start:traversal_function_end]
    if [line.strip() for line in traversal_function.splitlines() if "chmod " in line] != [
        'chmod 0755 -- "${libexec_root}" || return 1'
    ]:
        fail("Host-control traversal reconciliation can change more than the exact shared-directory mode.")
    if traversal_function.count(
        'sudo -u mochirii-forums-deploy test -x "${libexec_root}/ssh-deploy-dispatch.py"'
    ) != 2:
        fail("Host-control traversal reconciliation omits idempotent or corrected deploy-principal readback.")
    service_branch_end = control_upgrade.index("\nelse\n", predecessor_verifier)
    socket_branch_end = control_upgrade.index("\nfi\n", service_branch_end)
    if traversal_repair >= service_branch_end or "reconcile_shared_libexec_traversal" in control_upgrade[
        service_branch_end:socket_branch_end
    ]:
        fail("Host-control traversal reconciliation is not confined to the verified service predecessor.")
    post_readback_start = control_upgrade.index("post_install_readback() {")
    post_readback_end = control_upgrade.index("clear_transaction() {", post_readback_start)
    post_readback = control_upgrade[post_readback_start:post_readback_end]
    if any(
        value not in post_readback
        for value in (
            '"$(stat -c \'%U:%G %a\' "${libexec_root}")" == "root:root 755"',
            'sudo -u mochirii-forums-deploy test -x "${libexec_root}/ssh-deploy-dispatch.py"',
        )
    ):
        fail("Host-control terminal readback omits shared executable traversal.")
    reconcile_start = control_upgrade.index("reconcile_pending() {")
    recovery_predecessor_binding = control_upgrade.index(
        'bind_previous_source "${transaction}/backup/current-host-control.json"', reconcile_start
    )
    recovery_target_classification = control_upgrade.index(
        "if [[ ${successor_recovery} == false ]] && targets_are_new; then", recovery_predecessor_binding
    )
    if not reconcile_start < recovery_predecessor_binding < recovery_target_classification:
        fail("Interrupted host-control recovery trusts installed targets before predecessor reconstruction.")
    if '/opt/mochirii/forums/releases/${previous_commit}' in control_upgrade:
        fail("Host-control upgrade assumes an application release exists for its predecessor.")
    if control_upgrade.count("metadata.st_nlink != 1") != 2:
        fail("Host-control predecessor archive or extracted-source link guard differs.")
    if re.search(r"readarray -t (?:predecessor_state|previous_state) < <\(\s*bind_previous_source", control_upgrade):
        fail("Host-control predecessor binding status is hidden by process substitution.")
    if re.search(r"readarray -t state < <\(\s*read_journal", control_upgrade):
        fail("Host-control journal producer status is hidden by process substitution.")
    if '[[ -z "$(git -c core.fsmonitor=false -C "${invocation_source_root}" status' in control_upgrade:
        fail("Host-control successor binding can hide a failed Git status producer.")
    if '[[ -x ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh' in control_upgrade:
        fail("Host-control failed-bootstrap preflight still requires executable repository source.")
    if control_upgrade.count("validate_effective_hardened_ssh() {") != 1 or control_upgrade.count(
        "validate_effective_hardened_ssh || return 1"
    ) != 1:
        fail("Host-control effective SSH readback is undefined, duplicated, or unbound.")
    installer_restore_start = installer.index("restore_ssh_socket_activation_predecessor() {")
    installer_restore = installer[installer_restore_start:installer.index("\n}\n", installer_restore_start)]
    upgrade_restore_start = control_upgrade.index("restore_ssh_activation_predecessor() {")
    upgrade_restore = control_upgrade[upgrade_restore_start:control_upgrade.index("\n}\n", upgrade_restore_start)]
    restore_order = (
        "systemctl show ssh.service -p KillMode --value",
        "systemctl disable ssh.service",
        'durable_remove "${ssh_generator_mask}"',
        "systemctl daemon-reload",
        "systemctl enable ssh.socket",
        "systemctl stop ssh.service",
        "systemctl start ssh.socket",
        "systemctl start ssh.service",
        "ssh_socket_activation_is_exact_predecessor",
    )
    for restore in (installer_restore, upgrade_restore):
        positions = [restore.index(token) for token in restore_order]
        if positions != sorted(positions) or "systemctl enable --now ssh.socket" in restore:
            fail("SSH socket-predecessor restoration can conflict with the active service listener.")
    rollback_verifier_start = control_upgrade.index("verify_previous_host_controls() {")
    rollback_verifier_end = control_upgrade.index("\n}\n", rollback_verifier_start)
    rollback_verifier = control_upgrade[rollback_verifier_start:rollback_verifier_end]
    if '${previous_source}/scripts/verify-host-security.sh' in rollback_verifier:
        fail("SSH activation rollback uses the schema-incompatible predecessor verifier.")
    require_text(
        control_evidence,
        [
            "os.link(candidate, path, follow_symlinks=False)",
            "os.replace(candidate, path)",
            '"previousControlEvidenceSha256"',
            '"targetSetSha256"',
            'seal_access()',
            'seal_control(',
            'STATE_ROOT / "deploy/.ssh/authorized_keys", 0o644',
            'STATE_ROOT / "operator/.ssh/authorized_keys", 0o644',
        ],
        "host-control evidence sealing",
    )
    require_text(
        host_verify,
        [
            'timeout --signal=TERM --kill-after=15s 180s bash "${release_dir}/scripts/verify-discourse-docker-checkout.sh"',
            'timeout --signal=TERM --kill-after=10s 180s bash "${release_dir}/scripts/verify-runtime-assets.sh"',
            'timeout --signal=TERM --kill-after=5s 30s docker image inspect',
            "docker exec -u discourse app bash -lc",
            "export GIT_OPTIONAL_LOCKS=0",
            "git -C /var/www/discourse diff --no-ext-diff --quiet HEAD --",
            "git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --quiet HEAD --",
            "status --porcelain=v1 --untracked-files=all",
        ],
        "bounded full hosted source verification",
    )
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
        fail("Hosted Git proof is not exactly bound to the owner-scoped mutation-free block.")
    require_text(
        deployment_checkout,
        [
            'status --porcelain=v1 --untracked-files=all',
            'timeout --signal=TERM --kill-after=5s 15s docker image inspect',
            'timeout --signal=TERM --kill-after=5s 15s docker rm --force',
            'timeout --signal=TERM --kill-after=5s 15s docker container ls',
        ],
        "bounded sealed discourse_docker checkout verification",
    )
    control_manifest = json.loads(read("config/host-control-manifest.v1.json"))
    expected_control_targets = {
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
        "/usr/local/sbin/mochirii-forums-quarantine-failed-bootstrap",
        "/usr/local/sbin/mochirii-forums-restore",
        "/usr/local/sbin/mochirii-forums-stop-pending-activation",
        "/usr/local/sbin/mochirii-forums-upgrade-host-control",
        "/usr/local/sbin/mochirii-forums-verify",
    }
    expected_policy_targets = {
        "/etc/apt/apt.conf.d/20auto-upgrades",
        "/etc/docker/daemon.json",
        "/etc/fail2ban/jail.d/mochirii-forums.conf",
        "/etc/ssh/sshd_config.d/00-00-mochirii-forums.conf",
        "/etc/sudoers.d/mochirii-forums",
        "/etc/sudoers.d/mochirii-forums-operator",
    }
    expected_certificate_targets = {
        "/etc/systemd/system/mochirii-forums-media-certificate-renew.service",
        "/etc/systemd/system/mochirii-forums-media-certificate-renew.timer",
        "/usr/local/libexec/mochirii-forums/media-certificate-operation.sh",
        "/usr/local/libexec/mochirii-forums/reconcile-acme-dns.py",
        "/usr/local/libexec/mochirii-forums/rotate-media-certificate.py",
        "/usr/local/sbin/mochirii-forums-renew-media-certificate",
        "/usr/local/sbin/mochirii-forums-rotate-media-certificate",
    }
    for group, expected_targets in (
        ("coreTargets", expected_control_targets),
        ("hostPolicyTargets", expected_policy_targets),
        ("certificateTargets", expected_certificate_targets),
    ):
        rows = control_manifest.get(group)
        if not isinstance(rows, list) or {row.get("target") for row in rows if isinstance(row, dict)} != expected_targets:
            fail(f"Host-control manifest {group} inventory differs.")
        for row in rows:
            if set(row) != {"mode", "source", "target"} or row["mode"] not in {"0440", "0644", "0755"}:
                fail(f"Host-control manifest {group} row differs.")
            source = ROOT / row["source"]
            if not source.is_file() or source.is_symlink():
                fail(f"Host-control manifest source is absent or linked: {row['source']}")

    checkout = read("scripts/verify-discourse-docker-checkout.sh")
    require_text(
        checkout,
        [
            f'revision="{DOCKER_REVISION}"',
            'tree="588498dffbea91592fd4e2f10166bc11c8fe7a61"',
            'canonical="https://github.com/discourse/discourse_docker.git"',
            'disabled_push="no_push://mochirii-forums-upstream"',
            "status --porcelain=v1 --untracked-files=all",
            "symbolic-ref -q HEAD",
            "remote.origin.pushurl",
            "verify_file launcher 25507 61df33243194e85fc45ae5cad850ec6b646b8eef2ec0ff3da4974d50867c7c39",
            "verify_file samples/standalone.yml 4878 7690f2d3ee2eee6db7a701311bff310a7822ebdd62a0fa6687c5cb5b72296644",
            "verify_file templates/web.template.yml 17512 975f9933f31b0172679fb741193b222fdef712ebb901fdc6064634f1ec7a9037",
            "verify_file templates/postgres.template.yml 13450 37c12ba6725be36123a0e55f56a5fd98d045300d02f83dfda213aab3849efe8f",
            "(app|restore|activation)[.]yml",
            'docker image inspect "${base_image}"',
            "--pull=never",
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            BASE_DIGEST,
        ],
        "sealed deployment checkout",
    )

    rotation = read("scripts/rotate-media-certificate.py")
    renewal = read("scripts/run-media-certificate-renewal.sh")
    preparation = read("scripts/prepare-media-certificate.sh")
    certificate_installer = read("scripts/install-media-certificate-renewal.sh")
    contract_tests = read("scripts/test-contracts.py")
    provider_tls_docs = read("docs/operations/PROVIDER-DNS-TLS.md")
    require_text(
        rotation,
        [
            'media-certificate-rotation.pending.json',
            "MAX_CERTIFICATES = 200",
            "MAX_PRE_MUTATION_CERTIFICATES = 190",
            "write_journal(journal)",
            "reconcile_journal(token, endpoint_id, expected_origin)",
            "delete_transaction_certificate",
            '(method == "GET" and certificate_match is not None and UUID.fullmatch(certificate_match.group(1)))',
            "class RetirementSettlementPending",
            "def record_retirement_absence",
            "now - int(previous) < 60",
            "time.sleep(60)",
            "class NoRedirectHandler",
            "PROVIDER_OPENER.open",
            "response.geturl() != url",
            "Provider API redirect was blocked.",
        ],
        "certificate transaction boundary",
    )
    require_text(renewal, ["--reconcile-only", "--preflight-only"], "certificate renewal reconciliation")
    require_text(
        preparation,
        [
            'media_reconcile_acme "${acme_helper}" /etc/letsencrypt/mochirii-cloudflare.ini',
            "if validate_lineage; then",
            "write_preparation_journal issued",
            "clear_preparation_journal",
            '[[ ${san_names} == "DNS:media-forums.mochirii.com" ]]',
            "discard_incomplete_transaction_lineage()",
            'str(base) != "/etc/letsencrypt"',
            're.fullmatch(r"(?:cert|chain|fullchain|privkey)[1-9][0-9]{0,5}[.]pem", entry.name)',
            'normalized.parent != archive',
            "fsync_directory(live.parent)",
            "fsync_directory(archive.parent)",
            'discard_incomplete_transaction_lineage || fail "Interrupted certificate preparation has unsafe or ambiguous partial lineage state;',
        ],
        "prepared-phase certificate issuance recovery",
    )
    if any(value in preparation for value in ("shutil.rmtree", 'rm -rf -- "${lineage}"', "find ${lineage} -delete")):
        fail("Prepared certificate recovery exceeds its exact journal-owned lineage inventory.")
    require_text(
        certificate_installer,
        [
            'validate_prepared_input "${certbot_source}" "${prepared_certbot}"',
            'validate_prepared_input "${dns_source}" "${prepared_dns}"',
            '[[ -f ${prepared} && ! -L ${prepared} ]]',
            'cmp -s -- "${source}" "${prepared}"',
            'for target in "${install_targets[@]}"',
            'assert-held --locks primary,media',
            'run --locks primary,media',
            'read_current_control_binding()',
            'validate_installed_automation_bytes()',
            '"manifestSha256": manifest_sha',
            '"previousControlEvidenceSha256": predecessor',
            'seal_certificate_control_state()',
            '--operation certificate-install',
            'verify_certificate_control_state()',
            'timeout --signal=TERM --kill-after=10s 180s bash "${host_security_verifier}"',
            'install -d -m 0700 -o root -g root "${log_root}" /etc/mochirii /etc/letsencrypt',
            'install -d -m 0755 -o root -g root "${libexec_root}"',
            '"$(stat -c \'%U:%G %a\' "${libexec_root}")" == "root:root 755"',
        ],
        "preparation-owned certificate input and host-control evidence adoption",
    )
    collapsed_libexec_install = (
        'install -d -m 0700 -o root -g root "${log_root}" '
        '/usr/local/libexec/mochirii-forums /etc/mochirii /etc/letsencrypt'
    )
    private_directory_install = (
        'install -d -m 0700 -o root -g root "${log_root}" /etc/mochirii /etc/letsencrypt'
    )
    shared_directory_install = 'install -d -m 0755 -o root -g root "${libexec_root}"'
    if collapsed_libexec_install in certificate_installer:
        fail("Certificate installer collapses the shared executable parent to the private-directory mode.")
    installer_directory_order = tuple(
        certificate_installer.index(value)
        for value in (
            private_directory_install,
            shared_directory_install,
            '"$(stat -c \'%U:%G %a\' "${libexec_root}")" == "root:root 755"',
            '[[ ! -e ${preparation_journal}',
        )
    )
    if installer_directory_order != tuple(sorted(installer_directory_order)):
        fail("Certificate installer does not establish and verify shared traversal before mutation.")
    require_text(
        provider_tls_docs,
        [
            "shared executable traversal boundary",
            "mode-`0755` directory",
            "unprivileged deploy principal",
            "private-directory mode",
        ],
        "certificate shared executable traversal documentation",
    )
    recovery_start = certificate_installer.index('if [[ ${prior_install_phase} == committed ]]')
    recovery_end = certificate_installer.index('cleanup_installation || fail', recovery_start)
    recovery = certificate_installer[recovery_start:recovery_end]
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
    if [recovery.index(value) for value in recovery_order] != sorted(
        recovery.index(value) for value in recovery_order
    ):
        fail("Committed certificate install can terminate before exact control-evidence adoption and verification.")
    install_start = certificate_installer.index('write_install_journal installing')
    install = certificate_installer[install_start:]
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
    if [install.index(value) for value in install_order] != sorted(
        install.index(value) for value in install_order
    ):
        fail("Certificate install control reseal, terminal verification, event, or clearance ordering differs.")
    require_text(
        contract_tests,
        [
            "test_certificate_create_cleanup",
            "test_certificate_identity_read_allowlist",
            "test_certificate_inventory_capacity",
            "test_certificate_preparation_recovery_contract",
            "test_shared_libexec_traversal_contract",
            "test_certificate_control_evidence_adoption_contract",
            "test_certificate_commit_forward_retirement",
            "test_certificate_commit_forward_ignores_stale_absence",
            "test_http_redirect_boundaries",
            "test_storage_response_boundary",
            "test_ssh_dispatch_contract",
            "test_deployment_terminal_transaction_contract",
            "Capacity gate allowed a 201st certificate mutation.",
            "Hostile certificate identity method or path was accepted.",
            "Commit-forward retirement attempted to rebind the old certificate.",
            "A successful DELETE plus one immediate absence cleared the journal.",
            "First successful-DELETE absence was not retained in the sealed journal.",
            "Time-separated successful-DELETE retirement did not finish safely.",
            "Hosted storage cleanup state is not armed before the untrusted streamed response.",
            "Concurrent SSH intake did not fail closed.",
            "Overlong SSH intake deadline did not fail closed.",
        ],
        "hostile infrastructure fixtures",
    )
    storage_fixture = read("scripts/verify-storage-fixture.rb")
    storage_boundary = read("scripts/storage-response-boundary.rb")
    storage_boundary_test = read("scripts/test-storage-response-boundary.rb")
    require_text(
        storage_fixture,
        [
            'require_relative "storage-response-boundary"',
            "MochiriiStorageResponseBoundary.read(",
            "validate_public_metadata: public_media",
            'canonical_public_uri(store.url_for(upload), "original")',
            'canonical_public_uri(store.cdn_url(optimized.url), "optimized")',
        ],
        "hosted storage streamed response",
    )
    require_text(
        storage_boundary,
        [
            "def self.canonical_public_uri(value, exact_family)",
            'uri.host == "media-forums.mochirii.com"',
            'uri.path.start_with?("/#{exact_family}/")',
            'response["content-length"]',
            "ALLOWED_RESPONSE_HEADERS",
            "REQUIRED_PROVIDER_HEADERS",
            "FORBIDDEN_IDENTITY",
            "FORBIDDEN_URL_OR_CREDENTIAL_FIELD",
            "def self.valid_cdn_cookie?(value)",
            "MAX_CDN_COOKIE_BYTES = 4096",
            "anonymous media response contains a duplicate transport header",
            'value == "cloudflare"',
            'value == "Normal"',
            "def self.validate_metadata(response)",
            "response.read_body do |chunk|",
            "body.bytesize + chunk.bytesize <= maximum_bytes",
        ],
        "hosted storage response byte boundary",
    )
    require_text(
        storage_boundary_test,
        [
            "oversized declared response was accepted",
            "oversized chunked response was accepted",
            "chunked response was not stopped at the first oversized chunk",
            "wrong-family or noncanonical media URL was accepted",
            "provider or non-neutral media response metadata was accepted",
            "provider or upstream media response body was accepted",
            "hostile direct-CDN transport metadata was accepted",
            "range response without Content-Range was accepted",
            "bounded direct-CDN cookie was rejected",
            "duplicate direct-CDN transport header was accepted",
            '"https://media-forums.mochirii.com/uploads/default/wrong.png", "original"',
        ],
        "hosted storage response hostile fixture",
    )
    storage_docs = read("docs/operations/STORAGE.md")
    require_text(
        storage_docs,
        [
            "The public-branding boundary applies to rendered URLs",
            "non-rendered transport metadata",
            "optional Cloudflare `__cf_bm` transport cookie",
            "never logged, persisted, or compared",
            "does not authorize a proxy layer",
        ],
        "direct-CDN transport metadata decision",
    )
    recovery_docs = read("docs/operations/RECOVERY.md")
    validation_docs = read("docs/operations/VALIDATION.md")
    deployment_docs = read("docs/operations/DEPLOYMENT.md")
    backup_restore_contract = load("docs/operations/backup-restore-contract.v1.json")
    backup_contract = backup_restore_contract.get("backup", {})
    restore_contract = backup_restore_contract.get("restore", {})
    if any(
        backup_contract.get(key) is not expected
        for key, expected in {
            "backupRuntimeOwnershipRequiredThroughTerminalSuccess": True,
            "backupRuntimeOperationTokenPrearmedBeforePotentialStopRequired": True,
            "backupRuntimeIdentityAndOriginalStateBindingRequired": True,
            "backupOriginalRuntimeStateRestoredBeforeRetirementRequired": True,
            "backupPostCleanupAndPostRolloutCrashRecoveryRequired": True,
            "backupStoppedOriginContainmentPrearmRequired": True,
            "backupPostStopPrePhaseAdvanceCrashRecoveryRequired": True,
            "journalFreePreparedRetirementAllowed": False,
        }.items()
    ):
        fail("Backup-wide runtime recovery contract values differ.")
    if any(
        restore_contract.get(key) is not expected
        for key, expected in {
            "scratchReaderImmutableImageIdAndLabelRequired": True,
            "scratchReaderTagOnlyAbsenceAccepted": False,
            "scratchReaderPostImageDeleteRetryRequired": True,
            "restoreLauncherInvocationPrearmRequired": True,
            "restoreLauncherTokenPriorAndReplacementImageCommandConfigurationAndPhaseRequired": True,
            "restoreLauncherHostProcessEnvironmentTokenRequired": True,
            "restoreLauncherMarkedProcessAbsenceRequired": True,
            "restoreLauncherJournalClearedOnlyAfterTerminalIdentityProof": True,
        }.items()
    ):
        fail("Scratch or restore immutable launcher recovery contract values differ.")
    require_text(
        deployment_docs,
        [
            "`/var/lib/mochirii/forums/deployment-mutation.json`",
            "atomic no-replace hard link",
            "`launcher-armed`",
            "database-mutation boundary before the launcher process starts",
            "mutation plus promotion journals",
            "cross-version or mutation-possible failures never launch",
        ],
        "deployment runtime mutation recovery procedure",
    )
    require_text(
        recovery_docs,
        [
            "Every target configuration or launcher mutation is pre-armed",
            "`databaseMutationPossible=true`",
            "Other backup, restore, authentication, member-rollout, certificate, and",
            "It is cleared only after the",
        ],
        "deployment runtime mutation retry procedure",
    )
    require_text(
        recovery_docs,
        [
            "Every backup durably binds its original running or stopped state",
            "The backup journal is the sole bounded",
            "`temporary-stop-authorized`",
            "crash after the stop but before that second",
            "success idempotently restores the exact original running or stopped state",
            "replacement image ID is",
            "Altered or missing image-ID",
            "If deletion",
            "proved absence",
        ],
        "backup, restore, and scratch immutable-ID recovery procedure",
    )
    require_text(
        validation_docs,
        [
            "no active deployment-mutation, deployment-promotion, backup, or restore",
            "exact mutation-plus-promotion pair",
            "irreversible-mutation flag",
        ],
        "deployment runtime mutation validation ledger",
    )
    require_text(
        validation_docs,
        [
            "post-upload-cleanup, post-rollout, and",
            "stopped-origin crash after stop proof",
            "immutable-ID deletion but before absence proof",
            "durably binds any replacement ID before untag or deletion",
            "post-CID-unlink/final-rm-failure",
            "operation-created container and image",
            "mismatched",
            "detached changed-argv",
        ],
        "four recovery-blocker hostile validation ledger",
    )
    require_text(
        recovery_docs,
        [
            "one bounded ordinary GIF upload",
            "exact row, SHA-1, original object and tombstone paths",
            "disposable row, object, tombstone, and marker",
            "subsequent clean",
            "`latest-backup-evidence`",
        ],
        "hosted upload backup/restore recovery procedure",
    )
    require_text(
        validation_docs,
        [
            "ordinary normal-upload fixture",
            "restore must recreate the exact row, original bytes, content digest",
            "verified final clean backup",
        ],
        "hosted normal-upload restore gate",
    )

    backup_verifier = read("scripts/verify-backup.rb")
    backup_boundary = read("scripts/backup-url-boundary.rb")
    backup_boundary_test = read("scripts/test-backup-url-boundary.rb")
    require_text(
        backup_verifier,
        [
            'require_relative "backup-url-boundary"',
            "MochiriiBackupUrlBoundary.valid_filename!(backup.filename)",
            "MochiriiBackupUrlBoundary.signed_get_uri(retrievable.source, backup.filename)",
            "OpenSSL::SSL::VERIFY_PEER",
            "http.verify_hostname = true",
        ],
        "private backup retrieval boundary",
    )
    if backup_verifier.count("retrievable.source") != 1 or any(
        fragment in backup_verifier
        for fragment in ("puts signed_uri", "print signed_uri", "signed_uri.to_s", "retrievable.source.inspect")
    ):
        fail("Signed backup URL can enter output or evidence.")
    require_text(
        backup_boundary,
        [
            'EXPECTED_HOST = "mochirii-forums.sgp1.digitaloceanspaces.com"',
            'expected_path = "/backups/#{EXPECTED_DATABASE}/#{filename}"',
            "MAX_QUERY_BYTES = 4096",
            "keys.sort != REQUIRED_QUERY_KEYS.sort",
            '!filename.include?("..")',
        ],
        "signed backup URL allowlist",
    )
    require_text(
        backup_boundary_test,
        [
            "hostile backup retrieval URL was accepted",
            "hostile backup filename was accepted",
            '"-option.tar.gz"',
            '"fixture..backup.tar.gz"',
            '"/backups/other/"',
            '"#{exact}#fragment"',
        ],
        "signed backup URL hostile fixture",
    )

    require_text(
        host_deploy,
        [
            'docker exec -i -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app timeout --signal=TERM --kill-after=10s',
            'container_operation_absent "${operation_token}"',
            "emergency_stop",
            "remaining_mutation_seconds 300",
        ],
        "in-container hosted-storage runner timeout",
    )

    upstream_wrapper = read("scripts/verify-upstream-provenance.ps1")
    upstream_workflow = read(".github/workflows/inspect-upstream.yml")
    upstream_verifier = read("scripts/verify-pinned-source.py")
    validate_pinned_source_verifier(upstream_verifier)
    require_text(
        upstream_wrapper,
        ["[switch]$RequireCurrentMain", "--require-current-main", "also requires -Online"],
        "upstream-main PowerShell gate",
    )
    require_text(
        upstream_workflow,
        ["ref: ${{ github.sha }}", "-Online -RequireCurrentMain"],
        "monthly upstream-main gate",
    )
    require_text(
        upstream_verifier,
        [
            "def verify_current_main(provenance: dict)",
            "/git/ref/heads/main",
            "/compare/{pinned}...{revision}",
            "Official deployment-source main moved or returned an ambiguous reference.",
            "Official deployment-source comparison moved after review.",
            'PINNED_EMAIL_EXTRACT_PARTS_BLOCK = b\'\'\'  def self.extract_parts(raw)',
            "def verify_email_extract_parts_method(source: bytes) -> None:",
            "def verify_email_semantics(source: bytes) -> None:",
            'hashlib.sha256(source).hexdigest() != PINNED_EMAIL_SHA256',
            'verify_email_semantics(core["lib/email.rb"])',
        ],
        "bounded upstream-main verifier",
    )
    require_text(
        contract_tests,
        [
            "test_current_main_observation",
            "moved_request",
            "malformed_request",
            "ambiguous_request",
            "unreachable_request",
            "moved_compare_request",
        ],
        "upstream-main hostile fixtures",
    )

    for wrapper in (
        "scripts/check-repository.ps1",
        "scripts/check-source-introduction.ps1",
        "scripts/test-source-introduction.ps1",
        "scripts/verify-upstream-provenance.ps1",
    ):
        wrapper_text = read(wrapper)
        require_text(wrapper_text, ["-B", "__pycache__", ".pyc", ".pyo"], f"Python-residue guard {wrapper}")


def validate_runtime_rails_execution_contract() -> None:
    expected_wrappers = {
        ".github/workflows/disposable-bootstrap.yml": 14,
        "scripts/host-restore-validate.sh": 19,
        "scripts/host-backup.sh": 5,
        "scripts/verify-discourse-connect.py": 6,
        "scripts/host-deploy.sh": 3,
        "scripts/historical-recovery-scratch-reader.sh": 2,
        "scripts/verify-contained-activation.sh": 2,
        "scripts/verify-host.sh": 2,
        "scripts/host-break-glass-admin.sh": 1,
    }
    total = 0
    for relative, expected in expected_wrappers.items():
        source = read(relative)
        if (
            "bundle exec rails runner" in source
            or source.count("/usr/local/bin/rails runner") != expected
            or source.count("rails runner") != expected
        ):
            fail(f"Runtime Rails execution bypasses the pinned owner-scoped wrapper: {relative}")
        total += expected
    if total != 54:
        fail("Runtime Rails owner-wrapper inventory differs.")

    template = read("config/app.yml.example")
    owner_scoped_build_runner = """su discourse -c 'bundle exec rails runner
          \"$MOCHIRII_RELEASE_ASSET_ROOT/configure-site.rb\"'"""
    if (
        template.count("bundle exec rails runner") != 1
        or template.count("rails runner") != 1
        or template.count(owner_scoped_build_runner) != 1
    ):
        fail("Build-time Rails runner is not explicitly owner-scoped.")

    workflow = read(".github/workflows/disposable-bootstrap.yml")
    owner_probe = """sudo docker exec app /usr/local/bin/rails runner 'require \"etc\"; raise unless Process.euid == Etc.getpwnam(\"discourse\").uid; raise unless GitUtils.git_version == \"cbf996f65aae3da1843224aa624bcd9a225931ac\"; ActiveRecord::Base.connection.execute(\"SELECT 1\"); raise if Upload.exists?(sha1: \"0000000000000000000000000000000000000000\")'"""
    if workflow.count(owner_probe) != 1:
        fail("Disposable bootstrap does not prove Rails UID, Git, and database ownership together.")


def main() -> int:
    global ARCHIVE_MODE, ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive-root", type=Path)
    args = parser.parse_args()
    if args.archive_root is not None:
        supplied = args.archive_root.absolute()
        if supplied.is_symlink() or not supplied.is_dir():
            fail("Archive validation root must be one real directory.")
        resolved = supplied.resolve(strict=True)
        metadata = resolved.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail("Archive validation root is linked or special.")
        ROOT = resolved
        ARCHIVE_MODE = True
    validate_manifests()
    validate_template()
    validate_theme_and_public_source()
    validate_secrets_and_workflows()
    validate_runtime_rails_execution_contract()
    print("Repository source contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
