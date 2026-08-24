# frozen_string_literal: true

require "digest"

# Executed inside the exact standalone build after the deterministic theme is
# imported. It intentionally contains no credential.

theme = Theme.where(name: "Mochirii Forums").order(id: :desc).first
raise "Mochirii theme was not imported" if theme.nil?
raise "Mochirii theme must not be a component" if theme.component?

theme.update!(enabled: true, user_selectable: false)
theme.set_default!

uploads = theme.upload_fields.index_by(&:name)
required_uploads = %w[mochirii_emblem mochirii_icon mochirii_social_card]
missing = required_uploads.reject { |name| uploads[name]&.upload }
raise "Mochirii theme uploads are missing: #{missing.join(', ')}" if missing.any?

emblem_id = uploads.fetch("mochirii_emblem").upload.id
icon_id = uploads.fetch("mochirii_icon").upload.id
social_card_id = uploads.fetch("mochirii_social_card").upload.id
icon_upload = uploads.fetch("mochirii_icon").upload

SiteSetting.logo = emblem_id
SiteSetting.logo_dark = emblem_id
SiteSetting.mobile_logo = emblem_id
SiteSetting.mobile_logo_dark = emblem_id
SiteSetting.digest_logo = social_card_id
SiteSetting.logo_small = icon_id
SiteSetting.logo_small_dark = icon_id
SiteSetting.large_icon = social_card_id
SiteSetting.manifest_icon = social_card_id
SiteSetting.favicon = icon_id
SiteSetting.apple_touch_icon = icon_id
SiteSetting.opengraph_image = social_card_id

TranslationOverride.upsert!(
  "en",
  "powered_by_html",
  '<a href="https://mochirii.com">Mochirii Forums</a> works best with JavaScript enabled',
)
TranslationOverride.upsert!("en", "js.powered_by_discourse", "Mochirii Forums")
TranslationOverride.upsert!("en", "email_from", "Mochirii Forums")
TranslationOverride.upsert!("en", "email_from_group", "Mochirii Forums")
TranslationOverride.upsert!(
  "en",
  "js.browser_update",
  "Your browser is unsupported. Please use a current browser to view Mochirii Forums, log in, and reply.",
)
TranslationOverride.upsert!(
  "en",
  "system_messages.welcome_staff.text_body_template",
  [
    "You have been granted %{role} status in Mochirii Forums.",
    "",
    "Use the [Mochirii Forums administration area](%{base_url}/admin) and the approved internal operator runbooks.",
  ].join("\n"),
)
TranslationOverride.upsert!(
  "en",
  "badges.basic_user.description",
  "Granted all essential Mochirii community functions",
)
TranslationOverride.upsert!(
  "en",
  "badges.member.description",
  "Granted invitations, group messaging, and more participation in Mochirii Forums",
)
TranslationOverride.upsert!(
  "en",
  "badges.regular.description",
  "Granted topic organization, wiki editing, and more participation tools",
)
TranslationOverride.upsert!(
  "en",
  "badges.leader.description",
  "Granted global organization and moderation tools in Mochirii Forums",
)
TranslationOverride.upsert!(
  "en",
  "test_mailer.text_body_template",
  [
    "This is a test email from [**Mochirii Forums**](%{base_url}).",
    "",
    "This message verifies the Mochirii Forums mail path.",
    "",
    "Mochirii Forums",
  ].join("\n"),
)

expected = {
  title: "Mochirii Forums",
  short_title: "Mochirii",
  company_name: "Mochirii",
  login_required: true,
  allow_new_registrations: false,
  enable_signup_cta: false,
  enable_local_logins: false,
  enable_local_logins_via_email: false,
  enable_local_logins_via_code: false,
  enable_passkeys: false,
  enable_discourse_id: false,
  enable_google_oauth2_logins: false,
  enable_twitter_logins: false,
  enable_facebook_logins: false,
  enable_github_logins: false,
  enable_discord_logins: false,
  enable_linkedin_oidc_logins: false,
  sign_in_with_apple_enabled: false,
  enable_login_with_amazon: false,
  microsoft_auth_enabled: false,
  oauth2_enabled: false,
  openid_connect_enabled: false,
  enable_discourse_connect_provider: false,
  discourse_connect_csrf_protection: true,
  verbose_discourse_connect_logging: false,
  secure_uploads: false,
  enable_direct_s3_uploads: false,
  authorized_extensions: "jpg|jpeg|png|gif|webp",
  authorized_extensions_for_staff: "",
  allow_staff_to_upload_any_file_in_pm: false,
  allow_all_attachments_for_group_messages: false,
  s3_configure_tombstone_policy: false,
  include_s3_uploads_in_backups: true,
  enable_powered_by_discourse: false,
  version_checks: false,
  new_version_emails: false,
  send_welcome_message: false,
  send_tl1_welcome_message: false,
  send_tl2_promotion_message: false,
  send_old_credential_reminder_days: 0,
  simple_email_subject: false,
  allow_email_invites: false,
  allow_user_locale: false,
  set_locale_from_accept_language_header: false,
  set_locale_from_cookie: false,
  set_locale_from_param: false,
  discourse_narrative_bot_enabled: false,
  automatically_download_gravatars: false,
}

expected.each do |name, value|
  actual = SiteSetting.public_send(name)
  raise "Unexpected site setting #{name}" unless actual == value
end

def configure_narrative_system_user!(icon_upload)
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

# Preserve the pinned guideline seed and revise only its single upstream-brand
# phrase. Any unexpected seed or later edit stops instead of overwriting member
# content.
guidelines = Topic.find_by(id: SiteSetting.guidelines_topic_id)&.first_post
raise "Pinned guidelines topic is absent" if guidelines.nil?
upstream_guidelines_phrase = "Discourse provides tools"
mochirii_guidelines_phrase = "Mochirii Forums provides tools"
generic_guidelines_phrase = "civilized public discourse"
mochirii_generic_phrase = "civilized public discussion"
revised = guidelines.raw.dup
if revised.include?(upstream_guidelines_phrase)
  raise "Pinned guidelines branding phrase is duplicated" unless revised.scan(upstream_guidelines_phrase).one?
  revised.sub!(upstream_guidelines_phrase, mochirii_guidelines_phrase)
elsif !revised.include?(mochirii_guidelines_phrase)
  raise "Pinned guidelines branding phrase is unexpected"
end
if revised.include?(generic_guidelines_phrase)
  raise "Pinned guidelines generic phrase is duplicated" unless revised.scan(generic_guidelines_phrase).one?
  revised.sub!(generic_guidelines_phrase, mochirii_generic_phrase)
elsif !revised.include?(mochirii_generic_phrase)
  raise "Pinned guidelines generic phrase is unexpected"
end
if revised != guidelines.raw
  guidelines.revise(Discourse.system_user, { raw: revised })
  guidelines.reload
end
unless guidelines.raw.include?(mochirii_guidelines_phrase) && guidelines.raw.include?(mochirii_generic_phrase)
  raise "Guidelines branding revision failed"
end

# The pinned one-time seed returns without updating this staff topic on later
# supported rebuilds. Revise only the exact untouched upstream guide or accept
# the exact reviewed Mochirii replacement; an operator edit must never be
# overwritten by automation.
admin_quick_start_topic = Topic.find_by(id: SiteSetting.admin_quick_start_topic_id)
admin_quick_start = admin_quick_start_topic&.first_post
unless admin_quick_start_topic&.archetype == Archetype.default &&
    admin_quick_start_topic.category_id == SiteSetting.staff_category_id &&
    !Category.exists?(topic_id: admin_quick_start_topic.id) &&
    admin_quick_start&.post_number == 1 &&
    admin_quick_start.user_id == Discourse::SYSTEM_USER_ID
  raise "Pinned administrator quick-start topic is unexpected"
end

mochirii_admin_quick_start_template = <<~MARKDOWN
  *Mochirii staff setup guide*

  ## Verify email delivery

  Email supports member notifications and account recovery.

  → Send a **[<kbd>test email</kbd>](%{base_url}/admin/email/server-settings)**.

  → If delivery fails, use the approved private operations runbook without exposing credentials or member data.

  ## Invite the moderation team

  → **[<kbd>Send staff invitations</kbd>](%{base_url}/new-invite)** only to approved moderators and operators.

  ## Start reviewed conversations

  → Add useful topics, frequently asked questions, and community guidance before inviting members.

  → Keep staff planning in the staff category until it is approved for members.

  ## Review member-facing setup

  → Review the **[<kbd>welcome topic</kbd>](%{base_url}/t/-/5/)** and **[<kbd>about page</kbd>](%{base_url}/about)**.

  → Review **[<kbd>site appearance</kbd>](%{base_url}/admin/config/logo)** and approved sign-in configuration.

  ## Invite verified members

  → Use **[<kbd>member invitations</kbd>](%{base_url}/new-invite)** only after the reviewed privacy, recovery, moderation, and access checks pass.

  ## Continue operations

  Use the approved Mochirii source, validation, backup, recovery, privacy, and moderation runbooks. Keep credentials and private evidence in their designated recovery boundaries.
MARKDOWN
mochirii_admin_quick_start =
  mochirii_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url)
normalized_upstream_admin_quick_start =
  admin_quick_start.raw.gsub(Discourse.base_url, "%{base_url}")
untouched_upstream_admin_quick_start =
  normalized_upstream_admin_quick_start.bytesize == 1905 &&
    Digest::SHA256.hexdigest(normalized_upstream_admin_quick_start) ==
      "94d08273429f2e919890201c2d21608595b78d384e4d3d7dc180659918744f50"

if admin_quick_start.raw == mochirii_admin_quick_start
  # Exact idempotent successor; retain it without a new revision.
elsif untouched_upstream_admin_quick_start
  admin_quick_start.revise(Discourse.system_user, { raw: mochirii_admin_quick_start })
  admin_quick_start.reload
else
  raise "Pinned administrator quick-start content was edited"
end
unless admin_quick_start.raw == mochirii_admin_quick_start
  raise "Administrator quick-start branding revision failed"
end

fixture = ENV["MOCHIRII_STAGE4_FIXTURE"] == "true"
connect_fixture = ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"
raise "Fixture unexpectedly enabled external storage" if fixture && SiteSetting.enable_s3_uploads
raise "Connect fixture marker requires Stage 4 fixture mode" if connect_fixture && !fixture
if fixture && SiteSetting.enable_discourse_connect != connect_fixture
  raise "Fixture central-login state differs from its exact marker"
end
if connect_fixture
  fixture_external_id = "mochirii-stage4-consumer-fixture"
  fixture_username = "mochirii-s4-test"
  fixture_email = "stage4-fixture@forums.mochirii.com"
  fixture_records = SingleSignOnRecord.where(external_id: fixture_external_id).to_a
  raise "DiscourseConnect fixture external identity is duplicated" if fixture_records.length > 1
  fixture_user = User.find_by(username_lower: fixture_username)
  fixture_record = fixture_records.first
  if fixture_record.nil? && fixture_user.present?
    raise "DiscourseConnect fixture username exists without its exact external identity"
  end
  if fixture_record.present?
    raise "DiscourseConnect fixture external identity has no exact user" if fixture_user.nil?
    raise "DiscourseConnect fixture external identity is bound to another user" unless fixture_record.user_id == fixture_user.id
    raise "DiscourseConnect fixture email changed" unless fixture_user.email == fixture_email
    raise "DiscourseConnect fixture username changed" unless fixture_user.username_lower == fixture_username
  end
end

if !fixture
  production = {
    enable_s3_uploads: true,
    s3_region: "whatever",
    s3_endpoint: "https://sgp1.digitaloceanspaces.com",
    s3_upload_bucket: "mochirii-forums",
    s3_backup_bucket: "mochirii-forums/backups",
    s3_cdn_url: "https://media-forums.mochirii.com",
    s3_use_cdn_url_for_all_uploads: true,
    s3_use_acls: true,
    s3_install_cors_rule: false,
    backup_location: "s3",
    discourse_connect_url: "https://mochirii.com/forums/connect",
    discourse_connect_csrf_protection: true,
  }
  production.each do |name, value|
    raise "Unexpected production setting #{name}" unless SiteSetting.public_send(name) == value
  end
end

Theme.where(name: "Mochirii Forums").where.not(id: theme.id).find_each(&:destroy!)

puts "Mochirii site configuration applied."
