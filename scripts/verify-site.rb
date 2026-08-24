# frozen_string_literal: true

require "json"

checks = {}
checks["database"] = ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1
checks["redis"] = Discourse.redis.ping == "PONG"
sidekiq_probe_state = "completed"
begin
  checks["sidekiq_processing"] = MochiriiEmailMetadata.verify_sidekiq_processing!
rescue MochiriiEmailMetadata::SidekiqProbeError => error
  checks["sidekiq_processing"] = false
  sidekiq_probe_state = error.state
end
checks["sidekiq_process_present"] = Sidekiq::ProcessSet.new.any?
checks["theme"] = Theme.find_by(name: "Mochirii Forums")&.default? == true
checks["single_theme"] = Theme.where(name: "Mochirii Forums").count == 1
theme = Theme.find_by(name: "Mochirii Forums")
theme_uploads = theme&.upload_fields&.index_by(&:name) || {}
checks["theme_logo_uploads"] =
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
checks["core_revision"] = Discourse.git_version == "cbf996f65aae3da1843224aa624bcd9a225931ac"
checks["repository_revision"] = ENV["MOCHIRII_REPOSITORY_COMMIT"]&.match?(/\A[0-9a-f]{40}\z/) == true
checks["release_asset_root"] =
  ENV["MOCHIRII_RELEASE_ASSET_ROOT"] == "/opt/mochirii-release"
mail_plugin_source = "/var/www/discourse/plugins/mochirii_email_metadata/plugin.rb"
mail_plugin_asset = "#{ENV.fetch("MOCHIRII_RELEASE_ASSET_ROOT", "/invalid")}/mochirii-email-metadata-plugin.rb"
checks["mail_metadata_plugin_exact"] =
  defined?(MochiriiEmailMetadata::Interceptor) &&
    Mail.delivery_interceptors.include?(MochiriiEmailMetadata::Interceptor) &&
    File.file?(mail_plugin_source) &&
    File.file?(mail_plugin_asset) &&
    File.binread(mail_plugin_source) == File.binread(mail_plugin_asset)
checks["login_required"] = SiteSetting.login_required == true
checks["native_registration_closed"] = SiteSetting.allow_new_registrations == false
checks["english_only_branding"] =
    SiteSetting.default_locale == "en" &&
    SiteSetting.allow_user_locale == false &&
    SiteSetting.set_locale_from_accept_language_header == false &&
    SiteSetting.set_locale_from_cookie == false &&
    SiteSetting.set_locale_from_param == false
checks["local_login_disabled"] =
  SiteSetting.enable_local_logins == false &&
    SiteSetting.enable_local_logins_via_email == false &&
    SiteSetting.enable_local_logins_via_code == false
checks["alternate_login_disabled"] =
  SiteSetting.enable_discourse_id == false &&
    SiteSetting.enable_google_oauth2_logins == false &&
    SiteSetting.enable_twitter_logins == false &&
    SiteSetting.enable_facebook_logins == false &&
    SiteSetting.enable_github_logins == false &&
    SiteSetting.enable_discord_logins == false &&
    SiteSetting.enable_linkedin_oidc_logins == false &&
    SiteSetting.sign_in_with_apple_enabled == false &&
    SiteSetting.enable_login_with_amazon == false &&
    SiteSetting.microsoft_auth_enabled == false &&
    SiteSetting.oauth2_enabled == false &&
    SiteSetting.openid_connect_enabled == false
checks["secure_uploads_disabled"] = SiteSetting.secure_uploads == false
checks["no_secure_upload_rows"] = Upload.where(secure: true).none?
checks["image_extensions_only"] =
  SiteSetting.authorized_extensions == "jpg|jpeg|png|gif|webp" &&
    SiteSetting.authorized_extensions_for_staff == "" &&
    SiteSetting.allow_staff_to_upload_any_file_in_pm == false &&
    SiteSetting.allow_all_attachments_for_group_messages == false
checks["custom_media_hostname"] = SiteSetting.s3_cdn_url == "https://media-forums.mochirii.com"
checks["backups_separate_prefix"] = SiteSetting.s3_backup_bucket == "mochirii-forums/backups"
checks["direct_uploads_disabled"] = SiteSetting.enable_direct_s3_uploads == false
checks["public_upload_acls"] = SiteSetting.s3_use_acls == true
checks["lifecycle_mutation_disabled"] = SiteSetting.s3_configure_tombstone_policy == false
checks["backup_contains_uploads"] = SiteSetting.include_s3_uploads_in_backups == true
checks["discourse_connect_logging_disabled"] = SiteSetting.verbose_discourse_connect_logging == false
checks["discourse_connect_consumer_only"] = SiteSetting.enable_discourse_connect_provider == false
checks["discourse_connect_session_nonce"] = SiteSetting.discourse_connect_csrf_protection == true
checks["discourse_connect_log_parameters_filtered"] =
  Rails.application.config.filter_parameters.include?(:email) &&
    Rails.application.config.filter_parameters.include?(:sso) &&
    Rails.application.config.filter_parameters.include?(:sig) &&
    Rails.application.config.filter_parameters.include?(:token)
logster_string_identity_env = {}
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
lograge_payload = DiscourseLograge.custom_payload(
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
recovery_token = "a" * 32
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
auth_audit_probe_class =
  Class.new do
    class << self
      attr_reader :observed_info

      def log(info)
        @observed_info = info
        :completed
      end
    end
  end
auth_audit_probe_class.singleton_class.prepend(MochiriiSensitiveUserAuthTokenAuditFilter) if
  defined?(MochiriiSensitiveUserAuthTokenAuditFilter)
recovery_audit = { action: "generate", path: "/session/email-login/#{recovery_token}" }.freeze
recovery_result = auth_audit_probe_class.log(recovery_audit)
filtered_audit = auth_audit_probe_class.observed_info
ordinary_audit = { action: "rotate", path: "/session/email-login/too-short" }.freeze
ordinary_result = auth_audit_probe_class.log(ordinary_audit)
ordinary_observed = auth_audit_probe_class.observed_info
checks["admin_recovery_auth_audit_path_filtered"] =
  defined?(MochiriiSensitiveUserAuthTokenAuditFilter) &&
    UserAuthToken.singleton_class.ancestors.include?(MochiriiSensitiveUserAuthTokenAuditFilter) &&
    recovery_result == :completed &&
    filtered_audit.is_a?(Hash) &&
    !filtered_audit.equal?(recovery_audit) &&
    filtered_audit == { action: "generate", path: "/session/email-login/[FILTERED]" } &&
    recovery_audit == { action: "generate", path: "/session/email-login/#{recovery_token}" } &&
    ordinary_result == :completed &&
    ordinary_observed.equal?(ordinary_audit)
expected_discourse_connect =
  case ENV.fetch("DISCOURSE_ENABLE_DISCOURSE_CONNECT")
  when "true" then true
  when "false" then false
  else raise "DiscourseConnect runtime flag is malformed"
  end
checks["discourse_connect_activation_runtime_bound"] =
  SiteSetting.enable_discourse_connect == expected_discourse_connect
checks["upstream_marketing_disabled"] =
  SiteSetting.enable_powered_by_discourse == false &&
    SiteSetting.version_checks == false &&
    SiteSetting.new_version_emails == false &&
    SiteSetting.send_welcome_message == false &&
    SiteSetting.send_tl1_welcome_message == false &&
    SiteSetting.send_tl2_promotion_message == false &&
    SiteSetting.send_old_credential_reminder_days == 0 &&
    SiteSetting.simple_email_subject == false &&
    SiteSetting.discourse_narrative_bot_enabled == false
checks["automatic_gravatar_downloads_disabled"] =
  ENV["DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"] == "false" &&
    SiteSetting.automatically_download_gravatars == false
checks["mail_suppression_matches_runtime"] =
  SiteSetting.disable_emails == ENV.fetch("DISCOURSE_DISABLE_EMAILS")
smtp = GlobalSetting.smtp_settings
checks["smtp_transport_fail_closed"] =
  smtp.is_a?(Hash) &&
    smtp[:address] == ENV.fetch("DISCOURSE_SMTP_ADDRESS") &&
    smtp[:port] == ENV.fetch("DISCOURSE_SMTP_PORT").to_i &&
    smtp[:domain] == "forums.mochirii.com" &&
    smtp[:authentication].to_s == ENV.fetch("DISCOURSE_SMTP_AUTHENTICATION") &&
    smtp[:tls] == true &&
    smtp[:enable_starttls_auto] == false &&
    smtp[:openssl_verify_mode].to_s == "peer"
checks["notification_sender_runtime_bound"] =
  SiteSetting.notification_email == ENV.fetch("MOCHIRII_EXPECTED_NOTIFICATION_EMAIL") &&
    SiteSetting.contact_email == ENV.fetch("MOCHIRII_EXPECTED_NOTIFICATION_EMAIL")

bot = User.find_by(id: -2)
bot_profile_text = [bot&.name, bot&.username, bot&.user_profile&.bio_raw, bot&.user_profile&.bio_cooked, bot&.user_profile&.website].compact.join("\n")
checks["narrative_system_user_identity_branded"] =
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
checks["narrative_old_profile_unavailable"] = User.find_by_username("discobot").nil?

expected_badges = {
  Badge::BasicUser => "Granted all essential Mochirii community functions",
  Badge::Member => "Granted invitations, group messaging, and more participation in Mochirii Forums",
  Badge::Regular => "Granted topic organization, wiki editing, and more participation tools",
  Badge::Leader => "Granted global organization and moderation tools in Mochirii Forums",
}
checks["trust_badge_descriptions_branded"] =
  expected_badges.all? do |id, expected_description|
    badge = Badge.find_by(id: id)
    badge&.description == expected_description &&
      !badge.description.match?(/https?:|discourse[.]org|digitaloceanspaces|amazonaws/i)
  end

guidelines = Topic.find_by(id: SiteSetting.guidelines_topic_id)&.first_post
checks["guidelines_branded"] =
  guidelines&.raw&.include?("Mochirii Forums provides tools") == true &&
    !guidelines.raw.include?("Discourse provides tools") &&
    !guidelines.raw.match?(/discourse[.]org|digitaloceanspaces|amazonaws/i)

expected_admin_quick_start_template = <<~MARKDOWN
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
expected_admin_quick_start =
  TextCleaner.normalize_whitespaces(
    expected_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url),
  ).rstrip
admin_quick_start_topic = Topic.find_by(id: SiteSetting.admin_quick_start_topic_id)
admin_quick_start = admin_quick_start_topic&.first_post
checks["admin_quick_start_branded"] =
  admin_quick_start_topic&.archetype == Archetype.default &&
    admin_quick_start_topic.category_id == SiteSetting.staff_category_id &&
    !Category.exists?(topic_id: admin_quick_start_topic.id) &&
    admin_quick_start&.post_number == 1 &&
    admin_quick_start.user_id == Discourse::SYSTEM_USER_ID &&
    admin_quick_start.last_editor_id == Discourse::SYSTEM_USER_ID &&
    admin_quick_start.raw == expected_admin_quick_start &&
    !admin_quick_start.raw.match?(/\bDiscourse\b|discourse[.](?:org|com)|digitaloceanspaces|amazonaws/i)

failed = checks.select { |_name, passed| !passed }.keys
puts JSON.generate({ checks: checks, failed: failed, sidekiqProbeState: sidekiq_probe_state })
raise "Mochirii runtime verification failed" if failed.any?
