# frozen_string_literal: true

require "json"

checks = {}
checks["database"] = ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1
checks["redis"] = Discourse.redis.ping == "PONG"
checks["sidekiq_process_present"] = Sidekiq::ProcessSet.new.any?
sidekiq_probe_state = "completed"
begin
  checks["sidekiq_processing"] = MochiriiEmailMetadata.verify_sidekiq_processing!
rescue MochiriiEmailMetadata::SidekiqProbeError => error
  checks["sidekiq_processing"] = false
  sidekiq_probe_state = error.state
end
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
  Rails.application.config.filter_parameters.include?(:sso) &&
    Rails.application.config.filter_parameters.include?(:sig) &&
    Rails.application.config.filter_parameters.include?(:token)
recovery_token = "a" * 32
recovery_request = ActionDispatch::Request.new(
  Rack::MockRequest.env_for("/session/email-login/#{recovery_token}"),
)
ordinary_request = ActionDispatch::Request.new(Rack::MockRequest.env_for("/session/email-login/too-short"))
checks["admin_recovery_log_path_filtered"] =
  defined?(MochiriiSensitiveRequestPathFilter) &&
    ActionDispatch::Request.ancestors.include?(MochiriiSensitiveRequestPathFilter) &&
    recovery_request.path == "/session/email-login/#{recovery_token}" &&
    recovery_request.filtered_path == "/session/email-login/[FILTERED]" &&
    ordinary_request.filtered_path == "/session/email-login/too-short"
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
checks["narrative_system_user_branded"] =
  bot&.username == "mochirii-guide" &&
    bot&.name == "Mochirii Guide" &&
    bot&.email == "mochirii-guide@forums.mochirii.com" &&
    bot&.uploaded_avatar_id == icon_id &&
    bot&.user_avatar&.custom_upload_id == icon_id &&
    bot&.user_avatar&.gravatar_upload_id.nil? &&
    icon_upload.sha1 == "c1fde880bdf518e913d5eeb9a868f886e3e47fa0" &&
    !bot_profile_text.match?(/discobot|discourse[.]org|meta[.]discourse|blog[.]discourse|digitaloceanspaces|amazonaws/i) &&
    User.where(username_lower: "discobot").none?
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

failed = checks.select { |_name, passed| !passed }.keys
puts JSON.generate({ checks: checks, failed: failed, sidekiqProbeState: sidekiq_probe_state })
raise "Mochirii runtime verification failed" if failed.any?
