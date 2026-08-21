# frozen_string_literal: true

# Render representative built-in mail paths without delivering or printing
# recipient data. The exact From identity and every member-visible part must be
# Mochirii-owned.

expected_address = ENV.fetch("MOCHIRII_EXPECTED_NOTIFICATION_EMAIL")
expected_name = "Mochirii Forums"
forbidden = [
  /\bDiscourse\b/i,
  /powered by discourse/i,
  /friends at discourse/i,
  %r{https?://(?:[^/]+[.])?discourse[.](?:org|com)}i,
  /digitaloceanspaces[.]com/i,
  /amazonaws[.]com/i,
]
interceptor =
  if defined?(MochiriiEmailMetadata::Interceptor)
    MochiriiEmailMetadata::Interceptor
  else
    raise "Required Mochirii mail metadata interceptor is absent"
  end
unless Mail.delivery_interceptors.include?(interceptor)
  raise "Required Mochirii mail metadata interceptor is not registered"
end

preserved_member_text = "Member discussion about Discourse compatibility"
preservation_fixture = Mail.new
preservation_fixture.from = expected_address
preservation_fixture.to = "fixture@example.invalid"
preservation_fixture.subject = preserved_member_text
preservation_fixture.body = preserved_member_text
MochiriiEmailMetadata::APPLICATION_HEADER_NAMES.each do |name|
  preservation_fixture[name] = "fixture"
end
interceptor.delivering_email(preservation_fixture)
unless preservation_fixture.subject == preserved_member_text && preservation_fixture.body.decoded == preserved_member_text
  raise "Mail metadata interceptor altered member-authored subject or body"
end
remaining_fixture_names = preservation_fixture.header.fields.map { |field| field.name.to_s.downcase }
if (remaining_fixture_names & MochiriiEmailMetadata::APPLICATION_HEADER_NAMES).any?
  raise "Mail metadata interceptor retained an exact application identity header"
end

def materialize(delivery)
  delivery.respond_to?(:message) ? delivery.message : delivery
end

def render_parts(mail)
  text, html = Email.extract_parts(mail.encoded)
  [text, html]
end

def allow_fixture_admin_login_http?(stage4_fixture:, connect_fixture:, expected_address:)
  stage4_fixture == "true" &&
    connect_fixture == "true" &&
    expected_address == "notifications@fixture.invalid"
end

def verify_admin_login_link!(text_part:, html_part:, expected_base_url:, allow_fixture_http:)
  begin
    expected = URI.parse(expected_base_url)
  rescue URI::InvalidURIError
    raise RuntimeError, "Administrator recovery mail link is malformed", cause: nil
  end

  expected_scheme = allow_fixture_http ? "http" : "https"
  expected_port = allow_fixture_http ? 80 : 443
  expected_path = "/session/email-login/mochirii-fixture-admin-login-token"
  expected_link = "#{expected_scheme}://forums.mochirii.com#{expected_path}"
  expected_text =
    <<~TEXT.strip
      Somebody asked to log in to your account on [Mochirii Forums](#{expected_base_url}).

      If you did not make this request, you can safely ignore this email.

      Click the following link to log in:
      #{expected_link}
    TEXT
  expected_origin_exact =
    expected.scheme == expected_scheme &&
      expected.host == "forums.mochirii.com" &&
      expected.port == expected_port &&
      expected.userinfo.nil? &&
      expected.path.to_s.empty? &&
      expected.query.nil? &&
      expected.fragment.nil?
  normalized_text = text_part.to_s.gsub("\r\n", "\n").strip
  unless expected_origin_exact
    raise "Administrator recovery mail link escaped the exact Forums origin"
  end
  unless normalized_text.include?(expected_link)
    raise "Administrator recovery mail omitted its one-time login link"
  end
  unless html_part.nil? &&
      normalized_text == expected_text
    raise "Administrator recovery mail link escaped the exact Forums origin"
  end
end

bot = User.find_by(id: -2)
raise "Mochirii guide fixture is absent" unless bot&.username == "mochirii-guide"

post = Topic.find_by(id: SiteSetting.welcome_topic_id)&.first_post
post ||= Topic.find_by(id: SiteSetting.guidelines_topic_id)&.first_post
raise "Pinned member-visible mail fixture topic is absent" if post.nil?

notification_data = {
  original_username: post.user.username,
  original_user_id: post.user_id,
  topic_title: post.topic.title,
}
invite = Invite.new(
  email: "fixture@example.invalid",
  invited_by: bot,
  invite_key: "mochirii-fixture",
  email_token: "mochirii-fixture-token",
)

deliveries = {
  "test" => TestMailer.send_test("fixture@example.invalid"),
  "invite" => InviteMailer.send_invite(invite),
  "account" => UserNotifications.account_exists(bot),
  "security" => UserNotifications.account_second_factor_disabled(bot),
  "admin-login" => UserNotifications.admin_login(bot, email_token: "mochirii-fixture-admin-login-token"),
  "admin" =>
    AdminConfirmationMailer.send_email(
      "fixture@example.invalid",
      "fixture@example.invalid",
      "mochirii-fixture",
      "fixture-token",
    ),
  "backup" => DownloadBackupMailer.send_email("fixture@example.invalid", "mochirii-forums-fixture.tar.gz"),
  "rejection" =>
    RejectionMailer.send_rejection(
      "email_reject_topic_not_found",
      "fixture@example.invalid",
      former_title: "Mochirii fixture",
      destination: "fixture@example.invalid",
      site_name: SiteSetting.title,
    ),
}
if ENV["MOCHIRII_STAGE4_FIXTURE"] == "true"
  deliveries["notification"] =
    UserNotifications.user_posted(
      bot,
      post: post,
      notification_type: Notification.types[:posted],
      notification_data_hash: notification_data,
    )
  deliveries["digest"] = UserNotifications.digest(bot, since: 30.days.ago, skip_unsubscribe_links: true)
end

deliveries.each do |label, delivery|
  raise "#{label} mail path did not render" if delivery.nil?
  mail = materialize(delivery)
  pre_interceptor_names = mail.header.fields.map { |field| field.name.to_s }
  if ENV["MOCHIRII_STAGE4_FIXTURE"] == "true" && %w[notification digest].include?(label)
    unless pre_interceptor_names.any? { |name| name.match?(/\ADiscourse-|\AX-Discourse-/i) }
      raise "#{label} fixture did not exercise pinned upstream mail metadata"
    end
  end
  interceptor.delivering_email(mail)
  mail.encoded
  from = mail[:from]
  raise "#{label} mail From address is missing" if from.nil?
  raise "#{label} mail From display name changed" unless from.display_names == [expected_name]
  raise "#{label} mail From address changed" unless from.addresses == [expected_address]

  subject = mail.subject.to_s
  text_part, html_part = render_parts(mail)
  body = [text_part, html_part].compact.join("\n")
  visible_headers = [subject, from.to_s, mail[:reply_to]&.to_s].compact.join("\n")
  visible = [visible_headers, body].join("\n")
  raise "#{label} mail subject is not Mochirii-branded" unless subject.include?("Mochirii")
  if forbidden.any? { |pattern| visible.match?(pattern) }
    raise "#{label} mail contains prohibited public branding"
  end
  header_names = mail.header.fields.map { |field| field.name.to_s }
  if (header_names.map(&:downcase) & MochiriiEmailMetadata::APPLICATION_HEADER_NAMES).any?
    raise "#{label} mail retained an exact upstream application header"
  end
  if header_names.any? { |name| name.match?(/\bDiscourse\b/i) }
    raise "#{label} mail retained an unexpected upstream application header"
  end
  # Message-ID/References/In-Reply-To are non-rendered transport-threading
  # metadata. Every other field value is part of the recipient-visible or
  # application-controlled header boundary and must remain Mochirii-only.
  inspected_values =
    mail.header.fields.reject { |field| %w[message-id references in-reply-to].include?(field.name.to_s.downcase) }
      .map { |field| field.value.to_s }
      .join("\n")
  if forbidden.any? { |pattern| inspected_values.match?(pattern) }
    raise "#{label} mail contains prohibited recipient-visible metadata"
  end
  if label == "admin-login"
    allow_fixture_http =
      allow_fixture_admin_login_http?(
        stage4_fixture: ENV["MOCHIRII_STAGE4_FIXTURE"],
        connect_fixture: ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"],
        expected_address: expected_address,
      )
    verify_admin_login_link!(
      text_part: text_part,
      html_part: html_part,
      expected_base_url: Discourse.base_url,
      allow_fixture_http: allow_fixture_http,
    )
  end
end

if ENV["MOCHIRII_STAGE4_FIXTURE"] == "true"
  digest = materialize(deliveries.fetch("digest"))
  _digest_text, digest_html = Email.extract_parts(digest.encoded)
  raise "Digest HTML did not render" if digest_html.blank?
  raise "Digest HTML title is not Mochirii-branded" unless digest_html.include?("Mochirii Forums")
  digest_logo = SiteSetting.site_digest_logo_url.to_s
  raise "Digest logo URL is absent" if digest_logo.blank?
  uri = URI.parse(digest_logo)
  if uri.host.present? && !["forums.mochirii.com", "media-forums.mochirii.com"].include?(uri.host)
    raise "Digest logo URL escaped the Mochirii host boundary"
  end
  raise "Digest HTML omitted the reviewed logo" unless digest_html.include?(digest_logo)
end

staff_welcome =
  I18n.t(
    "system_messages.welcome_staff.text_body_template",
    role: "moderator",
    base_url: Discourse.base_url,
  )
raise "Staff welcome text is not Mochirii-branded" unless staff_welcome.include?("Mochirii Forums")
raise "Staff welcome text contains prohibited public branding" if forbidden.any? { |pattern| staff_welcome.match?(pattern) }

raise "Welcome mail path unexpectedly enabled" if SiteSetting.send_welcome_message
raise "Trust-level-one mail path unexpectedly enabled" if SiteSetting.send_tl1_welcome_message
raise "Trust-level-two mail path unexpectedly enabled" if SiteSetting.send_tl2_promotion_message
raise "Version mail path unexpectedly enabled" if SiteSetting.new_version_emails
raise "Old-credential reminder mail path unexpectedly enabled" unless SiteSetting.send_old_credential_reminder_days == 0
raise "Mail locale selection unexpectedly enabled" if SiteSetting.allow_user_locale

puts "Mochirii mail presentation passed."
