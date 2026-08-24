# frozen_string_literal: true

# Read one recovery identity privately from stdin and emit no identifier or token.
action = ARGV.fetch(0)
raise "recovery action differs" unless %w[verify send].include?(action)
email = STDIN.read.to_s.strip.downcase
raise "recovery identity is malformed" unless email.match?(
  /\A[A-Za-z0-9.!#$%&'*+\/=\?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\z/,
)
raise "recovery identity is too long" if email.bytesize > 254

developers = GlobalSetting.developer_emails.to_s.split(",").map { |value| value.strip.downcase }
raise "recovery administrator is outside the protected identity list" unless developers.include?(email)

matches = User.real.admins.with_email(email).distinct.to_a
raise "recovery administrator identity is not unique" unless matches.one?
user = matches.first
raise "recovery administrator identity differs" unless user.email.to_s.downcase == email
raise "recovery administrator is not active" unless user.active?
raise "recovery administrator is not approved" unless user.approved?
raise "recovery administrator is staged" if user.staged?
raise "recovery administrator is suspended" if user.suspended?
raise "recovery administrator lacks administrator authority" unless user.admin?
raise "recovery administrator email is unconfirmed" unless user.email_confirmed?

raise "ordinary local login is enabled" if SiteSetting.enable_local_logins
raise "email local login is enabled" if SiteSetting.enable_local_logins_via_email
raise "code local login is enabled" if SiteSetting.enable_local_logins_via_code
raise "passkey login is enabled" if SiteSetting.enable_passkeys
raise "third-party login remains enabled" unless Discourse.enabled_authenticators.empty?
raise "administrator login recovery requires configured delivery" if GlobalSetting.smtp_address.blank?

if action == "send"
  token_record = nil
  begin
    user.with_lock do
      user.email_tokens.where(scope: EmailToken.scopes[:email_login]).destroy_all
      token_record = user.email_tokens.create!(email: user.email, scope: EmailToken.scopes[:email_login])
      raise "recovery token is not unique" unless user.email_tokens.where(
        scope: EmailToken.scopes[:email_login],
      ).one?
    end
    Jobs.enqueue(
      :critical_user_email,
      type: "admin_login",
      user_id: user.id,
      email_token: token_record.token,
    )
  rescue StandardError
    token_record&.destroy!
    raise
  end
end

puts "Mochirii Forums recovery administrator boundary verified."
