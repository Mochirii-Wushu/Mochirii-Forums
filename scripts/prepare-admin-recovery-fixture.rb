# frozen_string_literal: true

# Disposable-only issuance/cleanup for the pinned admin email-login path.
raise "Admin recovery fixture is fixture-only" unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"

action = ARGV.fetch(0)
raise "Admin recovery fixture action differs" unless %w[issue cleanup].include?(action)
record = SingleSignOnRecord.find_by(external_id: "mochirii-stage4-consumer-fixture")
raise "Admin recovery fixture identity is absent" if record.nil?
user = record.user
raise "Admin recovery fixture user is absent" if user.nil?
raise "Admin recovery fixture email differs" unless user.email == "stage4-fixture@forums.mochirii.com"

if action == "issue"
  raise "Admin recovery fixture unexpectedly became a moderator" if user.moderator?
  raise "Admin recovery fixture has conflicting staff state" if user.staff? && !user.admin?
  user.update!(admin: true) unless user.admin?
  raise "Admin recovery fixture administrator promotion failed" unless user.reload.admin?
  raise "Admin recovery fixture email is unconfirmed" unless user.email_confirmed?
  token = nil
  user.with_lock do
    user.email_tokens.where(scope: EmailToken.scopes[:email_login]).destroy_all
    token = user.email_tokens.create!(email: user.email, scope: EmailToken.scopes[:email_login])
    raise "Admin recovery token is not unique" unless user.email_tokens.where(
      scope: EmailToken.scopes[:email_login],
    ).one?
  end
  print token.token
else
  user.email_tokens.where(scope: EmailToken.scopes[:email_login]).destroy_all
  user.update!(admin: false, moderator: false)
  raise "Admin recovery fixture cleanup failed" if user.reload.staff?
  puts "Admin recovery fixture cleanup passed."
end
