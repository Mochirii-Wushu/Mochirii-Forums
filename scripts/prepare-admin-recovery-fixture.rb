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
staff_group_ids = Group::STAFF_GROUPS.map { |name| Group::AUTO_GROUPS.fetch(name) }.sort.freeze
staff_memberships = -> { GroupUser.where(user_id: user.id, group_id: staff_group_ids).pluck(:group_id).sort }

if action == "issue"
  raise "Admin recovery fixture unexpectedly became a moderator" if user.moderator?
  raise "Admin recovery fixture has conflicting staff state" if user.staff? && !user.admin?
  if user.admin?
    raise "Admin recovery fixture administrator groups differ" unless staff_memberships.call == [
      Group::AUTO_GROUPS.fetch(:admins),
      Group::AUTO_GROUPS.fetch(:staff),
    ].sort
  else
    raise "Admin recovery fixture retained a staff group" if staff_memberships.call.any?
    user.grant_admin!
  end
  raise "Admin recovery fixture administrator promotion failed" unless user.reload.admin?
  raise "Admin recovery fixture administrator groups differ" unless staff_memberships.call == [
    Group::AUTO_GROUPS.fetch(:admins),
    Group::AUTO_GROUPS.fetch(:staff),
  ].sort
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
  UserAuthToken.where(user_id: user.id).destroy_all
  user.revoke_moderation! if user.moderator?
  user.revoke_admin! if user.admin?
  Group.refresh_automatic_groups!(:admins, :moderators, :staff)
  raise "Admin recovery fixture cleanup retained staff authority" if user.reload.staff?
  raise "Admin recovery fixture cleanup retained a staff group" if staff_memberships.call.any?
  raise "Admin recovery fixture cleanup retained an email token" if user.email_tokens.where(
    scope: EmailToken.scopes[:email_login],
  ).exists?
  raise "Admin recovery fixture cleanup retained an authenticated session" if UserAuthToken.where(
    user_id: user.id,
  ).exists?
  puts "Admin recovery fixture cleanup passed."
end
