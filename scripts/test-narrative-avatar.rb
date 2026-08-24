# frozen_string_literal: true

# Deterministic source-only fixture for the pinned narrative-system-user avatar
# callback. It evaluates the repository's exact extracted helper against a
# minimal model of User#refresh_avatar, Jobs::UpdateGravatar, and
# UserAvatar#update_gravatar!. No Rails application, queue, database, network,
# or provider is used.

CONFIGURE_SITE = File.expand_path("configure-site.rb", __dir__)
APP_CONFIG = File.expand_path("../config/app.yml.example", __dir__)

module NarrativeAvatarHarness
  class FixtureError < StandardError
  end

  APP_SETTING = "DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"
  ICON_UPLOAD_ID = 41
  GRAVATAR_UPLOAD_ID = 97

  class << self
    attr_accessor :gravatar_response, :rename_count
  end

  def self.apply_app_setting!(setting)
    environment = {}
    environment[APP_SETTING] = setting.to_s if setting != :omitted
    raw = environment.fetch(APP_SETTING, "true")
    unless %w[false true].include?(raw)
      raise FixtureError, "automatic Gravatar fixture setting differed"
    end

    SiteSetting.automatically_download_gravatars = raw == "true"
  end

  def self.reset!(app_setting:, gravatar_response:)
    self.gravatar_response = gravatar_response
    self.rename_count = 0
    Jobs.reset!
    User.reset!
    apply_app_setting!(app_setting)
  end
end

module SiteSetting
  class << self
    attr_accessor :automatically_download_gravatars

    def automatically_download_gravatars?
      automatically_download_gravatars
    end
  end
end

module Discourse
  def self.system_user
    :fixture_system_user
  end
end

class FixtureProfile
  attr_reader :attributes

  def update!(attributes)
    @attributes = attributes.dup
  end
end

class UserAvatar
  attr_accessor :custom_upload_id,
                :gravatar_upload_id,
                :last_gravatar_download_attempt,
                :user
  attr_reader :id

  class << self
    attr_accessor :record

    def find_by(id:)
      record if record&.id == id
    end
  end

  def initialize(id:, user:)
    @id = id
    @user = user
    @custom_upload_id = nil
    @gravatar_upload_id = nil
    @last_gravatar_download_attempt = nil
  end

  def update!(attributes)
    attributes.each { |name, value| public_send("#{name}=", value) }
  end

  def update_gravatar!
    self.last_gravatar_download_attempt = :attempted
    return if NarrativeAvatarHarness.gravatar_response == :not_found

    unless NarrativeAvatarHarness.gravatar_response == :success
      raise NarrativeAvatarHarness::FixtureError, "unexpected Gravatar fixture response"
    end

    self.gravatar_upload_id = NarrativeAvatarHarness::GRAVATAR_UPLOAD_ID
  end
end

class User
  attr_accessor :email, :name, :uploaded_avatar_id, :username
  attr_reader :avatar_create_count, :id, :profile_create_count, :user_avatar, :user_profile

  class << self
    attr_accessor :record

    def reset!
      self.record = new
      UserAvatar.record = nil
    end

    def find_by(id: nil, **)
      record if id == record&.id
    end

    def exists?(username_lower:)
      record && record.username.downcase == username_lower
    end
  end

  def initialize
    @id = -2
    @username = "discobot"
    @name = "Discourse Narrative Bot"
    @email = "discobot@discourse.org"
    @uploaded_avatar_id = nil
    @user_profile = nil
    @user_avatar = nil
    @profile_create_count = 0
    @avatar_create_count = 0
  end

  def primary_email
    email
  end

  def reload
    self
  end

  def update!(attributes)
    previous_uploaded_avatar_id = uploaded_avatar_id
    attributes.each { |name, value| public_send("#{name}=", value) }
    refresh_avatar(previous_uploaded_avatar_id != uploaded_avatar_id)
  end

  def update_column(name, value)
    public_send("#{name}=", value)
  end

  def create_user_profile!
    @profile_create_count += 1
    @user_profile = FixtureProfile.new
  end

  def create_user_avatar!
    @avatar_create_count += 1
    @user_avatar = UserAvatar.new(id: 73, user: self)
    UserAvatar.record = @user_avatar
  end

  private

  def refresh_avatar(uploaded_avatar_changed)
    avatar = user_avatar || create_user_avatar!
    if !primary_email.to_s.empty? && SiteSetting.automatically_download_gravatars? &&
         !avatar.last_gravatar_download_attempt
      Jobs.cancel_scheduled_job(:update_gravatar, user_id: id, avatar_id: avatar.id)
      Jobs.enqueue_in(1, :update_gravatar, user_id: id, avatar_id: avatar.id)
    end
    Jobs.enqueue(:rebake_quoted_posts_for_user, user_id: id) if uploaded_avatar_changed
  end
end

class UsernameChanger
  def initialize(user, username, actor)
    @user = user
    @username = username
    @actor = actor
  end

  def change(asynchronous:)
    unless asynchronous == false && @actor == Discourse.system_user
      raise NarrativeAvatarHarness::FixtureError, "username changer boundary differed"
    end

    NarrativeAvatarHarness.rename_count += 1
    @user.username = @username
    true
  end
end

module Jobs
  class << self
    attr_reader :enqueued, :executed_gravatar_jobs, :scheduled

    def reset!
      @enqueued = []
      @executed_gravatar_jobs = 0
      @scheduled = []
    end

    def cancel_scheduled_job(name, **arguments)
      scheduled.reject! { |job| job[:name] == name && job[:arguments] == arguments }
    end

    def enqueue_in(delay, name, **arguments)
      scheduled << { delay: delay, name: name, arguments: arguments.dup }
    end

    def enqueue(name, **arguments)
      enqueued << { name: name, arguments: arguments.dup }
    end

    def drain_update_gravatar!
      jobs = scheduled.dup
      scheduled.clear
      jobs.each do |job|
        unless job[:delay] == 1 && job[:name] == :update_gravatar
          raise NarrativeAvatarHarness::FixtureError, "unexpected delayed fixture job"
        end

        @executed_gravatar_jobs += 1
        UpdateGravatar.new.execute(job[:arguments])
      end
    end
  end

  class UpdateGravatar
    def execute(arguments)
      user = User.find_by(id: arguments[:user_id])
      avatar = UserAvatar.find_by(id: arguments[:avatar_id])
      return unless user && avatar && avatar.user&.id == user.id && !user.primary_email.to_s.empty?

      avatar.update_gravatar!
      if !user.uploaded_avatar_id && avatar.gravatar_upload_id
        user.update_column(:uploaded_avatar_id, avatar.gravatar_upload_id)
      end
    end
  end
end

def assert_fixture(condition, message)
  raise NarrativeAvatarHarness::FixtureError, message unless condition
end

def assert_branded_avatar(user)
  assert_fixture(user.username == "mochirii-guide", "narrative username differed")
  assert_fixture(user.name == "Mochirii Guide", "narrative name differed")
  assert_fixture(
    user.email == "mochirii-guide@forums.mochirii.com",
    "narrative email differed",
  )
  assert_fixture(
    user.uploaded_avatar_id == NarrativeAvatarHarness::ICON_UPLOAD_ID,
    "selected narrative avatar differed",
  )
  assert_fixture(
    user.user_avatar.custom_upload_id == NarrativeAvatarHarness::ICON_UPLOAD_ID,
    "custom narrative avatar differed",
  )
end

configure_source = File.binread(CONFIGURE_SITE)
method_marker = "def configure_narrative_system_user!(icon_upload)\n"
call_boundary = "\n\nconfigure_narrative_system_user!(icon_upload)\n"
assert_fixture(configure_source.scan(method_marker).length == 1, "narrative helper count differed")
assert_fixture(configure_source.scan(call_boundary).length == 1, "narrative helper call boundary differed")
method_start = configure_source.index(method_marker)
method_finish = configure_source.index(call_boundary, method_start)
assert_fixture(method_finish && method_finish > method_start, "narrative helper boundary was absent")
method_source = configure_source.byteslice(method_start, method_finish - method_start)
eval(method_source, TOPLEVEL_BINDING, CONFIGURE_SITE, configure_source.byteslice(0, method_start).count("\n") + 1)
avatar_write_order =
  "  bot.user_avatar.update!(custom_upload_id: icon_upload.id, gravatar_upload_id: nil)\n" \
  "  bot.update!(uploaded_avatar_id: icon_upload.id)\n"
reordered_avatar_write_order =
  "  bot.update!(uploaded_avatar_id: icon_upload.id)\n" \
  "  bot.user_avatar.update!(custom_upload_id: icon_upload.id, gravatar_upload_id: nil)\n"
assert_fixture(method_source.scan(avatar_write_order).length == 1, "avatar write-order anchor differed")
reordered_method_source = method_source
  .sub(
    "def configure_narrative_system_user!(icon_upload)",
    "def configure_narrative_system_user_reordered!(icon_upload)",
  )
  .sub(avatar_write_order, reordered_avatar_write_order)
assert_fixture(
  reordered_method_source.scan(reordered_avatar_write_order).length == 1 &&
    !reordered_method_source.include?(avatar_write_order),
  "reorder hostile did not invert the exact avatar writes",
)
eval(reordered_method_source, TOPLEVEL_BINDING, "#{CONFIGURE_SITE}:reordered-hostile", 1)

app_config_source = File.binread(APP_CONFIG)
false_app_setting = /^  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"\r?$/
assert_fixture(
  app_config_source.scan(false_app_setting).length == 1,
  "app configuration does not disable automatic Gravatar downloads exactly once",
)

icon_upload = Struct.new(:id).new(NarrativeAvatarHarness::ICON_UPLOAD_ID)

# The committed false application setting is effective before either User save.
# Both the first configure and an idempotent second configure remain quiescent,
# including after a post-return job drain.
NarrativeAvatarHarness.reset!(app_setting: :false, gravatar_response: :success)
configure_narrative_system_user!(icon_upload)
false_user = User.record
assert_branded_avatar(false_user)
assert_fixture(false_user.user_avatar.gravatar_upload_id.nil?, "disabled setting wrote a Gravatar")
assert_fixture(Jobs.scheduled.empty?, "disabled setting scheduled a Gravatar job")
profile = false_user.user_profile
avatar = false_user.user_avatar
Jobs.drain_update_gravatar!
configure_narrative_system_user!(icon_upload)
Jobs.drain_update_gravatar!
assert_branded_avatar(false_user)
assert_fixture(false_user.user_profile.equal?(profile), "second configure replaced the narrative profile")
assert_fixture(false_user.user_avatar.equal?(avatar), "second configure replaced the narrative avatar")
assert_fixture(false_user.profile_create_count == 1, "narrative profile creation was not idempotent")
assert_fixture(false_user.avatar_create_count == 1, "narrative avatar creation was not idempotent")
assert_fixture(NarrativeAvatarHarness.rename_count == 1, "narrative rename was not idempotent")
assert_fixture(Jobs.executed_gravatar_jobs.zero?, "disabled setting executed a Gravatar job")
assert_fixture(Jobs.scheduled.empty?, "second disabled configure left a delayed job")

# With the setting explicitly true, the helper's final clear and selected-avatar
# writes are safe only until the pinned delayed job runs. A successful response
# then writes gravatar_upload_id after the helper has returned.
NarrativeAvatarHarness.reset!(app_setting: :true, gravatar_response: :success)
configure_narrative_system_user!(icon_upload)
true_user = User.record
assert_branded_avatar(true_user)
assert_fixture(true_user.user_avatar.gravatar_upload_id.nil?, "pre-drain true fixture differed")
assert_fixture(Jobs.scheduled.length == 1, "true setting did not retain one exact delayed job")
Jobs.drain_update_gravatar!
assert_branded_avatar(true_user)
assert_fixture(
  true_user.user_avatar.gravatar_upload_id == NarrativeAvatarHarness::GRAVATAR_UPLOAD_ID,
  "successful delayed Gravatar did not reproduce the post-return write",
)
assert_fixture(Jobs.executed_gravatar_jobs == 1, "successful delayed Gravatar count differed")
configure_narrative_system_user!(icon_upload)
Jobs.drain_update_gravatar!
assert_branded_avatar(true_user)
assert_fixture(true_user.user_avatar.gravatar_upload_id.nil?, "second configure did not clear Gravatar state")
assert_fixture(Jobs.scheduled.empty?, "attempted Gravatar was rescheduled on second configure")

# Omitting the application setting preserves Discourse's pinned enabled default,
# so reordering the helper's own writes cannot prevent the same post-return job.
NarrativeAvatarHarness.reset!(app_setting: :omitted, gravatar_response: :success)
assert_fixture(SiteSetting.automatically_download_gravatars?, "omitted setting did not default true")
configure_narrative_system_user_reordered!(icon_upload)
omitted_user = User.record
assert_fixture(omitted_user.user_avatar.gravatar_upload_id.nil?, "pre-drain omitted fixture differed")
Jobs.drain_update_gravatar!
assert_fixture(
  omitted_user.user_avatar.gravatar_upload_id == NarrativeAvatarHarness::GRAVATAR_UPLOAD_ID,
  "omitted setting did not reproduce the delayed Gravatar write",
)

# A 404 still records an attempt but happens not to populate the Gravatar field.
# The disabled application setting is required because a successful response is
# valid pinned behavior and cannot be replaced by an assumption about the host.
NarrativeAvatarHarness.reset!(app_setting: :true, gravatar_response: :not_found)
configure_narrative_system_user!(icon_upload)
not_found_user = User.record
Jobs.drain_update_gravatar!
assert_branded_avatar(not_found_user)
assert_fixture(not_found_user.user_avatar.gravatar_upload_id.nil?, "404 fixture wrote a Gravatar")
assert_fixture(
  not_found_user.user_avatar.last_gravatar_download_attempt == :attempted,
  "404 fixture did not record the pinned download attempt",
)
assert_fixture(Jobs.executed_gravatar_jobs == 1, "404 delayed Gravatar count differed")
assert_fixture(Jobs.scheduled.empty?, "fixture ended with a delayed Gravatar job")

puts "Narrative avatar delayed-job fixture passed."
