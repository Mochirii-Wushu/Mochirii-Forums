#!/usr/bin/env python3
"""Verify exact upstream bytes and pin-specific semantic contracts."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKER_REPOSITORY = "discourse/discourse_docker"
CORE_REPOSITORY = "discourse/discourse"
MANAGER_REPOSITORY = "discourse/docker_manager"
ACME_REPOSITORY = "acmesh-official/acme.sh"
PINNED_EMAIL_SHA256 = "99ebebf096369af5bb765b5105abff94e28f6054be440ae922f0361ce1c1c0c2"
PINNED_EMAIL_BYTES = 1549
PINNED_OPENSEARCH_EVIDENCE = {
    "app/controllers/metadata_controller.rb": (
        4914,
        "7bf4d3f2034773d7cc5ad5c1ea621b8716caed198cd5f7a4a377bb6a04321de6",
    ),
    "app/views/metadata/opensearch.xml.erb": (
        926,
        "44e583c097b8dacc3a6825e7d9376505ff886c521b6632bd9ad176ea6360cc64",
    ),
}
PINNED_OPENSEARCH_CONTROLLER_BLOCK = b'''  def opensearch
    expires_in 1.minute
    render template: "metadata/opensearch", formats: [:xml]
  end

'''
PINNED_EMAIL_EXTRACT_PARTS_BLOCK = b'''  def self.extract_parts(raw)
    mail = Mail.new(raw)
    text = nil
    html = nil

    if mail.multipart?
      text = mail.text_part
      html = mail.html_part
    elsif mail.content_type.to_s["text/html"]
      html = mail
    else
      text = mail
    end

    [text&.decoded, html&.decoded]
  end

'''
PINNED_MAIL_SEMANTIC_EVIDENCE = {
    "app/mailers/user_notifications.rb": (
        28133,
        "eb6a22bb03b0731e81f9f560609bd344be3076fb49c1cffe21c6590f495063d4",
    ),
    "app/models/topic.rb": (
        78502,
        "fd6468dd779edc6767dd8fb380e36c735b0698f6f4a2951a5e8a3b186ea6f056",
    ),
    "app/mailers/admin_confirmation_mailer.rb": (
        438,
        "409f849e00ee2d001c2106e5c2aacdb15c448a9aee246005381b735194347849",
    ),
    "lib/admin_confirmation.rb": (
        1699,
        "d095168b0c36efabf5a74e6e7685865a8c39b4520d444e86470874113b963566",
    ),
    "lib/email/message_builder.rb": (
        13752,
        "6238ba3ecdb9a4003e0cce29938fc481c7c657bf07f392b00c1a2147db2f3502",
    ),
    "lib/email/build_email_helper.rb": (
        393,
        "bb537c8d6dcce21ef12184de53ec32bab64b807e34c6a872f3243686be0c8f7a",
    ),
    "lib/discourse.rb": (
        39279,
        "351e1170f79acb9b321746df618339de5412c95b1ce4c13db2c17e96bf1d0678",
    ),
    "config/locales/server.en.yml": (
        420250,
        "0ff18443abac07e496e27142f21b33e8935242ca3d55fd33531c1ace43a92f50",
    ),
    "app/helpers/user_notifications_helper.rb": (
        3229,
        "8916b4cf739dd589a2d6f8131332b9b59b2de20b9981b210c1bea0b189803aa5",
    ),
    "config/routes.rb": (
        81601,
        "f5b5a641132de5342d78e0e3579783c0dcd0391ec5997e2034dd6a99d8c3078b",
    ),
}
PINNED_TOPIC_SEED_EVIDENCE = {
    "db/fixtures/990_topics.rb": (
        321,
        "e25b129d6c76d27837e1d4a9e187cd7b49bacfe79e3d438e1a7473909e48a5c9",
    ),
    "docs/ADMIN-QUICK-START-GUIDE.md": (
        1905,
        "94d08273429f2e919890201c2d21608595b78d384e4d3d7dc180659918744f50",
    ),
    "lib/seed_data/topics.rb": (
        7537,
        "2e43f4a9f95f19d1e928e5ef6b873ed4f66144d91280f400a63e6e23e9029020",
    ),
}
PINNED_TOPIC_FIXTURE_SOURCE = b'''# frozen_string_literal: true

if !Rails.env.test?
  require "seed_data/topics"

  topics_exist = Topic.where(<<~SQL).exists?
    id NOT IN (
      SELECT topic_id
      FROM categories
      WHERE topic_id IS NOT NULL
    )
  SQL

  SeedData::Topics.with_default_locale.create(include_welcome_topics: !topics_exist)
end
'''
PINNED_ADMIN_QUICK_START_TOPIC_BLOCK = b'''        # Admin Quick Start Guide
        topics << {
          site_setting_name: "admin_quick_start_topic_id",
          title:
            DiscoursePluginRegistry.seed_data["admin_quick_start_title"] ||
              I18n.t("admin_quick_start_title"),
          raw: admin_quick_start_raw,
          category: staff_category,
        }
'''
PINNED_TOPIC_CREATE_GUARD_BLOCK = b'''      topic_id = SiteSetting.get(site_setting_name)
      return if topic_id > 0 || Topic.find_by(id: topic_id)

      post =
        PostCreator.create!(
          Discourse.system_user,
'''
PINNED_ADMIN_QUICK_START_RAW_BLOCK = b'''    def admin_quick_start_raw
      quick_start_filename = DiscoursePluginRegistry.seed_data["admin_quick_start_filename"]

      if !quick_start_filename || !File.exist?(quick_start_filename)
        # TODO Make the quick start guide translatable
        quick_start_filename = Rails.root.join("docs/ADMIN-QUICK-START-GUIDE.md").to_s
      end

      content = File.read(quick_start_filename)
      content.gsub!("%{base_url}", Discourse.base_url)
      content
    end
'''
PINNED_USER_NOTIFICATIONS_DIGEST_BLOCK = b'''  def digest(user, opts = {})
    build_summary_for(user)
    if !opts[:skip_unsubscribe_links]
      @unsubscribe_key = UnsubscribeKey.create_key_for(@user, UnsubscribeKey::DIGEST_TYPE)
    end

    @since = opts[:since].presence
    @since ||= [user.last_seen_at, user.user_stat&.digest_attempted_at, 1.month.ago].compact.max

    # Fetch some topics and posts to show
    digest_opts = {
      limit: SiteSetting.digest_topics + SiteSetting.digest_other_topics,
      top_order: true,
    }
    topics_for_digest = Topic.for_digest(user, @since, digest_opts)
    if topics_for_digest.empty? && !user.user_option.try(:include_tl0_in_digests)
      # Find some topics from new users that are at least 24 hours old
      topics_for_digest =
        Topic.for_digest(user, @since, digest_opts.merge(include_tl0: true)).where(
          "topics.created_at < ?",
          24.hours.ago,
        )
    end

    @popular_topics = topics_for_digest[0, SiteSetting.digest_topics]

    if @popular_topics.present?
      @other_new_for_you =
        (
          if topics_for_digest.size > SiteSetting.digest_topics
            topics_for_digest[SiteSetting.digest_topics..-1]
          else
            []
          end
        )

      @popular_posts =
        if SiteSetting.digest_posts > 0
          Post
            .order("posts.score DESC")
            .for_mailing_list(user, @since)
            .where("posts.post_type = ?", Post.types[:regular])
            .where(
              "posts.deleted_at IS NULL AND posts.hidden = false AND posts.user_deleted = false",
            )
            .where(
              "posts.post_number > ? AND posts.score > ?",
              1,
              ScoreCalculator.default_score_weights[:like_score] * 5.0,
            )
            .where("posts.created_at < ?", (SiteSetting.editing_grace_period || 0).seconds.ago)
            .limit(SiteSetting.digest_posts)
        else
          []
        end

      @excerpts = {}

      @popular_topics.each do |t|
        next if t.first_post.blank?
        @excerpts[t.first_post.id] = email_excerpt(t.first_post.cooked, t.first_post)
      end

      # Try to find 3 interesting stats for the top of the digest
      new_topics_count = Topic.for_digest(user, @since).count
      # We used topics from new users instead, so count should match
      new_topics_count = topics_for_digest.size if new_topics_count == 0

      @counts = [
        {
          id: "new_topics",
          label_key: "user_notifications.digest.new_topics",
          value: new_topics_count,
          href: "#{Discourse.base_url}/new",
        },
      ]

      # totalling unread notifications (which are low-priority only) and unread
      # PMs and bookmark reminder notifications, so the total is both unread low
      # and high priority PMs
      value = user.unread_notifications + user.unread_high_priority_notifications
      if value > 0
        @counts << {
          id: "unread_notifications",
          label_key: "user_notifications.digest.unread_notifications",
          value: value,
          href: "#{Discourse.base_url}/my/notifications",
        }
      end

      if @counts.size < 3
        value = user.unread_notifications_of_type(Notification.types[:liked], since: @since)
        if value > 0
          @counts << {
            id: "likes_received",
            label_key: "user_notifications.digest.liked_received",
            value: value,
            href: "#{Discourse.base_url}/my/notifications",
          }
        end
      end

      if @counts.size < 3 && user.user_option.digest_after_minutes.to_i >= 1440
        value = summary_new_users_count(@since)
        if value > 0
          @counts << {
            id: "new_users",
            label_key: "user_notifications.digest.new_users",
            value: value,
            href: "#{Discourse.base_url}/about",
          }
        end
      end

      @preheader_text = I18n.t("user_notifications.digest.preheader", since: @since)

      subject_key = "user_notifications.digest.subject_template"

      if SiteSetting.simple_email_subject && I18n.exists?("#{subject_key}_improved")
        subject_key += "_improved"
      end

      opts = {
        from_alias: I18n.t("user_notifications.digest.from", site_name: Email.site_title),
        subject: I18n.t(subject_key, email_prefix: @email_prefix, date: short_date(Time.now)),
        add_unsubscribe_link: !opts[:skip_unsubscribe_links],
        unsubscribe_url: "#{Discourse.base_url}/email/unsubscribe/#{@unsubscribe_key}",
        topic_ids: topics_for_digest.pluck(:id),
        post_ids:
          topics_for_digest.joins(:posts).where(posts: { post_number: 1 }).pluck("posts.id"),
      }

      opts[:recipient_user] = user

      build_email(user.email, opts)
    end
  end

'''
PINNED_TOPIC_FOR_DIGEST_BLOCK = b'''  def self.for_digest(user, since, opts = nil)
    opts ||= {}

    period = ListController.best_period_for(since)

    topics =
      Topic
        .visible
        .secured(Guardian.new(user))
        .joins(
          "LEFT OUTER JOIN topic_users ON topic_users.topic_id = topics.id AND topic_users.user_id = #{user.id.to_i}",
        )
        .joins(
          "LEFT OUTER JOIN category_users ON category_users.category_id = topics.category_id AND category_users.user_id = #{user.id.to_i}",
        )
        .joins("LEFT OUTER JOIN users ON users.id = topics.user_id")
        .where(closed: false, archived: false)
        .where(
          "COALESCE(topic_users.notification_level, 1) <> ?",
          TopicUser.notification_levels[:muted],
        )
        .created_since(since)
        .where("topics.created_at < ?", (SiteSetting.editing_grace_period || 0).seconds.ago)
        .listable_topics
        .includes(:category)

    unless opts[:include_tl0] || user.user_option.try(:include_tl0_in_digests)
      topics = topics.where("COALESCE(users.trust_level, 0) > 0")
    end

    if !!opts[:top_order]
      topics =
        topics.joins("LEFT OUTER JOIN top_topics ON top_topics.topic_id = topics.id").order(<<~SQL)
          COALESCE(topic_users.notification_level, 1) DESC,
          COALESCE(category_users.notification_level, 1) DESC,
          COALESCE(top_topics.#{TopTopic.score_column_for_period(period)}, 0) DESC,
          topics.bumped_at DESC
      SQL
    end

    topics = topics.limit(opts[:limit]) if opts[:limit]

    # Remove category topics
    topics = topics.where.not(id: Category.select(:topic_id).where.not(topic_id: nil))

    # Remove suppressed categories
    if SiteSetting.digest_suppress_categories.present?
      topics =
        topics.where.not(category_id: SiteSetting.digest_suppress_categories.split("|").map(&:to_i))
    end

    # Remove suppressed tags
    if SiteSetting.digest_suppress_tags.present?
      tag_ids = Tag.where_name(SiteSetting.digest_suppress_tags.split("|")).pluck(:id)

      topics =
        topics.where.not(id: TopicTag.where(tag_id: tag_ids).select(:topic_id)) if tag_ids.present?
    end

    # Remove muted and shared draft categories
    remove_category_ids =
      CategoryUser.where(user:, notification_level: CategoryUser.notification_levels[:muted]).pluck(
        :category_id,
      )

    remove_category_ids << SiteSetting.shared_drafts_category if SiteSetting.shared_drafts_enabled?

    if remove_category_ids.present?
      remove_category_ids.uniq!
      topics =
        topics.where(
          "topic_users.notification_level != ? OR topics.category_id NOT IN (?)",
          TopicUser.notification_levels[:muted],
          remove_category_ids,
        )
    end

    # Remove topics from ignored users
    ignored_user_ids =
      IgnoredUser.where(user:).where(expiring_at: Time.zone.now..).pluck(:ignored_user_id)
    topics = topics.where.not(user_id: ignored_user_ids) if ignored_user_ids.present?

    # Remove muted tags
    muted_tag_ids = TagUser.lookup(user, :muted).pluck(:tag_id)
    unless muted_tag_ids.empty?
      # If multiple tags per topic, include topics with tags that aren't muted,
      # and don't forget untagged topics.
      topics =
        topics.where(
          "EXISTS (SELECT 1 FROM topic_tags WHERE topic_tags.topic_id = topics.id AND tag_id NOT IN (?)) OR NOT EXISTS (SELECT 1 FROM topic_tags WHERE topic_tags.topic_id = topics.id)",
          muted_tag_ids,
        )
    end

    topics
  end

'''
PINNED_ADMIN_LOGIN_METHOD_BLOCK = b'''  def admin_login(user, opts = {})
    build_user_email_token_by_template("user_notifications.admin_login", user, opts[:email_token])
  end

'''
PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE = b'''# frozen_string_literal: true

class AdminConfirmationMailer < ActionMailer::Base
  include Email::BuildEmailHelper

  def send_email(to_address, target_email, target_username, token)
    build_email(
      to_address,
      template: "admin_confirmation_mailer",
      target_email: target_email,
      target_username: target_username,
      admin_confirm_url: confirm_admin_url(token: token, host: Discourse.base_url),
    )
  end
end
'''
PINNED_LOGIN_CODE_DENIAL_METHOD = b'''  def ensure_login_code_allowed
    if !UpcomingChanges.enabled_for_user?(:enable_local_logins_via_code, current_user)
      raise Discourse::NotFound
    end
    # Code login is a delivery variant of email login, so it also requires
    # `enable_local_logins_via_email` (checked via `check_login_via_email`).
    check_local_login_allowed(check_login_via_email: true)
    redirect_to path("/") if current_user
  end

'''
PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK = b'''  def create_confirmation
    guardian = Guardian.new(@performed_by)
    guardian.ensure_can_grant_admin!(@target_user)

    @token = SecureRandom.hex
    Discourse.redis.setex("admin-confirmation:#{@target_user.id}", 3.hours.to_i, @token)

    payload = { target_user_id: @target_user.id, performed_by: @performed_by.id }
    Discourse.redis.setex("admin-confirmation-token:#{@token}", 3.hours.to_i, payload.to_json)

    Jobs.enqueue(
      :admin_confirmation_email,
      to_address: @performed_by.email,
      target_email: @target_user.email,
      target_username: @target_user.username,
      token: @token,
    )
  end

'''
PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK = b'''      get(
        {
          "#{root_path}/confirm-admin/:token" => "users#confirm_admin",
          :constraints => {
            token: /[0-9a-f]+/,
          },
        }.merge(index == 1 ? { as: "confirm_admin" } : {}),
      )
      post "#{root_path}/confirm-admin/:token" => "users#confirm_admin",
           :constraints => {
             token: /[0-9a-f]+/,
           }
'''
PINNED_EMAIL_LOGIN_HELPER_BLOCK = b'''  def build_user_email_token_by_template(template, user, email_token)
    build_email(
      user.email,
      template: template,
      locale: user_locale(user),
      email_token: email_token,
      recipient_user: user,
    )
  end

'''
PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX = b'''    def initialize(to, opts = nil)
      @to = to
      @opts = opts || {}
      @template_args = {
        site_name: SiteSetting.title,
        email_prefix: SiteSetting.email_prefix.presence || SiteSetting.title,
        base_url: Discourse.base_url,
        user_preferences_url: "#{Discourse.base_url}/my/preferences",
        hostname: Discourse.current_hostname,
      }.merge!(@opts)

'''
PINNED_MESSAGE_BUILDER_BODY_BLOCK = b'''    def body
      body = nil

      if @opts[:template]
        %i[topic_title inviter_name].each do |key|
          @template_args[key] = escaped_template_arg(key) if @template_args.key?(key)
        end

        augmented_template_args =
          @template_args.merge(
            optional_re: "",
            optional_pm: "",
            optional_cat: format_category,
            optional_tags: format_tags,
          )

        body = I18n.t("#{@opts[:template]}.text_body_template", augmented_template_args).dup
      else
        body = @opts[:body].dup
      end

      if @template_args[:unsubscribe_instructions].present?
        body << "\\n"
        body << @template_args[:unsubscribe_instructions]
      end
      DiscoursePluginRegistry.apply_modifier(:message_builder_body, body, @opts, @to)
    end

'''
PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX = b'''    def html_part
      return unless html_override = @opts[:html_override]
'''
PINNED_BUILD_EMAIL_HELPER_SOURCE = b'''# frozen_string_literal: true

module Email
  module BuildEmailHelper
    def build_email(*builder_args)
      builder = Email::MessageBuilder.new(*builder_args)
      headers(builder.header_args) if builder.header_args.present?
      mail(builder.build_args).tap do |message|
        if message && h = builder.html_part
          message.html_part = h
        end
      end
    end
  end
end
'''
PINNED_BASE_PROTOCOL_BLOCK = b'''  def self.base_protocol
    SiteSetting.force_https? ? "https" : "http"
  end

'''
PINNED_ADMIN_LOGIN_LOCALE_BLOCK = b'''    admin_login:
      title: "Admin Login"
      preview: "Admin login requested."
      subject_template: "[%{email_prefix}] Login"
      subject_template_improved: "Login"
      text_body_template: |
        Somebody asked to log in to your account on [%{site_name}](%{base_url}).

        If you did not make this request, you can safely ignore this email.

        Click the following link to log in:
        %{base_url}/session/email-login/%{email_token}

'''
PINNED_DIGEST_LOGO_METHOD_BLOCK = b'''  def logo_url
    logo_url = SiteSetting.site_digest_logo_url
    logo_url = SiteSetting.site_logo_url if logo_url.blank? || logo_url =~ /\\.svg\\z/i
    return nil if logo_url.blank? || logo_url =~ /\\.svg\\z/i
    logo_url
  end

'''
PINNED_GRAVATAR_EVIDENCE = {
    "app/models/user.rb": (
        73523,
        "79c453b7bf56a69f7919572020ffa5fdf9b32de37255439d0a22c2b73f3ff7ca",
    ),
    "app/models/user_avatar.rb": (
        7189,
        "a53eb92ffe3793ef32c3f48f3e3216133916424a19a2ffea376b22e0b705a5a9",
    ),
    "app/jobs/regular/update_gravatar.rb": (
        539,
        "2757a35e7521b9b6d8a7cdf7d6cf5e5ebf1273132956533dcf3951b27bca397c",
    ),
}
PINNED_USER_GRAVATAR_SCHEDULE_BLOCK = b'''    if primary_email.present? && SiteSetting.automatically_download_gravatars? &&
         !avatar.last_gravatar_download_attempt
      Jobs.cancel_scheduled_job(:update_gravatar, user_id: id, avatar_id: avatar.id)
      Jobs.enqueue_in(1.second, :update_gravatar, user_id: id, avatar_id: avatar.id)
    end
'''


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        return None


OFFICIAL_OPENER = urllib.request.build_opener(NoRedirectHandler())


def validate_official_url(url: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.netloc != parsed.hostname
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RuntimeError("Official source URL is outside an exact HTTPS authority.")
    if parsed.hostname == "api.github.com":
        allowed_path = re.fullmatch(
            r"/repos/discourse/(?:discourse|discourse_docker|docker_manager)/(?:git/commits/[0-9a-f]{40}|git/tags/[0-9a-f]{40})",
            parsed.path,
        ) or re.fullmatch(
            r"/repos/acmesh-official/acme[.]sh/git/commits/[0-9a-f]{40}",
            parsed.path,
        ) or re.fullmatch(
            r"/repos/discourse/discourse_docker/(?:git/ref/heads/main|compare/[0-9a-f]{40}[.][.][.][0-9a-f]{40})",
            parsed.path,
        )
        if not allowed_path or parsed.query:
            raise RuntimeError("GitHub API URL is outside the exact source allowlist.")
    elif parsed.hostname == "raw.githubusercontent.com":
        decoded_path = urllib.parse.unquote(parsed.path, errors="strict")
        match = re.fullmatch(
            r"/discourse/(discourse|discourse_docker|docker_manager)/[0-9a-f]{40}/(.+)",
            decoded_path,
        ) or re.fullmatch(
            r"/acmesh-official/(acme[.]sh)/[0-9a-f]{40}/(.+)",
            decoded_path,
        )
        if (
            match is None
            or parsed.query
            or any(component in {"", ".", ".."} for component in match.group(2).split("/"))
        ):
            raise RuntimeError("Raw GitHub URL is outside the exact source allowlist.")
    elif parsed.hostname == "auth.docker.io":
        try:
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as error:
            raise RuntimeError("Registry authorization URL is malformed.") from error
        if parsed.path != "/token" or query != [
            ("service", "registry.docker.io"),
            ("scope", "repository:discourse/base:pull"),
        ]:
            raise RuntimeError("Registry authorization URL is outside the exact allowlist.")
    elif parsed.hostname == "registry-1.docker.io":
        if (
            not re.fullmatch(
                r"/v2/discourse/base/manifests/(?:[A-Za-z0-9_.-]{1,128}|sha256:[0-9a-f]{64})",
                parsed.path,
            )
            or parsed.query
        ):
            raise RuntimeError("Registry manifest URL is outside the exact allowlist.")
    else:
        raise RuntimeError("Official source URL hostname is not allowlisted.")
    return parsed


def request(url: str, *, headers: dict[str, str] | None = None, limit: int = 2 * 1024 * 1024) -> tuple[bytes, object]:
    parsed = validate_official_url(url)
    combined = {"User-Agent": "Mochirii-Forums-Pin-Verification/1", "Accept-Encoding": "identity"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and parsed.hostname == "api.github.com":
        combined["Authorization"] = f"Bearer {token}"
    if headers:
        combined.update(headers)
    error: Exception | None = None
    for attempt in range(3):
        try:
            with OFFICIAL_OPENER.open(urllib.request.Request(url, headers=combined), timeout=25) as response:
                if response.geturl() != url or response.status != 200:
                    raise RuntimeError("Official source response changed URL or status.")
                length = response.headers.get("Content-Length")
                if length and int(length) > limit:
                    raise RuntimeError(f"Remote response exceeds bound: {url}")
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise RuntimeError(f"Remote response exceeded bound: {url}")
                return body, response.headers
        except urllib.error.HTTPError as caught:
            if 300 <= caught.code < 400:
                raise RuntimeError("Official source redirect was blocked.") from None
            error = caught
            if attempt < 2:
                time.sleep(attempt + 1)
        except (OSError, urllib.error.URLError) as caught:
            error = caught
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError(f"Unable to verify official source URL: {url}") from error


def verified_file(repository: str, revision: str, entry: dict) -> bytes:
    path = urllib.parse.quote(entry["path"], safe="/")
    url = f"https://raw.githubusercontent.com/{repository}/{revision}/{path}"
    body, _ = request(url, limit=int(entry["bytes"]))
    if len(body) != entry["bytes"] or hashlib.sha256(body).hexdigest() != entry["sha256"]:
        raise RuntimeError(f"Official bytes changed: {repository}@{revision}:{entry['path']}")
    return body


def verify_commit(repository: str, revision: str, tree: str, verified: bool, reason: str) -> None:
    body, _ = request(f"https://api.github.com/repos/{repository}/git/commits/{revision}", limit=256 * 1024)
    document = json.loads(body)
    if (
        document.get("sha") != revision
        or document.get("tree", {}).get("sha") != tree
        or document.get("verification", {}).get("verified") is not verified
        or document.get("verification", {}).get("reason") != reason
    ):
        raise RuntimeError(f"Official commit identity changed: {repository}@{revision}")


def verify_current_main(provenance: dict) -> None:
    observation = provenance.get("driftObservation")
    expected_observation_keys = {
        "observedAt",
        "mainRevision",
        "mainTree",
        "mainCommitSignatureVerified",
        "mainCommitSignatureReason",
        "comparisonStatus",
        "commitsAheadOfPin",
        "commitsBehindPin",
        "totalCommits",
        "baseRevision",
        "mergeBaseRevision",
        "pinIsAncestor",
        "selectedForRuntime",
        "automaticPinUpdateAllowed",
        "changedPathInventoryComplete",
        "compatibilityReviewComplete",
        "reviewStatus",
        "changedPaths",
        "materialChangeScope",
        "rangeCommits",
    }
    if not isinstance(observation, dict) or set(observation) != expected_observation_keys:
        raise RuntimeError("Recorded deployment-source drift observation is malformed.")
    revision = observation.get("mainRevision")
    tree = observation.get("mainTree")
    pinned = provenance["upstream"]["revision"]
    if not isinstance(revision, str) or not isinstance(tree, str):
        raise RuntimeError("Recorded deployment-source main identity is malformed.")
    if not all(len(value) == 40 and value == value.lower() and all(character in "0123456789abcdef" for character in value) for value in (revision, tree)):
        raise RuntimeError("Recorded deployment-source main identity is malformed.")
    if (
        observation.get("observedAt") != "2026-08-20"
        or observation.get("comparisonStatus") != "ahead"
        or observation.get("baseRevision") != pinned
        or observation.get("mergeBaseRevision") != pinned
        or observation.get("pinIsAncestor") is not True
        or observation.get("selectedForRuntime") is not False
        or observation.get("automaticPinUpdateAllowed") is not False
        or observation.get("changedPathInventoryComplete") is not True
        or observation.get("compatibilityReviewComplete") is not False
        or observation.get("reviewStatus") != "drift-detected-separate-review-required"
    ):
        raise RuntimeError("Recorded deployment-source drift disposition changed.")
    counts = (
        observation.get("commitsAheadOfPin"),
        observation.get("commitsBehindPin"),
        observation.get("totalCommits"),
    )
    if any(type(value) is not int or value < 0 for value in counts) or counts != (11, 0, 11):
        raise RuntimeError("Recorded deployment-source comparison counts changed.")

    commits = observation.get("rangeCommits")
    material = observation.get("materialChangeScope")
    changed_paths = observation.get("changedPaths")
    if not isinstance(commits, list) or len(commits) != counts[2]:
        raise RuntimeError("Recorded deployment-source commit range is incomplete.")
    if not isinstance(material, list) or len(material) != len(commits):
        raise RuntimeError("Recorded deployment-source material-change scope is incomplete.")
    if (
        not isinstance(changed_paths, list)
        or changed_paths != sorted(changed_paths)
        or len(changed_paths) != len(set(changed_paths))
        or any(not isinstance(path, str) or not path or path.startswith(("/", ".")) or "\\" in path for path in changed_paths)
    ):
        raise RuntimeError("Recorded deployment-source changed-path inventory is malformed.")
    revisions: list[str] = []
    for entry in commits:
        if not isinstance(entry, dict) or set(entry) != {"revision", "tree", "signatureVerified", "signatureReason", "subject"}:
            raise RuntimeError("Recorded deployment-source range commit is malformed.")
        if type(entry["signatureVerified"]) is not bool or entry["signatureReason"] not in {"valid", "unsigned"}:
            raise RuntimeError("Recorded deployment-source range signature is malformed.")
        for key in ("revision", "tree"):
            value = entry.get(key)
            if not isinstance(value, str) or len(value) != 40 or value != value.lower() or any(character not in "0123456789abcdef" for character in value):
                raise RuntimeError("Recorded deployment-source range identity is malformed.")
        if not isinstance(entry.get("subject"), str) or not entry["subject"] or "\n" in entry["subject"]:
            raise RuntimeError("Recorded deployment-source range subject is malformed.")
        revisions.append(entry["revision"])
    if len(revisions) != len(set(revisions)) or revisions[-1] != revision:
        raise RuntimeError("Recorded deployment-source range order is malformed.")
    material_revisions: list[str] = []
    for entry in material:
        if not isinstance(entry, dict) or set(entry) != {"revision", "classification", "selectedForRuntime"}:
            raise RuntimeError("Recorded deployment-source material-change entry is malformed.")
        if entry.get("selectedForRuntime") is not False:
            raise RuntimeError("Observed upstream drift was selected without a compatibility change.")
        classification = entry.get("classification")
        if not isinstance(classification, str) or not classification or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in classification):
            raise RuntimeError("Recorded deployment-source material classification is malformed.")
        material_revisions.append(entry.get("revision"))
    if material_revisions != revisions:
        raise RuntimeError("Recorded deployment-source material scope does not bind the exact range.")

    ref_body, ref_headers = request(
        f"https://api.github.com/repos/{DOCKER_REPOSITORY}/git/ref/heads/main",
        limit=256 * 1024,
    )
    try:
        ref = json.loads(ref_body)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Official deployment-source main reference is malformed.") from error
    if not isinstance(ref, dict):
        raise RuntimeError("Official deployment-source main reference is ambiguous.")
    ref_object = ref.get("object")
    if (
        ref.get("ref") != "refs/heads/main"
        or not isinstance(ref_object, dict)
        or ref_object.get("type") != "commit"
        or ref_object.get("sha") != revision
        or ref_headers.get("Link") is not None
    ):
        raise RuntimeError("Official deployment-source main moved or returned an ambiguous reference.")

    verify_commit(
        DOCKER_REPOSITORY,
        revision,
        tree,
        observation["mainCommitSignatureVerified"],
        observation["mainCommitSignatureReason"],
    )
    compare_body, compare_headers = request(
        f"https://api.github.com/repos/{DOCKER_REPOSITORY}/compare/{pinned}...{revision}",
        limit=2 * 1024 * 1024,
    )
    try:
        comparison = json.loads(compare_body)
    except (TypeError, ValueError) as error:
        raise RuntimeError("Official deployment-source comparison is malformed.") from error
    if not isinstance(comparison, dict) or compare_headers.get("Link") is not None:
        raise RuntimeError("Official deployment-source comparison is ambiguous or paginated.")
    if (
        comparison.get("status") != observation["comparisonStatus"]
        or comparison.get("ahead_by") != counts[0]
        or comparison.get("behind_by") != counts[1]
        or comparison.get("total_commits") != counts[2]
        or comparison.get("base_commit", {}).get("sha") != observation["baseRevision"]
        or comparison.get("merge_base_commit", {}).get("sha") != observation["mergeBaseRevision"]
    ):
        raise RuntimeError("Official deployment-source comparison moved after review.")
    actual_commits = comparison.get("commits")
    if not isinstance(actual_commits, list) or len(actual_commits) != len(commits):
        raise RuntimeError("Official deployment-source comparison range is incomplete.")
    for expected, actual in zip(commits, actual_commits, strict=True):
        actual_document = actual if isinstance(actual, dict) else {}
        commit = actual_document.get("commit", {})
        verification = commit.get("verification", {}) if isinstance(commit, dict) else {}
        message = commit.get("message") if isinstance(commit, dict) else None
        subject = message.splitlines()[0] if isinstance(message, str) and message else None
        if (
            actual_document.get("sha") != expected["revision"]
            or commit.get("tree", {}).get("sha") != expected["tree"]
            or verification.get("verified") is not expected["signatureVerified"]
            or verification.get("reason") != expected["signatureReason"]
            or subject != expected["subject"]
        ):
            raise RuntimeError("Official deployment-source comparison commit changed after review.")
    actual_paths = [entry.get("filename") for entry in comparison.get("files", []) if isinstance(entry, dict)]
    if actual_paths != changed_paths:
        raise RuntimeError("Official deployment-source changed-path inventory moved after review.")


def verify_registry(provenance: dict) -> None:
    token_body, _ = request(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:discourse/base:pull",
        limit=64 * 1024,
    )
    token = json.loads(token_body).get("token")
    if not token:
        raise RuntimeError("Registry did not issue a bounded pull token.")
    accept = ", ".join(
        (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
    )
    tag = provenance["baseImage"]["tag"].split(":", 1)[1]
    body, headers = request(
        f"https://registry-1.docker.io/v2/discourse/base/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": accept},
        limit=4 * 1024 * 1024,
    )
    if headers.get("Docker-Content-Digest") != provenance["baseImage"]["registryIndexDigestObservedAtReview"]:
        raise RuntimeError("Mutable base tag no longer resolves to the reviewed index digest.")
    index = json.loads(body)
    matches = [
        item
        for item in index.get("manifests", [])
        if item.get("platform", {}).get("os") == "linux" and item.get("platform", {}).get("architecture") == "amd64"
    ]
    expected = provenance["baseImage"]["linuxAmd64Digest"]
    if len(matches) != 1 or matches[0].get("digest") != expected:
        raise RuntimeError("Base index does not bind exactly one reviewed Linux AMD64 manifest.")
    _, manifest_headers = request(
        f"https://registry-1.docker.io/v2/discourse/base/manifests/{expected}",
        headers={"Authorization": f"Bearer {token}", "Accept": accept},
        limit=4 * 1024 * 1024,
    )
    if manifest_headers.get("Docker-Content-Digest") != expected:
        raise RuntimeError("Linux AMD64 base manifest digest changed.")


def require(source: dict[str, bytes], path: str, snippets: tuple[bytes, ...]) -> None:
    body = source[path]
    for snippet in snippets:
        if snippet not in body:
            raise RuntimeError(f"Pinned semantic contract changed: {path}: {snippet!r}")


def verify_exact_region(source: bytes, start: bytes, end: bytes, expected: bytes, label: str) -> None:
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError(f"The pinned {label} boundary changed.")
    start_offset = source.index(start)
    end_offset = source.find(end, start_offset + len(start))
    if end_offset < 0 or source[start_offset:end_offset] != expected:
        raise RuntimeError(f"The pinned {label} changed.")


def verify_mail_evidence_manifest(components: dict) -> None:
    entries = components.get("application", {}).get("semanticEvidenceFiles")
    if not isinstance(entries, list):
        raise RuntimeError("Pinned mail semantic evidence inventory is absent.")
    for path, (expected_bytes, expected_sha256) in PINNED_MAIL_SEMANTIC_EVIDENCE.items():
        matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == path]
        if len(matches) != 1:
            raise RuntimeError(f"Pinned mail semantic evidence is not unique: {path}")
        entry = matches[0]
        if (
            set(entry) != {"path", "bytes", "sha256"}
            or type(entry["bytes"]) is not int
            or entry["bytes"] != expected_bytes
            or not isinstance(entry["sha256"], str)
            or entry["sha256"] != expected_sha256
        ):
            raise RuntimeError(f"Pinned mail semantic evidence changed: {path}")


def verify_topic_seed_evidence_manifest(components: dict) -> None:
    entries = components.get("application", {}).get("semanticEvidenceFiles")
    if not isinstance(entries, list):
        raise RuntimeError("Pinned topic-seed semantic evidence inventory is absent.")
    for path, (expected_bytes, expected_sha256) in PINNED_TOPIC_SEED_EVIDENCE.items():
        matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == path]
        if len(matches) != 1:
            raise RuntimeError(f"Pinned topic-seed semantic evidence is not unique: {path}")
        entry = matches[0]
        if (
            set(entry) != {"path", "bytes", "sha256"}
            or type(entry["bytes"]) is not int
            or entry["bytes"] != expected_bytes
            or not isinstance(entry["sha256"], str)
            or entry["sha256"] != expected_sha256
        ):
            raise RuntimeError(f"Pinned topic-seed semantic evidence changed: {path}")


def verify_opensearch_evidence_manifest(components: dict) -> None:
    entries = components.get("application", {}).get("semanticEvidenceFiles")
    if not isinstance(entries, list):
        raise RuntimeError("Pinned OpenSearch semantic evidence inventory is absent.")
    for path, (expected_bytes, expected_sha256) in PINNED_OPENSEARCH_EVIDENCE.items():
        matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == path]
        if len(matches) != 1:
            raise RuntimeError(f"Pinned OpenSearch semantic evidence is not unique: {path}")
        entry = matches[0]
        if (
            set(entry) != {"path", "bytes", "sha256"}
            or type(entry["bytes"]) is not int
            or entry["bytes"] != expected_bytes
            or not isinstance(entry["sha256"], str)
            or entry["sha256"] != expected_sha256
        ):
            raise RuntimeError(f"Pinned OpenSearch semantic evidence changed: {path}")


def verify_opensearch_controller_method(source: bytes) -> None:
    verify_exact_region(
        source,
        b"  def opensearch\n",
        b"  def app_association_android\n",
        PINNED_OPENSEARCH_CONTROLLER_BLOCK,
        "OpenSearch controller method",
    )


def verify_login_code_denial_semantics(source: bytes) -> None:
    if source.count(PINNED_LOGIN_CODE_DENIAL_METHOD) != 1:
        raise RuntimeError("Pinned local email-code denial semantics changed.")


def verify_opensearch_semantics(core: dict[str, bytes]) -> None:
    for path, (expected_bytes, expected_sha256) in PINNED_OPENSEARCH_EVIDENCE.items():
        source = core.get(path)
        if source is None:
            raise RuntimeError(f"Pinned OpenSearch semantic source is absent: {path}")
        if len(source) != expected_bytes or hashlib.sha256(source).hexdigest() != expected_sha256:
            raise RuntimeError(f"Pinned OpenSearch semantic source changed: {path}")
    verify_opensearch_controller_method(core["app/controllers/metadata_controller.rb"])
    require(
        core,
        "app/views/metadata/opensearch.xml.erb",
        (b"<Tags>discourse forum</Tags>",),
    )


def verify_email_extract_parts_method(source: bytes) -> None:
    start = b"  def self.extract_parts(raw)\n"
    end = b"  def self.site_title\n"
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError("The pinned email extraction method boundary changed.")
    block = source[source.index(start) : source.index(end)]
    if block != PINNED_EMAIL_EXTRACT_PARTS_BLOCK:
        raise RuntimeError("The pinned email extraction method changed.")
    if b"extract_body" in source:
        raise RuntimeError("The pinned email body extraction API changed.")


def verify_email_semantics(source: bytes) -> None:
    if len(source) != PINNED_EMAIL_BYTES or hashlib.sha256(source).hexdigest() != PINNED_EMAIL_SHA256:
        raise RuntimeError("The pinned email source bytes changed.")
    verify_email_extract_parts_method(source)


def verify_mail_semantics(core: dict[str, bytes]) -> None:
    for path, (expected_bytes, expected_sha256) in PINNED_MAIL_SEMANTIC_EVIDENCE.items():
        source = core.get(path)
        if source is None:
            raise RuntimeError(f"Pinned mail semantic source is absent: {path}")
        if len(source) != expected_bytes or hashlib.sha256(source).hexdigest() != expected_sha256:
            raise RuntimeError(f"Pinned mail semantic source changed: {path}")

    notifications = core["app/mailers/user_notifications.rb"]
    verify_exact_region(
        notifications,
        b"  def digest(user, opts = {})\n",
        b"  def user_replied(user, opts)\n",
        PINNED_USER_NOTIFICATIONS_DIGEST_BLOCK,
        "digest mail-production method",
    )
    verify_exact_region(
        core["app/models/topic.rb"],
        b"  def self.for_digest(user, since, opts = nil)\n",
        b"  def reload(options = nil)\n",
        PINNED_TOPIC_FOR_DIGEST_BLOCK,
        "digest topic-selection method",
    )
    verify_exact_region(
        notifications,
        b"  def admin_login(user, opts = {})\n",
        b"  def account_created(user, opts = {})\n",
        PINNED_ADMIN_LOGIN_METHOD_BLOCK,
        "administrator-login mailer method",
    )
    verify_exact_region(
        notifications,
        b"  def build_user_email_token_by_template(template, user, email_token)\n",
        b"  def build_summary_for(user)\n",
        PINNED_EMAIL_LOGIN_HELPER_BLOCK,
        "email-token template helper",
    )

    if core["app/mailers/admin_confirmation_mailer.rb"] != PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE:
        raise RuntimeError("The pinned administrator-confirmation mailer changed.")
    verify_exact_region(
        core["lib/admin_confirmation.rb"],
        b"  def create_confirmation\n",
        b"  def email_confirmed!\n",
        PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK,
        "administrator-confirmation token generator",
    )
    if core["config/routes.rb"].count(PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK) != 1:
        raise RuntimeError("The pinned administrator-confirmation route constraint changed.")

    message_builder = core["lib/email/message_builder.rb"]
    verify_exact_region(
        message_builder,
        b"    def initialize(to, opts = nil)\n",
        b"      if @opts[:recipient_user].present?\n",
        PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX,
        "message-builder template arguments",
    )
    verify_exact_region(
        message_builder,
        b"    def body\n",
        b"    def build_args\n",
        PINNED_MESSAGE_BUILDER_BODY_BLOCK,
        "message-builder template interpolation",
    )
    if message_builder.count(PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX) != 1:
        raise RuntimeError("The pinned message-builder optional HTML boundary changed.")
    if core["lib/email/build_email_helper.rb"] != PINNED_BUILD_EMAIL_HELPER_SOURCE:
        raise RuntimeError("The pinned build-email helper changed.")

    verify_exact_region(
        core["lib/discourse.rb"],
        b"  def self.base_protocol\n",
        b"  def self.current_hostname_with_port\n",
        PINNED_BASE_PROTOCOL_BLOCK,
        "force-HTTPS base protocol",
    )
    verify_exact_region(
        core["config/locales/server.en.yml"],
        b"    admin_login:\n",
        b"    account_created:\n",
        PINNED_ADMIN_LOGIN_LOCALE_BLOCK,
        "administrator-login locale template",
    )

    helper = core["app/helpers/user_notifications_helper.rb"]
    if b"SiteSetting.digest_logo_url" in helper:
        raise RuntimeError("The stale digest-logo site setting returned.")
    verify_exact_region(
        helper,
        b"  def logo_url\n",
        b"  def html_site_link\n",
        PINNED_DIGEST_LOGO_METHOD_BLOCK,
        "digest-logo helper method",
    )


def verify_topic_seed_semantics(core: dict[str, bytes]) -> None:
    for path, (expected_bytes, expected_sha256) in PINNED_TOPIC_SEED_EVIDENCE.items():
        source = core.get(path)
        if source is None:
            raise RuntimeError(f"Pinned topic-seed semantic source is absent: {path}")
        if len(source) != expected_bytes or hashlib.sha256(source).hexdigest() != expected_sha256:
            raise RuntimeError(f"Pinned topic-seed semantic source changed: {path}")

    if core["db/fixtures/990_topics.rb"] != PINNED_TOPIC_FIXTURE_SOURCE:
        raise RuntimeError("The pinned topic fixture invocation changed.")
    topics = core["lib/seed_data/topics.rb"]
    for block, label in (
        (PINNED_ADMIN_QUICK_START_TOPIC_BLOCK, "administrator quick-start topic seed"),
        (PINNED_TOPIC_CREATE_GUARD_BLOCK, "one-time topic creation guard"),
        (PINNED_ADMIN_QUICK_START_RAW_BLOCK, "administrator quick-start source loader"),
    ):
        if topics.count(block) != 1:
            raise RuntimeError(f"The pinned {label} changed.")

    guide = core["docs/ADMIN-QUICK-START-GUIDE.md"]
    if (
        guide.count(b"%{base_url}") != 7
        or guide.count(b"Discourse") != 7
        or guide.count(b"discourse.org") != 3
        or not guide.startswith(b"*Welcome to your new community, and thank you for choosing Discourse!*\n")
        or b"https://github.com/discourse/discourse/blob/main/docs/INSTALL-email.md" not in guide
    ):
        raise RuntimeError("The pinned administrator quick-start guide semantics changed.")


def verify_gravatar_semantics(core: dict[str, bytes]) -> None:
    for path, (expected_bytes, expected_sha256) in PINNED_GRAVATAR_EVIDENCE.items():
        source = core[path]
        if len(source) != expected_bytes or hashlib.sha256(source).hexdigest() != expected_sha256:
            raise RuntimeError(f"Pinned Gravatar lifecycle source changed: {path}")

    user = core["app/models/user.rb"]
    if (
        user.count(b"  after_save :refresh_avatar\n") != 1
        or user.count(PINNED_USER_GRAVATAR_SCHEDULE_BLOCK) != 1
    ):
        raise RuntimeError("Pinned user Gravatar scheduling semantics changed.")

    avatar = core["app/models/user_avatar.rb"]
    require(
        core,
        "app/models/user_avatar.rb",
        (
            b'Discourse::SYSTEM_USER_ID => User.email_hash("info@discourse.org")',
            b'DistributedMutex.synchronize("update_gravatar_#{user_id}")',
            b'"https://#{SiteSetting.gravatar_base_url}/avatar/#{email_hash}.png?s=#{max}&d=404&reset_cache=',
            b"update!(gravatar_upload: upload)",
        ),
    )
    if avatar.count(b"update!(gravatar_upload: upload)") != 1:
        raise RuntimeError("Pinned Gravatar upload mutation is ambiguous.")

    job = core["app/jobs/regular/update_gravatar.rb"]
    if (
        job.count(b'sidekiq_options queue: "low"') != 1
        or job.count(b"avatar.update_gravatar!") != 1
    ):
        raise RuntimeError("Pinned delayed Gravatar job semantics changed.")

    settings = core["config/site_settings.yml"]
    if settings.count(b"  automatically_download_gravatars: true\n") != 1:
        raise RuntimeError("Pinned automatic Gravatar default changed.")


def verify_semantics(docker: dict[str, bytes], core: dict[str, bytes]) -> None:
    require(
        docker,
        "templates/web.template.yml",
        (
            b"bundle install --jobs $(nproc --ignore=1) --retry 3",
            b"grep -q 'outlets/discourse' /etc/nginx/conf.d/discourse.conf",
            b"path: /usr/local/bin/rails",
            b'(cd /var/www/discourse && RAILS_ENV=production sudo -H -E -u discourse bundle exec script/rails "$@")',
            b"path: /usr/local/bin/discourse",
            b'(cd /var/www/discourse && RAILS_ENV=production sudo -H -E -u discourse bundle exec script/discourse "$@")',
        ),
    )
    if b"bundle install --jobs $(($(nproc) - 1)) --retry 3" in docker["templates/web.template.yml"]:
        raise RuntimeError("The one-core zero-job command returned.")
    require(
        docker,
        "launcher",
        (
            b"base_image=`cat $config_file",
            b"image=$base_image",
            b"pull_image",
            b"YAML.load(STDIN.readlines.join)['base_image']",
        ),
    )
    require(core, "app/models/translation_override.rb", (b"def self.upsert!(locale, key, value)",))
    require(
        core,
        "lib/tasks/themes.rake",
        (b'task "themes:install:archive" => :environment', b'filename = ENV["THEME_ARCHIVE"]', b"RemoteTheme.update_zipped_theme"),
    )
    require(
        core,
        "app/models/remote_theme.rb",
        (b'def self.update_zipped_theme(', b'theme_info["assets"]&.each', b"theme_id:"),
    )
    require(core, "app/models/theme.rb", (b"has_many :upload_fields", b"def set_default!"))
    require(core, "config/nginx.sample.conf", (b"include conf.d/outlets/discourse/*.conf;",))
    require(
        core,
        "app/views/layouts/_head.html.erb",
        (b'<meta name="generator" content="Discourse <%= Discourse::VERSION::STRING %> - https://github.com/discourse/discourse version <%= Discourse.git_version %>">',),
    )
    verify_opensearch_semantics(core)
    verify_email_semantics(core["lib/email.rb"])
    verify_mail_semantics(core)
    verify_topic_seed_semantics(core)
    verify_gravatar_semantics(core)
    require(
        core,
        "lib/file_store/s3_store.rb",
        (b'list_missing(Upload.by_users, "original/")', b'list_missing(OptimizedImage, "optimized/")', b"presigned_get_url"),
    )
    require(core, "lib/s3_helper.rb", (b"return if !SiteSetting.s3_configure_tombstone_policy",))
    require(
        core,
        "config/routes.rb",
        (
            b'get "session/email-login/:token" => "session#email_login_info"',
            b'post "session/email-login/:token" => "session#email_login"',
            b'get "#{root_path}/admin-login" => "users#admin_login"',
            b'put "#{root_path}/admin-login" => "users#admin_login"',
        ),
    )
    require(
        core,
        "app/controllers/users_controller.rb",
        (
            b"def admin_login",
            b"User.real.admins.with_email(params[:email]).first",
            b"scope: EmailToken.scopes[:email_login]",
            b"Jobs.enqueue(:critical_user_email, type: \"admin_login\"",
        ),
    )
    session_controller = core["app/controllers/session_controller.rb"]
    verify_login_code_denial_semantics(session_controller)
    require(
        core,
        "app/controllers/session_controller.rb",
        (
            b"before_action :ensure_login_code_allowed, only: %i[create_login_code verify_login_code]",
            b"def email_login_info",
            b"def email_login",
            b"check_local_login_allowed(user: user, check_login_via_email: true)",
            b"# admin-login can get around enabled SSO/disabled local logins",
            b"return if user&.admin?",
        ),
    )
    region = core["app/models/s3_region_site_setting.rb"]
    if b"whatever" in region or b"def self.valid_value?" not in region:
        raise RuntimeError("The pinned region enum no longer requires environment-only compatibility override.")
    settings = core["config/site_settings.yml"]
    for setting in (
        b"login_required:",
        b"allow_new_registrations:",
        b"discourse_connect_csrf_protection:",
        b"verbose_discourse_connect_logging:",
        b"secure_uploads:",
        b"enable_direct_s3_uploads:",
        b"s3_configure_tombstone_policy:",
        b"include_s3_uploads_in_backups:",
        b"allow_staff_to_upload_any_file_in_pm:",
        b"allow_all_attachments_for_group_messages:",
    ):
        if setting not in settings:
            raise RuntimeError(f"Pinned site setting disappeared: {setting!r}")
    plugin_settings = {
        "plugins/discourse-apple-auth/config/settings.yml": b"sign_in_with_apple_enabled:",
        "plugins/discourse-login-with-amazon/config/settings.yml": b"enable_login_with_amazon:",
        "plugins/discourse-microsoft-auth/config/settings.yml": b"microsoft_auth_enabled:",
        "plugins/discourse-oauth2-basic/config/settings.yml": b"oauth2_enabled:",
        "plugins/discourse-openid-connect/config/settings.yml": b"openid_connect_enabled:",
    }
    for path, setting in plugin_settings.items():
        require(core, path, (setting, b"default: false"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--require-current-main", action="store_true")
    args = parser.parse_args()

    if args.require_current_main and not args.online:
        parser.error("--require-current-main requires --online")

    provenance = load("docs/operations/upstream-provenance.v1.json")
    components = load("docs/operations/third-party-components.v1.json")
    identity = load("docs/operations/forum-central-identity.consumer.v1.json")
    verify_mail_evidence_manifest(components)
    verify_topic_seed_evidence_manifest(components)
    verify_opensearch_evidence_manifest(components)
    if not args.online:
        print("Pinned-source manifest structure passed; online bytes were not requested.")
        return 0

    docker_revision = provenance["upstream"]["revision"]
    core_revision = components["application"]["revision"]
    manager = components["defaultStandaloneComponent"]
    vendored = components["vendoredRuntimeComponents"]
    if not isinstance(vendored, list) or len(vendored) != 1 or not isinstance(vendored[0], dict):
        raise RuntimeError("Vendored runtime component inventory differs.")
    acme = vendored[0]
    docker_source = {
        entry["path"]: verified_file(DOCKER_REPOSITORY, docker_revision, entry)
        for entry in provenance["files"]
    }
    core_entries: dict[str, dict] = {}
    for group in (components["application"]["evidenceFiles"], components["application"]["semanticEvidenceFiles"], identity["pinnedConsumerEvidence"]["evidenceFiles"]):
        for entry in group:
            core_entries[entry["path"]] = entry
    core_source = {
        path: verified_file(CORE_REPOSITORY, core_revision, entry)
        for path, entry in sorted(core_entries.items())
    }
    for entry in manager["evidenceFiles"]:
        verified_file(MANAGER_REPOSITORY, manager["revision"], entry)
    acme_source = verified_file(ACME_REPOSITORY, acme["revision"], acme["source"])
    acme_license = verified_file(
        ACME_REPOSITORY,
        acme["revision"],
        {
            "path": acme["license"]["upstreamPath"],
            "bytes": acme["license"]["bytes"],
            "sha256": acme["license"]["sha256"],
        },
    )
    encoded_text = (ROOT / acme["encodedSource"]["path"]).read_text(encoding="ascii")
    encoded_lines = encoded_text.splitlines()
    if (
        not encoded_text.endswith("\n")
        or not encoded_lines
        or any(not 1 <= len(line) <= 76 for line in encoded_lines)
        or any(len(line) != 76 for line in encoded_lines[:-1])
        or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded_lines[-1])
        or any(not re.fullmatch(r"[A-Za-z0-9+/]{76}", line) for line in encoded_lines[:-1])
    ):
        raise RuntimeError("Vendored immutable ACME encoding is malformed.")
    encoded = base64.b64decode("".join(encoded_lines), validate=True)
    if (
        len(encoded) != acme["encodedSource"]["compressedBytes"]
        or hashlib.sha256(encoded).hexdigest() != acme["encodedSource"]["compressedSha256"]
        or gzip.decompress(encoded) != acme_source
        or (ROOT / acme["license"]["repositoryPath"]).read_bytes() != acme_license
    ):
        raise RuntimeError("Vendored immutable ACME bytes differ from exact upstream evidence.")

    verify_commit(
        DOCKER_REPOSITORY,
        docker_revision,
        provenance["upstream"]["revisionTree"],
        provenance["upstream"]["revisionCommitSignatureVerified"],
        provenance["upstream"]["revisionCommitSignatureReason"],
    )
    verify_commit(CORE_REPOSITORY, core_revision, components["application"]["revisionTree"], False, "unsigned")
    verify_commit(
        MANAGER_REPOSITORY,
        manager["revision"],
        manager["revisionTree"],
        manager["revisionCommitSignatureVerified"],
        manager["revisionCommitSignatureReason"],
    )
    verify_commit(
        ACME_REPOSITORY,
        acme["revision"],
        acme["revisionTree"],
        acme["revisionCommitSignatureVerified"],
        acme["revisionCommitSignatureReason"],
    )
    tag_body, _ = request(
        f"https://api.github.com/repos/{CORE_REPOSITORY}/git/tags/{components['application']['tagObjectSha1']}",
        limit=256 * 1024,
    )
    tag = json.loads(tag_body)
    if tag.get("tag") != components["application"]["release"] or tag.get("object", {}).get("sha") != core_revision:
        raise RuntimeError("Discourse annotated release tag changed.")

    verify_semantics(docker_source, core_source)
    verify_registry(provenance)
    if args.require_current_main:
        verify_current_main(provenance)
        print("Recorded official deployment-source main observation is still exact.")
    print("Exact upstream bytes, APIs, revisions, and base-image digests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
