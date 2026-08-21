# frozen_string_literal: true

# Deterministic source-only hostile fixture for the administrator recovery-mail
# link boundary. It evaluates the repository's exact production helper with only
# Ruby's URI implementation; no Mail gem, Rails application, database, network,
# or provider is used.

require "uri"

RENDERER = File.expand_path("render-branding-email.rb", __dir__)

class AdminLoginLinkFixtureError < StandardError
end

module Mail
  class Message
  end
end

class LazyMailMessageFixture
  attr_reader :message

  def initialize(message)
    @message = message
  end
end

class PermissiveNullMailFixture
  def respond_to?(_name, _include_all = false)
    true
  end

  def method_missing(...)
    nil
  end
end

def assert_fixture(condition, message)
  raise AdminLoginLinkFixtureError, message unless condition
end

def admin_login_text(base_url, recovery_link)
  <<~TEXT
    Somebody asked to log in to your account on [Mochirii Forums](#{base_url}).

    If you did not make this request, you can safely ignore this email.

    Click the following link to log in:
    #{recovery_link}
  TEXT
end

def expect_rejection(
  label,
  text_part:,
  html_part: nil,
  expected_base_url:,
  allow_fixture_http:,
  expected_message:,
  sensitive_fragments:
)
  begin
    verify_admin_login_link!(
      text_part: text_part,
      html_part: html_part,
      expected_base_url: expected_base_url,
      allow_fixture_http: allow_fixture_http,
    )
  rescue StandardError => error
    assert_fixture(error.instance_of?(RuntimeError), "#{label} raised a non-fixed error class")
    assert_fixture(error.message == expected_message, "#{label} raised a different fixed error")
    assert_fixture(error.cause.nil?, "#{label} retained an exception cause")
    disclosed = [error.message, error.full_message].join("\n")
    assert_fixture(
      sensitive_fragments.none? { |fragment| disclosed.include?(fragment) },
      "#{label} disclosed its URL or token",
    )
    return
  end

  raise AdminLoginLinkFixtureError, "#{label} was accepted"
end

source = File.binread(RENDERER)
materialize_marker = "def materialize(delivery, label:)\n"
materialize_boundary = "\n\ndef render_parts(mail)\n"
assert_fixture(source.scan(materialize_marker).length == 1, "mail materializer helper count differed")
assert_fixture(source.scan(materialize_boundary).length == 1, "mail materializer helper boundary differed")
materialize_start = source.index(materialize_marker)
materialize_finish = source.index(materialize_boundary, materialize_start)
assert_fixture(materialize_finish && materialize_finish > materialize_start, "mail materializer helper was absent")
materialize_source = source.byteslice(materialize_start, materialize_finish - materialize_start)
eval(materialize_source, TOPLEVEL_BINDING, RENDERER, source.byteslice(0, materialize_start).count("\n") + 1)

direct_mail = Mail::Message.new
assert_fixture(
  materialize(direct_mail, label: "direct").equal?(direct_mail),
  "direct Mail::Message was not preserved",
)
lazy_mail = Mail::Message.new
lazy_delivery = LazyMailMessageFixture.new(lazy_mail)
assert_fixture(
  materialize(lazy_delivery, label: "lazy").equal?(lazy_mail),
  "lazy Mail::Message was not materialized",
)

begin
  materialize(PermissiveNullMailFixture.new, label: "digest")
rescue StandardError => error
  assert_fixture(error.instance_of?(RuntimeError), "NullMail canary raised a non-fixed error class")
  assert_fixture(
    error.message == "digest mail path did not render a Mail::Message",
    "NullMail canary raised a different fixed error",
  )
  assert_fixture(error.cause.nil?, "NullMail canary retained an exception cause")
else
  raise AdminLoginLinkFixtureError, "permissive NullMail canary was accepted"
end

method_marker = "def allow_fixture_admin_login_http?(stage4_fixture:, connect_fixture:, expected_address:)\n"
call_boundary = "\n\nbot = User.find_by(id: -2)\n"
assert_fixture(source.scan(method_marker).length == 1, "administrator login policy helper count differed")
assert_fixture(
  source.scan("def verify_admin_login_link!(text_part:, html_part:, expected_base_url:, allow_fixture_http:)\n").length == 1,
  "administrator login URI helper count differed",
)
assert_fixture(source.scan(call_boundary).length == 1, "administrator login helper boundary differed")
method_start = source.index(method_marker)
method_finish = source.index(call_boundary, method_start)
assert_fixture(method_finish && method_finish > method_start, "administrator login helper was absent")
method_source = source.byteslice(method_start, method_finish - method_start)
eval(method_source, TOPLEVEL_BINDING, RENDERER, source.byteslice(0, method_start).count("\n") + 1)

assert_fixture(
  source.scan("SiteSetting.site_digest_logo_url").length == 1,
  "pinned digest-logo accessor count differed",
)
assert_fixture(
  source.scan("SiteSetting.digest_logo_url").empty?,
  "stale digest-logo accessor remains",
)

admin_confirmation_fixture_token = "0123456789abcdef" * 2
assert_fixture(
  source.scan('admin_confirmation_fixture_token = "0123456789abcdef" * 2').length == 1,
  "administrator confirmation fixture token assignment differed",
)
assert_fixture(
  source.scan("unless admin_confirmation_fixture_token.match?(/\\A[0-9a-f]+\\z/) && admin_confirmation_fixture_token.length == 32\n").length == 1,
  "administrator confirmation fixture token guard differed",
)
assert_fixture(
  source.scan("      admin_confirmation_fixture_token,\n").length == 1,
  "administrator confirmation mailer token argument differed",
)
assert_fixture(source.scan("SecureRandom").empty?, "renderer generated a real administrator confirmation token")
admin_confirmation_route_token = /\A[0-9a-f]+\z/
assert_fixture(
  admin_confirmation_fixture_token.match?(admin_confirmation_route_token) &&
    admin_confirmation_fixture_token.length == 32,
  "administrator confirmation fixture token was not pinned-route compatible",
)
assert_fixture("0".match?(admin_confirmation_route_token), "one-character pinned-route token was rejected")
assert_fixture(("0" * 33).match?(admin_confirmation_route_token), "long pinned-route token was rejected")
{
  "empty administrator confirmation token" => "",
  "uppercase administrator confirmation token" => "0123456789ABCDEF0123456789ABCDEF",
  "hyphenated administrator confirmation token" => "0123456789abcdef-0123456789abcde",
  "nonhex administrator confirmation token" => "0123456789abcdef0123456789abcdeg",
  "short administrator confirmation token" => "0" * 31,
  "long administrator confirmation token" => "0" * 33,
  "slash administrator confirmation token" => "0" * 16 + "/" + "0" * 15,
  "encoded-separator administrator confirmation token" => "0" * 15 + "%2F" + "0" * 14,
  "newline administrator confirmation token" => "0" * 15 + "\n" + "0" * 16,
}.each do |label, token|
  assert_fixture(
    !token.match?(admin_confirmation_route_token) || token.length != 32,
    "#{label} was accepted",
  )
end

fixture_base = "http://forums.mochirii.com"
production_base = "https://forums.mochirii.com"
fixture_link = "http://forums.mochirii.com/session/email-login/mochirii-fixture-admin-login-token"
production_link = "https://forums.mochirii.com/session/email-login/mochirii-fixture-admin-login-token"
fixture_text = admin_login_text(fixture_base, fixture_link)
production_text = admin_login_text(production_base, production_link)

assert_fixture(
  allow_fixture_admin_login_http?(
    stage4_fixture: "true",
    connect_fixture: "true",
    expected_address: "notifications@fixture.invalid",
  ),
  "exact fixture HTTP authorization was rejected",
)
[
  ["false", "true", "notifications@fixture.invalid"],
  [nil, "true", "notifications@fixture.invalid"],
  ["true", "false", "notifications@fixture.invalid"],
  ["true", nil, "notifications@fixture.invalid"],
  ["true", "true", "notifications@foreign.invalid"],
].each do |stage4_fixture, connect_fixture, address|
  assert_fixture(
    !allow_fixture_admin_login_http?(
      stage4_fixture: stage4_fixture,
      connect_fixture: connect_fixture,
      expected_address: address,
    ),
    "partial fixture HTTP authorization was accepted",
  )
end

assert_fixture(
  verify_admin_login_link!(
    text_part: fixture_text,
    html_part: nil,
    expected_base_url: fixture_base,
    allow_fixture_http: true,
  ).nil?,
  "exact fixture HTTP mail was rejected",
)
assert_fixture(
  verify_admin_login_link!(
    text_part: production_text,
    html_part: nil,
    expected_base_url: production_base,
    allow_fixture_http: false,
  ).nil?,
  "exact production HTTPS mail was rejected",
)
assert_fixture(
  verify_admin_login_link!(
    text_part: production_text.gsub("\n", "\r\n"),
    html_part: nil,
    expected_base_url: production_base,
    allow_fixture_http: false,
  ).nil?,
  "transport CRLF normalization changed the exact mail",
)

origin_error = "Administrator recovery mail link escaped the exact Forums origin"
omitted_error = "Administrator recovery mail omitted its one-time login link"
malformed_error = "Administrator recovery mail link is malformed"

expect_rejection(
  "production HTTP mode",
  text_part: fixture_text,
  expected_base_url: fixture_base,
  allow_fixture_http: false,
  expected_message: origin_error,
  sensitive_fragments: [fixture_link, "mochirii-fixture-admin-login-token"],
)
expect_rejection(
  "fixture HTTPS mode",
  text_part: production_text,
  expected_base_url: production_base,
  allow_fixture_http: true,
  expected_message: origin_error,
  sensitive_fragments: [production_link, "mochirii-fixture-admin-login-token"],
)
expect_rejection(
  "missing recovery link",
  text_part: production_text.sub(production_link, ""),
  expected_base_url: production_base,
  allow_fixture_http: false,
  expected_message: omitted_error,
  sensitive_fragments: ["mochirii-fixture-admin-login-token"],
)
expect_rejection(
  "malformed expected origin",
  text_part: production_text,
  expected_base_url: "https://[forums.mochirii.com",
  allow_fixture_http: false,
  expected_message: malformed_error,
  sensitive_fragments: [production_link, "mochirii-fixture-admin-login-token"],
)

hostile_additions = {
  "duplicate recovery link" => production_link,
  "duplicate base link" => "[Mochirii Forums](#{production_base}).",
  "foreign host" =>
    "https://foreign.example/session/email-login/mochirii-fixture-admin-login-token",
  "nondefault port" =>
    "https://forums.mochirii.com:444/session/email-login/mochirii-fixture-admin-login-token",
  "userinfo" =>
    "https://fixture-user@forums.mochirii.com/session/email-login/mochirii-fixture-admin-login-token",
  "wrong token" => "https://forums.mochirii.com/session/email-login/private-token",
  "wrong path" =>
    "https://forums.mochirii.com/wrong/session/email-login/mochirii-fixture-admin-login-token",
  "query" => "#{production_link}?fixture-query=private-value",
  "fragment" => "#{production_link}#fixture-fragment-value",
  "unrelated foreign URL" => "https://foreign.example/unrelated",
  "mixed-case foreign URL" => "HtTpS://foreign.example/unrelated",
  "relative wrong-token path" => "/session/email-login/relative-private-token",
  "uppercase relative path" => "/SESSION/EMAIL-LOGIN/relative-private-token",
  "uppercase scheme-relative path" =>
    "//forums.mochirii.com/SESSION/EMAIL-LOGIN/relative-private-token",
  "dot-segment relative path" => "/session/temporary/../email-login/relative-private-token",
  "doubled-separator relative path" => "/session//email-login/relative-private-token",
  "encoded mixed-case relative path" => "/session%2FEMAIL-login%2Fencoded-private-token",
  "encoded uppercase relative path" => "%2FSESSION%2FEMAIL-LOGIN%2Fencoded-private-token",
  "script-prefixed exact URL" => "javascript:#{production_link}",
  "token suffix after punctuation" => "#{production_link}.private-value",
  "foreign query wrapper" => "https://foreign.example/?next=#{production_link}",
  "encoded terminal slash" =>
    "https://forums.mochirii.com/session/email-login%2Fencoded-private-token",
  "encoded route slashes" =>
    "https://forums.mochirii.com/session%2Femail-login%2Fencoded-private-token",
  "encoded route hyphen" =>
    "https://forums.mochirii.com/session/email%2Dlogin/encoded-private-token",
  "fully encoded route" =>
    "https%3A%2F%2Fforums.mochirii.com%2Fsession%2Femail-login%2Fencoded-private-token",
  "fully encoded uppercase route" =>
    "HTTPS%3A%2F%2FFOREIGN.EXAMPLE%2FSESSION%2FEMAIL-LOGIN%2Fencoded-private-token",
  "overencoded recovery route" =>
    5.times.reduce(production_link) { |value| URI.encode_www_form_component(value) },
  "raw HTML scheme-relative anchor" => '<a href="//foreign.example/recovery">unrelated</a>',
  "raw HTML relative anchor" => '<a href="/foreign-recovery">unrelated</a>',
  "entity-encoded HTML anchor" =>
    "&lt;a href=&quot;//foreign.example/recovery&quot;&gt;unrelated&lt;/a&gt;",
  "Markdown scheme-relative link" => "[unrelated](//foreign.example/recovery)",
  "Markdown relative link" => "[unrelated](/foreign-recovery)",
  "entity-encoded Markdown link" => "[unrelated](&#47;&#47;foreign.example/recovery)",
  "site-name drift" => "Mochirii recovery presentation changed",
}
hostile_additions.each do |label, addition|
  expect_rejection(
    label,
    text_part: "#{production_text}\n#{addition}\n",
    expected_base_url: production_base,
    allow_fixture_http: false,
    expected_message: origin_error,
    sensitive_fragments: [addition, "private-token", "foreign.example", "mochirii-fixture-admin-login-token"],
  )
end

expect_rejection(
  "unexpected pre-delivery HTML part",
  text_part: production_text,
  html_part: "<a href=\"#{production_link}\">#{production_link}</a>",
  expected_base_url: production_base,
  allow_fixture_http: false,
  expected_message: origin_error,
  sensitive_fragments: [production_link, "mochirii-fixture-admin-login-token"],
)

assert_fixture(
  source.scan("    verify_admin_login_link!(\n").length == 1,
  "production administrator login helper call count differed",
)
assert_fixture(
  source.scan("allow_fixture_admin_login_http?(\n").length == 1,
  "production fixture HTTP authorization call count differed",
)

puts "Administrator recovery mail link hostile fixture passed."
