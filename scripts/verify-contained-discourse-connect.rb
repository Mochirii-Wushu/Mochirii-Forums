# frozen_string_literal: true

# Verify the real protected consumer secret against the actual outbound
# DiscourseConnect request while the host is loopback-contained. The request
# arrives only on stdin and is never printed or persisted.
require "uri"

raise "central login is not enabled" unless SiteSetting.enable_discourse_connect
raise "central login provider mode is enabled" if SiteSetting.enable_discourse_connect_provider
raise "central login CSRF protection is disabled" unless SiteSetting.discourse_connect_csrf_protection
raise "central login verbose logging is enabled" if SiteSetting.verbose_discourse_connect_logging
secret = SiteSetting.discourse_connect_secret.to_s
raise "central login secret is malformed" unless secret.match?(/\A[0-9a-f]{64}\z/)

raw = STDIN.read
raise "consumer request exceeds its bound" if raw.bytesize > 8192
uri = URI.parse(raw)
unless uri.scheme == "https" && uri.host == "mochirii.com" && uri.port == 443 &&
       uri.path == "/forums/connect" && uri.userinfo.nil? && uri.fragment.nil?
  raise "consumer producer origin differs"
end
query = Rack::Utils.parse_query(uri.query.to_s)
raise "consumer request fields differ" unless query.keys.sort == %w[sig sso]
raise "consumer signature is malformed" unless query.fetch("sig").match?(/\A[0-9a-f]{64}\z/)
parsed = DiscourseConnectBase.parse(uri.query.to_s, secret)
raise "consumer nonce is malformed" unless parsed.nonce.to_s.match?(/\A[0-9a-f]{32,128}\z/)
unless parsed.return_sso_url == "https://forums.mochirii.com/session/sso_login"
  raise "consumer return URL differs"
end

begin
  DiscourseConnectBase.parse("sso=#{CGI.escape(query.fetch("sso"))}&sig=#{"0" * 64}", secret)
rescue DiscourseConnectBase::SignatureError
  # Expected hostile signature rejection.
else
  raise "consumer parser accepted a hostile signature"
end

puts "Contained Mochirii Forums consumer signature verified."
