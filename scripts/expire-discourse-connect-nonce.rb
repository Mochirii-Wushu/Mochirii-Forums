# frozen_string_literal: true

# Disposable-fixture helper. The nonce arrives on stdin so it never appears in
# a process argument, environment, or public workflow output.

raise "Nonce expiry helper is fixture-only" unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"
nonce = STDIN.read.strip
raise "Fixture nonce is malformed" unless nonce.match?(/\A[0-9a-f]{32,128}\z/)

suffix = "SSO_NONCE_#{nonce}"
keys = Discourse.redis.scan_each(match: "*#{suffix}", count: 100).select { |key| key.end_with?(suffix) }.to_a
raise "Expected exactly one live session-bound fixture nonce" unless keys.length == 1
raise "Pinned nonce lifetime changed" unless DiscourseConnectBase.nonce_expiry_time.to_i == 1800
ttl = Discourse.redis.ttl(keys.first)
raise "Fixture nonce TTL is outside the pinned live range" unless ttl.between?(1, 1800)
Discourse.redis.del(keys.first)
puts "Fixture nonce expired."
