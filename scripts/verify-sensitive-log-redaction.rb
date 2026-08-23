# frozen_string_literal: true

require "pathname"

SENSITIVE_LOG_AUDIT_EXIT_CODES = {
  input: 40,
  identity: 41,
  authenticated_session: 42,
  authentication_audit_shape: 43,
  authentication_audit_marker: 44,
  log_inventory: 45,
  application_log_marker: 46,
  logster_shape: 47,
  logster_marker: 48,
  application_log_identity_marker: 49,
  application_log_callback_marker: 50,
  application_log_recovery_marker: 51,
}.freeze

APPLICATION_LOG_MARKER_CATEGORIES = {
  "identity" => :application_log_identity_marker,
  "callback" => :application_log_callback_marker,
  "recovery" => :application_log_recovery_marker,
}.freeze

def reject_sensitive_log!(category)
  exit SENSITIVE_LOG_AUDIT_EXIT_CODES.fetch(category)
end

reject_sensitive_log!(:input) unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"

raw = STDIN.binmode.read(1_048_577)
reject_sensitive_log!(:input) if raw.bytesize > 1_048_576 || !raw.end_with?("\n") || raw.include?("\r")
marker_records = raw.lines(chomp: true).map { |line| line.split("\t", 2) }
reject_sensitive_log!(:input) if marker_records.empty? || marker_records.length > 64
valid_marker_records = marker_records.all? do |record|
  record.length == 2 &&
    APPLICATION_LOG_MARKER_CATEGORIES.key?(record[0]) &&
    record[1].bytesize.between?(16, 16_384) &&
    record[1].ascii_only? &&
    !record[1].match?(/[\x00-\x1f\x7f]/)
end
reject_sensitive_log!(:input) unless valid_marker_records
markers = marker_records.map(&:last)
reject_sensitive_log!(:input) unless markers.uniq.length == markers.length

record = SingleSignOnRecord.find_by(external_id: "mochirii-stage4-consumer-fixture")
reject_sensitive_log!(:identity) if record.nil? || record.user.nil?
user = record.user
reject_sensitive_log!(:identity) unless user.email == "stage4-fixture@forums.mochirii.com"
reject_sensitive_log!(:authenticated_session) if UserAuthToken.where(user_id: user.id).exists?

auth_logs = UserAuthTokenLog.where(user_id: user.id).order(:id).limit(129).to_a
reject_sensitive_log!(:authentication_audit_shape) if auth_logs.empty? || auth_logs.length > 128
filtered_email_login_path = "/session/email-login/[FILTERED]"
unless auth_logs.any? { |entry| entry.action == "generate" && entry.path == filtered_email_login_path }
  reject_sensitive_log!(:authentication_audit_shape)
end
if auth_logs.any? { |entry| entry.path.to_s.match?(%r{\A/session/email-login/[A-Za-z0-9_-]{20,256}\z}) }
  reject_sensitive_log!(:authentication_audit_shape)
end
auth_log_bytes = 0
auth_logs.each do |entry|
  [entry.action, entry.auth_token, entry.path, entry.user_agent, entry.client_ip].compact.each do |value|
    bytes = value.to_s.b
    auth_log_bytes += bytes.bytesize
    if bytes.bytesize > 16_384 || auth_log_bytes > 1_048_576
      reject_sensitive_log!(:authentication_audit_shape)
    end
    reject_sensitive_log!(:authentication_audit_marker) if markers.any? { |marker| bytes.include?(marker) }
  end
end

roots = [
  Pathname.new("/var/log/nginx"),
  Pathname.new("/var/log/unicorn"),
  Pathname.new("/shared/log/rails"),
  Pathname.new("/var/www/discourse/log"),
].freeze
existing_roots = roots.select(&:directory?).map(&:realpath)
paths = existing_roots.flat_map { |root| root.glob("*.log") }.uniq
reject_sensitive_log!(:log_inventory) unless paths.any? { |path| path.to_s.include?("/nginx/") }
reject_sensitive_log!(:log_inventory) unless paths.any? { |path| path.to_s.include?("/rails/") || path.to_s.include?("/discourse/log/") || path.to_s.include?("/unicorn/") }

total_bytes = 0
paths.each do |path|
  resolved = path.realpath
  unless existing_roots.any? { |root| resolved.to_s.start_with?(root.to_s + File::SEPARATOR) }
    reject_sensitive_log!(:log_inventory)
  end
  next unless resolved.file?
  size = resolved.size
  total_bytes += size
  reject_sensitive_log!(:log_inventory) if size > 64 * 1024 * 1024 || total_bytes > 192 * 1024 * 1024
  content = resolved.binread
  if marker_record = marker_records.find { |_category, marker| content.include?(marker) }
    reject_sensitive_log!(APPLICATION_LOG_MARKER_CATEGORIES.fetch(marker_record[0]))
  end
end

redis = Discourse.redis
cursor = "0"
keys = []
loop do
  cursor, page = redis.scan(cursor, match: "*logster*", count: 100)
  keys.concat(page)
  reject_sensitive_log!(:logster_shape) if keys.length > 512
  break if cursor.to_s == "0"
end
redis_bytes = 0
keys.uniq.each do |key|
  values =
    case redis.type(key)
    when "string" then [redis.get(key)]
    when "hash" then redis.hvals(key)
    when "list" then redis.lrange(key, 0, 255)
    when "set" then redis.smembers(key)
    when "zset" then redis.zrange(key, 0, 255)
    else []
    end
  values.compact.each do |value|
    bytes = value.to_s.b
    redis_bytes += bytes.bytesize
    reject_sensitive_log!(:logster_shape) if bytes.bytesize > 2 * 1024 * 1024 || redis_bytes > 32 * 1024 * 1024
    reject_sensitive_log!(:logster_marker) if markers.any? { |marker| bytes.include?(marker) }
  end
end

puts "Mochirii Forums sensitive callback logs are redacted."
