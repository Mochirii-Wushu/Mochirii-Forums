# frozen_string_literal: true

require "pathname"

raise "Sensitive-log verification is fixture-only" unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"

raw = STDIN.binmode.read(1_048_577)
raise "Sensitive-log marker input exceeded its byte boundary" if raw.bytesize > 1_048_576
markers = raw.lines(chomp: true).uniq
raise "Sensitive-log marker inventory is empty or excessive" if markers.empty? || markers.length > 64
unless markers.all? { |value| value.bytesize.between?(16, 16_384) && value.ascii_only? && !value.match?(/[\x00-\x1f\x7f]/) }
  raise "Sensitive-log marker is malformed"
end

roots = [
  Pathname.new("/var/log/nginx"),
  Pathname.new("/var/log/unicorn"),
  Pathname.new("/shared/log/rails"),
  Pathname.new("/var/www/discourse/log"),
].freeze
existing_roots = roots.select(&:directory?).map(&:realpath)
paths = existing_roots.flat_map { |root| root.glob("*.log") }.uniq
raise "No nginx log was available for the sensitive-log fixture" unless paths.any? { |path| path.to_s.include?("/nginx/") }
raise "No Rails or application log was available for the sensitive-log fixture" unless paths.any? { |path| path.to_s.include?("/rails/") || path.to_s.include?("/discourse/log/") || path.to_s.include?("/unicorn/") }

total_bytes = 0
paths.each do |path|
  resolved = path.realpath
  unless existing_roots.any? { |root| resolved.to_s.start_with?(root.to_s + File::SEPARATOR) }
    raise "Sensitive-log fixture escaped an exact log root"
  end
  next unless resolved.file?
  size = resolved.size
  total_bytes += size
  raise "Sensitive-log file or inventory exceeded its byte boundary" if size > 64 * 1024 * 1024 || total_bytes > 192 * 1024 * 1024
  content = resolved.binread
  raise "A callback secret or member marker reached an application log" if markers.any? { |marker| content.include?(marker) }
end

redis = Discourse.redis
cursor = "0"
keys = []
loop do
  cursor, page = redis.scan(cursor, match: "*logster*", count: 100)
  keys.concat(page)
  raise "Logster key inventory exceeded its bound" if keys.length > 512
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
    raise "Logster fixture exceeded its response bound" if bytes.bytesize > 2 * 1024 * 1024 || redis_bytes > 32 * 1024 * 1024
    raise "A callback secret or member marker reached Logster" if markers.any? { |marker| bytes.include?(marker) }
  end
end

puts "Mochirii Forums sensitive callback logs are redacted."
