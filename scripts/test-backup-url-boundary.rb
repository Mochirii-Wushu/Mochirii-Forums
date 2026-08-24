# frozen_string_literal: true

require "uri"
require_relative "backup-url-boundary"

class FixtureAnonymousResponse
  attr_reader :code

  def initialize(code, chunks: [], headers: {})
    @code = code.to_s
    @chunks = chunks
    @headers = headers.transform_keys(&:downcase)
  end

  def [](name)
    @headers[name.downcase]
  end

  def read_body
    @chunks.each { |chunk| yield chunk }
  end
end

filename = "mochirii-forums-2026-08-14-120000-v2026.7.1.tar.gz"
query = URI.encode_www_form(
  {
    "X-Amz-Algorithm" => "AWS4-HMAC-SHA256",
    "X-Amz-Credential" => "fixture/20260814/whatever/s3/aws4_request",
    "X-Amz-Date" => "20260814T120000Z",
    "X-Amz-Expires" => "3600",
    "X-Amz-SignedHeaders" => "host",
    "X-Amz-Signature" => "a" * 64,
  },
)
exact = "https://mochirii-forums.sgp1.digitaloceanspaces.com/backups/default/#{filename}?#{query}"
uri = MochiriiBackupUrlBoundary.signed_get_uri(exact, filename)
raise "exact signed backup URI changed" unless uri.host == MochiriiBackupUrlBoundary::EXPECTED_HOST
cdn_uri = MochiriiBackupUrlBoundary.anonymous_cdn_uri(filename)
unless cdn_uri.to_s == "https://media-forums.mochirii.com/backups/default/#{filename}" && cdn_uri.query.nil?
  raise "exact anonymous CDN URI changed"
end

hostile_urls = [
  exact.sub(MochiriiBackupUrlBoundary::EXPECTED_HOST, "wrong.example.invalid"),
  exact.sub("https://", "https://user@"),
  exact.sub(MochiriiBackupUrlBoundary::EXPECTED_HOST, "#{MochiriiBackupUrlBoundary::EXPECTED_HOST}:444"),
  exact.sub("/backups/default/", "/backups/other/"),
  exact.sub(filename, "different.tar.gz"),
  "#{exact}#fragment",
  exact.split("?", 2).first,
  "#{exact}&#{URI.encode_www_form_component("X-Amz-Signature")}=#{"b" * 64}",
]
hostile_urls.each do |value|
  begin
    MochiriiBackupUrlBoundary.signed_get_uri(value, filename)
    raise "hostile backup retrieval URL was accepted"
  rescue MochiriiBackupUrlBoundary::InvalidBackupUrl
    nil
  end
end

hostile_filenames = [
  "-option.tar.gz",
  "--option.tgz",
  "fixture..backup.tar.gz",
  ".hidden.tar.gz",
  "nested/fixture.tar.gz",
  "a" * 201 + ".tar.gz",
]
hostile_filenames.each do |value|
  begin
    MochiriiBackupUrlBoundary.valid_filename!(value)
    raise "hostile backup filename was accepted"
  rescue MochiriiBackupUrlBoundary::InvalidBackupFilename
    nil
  end
end

unless MochiriiBackupUrlBoundary.anonymous_get_denied!(
  FixtureAnonymousResponse.new(403, chunks: ["denied"], headers: { "content-length" => "6" }),
)
  raise "exact anonymous GET denial changed"
end
unless MochiriiBackupUrlBoundary.anonymous_get_denied!(
  FixtureAnonymousResponse.new(404, chunks: ["not found"], headers: { "content-length" => "9" }),
  statuses: %w[401 403 404],
)
  raise "exact anonymous CDN GET denial changed"
end

hostile_anonymous_responses = [
  # A provider may deny HEAD but allow GET; only the GET response is accepted
  # by this boundary, and a successful GET must fail closed.
  FixtureAnonymousResponse.new(200, chunks: ["private backup bytes"]),
  # A missing origin object does not prove that the private backup object is
  # access-controlled. Only the custom CDN is allowed to normalize denial to
  # 404 under the reviewed provider behavior.
  FixtureAnonymousResponse.new(404, chunks: ["not found"]),
  FixtureAnonymousResponse.new(302, headers: { "location" => "https://example.invalid/object" }),
  FixtureAnonymousResponse.new(401, headers: { "location" => "https://example.invalid/object" }),
  FixtureAnonymousResponse.new(401, headers: { "set-cookie" => "leak=1" }),
  FixtureAnonymousResponse.new(401, headers: { "content-range" => "bytes 0-1/2" }),
  FixtureAnonymousResponse.new(401, headers: { "content-length" => "unknown" }),
  FixtureAnonymousResponse.new(401, headers: { "content-length" => (MochiriiBackupUrlBoundary::MAX_ANONYMOUS_DENIAL_BYTES + 1).to_s }),
  FixtureAnonymousResponse.new(401, chunks: ["a" * MochiriiBackupUrlBoundary::MAX_ANONYMOUS_DENIAL_BYTES, "b"]),
]
hostile_anonymous_responses.each do |response|
  begin
    MochiriiBackupUrlBoundary.anonymous_get_denied!(response)
    raise "hostile anonymous GET response was accepted"
  rescue MochiriiBackupUrlBoundary::InvalidBackupUrl
    nil
  end
end

hostile_cdn_denials = [
  FixtureAnonymousResponse.new(404, headers: { "location" => "https://example.invalid/object" }),
  FixtureAnonymousResponse.new(
    404,
    headers: {
      "content-length" => (MochiriiBackupUrlBoundary::MAX_ANONYMOUS_DENIAL_BYTES + 1).to_s,
    },
  ),
  FixtureAnonymousResponse.new(
    404,
    chunks: ["a" * MochiriiBackupUrlBoundary::MAX_ANONYMOUS_DENIAL_BYTES, "b"],
  ),
]
hostile_cdn_denials.each do |response|
  begin
    MochiriiBackupUrlBoundary.anonymous_get_denied!(response, statuses: %w[401 403 404])
    raise "hostile anonymous CDN denial response was accepted"
  rescue MochiriiBackupUrlBoundary::InvalidBackupUrl
    nil
  end
end

verifier_source = File.read(File.join(__dir__, "verify-backup.rb"), encoding: "UTF-8")
unless verifier_source.include?("MochiriiBackupUrlBoundary.anonymous_cdn_uri(backup.filename)") &&
    verifier_source.include?("[anonymous_uri, %w[401 403]]") &&
    verifier_source.include?("[anonymous_cdn_uri, %w[401 403 404]]") &&
    verifier_source.include?("Net::HTTP::Get.new(uri.request_uri)") &&
    !verifier_source.include?("Net::HTTP::Head.new(anonymous_uri.request_uri)")
  raise "hosted backup verifier does not prove origin and CDN anonymous GET denial"
end

puts "Backup retrieval URL and filename hostile fixtures passed."
