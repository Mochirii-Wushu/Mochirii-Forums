# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "net/http"
require "openssl"
require "uri"
require_relative "backup-url-boundary"
require_relative "normal-upload-inventory"

def verified_https(uri, read_timeout:)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.verify_hostname = true
  http.open_timeout = 15
  http.read_timeout = read_timeout
  http.start { |client| yield client }
end

inventory = MochiriiNormalUploadInventory.compute!
inventory_only = ENV.fetch("MOCHIRII_BACKUP_INVENTORY_ONLY", "false")
raise "Backup inventory mode is malformed" unless %w[true false].include?(inventory_only)
if inventory_only == "true"
  puts JSON.generate(inventory.sort.to_h)
  exit
end
expected_inventory = ENV.fetch("MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_BASE64")
raise "Expected normal upload inventory encoding exceeds its bound" unless
  expected_inventory.bytesize.between?(16, 4096)
expected_inventory_text = Base64.strict_decode64(expected_inventory)
raise "Expected normal upload inventory exceeds its bound" unless expected_inventory_text.bytesize <= 2048
parsed_expected_inventory = JSON.parse(expected_inventory_text)
raise "Expected normal upload inventory differs" unless
  parsed_expected_inventory == inventory &&
    expected_inventory_text == JSON.generate(parsed_expected_inventory.sort.to_h) + "\n"

store = BackupRestore::BackupStore.create
raise "Backup store is not remote" unless store.remote?
raise "Backup prefix differs from the reviewed boundary" unless SiteSetting.s3_backup_bucket == "mochirii-forums/backups"
backup = store.latest_file
raise "No backup is available" if backup.nil?
raise "Backup is empty" unless backup.size.to_i.positive?
maximum_backup_bytes = 50 * 1024 * 1024 * 1024
raise "Backup exceeds the reviewed retrieval bound" if backup.size.to_i > maximum_backup_bytes
MochiriiBackupUrlBoundary.valid_filename!(backup.filename)

retrievable = store.file(backup.filename, include_download_source: true)
raise "Backup cannot be retrieved through the application" if retrievable&.source.blank?
signed_uri = MochiriiBackupUrlBoundary.signed_get_uri(retrievable.source, backup.filename)

digest = Digest::SHA256.new
retrieved_bytes = 0
verified_https(signed_uri, read_timeout: 120) do |http|
  request = Net::HTTP::Get.new(signed_uri.request_uri)
  http.request(request) do |response|
    raise "Protected backup retrieval failed" unless response.is_a?(Net::HTTPSuccess)
    response.read_body do |chunk|
      digest.update(chunk)
      retrieved_bytes += chunk.bytesize
      raise "Protected backup retrieval exceeded its recorded size" if retrieved_bytes > backup.size.to_i
    end
  end
end
raise "Protected backup retrieval size changed" unless retrieved_bytes == backup.size.to_i
expected_filename = ENV["MOCHIRII_EXPECTED_BACKUP_FILENAME"]
expected_sha256 = ENV["MOCHIRII_EXPECTED_BACKUP_SHA256"]
if expected_filename.present? || expected_sha256.present?
  raise "Expected backup contract is incomplete" unless expected_filename.present? && expected_sha256.present?
  MochiriiBackupUrlBoundary.valid_filename!(expected_filename)
  raise "Expected backup digest is malformed" unless expected_sha256.match?(/\A[0-9a-f]{64}\z/)
  raise "Remote backup filename changed" unless backup.filename == expected_filename
  raise "Remote backup content changed" unless digest.hexdigest == expected_sha256
end

anonymous_uri = signed_uri.dup
anonymous_uri.query = nil
anonymous_cdn_uri = MochiriiBackupUrlBoundary.anonymous_cdn_uri(backup.filename)
[
  [anonymous_uri, %w[401 403]],
  [anonymous_cdn_uri, %w[401 403 404]],
].each do |uri, statuses|
  verified_https(uri, read_timeout: 30) do |http|
    request = Net::HTTP::Get.new(uri.request_uri)
    request["Accept"] = "*/*"
    request["Accept-Encoding"] = "identity"
    request["Cache-Control"] = "no-cache, no-store"
    http.request(request) do |response|
      MochiriiBackupUrlBoundary.anonymous_get_denied!(response, statuses: statuses)
    end
  end
end

puts JSON.generate(
  {
    repositoryCommit: ENV.fetch("MOCHIRII_REPOSITORY_COMMIT"),
    filename: backup.filename,
    size: backup.size,
    sha256: digest.hexdigest,
    lastModified: backup.last_modified.utc.iso8601,
    privateAdminRetrievalUrlPresent: true,
    anonymousRetrievalDenied: true,
    anonymousCdnRetrievalDenied: true,
    backupPrefix: "backups/",
  }.merge(inventory),
)
