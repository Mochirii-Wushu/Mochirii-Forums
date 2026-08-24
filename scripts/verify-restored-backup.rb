# frozen_string_literal: true

require "json"
require "base64"
require "digest"
require "uri"
require_relative "normal-upload-inventory"

RESTORED_CHECK_EXIT_CODES = {
  repository_revision: 64,
  recovery_marker: 65,
  recovery_normal_upload: 66,
  database: 67,
  redis: 68,
  sidekiq_process_present: 69,
  sidekiq_processing: 70,
  mail_suppression_matches_runtime: 71,
  central_login_disabled: 72,
  secure_uploads_absent: 73,
  normal_upload_inventory: 74,
}.freeze

def recovery_marker_bytes(commit)
  base = Base64.strict_decode64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
  comment = "mochirii-recovery-#{commit}".b
  base.byteslice(0, base.bytesize - 1) + "!\xFE".b + [comment.bytesize].pack("C") + comment + "\x00;".b
end

def verify_recovery_upload!(commit)
  expected_state_sha = ENV.fetch("MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256")
  raise "Expected recovery upload digest is malformed" unless expected_state_sha.match?(/\A[0-9a-f]{64}\z/)
  state_text = PluginStore.get("mochirii-recovery", "normal_upload_marker")
  raise "Restored recovery upload marker is absent" unless state_text.is_a?(String) && state_text.bytesize <= 4096
  state = JSON.parse(state_text)
  required = %w[
    schemaVersion repositoryCommit uploadId uploadSha1 originalFilename objectPath
    tombstonePath contentSha256 publicUrlSha256
  ]
  raise "Restored recovery upload marker schema differs" unless state.keys.sort == required.sort
  canonical = JSON.generate(state.sort.to_h)
  raise "Restored recovery upload marker is not canonical" unless state_text == canonical
  raise "Restored recovery upload marker digest differs" unless Digest::SHA256.hexdigest(canonical + "\n") == expected_state_sha
  raise "Restored recovery upload release differs" unless state["schemaVersion"] == 1 && state["repositoryCommit"] == commit
  expected_bytes = recovery_marker_bytes(commit)
  raise "Restored recovery upload content digest differs" unless Digest::SHA256.hexdigest(expected_bytes) == state["contentSha256"]
  upload = Upload.find_by(id: state["uploadId"])
  raise "Restored recovery upload row is absent" unless upload && upload.sha1 == state["uploadSha1"]
  raise "Restored recovery upload row identity differs" unless upload.original_filename == state["originalFilename"] && upload.user_id == Discourse.system_user.id && upload.secure == false
  raise "Restored recovery upload bytes differ" unless upload.content == expected_bytes
  store = Discourse.store
  raise "Restored recovery upload object path differs" unless store.get_path_for_upload(upload) == state["objectPath"]
  public_uri = URI.parse(store.url_for(upload))
  unless public_uri.scheme == "https" && public_uri.host == "media-forums.mochirii.com" &&
      public_uri.port == 443 && public_uri.userinfo.nil? && public_uri.query.nil? && public_uri.fragment.nil?
    raise "Restored recovery upload public URL differs"
  end
  raise "Restored recovery upload public URL digest differs" unless Digest::SHA256.hexdigest(public_uri.to_s) == state["publicUrlSha256"]
  raise "Restored recovery upload object is absent" unless store.object_from_path(state["objectPath"]).exists?
  raise "Restored recovery upload has an unexpected tombstone" if store.object_from_path(state["tombstonePath"]).exists?
  true
end

commit = ENV.fetch("MOCHIRII_REPOSITORY_COMMIT")
expected_inventory_count = ENV["MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT"]
expected_inventory_sha256 = ENV["MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256"]
raise "Expected normal upload inventory contract is incomplete" unless
  expected_inventory_count.nil? == expected_inventory_sha256.nil?
normal_upload_inventory_matches = true
unless expected_inventory_count.nil?
  raise "Expected normal upload inventory count is malformed" unless expected_inventory_count.match?(/\A(?:0|[1-9][0-9]{0,4})\z/)
  expected_count = Integer(expected_inventory_count, 10)
  raise "Expected normal upload inventory count exceeds its bound" unless expected_count <= MochiriiNormalUploadInventory::MAX_UPLOADS
  raise "Expected normal upload inventory digest is malformed" unless expected_inventory_sha256.match?(/\A[0-9a-f]{64}\z/)
  inventory = MochiriiNormalUploadInventory.compute!
  normal_upload_inventory_matches =
    inventory["normalUploadInventoryCount"] == expected_count &&
      inventory["normalUploadInventorySha256"] == expected_inventory_sha256
end
runtime_mail_suppression = ENV.fetch("DISCOURSE_DISABLE_EMAILS")
sidekiq_probe_state = "completed"
begin
  sidekiq_processing = MochiriiEmailMetadata.verify_sidekiq_processing!
rescue MochiriiEmailMetadata::SidekiqProbeError => error
  sidekiq_processing = false
  sidekiq_probe_state = error.state
end
checks = {
  repository_revision: commit.match?(/\A[0-9a-f]{40}\z/),
  recovery_marker: PluginStore.get("mochirii-recovery", "repository_commit") == commit,
  recovery_normal_upload:
    if ENV["MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256"].present?
      verify_recovery_upload!(commit)
    else
      PluginStore.get("mochirii-recovery", "normal_upload_marker").nil?
    end,
  database: ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1,
  redis: Discourse.redis.ping == "PONG",
  sidekiq_process_present: Sidekiq::ProcessSet.new.any?,
  sidekiq_processing: sidekiq_processing,
  mail_suppression_matches_runtime:
    %w[yes non-staff].include?(runtime_mail_suppression) &&
      SiteSetting.disable_emails == runtime_mail_suppression,
  central_login_disabled: SiteSetting.enable_discourse_connect == false,
  secure_uploads_absent: Upload.where(secure: true).none?,
  normal_upload_inventory: normal_upload_inventory_matches,
}

failed = checks.select { |_name, passed| !passed }.keys
puts JSON.generate({ checks: checks, failed: failed, sidekiqProbeState: sidekiq_probe_state })
exit(RESTORED_CHECK_EXIT_CODES.fetch(failed.first)) if failed.any?
