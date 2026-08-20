# frozen_string_literal: true

# Computes a bounded, privacy-preserving identity for every nonsecure Upload
# row and its exact S3 object HEAD metadata. Raw rows, paths, and ETags never
# leave the in-container process.

require "digest"
require "json"

module MochiriiNormalUploadInventory
  MAX_UPLOADS = 10_000
  MAX_OBJECT_BYTES = 50 * 1024 * 1024 * 1024
  MAX_OBJECT_PATH_BYTES = 1024
  MAX_ETAG_BYTES = 128
  BATCH_SIZE = 200
  DOMAIN_SEPARATOR = "mochirii-normal-upload-inventory-v1\n"

  def self.fail_inventory(message)
    raise "Normal upload inventory failed: #{message}"
  end

  def self.safe_path!(value, sha1)
    fail_inventory("object path is malformed") unless
      value.is_a?(String) && value.bytesize.between?(1, MAX_OBJECT_PATH_BYTES) &&
        value.match?(%r{\Aoriginal/[A-Za-z0-9._/-]+\z}) &&
        !value.split("/").any? { |part| part.empty? || part == "." || part == ".." } &&
        File.basename(value).start_with?("#{sha1}.")
    value
  end

  def self.safe_etag!(value)
    fail_inventory("object ETag is malformed") unless
      value.is_a?(String) && value.bytesize.between?(1, MAX_ETAG_BYTES) &&
        value.ascii_only? && value.match?(/\A[ -~]+\z/)
    value
  end

  def self.compute!
    store = Discourse.store
    fail_inventory("external S3 upload storage is inactive") unless
      store.is_a?(FileStore::S3Store) && store.external?
    relation = Upload.where(secure: false)
    expected_count = relation.count
    fail_inventory("row count exceeds its bound") unless expected_count.between?(0, MAX_UPLOADS)

    aggregate = Digest::SHA256.new
    aggregate.update(DOMAIN_SEPARATOR)
    observed_count = 0
    previous_id = 0
    relation.find_each(batch_size: BATCH_SIZE) do |upload|
      upload_id = upload.id
      sha1 = upload.sha1
      filesize = upload.filesize
      fail_inventory("row identifier is malformed") unless
        upload_id.is_a?(Integer) && upload_id > previous_id
      fail_inventory("row SHA-1 is malformed") unless
        sha1.is_a?(String) && sha1.match?(/\A[0-9a-f]{40}\z/)
      fail_inventory("row filesize is malformed") unless
        filesize.is_a?(Integer) && filesize.between?(1, MAX_OBJECT_BYTES)
      path = safe_path!(store.get_path_for_upload(upload), sha1)
      object = store.object_from_path(path)
      object.load
      object_size = object.size
      object_etag = safe_etag!(object.etag)
      fail_inventory("object size differs from its row") unless
        object_size.is_a?(Integer) && object_size == filesize
      record = {
        "id" => upload_id,
        "sha1" => sha1,
        "filesize" => filesize,
        "objectPath" => path,
        "objectSize" => object_size,
        "objectEtag" => object_etag,
      }
      aggregate.update(JSON.generate(record.sort.to_h))
      aggregate.update("\n")
      observed_count += 1
      fail_inventory("observed row count exceeds its bound") if observed_count > MAX_UPLOADS
      previous_id = upload_id
    end
    fail_inventory("row set changed during inventory") unless observed_count == expected_count
    aggregate.update(JSON.generate({ "count" => observed_count, "schemaVersion" => 1 }))
    aggregate.update("\n")
    {
      "normalUploadInventoryCount" => observed_count,
      "normalUploadInventorySha256" => aggregate.hexdigest,
    }
  end
end
