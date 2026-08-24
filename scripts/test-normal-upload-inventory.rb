# frozen_string_literal: true

require "digest"
require "json"

FakeUpload = Struct.new(:id, :sha1, :filesize, keyword_init: true)

class FakeUploadRelation
  def initialize(records, reported_count)
    @records = records
    @reported_count = reported_count
  end

  def count
    @reported_count || @records.length
  end

  def find_each(batch_size:)
    raise "unexpected batch size" unless batch_size == 200

    @records.sort_by(&:id).each { |record| yield record }
  end
end

class Upload
  class << self
    attr_accessor :records, :reported_count
  end

  def self.where(secure:)
    raise "secure uploads entered the normal inventory" unless secure == false

    FakeUploadRelation.new(records, reported_count)
  end
end

class FakeS3Object
  attr_reader :size, :etag

  def initialize(size:, etag:, present: true)
    @size = size
    @etag = etag
    @present = present
  end

  def load
    raise "object is absent" unless @present

    self
  end
end

module FileStore
  class S3Store
    attr_accessor :paths, :objects, :external

    def initialize
      @paths = {}
      @objects = {}
      @external = true
    end

    def external?
      @external
    end

    def get_path_for_upload(upload)
      paths.fetch(upload.id)
    end

    def object_from_path(path)
      objects.fetch(path)
    end
  end
end

module Discourse
  class << self
    attr_accessor :store
  end
end

require_relative "normal-upload-inventory"

def assert(condition, message)
  raise message unless condition
end

def assert_failure(fragment)
  yield
rescue RuntimeError => error
  raise "unexpected failure: #{error.message}" unless error.message.include?(fragment)
else
  raise "expected failure containing #{fragment.inspect}"
end

sha_one = "1" * 40
sha_two = "2" * 40
rows = [
  FakeUpload.new(id: 9, sha1: sha_two, filesize: 29),
  FakeUpload.new(id: 3, sha1: sha_one, filesize: 17),
]
store = FileStore::S3Store.new
store.paths = {
  3 => "original/1X/a/#{sha_one}.png",
  9 => "original/2X/b/#{sha_two}.gif",
}
store.objects = {
  store.paths.fetch(3) => FakeS3Object.new(size: 17, etag: '"etag-one"'),
  store.paths.fetch(9) => FakeS3Object.new(size: 29, etag: '"etag-two"'),
}
Discourse.store = store
Upload.records = rows
Upload.reported_count = nil

expected_digest = Digest::SHA256.new
expected_digest.update("mochirii-normal-upload-inventory-v1\n")
rows.sort_by(&:id).each do |row|
  path = store.paths.fetch(row.id)
  object = store.objects.fetch(path)
  expected_digest.update(
    JSON.generate(
      {
        "id" => row.id,
        "sha1" => row.sha1,
        "filesize" => row.filesize,
        "objectPath" => path,
        "objectSize" => object.size,
        "objectEtag" => object.etag,
      }.sort.to_h,
    ),
  )
  expected_digest.update("\n")
end
expected_digest.update(JSON.generate({ "count" => rows.length, "schemaVersion" => 1 }))
expected_digest.update("\n")

inventory = MochiriiNormalUploadInventory.compute!
assert(
  inventory == {
    "normalUploadInventoryCount" => 2,
    "normalUploadInventorySha256" => expected_digest.hexdigest,
  },
  "normal upload inventory aggregate differs",
)
assert(inventory.keys.length == 2, "normal upload inventory leaked raw identity")

original_path = store.paths.fetch(3)
store.paths[3] = "original/1X/../#{sha_one}.png"
assert_failure("object path is malformed") { MochiriiNormalUploadInventory.compute! }
store.paths[3] = original_path

original_object = store.objects.fetch(original_path)
store.objects[original_path] = FakeS3Object.new(size: 18, etag: '"etag-one"')
assert_failure("object size differs from its row") { MochiriiNormalUploadInventory.compute! }
store.objects[original_path] = FakeS3Object.new(size: 17, etag: "bad\netag")
assert_failure("object ETag is malformed") { MochiriiNormalUploadInventory.compute! }
store.objects[original_path] = FakeS3Object.new(size: 17, etag: '"etag-one"', present: false)
assert_failure("object is absent") { MochiriiNormalUploadInventory.compute! }
store.objects[original_path] = original_object

Upload.reported_count = MochiriiNormalUploadInventory::MAX_UPLOADS + 1
assert_failure("row count exceeds its bound") { MochiriiNormalUploadInventory.compute! }
Upload.reported_count = nil

store.external = false
assert_failure("external S3 upload storage is inactive") { MochiriiNormalUploadInventory.compute! }

# Exercise the publisher's actual sanitizer without reaching S3. Post-member
# backups intentionally carry the exact false/null recovery tuple, and their
# bounded normal-upload aggregate must remain part of the private DR record.
publisher_path = File.join(__dir__, "publish-disaster-recovery-evidence.rb")
publisher_source = File.binread(publisher_path)
validator_source, runner_source = publisher_source.split("\nencoded = ENV.fetch", 2)
raise "publisher validation boundary moved" unless validator_source && runner_source

publisher_module = Module.new
publisher_module.module_eval(validator_source, publisher_path, 1) # rubocop:disable Security/Eval
publisher_validator = Object.new.extend(publisher_module)
clean_document = {
  "schemaVersion" => 2,
  "backupLastModified" => "2026-08-15T01:02:03Z",
  "repositoryCommit" => "a" * 40,
  "repositoryTree" => "9" * 40,
  "productionConfigurationSha256" => "b" * 64,
  "backupFilename" => "mochirii-clean-v20260815010203.tar.gz",
  "backupSize" => 1234,
  "backupSha256" => "c" * 64,
  "backupEvidenceCoreSha256" => "d" * 64,
  "normalUploadInventoryCount" => 2,
  "normalUploadInventorySha256" => "e" * 64,
  "releaseEvidenceFile" => "#{'a' * 40}-#{'b' * 64}-release.json",
  "releaseEvidenceSha256" => "f" * 64,
  "releaseArchiveSha256" => "0" * 64,
  "releaseArchiveBytes" => 512,
  "releaseArchiveContentManifestSha256" => "9" * 64,
  "releaseArchiveObjectKey" => "backups/recovery-releases/archives/#{'0' * 64}.tar",
  "releaseArchiveSourceFormat" => "git-archive-tar-v1",
  "releaseSourceAuthorityObjectKey" => "pending",
  "releaseSourceAuthoritySha256" => "0" * 64,
  "restoreConfigurationSha256" => "1" * 64,
  "themeArchiveSha256" => "2" * 64,
  "mailMetadataPluginSha256" => "3" * 64,
  "discourseDockerRevision" => "4" * 40,
  "discourseRevision" => "5" * 40,
  "dockerManagerRevision" => "6" * 40,
  "baseImageDigest" => "sha256:#{'7' * 64}",
  "discourseConnectEnabled" => true,
  "memberRolloutMarkerFile" => "member-rollout-enabled",
  "memberRolloutMarkerSha256" => "8" * 64,
  "anonymousRetrievalDenied" => true,
  "anonymousCdnRetrievalDenied" => true,
  "recoveryUploadIncluded" => false,
  "recoveryUploadState" => nil,
  "recoveryUploadStateSha256" => nil,
  "recoveryUploadDeletedAfterBackup" => false,
  "cleanHostAdoptionRequiresEmptyPersistentData" => true,
  "containsSecrets" => false,
  "containsSignedUrls" => false,
  "releaseArchiveContainsSecrets" => false,
  "ordinaryDeploymentRequiresCurrentMain" => true,
  "historicalReleaseAdoptionScope" => "clean-target-disaster-recovery-only",
}
release_authority = publisher_validator.source_authority(clean_document)
release_authority_sha = Digest::SHA256.hexdigest(publisher_validator.canonical(release_authority))
clean_document["releaseSourceAuthoritySha256"] = release_authority_sha
clean_document["releaseSourceAuthorityObjectKey"] =
  "backups/recovery-releases/authorities/#{release_authority_sha}.json"
assert(
  publisher_validator.safe_document!(clean_document) == clean_document,
  "clean DR document was rejected",
)

bad_clean_state = clean_document.merge("recoveryUploadState" => {})
assert_failure("clean backup retained recovery upload identity") do
  publisher_validator.safe_document!(bad_clean_state)
end
bad_clean_deleted = clean_document.merge("recoveryUploadDeletedAfterBackup" => true)
assert_failure("clean backup retained recovery upload identity") do
  publisher_validator.safe_document!(bad_clean_deleted)
end
missing_inventory = clean_document.reject { |key, _| key == "normalUploadInventorySha256" }
assert_failure("document keys differ") { publisher_validator.safe_document!(missing_inventory) }
oversized_inventory = clean_document.merge(
  "normalUploadInventoryCount" => MochiriiNormalUploadInventory::MAX_UPLOADS + 1,
)
assert_failure("normal upload inventory count is malformed") do
  publisher_validator.safe_document!(oversized_inventory)
end

fake_grantee = Struct.new(:type, :id, keyword_init: true)
fake_grant = Struct.new(:permission, :grantee, keyword_init: true)
fake_owner = Struct.new(:id, keyword_init: true)
fake_acl = Struct.new(:owner, :grants, keyword_init: true)
fake_object = Struct.new(:acl, keyword_init: true)
owner = fake_owner.new(id: "owner-id")
owner_grant = fake_grant.new(
  permission: "FULL_CONTROL",
  grantee: fake_grantee.new(type: "CanonicalUser", id: owner.id),
)
exact_private_object = fake_object.new(acl: fake_acl.new(owner: owner, grants: [owner_grant]))
publisher_validator.private_object!(exact_private_object)
authenticated_grant = fake_grant.new(
  permission: "READ",
  grantee: fake_grantee.new(type: "Group", id: "authenticated-users"),
)
assert_failure("object ACL is not exact private owner-only") do
  publisher_validator.private_object!(
    fake_object.new(acl: fake_acl.new(owner: owner, grants: [owner_grant, authenticated_grant])),
  )
end

fetcher_path = File.join(__dir__, "fetch-disaster-recovery-evidence.rb")
fetcher_source = File.binread(fetcher_path)
fetch_validator_source, fetch_runner_source = fetcher_source.split("\nfetch_mode = ENV.fetch", 2)
raise "fetcher validation boundary moved" unless fetch_validator_source && fetch_runner_source

fetch_module = Module.new
fetch_module.module_eval(fetch_validator_source, fetcher_path, 1) # rubocop:disable Security/Eval
fetch_validator = Object.new.extend(fetch_module)
fetch_validator.private_object!(exact_private_object)
assert_failure("object ACL is not exact private owner-only") do
  fetch_validator.private_object!(
    fake_object.new(acl: fake_acl.new(owner: owner, grants: [owner_grant, authenticated_grant])),
  )
end
other_owner_grant = fake_grant.new(
  permission: "FULL_CONTROL",
  grantee: fake_grantee.new(type: "CanonicalUser", id: "other-owner"),
)
assert_failure("object ACL is not exact private owner-only") do
  fetch_validator.private_object!(
    fake_object.new(acl: fake_acl.new(owner: owner, grants: [other_owner_grant])),
  )
end

puts "Normal upload inventory checks passed."
