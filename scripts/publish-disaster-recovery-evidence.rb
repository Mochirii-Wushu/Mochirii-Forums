# frozen_string_literal: true

# Publishes only sanitized, digest-bound disaster-recovery metadata to the
# already-authorized private backup bucket. It never creates or prints a signed
# URL, credential, provider identifier, or member datum.

require "base64"
require "digest"
require "json"
require "tempfile"
require_relative "normal-upload-inventory"

MAX_DOCUMENT_BYTES = 32 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 64 * 1024 * 1024
EXPECTED_BUCKET = "mochirii-forums"
EXPECTED_FOLDER = "backups"
POINTER_PATH = "recovery-evidence/current.json"
RELEASE_ARCHIVE_PATH = "/opt/mochirii-release/mochirii-release.tar"
RELEASE_ARCHIVE_FORMAT = "git-archive-tar-v1"
HISTORICAL_ADOPTION_SCOPE = "clean-target-disaster-recovery-only"
DOCUMENT_KEYS = %w[
  schemaVersion backupLastModified repositoryCommit repositoryTree productionConfigurationSha256
  backupFilename backupSize backupSha256 backupEvidenceCoreSha256
  normalUploadInventoryCount normalUploadInventorySha256
  releaseEvidenceFile releaseEvidenceSha256 releaseArchiveSha256 releaseArchiveBytes
  releaseArchiveContentManifestSha256 releaseArchiveObjectKey releaseArchiveSourceFormat
  releaseSourceAuthorityObjectKey releaseSourceAuthoritySha256
  restoreConfigurationSha256 themeArchiveSha256 mailMetadataPluginSha256
  discourseDockerRevision discourseRevision dockerManagerRevision baseImageDigest
  discourseConnectEnabled memberRolloutMarkerFile memberRolloutMarkerSha256
  anonymousRetrievalDenied anonymousCdnRetrievalDenied recoveryUploadIncluded
  recoveryUploadState recoveryUploadStateSha256 recoveryUploadDeletedAfterBackup
  cleanHostAdoptionRequiresEmptyPersistentData containsSecrets containsSignedUrls
  releaseArchiveContainsSecrets ordinaryDeploymentRequiresCurrentMain
  historicalReleaseAdoptionScope
].freeze
AUTHORITY_KEYS = %w[
  schemaVersion repository repositoryCommit repositoryTree productionConfigurationSha256
  releaseArchiveSha256 releaseArchiveBytes releaseArchiveContentManifestSha256
  releaseArchiveObjectKey releaseArchiveSourceFormat containsSecrets containsSignedUrls
  ordinaryDeploymentRequiresCurrentMain historicalReleaseAdoptionScope
].freeze

def fail_publish(message)
  raise "Disaster-recovery evidence publication failed: #{message}"
end

def canonical(document)
  JSON.generate(document.sort.to_h) + "\n"
end

def digest?(value, size = 64)
  value.is_a?(String) && value.match?(/\A[0-9a-f]{#{size}}\z/)
end

def recovery_marker_bytes(commit)
  base = Base64.strict_decode64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
  fail_publish("recovery upload base fixture differs") unless base.bytesize == 34 && base.end_with?(";")
  comment = "mochirii-recovery-#{commit}".b
  fail_publish("recovery upload comment exceeds its bound") unless comment.bytesize.between?(32, 96)
  base.byteslice(0, base.bytesize - 1) + "!\xFE".b + [comment.bytesize].pack("C") + comment + "\x00;".b
end

def safe_document!(document)
  fail_publish("document keys differ") unless document.is_a?(Hash) && document.keys.sort == DOCUMENT_KEYS.sort
  fail_publish("document schema differs") unless document["schemaVersion"] == 2
  fail_publish("repository commit is malformed") unless digest?(document["repositoryCommit"], 40)
  fail_publish("repository tree is malformed") unless digest?(document["repositoryTree"], 40)
  %w[
    productionConfigurationSha256 backupSha256 backupEvidenceCoreSha256
    releaseEvidenceSha256 releaseArchiveSha256 restoreConfigurationSha256
    releaseArchiveContentManifestSha256 releaseSourceAuthoritySha256
    themeArchiveSha256 mailMetadataPluginSha256 dockerManagerRevision
  ].each { |key| fail_publish("#{key} is malformed") unless digest?(document[key], key == "dockerManagerRevision" ? 40 : 64) }
  %w[discourseDockerRevision discourseRevision].each do |key|
    fail_publish("#{key} is malformed") unless digest?(document[key], 40)
  end
  fail_publish("base image digest is malformed") unless document["baseImageDigest"].to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  release_bytes = document["releaseArchiveBytes"]
  fail_publish("release archive size is malformed") unless
    release_bytes.is_a?(Integer) && release_bytes.between?(1, MAX_RELEASE_ARCHIVE_BYTES)
  expected_archive_key = "#{EXPECTED_FOLDER}/recovery-releases/archives/#{document.fetch("releaseArchiveSha256")}.tar"
  fail_publish("release archive object key differs") unless document["releaseArchiveObjectKey"] == expected_archive_key
  fail_publish("release archive format differs") unless document["releaseArchiveSourceFormat"] == RELEASE_ARCHIVE_FORMAT
  fail_publish("historical release scope differs") unless
    document["historicalReleaseAdoptionScope"] == HISTORICAL_ADOPTION_SCOPE
  authority = source_authority(document)
  authority_payload = canonical(authority)
  authority_sha = Digest::SHA256.hexdigest(authority_payload)
  expected_authority_key = "#{EXPECTED_FOLDER}/recovery-releases/authorities/#{authority_sha}.json"
  fail_publish("release source authority digest differs") unless document["releaseSourceAuthoritySha256"] == authority_sha
  fail_publish("release source authority key differs") unless document["releaseSourceAuthorityObjectKey"] == expected_authority_key
  filename = document["backupFilename"].to_s
  fail_publish("backup filename is malformed") unless
    filename.bytesize <= 200 && filename.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz\z/) && !filename.include?("..")
  fail_publish("backup size is malformed") unless document["backupSize"].is_a?(Integer) && document["backupSize"].between?(1, 50 * 1024 * 1024 * 1024)
  fail_publish("normal upload inventory count is malformed") unless
    document["normalUploadInventoryCount"].is_a?(Integer) &&
      document["normalUploadInventoryCount"].between?(0, MochiriiNormalUploadInventory::MAX_UPLOADS)
  fail_publish("normal upload inventory digest is malformed") unless digest?(document["normalUploadInventorySha256"])
  fail_publish("backup timestamp is malformed") unless document["backupLastModified"].is_a?(String) && document["backupLastModified"].match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T/)
  release_name = "#{document["repositoryCommit"]}-#{document["productionConfigurationSha256"]}-release.json"
  fail_publish("release evidence filename differs") unless document["releaseEvidenceFile"] == release_name
  marker_file = document["memberRolloutMarkerFile"]
  marker_sha = document["memberRolloutMarkerSha256"]
  fail_publish("member rollout binding is incomplete") unless marker_file.nil? == marker_sha.nil?
  if marker_file
    fail_publish("member rollout binding differs") unless marker_file == "member-rollout-enabled" && digest?(marker_sha)
  end
  %w[
    discourseConnectEnabled anonymousRetrievalDenied anonymousCdnRetrievalDenied
    recoveryUploadIncluded recoveryUploadDeletedAfterBackup
    cleanHostAdoptionRequiresEmptyPersistentData containsSecrets containsSignedUrls
    releaseArchiveContainsSecrets ordinaryDeploymentRequiresCurrentMain
  ].each { |key| fail_publish("#{key} is not boolean") unless [true, false].include?(document[key]) }
  fail_publish("clean-host safety flags differ") unless
    document["cleanHostAdoptionRequiresEmptyPersistentData"] == true &&
      document["containsSecrets"] == false && document["containsSignedUrls"] == false &&
      document["releaseArchiveContainsSecrets"] == false &&
      document["ordinaryDeploymentRequiresCurrentMain"] == true
  fail_publish("backup privacy proof differs") unless
    document["anonymousRetrievalDenied"] == true && document["anonymousCdnRetrievalDenied"] == true
  recovery_state = document["recoveryUploadState"]
  recovery_state_sha = document["recoveryUploadStateSha256"]
  if document["recoveryUploadIncluded"]
    required_state = %w[
      schemaVersion repositoryCommit uploadId uploadSha1 originalFilename objectPath
      tombstonePath contentSha256 publicUrlSha256
    ]
    fail_publish("recovery upload state keys differ") unless
      recovery_state.is_a?(Hash) && recovery_state.keys.sort == required_state.sort
    fail_publish("recovery upload state release differs") unless
      recovery_state["schemaVersion"] == 1 && recovery_state["repositoryCommit"] == document["repositoryCommit"]
    fail_publish("recovery upload state identifier is malformed") unless recovery_state["uploadId"].is_a?(Integer) && recovery_state["uploadId"].positive?
    expected_bytes = recovery_marker_bytes(document.fetch("repositoryCommit"))
    expected_sha1 = Digest::SHA1.hexdigest(expected_bytes)
    fail_publish("recovery upload state SHA-1 differs") unless recovery_state["uploadSha1"] == expected_sha1
    fail_publish("recovery upload state content digest differs") unless
      recovery_state["contentSha256"] == Digest::SHA256.hexdigest(expected_bytes)
    fail_publish("recovery upload state URL digest is malformed") unless digest?(recovery_state["publicUrlSha256"])
    expected_filename = "mochirii-recovery-#{document.fetch("repositoryCommit")[0, 12]}.gif"
    fail_publish("recovery upload state filename differs") unless recovery_state["originalFilename"] == expected_filename
    object_path = recovery_state["objectPath"].to_s
    fail_publish("recovery upload state object path differs") unless
      object_path.match?(%r{\Aoriginal/[1-9][0-9]*X/(?:[0-9a-f]/)*#{expected_sha1}[.]gif\z})
    fail_publish("recovery upload state tombstone path differs") unless
      recovery_state["tombstonePath"] == File.join(FileStore::S3Store::TOMBSTONE_PREFIX, object_path)
    state_payload = JSON.generate(recovery_state.sort.to_h) + "\n"
    fail_publish("recovery upload state digest differs") unless
      digest?(recovery_state_sha) && Digest::SHA256.hexdigest(state_payload) == recovery_state_sha
    fail_publish("recovery upload was not deleted after backup") unless document["recoveryUploadDeletedAfterBackup"] == true
  else
    fail_publish("clean backup retained recovery upload identity") unless
      recovery_state.nil? && recovery_state_sha.nil? && document["recoveryUploadDeletedAfterBackup"] == false
  end
  document
end

def source_authority(document)
  authority = {
    "schemaVersion" => 1,
    "repository" => "Mochirii-Wushu/Mochirii-Forums",
    "repositoryCommit" => document.fetch("repositoryCommit"),
    "repositoryTree" => document.fetch("repositoryTree"),
    "productionConfigurationSha256" => document.fetch("productionConfigurationSha256"),
    "releaseArchiveSha256" => document.fetch("releaseArchiveSha256"),
    "releaseArchiveBytes" => document.fetch("releaseArchiveBytes"),
    "releaseArchiveContentManifestSha256" => document.fetch("releaseArchiveContentManifestSha256"),
    "releaseArchiveObjectKey" => document.fetch("releaseArchiveObjectKey"),
    "releaseArchiveSourceFormat" => document.fetch("releaseArchiveSourceFormat"),
    "containsSecrets" => false,
    "containsSignedUrls" => false,
    "ordinaryDeploymentRequiresCurrentMain" => true,
    "historicalReleaseAdoptionScope" => HISTORICAL_ADOPTION_SCOPE,
  }
  fail_publish("release source authority keys differ") unless authority.keys.sort == AUTHORITY_KEYS.sort
  authority
end

def bounded_read(object)
  response = object.get
  bytes = +""
  while (chunk = response.body.read(16 * 1024))
    bytes << chunk
    fail_publish("object exceeds its byte boundary") if bytes.bytesize > MAX_DOCUMENT_BYTES
  end
  bytes
end

def private_object!(object)
  acl = object.acl
  owner_id = acl.owner&.id.to_s
  grants = acl.grants
  exact_private = !owner_id.empty? && grants.length == 1 &&
    grants.first.permission == "FULL_CONTROL" &&
    grants.first.grantee&.type == "CanonicalUser" &&
    grants.first.grantee&.id.to_s == owner_id
  fail_publish("object ACL is not exact private owner-only") unless exact_private
end

def upload_exact!(helper, relative_path, payload, immutable:)
  object = helper.object(relative_path)
  if immutable && object.exists?
    fail_publish("immutable evidence object bytes differ") unless bounded_read(object) == payload
  else
    temporary = Tempfile.new(["mochirii-recovery-evidence", ".json"])
    begin
      temporary.binmode
      temporary.write(payload)
      temporary.flush
      temporary.rewind
      actual_path, = helper.upload(
        temporary,
        relative_path,
        acl: "private",
        cache_control: "no-store",
        content_type: "application/json",
      )
      fail_publish("uploaded object path differs") unless actual_path == object.key
    ensure
      temporary.close!
    end
  end
  fail_publish("published object is absent") unless object.exists?
  fail_publish("published object readback differs") unless bounded_read(object) == payload
  private_object!(object)
  object.key
end

def bounded_object_digest(object, maximum)
  response = object.get
  digest = Digest::SHA256.new
  size = 0
  while (chunk = response.body.read(64 * 1024))
    size += chunk.bytesize
    fail_publish("release archive object exceeds its byte boundary") if size > maximum
    digest.update(chunk)
  end
  [size, digest.hexdigest]
end

def local_release_archive!(document)
  path = RELEASE_ARCHIVE_PATH
  metadata = File.lstat(path)
  fail_publish("release archive is linked or non-regular") unless metadata.file? && !metadata.symlink?
  fail_publish("release archive size differs") unless metadata.size == document.fetch("releaseArchiveBytes")
  fail_publish("release archive exceeds its byte boundary") if metadata.size > MAX_RELEASE_ARCHIVE_BYTES
  digest = Digest::SHA256.file(path).hexdigest
  fail_publish("release archive digest differs") unless digest == document.fetch("releaseArchiveSha256")
  path
rescue Errno::ENOENT, Errno::EACCES => error
  fail_publish("release archive is unavailable: #{error.class}")
end

def upload_release_archive!(helper, document)
  full_key = document.fetch("releaseArchiveObjectKey")
  relative_path = full_key.delete_prefix("#{EXPECTED_FOLDER}/")
  fail_publish("release archive object path differs") unless
    full_key == "#{EXPECTED_FOLDER}/#{relative_path}" &&
      relative_path == "recovery-releases/archives/#{document.fetch("releaseArchiveSha256")}.tar"
  object = helper.object(relative_path)
  source = local_release_archive!(document)
  unless object.exists?
    File.open(source, "rb") do |archive|
      actual_path, = helper.upload(
        archive,
        relative_path,
        acl: "private",
        cache_control: "no-store",
        content_type: "application/x-tar",
      )
      fail_publish("uploaded release archive path differs") unless actual_path == object.key
    end
  end
  fail_publish("published release archive is absent") unless object.exists?
  size, digest = bounded_object_digest(object, MAX_RELEASE_ARCHIVE_BYTES)
  fail_publish("published release archive size differs") unless size == document.fetch("releaseArchiveBytes")
  fail_publish("published release archive digest differs") unless digest == document.fetch("releaseArchiveSha256")
  private_object!(object)
  object.key
end

encoded = ENV.fetch("MOCHIRII_DR_EVIDENCE_BASE64")
fail_publish("input encoding exceeds its bound") unless encoded.bytesize.between?(16, MAX_DOCUMENT_BYTES * 2)
raw = Base64.strict_decode64(encoded)
fail_publish("input exceeds its byte boundary") if raw.bytesize > MAX_DOCUMENT_BYTES
document = safe_document!(JSON.parse(raw))
payload = canonical(document)
fail_publish("input is not canonical") unless raw == payload

helper = S3Helper.build_from_config(for_backup: true)
fail_publish("backup bucket differs") unless
  helper.s3_bucket_name == EXPECTED_BUCKET && helper.s3_bucket_folder_path == EXPECTED_FOLDER
archive_key = upload_release_archive!(helper, document)
fail_publish("release archive publication key differs") unless archive_key == document.fetch("releaseArchiveObjectKey")
authority_payload = canonical(source_authority(document))
authority_sha = Digest::SHA256.hexdigest(authority_payload)
authority_relative_path = "recovery-releases/authorities/#{authority_sha}.json"
authority_key = upload_exact!(helper, authority_relative_path, authority_payload, immutable: true)
fail_publish("release source authority key differs") unless authority_key == document.fetch("releaseSourceAuthorityObjectKey")
evidence_sha = Digest::SHA256.hexdigest(payload)
relative_evidence_key = "recovery-evidence/records/#{evidence_sha}.json"
evidence_key = upload_exact!(helper, relative_evidence_key, payload, immutable: true)
expected_evidence_key = "#{EXPECTED_FOLDER}/#{relative_evidence_key}"
fail_publish("immutable evidence key differs") unless evidence_key == expected_evidence_key

pointer = {
  "schemaVersion" => 2,
  "repositoryCommit" => document.fetch("repositoryCommit"),
  "repositoryTree" => document.fetch("repositoryTree"),
  "productionConfigurationSha256" => document.fetch("productionConfigurationSha256"),
  "backupFilename" => document.fetch("backupFilename"),
  "backupSha256" => document.fetch("backupSha256"),
  "evidenceObjectKey" => evidence_key,
  "evidenceObjectSha256" => evidence_sha,
  "releaseArchiveObjectKey" => archive_key,
  "releaseArchiveSha256" => document.fetch("releaseArchiveSha256"),
  "releaseArchiveBytes" => document.fetch("releaseArchiveBytes"),
  "releaseArchiveContentManifestSha256" => document.fetch("releaseArchiveContentManifestSha256"),
  "releaseSourceAuthorityObjectKey" => authority_key,
  "releaseSourceAuthoritySha256" => authority_sha,
}
pointer_payload = canonical(pointer)
pointer_sha = Digest::SHA256.hexdigest(pointer_payload)
pointer_key = upload_exact!(helper, POINTER_PATH, pointer_payload, immutable: false)
fail_publish("pointer key differs") unless pointer_key == "#{EXPECTED_FOLDER}/#{POINTER_PATH}"

puts JSON.generate(
  {
    "schemaVersion" => 2,
    "evidenceObjectKey" => evidence_key,
    "evidenceObjectSha256" => evidence_sha,
    "pointerObjectKey" => pointer_key,
    "pointerObjectSha256" => pointer_sha,
    "releaseArchiveObjectKey" => archive_key,
    "releaseArchiveSha256" => document.fetch("releaseArchiveSha256"),
    "releaseArchiveBytes" => document.fetch("releaseArchiveBytes"),
    "releaseSourceAuthorityObjectKey" => authority_key,
    "releaseSourceAuthoritySha256" => authority_sha,
    "immutableEvidencePublished" => true,
    "immutableReleaseArchivePublished" => true,
    "immutableReleaseSourceAuthorityPublished" => true,
    "pointerSelected" => true,
    "privateAclPassed" => true,
  }.sort.to_h,
)
