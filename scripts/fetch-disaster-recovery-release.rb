# frozen_string_literal: true

# Fetches one exact historical, secret-free release archive selected by a
# previously validated clean-target disaster-recovery receipt. The archive is
# fully spooled and digest-verified before any byte reaches stdout. It never
# creates or prints a signed URL, credential, provider response, or member datum.

require "base64"
require "digest"
require "json"
require "tempfile"

MAX_RECEIPT_BYTES = 64 * 1024
MAX_DOCUMENT_BYTES = 32 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 64 * 1024 * 1024
EXPECTED_BUCKET = "mochirii-forums"
EXPECTED_FOLDER = "backups"
POINTER_PATH = "recovery-evidence/current.json"
RELEASE_ARCHIVE_FORMAT = "git-archive-tar-v1"
HISTORICAL_ADOPTION_SCOPE = "clean-target-disaster-recovery-only"

def fail_release_fetch(message)
  raise "Historical disaster-recovery release fetch failed: #{message}"
end

def digest?(value, size = 64)
  value.is_a?(String) && value.match?(/\A[0-9a-f]{#{size}}\z/)
end

def canonical(document)
  JSON.generate(document.sort.to_h) + "\n"
end

def bounded_read(object)
  response = object.get
  bytes = +""
  while (chunk = response.body.read(16 * 1024))
    bytes << chunk
    fail_release_fetch("object exceeds its document byte boundary") if bytes.bytesize > MAX_DOCUMENT_BYTES
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
  fail_release_fetch("object ACL is not exact private owner-only") unless exact_private
end

encoded = ENV.fetch("MOCHIRII_DR_FETCH_RECEIPT_BASE64")
fail_release_fetch("receipt encoding exceeds its bound") unless encoded.bytesize.between?(16, MAX_RECEIPT_BYTES * 2)
receipt_bytes = Base64.strict_decode64(encoded)
fail_release_fetch("receipt exceeds its byte boundary") if receipt_bytes.bytesize > MAX_RECEIPT_BYTES
receipt = JSON.parse(receipt_bytes)
required_receipt = %w[
  schemaVersion repositoryCommit productionConfigurationSha256 filename size sha256 lastModified
  privateAdminRetrievalUrlPresent anonymousRetrievalDenied anonymousCdnRetrievalDenied
  backupPrefix normalUploadInventoryCount normalUploadInventorySha256
  restoreConfigurationSha256 themeArchiveSha256 mailMetadataPluginSha256
  releaseEvidenceFile releaseEvidenceSha256 discourseDockerRevision discourseRevision
  dockerManagerRevision baseImageDigest discourseConnectEnabled memberRolloutMarkerFile
  memberRolloutMarkerSha256 recoveryUploadIncluded recoveryUploadState
  recoveryUploadStateSha256 recoveryUploadDeletedAfterBackup disasterRecoveryImported
  disasterRecoveryFetchMode disasterRecoveryBootstrapCommit
  disasterRecoveryEvidenceObjectKey disasterRecoveryEvidenceObjectSha256
  disasterRecoveryPointerObjectKey disasterRecoveryPointerObjectSha256
  disasterRecoveryRepositoryTree disasterRecoveryReleaseArchiveObjectKey
  disasterRecoveryReleaseArchiveSha256 disasterRecoveryReleaseArchiveBytes
  disasterRecoveryReleaseArchiveContentManifestSha256
  disasterRecoveryReleaseArchiveSourceFormat
  disasterRecoveryReleaseSourceAuthorityObjectKey
  disasterRecoveryReleaseSourceAuthoritySha256
  disasterRecoveryOrdinaryDeploymentRequiresCurrentMain
  disasterRecoveryHistoricalReleaseAdoptionScope disasterRecoveryPrivateAclPassed
]
fail_release_fetch("receipt schema differs") unless receipt.is_a?(Hash) && receipt.keys.sort == required_receipt.sort
commit = receipt["repositoryCommit"]
configuration = receipt["productionConfigurationSha256"]
bootstrap_commit = receipt["disasterRecoveryBootstrapCommit"]
archive_sha = receipt["disasterRecoveryReleaseArchiveSha256"]
archive_size = receipt["disasterRecoveryReleaseArchiveBytes"]
authority_sha = receipt["disasterRecoveryReleaseSourceAuthoritySha256"]
unless receipt["schemaVersion"] == 3 && digest?(commit, 40) && digest?(configuration) &&
    digest?(bootstrap_commit, 40) && bootstrap_commit != commit &&
    receipt["disasterRecoveryImported"] == true && receipt["disasterRecoveryFetchMode"] == "clean-target-historical" &&
    receipt["disasterRecoveryPrivateAclPassed"] == true &&
    receipt["disasterRecoveryOrdinaryDeploymentRequiresCurrentMain"] == true &&
    receipt["disasterRecoveryHistoricalReleaseAdoptionScope"] == HISTORICAL_ADOPTION_SCOPE &&
    digest?(receipt["disasterRecoveryRepositoryTree"], 40) && digest?(archive_sha) &&
    digest?(receipt["disasterRecoveryReleaseArchiveContentManifestSha256"]) &&
    digest?(authority_sha) && archive_size.is_a?(Integer) && archive_size.between?(1, MAX_RELEASE_ARCHIVE_BYTES) &&
    receipt["disasterRecoveryReleaseArchiveSourceFormat"] == RELEASE_ARCHIVE_FORMAT &&
    receipt["disasterRecoveryPointerObjectKey"] == "#{EXPECTED_FOLDER}/#{POINTER_PATH}" &&
    receipt["disasterRecoveryReleaseArchiveObjectKey"] == "#{EXPECTED_FOLDER}/recovery-releases/archives/#{archive_sha}.tar" &&
    receipt["disasterRecoveryReleaseSourceAuthorityObjectKey"] == "#{EXPECTED_FOLDER}/recovery-releases/authorities/#{authority_sha}.json"
  fail_release_fetch("receipt release authority differs")
end

helper = S3Helper.build_from_config(for_backup: true)
fail_release_fetch("backup bucket differs") unless
  helper.s3_bucket_name == EXPECTED_BUCKET && helper.s3_bucket_folder_path == EXPECTED_FOLDER

pointer_object = helper.object(POINTER_PATH)
fail_release_fetch("recovery pointer is absent") unless pointer_object.exists?
private_object!(pointer_object)
pointer_bytes = bounded_read(pointer_object)
fail_release_fetch("recovery pointer digest changed after receipt validation") unless
  Digest::SHA256.hexdigest(pointer_bytes) == receipt["disasterRecoveryPointerObjectSha256"]
pointer = JSON.parse(pointer_bytes)
pointer_keys = %w[
  schemaVersion repositoryCommit repositoryTree productionConfigurationSha256
  backupFilename backupSha256 evidenceObjectKey evidenceObjectSha256
  releaseArchiveObjectKey releaseArchiveSha256 releaseArchiveBytes
  releaseArchiveContentManifestSha256 releaseSourceAuthorityObjectKey
  releaseSourceAuthoritySha256
]
fail_release_fetch("pointer schema differs") unless pointer.keys.sort == pointer_keys.sort && pointer_bytes == canonical(pointer)
pointer_expected = {
  "schemaVersion" => 2,
  "repositoryCommit" => commit,
  "repositoryTree" => receipt["disasterRecoveryRepositoryTree"],
  "productionConfigurationSha256" => configuration,
  "backupFilename" => receipt["filename"],
  "backupSha256" => receipt["sha256"],
  "evidenceObjectKey" => receipt["disasterRecoveryEvidenceObjectKey"],
  "evidenceObjectSha256" => receipt["disasterRecoveryEvidenceObjectSha256"],
  "releaseArchiveObjectKey" => receipt["disasterRecoveryReleaseArchiveObjectKey"],
  "releaseArchiveSha256" => archive_sha,
  "releaseArchiveBytes" => archive_size,
  "releaseArchiveContentManifestSha256" => receipt["disasterRecoveryReleaseArchiveContentManifestSha256"],
  "releaseSourceAuthorityObjectKey" => receipt["disasterRecoveryReleaseSourceAuthorityObjectKey"],
  "releaseSourceAuthoritySha256" => authority_sha,
}
fail_release_fetch("pointer differs from the validated receipt") unless pointer == pointer_expected

authority_relative = receipt["disasterRecoveryReleaseSourceAuthorityObjectKey"].delete_prefix("#{EXPECTED_FOLDER}/")
authority_object = helper.object(authority_relative)
fail_release_fetch("release source authority is absent") unless authority_object.exists?
private_object!(authority_object)
authority_bytes = bounded_read(authority_object)
fail_release_fetch("release source authority digest differs") unless Digest::SHA256.hexdigest(authority_bytes) == authority_sha
authority = JSON.parse(authority_bytes)
authority_keys = %w[
  schemaVersion repository repositoryCommit repositoryTree productionConfigurationSha256
  releaseArchiveSha256 releaseArchiveBytes releaseArchiveContentManifestSha256
  releaseArchiveObjectKey releaseArchiveSourceFormat containsSecrets containsSignedUrls
  ordinaryDeploymentRequiresCurrentMain historicalReleaseAdoptionScope
]
expected_authority = {
  "schemaVersion" => 1,
  "repository" => "Mochirii-Wushu/Mochirii-Forums",
  "repositoryCommit" => commit,
  "repositoryTree" => receipt["disasterRecoveryRepositoryTree"],
  "productionConfigurationSha256" => configuration,
  "releaseArchiveSha256" => archive_sha,
  "releaseArchiveBytes" => archive_size,
  "releaseArchiveContentManifestSha256" => receipt["disasterRecoveryReleaseArchiveContentManifestSha256"],
  "releaseArchiveObjectKey" => receipt["disasterRecoveryReleaseArchiveObjectKey"],
  "releaseArchiveSourceFormat" => RELEASE_ARCHIVE_FORMAT,
  "containsSecrets" => false,
  "containsSignedUrls" => false,
  "ordinaryDeploymentRequiresCurrentMain" => true,
  "historicalReleaseAdoptionScope" => HISTORICAL_ADOPTION_SCOPE,
}
fail_release_fetch("release source authority differs") unless
  authority.keys.sort == authority_keys.sort && authority_bytes == canonical(authority) && authority == expected_authority

archive_relative = receipt["disasterRecoveryReleaseArchiveObjectKey"].delete_prefix("#{EXPECTED_FOLDER}/")
archive_object = helper.object(archive_relative)
fail_release_fetch("historical release archive is absent") unless archive_object.exists?
private_object!(archive_object)

temporary = Tempfile.new(["mochirii-historical-release", ".tar"])
begin
  temporary.binmode
  response = archive_object.get
  digest = Digest::SHA256.new
  size = 0
  while (chunk = response.body.read(64 * 1024))
    size += chunk.bytesize
    fail_release_fetch("historical release archive exceeds its byte boundary") if size > MAX_RELEASE_ARCHIVE_BYTES
    digest.update(chunk)
    temporary.write(chunk)
  end
  temporary.flush
  fail_release_fetch("historical release archive size differs") unless size == archive_size
  fail_release_fetch("historical release archive digest differs") unless digest.hexdigest == archive_sha
  temporary.rewind
  $stdout.binmode
  IO.copy_stream(temporary, $stdout)
ensure
  temporary.close!
end
