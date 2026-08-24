# frozen_string_literal: true

# Fetches only the sanitized, digest-bound private recovery pointer/evidence.
# It never generates or prints a signed URL, credential, provider response, or
# member datum. Output is one bounded local schema-3 backup-evidence document.

require "base64"
require "digest"
require "json"

MAX_DOCUMENT_BYTES = 32 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 64 * 1024 * 1024
EXPECTED_BUCKET = "mochirii-forums"
EXPECTED_FOLDER = "backups"
POINTER_PATH = "recovery-evidence/current.json"
RELEASE_ARCHIVE_FORMAT = "git-archive-tar-v1"
HISTORICAL_ADOPTION_SCOPE = "clean-target-disaster-recovery-only"

def fail_fetch(message)
  raise "Disaster-recovery evidence fetch failed: #{message}"
end

def digest?(value, size = 64)
  value.is_a?(String) && value.match?(/\A[0-9a-f]{#{size}}\z/)
end

def canonical(document)
  JSON.generate(document.sort.to_h) + "\n"
end

def recovery_marker_bytes(commit)
  base = Base64.strict_decode64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
  fail_fetch("recovery upload base fixture differs") unless base.bytesize == 34 && base.end_with?(";")
  comment = "mochirii-recovery-#{commit}".b
  fail_fetch("recovery upload comment exceeds its bound") unless comment.bytesize.between?(32, 96)
  base.byteslice(0, base.bytesize - 1) + "!\xFE".b + [comment.bytesize].pack("C") + comment + "\x00;".b
end

def bounded_read(object)
  response = object.get
  bytes = +""
  while (chunk = response.body.read(16 * 1024))
    bytes << chunk
    fail_fetch("object exceeds its byte boundary") if bytes.bytesize > MAX_DOCUMENT_BYTES
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
  fail_fetch("object ACL is not exact private owner-only") unless exact_private
end

fetch_mode = ENV.fetch("MOCHIRII_DR_FETCH_MODE", "current-release")
fail_fetch("fetch mode differs") unless %w[current-release clean-target-historical].include?(fetch_mode)
bootstrap_commit = nil
if fetch_mode == "current-release"
  commit = ENV.fetch("MOCHIRII_REPOSITORY_COMMIT")
  configuration = ENV.fetch("MOCHIRII_PRODUCTION_CONFIGURATION_SHA256")
  fail_fetch("release tuple is malformed") unless digest?(commit, 40) && digest?(configuration)
else
  bootstrap_commit = ENV.fetch("MOCHIRII_DR_BOOTSTRAP_COMMIT")
  fail_fetch("bootstrap release is malformed") unless digest?(bootstrap_commit, 40)
  commit = nil
  configuration = nil
end

helper = S3Helper.build_from_config(for_backup: true)
fail_fetch("backup bucket differs") unless
  helper.s3_bucket_name == EXPECTED_BUCKET && helper.s3_bucket_folder_path == EXPECTED_FOLDER

pointer_object = helper.object(POINTER_PATH)
fail_fetch("recovery pointer is absent") unless pointer_object.exists?
private_object!(pointer_object)
pointer_bytes = bounded_read(pointer_object)
pointer = JSON.parse(pointer_bytes)
pointer_keys = %w[
  schemaVersion repositoryCommit repositoryTree productionConfigurationSha256
  backupFilename backupSha256 evidenceObjectKey evidenceObjectSha256
  releaseArchiveObjectKey releaseArchiveSha256 releaseArchiveBytes
  releaseArchiveContentManifestSha256 releaseSourceAuthorityObjectKey
  releaseSourceAuthoritySha256
]
fail_fetch("pointer schema differs") unless pointer.keys.sort == pointer_keys.sort
fail_fetch("pointer is not canonical") unless pointer_bytes == canonical(pointer)
unless pointer["schemaVersion"] == 2 && digest?(pointer["repositoryCommit"], 40) &&
    digest?(pointer["repositoryTree"], 40) && digest?(pointer["productionConfigurationSha256"]) &&
    pointer["backupFilename"].is_a?(String) && pointer["backupFilename"].bytesize <= 200 &&
    pointer["backupFilename"].match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,190}[.]t?gz\z/) && !pointer["backupFilename"].include?("..") &&
    digest?(pointer["backupSha256"]) && digest?(pointer["evidenceObjectSha256"]) &&
    digest?(pointer["releaseArchiveSha256"]) && digest?(pointer["releaseArchiveContentManifestSha256"]) &&
    digest?(pointer["releaseSourceAuthoritySha256"]) &&
    pointer["releaseArchiveBytes"].is_a?(Integer) && pointer["releaseArchiveBytes"].between?(1, MAX_RELEASE_ARCHIVE_BYTES) &&
    pointer["evidenceObjectKey"] == "#{EXPECTED_FOLDER}/recovery-evidence/records/#{pointer["evidenceObjectSha256"]}.json" &&
    pointer["releaseArchiveObjectKey"] == "#{EXPECTED_FOLDER}/recovery-releases/archives/#{pointer["releaseArchiveSha256"]}.tar" &&
    pointer["releaseSourceAuthorityObjectKey"] == "#{EXPECTED_FOLDER}/recovery-releases/authorities/#{pointer["releaseSourceAuthoritySha256"]}.json"
  fail_fetch("pointer identity differs")
end
if fetch_mode == "current-release"
  fail_fetch("pointer release tuple differs") unless
    pointer["repositoryCommit"] == commit && pointer["productionConfigurationSha256"] == configuration
else
  fail_fetch("historical recovery selector did not select a prior release") if pointer["repositoryCommit"] == bootstrap_commit
  commit = pointer.fetch("repositoryCommit")
  configuration = pointer.fetch("productionConfigurationSha256")
end
relative_evidence_path = pointer["evidenceObjectKey"].delete_prefix("#{EXPECTED_FOLDER}/")
evidence_object = helper.object(relative_evidence_path)
fail_fetch("immutable recovery evidence is absent") unless evidence_object.exists?
private_object!(evidence_object)
evidence_bytes = bounded_read(evidence_object)
fail_fetch("immutable recovery evidence digest differs") unless Digest::SHA256.hexdigest(evidence_bytes) == pointer["evidenceObjectSha256"]
source = JSON.parse(evidence_bytes)
source_keys = %w[
  schemaVersion backupLastModified repositoryCommit repositoryTree productionConfigurationSha256
  backupFilename backupSize backupSha256 backupEvidenceCoreSha256
  normalUploadInventoryCount normalUploadInventorySha256
  releaseEvidenceFile releaseEvidenceSha256 releaseArchiveSha256 releaseArchiveBytes
  releaseArchiveContentManifestSha256 releaseArchiveObjectKey releaseArchiveSourceFormat
  releaseSourceAuthorityObjectKey releaseSourceAuthoritySha256
  restoreConfigurationSha256 themeArchiveSha256 mailMetadataPluginSha256
  discourseDockerRevision discourseRevision dockerManagerRevision baseImageDigest
  discourseConnectEnabled memberRolloutMarkerFile memberRolloutMarkerSha256
  recoveryUploadIncluded recoveryUploadState recoveryUploadStateSha256
  recoveryUploadDeletedAfterBackup anonymousRetrievalDenied anonymousCdnRetrievalDenied
  cleanHostAdoptionRequiresEmptyPersistentData containsSecrets containsSignedUrls
  releaseArchiveContainsSecrets ordinaryDeploymentRequiresCurrentMain
  historicalReleaseAdoptionScope
]
fail_fetch("immutable recovery evidence schema differs") unless source.keys.sort == source_keys.sort
fail_fetch("immutable recovery evidence is not canonical") unless evidence_bytes == canonical(source)
unless source["schemaVersion"] == 2 && source["repositoryCommit"] == commit &&
    source["repositoryTree"] == pointer["repositoryTree"] &&
    source["productionConfigurationSha256"] == configuration && source["backupFilename"] == pointer["backupFilename"] &&
    source["backupSha256"] == pointer["backupSha256"] && source["anonymousRetrievalDenied"] == true &&
    source["anonymousCdnRetrievalDenied"] == true && source["cleanHostAdoptionRequiresEmptyPersistentData"] == true &&
    source["containsSecrets"] == false && source["containsSignedUrls"] == false &&
    source["releaseArchiveContainsSecrets"] == false && source["ordinaryDeploymentRequiresCurrentMain"] == true &&
    source["historicalReleaseAdoptionScope"] == HISTORICAL_ADOPTION_SCOPE
  fail_fetch("immutable recovery evidence safety flags differ")
end
%w[
  productionConfigurationSha256 backupSha256 backupEvidenceCoreSha256 releaseEvidenceSha256
  releaseArchiveSha256 releaseArchiveContentManifestSha256 releaseSourceAuthoritySha256
  restoreConfigurationSha256 themeArchiveSha256 mailMetadataPluginSha256
].each { |key| fail_fetch("#{key} is malformed") unless digest?(source[key]) }
%w[discourseDockerRevision discourseRevision dockerManagerRevision].each do |key|
  fail_fetch("#{key} is malformed") unless digest?(source[key], 40)
end
fail_fetch("base image digest is malformed") unless source["baseImageDigest"].to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
fail_fetch("repository tree is malformed") unless digest?(source["repositoryTree"], 40)
fail_fetch("release archive size is malformed") unless
  source["releaseArchiveBytes"].is_a?(Integer) && source["releaseArchiveBytes"].between?(1, MAX_RELEASE_ARCHIVE_BYTES)
fail_fetch("release archive format differs") unless source["releaseArchiveSourceFormat"] == RELEASE_ARCHIVE_FORMAT
%w[
  repositoryTree releaseArchiveSha256 releaseArchiveBytes releaseArchiveContentManifestSha256
  releaseArchiveObjectKey releaseSourceAuthorityObjectKey releaseSourceAuthoritySha256
].each { |key| fail_fetch("recovery pointer release authority differs") unless source[key] == pointer[key] }
fail_fetch("backup size is malformed") unless source["backupSize"].is_a?(Integer) && source["backupSize"].between?(1, 50 * 1024 * 1024 * 1024)
fail_fetch("normal-upload inventory count is malformed") unless
  source["normalUploadInventoryCount"].is_a?(Integer) &&
    source["normalUploadInventoryCount"].between?(0, 10_000)
fail_fetch("normal-upload inventory digest is malformed") unless digest?(source["normalUploadInventorySha256"])
fail_fetch("backup timestamp is malformed") unless source["backupLastModified"].is_a?(String) && source["backupLastModified"].match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T/)
fail_fetch("release evidence filename differs") unless source["releaseEvidenceFile"] == "#{commit}-#{configuration}-release.json"
fail_fetch("consumer evidence is malformed") unless [true, false].include?(source["discourseConnectEnabled"])
marker_file = source["memberRolloutMarkerFile"]
marker_sha = source["memberRolloutMarkerSha256"]
fail_fetch("member rollout binding is incomplete") unless marker_file.nil? == marker_sha.nil?
if marker_file
  fail_fetch("member rollout binding differs") unless marker_file == "member-rollout-enabled" && digest?(marker_sha)
end
state = source["recoveryUploadState"]
state_keys = %w[
  schemaVersion repositoryCommit uploadId uploadSha1 originalFilename objectPath
  tombstonePath contentSha256 publicUrlSha256
]
if source["recoveryUploadIncluded"] == true
  unless state.is_a?(Hash) && state.keys.sort == state_keys.sort && state["schemaVersion"] == 1 && state["repositoryCommit"] == commit
    fail_fetch("recovery-upload state differs")
  end
  fail_fetch("recovery-upload identifier is malformed") unless state["uploadId"].is_a?(Integer) && state["uploadId"].positive?
  marker_bytes = recovery_marker_bytes(commit)
  marker_sha1 = Digest::SHA1.hexdigest(marker_bytes)
  fail_fetch("recovery-upload SHA-1 differs") unless state["uploadSha1"] == marker_sha1
  fail_fetch("recovery-upload content digest differs") unless state["contentSha256"] == Digest::SHA256.hexdigest(marker_bytes)
  fail_fetch("recovery-upload filename differs") unless state["originalFilename"] == "mochirii-recovery-#{commit[0, 12]}.gif"
  object_path = state["objectPath"].to_s
  fail_fetch("recovery-upload object path differs") unless object_path.match?(%r{\Aoriginal/[1-9][0-9]*X/(?:[0-9a-f]/)*#{marker_sha1}[.]gif\z})
  fail_fetch("recovery-upload tombstone path differs") unless state["tombstonePath"] == "tombstone/#{object_path}"
  fail_fetch("recovery-upload URL digest is malformed") unless digest?(state["publicUrlSha256"])
  state_bytes = JSON.generate(state.sort.to_h) + "\n"
  fail_fetch("recovery-upload state digest differs") unless digest?(source["recoveryUploadStateSha256"]) && Digest::SHA256.hexdigest(state_bytes) == source["recoveryUploadStateSha256"]
  fail_fetch("recovery upload was not deleted after backup") unless source["recoveryUploadDeletedAfterBackup"] == true
elsif source["recoveryUploadIncluded"] == false
  fail_fetch("clean backup retained recovery-upload identity") unless state.nil? && source["recoveryUploadStateSha256"].nil? && source["recoveryUploadDeletedAfterBackup"] == false
else
  fail_fetch("recovery-upload inclusion flag is malformed")
end

authority_relative_path = pointer["releaseSourceAuthorityObjectKey"].delete_prefix("#{EXPECTED_FOLDER}/")
authority_object = helper.object(authority_relative_path)
fail_fetch("immutable release source authority is absent") unless authority_object.exists?
private_object!(authority_object)
authority_bytes = bounded_read(authority_object)
fail_fetch("release source authority digest differs") unless
  Digest::SHA256.hexdigest(authority_bytes) == pointer["releaseSourceAuthoritySha256"]
authority = JSON.parse(authority_bytes)
authority_keys = %w[
  schemaVersion repository repositoryCommit repositoryTree productionConfigurationSha256
  releaseArchiveSha256 releaseArchiveBytes releaseArchiveContentManifestSha256
  releaseArchiveObjectKey releaseArchiveSourceFormat containsSecrets containsSignedUrls
  ordinaryDeploymentRequiresCurrentMain historicalReleaseAdoptionScope
]
fail_fetch("release source authority schema differs") unless authority.keys.sort == authority_keys.sort
fail_fetch("release source authority is not canonical") unless authority_bytes == canonical(authority)
expected_authority = {
  "schemaVersion" => 1,
  "repository" => "Mochirii-Wushu/Mochirii-Forums",
  "repositoryCommit" => commit,
  "repositoryTree" => source["repositoryTree"],
  "productionConfigurationSha256" => configuration,
  "releaseArchiveSha256" => source["releaseArchiveSha256"],
  "releaseArchiveBytes" => source["releaseArchiveBytes"],
  "releaseArchiveContentManifestSha256" => source["releaseArchiveContentManifestSha256"],
  "releaseArchiveObjectKey" => source["releaseArchiveObjectKey"],
  "releaseArchiveSourceFormat" => RELEASE_ARCHIVE_FORMAT,
  "containsSecrets" => false,
  "containsSignedUrls" => false,
  "ordinaryDeploymentRequiresCurrentMain" => true,
  "historicalReleaseAdoptionScope" => HISTORICAL_ADOPTION_SCOPE,
}
fail_fetch("release source authority differs") unless authority == expected_authority

archive_relative_path = pointer["releaseArchiveObjectKey"].delete_prefix("#{EXPECTED_FOLDER}/")
archive_object = helper.object(archive_relative_path)
fail_fetch("immutable historical release archive is absent") unless archive_object.exists?
private_object!(archive_object)

core_document = {
  "schemaVersion" => 3,
  "repositoryCommit" => commit,
  "productionConfigurationSha256" => configuration,
  "filename" => source["backupFilename"],
  "size" => source["backupSize"],
  "sha256" => source["backupSha256"],
  "lastModified" => source["backupLastModified"],
  "privateAdminRetrievalUrlPresent" => true,
  "anonymousRetrievalDenied" => true,
  "anonymousCdnRetrievalDenied" => true,
  "backupPrefix" => "backups/",
  "normalUploadInventoryCount" => source["normalUploadInventoryCount"],
  "normalUploadInventorySha256" => source["normalUploadInventorySha256"],
  "restoreConfigurationSha256" => source["restoreConfigurationSha256"],
  "themeArchiveSha256" => source["themeArchiveSha256"],
  "mailMetadataPluginSha256" => source["mailMetadataPluginSha256"],
  "releaseEvidenceFile" => source["releaseEvidenceFile"],
  "releaseEvidenceSha256" => source["releaseEvidenceSha256"],
  "discourseDockerRevision" => source["discourseDockerRevision"],
  "discourseRevision" => source["discourseRevision"],
  "dockerManagerRevision" => source["dockerManagerRevision"],
  "baseImageDigest" => source["baseImageDigest"],
  "discourseConnectEnabled" => source["discourseConnectEnabled"],
  "memberRolloutMarkerFile" => marker_file,
  "memberRolloutMarkerSha256" => marker_sha,
  "recoveryUploadIncluded" => source["recoveryUploadIncluded"],
  "recoveryUploadState" => state,
  "recoveryUploadStateSha256" => source["recoveryUploadStateSha256"],
  "recoveryUploadDeletedAfterBackup" => source["recoveryUploadDeletedAfterBackup"],
}
core_bytes = JSON.pretty_generate(core_document.sort.to_h) + "\n"
fail_fetch("backup core evidence digest differs") unless Digest::SHA256.hexdigest(core_bytes) == source["backupEvidenceCoreSha256"]

document = {
  **core_document,
  "disasterRecoveryImported" => true,
  "disasterRecoveryFetchMode" => fetch_mode,
  "disasterRecoveryBootstrapCommit" => bootstrap_commit,
  "disasterRecoveryEvidenceObjectKey" => pointer["evidenceObjectKey"],
  "disasterRecoveryEvidenceObjectSha256" => pointer["evidenceObjectSha256"],
  "disasterRecoveryPointerObjectKey" => "#{EXPECTED_FOLDER}/#{POINTER_PATH}",
  "disasterRecoveryPointerObjectSha256" => Digest::SHA256.hexdigest(pointer_bytes),
  "disasterRecoveryRepositoryTree" => source["repositoryTree"],
  "disasterRecoveryReleaseArchiveObjectKey" => source["releaseArchiveObjectKey"],
  "disasterRecoveryReleaseArchiveSha256" => source["releaseArchiveSha256"],
  "disasterRecoveryReleaseArchiveBytes" => source["releaseArchiveBytes"],
  "disasterRecoveryReleaseArchiveContentManifestSha256" => source["releaseArchiveContentManifestSha256"],
  "disasterRecoveryReleaseArchiveSourceFormat" => source["releaseArchiveSourceFormat"],
  "disasterRecoveryReleaseSourceAuthorityObjectKey" => pointer["releaseSourceAuthorityObjectKey"],
  "disasterRecoveryReleaseSourceAuthoritySha256" => pointer["releaseSourceAuthoritySha256"],
  "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain" => true,
  "disasterRecoveryHistoricalReleaseAdoptionScope" => HISTORICAL_ADOPTION_SCOPE,
  "disasterRecoveryPrivateAclPassed" => true,
}
output = JSON.pretty_generate(document.sort.to_h) + "\n"
fail_fetch("reconstructed backup evidence exceeds its byte boundary") if output.bytesize > MAX_DOCUMENT_BYTES
$stdout.write(output)
