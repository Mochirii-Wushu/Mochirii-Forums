# frozen_string_literal: true

# In-memory private-object fixture for the release archive -> authority ->
# evidence -> selector -> historical fetch chain. The caller mounts any
# bounded fixture bytes at /opt/mochirii-release/mochirii-release.tar.

require "base64"
require "digest"
require "json"
require "stringio"

ROOT = File.expand_path("..", __dir__)
ARCHIVE_PATH = "/opt/mochirii-release/mochirii-release.tar"

Owner = Struct.new(:id)
Grantee = Struct.new(:type, :id)
Grant = Struct.new(:permission, :grantee)
Acl = Struct.new(:owner, :grants)
Response = Struct.new(:body)

class FixtureObject
  attr_reader :key

  def initialize(key)
    @key = key
  end

  def exists?
    $fixture_objects.key?(key)
  end

  def get
    raise "fixture object absent" unless exists?
    Response.new(StringIO.new($fixture_objects.fetch(key)))
  end

  def acl
    owner = Owner.new("fixture-canonical-owner")
    Acl.new(owner, [Grant.new("FULL_CONTROL", Grantee.new("CanonicalUser", owner.id))])
  end
end

class S3Helper
  attr_reader :s3_bucket_name, :s3_bucket_folder_path

  def self.build_from_config(for_backup:)
    raise "fixture requires backup storage" unless for_backup
    new
  end

  def initialize
    @s3_bucket_name = "mochirii-forums"
    @s3_bucket_folder_path = "backups"
  end

  def object(relative)
    FixtureObject.new("backups/#{relative}")
  end

  def upload(source, relative, acl:, cache_control:, content_type:)
    raise "fixture upload ACL differs" unless acl == "private" && cache_control == "no-store"
    raise "fixture content type differs" unless %w[application/json application/x-tar].include?(content_type)
    source.rewind if source.respond_to?(:rewind)
    key = "backups/#{relative}"
    $fixture_objects[key] = source.read
    [key, nil]
  end
end

def canonical(value)
  JSON.generate(value.sort.to_h) + "\n"
end

def capture_load(path)
  previous = $stdout
  stream = StringIO.new
  $stdout = stream
  load(path, true)
  stream.string
ensure
  $stdout = previous
end

archive = File.binread(ARCHIVE_PATH)
raise "fixture release archive is empty" if archive.empty?
archive_sha = Digest::SHA256.hexdigest(archive)
commit = "1" * 40
bootstrap = "2" * 40
tree = "3" * 40
configuration = "4" * 64
restore_configuration = "5" * 64
manifest_sha = "6" * 64
authority = {
  "schemaVersion" => 1,
  "repository" => "Mochirii-Wushu/Mochirii-Forums",
  "repositoryCommit" => commit,
  "repositoryTree" => tree,
  "productionConfigurationSha256" => configuration,
  "releaseArchiveSha256" => archive_sha,
  "releaseArchiveBytes" => archive.bytesize,
  "releaseArchiveContentManifestSha256" => manifest_sha,
  "releaseArchiveObjectKey" => "backups/recovery-releases/archives/#{archive_sha}.tar",
  "releaseArchiveSourceFormat" => "git-archive-tar-v1",
  "containsSecrets" => false,
  "containsSignedUrls" => false,
  "ordinaryDeploymentRequiresCurrentMain" => true,
  "historicalReleaseAdoptionScope" => "clean-target-disaster-recovery-only",
}
authority_sha = Digest::SHA256.hexdigest(canonical(authority))
core = {
  "schemaVersion" => 3,
  "repositoryCommit" => commit,
  "productionConfigurationSha256" => configuration,
  "filename" => "fixture-backup.tar.gz",
  "size" => 4096,
  "sha256" => "7" * 64,
  "lastModified" => "2026-08-20T00:00:00Z",
  "privateAdminRetrievalUrlPresent" => true,
  "anonymousRetrievalDenied" => true,
  "anonymousCdnRetrievalDenied" => true,
  "backupPrefix" => "backups/",
  "normalUploadInventoryCount" => 0,
  "normalUploadInventorySha256" => "8" * 64,
  "restoreConfigurationSha256" => restore_configuration,
  "themeArchiveSha256" => "9" * 64,
  "mailMetadataPluginSha256" => "a" * 64,
  "releaseEvidenceFile" => "#{commit}-#{configuration}-release.json",
  "releaseEvidenceSha256" => "b" * 64,
  "discourseDockerRevision" => "c" * 40,
  "discourseRevision" => "d" * 40,
  "dockerManagerRevision" => "e" * 40,
  "baseImageDigest" => "sha256:#{"f" * 64}",
  "discourseConnectEnabled" => false,
  "memberRolloutMarkerFile" => nil,
  "memberRolloutMarkerSha256" => nil,
  "recoveryUploadIncluded" => false,
  "recoveryUploadState" => nil,
  "recoveryUploadStateSha256" => nil,
  "recoveryUploadDeletedAfterBackup" => false,
}
core_sha = Digest::SHA256.hexdigest(JSON.pretty_generate(core.sort.to_h) + "\n")
document = {
  "schemaVersion" => 2,
  "backupLastModified" => core.fetch("lastModified"),
  "repositoryCommit" => commit,
  "repositoryTree" => tree,
  "productionConfigurationSha256" => configuration,
  "backupFilename" => core.fetch("filename"),
  "backupSize" => core.fetch("size"),
  "backupSha256" => core.fetch("sha256"),
  "backupEvidenceCoreSha256" => core_sha,
  "normalUploadInventoryCount" => core.fetch("normalUploadInventoryCount"),
  "normalUploadInventorySha256" => core.fetch("normalUploadInventorySha256"),
  "releaseEvidenceFile" => core.fetch("releaseEvidenceFile"),
  "releaseEvidenceSha256" => core.fetch("releaseEvidenceSha256"),
  "releaseArchiveSha256" => archive_sha,
  "releaseArchiveBytes" => archive.bytesize,
  "releaseArchiveContentManifestSha256" => manifest_sha,
  "releaseArchiveObjectKey" => authority.fetch("releaseArchiveObjectKey"),
  "releaseArchiveSourceFormat" => "git-archive-tar-v1",
  "releaseSourceAuthorityObjectKey" => "backups/recovery-releases/authorities/#{authority_sha}.json",
  "releaseSourceAuthoritySha256" => authority_sha,
  "restoreConfigurationSha256" => restore_configuration,
  "themeArchiveSha256" => core.fetch("themeArchiveSha256"),
  "mailMetadataPluginSha256" => core.fetch("mailMetadataPluginSha256"),
  "discourseDockerRevision" => core.fetch("discourseDockerRevision"),
  "discourseRevision" => core.fetch("discourseRevision"),
  "dockerManagerRevision" => core.fetch("dockerManagerRevision"),
  "baseImageDigest" => core.fetch("baseImageDigest"),
  "discourseConnectEnabled" => false,
  "memberRolloutMarkerFile" => nil,
  "memberRolloutMarkerSha256" => nil,
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

$fixture_objects = {}
ENV["MOCHIRII_DR_EVIDENCE_BASE64"] = Base64.strict_encode64(canonical(document))
publication = JSON.parse(capture_load(File.join(ROOT, "scripts", "publish-disaster-recovery-evidence.rb")))
unless publication["immutableReleaseArchivePublished"] == true &&
    publication["immutableReleaseSourceAuthorityPublished"] == true &&
    publication["releaseArchiveSha256"] == archive_sha &&
    publication["releaseSourceAuthoritySha256"] == authority_sha
  raise "fixture publication chain is incomplete"
end

ENV.delete("MOCHIRII_DR_EVIDENCE_BASE64")
ENV["MOCHIRII_DR_FETCH_MODE"] = "clean-target-historical"
ENV["MOCHIRII_DR_BOOTSTRAP_COMMIT"] = bootstrap
receipt_bytes = capture_load(File.join(ROOT, "scripts", "fetch-disaster-recovery-evidence.rb"))
receipt = JSON.parse(receipt_bytes)
unless receipt["repositoryCommit"] == commit &&
    receipt["disasterRecoveryBootstrapCommit"] == bootstrap &&
    receipt["disasterRecoveryReleaseArchiveSha256"] == archive_sha &&
    receipt["disasterRecoveryReleaseSourceAuthoritySha256"] == authority_sha
  raise "fixture historical receipt differs"
end

ENV.delete("MOCHIRII_DR_FETCH_MODE")
ENV.delete("MOCHIRII_DR_BOOTSTRAP_COMMIT")
ENV["MOCHIRII_DR_FETCH_RECEIPT_BASE64"] = Base64.strict_encode64(receipt_bytes)
fetched_archive = capture_load(File.join(ROOT, "scripts", "fetch-disaster-recovery-release.rb"))
raise "fixture fetched archive differs" unless fetched_archive.b == archive

# An archive mutation under the same selector fails before any byte is emitted.
$fixture_objects[authority.fetch("releaseArchiveObjectKey")] = archive + "tampered"
begin
  capture_load(File.join(ROOT, "scripts", "fetch-disaster-recovery-release.rb"))
rescue RuntimeError
  nil
else
  raise "fixture accepted a mutated historical release object"
end

puts "Private disaster-recovery release publication and fetch chain passed."
