# frozen_string_literal: true

# Hosted, disposable object-storage contract fixture. This script is copied
# into the immutable release assets and is invoked only through the protected
# host deployer. Its JSON output is captured inside the root-only evidence
# boundary; it never prints object keys, URLs, credentials, or member data.

require "digest"
require "json"
require "net/http"
require "openssl"
require "stringio"
require "tempfile"
require "uri"
require "zlib"
require_relative "storage-response-boundary"

EXPECTED_MEDIA_ORIGIN = "https://media-forums.mochirii.com"
EXPECTED_BUCKET = "mochirii-forums"
EXPECTED_ENDPOINT = "https://sgp1.digitaloceanspaces.com"
FIXTURE_FILENAME = "mochirii-hosted-storage-fixture.png"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TRANSACTION_NAMESPACE = "mochirii-hosted-storage"
TRANSACTION_KEY_PREFIX = "fixture-transaction:"
TRANSACTION_JOURNAL_KEYS = %w[
  schemaVersion repositoryCommit productionConfigurationSha256 cleanupOnly
  transactionId pluginStoreNamespace pluginStoreKey phase
].freeze
TRANSACTION_STATE_KEYS = %w[
  schemaVersion repositoryCommit productionConfigurationSha256 transactionId
  pluginStoreNamespace pluginStoreKey uploadOrigin uploadSha1 originalFilename
  phase uploadId originalKey optimizedImageIds optimizedKeys
].freeze

def fail_fixture(message)
  raise "Hosted storage fixture failed: #{message}"
end

def validate_identity!
  commit = ARGV.fetch(1)
  configuration = ARGV.fetch(2)
  fail_fixture("repository commit is malformed") unless commit.match?(/\A[0-9a-f]{40}\z/)
  fail_fixture("configuration digest is malformed") unless configuration.match?(/\A[0-9a-f]{64}\z/)
  fail_fixture("running repository commit differs") unless ENV["MOCHIRII_REPOSITORY_COMMIT"] == commit
  fail_fixture("external object store is inactive") unless Discourse.store.is_a?(FileStore::S3Store)
  fail_fixture("upload storage is inactive") unless SiteSetting.enable_s3_uploads
  fail_fixture("secure uploads are enabled") if SiteSetting.secure_uploads
  fail_fixture("upload bucket differs") unless SiteSetting.s3_upload_bucket == EXPECTED_BUCKET
  fail_fixture("object-storage endpoint differs") unless SiteSetting.s3_endpoint == EXPECTED_ENDPOINT
  fail_fixture("custom media hostname differs") unless SiteSetting.s3_cdn_url == EXPECTED_MEDIA_ORIGIN
  fail_fixture("custom media hostname is not enforced") unless SiteSetting.s3_use_cdn_url_for_all_uploads
  fail_fixture("object ACLs are disabled") unless SiteSetting.s3_use_acls
  fail_fixture("direct uploads are enabled") if SiteSetting.enable_direct_s3_uploads
  fail_fixture("automatic CORS installation is enabled") if SiteSetting.s3_install_cors_rule
  fail_fixture("tombstone lifecycle mutation is enabled") if SiteSetting.s3_configure_tombstone_policy
  [commit, configuration]
end

def png_bytes(commit, configuration, transaction_id = nil)
  suffix = transaction_id ? "#{transaction_id}:mochirii-hosted-storage-v2" : "mochirii-hosted-storage-v1"
  seed = Digest::SHA256.digest("#{commit}:#{configuration}:#{suffix}")
  width = 256
  height = 256
  raw = String.new(capacity: height * (width * 3 + 1), encoding: Encoding::BINARY)
  height.times do |y|
    raw << "\x00"
    width.times do |x|
      offset = (x * 7 + y * 13) % seed.bytesize
      raw << seed.getbyte(offset).chr << seed.getbyte((offset + 11) % seed.bytesize).chr << seed.getbyte((offset + 23) % seed.bytesize).chr
    end
  end
  chunk = lambda do |type, payload|
    type_and_payload = type.b + payload
    [payload.bytesize].pack("N") + type_and_payload + [Zlib.crc32(type_and_payload)].pack("N")
  end
  "\x89PNG\r\n\x1a\n".b +
    chunk.call("IHDR", [width, height, 8, 2, 0, 0, 0].pack("NNC5")) +
    chunk.call("IDAT", Zlib::Deflate.deflate(raw, Zlib::BEST_COMPRESSION)) +
    chunk.call("IEND", "".b)
end

def canonical_public_uri(value, exact_family)
  MochiriiStorageResponseBoundary.canonical_public_uri(value, exact_family)
rescue MochiriiStorageResponseBoundary::InvalidMediaUrl => error
  fail_fixture(error.message)
end

def bounded_anonymous_get(uri, expected_statuses: [200], public_media: true)
  request = Net::HTTP::Get.new(uri.request_uri)
  response = nil
  body = nil
  Net::HTTP.start(
    uri.host,
    uri.port,
    use_ssl: true,
    verify_mode: OpenSSL::SSL::VERIFY_PEER,
    open_timeout: 10,
    read_timeout: 20,
  ) do |http|
    http.request(request) do |candidate|
      response = candidate
      fail_fixture("anonymous HTTP status differs") unless expected_statuses.include?(candidate.code.to_i)
      fail_fixture("anonymous HTTP redirect was returned") if candidate.is_a?(Net::HTTPRedirection)
      body = MochiriiStorageResponseBoundary.read(
        candidate,
        MAX_RESPONSE_BYTES,
        validate_public_metadata: public_media,
      )
    end
  end
  fail_fixture("anonymous HTTP response was absent") unless response
  fail_fixture("anonymous HTTP response body was absent") unless body
  fail_fixture("anonymous HTTP status differs") unless expected_statuses.include?(response.code.to_i)
  fail_fixture("anonymous HTTP redirect was returned") if response.is_a?(Net::HTTPRedirection)
  [response, body]
rescue MochiriiStorageResponseBoundary::ResponseTooLarge, MochiriiStorageResponseBoundary::InvalidMediaMetadata => error
  fail_fixture(error.message)
end

def object_public_read?(object)
  object.acl.grants.any? do |grant|
    grant.permission == "READ" && grant.grantee&.type == "Group" &&
      grant.grantee&.uri.to_s.end_with?("/AllUsers")
  end
end

def object_exists?(helper, key)
  helper.object(key).exists?
end

def original_key(store, upload)
  store.get_path_for_upload(upload)
end

def owned_origin(commit, configuration, transaction_id = nil)
  suffix = transaction_id ? ":#{transaction_id}" : ""
  "mochirii-hosted-storage-fixture:#{commit}:#{configuration}#{suffix}"
end

def safe_object_key!(value, family)
  fail_fixture("fixture object key is malformed") unless value.is_a?(String) &&
    value.match?(%r{\A#{family}/[A-Za-z0-9._/-]{1,900}\z}) &&
    !value.split("/").any? { |part| part.empty? || part == "." || part == ".." }
  value
end

def optimized_key(store, optimized)
  store.get_path_for_optimized_image(optimized)
end

def load_state(commit, configuration)
  document = JSON.parse($stdin.read)
  expected_keys = %w[
    schemaVersion repositoryCommit productionConfigurationSha256 transactionId
    pluginStoreNamespace pluginStoreKey uploadOrigin uploadId
    optimizedImageId uploadSha1 originalKeySha256 optimizedKeySha256
    originalKey optimizedKey originalUrlSha256 optimizedUrlSha256
    originalContentSha256 optimizedContentSha256
  ]
  fail_fixture("state keys differ") unless document.is_a?(Hash) && document.keys.sort == expected_keys.sort
  fail_fixture("state schema differs") unless document["schemaVersion"] == 4
  fail_fixture("state repository commit differs") unless document["repositoryCommit"] == commit
  fail_fixture("state configuration digest differs") unless document["productionConfigurationSha256"] == configuration
  transaction_id = document["transactionId"].to_s
  fail_fixture("state transaction identifier is malformed") unless transaction_id.match?(/\A[0-9a-f]{32}\z/)
  fail_fixture("state transaction namespace differs") unless document["pluginStoreNamespace"] == TRANSACTION_NAMESPACE
  fail_fixture("state transaction key differs") unless document["pluginStoreKey"] == "#{TRANSACTION_KEY_PREFIX}#{transaction_id}"
  fail_fixture("state upload ownership differs") unless document["uploadOrigin"] == owned_origin(commit, configuration, transaction_id)
  fail_fixture("state upload identifier is malformed") unless document["uploadId"].is_a?(Integer) && document["uploadId"].positive?
  fail_fixture("state optimized identifier is malformed") unless document["optimizedImageId"].is_a?(Integer) && document["optimizedImageId"].positive?
  fail_fixture("state upload digest differs") unless document["uploadSha1"] == Digest::SHA1.hexdigest(png_bytes(commit, configuration, transaction_id))
  safe_object_key!(document["originalKey"], "original")
  safe_object_key!(document["optimizedKey"], "optimized")
  fail_fixture("state original-key binding differs") unless
    document["originalKeySha256"] == Digest::SHA256.hexdigest(document["originalKey"])
  fail_fixture("state optimized-key binding differs") unless
    document["optimizedKeySha256"] == Digest::SHA256.hexdigest(document["optimizedKey"])
  %w[originalKeySha256 optimizedKeySha256 originalUrlSha256 optimizedUrlSha256 originalContentSha256 optimizedContentSha256].each do |key|
    fail_fixture("state digest is malformed") unless document[key].to_s.match?(/\A[0-9a-f]{64}\z/)
  end
  document
rescue JSON::ParserError
  fail_fixture("state JSON is malformed")
end


def safe_transaction_journal!(document, commit, configuration)
  fail_fixture("transaction journal keys differ") unless document.is_a?(Hash) && document.keys.sort == TRANSACTION_JOURNAL_KEYS.sort
  fail_fixture("transaction journal schema differs") unless document["schemaVersion"] == 3
  fail_fixture("transaction journal repository commit differs") unless document["repositoryCommit"] == commit
  fail_fixture("transaction journal configuration differs") unless document["productionConfigurationSha256"] == configuration
  fail_fixture("transaction journal is not cleanup-only") unless document["cleanupOnly"] == true
  transaction_id = document["transactionId"].to_s
  fail_fixture("transaction journal identifier is malformed") unless transaction_id.match?(/\A[0-9a-f]{32}\z/)
  fail_fixture("transaction journal namespace differs") unless document["pluginStoreNamespace"] == TRANSACTION_NAMESPACE
  fail_fixture("transaction journal key differs") unless document["pluginStoreKey"] == "#{TRANSACTION_KEY_PREFIX}#{transaction_id}"
  fail_fixture("transaction journal phase differs") unless document["phase"] == "prepared"
  document
end


def load_cleanup_state(commit, configuration)
  document = JSON.parse($stdin.read)
  fail_fixture("cleanup state is not an object") unless document.is_a?(Hash)
  fail_fixture("cleanup state repository commit differs") unless document["repositoryCommit"] == commit
  fail_fixture("cleanup state configuration differs") unless document["productionConfigurationSha256"] == configuration
  case document["schemaVersion"]
  when 0
    expected = %w[schemaVersion repositoryCommit productionConfigurationSha256 cleanupOnly]
    fail_fixture("pre-armed cleanup state keys differ") unless document.keys.sort == expected.sort && document["cleanupOnly"] == true
  when 1
    # Reuse the strict full-state parser without reading standard input twice.
    expected = %w[
      schemaVersion repositoryCommit productionConfigurationSha256 uploadId
      optimizedImageId uploadSha1 originalKeySha256 optimizedKeySha256
      originalKey optimizedKey originalUrlSha256 optimizedUrlSha256
      originalContentSha256 optimizedContentSha256
    ]
    fail_fixture("full cleanup state keys differ") unless document.keys.sort == expected.sort
    fail_fixture("full cleanup upload identifier is malformed") unless document["uploadId"].is_a?(Integer) && document["uploadId"].positive?
    fail_fixture("full cleanup optimized identifier is malformed") unless document["optimizedImageId"].is_a?(Integer) && document["optimizedImageId"].positive?
    fail_fixture("full cleanup upload digest differs") unless document["uploadSha1"] == Digest::SHA1.hexdigest(png_bytes(commit, configuration))
    safe_object_key!(document["originalKey"], "original")
    safe_object_key!(document["optimizedKey"], "optimized")
    fail_fixture("full cleanup original-key binding differs") unless
      document["originalKeySha256"] == Digest::SHA256.hexdigest(document["originalKey"])
    fail_fixture("full cleanup optimized-key binding differs") unless
      document["optimizedKeySha256"] == Digest::SHA256.hexdigest(document["optimizedKey"])
    %w[originalUrlSha256 optimizedUrlSha256 originalContentSha256 optimizedContentSha256].each do |key|
      fail_fixture("full cleanup digest is malformed") unless document[key].to_s.match?(/\A[0-9a-f]{64}\z/)
    end
  when 2
    expected = %w[
      schemaVersion repositoryCommit productionConfigurationSha256 cleanupOnly
      uploadId uploadSha1 originalKey optimizedImageIds optimizedKeys
    ]
    fail_fixture("recovery cleanup state keys differ") unless document.keys.sort == expected.sort && document["cleanupOnly"] == true
    fail_fixture("recovery upload identifier is malformed") unless document["uploadId"].is_a?(Integer) && document["uploadId"].positive?
    fail_fixture("recovery upload digest differs") unless document["uploadSha1"] == Digest::SHA1.hexdigest(png_bytes(commit, configuration))
    safe_object_key!(document["originalKey"], "original")
    fail_fixture("recovery optimized identifiers are malformed") unless document["optimizedImageIds"].is_a?(Array) &&
      document["optimizedImageIds"].all? { |value| value.is_a?(Integer) && value.positive? }
    fail_fixture("recovery optimized identifiers are ambiguous") unless
      document["optimizedImageIds"].uniq == document["optimizedImageIds"] &&
        document["optimizedImageIds"].sort == document["optimizedImageIds"]
    fail_fixture("recovery optimized keys are malformed") unless document["optimizedKeys"].is_a?(Array) &&
      document["optimizedKeys"].all? { |value| safe_object_key!(value, "optimized") }
    fail_fixture("recovery optimized keys are ambiguous") unless document["optimizedKeys"].uniq == document["optimizedKeys"]
    fail_fixture("recovery optimized binding is incomplete") unless document["optimizedImageIds"].length == document["optimizedKeys"].length
  when 3
    safe_transaction_journal!(document, commit, configuration)
  when 4
    expected = %w[
      schemaVersion repositoryCommit productionConfigurationSha256 transactionId
      pluginStoreNamespace pluginStoreKey uploadOrigin uploadId optimizedImageId
      uploadSha1 originalKeySha256 optimizedKeySha256 originalKey optimizedKey
      originalUrlSha256 optimizedUrlSha256 originalContentSha256 optimizedContentSha256
    ]
    fail_fixture("full transaction cleanup state keys differ") unless document.keys.sort == expected.sort
    fail_fixture("full transaction cleanup identifier is malformed") unless document["transactionId"].to_s.match?(/\A[0-9a-f]{32}\z/)
    fail_fixture("full transaction cleanup namespace differs") unless document["pluginStoreNamespace"] == TRANSACTION_NAMESPACE
    fail_fixture("full transaction cleanup key differs") unless document["pluginStoreKey"] == "#{TRANSACTION_KEY_PREFIX}#{document["transactionId"]}"
    fail_fixture("full transaction cleanup ownership differs") unless
      document["uploadOrigin"] == owned_origin(commit, configuration, document["transactionId"])
    fail_fixture("full transaction cleanup upload digest differs") unless
      document["uploadSha1"] == Digest::SHA1.hexdigest(png_bytes(commit, configuration, document["transactionId"]))
    fail_fixture("full transaction cleanup upload identifier is malformed") unless document["uploadId"].is_a?(Integer) && document["uploadId"].positive?
    fail_fixture("full transaction cleanup optimized identifier is malformed") unless document["optimizedImageId"].is_a?(Integer) && document["optimizedImageId"].positive?
    safe_object_key!(document["originalKey"], "original")
    safe_object_key!(document["optimizedKey"], "optimized")
  else
    fail_fixture("cleanup state schema differs")
  end
  document
rescue JSON::ParserError
  fail_fixture("cleanup state JSON is malformed")
end


def transaction_journal_from_state(state)
  {
    "schemaVersion" => 3,
    "repositoryCommit" => state.fetch("repositoryCommit"),
    "productionConfigurationSha256" => state.fetch("productionConfigurationSha256"),
    "cleanupOnly" => true,
    "transactionId" => state.fetch("transactionId"),
    "pluginStoreNamespace" => state.fetch("pluginStoreNamespace"),
    "pluginStoreKey" => state.fetch("pluginStoreKey"),
    "phase" => "prepared",
  }
end

def initial_transaction_state(journal)
  commit = journal.fetch("repositoryCommit")
  configuration = journal.fetch("productionConfigurationSha256")
  transaction_id = journal.fetch("transactionId")
  {
    "schemaVersion" => 1,
    "repositoryCommit" => commit,
    "productionConfigurationSha256" => configuration,
    "transactionId" => transaction_id,
    "pluginStoreNamespace" => TRANSACTION_NAMESPACE,
    "pluginStoreKey" => journal.fetch("pluginStoreKey"),
    "uploadOrigin" => owned_origin(commit, configuration, transaction_id),
    "uploadSha1" => Digest::SHA1.hexdigest(png_bytes(commit, configuration, transaction_id)),
    "originalFilename" => FIXTURE_FILENAME,
    "phase" => "prepared",
    "uploadId" => nil,
    "originalKey" => nil,
    "optimizedImageIds" => [],
    "optimizedKeys" => [],
  }
end

def safe_transaction_state!(state, journal)
  expected = initial_transaction_state(journal)
  fail_fixture("transaction state keys differ") unless state.is_a?(Hash) && state.keys.sort == TRANSACTION_STATE_KEYS.sort
  %w[
    schemaVersion repositoryCommit productionConfigurationSha256 transactionId
    pluginStoreNamespace pluginStoreKey uploadOrigin uploadSha1 originalFilename
  ].each do |key|
    fail_fixture("transaction state #{key} differs") unless state[key] == expected[key]
  end
  fail_fixture("transaction state phase differs") unless %w[prepared upload-created complete].include?(state["phase"])
  fail_fixture("transaction optimized identities are malformed") unless
    state["optimizedImageIds"].is_a?(Array) && state["optimizedKeys"].is_a?(Array) &&
      state["optimizedImageIds"].all? { |value| value.is_a?(Integer) && value.positive? } &&
      state["optimizedImageIds"].uniq == state["optimizedImageIds"] &&
      state["optimizedKeys"].all? { |value| safe_object_key!(value, "optimized") } &&
      state["optimizedKeys"].uniq == state["optimizedKeys"] &&
      state["optimizedImageIds"].length == state["optimizedKeys"].length &&
      state["optimizedImageIds"].length <= 1
  case state["phase"]
  when "prepared"
    fail_fixture("prepared transaction has dynamic identity") unless
      state["uploadId"].nil? && state["originalKey"].nil? && state["optimizedImageIds"].empty?
  when "upload-created"
    fail_fixture("upload-created transaction identifier is malformed") unless state["uploadId"].is_a?(Integer) && state["uploadId"].positive?
    safe_object_key!(state["originalKey"], "original")
    fail_fixture("upload-created transaction has an unexpected optimized identity") unless state["optimizedImageIds"].empty?
  when "complete"
    fail_fixture("complete transaction identifier is malformed") unless state["uploadId"].is_a?(Integer) && state["uploadId"].positive?
    safe_object_key!(state["originalKey"], "original")
    fail_fixture("complete transaction optimized identity differs") unless state["optimizedImageIds"].length == 1
  end
  state
end

def write_transaction_state!(state)
  key = state.fetch("pluginStoreKey")
  text = JSON.generate(state.sort.to_h)
  PluginStore.set(TRANSACTION_NAMESPACE, key, text)
  fail_fixture("transaction state was not persisted") unless PluginStore.get(TRANSACTION_NAMESPACE, key) == text
  state
end

# UploadCreator saves the row before its S3 PUT. Seal the exact row and object
# identity inside that same database transaction, independently of runner
# stdout and before external object mutation can begin.
def arm_upload_identity_callback!(journal)
  expected = initial_transaction_state(journal)
  Upload.after_create do |created|
    next unless created.origin == expected.fetch("uploadOrigin")

    fail_fixture("transaction callback filename differs") unless created.original_filename == expected.fetch("originalFilename")
    fail_fixture("transaction callback digest differs") unless created.sha1 == expected.fetch("uploadSha1")
    state = expected.merge(
      "phase" => "upload-created",
      "uploadId" => created.id,
      "originalKey" => original_key(Discourse.store, created),
    )
    write_transaction_state!(safe_transaction_state!(state, journal))
  end
end

# OptimizedImage.create_for likewise persists its row before writing the
# variant object. Seal that key in the row transaction so cleanup survives a
# kill between the PUT and the caller receiving a result.
def arm_optimized_identity_callback!(journal, upload)
  expected_upload_id = upload.id
  OptimizedImage.after_create do |created|
    next unless created.upload_id == expected_upload_id

    current_text = PluginStore.get(TRANSACTION_NAMESPACE, journal.fetch("pluginStoreKey"))
    fail_fixture("optimized callback transaction state is absent") unless current_text.is_a?(String) && current_text.bytesize <= 8192
    current = safe_transaction_state!(JSON.parse(current_text), journal)
    fail_fixture("optimized callback transaction state is not canonical") unless current_text == JSON.generate(current.sort.to_h)
    fail_fixture("optimized callback upload identity differs") unless
      current["phase"] == "upload-created" && current["uploadId"] == expected_upload_id
    state = current.merge(
      "phase" => "complete",
      "optimizedImageIds" => [created.id],
      "optimizedKeys" => [optimized_key(Discourse.store, created)],
    )
    write_transaction_state!(safe_transaction_state!(state, journal))
  rescue JSON::ParserError
    fail_fixture("optimized callback transaction state JSON is malformed")
  end
end

def recover_transaction_state!(journal)
  key = journal.fetch("pluginStoreKey")
  text = PluginStore.get(TRANSACTION_NAMESPACE, key)
  state =
    if text.nil?
      initial_transaction_state(journal)
    else
      fail_fixture("transaction state exceeds its byte bound") unless text.is_a?(String) && text.bytesize <= 8192
      parsed = safe_transaction_state!(JSON.parse(text), journal)
      fail_fixture("transaction state is not canonical") unless text == JSON.generate(parsed.sort.to_h)
      parsed
    end
  uploads = Upload.where(origin: state.fetch("uploadOrigin")).to_a
  fail_fixture("transaction has multiple owned uploads") if uploads.length > 1
  upload = uploads.first
  optimized_rows = []
  if upload
    fail_fixture("transaction upload filename differs") unless upload.original_filename == FIXTURE_FILENAME
    fail_fixture("transaction upload digest differs") unless upload.sha1 == state.fetch("uploadSha1")
    fail_fixture("transaction upload owner differs") unless upload.user_id == Discourse.system_user.id
    fail_fixture("transaction upload became secure") if upload.secure?
    store = Discourse.store
    original = original_key(store, upload)
    optimized_rows = OptimizedImage.where(upload_id: upload.id).order(:id).to_a
    fail_fixture("transaction has multiple optimized rows") if optimized_rows.length > 1
    recovered = initial_transaction_state(journal).merge(
      "phase" => optimized_rows.one? ? "complete" : "upload-created",
      "uploadId" => upload.id,
      "originalKey" => original,
      "optimizedImageIds" => optimized_rows.map(&:id),
      "optimizedKeys" => optimized_rows.map { |row| optimized_key(store, row) },
    )
    if state["optimizedImageIds"].any? && optimized_rows.empty?
      fail_fixture("transaction optimized identifier was rebound") if
        OptimizedImage.where(id: state.fetch("optimizedImageIds")).exists?
      recovered.update(
        "phase" => "complete",
        "optimizedImageIds" => state.fetch("optimizedImageIds"),
        "optimizedKeys" => state.fetch("optimizedKeys"),
      )
    end
    if state["phase"] != "prepared"
      fail_fixture("transaction upload identifier differs") unless state["uploadId"] == recovered["uploadId"]
      fail_fixture("transaction original object binding differs") unless state["originalKey"] == recovered["originalKey"]
      if state["optimizedImageIds"].any? && optimized_rows.any?
        fail_fixture("transaction optimized identities differ") unless
          state.values_at("optimizedImageIds", "optimizedKeys") == recovered.values_at("optimizedImageIds", "optimizedKeys")
      end
    end
    state = write_transaction_state!(safe_transaction_state!(recovered, journal)) if state != recovered
  elsif state["uploadId"]
    fail_fixture("transaction upload identifier was rebound") if Upload.exists?(id: state.fetch("uploadId"))
    optimized_rows = OptimizedImage.where(id: state.fetch("optimizedImageIds")).order(:id).to_a
    fail_fixture("transaction optimized identifier was rebound") unless
      optimized_rows.all? { |row| row.upload_id == state.fetch("uploadId") }
  end
  [state, upload, optimized_rows]
rescue JSON::ParserError
  fail_fixture("transaction state JSON is malformed")
end

def cleanup_transaction_fixture!(journal, require_tombstones: false)
  state, upload, optimized_rows = recover_transaction_state!(journal)
  store = Discourse.store
  helper = store.s3_helper
  keys = [state["originalKey"], *state.fetch("optimizedKeys")].compact
  tombstones = keys.map { |key| File.join("tombstone", key) }
  if upload
    upload.destroy!
  else
    optimized_rows.each(&:destroy!)
  end
  if require_tombstones && keys.any?
    fail_fixture("expected transaction tombstone object is absent") unless tombstones.all? { |key| object_exists?(helper, key) }
  end
  keys.each { |key| helper.delete_object(key) if object_exists?(helper, key) }
  tombstones.each { |key| helper.delete_object(key) if object_exists?(helper, key) }

  fail_fixture("transaction owned upload survived cleanup") if Upload.where(origin: state.fetch("uploadOrigin")).exists?
  fail_fixture("transaction upload digest survived cleanup") if Upload.where(sha1: state.fetch("uploadSha1")).exists?
  if state["uploadId"]
    fail_fixture("transaction upload identifier survived cleanup") if Upload.exists?(id: state.fetch("uploadId"))
    fail_fixture("transaction user-upload reference survived cleanup") if UserUpload.where(upload_id: state.fetch("uploadId")).exists?
  end
  if state["optimizedImageIds"].any?
    fail_fixture("transaction optimized row survived cleanup") if OptimizedImage.where(id: state.fetch("optimizedImageIds")).exists?
  end
  fail_fixture("transaction primary object survived cleanup") if keys.any? { |key| object_exists?(helper, key) }
  fail_fixture("transaction tombstone survived cleanup") if tombstones.any? { |key| object_exists?(helper, key) }
  PluginStore.remove(TRANSACTION_NAMESPACE, journal.fetch("pluginStoreKey")) if
    PluginStore.get(TRANSACTION_NAMESPACE, journal.fetch("pluginStoreKey")).present?
  fail_fixture("transaction PluginStore identity survived cleanup") unless
    PluginStore.get(TRANSACTION_NAMESPACE, journal.fetch("pluginStoreKey")).nil?
  true
end


def cleanup_owned_fixture!(state, require_tombstones: false)
  commit = state.fetch("repositoryCommit")
  configuration = state.fetch("productionConfigurationSha256")
  origin = owned_origin(commit, configuration)
  uploads = Upload.where(origin: origin).to_a
  fail_fixture("cleanup found multiple owned uploads") if uploads.length > 1
  upload = uploads.first
  expected_sha1 = Digest::SHA1.hexdigest(png_bytes(commit, configuration))
  if upload
    fail_fixture("cleanup upload filename differs") unless upload.original_filename == FIXTURE_FILENAME
    fail_fixture("cleanup upload digest differs") unless upload.sha1 == expected_sha1
    if state["uploadId"]
      fail_fixture("cleanup upload identifier differs") unless upload.id == state["uploadId"]
    end
  elsif state["uploadId"] && Upload.exists?(id: state["uploadId"])
    fail_fixture("cleanup identifier was rebound to a different upload")
  end

  store = Discourse.store
  helper = store.s3_helper
  optimized_rows =
    if upload
      OptimizedImage.where(upload_id: upload.id).order(:id).to_a
    elsif state["optimizedImageIds"]
      OptimizedImage.where(id: state["optimizedImageIds"]).order(:id).to_a
    elsif state["optimizedImageId"]
      OptimizedImage.where(id: state["optimizedImageId"]).order(:id).to_a
    else
      []
    end
  if !upload && optimized_rows.any?
    fail_fixture("cleanup optimized row was rebound") unless state["uploadId"] && optimized_rows.all? { |row| row.upload_id == state["uploadId"] }
  end
  if state["optimizedImageId"]
    fail_fixture("cleanup optimized identifier differs") unless optimized_rows.map(&:id) == [state["optimizedImageId"]]
  elsif state["optimizedImageIds"]
    fail_fixture("cleanup optimized identifiers differ") unless optimized_rows.map(&:id) == state["optimizedImageIds"]
  end

  derived_original = original_key(store, upload) if upload
  supplied_original = state["originalKey"]
  fail_fixture("cleanup original object binding differs") if
    supplied_original && derived_original && supplied_original != derived_original
  original = supplied_original || derived_original

  derived_optimized = optimized_rows.map { |row| optimized_key(store, row) }
  supplied_optimized = if state["optimizedKey"]
    [state["optimizedKey"]]
  elsif state["optimizedKeys"]
    state["optimizedKeys"]
  end
  fail_fixture("cleanup optimized object binding differs") if
    supplied_optimized && optimized_rows.any? && supplied_optimized != derived_optimized
  optimized = supplied_optimized || derived_optimized
  safe_object_key!(original, "original") if original
  optimized.each { |key| safe_object_key!(key, "optimized") }
  keys = [original, *optimized].compact
  if upload
    upload.destroy!
  else
    optimized_rows.each(&:destroy!)
  end
  tombstones = keys.map { |key| File.join("tombstone", key) }
  if require_tombstones
    fail_fixture("expected tombstone object is absent") unless tombstones.all? { |key| object_exists?(helper, key) }
  end
  keys.each { |key| helper.delete_object(key) if object_exists?(helper, key) }
  tombstones.each { |key| helper.delete_object(key) if object_exists?(helper, key) }
  fail_fixture("owned upload row survived cleanup") if Upload.exists?(origin: origin)
  fail_fixture("owned optimized row survived cleanup") if state["optimizedImageId"] && OptimizedImage.exists?(id: state["optimizedImageId"])
  if state["optimizedImageIds"]&.any?
    fail_fixture("owned optimized row survived cleanup") if OptimizedImage.where(id: state["optimizedImageIds"]).exists?
  end
  fail_fixture("owned primary object survived cleanup") if keys.any? { |key| object_exists?(helper, key) }
  fail_fixture("owned tombstone survived cleanup") if tombstones.any? { |key| object_exists?(helper, key) }
  true
end

def bind_records!(state)
  upload = Upload.find_by(id: state.fetch("uploadId"))
  optimized = OptimizedImage.find_by(id: state.fetch("optimizedImageId"))
  fail_fixture("fixture upload is absent") unless upload && optimized
  fail_fixture("fixture upload binding differs") unless optimized.upload_id == upload.id
  fail_fixture("fixture filename differs") unless upload.original_filename == FIXTURE_FILENAME
  expected_origin = owned_origin(
    state.fetch("repositoryCommit"),
    state.fetch("productionConfigurationSha256"),
    state["transactionId"],
  )
  fail_fixture("fixture ownership binding differs") unless upload.origin == expected_origin
  fail_fixture("fixture upload digest differs") unless upload.sha1 == state.fetch("uploadSha1")
  fail_fixture("fixture upload became secure") if upload.secure?
  [upload, optimized]
end

def verify_objects!(state)
  store = Discourse.store
  helper = store.s3_helper
  upload, optimized = bind_records!(state)
  upload_key = original_key(store, upload)
  variant_key = optimized_key(store, optimized)
  fail_fixture("original key binding differs") unless Digest::SHA256.hexdigest(upload_key) == state.fetch("originalKeySha256")
  fail_fixture("optimized key binding differs") unless Digest::SHA256.hexdigest(variant_key) == state.fetch("optimizedKeySha256")
  fail_fixture("original object is absent") unless object_exists?(helper, upload_key)
  fail_fixture("optimized object is absent") unless object_exists?(helper, variant_key)
  fail_fixture("original ACL is not public-read") unless object_public_read?(helper.object(upload_key))
  fail_fixture("optimized ACL is not public-read") unless object_public_read?(helper.object(variant_key))

  upload_uri = canonical_public_uri(store.url_for(upload), "original")
  optimized_uri = canonical_public_uri(store.cdn_url(optimized.url), "optimized")
  fail_fixture("original rendered URL binding differs") unless Digest::SHA256.hexdigest(upload_uri.to_s) == state.fetch("originalUrlSha256")
  fail_fixture("optimized rendered URL binding differs") unless Digest::SHA256.hexdigest(optimized_uri.to_s) == state.fetch("optimizedUrlSha256")
  upload_response, upload_body = bounded_anonymous_get(upload_uri)
  optimized_response, optimized_body = bounded_anonymous_get(optimized_uri)
  fail_fixture("original response is not an image") unless upload_response["content-type"].to_s.start_with?("image/")
  fail_fixture("optimized response is not an image") unless optimized_response["content-type"].to_s.start_with?("image/")
  fail_fixture("original response bytes changed") unless Digest::SHA256.hexdigest(upload_body) == state.fetch("originalContentSha256")
  fail_fixture("optimized response bytes changed") unless Digest::SHA256.hexdigest(optimized_body) == state.fetch("optimizedContentSha256")

  list_uri = URI("https://#{EXPECTED_BUCKET}.sgp1.digitaloceanspaces.com/?list-type=2&max-keys=1")
  list_response, list_body = bounded_anonymous_get(list_uri, expected_statuses: [401, 403], public_media: false)
  %w[location content-location link set-cookie content-disposition].each do |name|
    fail_fixture("anonymous listing denial exposed redirect, cookie, or object metadata") if list_response[name]
  end
  if [FIXTURE_FILENAME, upload_key, variant_key].any? { |value| list_body.include?(value) }
    fail_fixture("anonymous listing denial exposed fixture object identity")
  end
  [upload, optimized, upload_key, variant_key]
end

action = ARGV.fetch(0)
commit, configuration = validate_identity!

case action
when "create"
  journal = load_cleanup_state(commit, configuration)
  fail_fixture("create requires the exact pre-armed transaction journal") unless journal["schemaVersion"] == 3
  transaction_id = journal.fetch("transactionId")
  bytes = png_bytes(commit, configuration, transaction_id)
  expected_sha1 = Digest::SHA1.hexdigest(bytes)
  if PluginStore.get(TRANSACTION_NAMESPACE, journal.fetch("pluginStoreKey")).nil?
    write_transaction_state!(initial_transaction_state(journal))
  end
  upload = nil
  fixture_origin = owned_origin(commit, configuration, transaction_id)
  tempfile = nil
  begin
    transaction, upload, optimized_rows = recover_transaction_state!(journal)
    if upload.nil?
      fail_fixture("fixture transaction content collides with an unowned upload") if Upload.exists?(sha1: expected_sha1)
      arm_upload_identity_callback!(journal)
      tempfile = Tempfile.new(["mochirii-storage-fixture", ".png"])
      tempfile.binmode
      tempfile.write(bytes)
      tempfile.flush
      tempfile.rewind
      upload = UploadCreator.new(tempfile, FIXTURE_FILENAME, type: "composer", origin: fixture_origin).create_for(Discourse.system_user.id)
      fail_fixture("fixture upload was rejected") unless upload.persisted? && upload.errors.empty?
      fail_fixture("fixture upload digest changed unexpectedly") unless upload.sha1 == expected_sha1
      fail_fixture("fixture upload ownership binding differs") unless upload.origin == fixture_origin
      transaction, upload, optimized_rows = recover_transaction_state!(journal)
    end
    if optimized_rows.empty?
      arm_optimized_identity_callback!(journal, upload)
      optimized = OptimizedImage.create_for(upload, 128, 128, raise_on_error: true)
      fail_fixture("optimized fixture was not persisted") unless optimized&.persisted?
      transaction, upload, optimized_rows = recover_transaction_state!(journal)
    end
    fail_fixture("fixture transaction did not reach its complete identity") unless
      transaction["phase"] == "complete" && optimized_rows.one?
    optimized = optimized_rows.first
    store = Discourse.store
    upload_key = transaction.fetch("originalKey")
    variant_key = transaction.fetch("optimizedKeys").fetch(0)
    upload_uri = canonical_public_uri(store.url_for(upload), "original")
    optimized_uri = canonical_public_uri(store.cdn_url(optimized.url), "optimized")
    upload_response, upload_body = bounded_anonymous_get(upload_uri)
    optimized_response, optimized_body = bounded_anonymous_get(optimized_uri)
    fail_fixture("original response is not an image") unless upload_response["content-type"].to_s.start_with?("image/")
    fail_fixture("optimized response is not an image") unless optimized_response["content-type"].to_s.start_with?("image/")
    fail_fixture("original ACL is not public-read") unless object_public_read?(store.s3_helper.object(upload_key))
    fail_fixture("optimized ACL is not public-read") unless object_public_read?(store.s3_helper.object(variant_key))
    state = {
      "schemaVersion" => 4,
      "repositoryCommit" => commit,
      "productionConfigurationSha256" => configuration,
      "transactionId" => transaction_id,
      "pluginStoreNamespace" => TRANSACTION_NAMESPACE,
      "pluginStoreKey" => journal.fetch("pluginStoreKey"),
      "uploadOrigin" => fixture_origin,
      "uploadId" => upload.id,
      "optimizedImageId" => optimized.id,
      "uploadSha1" => upload.sha1,
      "originalKey" => upload_key,
      "optimizedKey" => variant_key,
      "originalKeySha256" => Digest::SHA256.hexdigest(upload_key),
      "optimizedKeySha256" => Digest::SHA256.hexdigest(variant_key),
      "originalUrlSha256" => Digest::SHA256.hexdigest(upload_uri.to_s),
      "optimizedUrlSha256" => Digest::SHA256.hexdigest(optimized_uri.to_s),
      "originalContentSha256" => Digest::SHA256.hexdigest(upload_body),
      "optimizedContentSha256" => Digest::SHA256.hexdigest(optimized_body),
    }
    puts JSON.generate(state.sort.to_h)
  rescue Exception
    cleanup_transaction_fixture!(journal) rescue nil
    raise
  ensure
    tempfile&.close!
  end
when "verify"
  state = load_state(commit, configuration)
  verify_objects!(state)
  puts JSON.generate(
    {
      "schemaVersion" => 1,
      "repositoryCommit" => commit,
      "productionConfigurationSha256" => configuration,
      "objectWriteReadPassed" => true,
      "optimizedVariantPassed" => true,
      "customHostnameOnlyPassed" => true,
      "anonymousDirectRetrievalPassed" => true,
      "anonymousListingDenied" => true,
      "publicAclPassed" => true,
    }.sort.to_h,
  )
when "delete"
  state = load_state(commit, configuration)
  verify_objects!(state)
  cleanup_transaction_fixture!(transaction_journal_from_state(state), require_tombstones: true)
  puts JSON.generate(
    {
      "schemaVersion" => 1,
      "repositoryCommit" => commit,
      "productionConfigurationSha256" => configuration,
      "databaseRowsDeleted" => true,
      "primaryObjectsDeleted" => true,
      "tombstonesDeleted" => true,
    }.sort.to_h,
  )
when "cleanup"
  state = load_cleanup_state(commit, configuration)
  if [3, 4].include?(state["schemaVersion"])
    cleanup_transaction_fixture!(state["schemaVersion"] == 3 ? state : transaction_journal_from_state(state))
  else
    cleanup_owned_fixture!(state)
  end
  puts JSON.generate(
    {
      "schemaVersion" => 1,
      "repositoryCommit" => commit,
      "productionConfigurationSha256" => configuration,
      "cleanupPassed" => true,
    }.sort.to_h,
  )
else
  fail_fixture("action is not create, verify, delete, or cleanup")
end
