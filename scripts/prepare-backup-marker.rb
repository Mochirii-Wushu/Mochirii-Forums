# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "stringio"
require "tempfile"
require "uri"

RECOVERY_NAMESPACE = "mochirii-recovery"
REPOSITORY_KEY = "repository_commit"
UPLOAD_STATE_KEY = "normal_upload_marker"
TRANSACTION_KEY_PREFIX = "normal_upload_transaction:"
STATE_KEYS = %w[
  schemaVersion repositoryCommit uploadId uploadSha1 originalFilename objectPath
  tombstonePath contentSha256 publicUrlSha256
].freeze
JOURNAL_KEYS = %w[
  schemaVersion repositoryCommit productionConfigurationSha256
  backupOperationSha256 transactionId pluginStoreKey phase
].freeze
TRANSACTION_STATE_KEYS = %w[
  schemaVersion repositoryCommit productionConfigurationSha256
  backupOperationSha256 transactionId pluginStoreKey uploadOrigin uploadSha1
  originalFilename contentSha256 phase uploadId objectPath tombstonePath
].freeze

def canonical_json(document)
  JSON.generate(document.sort.to_h)
end

def marker_bytes(commit)
  base = Base64.strict_decode64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
  raise "Recovery image fixture changed" unless base.bytesize == 34 && base.end_with?(";")
  comment = "mochirii-recovery-#{commit}".b
  raise "Recovery image comment is outside its bound" unless comment.bytesize.between?(32, 96)
  base.byteslice(0, base.bytesize - 1) + "!\xFE".b + [comment.bytesize].pack("C") + comment + "\x00;".b
end

def safe_transaction_journal!(document, commit)
  raise "Recovery upload journal schema differs" unless document.is_a?(Hash) && document.keys.sort == JOURNAL_KEYS.sort
  raise "Recovery upload journal version differs" unless document["schemaVersion"] == 1
  raise "Recovery upload journal release differs" unless document["repositoryCommit"] == commit
  raise "Recovery upload journal configuration is malformed" unless document["productionConfigurationSha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
  raise "Recovery upload journal operation is malformed" unless document["backupOperationSha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
  transaction_id = document["transactionId"].to_s
  raise "Recovery upload transaction identifier is malformed" unless transaction_id.match?(/\A[0-9a-f]{32}\z/)
  raise "Recovery upload transaction key differs" unless document["pluginStoreKey"] == "#{TRANSACTION_KEY_PREFIX}#{transaction_id}"
  raise "Recovery upload journal phase differs" unless document["phase"] == "prepared"
  document
end

def load_transaction_journal!(commit)
  encoded = ENV.fetch("MOCHIRII_RECOVERY_UPLOAD_TRANSACTION_BASE64")
  raise "Recovery upload journal encoding exceeds its bound" unless encoded.bytesize.between?(16, 8192)
  text = Base64.strict_decode64(encoded)
  raise "Recovery upload journal exceeds its bound" unless text.bytesize <= 4096
  document = safe_transaction_journal!(JSON.parse(text), commit)
  raise "Recovery upload journal is not canonical" unless text == canonical_json(document) + "\n"
  document
rescue ArgumentError, JSON::ParserError
  raise "Recovery upload journal is malformed"
end

def transaction_origin(commit, transaction_id)
  "mochirii-recovery-upload:#{commit}:#{transaction_id}"
end

def transaction_state(journal, expected_sha1, expected_content_sha, phase: "prepared", upload: nil, store: nil)
  state = {
    "schemaVersion" => 1,
    "repositoryCommit" => journal.fetch("repositoryCommit"),
    "productionConfigurationSha256" => journal.fetch("productionConfigurationSha256"),
    "backupOperationSha256" => journal.fetch("backupOperationSha256"),
    "transactionId" => journal.fetch("transactionId"),
    "pluginStoreKey" => journal.fetch("pluginStoreKey"),
    "uploadOrigin" => transaction_origin(journal.fetch("repositoryCommit"), journal.fetch("transactionId")),
    "uploadSha1" => expected_sha1,
    "originalFilename" => "mochirii-recovery-#{journal.fetch("repositoryCommit")[0, 12]}.gif",
    "contentSha256" => expected_content_sha,
    "phase" => phase,
    "uploadId" => nil,
    "objectPath" => nil,
    "tombstonePath" => nil,
  }
  if upload
    object_path = store.get_path_for_upload(upload)
    state.update(
      "phase" => "created",
      "uploadId" => upload.id,
      "objectPath" => object_path,
      "tombstonePath" => File.join(FileStore::S3Store::TOMBSTONE_PREFIX, object_path),
    )
  end
  state
end

def safe_transaction_state!(state, journal, expected_sha1, expected_content_sha)
  expected = transaction_state(journal, expected_sha1, expected_content_sha)
  raise "Recovery upload transaction state schema differs" unless state.is_a?(Hash) && state.keys.sort == TRANSACTION_STATE_KEYS.sort
  %w[
    schemaVersion repositoryCommit productionConfigurationSha256
    backupOperationSha256 transactionId pluginStoreKey uploadOrigin uploadSha1
    originalFilename contentSha256
  ].each do |key|
    raise "Recovery upload transaction #{key} differs" unless state[key] == expected[key]
  end
  raise "Recovery upload transaction phase is malformed" unless %w[prepared created].include?(state["phase"])
  if state["phase"] == "prepared"
    raise "Prepared recovery upload transaction has dynamic identity" unless
      state.values_at("uploadId", "objectPath", "tombstonePath") == [nil, nil, nil]
  else
    raise "Recovery upload transaction id is malformed" unless state["uploadId"].is_a?(Integer) && state["uploadId"].positive?
    safe_object = state["objectPath"].to_s
    unless safe_object.match?(%r{\Aoriginal/[1-9][0-9]*X/(?:[0-9a-f]/)*#{expected_sha1}[.]gif\z})
      raise "Recovery upload transaction object path is malformed"
    end
    unless state["tombstonePath"] == File.join(FileStore::S3Store::TOMBSTONE_PREFIX, safe_object)
      raise "Recovery upload transaction tombstone path differs"
    end
  end
  state
end

def write_transaction_state!(state)
  text = canonical_json(state)
  PluginStore.set(RECOVERY_NAMESPACE, state.fetch("pluginStoreKey"), text)
  raise "Recovery upload transaction state was not persisted" unless
    PluginStore.get(RECOVERY_NAMESPACE, state.fetch("pluginStoreKey")) == text
  state
end

# UploadCreator commits its Upload row before it starts the external store PUT.
# Persist the row-derived object identity in the same database transaction so a
# killed runner can still delete and prove absence of an object whose URL save
# never completed.
def arm_upload_identity_callback!(journal, expected_sha1, expected_content_sha, store)
  expected_origin = transaction_origin(journal.fetch("repositoryCommit"), journal.fetch("transactionId"))
  Upload.after_create do |created|
    next unless created.origin == expected_origin

    raise "Recovery upload callback digest differs" unless created.sha1 == expected_sha1
    raise "Recovery upload callback filename differs" unless created.original_filename ==
      "mochirii-recovery-#{journal.fetch("repositoryCommit")[0, 12]}.gif"
    state = transaction_state(
      journal,
      expected_sha1,
      expected_content_sha,
      phase: "created",
      upload: created,
      store: store,
    )
    write_transaction_state!(safe_transaction_state!(state, journal, expected_sha1, expected_content_sha))
  end
end

def recover_transaction_state!(journal, expected_sha1, expected_content_sha, store)
  key = journal.fetch("pluginStoreKey")
  text = PluginStore.get(RECOVERY_NAMESPACE, key)
  state =
    if text.nil?
      transaction_state(journal, expected_sha1, expected_content_sha)
    else
      raise "Recovery upload transaction state exceeds its bound" unless text.is_a?(String) && text.bytesize <= 4096
      parsed = safe_transaction_state!(JSON.parse(text), journal, expected_sha1, expected_content_sha)
      raise "Recovery upload transaction state is not canonical" unless text == canonical_json(parsed)
      parsed
    end
  uploads = Upload.where(origin: state.fetch("uploadOrigin")).to_a
  raise "Recovery upload transaction has multiple owned rows" if uploads.length > 1
  upload = uploads.first
  if upload
    raise "Recovery upload transaction filename differs" unless upload.original_filename == state.fetch("originalFilename")
    raise "Recovery upload transaction digest differs" unless upload.sha1 == expected_sha1
    raise "Recovery upload transaction owner differs" unless upload.user_id == Discourse.system_user.id
    raise "Recovery upload transaction security differs" unless upload.secure == false
    recovered = transaction_state(journal, expected_sha1, expected_content_sha, phase: "created", upload: upload, store: store)
    if state["phase"] == "created"
      %w[uploadId objectPath tombstonePath].each do |field|
        raise "Recovery upload transaction #{field} differs" unless state[field] == recovered[field]
      end
    else
      state = write_transaction_state!(recovered)
    end
  elsif state["phase"] == "created" && Upload.exists?(id: state.fetch("uploadId"))
    raise "Recovery upload transaction id was rebound"
  end
  [state, upload]
rescue JSON::ParserError
  raise "Recovery upload transaction state is malformed"
end

def cleanup_transaction!(journal, expected_sha1, expected_content_sha, store)
  key = journal.fetch("pluginStoreKey")
  state, upload = recover_transaction_state!(journal, expected_sha1, expected_content_sha, store)
  if upload
    upload.destroy!
  end
  object_paths = state.values_at("objectPath", "tombstonePath").compact
  object_paths.each { |path| store.delete_file(path) if store.object_from_path(path).exists? }
  if state["uploadId"]
    raise "Recovery upload transaction row remains" if Upload.exists?(id: state.fetch("uploadId"))
    raise "Recovery upload transaction user reference remains" if UserUpload.where(upload_id: state.fetch("uploadId")).exists?
  end
  raise "Recovery upload transaction owned row remains" if Upload.where(origin: state.fetch("uploadOrigin")).exists?
  bounded_absent!(store, { "objectPath" => object_paths[0], "tombstonePath" => object_paths[1] }) if object_paths.length == 2

  legacy_text = PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)
  if legacy_text.present?
    raise "Recovery upload database state exceeds its bound" unless legacy_text.is_a?(String) && legacy_text.bytesize <= 4096
    legacy = safe_state!(JSON.parse(legacy_text), journal.fetch("repositoryCommit"))
    raise "Recovery upload database state is not canonical" unless legacy_text == canonical_json(legacy)
    raise "Recovery upload database state differs from its transaction" unless
      state["phase"] == "created" &&
        legacy.values_at("uploadId", "uploadSha1", "objectPath", "tombstonePath", "contentSha256") ==
          state.values_at("uploadId", "uploadSha1", "objectPath", "tombstonePath", "contentSha256")
    PluginStore.remove(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)
  end
  raise "Recovery upload database marker remains" unless PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY).nil?
  PluginStore.remove(RECOVERY_NAMESPACE, key) if PluginStore.get(RECOVERY_NAMESPACE, key).present?
  raise "Recovery upload transaction marker remains" unless PluginStore.get(RECOVERY_NAMESPACE, key).nil?
  true
rescue JSON::ParserError
  raise "Recovery upload database state is malformed"
end

def safe_state!(state, commit)
  raise "Recovery upload state schema differs" unless state.is_a?(Hash) && state.keys.sort == STATE_KEYS.sort
  raise "Recovery upload state version differs" unless state["schemaVersion"] == 1
  raise "Recovery upload release differs" unless state["repositoryCommit"] == commit
  raise "Recovery upload id is malformed" unless state["uploadId"].is_a?(Integer) && state["uploadId"].positive?
  raise "Recovery upload digest is malformed" unless state["uploadSha1"].to_s.match?(/\A[0-9a-f]{40}\z/)
  raise "Recovery upload content digest is malformed" unless state["contentSha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
  raise "Recovery upload URL digest is malformed" unless state["publicUrlSha256"].to_s.match?(/\A[0-9a-f]{64}\z/)
  filename = "mochirii-recovery-#{commit[0, 12]}.gif"
  raise "Recovery upload filename differs" unless state["originalFilename"] == filename
  object_path = state["objectPath"].to_s
  unless object_path.match?(%r{\Aoriginal/[1-9][0-9]*X/(?:[0-9a-f]/)*#{state["uploadSha1"]}[.]gif\z})
    raise "Recovery upload object path is malformed"
  end
  unless state["tombstonePath"] == File.join(FileStore::S3Store::TOMBSTONE_PREFIX, object_path)
    raise "Recovery upload tombstone path differs"
  end
  state
end

def bounded_absent!(store, state)
  20.times do
    primary_absent = !store.object_from_path(state.fetch("objectPath")).exists?
    tombstone_absent = !store.object_from_path(state.fetch("tombstonePath")).exists?
    return true if primary_absent && tombstone_absent
    sleep 0.5
  end
  raise "Recovery upload object cleanup could not be proved"
end

def validate_upload!(upload, state, expected_bytes)
  raise "Recovery upload row is absent" if upload.nil?
  raise "Recovery upload id differs" unless upload.id == state.fetch("uploadId")
  raise "Recovery upload SHA-1 differs" unless upload.sha1 == state.fetch("uploadSha1")
  raise "Recovery upload filename differs" unless upload.original_filename == state.fetch("originalFilename")
  raise "Recovery upload owner differs" unless upload.user_id == Discourse.system_user.id
  raise "Recovery upload security differs" unless upload.secure == false
  raise "Recovery upload bytes differ" unless upload.content == expected_bytes
  store = Discourse.store
  raise "Recovery upload object path differs" unless store.get_path_for_upload(upload) == state.fetch("objectPath")
  public_uri = URI.parse(store.url_for(upload))
  unless public_uri.scheme == "https" && public_uri.host == "media-forums.mochirii.com" &&
      public_uri.port == 443 && public_uri.userinfo.nil? && public_uri.query.nil? && public_uri.fragment.nil?
    raise "Recovery upload public URL differs"
  end
  raise "Recovery upload public URL digest differs" unless Digest::SHA256.hexdigest(public_uri.to_s) == state.fetch("publicUrlSha256")
  raise "Recovery upload primary object is absent" unless store.object_from_path(state.fetch("objectPath")).exists?
  raise "Recovery upload unexpectedly has a tombstone" if store.object_from_path(state.fetch("tombstonePath")).exists?
  true
end

commit = ENV.fetch("MOCHIRII_REPOSITORY_COMMIT")
raise "Repository revision is malformed" unless commit.match?(/\A[0-9a-f]{40}\z/)
action = ENV.fetch("MOCHIRII_RECOVERY_UPLOAD_ACTION", "database-only")
raise "Recovery upload action is malformed" unless %w[database-only prepare cleanup verify-clean].include?(action)
expected_bytes = marker_bytes(commit)
expected_sha1 = Digest::SHA1.hexdigest(expected_bytes)
expected_content_sha = Digest::SHA256.hexdigest(expected_bytes)

PluginStore.set(RECOVERY_NAMESPACE, REPOSITORY_KEY, commit)
raise "Backup marker was not persisted" unless PluginStore.get(RECOVERY_NAMESPACE, REPOSITORY_KEY) == commit
if action == "database-only"
  raise "Unexpected hosted recovery upload marker in the local fixture" unless PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY).nil?
  puts "Mochirii recovery marker prepared."
  exit
end

store = Discourse.store
raise "Recovery upload store is not the exact external store" unless store.is_a?(FileStore::S3Store) && store.external?

if action == "prepare"
  journal = load_transaction_journal!(commit)
  transaction_text = PluginStore.get(RECOVERY_NAMESPACE, journal.fetch("pluginStoreKey"))
  if transaction_text.nil?
    prearmed = transaction_state(journal, expected_sha1, expected_content_sha)
    write_transaction_state!(prearmed)
  end
  transaction, upload = recover_transaction_state!(journal, expected_sha1, expected_content_sha, store)
  if upload.nil?
    raise "Recovery upload content collides with an unowned row" if Upload.exists?(sha1: expected_sha1)
    arm_upload_identity_callback!(journal, expected_sha1, expected_content_sha, store)
    file = Tempfile.new(["mochirii-recovery", ".gif"])
    file.binmode
    file.write(expected_bytes)
    file.rewind
    upload = UploadCreator.new(
      file,
      "mochirii-recovery-#{commit[0, 12]}.gif",
      origin: transaction.fetch("uploadOrigin"),
    ).create_for(Discourse.system_user.id)
    raise "Recovery upload creation failed" if upload.errors.present? || !upload.persisted?
    raise "Recovery upload transaction ownership differs" unless upload.origin == transaction.fetch("uploadOrigin")
    transaction, upload = recover_transaction_state!(journal, expected_sha1, expected_content_sha, store)
  end
  raise "Recovery upload transaction was not durably bound" unless transaction["phase"] == "created" && upload
  object_path = transaction.fetch("objectPath")
  public_uri = URI.parse(store.url_for(upload))
  state = {
    "schemaVersion" => 1,
    "repositoryCommit" => commit,
    "uploadId" => upload.id,
    "uploadSha1" => expected_sha1,
    "originalFilename" => "mochirii-recovery-#{commit[0, 12]}.gif",
    "objectPath" => object_path,
    "tombstonePath" => transaction.fetch("tombstonePath"),
    "contentSha256" => expected_content_sha,
    "publicUrlSha256" => Digest::SHA256.hexdigest(public_uri.to_s),
  }
  safe_state!(state, commit)
  validate_upload!(upload, state, expected_bytes)
  existing_text = PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)
  if existing_text.present? && existing_text != canonical_json(state)
    raise "Recovery upload database state differs"
  elsif existing_text.nil?
    PluginStore.set(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY, canonical_json(state))
    raise "Recovery upload state was not persisted" unless PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY) == canonical_json(state)
  end
  puts canonical_json(state)
else
  if action == "cleanup" && ENV["MOCHIRII_RECOVERY_UPLOAD_TRANSACTION_BASE64"].present?
    journal = load_transaction_journal!(commit)
    cleanup_transaction!(journal, expected_sha1, expected_content_sha, store)
    puts JSON.generate(recoveryUploadCleanupPassed: true)
    exit
  end
  encoded = ENV.fetch("MOCHIRII_RECOVERY_UPLOAD_STATE_BASE64")
  raise "Recovery upload state encoding exceeds its bound" unless encoded.bytesize.between?(16, 8192)
  state_text = Base64.strict_decode64(encoded)
  raise "Recovery upload state exceeds its bound" unless state_text.bytesize <= 4096
  state = safe_state!(JSON.parse(state_text), commit)
  raise "Recovery upload state is not canonical" unless state_text == canonical_json(state) + "\n"
  raise "Recovery upload state content differs" unless state.fetch("uploadSha1") == expected_sha1 && state.fetch("contentSha256") == expected_content_sha
  current_text = PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)
  if current_text.present? && current_text != canonical_json(state)
    raise "Recovery upload database state differs"
  end
  upload = Upload.find_by(id: state.fetch("uploadId"))
  duplicate = Upload.where(sha1: state.fetch("uploadSha1")).where.not(id: state.fetch("uploadId")).exists?
  raise "Recovery upload has a duplicate row" if duplicate
  if action == "cleanup"
    validate_upload!(upload, state, expected_bytes) unless upload.nil?
    upload&.destroy
    raise "Recovery upload row destruction failed" if upload && !upload.destroyed?
    store.delete_file(state.fetch("objectPath"))
    store.delete_file(state.fetch("tombstonePath"))
    bounded_absent!(store, state)
    raise "Recovery upload row remains" if Upload.where(id: state.fetch("uploadId")).or(Upload.where(sha1: state.fetch("uploadSha1"))).exists?
    raise "Recovery upload user reference remains" if UserUpload.where(upload_id: state.fetch("uploadId")).exists?
    PluginStore.remove(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)
    raise "Recovery upload database marker remains" unless PluginStore.get(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY).nil?
  else
    raise "Recovery upload database marker remains" unless current_text.nil?
    raise "Recovery upload row remains" unless upload.nil? && !Upload.exists?(sha1: state.fetch("uploadSha1"))
    raise "Recovery upload user reference remains" if UserUpload.where(upload_id: state.fetch("uploadId")).exists?
    bounded_absent!(store, state)
  end
  puts JSON.generate(recoveryUploadCleanupPassed: true)
end
