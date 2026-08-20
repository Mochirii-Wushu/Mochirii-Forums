# frozen_string_literal: true

require "uri"

# Pure trust-boundary validation for application-generated backup retrieval
# URLs. It performs no network I/O and never includes a signed URL in errors.
module MochiriiBackupUrlBoundary
  EXPECTED_HOST = "mochirii-forums.sgp1.digitaloceanspaces.com"
  EXPECTED_CDN_HOST = "media-forums.mochirii.com"
  EXPECTED_DATABASE = "default"
  MAX_FILENAME_BYTES = 200
  MAX_QUERY_BYTES = 4096
  MAX_QUERY_PAIRS = 12
  MAX_ANONYMOUS_DENIAL_BYTES = 16 * 1024
  REQUIRED_QUERY_KEYS = %w[
    X-Amz-Algorithm
    X-Amz-Credential
    X-Amz-Date
    X-Amz-Expires
    X-Amz-Signature
    X-Amz-SignedHeaders
  ].freeze

  class InvalidBackupUrl < StandardError; end
  class InvalidBackupFilename < StandardError; end

  def self.valid_filename!(filename)
    unless filename.is_a?(String) && filename.ascii_only? && filename.bytesize.between?(5, MAX_FILENAME_BYTES)
      raise InvalidBackupFilename, "backup filename is outside the reviewed byte boundary"
    end
    unless filename.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]*\.t?gz\z/) && !filename.include?("..")
      raise InvalidBackupFilename, "backup filename is not a safe supported archive basename"
    end
    filename
  end

  def self.signed_get_uri(value, filename)
    valid_filename!(filename)
    uri = URI.parse(value)
    unless uri.scheme == "https" && uri.host == EXPECTED_HOST && uri.port == 443
      raise InvalidBackupUrl, "backup retrieval authority differs from the reviewed boundary"
    end
    if uri.user || uri.password || uri.fragment
      raise InvalidBackupUrl, "backup retrieval URL contains forbidden authority data"
    end
    expected_path = "/backups/#{EXPECTED_DATABASE}/#{filename}"
    unless uri.path == expected_path
      raise InvalidBackupUrl, "backup retrieval path differs from the exact backup object"
    end
    query = uri.query
    unless query.is_a?(String) && query.bytesize.between?(1, MAX_QUERY_BYTES) && query.ascii_only?
      raise InvalidBackupUrl, "backup retrieval query is absent or outside its byte boundary"
    end
    begin
      pairs = URI.decode_www_form(query)
    rescue ArgumentError
      raise InvalidBackupUrl, "backup retrieval query is malformed"
    end
    invalid_pair = pairs.any? do |key, value|
      key.empty? || value.empty? || !key.ascii_only? || !value.ascii_only? ||
        key.match?(/[[:cntrl:]]/) || value.match?(/[[:cntrl:]]/) ||
        key.bytesize > 64 || value.bytesize > 2048
    end
    if pairs.empty? || pairs.length > MAX_QUERY_PAIRS || invalid_pair
      raise InvalidBackupUrl, "backup retrieval query is outside its field boundary"
    end
    keys = pairs.map(&:first)
    if keys.uniq.length != keys.length || keys.sort != REQUIRED_QUERY_KEYS.sort
      raise InvalidBackupUrl, "backup retrieval query lacks one exact signature field"
    end
    fields = pairs.to_h
    unless fields["X-Amz-Algorithm"] == "AWS4-HMAC-SHA256" &&
        fields["X-Amz-Credential"]&.match?(/\A[A-Za-z0-9]{3,128}\/[0-9]{8}\/whatever\/s3\/aws4_request\z/) &&
        fields["X-Amz-Date"]&.match?(/\A[0-9]{8}T[0-9]{6}Z\z/) &&
        fields["X-Amz-Expires"]&.match?(/\A[0-9]{1,6}\z/) &&
        fields["X-Amz-Expires"].to_i.between?(1, 604_800) &&
        fields["X-Amz-SignedHeaders"] == "host" &&
        fields["X-Amz-Signature"]&.match?(/\A[0-9a-f]{64}\z/)
      raise InvalidBackupUrl, "backup retrieval signature fields are malformed"
    end
    uri
  rescue URI::InvalidURIError
    raise InvalidBackupUrl, "backup retrieval URL is malformed"
  end

  def self.anonymous_cdn_uri(filename)
    valid_filename!(filename)
    URI::HTTPS.build(
      host: EXPECTED_CDN_HOST,
      path: "/backups/#{EXPECTED_DATABASE}/#{filename}",
    )
  end

  # Prove that the exact unsigned object cannot be retrieved with GET. The
  # response body is counted and discarded so an error document cannot become
  # an unbounded or retained evidence artifact.
  def self.anonymous_get_denied!(response, statuses: %w[401 403])
    status = response.code.to_s
    unless statuses.include?(status)
      raise InvalidBackupUrl, "anonymous backup GET was not denied"
    end
    unless response["location"].to_s.empty?
      raise InvalidBackupUrl, "anonymous backup GET returned a redirect target"
    end
    unless response["set-cookie"].to_s.empty?
      raise InvalidBackupUrl, "anonymous backup GET attempted to set a browser cookie"
    end
    unless response["content-range"].to_s.empty?
      raise InvalidBackupUrl, "anonymous backup denial exposed object range metadata"
    end

    declared_length = response["content-length"]
    if declared_length
      unless declared_length.match?(/\A[0-9]+\z/) && declared_length.to_i <= MAX_ANONYMOUS_DENIAL_BYTES
        raise InvalidBackupUrl, "anonymous backup denial body exceeded its declared boundary"
      end
    end

    received = 0
    response.read_body do |chunk|
      unless chunk.is_a?(String) && received + chunk.bytesize <= MAX_ANONYMOUS_DENIAL_BYTES
        raise InvalidBackupUrl, "anonymous backup denial body exceeded its streamed boundary"
      end
      received += chunk.bytesize
    end
    true
  end
end
