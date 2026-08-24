# frozen_string_literal: true

require "uri"
require "time"

# Pure bounded-reader helper shared by the hosted storage fixture and its
# hostile source test. It never performs network I/O itself.
module MochiriiStorageResponseBoundary
  class ResponseTooLarge < StandardError; end
  class InvalidMediaUrl < StandardError; end
  class InvalidMediaMetadata < StandardError; end

  ALLOWED_RESPONSE_HEADERS = %w[
    accept-ranges age cache-control cf-cache-status cf-ray connection
    content-length content-range content-type date etag last-modified server
    set-cookie strict-transport-security vary x-amz-request-id x-do-cdn-uuid
    x-rgw-object-type
  ].freeze
  REQUIRED_PROVIDER_HEADERS = %w[
    cf-cache-status cf-ray server x-amz-request-id x-do-cdn-uuid
    x-rgw-object-type
  ].freeze
  FORBIDDEN_IDENTITY = /(?:\bdiscourse\b|discourse[.](?:org|com)|\bdigitalocean\b|digitaloceanspaces[.]com|\bamazon\b|amazonaws[.]com|\baws\b)/i
  FORBIDDEN_URL_OR_CREDENTIAL_FIELD = /(?:https?:\/\/|x-amz-(?:algorithm|credential|date|expires|signature|signedheaders)|awsaccesskeyid|[?&](?:token|signature|key)=)/i
  PUBLIC_MEDIA_HOST = "media-forums.mochirii.com"
  MAX_HEADER_COUNT = 32
  MAX_HEADER_BYTES = 32 * 1024
  MAX_HEADER_VALUE_BYTES = 4096
  MAX_CDN_COOKIE_BYTES = 4096

  def self.canonical_public_uri(value, exact_family)
    unless %w[original optimized].include?(exact_family)
      raise ArgumentError, "media object family is invalid"
    end

    uri = URI.parse(value)
    unless uri.scheme == "https" && uri.host == "media-forums.mochirii.com"
      raise InvalidMediaUrl, "rendered media URL is not canonical HTTPS"
    end
    if uri.user || uri.password || uri.port != 443 || uri.query || uri.fragment
      raise InvalidMediaUrl, "rendered media URL contains forbidden authority data"
    end
    unless uri.path.start_with?("/#{exact_family}/")
      raise InvalidMediaUrl, "rendered media URL object family differs"
    end
    uri
  rescue URI::InvalidURIError
    raise InvalidMediaUrl, "rendered media URL is malformed"
  end

  def self.read(response, maximum_bytes, validate_public_metadata: true)
    raise ArgumentError, "response byte boundary is invalid" unless maximum_bytes.is_a?(Integer) && maximum_bytes.positive?

    validate_metadata(response) if validate_public_metadata
    declared_length = response["content-length"]
    if declared_length&.match?(/\A[0-9]+\z/) && declared_length.to_i > maximum_bytes
      raise ResponseTooLarge, "anonymous HTTP response exceeded its declared byte bound"
    end

    body = String.new(encoding: Encoding::BINARY)
    response.read_body do |chunk|
      unless chunk.is_a?(String) && body.bytesize + chunk.bytesize <= maximum_bytes
        raise ResponseTooLarge, "anonymous HTTP response exceeded its streamed byte bound"
      end
      body << chunk
    end
    if validate_public_metadata && body.match?(FORBIDDEN_IDENTITY)
      raise InvalidMediaMetadata, "anonymous media body exposes upstream or provider identity"
    end
    body
  end

  def self.validate_metadata(response)
    count = 0
    total = 0
    names = []
    status = response.code.to_s
    unless %w[200 206].include?(status)
      raise InvalidMediaMetadata, "anonymous media response status is outside the public object boundary"
    end
    response.each_header do |raw_name, raw_value|
      name = raw_name.to_s.downcase
      value = raw_value.to_s
      unless name.match?(/\A[a-z0-9-]{1,64}\z/) && ALLOWED_RESPONSE_HEADERS.include?(name)
        raise InvalidMediaMetadata, "anonymous media response header is outside the transport allowlist"
      end
      if value.empty? || !value.ascii_only? || value.bytesize > MAX_HEADER_VALUE_BYTES ||
          value.match?(/[[:cntrl:]]/) || value.match?(FORBIDDEN_URL_OR_CREDENTIAL_FIELD)
        raise InvalidMediaMetadata, "anonymous media response metadata exposes unsafe transport bytes"
      end
      unless valid_transport_header?(name, value, status)
        raise InvalidMediaMetadata, "anonymous media response header value is outside its transport grammar"
      end
      if names.include?(name)
        raise InvalidMediaMetadata, "anonymous media response contains a duplicate transport header"
      end
      names << name
      count += 1
      total += name.bytesize + value.bytesize
      if count > MAX_HEADER_COUNT || total > MAX_HEADER_BYTES
        raise InvalidMediaMetadata, "anonymous media response metadata exceeded its bound"
      end
    end
    unless REQUIRED_PROVIDER_HEADERS.all? { |name| names.include?(name) }
      raise InvalidMediaMetadata, "anonymous media response lacks the exact direct-CDN transport evidence"
    end
    if status == "206" && !names.include?("content-range")
      raise InvalidMediaMetadata, "anonymous range response lacks its exact content range"
    end
    if status == "200" && names.include?("content-range")
      raise InvalidMediaMetadata, "anonymous full response unexpectedly contains a content range"
    end
  end

  def self.valid_transport_header?(name, value, status)
    case name
    when "accept-ranges"
      value == "bytes"
    when "age", "content-length"
      value.match?(/\A(?:0|[1-9][0-9]{0,19})\z/)
    when "cache-control"
      value.split(",").all? do |part|
        part.strip.match?(/\A(?:public|private|no-cache|no-store|must-revalidate|immutable|max-age=[0-9]{1,10}|s-maxage=[0-9]{1,10}|stale-(?:while-revalidate|if-error)=[0-9]{1,10})\z/i)
      end
    when "cf-cache-status"
      value.match?(/\A[A-Z_-]{1,32}\z/)
    when "cf-ray"
      value.match?(/\A[0-9a-f]{16}-[A-Z]{3}\z/)
    when "connection"
      value.casecmp?("keep-alive") || value.casecmp?("close")
    when "content-range"
      return false unless status == "206"
      match = value.match(/\Abytes ([0-9]+)-([0-9]+)\/([0-9]+)\z/)
      match && match[1].to_i <= match[2].to_i && match[2].to_i < match[3].to_i
    when "content-type"
      value.match?(/\Aimage\/(?:avif|gif|jpeg|png|svg\+xml|webp)(?:; charset=(?:utf-8|us-ascii))?\z/i)
    when "date", "last-modified"
      valid_http_date?(value)
    when "etag"
      value.match?(/\A(?:W\/)?"[!#-~]{1,256}"\z/)
    when "server"
      value == "cloudflare"
    when "set-cookie"
      valid_cdn_cookie?(value)
    when "strict-transport-security"
      value.match?(/\Amax-age=[0-9]{1,10}(?:; includeSubDomains)?\z/i)
    when "vary"
      value.split(",").all? { |field| field.strip.match?(/\A(?:Accept-Encoding|Origin)\z/i) }
    when "x-amz-request-id"
      value.match?(/\A[a-z0-9-]{1,128}\z/)
    when "x-do-cdn-uuid"
      value.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/)
    when "x-rgw-object-type"
      value == "Normal"
    else
      false
    end
  end

  def self.valid_http_date?(value)
    Time.httpdate(value)
    true
  rescue ArgumentError
    false
  end

  def self.valid_cdn_cookie?(value)
    return false if value.bytesize > MAX_CDN_COOKIE_BYTES

    fields = value.split(";").map(&:strip)
    name_value = fields.shift
    return false unless name_value&.match?(/\A__cf_bm=[A-Za-z0-9._~-]{1,3584}\z/)

    attributes = {}
    fields.each do |field|
      key, attribute_value = field.split("=", 2)
      normalized = key.downcase
      return false if attributes.key?(normalized)
      attributes[normalized] = attribute_value
    end
    return false unless attributes.keys.sort == %w[domain expires httponly path samesite secure]
    return false unless attributes["httponly"].nil? && attributes["secure"].nil?
    return false unless attributes["domain"]&.casecmp?(PUBLIC_MEDIA_HOST)
    return false unless attributes["path"] == "/" && attributes["samesite"]&.casecmp?("None")

    valid_http_date?(attributes.fetch("expires", ""))
  end
end
