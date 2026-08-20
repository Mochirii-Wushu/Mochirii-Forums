# frozen_string_literal: true

require_relative "storage-response-boundary"

class FixtureChunkedResponse
  attr_reader :chunks_read
  attr_reader :code

  def initialize(chunks, declared_length: nil, headers: {}, code: 200)
    @chunks = chunks
    @declared_length = declared_length
    @code = code.to_s
    @headers = {
      "content-type" => "image/png",
      "server" => "cloudflare",
      "x-do-cdn-uuid" => "12345678-1234-1234-1234-123456789abc",
      "x-amz-request-id" => "fixture-request-123",
      "x-rgw-object-type" => "Normal",
      "cf-cache-status" => "HIT",
      "cf-ray" => "0123456789abcdef-SIN",
      **headers,
    }
    @headers["content-length"] = declared_length if declared_length
    @chunks_read = 0
  end

  def [](name)
    @headers[name]
  end

  def each_header(&block)
    @headers.each(&block)
  end

  def read_body
    @chunks.each do |chunk|
      @chunks_read += 1
      yield chunk
    end
  end
end

maximum = 16
hostile_metadata = [
  { "location" => "https://digitaloceanspaces.com/fixture" },
  { "set-cookie" => "provider=DigitalOcean" },
  { "server" => "Amazon Web Services" },
  { "via" => "neutral-proxy.example" },
  { "x-served-by" => "edge-node.example" },
]
hostile_metadata.each do |headers|
  begin
    MochiriiStorageResponseBoundary.read(FixtureChunkedResponse.new(["safe"], headers: headers), maximum)
    raise "provider or non-neutral media response metadata was accepted"
  rescue MochiriiStorageResponseBoundary::InvalidMediaMetadata
    nil
  end
end

valid_cookie = "__cf_bm=opaque_value-123.abc; HttpOnly; SameSite=None; Secure; Path=/; Domain=media-forums.mochirii.com; Expires=Fri, 14 Aug 2026 12:30:00 GMT"
cookie_response = FixtureChunkedResponse.new(["safe"], headers: { "set-cookie" => valid_cookie })
raise "bounded direct-CDN cookie was rejected" unless MochiriiStorageResponseBoundary.read(cookie_response, maximum) == "safe"

range_response = FixtureChunkedResponse.new(
  ["four"],
  declared_length: "4",
  code: 206,
  headers: { "content-range" => "bytes 0-3/16" },
)
raise "bounded range transport response was rejected" unless MochiriiStorageResponseBoundary.read(range_response, maximum) == "four"

hostile_transport_headers = [
  { "server" => "nginx" },
  { "x-do-cdn-uuid" => "not-a-uuid" },
  { "x-amz-request-id" => "UPPERCASE" },
  { "x-rgw-object-type" => "Other" },
  { "cf-cache-status" => "hit" },
  { "cf-ray" => "0123456789abcdef-too-long" },
  { "set-cookie" => valid_cookie.sub("Domain=media-forums.mochirii.com", "Domain=provider.example") },
  { "set-cookie" => valid_cookie.sub("__cf_bm=", "session=") },
  { "set-cookie" => "#{valid_cookie}; Unknown=value" },
  { "etag" => "https://provider.example/object" },
  { "cache-control" => "public\r\nLocation: https://provider.example" },
  { "content-range" => "bytes 0-3/16" },
  { "set-cookie" => "__cf_bm=#{"a" * 4097}" },
]
hostile_transport_headers.each do |headers|
  begin
    MochiriiStorageResponseBoundary.read(FixtureChunkedResponse.new(["safe"], headers: headers), maximum)
    raise "hostile direct-CDN transport metadata was accepted"
  rescue MochiriiStorageResponseBoundary::InvalidMediaMetadata
    nil
  end
end

duplicate_response = FixtureChunkedResponse.new(["safe"])
def duplicate_response.each_header
  super { |name, value| yield name, value }
  yield "server", "cloudflare"
end
begin
  MochiriiStorageResponseBoundary.read(duplicate_response, maximum)
  raise "duplicate direct-CDN transport header was accepted"
rescue MochiriiStorageResponseBoundary::InvalidMediaMetadata
  nil
end

begin
  MochiriiStorageResponseBoundary.read(FixtureChunkedResponse.new(["safe"], code: 206), maximum)
  raise "range response without Content-Range was accepted"
rescue MochiriiStorageResponseBoundary::InvalidMediaMetadata
  nil
end

begin
  MochiriiStorageResponseBoundary.read(FixtureChunkedResponse.new(["powered by Discourse"]), maximum * 2)
  raise "provider or upstream media response body was accepted"
rescue MochiriiStorageResponseBoundary::InvalidMediaMetadata
  nil
end

exact = FixtureChunkedResponse.new(["a" * 7, "b" * 9])
unless MochiriiStorageResponseBoundary.read(exact, maximum).bytesize == maximum
  raise "exact bounded response changed"
end

declared = FixtureChunkedResponse.new([], declared_length: "17")
begin
  MochiriiStorageResponseBoundary.read(declared, maximum)
  raise "oversized declared response was accepted"
rescue MochiriiStorageResponseBoundary::ResponseTooLarge
  unless declared.chunks_read.zero?
    raise "declared response consumed a chunk before rejection"
  end
end

chunked = FixtureChunkedResponse.new(["a" * 10, "b" * 7, "never-read"])
begin
  MochiriiStorageResponseBoundary.read(chunked, maximum)
  raise "oversized chunked response was accepted"
rescue MochiriiStorageResponseBoundary::ResponseTooLarge
  unless chunked.chunks_read == 2
    raise "chunked response was not stopped at the first oversized chunk"
  end
end

original = MochiriiStorageResponseBoundary.canonical_public_uri(
  "https://media-forums.mochirii.com/original/1X/fixture.png",
  "original",
)
optimized = MochiriiStorageResponseBoundary.canonical_public_uri(
  "https://media-forums.mochirii.com/optimized/1X/fixture_2_128x128.png",
  "optimized",
)
raise "canonical object-family URL changed" unless original.path.start_with?("/original/") && optimized.path.start_with?("/optimized/")

hostile_urls = [
  ["https://media-forums.mochirii.com/optimized/1X/wrong.png", "original"],
  ["https://media-forums.mochirii.com/original/1X/wrong.png", "optimized"],
  ["https://media-forums.mochirii.com/uploads/default/wrong.png", "original"],
  ["//media-forums.mochirii.com/original/1X/wrong.png", "original"],
  ["https://user@media-forums.mochirii.com/original/1X/wrong.png", "original"],
  ["https://media-forums.mochirii.com:444/original/1X/wrong.png", "original"],
  ["https://media-forums.mochirii.com/original/1X/wrong.png?token=forbidden", "original"],
  ["https://media-forums.mochirii.com/original/1X/wrong.png#fragment", "original"],
]
hostile_urls.each do |value, family|
  begin
    MochiriiStorageResponseBoundary.canonical_public_uri(value, family)
    raise "wrong-family or noncanonical media URL was accepted"
  rescue MochiriiStorageResponseBoundary::InvalidMediaUrl
    nil
  end
end

puts "Hosted storage response byte-bound hostile fixtures passed."
