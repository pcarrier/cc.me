# frozen_string_literal: true

# cc.me client library.
#
# Mirrors the canonical JavaScript implementation in +client/js/index.js+ and
# follows the wire protocol described in +client/PROTOCOL.md+. The Rust server
# in +src/main.rs+ is the source of truth for the wire format.

require "base64"
require "digest"
require "json"
require "net/http"
require "uri"

require "rbnacl"

require_relative "cc_me/version"

module CcMe
  DEFAULT_BASE_URL = "https://cc.me/"
  AUTH_VERSION = "cc-me-v1"
  AUTH_TIMESTAMP_HEADER = "x-cc-me-timestamp"
  AUTH_SIGNATURE_HEADER = "x-cc-me-signature"
  SEED_BYTES = 32
  SEALED_BOX_PUBLIC_KEY_BYTES = 32
  SEALED_BOX_NONCE_BYTES = 24

  # Raised for invalid keys, transport/non-2xx responses, and decode failures.
  class Error < StandardError; end

  # --- base64url helpers (no padding) -------------------------------------

  def self.b64u_encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def self.b64u_decode(value)
    str = value.to_s.strip
    padding = "=" * ((4 - (str.length % 4)) % 4)
    Base64.urlsafe_decode64(str + padding)
  rescue ArgumentError => e
    raise Error, "invalid base64url: #{e.message}"
  end

  def self.sha256_b64u(bytes)
    b64u_encode(Digest::SHA256.digest(bytes))
  end

  # --- key handling --------------------------------------------------------

  # Decode a base64url private key into its 32 seed bytes, validating length.
  def self.seed_bytes(value)
    seed = b64u_decode(value)
    unless seed.bytesize == SEED_BYTES
      raise Error, "private_key must be 32 bytes of base64url"
    end

    seed
  end

  def self.signing_key(value)
    RbNaCl::SigningKey.new(seed_bytes(value))
  end

  def self.generate_private_key
    b64u_encode(RbNaCl::Random.random_bytes(SEED_BYTES))
  end

  # Load or create a base64url Ed25519 seed.
  #
  # With +nil+ a fresh in-memory key is generated and returned (not persisted).
  # With a +path+ the file is reused if present (and re-secured to mode 0600 on
  # Unix), otherwise created with mode 0600 containing the base64url seed
  # followed by a newline.
  def self.private_key(path = nil)
    return generate_private_key if path.nil?

    if File.exist?(path)
      key = File.read(path).strip
      seed_bytes(key) # validate
      secure_key_file(path)
      return key
    end

    key = generate_private_key
    File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write("#{key}\n")
    end
    secure_key_file(path)
    key
  end

  def self.secure_key_file(path)
    return if Gem.win_platform?

    File.chmod(0o600, path)
  end

  # --- URL helpers ---------------------------------------------------------

  def self.normalize_base(base_url)
    base = base_url.nil? || base_url.empty? ? DEFAULT_BASE_URL : base_url
    base.end_with?("/") ? base : "#{base}/"
  end

  def self.trim_trailing_slash(value)
    value.end_with?("/") ? value[0...-1] : value
  end

  # Percent-encode a single path segment, matching JS +encodeURIComponent+
  # (everything but the RFC 3986 unreserved set).
  def self.percent_encode(value)
    value.to_s.b.each_byte.map do |byte|
      if (0x41..0x5A).cover?(byte) || (0x61..0x7A).cover?(byte) ||
         (0x30..0x39).cover?(byte) || [0x2D, 0x5F, 0x2E, 0x7E].include?(byte)
        byte.chr
      else
        format("%%%02X", byte)
      end
    end.join
  end

  # Encode a query parameter value, matching JS +URLSearchParams+ / Python
  # +urlencode+ (space becomes +).
  def self.encode_query_value(value)
    URI.encode_www_form_component(value.to_s)
  end

  # Build a trampoline URL: <tt>{base}/?at={target}</tt> plus any extra params.
  def self.trampoline_url(target, base_url: nil, params: nil)
    query = +"at=#{encode_query_value(target)}"
    (params || {}).each do |key, value|
      next if value.nil?

      query << "&#{encode_query_value(key)}=#{encode_query_value(value)}"
    end
    "#{normalize_base(base_url)}?#{query}"
  end

  # Alias response wrapper: exposes +url+.
  AliasResponse = Struct.new(:url)

  # POST <tt>{base}/c</tt> with <tt>{"at": target}</tt> -> alias URL. Idempotent,
  # no auth.
  def self.create_alias(target, base_url: nil)
    url = "#{normalize_base(base_url)}c"
    body = JSON.generate("at" => target.to_s)
    response = http_request("POST", url, body, "content-type" => "application/json")
    AliasResponse.new(response["url"])
  end

  # --- HTTP helpers --------------------------------------------------------

  def self.http_request(method, url, body, headers)
    uri = URI(url)
    request =
      case method
      when "GET" then Net::HTTP::Get.new(uri)
      when "POST" then Net::HTTP::Post.new(uri)
      else raise Error, "unsupported method #{method}"
      end
    headers.each { |name, value| request[name] = value }
    request.body = body if body

    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = uri.scheme == "https"
    parse_json_response(http.request(request))
  rescue SocketError, SystemCallError, Net::OpenTimeout, Net::ReadTimeout => e
    raise Error, "cc.me request failed: #{e.message}"
  end

  def self.parse_json_response(response)
    raw = response.body
    parsed =
      if raw && !raw.empty?
        begin
          JSON.parse(raw)
        rescue JSON::ParserError
          {}
        end
      else
        {}
      end

    code = response.code.to_i
    unless (200..299).cover?(code)
      message = (parsed.is_a?(Hash) && parsed["error"]) || "cc.me request failed with #{code}"
      raise Error, message
    end
    parsed
  end

  # --- captured requests ---------------------------------------------------

  CapturedHeader = Struct.new(:name, :value, :value_bytes)

  # A decrypted delivery (the captured HTTP request).
  class CapturedRequest
    attr_reader :id, :received_at_unix_ms, :method, :path, :query, :headers, :body_bytes

    def initialize(id:, received_at_unix_ms:, method:, path:, query:, headers:, body_bytes:)
      @id = id
      @received_at_unix_ms = received_at_unix_ms
      @method = method
      @path = path
      @query = query
      @headers = headers
      @body_bytes = body_bytes
    end

    # Body decoded as UTF-8.
    def text
      @body_bytes.dup.force_encoding(Encoding::UTF_8)
    end

    # Body parsed as JSON.
    def json
      JSON.parse(text)
    end
  end

  def self.decode_captured_request(plaintext)
    parsed = JSON.parse(plaintext)
    body_bytes = b64u_decode(parsed["body_b64u"])
    headers = (parsed["headers"] || []).map do |header|
      value_bytes = b64u_decode(header["value_b64u"])
      value = value_bytes.dup.force_encoding(Encoding::UTF_8)
      value = value.scrub unless value.valid_encoding?
      CapturedHeader.new(header["name"], value, value_bytes)
    end
    CapturedRequest.new(
      id: parsed["id"],
      received_at_unix_ms: parsed["received_at_unix_ms"],
      method: parsed["method"],
      path: parsed["path"],
      query: parsed["query"],
      headers: headers,
      body_bytes: body_bytes
    )
  end

  # Response from peek/claim: the count, raw items, cursor, and decrypted
  # requests.
  DeliveryResponse = Struct.new(:count, :items, :cursor, :requests, keyword_init: true)

  # A client bound to a single private key and base URL.
  class Client
    def initialize(private_key:, base_url: nil)
      raise Error, "private_key is required" if private_key.nil? || private_key.empty?

      @private_key = private_key
      @base_url = CcMe.normalize_base(base_url)
      @signing_key = CcMe.signing_key(private_key)
      @public_key = CcMe.b64u_encode(@signing_key.verify_key.to_bytes)

      # Recipient X25519 secret key, derived from the Ed25519 seed the same way
      # libsodium's crypto_sign_ed25519_sk_to_curve25519 does: the first 32
      # bytes of SHA512(seed). The X25519 public key is then scalarmult_base of
      # that secret, which equals the Montgomery form of the Ed25519 public key.
      seed = CcMe.seed_bytes(private_key)
      @x_secret = RbNaCl::PrivateKey.new(Digest::SHA512.digest(seed)[0, 32])
      @x_public = @x_secret.public_key
    end

    # -- URL helpers --

    def inbox_url(limit: nil, cursor: nil, poll: false)
      "#{CcMe.trim_trailing_slash(@base_url)}#{inbox_query(limit: limit, cursor: cursor, poll: poll)}"
    end

    def webmention_url
      protocol_url("webmention")
    end

    def websub_url
      protocol_url("websub")
    end

    def slack_url
      protocol_url("slack")
    end

    def pingback_url
      protocol_url("pingback")
    end

    def meta_url(verify_token = nil)
      base = protocol_url("meta")
      return base if verify_token.nil?

      "#{base}?v=#{CcMe.encode_query_value(verify_token)}"
    end

    def cloudevents_url
      protocol_url("cloudevents")
    end

    def discord_url(app_public_key)
      if app_public_key.nil? || app_public_key.to_s.empty?
        raise Error, "app_public_key is required"
      end

      "#{CcMe.trim_trailing_slash(@base_url)}#{inbox_path}/discord/#{CcMe.percent_encode(app_public_key)}"
    end

    # -- requests --

    def peek(limit: nil, cursor: nil, poll: false, decrypt: true)
      path_and_query = inbox_query(limit: limit, cursor: cursor, poll: poll)
      url = "#{CcMe.trim_trailing_slash(@base_url)}#{path_and_query}"
      headers = sign("GET", path_and_query, "")
      decrypt_response(CcMe.http_request("GET", url, nil, headers), decrypt)
    end

    def claim(limit: nil, poll: false, decrypt: true)
      payload = { "poll" => poll }
      payload["limit"] = limit unless limit.nil?
      body = JSON.generate(payload)
      decrypt_response(signed_post("claim", body), decrypt)
    end

    def ack(ids)
      signed_post("ack", JSON.generate("ids" => Array(ids)))
    end

    def release(ids)
      signed_post("release", JSON.generate("ids" => Array(ids)))
    end

    private

    def inbox_path
      "/i/#{@public_key}"
    end

    # Build the inbox path+query string used both for signing and the wire.
    def inbox_query(limit: nil, cursor: nil, poll: false)
      path = inbox_path.dup
      params = []
      params << "l=#{limit}" unless limit.nil?
      params << "c=#{CcMe.encode_query_value(cursor)}" unless cursor.nil?
      params << "p=" if poll
      path << "?#{params.join('&')}" unless params.empty?
      path
    end

    def protocol_url(protocol)
      "#{CcMe.trim_trailing_slash(@base_url)}#{inbox_path}/#{protocol}"
    end

    def signed_post(action, body)
      path_and_query = "#{inbox_path}/#{action}"
      url = "#{CcMe.trim_trailing_slash(@base_url)}#{path_and_query}"
      headers = { "content-type" => "application/json" }.merge(sign("POST", path_and_query, body))
      CcMe.http_request("POST", url, body, headers)
    end

    # Build the two owner-auth headers for a request. The +path_and_query+ bytes
    # signed here MUST equal the bytes sent on the wire.
    def sign(method, path_and_query, body)
      timestamp = Time.now.to_i
      message = "#{AUTH_VERSION}\n#{method}\n#{path_and_query}\n#{timestamp}\n#{CcMe.sha256_b64u(body)}"
      {
        AUTH_TIMESTAMP_HEADER => timestamp.to_s,
        AUTH_SIGNATURE_HEADER => CcMe.b64u_encode(@signing_key.sign(message))
      }
    end

    def decrypt_response(body, decrypt)
      items = body["items"] || []
      requests = decrypt ? items.map { |item| decrypt_envelope(item) } : []
      DeliveryResponse.new(
        count: body.fetch("count", items.length),
        items: items,
        cursor: body["cursor"],
        requests: requests
      )
    end

    def decrypt_envelope(envelope)
      sealed = CcMe.b64u_decode(envelope["sealed"])
      if sealed.bytesize <= SEALED_BOX_PUBLIC_KEY_BYTES
        raise Error, "encrypted delivery is too short"
      end

      ephemeral_public = sealed[0, SEALED_BOX_PUBLIC_KEY_BYTES]
      box = sealed[SEALED_BOX_PUBLIC_KEY_BYTES..]
      nonce = RbNaCl::Hash.blake2b(
        ephemeral_public + @x_public.to_bytes,
        digest_size: SEALED_BOX_NONCE_BYTES
      )
      begin
        plaintext = RbNaCl::Box.new(RbNaCl::PublicKey.new(ephemeral_public), @x_secret).open(nonce, box)
      rescue RbNaCl::CryptoError
        raise Error, "failed to decrypt delivery"
      end

      request = CcMe.decode_captured_request(plaintext)
      raise Error, "delivery id mismatch" unless request.id == envelope["id"]

      request
    end
  end
end
