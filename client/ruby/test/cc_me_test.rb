# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class CcMeTest < Minitest::Test
  include SealHelper

  def client(base_url = "https://cc.me/")
    CcMe::Client.new(private_key: key_b64u, base_url: base_url)
  end

  # --- base64url round-trips ------------------------------------------------

  def test_b64u_roundtrip_arbitrary_bytes
    [0, 1, 2, 3, 4, 5, 16, 31, 32, 33, 100, 4096].each do |len|
      data = (0...len).map { |i| (i * 31 + 7) % 256 }.pack("C*")
      assert_equal data, CcMe.b64u_decode(CcMe.b64u_encode(data)), "len #{len}"
    end
  end

  def test_b64u_has_no_padding
    refute_includes CcMe.b64u_encode("a"), "="
    refute_includes CcMe.b64u_encode("ab"), "="
    refute_includes CcMe.b64u_encode("abcde"), "="
  end

  def test_b64u_uses_url_safe_alphabet
    encoded = CcMe.b64u_encode([0xfb, 0xff, 0xbf].pack("C*"))
    refute_includes encoded, "+"
    refute_includes encoded, "/"
    assert_equal [0xfb, 0xff, 0xbf].pack("C*"), CcMe.b64u_decode(encoded)
  end

  def test_b64u_empty_is_empty_string
    assert_equal "", CcMe.b64u_encode("")
    assert_equal "", CcMe.b64u_decode("")
  end

  def test_b64u_decode_trims_whitespace
    encoded = CcMe.b64u_encode("trimmed")
    assert_equal "trimmed", CcMe.b64u_decode("  #{encoded}\n")
  end

  # --- keys -----------------------------------------------------------------

  def test_in_memory_private_key_is_32_byte_seed
    key = CcMe.private_key
    assert_equal 32, CcMe.b64u_decode(key).bytesize
    assert_equal 32, CcMe.seed_bytes(key).bytesize
  end

  def test_generated_keys_are_random
    refute_equal CcMe.private_key, CcMe.private_key
  end

  def test_seed_bytes_rejects_wrong_length
    assert_raises(CcMe::Error) { CcMe.seed_bytes(CcMe.b64u_encode("\x00" * 31)) }
    assert_raises(CcMe::Error) { CcMe.seed_bytes(CcMe.b64u_encode("\x00" * 33)) }
  end

  def test_seed_bytes_rejects_non_base64url
    assert_raises(CcMe::Error) { CcMe.seed_bytes("definitely not base64!!") }
  end

  def test_fixed_seed_has_deterministic_public_key
    assert_equal ed25519_pubkey_b64u, CcMe.b64u_encode(CcMe.signing_key(key_b64u).verify_key.to_bytes)
    assert_equal 32, CcMe.b64u_decode(ed25519_pubkey_b64u).bytesize
  end

  def test_private_key_file_has_trailing_newline_and_reuses
    Dir.mktmpdir do |dir|
      path = File.join(dir, "key")
      key = CcMe.private_key(path)
      assert_equal "#{key}\n", File.read(path)
      assert_equal key, CcMe.private_key(path)
      assert_equal key, CcMe.private_key(path)
    end
  end

  def test_newly_created_key_file_is_0600
    skip "POSIX modes only" if Gem.win_platform?
    Dir.mktmpdir do |dir|
      path = File.join(dir, "key")
      CcMe.private_key(path)
      assert_equal 0o600, File.stat(path).mode & 0o777
    end
  end

  def test_existing_key_file_mode_is_tightened_on_read
    skip "POSIX modes only" if Gem.win_platform?
    Dir.mktmpdir do |dir|
      path = File.join(dir, "key")
      File.write(path, "#{key_b64u}\n")
      File.chmod(0o644, path)
      assert_equal key_b64u, CcMe.private_key(path)
      assert_equal 0o600, File.stat(path).mode & 0o777
    end
  end

  def test_private_key_file_rejects_malformed_contents
    Dir.mktmpdir do |dir|
      path = File.join(dir, "key")
      File.write(path, CcMe.b64u_encode("too-short"))
      assert_raises(CcMe::Error) { CcMe.private_key(path) }
      File.write(path, "this is not a key!!")
      assert_raises(CcMe::Error) { CcMe.private_key(path) }
    end
  end

  def test_client_rejects_bad_key
    assert_raises(CcMe::Error) { CcMe::Client.new(private_key: "nope!!") }
    assert_raises(CcMe::Error) { CcMe::Client.new(private_key: "") }
  end

  # --- signing --------------------------------------------------------------

  def verify_signature(headers, method, path_and_query, body)
    ts = headers[CcMe::AUTH_TIMESTAMP_HEADER]
    body_hash = CcMe.sha256_b64u(body)
    message = "cc-me-v1\n#{method}\n#{path_and_query}\n#{ts}\n#{body_hash}"
    signature = CcMe.b64u_decode(headers[CcMe::AUTH_SIGNATURE_HEADER])
    RbNaCl::SigningKey.new(SEED).verify_key.verify(signature, message)
  end

  def test_canonical_string_format_for_get
    headers = client.send(:sign, "GET", "/i/KEY?l=10&p=", "")
    assert verify_signature(headers, "GET", "/i/KEY?l=10&p=", "")
  end

  def test_empty_body_hash_is_sha256_of_empty
    assert_equal "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", CcMe.sha256_b64u("")
  end

  def test_signature_headers_have_expected_names_and_size
    headers = client.send(:sign, "POST", "/y", "body")
    assert_equal "x-cc-me-timestamp", CcMe::AUTH_TIMESTAMP_HEADER
    assert_equal "x-cc-me-signature", CcMe::AUTH_SIGNATURE_HEADER
    assert headers.key?(CcMe::AUTH_TIMESTAMP_HEADER)
    assert_equal 64, CcMe.b64u_decode(headers[CcMe::AUTH_SIGNATURE_HEADER]).bytesize
  end

  def test_signs_post_with_canonical_string
    headers = client.send(:sign, "POST", "/i/KEY/claim", "{}")
    assert verify_signature(headers, "POST", "/i/KEY/claim", "{}")
  end

  # --- URL builders ---------------------------------------------------------

  def test_trampoline_default_base
    assert_equal "https://cc.me/?at=https%3A%2F%2Fx%2Fcb", CcMe.trampoline_url("https://x/cb")
  end

  def test_trampoline_base_override_without_trailing_slash
    assert_equal "https://alt.example/?at=t", CcMe.trampoline_url("t", base_url: "https://alt.example")
  end

  def test_trampoline_params_in_order
    url = CcMe.trampoline_url("t", base_url: "https://cc.me/", params: { "a" => "1", "b" => "2", "c" => "3" })
    assert_equal "https://cc.me/?at=t&a=1&b=2&c=3", url
  end

  def test_trampoline_encodes_target_and_params
    url = CcMe.trampoline_url("https://x/cb?a=1", base_url: "https://cc.me/", params: { "state" => "s 1" })
    assert_equal "https://cc.me/?at=https%3A%2F%2Fx%2Fcb%3Fa%3D1&state=s+1", url
  end

  def test_inbox_url_param_order_l_c_p
    pk = ed25519_pubkey_b64u
    assert_equal "https://cc.me/i/#{pk}", client.inbox_url
    assert_equal "https://cc.me/i/#{pk}?l=3&c=cur&p=", client.inbox_url(limit: 3, cursor: "cur", poll: true)
    assert_equal "https://cc.me/i/#{pk}?c=c", client.inbox_url(cursor: "c")
    assert_equal "https://cc.me/i/#{pk}?p=", client.inbox_url(poll: true)
    assert_equal "https://cc.me/i/#{pk}?l=1", client.inbox_url(limit: 1)
  end

  def test_inbox_url_encodes_cursor_value
    pk = ed25519_pubkey_b64u
    assert_equal "https://cc.me/i/#{pk}?c=a+b", client.inbox_url(cursor: "a b")
  end

  def test_all_protocol_urls
    pk = ed25519_pubkey_b64u
    assert_equal "https://cc.me/i/#{pk}/webmention", client.webmention_url
    assert_equal "https://cc.me/i/#{pk}/websub", client.websub_url
    assert_equal "https://cc.me/i/#{pk}/slack", client.slack_url
    assert_equal "https://cc.me/i/#{pk}/pingback", client.pingback_url
    assert_equal "https://cc.me/i/#{pk}/cloudevents", client.cloudevents_url
    assert_equal "https://cc.me/i/#{pk}/meta", client.meta_url
  end

  def test_meta_url_with_and_without_token
    pk = ed25519_pubkey_b64u
    assert_equal "https://cc.me/i/#{pk}/meta", client.meta_url
    assert_equal "https://cc.me/i/#{pk}/meta?v=tok", client.meta_url("tok")
    assert_equal "https://cc.me/i/#{pk}/meta?v=a+b%2Fc", client.meta_url("a b/c")
  end

  def test_discord_url_path_and_encoding
    pk = ed25519_pubkey_b64u
    assert_equal "https://cc.me/i/#{pk}/discord/app", client.discord_url("app")
    assert_equal "https://cc.me/i/#{pk}/discord/a%2Fb", client.discord_url("a/b")
    assert_raises(CcMe::Error) { client.discord_url("") }
  end

  def test_base_url_normalisation_adds_trailing_slash
    assert_equal client("https://cc.me").inbox_url, client("https://cc.me/").inbox_url
  end

  def test_default_base_url
    assert_equal "https://cc.me/", CcMe::DEFAULT_BASE_URL
    assert CcMe::Client.new(private_key: key_b64u).inbox_url.start_with?("https://cc.me/i/")
  end

  # --- decryption -----------------------------------------------------------

  def decrypt(json)
    client.send(:decrypt_response, JSON.parse(json), true)
  end

  def test_decrypts_empty_body
    payload = {
      "id" => "m_empty", "received_at_unix_ms" => 1, "method" => "GET",
      "path" => "/i/x", "query" => nil, "headers" => [], "body_b64u" => ""
    }
    d = decrypt(sealed_response("m_empty", payload)).requests[0]
    assert_equal "", d.body_bytes
    assert_equal "", d.text
    assert_nil d.query
    assert_empty d.headers
  end

  def test_decrypts_query_none_vs_some
    no_query = {
      "id" => "m_a", "received_at_unix_ms" => 1, "method" => "GET",
      "path" => "/p", "headers" => [], "body_b64u" => ""
    }
    assert_nil decrypt(sealed_response("m_a", no_query)).requests[0].query

    with_query = no_query.merge("id" => "m_b", "query" => "x=1")
    assert_equal "x=1", decrypt(sealed_response("m_b", with_query)).requests[0].query
  end

  def test_decrypts_various_body_sizes
    [0, 1, 16, 1024, 4096, 9000].each do |len|
      body = (0...len).map { |i| i % 251 }.pack("C*")
      id = "m_#{len}"
      payload = {
        "id" => id, "received_at_unix_ms" => 1, "method" => "POST",
        "path" => "/p", "headers" => [], "body_b64u" => CcMe.b64u_encode(body)
      }
      assert_equal body, decrypt(sealed_response(id, payload)).requests[0].body_bytes, "len #{len}"
    end
  end

  def test_decrypts_headers_with_value_and_value_bytes
    headers = (0...25).map { |i| { "name" => "x-h#{i}", "value_b64u" => CcMe.b64u_encode("v#{i}") } }
    payload = {
      "id" => "m_h", "received_at_unix_ms" => 1, "method" => "POST",
      "path" => "/p", "headers" => headers, "body_b64u" => ""
    }
    d = decrypt(sealed_response("m_h", payload)).requests[0]
    assert_equal 25, d.headers.length
    d.headers.each_with_index do |h, i|
      assert_equal "x-h#{i}", h.name
      assert_equal "v#{i}", h.value
      assert_equal "v#{i}".b, h.value_bytes
    end
  end

  def test_decrypts_non_utf8_header_value_lossily
    raw = [0xff, 0xfe, 0x41].pack("C*")
    payload = {
      "id" => "m_nb", "received_at_unix_ms" => 1, "method" => "GET", "path" => "/p",
      "headers" => [{ "name" => "x-bin", "value_b64u" => CcMe.b64u_encode(raw) }], "body_b64u" => ""
    }
    h = decrypt(sealed_response("m_nb", payload)).requests[0].headers[0]
    assert_equal raw, h.value_bytes
    assert h.value.end_with?("A")
  end

  def test_json_helper_parses_body
    payload = {
      "id" => "m_j", "received_at_unix_ms" => 1, "method" => "POST", "path" => "/p",
      "headers" => [], "body_b64u" => CcMe.b64u_encode('{"k":[1,2,3]}')
    }
    assert_equal 2, decrypt(sealed_response("m_j", payload)).requests[0].json["k"][1]
  end

  def test_too_short_ciphertext_errors
    response = JSON.generate("count" => 1, "items" => [{ "id" => "m_short", "sealed" => CcMe.b64u_encode("\x00" * 16) }])
    error = assert_raises(CcMe::Error) { decrypt(response) }
    assert_includes error.message, "too short"
  end

  def test_exactly_32_byte_ciphertext_errors
    response = JSON.generate("count" => 1, "items" => [{ "id" => "m_32", "sealed" => CcMe.b64u_encode("\x00" * 32) }])
    error = assert_raises(CcMe::Error) { decrypt(response) }
    assert_includes error.message, "too short"
  end

  def test_undecryptable_ciphertext_errors
    response = JSON.generate("count" => 1, "items" => [{ "id" => "m_g", "sealed" => CcMe.b64u_encode("\x03" * 80) }])
    error = assert_raises(CcMe::Error) { decrypt(response) }
    assert_includes error.message, "decrypt"
  end

  def test_ciphertext_for_wrong_recipient_fails
    other_seed = ("\x2a" * 32).b
    payload = {
      "id" => "m_w", "received_at_unix_ms" => 1, "method" => "GET", "path" => "/p",
      "headers" => [], "body_b64u" => ""
    }
    response = JSON.generate(
      "count" => 1,
      "items" => [{ "id" => "m_w", "sealed" => server_seal(JSON.generate(payload), other_seed) }]
    )
    assert_raises(CcMe::Error) { decrypt(response) }
  end

  def test_decrypts_multiple_deliveries
    items = (0...3).map do |i|
      id = "m_#{i}"
      payload = {
        "id" => id, "received_at_unix_ms" => i, "method" => "GET",
        "path" => "/p/#{i}", "headers" => [], "body_b64u" => CcMe.b64u_encode("body#{i}")
      }
      { "id" => id, "sealed" => server_seal(JSON.generate(payload)) }
    end
    resp = decrypt(JSON.generate("count" => 3, "items" => items))
    assert_equal 3, resp.requests.length
    resp.requests.each_with_index do |d, i|
      assert_equal "m_#{i}", d.id
      assert_equal "body#{i}", d.text
    end
  end

  def test_empty_delivery_response_decodes
    resp = decrypt('{"count":0,"items":[],"cursor":null}')
    assert_equal 0, resp.count
    assert_empty resp.requests
    assert_nil resp.cursor
  end

  def test_rejects_id_mismatch
    payload = {
      "id" => "m_real", "received_at_unix_ms" => 1, "method" => "GET",
      "path" => "/i/x", "query" => nil, "headers" => [], "body_b64u" => ""
    }
    response = JSON.generate("count" => 1, "items" => [{ "id" => "m_envelope", "sealed" => server_seal(JSON.generate(payload)) }])
    error = assert_raises(CcMe::Error) { decrypt(response) }
    assert_includes error.message, "id mismatch"
  end

  def test_decrypts_a_server_sealed_delivery
    pubkey = ed25519_pubkey_b64u
    payload = {
      "id" => "m_test123",
      "received_at_unix_ms" => 1_781_337_600_000,
      "method" => "POST",
      "path" => "/i/#{pubkey}/slack",
      "query" => "a=1&b=2",
      "headers" => [{ "name" => "content-type", "value_b64u" => CcMe.b64u_encode("application/json") }],
      "body_b64u" => CcMe.b64u_encode('{"hello":"world"}')
    }
    resp = decrypt(sealed_response("m_test123", payload))
    assert_equal 1, resp.count
    d = resp.requests[0]
    assert_equal "m_test123", d.id
    assert_equal "POST", d.method
    assert_equal "a=1&b=2", d.query
    assert_equal '{"hello":"world"}', d.text
    assert_equal "content-type", d.headers[0].name
    assert_equal "application/json", d.headers[0].value
    assert_equal "world", d.json["hello"]
  end

  def test_decrypt_false_skips_decryption
    payload = {
      "id" => "m_x", "received_at_unix_ms" => 1, "method" => "GET",
      "path" => "/p", "headers" => [], "body_b64u" => ""
    }
    resp = client.send(:decrypt_response, JSON.parse(sealed_response("m_x", payload)), false)
    assert_empty resp.requests
    assert_equal 1, resp.items.length
  end
end
