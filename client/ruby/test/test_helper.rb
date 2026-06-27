# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "json"
require "digest"
require "rbnacl"

require "cc_me"

module SealHelper
  # All-7s seed used across the decryption tests.
  SEED = ("\x07" * 32).b

  def key_b64u(seed = SEED)
    CcMe.b64u_encode(seed)
  end

  def ed25519_pubkey_b64u(seed = SEED)
    CcMe.b64u_encode(RbNaCl::SigningKey.new(seed).verify_key.to_bytes)
  end

  # Reproduce the server's seal path: derive the recipient X25519 public key
  # from the Ed25519 seed exactly as the client does (so the two agree), then
  # perform the libsodium sealed-box construction (ephemeral pk || box, with the
  # BLAKE2b nonce).
  def server_seal(plaintext, seed = SEED)
    recipient_secret = RbNaCl::PrivateKey.new(Digest::SHA512.digest(seed)[0, 32])
    recipient_public = recipient_secret.public_key

    ephemeral = RbNaCl::PrivateKey.generate
    ephemeral_public = ephemeral.public_key
    nonce = RbNaCl::Hash.blake2b(
      ephemeral_public.to_bytes + recipient_public.to_bytes,
      digest_size: 24
    )
    box = RbNaCl::Box.new(recipient_public, ephemeral).box(nonce, plaintext)
    CcMe.b64u_encode(ephemeral_public.to_bytes + box)
  end

  # Build a single-delivery sealed envelope-response JSON.
  def sealed_response(id, payload, seed = SEED)
    JSON.generate(
      "count" => 1,
      "items" => [{ "id" => id, "sealed" => server_seal(JSON.generate(payload), seed) }],
      "cursor" => nil
    )
  end
end
