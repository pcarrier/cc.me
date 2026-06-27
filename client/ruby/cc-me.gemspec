# frozen_string_literal: true

require_relative "lib/cc_me/version"

Gem::Specification.new do |spec|
  spec.name = "cc-me"
  spec.version = CcMe::VERSION
  spec.summary = "cc.me trampoline and encrypted webhook queue client + CLI"
  spec.description = <<~DESC.strip
    Ruby client for cc.me. Builds trampoline and inbox URLs and decrypts
    deliveries; the cc-me CLI forwards inbox deliveries to a local endpoint.
    Mirrors the canonical JavaScript client.
  DESC
  spec.authors = ["xmit dev team"]
  spec.homepage = "https://cc.me/"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata = {
    "homepage_uri" => "https://cc.me/",
    "source_code_uri" => "https://github.com/xmit-co/cc.me",
    "documentation_uri" => "https://github.com/xmit-co/cc.me/blob/main/client/PROTOCOL.md"
  }

  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.bindir = "exe"
  spec.executables = ["cc-me"]
  spec.require_paths = ["lib"]

  spec.add_dependency "base64", "~> 0.2"
  spec.add_dependency "rbnacl", "~> 7.1"
end
