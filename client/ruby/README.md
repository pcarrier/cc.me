# cc-me

Ruby client for [cc.me](https://cc.me/). The library builds trampoline and
inbox URLs and decrypts deliveries; the CLI forwards inbox deliveries to a local
endpoint. Mirrors the canonical JavaScript client and follows the wire protocol
in [`../PROTOCOL.md`](../PROTOCOL.md).

Requires Ruby 3.0+ and [RbNaCl](https://github.com/RubyCrypto/rbnacl) (which
needs libsodium installed).

```sh
gem install cc-me
```

Forward an inbox to a local endpoint:

```sh
cc-me http://example.local:8080/webhook
```

The CLI prints the inbox URL to register with the provider. It uses
`~/.cc-me.key` by default, creating it if needed and reusing it later. The key
is an Ed25519 seed; the URL shows the derived Ed25519 public key. Use `--key` to
choose a specific path:

```sh
cc-me --key ~/hooks.key http://example.local:8080/webhook
```

You can also set `CC_ME_KEY`, `CC_ME_URL`, and `CC_ME_LIMIT`.

```ruby
require "cc_me"

alias_url = CcMe.create_alias("http://example.local/auth/callback")
puts "OAuth callback URL: #{alias_url.url}"

key = CcMe.private_key(File.join(Dir.home, ".cc-me.key"))
cc = CcMe::Client.new(private_key: key)

puts "Webhook URL: #{cc.inbox_url}"
puts "Webmention URL: #{cc.webmention_url}"
puts "WebSub URL: #{cc.websub_url}"
puts "Slack URL: #{cc.slack_url}"
puts "Pingback URL: #{cc.pingback_url}"
puts "Meta URL: #{cc.meta_url('shared-verify-token')}"
puts "CloudEvents URL: #{cc.cloudevents_url}"
puts "Discord URL: #{cc.discord_url('discord-app-public-key')}"

result = cc.claim(limit: 10, poll: true)

handled = []
result.requests.each do |request|
  puts [request.method, request.path, request.text].join(" ")
  handled << request.id
end
cc.ack(handled)
```

`create_alias` is idempotent: calling it again with the same target returns the
same URL.

Protocol URL helpers return provider-ready receiver URLs. Webmention, WebSub,
Slack Events API, Pingback, Meta-style webhooks, CloudEvents, and Discord
Interactions deliveries arrive in the same inbox and are read with `peek` or
`claim`.

`meta_url(token)` adds an optional verify token for Meta-style handshakes.
`cloudevents_url` accepts binary, structured, and batched JSON CloudEvents.
`discord_url(app_public_key)` verifies Discord signatures and answers
interaction PINGs before storing non-PING interactions.

`limit` is optional. Omit it to use the service default:

```ruby
result = cc.claim(poll: true)
```

`peek` returns a cursor for live inspectors and dashboards:

```ruby
page = cc.peek(poll: true)
nxt = cc.peek(cursor: page.cursor, poll: true)
```

Call `CcMe.private_key` with no argument to create an in-memory key, or pass your
own stored base64url seed string to `CcMe::Client.new(private_key: ...)`.
`CcMe.private_key(path)` creates and reuses a key file, keeping it private to the
user (mode 0600) on Unix-like systems.

Each decrypted request exposes `id`, `received_at_unix_ms`, `method`, `path`,
`query`, `headers` (each with `name`, `value`, `value_bytes`), `body_bytes`, and
`text` / `json` helpers. The decrypted `id` is verified against the envelope
`id`.

The `inspect` subcommand from the JS CLI is intentionally not ported.

## Build & test

```sh
bundle install
bundle exec rake test
```
