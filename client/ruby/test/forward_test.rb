# frozen_string_literal: true

require "test_helper"
require "cc_me/forward"
require "socket"

# Minimal recording HTTP server: replies with a fixed status/body to every
# request and records method, target, headers, and body.
class MockServer
  Recorded = Struct.new(:method, :target, :headers, :body)

  attr_reader :recorded

  def initialize(status: 200, body: "{}")
    @status = status
    @body = body
    @recorded = []
    @server = TCPServer.new("127.0.0.1", 0)
    @thread = Thread.new { accept_loop }
  end

  def url
    "http://127.0.0.1:#{@server.addr[1]}/"
  end

  def posts_ending(suffix)
    @recorded.select { |r| r.method == "POST" && r.target.end_with?(suffix) }
  end

  def close
    @server.close
    @thread.kill
  end

  private

  def accept_loop
    loop do
      socket = @server.accept
      handle(socket)
    rescue IOError, Errno::EBADF
      break
    end
  end

  def handle(socket)
    request_line = socket.gets
    return socket.close if request_line.nil?

    method, target, = request_line.split
    headers = {}
    while (line = socket.gets) && line != "\r\n"
      name, value = line.split(":", 2)
      headers[name.strip.downcase] = value.strip if value
    end
    length = headers.fetch("content-length", "0").to_i
    body = length.positive? ? socket.read(length) : ""
    @recorded << Recorded.new(method, target, headers, body)

    socket.write("HTTP/1.1 #{@status} OK\r\ncontent-type: application/json\r\n" \
                 "content-length: #{@body.bytesize}\r\nconnection: close\r\n\r\n#{@body}")
    socket.close
  end
end

# Records ack/release calls; optionally raises from each.
class FakeClient
  attr_reader :acked, :released

  def initialize(raise_on: nil)
    @acked = []
    @released = []
    @raise_on = raise_on
  end

  def ack(ids)
    raise CcMe::Error, "ack failed" if @raise_on == :ack

    @acked << ids
  end

  def release(ids)
    raise CcMe::Error, "release failed" if @raise_on == :release

    @released << ids
  end
end

class ForwardTest < Minitest::Test
  include SealHelper

  def delivery(id, method, query, body: "", headers: [])
    CcMe::CapturedRequest.new(
      id: id, received_at_unix_ms: 0, method: method, path: "/i/x",
      query: query, headers: headers, body_bytes: body.b
    )
  end

  # --- hop-by-hop ----------------------------------------------------------

  def test_hop_by_hop_constant
    %w[connection content-length host keep-alive proxy-authenticate
       proxy-authorization te trailer transfer-encoding upgrade].each do |name|
      assert_includes CcMe::Forward::HOP_BY_HOP, name
    end
    refute_includes CcMe::Forward::HOP_BY_HOP, "content-type"
    refute_includes CcMe::Forward::HOP_BY_HOP, "authorization"
  end

  # --- forward_url ---------------------------------------------------------

  def test_forward_url_no_query_is_unchanged
    assert_equal "http://x/cb", CcMe::Forward.forward_url("http://x/cb", nil)
    assert_equal "http://x/cb", CcMe::Forward.forward_url("http://x/cb", "")
  end

  def test_forward_url_adds_query_when_base_has_none
    assert_equal "http://x/cb?a=1&b=2", CcMe::Forward.forward_url("http://x/cb", "a=1&b=2")
  end

  def test_forward_url_merges_with_existing_query
    assert_equal "http://x/cb?z=9&a=1", CcMe::Forward.forward_url("http://x/cb?z=9", "a=1")
  end

  def test_forward_url_handles_trailing_question_mark
    assert_equal "http://x/cb?a=1", CcMe::Forward.forward_url("http://x/cb?", "a=1")
  end

  # --- forward_request -----------------------------------------------------

  def test_forward_request_replays_method_headers_and_body
    server = MockServer.new
    d = delivery("m_1", "POST", "a=1", body: "hello-body", headers: [
                   CcMe::CapturedHeader.new("x-custom", "v", "v".b),
                   CcMe::CapturedHeader.new("host", "evil.example", "evil.example".b)
                 ])
    CcMe::Forward.forward_request(server.url, d)
    r = server.recorded[0]
    assert_equal "POST", r.method
    assert_equal "/?a=1", r.target
    assert_equal "hello-body", r.body
    assert_equal "v", r.headers["x-custom"]
    refute_equal "evil.example", r.headers["host"]
  ensure
    server&.close
  end

  def test_forward_request_get_sends_no_body
    server = MockServer.new
    d = delivery("m_g", "GET", nil, body: "should-be-ignored")
    CcMe::Forward.forward_request(server.url, d)
    assert_equal "", server.recorded[0].body
  ensure
    server&.close
  end

  def test_forward_request_non_2xx_is_error
    server = MockServer.new(status: 500)
    error = assert_raises(CcMe::Error) { CcMe::Forward.forward_request(server.url, delivery("m_e", "POST", nil)) }
    assert_includes error.message, "500"
  ensure
    server&.close
  end

  def test_forward_request_transport_error
    error = assert_raises(CcMe::Error) do
      CcMe::Forward.forward_request("http://127.0.0.1:1/", delivery("m_t", "GET", nil))
    end
    assert_includes error.message, "transport"
  end

  # --- process_batch -------------------------------------------------------

  def test_process_batch_acks_all_on_success
    client = FakeClient.new
    requests = [delivery("m_1", "POST", nil), delivery("m_2", "POST", nil)]
    CcMe::Forward.process_batch(client, requests) { |_| nil }
    assert_equal [%w[m_1 m_2]], client.acked
    assert_empty client.released
  end

  def test_process_batch_acks_handled_and_releases_remainder_on_failure
    client = FakeClient.new
    requests = [delivery("m_1", "POST", nil), delivery("m_2", "POST", nil), delivery("m_3", "POST", nil)]
    calls = 0
    error = assert_raises(RuntimeError) do
      CcMe::Forward.process_batch(client, requests) do |_|
        calls += 1
        raise "boom" if calls > 1
      end
    end
    assert_equal "boom", error.message
    assert_equal [%w[m_1]], client.acked
    assert_equal [%w[m_2 m_3]], client.released
  end

  def test_process_batch_first_failure_releases_all_and_skips_ack
    client = FakeClient.new
    requests = [delivery("m_1", "POST", nil), delivery("m_2", "POST", nil)]
    assert_raises(RuntimeError) do
      CcMe::Forward.process_batch(client, requests) { |_| raise "nope" }
    end
    assert_empty client.acked
    assert_equal [%w[m_1 m_2]], client.released
  end

  def test_process_batch_empty_does_nothing
    client = FakeClient.new
    CcMe::Forward.process_batch(client, []) { |_| nil }
    assert_empty client.acked
    assert_empty client.released
  end

  # --- argument parsing ----------------------------------------------------

  def test_parse_args_target_and_default_key
    ENV.delete("CC_ME_KEY")
    key_file, target = CcMe::Forward.parse_args(["http://x/cb"])
    assert_equal CcMe::Forward.default_key_file, key_file
    assert_equal "http://x/cb", target
  end

  def test_parse_args_key_flag
    _, = CcMe::Forward.parse_args(["--key", "/tmp/k", "http://x"])
    key_file, target = CcMe::Forward.parse_args(["--key", "/tmp/k", "http://x"])
    assert_equal "/tmp/k", key_file
    assert_equal "http://x", target

    key_eq, = CcMe::Forward.parse_args(["--key=/tmp/k2", "http://x"])
    assert_equal "/tmp/k2", key_eq
  end

  def test_parse_args_rejects_unknown_option_and_extra_positionals
    assert_raises(CcMe::Error) { CcMe::Forward.parse_args(["--nope"]) }
    assert_raises(CcMe::Error) { CcMe::Forward.parse_args(["a", "b"]) }
    assert_raises(CcMe::Error) { CcMe::Forward.parse_args(["--key"]) }
  end

  def test_parse_args_no_target
    ENV.delete("CC_ME_KEY")
    _, target = CcMe::Forward.parse_args([])
    assert_nil target
  end

  def test_parse_args_honours_cc_me_key_env
    ENV["CC_ME_KEY"] = "/env/key"
    key_file, = CcMe::Forward.parse_args(["http://x"])
    assert_equal "/env/key", key_file
  ensure
    ENV.delete("CC_ME_KEY")
  end
end
