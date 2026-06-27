# frozen_string_literal: true

# cc-me forward CLI.
#
# Ports the <tt><forward-url></tt> command from +client/js/forward.js+. The
# +inspect+ subcommand is intentionally not ported.

require "cc_me"

module CcMe
  module Forward
    DEFAULT_LIMIT = 10

    HOP_BY_HOP = %w[
      connection
      content-length
      host
      keep-alive
      proxy-authenticate
      proxy-authorization
      te
      trailer
      transfer-encoding
      upgrade
    ].freeze

    module_function

    def default_key_file
      File.join(Dir.home, ".cc-me.key")
    end

    def usage
      warn "usage:\n  cc-me [--key <path>] <forward-url>"
    end

    def parse_args(args)
      env_key = ENV["CC_ME_KEY"]
      key_file = env_key && !env_key.empty? ? env_key : default_key_file
      positionals = []

      i = 0
      while i < args.length
        arg = args[i]
        if arg == "--help" || arg == "-h"
          usage
          exit 0
        elsif arg == "--key"
          i += 1
          raise Error, "--key needs a value" if i >= args.length || args[i].empty?

          key_file = args[i]
        elsif arg.start_with?("--key=")
          value = arg.split("=", 2)[1]
          raise Error, "--key needs a value" if value.nil? || value.empty?

          key_file = value
        elsif arg.start_with?("-")
          raise Error, "unknown option: #{arg}"
        else
          positionals << arg
        end
        i += 1
      end

      raise Error, "only one forward URL is supported" if positionals.length > 1

      [key_file, positionals.first]
    end

    # Build the forward target URL by merging the delivery query into the base.
    def forward_url(base, query)
      return base if query.nil? || query.empty?

      if base.include?("?")
        path, existing = base.split("?", 2)
        existing.empty? ? "#{path}?#{query}" : "#{path}?#{existing}&#{query}"
      else
        "#{base}?#{query}"
      end
    end

    # Replay a single delivery to the target. Raises on transport failure or a
    # non-2xx response.
    def forward_request(target, request)
      uri = URI(forward_url(target, request.query))
      has_body = request.method != "GET" && request.method != "HEAD" && !request.body_bytes.empty?

      req = Net::HTTPGenericRequest.new(request.method, has_body, request.method != "HEAD", uri)
      request.headers.each do |header|
        next if HOP_BY_HOP.include?(header.name.downcase)

        req[header.name] = header.value
      end
      req.body = request.body_bytes if has_body

      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = uri.scheme == "https"
      response = http.request(req)
      code = response.code.to_i
      raise Error, "forward failed with #{code}" unless (200..299).cover?(code)
    rescue SocketError, SystemCallError, Net::OpenTimeout, Net::ReadTimeout => e
      raise Error, "forward transport error: #{e.message}"
    end

    # Process one claimed batch: replay each delivery in order, acking on
    # success. On a forward failure, ack the ids already handled, release the
    # current and remaining ids, and re-raise. On full success, ack every
    # handled id.
    #
    # The optional block replays a single delivery (defaults to
    # +forward_request+); factored out so it is testable against a mock server.
    def process_batch(client, requests, target = nil, &block)
      forward = block || ->(request) { forward_request(target, request) }
      acked = []

      requests.each_with_index do |request, index|
        begin
          forward.call(request)
        rescue StandardError
          release_ids = requests[index..].map(&:id)
          begin
            client.ack(acked) unless acked.empty?
          rescue StandardError
            # already-handled ids are best-effort acked
          end
          begin
            client.release(release_ids) unless release_ids.empty?
          rescue StandardError
            # remaining ids are best-effort released
          end
          raise
        end

        acked << request.id
        suffix = request.query && !request.query.empty? ? "?#{request.query}" : ""
        warn "#{request.method} #{request.path}#{suffix}"
      end

      client.ack(acked) unless acked.empty?
    end

    def run(args)
      key_file, target = parse_args(args)
      if target.nil?
        usage
        exit 64
      end

      key = CcMe.private_key(key_file)
      client = CcMe::Client.new(private_key: key, base_url: ENV["CC_ME_URL"])

      warn "cc.me inbox: #{client.inbox_url}"
      warn "forwarding to: #{target}"

      env_limit = ENV["CC_ME_LIMIT"]
      limit = env_limit && !env_limit.empty? ? env_limit.to_i : DEFAULT_LIMIT

      loop do
        result = client.claim(limit: limit, poll: true)
        process_batch(client, result.requests, target)
      end
    end

    def main(args = ARGV)
      run(args)
    rescue SystemExit
      raise
    rescue StandardError => e
      warn e.message
      exit 1
    end
  end
end
