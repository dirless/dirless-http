require "http/client"
require "openssl"

module Dirless
  module HTTP
    # HTTP::Client subclass that connects to a specific IP address while using
    # the original hostname for TLS SNI and certificate verification.
    #
    # Crystal's HTTP::Client resolves @host for both TCP and SNI. By
    # overriding #connect we direct the TCP connection to @target_ip while
    # keeping @host (the FQDN) for the TLS handshake so the server presents
    # the right certificate and hostname verification succeeds.
    #
    # Usage:
    #   tls = OpenSSL::SSL::Context::Client.new
    #   client = Dirless::HTTP::TargetedClient.new("1.2.3.4", "example.com", 443, tls)
    #   response = client.get("/health")
    class TargetedClient < ::HTTP::Client
      def initialize(@target_ip : String, sni_host : String, port : Int32, tls : OpenSSL::SSL::Context::Client)
        super(sni_host, port, tls: tls)
      end

      private def connect : IO
        socket = TCPSocket.new(@target_ip, @port, connect_timeout: @connect_timeout)
        socket.read_timeout = @read_timeout if @read_timeout
        socket.write_timeout = @write_timeout if @write_timeout
        OpenSSL::SSL::Socket::Client.new(
          socket,
          context: @tls.as(OpenSSL::SSL::Context::Client),
          sync_close: true,
          hostname: @host,
        )
      end
    end
  end
end
