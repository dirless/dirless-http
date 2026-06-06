require "http/client"
require "openssl"

module Dirless
  module Net
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
    #   client = Dirless::Net::TargetedClient.new("1.2.3.4", "example.com", 443, tls)
    #   response = client.get("/health")
    class TargetedClient < ::HTTP::Client
      def initialize(@target_ip : String, sni_host : String, port : Int32, tls : OpenSSL::SSL::Context::Client)
        super(sni_host, port, tls: tls)
      end

      # Crystal 1.14+ moved connection logic from #connect to #io. Override #io
      # so TCP connects to @target_ip while TLS SNI still uses @host (the FQDN).
      private def io
        cached = @io
        return cached if cached
        unless @reconnect
          raise "This HTTP::Client cannot be reconnected"
        end

        tcp = TCPSocket.new(@target_ip, @port, connect_timeout: @connect_timeout)
        tcp.read_timeout = @read_timeout if @read_timeout
        tcp.write_timeout = @write_timeout if @write_timeout
        tcp.sync = false

        if tls = @tls
          begin
            ssl = OpenSSL::SSL::Socket::Client.new(tcp, context: tls.as(OpenSSL::SSL::Context::Client), sync_close: true, hostname: @host.rchop('.'))
            @io = ssl
          rescue ex
            tcp.close
            raise ex
          end
        else
          @io = tcp
        end
      end

      # Crystal's HTTP::Client#close only rescues IO::Error, but in TLS 1.3 Caddy
      # sends close_notify immediately after the response body. When Crystal's
      # exec_internal retry path calls close() on the already-shutdown session,
      # SSL_shutdown raises OpenSSL::SSL::Error (bad_record_mac). That escapes
      # uncaught (not IO::Error) and masks the actual HTTP response.
      # Override to also suppress SSL teardown errors, matching Crystal's intent.
      def close : Nil
        @io.try &.close
      rescue IO::Error | OpenSSL::SSL::Error
        nil
      ensure
        @io = nil
      end
    end
  end
end
