# dirless-http

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Tiny Crystal shard providing `Dirless::Net::TargetedClient` — an `HTTP::Client` subclass that connects to a specific IP address while using a different hostname for TLS SNI and certificate verification.

## Why it exists

Crystal's `HTTP::Client` resolves `@host` for both the TCP connection and TLS SNI. When you need to hit a specific backend node by IP (e.g. bypassing DNS) while still presenting the correct hostname for TLS, the standard client gets in the way. `TargetedClient` overrides `#connect` to direct the TCP connection to a given IP while keeping the FQDN in `@host` so the TLS handshake uses the correct SNI and hostname verification succeeds.

## Installation

Add to `shard.yml`:

```yaml
dependencies:
  dirless-http:
    github: dirless/dirless-http
```

## Usage

```crystal
require "dirless-http"

tls = OpenSSL::SSL::Context::Client.new
client = Dirless::Net::TargetedClient.new("1.2.3.4", "example.com", 443, tls)
response = client.get("/v1/health")
```

## Build & test

```sh
shards install
crystal spec
```
