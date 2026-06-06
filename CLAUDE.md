# dirless-http

Tiny Crystal shard providing `Dirless::Net::TargetedClient` — an `HTTP::Client` subclass that connects to a specific IP address while using a different hostname for TLS SNI and certificate verification.

## What it does

Works around Crystal's `HTTP::Client` resolving `@host` for both TCP and SNI. By overriding `#connect`, it directs the TCP connection to `@target_ip` while keeping the FQDN in `@host` so the TLS handshake uses the correct SNI and hostname verification succeeds.

Useful when you want to hit a specific backend node directly (e.g. by IP from a load balancer health check or direct agent→backend call) without DNS resolution.

## Language / stack

- Crystal
- No external dependencies (wraps Crystal stdlib `HTTP::Client` and `OpenSSL`)

## Key entry points

| File | Purpose |
|------|---------|
| `src/dirless/http/targeted_client.cr` | `Dirless::Net::TargetedClient` — the entire shard |

## Usage

```crystal
require "dirless-http"

tls = OpenSSL::SSL::Context::Client.new
client = Dirless::Net::TargetedClient.new("1.2.3.4", "example.com", 443, tls)
response = client.get("/health")
```

## Used by

`dirless-agent` — connects to backend nodes by IP while presenting the correct SNI hostname.
