# satsgate-gate

The hosted gate. One process serves many approved sites at `https://gate.satsgate.org/<slug>/<path>`.

Version **0.11.0**. Core is **0.12.0**. This process still speaks Lightning only. A route priced in USD is omitted from the site config it reads, so that path is not served here yet. The self-hosted proxy stays **0.8.0** and is a different program: one merchant, one YAML file, one origin secret in the environment. This process has no origin secret of its own.

## Why an internal API

The gate and core run on the same host, on one docker network. The gate does not mount the sqlite file.

A shared database would give this process every client row, every API-key hash, and the ledger, and it would need `SATSGATE_SITE_SECRET_KEY` to decrypt every origin secret. The internal routes return one approved site (routes, origin, that site's secret, the owner's Lightning Address) and call the same challenge and unlock functions the public paywall uses. The token is `SATSGATE_GATE_TOKEN`. It is not the admin token. The admin token can approve a site. This token cannot.

The routes are not in the public OpenAPI document. When the token is unset they answer 404. Compose also sets `SATSGATE_GATE_PEERS` to the gate container (`172.28.0.4`), so a request that arrives through Caddy is rejected even if the token leaks. The public Caddy host answers 404 for `/internal/*` before the request reaches core. The gate calls `http://satsgate:8000` on the docker network.

## What a request does

1. `GET /internal/gate/sites/<slug>/status` on every request. This is not cached. Anything other than `approved` is HTTP 404, with no distinction between missing, pending, and disabled. A cached secret is dropped first.
2. The site record (origin, routes, decrypted secret) is cached for `SATSGATE_GATE_CACHE_SECONDS` (default 5). A disable still takes effect on the next request because step 1 is uncached.
3. The path after the slug is an exact route. `/slug` and `/slug/` are the route `/`. The query string is not part of the match. Unknown paths are 404. There is no free path.
4. No `Authorization: L402` yet: core mints a challenge for resource `gate:<slug>:<path>`, at the route price and usage policy, on the owner's account. The buyer gets HTTP 402 and `WWW-Authenticate: L402 macaroon="...", invoice="..."`. Credits are not spent yet.
5. `Authorization: L402 <macaroon>` polls status with `consume=true`. Pending is HTTP 402 `payment_pending` and does not include a new invoice. `Authorization: L402 <macaroon>:<preimage>` verifies with `consume=true`. A used or expired grant is a new 402: `error` stays `payment_required` (the same field as an unpaid request and as satsgate-proxy 0.8.0), `reason` is `token_used_up` or `token_expired`, and `invoice` is a new BOLT11 invoice. Core's status body for that case is HTTP 401 with `settled: true`; the gate does not treat that as another forward. The owner being out of credits is HTTP 502 `paywall_unavailable`. The origin is not called. Sats already paid went to the owner's Lightning Address. The gate does not custody them.
6. A settled request is forwarded. The gate resolves the origin again, refuses a private, loopback, link-local, CGNAT, or metadata address, and connects to the public IP from that lookup. TLS still uses the hostname. Redirects are not followed, including a redirect to the same host, because the signed request would no longer be the one the origin receives. The body is read in chunks up to `SATSGATE_GATE_MAX_RESPONSE_BYTES` and is not stored. The buyer response sets `Cache-Control: no-store`.

The signature header is the proxy 0.8.0 scheme: `t=<unix>, v1=<hex hmac-sha256>` over `{unix}|{METHOD}|{path and raw query the origin receives}|{payment_hash}`. Client `X-Satsgate-*` headers and an L402 or LSAT `Authorization` are not forwarded. Other `Authorization` schemes are forwarded so the origin can still see its own credential.

`X-Satsgate-Buyer-Ip` is set by the gate from `X-Forwarded-For`, and only when the TCP peer is in `SATSGATE_GATE_TRUSTED_PROXIES` (Caddy, `172.28.0.2`). Core accepts that header only from the gate (`172.28.0.4` is added to `SATSGATE_TRUSTED_PROXIES`). Caddy deletes the header on both the API host and the gate host, so a buyer cannot pick a bucket. Per-buyer challenge limits on core then apply. The gate also rate-limits per site and per buyer IP in memory.

The resource `gate:<slug>:<path>` must be at most 200 characters. A longer route is stored by core and is not served.

## Run it

Compose builds this directory and does not publish a port. Caddy is the only public listener, and the gate site block ships commented out. See the repository `docker-compose.yml` and `Caddyfile`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_GATE_CORE_URL` | `http://satsgate:8000` | Core on the docker network. Not the public API URL. |
| `SATSGATE_GATE_TOKEN` | unset | Same value as on core. |
| `SATSGATE_GATE_TRUSTED_PROXIES` | empty (Compose sets `172.28.0.2`) | Peer allowed to supply `X-Forwarded-For`. |
| `SATSGATE_GATE_CACHE_SECONDS` | 5 | Site record cache. Status is never cached. |
| `SATSGATE_GATE_UPSTREAM_TIMEOUT` | 15 | Seconds for the origin. |
| `SATSGATE_GATE_MAX_RESPONSE_BYTES` | 10485760 | Response cap. |
| `SATSGATE_GATE_RL_PER_SITE` | 600 | Requests per window. `0` disables. |
| `SATSGATE_GATE_RL_PER_BUYER` | 60 | Requests per buyer IP per window. |

`GET /healthz` returns `{"ok": true, "component": "satsgate-gate", "version": "0.11.0"}`.
