# satsgate-proxy

A reverse proxy a merchant runs beside an existing HTTP API. The buyer hits the proxy. The proxy sells the request through [satsgate](https://api.satsgate.org) and forwards only a paid request to the origin. The merchant does not write paywall code.

The proxy is version **0.8.0**. It talks to the satsgate core paywall (challenge, verify, status, usage policy, buyer IP). Core is **0.10.0**. Those paywall calls are unchanged.

## Run it

1. On the core, with the account key (`sg_...`), set the Lightning Address that should be paid. Then mint a restricted key. The proxy refuses any key that does not start with `sgr_`.

   Resources are `route:<name>` or `site`. A prefix of `route:` covers every route-scoped route in the example config. Omit `resource_prefix` if you also use `scope: site`.

   ```bash
   curl -s -X POST https://api.satsgate.org/v1/api-keys \
     -H 'Content-Type: application/json' \
     -H 'X-Api-Key: sg_...ACCOUNT_KEY...' \
     -d '{"label":"shop-proxy","resource_prefix":"route:"}'
   ```

2. Generate one origin secret and give it to both the proxy and the origin. `openssl rand -hex 32` is a good value. Shorter than 16 characters refuses to start. Shorter than 32 logs a warning.

3. Copy `satsgate-proxy.example.yaml` to `satsgate-proxy.yaml`. Set `upstream.base_url` to the origin (no path, no userinfo). Put the `sgr_` key and the origin secret in the environment, not in the file. Upstream credentials, if you inject any, are also environment variables and are never logged.

4. Add an origin check from `snippets/` (FastAPI, Express, or nginx). Reject a missing or bad `X-Satsgate-Signature`. A client who can reach the origin directly must not skip the paywall. Stock Caddy does not verify HMAC; `snippets/Caddyfile` only shows a network gate in front of that check.

5. Start the proxy and do not publish the origin port.

   ```bash
   export SATSGATE_API_KEY='sgr_...'
   export SATSGATE_ORIGIN_SECRET="$(openssl rand -hex 32)"
   docker compose -f proxy/docker-compose.yml up --build
   ```

   Buyers use the proxy's published port. `GET /healthz` is the proxy (`{"ok":true,"component":"satsgate-proxy","version":"0.8.0"}`). It is not forwarded.

Without Docker, from a checkout:

```bash
pip install -r proxy/requirements.txt
PYTHONPATH=proxy/src python -m satsgate_proxy --config proxy/satsgate-proxy.yaml
```

The image listens as uid 65532. Build it from the repo root: `docker build -f proxy/Dockerfile -t satsgate-proxy:0.8.0 .`

## What a buyer sees

An unpaid request gets **402** and:

```
WWW-Authenticate: L402 macaroon="<standard base64>", invoice="<bolt11>"
```

`macaroon` comes before `invoice`, which is what lnget and Alby `fetch402` parse. The JSON body has `amount_sats`, `payment_hash`, `invoice`, `invoice_expires_at`, `max_uses`, `access_seconds` (null when that side is unset), and a `hint` for the no-preimage path.

A paid retry is `Authorization: L402 <macaroon>:<64-hex-preimage>` (`LSAT` is accepted too). The proxy calls `POST /v1/paywall/verify` with `consume=true`.

`Authorization: L402 <macaroon>` with no preimage calls `GET /v1/paywall/status/{payment_hash}?consume=true`. That is the phone-wallet path: the wallet pays the invoice and does not return a preimage. While the invoice is unpaid the proxy answers **402** `payment_pending` with `Retry-After` and does **not** mint a second invoice. Pending does not consume a use.

A token for another route, a used-up bundle, or an expired pass becomes a **fresh 402**, not 401, so a standard client can pay again. The body includes `reason` (`token_used_up`, `token_expired`, `resource mismatch`, and the other core reject strings).

Core **429** (`buyer_rate_limited`, `too_many_open_challenges_for_buyer`, `rate_limited`, `too_many_open_challenges`) is passed through with `Retry-After`. A revoked key, a missing payee, an empty credit balance, or a resource outside the key prefix is **502** `paywall_unavailable` for the buyer. The core error code is logged on the proxy only.

## Routes

First match wins. Anything that is not a free path or a route is **404**. A path that matches with the wrong method is **405** and does not mint an invoice. `OPTIONS` is not special: list it, or put the path in `free_paths`, if a browser must call it.

| `access` | Core policy | Meaning |
| --- | --- | --- |
| `per_request` | `max_uses: 1` | One payment, one request |
| `uses:N` | `max_uses: N` | A bundle of N requests (N is 1 to 100000) |
| `pass:<seconds>` | `access_seconds` | A time pass starting at settlement (1 to 604800 seconds) |

`scope: route` binds the macaroon to `route:<name>`. A token for one route does not open another. `scope: site` binds every site-scoped route to the resource `site`. Those routes must share `price_sats` and `access`, because one macaroon has one amount. Startup fails if they differ.

`free_paths` are forwarded with no challenge. Globs: `*` is one segment, a trailing `/**` is that prefix and anything under it (including the prefix). `path_regex` is a full match. A route has one of `path` or `path_regex`.

`description` is sent as the challenge memo, trimmed to 250 characters.

## Price and credits

One credit is one settled payment, not one HTTP call and not the sats the buyer paid. The trial plan is about **5 sats per credit**. Set `pricing.sats_per_credit` to the plan you bought. A `per_request` price below **10 times** that number logs a warning at startup (under 50 sats on the trial plan). Cheap calls should be `uses:N` or `pass:<seconds>`, so one credit covers many requests. Bundles and passes do not warn.

Credits are charged once per `payment_hash`, on the first settlement, and are **not refunded**. The Lightning payment goes straight to the merchant's payee. The credit is the fee for that verification.

## Buyer IP

When the proxy resolved a real IP, it sends `X-Satsgate-Buyer-Ip` on challenge create. `X-Forwarded-For` is used only when the TCP peer is in this proxy's `server.trusted_proxies`. Otherwise the peer is the buyer. A non-IP peer (the test client, for example) is omitted rather than sent.

**Hosted `https://api.satsgate.org` ignores that header unless the proxy's egress IP is listed in the core's `SATSGATE_TRUSTED_PROXIES`.** The core's Caddyfile also deletes `X-Satsgate-Buyer-Ip` on public requests, because Caddy is the trusted peer. Until an operator trusts the proxy and stops stripping the header, per-buyer limits do not apply. The merchant's per-client caps still do. Self-hosting the core: set `SATSGATE_TRUSTED_PROXIES` to the proxy egress IP and let the header through only from that address.

The core stores an HMAC of a truncated address (IPv4 /24, IPv6 /64), not the raw IP.

## What the origin receives

After a successful consume the proxy forwards the original method, raw path, and raw query. It does not follow redirects.

Headers added:

| Header | Value |
| --- | --- |
| `X-Satsgate-Signature` | `t=<unix>, v1=<hex hmac-sha256>` |
| `X-Satsgate-Payment-Hash` | lowercase payment hash |
| `X-Satsgate-Resource` | `route:<name>` or `site` |
| `X-Satsgate-Paid-Sats` | sats for this challenge |

The signed message is:

```
{unix}|{METHOD}|{target}|{payment_hash}
```

`target` is the raw path, then `?` and the raw query string when a query is present. Percent-encoding is kept and the query is not reordered. The method is uppercased. Default skew is 300 seconds (`origin.max_skew_seconds`).

Client `X-Satsgate-*` headers are stripped before this, so a buyer cannot forge the signature. `Authorization` is removed when the scheme is `L402` or `LSAT`. Other schemes, such as `Bearer`, are forwarded unless `inject_headers` replaces that name. Hop-by-hop headers are dropped. `Accept-Encoding` is set to `identity`.

`inject_headers` reads the value from `value_env`. The name cannot be hop-by-hop or `X-Satsgate-*`. The value is not logged. Startup fails if the variable is unset.

Responses drop `Server`, `Via`, `X-Powered-By`, `Location`, and `Content-Encoding`. A **3xx** from the origin becomes **502** `upstream_redirect` with no `Location`, so an internal host does not leak. The proxy does not follow the redirect.

The response is buffered up to `limits.max_response_bytes` (default 10 MiB, max 64 MiB). Over that, the buyer gets **502** `upstream_response_too_large` instead of a truncated 200. A request larger than `limits.max_request_bytes` (default 1 MiB, max 32 MiB) is **413** before any core call, so it does not mint an invoice or consume a use.

## If the origin fails after consume

The proxy consumes first, then forwards. There is no un-consume. Two parallel requests cannot both pass a check and both hit the origin.

If the origin then times out, refuses the connection, redirects, or returns a body over the cap, the buyer gets a proxy error with `use_spent: true`. The note is: the payment was accepted before the origin was called, this use is spent, and credits are not refunded. An origin **5xx** is passed through with the host headers removed, and that use is spent too. The 5xx body is the origin's. Do not put internal hostnames in it.

A retry of the same token takes another use when the bundle still has one. A `per_request` token is then `token_used_up`, and the next call is a new 402. Pending polls do not consume.

## Known limitations

- Hosted core ignores `X-Satsgate-Buyer-Ip` unless the proxy egress IP is trusted and the edge does not strip the header. Per-buyer limits are then off. Per-client caps remain.
- The query string is signed only as part of `target`. An origin that checks the path and ignores the query is not checking what the buyer paid for.
- Responses are buffered up to the size cap. This is not an unbounded stream. WebSockets are not supported.
- There is no CORS middleware. A browser preflight needs `OPTIONS` on the route or a free path.
- `Accept-Encoding` is forced to `identity`. The proxy does not gzip.
- `Location` is always removed. An origin that redirects the buyer has to use a URL in the body, or not redirect.
- One use is burned if the origin fails after consume. Credits are never refunded. There is no idempotency key: a retry after a lost response consumes another use.
- Aperture cannot verify satsgate macaroons. lnget and `fetch402` can, using the 402 header and `mac:preimage`. A phone wallet uses the macaroon-only poll.
- Replicas of the proxy do not need shared state. Uses, buyer limits, and challenge reuse live in the core database. The core's in-memory challenge rate limit is per core process.
- The macaroon-only path decodes the macaroon to learn the payment hash. A garbage token becomes a fresh 402.
- `scope: site` cannot mix prices. `scope: route` tokens do not unlock other routes.
- The restricted key's `resource_prefix` is a case-sensitive prefix of the resource id the proxy sends.

## Mainnet check with a small payment

Use 1 to 21 sats on a test route. Pay from a different wallet than the payee.

- **lnget.** The 402 header parses, the macaroon is standard base64, the payment hash is in the L402 identifier, payment succeeds, and the retry is `L402 <macaroon>:<preimage>`. The origin sees the request and the signature verifies. A tampered path, a tampered payment hash, or a stale `t=` is rejected.
- **Alby `fetch402`.** The macaroon is treated as opaque. The retry includes the preimage. The macaroon base64 does not contain the substrings `L402` or `LSAT` (the core re-rolls those).
- **Phone wallet.** Pay the invoice without a preimage. Retry `Authorization: L402 <macaroon>` until `payment_pending` stops and the origin responds. `Retry-After` is present while pending, and a second invoice is not minted.
- A used `per_request` token gets a new **402**, not 401.
- The payee receives the sats. The account loses **one** credit on the first unlock only. A second use of a bundle does not charge another credit.
- Against hosted core, the proxy sends `X-Satsgate-Buyer-Ip` and it is ignored unless that egress IP was added to `SATSGATE_TRUSTED_PROXIES`. Record what you observed.
