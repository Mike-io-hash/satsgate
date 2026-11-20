# satsgate-proxy

Charge AI agents in Lightning and USDC on the same 402. Payments go straight to your wallet. 500 free unlocks a month.

A reverse proxy a merchant runs beside an existing HTTP API. The buyer hits the proxy. The proxy sells the request through [Satsgate](https://api.satsgate.org) and forwards only a paid request to the origin. The merchant does not write paywall code.

The proxy is version **0.14.2**. It works with core 0.20.3 or later and with gate 0.15.2 or later. Default `mode: paywall` talks to the Satsgate core paywall (challenge, verify, status, charge, and x402 verify/settle). `mode: receipt` does not call core and does not use an API key. It checks `Satsgate-Receipt` with the site secret and forwards a successful check to the origin. The proxy does not sell prepaid balance and does not call the facilitator. Top up on the core with `POST /v1/topup/lightning` or `POST /v1/topup/usdc`. On api.satsgate.org a USDC top-up is Base mainnet USDC (a self-hosted core needs `SATSGATE_X402_CDP=1`; see [self-hosting](https://github.com/Mike-io-hash/satsgate/blob/main/docs/self-hosting.md)). The hosted gate is a separate program and only sells receipts. Buyer USDC on a proxied paywall route goes to the merchant's verified `payTo`. In receipt mode the buyer already paid the gate.

## Install

```bash
pip install satsgate-proxy
```

or

```bash
uvx --env-file .env satsgate-proxy --config satsgate-proxy.yaml
```

or

```bash
docker pull ghcr.io/mike-io-hash/satsgate-proxy:0.14.2
```

`satsgate init --docker` writes a compose file for that image. The minor tag is `ghcr.io/mike-io-hash/satsgate-proxy:0.14`.

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. `x402: true` without `x402_mode`, or `x402_mode: test`, offers only this USDC. It is not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode (on by default on api.satsgate.org; a self-hosted core needs `SATSGATE_X402_CDP=1` and CDP credentials, [self-hosting](https://github.com/Mike-io-hash/satsgate/blob/main/docs/self-hosting.md)). The 402 offers only this USDC. |

Merchants: `payTo` must be an address you control on Base. Prove it with the same EVM challenge the hosted gate uses. The USDC is paid to that address on the one network the route is in. Try on Base Sepolia with your agent first, then switch the site to live. Buyers: USDC sent on another network will not be accepted. A balance on Ethereum, Polygon, Solana, or Arbitrum does not pay this proxy.

Satsgate never custodies, receives, forwards, or refunds buyer funds. The USDC moves from the buyer to the merchant's `payTo`. The proxy does not hold a buyer wallet and does not run its own facilitator.

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

3. Run `satsgate init` to write `satsgate-proxy.yaml`. Set `upstream.base_url` to the origin (no path, no userinfo). Put the `sgr_` key and the origin secret in the environment, not in the file. Upstream credentials, if you inject any, are also environment variables and are never logged.

4. Add an origin check from `snippets/` (FastAPI, Express, or nginx). Reject a missing or bad `X-Satsgate-Signature`. A client who can reach the origin directly must not skip the paywall. Stock Caddy does not verify HMAC; `snippets/Caddyfile` only shows a network gate in front of that check.

5. Start the proxy and do not publish the origin port.

   ```bash
   export SATSGATE_API_KEY='sgr_...'
   export SATSGATE_ORIGIN_SECRET="$(openssl rand -hex 32)"
   uvx --env-file .env satsgate-proxy --config satsgate-proxy.yaml
   ```

   Buyers use the proxy's published port. `GET /healthz` is the proxy (`{"ok":true,"component":"satsgate-proxy","version":"0.14.2"}`). It is not forwarded.

   Startup logs `key fp` and 12 hex characters. That is the start of SHA-256 of the API key. It is not a prefix of the key, and the key itself is not written to the log.

The image listens as uid 65532.

## Receipt mode

Set `mode: receipt` and a `receipt` block. There is no `core` block and no `sgr_` key. The buyer pays `https://gate.satsgate.org/<site><path>`, then calls this proxy with `Satsgate-Receipt`. A 2xx from the origin commits one use. The origin still sees the HMAC in `X-Satsgate-Signature`.

```yaml
mode: receipt
core:
  base_url: https://api.satsgate.org
upstream:
  base_url: https://origin.example
origin:
  secret_env: SATSGATE_ORIGIN_SECRET
receipt:
  site: my-shop
  gate_base: https://gate.satsgate.org
  store: /data/receipts.sqlite3
routes:
  - path: /blog/post
    price_sats: 21
```

`core.base_url` is still required by the config parser. Receipt mode does not call it and does not read `SATSGATE_API_KEY`. `price_sats` is stored on the route and is not charged here. The buyer already paid the gate.

`proxy/snippets/fastapi_receipt.py` is the five-line SDK wrapper. `proxy/snippets/express_receipt.js` checks the same test vectors in `tests/fixtures/receipt_vectors.json` with Node's `crypto` module and no npm dependency.

## What a buyer sees

An unpaid request gets **402** and:

```
WWW-Authenticate: L402 macaroon="<standard base64>", invoice="<bolt11>"
```

`macaroon` comes before `invoice`, which is what lnget and Alby `fetch402` parse. The JSON body has `amount_sats`, `payment_hash`, `invoice`, `invoice_expires_at`, `max_uses`, `access_seconds` (null when that side is unset), and a `hint` for the no-preimage path.

A paid retry is `Authorization: L402 <macaroon>:<64-hex-preimage>` (`LSAT` is accepted too). The proxy calls `POST /v1/paywall/verify` with `consume=true`.

`Authorization: L402 <macaroon>` with no preimage calls `GET /v1/paywall/status/{payment_hash}?consume=true`. That is the phone-wallet path: the wallet pays the invoice and does not return a preimage. While the invoice is unpaid the proxy answers **402** `payment_pending` with `Retry-After` and does **not** mint a second invoice. Pending does not consume a use.

A token for another route, a used-up bundle, or an expired pass becomes a **fresh 402**, not 401, so a standard client can pay again. The body includes `reason` (`token_used_up`, `token_expired`, `resource mismatch`, and the other core reject strings).

Core **429** (`buyer_rate_limited`, `too_many_open_challenges_for_buyer`, `rate_limited`, `too_many_open_challenges`) is passed through with `Retry-After`. A revoked key, a missing payee, an empty prepaid service balance (and no free unlocks left), or a resource outside the key prefix is **502** `paywall_unavailable` for the buyer. The core error code is logged on the proxy only.

## Routes

First match wins. Anything that is not a free path or a route is **404**. A path that matches with the wrong method is **405** and does not mint an invoice. `OPTIONS` is not special: list it, or put the path in `free_paths`, if a browser must call it.

A request path with a `.` or `..` segment, also when percent-encoded (such as `%2e%2e`), a backslash, or an encoded slash or backslash (`%2F`, `%5C`) is **404** as well. It is checked before free paths and routes, so such a path never reaches the origin. This check is not in a published release yet.

| `access` | Core policy | Meaning |
| --- | --- | --- |
| `per_request` | `max_uses: 1` | One payment, one request |
| `uses:N` | `max_uses: N` | A bundle of N requests (N is 1 to 100000) |
| `pass:<seconds>` | `access_seconds` | A time pass starting at settlement (1 to 604800 seconds) |

`scope: route` binds the macaroon to `route:<name>`. A token for one route does not open another. `scope: site` binds every site-scoped route to the resource `site`. Those routes must share `price_sats` and `access`, because one macaroon has one amount. Startup fails if they differ.

`free_paths` are forwarded with no challenge. Globs: `*` is one segment, a trailing `/**` is that prefix and anything under it (including the prefix). `path_regex` is a full match. A route has one of `path` or `path_regex`.

`description` is sent as the challenge memo, trimmed to 250 characters.

## MCP servers

Not in a published release yet. The published 0.14.2 does not read MCP; this section describes the code on the main branch.

```yaml
routes:
  - name: tools
    path: /mcp
    methods: [POST, DELETE]
    x402: true            # optional, as today; applies to every paid tool
    description: Market data tools   # optional; memo fallback
    mcp:
      signal: in_band     # optional; in_band (default) or http_402
      default: free       # required: free, or {price_sats, access[, description]}
      tools:              # optional
        quote:
          price_sats: 21
          access: per_request
          description: One market quote
        deep_search:
          price_sats: 100
          access: uses:10
        echo: free
```

An MCP route speaks [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). The proxy reads the JSON-RPC body, decides whether the call is free or priced, and only then talks to the core. `signal` may be omitted. The only accepted value in this code is `http_402`.

`default` is required. It is the string `free`, or a price mapping with `price_sats`, `access`, and an optional `description`. Each key under `tools` is either `free` or the same kind of mapping. A missing `default`, a bad tool name, a route-level `price_sats` or `access`, a glob path, `path_regex`, a method other than `POST` and `DELETE`, or `mode: receipt` refuses to start.

What is free: every MCP message that is not a priced `tools/call`. That includes `initialize`, `tools/list`, `ping`, resources, prompts, a tool marked `free`, an unlisted tool when `default` is `free`, notifications, client responses, and `DELETE`. A batch is free when every `tools/call` in it is free. A batch that contains a priced tool is rejected and no invoice is minted.

What is charged: one `tools/call` whose name is a priced tool, or an unlisted name when `default` is a price. The resource is `route:<route>:<tool>`. A restricted key with `resource_prefix: route:` covers every one of those resources. The memo is the tool description, then the route description.

The proxy checks the request before it mints an invoice. A failed check is HTTP 400, `Content-Type: application/json`, `Cache-Control: no-store`, and a JSON-RPC error. `data.error` is the code word:

| Code word | Meaning |
| --- | --- |
| `invalid_json` | The body is empty, not UTF-8, or not strict JSON. Duplicate keys are rejected. |
| `unsupported_content_type` | `Content-Type` is not `application/json`. |
| `accept_json_and_sse_required` | `Accept` does not list both `application/json` and `text/event-stream`. A wildcard does not count. |
| `invalid_message` | The JSON-RPC shape is wrong, a `tools/call` has no id, or a batch is not allowed for this protocol version. |
| `invalid_method` | The method is a disguised form of `tools/call` or of a method this proxy does not forward. |
| `invalid_tool_call` | A `tools/call` has no tool name. |
| `invalid_tool_name` | The name is a look-alike of a priced tool, or it cannot be used with a priced `default`. |
| `tasks_not_supported` | `params.task` is set. |
| `batch_with_paid_tool` | A batch contains a priced `tools/call`. |
| `duplicate_routing_header` | `MCP-Protocol-Version`, `Mcp-Method`, or `Mcp-Name` is repeated. |
| `header_mismatch` | `Mcp-Method` or `Mcp-Name` does not match the body, or a 2026-07-28 request is missing one of them. |
| `unsupported_protocol_version` | `MCP-Protocol-Version` is not one of the versions below. |
| `missing_request_envelope` | A 2026-07-28 request is missing `params._meta`. |
| `delete_body_not_allowed` | `DELETE` included a body. |

`GET` on an MCP route is **405** from the proxy, with `Allow: DELETE, POST`. `DELETE` with an empty body is free. `subscriptions/listen` and `tasks/get`, `tasks/result`, `tasks/list`, and `tasks/cancel` are not forwarded. A request gets HTTP 200 and JSON-RPC `-32601`. A notification gets HTTP 202 and an empty body.

On a free forward and on `DELETE`, the origin receives the original body bytes and these headers:

| Header | Value |
| --- | --- |
| `X-Satsgate-Signature` | `t=<unix>, v1=<hex hmac-sha256>` over `{unix}\|{METHOD}\|{target}\|{64 zeros}` |
| `X-Satsgate-Payment-Hash` | 64 zeros |
| `X-Satsgate-Resource` | `free` |
| `X-Satsgate-Paid-Sats` | `0` |
| `X-Satsgate-Mcp-Tool` | The tool name, on a single `tools/call` only. A name that is not plain ASCII uses the `=?base64?...?=` form. |

There is no `X-Satsgate-Paid-Usd-Atomic` on a free forward. A priced call adds the same signature headers the paywall uses today, with `X-Satsgate-Resource: route:<route>:<tool>`, the real payment hash, `X-Satsgate-Paid-Sats` or `X-Satsgate-Paid-Usd-Atomic`, and `X-Satsgate-Mcp-Tool`. `X-Satsgate-Mcp-Tool` is informational and is not part of the signed message. The snippets in `snippets/` verify both the free hash and a paid hash with no change. A valid signature proves the request came through the proxy. It does not by itself mean the call was paid. The origin reads `X-Satsgate-Resource` to see `free` or the tool resource.

The price notice is the HTTP 402 described in [What a buyer sees](#what-a-buyer-sees). On an `x402: true` route that 402 carries both the Lightning challenge and `PAYMENT-REQUIRED`. A standard MCP client surfaces the 402 as an HTTP error, so the buyer needs an L402-aware or x402-aware client.

A failed tool call takes no unlock fee and no use. That includes a JSON-RPC error, `result.isError: true`, and `resultType` other than `complete`. The same token can be retried. The Lightning payment has already reached the merchant's wallet, because the buyer paid that wallet directly. An x402 payment is not settled. Buyers pay the merchant's wallet directly. Satsgate does not hold those funds.

Supported `MCP-Protocol-Version` values: `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`. A missing header is treated as the handshake era, including `initialize`. The origin negotiates `params.protocolVersion`.

Limits that apply to MCP routes:

- There is no long-lived GET stream. Responses are buffered.
- A tool slower than `upstream.timeout_seconds` times out.
- `tasks/*` and `subscriptions/listen` are answered with a JSON-RPC error.
- The proxy cannot tell whether the origin needs a session. The buyer initializes first, and that call is free.
- `Mcp-Param-*` headers are not checked here. A mismatch is an origin error, and it is not charged.
- The HMAC does not cover the body.
- The origin must look up a tool by its exact name. Both official MCP SDKs do that.
- A token is bound to one tool, not to an MCP session.

## Price

A new account gets **500 free unlocks per UTC month**. After that, each unlock is **2 sats**, with a **10%** cap. The fee is taken once per payment, and only after the origin returns 2xx. `uses:N` and `pass:<seconds>` still bundle requests inside that one payment. `pricing.sats_per_credit` in an old config is ignored.

The Lightning payment goes to the merchant's payee when the invoice is paid, before the origin runs. A failed origin takes no fee and no use. The buyer retries the same macaroon or signature. Any remedy for that failed origin is between the buyer and the merchant. USDC test payments through this proxy do not use the free unlocks or the prepaid balance.

## Buyer IP

When the proxy resolved a real IP, it sends `X-Satsgate-Buyer-Ip` on challenge create. `X-Forwarded-For` is used only when the TCP peer is in this proxy's `server.trusted_proxies`. Otherwise the peer is the buyer. A non-IP peer (the test client, for example) is omitted rather than sent.

**Hosted `https://api.satsgate.org` ignores that header unless the proxy's egress IP is listed in the core's `SATSGATE_TRUSTED_PROXIES`.** The core's Caddyfile also deletes `X-Satsgate-Buyer-Ip` on public requests, because Caddy is the trusted peer. Until an operator trusts the proxy and stops stripping the header, per-buyer limits do not apply. The merchant's per-client caps still do. Self-hosting the core: set `SATSGATE_TRUSTED_PROXIES` to the proxy egress IP and let the header through only from that address.

The core stores an HMAC of a truncated address (IPv4 /24, IPv6 /64), not the raw IP.

## What the origin receives

When the payment is confirmed, the proxy forwards the original method, raw path, and raw query. The unlock fee and the use are taken only after a 2xx. It does not follow redirects.

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

## If the origin fails

The proxy confirms the payment first and calls the origin next. The unlock fee is debited from the prepaid service balance (or the monthly free quota) only when that response is 2xx. An origin **4xx** or **5xx** is passed through with the host headers removed, and nothing is debited. The same macaroon can be retried. If the origin times out, refuses the connection, redirects, or returns a body over the cap, the buyer gets a proxy error with `use_spent: false`. Do not put internal hostnames in an origin error body.

A route may set `x402: true`. Without `x402_mode`, that is test mode (Base Sepolia only). `x402_mode: live` is Base only, and core rejects it while `SATSGATE_X402_CDP` is off. `x402_mode` without `x402: true` refuses to start. The two networks are never in the same 402. Try on Base Sepolia with your agent first, then switch the site to live. See [USDC payments: Base network only](#usdc-payments-base-network-only). x402 also requires `server.public_base`, the `http://` or `https://` origin buyers pay (no path). The account needs a verified EVM payee on Base, the same challenge used by the hosted gate. The 402 then includes `PAYMENT-REQUIRED`. Test mode is labeled `testing: true`. `PAYMENT-SIGNATURE` is verified, the origin is called with `X-Satsgate-Paid-Usd-Atomic` and no `X-Satsgate-Paid-Sats`, and settle runs only after a 2xx. `PAYMENT-RESPONSE` carries `success`, `transaction`, `network`, `payer`, and `tx`. An origin 4xx or 5xx does not settle and does not debit. The buyer retries the same `PAYMENT-SIGNATURE`. Sending both `Authorization: L402` and `PAYMENT-SIGNATURE` is 400 `one_rail_only`. The proxy never calls the facilitator. The settle call uses the restricted `sgr_` key, and core records that key's id on the new ledger debit. The key string is not stored.

A retry of the same token takes another use when the bundle still has one. A `per_request` token is then `token_used_up`, and the next call is a new 402. Pending polls do not consume.

## Known limitations

- Hosted core ignores `X-Satsgate-Buyer-Ip` unless the proxy egress IP is trusted and the edge does not strip the header. Per-buyer limits are then off. Per-client caps remain.
- The query string is signed only as part of `target`. An origin that checks the path and ignores the query is not checking what the buyer paid for.
- Responses are buffered up to the size cap. This is not an unbounded stream. WebSockets are not supported.
- There is no CORS middleware. A browser preflight needs `OPTIONS` on the route or a free path.
- `Accept-Encoding` is forced to `identity`. The proxy does not gzip.
- `Location` is always removed. An origin that redirects the buyer has to use a URL in the body, or not redirect.
- An origin failure does not burn the use. A retry after a lost 2xx can take another use if the first charge succeeded and the buyer did not see it. A debited unlock fee is not refunded. There is no idempotency key.
- Aperture cannot verify Satsgate macaroons. lnget and `fetch402` can, using the 402 header and `mac:preimage`. A phone wallet uses the macaroon-only poll.

- Replicas of the proxy do not need shared state. Uses, buyer limits, and challenge reuse live in the core database. The core's in-memory challenge rate limit is per core process.
- The macaroon-only path decodes the macaroon to learn the payment hash. A garbage token becomes a fresh 402.
- `scope: site` cannot mix prices. `scope: route` tokens do not unlock other routes.
- The restricted key's `resource_prefix` is a case-sensitive prefix of the resource id the proxy sends.
- MCP routes have further limits. See [MCP servers](#mcp-servers).

## Contributors' note

From a checkout: `pip install -e proxy`. Build the image from the repo root with `docker build -f proxy/Dockerfile -t satsgate-proxy:0.14.2 .`, or `docker compose -f proxy/docker-compose.yml up --build`.

## Mainnet check with a small payment

Use 1 to 21 sats on a test route. Pay from a different wallet than the payee.

- **lnget.** The 402 header parses, the macaroon is standard base64, the payment hash is in the L402 identifier, payment succeeds, and the retry is `L402 <macaroon>:<preimage>`. The origin sees the request and the signature verifies. A tampered path, a tampered payment hash, or a stale `t=` is rejected.
- **Alby `fetch402`.** The macaroon is treated as opaque. The retry includes the preimage. The macaroon base64 does not contain the substrings `L402` or `LSAT` (the core re-rolls those).
- **Phone wallet.** Pay the invoice without a preimage. Retry `Authorization: L402 <macaroon>` until `payment_pending` stops and the origin responds. `Retry-After` is present while pending, and a second invoice is not minted.
- A used `per_request` token gets a new **402**, not 401.
- The payee receives the sats when the invoice is paid. The unlock fee is debited from the prepaid service balance (or the monthly free quota) on the first successful delivery only, after the origin returns 2xx. A second use of a bundle does not debit again. A failed origin takes nothing.
- Against hosted core, the proxy sends `X-Satsgate-Buyer-Ip` and it is ignored unless that egress IP was added to `SATSGATE_TRUSTED_PROXIES`. Record what you observed.
