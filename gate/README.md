# satsgate-gate

The hosted gate. One process serves many approved sites at `https://gate.satsgate.org/<slug>/<path>`.

Version **0.14.0**. Core is **0.16.0**. A site can offer Lightning, x402 (USDC on one Base network), or both. x402 is off until the merchant turns it on. A new site stores no mode. Turning x402 on without a mode stores test (Base Sepolia). Live (Base) is a separate choice and only works when the operator has enabled CDP. The self-hosted proxy is **0.13.0** and is a different program: one merchant, one YAML file, one origin secret in the environment. It charges after a successful origin on both rails. This process has no origin secret of its own, and it does not call the facilitator. A debit from this gate still has a null `api_key_id`, because the gate authenticates with `GATE_TOKEN` rather than an `sgr_` key.

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. A site in test mode offers only this USDC. It is not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode. Available only when the operator sets `SATSGATE_X402_CDP=1` and both CDP credentials. The 402 offers only this USDC. |

Merchants: `payTo` must be an address you control on Base. The USDC is paid to that address on the one network the site is in. The EIP-712 name in `extra` is `USDC` on Base Sepolia and `USD Coin` on Base. Try on Base Sepolia with your agent first, then switch the site to live. Buyers: USDC sent on another network will not be accepted. A balance on Ethereum, Polygon, Solana, or Arbitrum does not pay this gate.

Satsgate never custodies, receives, forwards, or refunds buyer funds. The USDC moves from the buyer to the merchant's `payTo`. This process does not hold a buyer wallet and does not run its own facilitator.

## Why an internal API

The gate and core run on the same host, on one docker network. The gate does not mount the sqlite file.

A shared database would give this process every client row, every API-key hash, and the ledger, and it would need `SATSGATE_SITE_SECRET_KEY` to decrypt every origin secret. The internal routes return one approved site (routes, origin, that site's secret, the owner's Lightning Address) and call the same challenge and unlock functions the public paywall uses. The token is `SATSGATE_GATE_TOKEN`. It is not the admin token. The admin token can approve a site. This token cannot.

The routes are not in the public OpenAPI document. When the token is unset they answer 404. Compose also sets `SATSGATE_GATE_PEERS` to the gate container (`172.28.0.4`), so a request that arrives through Caddy is rejected even if the token leaks. The public Caddy host answers 404 for `/internal/*` before the request reaches core. The gate calls `http://satsgate:8000` on the docker network.

## What a request does

1. `GET /internal/gate/sites/<slug>/status` on every request. This is not cached. Anything other than `approved` is HTTP 404, with no distinction between missing, pending, and disabled. A cached secret is dropped first.
2. The site record (origin, routes, decrypted secret) is cached for `SATSGATE_GATE_CACHE_SECONDS` (default 5). A disable still takes effect on the next request because step 1 is uncached.
3. The path after the slug is an exact route. `/slug` and `/slug/` are the route `/`. The query string is not part of the match. Unknown paths are 404. There is no free path.
4. No payment header yet: core mints a challenge for resource `gate:<slug>:<path>`, on the owner's account, for the rails that site has enabled. Lightning produces the same HTTP 402 as 0.11.0: `WWW-Authenticate: L402 macaroon="...", invoice="..."` and the same JSON fields. x402 adds the header `PAYMENT-REQUIRED` (base64 of the v2 requirements: scheme `exact`, one network, that network's USDC, `payTo` the verified address) and a JSON `x402` object with `scheme`, `network`, `asset`, `amount`, `payTo`, `expires_at`, `testing`, and `x402_mode`. Test mode is Base Sepolia and `testing` is true. Live mode is Base and `testing` is false. The header is canonical. A Lightning-only response has no `PAYMENT-REQUIRED`. An x402-only response has no invoice and no `WWW-Authenticate`. Credits are not spent yet. The site cache stores the main price and the rails. It does not store a derived quote. That amount is locked when the challenge is minted.
5. `Authorization: L402 <macaroon>` confirms the payment and does not debit. Pending is HTTP 402 `payment_pending` and does not include a new invoice. `Authorization: L402 <macaroon>:<preimage>` confirms the same way. Core sets `settled_at` and checks that the account has a credit. It does not take the credit yet. The gate then calls the origin. A 2xx is when core takes one use and, the first time, one credit. A 4xx or 5xx from the origin is returned as that status and body, with no debit, and the same macaroon can be retried. A redirect, timeout, rebind, or oversized body is 502 or 504 with `use_spent: false`. The merchant pays a Satsgate credit only for a successful delivery. A used or expired grant is a new 402: `error` stays `payment_required` (the same field as an unpaid request and as satsgate-proxy 0.8.0), `reason` is `token_used_up` or `token_expired`, and `invoice` is a new BOLT11 invoice. The origin body is not returned in that case. Core's status body for a spent grant is HTTP 401 with `settled: true`; the gate does not treat that as another forward. The owner being out of credits is HTTP 502 `paywall_unavailable`. The origin is not called. Sats already paid went to the owner's Lightning Address. The gate does not custody them and does not refund them. The self-hosted proxy still debits before its origin call. An x402 offer on this 402 lasts `SATSGATE_X402_OFFER_SECONDS` clamped to 60–300 seconds. That is not the Lightning invoice lifetime.
6. `PAYMENT-SIGNATURE` is the x402 payload. The gate rejects a value over 8 KB before calling core. Core checks it and calls the facilitator `/verify`. The gate does not. Verify failure is 402 `x402_rejected` and the origin is not called. Verify success forwards to the origin. The origin must return 2xx before core calls `/settle`. The buyer then gets that body plus `PAYMENT-RESPONSE`. One credit is taken only after settle succeeds. An origin HTTP error is returned as that status, with no settle and no credit. A failed settle is 402 and the origin body is not returned. The credit stays. A later retry of the same signature calls the origin again and then settle. A transport failure is 502 or 504 with `use_spent: false`.
7. Both `Authorization: L402` and `PAYMENT-SIGNATURE` is HTTP 400 `one_rail_only`. Neither rail is settled.
8. A settled Lightning request, and a verified x402 request, are forwarded the same way. The gate resolves the origin again, refuses a private, loopback, link-local, CGNAT, or metadata address, and connects to the public IP from that lookup. TLS still uses the hostname. Redirects are not followed, including a redirect to the same host, because the signed request would no longer be the one the origin receives. The body is read in chunks up to `SATSGATE_GATE_MAX_RESPONSE_BYTES` and is not stored. The buyer response sets `Cache-Control: no-store`.

`PAYMENT-SIGNATURE` is not forwarded. Lightning sends `X-Satsgate-Paid-Sats`. A USDC payment sends `X-Satsgate-Paid-Usd-Atomic` and does not send a sats amount. `X-Satsgate-Payment-Hash` on that path is the EIP-3009 nonce (64 hex characters, no `0x`), because the transaction id is only known after settle and the origin is called first. The HMAC message is unchanged: `{unix}|{METHOD}|{path and raw query}|{payment_hash}`.

The signature header is the proxy 0.8.0 scheme: `t=<unix>, v1=<hex hmac-sha256>`. Client `X-Satsgate-*` headers, `PAYMENT-SIGNATURE`, `PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`, and an L402 or LSAT `Authorization` are not forwarded. Other `Authorization` schemes are forwarded so the origin can still see its own credential.

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

`GET /healthz` returns `{"ok": true, "component": "satsgate-gate", "version": "0.14.0"}`.

## Turn on x402

Use the account key. A restricted `sgr_` key cannot set a payee, a rail, or `x402_mode`. `payTo` must be an address you control on Base. USDC sent on another network will not be accepted. See [USDC payments: Base network only](#usdc-payments-base-network-only).

Try on Base Sepolia with your agent first, then switch the site to live.

1. `POST /v1/client/payee/evm/challenge` with `{"address":"0x..."}`. Sign the returned text with `personal_sign` (EIP-191). Nothing happens on chain. Or create a one-time connect link with `POST /v1/client/payee/evm/connect` and open it in a browser.
2. `POST /v1/client/payee/evm` with `{"address","signature"}`. `GET /v1/client` then shows `payee_evm_verified: true`. It does not return the signature.
3. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}`. That stores `x402_mode: "test"` when the mode was unset. The 402 offers only Base Sepolia (`eip155:84532`, contract [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e)) and the JSON says `testing: true`. Set `rail_lightning` false for x402 only. Both false is `400 rails_required`.
4. After the operator has set `SATSGATE_X402_CDP=1`, `PATCH` `{"x402_mode":"live"}`. The 402 then offers only Base (`eip155:8453`, contract [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)). While the switch is off, that PATCH is `400 x402_mainnet_disabled`. A new site does not start in live mode, so a merchant cannot take real USDC by accident.
5. Add a route. `{"path":"/blog/post","price_sats":21}` keeps sats as the main price. `{"path":"/blog/post","price_currency":"usd","price_usd_atomic":10000}` is $0.01 USDC (6 decimals). Sending both is `400 price_conflict`. A sats price is quoted as USDC only while `GET /v1/rates` is `ok` and the quote is at least $0.001.

The site must be `approved`. `listed: false` keeps it off `GET /v1/sites`. The gate still serves an approved unlisted site. The public directory may show `x402_mode` and `x402_testing`. It does not show `payTo`.

There is no new gate environment variable. The CDP key stays on core. Core already has `SATSGATE_X402_FACILITATOR_URL` (default `https://x402.org/facilitator`) for test mode, `SATSGATE_X402_NETWORK` (`eip155:84532` only; mainnet is `SATSGATE_X402_CDP`, not this variable), and `SATSGATE_X402_OFFER_SECONDS`. Do not point those at a Satsgate process. This service does not custody, receive, forward, or refund buyer funds.

## Private Sepolia check

After the gate image is deployed, use an unlisted approved site and a buyer wallet funded with faucet USDC on Base Sepolia. The merchant test `payTo` for that check is `0x4A9E2CA774BB87110ffF3CB8a250e935cFE52Ce3`. It is a public test address. It is not a default and it is not compiled into the gate. Confirm the settlement transaction's `to` is that address. Confirm the origin request has `X-Satsgate-Paid-Usd-Atomic` and no `PAYMENT-SIGNATURE`. Then make the origin fail and confirm the credit balance does not move. Retry the same `PAYMENT-SIGNATURE` and confirm it still serves, then settles once.
