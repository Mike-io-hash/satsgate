# satsgate

[![CI](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml)

`satsgate` lets you **charge sats** for AI agents, APIs, and web apps — without building a payment stack.

The merchant flow from a cold start:

1. Top up payment verifications (credits) and save the API key. `GET /v1/topup/{plan_id}` returns the invoice. Pay it, then poll `GET /v1/topup/status/{payment_hash}`.
2. Register the Lightning Address that receives your users' payments with `POST /v1/client/payee`. The first `POST /v1/paywall/challenge` that includes `payee_lightning_address` saves it too (`payee_saved: true`). Change it later with `POST /v1/client/payee`.
3. `POST /v1/paywall/challenge` and give that invoice to your user. A proxy or MCP server should use a restricted key for this step (see [Restricted API keys](#restricted-api-keys)).
4. When they have paid, unlock with `GET /v1/paywall/status/{payment_hash}` (any wallet, when the payee advertises LUD-21) or `POST /v1/paywall/verify` (preimage). The first settled call spends 1 credit. A repeat spends 0.

Challenge plus status (or verify) is the per-purchase pair, after the account has credits and a payee.

It’s a hosted + self-hostable FastAPI service that gives you:

- **L402 paywall primitives** (invoice + macaroon, preimage or LUD-21 confirmation)
- **Prepaid payment verifications** (credits) for predictable costs (**1 verification = 1 successful paid unlock**; **verifications don’t expire**)
- **Usage & reporting** (ledger, daily series, forecast + purchase recommendation)
- **Roadmap (active)**: new wallet backends, integrations, and production hardening

Your users pay **your** Lightning Address (LNURL-pay). satsgate is **non-custodial** (we never hold your funds) and doesn’t require end-user accounts or KYC.

Hosted beta: https://api.satsgate.org (start in [`CUSTOMER_QUICKSTART.md`](./CUSTOMER_QUICKSTART.md)). Minimum top-up: **1000 sats → 200 payment verifications** (anti-abuse; no expiry).

No LLM in the hot path: satsgate is a lightweight, low-latency “cashier/turnstile” that sits in front of your agent.

## Beta

This project is currently in **beta**. See [`BETA.md`](./BETA.md).

## Customer quickstart

If you're integrating satsgate as a **customer** (agent operator), start here:

- [`CUSTOMER_QUICKSTART.md`](./CUSTOMER_QUICKSTART.md)

## Status

- Hosted health: https://api.satsgate.org/health
- Hosted manifest: https://api.satsgate.org/.well-known/satsgate.json

See [`STATUS.md`](./STATUS.md).

## Support

- Support: [`SUPPORT.md`](./SUPPORT.md)
- Contributing: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Changelog: [`CHANGELOG.md`](./CHANGELOG.md)
- Security: [`SECURITY.md`](./SECURITY.md)

## Manifest (.well-known)

- `GET /.well-known/satsgate.json` → machine-readable manifest (endpoints + auth + pricing)
- `GET /openapi.json` → OpenAPI

## Wallet backends

Configured via env vars:

- `SATSGATE_WALLET_MODE=mock` (recommended for local testing)
  - invoices are simulated
  - DEV helper: `/dev/mock/pay/{payment_hash}` returns the `preimage`

- `SATSGATE_WALLET_MODE=lnaddr`
  - generates **real** invoices via your **Lightning Address** (LNURL-pay)
  - requires: `SATSGATE_LIGHTNING_ADDRESS=user@domain`
  - checks the BOLT11 amount, network, `description_hash` (LUD-06), expiry, and payment hash before issuing a challenge
  - if the provider advertises LUD-21 `verify`, settlement is confirmed there too, including without the payer returning a preimage. Providers that omit it (Wallet of Satoshi) stay preimage-only

`GET /health` returns `{"ok": true, "version": "0.7.0"}` and nothing else.

## Prepaid payment verifications (credits)

In the API these are called `credits`. They **do not expire**.

Endpoints:

- `GET /v1/plans` → list plans
- `GET /v1/topup/{plan_id}` → start purchase (returns 402 + invoice + macaroon)
- `GET /v1/topup/{plan_id}` with `Authorization: L402 <macaroon>:<preimage>` → finalize purchase
- `GET /v1/topup/status/{payment_hash}` with `Authorization: L402 <macaroon>` → poll until the stored LUD-21 URL says the invoice settled, then credit the account
- `GET /v1/balance` with `X-Api-Key: ...` → current verification balance (credits)
- `GET /v1/client` with `X-Api-Key: ...` → client info (incl. payee)
- `POST /v1/client/payee` with `X-Api-Key: ...` → register client payee (Lightning Address)

Restricted keys (account key only):

- `POST /v1/api-keys` with `X-Api-Key: sg_...` → create a restricted key (`sgr_...`, shown once)
- `GET /v1/api-keys` → list restricted keys (no secrets). `include_revoked=true` includes revoked rows
- `POST /v1/api-keys/{key_id}/revoke` → revoke a restricted key

Reporting:

- `GET /v1/ledger` with `X-Api-Key: ...` → verification ledger entries (credits). Paywall debits include `api_key_id`, `api_key_label`, `api_key_prefix`, and `resource` (`api_key_id` is null when the account key spent the credit)
- `GET /v1/usage/summary?since_hours=24` with `X-Api-Key: ...` → usage summary. `summary.by_api_key` groups paywall debits by the key that spent them (null `api_key_id` is the account key)
- `GET /v1/usage/daily?days=30` with `X-Api-Key: ...` → daily series (UTC)
- `GET /v1/usage/forecast?lookback_hours=24&buffer_days=7&max_topups=3&trigger_hours=24` with `X-Api-Key: ...`
  - forecast + recommended purchase + “when to top up” trigger

## What a credit costs

Each successful unlock spends **1 credit**, whatever `amount_sats` on the invoice is. Credits are the merchant's prepaid fee for the verification. The buyer pays the invoice amount to the merchant's Lightning Address.

| Plan | Price | Credits | Sats per unlock |
| --- | --- | --- | --- |
| trial | 1000 | 200 | 5 |
| starter | 10000 | 2500 | 4 |
| growth | 100000 | 30000 | ~3.33 |
| scale | 500000 | 200000 | 2.5 |
| hyper | 1000000 | 500000 | 2 |
| mega | 10000000 | 10000000 | 1 |

Example: a **21-sat** item on the trial plan. The buyer pays 21 sats to you. You spend 1 credit, about 5 sats. That fee is 5/21 of the item, about **25%**. A 100-sat item on the same plan is about 5%. Price the item so this fee is the margin you intend. Larger packs lower the fee per unlock.

One credit is one settled payment, not one HTTP call. A cheap call should be a bundle or a time pass on that payment (`max_uses` or `access_seconds` below), so one Lightning payment and one credit cover many requests. `max_uses: 1` is one payment, one request.

## Paywall (for your customers)

These are the endpoints your **customers** (agent operators) integrate:

- `POST /v1/paywall/challenge` with `X-Api-Key: ...` → returns `invoice + macaroon` for a resource
  - `invoice_expires_at` is when the Lightning invoice stops being payable (often about 24 hours from the payee's provider)
  - `claim_until` is when satsgate will still accept a first unlock: that invoice expiry plus a grace period (default 1 hour), and never later than 48 hours after the challenge was created
  - `valid_until` matches `claim_until` on a newly minted token. It is the macaroon expiry caveat. The merchant chooses how long the buyer may use the product
  - `cache_until` is the hint for how long to cache a successful unlock. On this response it matches `claim_until`
  - `ttl_seconds`, when sent, is the minimum time the invoice must stay payable. It does not shorten the macaroon below the invoice
  - `payee_saved: true` means this call stored `payee_lightning_address`. Later challenges use it. `payee_mismatch` means a different address was sent after that save. Change the saved address with `POST /v1/client/payee`
- `POST /v1/paywall/verify` with `X-Api-Key: ...` + `Authorization: L402 ...` and **`expected_resource` (required)**
  - `expected_resource` must exactly match the challenge `resource` (case-sensitive). A mismatch is HTTP 401 `resource mismatch`, and the body includes the issued `resource` when the macaroon belongs to this API key
  - verifies the preimage, or the stored LUD-21 URL when the header is `L402 <macaroon>` with no preimage
  - checks that the token was issued to **this client**, for **this** resource, amount, payee, and invoice. Any of that client's keys can unlock it, unless the key has a `resource_prefix` the resource does not start with
  - charges payment verifications (credits) once per `payment_hash` (`cost_credits`, default 1, is the merchant's own debit). `charged_credits` on the response is that debit. Later uses of the same payment do not charge again
  - `consume: true` atomically takes one use when the challenge set `max_uses` and/or `access_seconds`. Omit it, or send false, to check without taking a use
- `GET /v1/paywall/status/{payment_hash}` with the same API key and macaroon. **This GET spends a credit when it first settles.** Verify is the other call that can settle the same payment. `charged_credits` is 0 while pending and on every repeat. `consume=true` takes one use here too

`POST /v1/paywall/verify` and `GET /v1/paywall/status/{payment_hash}` share one debit per `payment_hash`. Use either one.

| State | `POST /v1/paywall/verify` | `GET /v1/paywall/status/{payment_hash}` |
| --- | --- | --- |
| Invoice not settled yet (LUD-21, no preimage) | HTTP 402, `error: payment_pending`, `status: pending`, `charged_credits: 0` | HTTP 200, `status: pending`, `settled: false`, `charged_credits: 0` |
| No LUD-21 URL and no preimage | HTTP 401 `preimage_required` | HTTP 401 `preimage_required` |
| LUD-21 disagrees after a preimage was sent | HTTP 401 `lud21_not_settled` | HTTP 401 `lud21_not_settled` |
| Bad macaroon, wrong client, or `resource mismatch` | HTTP 401 | HTTP 401 |
| Claim window has closed and this payment was not unlocked yet | HTTP 401 `invoice expired` | HTTP 401 `invoice expired` |
| Not enough credits | HTTP 402 | HTTP 402 |
| Settled (first time) | HTTP 200, `charged_credits` is `cost_credits` (default 1) | HTTP 200, same debit |
| Settled again | HTTP 200, `charged_credits: 0` | HTTP 200, `charged_credits: 0` |
| `consume=true` and the use counter is exhausted | HTTP 401 `token_used_up` | HTTP 401 `token_used_up` |
| `consume=true` and the access window has ended | HTTP 401 `token_expired` | HTTP 401 `token_expired` |

The 402-vs-200 difference for "not paid yet" stays so existing clients keep working. Both bodies say which code the other route uses.

On a successful unlock, `valid_until` remains the macaroon `exp` caveat (older clients cache with it). `claim_until` is the server deadline for a first unlock. `cache_until` is how long to cache that successful result so you do not call again. A token minted before 0.4.2 can have `valid_until` in the past while `claim_until` is still open. Cache with `cache_until`.

Tokens are version 2 (`token_version` on the challenge). A token minted for one client never verifies for another. v1 tokens are rejected. See the 0.4.2 notes in [`CHANGELOG.md`](./CHANGELOG.md).

## What one payment buys

With no `max_uses` and no `access_seconds`, a settled payment can be verified again until the challenge row is cleaned up (about a day for an Alby invoice). That is the previous behaviour, and it is still the default. Behind a proxy, that one payment would cover every call in that window.

Set a policy on `POST /v1/paywall/challenge` when the proxy should decide what the buyer paid for:

| Policy | Meaning |
| --- | --- |
| `{"max_uses": 1}` | One payment, one request. The server also ends the grant 7 days after settlement. |
| `{"max_uses": 50}` | A bundle of 50 requests, same 7-day cap when `access_seconds` is omitted. |
| `{"access_seconds": 3600}` | A time pass. The clock starts at settlement, not at challenge creation. |
| both | The buyer needs a remaining use and an open window. |
| neither | Unlimited re-verify, as before. |

`access_seconds` must be from 1 to the server cap. The cap is `SATSGATE_PAYWALL_ACCESS_CAP_SECONDS` (default `604800`, seven days, and it cannot be set higher). Lower it if you want shorter passes. You do not have to set it.

The proxy takes a use by sending `consume=true` on verify or status. That update is one database transaction, so two replicas cannot both take the last use. A check without `consume` still works and returns `uses_remaining` and `access_until` without changing the counter. `uses_remaining` is null when there is no `max_uses`. `access_until` is null until the payment settles, then it is the deadline. `consumed` is true when this call took a use. Each `consume=true` takes one use, including a retry after a lost response.

When the grant is over, `consume=true` returns HTTP 401 `token_used_up` or `token_expired`. Create a new challenge. Credits were already charged once, on the first settled unlock, and are not charged again for these errors.

Do not cache a policy grant locally for `cache_until`. That hint is for challenges with no policy. The Python SDK skips its cache when a policy is present or when `consume=true`. Call the server on each buyer request.

A restricted key can set this policy on the challenges it creates, and `resource_prefix` still applies.

```bash
curl -s -X POST https://api.satsgate.org/v1/paywall/challenge \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sgr_...RESTRICTED_KEY...' \
  -d '{"resource":"blog/post","amount_sats":21,"max_uses":1}'
```

## Buyer limits

`POST /v1/paywall/challenge` is per merchant. Without a buyer address, one caller can use the whole account budget (`SATSGATE_RL_MAX_CHALLENGE`, default 30 per minute, and `SATSGATE_MAX_OPEN_CHALLENGES_PER_CLIENT`, default 100) and each of those calls asks the payee's LNURL provider for an invoice.

A proxy that holds a restricted key can send the end buyer's address:

```bash
curl -s -X POST https://api.satsgate.org/v1/paywall/challenge \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sgr_...RESTRICTED_KEY...' \
  -H 'X-Satsgate-Buyer-Ip: 203.0.113.10' \
  -d '{"resource":"blog/post","amount_sats":21,"max_uses":1}'
```

The header is used only when the TCP connection comes from `SATSGATE_TRUSTED_PROXIES` (the same list as `X-Forwarded-For`). Any other caller can send the header and it is ignored, so the request behaves as before. `buyer_ip_accepted: false` on the response means the address was not used. A trusted peer that sends a value which is not one IP gets HTTP 400 `invalid_buyer_ip`.

The address is not stored. Satsgate keeps an HMAC of the truncated form (IPv4 /24, IPv6 /64), keyed by the macaroon secret, on the challenge row. That digest is deleted with the row, on the same cleanup as every other challenge. `1.2.3.4` and `1.2.3.50` share a bucket. `1.2.4.1` does not.

| Limit | Default | Env |
| --- | --- | --- |
| New challenges per buyer per `SATSGATE_RL_WINDOW_SECONDS` | 10 | `SATSGATE_BUYER_CHALLENGE_MAX` (`0` disables) |
| Unpaid challenges still inside the claim window | 5 | `SATSGATE_BUYER_MAX_OPEN_CHALLENGES` (`0` disables) |
| Bucket | the whole client | `SATSGATE_BUYER_LIMIT_SCOPE=client`, or `key` for a separate budget per restricted key |
| Reuse an identical pending challenge | 30 seconds | `SATSGATE_CHALLENGE_REUSE_SECONDS` (`0` disables) |

Over the rate: HTTP 429 `buyer_rate_limited`. Too many unpaid challenges: HTTP 429 `too_many_open_challenges_for_buyer`. The account cap is still HTTP 429 `too_many_open_challenges`. Each of these sends `Retry-After` and `retry_after_seconds`. Paying a challenge frees the unpaid slot. It does not reset the rate window. The per-client rate limit still applies on top of the buyer limits.

Reuse returns the same invoice and payment hash when the buyer, resource, amount, usage policy, payee, and key match an unpaid challenge from the last few seconds. `reused: true`. The macaroon is signed again for that invoice (it carries a new token id) and either copy verifies. A retry does not call the LNURL provider and does not count as a new challenge. Memo and `ttl_seconds` are not part of that match. Callers that omit the buyer header never receive someone else's invoice this way.

The Docker Caddyfile deletes `X-Satsgate-Buyer-Ip` from public requests, because Caddy itself is the trusted peer. Let the header through only from the paywall proxy's address. Python SDK 0.6.0: `paywall_challenge(..., buyer_ip="203.0.113.10")`.

## Restricted API keys

The key from top-up (`sg_...`) is the account key. It can top up, change the payee, read the ledger, and mint other keys. A proxy or MCP server that only needs to sell access should not hold that key: if it leaked, the holder could point payouts at another Lightning Address.

Create a restricted key with the account key. The full secret starts with `sgr_` and is returned once. Store only its hash. Up to 50 active restricted keys per client. Revoked keys stay in the list when you ask for them, so ledger rows can still name them.

```bash
curl -s -X POST https://api.satsgate.org/v1/api-keys \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...ACCOUNT_KEY...' \
  -d '{"label":"blog-proxy","resource_prefix":"blog/"}'
```

`resource_prefix` is optional. When it is set, challenge, status, and verify accept only resources that start with it (case-sensitive, same rule as `expected_resource`). Use a trailing slash (`blog/`) when you want a path boundary. `blog` also matches `blogger`.

| Call | Account key `sg_` | Restricted key `sgr_` |
| --- | --- | --- |
| `POST /v1/paywall/challenge` | yes | yes, and it cannot save or change the payee |
| `POST /v1/paywall/verify` and `GET /v1/paywall/status/{payment_hash}` | yes | yes |
| Top-up, payee, balance, client, ledger, usage, create/list/revoke keys | yes | HTTP 403 `insufficient_scope` |
| Resource outside the key's prefix | yes | HTTP 403 `resource_not_allowed` |
| After revoke | — | HTTP 401 `api_key_revoked` |

A restricted key is still the same client. It spends that client's credits, and a challenge minted by one key can be unlocked by another key of that client when the resource is allowed. The paywall debit records which key did it.

Set the payee with the account key before the proxy creates challenges. There is nothing new to configure. Restarting on 0.5.0 applies the migration.

## No-code proxy

`satsgate-proxy` (version 0.8.0, in [`proxy/`](./proxy/README.md)) sits in front of an HTTP API you already run. Buyers talk to the proxy. The proxy calls this core with a restricted `sgr_` key. The origin does not implement L402. It checks an HMAC instead.

An unpaid request is **402** with `WWW-Authenticate: L402 macaroon="...", invoice="..."` (macaroon before invoice, standard base64), which lnget and Alby `fetch402` already parse. The JSON body carries `amount_sats`, `payment_hash`, `invoice_expires_at`, and a hint for wallets that do not return a preimage. `Authorization: L402 <macaroon>:<preimage>` verifies with `consume=true`. `Authorization: L402 <macaroon>` polls status with `consume=true`. Pending stays on that invoice (`402 payment_pending`, `Retry-After`). A used, expired, or wrong-route token is a fresh 402, not 401.

The core API is still 0.7.0. `GET /health` on the core reports `0.7.0`. `GET /healthz` on the proxy reports `0.8.0`.

Config is YAML: upstream base URL, routes (`per_request`, `uses:N`, `pass:<seconds>`, scope `route` or `site`), free paths, body limits, and an origin secret from the environment. A `per_request` price below about 10 times the plan's sats-per-credit logs a warning at startup. The trial plan is about 5 sats per credit, so that line is 50 sats. Cheap calls should be bundles or passes.

The proxy sends `X-Satsgate-Buyer-Ip` when it has a real buyer address. Hosted `https://api.satsgate.org` uses that header only if the proxy's egress IP is in `SATSGATE_TRUSTED_PROXIES` and the edge does not strip it. Otherwise per-buyer limits do not apply and the per-client caps still do.

After consume, the proxy signs `X-Satsgate-Signature: t=<unix>, v1=<hmac-sha256>` over `{unix}|{METHOD}|{raw path and query}|{payment_hash}`. Snippets for FastAPI, Express, nginx, and a Caddy network gate are in `proxy/snippets/`. If the origin fails after that consume, the use is spent. Credits are not refunded: the sats already went to the merchant, and the credit was the one-time verification fee.

```bash
export SATSGATE_API_KEY='sgr_...'
export SATSGATE_ORIGIN_SECRET="$(openssl rand -hex 32)"
docker compose -f proxy/docker-compose.yml up --build
```

Full steps, the signature, and a mainnet checklist are in [`proxy/README.md`](./proxy/README.md).

## Pay from any wallet, then poll

When the payee's LNURL provider returns a LUD-21 `verify` URL (Alby does):

1. `GET /v1/topup/trial` and read `invoice`, `macaroon`, and `payment_hash` from the 402.
2. Pay that invoice in any Lightning wallet. You do not need the preimage.
3. Poll `GET /v1/topup/status/{payment_hash}` with `Authorization: L402 <macaroon>` until `settled` is true.
4. Save `api_key` from that response. A later poll succeeds but does not show the key again.

The Python SDK helpers are `SatsgateClient.poll_topup` and `SatsgateClient.poll_paywall`. If the provider did not send `verify`, the status call returns `preimage_required` and the `L402 <macaroon>:<preimage>` flow is still the way to finish.

The top-up macaroon stays valid until the invoice's `expires_at`, plus a grace period (default 1 hour) so a buyer can finish polling after paying near the end of the invoice, and never longer than 48 hours. A buyer can pay at any point while the invoice itself is still valid. `SATSGATE_TOKEN_TTL_SECONDS` does not apply to top-ups. A top-up token minted before 0.4.1, whose caveat expires after 10 minutes, is still accepted inside that same window when the pending row is unpaid, as long as the caller presents that macaroon and a preimage or a settled LUD-21 check. Past the window the response is `invoice expired` and nothing is credited.

Paywall challenges use the same shape of window (`SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS`, `SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS`, same defaults). A buyer can pay the paywall invoice at any point while that invoice is payable, then the merchant can unlock until `claim_until`. A paywall token minted before 0.4.2, whose caveat expires after 10 minutes, is still accepted inside that window when the caller presents the macaroon and a preimage or a settled LUD-21 check. `SATSGATE_TOKEN_TTL_SECONDS` is only the minimum invoice lifetime (and the dev-ticket macaroon TTL). Dev-ticket macaroons still use that TTL.

## L402 client compatibility

Challenges use `WWW-Authenticate: L402 macaroon="<standard base64>", invoice="<bolt11>"`. `Authorization` accepts `L402` and the legacy `LSAT` prefix, in the form `<macaroon>:<64-hex-preimage>`.

| Client | What it does with the challenge | Status |
| --- | --- | --- |
| lnget (Lightning Labs) | Parses the header, unmarshals a real macaroon, reads the payment hash from the L402 v0 identifier, pays, retries with `L402 <macaroon>:<preimage>` | Works. The macaroon is libmacaroons V2, standard base64 (Aperture's credential grammar is `[A-Za-z0-9+/=]+`, not url-safe). |
| Alby `fetch402` (`@getalby/lightning-tools`) | Treats the macaroon as an opaque string, pays, retries with `L402 <token>:<preimage>` | Works. The macaroon is re-rolled if its base64 would contain the substrings `L402` or `LSAT`, which that parser strips from the whole header. |
| Aperture as a verifying proxy | Expects its own service and capability caveats | Does not accept satsgate tokens. Our caveats are the v2 bindings (`v`, `kid`, `purpose`, `cid`, `ph`, `res`, `amt`, `payee_h`, `inv_h`, `exp`), not Aperture's. |

Tokens issued before 0.4.0 were signed JSON in url-safe base64. This server still verifies those. lnget cannot unmarshal them. A top-up or paywall token whose `exp` has passed still completes while its stored invoice window is open. Dev tickets do not.

## Scripts

- `python client_mock_demo.py` (mock L402 demo)
- `node client_nwc_demo.mjs` (pays `/v1/tickets` using NWC)
- `node client_topup_nwc.mjs trial|starter|growth|scale|hyper|mega` (top up payment verifications (credits) via NWC)
- `node client_paywall_credit_demo.mjs <resource> <amount_sats>` (challenge + pay + verify; spends 1 payment verification / credit)

## SDK (Python)

- `sdk/python` (package `satsgate-sdk`)
  - install locally: `pip install -e sdk/python`
  - FastAPI examples:
    - Minimal: `sdk/python/examples/fastapi_demo/main.py`
    - Reference integration: `sdk/python/examples/fastapi_reference/`

## Quickstart (local)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# .env.example is production-shaped and will refuse to boot until you set a
# real secret. For local mock mode:
export SATSGATE_ENV=development
export SATSGATE_DEV_MODE=1
export SATSGATE_WALLET_MODE=mock
export SATSGATE_MACAROON_SECRET=local-dev-only

uvicorn app.main:app --reload --port 8000
```

`/dev/mock/pay/{payment_hash}` is available only in that local configuration.

## Docker (recommended for deployment)

This repo includes a minimal Docker setup with **Caddy** (TLS) and a persistent SQLite volume.

1) Copy env file:

```bash
cp .env.example .env
```

2) Edit `.env` and set at least:

- `SATSGATE_HOSTNAME=api.yourdomain.com`
- `SATSGATE_ENV=production`
- `SATSGATE_MACAROON_SECRET=$(openssl rand -hex 32)`
- `SATSGATE_WALLET_MODE=lnaddr`
- `SATSGATE_LIGHTNING_ADDRESS=user@domain`
- `SATSGATE_DEV_MODE=0`

The stack pins Caddy at `172.28.0.2` and the app at `172.28.0.3`, and only trusts forwarded headers from Caddy. Do not set `SATSGATE_TRUSTED_PROXIES=*` or uvicorn `--forwarded-allow-ips *`.

3) Start:

```bash
docker compose up -d --build
```

Notes:
- Your DNS must point `SATSGATE_HOSTNAME` to your server IP.
- Ports **80** and **443** must be open for Caddy/Let’s Encrypt.
