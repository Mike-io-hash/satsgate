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
- x402 design (not implemented): [`docs/x402-design.md`](./docs/x402-design.md)

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

`GET /health` returns `{"ok": true, "version": "0.14.0"}` and nothing else.

## Prepaid payment verifications (credits)

In the API these are called `credits`. They **do not expire**.

Endpoints:

- `GET /v1/plans` → list plans
- `GET /v1/topup/{plan_id}` → start purchase (returns 402 + invoice + macaroon)
- `GET /v1/topup/{plan_id}` with `Authorization: L402 <macaroon>:<preimage>` → finalize purchase
- `GET /v1/topup/status/{payment_hash}` with `Authorization: L402 <macaroon>` → poll until the stored LUD-21 URL says the invoice settled, then credit the account
- `GET /v1/topup/{plan_id}/x402` with the account key → buy the same pack with USDC, when `SATSGATE_TREASURY_EVM_ADDRESS` is set. See below. Lightning is unchanged when it is not.
- `GET /v1/balance` with `X-Api-Key: ...` → current verification balance (credits)
- `GET /v1/client` with `X-Api-Key: ...` → client info (Lightning payee, and `payee_evm_address` / `payee_evm_verified` when set)
- `POST /v1/client/payee` with `X-Api-Key: ...` → register client payee (Lightning Address)
- `POST /v1/client/payee/evm/challenge` then `POST /v1/client/payee/evm` with the account key → prove an EVM address with an EIP-191 signature (x402 `payTo`; nothing is written on chain)

Restricted keys (account key only):

- `POST /v1/api-keys` with `X-Api-Key: sg_...` → create a restricted key (`sgr_...`, shown once)
- `GET /v1/api-keys` → list restricted keys (no secrets). `include_revoked=true` includes revoked rows
- `POST /v1/api-keys/{key_id}/revoke` → revoke a restricted key

Hosted sites (closed beta):

- `POST /v1/sites` → register a site. The origin HMAC secret is returned once
- `GET /v1/sites/mine`, `GET /v1/sites/{slug}`, `PATCH /v1/sites/{slug}`, `DELETE /v1/sites/{slug}`
- `POST /v1/sites/{slug}/rotate-secret` → replace the origin secret, shown once
- `POST /v1/sites/{slug}/routes`, `PATCH` and `DELETE /v1/sites/{slug}/routes/{route_id}`
- `GET /v1/sites` → public directory of approved sites that opted in. No owner, origin, or secret
- `POST /v1/admin/sites/{slug}/approve` and `/disable` with `X-Admin-Token`

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

| Call | Account key `sg_` | Paywall key `sgr_` (default) |
| --- | --- | --- |
| `POST /v1/paywall/challenge` | yes | yes, and it cannot save or change the payee |
| `POST /v1/paywall/verify` and `GET /v1/paywall/status/{payment_hash}` | yes | yes |
| Top-up, payee, balance, client, ledger, usage, create/list/revoke keys | yes | HTTP 403 `insufficient_scope` |
| Resource outside the key's prefix | yes | HTTP 403 `resource_not_allowed` |
| After revoke | — | HTTP 401 `api_key_revoked` |

Omit `scope` and the key stays `paywall`, which is the row above. `{"scope":"sites:read"}` or `{"scope":"sites:write"}` is for the hosted site registry below. Those keys cannot create challenges, and `resource_prefix` is rejected on them.

A restricted key is still the same client. It spends that client's credits, and a challenge minted by one key can be unlocked by another key of that client when the resource is allowed. The paywall debit records which key did it.

Set the payee with the account key before the proxy creates challenges. There is nothing new to configure. Restarting on 0.5.0 applies the migration.

## Hosted sites (closed beta)

Core stores the site. `satsgate-gate` (version 0.12.0, in [`gate/`](./gate/README.md)) serves `https://gate.satsgate.org/<slug>/<path>` after an operator approves the site. The public hostname stays commented out in the Caddyfile until DNS exists. Lightning goes to the merchant's Lightning Address. USDC goes to the merchant's verified Base Sepolia address through the public facilitator. One credit is still one unlock. The gate does not hold the sats or the USDC.

```bash
curl -s -X POST https://api.satsgate.org/v1/sites \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...ACCOUNT_KEY...' \
  -d '{"slug":"my-shop","display_name":"My Shop","origin_url":"https://origin.example","listed":false}'
```

The response includes `origin_secret` once. It is the HMAC key the origin uses to check `X-Satsgate-Signature`. Store it on the origin. Core keeps ciphertext in sqlite, encrypted with `SATSGATE_SITE_SECRET_KEY` (`openssl rand -hex 32`). A hash would not be enough, because the gate has to sign. The public API does not return the secret again. `POST /v1/sites/{slug}/rotate-secret` replaces it. The gate receives the current secret from an internal core route that requires `SATSGATE_GATE_TOKEN`.

`origin_url` must be https, with no userinfo, query, or fragment. Hostnames are resolved at registration. Private, loopback, link-local, CGNAT (`100.64.0.0/10`), and metadata addresses are rejected, including when any DNS answer is in those ranges. The gate repeats that check on every forward and connects to the public address from that lookup, so a name that later points at a private address (DNS rebinding) is not followed. Redirects are not followed.

Routes use the same usage policy as 0.6.0: `price_sats`, optional `max_uses`, optional `access_seconds`. Omit both policy fields and the grant stays open, as a challenge does today. Slugs are lowercase `[a-z0-9-]`, 3 to 40 characters, and a reserved-word list blocks names such as `admin` and `api`.

New sites start `pending`. `GET /v1/sites` lists only `approved` sites with `listed: true`. It returns `name`, `slug`, `url` (the gate URL), `description`, and `routes` (`price_currency`, `price_sats` or `price_usd_atomic`, `max_uses`, `access_seconds`). It does not return the owner, the origin, the secret, or an EVM `payTo`. `list_sites` in satsgate-mcp reads that directory by default. `SATSGATE_MCP_REGISTRY` can still point at a local file or another URL instead. Approve and disable with `X-Admin-Token` when `SATSGATE_ADMIN_TOKEN` is set. Without that env var those admin routes answer 404.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_SITE_SECRET_KEY` | unset | 64 hex characters. Required to create or rotate a site secret. Unset does not stop the process. |
| `SATSGATE_SITES_AUTO_APPROVE` | off | `1` marks new sites approved. Leave it off for the closed beta. |
| `SATSGATE_SITES_MAX_PER_ACCOUNT` | 3 | Sites per account, including disabled ones. |
| `SATSGATE_SITES_MAX_ROUTES` | 20 | Routes per site. |
| `SATSGATE_GATE_PUBLIC_BASE` | `https://gate.satsgate.org` | https origin used in public `url` values. No path. |
| `SATSGATE_GATE_TOKEN` | unset | Shared with the gate container. Unset means `/internal/gate/*` is 404. |
| `SATSGATE_GATE_PEERS` | empty (Compose sets `172.28.0.4`) | When set, only that TCP peer may present the gate token. |

Restart to serve 0.13.0. Copy `satsgate.sqlite3` before you restart. The 0.12.0 startup adds columns and rebuilds `site_routes` (see below). 0.13.0 does not add another table. Current API keys, credits, and Lightning challenges keep working if you do not set the new variables. Set `SATSGATE_SITE_SECRET_KEY` before the first site is created, and keep that value. Losing it makes stored secrets unreadable. Rotation still works and issues a new secret. Leave `SATSGATE_GATE_TOKEN` unset until the gate container is deployed. The public API host rejects `/internal/*` in Caddy either way.

### x402 on Base Sepolia (0.12.0)

A site can take USDC on Base Sepolia as well as Lightning. x402 is off until the merchant turns it on. The hosted gate 0.12.0 puts both enabled rails on one 402. The self-hosted proxy is still Lightning only. Core builds the `PAYMENT-REQUIRED` document, checks a `PAYMENT-SIGNATURE`, and asks the public facilitator to verify and settle. The gate does not call the facilitator and does not hold a key. Satsgate never signs or broadcasts a transaction. On x402, one merchant credit is charged only after the origin returns 2xx and the facilitator settles. Lightning still charges the credit before the origin is called.

The account key sets the receiving address. `POST /v1/client/payee/evm/challenge` with `{"address":"0x..."}` returns a message. The merchant signs that exact text (EIP-191, `personal_sign`) and posts `{"address","signature"}` to `POST /v1/client/payee/evm`. A wrong signature does not replace a stored address. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}` is account-key only and requires that verified address. `{"rail_lightning": false, "rail_x402": false}` is rejected.

A route has one price. `{"path":"/blog/post","price_sats":21}` stays Lightning. `{"path":"/blog/post","price_currency":"usd","price_usd_atomic":10000}` is 0.01 USDC (6 decimals) and is the only shape this release will offer over x402. Sending both amounts is `400 price_conflict`. There is no sats-to-USD conversion yet.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_X402_FACILITATOR_URL` | `https://x402.org/facilitator` | https facilitator base. No userinfo, query, or fragment. Core calls `POST /verify` and `POST /settle`. |
| `SATSGATE_X402_NETWORK` | `eip155:84532` | Base Sepolia only. Any other value, including Base mainnet `eip155:8453`, refuses to boot. |
| `SATSGATE_X402_OFFER_SECONDS` | 60 | How long a `PAYMENT-REQUIRED` offer stays reusable (15 to 300). |

Deployment of 0.12.0: stop the process, copy the sqlite file, then start. That migration adds six `payee_evm_*` columns on `clients` (existing rows stay empty), `rail_lightning` (default on) and `rail_x402` (default off) on `sites`, rebuilds `site_routes` so an existing row keeps its sats price, and creates `payment_offers` and `x402_authorizations`. You do not need a new secret. Leave the three x402 variables unset unless you are pointing at another testnet facilitator. The current gate ignores USD routes, so a mixed site's Lightning routes keep working and a USD path is not served until a later gate release.

### Rates (0.13.0)

`GET /v1/rates` is public. It returns the BTC/USD median, the sources that agreed, `fetched_at`, and `status` (`ok`, `stale`, or `unavailable`). Core reads Coinbase `BTC-USD`, Kraken `XBTUSD`, and Bitstamp `btcusd` about once a minute. Two sources are required. A source more than 2% from the median is dropped. The median is stale after 3 minutes.

The median is a quote. Satsgate does not convert, hold, or forward funds. The merchant is paid whatever the buyer sends on the rail they use.

When both rails are on and the median is fresh, the challenge locks the other currency on the offer. Derived sats round up to the next sat. Derived USDC rounds up to the next 0.000001 USDC, and a result below $0.001 is left off. A stale or missing median offers only the main currency. `GET /v1/sites/mine` shows that live quote as `derived`. The public directory does not, because it moves.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_RATES_ENABLED` | on | `0` skips the background refresh. |
| `SATSGATE_RATES_REFRESH_SECONDS` | 60 | How often the three sources are read (15 to 600). |
| `SATSGATE_RATES_STALE_SECONDS` | 180 | After this, the last median is not used to price a challenge. |
| `SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS` | 2 | Timeout for one source (0.5 to 5). |
| `SATSGATE_RATES_OUTLIER_BPS` | 200 | Drop a source this far from the median. 200 is 2%. |

No new table. Copy `satsgate.sqlite3` before restarting onto 0.13.0 anyway. Lightning is unchanged when the quote is not used.

### Hosted gate x402 (gate 0.12.0)

The gate offers Lightning, x402, or both, matching the site. A Lightning-only 402 is the 0.11.0 body and `WWW-Authenticate`, and it has no `PAYMENT-REQUIRED`. An x402 offer uses scheme `exact` on `eip155:84532`, the Base Sepolia USDC contract, and `payTo` equal to the verified address. The amount is the route's USD price, or the sats price converted with the live median and locked on that challenge. The gate does not cache the converted amount.

`PAYMENT-SIGNATURE` is checked by core (verify, then the origin, then settle). Both payment headers on one request is `400 one_rail_only`. The origin does not see `PAYMENT-SIGNATURE`. A USDC payment is signed with `X-Satsgate-Paid-Usd-Atomic`. The payment-hash header is the EIP-3009 nonce, because the transaction id does not exist until settle, and settle runs after the origin.

Enable it with the account key, not a restricted `sgr_` key:

1. `POST /v1/client/payee/evm/challenge` with `{"address":"0x..."}`. The response is an EIP-191 message. Nothing is written on chain.
2. Sign that exact text with `personal_sign` and `POST /v1/client/payee/evm` with `{"address","signature"}`. A bad signature does not replace a stored address.
3. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}`. Lightning can stay true. Both false is rejected.
4. Price the route in sats or in USD (`price_usd_atomic`, 6 decimals, 1 to 100000000). One main price per route.

No new migration and no new environment variable for the gate. Rebuild the gate image and the core image. Start them together, or start the gate first. `GET /health` reports `0.14.0`. `GET /healthz` on the gate reports `0.12.0`. Keep the facilitator at `https://x402.org/facilitator`. Route payments still go to the merchant's verified address. The treasury variable below is only for Satsgate credit packs. The private Sepolia check, including the merchant test address, is in [`gate/README.md`](./gate/README.md).

The gate resource string is `gate:<slug>:<path>` and must be at most 200 characters, which is the paywall resource limit. A longer route is stored and is not served.

### USDC credit packs (0.14.0)

`GET /v1/topup/{plan_id}` is still Lightning and still uses `price_sats`. `GET /v1/topup/{plan_id}/x402` sells that same pack for USDC, paid to Satsgate. The account key (`sg_...`) is required. A restricted `sgr_` key is rejected. Credits from either rail are closed-loop: they are not transferable and they are not redeemable for sats or USDC.

The USDC amount is the pack's sats price converted with `GET /v1/rates`. The median has to be fresh. Derived USDC rounds up to the next atomic unit (6 decimals). A quote below $0.001 or above $1,000,000 is not offered. The $100 cap on a merchant route does not apply here. At a $65,000 median, the trial pack (1000 sats) is 650000 atomic units, which is $0.65. That integer is locked on the offer until it expires. A missing or stale median is `503 rate_unavailable` on this route only.

No `PAYMENT-SIGNATURE` yet: `402` and the header `PAYMENT-REQUIRED` (x402 v2, scheme `exact`, network `eip155:84532`, Base Sepolia USDC, `payTo` the treasury). The body repeats `x402.amount`, `x402.payTo`, and `x402.network`. The header is canonical. `maxTimeoutSeconds` is `SATSGATE_X402_OFFER_SECONDS` clamped into 60–300 seconds (the default is 60).

With `PAYMENT-SIGNATURE`: core checks payTo, amount, asset, and network against the stored offer, then `POST /verify` and `POST /settle` on the facilitator. Credits are added only after settle returns a transaction. The response includes `PAYMENT-RESPONSE`. One EIP-3009 nonce grants the pack once. A replay is `409 x402_replay`. A second request still in flight is `409 x402_in_progress`. The ledger row has reason `topup_x402`, the tx hash in `ref`, plus `network` and `amount_usd_atomic`.

If `SATSGATE_TREASURY_EVM_ADDRESS` is unset, empty, or not a 20-byte address, this route answers `400 x402_topup_disabled` and Lightning top-up is unchanged. The process still boots. A worked request, without a signer, is `scripts/x402_topup_example.py`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_TREASURY_EVM_ADDRESS` | unset | Satsgate's own Base payTo for credit packs. Unset or invalid turns this rail off. Not used for merchant route payments. |

Startup adds columns. It does not add a table. Copy `satsgate.sqlite3` before restart if you want a rollback point. Restart the core image. The gate does not change. Leave the facilitator at `https://x402.org/facilitator`. Do not run a Satsgate facilitator.

## No-code proxy

`satsgate-proxy` (version 0.8.0, in [`proxy/`](./proxy/README.md)) sits in front of an HTTP API you already run. Buyers talk to the proxy. The proxy calls this core with a restricted `sgr_` key. The origin does not implement L402. It checks an HMAC instead.

An unpaid request is **402** with `WWW-Authenticate: L402 macaroon="...", invoice="..."` (macaroon before invoice, standard base64), which lnget and Alby `fetch402` already parse. The JSON body carries `amount_sats`, `payment_hash`, `invoice_expires_at`, and a hint for wallets that do not return a preimage. `Authorization: L402 <macaroon>:<preimage>` verifies with `consume=true`. `Authorization: L402 <macaroon>` polls status with `consume=true`. Pending stays on that invoice (`402 payment_pending`, `Retry-After`). A used, expired, or wrong-route token is a fresh 402, not 401.

The self-hosted proxy stays 0.8.0. `GET /healthz` on the proxy reports `0.8.0`. Core health is `0.14.0`. The proxy's paywall calls are unchanged. It does not sell credit packs. Top up on the core, with Lightning or with the USDC pack route. The hosted gate is a different process.

Config is YAML: upstream base URL, routes (`per_request`, `uses:N`, `pass:<seconds>`, scope `route` or `site`), free paths, body limits, and an origin secret from the environment. A `per_request` price below about 10 times the plan's sats-per-credit logs a warning at startup. The trial plan is about 5 sats per credit, so that line is 50 sats. Cheap calls should be bundles or passes.

The proxy sends `X-Satsgate-Buyer-Ip` when it has a real buyer address. Hosted `https://api.satsgate.org` uses that header only if the proxy's egress IP is in `SATSGATE_TRUSTED_PROXIES` and the edge does not strip it. Otherwise per-buyer limits do not apply and the per-client caps still do.

After consume, the proxy signs `X-Satsgate-Signature: t=<unix>, v1=<hmac-sha256>` over `{unix}|{METHOD}|{raw path and query}|{payment_hash}`. Snippets for FastAPI, Express, nginx, and a Caddy network gate are in `proxy/snippets/`. If the origin fails after that consume, the use is spent. Credits are not refunded: the sats already went to the merchant, and the credit was the one-time verification fee.

```bash
export SATSGATE_API_KEY='sgr_...'
export SATSGATE_ORIGIN_SECRET="$(openssl rand -hex 32)"
docker compose -f proxy/docker-compose.yml up --build
```

Full steps, the signature, and a mainnet checklist are in [`proxy/README.md`](./proxy/README.md).

## Buyer MCP

`satsgate-mcp` (version 0.10.0, in [`mcp/`](./mcp/README.md)) is a separate process an agent runs over stdio. It is a client. It does not change the core.

`discover` and `quote` request a URL and read the 402: price in sats, `max_uses`, `access_seconds`, and expiry. `pay_and_fetch` with mode `human` returns the invoice and a QR. `check_payment` polls settlement without a preimage, then retries the URL with the macaroon. Mode `nwc` pays from `SATSGATE_MCP_NWC_URI` in the environment, never from a tool argument, and only inside `SATSGATE_MCP_MAX_PAYMENT_SATS` and `SATSGATE_MCP_DAILY_MAX_SATS`. A token with uses or time left is reused. `token_used_up` comes back as a new quote unless `SATSGATE_MCP_AUTO_PAY` is on and the new invoice is inside the budget.

An optional `sgr_` key enables read-only `challenge_status` and `credits_balance`. The key cannot top up or change the payee. `list_sites` reads `GET /v1/sites` on the core URL: approved, listed sites, each with a gate URL and route prices. Set `SATSGATE_MCP_REGISTRY` to a JSON file or another URL only when that directory should be replaced.

Core health is `0.14.0`. `GET /health` reports `0.14.0`. The MCP package is 0.10.0. It still cannot top up. Buying credits with USDC is `GET /v1/topup/{plan_id}/x402` on the core with the account key, not an MCP tool. A USD route in the public directory is skipped by `list_sites` until a later MCP release, because that tool still requires `price_sats`.

```bash
pip install -r mcp/requirements.txt
PYTHONPATH=mcp/src python -m satsgate_mcp.manual https://your-proxy.example/blog/post
```

That command shows a QR and polls. It does not set a wallet. NWC and the mainnet lnget / fetch402 steps are in [`mcp/README.md`](./mcp/README.md).

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
