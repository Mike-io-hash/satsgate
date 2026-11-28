# API reference

Reference for the hosted API, the paywall, and the buyer tools. A short tour is in the [README](../README.md). Running the core yourself is in [self-hosting](self-hosting.md).

## USDC payments: Base network only

USDC payments use Base only. Ethereum mainnet, Polygon, Solana, Arbitrum, and any other chain are not accepted.

| Network | Network id | Circle USDC contract | Status |
| --- | --- | --- | --- |
| Base Sepolia (testnet) | `eip155:84532` | [`0x036CbD53842c5426634e7929541eC2318f3dCF7e`](https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e) | Testing. A site in test mode offers only this USDC, through `https://x402.org/facilitator`. It is not a network for real buyers. |
| Base | `eip155:8453` | [`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) | Live mode (on by default on api.satsgate.org; a self-hosted core needs `SATSGATE_X402_CDP=1` and CDP credentials, see [self-hosting](self-hosting.md)). A site in live mode offers only this USDC, through the Coinbase CDP facilitator. |

Merchants: `payTo` must be an address you control on Base. The USDC is paid to that address on the one network that site is in. A 402 never lists both. The EIP-712 domain name in `extra` follows that contract: `USDC` on Base Sepolia and `USD Coin` on Base. Both use version `2`. Try on Base Sepolia with your agent first, then switch the site to live. Buyers: USDC sent on another network will not be accepted. A balance on Ethereum, Polygon, Solana, or Arbitrum does not pay a Satsgate 402.

A new site leaves x402 off and the mode unset. Turning x402 on without a mode stores `test`. That default is deliberate: a merchant does not take real USDC until they set `x402_mode` to `live`. Live mode is on by default on api.satsgate.org. A self-hosted core rejects live mode until `SATSGATE_X402_CDP=1` is set. Test mode is labeled `testing: true` on the API response. The resource description says it is Base Sepolia, not Base mainnet.

Satsgate never custodies, receives, forwards, or refunds buyer funds. The USDC moves from the buyer to the merchant's `payTo`. Satsgate does not hold a buyer wallet and does not run its own facilitator.

Hosted beta: https://api.satsgate.org (start in [`CUSTOMER_QUICKSTART.md`](../CUSTOMER_QUICKSTART.md)). Minimum Lightning top-up: **1,000 sats**. Minimum USDC top-up: **US$1**. Prepaid balance does not expire.

No LLM in the hot path: Satsgate is a lightweight, low-latency “cashier/turnstile” that sits in front of your agent.

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

`GET /health` returns `{"ok": true, "version": "0.20.5"}` and nothing else. Works with core 0.20.3 or later.

## Prepaid balance (millisatoshis)

The balance field is `balance_msat`. It does not expire. The 500 free unlocks reset on the first of each UTC month.

Endpoints:

- `POST /v1/accounts` → open an account. The `sg_` key is returned once.
- `GET /v1/plans` → model B (quota, 2 sats, 10% cap, US$0.001 floor, bonus tiers). Not a pack list.
- `POST /v1/topup/lightning` with `{"sats": N}` → 402 invoice for exactly N sats (minimum 1,000).
- `POST /v1/topup/usdc` with `{"usd": "1.00"}` → 402 USDC payment for a free amount (minimum US$1), when the treasury address is set.
- `GET /v1/topup/status/{payment_hash}` with `Authorization: L402 <macaroon>` → poll until the invoice settles, then add the settled amount to `balance_msat`.
- `GET /v1/balance` with `X-Api-Key: ...` → `balance_msat`, `balance_sats`, and the unlock estimate. An `sgr_` key can read this.
- `GET /v1/client` with `X-Api-Key: ...` → client info (Lightning payee, and `payee_evm_address` / `payee_evm_verified` when set)
- `POST /v1/client/payee` with `X-Api-Key: ...` → register client payee (Lightning Address)
- `POST /v1/client/payee/evm/challenge` then `POST /v1/client/payee/evm` with the account key → prove an EVM address with an EIP-191 signature (x402 `payTo`; nothing is written on chain)

Restricted keys (account key only):

- `POST /v1/api-keys` with `X-Api-Key: sg_...` → create a restricted key (`sgr_...`, shown once)
- `GET /v1/api-keys` → list restricted keys (no secrets). `include_revoked=true` includes revoked rows
- `POST /v1/api-keys/{key_id}/revoke` → revoke a restricted key

Hosted sites:

- `POST /v1/sites` → register a site. The origin HMAC secret is returned once
- `GET /v1/sites/mine`, `GET /v1/sites/{slug}`, `PATCH /v1/sites/{slug}`, `DELETE /v1/sites/{slug}`
- `POST /v1/sites/{slug}/rotate-secret` → replace the origin secret, shown once
- `POST /v1/sites/{slug}/routes`, `PATCH` and `DELETE /v1/sites/{slug}/routes/{route_id}`
- `GET /v1/sites` → public directory of approved sites that opted in. No owner, origin, or secret
- `POST /v1/admin/sites/{slug}/approve` and `/disable` with `X-Admin-Token`

Reporting:

- `GET /v1/ledger` with `X-Api-Key: ...` → ledger entries in millisatoshis (`delta_msat`). Paywall debits include `api_key_id`, `api_key_label`, `api_key_prefix`, and `resource` (`api_key_id` is null when the account key spent it)
- `GET /v1/usage/summary?since_hours=24` with `X-Api-Key: ...` → usage summary. `summary.by_api_key` groups paywall debits by the key that spent them (null `api_key_id` is the account key)
- `GET /v1/usage/daily?days=30` with `X-Api-Key: ...` → daily series (UTC)
- `GET /v1/usage/forecast` with `X-Api-Key: ...` → runway in millisatoshis. It does not recommend a purchase.

## What an unlock costs

The first 500 successful live unlocks in a UTC month are free, shared by accounts that pay out to the same Lightning Address or the same verified EVM address. After that, the merchant pays a prepaid fee: 2 sats, capped at 10% of the item, with a US$0.001 floor on USDC items only. The fee is locked when the challenge is issued. The buyer still pays the item price to the merchant.

A 10-sat Lightning item is a 1-sat fee (10%). A 21-sat item is 2 sats. A USDC item uses the same cap plus the floor. One settled payment is one unlock, not one HTTP call. A cheap call can be a bundle or a time pass (`max_uses` or `access_seconds`).

## Paywall (for your customers)

These are the endpoints your **customers** (agent operators) integrate:

- `POST /v1/paywall/challenge` with `X-Api-Key: ...` → returns `invoice + macaroon` for a resource
  - `invoice_expires_at` is when the Lightning invoice stops being payable (often about 24 hours from the payee's provider)
  - `claim_until` is when Satsgate will still accept a first unlock: that invoice expiry plus a grace period (default 1 hour), and never later than 48 hours after the challenge was created
  - `valid_until` matches `claim_until` on a newly minted token. It is the macaroon expiry caveat. The merchant chooses how long the buyer may use the product
  - `cache_until` is the hint for how long to cache a successful unlock. On this response it matches `claim_until`
  - `ttl_seconds`, when sent, is the minimum time the invoice must stay payable. It does not shorten the macaroon below the invoice
  - `payee_saved: true` means this call stored `payee_lightning_address`. Later challenges use it. `payee_mismatch` means a different address was sent after that save. Change the saved address with `POST /v1/client/payee`
- `POST /v1/paywall/verify` with `X-Api-Key: ...` + `Authorization: L402 ...` and **`expected_resource` (required)**
  - `expected_resource` must exactly match the challenge `resource` (case-sensitive). A mismatch is HTTP 401 `resource mismatch`, and the body includes the issued `resource` when the macaroon belongs to this API key
  - verifies the preimage, or the stored LUD-21 URL when the header is `L402 <macaroon>` with no preimage
  - checks that the token was issued to **this client**, for **this** resource, amount, payee, and invoice. Any of that client's keys can unlock it, unless the key has a `resource_prefix` the resource does not start with
  - debits the prepaid balance once per `payment_hash` after the free quota. `cost_credits`, if sent, is ignored. `charged_credits` is 1 when that debit happened and 0 otherwise. `new_balance` is millisatoshis. Later uses of the same payment do not debit again
  - `consume: true` atomically takes one use when the challenge set `max_uses` and/or `access_seconds`. Omit it, or send false, to check without taking a use
- `GET /v1/paywall/status/{payment_hash}` with the same API key and macaroon. **This GET debits the prepaid balance when it first settles.** Verify is the other call that can settle the same payment. `charged_credits` is 0 while pending and on every repeat. `consume=true` takes one use here too

`POST /v1/paywall/verify` and `GET /v1/paywall/status/{payment_hash}` share one debit per `payment_hash`. Use either one.

| State | `POST /v1/paywall/verify` | `GET /v1/paywall/status/{payment_hash}` |
| --- | --- | --- |
| Invoice not settled yet (LUD-21, no preimage) | HTTP 402, `error: payment_pending`, `status: pending`, `charged_credits: 0` | HTTP 200, `status: pending`, `settled: false`, `charged_credits: 0` |
| No LUD-21 URL and no preimage | HTTP 401 `preimage_required` | HTTP 401 `preimage_required` |
| LUD-21 disagrees after a preimage was sent | HTTP 401 `lud21_not_settled` | HTTP 401 `lud21_not_settled` |
| Bad macaroon, wrong client, or `resource mismatch` | HTTP 401 | HTTP 401 |
| Claim window has closed and this payment was not unlocked yet | HTTP 401 `invoice expired` | HTTP 401 `invoice expired` |
| Not enough prepaid balance | HTTP 402 | HTTP 402 |
| Settled (first time) | HTTP 200, `charged_credits` is 1 when the balance was debited | HTTP 200, same debit |
| Settled again | HTTP 200, `charged_credits: 0` | HTTP 200, `charged_credits: 0` |
| `consume=true` and the use counter is exhausted | HTTP 401 `token_used_up` | HTTP 401 `token_used_up` |
| `consume=true` and the access window has ended | HTTP 401 `token_expired` | HTTP 401 `token_expired` |

The 402-vs-200 difference for "not paid yet" stays so existing clients keep working. Both bodies say which code the other route uses.

On a successful unlock, `valid_until` remains the macaroon `exp` caveat (older clients cache with it). `claim_until` is the server deadline for a first unlock. `cache_until` is how long to cache that successful result so you do not call again. A token minted before 0.4.2 can have `valid_until` in the past while `claim_until` is still open. Cache with `cache_until`.

Tokens are version 2 (`token_version` on the challenge). A token minted for one client never verifies for another. v1 tokens are rejected. See the 0.4.2 notes in [`CHANGELOG.md`](../CHANGELOG.md).

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

When the grant is over, `consume=true` returns HTTP 401 `token_used_up` or `token_expired`. Create a new challenge. The unlock fee was already debited once, on the first settled unlock, and is not debited again for these errors.

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
| Unpaid challenges still inside the offer window, per rail | 5 | `SATSGATE_BUYER_MAX_OPEN_CHALLENGES` (`0` disables) |
| Bucket | the whole client | `SATSGATE_BUYER_LIMIT_SCOPE=client`, or `key` for a separate budget per restricted key |
| Reuse an identical pending challenge | 30 seconds | `SATSGATE_CHALLENGE_REUSE_SECONDS` (`0` disables) |

Over the rate: HTTP 429 `buyer_rate_limited`. Too many unpaid challenges still inside the offer window on one rail: HTTP 429 `too_many_open_challenges_for_buyer`. Lightning invoices and x402 offers each have that budget, so five open invoices do not block an x402 offer. An expired challenge does not count. An unpaid Lightning invoice also stops counting after `SATSGATE_X402_OFFER_SECONDS` (clamped to 60–300), even when the invoice itself is still payable. `Retry-After` is the soonest of those slot ends. The account cap is HTTP 429 `too_many_open_challenges` with the same rule. Paying a challenge frees the unpaid slot. It does not reset the rate window. The per-minute rate still counts new challenges on both rails together. The per-client rate limit still applies on top of the buyer limits.

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

A restricted key is still the same client. It spends that client's prepaid service balance, and a challenge minted by one key can be unlocked by another key of that client when the resource is allowed. The paywall debit records which key did it.

Set the payee with the account key before the proxy creates challenges. There is nothing new to configure. Restarting on 0.5.0 applies the migration.

## Hosted sites

Core stores the site. `satsgate-gate` (version 0.15.3, in [`gate/`](../gate/README.md)) charges at `https://gate.satsgate.org/<slug>/<path>` and returns a signed receipt. It does not call, relay, or serve the origin. The buyer repeats the request at `redeem_url` with the header `Satsgate-Receipt`. Works with core 0.20.3 or later. The self-hosted proxy is 0.15.1. satsgate-mcp is 0.14.1 and follows that receipt when the host is allowed. The connect page stays 0.17.0. Lightning goes to the merchant's Lightning Address. USDC goes to the merchant's verified address on the one network that site is in: Base Sepolia in test mode, Base when the site is live (on by default on api.satsgate.org). On this gate, the prepaid balance is debited when the receipt is issued. Test mode stores the receipt and does not debit. Self-hosted `/v1/paywall/*` still debits on settle and still forwards from the proxy. Satsgate does not hold the sats or the USDC and does not refund buyers.

```bash
curl -sI https://gate.satsgate.org/my-shop/blog/post
# 402, Link: <https://origin.example/blog/post>; rel="satsgate-redeem"
# JSON includes delivery=receipt, redeem_url, receipt_header, seller_host

curl -sD - -o /dev/null -X POST https://gate.satsgate.org/my-shop/blog/post \
  -H 'Authorization: L402 <macaroon>:<preimage>'
# 200, Satsgate-Receipt: <compact JWT>, body.receipt is the same token
```

The receipt payload (the middle segment) looks like this. `kid` in the header is the first 16 hex characters of SHA-256 of the site secret. `amt` is `{"sats": 21}` or `{"usd_atomic": 10000, "network": "eip155:8453"}`.

```json
{
  "iss": "https://gate.satsgate.org",
  "aud": "my-shop",
  "sub": "/blog/post",
  "jti": "rcp_abcdefghijklmnopqrstuv",
  "iat": 1700000000,
  "exp": 1700086400,
  "res": "gate:my-shop:/blog/post",
  "rail": "lightning",
  "amt": {"sats": 21},
  "uses": 1,
  "ph": "<payment hash, or the x402 nonce without 0x>"
}
```

A seller checks it with the SDK. The secret stays on the seller.

```python
from satsgate_sdk.receipts import SatsgateReceiptMiddleware, SqliteReceiptStore

app = SatsgateReceiptMiddleware(
    app,
    site="my-shop",
    secret=os.environ["SATSGATE_SITE_SECRET"],
    store=SqliteReceiptStore("/data/receipts.sqlite3"),
)
```

```bash
curl -s -X POST https://api.satsgate.org/v1/sites \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...ACCOUNT_KEY...' \
  -d '{"slug":"my-shop","display_name":"My Shop","origin_url":"https://origin.example","listed":false,"accept_terms":"<terms_version>"}'
```

The response includes `origin_secret` once. It is the HMAC key the seller uses to verify `Satsgate-Receipt`. Store it on the origin. Core keeps ciphertext in sqlite, encrypted with `SATSGATE_SITE_SECRET_KEY` (`openssl rand -hex 32`). The public API does not return the secret again. `POST /v1/sites/{slug}/rotate-secret` replaces it and clears `origin_verified_at`. The gate does not receive the secret. A receipt the buyer already paid for is rebuilt with the current secret when they present the same payment.

`origin_url` must be https, with no userinfo, query, or fragment. Hostnames are resolved at registration and again on `POST /v1/sites/{slug}/verify-origin`. Private, loopback, link-local, CGNAT (`100.64.0.0/10`), and metadata addresses are rejected, including when any DNS answer is in those ranges. The hosted gate does not connect to the origin.

Routes take `price_sats` or a USD price, optional `max_uses`, and optional `access_seconds`. On the hosted gate a missing `max_uses` is one use and a missing `access_seconds` is `SATSGATE_RECEIPT_SECONDS`. A self-hosted paywall challenge still stays open when both policy fields are omitted. Slugs are lowercase `[a-z0-9-]`, 3 to 40 characters, and a reserved-word list blocks names such as `admin` and `api`.

New sites start `pending`. On `api.satsgate.org` a site moves to `approved` by itself after two steps: a successful `POST /v1/sites/{slug}/verify-origin`, and acceptance of the current terms (`accept_terms` on create, or `PATCH /v1/sites/{slug}` with `accept_terms`). The current version is `terms_version` in `/.well-known/satsgate.json`, and a `terms_not_accepted` error returns it with `terms_url`. A suspended account cannot go live.

`POST /v1/sites`, `GET /v1/sites/mine`, `GET /v1/sites/{slug}`, `PATCH /v1/sites/{slug}`, and `POST /v1/sites/{slug}/verify-origin` return `site.activation`: `live` (true or false) and `reasons`, a list of `{"code", "detail"}`. The codes are `origin_not_verified`, `terms_not_accepted` (with `terms_version` and `terms_url`), `recheck_needed`, `operator_review`, `site_disabled`, and `account_suspended`. An approved site of an account in good standing has `live: true` and no reasons.

On the gate, a registered site that is not approved answers HTTP 404 with `error: site_not_active` and a `hint`. Nothing is charged. Pending and disabled look the same to a buyer. An unknown slug answers `not_found`.

`GET /v1/sites` lists only `approved` sites with `listed: true`. It returns `name`, `slug`, `url` (the gate URL), `description`, and `routes` (`price_currency`, `price_sats` or `price_usd_atomic`, `max_uses`, `access_seconds`). It does not return the owner, the origin, the secret, or an EVM `payTo`. `list_sites` in satsgate-mcp reads that directory by default. `SATSGATE_MCP_REGISTRY` can still point at a local file or another URL instead. With `SATSGATE_SITES_AUTO_APPROVE` off, an operator approves sites. Approve and disable with `X-Admin-Token` when `SATSGATE_ADMIN_TOKEN` is set. Without that env var those admin routes answer 404.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_SITE_SECRET_KEY` | unset | 64 hex characters. Required to create or rotate a site secret. Unset does not stop the process. |
| `SATSGATE_SITES_AUTO_APPROVE` | off | `1` approves a new site only after a successful origin check, acceptance of the current `SATSGATE_TERMS_VERSION`, and an account that is not suspended. Empty terms with this switch on refuses to boot. The default is off. |
| `SATSGATE_RECEIPT_SECONDS` | 86400 | Receipt lifetime when the route sets no `access_seconds`. Clamped to 60–86400 and to the paywall access cap. |
| `SATSGATE_TERMS_VERSION` | empty | Effective date of the terms you serve. |
| `SATSGATE_TERMS_URL` | empty | https page linked from the API and the gate 402 when set. Empty means the key is present and null. |
| `SATSGATE_ABUSE_CONTACT` | empty | Bare email. Shown on `GET /` of the gate when set. |
| `SATSGATE_GEOBLOCK_COUNTRIES` | empty | ISO codes refused on signups and quotes. Empty skips the lookup. |
| `SATSGATE_GEOIP_DB` | `/data/geoip/dbip-country-lite.mmdb` | DB-IP Country Lite. Required only when the country list is set. |
| `SATSGATE_OFAC_EVM_FILE` | `/data/ofac/ofac_evm.txt` | Local EVM addresses from the OFAC SDN list. Missing file fails open. |
| `SATSGATE_SITES_MAX_PER_ACCOUNT` | 3 | Sites per account, including disabled ones. |
| `SATSGATE_SITES_MAX_ROUTES` | 20 | Routes per site. |
| `SATSGATE_GATE_PUBLIC_BASE` | `https://gate.satsgate.org` | https origin used in public `url` values. No path. |
| `SATSGATE_GATE_TOKEN` | unset | Shared with the gate container. Unset means `/internal/gate/*` is 404. |
| `SATSGATE_GATE_PEERS` | empty (Compose sets `172.28.0.4`) | When set, only that TCP peer may present the gate token. |

Copy `satsgate.sqlite3` before you restart. Set `SATSGATE_SITE_SECRET_KEY` before the first site is created, and keep that value. Losing it makes stored secrets unreadable. Rotation still works and issues a new secret. Leave `SATSGATE_GATE_TOKEN` unset until the gate container is deployed. The public API host rejects `/internal/*` in Caddy either way. Version notes are in [`CHANGELOG.md`](../CHANGELOG.md).

### x402

A site can take USDC on Base as well as Lightning. x402 is off until the merchant turns it on. Core builds the `PAYMENT-REQUIRED` document, checks a `PAYMENT-SIGNATURE`, and asks the facilitator to verify and settle. The gate does not call the facilitator and does not hold a key. Satsgate never signs or broadcasts a transaction. On x402, the unlock fee is debited from the prepaid service balance only after the origin returns 2xx and the facilitator settles. On the hosted gate, Lightning debits when the receipt is issued. The proxy debits the unlock fee only after the origin returns 2xx. Buyer sats go to the merchant's Lightning Address when the invoice is paid. Any remedy for a failed origin is between the buyer and the merchant. Satsgate does not custody those sats and does not refund buyers.

The account key sets the receiving address. `POST /v1/client/payee/evm/challenge` with `{"address":"0x..."}` returns a message. The merchant signs that exact text (EIP-191, `personal_sign`) and posts `{"address","signature"}` to `POST /v1/client/payee/evm`. A wrong signature does not replace a stored address. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}` is account-key only and requires that verified address. `{"rail_lightning": false, "rail_x402": false}` is rejected.

A route has one price. `{"path":"/blog/post","price_sats":21}` stays Lightning. `{"path":"/blog/post","price_currency":"usd","price_usd_atomic":10000}` is 0.01 USDC (6 decimals). A sats price can also be offered as USDC when the quote is fresh. Sending both amounts is `400 price_conflict`. 

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_X402_FACILITATOR_URL` | `https://x402.org/facilitator` | https facilitator base. No userinfo, query, or fragment. Core calls `POST /verify` and `POST /settle`. |
| `SATSGATE_X402_NETWORK` | `eip155:84532` | Base Sepolia only. Any other value, including Base mainnet `eip155:8453`, refuses to boot. |
| `SATSGATE_X402_OFFER_SECONDS` | 60 | Offer lifetime. Config accepts 15 to 300. Gate routes and USDC top-up clamp it to 60–300. A Lightning invoice uses its own expiry. |
| `SATSGATE_X402_PAYEE_CHALLENGE_SECONDS` | 1800 | Payee signature window. Values outside 300–3600 are clamped. |
| `SATSGATE_PAYEE_CONNECT_SECONDS` | 3600 | Connect-link lifetime. Values outside 600–86400 are clamped. |
| `SATSGATE_CONNECT_PUBLIC_BASE` | `https://satsgate.org/connect` | https URL with the page path. The token is appended as a fragment. |

Gate 0.15.3 serves both Lightning and USD routes. Leave the facilitator variables unset unless you are pointing at another facilitator. `SATSGATE_X402_NETWORK` stays `eip155:84532`; mainnet USDC is `SATSGATE_X402_CDP`, not that variable.

### Rates

`GET /v1/rates` is public. It returns the effective BTC/USD quote: `pair`, `value`, `fetched_at`, `status` (`ok` or `unavailable`), and `source` (`oracle` or `fallback`) when a quote is usable. It does not list where the number came from.

The quote is an on-chain BTC/USD price, with an internal backup when that price is missing or unusable. Satsgate does not convert, hold, or forward funds. The merchant is paid whatever the buyer sends on the rail they use.

When both rails are on and the quote is fresh, the challenge locks the other currency on the offer. Derived sats round up to the next sat. Derived USDC rounds up to the next 0.000001 USDC, and a result below $0.001 is left off. A missing quote offers only the main currency. `GET /v1/sites/mine` shows that live quote as `derived`. The public directory does not, because it moves.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_RATES_ENABLED` | on | `0` skips the background refresh. |
| `SATSGATE_RATES_REFRESH_SECONDS` | 60 | How often the quote is refreshed (15 to 600). |
| `SATSGATE_RATES_STALE_SECONDS` | 180 | After this, the internal backup is not used to price a challenge. The primary read stays fresh for 3,600 seconds. |
| `SATSGATE_RATES_SOURCE_TIMEOUT_SECONDS` | 2 | Timeout for one source (0.5 to 5). |
| `SATSGATE_RATES_OUTLIER_BPS` | 200 | Drop a backup sample this far from the others. 200 is 2%. |
| `SATSGATE_BASE_RPC_URL` | `https://mainnet.base.org` | Primary Base RPC for the on-chain quote and for smart-wallet checks. |
| `SATSGATE_BASE_RPC_FALLBACK_URL` | empty | Optional second Base RPC. Same https rules. Used only when the primary does not answer. |
| `SATSGATE_ACCOUNTING_RATE_CACHE_S` | 60 | How long a quote is reused. |
| `SATSGATE_ACCOUNTING_RATE_STALE_S` | 3600 | How old the primary read may be. |
| `SATSGATE_ACCOUNTING_RATE_TIMEOUT_S` | 3 | Timeout for one primary read. |

Lightning is unchanged when the quote is not used.

### Hosted gate x402

The gate offers Lightning, x402, or both, matching the site. A Lightning-only 402 is the 0.11.0 body and `WWW-Authenticate`, and it has no `PAYMENT-REQUIRED`. An x402 offer uses scheme `exact` on the site's network: `eip155:84532` (Base Sepolia USDC) in test mode, `eip155:8453` (Base USDC) in live mode. The amount is the route's USD price, or the sats price converted with the effective quote and locked on that challenge. The gate does not cache the converted amount.

`PAYMENT-SIGNATURE` is checked by core (verify, then the origin, then settle). Both payment headers on one request is `400 one_rail_only`. The origin does not see `PAYMENT-SIGNATURE`. A USDC payment is signed with `X-Satsgate-Paid-Usd-Atomic`. The payment-hash header is the EIP-3009 nonce, because the transaction id does not exist until settle, and settle runs after the origin.

Enable it with the account key, not a restricted `sgr_` key. Set `payTo` to an address you control on Base. Gate 0.12.0 offered Base Sepolia. Current mode choice is in [USDC payments: Base network only](#usdc-payments-base-network-only).

1. `POST /v1/client/payee/evm/challenge` with `{"address":"0x..."}`. The response is an EIP-191 message. Nothing is written on chain.
2. Sign that exact text with `personal_sign` and `POST /v1/client/payee/evm` with `{"address","signature"}`. A bad signature does not replace a stored address.

Or create a one-time connect link with `POST /v1/client/payee/evm/connect` and open it in a browser.

3. `PATCH /v1/sites/{slug}` with `{"rail_x402": true}`. Lightning can stay true. Both false is rejected.
4. Price the route in sats or in USD (`price_usd_atomic`, 6 decimals, 1 to 100000000). One main price per route.

Keep the facilitator at `https://x402.org/facilitator`. Route payments go to the merchant's verified address. An x402 offer, and the cap slot of an unpaid Lightning quote, last `SATSGATE_X402_OFFER_SECONDS` clamped to 60–300 seconds. The Lightning invoice itself is not shortened. The treasury variable below is only for Satsgate USDC top-ups. The private Sepolia check is in [`gate/README.md`](../gate/README.md).

Base Sepolia offers use `extra.name` `USDC`. Base offers and mainnet USDC top-ups use `USD Coin`, which is what that USDC contract returns from `name()`. Live mode is `SATSGATE_X402_CDP` (on by default on api.satsgate.org). A self-hosted core stores `sites.x402_mode` as `''`, `test`, or `live`. Turning the switch off does not drop the column.

To enable mainnet, on the core service only (the gate container must not receive these):

```bash
SATSGATE_X402_CDP=1
SATSGATE_X402_CDP_KEY_ID=organizations/.../apiKeys/...
SATSGATE_X402_CDP_KEY_SECRET=...   # CDP Secret API key, the base64 value shown once
```

Leave `SATSGATE_X402_NETWORK` at `eip155:84532`. That variable is the public facilitator network. Setting it to `eip155:8453` still refuses to boot. Restart core. A missing or unusable credential logs `USDC mainnet disabled` and does not print the value. Sepolia and Lightning still start.

Rollback: set `SATSGATE_X402_CDP=0` and restart core. Live sites stop offering USDC. If Lightning is also on, the 402 is Lightning only. If x402 is the only rail, the challenge is `400 x402_mainnet_disabled`. Test mode and Lightning keep working. USDC top-up follows the mode that is still enabled. The column stays.

A site chooses one mode with the account key (not an `sgr_` key):

```bash
curl -s -X PATCH https://api.satsgate.org/v1/sites/SLUG \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...' \
  -d '{"rail_x402":true}'
```

That stores `test` when the mode was unset. Then, after the switch is on:

```bash
curl -s -X PATCH https://api.satsgate.org/v1/sites/SLUG \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...' \
  -d '{"x402_mode":"live"}'
```

Try on Base Sepolia with your agent first, then switch the site to live. The self-hosted proxy sets `x402_mode: test` or `x402_mode: live` on the route. `x402: true` without a mode means test.

USDC top-ups (`POST /v1/topup/usdc`) are mainnet-only while the switch is on, and Sepolia-only while it is off. Prepaid balance is not sold for faucet USDC once real USDC is on. A merchant route can stay in test mode while top-ups are on mainnet.

Watch the facilitator without printing a secret. The unauthenticated `/v1` limit is 60 requests a minute per IP, and the handler caches the CDP check for 60 seconds, so call it at most once a minute:

```bash
curl -fsS -H "X-Admin-Token: $SATSGATE_ADMIN_TOKEN" https://api.satsgate.org/v1/admin/x402
```

Alert only when `mainnet_enabled` is true and `cdp.supported_ok` is not true. Port 8000 is not published. Caddy fronts 80 and 443. The body is not on `/health` and not in the manifest.

An x402 ledger debit records `api_key_id` when settle was called with a restricted `sgr_` key. The hosted gate uses `GATE_TOKEN`, so those debits stay null. The proxy logs `key fp` and a 12-character SHA-256 fingerprint of the API key at startup. It does not log a prefix of the key.

The gate resource string is `gate:<slug>:<path>` and must be at most 200 characters, which is the paywall resource limit. A longer route is stored and is not served.

### USDC top-up

`POST /v1/topup/lightning` sells any amount of sats. `POST /v1/topup/usdc` sells a free USDC amount, paid to Satsgate, minimum US$1. The account key (`sg_...`) is required. A restricted `sgr_` key is rejected. The prepaid balance is closed-loop: it is not transferable and it is not redeemable for sats or USDC.

The credited millisatoshis are the USDC amount converted at the accounting rate and locked on the offer, then the per-top-up bonus. A missing or stale accounting rate is `503 rate_unavailable` on this route only. Lightning top-up still works.

No `PAYMENT-SIGNATURE` yet: `402` and the header `PAYMENT-REQUIRED` (x402 v2, scheme `exact`, `payTo` the treasury). Live mode uses Base (`eip155:8453`). Test mode uses Base Sepolia (`eip155:84532`). The body repeats `x402.amount`, `x402.payTo`, and `x402.network`. The header is canonical. `maxTimeoutSeconds` is `SATSGATE_X402_OFFER_SECONDS` clamped into 60–300 seconds (the default is 60).

With `PAYMENT-SIGNATURE`: core checks payTo, amount, asset, and network against the stored offer, then `POST /verify` and `POST /settle` on the facilitator. The prepaid service balance is credited only after settle returns a transaction. The response includes `PAYMENT-RESPONSE` with `success`, `transaction`, `network`, and `payer`. `tx` repeats `transaction`. One EIP-3009 nonce grants the top-up once. A replay is `409 x402_replay`. A second request still in flight is `409 x402_in_progress`. The ledger row has reason `topup_x402`, the tx hash in `ref`, plus `network` and `amount_usd_atomic`.

If `SATSGATE_TREASURY_EVM_ADDRESS` is unset, empty, or not a 20-byte address, this route answers `400 x402_topup_disabled` and Lightning top-up is unchanged. The process still boots. The SDK method is `topup_usdc`. `scripts/x402_topup_example.py` is retired.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SATSGATE_TREASURY_EVM_ADDRESS` | unset | Satsgate's own Base payTo for USDC top-ups. Unset or invalid turns this rail off. Not used for merchant route payments. |

Startup adds columns. It does not add a table. Copy `satsgate.sqlite3` before restart if you want a rollback point. Restart the core image. The gate does not change. Leave the facilitator at `https://x402.org/facilitator`. Do not run a Satsgate facilitator.

## No-code proxy

`satsgate-proxy` (version 0.15.1, in [`proxy/`](../proxy/README.md)) sits in front of an HTTP API you already run. The default `mode: paywall` is unchanged: buyers talk to the proxy, the proxy calls this core with a restricted `sgr_` key, and the origin checks an HMAC. `mode: receipt` does not call core and does not need an `sgr_` key. The buyer pays the hosted gate, then calls the proxy with `Satsgate-Receipt`. The proxy checks the receipt and forwards a 2xx to the origin with the same HMAC.

An unpaid request is **402** with `WWW-Authenticate: L402 macaroon="...", invoice="..."` (macaroon before invoice, standard base64), which lnget and Alby `fetch402` already parse. The JSON body carries `amount_sats`, `payment_hash`, `invoice_expires_at`, and a hint for wallets that do not return a preimage. A route with `x402: true` adds `PAYMENT-REQUIRED` on that same 402. `Authorization: L402 <macaroon>:<preimage>` confirms the payment. `Authorization: L402 <macaroon>` polls status. The unlock fee is debited after the origin returns 2xx. Pending stays on that invoice (`402 payment_pending`, `Retry-After`). A used, expired, or wrong-route token is a fresh 402, not 401.

The self-hosted proxy is 0.15.1. `GET /healthz` on the proxy reports `0.15.1`. Core health is `0.20.5`. In `mode: paywall` the proxy confirms payment, calls the origin, and debits only after a 2xx, on Lightning and on x402. A failed origin reports no debit. The same `PAYMENT-SIGNATURE` can be retried after that failure. Set `x402: true` on a route, and `server.public_base` to the URL buyers pay, to offer USDC as well. `x402: true` without `x402_mode` is test (Base Sepolia). `x402_mode: live` is Base (on by default on api.satsgate.org; a self-hosted core needs `SATSGATE_X402_CDP=1`, see [self-hosting](self-hosting.md)). Try on Base Sepolia with your agent first, then switch the site to live. Startup logs `key fp` and a SHA-256 fingerprint of the restricted key, not any part of the key. An x402 settle through this proxy records that key's id on the ledger debit. The proxy does not sell prepaid balance. Top up on the core, with Lightning or with `POST /v1/topup/usdc`.

Config is YAML: upstream base URL, routes (`per_request`, `uses:N`, `pass:<seconds>`, scope `route` or `site`), free paths, body limits, and an origin secret from the environment. `pricing.sats_per_credit` in an old file is ignored. Cheap calls should be bundles or passes.

The proxy sends `X-Satsgate-Buyer-Ip` when it has a real buyer address. Hosted `https://api.satsgate.org` uses that header only if the proxy's egress IP is in `SATSGATE_TRUSTED_PROXIES` and the edge does not strip it. Otherwise per-buyer limits do not apply and the per-client caps still do.

The proxy signs `X-Satsgate-Signature: t=<unix>, v1=<hmac-sha256>` over `{unix}|{METHOD}|{raw path and query}|{payment_hash}` on the request to the origin. Snippets for FastAPI, Express, nginx, and a Caddy network gate are in `proxy/snippets/`. The unlock fee and the use are taken only after that response is 2xx. For USDC, settle runs after that 2xx. If the origin fails, nothing is taken, and the buyer retries the same macaroon or signature. Lightning sats already reached the merchant when the invoice was paid. Any remedy for that failed origin is between the buyer and the merchant. Satsgate does not refund buyers.

```bash
export SATSGATE_API_KEY='sgr_...'
export SATSGATE_ORIGIN_SECRET="$(openssl rand -hex 32)"
see CONTRIBUTING.md to build the proxy from a checkout
```

Full steps, the signature, and a mainnet checklist are in [`proxy/README.md`](../proxy/README.md).

## Buyer MCP

`satsgate-mcp` (version 0.14.1, in [`mcp/`](https://github.com/Mike-io-hash/satsgate/blob/main/mcp/README.md)) is a separate process an agent runs over stdio. Works with core 0.20.3 or later. It is a client. It does not change the core.

`discover` and `quote` request a URL and read the 402. Lightning still returns the price in sats, `max_uses`, `access_seconds`, and expiry. An x402 offer adds the `PAYMENT-REQUIRED` accepts: network, asset, atomic amount, human USDC, `payTo`, resource, scheme, and expiry. The amount is whatever the 402 locked. This process does not recompute it. `pay_and_fetch` with mode `human` returns the invoice and a QR when Lightning is offered, including when x402 is on the same 402. With no Lightning wallet connected, a person can pay that invoice from a phone and the agent continues through `check_payment`. Mode `nwc` pays Lightning from `SATSGATE_MCP_NWC_URI` in the environment, never from a tool argument, and only inside `SATSGATE_MCP_MAX_PAYMENT_SATS` and `SATSGATE_MCP_DAILY_MAX_SATS`. USDC uses a separate pair, `SATSGATE_MCP_MAX_PAYMENT_USD` and `SATSGATE_MCP_DAILY_MAX_USD`. Both must be set before a `PAYMENT-SIGNATURE` is forwarded. This process holds no buyer key and does not sign. The agent retries `pay_and_fetch` with `payment_signature` from an external wallet. A token with uses or time left is reused. `token_used_up` comes back as a new quote unless `SATSGATE_MCP_AUTO_PAY` is on and the new invoice is inside the budget.

An optional `sgr_` key enables read-only `challenge_status` and `credits_balance`. The key cannot top up or change the payee. Nothing in the x402 path asks for an account key. `list_sites` reads `GET /v1/sites` on the core URL: approved, listed sites, each with a gate URL and route prices. A USD-only route is included, with `price_currency` and `price_usd_atomic`. Set `SATSGATE_MCP_REGISTRY` to a JSON file or another URL only when that directory should be replaced.

Core health is `0.20.5`. `GET /health` reports `0.20.5`. The MCP package is 0.14.1. Works with core 0.20.3 or later and gate 0.15.2 or later. It still cannot top up. Buying prepaid balance with USDC is `POST /v1/topup/usdc` on the core with the account key, not an MCP tool. While `SATSGATE_X402_CDP` is on, that top-up is Base mainnet USDC only. While it is off, it stays on Base Sepolia.

```bash
pip install satsgate-mcp
satsgate-mcp-pay https://your-proxy.example/blog/post
```

That command shows a QR and polls. It does not set a wallet. NWC and the mainnet lnget / fetch402 steps are in [`mcp/README.md`](../mcp/README.md).

## Pay from any wallet, then poll

When the payee's LNURL provider returns a LUD-21 `verify` URL (Alby does):

1. `POST /v1/topup/lightning` with `{"sats": 1000}` and read `invoice`, `macaroon`, and `payment_hash` from the 402.
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
- `POST /v1/topup/lightning` with `{"sats": 1000}` (top up prepaid balance via Lightning)
- `node client_paywall_credit_demo.mjs <resource> <amount_sats>` (challenge + pay + verify; spends 1 payment verification)

## SDK (Python)

- `sdk/python` (package `satsgate-sdk`)
  - install locally: `pip install satsgate-sdk`
  - FastAPI examples:
    - Minimal: `sdk/python/examples/fastapi_demo/main.py`
    - Reference integration: `sdk/python/examples/fastapi_reference/`

