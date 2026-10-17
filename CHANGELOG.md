# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-10-17

### Added
- `X-Satsgate-Buyer-Ip` on `POST /v1/paywall/challenge`. A trusted proxy (the TCP peer is in `SATSGATE_TRUSTED_PROXIES`, the same rule as `X-Forwarded-For`) can name the end buyer. Any other peer can send the header and it is ignored, so existing callers are unchanged. The response says `buyer_ip_accepted`.
- Per-buyer limits inside one client: `SATSGATE_BUYER_CHALLENGE_MAX` (default 10 per `SATSGATE_RL_WINDOW_SECONDS`) and `SATSGATE_BUYER_MAX_OPEN_CHALLENGES` (default 5 unpaid challenges still inside the claim window). `0` disables that limit. HTTP 429 `buyer_rate_limited` or `too_many_open_challenges_for_buyer`, with `Retry-After`. The account cap remains `too_many_open_challenges` and now also sends `Retry-After`.
- `SATSGATE_BUYER_LIMIT_SCOPE=client` (default) shares a buyer's budget across the account's keys. `key` gives each restricted key its own budget. The account key is its own bucket in that mode.
- `SATSGATE_CHALLENGE_REUSE_SECONDS` (default 30, `0` disables). An identical unpaid challenge for the same buyer, resource, amount, usage policy, payee, and key returns the same invoice (`reused: true`) instead of minting another one. The macaroon is signed again for that invoice. Retries do not call the LNURL provider.
- Python SDK `0.6.0`: `paywall_challenge(..., buyer_ip=)`.

### Security
- The buyer address is not stored. The challenge row keeps HMAC-SHA256 of the truncated address (IPv4 /24, IPv6 /64), keyed by the macaroon secret. The digest is removed with the row, on the existing challenge cleanup. A /24 or /64 shares one bucket.
- The header cannot move a buyer into a bucket unless the connection comes from a configured trusted proxy. The shipped Caddyfile deletes `X-Satsgate-Buyer-Ip` on public requests, because Caddy is that trusted peer. Forward the header only from the paywall proxy.

### Changed
- `GET /health` reports `0.7.0`.
- Caps are checked before the LNURL call, and again in the insert transaction, so a buyer at the limit does not ask the payee's provider for an invoice. Two concurrent inserts cannot both take the last unpaid slot.

### Migration
Restart the process to serve 0.7.0. Startup adds nullable `paywall_challenges.buyer_ip_hash` and an index on `(client_id, buyer_ip_hash, created_at)`. Existing rows stay unlimited. Copy the SQLite file first if you want a rollback point. No environment variable is required. Leave the new settings unset to keep the defaults above.

## [0.6.0] - 2026-10-17

### Added
- Per-challenge usage policy. `POST /v1/paywall/challenge` accepts optional `max_uses` (1 to 100000) and `access_seconds` (1 to the server cap). Omit both and the payment behaves as before: a settled token can be verified again without consuming a unit.
- `consume=true` on `POST /v1/paywall/verify` and `GET /v1/paywall/status/{payment_hash}` atomically takes one use and returns `uses_remaining`, `uses_consumed`, `access_until`, `settled_at`, and `consumed`. The check is one SQLite transaction, so two callers cannot both take the last use. Omit `consume` to read that state without changing it. Each `consume=true` is one use, including a retry after a lost response.
- `access_seconds` starts at the first settled unlock. A `max_uses` bundle that omits `access_seconds` still ends at the server cap (default 7 days) and that deadline is stored in `access_until`. Responses name it so a proxy can see when the grant dies.
- Exhausted and expired consumes return HTTP 401 `token_used_up` or `token_expired`, with `uses_remaining` and `access_until`, so the client can mint a new challenge. A non-consuming check of that same payment still returns HTTP 200.
- Python SDK `0.5.0`: `paywall_challenge(..., max_uses=, access_seconds=)`, `paywall_verify(..., consume=)`, `poll_paywall(..., consume=)`. A policy grant is not stored in the SDK cache.

### Changed
- Credits are still charged once per `payment_hash`, on the first settled unlock, including when that call also consumes a use. Later uses and the 401s above charge 0.
- `GET /health` reports `0.6.0`.
- Optional `SATSGATE_PAYWALL_ACCESS_CAP_SECONDS` (default `604800`, minimum `60`, maximum `604800`) shortens the longest pass. Leave it unset to keep 7 days.

### Security
- A settled macaroon is no longer an unlimited replay for the whole claim window when the merchant set a policy. The counter and `access_until` live in SQLite, shared by every replica that uses that database file. Writers wait up to 30 seconds for the lock.
- Restricted keys can create these challenges and consume uses. `resource_prefix` still applies. A restricted key still cannot change the payee or top up.

### Migration
Restart the process to serve 0.6.0. Startup adds nullable `paywall_challenges.max_uses`, `access_seconds`, `settled_at`, and `access_until`, plus `uses_consumed` (default 0). Existing rows stay unlimited. Copy the SQLite file first if you want a rollback point. No environment variable is required.

## [0.5.0] - 2026-10-17

### Added
- Restricted API keys. The account key (`sg_...`, from top-up) can `POST /v1/api-keys`, `GET /v1/api-keys`, and `POST /v1/api-keys/{key_id}/revoke`. A new key is returned once, stored as a SHA-256 hash, and starts with `sgr_` so it is distinguishable from the account key. Each key has a label, `created_at`, `last_used_at` (updated at most once a minute), and `revoked_at`.
- An optional `resource_prefix` limits that key to paywall resources that start with the prefix (case-sensitive). Omit it to allow every resource. Up to 50 active restricted keys per client.
- A restricted key can `POST /v1/paywall/challenge`, `GET /v1/paywall/status/{payment_hash}`, and `POST /v1/paywall/verify`. It cannot top up, set or change the payee (including on the first challenge), create or revoke keys, or read balance, client, ledger, or usage.
- Paywall debits record `api_key_id` and `resource`. `GET /v1/ledger` adds `api_key_id`, `api_key_label`, `api_key_prefix`, and `resource`. Null `api_key_id` means the account key. `GET /v1/usage/summary` adds `summary.by_api_key`.
- Python SDK `0.4.0`: `create_api_key`, `list_api_keys`, `revoke_api_key`.

### Security
- A leaked restricted key cannot redirect payouts or mint another key. Revocation is checked on every request (`api_key_revoked`). Forbidden account calls return HTTP 403 `insufficient_scope`. A resource outside the prefix returns HTTP 403 `resource_not_allowed`.
- The account key is unchanged. Existing `sg_` keys keep full access. Unknown account keys on top-up stay anonymous, as before. A presented `sgr_` key is never treated as anonymous.

### Migration
No new environment variables. Restart the process to serve 0.5.0. Startup adds the `api_keys` table and nullable `ledger.api_key_id`, `ledger.resource`, and `paywall_challenges.api_key_id` columns. Existing rows are left in place. Copy the SQLite file first if you want a rollback point. Nothing else has to be configured.

## [0.4.2] - 2026-10-17

### Fixed
- A paywall macaroon no longer expires at `SATSGATE_TOKEN_TTL_SECONDS` (default 10 minutes) while the payee's Lightning invoice is still payable. Paying an Alby invoice hours later, then `GET /v1/paywall/status/{payment_hash}` or `POST /v1/paywall/verify`, unlocks the challenge. The macaroon `exp` is the invoice expiry plus a grace window (default 1 hour), and never later than 48 hours after the challenge was created. This is the same claim window top-ups got in 0.4.1.
- A paywall token already issued with that 10-minute `exp` can still unlock while the invoice window is open. Rows written before 0.4.2 stored the token TTL in `expires_at`; the BOLT11 expiry is used when it is later. Signature, client, resource, amount, payee, and invoice bindings are unchanged. A first unlock still requires a preimage or a stored LUD-21 `verify` response that carries a matching preimage. After the window the route returns `invoice expired` and does not spend a credit, including when the macaroon `exp` has not passed and including when the provider would report the invoice settled.

### Added
- Challenge responses add `invoice_expires_at`, `claim_until`, `cache_until`, `payee_saved`, and `payee_note`. `valid_until` stays and, for a new token, equals `claim_until` (the macaroon expiry). `cache_until` is how long to cache a successful unlock. How long the buyer may use the product is the merchant's decision.
- Unlock responses add `claim_until`, `invoice_expires_at`, and `cache_until`. `valid_until` stays the macaroon `exp` caveat, which can be earlier than `claim_until` for a token minted before this release.
- The first challenge that includes `payee_lightning_address` still saves it. The response now says so (`payee_saved: true`, `payee_note`). A later different address returns `payee_mismatch` with the saved address and `POST /v1/client/payee` as the way to change it.
- `resource mismatch` includes `detail`, the caller's `expected_resource`, and, after the macaroon is verified for this API key, the issued `resource`. Another client's token still returns `client mismatch` without that resource.
- Pending unlocks name the charge: `charged_credits: 0` until settlement. Verify's HTTP 402 `payment_pending` body also includes `status: pending`. Status stays HTTP 200 `pending`. Both notes describe the other route. Settled responses keep `charged_credits` and state that verify and status share one debit per `payment_hash`.
- Python SDK `0.3.1` reads the new fields and caches until `cache_until`.

### Changed
- `ttl_seconds` on `POST /v1/paywall/challenge` is the minimum invoice lifetime. It no longer shortens the macaroon below the invoice claim window.
- `GET /health` reports `0.4.2`.
- Optional `SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS` (default `172800`, max `604800`) and `SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS` (default `3600`, max `86400`). The grace cannot exceed the cap. Neither is required. Dev-ticket macaroons still use `SATSGATE_TOKEN_TTL_SECONDS`.

### Security
- Credits are still not spent without a preimage or a stored LUD-21 `verify` response that carries a matching preimage. The claim cap and the grace window bound how long a macaroon can unlock a payment. A replay after the first debit spends 0.

## [0.4.1] - 2026-10-17

### Fixed
- A top-up macaroon no longer expires at `SATSGATE_TOKEN_TTL_SECONDS` (default 10 minutes) while the Lightning invoice is still payable. Paying an Alby invoice hours later, then `GET /v1/topup/status/{payment_hash}` or `GET /v1/topup/{plan_id}` with the preimage, credits the account. The macaroon `exp` is the invoice `expires_at` the service already stores, plus a grace window (default 1 hour) so a payment made near expiry can still be polled, and never later than 48 hours after the row was created.
- A top-up token already issued with that 10-minute `exp` (0.4.0 macaroon or in-flight 0.3.0 JSON) can still complete while the ledger row is pending and that server-side window is open. The macaroon signature, the invoice/amount/payee bindings, and proof of payment are unchanged.

### Security
- Credits are still not issued without a preimage or a stored LUD-21 `verify` response that carries a matching preimage. After `expires_at` plus the grace window, or after the cap, the claim returns `invoice expired` and does not credit, including when the macaroon's own `exp` has not passed and including when the provider would report the invoice settled.
- Paywall and dev-ticket macaroons keep `SATSGATE_TOKEN_TTL_SECONDS` (or the paywall request's `ttl_seconds`). An expired paywall token still returns `token expired`.

### Changed
- `GET /health` reports `0.4.1`.
- Optional `SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS` (default `172800`, max `604800`) and `SATSGATE_TOPUP_CLAIM_GRACE_SECONDS` (default `3600`, max `86400`). The grace cannot exceed the cap. Neither is required.

## [0.4.0] - 2026-10-17

### Added
- Top-ups, paywall unlocks, and dev-only tickets can finish without a preimage when the LNURL-pay provider returned a LUD-21 `verify` URL (Alby does). Poll `GET /v1/topup/status/{payment_hash}` or `GET /v1/paywall/status/{payment_hash}` with `Authorization: L402 <macaroon>` and no preimage. The same macaroon-only header is accepted on `GET /v1/topup/{plan_id}`, `POST /v1/paywall/verify`, and `GET /v1/tickets`.
- The new account's API key is returned only by the request that creates it. A replay is idempotent: it does not credit again and does not show the key. The macaroon (not the payment hash) is the claim.
- Python SDK `0.3.0`: `poll_topup` and `poll_paywall` for that pay-from-any-wallet flow.
- New tokens are libmacaroons V2 macaroons, standard base64, with an L402 v0 identifier (so lnget can read the payment hash) and caveats for the existing v2 bindings. `Authorization` accepts `L402` and legacy `LSAT`.

### Changed
- In production, `/openapi.json` and `/docs` omit `/v1/admin/*`, `/v1/tickets`, `/v1/spend`, and `/dev/mock/pay`. Those routes still behave as before.
- `GET /health` reports `0.4.0`.

### Fixed
- `GET` and `HEAD` for `/health` and `/.well-known/satsgate.json` no longer share one OpenAPI operation id.
- LNURL-pay invoice requests no longer send a LUD-12 `comment` unless `SATSGATE_LNURL_SEND_COMMENT=1` and the provider advertises `commentAllowed`. Alby puts that comment in the BOLT11 description and omits `description_hash = SHA256(metadata)`, which challenge and top-up routes rejected (`invoice_rejected` / `description_hash_mismatch`). The description-hash check stays strict.
- Docker Compose assigns the app container `172.28.0.3` so it cannot take Caddy's pinned address `172.28.0.2` (`Address already in use`). The app service checks `GET /health`.

### Security
- Auto-confirm reads only the verify URL stored with the invoice, checks it again with the SSRF guard, and credits only when the provider returns a preimage that hashes to that invoice. A caller cannot pass a verify URL. `settled: true` without that preimage does not credit.
- In-flight v2 JSON tokens from 0.3.0 still verify until they expire. v1 tokens stay rejected. Client, resource, amount, payee, and invoice bindings are unchanged.

### Migration
No new environment variables. Restart the process to serve 0.4.0.

Buyers on a provider that advertises LUD-21 `verify` can pay the invoice from any wallet and poll. Wallet of Satoshi does not advertise `verify`; those payments still need `Authorization: L402 <macaroon>:<preimage>`.

HTTP clients that pass the macaroon through unchanged (the Node demos, lnget, Alby `fetch402`) keep working. Code that decodes the old JSON token locally, including satsgate-sdk `0.2.0`, should upgrade to satsgate-sdk `0.3.0`.

## [0.3.0] - 2026-10-16

### Security
- Paywall tokens are now **v2**. The signed payload is `{v, kid, purpose, cid, ph, res, amt, payee_h, inv_h, exp, nonce}`. `/v1/paywall/verify` rejects a token whose `cid` is not the calling client, whose resource does not match, or whose invoice/amount/payee binding does not match the challenge satsgate issued. v1 tokens are rejected.
- `expected_resource` is required on `/v1/paywall/verify` (HTTP 422 when it is omitted).
- BOLT11 invoices from LNURL-pay are checked before a challenge is returned: amount, mainnet (or `SATSGATE_LN_NETWORK`), `description_hash` = SHA256 of the LUD-06 metadata string, expiry covering the token TTL, and a 32-byte payment hash. The decoder also checks the invoice signature.
- LUD-21 `verify` is used as an extra settlement check only when the provider includes it. Wallet of Satoshi does not; those payees stay preimage-only.
- Outbound LNURL fetches are https-only, DNS-checked, and pinned to a public address. Private, loopback, link-local, and CGNAT targets are refused, redirects are not followed, and responses are capped at 5s and 64 KiB.
- The process refuses to start when `SATSGATE_ENV` is production (the default) and the signing secret is empty, `dev-change-me`, or shorter than 32 bytes, or when dev mode or the mock wallet is enabled. `/dev/mock/pay`, `/v1/tickets`, and `/v1/spend` exist only in an explicit local environment with `SATSGATE_DEV_MODE=1`.
- `/health` returns only `{ok, version}`.
- Rate limits use the TCP peer unless that peer is listed in `SATSGATE_TRUSTED_PROXIES`. Unknown API keys share the IP bucket. The in-memory limiter caps how many keys it tracks. Pending top-ups per IP and open challenges per client are capped.
- `bitstring` is pinned to 4.x so `bolt11` can import (`ConstBitStream` was removed in bitstring 5).

### Changed
- Verify responses add `amount_sats` and `payee_lightning_address`. Challenge responses add `token_version`.
- Signing keys can be rotated with `SATSGATE_MACAROON_KEY_ID` and `SATSGATE_MACAROON_PREVIOUS_KEYS` (JSON object of retired kid → secret, verify-only).
- Python SDK `0.2.0`: `paywall_verify` requires `expected_resource` and rejects tokens that are not v2.

### Migration
There are no production clients to migrate. Outstanding v1 tokens stop verifying immediately (they were unbound bearer credentials). Integrators must send `expected_resource` on every verify. Copying the old `.env` with `SATSGATE_MACAROON_SECRET=dev-change-me` or `SATSGATE_DEV_MODE=1` will not boot under the default `SATSGATE_ENV=production`. Local mock:

```bash
SATSGATE_ENV=development SATSGATE_DEV_MODE=1 SATSGATE_WALLET_MODE=mock \
  SATSGATE_MACAROON_SECRET=local-dev-only \
  uvicorn app.main:app --reload --port 8000
```

`cost_credits` is unchanged: the authenticated merchant still chooses how many of their own credits a verification spends (default 1). That value is not part of the cross-tenant bypass.

## [0.2.0] - 2026-03-06

### Added
- L402 paywall endpoints (challenge/verify) with prepaid credits (plans)
- Operator reporting: ledger, usage summary, daily series, forecast + recommended purchase + trigger
- `.well-known/satsgate.json` discovery manifest + OpenAPI
- Docker + Caddy deployment configuration
- Python SDK (`satsgate-sdk`) + FastAPI examples (minimal + reference)
- CI smoke tests (mock mode)
- Trust layer docs: `SECURITY.md`, `SUPPORT.md`, `STATUS.md`, `BETA.md`

### Changed
- Improved onboarding UX in SDK examples (handle missing payee without returning 500)

### Security
- SSH hardening and access guidance documented (operator runbook is private)
