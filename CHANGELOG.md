# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
