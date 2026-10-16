# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
