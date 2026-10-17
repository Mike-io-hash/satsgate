# satsgate

[![CI](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml)

`satsgate` lets you **charge sats** for AI agents, APIs, and web apps in minutes — without building a payment stack.

Add a Lightning paywall to any endpoint with two calls: `/v1/paywall/challenge` (return 402) and `/v1/paywall/verify`.

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

`GET /health` returns `{"ok": true, "version": "0.4.0"}` and nothing else.

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

Reporting:

- `GET /v1/ledger` with `X-Api-Key: ...` → verification ledger entries (credits)
- `GET /v1/usage/summary?since_hours=24` with `X-Api-Key: ...` → usage summary
- `GET /v1/usage/daily?days=30` with `X-Api-Key: ...` → daily series (UTC)
- `GET /v1/usage/forecast?lookback_hours=24&buffer_days=7&max_topups=3&trigger_hours=24` with `X-Api-Key: ...`
  - forecast + recommended purchase + “when to top up” trigger

## Paywall (for your customers)

These are the endpoints your **customers** (agent operators) integrate:

- `POST /v1/paywall/challenge` with `X-Api-Key: ...` → returns `invoice + macaroon` for a resource
- `POST /v1/paywall/verify` with `X-Api-Key: ...` + `Authorization: L402 ...` and **`expected_resource` (required)**
  - verifies the preimage, or the stored LUD-21 URL when the header is `L402 <macaroon>` with no preimage
  - checks that the token was issued to **this** API key, for **this** resource, amount, payee, and invoice
  - charges payment verifications (credits) once per `payment_hash` (`cost_credits`, default 1, is the merchant's own debit)
- `GET /v1/paywall/status/{payment_hash}` with the same API key and macaroon → poll that check

Tokens are version 2 (`token_version` on the challenge). A token minted for one client never verifies for another. v1 tokens are rejected. See the 0.4.0 notes in [`CHANGELOG.md`](./CHANGELOG.md).

## Pay from any wallet, then poll

When the payee's LNURL provider returns a LUD-21 `verify` URL (Alby does):

1. `GET /v1/topup/trial` and read `invoice`, `macaroon`, and `payment_hash` from the 402.
2. Pay that invoice in any Lightning wallet. You do not need the preimage.
3. Poll `GET /v1/topup/status/{payment_hash}` with `Authorization: L402 <macaroon>` until `settled` is true.
4. Save `api_key` from that response. A later poll succeeds but does not show the key again.

The Python SDK helpers are `SatsgateClient.poll_topup` and `SatsgateClient.poll_paywall`. If the provider did not send `verify`, the status call returns `preimage_required` and the `L402 <macaroon>:<preimage>` flow is still the way to finish.

## L402 client compatibility

Challenges use `WWW-Authenticate: L402 macaroon="<standard base64>", invoice="<bolt11>"`. `Authorization` accepts `L402` and the legacy `LSAT` prefix, in the form `<macaroon>:<64-hex-preimage>`.

| Client | What it does with the challenge | Status |
| --- | --- | --- |
| lnget (Lightning Labs) | Parses the header, unmarshals a real macaroon, reads the payment hash from the L402 v0 identifier, pays, retries with `L402 <macaroon>:<preimage>` | Works. The macaroon is libmacaroons V2, standard base64 (Aperture's credential grammar is `[A-Za-z0-9+/=]+`, not url-safe). |
| Alby `fetch402` (`@getalby/lightning-tools`) | Treats the macaroon as an opaque string, pays, retries with `L402 <token>:<preimage>` | Works. The macaroon is re-rolled if its base64 would contain the substrings `L402` or `LSAT`, which that parser strips from the whole header. |
| Aperture as a verifying proxy | Expects its own service and capability caveats | Does not accept satsgate tokens. Our caveats are the v2 bindings (`v`, `kid`, `purpose`, `cid`, `ph`, `res`, `amt`, `payee_h`, `inv_h`, `exp`), not Aperture's. |

Tokens issued before 0.4.0 were signed JSON in url-safe base64. This server still verifies those until they expire. lnget cannot unmarshal them.

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
