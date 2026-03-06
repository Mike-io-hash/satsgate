# satsgate

[![CI](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Mike-io-hash/satsgate/actions/workflows/ci.yml)

`satsgate` lets you **charge sats** for AI agents, APIs, and web apps in minutes — without building a payment stack.

Add a Lightning paywall to any endpoint with two calls: `/v1/paywall/challenge` (return 402) and `/v1/paywall/verify`.

It’s a hosted + self-hostable FastAPI service that gives you:

- **L402 paywall primitives** (invoice + macaroon + preimage verification)
- **Prepaid credits** (plans) for predictable costs (**1 credit = 1 successful verification**)
- **Usage & reporting** (ledger, daily series, forecast + purchase recommendation)
- **Roadmap (active)**: new wallet backends, integrations, and production hardening

Your users pay **your** Lightning Address (LNURL-pay). You don’t need to run a node or manage webhooks.

Hosted beta: https://api.satsgate.org (start in [`CUSTOMER_QUICKSTART.md`](./CUSTOMER_QUICKSTART.md)).

No LLM in the hot path: satsgate is a lightweight “cashier/turnstile” that sits in front of your agent.

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

## Prepaid credits

Endpoints:

- `GET /v1/plans` → list plans
- `GET /v1/topup/{plan_id}` → start purchase (returns 402 + invoice + macaroon)
- `GET /v1/topup/{plan_id}` with `Authorization: L402 ...` → finalize purchase, credit balance
- `GET /v1/balance` with `X-Api-Key: ...` → current credit balance
- `GET /v1/client` with `X-Api-Key: ...` → client info (incl. payee)
- `POST /v1/client/payee` with `X-Api-Key: ...` → register client payee (Lightning Address)

Reporting:

- `GET /v1/ledger` with `X-Api-Key: ...` → credit ledger entries
- `GET /v1/usage/summary?since_hours=24` with `X-Api-Key: ...` → usage summary
- `GET /v1/usage/daily?days=30` with `X-Api-Key: ...` → daily series (UTC)
- `GET /v1/usage/forecast?lookback_hours=24&buffer_days=7&max_topups=3&trigger_hours=24` with `X-Api-Key: ...`
  - forecast + recommended purchase + “when to top up” trigger

## Paywall (for your customers)

These are the endpoints your **customers** (agent operators) integrate:

- `POST /v1/paywall/challenge` with `X-Api-Key: ...` → returns `invoice + macaroon` for a resource
- `POST /v1/paywall/verify` with `X-Api-Key: ...` + `Authorization: L402 ...`
  - verifies the preimage
  - charges **1 credit** (only once per `payment_hash`)

## Scripts

- `python client_mock_demo.py` (mock L402 demo)
- `node client_nwc_demo.mjs` (pays `/v1/tickets` using NWC)
- `node client_topup_nwc.mjs trial|starter|growth|scale|hyper|mega` (buy credits via NWC)
- `node client_paywall_credit_demo.mjs <resource> <amount_sats>` (challenge + pay + verify)

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

cp .env.example .env

uvicorn app.main:app --reload --port 8000
```

## Docker (recommended for deployment)

This repo includes a minimal Docker setup with **Caddy** (TLS) and a persistent SQLite volume.

1) Copy env file:

```bash
cp .env.example .env
```

2) Edit `.env` and set at least:

- `SATSGATE_HOSTNAME=api.yourdomain.com`
- `SATSGATE_MACAROON_SECRET=...` (use a long random value)
- `SATSGATE_WALLET_MODE=lnaddr`
- `SATSGATE_LIGHTNING_ADDRESS=user@domain`
- `SATSGATE_DEV_MODE=0`

3) Start:

```bash
docker compose up -d --build
```

Notes:
- Your DNS must point `SATSGATE_HOSTNAME` to your server IP.
- Ports **80** and **443** must be open for Caddy/Let’s Encrypt.
