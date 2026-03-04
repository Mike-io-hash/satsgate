# satsgate (MVP)

`satsgate` is a Python (FastAPI) service that provides:

- **L402 paywall primitives** (invoice + macaroon + preimage verification)
- **Prepaid credits** (plans) for charging *your customers* (agent operators) per successful verification
- **Usage & reporting** (ledger, daily series, forecast + purchase recommendation)

It is designed to be a lightweight “cashier/turnstile” (no LLM in the hot path).

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
  - FastAPI client example: `sdk/python/examples/fastapi_demo/main.py`

## Quickstart

```bash
# from the repo root
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env

uvicorn app.main:app --reload --port 8000
```

Mock mode demo (in another terminal):

```bash
# 1) Request a ticket (no auth) => 402 + invoice + macaroon
curl -i http://127.0.0.1:8000/v1/tickets

# 2) DEV: simulate payment and get preimage
curl -s http://127.0.0.1:8000/dev/mock/pay/<PAYMENT_HASH>

# 3) Retry with Authorization: L402
curl -s \
  -H 'Authorization: L402 <MACAROON>:<PREIMAGE_HEX>' \
  http://127.0.0.1:8000/v1/tickets
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
