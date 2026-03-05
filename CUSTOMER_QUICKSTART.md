# Customer Quickstart (hosted)

This is the fastest path to integrate **satsgate** as a *customer* (agent operator).

Hosted API:

- `https://api.satsgate.org`
- Manifest: `https://api.satsgate.org/.well-known/satsgate.json`
- OpenAPI: `https://api.satsgate.org/openapi.json`

## Prerequisites

- Node.js **18+**
- An **NWC-enabled** Lightning wallet to pay top-ups (e.g. CoinOS, Alby, Blink, etc.)
  - You will need a `nostr+walletconnect://...` connection string
  - Treat it like a password (do not paste it in chats or commit it)

## 1) Get an API key (buy credits)

Clone and install deps:

```bash
git clone https://github.com/Mike-io-hash/satsgate.git
cd satsgate
npm install
```

Buy the `trial` plan (1000 sats → 200 credits):

```bash
SATSGATE_BASE_URL='https://api.satsgate.org' \
SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' \
node client_topup_nwc.mjs trial
```

Save the returned `api_key` (it may only be shown once).

## 2) Register your payee (where your users will pay)

```bash
curl -s -X POST https://api.satsgate.org/v1/client/payee \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...YOUR_API_KEY...' \
  -d '{"payee_lightning_address":"yourname@yourdomain.com"}'
```

## 3) End-to-end test (challenge → pay → verify)

This script:
- requests a paywall challenge
- pays the Lightning invoice via NWC
- verifies the L402 proof
- spends **1 credit**

```bash
SATSGATE_BASE_URL='https://api.satsgate.org' \
SATSGATE_CLIENT_API_KEY='sg_...YOUR_API_KEY...' \
SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' \
node client_paywall_credit_demo.mjs demo/test 1
```

Expected:
- your payee receives **1 sat**
- your credit balance decreases by **1**

## 4) Integrate into your backend (Python)

Install the SDK (from this repo):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e sdk/python
```

If you want to run the included FastAPI examples locally:

```bash
pip install fastapi uvicorn[standard]
```

FastAPI examples:

- Minimal: `sdk/python/examples/fastapi_demo/main.py`
- Reference integration: `sdk/python/examples/fastapi_reference/`

## Usage & automation

- Forecast + recommended purchase + top-up trigger:

```bash
curl -s \
  -H 'X-Api-Key: sg_...YOUR_API_KEY...' \
  'https://api.satsgate.org/v1/usage/forecast?lookback_hours=24&buffer_days=7&max_topups=3&trigger_hours=24'
```
