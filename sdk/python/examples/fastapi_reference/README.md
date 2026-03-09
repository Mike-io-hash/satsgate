# FastAPI reference integration (customer)

This example shows a more complete paywall integration pattern for satsgate customers.

What it demonstrates:
- Proper HTTP 402 + `WWW-Authenticate` L402 challenge when Authorization is missing
- L402 verification + prepaid credit spending via satsgate
- In-memory caching (SDK) to avoid repeated `/verify` calls for the same payment/session

## Setup

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate

# SDK
pip install -e sdk/python

# only needed to run this FastAPI example
pip install fastapi uvicorn[standard]

# for the optional NWC payer script (Node.js)
npm install

# for the optional Python payer script
pip install httpx
# + one of the payment backends (see below)
```

Set env vars:

```bash
export SATSGATE_BASE_URL=https://api.satsgate.org
export SATSGATE_API_KEY=sg_...YOUR_API_KEY...

export PAYWALL_RESOURCE=example/premium
export PAYWALL_AMOUNT_SATS=10
export PAYWALL_MEMO="Premium access"
```

## One-time: configure your payee

Before this example can create Lightning invoices, your satsgate customer account must have a payee set.

```bash
curl -s -X POST https://api.satsgate.org/v1/client/payee \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...YOUR_API_KEY...' \
  -d '{"payee_lightning_address":"yourname@yourdomain.com"}'
```

If the payee is not set, this example will return HTTP 503 with `paywall_not_configured`.

## Run the customer service

```bash
cd sdk/python/examples/fastapi_reference
uvicorn main:app --reload --port 9000
```

## Test (manual)

```bash
curl -i http://127.0.0.1:9000/premium
```

You should get `402 Payment Required` with an invoice + macaroon.

## Test (automated — Node.js payer)

```bash
cd sdk/python/examples/fastapi_reference
TEST_PAYER_NWC='nostr+walletconnect://...' node payer_nwc.mjs http://127.0.0.1:9000/premium
```

Optional: repeat the authorized call to see cache behavior:

```bash
REPEAT=2 TEST_PAYER_NWC='nostr+walletconnect://...' node payer_nwc.mjs http://127.0.0.1:9000/premium
```

## Test (automated — Python payer)

`payer_nwc.py` is a drop-in Python alternative to the Node.js payer above —
useful for AI agents and Python-based backends that want to test the full L402
flow without Node.js.

### Payment backends

| Backend | How it pays | Extra deps |
|---------|------------|------------|
| `nwc` (default) | Nostr Wallet Connect ([NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md)) | `pip install nostr-sdk` |
| `alby` | Alby CLI (`npx @getalby/cli pay-invoice`) | Node.js + `npm install -g @getalby/cli` |
| `mock` | Calls `/dev/mock/pay/<hash>` on the satsgate server | None (local dev only) |

### Usage

```bash
cd sdk/python/examples/fastapi_reference

# NWC backend (default):
TEST_PAYER_NWC='nostr+walletconnect://...' python payer_nwc.py http://127.0.0.1:9000/premium

# Alby CLI backend:
PAYMENT_BACKEND=alby python payer_nwc.py http://127.0.0.1:9000/premium

# Mock backend (local dev only):
PAYMENT_BACKEND=mock SATSGATE_BASE_URL=http://127.0.0.1:8000 \
    python payer_nwc.py http://127.0.0.1:9000/premium
```

### Optional: spending cap

Set `MAX_SATS` to abort before paying if the invoice exceeds a threshold — useful
for autonomous agents that need a spending limit:

```bash
MAX_SATS=100 TEST_PAYER_NWC='nostr+walletconnect://...' python payer_nwc.py http://127.0.0.1:9000/premium
```
