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
pip install -e sdk/python

# for the optional NWC payer script
npm install
```

Set env vars:

```bash
export SATSGATE_BASE_URL=https://api.satsgate.org
export SATSGATE_API_KEY=sg_...YOUR_API_KEY...

export PAYWALL_RESOURCE=example/premium
export PAYWALL_AMOUNT_SATS=10
export PAYWALL_MEMO="Premium access"
```

Run the customer service:

```bash
cd sdk/python/examples/fastapi_reference
uvicorn main:app --reload --port 9000
```

## Test (manual)

```bash
curl -i http://127.0.0.1:9000/premium
```

You should get `402 Payment Required` with an invoice + macaroon.

## Test (automated with NWC)

```bash
cd sdk/python/examples/fastapi_reference
TEST_PAYER_NWC='nostr+walletconnect://...' node payer_nwc.mjs http://127.0.0.1:9000/premium
```

Optional: repeat the authorized call to see cache behavior:

```bash
REPEAT=2 TEST_PAYER_NWC='nostr+walletconnect://...' node payer_nwc.mjs http://127.0.0.1:9000/premium
```
