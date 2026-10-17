# Customer Quickstart (hosted)

This is the fastest path to integrate **satsgate** as a *customer* (agent operator).

Notes:
- **Non-custodial:** your users pay **your** Lightning Address (LNURL-pay). satsgate never holds your funds.
- **No end-user accounts / no KYC** (via satsgate).
- Hosted pricing is prepaid **payment verifications** (called `credits` in the API). **They do not expire.**
- The small minimum top-up is there for **anti-abuse** on the hosted API.

Hosted API:

- `https://api.satsgate.org`
- Manifest: `https://api.satsgate.org/.well-known/satsgate.json`
- OpenAPI: `https://api.satsgate.org/openapi.json`

## Prerequisites

- Node.js **18+**
- An **NWC-enabled** Lightning wallet to pay top-ups (e.g. CoinOS, Alby, Blink, etc.)
  - You will need a `nostr+walletconnect://...` connection string
  - Treat it like a password (do not paste it in chats or commit it)

## 1) Get an API key (top up payment verifications)

Clone and install deps:

```bash
git clone https://github.com/Mike-io-hash/satsgate.git
cd satsgate
npm install
```

Buy the `trial` plan (1000 sats → 200 payment verifications, no expiry). Each unlock spends **1 credit**, about **5 sats** on this plan, no matter how many sats the buyer pays you. A 21-sat item therefore has about **25%** verification overhead (5/21). See the plan table in [`README.md`](./README.md) before you pick a price.

```bash
SATSGATE_BASE_URL='https://api.satsgate.org' \
SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' \
node client_topup_nwc.mjs trial
```

Save the returned `api_key` (it may only be shown once).

If the hosted payee's provider advertises LUD-21 `verify` (Alby does), you can skip NWC: pay the 402 invoice from any wallet, then poll `GET /v1/topup/status/{payment_hash}` with `Authorization: L402 <macaroon>` until `settled` is true. The Python SDK method is `poll_topup`. Wallet of Satoshi still needs the preimage. The invoice is payable until its own expiry (often about a day). The macaroon stays valid through that time plus a short grace, not only for 10 minutes.

Pay the invoice from a **different** wallet than the one that receives it. Paying yourself from the same node (for example Alby Go on the same Alby Hub) usually fails.

## 2) Register your payee (where your users will pay)

```bash
curl -s -X POST https://api.satsgate.org/v1/client/payee \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...YOUR_API_KEY...' \
  -d '{"payee_lightning_address":"yourname@yourdomain.com"}'
```

`payee_lightning_address` on the first `POST /v1/paywall/challenge` also saves the payee (`payee_saved: true` on that response). A later challenge with a different address returns `payee_mismatch` and does not change it. Use this endpoint to change it.

## 3) End-to-end test (challenge → pay → unlock)

This script:
- requests a paywall challenge
- pays the Lightning invoice via NWC
- verifies the L402 proof (`expected_resource` is required and must exactly match the challenge `resource`, including case)
- spends **1 payment verification** (1 credit)

Pay that invoice from a **different** wallet than the payee. Alby Go paying an invoice that the same Alby Hub issued usually fails. Use a second wallet for the buyer.

If you pay from a wallet that does not hand you the preimage, poll `GET /v1/paywall/status/{payment_hash}` with the API key and `Authorization: L402 <macaroon>` until `settled` is true. That GET spends the credit when it settles. `POST /v1/paywall/verify` is the preimage alternative. Only the first settled call spends a credit.

`invoice_expires_at` is when the buyer must pay. `claim_until` (and `valid_until` on a new challenge) is when you can still unlock. Those used to differ by hours: the invoice lived about a day and the token died after 10 minutes. They now stay aligned, plus a grace period. `cache_until` on a successful unlock is how long to cache that result. How long the buyer may use your product is your decision.

```bash
SATSGATE_BASE_URL='https://api.satsgate.org' \
SATSGATE_CLIENT_API_KEY='sg_...YOUR_API_KEY...' \
SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' \
node client_paywall_credit_demo.mjs demo/test 1
```

Expected:
- your payee receives **1 sat**
- your verification balance decreases by **1**

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
