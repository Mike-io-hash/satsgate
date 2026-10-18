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

## 2b) Mint a restricted key for a proxy

Do this when a reverse proxy or MCP server will create challenges. Give that process the restricted key, and keep the `sg_...` account key off that host. The `sgr_...` secret is shown once.

```bash
curl -s -X POST https://api.satsgate.org/v1/api-keys \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...YOUR_API_KEY...' \
  -d '{"label":"my-proxy","resource_prefix":"demo/"}'
```

That key can call the paywall challenge, status, and verify routes for resources starting with `demo/`. It cannot top up, change the payee, manage keys, or read the ledger. Drop the prefix field to allow every resource. Revoke it with `POST /v1/api-keys/{id}/revoke` using the account key. Python: `SatsgateClient.create_api_key`, `list_api_keys`, `revoke_api_key` (satsgate-sdk 0.4.0).

To put that key in front of an API you already have, without writing paywall code, run [`satsgate-proxy`](./proxy/README.md). It is a separate process (version 0.8.0) and uses resource ids `route:<name>` or `site`, so set `resource_prefix` to match those (or omit it). The core in this quickstart stays the hosted API.

A buyer-side agent uses [`satsgate-mcp`](./mcp/README.md) (version 0.9.1). That process does not create challenges. It pays a URL the proxy already protects. The optional `sgr_` key on the MCP server is only for read-only status and is a different key from the one in the proxy.

## 3) End-to-end test (challenge → pay → unlock)

This script:
- requests a paywall challenge
- pays the Lightning invoice via NWC
- verifies the L402 proof (`expected_resource` is required and must exactly match the challenge `resource`, including case)
- spends **1 payment verification** (1 credit)

Pay that invoice from a **different** wallet than the payee. Alby Go paying an invoice that the same Alby Hub issued usually fails. Use a second wallet for the buyer.

If you pay from a wallet that does not hand you the preimage, poll `GET /v1/paywall/status/{payment_hash}` with the API key and `Authorization: L402 <macaroon>` until `settled` is true. That GET spends the credit when it settles. `POST /v1/paywall/verify` is the preimage alternative. Only the first settled call spends a credit.

`invoice_expires_at` is when the buyer must pay. `claim_until` (and `valid_until` on a new challenge) is when you can still unlock. Those used to differ by hours: the invoice lived about a day and the token died after 10 minutes. They now stay aligned, plus a grace period. `cache_until` on a successful unlock is how long to cache that result when the challenge has no usage policy.

One credit is one settled payment. A cheap API call should be a bundle or a time pass, not a new Lightning invoice. On the challenge, send `max_uses` (how many requests) and/or `access_seconds` (how long after settlement). Then each buyer request calls verify or status with `consume=true`. The server stores the counter, so more than one proxy replica shares it. HTTP 401 `token_used_up` or `token_expired` means mint a new challenge. Without those fields, behaviour is unchanged. Python SDK 0.6.0: `paywall_challenge(max_uses=1)` and `paywall_verify(..., consume=True)`. `max_uses: 1` is the right default for a proxy in front of a paid request. A 50-call bundle or a one-hour pass is how you price something cheaper than one credit.

If that proxy is public, send the end buyer's IP in `X-Satsgate-Buyer-Ip` (`paywall_challenge(..., buyer_ip=)`). Satsgate uses it only when your connection comes from `SATSGATE_TRUSTED_PROXIES`. One buyer then gets a small budget (default 10 challenges per minute and 5 unpaid at a time) instead of the whole account budget, and an identical retry within 30 seconds gets the same invoice back. HTTP 429 `buyer_rate_limited` or `too_many_open_challenges_for_buyer` includes `Retry-After`. The address is stored only as a truncated hash, and that hash is deleted with the challenge.

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
