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

The same packs can be bought with USDC when the operator has set `SATSGATE_TREASURY_EVM_ADDRESS`. While `SATSGATE_X402_CDP` is on, the pack is Base mainnet USDC only (`eip155:8453`). While it is off, the pack is Base Sepolia only (`eip155:84532`) and the response says `testing: true`. Credits are not sold for faucet USDC once mainnet is on. `GET /v1/topup/trial/x402` with the account key returns `402` and `PAYMENT-REQUIRED`. Retry with `PAYMENT-SIGNATURE` after your wallet signs that exact USDC authorization. Credits land only after the facilitator settles, and they are not redeemable for USDC. If the treasury variable is unset, the route says `x402_topup_disabled` and the Lightning steps above are unchanged. A request sketch is `scripts/x402_topup_example.py`. The proxy and the MCP server do not call this route.

A hosted site that takes USDC starts in test mode. Try on Base Sepolia with your agent first, then switch the site to live. See [`gate/README.md`](./gate/README.md).

To set the USDC address, create a one-time link with `POST /v1/client/payee/evm/connect` (the account key) and open it in a browser. The page connects a wallet you already use and asks for one signature. It does not ask for the account key, a seed phrase, or a private key. USDC is on Base only. A Safe on Base and a Coinbase Smart Wallet work on that page. The manual challenge and verify calls still work, including a smart-wallet signature.

Add an alert email (recommended) on the connect page or with `PUT /v1/client/alert-email`, and confirm it from your inbox. You'll get an email whenever a payout address changes. Remove it with `DELETE /v1/client/alert-email`. The address is optional. Satsgate does not use it for marketing.

## Rotate the account key

If the `sg_…` account key may have leaked, rotate it yourself. The old key stops working as soon as this returns. There is no grace period. Restricted `sgr_…` keys are not changed and do not have permission to call this. The new key is shown once.

```bash
curl -s -X POST https://api.satsgate.org/v1/client/api-key/rotate \
  -H 'X-Api-Key: sg_...YOUR_CURRENT_ACCOUNT_KEY...'
```

`200` is `{ "ok": true, "api_key": "sg_…", "prefix": "sg_…xxxx" }`. `prefix` is the first 8 characters. A restricted key is `403 insufficient_scope`. After a successful rotate, the previous key is `401 invalid_api_key`. Save the new key, then keep using it as `X-Api-Key`. If you did not mean to rotate, write to support and ask for your sites to be paused. Never send the key, a seed phrase, or a private key.

A confirmed alert email is told. A security webhook, if you have one, gets the same `account_key_rotated` event. The event data is `at` (UTC text), `prefix`, and `via` (`api`). It does not include the old or new key.

## Security webhook

Register an https URL to receive the same security events as the alert email, plus rotation. The URL is checked when you save it and again on every delivery: https only, no username or password, a public address, no redirects, a 5 second timeout, and at most 300 characters. Satsgate reads at most 4 KiB of the response.

```bash
curl -s -X PUT https://api.satsgate.org/v1/client/webhook \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: sg_...YOUR_ACCOUNT_KEY...' \
  -d '{"url":"https://example.com/satsgate-webhook"}'
```

The first response includes `secret` (`whsec_…`) once. A later `PUT` with a new URL keeps that secret and does not return it. Send `"rotate_secret": true` to replace the secret and read the new one once. `GET /v1/client/webhook` returns `url`, `enabled`, `secret_prefix`, and `last_delivery` (or `null`). It never returns the secret. `DELETE /v1/client/webhook` removes it. `POST /v1/client/webhook/test` queues a test event. All four calls use the account key.

Each delivery is `POST` with `Content-Type: application/json` and these headers:

- `Satsgate-Webhook-Id` — the same value as the JSON `id` (`evt_…`). Retries reuse it. Dedupe on it.
- `Satsgate-Webhook-Timestamp` — unix seconds. A new value on every attempt, including retries.
- `Satsgate-Webhook-Signature` — `v1=` plus hex HMAC-SHA256.

The HMAC key is the UTF-8 bytes of the entire `whsec_…` string. The message is the timestamp, a dot, and the raw body bytes. Verify those bytes before you parse JSON, with a constant-time compare. Reject a timestamp more than 300 seconds from your clock.

Worked example. Secret `whsec_test_vector_secret`, timestamp `1700000000`, body:

```text
{"created_at":1700000000,"data":{"at":"2023-11-14 22:13 UTC"},"id":"evt_test","type":"webhook_test"}
```

Signature: `v1=cc9626aae0328af78a2024d37a78706c0f330fe98457609c5e91517dc0ee28f9`

Python:

```python
import hmac, hashlib

def verify_satsgate_webhook(secret: str, timestamp: str, raw_body: bytes, signature: str, now: int) -> bool:
    if abs(int(now) - int(timestamp)) > 300:
        return False
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{int(timestamp)}.".encode("ascii") + raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(f"v1={digest}", signature)
```

Node:

```javascript
const crypto = require("crypto");

function verifySatsgateWebhook(secret, timestamp, rawBody, signature, now) {
  const skew = Math.abs(Number(now) - Number(timestamp));
  if (!Number.isFinite(skew) || skew > 300) return false;
  const expected = "v1=" + crypto.createHmac("sha256", secret).update(`${timestamp}.`).update(rawBody).digest("hex");
  const left = Buffer.from(expected);
  const right = Buffer.from(String(signature));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}
```

Events: `payee_lightning_changed`, `payee_evm_changed`, `payee_ofac_flagged`, `alert_email_changed`, `alert_email_removed`, `account_key_rotated`, `webhook_test`. The JSON is `{ "id", "type", "created_at", "data" }`. `data` uses the same masked fields as the email: shortened payout addresses, a masked alert address, and the new key's prefix. It does not include a full key, a full payout address, a signature, or an email confirmation token. `created_at` is unix seconds and stays the same on retry. The body bytes stay the same on retry. Only the timestamp and signature change.

A 2xx means delivered. Anything else is retried up to 5 sends in total (the first try, then after 60 seconds, 5 minutes, 30 minutes, and 2 hours). HTTP 404 or 410 turns the webhook off and stops the retries. If you have a confirmed alert email, Satsgate mails you that the webhook was disabled. It does not include the URL. Register a new URL with `PUT` if you still want events. No webhook configured means nothing here changes: email alerts, when you have them, are the same as before.

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

To put that key in front of an API you already have, without writing paywall code, run [`satsgate-proxy`](./proxy/README.md). It is a separate process (version 0.14.0) and uses resource ids `route:<name>` or `site`, so set `resource_prefix` to match those (or omit it). The core in this quickstart stays the hosted API. `x402: true` without `x402_mode` is Base Sepolia. `x402_mode: live` is Base, after the operator has enabled it.

A buyer-side agent uses [`satsgate-mcp`](./mcp/README.md) (version 0.11.0). That process does not create challenges. It pays a Lightning URL the proxy already protects, reads an x402 offer without signing it, and `list_sites` reads the public directory of approved sites, including a USD-priced route. The optional `sgr_` key on the MCP server is only for read-only status and is a different key from the one in the proxy.

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

If that proxy is public, send the end buyer's IP in `X-Satsgate-Buyer-Ip` (`paywall_challenge(..., buyer_ip=)`). Satsgate uses it only when your connection comes from `SATSGATE_TRUSTED_PROXIES`. One buyer then gets a small budget (default 10 challenges per minute, and 5 unexpired unpaid challenges at a time on each rail) instead of the whole account budget, and an identical retry within 30 seconds gets the same invoice back. HTTP 429 `buyer_rate_limited` or `too_many_open_challenges_for_buyer` includes `Retry-After`. That wait is the soonest expiry of the challenges that still count. An expired challenge does not count. Lightning and x402 are counted separately. The address is stored only as a truncated hash, and that hash is deleted with the challenge.

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

## Hosted gate

Core stores a site, and `satsgate-gate` charges at `https://gate.satsgate.org/<slug>/...` after an operator approves it. The gate returns a signed receipt. It does not call your origin. The buyer repeats the request at your origin with `Satsgate-Receipt`. The Caddy site block for that hostname is in the repo. Registering a site does not change challenge, verify, or status on `api.satsgate.org`. Details are in the README section "Hosted sites (closed beta)" and in `gate/README.md`.

## Usage & automation

- Forecast + recommended purchase + top-up trigger:

```bash
curl -s \
  -H 'X-Api-Key: sg_...YOUR_API_KEY...' \
  'https://api.satsgate.org/v1/usage/forecast?lookback_hours=24&buffer_days=7&max_topups=3&trigger_hours=24'
```
