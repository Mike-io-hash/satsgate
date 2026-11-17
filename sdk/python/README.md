# satsgate-sdk (Python)

Python client for **satsgate** model B. A vendor opens an account, holds a prepaid balance in milisatoshis, and charges a live unlock from that balance. The balance is not money and is not redeemable for sats, USDC, or fiat. PyPI publication is forthcoming; install from this repo until then.

## Install (editable, from this repo)

```bash
# from the satsgate repo root
python3 -m venv .venv
source .venv/bin/activate

pip install -e sdk/python
```

## Account and top-up

`create_account(base_url=...)` calls `POST /v1/accounts` with no API key and an empty body. The response includes `api_key` (shown once), `client_id`, `balance_msat`, `balance_sats`, and `estimated_unlocks_remaining`. A 429 is raised. The client does not retry.

```python
from satsgate_sdk import SatsgateClient, create_account

opened = create_account(base_url="http://127.0.0.1:8000")
sg = SatsgateClient(base_url="http://127.0.0.1:8000", api_key=opened["api_key"])
print(sg.balance()["balance_msat"], sg.balance()["estimated_unlocks_remaining"])

# Lightning: minimum 1,000 sats. The 402 body includes invoice, macaroon,
# payment_hash, and msat_credit (principal plus any bonus the server computed).
invoice = sg.topup_lightning(sats=1000)

# USDC: minimum US$1. The 402 body includes PAYMENT-REQUIRED from the response header.
# Pass payment_signature on a later call to settle. This SDK does not sign.
offer = sg.topup_usdc(usd="1.00")
```

`balance()` and `get_client()` return `balance_msat`, `balance_sats`, and `estimated_unlocks_remaining`, plus `free_unlocks_remaining` and `paid_unlocks_estimate` when the server sends them. `list_plans()` returns the model B document.

## Example

```python
from satsgate_sdk import SatsgateClient

sg = SatsgateClient(base_url="http://127.0.0.1:8000", api_key="sg_...")

# 1) Register payee (once)
sg.set_payee("burlybakery53@walletofsatoshi.com")

# One-time browser link for a USDC payee. The URL is not logged.
# link = sg.create_connect_link()

# 2) Create a challenge for your resource
ch = sg.paywall_challenge(resource="demo/test", amount_sats=10, memo="my service")

# Your backend should respond to your end user with HTTP 402 + header:
#   WWW-Authenticate: ch.www_authenticate
# and optionally JSON containing ch.invoice and ch.macaroon.

# 3) When your end user retries with Authorization: L402 ...
# expected_resource is required. The token is v2 and only verifies for the
# client that created the challenge.
res = sg.paywall_verify(
    authorization_header="L402 <macaroon>:<preimage>",
    expected_resource="demo/test",
)
print(res)

# Or, when the payee's wallet advertised LUD-21 verify: the payer pays `ch.invoice`
# from any wallet and you poll without a preimage.
# settled = sg.poll_paywall(
#     macaroon=ch.macaroon,
#     payment_hash=ch.payment_hash,
#     expected_resource="demo/test",
# )

# 4) Reporting
print(sg.usage_forecast(lookback_hours=24, buffer_days=7, trigger_hours=24))
print(sg.usage_daily(days=30))
print(sg.ledger(limit=50))

# 5) Restricted key for a proxy or MCP server (account key only).
# The secret is in created["api_key"] and is not shown again.
# created = sg.create_api_key(label="blog-proxy", resource_prefix="blog/")
# proxy = SatsgateClient(base_url="http://127.0.0.1:8000", api_key=created["api_key"])
# proxy.paywall_challenge(resource="blog/post", amount_sats=10)
# sg.revoke_api_key(created["key"]["id"])
```

## Buyer IP

`paywall_challenge(..., buyer_ip="203.0.113.10")` sends `X-Satsgate-Buyer-Ip`. The server applies per-buyer challenge limits and may reuse a pending invoice only when the TCP peer is a trusted proxy. `buyer_ip_accepted` on the result says whether it did. `reused` is true when the response is an invoice that buyer already has.

## Usage policy

`paywall_challenge(..., max_uses=1)` or `access_seconds=3600` records what that payment buys. Pass `consume=True` to `paywall_verify` or `poll_paywall` on every buyer request. Each call takes one use, including a retry. The server returns `uses_remaining` and `access_until`. HTTP 401 `token_used_up` or `token_expired` means create a new challenge. The SDK does not cache a challenge that has a policy.

## Restricted keys

`create_api_key`, `list_api_keys`, and `revoke_api_key` talk to `/v1/api-keys` with the account key (`sg_...`).

A restricted key starts with `sgr_`. It can call `paywall_challenge`, `paywall_verify`, `poll_paywall`, and `balance` (including `balance_msat` and `estimated_unlocks_remaining`). It cannot open an account or top up. Payee changes, key management, and other account writes return HTTP 403 `insufficient_scope`. `resource_prefix` limits the paywall calls to resources that start with that prefix (HTTP 403 `resource_not_allowed`). A revoked key returns HTTP 401 `api_key_revoked`.

## Receipts (0.7.0)

`satsgate_sdk.receipts` checks a hosted-gate receipt without calling Satsgate. The secret is the site `origin_secret`. `verify_receipt` checks the HS256 signature, `aud`, `sub`, `iss`, `exp`, and `uses`. `MemoryReceiptStore` and `SqliteReceiptStore` reserve a use and commit it on a 2xx. `SatsgateReceiptMiddleware` is the ASGI wrapper. `python -m satsgate_sdk.receipts verify` checks one token. Vectors shared with the Express snippet are `tests/fixtures/receipt_vectors.json`.

```python
from satsgate_sdk.receipts import SatsgateReceiptMiddleware, SqliteReceiptStore

app = SatsgateReceiptMiddleware(
    app,
    site="my-shop",
    secret=os.environ["SATSGATE_SITE_SECRET"],
    store=SqliteReceiptStore("/data/receipts.sqlite3"),
)
```

The demo seller is `sdk/python/examples/receipt_seller.py`. `x402-test` is mounted at `/live` and `demo-test` at `/test`. Each accepts only its own receipts.

## Cache

`paywall_verify(..., use_cache=True)` remembers a successful `payment_hash` until `cache_until`.
Older servers only return `valid_until`, and the SDK falls back to that. The cache is there so a busy route does not call satsgate on every request. It is not how long the buyer may use your product. `valid_until` is the macaroon expiry caveat. `claim_until` is the latest time a first unlock is accepted.
