# satsgate-sdk (Python)

Minimal Python SDK to integrate **satsgate** (L402 paywall + prepaid payment verifications (credits)) into your backend.

## Install (editable, from this repo)

```bash
# from the satsgate repo root
python3 -m venv .venv
source .venv/bin/activate

pip install -e sdk/python
```

## Example

```python
from satsgate_sdk import SatsgateClient

sg = SatsgateClient(base_url="http://127.0.0.1:8000", api_key="sg_...")

# 1) Register payee (once)
sg.set_payee("burlybakery53@walletofsatoshi.com")

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

## Usage policy

`paywall_challenge(..., max_uses=1)` or `access_seconds=3600` records what that payment buys. One credit is still one settled payment. Pass `consume=True` to `paywall_verify` or `poll_paywall` on every buyer request. Each call takes one use, including a retry. The server returns `uses_remaining` and `access_until`. HTTP 401 `token_used_up` or `token_expired` means create a new challenge. The SDK does not cache a challenge that has a policy.

## Restricted keys

`create_api_key`, `list_api_keys`, and `revoke_api_key` talk to `/v1/api-keys` with the account key (`sg_...`).

A restricted key starts with `sgr_`. It can call `paywall_challenge`, `paywall_verify`, and `poll_paywall`. Top-up, payee changes, key management, balance, client, ledger, and usage calls return HTTP 403 `insufficient_scope`. `resource_prefix` limits the three paywall calls to resources that start with that prefix (HTTP 403 `resource_not_allowed`). A revoked key returns HTTP 401 `api_key_revoked`.

## Cache

`paywall_verify(..., use_cache=True)` remembers a successful `payment_hash` until `cache_until`.
Older servers only return `valid_until`, and the SDK falls back to that. The cache is there so a busy route does not call satsgate on every request. It is not how long the buyer may use your product. `valid_until` is the macaroon expiry caveat. `claim_until` is the latest time a first unlock is accepted.
