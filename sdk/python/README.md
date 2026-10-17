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
```

## Cache

`paywall_verify(..., use_cache=True)` remembers a successful `payment_hash` until `cache_until`.
Older servers only return `valid_until`, and the SDK falls back to that. The cache is there so a busy route does not call satsgate on every request. It is not how long the buyer may use your product. `valid_until` is the macaroon expiry caveat. `claim_until` is the latest time a first unlock is accepted.
