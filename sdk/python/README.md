# satsgate-sdk (Python)

Minimal Python SDK to integrate **satsgate** (L402 paywall + prepaid credits) into your backend.

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
# you verify it like this:
res = sg.paywall_verify(
    authorization_header="L402 <macaroon>:<preimage>",
    expected_resource="demo/test",
)
print(res)

# 4) Reporting
print(sg.usage_forecast(lookback_hours=24, buffer_days=7, trigger_hours=24))
print(sg.usage_daily(days=30))
print(sg.ledger(limit=50))
```

## Cache

`paywall_verify(..., use_cache=True)` caches `payment_hash` until `valid_until`.
This avoids calling satsgate repeatedly for the same payment/session.
