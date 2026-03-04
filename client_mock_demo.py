"""Test client (mock mode).

This script runs the full L402 flow against your local server:
1) Request /v1/tickets without auth -> gets 402 + invoice + macaroon + payment_hash
2) Simulate payment (mock mode only) -> gets preimage
3) Retry with Authorization: L402 <macaroon>:<preimage>

Usage:
  source .venv/bin/activate
  python client_mock_demo.py

Requirements:
  - server running at http://127.0.0.1:8000
  - SATSGATE_WALLET_MODE=mock
"""

from __future__ import annotations

import os

import httpx

BASE_URL = os.environ.get("SATSGATE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def main() -> None:
    with httpx.Client(timeout=10) as c:
        r1 = c.get(f"{BASE_URL}/v1/tickets")
        print("STEP 1 status:", r1.status_code)
        data1 = r1.json()
        print("STEP 1 body:", data1)

        if r1.status_code != 402:
            raise SystemExit("Expected 402 Payment Required. Is the server running?")

        payment_hash = data1["payment_hash"]
        macaroon = data1["macaroon"]

        # mock-pay
        r2 = c.get(f"{BASE_URL}/dev/mock/pay/{payment_hash}")
        print("STEP 2 status:", r2.status_code)
        data2 = r2.json()
        print("STEP 2 body:", data2)
        preimage = data2["preimage"]

        # retry with auth
        auth = f"L402 {macaroon}:{preimage}"
        r3 = c.get(f"{BASE_URL}/v1/tickets", headers={"Authorization": auth})
        print("STEP 3 status:", r3.status_code)
        print("STEP 3 body:", r3.json())


if __name__ == "__main__":
    main()
