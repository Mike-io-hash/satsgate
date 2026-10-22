#!/usr/bin/env python3
"""Show a USDC credit-pack request. This script does not sign or hold a key.

The wallet signs the EIP-3009 authorization in PAYMENT-REQUIRED. Core asks
the public facilitator to verify and settle. Credits are added only after
that settle, and they are not redeemable for USDC.

  SATSGATE_BASE_URL=https://api.satsgate.org \\
  SATSGATE_API_KEY=sg_... \\
  python3 scripts/x402_topup_example.py trial

Set SATSGATE_X402_PAYMENT_SIGNATURE to the base64 payload from the wallet
to send the paid retry. The signature is not printed.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def _request(url: str, api_key: str, signature: str | None) -> tuple[int, dict, dict]:
    headers = {"Accept": "application/json", "X-Api-Key": api_key}
    if signature:
        headers["PAYMENT-SIGNATURE"] = signature
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
            return response.status, dict(response.headers), json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"error": "unreadable_body"}
        return exc.code, dict(exc.headers), payload


def main() -> int:
    plan = sys.argv[1] if len(sys.argv) > 1 else "trial"
    base = os.environ.get("SATSGATE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    api_key = os.environ.get("SATSGATE_API_KEY", "").strip()
    if not api_key:
        print("Set SATSGATE_API_KEY to the account key (sg_...).", file=sys.stderr)
        return 2
    signature = os.environ.get("SATSGATE_X402_PAYMENT_SIGNATURE", "").strip() or None
    status, headers, body = _request(f"{base}/v1/topup/{plan}/x402", api_key, signature)
    if status == 402:
        print(json.dumps({"status": status, "x402": body.get("x402"), "credits": body.get("credits"), "expires_at": body.get("expires_at")}, indent=2))
        print("Header PAYMENT-REQUIRED is set." if headers.get("PAYMENT-REQUIRED") or headers.get("payment-required") else "Header PAYMENT-REQUIRED is missing.")
        print("Sign that requirement in a wallet, then rerun with SATSGATE_X402_PAYMENT_SIGNATURE.")
        return 0
    if status == 200:
        print(json.dumps({"status": status, "credits_added": body.get("credits_added"), "credits": body.get("credits"), "tx": body.get("tx"), "network": body.get("network"), "amount_usd_atomic": body.get("amount_usd_atomic")}, indent=2))
        return 0
    print(json.dumps({"status": status, "error": body.get("error"), "reason": body.get("reason")}, indent=2))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
