"""Automated payer: Python equivalent of payer_nwc.mjs.

Calls a paywalled endpoint without Authorization (expects 402), pays the
returned Lightning invoice, then retries with ``Authorization: L402 ...``.

Mirrors ``payer_nwc.mjs`` in this folder so Python-based AI agents and
backends can be tested end-to-end without Node.js.

Requirements
------------
- Python 3.10+
- ``pip install httpx``
- One of the payment backends below (see PAYMENT_BACKEND):

  ``nwc``   (default)
      ``pip install nostr-sdk``
      ``export TEST_PAYER_NWC='nostr+walletconnect://...'``

  ``alby``
      ``npm install -g @getalby/cli``  (or ``npx @getalby/cli``)
      Alby Hub / Alby Desktop configured with a funded wallet.

  ``mock``
      No extra setup.  Works only against a server running with
      ``SATSGATE_WALLET_MODE=mock`` (dev/local testing only).

Usage
-----
    # NWC backend:
    TEST_PAYER_NWC='nostr+walletconnect://...' python payer_nwc.py http://127.0.0.1:9000/premium

    # Alby CLI backend:
    PAYMENT_BACKEND=alby python payer_nwc.py http://127.0.0.1:9000/premium

    # Mock backend (local dev only):
    PAYMENT_BACKEND=mock SATSGATE_BASE_URL=http://127.0.0.1:8000 \\
        python payer_nwc.py http://127.0.0.1:9000/premium
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from typing import Literal

import httpx

# ---------------------------------------------------------------------------
# Config (all overridable via env vars)
# ---------------------------------------------------------------------------

PAYMENT_BACKEND: Literal["nwc", "alby", "mock"] = os.environ.get(  # type: ignore[assignment]
    "PAYMENT_BACKEND", "nwc"
)
TEST_PAYER_NWC: str = os.environ.get("TEST_PAYER_NWC", "")

# Only needed for the mock backend — points at the satsgate server itself
SATSGATE_BASE_URL: str = os.environ.get("SATSGATE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

# Optional: abort if the invoice amount exceeds this (sats).  0 = unlimited.
MAX_SATS: int = int(os.environ.get("MAX_SATS", "0"))


# ---------------------------------------------------------------------------
# Payment helpers
# ---------------------------------------------------------------------------


def _pay_mock(payment_hash: str) -> str:
    """Simulate payment via the satsgate dev endpoint (mock mode only)."""
    r = httpx.get(f"{SATSGATE_BASE_URL}/dev/mock/pay/{payment_hash}", timeout=10)
    r.raise_for_status()
    preimage = r.json().get("preimage")
    if not preimage:
        raise RuntimeError(f"Mock pay returned no preimage: {r.json()}")
    return preimage


def _pay_alby(invoice: str) -> str:
    """Pay via ``npx @getalby/cli pay-invoice`` and return the preimage."""
    try:
        result = subprocess.run(
            ["npx", "@getalby/cli", "pay-invoice", invoice, "--json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"alby-cli failed:\n{exc.stderr.strip()}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("npx not found — install Node.js and @getalby/cli") from exc

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"alby-cli returned non-JSON: {result.stdout}") from exc

    preimage = data.get("payment_preimage") or data.get("preimage")
    if not preimage:
        raise RuntimeError(f"alby-cli returned no preimage: {result.stdout}")
    return preimage


async def _pay_nwc(invoice: str) -> str:
    """Pay via Nostr Wallet Connect (NIP-47) and return the preimage.

    Requires: ``pip install nostr-sdk``
    Wallet must support preimage disclosure (Alby Hub, Mutiny, Phoenix, …).
    """
    if not TEST_PAYER_NWC:
        raise RuntimeError(
            "TEST_PAYER_NWC not set.\n"
            "Format: nostr+walletconnect://<pubkey>?relay=<url>&secret=<hex>\n"
            "Or switch backend: PAYMENT_BACKEND=alby"
        )
    try:
        from nostr_sdk import NostrWalletConnectUri, Nwc  # type: ignore[import]
    except ModuleNotFoundError as exc:
        raise RuntimeError("nostr-sdk not installed — run: pip install nostr-sdk") from exc

    uri = NostrWalletConnectUri.parse(TEST_PAYER_NWC)
    nwc = Nwc(uri)
    result = await nwc.pay_invoice(invoice)
    preimage = getattr(result, "preimage", None)
    if not preimage:
        raise RuntimeError(
            "NWC wallet returned no preimage.  "
            "Ensure your wallet supports preimage disclosure."
        )
    return preimage


async def pay_invoice(invoice: str, payment_hash: str) -> str:
    """Dispatch to the configured payment backend."""
    if PAYMENT_BACKEND == "mock":
        return _pay_mock(payment_hash)
    if PAYMENT_BACKEND == "alby":
        return _pay_alby(invoice)
    if PAYMENT_BACKEND == "nwc":
        return await _pay_nwc(invoice)
    raise ValueError(f"Unknown PAYMENT_BACKEND: {PAYMENT_BACKEND!r}")


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------


async def main(target_url: str) -> None:
    print(f"Target  : {target_url}")
    print(f"Backend : {PAYMENT_BACKEND}")
    print()

    async with httpx.AsyncClient(timeout=30) as c:
        # STEP 1 — request without auth, expect 402
        print("STEP 1: requesting without Authorization …")
        r1 = await c.get(target_url)
        print(f"  status: {r1.status_code}")

        body1: dict = {}
        try:
            body1 = r1.json()
            print(f"  body  : {body1}")
        except Exception:
            print(f"  body  : (non-JSON) {r1.text[:120]}")

        if r1.status_code != 402:
            print(f"\n✗ Expected 402 Payment Required, got {r1.status_code}")
            sys.exit(1)

        invoice: str = body1.get("invoice", "")
        macaroon: str = body1.get("macaroon", "")
        payment_hash: str = body1.get("payment_hash", "")
        amount_sats: int = int(body1.get("amount_sats", 0))

        if not invoice or not macaroon:
            print("\n✗ Response missing 'invoice' or 'macaroon' — is the server configured correctly?")
            sys.exit(1)

        # Warn when fields needed by specific backends/features are absent
        if not payment_hash:
            if PAYMENT_BACKEND == "mock":
                print("\n✗ 402 response missing 'payment_hash' — required for PAYMENT_BACKEND=mock.")
                print("  Hint: update the server's 402 JSON to include 'payment_hash' from the challenge.")
                sys.exit(1)
            print("  ⚠ 402 response missing 'payment_hash' (mock backend will not work)")

        if not amount_sats:
            if MAX_SATS:
                print("  ⚠ 402 response missing 'amount_sats' — MAX_SATS guard cannot be applied")
            else:
                print("  ⚠ 402 response missing 'amount_sats' (invoice amount unknown)")

        # Optional guard: refuse to pay more than MAX_SATS
        if MAX_SATS and amount_sats and amount_sats > MAX_SATS:
            print(f"\n✗ Invoice amount {amount_sats} sats exceeds MAX_SATS={MAX_SATS} — aborting")
            sys.exit(1)

        # STEP 2 — pay the invoice
        print(f"\nSTEP 2: paying invoice ({amount_sats or '?'} sats) via '{PAYMENT_BACKEND}' …")
        try:
            preimage = await pay_invoice(invoice, payment_hash)
        except RuntimeError as exc:
            print(f"\n✗ Payment failed: {exc}")
            sys.exit(1)
        print(f"  preimage: {preimage}")

        # STEP 3 — retry with L402 auth
        print("\nSTEP 3: retrying with Authorization: L402 …")
        auth = f"L402 {macaroon}:{preimage}"
        r3 = await c.get(target_url, headers={"Authorization": auth})
        print(f"  status: {r3.status_code}")
        try:
            print(f"  body  : {r3.json()}")
        except Exception:
            print(f"  body  : {r3.text[:120]}")

        print()
        if r3.status_code == 200:
            print("✓ L402 flow complete — payment verified, content unlocked.")
        else:
            print(f"✗ Unexpected status {r3.status_code} after payment.")
            sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            f"Usage: python {sys.argv[0]} <url>\n"
            "  Example: python payer_nwc.py http://127.0.0.1:9000/premium\n\n"
            "Env vars:\n"
            "  PAYMENT_BACKEND   nwc | alby | mock  (default: nwc)\n"
            "  TEST_PAYER_NWC    nostr+walletconnect://... (for nwc backend)\n"
            "  MAX_SATS          abort if invoice > N sats (default: 0 = unlimited)\n"
            "  SATSGATE_BASE_URL satsgate server URL (mock backend only)"
        )
        sys.exit(2)

    asyncio.run(main(sys.argv[1]))
