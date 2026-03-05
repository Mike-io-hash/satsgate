"""Reference paywall integration (FastAPI).

Goals:
- Return a proper L402 challenge (HTTP 402 + WWW-Authenticate) when Authorization is missing.
- Verify L402 proofs and spend credits via satsgate.
- Avoid calling satsgate repeatedly for the same payment/session using the SDK's in-memory cache.

Run:
  export SATSGATE_BASE_URL=https://api.satsgate.org
  export SATSGATE_API_KEY=sg_...
  export PAYWALL_RESOURCE=example/premium
  export PAYWALL_AMOUNT_SATS=10
  uvicorn main:app --reload --port 9000

Test:
  curl -i http://127.0.0.1:9000/premium

For automated testing with an NWC payer, see payer_nwc.mjs in this folder.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from satsgate_sdk import SatsgateClient, SatsgateError

SATSGATE_BASE_URL = os.environ.get("SATSGATE_BASE_URL", "https://api.satsgate.org").rstrip("/")
SATSGATE_API_KEY = os.environ.get("SATSGATE_API_KEY", "")

PAYWALL_RESOURCE = os.environ.get("PAYWALL_RESOURCE", "example/premium")
PAYWALL_AMOUNT_SATS = int(os.environ.get("PAYWALL_AMOUNT_SATS", "10"))
PAYWALL_MEMO = os.environ.get("PAYWALL_MEMO", "Premium access")

_sg: SatsgateClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _sg
    if not SATSGATE_API_KEY:
        raise RuntimeError("Missing SATSGATE_API_KEY")

    _sg = SatsgateClient(base_url=SATSGATE_BASE_URL, api_key=SATSGATE_API_KEY)
    yield
    if _sg is not None:
        _sg.close()


app = FastAPI(title="satsgate-customer-reference", version="0.1.0", lifespan=lifespan)


def sg() -> SatsgateClient:
    assert _sg is not None
    return _sg


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "satsgate_base_url": SATSGATE_BASE_URL,
        "paywall": {
            "resource": PAYWALL_RESOURCE,
            "amount_sats": PAYWALL_AMOUNT_SATS,
        },
    }


@app.get("/premium")
def premium(authorization: str | None = Header(default=None)):
    """A paywalled endpoint.

    - If Authorization is missing, return 402 + L402 challenge.
    - If Authorization is present, verify it (spend credits once per payment_hash) and return the content.

    Note: this example uses an in-memory cache in the SDK to avoid repeated /verify calls for the
    same payment/session.
    """

    # 1) Missing Authorization => create challenge
    if not authorization:
        try:
            ch = sg().paywall_challenge(
                resource=PAYWALL_RESOURCE,
                amount_sats=PAYWALL_AMOUNT_SATS,
                memo=PAYWALL_MEMO,
            )
        except SatsgateError as e:
            # Common onboarding issue: customer has not registered a payee Lightning Address yet.
            if getattr(e, "data", None) and e.data.get("error") == "client_payee_not_set":
                return JSONResponse(
                    status_code=503,
                    content={
                        "ok": False,
                        "error": "paywall_not_configured",
                        "hint": "Configure your satsgate payee first: POST /v1/client/payee",
                        "satsgate": e.data,
                    },
                )

            return JSONResponse(
                status_code=502,
                content={
                    "ok": False,
                    "error": "satsgate_error",
                    "details": str(e),
                    "satsgate": getattr(e, "data", None),
                },
            )

        return JSONResponse(
            status_code=402,
            headers={"WWW-Authenticate": ch.www_authenticate},
            content={
                "ok": False,
                "error": "payment_required",
                "resource": ch.resource,
                "invoice": ch.invoice,
                "macaroon": ch.macaroon,
                "hint": "Pay the invoice, then retry with Authorization: L402 <macaroon>:<preimage>",
            },
        )

    # 2) Authorization present => verify
    try:
        vr = sg().paywall_verify(
            authorization_header=authorization,
            expected_resource=PAYWALL_RESOURCE,
            cost_credits=1,
            use_cache=True,
        )
    except SatsgateError as e:
        status = int(e.status_code) if getattr(e, "status_code", None) else 401
        if status < 400 or status > 599:
            status = 401
        return JSONResponse(
            status_code=status,
            content={"ok": False, "error": "verification_failed", "details": str(e), "satsgate": getattr(e, "data", None)},
        )

    # vr.charged_credits is 1 on the first successful verification for a payment_hash.
    # It may be 0 on cache hits.
    return {
        "ok": True,
        "data": "Premium content",
        "payment_hash": vr.payment_hash,
        "charged_credits": vr.charged_credits,
        "note": "charged_credits may be 0 on cache hits (same payment/session).",
    }
