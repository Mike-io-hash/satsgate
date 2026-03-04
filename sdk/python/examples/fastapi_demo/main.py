"""Integration example (FastAPI) for a satsgate customer.

This service exposes `/premium`:
- if Authorization (L402) is missing -> requests a challenge from satsgate and returns 402
- if Authorization is present -> calls /verify (consumes 1 credit) and returns the content

Run:
  export SATSGATE_BASE_URL=http://127.0.0.1:8000
  export SATSGATE_API_KEY=sg_...
  uvicorn main:app --reload --port 9000

Then:
  curl -i http://127.0.0.1:9000/premium
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from satsgate_sdk import SatsgateClient, SatsgateError

BASE_URL = os.environ.get("SATSGATE_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.environ.get("SATSGATE_API_KEY", "")

app = FastAPI(title="client-fastapi-demo")


def _client() -> SatsgateClient:
    if not API_KEY:
        raise RuntimeError("Missing SATSGATE_API_KEY")
    return SatsgateClient(base_url=BASE_URL, api_key=API_KEY)


@app.get("/premium")
def premium(authorization: str | None = Header(default=None)):
    sg = _client()

    # 1) missing Authorization => challenge
    if not authorization:
        ch = sg.paywall_challenge(resource="demo/premium", amount_sats=10, memo="premium")
        # return 402 with WWW-Authenticate + JSON
        return JSONResponse(
            status_code=402,
            headers={"WWW-Authenticate": ch.www_authenticate},
            content={
                "ok": False,
                "error": "payment_required",
                "invoice": ch.invoice,
                "macaroon": ch.macaroon,
            },
        )

    # 2) Authorization present => verify
    try:
        sg.paywall_verify(authorization_header=authorization, expected_resource="demo/premium")
    except SatsgateError as e:
        return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})

    return {"ok": True, "data": "Premium content"}
