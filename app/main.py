from __future__ import annotations

import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from math import ceil
from typing import Any

from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config
from . import db
from . import db_clients
from . import db_reports
from . import db_verify
from . import ssrf
from . import wallet_lnaddr
from .admin import router as admin_router
from .client_ip import resolve_client_ip
from .invoices import InvoiceValidationError
from .l402 import (
    L402Error,
    PURPOSE_PAYWALL,
    PURPOSE_TICKET,
    PURPOSE_TOPUP,
    TOKEN_VERSION,
    invoice_binding,
    make_macaroon,
    parse_and_verify_macaroon,
    parse_authorization_header,
    payee_binding,
    peek_bindings,
    verify_preimage_matches_payment_hash,
    www_authenticate_header,
)
from .mock_wallet import MockWallet
from .plans import get_plan, list_plans, recommend_purchase
from .rate_limit import RateLimiter
from .wallet_lnaddr import LightningAddressWallet, LnurlError


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    yield
    ssrf.close()


app = FastAPI(title="satsgate", version=config.APP_VERSION, lifespan=_lifespan)

app.include_router(admin_router)


def _get_wallet() -> Any:
    if config.WALLET_MODE == "mock":
        return MockWallet()
    if config.WALLET_MODE == "lnaddr":
        if not config.LIGHTNING_ADDRESS:
            raise RuntimeError("SATSGATE_LIGHTNING_ADDRESS is required when SATSGATE_WALLET_MODE=lnaddr")
        return LightningAddressWallet(
            config.LIGHTNING_ADDRESS,
            network=config.LN_NETWORK,
            send_comment=config.LNURL_SEND_COMMENT,
        )
    raise RuntimeError(f"Invalid SATSGATE_WALLET_MODE: {config.WALLET_MODE}")


# Note: for a simple MVP we keep it global.
# In production, prefer dependency injection with lifespan and a reusable HTTP client.
WALLET = _get_wallet()

# DB init
try:
    db.init_db(config.DB_PATH)
except Exception as e:  # noqa: BLE001
    raise RuntimeError(f"Failed to initialize DB at {config.DB_PATH}: {e}") from e

# Rate limiters. Auth buckets are only for keys that exist. Unknown keys share the IP bucket.
RL_ANON = RateLimiter(
    window_seconds=config.RL_WINDOW_SECONDS,
    max_requests=config.RL_MAX_ANON,
    max_keys=config.RL_MAX_KEYS,
)
RL_AUTH = RateLimiter(
    window_seconds=config.RL_WINDOW_SECONDS,
    max_requests=config.RL_MAX_AUTH,
    max_keys=config.RL_MAX_KEYS,
)
RL_CHALLENGE = RateLimiter(
    window_seconds=config.RL_WINDOW_SECONDS,
    max_requests=config.RL_MAX_CHALLENGE,
    max_keys=config.RL_MAX_KEYS,
)
RL_TOPUP = RateLimiter(
    window_seconds=config.RL_WINDOW_SECONDS,
    max_requests=config.RL_MAX_TOPUP,
    max_keys=config.RL_MAX_KEYS,
)


def _get_client_from_api_key(x_api_key: str | None) -> db.Client | None:
    if not x_api_key or len(x_api_key) > 512:
        return None
    return db.get_client_by_api_key(config.DB_PATH, x_api_key)


def _peer_ip(request: Request) -> str:
    return resolve_client_ip(
        peer=request.client.host if request.client else None,
        forwarded_for=request.headers.get("x-forwarded-for"),
        trusted_proxies=config.TRUSTED_PROXIES,
    )


def _rate_limited(retry_after: int) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": str(retry_after)},
        content={
            "ok": False,
            "error": "rate_limited",
            "retry_after_seconds": retry_after,
        },
    )


def _reject_if_limited(limiter: RateLimiter, key: str) -> JSONResponse | None:
    allowed, retry_after = limiter.allow(key)
    if allowed:
        return None
    return _rate_limited(retry_after)


@app.middleware("http")
async def rate_limit_mw(request: Request, call_next):
    if not config.RL_ENABLED:
        return await call_next(request)

    # Apply RL only to /v1 (API). Health and other endpoints remain free.
    if not request.url.path.startswith("/v1"):
        return await call_next(request)

    ip = _peer_ip(request)
    raw_key = request.headers.get("x-api-key")
    client = _get_client_from_api_key(raw_key)
    if client is not None and raw_key is not None:
        # Hash only. A random key must not open its own auth bucket.
        blocked = _reject_if_limited(RL_AUTH, "k:" + db.hash_api_key(raw_key))
    else:
        blocked = _reject_if_limited(RL_ANON, "ip:" + ip)
    if blocked:
        return blocked

    path = request.url.path
    if client is not None and path == "/v1/paywall/challenge" and request.method == "POST":
        blocked = _reject_if_limited(RL_CHALLENGE, "c:" + str(client.id))
        if blocked:
            return blocked

    if path.startswith("/v1/topup/") and request.method == "GET" and not request.headers.get("authorization"):
        topup_key = ("c:" + str(client.id)) if client is not None else ("ip:" + ip)
        blocked = _reject_if_limited(RL_TOPUP, topup_key)
        if blocked:
            return blocked

    return await call_next(request)


def _upstream_error(exc: Exception) -> JSONResponse:
    """Stable errors for LNURL/BOLT11 failures. Do not echo upstream URLs or bodies."""
    if isinstance(exc, ssrf.SSRFError):
        code = "payee_destination_rejected" if exc.code == "destination_rejected" else "payee_fetch_failed"
        if exc.code == "redirects_not_allowed":
            code = "payee_destination_rejected"
        return JSONResponse(status_code=502, content={"ok": False, "error": code})
    if isinstance(exc, InvoiceValidationError):
        return JSONResponse(
            status_code=502,
            content={"ok": False, "error": "invoice_rejected", "reason": exc.code},
        )
    if isinstance(exc, LnurlError):
        return JSONResponse(status_code=502, content={"ok": False, "error": exc.code})
    if isinstance(exc, ValueError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "amount_out_of_range"})
    return JSONResponse(status_code=502, content={"ok": False, "error": "payee_fetch_failed"})


@app.get("/health", operation_id="health_get")
def health() -> dict:
    return {"ok": True, "version": config.APP_VERSION}


@app.head("/health", include_in_schema=False)
def health_head() -> dict:
    return health()


@app.get("/.well-known/satsgate.json", operation_id="well_known_satsgate_get")
def well_known_satsgate(request: Request) -> dict:
    """Machine-readable manifest for discovery (agents/frameworks).

    Note: this does not replace OpenAPI; it complements it with pricing, auth, and links.
    """

    base_url = str(request.base_url).rstrip("/")

    return {
        "schema": "satsgate.manifest.v1",
        "name": "satsgate",
        "version": app.version,
        "token_version": TOKEN_VERSION,
        "description": "Lightning L402 paywall + prepaid payment verifications (credits). 1 verification = 1 successful paid unlock.",
        "generated_at": int(time.time()),
        "api": {
            "base_url": base_url,
            "openapi_url": f"{base_url}/openapi.json",
            "docs_url": f"{base_url}/docs",
            "redoc_url": f"{base_url}/redoc",
            "auth": [
                {"type": "header", "name": "X-Api-Key", "required": True},
                {
                    "type": "header",
                    "name": "Authorization",
                    "scheme": "L402",
                    "required_for": [
                        "/v1/paywall/verify",
                        "/v1/paywall/status/{payment_hash}",
                        "/v1/topup/{plan_id}",
                        "/v1/topup/status/{payment_hash}",
                    ],
                },
            ],
            "endpoints": {
                "plans": {"method": "GET", "path": "/v1/plans"},
                "topup": {"method": "GET", "path": "/v1/topup/{plan_id}"},
                "topup_status": {"method": "GET", "path": "/v1/topup/status/{payment_hash}"},
                "balance": {"method": "GET", "path": "/v1/balance"},
                "client": {"method": "GET", "path": "/v1/client"},
                "set_payee": {"method": "POST", "path": "/v1/client/payee"},
                "paywall_challenge": {"method": "POST", "path": "/v1/paywall/challenge"},
                "paywall_verify": {"method": "POST", "path": "/v1/paywall/verify"},
                "paywall_status": {"method": "GET", "path": "/v1/paywall/status/{payment_hash}"},
                "ledger": {"method": "GET", "path": "/v1/ledger"},
                "usage_summary": {"method": "GET", "path": "/v1/usage/summary"},
                "usage_daily": {"method": "GET", "path": "/v1/usage/daily"},
                "usage_forecast": {"method": "GET", "path": "/v1/usage/forecast"},
            },
        },
        "pricing": {
            "currency": "sats",
            "credit_definition": "1 credit (payment verification) = 1 successful /v1/paywall/verify (charged once per payment_hash). Credits do not expire.",
            "plans": list_plans(),
        },
        "links": {
            "health": f"{base_url}/health",
        },
    }


@app.head("/.well-known/satsgate.json", include_in_schema=False)
def well_known_satsgate_head(request: Request) -> dict:
    return well_known_satsgate(request)


@app.get("/v1/plans")
def v1_plans() -> dict:
    return {"ok": True, "plans": list_plans()}


@app.get("/v1/balance")
def v1_balance(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})
    return {"ok": True, "client_id": client.id, "credits": client.credits}


@app.get("/v1/client")
def v1_client(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    return {
        "ok": True,
        "client_id": client.id,
        "credits": client.credits,
        "payee_lightning_address": client.payee_lightning_address,
    }


@app.get("/v1/ledger")
def v1_ledger(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    limit: int = 50,
    before_id: int | None = None,
):
    """Return this client's verification ledger entries (credits)."""

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    entries = db_reports.list_ledger(
        config.DB_PATH,
        client_id=client.id,
        limit=limit,
        before_id=before_id,
    )

    next_before_id = entries[-1]["id"] if entries else None

    return {
        "ok": True,
        "client_id": client.id,
        "balance": client.credits,
        "entries": entries,
        "next_before_id": next_before_id,
    }


@app.get("/v1/usage/summary")
def v1_usage_summary(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    since_hours: int = 24,
):
    """Usage summary over a time window (default: last 24h)."""

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    since_hours = max(1, min(int(since_hours), 24 * 365))
    since_ts = int(time.time()) - (since_hours * 3600)

    summary = db_reports.usage_summary(config.DB_PATH, client_id=client.id, since_ts=since_ts)

    return {
        "ok": True,
        "client_id": client.id,
        "balance": client.credits,
        "window_hours": since_hours,
        "summary": summary,
    }


@app.get("/v1/usage/daily")
def v1_usage_daily(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    days: int = 30,
):
    """Daily (UTC) series for charts and automated top-ups."""

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    days = max(1, min(int(days), 366))

    daily = db_reports.usage_daily(config.DB_PATH, client_id=client.id, days=days)

    return {
        "ok": True,
        "client_id": client.id,
        "balance": client.credits,
        "daily": daily,
    }


@app.get("/v1/usage/forecast")
def v1_usage_forecast(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    lookback_hours: int = 24,
    buffer_days: int = 7,
    max_topups: int = 3,
    trigger_hours: int = 24,
):
    """Simple forecast + purchase recommendation.

    - Forecast: estimates hours/days remaining based on recent usage.
    - Recommendation: suggests a plan to keep a buffer (default: 7 days).
    """

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    lookback_hours = max(1, min(int(lookback_hours), 24 * 30))
    buffer_days = max(1, min(int(buffer_days), 365))
    max_topups = max(1, min(int(max_topups), 50))
    trigger_hours = max(0, min(int(trigger_hours), 24 * 365))

    forecast = db_reports.usage_forecast(
        config.DB_PATH,
        client_id=client.id,
        current_balance_credits=client.credits,
        lookback_hours=lookback_hours,
    )

    rate_per_day = float(forecast.get("verify_rate_credits_per_day") or 0.0)
    rate_per_hour = (rate_per_day / 24.0) if rate_per_day > 0 else 0.0
    now_ts = int(forecast.get("now_ts") or int(time.time()))

    # Minimum desired buffer (in credits) to cover `buffer_days` at the current pace.
    target_balance_credits = int(ceil(rate_per_day * float(buffer_days))) if rate_per_day > 0 else 0
    additional_credits_needed = max(0, target_balance_credits - int(client.credits))

    # When should we buy?
    credits_until_target: int | None = None
    # tiempo hasta llegar al "buffer" (target_balance_credits)
    topup_in_hours: float | None = None
    topup_in_days: float | None = None
    topup_at_ts: int | None = None
    topup_at_iso: str | None = None
    topup_now: bool | None = None

    # Trigger: recargar cuando falten <= trigger_hours para llegar al buffer
    trigger_now: bool | None = None
    trigger_in_hours: float | None = None
    trigger_at_ts: int | None = None
    trigger_at_iso: str | None = None

    if rate_per_hour > 0 and target_balance_credits > 0:
        credits_until_target = int(client.credits) - target_balance_credits

        # If you're at/below the buffer, recommend buying now.
        if credits_until_target <= 0:
            topup_in_hours = 0.0
        else:
            topup_in_hours = credits_until_target / rate_per_hour

        topup_in_days = topup_in_hours / 24.0
        topup_at_ts = int(now_ts + (topup_in_hours * 3600))
        topup_at_iso = datetime.fromtimestamp(topup_at_ts, tz=timezone.utc).isoformat()
        topup_now = topup_in_hours == 0.0

        # Trigger: sugerir recarga cuando falten <= trigger_hours para llegar al buffer
        trigger_now = topup_in_hours <= float(trigger_hours)
        trigger_in_hours = max(0.0, topup_in_hours - float(trigger_hours))
        trigger_at_ts = int(now_ts + (trigger_in_hours * 3600))
        trigger_at_iso = datetime.fromtimestamp(trigger_at_ts, tz=timezone.utc).isoformat()

    # What to buy when it's time to top up?
    credits_to_buy_recommended = 0
    recommended = None
    if rate_per_day > 0 and target_balance_credits > 0:
        # Typical buy: 1 full buffer. This tends to space top-ups ~buffer_days apart.
        credits_to_buy_recommended = target_balance_credits
        recommended = recommend_purchase(credits_to_buy_recommended, max_topups=max_topups)

    projected_balance = int(client.credits)
    if recommended:
        projected_balance += int(recommended.get("credits_total") or 0)

    projected_days_remaining = None
    if rate_per_day > 0:
        projected_days_remaining = projected_balance / rate_per_day

    recommendation_reason: str
    if rate_per_day <= 0 or topup_in_hours is None:
        recommendation_reason = "insufficient_data"
    elif topup_now is True:
        recommendation_reason = "topup_now"
    elif trigger_now is True:
        recommendation_reason = "trigger_now"
    else:
        recommendation_reason = "wait_until_trigger"

    return {
        "ok": True,
        "client_id": client.id,
        "balance": client.credits,
        "forecast": forecast,
        "recommendation": {
            "buffer_days": buffer_days,
            "max_topups": max_topups,
            "lookback_hours": lookback_hours,
            "rate_credits_per_day": rate_per_day,
            "target_balance_credits": target_balance_credits,
            "additional_credits_needed": additional_credits_needed,
            "credits_until_target": credits_until_target,
            "topup_now": topup_now,
            "topup_in_hours": topup_in_hours,
            "topup_in_days": topup_in_days,
            "topup_at_ts": topup_at_ts,
            "topup_at_iso": topup_at_iso,
            "trigger_hours": trigger_hours,
            "should_topup_now": trigger_now,
            "trigger_in_hours": trigger_in_hours,
            "trigger_at_ts": trigger_at_ts,
            "trigger_at_iso": trigger_at_iso,
            "credits_to_buy_recommended": credits_to_buy_recommended,
            "recommended_purchase": recommended,
            "projected_balance_after_purchase": projected_balance,
            "projected_days_remaining_after_purchase": projected_days_remaining,
            "reason": recommendation_reason,
            "note": "Suggested purchase aims to keep ~buffer_days of runway and reduce top-up friction.",
        },
    }


class ClientPayeeIn(BaseModel):
    payee_lightning_address: str = Field(..., min_length=3, max_length=200)


@app.post("/v1/client/payee")
def v1_client_set_payee(
    body: ClientPayeeIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    payee = body.payee_lightning_address.strip()
    if not _looks_like_lightning_address(payee):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_lightning_address"})

    try:
        db_clients.set_client_payee(config.DB_PATH, client_id=client.id, payee_lightning_address=payee)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})

    return {
        "ok": True,
        "client_id": client.id,
        "payee_lightning_address": payee,
        "note": "Saved. From now on /v1/paywall/challenge will use this payee by default.",
    }


@app.post("/v1/spend", include_in_schema=config.dev_endpoints_enabled())
def v1_spend(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    cost: int = 1,
):
    # Demo-only. Burning credits from a public route is not part of the paywall API.
    if not config.dev_endpoints_enabled():
        return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    try:
        new_balance = db.spend_credits(
            config.DB_PATH,
            client_id=client.id,
            cost=int(cost),
            reason="manual_spend",
            ref=None,
        )
        return {"ok": True, "client_id": client.id, "spent": int(cost), "new_balance": new_balance}
    except ValueError as e:
        return JSONResponse(status_code=402, content={"ok": False, "error": str(e)})


def _payment_hash_or_none(payment_hash: str) -> str | None:
    if len(payment_hash) != 64:
        return None
    try:
        raw = bytes.fromhex(payment_hash)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return payment_hash.lower()


def _pending_body(payment_hash: str) -> dict:
    return {
        "ok": True,
        "status": "pending",
        "settled": False,
        "payment_hash": payment_hash,
    }


def _lud21_state(*, verify_url: str, payment_hash: str, preimage_hex: str | None) -> str | JSONResponse:
    """Return 'settled', 'pending', or an error response. Never uses a client-supplied URL."""
    try:
        wallet_lnaddr.confirm_lud21(
            verify_url=verify_url,
            payment_hash=payment_hash,
            preimage_hex=preimage_hex,
        )
    except InvoiceValidationError as exc:
        if preimage_hex is None and exc.code == "lud21_not_settled":
            return "pending"
        status = 401 if exc.code in {"lud21_not_settled", "lud21_mismatch"} else 502
        return JSONResponse(status_code=status, content={"ok": False, "error": exc.code})
    except (ssrf.SSRFError, LnurlError) as exc:
        return _upstream_error(exc)
    return "settled"


def _topup_success_body(*, plan: dict | None, payment_hash: str, res: dict) -> dict:
    out = {
        "ok": True,
        "status": "settled",
        "settled": True,
        "payment_hash": payment_hash,
        "credits_added": res["credits_added"],
        "new_balance": res["new_balance"],
        "client_id": res["client_id"],
    }
    if plan is not None:
        out["plan"] = plan
    api_key = res.get("api_key")
    if api_key:
        out["api_key"] = api_key
        out["note"] = "Save this API key. We will not show it again."
    return out


def _claim_topup(
    *,
    authorization: str,
    resource: str,
    client: db.Client | None,
    plan: dict | None,
) -> JSONResponse | dict:
    """Settle a top-up from a preimage or, when we stored a verify URL, from LUD-21.

    The macaroon is the claim capability. A payment hash alone does not reveal
    the API key, and a replay does not credit twice or return the key again.
    """
    macaroon_b64, preimage_hex = parse_authorization_header(authorization)
    payload = parse_and_verify_macaroon(
        keys=config.MACAROON_KEYS,
        macaroon_b64=macaroon_b64,
        purpose=PURPOSE_TOPUP,
        resource=resource,
        client_id=client.id if client else None,
    )
    payment_hash = payload["ph"]
    if preimage_hex is not None:
        verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=payment_hash)

    topup = db.get_topup(config.DB_PATH, payment_hash)
    if not topup:
        return JSONResponse(status_code=404, content={"ok": False, "error": "topup_not_found"})

    if invoice_binding(topup["invoice"]) != payload["inv_h"]:
        raise L402Error("invoice mismatch")
    if int(payload["amt"]) != int(topup["sats"]):
        raise L402Error("amount mismatch")
    if payee_binding(config.LIGHTNING_ADDRESS or None) != payload["payee_h"]:
        raise L402Error("payee mismatch")

    topup_client_id = topup["client_id"]
    token_cid = payload.get("cid")
    if token_cid is not None and topup_client_id is not None and int(token_cid) != int(topup_client_id):
        raise L402Error("client mismatch")

    if topup["status"] != "settled":
        verify_url = topup["verify_url"]
        if preimage_hex is None and not verify_url:
            return JSONResponse(status_code=401, content={"ok": False, "error": "preimage_required"})
        if verify_url:
            state = _lud21_state(
                verify_url=str(verify_url),
                payment_hash=payment_hash,
                preimage_hex=preimage_hex,
            )
            if isinstance(state, JSONResponse):
                return state
            if state == "pending":
                return _pending_body(payment_hash)

    if topup_client_id is not None:
        credit_client_id: int | None = int(topup_client_id)
    elif token_cid is not None:
        credit_client_id = int(token_cid)
    elif client is not None:
        credit_client_id = client.id
    else:
        # Created inside the settlement transaction so two claims cannot mint two keys.
        credit_client_id = None

    res = db.settle_topup_and_credit(
        config.DB_PATH,
        payment_hash=payment_hash,
        client_id=credit_client_id,
    )
    return _topup_success_body(plan=plan, payment_hash=payment_hash, res=res)


@app.get("/v1/topup/status/{payment_hash}")
def v1_topup_status(
    payment_hash: str,
    authorization: str | None = Header(default=None),
):
    """Poll a top-up that was paid from any wallet.

    Authorization is `L402 <macaroon>` (no preimage) or the usual preimage form.
    Settlement is read from the verify URL stored when the invoice was created.
    The API key is returned only on the call that creates the account.
    """
    normalized = _payment_hash_or_none(payment_hash)
    if normalized is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_payment_hash"})
    if not authorization:
        return JSONResponse(status_code=401, content={"ok": False, "error": "missing credentials"})

    try:
        macaroon_b64, _preimage = parse_authorization_header(authorization)
        peeked = peek_bindings(macaroon_b64)
    except L402Error as exc:
        return JSONResponse(status_code=401, content={"ok": False, "error": str(exc)})

    resource = str(peeked.get("res") or "")
    peeked_hash = str(peeked.get("ph") or "").lower()
    if peeked_hash != normalized:
        return JSONResponse(status_code=401, content={"ok": False, "error": "payment_hash mismatch"})
    if not resource.startswith("v1/topup/") or "/" in resource.removeprefix("v1/topup/"):
        return JSONResponse(status_code=401, content={"ok": False, "error": "resource mismatch"})

    plan_body = None
    plan_id = resource.removeprefix("v1/topup/")
    if plan_id and "/" not in plan_id:
        try:
            plan_body = get_plan(plan_id).to_dict()
        except KeyError:
            plan_body = None

    try:
        result = _claim_topup(authorization=authorization, resource=resource, client=None, plan=plan_body)
    except L402Error as exc:
        return JSONResponse(status_code=401, content={"ok": False, "error": str(exc)})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    return result


@app.get("/v1/topup/{plan_id}")
def v1_topup(
    plan_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Buy prepaid payment verifications (credits) by plan.

    - No Authorization: 402 + invoice + macaroon
    - `Authorization: L402 <macaroon>:<preimage>`: credit the account
    - `Authorization: L402 <macaroon>`: credit the account when the provider's
      stored LUD-21 verify URL reports the invoice settled

    The preimage flow keeps working for providers that do not advertise verify.
    """

    try:
        plan = get_plan(plan_id)
    except KeyError as e:
        return JSONResponse(status_code=404, content={"ok": False, "error": str(e)})

    resource = f"v1/topup/{plan.id}"

    client = _get_client_from_api_key(x_api_key)

    if authorization:
        try:
            return _claim_topup(
                authorization=authorization,
                resource=resource,
                client=client,
                plan=plan.to_dict(),
            )
        except L402Error as e:
            return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})
        except ValueError as e:
            return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})

    # CREAR CHALLENGE (402)
    memo = f"satsgate topup {plan.id}"
    try:
        inv = WALLET.create_invoice(
            amount_sats=plan.price_sats,
            memo=memo,
            min_expiry_seconds=config.TOKEN_TTL_SECONDS,
        )
    except (ssrf.SSRFError, InvoiceValidationError, LnurlError, ValueError) as exc:
        return _upstream_error(exc)

    # Persist pending topup
    try:
        db.add_topup(
            config.DB_PATH,
            payment_hash=inv.payment_hash,
            invoice=inv.invoice,
            sats=plan.price_sats,
            credits=plan.credits,
            client_id=client.id if client else None,
            requester_ip=_peer_ip(request),
            verify_url=getattr(inv, "verify_url", None),
            expires_at=getattr(inv, "expires_at", None),
            max_pending_per_ip=config.MAX_PENDING_TOPUPS_PER_IP,
        )
    except ValueError as exc:
        if str(exc) == "too_many_pending_topups":
            return JSONResponse(
                status_code=429,
                content={"ok": False, "error": "too_many_pending_topups"},
            )
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})
    except Exception:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=PURPOSE_TOPUP,
        payment_hash=inv.payment_hash,
        resource=resource,
        amount_sats=plan.price_sats,
        invoice=inv.invoice,
        ttl_seconds=config.TOKEN_TTL_SECONDS,
        client_id=client.id if client else None,
        payee=config.LIGHTNING_ADDRESS or None,
    )

    www_auth = www_authenticate_header(macaroon=macaroon, invoice=inv.invoice)

    return JSONResponse(
        status_code=402,
        headers={"WWW-Authenticate": www_auth},
        content={
            "ok": False,
            "error": "payment_required",
            "plan": plan.to_dict(),
            "macaroon": macaroon,
            "invoice": inv.invoice,
            "payment_hash": inv.payment_hash,
            "expires_at": getattr(inv, "expires_at", None),
        },
    )


class PaywallChallengeIn(BaseModel):
    payee_lightning_address: str | None = Field(
        default=None,
        description=(
            "Lightning Address that will receive the payment (user@domain). "
            "If omitted, the client's registered payee is used (see /v1/client/payee)."
        ),
    )
    amount_sats: int = Field(..., ge=1, le=10_000_000)
    resource: str = Field(..., min_length=1, max_length=200)
    memo: str | None = Field(default=None, max_length=250)
    ttl_seconds: int | None = Field(default=None, ge=30, le=86_400)


class PaywallVerifyIn(BaseModel):
    expected_resource: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Resource this token must have been issued for. Required.",
    )
    cost_credits: int = Field(default=1, ge=1, le=10_000)


# Simple cache of LNURL-pay wallets by Lightning Address
PAYEE_WALLETS: dict[str, LightningAddressWallet] = {}


def _looks_like_lightning_address(addr: str) -> bool:
    # Minimal validation (MVP). For production: add SSRF mitigations.
    if not addr:
        return False
    if "@" not in addr:
        return False
    if "://" in addr:
        return False
    if "/" in addr:
        return False
    user, domain = addr.split("@", 1)
    if not user or not domain:
        return False
    if "." not in domain:
        return False
    return True


def _get_payee_wallet(lightning_address: str) -> LightningAddressWallet:
    w = PAYEE_WALLETS.get(lightning_address)
    if w is None:
        if len(PAYEE_WALLETS) >= 1024:
            PAYEE_WALLETS.pop(next(iter(PAYEE_WALLETS)))
        w = LightningAddressWallet(
            lightning_address,
            network=config.LN_NETWORK,
            send_comment=config.LNURL_SEND_COMMENT,
        )
        PAYEE_WALLETS[lightning_address] = w
    return w


@app.post("/v1/paywall/challenge")
def v1_paywall_challenge(
    body: PaywallChallengeIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Generate an L402 challenge for a resource.

    How to use it:
    - Your backend (customer) calls this endpoint and receives invoice + macaroon.
    - Your backend returns HTTP 402 to *your* end user with those values.
    """

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    ttl = int(body.ttl_seconds or config.TOKEN_TTL_SECONDS)
    memo = body.memo or "satsgate paywall"

    requested_payee = (body.payee_lightning_address or "").strip() or None
    stored_payee = (client.payee_lightning_address or "").strip() or None

    # Rule: each client has 1 registered payee. We do not allow changing it per request.
    if stored_payee:
        if requested_payee and requested_payee != stored_payee:
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error": "payee_mismatch",
                    "hint": "Your registered payee differs. Update it via POST /v1/client/payee.",
                },
            )
        payee = stored_payee
    else:
        # Fast onboarding: if no payee is set yet, allow setting it on the first challenge.
        if requested_payee:
            if not _looks_like_lightning_address(requested_payee):
                return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_lightning_address"})
            try:
                db_clients.set_client_payee(
                    config.DB_PATH,
                    client_id=client.id,
                    payee_lightning_address=requested_payee,
                )
            except ValueError as e:
                return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})
            payee = requested_payee
        elif config.WALLET_MODE == "mock":
            payee = None
        else:
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error": "client_payee_not_set",
                    "hint": "Set it via POST /v1/client/payee (or include payee_lightning_address in the request body).",
                },
            )

    # Generate invoice
    try:
        if config.WALLET_MODE == "mock":
            inv = WALLET.create_invoice(
                amount_sats=int(body.amount_sats),
                memo=memo,
                expiry_seconds=ttl,
                min_expiry_seconds=ttl,
            )
        else:
            if not payee or not _looks_like_lightning_address(payee):
                return JSONResponse(status_code=400, content={"ok": False, "error": "payee_invalid_lightning_address"})
            inv = _get_payee_wallet(payee).create_invoice(
                amount_sats=int(body.amount_sats),
                memo=memo,
                min_expiry_seconds=ttl,
            )
    except (ssrf.SSRFError, InvoiceValidationError, LnurlError, ValueError) as exc:
        return _upstream_error(exc)

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=PURPOSE_PAYWALL,
        payment_hash=inv.payment_hash,
        resource=body.resource,
        amount_sats=int(body.amount_sats),
        invoice=inv.invoice,
        ttl_seconds=ttl,
        client_id=client.id,
        payee=payee,
    )

    try:
        db.add_paywall_challenge(
            config.DB_PATH,
            payment_hash=inv.payment_hash,
            client_id=client.id,
            invoice=inv.invoice,
            amount_sats=int(body.amount_sats),
            payee=payee,
            resource=body.resource,
            verify_url=getattr(inv, "verify_url", None),
            expires_at=int(time.time()) + ttl,
            max_open_per_client=config.MAX_OPEN_CHALLENGES_PER_CLIENT,
        )
    except ValueError as exc:
        if str(exc) == "too_many_open_challenges":
            return JSONResponse(status_code=429, content={"ok": False, "error": "too_many_open_challenges"})
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})
    except Exception:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})

    www_auth = www_authenticate_header(macaroon=macaroon, invoice=inv.invoice)

    return {
        "ok": True,
        "resource": body.resource,
        "amount_sats": int(body.amount_sats),
        "payee_lightning_address": payee,
        "macaroon": macaroon,
        "invoice": inv.invoice,
        "payment_hash": inv.payment_hash,
        "valid_until": int(time.time()) + ttl,
        "www_authenticate": www_auth,
        "token_version": TOKEN_VERSION,
    }


def _paywall_lud21(*, verify_url: str, payment_hash: str, preimage_hex: str | None) -> str | JSONResponse:
    try:
        wallet_lnaddr.confirm_lud21(
            verify_url=verify_url,
            payment_hash=payment_hash,
            preimage_hex=preimage_hex,
        )
    except InvoiceValidationError as exc:
        if preimage_hex is None and exc.code == "lud21_not_settled":
            return "pending"
        status = 401 if exc.code in {"lud21_not_settled", "lud21_mismatch"} else 502
        return JSONResponse(status_code=status, content={"ok": False, "error": exc.code})
    except (ssrf.SSRFError, LnurlError):
        return JSONResponse(status_code=502, content={"ok": False, "error": "lud21_unavailable"})
    return "settled"


def _unlock_paywall(
    *,
    authorization: str | None,
    expected_resource: str,
    cost_credits: int,
    client: db.Client,
    payment_hash: str | None = None,
    poll: bool = False,
) -> JSONResponse | dict:
    macaroon_b64, preimage_hex = parse_authorization_header(authorization)
    payload = parse_and_verify_macaroon(
        keys=config.MACAROON_KEYS,
        macaroon_b64=macaroon_b64,
        purpose=PURPOSE_PAYWALL,
        resource=expected_resource,
        client_id=client.id,
    )

    token_hash = payload["ph"]
    if payment_hash is not None and token_hash != payment_hash:
        raise L402Error("payment_hash mismatch")
    if preimage_hex is not None:
        verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=token_hash)

    row = db.get_paywall_challenge(config.DB_PATH, token_hash)
    if row is None or int(row["client_id"]) != int(client.id):
        raise L402Error("client mismatch")
    if row["resource"] != expected_resource or payload.get("res") != expected_resource:
        raise L402Error("resource mismatch")
    if int(row["amount_sats"]) != int(payload["amt"]):
        raise L402Error("amount mismatch")
    if invoice_binding(row["invoice"]) != payload["inv_h"]:
        raise L402Error("invoice mismatch")
    if payee_binding(row["payee"]) != payload["payee_h"]:
        raise L402Error("payee mismatch")

    already = db_verify.has_verification(config.DB_PATH, client_id=client.id, payment_hash=token_hash)
    if preimage_hex is None and not already and not row["verify_url"]:
        return JSONResponse(status_code=401, content={"ok": False, "error": "preimage_required"})

    if not already and row["verify_url"]:
        state = _paywall_lud21(
            verify_url=str(row["verify_url"]),
            payment_hash=token_hash,
            preimage_hex=preimage_hex,
        )
        if isinstance(state, JSONResponse):
            return state
        if state == "pending":
            if poll:
                return _pending_body(token_hash)
            return JSONResponse(
                status_code=402,
                content={"ok": False, "error": "payment_pending", "settled": False, "payment_hash": token_hash},
            )

    spend = db_verify.verify_once_and_spend(
        config.DB_PATH,
        client_id=client.id,
        payment_hash=token_hash,
        cost=int(cost_credits),
        resource=expected_resource,
    )

    return {
        "ok": True,
        "status": "settled",
        "settled": True,
        "client_id": client.id,
        "resource": expected_resource,
        "amount_sats": int(row["amount_sats"]),
        "payee_lightning_address": row["payee"],
        "payment_hash": token_hash,
        "charged_credits": spend["charged"],
        "new_balance": spend["new_balance"],
        "valid_until": payload.get("exp"),
        "note": "Cache by payment_hash until valid_until to avoid calling verify on every request.",
    }


@app.post("/v1/paywall/verify")
def v1_paywall_verify(
    body: PaywallVerifyIn,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Verify an L402 Authorization and spend payment verifications (credits) (once per payment_hash).

    This is the core of the "plans + prepay" model:
    - the customer tops up payment verifications (credits)
    - each verified payment consumes 1 verification (credit) (exactly once per payment_hash)

    `Authorization: L402 <macaroon>:<preimage>` is the original flow.
    `Authorization: L402 <macaroon>` settles from the stored LUD-21 verify URL when the
    payee's provider advertised one.
    """

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    try:
        return _unlock_paywall(
            authorization=authorization,
            expected_resource=body.expected_resource,
            cost_credits=int(body.cost_credits),
            client=client,
        )
    except L402Error as e:
        return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})
    except ValueError as e:
        # insufficient balance / client missing
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(e),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
        )


@app.get("/v1/paywall/status/{payment_hash}")
def v1_paywall_status(
    payment_hash: str,
    expected_resource: str = Query(..., min_length=1, max_length=200),
    cost_credits: int = Query(default=1, ge=1, le=10_000),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Poll a paywall challenge paid from any wallet.

    Requires the merchant API key and the macaroon issued for this payment hash.
    Credits are spent once, when the stored LUD-21 URL reports the invoice settled.
    """
    normalized = _payment_hash_or_none(payment_hash)
    if normalized is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_payment_hash"})

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    try:
        return _unlock_paywall(
            authorization=authorization,
            expected_resource=expected_resource,
            cost_credits=int(cost_credits),
            client=client,
            payment_hash=normalized,
            poll=True,
        )
    except L402Error as e:
        return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})
    except ValueError as e:
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(e),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
        )


@app.get("/v1/tickets", include_in_schema=config.dev_endpoints_enabled())
def get_ticket(authorization: str | None = Header(default=None)):
    """Demo endpoint (direct pay-per-access, no credits).

    - Without Authorization => responds 402 + challenge (macaroon + invoice)
    - With a valid L402 Authorization => returns a "ticket" (access granted)

    In real life, this would be a protected resource (e.g. /api/resource).
    """

    if not config.dev_endpoints_enabled():
        return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})

    resource = "v1/tickets"

    # 1) Si viene credencial, verificamos
    if authorization:
        try:
            macaroon_b64, preimage_hex = parse_authorization_header(authorization)
            payload = parse_and_verify_macaroon(
                keys=config.MACAROON_KEYS,
                macaroon_b64=macaroon_b64,
                purpose=PURPOSE_TICKET,
                resource=resource,
            )
            payment_hash = payload["ph"]
            if preimage_hex is not None:
                verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=payment_hash)

            row = db.get_ticket_challenge(config.DB_PATH, payment_hash)
            if row is None or row["resource"] != resource:
                raise L402Error("invoice mismatch")
            if int(row["amount_sats"]) != int(payload["amt"]):
                raise L402Error("amount mismatch")
            if invoice_binding(row["invoice"]) != payload["inv_h"]:
                raise L402Error("invoice mismatch")
            if payee_binding(row["payee"]) != payload["payee_h"]:
                raise L402Error("payee mismatch")

            already = row["settled_at"] is not None
            if preimage_hex is None and not already and not row["verify_url"]:
                return JSONResponse(status_code=401, content={"ok": False, "error": "preimage_required"})
            if not already and row["verify_url"]:
                state = _paywall_lud21(
                    verify_url=str(row["verify_url"]),
                    payment_hash=payment_hash,
                    preimage_hex=preimage_hex,
                )
                if isinstance(state, JSONResponse):
                    return state
                if state == "pending":
                    return JSONResponse(
                        status_code=402,
                        content={
                            "ok": False,
                            "error": "payment_pending",
                            "settled": False,
                            "payment_hash": payment_hash,
                        },
                    )
            if not already and preimage_hex is None and not row["verify_url"]:
                return JSONResponse(status_code=401, content={"ok": False, "error": "preimage_required"})

            db.mark_ticket_settled(config.DB_PATH, payment_hash=payment_hash)
            return {
                "ok": True,
                "status": "settled",
                "settled": True,
                "ticket": {
                    "resource": resource,
                    "payment_hash": payment_hash,
                    "expires_at": payload["exp"],
                },
                "note": "You can reuse the same L402 Authorization until it expires (TTL).",
            }
        except L402Error as e:
            return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})

    # 2) Si no viene credencial, generamos challenge
    memo = "satsgate ticket"
    try:
        inv = WALLET.create_invoice(
            amount_sats=config.PRICE_SATS,
            memo=memo,
            min_expiry_seconds=config.TOKEN_TTL_SECONDS,
        )
    except (ssrf.SSRFError, InvoiceValidationError, LnurlError, ValueError) as exc:
        return _upstream_error(exc)

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=PURPOSE_TICKET,
        payment_hash=inv.payment_hash,
        resource=resource,
        amount_sats=config.PRICE_SATS,
        invoice=inv.invoice,
        ttl_seconds=config.TOKEN_TTL_SECONDS,
        client_id=None,
        payee=config.LIGHTNING_ADDRESS or None,
    )

    try:
        db.add_ticket_challenge(
            config.DB_PATH,
            payment_hash=inv.payment_hash,
            invoice=inv.invoice,
            amount_sats=config.PRICE_SATS,
            payee=config.LIGHTNING_ADDRESS or None,
            resource=resource,
            verify_url=getattr(inv, "verify_url", None),
            expires_at=int(getattr(inv, "expires_at", None) or (int(time.time()) + config.TOKEN_TTL_SECONDS)),
        )
    except ValueError as exc:
        if str(exc) == "too_many_open_challenges":
            return JSONResponse(status_code=429, content={"ok": False, "error": "too_many_open_challenges"})
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})
    except Exception:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})

    www_auth = www_authenticate_header(macaroon=macaroon, invoice=inv.invoice)

    return JSONResponse(
        status_code=402,
        headers={"WWW-Authenticate": www_auth},
        content={
            "ok": False,
            "error": "payment_required",
            "price_sats": config.PRICE_SATS,
            "macaroon": macaroon,
            "invoice": inv.invoice,
            "payment_hash": inv.payment_hash,
            "expires_at": getattr(inv, "expires_at", None),
        },
    )


@app.get("/dev/mock/pay/{payment_hash}", include_in_schema=config.dev_endpoints_enabled())
def dev_mock_pay(payment_hash: str):
    """DEV ONLY: if the wallet backend is mock, return the preimage for payment_hash."""
    if not config.dev_endpoints_enabled():
        return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})

    if not hasattr(WALLET, "dev_get_preimage"):
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "wallet_backend_does_not_support_mock_pay",
                "hint": "Use SATSGATE_WALLET_MODE=mock for this endpoint.",
            },
        )

    preimage_hex = WALLET.dev_get_preimage(payment_hash)
    if not preimage_hex:
        return JSONResponse(status_code=404, content={"ok": False, "error": "payment_hash_not_found_or_expired"})

    return {"ok": True, "payment_hash": payment_hash, "preimage": preimage_hex}
