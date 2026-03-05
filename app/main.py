from __future__ import annotations

import time
from datetime import datetime, timezone
from math import ceil
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config
from . import db
from . import db_clients
from . import db_reports
from .rate_limit import RateLimiter
from . import db_verify
from .l402 import (
    L402Error,
    make_macaroon,
    parse_and_verify_macaroon,
    parse_authorization_header,
    verify_preimage_matches_payment_hash,
)
from .mock_wallet import MockWallet
from .plans import get_plan, list_plans, recommend_purchase
from .wallet_lnaddr import LightningAddressWallet
from .admin import router as admin_router

app = FastAPI(title="satsgate", version="0.2.0")

app.include_router(admin_router)


def _get_wallet() -> Any:
    if config.WALLET_MODE == "mock":
        return MockWallet()
    if config.WALLET_MODE == "lnaddr":
        if not config.LIGHTNING_ADDRESS:
            raise RuntimeError("SATSGATE_LIGHTNING_ADDRESS is required when SATSGATE_WALLET_MODE=lnaddr")
        return LightningAddressWallet(config.LIGHTNING_ADDRESS)
    raise RuntimeError(f"Invalid SATSGATE_WALLET_MODE: {config.WALLET_MODE}")


# Note: for a simple MVP we keep it global.
# In production, prefer dependency injection with lifespan and a reusable HTTP client.
WALLET = _get_wallet()

# DB init
try:
    db.init_db(config.DB_PATH)
except Exception as e:  # noqa: BLE001
    raise RuntimeError(f"Failed to initialize DB at {config.DB_PATH}: {e}") from e

# Rate limiters
RL_ANON = RateLimiter(window_seconds=config.RL_WINDOW_SECONDS, max_requests=config.RL_MAX_ANON)
RL_AUTH = RateLimiter(window_seconds=config.RL_WINDOW_SECONDS, max_requests=config.RL_MAX_AUTH)


def _get_client_from_api_key(x_api_key: str | None) -> db.Client | None:
    if not x_api_key:
        return None
    return db.get_client_by_api_key(config.DB_PATH, x_api_key)


def _rate_limit_key(request: Request, x_api_key: str | None) -> tuple[str, bool]:
    """Returns (key, is_auth)."""
    if x_api_key:
        # store only the hash (not the raw api key) to reduce accidental leaks in memory/logs
        return "k:" + db.hash_api_key(x_api_key), True

    ip = request.client.host if request.client else "unknown"
    return "ip:" + ip, False


@app.middleware("http")
async def rate_limit_mw(request: Request, call_next):
    if not config.RL_ENABLED:
        return await call_next(request)

    # Apply RL only to /v1 (API). Health and other endpoints remain free.
    if not request.url.path.startswith("/v1"):
        return await call_next(request)

    x_api_key = request.headers.get("x-api-key")
    key, is_auth = _rate_limit_key(request, x_api_key)

    limiter = RL_AUTH if is_auth else RL_ANON
    allowed, retry_after = limiter.allow(key)
    if not allowed:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "ok": False,
                "error": "rate_limited",
                "retry_after_seconds": retry_after,
            },
        )

    return await call_next(request)


@app.api_route("/health", methods=["GET", "HEAD"])
def health() -> dict:
    return {
        "ok": True,
        "wallet_mode": config.WALLET_MODE,
        "receive_lightning_address": config.LIGHTNING_ADDRESS if config.WALLET_MODE == "lnaddr" else None,
        "price_sats_demo": config.PRICE_SATS,
        "token_ttl_seconds": config.TOKEN_TTL_SECONDS,
        "db_path": config.DB_PATH,
        "time": int(time.time()),
    }


@app.api_route("/.well-known/satsgate.json", methods=["GET", "HEAD"])
def well_known_satsgate(request: Request) -> dict:
    """Machine-readable manifest for discovery (agents/frameworks).

    Note: this does not replace OpenAPI; it complements it with pricing, auth, and links.
    """

    base_url = str(request.base_url).rstrip("/")

    return {
        "schema": "satsgate.manifest.v1",
        "name": "satsgate",
        "version": app.version,
        "description": "Lightning L402 paywall + prepaid credits (1 credit = 1 successful verification)",
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
                    "required_for": ["/v1/paywall/verify", "/v1/topup/{plan_id}", "/v1/tickets"],
                },
            ],
            "endpoints": {
                "plans": {"method": "GET", "path": "/v1/plans"},
                "topup": {"method": "GET", "path": "/v1/topup/{plan_id}"},
                "balance": {"method": "GET", "path": "/v1/balance"},
                "client": {"method": "GET", "path": "/v1/client"},
                "set_payee": {"method": "POST", "path": "/v1/client/payee"},
                "paywall_challenge": {"method": "POST", "path": "/v1/paywall/challenge"},
                "paywall_verify": {"method": "POST", "path": "/v1/paywall/verify"},
                "ledger": {"method": "GET", "path": "/v1/ledger"},
                "usage_summary": {"method": "GET", "path": "/v1/usage/summary"},
                "usage_daily": {"method": "GET", "path": "/v1/usage/daily"},
                "usage_forecast": {"method": "GET", "path": "/v1/usage/forecast"},
            },
        },
        "pricing": {
            "currency": "sats",
            "credit_definition": "1 credit = 1 successful /v1/paywall/verify",
            "plans": list_plans(),
        },
        "links": {
            "health": f"{base_url}/health",
        },
    }


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
    """Return this client's credit ledger entries."""

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


@app.post("/v1/spend")
def v1_spend(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    cost: int = 1,
):
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


@app.get("/v1/topup/{plan_id}")
def v1_topup(
    plan_id: str,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Buy prepaid credits by plan.

    - If there is NO Authorization => 402 + invoice + macaroon
    - If a valid L402 Authorization is provided => credits are added and balance is returned (+ API key if new)

    Note: payment is verified *only* via the preimage (L402). We do not depend on wallet webhooks.
    """

    try:
        plan = get_plan(plan_id)
    except KeyError as e:
        return JSONResponse(status_code=404, content={"ok": False, "error": str(e)})

    resource = f"v1/topup/{plan.id}"

    client = _get_client_from_api_key(x_api_key)

    # FINALIZAR (si trae Authorization)
    if authorization:
        try:
            macaroon_b64, preimage_hex = parse_authorization_header(authorization)
            payload = parse_and_verify_macaroon(
                secret=config.MACAROON_SECRET,
                macaroon_b64=macaroon_b64,
                resource=resource,
            )
            payment_hash = payload["ph"]
            verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=payment_hash)

            topup = db.get_topup(config.DB_PATH, payment_hash)
            if not topup:
                return JSONResponse(status_code=404, content={"ok": False, "error": "topup_not_found"})

            # If the topup is already linked to a client, respect it.
            topup_client_id = topup["client_id"]

            api_key_out: str | None = None
            if topup_client_id is not None:
                client_id = int(topup_client_id)
            elif client is not None:
                client_id = client.id
            else:
                api_key_out, new_client = db.create_client(config.DB_PATH)
                client_id = new_client.id

            res = db.settle_topup_and_credit(config.DB_PATH, payment_hash=payment_hash, client_id=client_id)

            out = {
                "ok": True,
                "plan": plan.to_dict(),
                "payment_hash": payment_hash,
                "credits_added": res["credits_added"],
                "new_balance": res["new_balance"],
                "client_id": client_id,
            }
            if api_key_out:
                out["api_key"] = api_key_out
                out["note"] = "Save this API key. We will not show it again."
            return out

        except L402Error as e:
            return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})
        except ValueError as e:
            return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})

    # CREAR CHALLENGE (402)
    memo = f"satsgate topup {plan.id}"
    inv = WALLET.create_invoice(amount_sats=plan.price_sats, memo=memo)

    # Persist pending topup
    try:
        db.add_topup(
            config.DB_PATH,
            payment_hash=inv.payment_hash,
            invoice=inv.invoice,
            sats=plan.price_sats,
            credits=plan.credits,
            client_id=client.id if client else None,
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"ok": False, "error": f"db_error: {e}"})

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        payment_hash=inv.payment_hash,
        resource=resource,
        ttl_seconds=config.TOKEN_TTL_SECONDS,
    )

    www_auth = f'L402 macaroon="{macaroon}", invoice="{inv.invoice}"'

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
    expected_resource: str | None = Field(
        default=None,
        description="If provided, requires that the token was issued for this resource.",
        max_length=200,
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
        w = LightningAddressWallet(lightning_address)
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
    if config.WALLET_MODE == "mock":
        inv = WALLET.create_invoice(amount_sats=int(body.amount_sats), memo=memo, expiry_seconds=ttl)
    else:
        if not payee or not _looks_like_lightning_address(payee):
            return JSONResponse(status_code=400, content={"ok": False, "error": "payee_invalid_lightning_address"})
        inv = _get_payee_wallet(payee).create_invoice(amount_sats=int(body.amount_sats), memo=memo)

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        payment_hash=inv.payment_hash,
        resource=body.resource,
        ttl_seconds=ttl,
    )

    www_auth = f'L402 macaroon="{macaroon}", invoice="{inv.invoice}"'

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
    }


@app.post("/v1/paywall/verify")
def v1_paywall_verify(
    body: PaywallVerifyIn,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Verify an L402 Authorization and spend credits (once per payment_hash).

    This is the core of the "plans + prepay" model:
    - the customer buys credits
    - each verified payment consumes credits (exactly once per payment_hash)
    """

    client = _get_client_from_api_key(x_api_key)
    if not client:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})

    try:
        macaroon_b64, preimage_hex = parse_authorization_header(authorization)
        payload = parse_and_verify_macaroon(
            secret=config.MACAROON_SECRET,
            macaroon_b64=macaroon_b64,
            resource=None,
        )

        if body.expected_resource and payload.get("res") != body.expected_resource:
            raise L402Error("resource mismatch")

        payment_hash = payload["ph"]
        verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=payment_hash)

        spend = db_verify.verify_once_and_spend(
            config.DB_PATH,
            client_id=client.id,
            payment_hash=payment_hash,
            cost=int(body.cost_credits),
            resource=str(payload.get("res")),
        )

        return {
            "ok": True,
            "client_id": client.id,
            "resource": payload.get("res"),
            "payment_hash": payment_hash,
            "charged_credits": spend["charged"],
            "new_balance": spend["new_balance"],
            "valid_until": payload.get("exp"),
            "note": "Cache by payment_hash until valid_until to avoid calling verify on every request.",
        }

    except L402Error as e:
        return JSONResponse(status_code=401, content={"ok": False, "error": str(e)})
    except ValueError as e:
        # insufficient balance / client missing
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(e),
                "hint": "Top up credits: GET /v1/plans then /v1/topup/{plan_id}",
            },
        )


@app.get("/v1/tickets")
def get_ticket(authorization: str | None = Header(default=None)):
    """Demo endpoint (direct pay-per-access, no credits).

    - Without Authorization => responds 402 + challenge (macaroon + invoice)
    - With a valid L402 Authorization => returns a "ticket" (access granted)

    In real life, this would be a protected resource (e.g. /api/resource).
    """

    resource = "v1/tickets"

    # 1) Si viene credencial, verificamos
    if authorization:
        try:
            macaroon_b64, preimage_hex = parse_authorization_header(authorization)
            payload = parse_and_verify_macaroon(
                secret=config.MACAROON_SECRET,
                macaroon_b64=macaroon_b64,
                resource=resource,
            )
            payment_hash = payload["ph"]
            verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=payment_hash)

            return {
                "ok": True,
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
    inv = WALLET.create_invoice(amount_sats=config.PRICE_SATS, memo=memo)

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        payment_hash=inv.payment_hash,
        resource=resource,
        ttl_seconds=config.TOKEN_TTL_SECONDS,
    )

    www_auth = f'L402 macaroon="{macaroon}", invoice="{inv.invoice}"'

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


@app.get("/dev/mock/pay/{payment_hash}")
def dev_mock_pay(payment_hash: str):
    """DEV ONLY: if the wallet backend is mock, return the preimage for payment_hash."""
    if not config.DEV_MODE:
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
