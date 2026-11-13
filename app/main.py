from __future__ import annotations

import json
import logging
import threading
import time
from urllib.parse import urlsplit
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import config
from . import db
from . import db_account_key
from . import db_alert_email
from . import db_clients
from . import db_keys
from . import db_webhooks
from . import email_send
from . import webhook_send
from . import db_reports
from . import db_sites
from . import db_verify
from . import db_x402
from . import rates
from . import x402 as x402_mod
from . import ssrf
from . import wallet_lnaddr
from .admin import router as admin_router
from .internal_gate import _lock_lightning_offer, router as internal_gate_router
from .client_ip import buyer_ip_from_trusted_proxy, hash_buyer_ip, resolve_client_ip
from .invoices import InvoiceValidationError, bolt11_expiry_unix
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
from .plans import get_plan
from .quota import FundsRefused
from .rate_limit import RateLimiter
from .wallet_lnaddr import LightningAddressWallet, LnurlError


_log = logging.getLogger("satsgate")


def _rates_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            rates.refresh()
        except Exception:
            _log.warning("btc/usd refresh failed")
        stop.wait(config.RATES_REFRESH_SECONDS)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    stop = threading.Event()
    thread = None
    if config.RATES_ENABLED:
        thread = threading.Thread(target=_rates_loop, args=(stop,), name="satsgate-rates", daemon=True)
        thread.start()
    email_stop = threading.Event()
    email_thread = None
    if email_send.sender_should_run():
        email_thread = threading.Thread(
            target=email_send.loop, args=(email_stop,), name="satsgate-email", daemon=True
        )
        email_thread.start()
    webhook_stop = threading.Event()
    webhook_thread = None
    if webhook_send.sender_should_run():
        webhook_thread = threading.Thread(
            target=webhook_send.loop, args=(webhook_stop,), name="satsgate-webhook", daemon=True
        )
        webhook_thread.start()
    try:
        yield
    finally:
        stop.set()
        email_stop.set()
        webhook_stop.set()
        email_send.wake.set()
        webhook_send.wake.set()
        if thread is not None:
            thread.join(timeout=1)
        if email_thread is not None:
            email_thread.join(timeout=1)
        if webhook_thread is not None:
            webhook_thread.join(timeout=1)
        ssrf.close()


app = FastAPI(title="satsgate", version=config.APP_VERSION, lifespan=_lifespan)

app.include_router(admin_router)
app.include_router(internal_gate_router)


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
# Keyed by client id. A new account key must not reset this bucket.
RL_SECURITY = RateLimiter(
    window_seconds=config.RL_WINDOW_SECONDS,
    max_requests=config.RL_MAX_SECURITY,
    max_keys=config.RL_MAX_KEYS,
)
_SECURITY_LIMIT_PATHS = frozenset(
    {
        ("POST", "/v1/client/api-key/rotate"),
        ("PUT", "/v1/client/webhook"),
        ("DELETE", "/v1/client/webhook"),
        ("POST", "/v1/client/webhook/test"),
    }
)
_MAX_WEBHOOK_BODY = 2048


def _authenticate(x_api_key: str | None) -> db_keys.Principal | JSONResponse:
    if not x_api_key or len(x_api_key) > 512:
        return JSONResponse(status_code=401, content={"ok": False, "error": "invalid_api_key"})
    try:
        return db_keys.authenticate(config.DB_PATH, x_api_key)
    except db_keys.AuthError as exc:
        return JSONResponse(status_code=401, content={"ok": False, "error": exc.code})


def _insufficient_scope(scope: str) -> JSONResponse:
    if scope == db_keys.SCOPE_PAYWALL:
        detail = "This API key can only create paywall challenges, check their status, and verify them."
    elif scope == db_keys.SCOPE_SITES_READ:
        detail = "This API key can only read this account's sites."
    elif scope == db_keys.SCOPE_SITES_WRITE:
        detail = "This API key can manage this account's sites, not the paywall or the account."
    else:
        detail = "This API key does not allow that call."
    return JSONResponse(
        status_code=403,
        content={"ok": False, "error": "insufficient_scope", "scope": scope, "detail": detail},
    )


def _account_client(x_api_key: str | None) -> db.Client | JSONResponse:
    """Account key only. Restricted keys get insufficient_scope."""
    auth = _authenticate(x_api_key)
    if isinstance(auth, JSONResponse):
        return auth
    if auth.scope != db_keys.SCOPE_ACCOUNT:
        return _insufficient_scope(auth.scope)
    return auth.client


def _reader_client(x_api_key: str | None) -> db.Client | JSONResponse:
    """Account key or restricted key. Reads only: balance, quota, forecast, advice."""
    auth = _authenticate(x_api_key)
    if isinstance(auth, JSONResponse):
        return auth
    if auth.scope not in {db_keys.SCOPE_ACCOUNT, db_keys.SCOPE_PAYWALL, db_keys.SCOPE_SITES_READ, db_keys.SCOPE_SITES_WRITE}:
        return _insufficient_scope(auth.scope)
    return auth.client


def _connect_session(token: str | None) -> dict | JSONResponse:
    """Connect-link session. An API key in this header is not a connect token."""
    if not token or len(token) > 200:
        return JSONResponse(status_code=401, content={"ok": False, "error": "connect_link_invalid"})
    try:
        return db_x402.connect_session(config.DB_PATH, token)
    except x402_mod.X402Error as exc:
        return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code})


def _paywall_principal(x_api_key: str | None, resource: str) -> db_keys.Principal | JSONResponse:
    """Account or restricted key, limited to the key's resource prefix when one is set."""
    auth = _authenticate(x_api_key)
    if isinstance(auth, JSONResponse):
        return auth
    if auth.scope not in {db_keys.SCOPE_ACCOUNT, db_keys.SCOPE_PAYWALL}:
        return _insufficient_scope(auth.scope)
    prefix = auth.resource_prefix
    if prefix and not resource.startswith(prefix):
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "resource_not_allowed",
                "resource": resource,
                "resource_prefix": prefix,
                "detail": "This API key can only use resources that start with its resource_prefix.",
            },
        )
    return auth


def _topup_client(x_api_key: str | None) -> db.Client | JSONResponse | None:
    """Client to attach a top-up to.

    Missing or unknown account keys stay anonymous, matching previous behaviour.
    A restricted key is rejected: it must not buy credits or open a new account.
    """
    if not x_api_key or len(x_api_key) > 512:
        return None
    if db_keys.key_kind(x_api_key) == "restricted":
        try:
            auth = db_keys.authenticate(config.DB_PATH, x_api_key)
        except db_keys.AuthError as exc:
            return JSONResponse(status_code=401, content={"ok": False, "error": exc.code})
        return _insufficient_scope(auth.scope)
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
    client = None
    if raw_key and len(raw_key) <= 512:
        client = db_keys.client_for_rate_limit(config.DB_PATH, raw_key)
    if client is not None and raw_key is not None:
        # Hash only. A random key must not open its own auth bucket.
        blocked = _reject_if_limited(RL_AUTH, "k:" + db.hash_api_key(raw_key))
    else:
        blocked = _reject_if_limited(RL_ANON, "ip:" + ip)
    if blocked:
        return blocked

    path = request.url.path
    # Only a live account key spends this bucket. A restricted key, a connect
    # token, or an unknown key is rejected by the route and must not lock the
    # owner out of rotation or webhook changes. The client id is stable across
    # account-key rotation, so a new sg_ key does not reset the bucket.
    if (
        client is not None
        and raw_key is not None
        and db_keys.key_kind(raw_key) == db_keys.SCOPE_ACCOUNT
        and (request.method, path) in _SECURITY_LIMIT_PATHS
    ):
        blocked = _reject_if_limited(RL_SECURITY, "s:" + str(client.id))
        if blocked:
            return blocked
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


@app.get("/v1/rates")
def v1_rates():
    """BTC/USD median. A quote for merchants. Not a price Satsgate converts at."""
    view = rates.snapshot()
    return {
        "ok": True,
        "pair": "BTC-USD",
        "value": view["value"],
        "sources": view["sources"],
        "fetched_at": view["fetched_at"],
        "status": view["status"],
    }


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
                "topup_x402": {"method": "GET", "path": "/v1/topup/{plan_id}/x402"},
                "topup_status": {"method": "GET", "path": "/v1/topup/status/{payment_hash}"},
                "balance": {"method": "GET", "path": "/v1/balance"},
                "client": {"method": "GET", "path": "/v1/client"},
                "set_payee": {"method": "POST", "path": "/v1/client/payee"},
                "evm_payee_challenge": {"method": "POST", "path": "/v1/client/payee/evm/challenge"},
                "evm_payee": {"method": "POST", "path": "/v1/client/payee/evm"},
                "evm_payee_connect": {"method": "POST", "path": "/v1/client/payee/evm/connect"},
                "alert_email": {"method": "PUT", "path": "/v1/client/alert-email"},
                "alert_email_delete": {"method": "DELETE", "path": "/v1/client/alert-email"},
                "api_key_rotate": {"method": "POST", "path": "/v1/client/api-key/rotate"},
                "webhook": {"method": "PUT", "path": "/v1/client/webhook"},
                "webhook_get": {"method": "GET", "path": "/v1/client/webhook"},
                "webhook_delete": {"method": "DELETE", "path": "/v1/client/webhook"},
                "webhook_test": {"method": "POST", "path": "/v1/client/webhook/test"},
                "connect_evm": {"method": "GET", "path": "/v1/connect/evm"},
                "connect_evm_challenge": {"method": "POST", "path": "/v1/connect/evm/challenge"},
                "connect_evm_verify": {"method": "POST", "path": "/v1/connect/evm/verify"},
                "connect_alert_email": {"method": "POST", "path": "/v1/connect/alert-email"},
                "connect_alert_email_preview": {"method": "GET", "path": "/v1/connect/alert-email"},
                "connect_alert_email_confirm": {"method": "POST", "path": "/v1/connect/alert-email/confirm"},
                "api_keys_create": {"method": "POST", "path": "/v1/api-keys"},
                "api_keys_list": {"method": "GET", "path": "/v1/api-keys"},
                "api_keys_revoke": {"method": "POST", "path": "/v1/api-keys/{key_id}/revoke"},
                "sites_public": {"method": "GET", "path": "/v1/sites"},
                "sites_create": {"method": "POST", "path": "/v1/sites"},
                "sites_mine": {"method": "GET", "path": "/v1/sites/mine"},
                "sites_get": {"method": "GET", "path": "/v1/sites/{slug}"},
                "sites_update": {"method": "PATCH", "path": "/v1/sites/{slug}"},
                "sites_delete": {"method": "DELETE", "path": "/v1/sites/{slug}"},
                "sites_rotate_secret": {"method": "POST", "path": "/v1/sites/{slug}/rotate-secret"},
                "sites_verify_origin": {"method": "POST", "path": "/v1/sites/{slug}/verify-origin"},
                "site_routes_create": {"method": "POST", "path": "/v1/sites/{slug}/routes"},
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
            "model": "B",
            "unit": "msat",
            "accounts": {"method": "POST", "path": "/v1/accounts"},
            "topup_lightning": {"method": "POST", "path": "/v1/topup/lightning"},
            "topup_usdc": {"method": "POST", "path": "/v1/topup/usdc"},
            "balance": "balance_msat",
            "free_quota_per_utc_month": int(config.FREE_QUOTA),
        },
        "links": {
            "health": f"{base_url}/health",
        },
        "abuse_contact": config.ABUSE_CONTACT or None,
        "terms_url": config.TERMS_URL or None,
        "delivery": "receipt",
    }


@app.head("/.well-known/satsgate.json", include_in_schema=False)
def well_known_satsgate_head(request: Request) -> dict:
    return well_known_satsgate(request)


def _balance_fields(client: db.Client) -> dict:
    """Seller-facing milisat balance and the standard-rate unlock estimate."""
    from . import quota
    from .pricing import balance_sats_text, estimate_unlocks

    now = int(time.time())
    with db._connect(config.DB_PATH) as conn:
        free = quota.free_remaining(conn, client.id, now)
        resets, local = quota.reset_displays(now)
    estimate = estimate_unlocks(int(client.balance_msat), free)
    fields = {
        "balance_msat": int(client.balance_msat),
        "balance_sats": balance_sats_text(int(client.balance_msat)),
        "quota_remaining": free,
        "quota_resets_at": resets,
        "quota_resets_at_local": local,
        **estimate,
    }
    from .advice import balance_advice

    tip = balance_advice(
        balance_msat=int(client.balance_msat),
        free_remaining=free,
        resets_at=resets,
        resets_local=local,
    )
    if tip is not None:
        fields["advice"] = tip
    return fields


def _site_lightning_advice(client: db.Client, site: dict) -> dict | None:
    """add_lightning when a route is under US$0.01 and no Lightning Address is set."""
    from .advice import add_lightning_for_price

    rate = rates.quote_rate()
    has = bool(client.payee_lightning_address)
    for route in site.get("routes") or []:
        currency = route.get("price_currency") or "sats"
        atomic = None
        if currency == "sats" and rate is not None and route.get("price_sats"):
            atomic = rates._raw_usd_atomic(int(route["price_sats"]), rate)
        tip = add_lightning_for_price(
            price_currency=currency,
            price_usd_atomic=route.get("price_usd_atomic"),
            price_sats=route.get("price_sats"),
            has_lightning=has,
            buyer_usd_atomic=atomic,
            rate_known=rate is not None,
        )
        if tip is not None:
            return tip
    return None


@app.get("/v1/plans")
def v1_plans() -> dict:
    from .pricing import plans_document

    return plans_document()


@app.get("/v1/balance")
def v1_balance(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    client = _reader_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    return {"ok": True, "client_id": client.id, **_balance_fields(client)}


@app.get("/v1/client")
def v1_client(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    client = _reader_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client

    evm = db_x402.get_evm_payee(config.DB_PATH, client_id=client.id)
    alerts = db_alert_email.describe(config.DB_PATH, client_id=client.id)
    return {
        "ok": True,
        "client_id": client.id,
        **_balance_fields(client),
        "payee_lightning_address": client.payee_lightning_address,
        "payee_evm_address": evm["address"] if evm else None,
        "payee_evm_verified": bool(evm and evm["verified_at"]),
        "payee_evm_kind": evm["kind"] if evm else "eoa",
        "alert_email": alerts["alert_email"],
        "alert_email_status": alerts["alert_email_status"],
        "alert_email_pending": alerts["alert_email_pending"],
        "email_alerts_available": db_alert_email.alerts_available(),
        "suspended": db.client_is_suspended(config.DB_PATH, client_id=client.id),
    }


@app.get("/v1/ledger")
def v1_ledger(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    limit: int = 50,
    before_id: int | None = None,
):
    """Return this client's verification ledger entries (credits)."""

    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client

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
        "balance_msat": int(client.balance_msat),
        "entries": entries,
        "next_before_id": next_before_id,
    }


@app.get("/v1/usage/summary")
def v1_usage_summary(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    since_hours: int = 24,
):
    """Usage summary over a time window (default: last 24h)."""

    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client

    since_hours = max(1, min(int(since_hours), 24 * 365))
    since_ts = int(time.time()) - (since_hours * 3600)

    summary = db_reports.usage_summary(config.DB_PATH, client_id=client.id, since_ts=since_ts)

    return {
        "ok": True,
        "client_id": client.id,
        "balance_msat": int(client.balance_msat),
        "window_hours": since_hours,
        "summary": summary,
    }


@app.get("/v1/usage/daily")
def v1_usage_daily(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    days: int = 30,
):
    """Daily (UTC) series for charts and automated top-ups."""

    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client

    days = max(1, min(int(days), 366))

    daily = db_reports.usage_daily(config.DB_PATH, client_id=client.id, days=days)

    return {
        "ok": True,
        "client_id": client.id,
        "balance_msat": int(client.balance_msat),
        "daily": daily,
    }


@app.get("/v1/usage/forecast")
def v1_usage_forecast(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    lookback_hours: int = 24,
):
    """Pace of recent paid unlocks, in milisatoshis. Never names a pack."""
    client = _reader_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    lookback_hours = max(1, min(int(lookback_hours), 24 * 30))
    forecast = db_reports.usage_forecast(
        config.DB_PATH,
        client_id=client.id,
        current_balance_credits=int(client.balance_msat),
        lookback_hours=lookback_hours,
    )
    public = dict(forecast)
    public["current_balance_msat"] = int(client.balance_msat)
    if int(public.get("verify_events") or 0) == 0:
        public["status"] = "insufficient_data"
        public["estimated_hours_remaining"] = None
        public["estimated_days_remaining"] = None
        public["estimated_depletion_ts"] = None
        public["estimated_depletion_iso"] = None
    return {
        "ok": True,
        "client_id": client.id,
        "balance_msat": int(client.balance_msat),
        "forecast": public,
        "recommendation": None,
    }


class ClientPayeeIn(BaseModel):
    payee_lightning_address: str = Field(..., min_length=3, max_length=200)


@app.post("/v1/client/payee")
def v1_client_set_payee(
    body: ClientPayeeIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client

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


class EvmPayeeChallengeIn(BaseModel):
    address: str = Field(..., min_length=42, max_length=42)


def _x402_error(exc: x402_mod.X402Error) -> JSONResponse:
    if exc.retry_after:
        return JSONResponse(
            status_code=exc.status,
            headers={"Retry-After": str(exc.retry_after)},
            content={"ok": False, "error": exc.code, "retry_after_seconds": exc.retry_after},
        )
    return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code})


def _payee_verified_body(client_id: int, saved: dict) -> dict:
    return {
        "ok": True,
        "client_id": client_id,
        "payee_evm_address": saved["address"],
        "payee_evm_verified": True,
        "payee_evm_kind": saved["kind"],
        "rails_cleared": saved["rails_cleared"],
        "note": "x402 stays off until you enable it on a site. Changing the address turns it off again.",
    }


async def _read_payee_body(request: Request) -> tuple[object, object] | JSONResponse:
    """Parse address and signature without echoing a long signature in a 422."""
    raw = await request.body()
    if len(raw) > config.X402_SIGNATURE_MAX_BYTES * 2 + 512:
        return JSONResponse(status_code=400, content={"ok": False, "error": "bad_signature"})
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "bad_signature"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"ok": False, "error": "bad_signature"})
    return payload.get("address"), payload.get("signature")


@app.post("/v1/client/payee/evm/challenge")
def v1_client_evm_challenge(
    body: EvmPayeeChallengeIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Ask for an EIP-191 message. Nothing is written on chain and the stored address does not change."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    try:
        challenge = db_x402.begin_payee_challenge(config.DB_PATH, client_id=client.id, address=body.address)
    except x402_mod.X402Error as exc:
        return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    return {
        "ok": True,
        "address": challenge["address"],
        "message": challenge["message"],
        "expires_at": challenge["expires_at"],
        "note": "Sign this message with that address. A wallet may drop the trailing newline. Nothing is written on chain.",
    }


@app.post("/v1/client/payee/evm")
async def v1_client_evm_payee(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Verify the signed message and save one EVM payTo. A bad signature does not change the stored address."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    parsed = await _read_payee_body(request)
    if isinstance(parsed, JSONResponse):
        return parsed
    address, signature = parsed

    def _verify():
        return db_x402.verify_payee_signature(
            config.DB_PATH,
            client_id=client.id,
            address=address,
            signature=signature,
            via="API",
        )

    try:
        saved = await run_in_threadpool(_verify)
    except x402_mod.X402Error as exc:
        return _x402_error(exc)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    return _payee_verified_body(client.id, saved)


@app.post("/v1/client/payee/evm/connect")
def v1_client_evm_connect(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Mint a one-time browser link. The account key is not sent to the page."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    if db.client_is_suspended(config.DB_PATH, client_id=client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "account_suspended"})
    try:
        created = db_x402.create_connect_link(config.DB_PATH, client_id=client.id)
    except ValueError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "unavailable"})
    return {
        "ok": True,
        "connect_url": created["connect_url"],
        "expires_at": created["expires_at"],
        "note": (
            "Open this link in a browser to connect a wallet. "
            "It works once and expires at expires_at. Do not share it."
        ),
    }


@app.get("/v1/connect/evm")
def v1_connect_evm(x_connect_token: str | None = Header(default=None, alias="X-Connect-Token")):
    """What the page may show before the wallet connects. No API key."""
    session = _connect_session(x_connect_token)
    if isinstance(session, JSONResponse):
        return session
    alerts = db_alert_email.describe(config.DB_PATH, client_id=session["client_id"])
    return {
        "ok": True,
        "client_id": session["client_id"],
        "current_payee_evm_address": session["address"],
        "current_payee_evm_verified": session["verified"],
        "payee_evm_kind": session["kind"],
        "expires_at": session["expires_at"],
        "challenge_seconds": int(config.X402_PAYEE_CHALLENGE_SECONDS),
        "alert_email": alerts["alert_email"],
        "alert_email_status": alerts["alert_email_status"],
        "alert_email_pending": alerts["alert_email_pending"],
        "email_alerts_available": db_alert_email.alerts_available(),
    }


@app.post("/v1/connect/evm/challenge")
def v1_connect_evm_challenge(
    body: EvmPayeeChallengeIn,
    x_connect_token: str | None = Header(default=None, alias="X-Connect-Token"),
):
    """Same challenge as the account-key route. A bad token does not start one."""
    session = _connect_session(x_connect_token)
    if isinstance(session, JSONResponse):
        return session
    try:
        challenge = db_x402.begin_payee_challenge(
            config.DB_PATH,
            client_id=session["client_id"],
            address=body.address,
        )
    except x402_mod.X402Error as exc:
        return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code})
    except ValueError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "unavailable"})
    return {
        "ok": True,
        "address": challenge["address"],
        "message": challenge["message"],
        "expires_at": challenge["expires_at"],
        "note": "Sign this message with that address. A wallet may drop the trailing newline. Nothing is written on chain.",
    }


@app.post("/v1/connect/evm/verify")
async def v1_connect_evm_verify(
    request: Request,
    x_connect_token: str | None = Header(default=None, alias="X-Connect-Token"),
):
    """Verify the signature. Success clears the connect token. Failure leaves it in place.

    The body is parsed here so a long signature is not echoed in a 422. A contract
    signature is checked on Base outside the event loop.
    """
    session = _connect_session(x_connect_token)
    if isinstance(session, JSONResponse):
        return session
    parsed = await _read_payee_body(request)
    if isinstance(parsed, JSONResponse):
        return parsed
    address, signature = parsed

    def _verify():
        return db_x402.verify_payee_signature(
            config.DB_PATH,
            client_id=session["client_id"],
            address=address,
            signature=signature,
            consume_connect=True,
            connect_token=x_connect_token,
            via="connect page",
        )

    try:
        saved = await run_in_threadpool(_verify)
    except x402_mod.X402Error as exc:
        return _x402_error(exc)
    except ValueError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "unavailable"})
    return _payee_verified_body(session["client_id"], saved)


def _alert_body(result: dict) -> dict:
    body = {"ok": True}
    body.update(result)
    return body


async def _read_alert_email(request: Request) -> object | JSONResponse:
    """Read the email field. A bad body is invalid_email and does not echo the address."""
    raw = await request.body()
    if len(raw) > 1024:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_email"})
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_email"})
    if not isinstance(payload, dict) or "email" not in payload:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_email"})
    return payload.get("email")


@app.put("/v1/client/alert-email")
async def v1_client_alert_email_put(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Set or replace the pending alert address. The account key is required."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    email = await _read_alert_email(request)
    if isinstance(email, JSONResponse):
        return email
    try:
        saved = db_alert_email.set_pending(
            config.DB_PATH,
            client_id=client.id,
            email=email,
            allow_when_confirmed=True,
        )
    except x402_mod.X402Error as exc:
        return _x402_error(exc)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    return _alert_body(saved)


@app.delete("/v1/client/alert-email")
def v1_client_alert_email_delete(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Remove the confirmed address and any pending one. The account key is required."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    try:
        saved = db_alert_email.remove(config.DB_PATH, client_id=client.id)
    except x402_mod.X402Error as exc:
        return _x402_error(exc)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    return _alert_body(saved)


_WEBHOOK_PUT_BODY = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "required": ["url"],
                    "additionalProperties": False,
                    "properties": {
                        "url": {
                            "type": "string",
                            "maxLength": 300,
                            "description": "https URL with no username or password. Public addresses only.",
                        },
                        "rotate_secret": {
                            "type": "boolean",
                            "description": "When true, replace the whsec_ signing secret and return it once.",
                        },
                    },
                }
            }
        },
    }
}


@app.post("/v1/client/api-key/rotate")
def v1_client_api_key_rotate(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Replace the account key now. Empty body. Only the current account key in X-Api-Key.

    X-Connect-Token, an sgc_ session, a restricted sgr_ key, and X-Admin-Token are not accepted.
    The old key stops working as soon as this commits. There is no grace period.
    200 returns ``api_key`` (shown once) and ``prefix`` (the first 8 characters).
    A restricted key is 403 insufficient_scope. A lost race is 401 invalid_api_key.
    Shares the account security limit (``SATSGATE_RL_MAX_SECURITY`` per
    ``SATSGATE_RL_WINDOW_SECONDS``, keyed by client id) with webhook writes.
    """
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    try:
        rotated = db_account_key.rotate_account_key(config.DB_PATH, x_api_key or "")
    except db_keys.AuthError as exc:
        return JSONResponse(status_code=401, content={"ok": False, "error": exc.code})
    return {"ok": True, "api_key": rotated["api_key"], "prefix": rotated["prefix"]}


@app.put("/v1/client/webhook", openapi_extra=_WEBHOOK_PUT_BODY)
async def v1_client_webhook_put(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Create or replace the security webhook. Account key only.

    200 is ``ok``, ``url``, and ``enabled``. ``secret`` (``whsec_…``) is present
    only on the first create or when ``rotate_secret`` is true. Replacing only
    the URL keeps the secret and omits it. 503 ``webhooks_unavailable`` when
    ``SATSGATE_SITE_SECRET_KEY`` is unset. ``SATSGATE_WEBHOOKS=0`` stops the
    sender thread and does not block this call. The URL is not echoed in errors.
    """
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    payload = await _read_webhook_body(request)
    if isinstance(payload, JSONResponse):
        return payload

    def _save() -> dict:
        return db_webhooks.put_webhook(
            config.DB_PATH,
            client_id=client.id,
            url=payload.get("url"),
            rotate_secret=bool(payload.get("rotate_secret", False)),
        )

    try:
        return await run_in_threadpool(_save)
    except x402_mod.X402Error as exc:
        return _x402_error(exc)


@app.get("/v1/client/webhook")
def v1_client_webhook_get(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Read the webhook. Account key only. Never returns the signing secret.

    ``secret_prefix`` is the start of the ``whsec_`` value. ``last_delivery`` is
    ``{"status", "at"}`` or null. No webhook is ``url: null`` and ``enabled: false``.
    """
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    return db_webhooks.get_webhook(config.DB_PATH, client_id=client.id)


@app.delete("/v1/client/webhook")
def v1_client_webhook_delete(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Remove the webhook and drop deliveries that have not been posted. Account key only."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    return db_webhooks.delete_webhook(config.DB_PATH, client_id=client.id)


@app.post("/v1/client/webhook/test")
def v1_client_webhook_test(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Queue a webhook_test event. Account key only.

    404 ``webhook_not_configured`` when none is saved. 409 ``webhook_disabled`` when
    a 404 or 410 turned it off. 503 ``webhooks_unavailable`` when the encryption
    key is unset. Shares the account security limit with rotation and webhook
    writes (``SATSGATE_RL_MAX_SECURITY`` calls per window, keyed by client id).
    """
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    try:
        return db_webhooks.queue_test(config.DB_PATH, client_id=client.id)
    except x402_mod.X402Error as exc:
        return _x402_error(exc)


def _webhook_body_rejected() -> JSONResponse:
    return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_webhook_url"})


async def _read_webhook_body(request: Request) -> dict | JSONResponse:
    """Read url and rotate_secret. A bad body is invalid_webhook_url and does not echo the URL.

    Content-Length is rejected before the body is read. The stream stops at
    ``_MAX_WEBHOOK_BODY`` and the extra bytes are not kept or parsed.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > _MAX_WEBHOOK_BODY:
                return _webhook_body_rejected()
        except ValueError:
            return _webhook_body_rejected()
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if total + len(chunk) > _MAX_WEBHOOK_BODY:
            return _webhook_body_rejected()
        chunks.append(chunk)
        total += len(chunk)
    raw = b"".join(chunks)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return _webhook_body_rejected()
    if not isinstance(payload, dict) or "url" not in payload:
        return _webhook_body_rejected()
    if set(payload) - {"url", "rotate_secret"}:
        return _webhook_body_rejected()
    flag = payload.get("rotate_secret", False)
    if not isinstance(flag, bool):
        return _webhook_body_rejected()
    return {"url": payload.get("url"), "rotate_secret": flag}


@app.post("/v1/connect/alert-email")
async def v1_connect_alert_email(
    request: Request,
    x_connect_token: str | None = Header(default=None, alias="X-Connect-Token"),
):
    """First alert address only. A confirmed address has to be changed with the account key.

    This does not consume the connect token.
    """
    session = _connect_session(x_connect_token)
    if isinstance(session, JSONResponse):
        return session
    email = await _read_alert_email(request)
    if isinstance(email, JSONResponse):
        return email
    try:
        saved = db_alert_email.set_pending(
            config.DB_PATH,
            client_id=session["client_id"],
            email=email,
            allow_when_confirmed=False,
        )
    except x402_mod.X402Error as exc:
        return _x402_error(exc)
    except ValueError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "unavailable"})
    return _alert_body(saved)


@app.get("/v1/connect/alert-email")
def v1_connect_alert_email_preview(x_email_token: str | None = Header(default=None, alias="X-Email-Token")):
    """What the confirmation screen may show. The token is not consumed."""
    try:
        return db_alert_email.preview(config.DB_PATH, x_email_token or "")
    except x402_mod.X402Error as exc:
        return _x402_error(exc)


@app.post("/v1/connect/alert-email/confirm")
def v1_connect_alert_email_confirm(x_email_token: str | None = Header(default=None, alias="X-Email-Token")):
    """Confirm on a POST. A mail scanner that only fetches the link does not confirm it."""
    try:
        return db_alert_email.confirm(config.DB_PATH, x_email_token or "")
    except x402_mod.X402Error as exc:
        return _x402_error(exc)


class ApiKeyCreateIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=64)
    scope: str = Field(
        default=db_keys.SCOPE_PAYWALL,
        max_length=32,
        description="paywall (default), sites:read, or sites:write. Omit it to keep a paywall key.",
    )
    resource_prefix: str | None = Field(
        default=None,
        max_length=200,
        description=(
            "When set, this key can only challenge, check, and verify resources that "
            "start with this prefix. The comparison is case-sensitive. Omit it to allow any resource."
        ),
    )


@app.post("/v1/api-keys")
def v1_api_keys_create(
    body: ApiKeyCreateIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Create a restricted key. The account key is required. The secret is returned once."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    try:
        created = db_keys.create_restricted_key(
            config.DB_PATH,
            client_id=client.id,
            label=body.label,
            resource_prefix=body.resource_prefix,
            scope=body.scope,
        )
    except ValueError as exc:
        code = str(exc)
        status = 409 if code == "too_many_api_keys" else 400
        return JSONResponse(status_code=status, content={"ok": False, "error": code})
    api_key = created.pop("api_key")
    return {
        "ok": True,
        "api_key": api_key,
        "key": created,
        "note": "Save this API key. We will not show it again.",
    }


@app.get("/v1/api-keys")
def v1_api_keys_list(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    include_revoked: bool = False,
):
    """List this client's restricted keys. Secrets are never included."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    keys = db_keys.list_restricted_keys(
        config.DB_PATH,
        client_id=client.id,
        include_revoked=include_revoked,
    )
    return {"ok": True, "keys": keys}


@app.post("/v1/api-keys/{key_id}/revoke")
def v1_api_keys_revoke(
    key_id: int,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Revoke a restricted key. Repeating this call stays revoked."""
    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    revoked = db_keys.revoke_restricted_key(config.DB_PATH, client_id=client.id, key_id=key_id)
    if revoked is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "api_key_not_found"})
    return {"ok": True, "key": revoked}


def _sites_caller(x_api_key: str | None, *, write: bool) -> db_keys.Principal | JSONResponse:
    auth = _authenticate(x_api_key)
    if isinstance(auth, JSONResponse):
        return auth
    allowed = {db_keys.SCOPE_ACCOUNT, db_keys.SCOPE_SITES_WRITE}
    if not write:
        allowed.add(db_keys.SCOPE_SITES_READ)
    if auth.scope not in allowed:
        return _insufficient_scope(auth.scope)
    return auth


def _geoblock_quote(request: Request) -> JSONResponse | None:
    from .geoblock import GeoblockUnavailable, blocked_country

    peer = request.client.host if request.client else None
    try:
        ip = resolve_client_ip(
            peer=peer,
            forwarded_for=request.headers.get("x-forwarded-for"),
            trusted_proxies=config.TRUSTED_PROXIES,
        )
        code = blocked_country(ip)
    except GeoblockUnavailable:
        return JSONResponse(
            status_code=503,
            content={"ok": False, "error": "geoblock_unavailable"},
            headers={"Cache-Control": "no-store"},
        )
    if code is None:
        return None
    return JSONResponse(
        status_code=451,
        content={
            "ok": False,
            "error": "region_unavailable",
            "detail": "Credit purchases are not available from this region.",
        },
        headers={"Cache-Control": "no-store"},
    )


def _sites_error(exc: Exception) -> JSONResponse:
    code = getattr(exc, "code", None) or str(exc)
    if code in {"slug_taken", "route_exists", "site_limit", "route_limit"}:
        status = 409
    elif code == "site_secret_key_unconfigured":
        status = 503
    else:
        status = 400
    return JSONResponse(status_code=status, content={"ok": False, "error": code})


class SiteCreateIn(BaseModel):
    slug: str = Field(..., min_length=3, max_length=40)
    display_name: str = Field(..., min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=300)
    origin_url: str = Field(..., min_length=8, max_length=300)
    listed: bool = False
    accept_terms: str | None = Field(default=None, max_length=64)


class SiteUpdateIn(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=300)
    origin_url: str | None = Field(default=None, max_length=300)
    listed: bool | None = None
    rail_lightning: bool | None = None
    rail_x402: bool | None = None
    x402_mode: str | None = Field(
        default=None,
        description=(
            "Exclusive USDC mode. test offers only Base Sepolia. live offers only Base "
            "and requires the operator CDP switch. A new site leaves this unset. "
            "Turning x402 on without a mode stores test."
        ),
    )
    accept_terms: str | None = Field(default=None, max_length=64)


class RouteCreateIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=200)
    price_sats: int | None = Field(default=None, ge=1, le=10_000_000)
    price_currency: str | None = Field(default=None, max_length=8)
    price_usd_atomic: int | None = Field(default=None, ge=1, le=config.X402_MAX_USD_ATOMIC)
    max_uses: int | None = Field(default=None, ge=1, le=config.MAX_PAYWALL_USES)
    access_seconds: int | None = Field(default=None, ge=1, le=config._MAX_PAYWALL_ACCESS_CAP_SECONDS)


class RouteUpdateIn(BaseModel):
    path: str | None = Field(default=None, max_length=200)
    price_sats: int | None = Field(default=None, ge=1, le=10_000_000)
    price_currency: str | None = Field(default=None, max_length=8)
    price_usd_atomic: int | None = Field(default=None, ge=1, le=config.X402_MAX_USD_ATOMIC)
    max_uses: int | None = Field(default=None, ge=1, le=config.MAX_PAYWALL_USES)
    access_seconds: int | None = Field(default=None, ge=1, le=config._MAX_PAYWALL_ACCESS_CAP_SECONDS)


def _without_secret(site: dict) -> dict:
    view = dict(site)
    view.pop("origin_secret", None)
    return view


def _with_derived(site: dict) -> dict:
    view = dict(site)
    routes = []
    for route in site.get("routes") or []:
        item = dict(route)
        item["derived"] = rates.describe_derived(
            price_currency=item.get("price_currency") or "sats",
            price_sats=item.get("price_sats"),
            price_usd_atomic=item.get("price_usd_atomic"),
        )
        routes.append(item)
    view["routes"] = routes
    return view


@app.get("/v1/sites")
def v1_sites_public(limit: int = 20, cursor: str | None = None):
    """Approved sites that opted in. No owner, origin, or secret."""
    try:
        return db_sites.list_public_sites(config.DB_PATH, limit=int(limit), cursor=cursor)
    except ValueError as exc:
        return _sites_error(exc)


@app.get("/v1/sites/mine")
def v1_sites_mine(x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    auth = _sites_caller(x_api_key, write=False)
    if isinstance(auth, JSONResponse):
        return auth
    sites = db_sites.list_sites_for_client(config.DB_PATH, client_id=auth.client.id)
    return {"ok": True, "sites": [_with_derived(_without_secret(site)) for site in sites]}


@app.post("/v1/sites")
def v1_sites_create(
    body: SiteCreateIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Register a site. The origin HMAC secret is returned once. New sites start pending."""
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    if db.client_is_suspended(config.DB_PATH, client_id=auth.client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "account_suspended"})
    if config.TERMS_VERSION and body.accept_terms != config.TERMS_VERSION:
        return JSONResponse(status_code=400, content={"ok": False, "error": "terms_not_accepted"})
    try:
        created = db_sites.create_site(
            config.DB_PATH,
            client_id=auth.client.id,
            slug=body.slug,
            display_name=body.display_name,
            description=body.description,
            origin_url=body.origin_url,
            listed=body.listed,
            max_sites=config.SITES_MAX_PER_ACCOUNT,
            terms_version=body.accept_terms,
        )
    except (ValueError, db_sites.OriginError) as exc:
        return _sites_error(exc)
    secret = created.pop("origin_secret")
    return {
        "ok": True,
        "origin_secret": secret,
        "site": created,
        "note": (
            "Save this origin secret. We will not show it again. "
            "The hosted proxy will sign X-Satsgate-Signature with it. "
            "New sites stay pending until an operator approves them."
        ),
    }


@app.get("/v1/sites/{slug}")
def v1_sites_get(slug: str, x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    auth = _sites_caller(x_api_key, write=False)
    if isinstance(auth, JSONResponse):
        return auth
    site = db_sites.get_site_for_client(config.DB_PATH, client_id=auth.client.id, slug=slug)
    if site is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    public = _without_secret(site)
    tip = _site_lightning_advice(auth.client, public)
    body = {"ok": True, "site": public}
    if tip is not None:
        body["advice"] = tip
    return body


@app.patch("/v1/sites/{slug}")
def v1_sites_update(
    slug: str,
    body: SiteUpdateIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    fields = body.model_fields_set
    if "rail_lightning" in fields or "rail_x402" in fields or "x402_mode" in fields:
        if auth.scope != db_keys.SCOPE_ACCOUNT:
            return _insufficient_scope(auth.scope)
    try:
        updated = db_sites.update_site(
            config.DB_PATH,
            client_id=auth.client.id,
            slug=slug,
            display_name=body.display_name if "display_name" in fields else None,
            description=body.description,
            origin_url=body.origin_url if "origin_url" in fields else None,
            listed=body.listed if "listed" in fields else None,
            set_description="description" in fields,
            rail_lightning=body.rail_lightning if "rail_lightning" in fields else None,
            rail_x402=body.rail_x402 if "rail_x402" in fields else None,
            x402_mode=body.x402_mode if "x402_mode" in fields else None,
            set_x402_mode="x402_mode" in fields,
            accept_terms=body.accept_terms if "accept_terms" in fields else None,
        )
    except (ValueError, db_sites.OriginError) as exc:
        return _sites_error(exc)
    if updated is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    return {"ok": True, "site": _without_secret(updated)}


@app.delete("/v1/sites/{slug}")
def v1_sites_delete(slug: str, x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    if not db_sites.delete_site(config.DB_PATH, client_id=auth.client.id, slug=slug):
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    return {"ok": True}


@app.post("/v1/sites/{slug}/rotate-secret")
def v1_sites_rotate_secret(slug: str, x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    try:
        rotated = db_sites.rotate_site_secret(config.DB_PATH, client_id=auth.client.id, slug=slug)
    except ValueError as exc:
        return _sites_error(exc)
    if rotated is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    secret = rotated.pop("origin_secret")
    return {
        "ok": True,
        "origin_secret": secret,
        "site": rotated,
        "note": "Save this origin secret. We will not show it again. The previous secret no longer matches.",
    }


@app.post("/v1/sites/{slug}/verify-origin")
def v1_sites_verify_origin(slug: str, x_api_key: str | None = Header(default=None, alias="X-Api-Key")):
    """Ask the origin to prove the receipt checker is installed. Any site status is accepted."""
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    site = db_sites.get_site_for_client(config.DB_PATH, client_id=auth.client.id, slug=slug)
    if site is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    from .origin_check import OriginCheckError, verify_origin

    try:
        checked = verify_origin(config.DB_PATH, site=site)
    except OriginCheckError as exc:
        headers = {"Cache-Control": "no-store"}
        if exc.code == "rate_limited":
            headers["Retry-After"] = "3600"
        return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code}, headers=headers)
    return {
        "ok": True,
        "origin_verified_at": checked.get("origin_verified_at"),
        "status": checked.get("status"),
        "site": _without_secret(checked),
    }


@app.post("/v1/sites/{slug}/routes")
def v1_site_routes_create(
    slug: str,
    body: RouteCreateIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    try:
        route = db_sites.add_route(
            config.DB_PATH,
            client_id=auth.client.id,
            slug=slug,
            path_pattern=body.path,
            price_sats=body.price_sats,
            max_uses=body.max_uses,
            access_seconds=body.access_seconds,
            max_routes=config.SITES_MAX_ROUTES,
            price_currency=body.price_currency or "sats",
            price_usd_atomic=body.price_usd_atomic,
        )
    except ValueError as exc:
        code = str(exc)
        status = 404 if code == "site_not_found" else None
        if status == 404:
            return JSONResponse(status_code=404, content={"ok": False, "error": code})
        return _sites_error(exc)
    return {"ok": True, "route": route}


@app.patch("/v1/sites/{slug}/routes/{route_id}")
def v1_site_routes_update(
    slug: str,
    route_id: int,
    body: RouteUpdateIn,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    fields = body.model_fields_set
    try:
        route = db_sites.update_route(
            config.DB_PATH,
            client_id=auth.client.id,
            slug=slug,
            route_id=route_id,
            path_pattern=body.path if "path" in fields else None,
            price_sats=body.price_sats if "price_sats" in fields else None,
            max_uses=body.max_uses,
            access_seconds=body.access_seconds,
            set_max_uses="max_uses" in fields,
            set_access_seconds="access_seconds" in fields,
            price_currency=body.price_currency if "price_currency" in fields else None,
            price_usd_atomic=body.price_usd_atomic if "price_usd_atomic" in fields else None,
            set_price="price_currency" in fields or "price_usd_atomic" in fields,
        )
    except ValueError as exc:
        return _sites_error(exc)
    if route is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "route_not_found"})
    return {"ok": True, "route": route}


@app.delete("/v1/sites/{slug}/routes/{route_id}")
def v1_site_routes_delete(
    slug: str,
    route_id: int,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    auth = _sites_caller(x_api_key, write=True)
    if isinstance(auth, JSONResponse):
        return auth
    if not db_sites.delete_route(config.DB_PATH, client_id=auth.client.id, slug=slug, route_id=route_id):
        return JSONResponse(status_code=404, content={"ok": False, "error": "route_not_found"})
    return {"ok": True}


@app.post("/v1/spend", include_in_schema=config.dev_endpoints_enabled())
def v1_spend(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    cost: int = 1,
):
    # Demo-only. Burning credits from a public route is not part of the paywall API.
    if not config.dev_endpoints_enabled():
        return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})

    client = _account_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client

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


def _topup_claim_deadline(*, expires_at: int | None, created_at: int) -> int | None:
    """Unix time through which this top-up may still be claimed.

    None means the row has no stored invoice expiry, so the macaroon's own
    `exp` remains the limit (the historical token TTL).
    """
    if expires_at is None:
        return None
    by_invoice = int(expires_at) + int(config.TOPUP_CLAIM_GRACE_SECONDS)
    by_cap = int(created_at) + int(config.TOPUP_TOKEN_TTL_CAP_SECONDS)
    return min(by_invoice, by_cap)


def _topup_macaroon_exp(*, expires_at: int | None, created_at: int) -> int:
    """Absolute `exp` caveat for a newly minted top-up macaroon."""
    deadline = _topup_claim_deadline(expires_at=expires_at, created_at=created_at)
    if deadline is None:
        return int(created_at) + int(config.TOKEN_TTL_SECONDS)
    return deadline


def _paywall_invoice_expiry(*, stored_expires_at: int | None, invoice: str | None) -> int | None:
    """Invoice lifetime for a challenge row.

    New rows store the BOLT11 expiry. Rows written before 0.4.2 stored the
    macaroon TTL instead, so a decoded invoice expiry is used when it is later.
    """
    decoded = bolt11_expiry_unix(invoice)
    if stored_expires_at is None:
        return decoded
    if decoded is None:
        return int(stored_expires_at)
    return max(int(stored_expires_at), int(decoded))


def _paywall_claim_deadline(*, expires_at: int | None, created_at: int, invoice: str | None = None) -> int | None:
    """Unix time through which a paywall payment may still be unlocked the first time.

    None means there is no invoice expiry to follow, so the macaroon `exp` remains
    the limit.
    """
    invoice_expiry = _paywall_invoice_expiry(stored_expires_at=expires_at, invoice=invoice)
    if invoice_expiry is None:
        return None
    by_invoice = int(invoice_expiry) + int(config.PAYWALL_CLAIM_GRACE_SECONDS)
    by_cap = int(created_at) + int(config.PAYWALL_TOKEN_TTL_CAP_SECONDS)
    return min(by_invoice, by_cap)


def _paywall_macaroon_exp(*, expires_at: int | None, created_at: int) -> int:
    """Absolute `exp` caveat for a newly minted paywall macaroon."""
    deadline = _paywall_claim_deadline(expires_at=expires_at, created_at=created_at)
    if deadline is None:
        return int(created_at) + int(config.TOKEN_TTL_SECONDS)
    return max(int(created_at) + 1, int(deadline))


def _challenge_expiry_note(*, invoice_expires_at: int, claim_until: int) -> str:
    text = (
        "invoice_expires_at is when the Lightning invoice stops being payable. "
        "claim_until and valid_until are when a payment of that invoice can still be unlocked "
        "(invoice expiry plus grace, and never later than the claim cap). "
        "valid_until is the macaroon expiry. cache_until on a successful unlock is how long to cache that result. "
        "How long the buyer may use your product is your decision."
    )
    if int(claim_until) < int(invoice_expires_at):
        text += (
            " claim_until is earlier than the invoice because the claim cap applies;"
            " a payment after claim_until cannot be unlocked."
        )
    return text


_PAYWALL_UNLOCK_NOTE = (
    "charged_credits is the debit from this call (0 when this payment_hash was already unlocked). "
    "POST /v1/paywall/verify and GET /v1/paywall/status are alternatives and share that one-time debit. "
    "cache_until is how long to cache this successful result. "
    "valid_until is the macaroon exp caveat. claim_until is the latest time a first unlock is still accepted. "
    "How long the buyer may use your product is your decision."
)

_PAYWALL_PENDING_NOTE = (
    "Not settled, so charged_credits is 0. "
    "GET /v1/paywall/status returns HTTP 200 with status pending for this state. "
    "POST /v1/paywall/verify returns HTTP 402 with error payment_pending for this state. "
    "The first settled call on either route spends credits once for this payment_hash."
)


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

    Expiry of the macaroon caveat is not the claim limit. The stored invoice
    `expires_at` plus the grace window is, capped from `created_at`. That lets
    a buyer pay any time the invoice is still valid, and it lets a macaroon
    minted before 0.4.1 (10-minute `exp`) finish the same way. Signature,
    bindings, and payment proof are still required. Paywall tokens do not use
    this path.
    """
    macaroon_b64, preimage_hex = parse_authorization_header(authorization)
    payload = parse_and_verify_macaroon(
        keys=config.MACAROON_KEYS,
        macaroon_b64=macaroon_b64,
        purpose=PURPOSE_TOPUP,
        resource=resource,
        client_id=client.id if client else None,
        skip_expiry=True,
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

    now = int(time.time())
    deadline = _topup_claim_deadline(expires_at=topup["expires_at"], created_at=int(topup["created_at"]))
    if deadline is None:
        if now > int(payload["exp"]):
            raise L402Error("token expired")
    elif now > deadline:
        raise L402Error("invoice expired")

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

    from .signup import SignupLimited

    try:
        res = db.settle_topup_and_credit(
            config.DB_PATH,
            payment_hash=payment_hash,
            client_id=credit_client_id,
        )
    except SignupLimited as exc:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
            content={"ok": False, "error": exc.code, "retry_after_seconds": exc.retry_after},
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


class SignupIn(BaseModel):
    """Empty object only. Personal data is refused."""

    model_config = {"extra": "forbid"}


@app.post("/v1/accounts")
def v1_accounts(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    body: SignupIn | None = Body(default=None),
):
    """Open an account. The sg_ key is returned once. No invoice and no personal data."""
    del body
    from .signup import SignupLimited, create_account

    if x_api_key:
        if db_keys.key_kind(x_api_key) == "restricted":
            try:
                auth = db_keys.authenticate(config.DB_PATH, x_api_key)
            except db_keys.AuthError as exc:
                return JSONResponse(status_code=401, content={"ok": False, "error": exc.code})
            return _insufficient_scope(auth.scope)
        existing = db.get_client_by_api_key(config.DB_PATH, x_api_key)
        if existing is not None:
            return JSONResponse(
                status_code=409,
                content={"ok": False, "error": "account_exists", "client_id": existing.id},
            )
    blocked = _geoblock_quote(request)
    if blocked is not None:
        return blocked
    try:
        api_key, client_id = create_account(config.DB_PATH, ip=_peer_ip(request) or None)
    except SignupLimited as exc:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
            content={"ok": False, "error": exc.code, "retry_after_seconds": exc.retry_after},
        )
    client = db.get_client_by_id(config.DB_PATH, client_id)
    assert client is not None
    return JSONResponse(
        status_code=201,
        content={"ok": True, "api_key": api_key, "client_id": client_id, **_balance_fields(client)},
    )


class UsdcTopupIn(BaseModel):
    model_config = {"extra": "forbid"}
    usd: str | None = None
    usd_atomic: int | None = Field(default=None, ge=1)


def _usd_to_atomic(body: UsdcTopupIn) -> int | JSONResponse:
    if body.usd is not None and body.usd_atomic is not None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "amount_conflict"})
    if body.usd_atomic is not None:
        return int(body.usd_atomic)
    text = (body.usd or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"ok": False, "error": "amount_required"})
    import re

    if re.fullmatch(r"\d+(\.\d{1,6})?", text) is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_amount"})
    whole, _, frac = text.partition(".")
    atomic = int(whole) * 1_000_000 + int((frac + "000000")[:6])
    return atomic


@app.post("/v1/topup/usdc")
def v1_topup_usdc(
    body: UsdcTopupIn,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    payment_signature: str | None = Header(default=None, alias="PAYMENT-SIGNATURE"),
):
    """Authenticated free-amount USDC top-up. A missing accounting rate is 503, not a 402."""
    from . import x402_topup

    client = _topup_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    if client is None:
        return JSONResponse(status_code=401, content={"ok": False, "error": "api_key_required"})
    if db.client_is_suspended(config.DB_PATH, client_id=client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "account_suspended"})
    atomic = _usd_to_atomic(body)
    if isinstance(atomic, JSONResponse):
        return atomic
    if atomic < int(config.TOPUP_MIN_USD_ATOMIC):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "amount_too_small", "min_usd_atomic": int(config.TOPUP_MIN_USD_ATOMIC)},
        )
    if payment_signature:
        try:
            return x402_topup.settle_amount(client_id=client.id, encoded=payment_signature)
        except x402_mod.X402Error as exc:
            return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code})
    blocked = _geoblock_quote(request)
    if blocked is not None:
        return blocked
    base = str(request.base_url).rstrip("/")
    try:
        view = x402_topup.issue_amount(
            client_id=client.id,
            usd_atomic=atomic,
            resource_url=f"{base}/v1/topup/usdc",
        )
    except x402_mod.X402Error as exc:
        return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code})
    return JSONResponse(
        status_code=402,
        headers={"PAYMENT-REQUIRED": view["payment_required"]},
        content=view,
    )


class LightningTopupIn(BaseModel):
    sats: int = Field(..., ge=1, le=10_000_000)


@app.post("/v1/topup/lightning")
def v1_topup_lightning(
    body: LightningTopupIn,
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Top up any amount of sats. Minimum is SATSGATE_TOPUP_MIN_SATS.

    No key: the invoice can create the account when it is paid. A restricted
    key cannot top up. The credited milisatoshis include the per-top-up bonus.
    """
    from .pricing import bonus_bps, credit_msat_for_principal

    resource = "v1/topup/lightning"
    if int(body.sats) < int(config.TOPUP_MIN_SATS):
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "amount_too_small",
                "min_sats": int(config.TOPUP_MIN_SATS),
            },
        )
    client = _topup_client(x_api_key)
    if isinstance(client, JSONResponse):
        return client
    if client is not None and db.client_is_suspended(config.DB_PATH, client_id=client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "account_suspended"})
    if authorization:
        try:
            return _claim_topup(authorization=authorization, resource=resource, client=client, plan=None)
        except L402Error as exc:
            return JSONResponse(status_code=401, content={"ok": False, "error": str(exc)})
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    blocked = _geoblock_quote(request)
    if blocked is not None:
        return blocked
    if client is None:
        from .signup import SignupLimited, room_for_signup

        try:
            with db._connect(config.DB_PATH) as conn:
                room_for_signup(conn, ip=_peer_ip(request) or None, now=int(time.time()))
        except SignupLimited as exc:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(exc.retry_after)},
                content={"ok": False, "error": exc.code, "retry_after_seconds": exc.retry_after},
            )
    msat_credit = credit_msat_for_principal(int(body.sats))
    try:
        inv = WALLET.create_invoice(
            amount_sats=int(body.sats),
            memo="satsgate topup",
            min_expiry_seconds=config.TOKEN_TTL_SECONDS,
        )
    except (ssrf.SSRFError, InvoiceValidationError, LnurlError, ValueError) as exc:
        return _upstream_error(exc)
    created_at = int(time.time())
    invoice_expires_at = getattr(inv, "expires_at", None)
    macaroon_exp = _topup_macaroon_exp(expires_at=invoice_expires_at, created_at=created_at)
    try:
        db.add_topup(
            config.DB_PATH,
            payment_hash=inv.payment_hash,
            invoice=inv.invoice,
            sats=int(body.sats),
            credits=msat_credit // 2000,
            client_id=client.id if client else None,
            requester_ip=_peer_ip(request),
            verify_url=getattr(inv, "verify_url", None),
            expires_at=invoice_expires_at,
            max_pending_per_ip=config.MAX_PENDING_TOPUPS_PER_IP,
            now=created_at,
            claim_grace_seconds=config.TOPUP_CLAIM_GRACE_SECONDS,
            claim_cap_seconds=config.TOPUP_TOKEN_TTL_CAP_SECONDS,
        )
    except ValueError as exc:
        if str(exc) == "too_many_pending_topups":
            return JSONResponse(status_code=429, content={"ok": False, "error": "too_many_pending_topups"})
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            """
            UPDATE topups
            SET delta_msat = ?, bonus_bps = ?, rate_source = 'lightning'
            WHERE payment_hash = ?
            """,
            (msat_credit, bonus_bps(int(body.sats)), inv.payment_hash),
        )
    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=PURPOSE_TOPUP,
        payment_hash=inv.payment_hash,
        resource=resource,
        amount_sats=int(body.sats),
        invoice=inv.invoice,
        ttl_seconds=max(1, macaroon_exp - created_at),
        exp=macaroon_exp,
        client_id=client.id if client else None,
        payee=config.LIGHTNING_ADDRESS or None,
    )
    return JSONResponse(
        status_code=402,
        headers={"WWW-Authenticate": www_authenticate_header(macaroon=macaroon, invoice=inv.invoice)},
        content={
            "ok": False,
            "error": "payment_required",
            "sats": int(body.sats),
            "msat_credit": msat_credit,
            "macaroon": macaroon,
            "invoice": inv.invoice,
            "payment_hash": inv.payment_hash,
            "expires_at": invoice_expires_at,
        },
    )


@app.get("/v1/topup/{plan_id}/x402")
def v1_topup_x402(
    plan_id: str,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    payment_signature: str | None = Header(default=None, alias="PAYMENT-SIGNATURE"),
):
    """Buy a credit pack with USDC.

    While the operator CDP switch is on, the only network is Base
    (`eip155:8453`) through the CDP facilitator. While it is off, the only
    network is Base Sepolia (`eip155:84532`). Credits are not sold for testnet
    USDC once mainnet is on. No `PAYMENT-SIGNATURE`: 402 and `PAYMENT-REQUIRED`
    (scheme `exact`, payTo the treasury, amount from the locked BTC/USD quote).
    With that header: verify, settle, then grant credits. A failed settle grants
    nothing. Credits are not redeemable for USDC. Lightning top-up is separate.
    """
    from .pricing import RETIRED_PLAN_IDS, packs_retired_body

    if (plan_id or "").strip().lower() in RETIRED_PLAN_IDS:
        return JSONResponse(status_code=410, content=packs_retired_body())
    return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})



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

    from .pricing import RETIRED_PLAN_IDS, packs_retired_body

    if (plan_id or "").strip().lower() in RETIRED_PLAN_IDS:
        return JSONResponse(status_code=410, content=packs_retired_body())
    return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})



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
    ttl_seconds: int | None = Field(
        default=None,
        ge=30,
        le=86_400,
        description=(
            "Minimum seconds the Lightning invoice must stay payable. "
            "Does not shorten the macaroon. claim_until follows the invoice expiry plus grace, capped. "
            "Omit it to use SATSGATE_TOKEN_TTL_SECONDS as that minimum."
        ),
    )
    max_uses: int | None = Field(
        default=None,
        ge=1,
        le=config.MAX_PAYWALL_USES,
        description=(
            "How many consume=true calls this payment covers. "
            "Omit it, and omit access_seconds, to keep the previous unlimited re-verify behaviour."
        ),
    )
    access_seconds: int | None = Field(
        default=None,
        ge=1,
        le=config._MAX_PAYWALL_ACCESS_CAP_SECONDS,
        description=(
            "Seconds of access starting when the payment first settles. "
            "The server caps this (SATSGATE_PAYWALL_ACCESS_CAP_SECONDS, default 7 days). "
            "A max_uses bundle that omits this still ends at that cap."
        ),
    )
    x402: bool = Field(
        default=False,
        description=(
            "Also attach an x402 USDC offer for resource_url. "
            "Requires a verified EVM payee. Lightning is still issued."
        ),
    )
    resource_url: str | None = Field(
        default=None,
        max_length=500,
        description="Public http(s) URL the buyer will pay. Required when x402 is true.",
    )
    x402_mode: str | None = Field(
        default=None,
        description=(
            "test or live. Omitted with x402 true means test (Base Sepolia). "
            "live offers only Base and requires the operator CDP switch. "
            "The two networks are never in the same 402."
        ),
    )


class PaywallVerifyIn(BaseModel):
    expected_resource: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description=(
            "Must exactly match the resource from POST /v1/paywall/challenge. "
            "The comparison is case-sensitive."
        ),
    )
    cost_credits: int = Field(default=1, ge=1, le=10_000)
    consume: bool = Field(
        default=False,
        description=(
            "When true, atomically take one use of this payment. "
            "Required to enforce max_uses or access_seconds. "
            "False leaves the counter unchanged and still settles a first unlock."
        ),
    )
    charge: bool = Field(
        default=True,
        description=(
            "When true, debit on this call, which is what proxy 0.8.0 does before it forwards. "
            "When false, confirm the payment and leave the credit. "
            "POST /v1/paywall/charge debits after the origin returns 2xx."
        ),
    )


class PaywallChargeIn(BaseModel):
    expected_resource: str = Field(min_length=1, max_length=200)
    payment_hash: str = Field(min_length=64, max_length=64)
    cost_credits: int = Field(default=1, ge=1, le=10_000)


class PaywallX402In(BaseModel):
    resource: str = Field(min_length=1, max_length=200)
    resource_url: str = Field(min_length=8, max_length=500)
    payment_signature: str = Field(min_length=1, max_length=12000)


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


def _challenge_limited(exc: db.ChallengeLimit) -> JSONResponse:
    detail = {
        "buyer_rate_limited": "This buyer has created too many challenges in the current window. Wait for Retry-After.",
        "too_many_open_challenges_for_buyer": (
            "This buyer has too many unexpired unpaid challenges on this rail. "
            "Pay one, or wait for Retry-After, which is the soonest expiry. "
            "Lightning and x402 are counted separately. An expired challenge does not count."
        ),
        "too_many_open_challenges": (
            "This account has too many unexpired unpaid challenges. Wait for Retry-After."
        ),
    }.get(exc.code, "Try again later.")
    retry_after = max(1, int(exc.retry_after))
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": str(retry_after)},
        content={
            "ok": False,
            "error": exc.code,
            "retry_after_seconds": retry_after,
            "detail": detail,
        },
    )


def _challenge_body(
    *,
    resource: str,
    amount_sats: int,
    payee: str | None,
    payee_saved: bool,
    macaroon: str,
    invoice: str,
    payment_hash: str,
    claim_until: int,
    invoice_expires_at: int,
    max_uses: int | None,
    access_seconds: int | None,
    uses_consumed: int,
    access_until: int | None,
    settled_at: int | None,
    reused: bool,
    buyer_ip_accepted: bool,
) -> dict:
    www_auth = www_authenticate_header(macaroon=macaroon, invoice=invoice)
    payee_note = None
    if payee_saved:
        payee_note = (
            "Saved payee_lightning_address as this client's payee. "
            "Later challenges use it. Change it with POST /v1/client/payee."
        )
    note = _challenge_expiry_note(invoice_expires_at=invoice_expires_at, claim_until=claim_until)
    if max_uses is not None or access_seconds is not None:
        note += (
            " This challenge has a usage policy. Pass consume=true on verify or status to take one use."
            " access_until is set when the payment first settles."
            " HTTP 401 token_used_up or token_expired means the buyer needs a new challenge."
        )
    if reused:
        note += " This is an unpaid challenge from a moment ago, returned so a retry does not mint another invoice."
    remaining = None if max_uses is None else max(0, int(max_uses) - int(uses_consumed))
    return {
        "ok": True,
        "resource": resource,
        "amount_sats": int(amount_sats),
        "payee_lightning_address": payee,
        "payee_saved": payee_saved,
        "payee_note": payee_note,
        "macaroon": macaroon,
        "invoice": invoice,
        "payment_hash": payment_hash,
        "valid_until": claim_until,
        "claim_until": claim_until,
        "invoice_expires_at": invoice_expires_at,
        "cache_until": claim_until,
        "max_uses": int(max_uses) if max_uses is not None else None,
        "access_seconds": int(access_seconds) if access_seconds is not None else None,
        "uses_consumed": int(uses_consumed),
        "uses_remaining": remaining,
        "access_until": int(access_until) if access_until is not None else None,
        "settled_at": int(settled_at) if settled_at is not None else None,
        "reused": bool(reused),
        "buyer_ip_accepted": bool(buyer_ip_accepted),
        "www_authenticate": www_auth,
        "token_version": TOKEN_VERSION,
        "note": note,
    }


def _challenge_from_row(row, *, payee_saved: bool, reused: bool, buyer_ip_accepted: bool) -> dict:
    created_at = int(row["created_at"])
    invoice_expires_at = int(row["expires_at"])
    claim_until = _paywall_macaroon_exp(expires_at=invoice_expires_at, created_at=created_at)
    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=PURPOSE_PAYWALL,
        payment_hash=str(row["payment_hash"]),
        resource=str(row["resource"]),
        amount_sats=int(row["amount_sats"]),
        invoice=str(row["invoice"]),
        ttl_seconds=max(1, claim_until - created_at),
        exp=claim_until,
        client_id=int(row["client_id"]),
        payee=row["payee"],
    )
    return _challenge_body(
        resource=str(row["resource"]),
        amount_sats=int(row["amount_sats"]),
        payee=row["payee"],
        payee_saved=payee_saved,
        macaroon=macaroon,
        invoice=str(row["invoice"]),
        payment_hash=str(row["payment_hash"]),
        claim_until=claim_until,
        invoice_expires_at=invoice_expires_at,
        max_uses=row["max_uses"],
        access_seconds=row["access_seconds"],
        uses_consumed=int(row["uses_consumed"] or 0),
        access_until=row["access_until"],
        settled_at=row["settled_at"],
        reused=reused,
        buyer_ip_accepted=buyer_ip_accepted,
    )


def _capacity_kwargs(
    *,
    client_id: int,
    api_key_id: int | None,
    buyer_ip_hash: str | None,
    now: int,
) -> dict:
    return {
        "client_id": int(client_id),
        "now": int(now),
        "claim_grace_seconds": config.PAYWALL_CLAIM_GRACE_SECONDS,
        "claim_cap_seconds": config.PAYWALL_TOKEN_TTL_CAP_SECONDS,
        "max_open_per_client": config.MAX_OPEN_CHALLENGES_PER_CLIENT,
        "buyer_ip_hash": buyer_ip_hash,
        "buyer_rate_max": config.BUYER_CHALLENGE_MAX,
        "buyer_rate_window_seconds": config.RL_WINDOW_SECONDS,
        "buyer_max_open": config.BUYER_MAX_OPEN_CHALLENGES,
        "buyer_limit_scope": config.BUYER_LIMIT_SCOPE,
        "api_key_id": api_key_id,
    }


def _http_resource_url(value: str | None) -> str | None:
    """A public http(s) URL with no userinfo and no fragment."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 500 or any(char in text for char in "\r\n\0 "):
        return None
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    if parts.username or parts.password or parts.fragment:
        return None
    return text


def _buyer_hash_for(request: Request, header: str | None) -> str | None:
    peer = request.client.host if request.client else None
    buyer_ip = buyer_ip_from_trusted_proxy(
        peer=peer,
        header=header,
        trusted_proxies=config.TRUSTED_PROXIES,
    )
    if not buyer_ip:
        return None
    return hash_buyer_ip(buyer_ip, secret=config.MACAROON_SECRET)


def _attach_x402_quote(
    lightning_body: dict,
    body: PaywallChallengeIn,
    request: Request,
    auth: db_keys.Principal,
    buyer_header: str | None,
) -> JSONResponse | dict:
    """Keep the Lightning challenge and attach the locked USDC quote when a rate exists."""
    from . import x402_service

    pay_to = db_x402.payee_verified(config.DB_PATH, client_id=auth.client.id)
    if not pay_to:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "payee_evm_not_verified"},
            headers={"Cache-Control": "no-store"},
        )
    mode = body.x402_mode or "test"
    plan = x402_service.quote_plan(
        {"rail_lightning": 1, "rail_x402": 1, "x402_mode": mode},
        {
            "price_currency": "sats",
            "price_sats": int(lightning_body["amount_sats"]),
            "price_usd_atomic": None,
        },
    )
    try:
        buyer_hash = _buyer_hash_for(request, buyer_header)
    except ValueError:
        buyer_hash = None
    resource_url = _http_resource_url(body.resource_url)
    if resource_url is None:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "invalid_resource_url"},
            headers={"Cache-Control": "no-store"},
        )
    merged = _lock_lightning_offer(
        lightning_body,
        plan=plan,
        pay_to=pay_to,
        client_id=auth.client.id,
        resource=body.resource,
        resource_url=resource_url,
        buyer_ip_hash=buyer_hash,
        max_uses=body.max_uses,
        access_seconds=body.access_seconds,
    )
    response = JSONResponse(content=merged, headers={"Cache-Control": "no-store"})
    if merged.get("payment_required"):
        response.headers["PAYMENT-REQUIRED"] = str(merged["payment_required"])
    return response


@app.post("/v1/paywall/challenge")
def v1_paywall_challenge(
    body: PaywallChallengeIn,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    x_satsgate_buyer_ip: str | None = Header(default=None, alias="X-Satsgate-Buyer-Ip"),
):
    """Generate an L402 challenge for a resource.

    How to use it:
    - Your backend (customer) calls this endpoint and receives invoice + macaroon.
    - Your backend returns HTTP 402 to *your* end user with those values.

    `invoice_expires_at` is when the invoice stops being payable. `claim_until`
    (also returned as `valid_until`) is when satsgate will still unlock it.
    Passing `payee_lightning_address` on the first challenge saves it. Change
    the saved payee with POST /v1/client/payee. A restricted key cannot save or
    change the payee.

    A trusted proxy may send `X-Satsgate-Buyer-Ip` with the end buyer's address.
    The header is ignored unless the TCP peer is in `SATSGATE_TRUSTED_PROXIES`.
    Without it, limits stay per client, as before.
    """

    auth = _paywall_principal(x_api_key, body.resource)
    if isinstance(auth, JSONResponse):
        return auth
    if body.x402_mode is not None and not body.x402:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "x402_mode_invalid"},
            headers={"Cache-Control": "no-store"},
        )
    if body.x402:
        mode = body.x402_mode or "test"
        if mode not in {"test", "live"}:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "x402_mode_invalid"},
                headers={"Cache-Control": "no-store"},
            )
        if mode == "live" and not x402_mod.mainnet_enabled():
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "x402_mainnet_disabled"},
                headers={"Cache-Control": "no-store"},
            )
        if _http_resource_url(body.resource_url) is None:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "invalid_resource_url"},
                headers={"Cache-Control": "no-store"},
            )
        if not db_x402.payee_verified(config.DB_PATH, client_id=auth.client.id):
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "payee_evm_not_verified"},
                headers={"Cache-Control": "no-store"},
            )
    issued = _issue_paywall_challenge(body, request, auth, x_satsgate_buyer_ip)
    if isinstance(issued, JSONResponse) or not body.x402:
        return issued
    return _attach_x402_quote(issued, body, request, auth, x_satsgate_buyer_ip)


def _issue_paywall_challenge(
    body: PaywallChallengeIn,
    request: Request,
    auth: db_keys.Principal,
    x_satsgate_buyer_ip: str | None,
    test_mode: bool = False,
):
    """Create a challenge for a principal the caller already authenticated.

    The public route checks the API key. The internal gate builds an account
    principal for the site owner, with no payee override, and calls this.
    """
    if body.access_seconds is not None and int(body.access_seconds) > int(config.PAYWALL_ACCESS_CAP_SECONDS):
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "access_seconds_too_long",
                "max_access_seconds": int(config.PAYWALL_ACCESS_CAP_SECONDS),
                "detail": "access_seconds cannot exceed the server cap. Shorten the pass or raise the cap.",
            },
        )
    client = auth.client

    # Minimum payable lifetime. The macaroon follows the invoice claim window,
    # the same way a top-up does, so a 24h invoice is not trapped behind a 10-minute token.
    min_expiry = int(body.ttl_seconds or config.TOKEN_TTL_SECONDS)
    memo = body.memo or "satsgate paywall"

    requested_payee = (body.payee_lightning_address or "").strip() or None
    stored_payee = (client.payee_lightning_address or "").strip() or None
    payee_saved = False

    # Rule: each client has 1 registered payee. We do not allow changing it per request.
    if stored_payee:
        if requested_payee and requested_payee != stored_payee:
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error": "payee_mismatch",
                    "detail": (
                        "This client already has a saved payee. The first challenge that includes "
                        "payee_lightning_address saves it, and so does POST /v1/client/payee. "
                        "This request did not change it."
                    ),
                    "registered_payee_lightning_address": stored_payee,
                    "hint": "Change it with POST /v1/client/payee, then create the challenge again.",
                },
            )
        payee = stored_payee
    else:
        # Fast onboarding: if no payee is set yet, the account key may set it on the first challenge.
        if requested_payee:
            if auth.scope != db_keys.SCOPE_ACCOUNT:
                return _insufficient_scope(auth.scope)
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
            payee_saved = True
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

    peer = request.client.host if request.client else None
    try:
        buyer_ip = buyer_ip_from_trusted_proxy(
            peer=peer,
            header=x_satsgate_buyer_ip,
            trusted_proxies=config.TRUSTED_PROXIES,
        )
    except ValueError as exc:
        if str(exc) == "invalid_buyer_ip":
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error": "invalid_buyer_ip",
                    "detail": "X-Satsgate-Buyer-Ip must be a single IP address.",
                },
            )
        raise
    buyer_hash = hash_buyer_ip(buyer_ip, secret=config.MACAROON_SECRET) if buyer_ip else None
    buyer_accepted = buyer_hash is not None
    created_at = int(time.time())

    if buyer_hash and config.CHALLENGE_REUSE_SECONDS > 0:
        existing = db.find_reusable_paywall_challenge(
            config.DB_PATH,
            client_id=client.id,
            buyer_ip_hash=buyer_hash,
            resource=body.resource,
            amount_sats=int(body.amount_sats),
            payee=payee,
            max_uses=body.max_uses,
            access_seconds=body.access_seconds,
            api_key_id=auth.api_key_id,
            reuse_seconds=config.CHALLENGE_REUSE_SECONDS,
            now=created_at,
        )
        if existing is not None:
            return _challenge_from_row(existing, payee_saved=False, reused=True, buyer_ip_accepted=True)

    try:
        db.preview_challenge_capacity(
            config.DB_PATH,
            **_capacity_kwargs(
                client_id=client.id,
                api_key_id=auth.api_key_id,
                buyer_ip_hash=buyer_hash,
                now=created_at,
            ),
        )
    except db.ChallengeLimit as exc:
        return _challenge_limited(exc)

    # Generate invoice. min_expiry rejects an invoice that dies too soon. It does
    # not shorten a longer invoice from the payee's provider.
    try:
        if config.WALLET_MODE == "mock":
            inv = WALLET.create_invoice(
                amount_sats=int(body.amount_sats),
                memo=memo,
                expiry_seconds=min_expiry,
                min_expiry_seconds=min_expiry,
            )
        else:
            if not payee or not _looks_like_lightning_address(payee):
                return JSONResponse(status_code=400, content={"ok": False, "error": "payee_invalid_lightning_address"})
            inv = _get_payee_wallet(payee).create_invoice(
                amount_sats=int(body.amount_sats),
                memo=memo,
                min_expiry_seconds=min_expiry,
            )
    except (ssrf.SSRFError, InvoiceValidationError, LnurlError, ValueError) as exc:
        return _upstream_error(exc)

    created_at = int(time.time())
    invoice_expires_at = getattr(inv, "expires_at", None)
    if invoice_expires_at is None:
        invoice_expires_at = created_at + min_expiry
    invoice_expires_at = int(invoice_expires_at)
    claim_until = _paywall_macaroon_exp(expires_at=invoice_expires_at, created_at=created_at)

    macaroon = make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=PURPOSE_PAYWALL,
        payment_hash=inv.payment_hash,
        resource=body.resource,
        amount_sats=int(body.amount_sats),
        invoice=inv.invoice,
        ttl_seconds=max(1, claim_until - created_at),
        exp=claim_until,
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
            expires_at=invoice_expires_at,
            api_key_id=auth.api_key_id,
            max_uses=body.max_uses,
            access_seconds=body.access_seconds,
            buyer_ip_hash=buyer_hash,
            max_open_per_client=config.MAX_OPEN_CHALLENGES_PER_CLIENT,
            buyer_rate_max=config.BUYER_CHALLENGE_MAX,
            buyer_rate_window_seconds=config.RL_WINDOW_SECONDS,
            buyer_max_open=config.BUYER_MAX_OPEN_CHALLENGES,
            buyer_limit_scope=config.BUYER_LIMIT_SCOPE,
            now=created_at,
            claim_grace_seconds=config.PAYWALL_CLAIM_GRACE_SECONDS,
            claim_cap_seconds=config.PAYWALL_TOKEN_TTL_CAP_SECONDS,
            test_mode=bool(test_mode),
        )
    except db.ChallengeLimit as exc:
        return _challenge_limited(exc)
    except FundsRefused:
        from .advice import balance_advice
        from .quota import free_remaining, reset_displays

        now = int(time.time())
        with db._connect(config.DB_PATH) as conn:
            free = free_remaining(conn, auth.client.id, now)
        resets, local = reset_displays(now)
        content = {
            "ok": False,
            "error": "insufficient_balance",
            "hint": "Top up with POST /v1/topup/lightning or POST /v1/topup/usdc.",
        }
        tip = balance_advice(
            balance_msat=int(auth.client.balance_msat),
            free_remaining=free,
            resets_at=resets,
            resets_local=local,
            cannot_cover_fee=True,
        )
        if tip is not None:
            content["advice"] = tip
        return JSONResponse(
            status_code=409,
            content=content,
        )
    except Exception:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"ok": False, "error": "db_error"})

    return _challenge_body(
        resource=body.resource,
        amount_sats=int(body.amount_sats),
        payee=payee,
        payee_saved=payee_saved,
        macaroon=macaroon,
        invoice=inv.invoice,
        payment_hash=inv.payment_hash,
        claim_until=claim_until,
        invoice_expires_at=invoice_expires_at,
        max_uses=body.max_uses,
        access_seconds=body.access_seconds,
        uses_consumed=0,
        access_until=None,
        settled_at=None,
        reused=False,
        buyer_ip_accepted=buyer_accepted,
    )


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


def _resource_mismatch_response(*, expected_resource: str, resource: str | None = None) -> JSONResponse:
    content: dict[str, Any] = {
        "ok": False,
        "error": "resource mismatch",
        "detail": (
            "expected_resource must exactly match the resource from the challenge. "
            "The comparison is case-sensitive and does not trim or rewrite the value."
        ),
        "expected_resource": expected_resource,
    }
    if resource is not None:
        content["resource"] = resource
        content["hint"] = "The resource field is the value this challenge was issued for."
    return JSONResponse(status_code=401, content=content)


def _paywall_auth_error(exc: L402Error, *, expected_resource: str) -> JSONResponse:
    if str(exc) == "resource mismatch":
        return _resource_mismatch_response(expected_resource=expected_resource)
    return JSONResponse(status_code=401, content={"ok": False, "error": str(exc)})


def _paywall_pending(*, payment_hash: str, poll: bool) -> JSONResponse | dict:
    if poll:
        return {
            "ok": True,
            "status": "pending",
            "settled": False,
            "payment_hash": payment_hash,
            "charged_credits": 0,
            "note": _PAYWALL_PENDING_NOTE,
        }
    return JSONResponse(
        status_code=402,
        content={
            "ok": False,
            "status": "pending",
            "settled": False,
            "error": "payment_pending",
            "payment_hash": payment_hash,
            "charged_credits": 0,
            "note": _PAYWALL_PENDING_NOTE,
        },
    )


def _unlock_paywall(
    *,
    authorization: str | None,
    expected_resource: str,
    cost_credits: int,
    client: db.Client,
    payment_hash: str | None = None,
    poll: bool = False,
    api_key_id: int | None = None,
    consume: bool = False,
    mode: str = "settle",
    receipt_site: dict | None = None,
    receipt_route: dict | None = None,
) -> JSONResponse | dict:
    macaroon_b64, preimage_hex = parse_authorization_header(authorization)
    peeked = peek_bindings(macaroon_b64)
    token_resource = peeked.get("res") if isinstance(peeked, dict) else None
    if not isinstance(token_resource, str) or not token_resource:
        raise L402Error("resource mismatch")

    # Verify against the token's own resource so a mismatch can name the issued
    # resource after the signature and client checks succeed. skip_expiry lets a
    # macaroon minted with the old 10-minute TTL finish inside the invoice window.
    # The claim deadline below is what limits that.
    payload = parse_and_verify_macaroon(
        keys=config.MACAROON_KEYS,
        macaroon_b64=macaroon_b64,
        purpose=PURPOSE_PAYWALL,
        resource=token_resource,
        client_id=client.id,
        skip_expiry=True,
    )

    token_hash = payload["ph"]
    if payment_hash is not None and token_hash != payment_hash:
        raise L402Error("payment_hash mismatch")

    row = db.get_paywall_challenge(config.DB_PATH, token_hash)
    if row is None or int(row["client_id"]) != int(client.id):
        raise L402Error("client mismatch")
    issued_resource = str(row["resource"])
    if issued_resource != expected_resource or payload.get("res") != expected_resource:
        return _resource_mismatch_response(expected_resource=expected_resource, resource=issued_resource)
    if preimage_hex is not None:
        verify_preimage_matches_payment_hash(preimage_hex=preimage_hex, payment_hash=token_hash)
    if int(row["amount_sats"]) != int(payload["amt"]):
        raise L402Error("amount mismatch")
    if invoice_binding(row["invoice"]) != payload["inv_h"]:
        raise L402Error("invoice mismatch")
    if payee_binding(row["payee"]) != payload["payee_h"]:
        raise L402Error("payee mismatch")

    if mode == "receipt" and receipt_site is not None:
        from . import db_sites
        from .gate_receipts import ReceiptIssueError, existing_body

        try:
            secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(receipt_site["id"]))
            early = existing_body(token_hash, secret=secret, aud=receipt_site["slug"], now=int(time.time()))
        except ReceiptIssueError as exc:
            return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code, **exc.extra})
        if early is not None:
            return early

    stored_expiry = int(row["expires_at"]) if row["expires_at"] is not None else None
    now = int(time.time())
    deadline = _paywall_claim_deadline(
        expires_at=stored_expiry,
        created_at=int(row["created_at"]),
        invoice=str(row["invoice"]),
    )
    already = db_verify.has_verification(config.DB_PATH, client_id=client.id, payment_hash=token_hash)
    confirmed = row["settled_at"] is not None
    if mode == "deliver" and not confirmed:
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "error": "payment_pending",
                "status": "pending",
                "settled": False,
                "payment_hash": token_hash,
                "charged_credits": 0,
            },
        )
    # A confirmed payment is not proved again. The gate retries an origin
    # failure with the same macaroon and does not poll the wallet a second time.
    if mode != "deliver" and not already and not confirmed:
        if deadline is None:
            if now > int(payload["exp"]):
                raise L402Error("token expired")
        elif now > int(deadline):
            raise L402Error("invoice expired")

        if preimage_hex is None and not row["verify_url"]:
            return JSONResponse(status_code=401, content={"ok": False, "error": "preimage_required"})

        if row["verify_url"]:
            state = _paywall_lud21(
                verify_url=str(row["verify_url"]),
                payment_hash=token_hash,
                preimage_hex=preimage_hex,
            )
            if isinstance(state, JSONResponse):
                return state
            if state == "pending":
                return _paywall_pending(payment_hash=token_hash, poll=poll)

    try:
        if mode == "receipt":
            from .gate_receipts import ReceiptIssueError, mint_lightning

            if receipt_site is None or receipt_route is None:
                raise ReceiptIssueError("paywall_unavailable", 502)
            try:
                return mint_lightning(
                    client_id=client.id,
                    site=receipt_site,
                    route=receipt_route,
                    payment_hash=token_hash,
                    amount_sats=int(row["amount_sats"]),
                    now=now,
                    test_mode=str(receipt_site.get("x402_mode") or "") == "test",
                )
            except ReceiptIssueError as exc:
                return JSONResponse(status_code=exc.status, content={"ok": False, "error": exc.code, **exc.extra})
        if mode == "confirm":
            spend = db_verify.confirm_payment(
                config.DB_PATH,
                client_id=client.id,
                payment_hash=token_hash,
                cost=int(cost_credits),
                access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
                now=now,
            )
        elif mode == "deliver":
            spend = db_verify.charge_after_delivery(
                config.DB_PATH,
                client_id=client.id,
                payment_hash=token_hash,
                cost=int(cost_credits),
                resource=expected_resource,
                api_key_id=api_key_id,
                now=now,
            )
        else:
            spend = db_verify.settle_and_consume(
                config.DB_PATH,
                client_id=client.id,
                payment_hash=token_hash,
                cost=int(cost_credits),
                resource=expected_resource,
                api_key_id=api_key_id,
                consume=bool(consume),
                access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
                now=now,
            )
    except db_verify.UsageDenied as exc:
        detail = (
            "This payment has no uses left. Create a new challenge for another request."
            if exc.code == "token_used_up"
            else "This payment's access window has ended. Create a new challenge for another request."
        )
        return JSONResponse(
            status_code=401,
            content={
                "ok": False,
                "error": exc.code,
                "status": "settled",
                "settled": True,
                "payment_hash": token_hash,
                "resource": expected_resource,
                "charged_credits": exc.charged,
                "new_balance": exc.new_balance,
                "detail": detail,
                **exc.usage,
            },
        )

    claim_until = int(deadline) if deadline is not None else int(payload["exp"])
    note = _PAYWALL_UNLOCK_NOTE
    if spend.get("max_uses") is not None or spend.get("access_seconds") is not None:
        note += (
            " consume=true takes one use. uses_remaining and access_until are what this payment has left."
            " HTTP 401 token_used_up or token_expired means the buyer needs a new challenge."
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
        "claim_until": claim_until,
        "invoice_expires_at": _paywall_invoice_expiry(stored_expires_at=stored_expiry, invoice=str(row["invoice"])),
        "cache_until": claim_until,
        "max_uses": spend["max_uses"],
        "access_seconds": spend["access_seconds"],
        "uses_consumed": spend["uses_consumed"],
        "uses_remaining": spend["uses_remaining"],
        "access_until": spend["access_until"],
        "settled_at": spend["settled_at"],
        "consumed": spend["consumed"],
        "note": note,
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

    `GET /v1/paywall/status/{payment_hash}` is the poll alternative. While the invoice
    is unpaid, this route returns HTTP 402 `payment_pending` and status returns HTTP 200
    `pending`. The first settled call on either route spends credits; a repeat spends 0.
    """

    auth = _paywall_principal(x_api_key, body.expected_resource)
    if isinstance(auth, JSONResponse):
        return auth

    try:
        return _unlock_paywall(
            authorization=authorization,
            expected_resource=body.expected_resource,
            cost_credits=int(body.cost_credits),
            client=auth.client,
            api_key_id=auth.api_key_id,
            consume=bool(body.consume),
            mode="confirm" if body.charge is False else "settle",
        )
    except L402Error as e:
        return _paywall_auth_error(e, expected_resource=body.expected_resource)
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
    consume: bool = Query(
        default=False,
        description="When true, atomically take one use of this payment. False checks without consuming.",
    ),
    charge: bool = Query(
        default=True,
        description="When false, confirm without debiting. The default still debits on the first settled call.",
    ),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Poll a paywall challenge paid from any wallet.

    Requires the merchant API key and the macaroon issued for this payment hash.
    This is an alternative to POST /v1/paywall/verify, not a free read. The first
    settled call spends credits once for this payment_hash. A repeat, on either
    route, spends 0. While the invoice is unpaid this route returns HTTP 200
    `status=pending` (verify returns HTTP 402 `payment_pending` for that same state).
    """
    normalized = _payment_hash_or_none(payment_hash)
    if normalized is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_payment_hash"})

    auth = _paywall_principal(x_api_key, expected_resource)
    if isinstance(auth, JSONResponse):
        return auth

    try:
        return _unlock_paywall(
            authorization=authorization,
            expected_resource=expected_resource,
            cost_credits=int(cost_credits),
            client=auth.client,
            payment_hash=normalized,
            poll=True,
            api_key_id=auth.api_key_id,
            consume=bool(consume),
            mode="confirm" if charge is False else "settle",
        )
    except L402Error as e:
        return _paywall_auth_error(e, expected_resource=expected_resource)
    except ValueError as e:
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(e),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
        )


@app.post("/v1/paywall/charge")
def v1_paywall_charge(
    body: PaywallChargeIn,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Debit after the origin returned 2xx. A confirm call does not debit.

    Old clients omit this route. They keep sending charge=true on verify, which
    still debits before they forward.
    """
    normalized = _payment_hash_or_none(body.payment_hash)
    if normalized is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_payment_hash"})
    auth = _paywall_principal(x_api_key, body.expected_resource)
    if isinstance(auth, JSONResponse):
        return auth
    try:
        return _unlock_paywall(
            authorization=authorization,
            expected_resource=body.expected_resource,
            cost_credits=int(body.cost_credits),
            client=auth.client,
            payment_hash=normalized,
            api_key_id=auth.api_key_id,
            consume=False,
            mode="deliver",
        )
    except L402Error as e:
        return _paywall_auth_error(e, expected_resource=body.expected_resource)
    except ValueError as e:
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(e),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
        )


def _paywall_x402(body: PaywallX402In, x_api_key: str | None, *, settle: bool):
    auth = _paywall_principal(x_api_key, body.resource)
    if isinstance(auth, JSONResponse):
        return auth
    resource_url = _http_resource_url(body.resource_url)
    if resource_url is None:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "invalid_resource_url"},
            headers={"Cache-Control": "no-store"},
        )
    from . import x402_service

    try:
        if settle:
            result = x402_service.settle_payment(
                client_id=auth.client.id,
                slug="",
                path="",
                resource=body.resource,
                encoded=body.payment_signature,
                resource_url=resource_url,
                api_key_id=auth.api_key_id,
            )
        else:
            result = x402_service.verify_payment(
                client_id=auth.client.id,
                slug="",
                path="",
                resource=body.resource,
                encoded=body.payment_signature,
                resource_url=resource_url,
            )
    except x402_mod.X402Error as exc:
        content: dict[str, object] = {"ok": False, "error": exc.code}
        if exc.reason:
            content["reason"] = exc.reason
        return JSONResponse(status_code=exc.status, content=content, headers={"Cache-Control": "no-store"})
    except ValueError as exc:
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(exc),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
            headers={"Cache-Control": "no-store"},
        )
    response = JSONResponse(content=result, headers={"Cache-Control": "no-store"})
    if result.get("payment_response"):
        response.headers["PAYMENT-RESPONSE"] = str(result["payment_response"])
    return response


@app.post("/v1/paywall/x402/verify")
def v1_paywall_x402_verify(
    body: PaywallX402In,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Check a PAYMENT-SIGNATURE. serve=true means the caller may call the origin. No credit moves."""
    return _paywall_x402(body, x_api_key, settle=False)


@app.post("/v1/paywall/x402/settle")
def v1_paywall_x402_settle(
    body: PaywallX402In,
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
):
    """Call only after the origin returned 2xx. The facilitator settles, then one credit is taken."""
    return _paywall_x402(body, x_api_key, settle=True)


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



