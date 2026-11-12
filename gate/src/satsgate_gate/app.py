"""ASGI app. ``https://gate.satsgate.org/<slug>/<path>`` sells a receipt and nothing else.

The gate does not read the request body and does not call the seller.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from satsgate_gate import __version__
from satsgate_gate.cache import CachedSite, SiteCache
from satsgate_gate.client_ip import buyer_ip_for_core
from satsgate_gate.config import Settings, load_settings
from satsgate_gate.core_client import (
    CoreResult,
    core_http_client,
    create_challenge,
    fetch_site,
    fetch_status,
    request_lightning_receipt,
    request_x402_receipt,
)
from satsgate_gate.rate_limit import RateLimiter
from satsgate_gate.redeem import origin_target, seller_host

log = logging.getLogger("satsgate_gate")

_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_ALLOWED = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
_POLL_HINT = (
    "Pay the invoice, then retry with Authorization: L402 <macaroon>:<preimage>. "
    "If the wallet does not return a preimage, retry with Authorization: L402 <macaroon> "
    "and this gate will poll until the invoice settles."
)
_PENDING_HINT = (
    "The invoice is not settled yet. Retry the same Authorization header. Do not pay a new invoice."
)
_PAYMENT_SIGNATURE_MAX = 8192


def _json(status: int, error: str, **extra: object) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    retry = extra.get("retry_after_seconds")
    if isinstance(retry, int):
        headers["Retry-After"] = str(retry)
    return JSONResponse({"ok": False, "error": error, **extra}, status_code=status, headers=headers)


def parse_public_path(path: str) -> tuple[str, str] | None:
    if not path.startswith("/") or "\\" in path or "\x00" in path:
        return None
    raw = path[1:]
    if not raw:
        return None
    if "/" not in raw:
        slug, route = raw, "/"
    else:
        slug, rest = raw.split("/", 1)
        route = "/" + rest
    if not slug or "/" in slug or slug in {".", ".."}:
        return None
    if route != "/" and (".." in route or "//" in route):
        return None
    return slug, route


def _payment_signature(request: Request) -> str | None:
    if "payment-signature" not in request.headers:
        return None
    return request.headers.get("payment-signature", "").strip()


def _l402_authorization(request: Request) -> str | None:
    raw = request.headers.get("authorization")
    if not raw:
        return None
    scheme = raw.split(None, 1)[0].lower()
    if scheme in {"l402", "lsat"}:
        return raw.strip()
    return None


def _peer(request: Request) -> str:
    client = request.client
    if client is None or not client.host:
        return "unknown"
    return client.host


def _redeem(site: CachedSite, route_path: str) -> str:
    return origin_target(site.origin_url, route_path, "")


def _delivery(site: CachedSite, route_path: str, settings: Settings) -> dict[str, object]:
    body: dict[str, object] = {
        "delivery": "receipt",
        "redeem_url": _redeem(site, route_path),
        "receipt_header": "Satsgate-Receipt",
        "seller_host": seller_host(site.origin_url),
    }
    if settings.terms_url:
        body["terms_url"] = settings.terms_url
    if settings.abuse_contact:
        body["abuse_contact"] = settings.abuse_contact
    return body


def _link(url: str) -> str:
    return f"<{url}>; rel=\"satsgate-redeem\""


def _challenge_response(result: CoreResult, reason: str | None, site: CachedSite, route_path: str, settings: Settings) -> JSONResponse:
    challenge = result.challenge
    if challenge is None or (not challenge.offers_lightning and not challenge.offers_x402):
        return _json(502, "paywall_unavailable")
    url = _redeem(site, route_path)
    headers = {"Cache-Control": "no-store", "Link": _link(url)}
    delivery = _delivery(site, route_path, settings)
    if challenge.offers_lightning:
        body: dict[str, object] = {
            "ok": False,
            "error": "payment_required",
            "amount_sats": challenge.amount_sats,
            "payment_hash": challenge.payment_hash,
            "invoice": challenge.invoice,
            "invoice_expires_at": challenge.invoice_expires_at,
            "macaroon": challenge.macaroon,
            "resource": challenge.resource,
            "max_uses": challenge.max_uses,
            "access_seconds": challenge.access_seconds,
            "hint": _POLL_HINT,
            **delivery,
        }
        headers["WWW-Authenticate"] = challenge.www_authenticate
    else:
        body = {
            "ok": False,
            "error": "payment_required",
            "resource": challenge.resource,
            "max_uses": challenge.max_uses,
            "access_seconds": challenge.access_seconds,
            **delivery,
        }
    if reason:
        body["reason"] = reason
    if challenge.offers_x402 and challenge.x402 is not None:
        body["x402"] = challenge.x402
        if "testing" in challenge.x402:
            body["testing"] = challenge.x402["testing"]
        if "x402_mode" in challenge.x402:
            body["x402_mode"] = challenge.x402["x402_mode"]
        headers["PAYMENT-REQUIRED"] = challenge.payment_required
    return JSONResponse(body, status_code=402, headers=headers)


def _with_abuse_contact(body: dict[str, object], status: int, settings: Settings) -> dict[str, object]:
    """Add the configured contact on a public 402 JSON body. Other statuses stay as they are."""
    if status == 402 and settings.abuse_contact:
        body["abuse_contact"] = settings.abuse_contact
    return body


def _failure(result: CoreResult, settings: Settings) -> JSONResponse:
    if result.action == "missing":
        return _json(404, "not_found")
    if result.action == "limited":
        retry = result.retry_after if result.retry_after is not None else 1
        return _json(429, result.error or "rate_limited", retry_after_seconds=retry)
    if result.action == "pending":
        retry = result.retry_after if result.retry_after is not None else 1
        body = _with_abuse_contact(
            {
                "ok": False,
                "error": "payment_pending",
                "retry_after_seconds": retry,
                "payment_hash": result.payment_hash,
                "hint": _PENDING_HINT,
            },
            402,
            settings,
        )
        return JSONResponse(
            body,
            status_code=402,
            headers={"Retry-After": str(retry), "Cache-Control": "no-store"},
        )
    if result.action == "rejected" and result.http_status in {400, 401, 402, 403, 409} and result.error.isidentifier():
        extra: dict[str, object] = {}
        if result.reason:
            extra["reason"] = result.reason
        if result.http_status == 402 and settings.abuse_contact:
            extra["abuse_contact"] = settings.abuse_contact
        return _json(result.http_status, result.error, **extra)
    return _json(502, "paywall_unavailable")


def _head_if_402(response: Response, *, head: bool) -> Response:
    """HEAD keeps the 402 status and headers and does not invent a JSON body."""
    if head and response.status_code == 402:
        return Response(status_code=402, headers=dict(response.headers))
    return response


def _rate_limited(request: Request, slug: str, buyer_ip: str | None, *, test_mode: bool) -> JSONResponse | None:
    settings: Settings = request.app.state.settings
    per_site = settings.rl_test_per_site if test_mode else settings.rl_per_site
    per_buyer = settings.rl_test_per_buyer if test_mode else settings.rl_per_buyer
    site_limiter = request.app.state.test_site_limiter if test_mode else request.app.state.site_limiter
    buyer_limiter = request.app.state.test_buyer_limiter if test_mode else request.app.state.buyer_limiter
    if per_site > 0:
        allowed, retry = site_limiter.allow(f"site:{slug}")
        if not allowed:
            return _json(429, "rate_limited", retry_after_seconds=retry)
    if per_buyer > 0:
        allowed, retry = buyer_limiter.allow(f"buyer:{buyer_ip or _peer(request)}")
        if not allowed:
            return _json(429, "rate_limited", retry_after_seconds=retry)
    return None


async def _load_site(request: Request, slug: str) -> CachedSite | JSONResponse:
    settings: Settings = request.app.state.settings
    client = request.app.state.core_client
    cache: SiteCache = request.app.state.cache
    state = await fetch_status(client, settings, slug)
    if state == "missing":
        cache.drop(slug)
        return _json(404, "not_found")
    if state != "approved":
        cache.drop(slug)
        return _json(502, "paywall_unavailable")
    cached = cache.get(slug)
    if cached is not None:
        return cached
    loaded = await fetch_site(client, settings, slug)
    if loaded is None:
        cache.drop(slug)
        return _json(404, "not_found")
    if isinstance(loaded, str):
        return _json(502, "paywall_unavailable")
    cache.put(loaded)
    return loaded


def _receipt_response(result: CoreResult, site: CachedSite, route_path: str, *, head: bool) -> Response:
    payload = dict(result.receipt or {})
    payload["redeem_url"] = _redeem(site, route_path)
    payload["receipt_header"] = "Satsgate-Receipt"
    token = str(payload.get("receipt") or "")
    expires = str(payload.get("expires_at_iso") or "")
    headers = {"Cache-Control": "no-store", "Link": _link(str(payload["redeem_url"]))}
    if token and "\r" not in token and "\n" not in token:
        headers["Satsgate-Receipt"] = token
    if expires and "\r" not in expires and "\n" not in expires:
        headers["Satsgate-Receipt-Expires"] = expires
    if result.payment_response:
        headers["PAYMENT-RESPONSE"] = result.payment_response
    if head:
        return Response(status_code=200, headers=headers)
    return Response(json.dumps(payload).encode("utf-8"), status_code=200, media_type="application/json", headers=headers)


def _root(settings: Settings, *, head: bool) -> Response:
    payload: dict[str, object] = {
        "ok": True,
        "service": "satsgate-gate",
        "version": __version__,
        "delivery": "receipt",
    }
    if settings.terms_url:
        payload["terms_url"] = settings.terms_url
    if settings.abuse_contact:
        payload["abuse_contact"] = settings.abuse_contact
    headers = {"Cache-Control": "no-store"}
    if head:
        return Response(status_code=200, media_type="application/json", headers=headers)
    return JSONResponse(payload, headers=headers)


async def handle(request: Request) -> Response:
    settings: Settings = request.app.state.settings
    method = request.method.upper()
    path = request.url.path
    if path == "/healthz" and method in {"GET", "HEAD"}:
        if method == "HEAD":
            return Response(status_code=200, media_type="application/json", headers={"Cache-Control": "no-store"})
        return JSONResponse(
            {"ok": True, "component": "satsgate-gate", "version": __version__},
            headers={"Cache-Control": "no-store"},
        )
    if path == "/" and method in {"GET", "HEAD"}:
        return _root(settings, head=method == "HEAD")

    parsed = parse_public_path(path)
    if parsed is None:
        return _json(404, "not_found")
    slug, route_path = parsed
    if method not in _ALLOWED:
        return JSONResponse(
            {"ok": False, "error": "method_not_allowed"},
            status_code=405,
            headers={"Allow": "GET, HEAD, POST, PUT, PATCH, DELETE", "Cache-Control": "no-store"},
        )

    buyer_ip = buyer_ip_for_core(
        peer=_peer(request),
        forwarded_for=request.headers.get("x-forwarded-for"),
        trusted_proxies=settings.trusted_proxies,
    )
    site = await _load_site(request, slug)
    if isinstance(site, Response):
        return site
    limited = _rate_limited(request, slug, buyer_ip, test_mode=site.x402_mode == "test")
    if limited is not None:
        return limited
    route = site.route(route_path)
    if route is None:
        return _json(404, "not_found")

    authorization = _l402_authorization(request)
    payment_signature = _payment_signature(request)
    if authorization is not None and payment_signature is not None:
        return _json(400, "one_rail_only")
    client = request.app.state.core_client
    paid: CoreResult | None = None
    if payment_signature is not None:
        if (
            not payment_signature
            or len(payment_signature.encode("utf-8")) > _PAYMENT_SIGNATURE_MAX
            or any(char in payment_signature for char in "\r\n")
        ):
            return _json(400, "bad_signature")
        paid = await request_x402_receipt(
            client, settings, site, route, method=method, payment_signature=payment_signature
        )
    elif authorization is not None:
        paid = await request_lightning_receipt(
            client, settings, site, route, method=method, authorization=authorization
        )
    if paid is not None:
        if paid.action == "receipt":
            return _receipt_response(paid, site, route_path, head=method == "HEAD")
        if paid.action == "missing":
            request.app.state.cache.drop(slug)
        return _head_if_402(_failure(paid, settings), head=method == "HEAD")

    challenge = await create_challenge(client, settings, site, route, buyer_ip)
    if challenge.action == "missing":
        request.app.state.cache.drop(slug)
        return _json(404, "not_found")
    if challenge.action == "limited":
        return _failure(challenge, settings)
    if challenge.action != "challenge":
        return _json(502, "paywall_unavailable")
    response = _challenge_response(challenge, None, site, route_path, settings)
    return _head_if_402(response, head=method == "HEAD")


@asynccontextmanager
async def _lifespan(app: Starlette) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    if not settings.gate_token:
        log.warning("SATSGATE_GATE_TOKEN is unset; site requests cannot be charged")
    owns_core = not hasattr(app.state, "core_client")
    if owns_core:
        app.state.core_client = core_http_client(settings)
    try:
        yield
    finally:
        if owns_core:
            await app.state.core_client.aclose()


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or load_settings()
    app = Starlette(
        routes=[
            Route("/", handle, methods=_METHODS),
            Route("/{path:path}", handle, methods=_METHODS),
        ],
        lifespan=_lifespan,
    )
    app.state.settings = settings
    app.state.cache = SiteCache(settings.cache_seconds)
    window = settings.rl_window_seconds
    app.state.site_limiter = RateLimiter(window_seconds=window, max_requests=max(1, settings.rl_per_site))
    app.state.buyer_limiter = RateLimiter(window_seconds=window, max_requests=max(1, settings.rl_per_buyer))
    app.state.test_site_limiter = RateLimiter(window_seconds=window, max_requests=max(1, settings.rl_test_per_site))
    app.state.test_buyer_limiter = RateLimiter(window_seconds=window, max_requests=max(1, settings.rl_test_per_buyer))
    return app


app = create_app()
