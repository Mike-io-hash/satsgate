"""ASGI app. ``https://gate.satsgate.org/<slug>/<path>`` sells the route, then forwards it."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
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
    create_challenge,
    fetch_site,
    fetch_status,
    charge_lightning,
    settle_x402,
    unlock_with_preimage,
    unlock_without_preimage,
    verify_x402,
)
from satsgate_gate.forward import call_origin
from satsgate_gate.macaroon import macaroon_fields
from satsgate_gate.rate_limit import RateLimiter
from satsgate_gate.ssrf import build_origin_client

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
# Encoded header, before core sees it. Core also caps the decoded JSON at 8 KB.
_PAYMENT_SIGNATURE_MAX = 8192


def _json(status: int, error: str, **extra: object) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    retry = extra.get("retry_after_seconds")
    if isinstance(retry, int):
        headers["Retry-After"] = str(retry)
    return JSONResponse({"ok": False, "error": error, **extra}, status_code=status, headers=headers)


def parse_public_path(path: str) -> tuple[str, str] | None:
    """``/slug`` and ``/slug/`` are route ``/``. A longer path is exact, query excluded."""
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


async def _read_body(request: Request, limit: int) -> bytes | JSONResponse:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            return _json(400, "invalid_content_length")
        if size > limit:
            return _json(413, "request_too_large")
    chunks = bytearray()
    async for chunk in request.stream():
        if len(chunks) + len(chunk) > limit:
            return _json(413, "request_too_large")
        chunks.extend(chunk)
    return bytes(chunks)


def _payment_signature(request: Request) -> str | None:
    """The raw header, or None when the buyer did not send one."""
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


def _split_token(header: str) -> tuple[str, str | None]:
    try:
        _scheme, token = header.split(None, 1)
    except ValueError as exc:
        raise ValueError("malformed Authorization header") from exc
    token = token.strip()
    if ":" in token:
        macaroon, preimage = token.split(":", 1)
    else:
        macaroon, preimage = token, ""
    if not macaroon or any(char.isspace() for char in macaroon):
        raise ValueError("malformed L402 token")
    if preimage == "":
        return macaroon, None
    try:
        raw = bytes.fromhex(preimage)
    except ValueError as exc:
        raise ValueError("preimage is not hex") from exc
    if len(raw) != 32:
        raise ValueError("preimage is not hex")
    return macaroon, preimage.lower()


def _peer(request: Request) -> str:
    client = request.client
    if client is None or not client.host:
        return "unknown"
    return client.host


def _limited(result: CoreResult) -> JSONResponse:
    retry = result.retry_after if result.retry_after is not None else 1
    return _json(429, result.error or "rate_limited", retry_after_seconds=retry)


def _pending(result: CoreResult) -> JSONResponse:
    retry = result.retry_after if result.retry_after is not None else 1
    return JSONResponse(
        {
            "ok": False,
            "error": "payment_pending",
            "retry_after_seconds": retry,
            "payment_hash": result.payment_hash,
            "hint": _PENDING_HINT,
        },
        status_code=402,
        headers={"Retry-After": str(retry), "Cache-Control": "no-store"},
    )


def _challenge_response(result: CoreResult, reason: str | None) -> JSONResponse:
    challenge = result.challenge
    if challenge is None or (not challenge.offers_lightning and not challenge.offers_x402):
        return _json(502, "paywall_unavailable")
    headers = {"Cache-Control": "no-store"}
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
        }
        headers["WWW-Authenticate"] = challenge.www_authenticate
    else:
        body = {
            "ok": False,
            "error": "payment_required",
            "resource": challenge.resource,
            "max_uses": challenge.max_uses,
            "access_seconds": challenge.access_seconds,
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


def _x402_failure(result: CoreResult) -> JSONResponse:
    if result.action == "missing":
        return _json(404, "not_found")
    code = result.error
    status = result.http_status
    if result.action == "rejected" and status in {400, 402, 409} and code.isidentifier():
        extra: dict[str, object] = {}
        if result.reason:
            extra["reason"] = result.reason
        return _json(status, code, **extra)
    return _json(502, "paywall_unavailable")


def _rate_limited(request: Request, slug: str, buyer_ip: str | None) -> JSONResponse | None:
    settings: Settings = request.app.state.settings
    if settings.rl_per_site > 0:
        allowed, retry = request.app.state.site_limiter.allow(f"site:{slug}")
        if not allowed:
            return _json(429, "rate_limited", retry_after_seconds=retry)
    if settings.rl_per_buyer > 0:
        who = buyer_ip or _peer(request)
        allowed, retry = request.app.state.buyer_limiter.allow(f"buyer:{who}")
        if not allowed:
            return _json(429, "rate_limited", retry_after_seconds=retry)
    return None


async def _load_site(request: Request, slug: str) -> CachedSite | JSONResponse:
    settings: Settings = request.app.state.settings
    client: httpx.AsyncClient = request.app.state.core_client
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


async def _unlock(request: Request, site: CachedSite, route_path: str, header: str) -> CoreResult:
    from satsgate_gate.cache import GateRoute

    route = site.route(route_path)
    if not isinstance(route, GateRoute):
        return CoreResult(action="missing", error="not_found")
    client: httpx.AsyncClient = request.app.state.core_client
    settings: Settings = request.app.state.settings
    try:
        macaroon, preimage = _split_token(header)
    except ValueError as exc:
        return CoreResult(action="fresh", error=str(exc))
    fields = macaroon_fields(macaroon)
    resource = site.resource(route.path)
    if fields is not None and fields.get("res") and fields["res"] != resource:
        return CoreResult(action="fresh", error="resource mismatch")
    if preimage is None:
        if fields is None or "ph" not in fields:
            return CoreResult(action="fresh", error="invalid macaroon")
        scheme = header.split(None, 1)[0]
        return await unlock_without_preimage(
            client,
            settings,
            site,
            route,
            authorization=f"{scheme} {macaroon}",
            payment_hash=fields["ph"],
        )
    return await unlock_with_preimage(client, settings, site, route, header)


async def _pay_x402(request: Request, site: CachedSite, route, payment_signature: str) -> Response:
    """Verify, call the origin, and settle only after a 2xx. The gate never calls the facilitator."""
    settings: Settings = request.app.state.settings
    client: httpx.AsyncClient = request.app.state.core_client
    verified = await verify_x402(client, settings, site, route, payment_signature)
    if verified.action == "missing":
        request.app.state.cache.drop(site.slug)
        return _json(404, "not_found")
    if verified.action != "serve" or verified.amount_usd_atomic is None or not verified.payment_hash:
        return _x402_failure(verified)
    exchanged = await call_origin(
        request,
        settings,
        site,
        route_path=route.path,
        payment_hash=verified.payment_hash,
        resource=site.resource(route.path),
        paid_usd_atomic=verified.amount_usd_atomic,
    )
    if exchanged.error or not (200 <= exchanged.status < 300):
        return exchanged.response(use_spent=False if exchanged.error else None)
    settled = await settle_x402(client, settings, site, route, payment_signature)
    if settled.action != "settled" or not settled.payment_response:
        return _x402_failure(settled)
    return exchanged.response(use_spent=None, extra=(("PAYMENT-RESPONSE", settled.payment_response),))


async def _serve_lightning(request: Request, site: CachedSite, route, authorization: str) -> Response | str | None:
    """Confirm the Lightning payment, call the origin, and charge only on 2xx.

    A transport failure or a non-2xx origin response does not debit. The same
    macaroon can be retried. A grant that is already used up becomes a new 402.
    The origin body is not returned when the charge loses the use.
    """
    settings: Settings = request.app.state.settings
    unlocked = await _unlock(request, site, route.path, authorization)
    if unlocked.action == "pending":
        return _pending(unlocked)
    if unlocked.action == "limited":
        return _limited(unlocked)
    if unlocked.action == "unavailable":
        return _json(502, "paywall_unavailable")
    if unlocked.action == "missing":
        request.app.state.cache.drop(site.slug)
        return _json(404, "not_found")
    if unlocked.action != "forward":
        return unlocked.error or None

    payment_hash = unlocked.payment_hash
    if not payment_hash:
        fields = None
        try:
            macaroon, _preimage = _split_token(authorization)
            fields = macaroon_fields(macaroon)
        except ValueError:
            fields = None
        if fields is not None:
            payment_hash = fields["ph"]
    if not payment_hash:
        log.warning("settled unlock had no payment hash")
        return _json(502, "paywall_unavailable")
    paid = unlocked.amount_sats if unlocked.amount_sats is not None else route.price_sats
    if isinstance(paid, bool) or not isinstance(paid, int) or paid < 1:
        log.warning("settled unlock had no sats amount")
        return _json(502, "paywall_unavailable")
    exchanged = await call_origin(
        request,
        settings,
        site,
        route_path=route.path,
        payment_hash=payment_hash.lower(),
        resource=site.resource(route.path),
        paid_sats=paid,
    )
    if exchanged.error:
        return exchanged.response(use_spent=False)
    if not (200 <= exchanged.status < 300):
        return exchanged.response(use_spent=None)
    charged = await charge_lightning(
        request.app.state.core_client,
        settings,
        site,
        route,
        authorization=authorization,
        payment_hash=payment_hash.lower(),
    )
    if charged.action == "charged":
        return exchanged.response(use_spent=None)
    if charged.action == "fresh":
        return charged.error or "token_used_up"
    return _json(502, "paywall_unavailable")


async def handle(request: Request) -> Response:
    settings: Settings = request.app.state.settings
    method = request.method.upper()
    path = request.url.path
    if path == "/healthz" and method in {"GET", "HEAD"}:
        if method == "HEAD":
            return Response(status_code=200, media_type="application/json")
        payload = {"ok": True, "component": "satsgate-gate", "version": __version__}
        return Response(json.dumps(payload).encode("utf-8"), status_code=200, media_type="application/json")

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

    body = await _read_body(request, settings.max_request_bytes)
    if isinstance(body, Response):
        return body
    request.state.body = body

    buyer_ip = buyer_ip_for_core(
        peer=_peer(request),
        forwarded_for=request.headers.get("x-forwarded-for"),
        trusted_proxies=settings.trusted_proxies,
    )
    limited = _rate_limited(request, slug, buyer_ip)
    if limited is not None:
        return limited

    site = await _load_site(request, slug)
    if isinstance(site, Response):
        return site
    route = site.route(route_path)
    if route is None:
        return _json(404, "not_found")

    reason: str | None = None
    authorization = _l402_authorization(request)
    payment_signature = _payment_signature(request)
    if authorization is not None and payment_signature is not None:
        return _json(400, "one_rail_only")
    if payment_signature is not None:
        if (
            not payment_signature
            or len(payment_signature.encode("utf-8")) > _PAYMENT_SIGNATURE_MAX
            or any(char in payment_signature for char in "\r\n")
        ):
            return _json(400, "bad_signature")
        return await _pay_x402(request, site, route, payment_signature)
    if authorization is not None:
        served = await _serve_lightning(request, site, route, authorization)
        if isinstance(served, Response):
            return served
        reason = served

    challenge = await create_challenge(request.app.state.core_client, settings, site, route, buyer_ip)
    if challenge.action == "missing":
        request.app.state.cache.drop(slug)
        return _json(404, "not_found")
    if challenge.action == "limited":
        return _limited(challenge)
    if challenge.action != "challenge":
        return _json(502, "paywall_unavailable")
    return _challenge_response(challenge, reason)


@asynccontextmanager
async def _lifespan(app: Starlette) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    if not settings.gate_token:
        log.warning("SATSGATE_GATE_TOKEN is unset; site requests cannot be charged")
    owns_core = not hasattr(app.state, "core_client")
    owns_origin = not hasattr(app.state, "origin_client")
    if owns_core:
        app.state.core_client = httpx.AsyncClient(
            base_url=settings.core_base_url,
            timeout=httpx.Timeout(settings.core_timeout),
            follow_redirects=False,
            trust_env=False,
        )
    if owns_origin:
        app.state.origin_client = await build_origin_client(timeout=settings.upstream_timeout)
    try:
        yield
    finally:
        if owns_core:
            await app.state.core_client.aclose()
        if owns_origin:
            await app.state.origin_client.aclose()


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or load_settings()
    app = Starlette(
        routes=[Route("/{path:path}", handle, methods=_METHODS)],
        lifespan=_lifespan,
    )
    app.state.settings = settings
    app.state.cache = SiteCache(settings.cache_seconds)
    app.state.site_limiter = RateLimiter(
        window_seconds=settings.rl_window_seconds,
        max_requests=max(1, settings.rl_per_site),
    )
    app.state.buyer_limiter = RateLimiter(
        window_seconds=settings.rl_window_seconds,
        max_requests=max(1, settings.rl_per_buyer),
    )
    return app


app = create_app()
