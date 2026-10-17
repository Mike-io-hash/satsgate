"""ASGI app. Unpaid requests get a 402. Paid requests are consumed, then forwarded."""

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

from satsgate_proxy import __version__
from satsgate_proxy.client_ip import buyer_ip_for_core
from satsgate_proxy.config import Route as PayRoute
from satsgate_proxy.config import Settings
from satsgate_proxy.core_client import (
    CoreResult,
    create_challenge,
    unlock_with_preimage,
    unlock_without_preimage,
)
from satsgate_proxy.forward import forward
from satsgate_proxy.macaroon import macaroon_fields
from satsgate_proxy.match import match_request

log = logging.getLogger("satsgate_proxy")

_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_POLL_HINT = (
    "Pay the invoice, then retry with Authorization: L402 <macaroon>:<preimage>. "
    "If the wallet does not return a preimage, retry with Authorization: L402 <macaroon> "
    "and this proxy will poll until the invoice settles."
)
_PENDING_HINT = (
    "The invoice is not settled yet. Retry the same Authorization header. Do not pay a new invoice."
)


def _json(status: int, error: str, **extra: object) -> JSONResponse:
    headers = {}
    retry = extra.get("retry_after_seconds")
    if isinstance(retry, int):
        headers["Retry-After"] = str(retry)
    return JSONResponse({"ok": False, "error": error, **extra}, status_code=status, headers=headers)


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


def _challenge_response(result: CoreResult, reason: str | None, route: PayRoute) -> JSONResponse:
    challenge = result.challenge
    if challenge is None:
        return _json(502, "paywall_unavailable")
    max_uses, access_seconds = route.access.policy()
    body: dict[str, object] = {
        "ok": False,
        "error": "payment_required",
        "amount_sats": challenge.amount_sats,
        "payment_hash": challenge.payment_hash,
        "invoice": challenge.invoice,
        "invoice_expires_at": challenge.invoice_expires_at,
        "macaroon": challenge.macaroon,
        "resource": challenge.resource,
        "max_uses": max_uses,
        "access_seconds": access_seconds,
        "hint": _POLL_HINT,
    }
    if reason:
        body["reason"] = reason
    return JSONResponse(body, status_code=402, headers={"WWW-Authenticate": challenge.www_authenticate})


def _limited(result: CoreResult) -> JSONResponse:
    retry = result.retry_after if result.retry_after is not None else 1
    return _json(429, result.error or "rate_limited", retry_after_seconds=retry)


def _pending(result: CoreResult) -> JSONResponse:
    retry = result.retry_after if result.retry_after is not None else 1
    body: dict[str, object] = {
        "ok": False,
        "error": "payment_pending",
        "retry_after_seconds": retry,
        "hint": _PENDING_HINT,
    }
    if result.payment_hash:
        body["payment_hash"] = result.payment_hash
    return JSONResponse(body, status_code=402, headers={"Retry-After": str(retry)})


async def _unlock(request: Request, settings: Settings, route: PayRoute, header: str) -> CoreResult:
    client: httpx.AsyncClient = request.app.state.http
    try:
        macaroon, preimage = _split_token(header)
    except ValueError as exc:
        return CoreResult(action="fresh", error=str(exc))
    fields = macaroon_fields(macaroon)
    if fields is not None and fields.get("res") and fields["res"] != route.resource:
        return CoreResult(action="fresh", error="resource mismatch")
    if preimage is None:
        if fields is None or "ph" not in fields:
            return CoreResult(action="fresh", error="invalid macaroon")
        scheme = header.split(None, 1)[0]
        return await unlock_without_preimage(
            client,
            settings,
            route,
            authorization=f"{scheme} {macaroon}",
            payment_hash=fields["ph"],
        )
    return await unlock_with_preimage(client, settings, route, header)


async def handle(request: Request) -> Response:
    settings: Settings = request.app.state.settings
    method = request.method.upper()
    path = request.url.path
    if path == "/healthz" and method in {"GET", "HEAD"}:
        if method == "HEAD":
            return Response(status_code=200, media_type="application/json")
        payload = {"ok": True, "component": "satsgate-proxy", "version": __version__}
        return Response(json.dumps(payload).encode("utf-8"), status_code=200, media_type="application/json")

    body = await _read_body(request, settings.max_request_bytes)
    if isinstance(body, Response):
        return body
    request.state.body = body

    found = match_request(settings.routes, settings.free_patterns, method, path)
    if found.kind == "not_found":
        return _json(404, "not_found")
    if found.kind == "method":
        return JSONResponse(
            {"ok": False, "error": "method_not_allowed"},
            status_code=405,
            headers={"Allow": ", ".join(found.allow)},
        )

    if found.kind == "free":
        return await forward(
            request,
            settings,
            payment_hash=None,
            resource=None,
            paid_sats=None,
            use_spent=False,
        )

    route = found.route
    if not isinstance(route, PayRoute):
        return _json(404, "not_found")

    reason: str | None = None
    authorization = _l402_authorization(request)
    if authorization is not None:
        unlocked = await _unlock(request, settings, route, authorization)
        if unlocked.action == "forward":
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
            return await forward(
                request,
                settings,
                payment_hash=payment_hash.lower(),
                resource=route.resource,
                paid_sats=paid,
                use_spent=True,
            )
        if unlocked.action == "pending":
            return _pending(unlocked)
        if unlocked.action == "limited":
            return _limited(unlocked)
        if unlocked.action == "unavailable":
            return _json(502, "paywall_unavailable")
        reason = unlocked.error or None

    buyer_ip = buyer_ip_for_core(
        peer=_peer(request),
        forwarded_for=request.headers.get("x-forwarded-for"),
        trusted_proxies=settings.trusted_proxies,
    )
    challenge = await create_challenge(request.app.state.http, settings, route, buyer_ip)
    if challenge.action == "limited":
        return _limited(challenge)
    if challenge.action != "challenge":
        return _json(502, "paywall_unavailable")
    return _challenge_response(challenge, reason, route)


def build_app(settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> Starlette:
    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        timeout = httpx.Timeout(max(settings.core_timeout, settings.upstream_timeout))
        app.state.http = httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
        )
        try:
            yield
        finally:
            await app.state.http.aclose()

    app = Starlette(
        routes=[
            Route("/", handle, methods=_METHODS),
            Route("/{path:path}", handle, methods=_METHODS),
        ],
        lifespan=lifespan,
    )
    app.state.settings = settings
    return app
