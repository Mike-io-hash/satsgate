"""Internal API for the hosted gate process.

The gate and the core share a docker network. They do not share the sqlite
file. Sharing the file would give the gate every client row, API-key hash,
and ledger entry, plus ``SATSGATE_SITE_SECRET_KEY``, which decrypts every
origin secret. These routes return one approved site (including that site's
secret) and call the same challenge and unlock functions the public paywall
uses, on behalf of the site owner.

``SATSGATE_GATE_TOKEN`` is a different secret from the admin token. The admin
token can approve a site. This token cannot. When the gate token is unset the
routes answer 404, so a core that is not running a gate does not advertise
them. ``SATSGATE_GATE_PEERS``, when set, also requires the TCP peer. A public
request that reaches core through Caddy is not that peer. Caddy additionally
rejects ``/internal/*`` on the public hostname.

The routes are omitted from the public OpenAPI document.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config, db, db_keys, db_sites
from .client_ip import peer_is_trusted

router = APIRouter(include_in_schema=False)

_RESOURCE_MAX = 200
_NO_STORE = {"Cache-Control": "no-store"}


class GateChallengeIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)


class GateVerifyIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)
    consume: bool = True


def gate_resource(slug: str, path: str) -> str:
    return f"gate:{slug}:{path}"


def _not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"}, headers=_NO_STORE)


def _token_matches(presented: str, expected: str) -> bool:
    left = presented.encode("utf-8")
    right = expected.encode("utf-8")
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def _authorized(request: Request) -> JSONResponse | None:
    token = config.GATE_TOKEN
    if not token:
        return _not_found()
    presented = request.headers.get("x-satsgate-gate-token", "")
    if not presented or not _token_matches(presented, token):
        return _not_found()
    if config.GATE_PEERS:
        peer = request.client.host if request.client else None
        if not peer_is_trusted(peer, config.GATE_PEERS):
            return _not_found()
    return None


def _clean_slug(slug: str) -> str | None:
    try:
        return db_sites.clean_slug(slug)
    except ValueError:
        return None


def _clean_path(path: str) -> str | None:
    try:
        return db_sites.clean_path(path)
    except ValueError:
        return None


def _approved(slug: str) -> dict | None:
    site = db_sites.get_site_by_slug(config.DB_PATH, slug)
    if site is None or site.get("status") != "approved":
        return None
    return site


def _route(site: dict, path: str) -> dict | None:
    for route in site.get("routes") or []:
        if route.get("path") == path and len(gate_resource(site["slug"], path)) <= _RESOURCE_MAX:
            return route
    return None


def _owner(site: dict) -> db.Client | None:
    return db.get_client_by_id(config.DB_PATH, int(site["client_id"]))


def _owner_principal(client: db.Client) -> db_keys.Principal:
    return db_keys.Principal(
        client=client,
        api_key_id=None,
        scope=db_keys.SCOPE_ACCOUNT,
        resource_prefix=None,
        label=None,
    )


def _json(result: JSONResponse | dict) -> JSONResponse | dict:
    if isinstance(result, JSONResponse):
        result.headers["Cache-Control"] = "no-store"
        return result
    return JSONResponse(content=result, headers=_NO_STORE)


@router.get("/internal/gate/sites/{slug}/status")
def internal_site_status(slug: str, request: Request):
    """Approved or not. No secret, and no distinction between missing, pending, and disabled."""
    denied = _authorized(request)
    if denied is not None:
        return denied
    cleaned = _clean_slug(slug)
    if cleaned is None or _approved(cleaned) is None:
        return _not_found()
    return JSONResponse(content={"ok": True, "status": "approved"}, headers=_NO_STORE)


@router.get("/internal/gate/sites/{slug}")
def internal_site_config(slug: str, request: Request):
    """Approved site, routes, and that site's decrypted origin secret."""
    denied = _authorized(request)
    if denied is not None:
        return denied
    cleaned = _clean_slug(slug)
    site = _approved(cleaned) if cleaned is not None else None
    if site is None:
        return _not_found()
    try:
        secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(site["id"]))
    except ValueError as exc:
        if str(exc) == "site_secret_key_unconfigured":
            return JSONResponse(
                status_code=503,
                content={"ok": False, "error": "site_secret_key_unconfigured"},
                headers=_NO_STORE,
            )
        return _not_found()
    client = _owner(site)
    payee = None
    if client is not None:
        payee = (client.payee_lightning_address or "").strip() or None
    routes = []
    for route in site["routes"]:
        if len(gate_resource(site["slug"], route["path"])) > _RESOURCE_MAX:
            continue
        if route.get("price_currency", "sats") != "sats":
            continue
        price = route.get("price_sats")
        if isinstance(price, bool) or not isinstance(price, int) or price < 1:
            continue
        routes.append(
            {
                "path": route["path"],
                "price_sats": price,
                "max_uses": route["max_uses"],
                "access_seconds": route["access_seconds"],
            }
        )
    return JSONResponse(
        content={
            "ok": True,
            "slug": site["slug"],
            "client_id": int(site["client_id"]),
            "origin_url": site["origin_url"],
            "origin_secret": secret,
            "payee_lightning_address": payee,
            "routes": routes,
        },
        headers=_NO_STORE,
    )


@router.post("/internal/gate/challenge")
def internal_challenge(
    body: GateChallengeIn,
    request: Request,
    x_satsgate_buyer_ip: str | None = Header(default=None, alias="X-Satsgate-Buyer-Ip"),
):
    """Mint a challenge for one approved route, charged to the site owner."""
    denied = _authorized(request)
    if denied is not None:
        return denied
    slug = _clean_slug(body.slug)
    path = _clean_path(body.path)
    if slug is None or path is None:
        return _not_found()
    site = _approved(slug)
    if site is None:
        return _not_found()
    route = _route(site, path)
    client = _owner(site) if route is not None else None
    if route is None or client is None:
        return _not_found()
    from . import main as core

    from . import x402_service

    if x402_service.rail_for(site, route) == "x402":
        from . import db_x402

        pay_to = db_x402.payee_verified(config.DB_PATH, client_id=client.id)
        if not pay_to:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "payee_evm_not_verified"},
                headers=_NO_STORE,
            )
        peer = request.client.host if request.client else None
        try:
            buyer_ip = core.buyer_ip_from_trusted_proxy(
                peer=peer,
                header=x_satsgate_buyer_ip,
                trusted_proxies=config.TRUSTED_PROXIES,
            )
        except ValueError as exc:
            if str(exc) == "invalid_buyer_ip":
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "error": "invalid_buyer_ip"},
                    headers=_NO_STORE,
                )
            raise
        buyer_hash = core.hash_buyer_ip(buyer_ip, secret=config.MACAROON_SECRET) if buyer_ip else None
        try:
            body_out = x402_service.issue_offer(
                client_id=client.id,
                slug=slug,
                path=path,
                resource=gate_resource(slug, path),
                pay_to=pay_to,
                amount=int(route["price_usd_atomic"]),
                max_uses=route["max_uses"],
                access_seconds=route["access_seconds"],
                buyer_ip_hash=buyer_hash,
            )
        except core.db.ChallengeLimit as exc:
            response = core._challenge_limited(exc)
            response.headers["Cache-Control"] = "no-store"
            return response
        response = JSONResponse(content=body_out, headers=_NO_STORE)
        response.headers["PAYMENT-REQUIRED"] = body_out["payment_required"]
        return response
    if x402_service.rail_for(site, route) != "lightning":
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "rail_unavailable"},
            headers=_NO_STORE,
        )

    resource = gate_resource(slug, path)
    memo = f"satsgate {slug} {path}"
    if len(memo) > 250:
        memo = memo[:250]
    challenge = core.PaywallChallengeIn(
        amount_sats=int(route["price_sats"]),
        resource=resource,
        memo=memo,
        max_uses=route["max_uses"],
        access_seconds=route["access_seconds"],
    )
    return _json(
        core._issue_paywall_challenge(
            challenge,
            request,
            _owner_principal(client),
            x_satsgate_buyer_ip,
        )
    )


def _unlock(
    *,
    request: Request,
    slug: str,
    path: str,
    authorization: str | None,
    payment_hash: str | None,
    poll: bool,
    consume: bool,
):
    denied = _authorized(request)
    if denied is not None:
        return denied
    cleaned_slug = _clean_slug(slug)
    cleaned_path = _clean_path(path)
    if cleaned_slug is None or cleaned_path is None:
        return _not_found()
    site = _approved(cleaned_slug)
    if site is None:
        return _not_found()
    route = _route(site, cleaned_path)
    client = _owner(site) if route is not None else None
    if route is None or client is None:
        return _not_found()
    from . import main as core

    try:
        return _json(
            core._unlock_paywall(
                authorization=authorization,
                expected_resource=gate_resource(cleaned_slug, cleaned_path),
                cost_credits=1,
                client=client,
                payment_hash=payment_hash,
                poll=poll,
                api_key_id=None,
                consume=bool(consume),
            )
        )
    except core.L402Error as exc:
        response = core._paywall_auth_error(exc, expected_resource=gate_resource(cleaned_slug, cleaned_path))
        response.headers["Cache-Control"] = "no-store"
        return response
    except ValueError as exc:
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(exc),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
            headers=_NO_STORE,
        )


@router.post("/internal/gate/verify")
def internal_verify(
    body: GateVerifyIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    return _unlock(
        request=request,
        slug=body.slug,
        path=body.path,
        authorization=authorization,
        payment_hash=None,
        poll=False,
        consume=bool(body.consume),
    )


@router.get("/internal/gate/status/{payment_hash}")
def internal_status(
    payment_hash: str,
    request: Request,
    slug: str = Query(..., min_length=1, max_length=80),
    path: str = Query(..., min_length=1, max_length=200),
    consume: bool = Query(default=True),
    authorization: str | None = Header(default=None),
):
    from . import main as core

    denied = _authorized(request)
    if denied is not None:
        return denied
    normalized = core._payment_hash_or_none(payment_hash)
    if normalized is None:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "invalid_payment_hash"},
            headers=_NO_STORE,
        )
    return _unlock(
        request=request,
        slug=slug,
        path=path,
        authorization=authorization,
        payment_hash=normalized,
        poll=True,
        consume=bool(consume),
    )


class X402PaymentIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)
    payment_signature: str = Field(min_length=1, max_length=12000)


def _x402_call(request: Request, body: X402PaymentIn, *, settle: bool):
    denied = _authorized(request)
    if denied is not None:
        return denied
    slug = _clean_slug(body.slug)
    path = _clean_path(body.path)
    if slug is None or path is None:
        return _not_found()
    site = _approved(slug)
    route = _route(site, path) if site is not None else None
    client = _owner(site) if site is not None and route is not None else None
    if site is None or route is None or client is None:
        return _not_found()
    from . import x402
    from . import x402_service

    if x402_service.rail_for(site, route) != "x402":
        return JSONResponse(status_code=400, content={"ok": False, "error": "rail_unavailable"}, headers=_NO_STORE)
    try:
        if settle:
            result = x402_service.settle_payment(
                client_id=client.id,
                slug=slug,
                path=path,
                resource=gate_resource(slug, path),
                encoded=body.payment_signature,
            )
        else:
            result = x402_service.verify_payment(
                client_id=client.id,
                slug=slug,
                path=path,
                resource=gate_resource(slug, path),
                encoded=body.payment_signature,
            )
    except x402.X402Error as exc:
        content = {"ok": False, "error": exc.code}
        if exc.reason:
            content["reason"] = exc.reason
        return JSONResponse(status_code=exc.status, content=content, headers=_NO_STORE)
    except ValueError as exc:
        return JSONResponse(
            status_code=402,
            content={
                "ok": False,
                "error": str(exc),
                "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
            },
            headers=_NO_STORE,
        )
    response = JSONResponse(content=result, headers=_NO_STORE)
    if result.get("payment_response"):
        response.headers["PAYMENT-RESPONSE"] = result["payment_response"]
    return response


@router.post("/internal/gate/x402/verify")
def internal_x402_verify(body: X402PaymentIn, request: Request):
    """Facilitator /verify. serve=true means the caller may call the origin. No credit is taken."""
    return _x402_call(request, body, settle=False)


@router.post("/internal/gate/x402/settle")
def internal_x402_settle(body: X402PaymentIn, request: Request):
    """Call only after the origin returned 2xx. Facilitator /settle, then one credit."""
    return _x402_call(request, body, settle=True)
