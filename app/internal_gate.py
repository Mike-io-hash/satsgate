"""Internal API for the hosted gate process.

The gate and the core share a docker network. They do not share the sqlite
file. Sharing the file would give the gate every client row, API-key hash,
and ledger entry, plus ``SATSGATE_SITE_SECRET_KEY``, which decrypts every
origin secret. These routes return one approved site and do not include that
secret. Core mints the receipt. The gate never sees the origin secret.

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
import logging
import time

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config, db, db_keys, db_sites
from .client_ip import peer_is_trusted

router = APIRouter(include_in_schema=False)
log = logging.getLogger("satsgate.gate")

_RESOURCE_MAX = 200
_NO_STORE = {"Cache-Control": "no-store"}


class GateChallengeIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)


class GateVerifyIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)
    consume: bool = True
    charge: bool = True


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
    """Approved site and routes. The origin secret stays in core."""
    denied = _authorized(request)
    if denied is not None:
        return denied
    cleaned = _clean_slug(slug)
    site = _approved(cleaned) if cleaned is not None else None
    if site is None:
        return _not_found()
    client = _owner(site)
    payee = None
    if client is not None:
        payee = (client.payee_lightning_address or "").strip() or None
    routes = []
    for route in site["routes"]:
        if len(gate_resource(site["slug"], route["path"])) > _RESOURCE_MAX:
            continue
        priced = _priced_route(route)
        if priced is None:
            continue
        routes.append(priced)
    return JSONResponse(
        content={
            "ok": True,
            "slug": site["slug"],
            "client_id": int(site["client_id"]),
            "origin_url": site["origin_url"],
            "payee_lightning_address": payee,
            "rail_lightning": bool(int(site.get("rail_lightning", 1))),
            "rail_x402": bool(int(site.get("rail_x402", 0))),
            "x402_mode": site.get("x402_mode") or "",
            "routes": routes,
        },
        headers=_NO_STORE,
    )


def _priced_route(route: dict) -> dict | None:
    """Main price only. A derived quote is not part of the cached site."""
    currency = route.get("price_currency") or "sats"
    price_sats = route.get("price_sats")
    price_usd = route.get("price_usd_atomic")
    if currency == "sats":
        if isinstance(price_sats, bool) or not isinstance(price_sats, int) or price_sats < 1:
            return None
        price_usd = None
    elif currency == "usd":
        if isinstance(price_usd, bool) or not isinstance(price_usd, int) or price_usd < 1:
            return None
        price_sats = None
    else:
        return None
    return {
        "path": route["path"],
        "price_currency": currency,
        "price_sats": price_sats,
        "price_usd_atomic": price_usd,
        "max_uses": route["max_uses"],
        "access_seconds": route["access_seconds"],
    }


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
    from . import db_x402
    from . import main as core
    from . import x402
    from . import x402_service

    plan = x402_service.quote_plan(site, route)
    pay_to = None
    if plan["x402_on"]:
        pay_to = db_x402.payee_verified(config.DB_PATH, client_id=client.id)
        if not pay_to:
            plan["x402_atomic"] = None
    if plan["lightning_sats"] is None and plan["x402_atomic"] is None:
        if plan.get("x402_blocked"):
            code = "x402_mainnet_disabled"
        elif bool(int(site.get("rail_x402", 0))) and not pay_to:
            code = "payee_evm_not_verified"
        else:
            code = "rail_unavailable"
        return JSONResponse(status_code=400, content={"ok": False, "error": code}, headers=_NO_STORE)

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
    resource = gate_resource(slug, path)
    lightning_body = None
    if plan["lightning_sats"] is not None:
        memo = f"satsgate {slug} {path}"
        if len(memo) > 250:
            memo = memo[:250]
        challenge = core.PaywallChallengeIn(
            amount_sats=int(plan["lightning_sats"]),
            resource=resource,
            memo=memo,
            max_uses=route["max_uses"],
            access_seconds=route["access_seconds"],
        )
        issued = core._issue_paywall_challenge(
            challenge,
            request,
            _owner_principal(client),
            x_satsgate_buyer_ip,
        )
        if isinstance(issued, JSONResponse):
            # A limit applies to the whole request. A failed derived invoice
            # still leaves the main x402 price available.
            if issued.status_code == 429 or plan["price_currency"] == "sats" or plan["x402_atomic"] is None:
                issued.headers["Cache-Control"] = "no-store"
                return issued
        else:
            lightning_body = issued

    if lightning_body is not None:
        merged = _lock_lightning_offer(
            lightning_body,
            plan=plan,
            pay_to=pay_to,
            client_id=client.id,
            resource=resource,
            resource_url=x402.resource_url(slug, path),
            buyer_ip_hash=buyer_hash,
            max_uses=route["max_uses"],
            access_seconds=route["access_seconds"],
            description=_receipt_description(site, path, plan),
        )
        response = JSONResponse(content=merged, headers=_NO_STORE)
        if merged.get("payment_required"):
            response.headers["PAYMENT-REQUIRED"] = merged["payment_required"]
        return response

    try:
        body_out = x402_service.issue_offer(
            client_id=client.id,
            slug=slug,
            path=path,
            resource=resource,
            pay_to=pay_to,
            plan=plan,
            max_uses=route["max_uses"],
            access_seconds=route["access_seconds"],
            buyer_ip_hash=buyer_hash,
            description=_receipt_description(site, path, plan),
        )
    except core.db.ChallengeLimit as exc:
        response = core._challenge_limited(exc)
        response.headers["Cache-Control"] = "no-store"
        return response
    response = JSONResponse(content=body_out, headers=_NO_STORE)
    response.headers["PAYMENT-REQUIRED"] = body_out["payment_required"]
    return response


def _receipt_description(site: dict, path: str, plan: dict) -> str:
    from .gate_receipts import resource_description

    return resource_description(site["origin_url"], path, network=plan.get("x402_network"))


def _lock_lightning_offer(
    body: dict,
    *,
    plan: dict,
    pay_to: str | None,
    client_id: int,
    resource: str,
    resource_url: str,
    buyer_ip_hash: str | None,
    max_uses: int | None,
    access_seconds: int | None,
    description: str | None = None,
) -> dict:
    """Keep the Lightning body. Attach the locked x402 quote when that rail was offered."""
    from . import db_x402
    from . import x402
    from . import x402_service

    now = int(time.time())
    offer = db_x402.offer_by_payment_hash(config.DB_PATH, str(body["payment_hash"]))
    window = x402.offer_timeout_seconds()
    stored_requirements = offer.get("requirements") if offer is not None else None
    quote_live = (
        plan["x402_on"]
        and pay_to
        and offer is not None
        and int(offer["expires_at"]) > now
        and offer.get("pay_to") == pay_to
        and offer.get("network") == plan.get("x402_network")
        and isinstance(stored_requirements, dict)
        and stored_requirements.get("network") == plan.get("x402_network")
        and offer.get("amount_usd_atomic")
        and offer.get("requirements")
    )
    if body.get("reused") and quote_live:
        view = x402_service.x402_view(
            offer, resource_url=resource_url, reused=True, resource=resource, description=description
        )
        merged = dict(body)
        merged.update(view)
        merged["rail"] = "lightning"
        return merged

    invoice_expires = int(body["invoice_expires_at"])
    if invoice_expires <= now:
        return body
    if body.get("reused") and not (plan["x402_atomic"] and pay_to):
        return body
    requirements = None
    stored_pay_to = None
    offer_expires = invoice_expires
    if plan["x402_atomic"] and pay_to:
        requirements = x402.accept_for(
            resource_url=resource_url,
            amount=int(plan["x402_atomic"]),
            pay_to=pay_to,
            timeout_seconds=window,
            network=plan.get("x402_network") or x402.NETWORK_SEPOLIA,
        )
        stored_pay_to = pay_to
        offer_expires = now + window
    elif plan.get("rate") is None:
        return body
    stored = x402_service._store_kwargs(plan, pay_to=stored_pay_to, requirements=requirements)
    if offer is not None and requirements is not None:
        offer = db_x402.replace_x402_quote(
            config.DB_PATH,
            payment_hash=str(body["payment_hash"]),
            expires_at=offer_expires,
            requirements=requirements,
            amount_usd_atomic=stored["amount_usd_atomic"],
            pay_to=stored_pay_to,
            rate_num=stored["rate_num"],
            rate_den=stored["rate_den"],
            rate_fetched_at=stored["rate_fetched_at"],
            now=now,
        )
    elif offer is None:
        offer = db_x402.create_offer(
            config.DB_PATH,
            client_id=client_id,
            resource=resource,
            resource_url=resource_url,
            buyer_ip_hash=buyer_ip_hash,
            max_uses=max_uses,
            access_seconds=access_seconds,
            payment_hash=str(body["payment_hash"]),
            expires_at=offer_expires,
            enforce=False,
            now=now,
            **stored,
        )
    if offer is None:
        return body
    merged = dict(body)
    if requirements is not None:
        view = x402_service.x402_view(
            offer,
            resource_url=resource_url,
            reused=bool(body.get("reused")),
            resource=resource,
            description=description,
        )
        merged.update(view)
        merged["rail"] = "lightning"
        if not body.get("reused"):
            merged["reused"] = False
    else:
        rate = x402_service._rate_view(offer)
        if rate is not None:
            merged["rate"] = rate
            merged["price_currency"] = plan["price_currency"]
            merged["price_usd_atomic"] = plan["main_usd"]
    return merged


def _unlock(
    *,
    request: Request,
    slug: str,
    path: str,
    authorization: str | None,
    payment_hash: str | None,
    poll: bool,
    consume: bool,
    mode: str,
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
                mode=mode,
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
        mode="confirm" if not body.charge else "settle",
    )


@router.get("/internal/gate/status/{payment_hash}")
def internal_status(
    payment_hash: str,
    request: Request,
    slug: str = Query(..., min_length=1, max_length=80),
    path: str = Query(..., min_length=1, max_length=200),
    consume: bool = Query(default=True),
    charge: bool = Query(default=True),
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
        mode="confirm" if not charge else "settle",
    )


class GateReceiptIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)
    method: str = Field(default="GET", min_length=1, max_length=16)
    authorization: str = Field(min_length=1, max_length=8000)


class X402ReceiptIn(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=200)
    method: str = Field(default="GET", min_length=1, max_length=16)
    payment_signature: str = Field(min_length=1, max_length=12000)


def _balance_error(exc: ValueError) -> JSONResponse:
    if str(exc) == "site_secret_key_unconfigured":
        return JSONResponse(
            status_code=503,
            content={"ok": False, "error": "site_secret_key_unconfigured"},
            headers=_NO_STORE,
        )
    return JSONResponse(
        status_code=402,
        content={
            "ok": False,
            "error": str(exc),
            "hint": "Top up payment verifications (credits): GET /v1/plans then /v1/topup/{plan_id}",
        },
        headers=_NO_STORE,
    )


@router.post("/internal/gate/receipt")
def internal_receipt(body: GateReceiptIn, request: Request):
    """Confirm Lightning, debit one credit, and mint a receipt. Pending stays pending."""
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
    from . import db as core_db
    from . import main as core
    from . import x402_service

    if core_db.client_is_suspended(config.DB_PATH, client_id=client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "account_suspended"}, headers=_NO_STORE)
    if not bool(int(site.get("rail_lightning", 1))):
        return JSONResponse(status_code=400, content={"ok": False, "error": "rail_unavailable"}, headers=_NO_STORE)
    try:
        issued = core._unlock_paywall(
            authorization=body.authorization,
            expected_resource=gate_resource(slug, path),
            cost_credits=x402_service._COST,
            client=client,
            poll=False,
            api_key_id=None,
            consume=False,
            mode="receipt",
            receipt_site=site,
            receipt_route=route,
        )
    except core.L402Error as exc:
        response = core._paywall_auth_error(exc, expected_resource=gate_resource(slug, path))
        response.headers["Cache-Control"] = "no-store"
        return response
    except ValueError as exc:
        return _balance_error(exc)
    return _json(issued)


def _x402_receipt_after_expired_offer(
    *,
    encoded: str,
    client_id: int,
    site_id: int,
    path: str,
    aud: str,
    now: int,
) -> dict | None:
    """Return the stored receipt after the offer window has closed.

    Called only when binding failed with ``expired``. Read-only: no insert,
    verify, settle, ledger row, or credit movement. The presented
    PAYMENT-SIGNATURE must be byte-identical to the one that settled: SHA-256
    of its exact UTF-8 string, compared in constant time. A row with no stored
    hash (issued before that column) is not recoverable. Recovery also stops
    ``X402_RECEIPT_RECOVERY_SECONDS`` after settle. ``0`` disables this path,
    including the same second as settle, and does not load the origin secret.
    A mismatch on client, site, path, hash, or that clock returns None so the
    caller sends the original 402. A receipt whose own ``exp`` has passed, with
    the window enabled, still raises ``token_expired``. A coherent persisted
    settlement adds the original ``PAYMENT-RESPONSE``. A missing or inconsistent
    settlement raises ``paywall_unavailable`` and does not return a receipt.
    """
    from . import db_receipts
    from . import x402
    from .gate_receipts import existing_body

    try:
        payload = x402.decode_payment_signature(encoded)
    except x402.X402Error:
        return None
    inner = payload.get("payload")
    authorization = inner.get("authorization") if isinstance(inner, dict) else None
    nonce = authorization.get("nonce") if isinstance(authorization, dict) else None
    if not isinstance(nonce, str) or not x402._BYTES32.fullmatch(nonce):
        return None
    payment_key = db_receipts.x402_key(nonce)
    row = db_receipts.get_receipt(config.DB_PATH, payment_key)
    if row is None:
        return None
    if int(row["client_id"]) != int(client_id) or int(row["site_id"]) != int(site_id) or row["path"] != path:
        log.warning(
            "x402 expired offer ignored stored receipt client_id=%s site_id=%s path=%s row_client_id=%s row_site_id=%s row_path=%s",
            client_id,
            site_id,
            path,
            row["client_id"],
            row["site_id"],
            row["path"],
        )
        return None
    stored_hash = row.get("signature_sha256")
    presented = db_receipts.signature_sha256(encoded)
    if not isinstance(stored_hash, str) or len(stored_hash) != len(presented) or not hmac.compare_digest(stored_hash, presented):
        log.warning(
            "x402 expired offer signature mismatch client_id=%s site_id=%s path=%s",
            client_id,
            site_id,
            path,
        )
        return None
    window = int(config.X402_RECEIPT_RECOVERY_SECONDS)
    # 0 disables recovery. The inclusive comparison below would otherwise
    # accept the settle second, and an expired receipt must stay 402 here.
    if window == 0:
        return None
    settled_at = row.get("settled_at")
    in_window = settled_at is not None and now <= int(settled_at) + window
    if not in_window and now < int(row["exp"]):
        log.warning(
            "x402 expired offer recovery window closed client_id=%s site_id=%s path=%s",
            client_id,
            site_id,
            path,
        )
        return None
    secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(site_id))
    if now >= int(row["exp"]):
        return existing_body(payment_key, secret=secret, aud=aud, now=now)
    header = _persisted_payment_response(
        row,
        payload,
        client_id=client_id,
        aud=aud,
        path=path,
        payment_key=payment_key,
    )
    issued = existing_body(payment_key, secret=secret, aud=aud, now=now)
    if issued is None:
        return None
    issued["payment_response"] = header
    return issued


def _persisted_payment_response(
    receipt: dict,
    payload: dict,
    *,
    client_id: int,
    aud: str,
    path: str,
    payment_key: str,
) -> str:
    """Rebuild ``PAYMENT-RESPONSE`` from the settled authorization row.

    Decoded signature fields are used only as the lookup key, and only after
    the exact header hash matched. They are not proof of payment. A missing or
    inconsistent row is an internal inconsistency, not a buyer signature error.
    """
    from . import db_x402
    from . import x402
    from .gate_receipts import ReceiptIssueError

    fields = _settlement_lookup_key(payload)
    if fields is None or receipt.get("payment_hash") != payment_key:
        raise ReceiptIssueError("paywall_unavailable", 502)
    network, asset, payer, nonce = fields
    if receipt.get("network") != network:
        raise ReceiptIssueError("paywall_unavailable", 502)
    row = db_x402.authorization_row(
        config.DB_PATH,
        network=network,
        asset=asset,
        payer=payer,
        nonce=nonce,
    )
    if row is None:
        raise ReceiptIssueError("paywall_unavailable", 502)
    if (
        str(row["nonce"]).lower() != nonce
        or row["network"] != network
        or row["asset"] != asset
        or row["payer"] != payer
        or row["state"] != "settled"
    ):
        raise ReceiptIssueError("paywall_unavailable", 502)
    tx = row["tx_hash"]
    if not isinstance(tx, str) or not _valid_tx(tx):
        raise ReceiptIssueError("paywall_unavailable", 502)
    offer = db_x402.get_offer(config.DB_PATH, str(row["offer_id"]))
    expected = gate_resource(aud, path)
    if offer is None or int(offer["client_id"]) != int(client_id) or offer.get("resource") != expected:
        raise ReceiptIssueError("paywall_unavailable", 502)
    offer_network = offer.get("network")
    if offer_network not in {None, ""} and offer_network != network:
        raise ReceiptIssueError("paywall_unavailable", 502)
    return x402.payment_response_b64(tx=tx, payer=str(row["payer"]), network=network)


def _settlement_lookup_key(payload: dict) -> tuple[str, str, str, str] | None:
    """Network, asset, payer, and nonce from a hash-checked payload. No time check."""
    from . import x402

    accepted = payload.get("accepted")
    inner = payload.get("payload")
    authorization = inner.get("authorization") if isinstance(inner, dict) else None
    if not isinstance(accepted, dict) or not isinstance(authorization, dict):
        return None
    network = accepted.get("network")
    nonce = authorization.get("nonce")
    if not isinstance(network, str) or network not in x402._USDC_BY_NETWORK:
        return None
    if not isinstance(nonce, str) or not x402._BYTES32.fullmatch(nonce):
        return None
    try:
        asset = x402.checksum_address(accepted.get("asset"))
        payer = x402.checksum_address(authorization.get("from"))
    except x402.X402Error:
        return None
    if asset != x402.usdc_for_network(network):
        return None
    if not x402.is_checksum_address(str(authorization.get("from"))):
        return None
    return network, asset, payer, nonce.lower()


def _valid_tx(tx: str) -> bool:
    if not tx.startswith("0x") or len(tx) < 10:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in tx[2:])


def _json_with_payment_response(issued: dict) -> JSONResponse:
    response = JSONResponse(content=issued, headers=_NO_STORE)
    header = issued.get("payment_response")
    if isinstance(header, str) and header and "\r" not in header and "\n" not in header:
        response.headers["PAYMENT-RESPONSE"] = header
    return response


@router.post("/internal/gate/x402/receipt")
def internal_x402_receipt(body: X402ReceiptIn, request: Request):
    """Verify, settle, and mint a receipt. Test mode does not debit a credit."""
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
    from . import db as core_db
    from . import db_receipts
    from . import db_x402
    from . import x402
    from . import x402_service
    from .gate_receipts import ReceiptIssueError, public_body
    from . import receipts as receipt_mod

    if core_db.client_is_suspended(config.DB_PATH, client_id=client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "account_suspended"}, headers=_NO_STORE)
    if db_x402.payee_is_flagged(config.DB_PATH, client_id=client.id):
        return JSONResponse(status_code=403, content={"ok": False, "error": "payee_not_allowed"}, headers=_NO_STORE)
    if not bool(int(site.get("rail_x402", 0))):
        return JSONResponse(status_code=400, content={"ok": False, "error": "rail_unavailable"}, headers=_NO_STORE)
    resource = gate_resource(slug, path)
    test_mode = str(site.get("x402_mode") or "") == "test"
    try:
        try:
            _payload, offer, fields = x402_service.peek_authorization(
                client_id=client.id,
                slug=slug,
                path=path,
                resource=resource,
                encoded=body.payment_signature,
            )
        except x402.X402Error as exc:
            if exc.code != "expired":
                raise
            issued = _x402_receipt_after_expired_offer(
                encoded=body.payment_signature,
                client_id=client.id,
                site_id=int(site["id"]),
                path=route["path"],
                aud=slug,
                now=int(time.time()),
            )
            if issued is None:
                raise
            return _json_with_payment_response(issued)
        payment_key = db_receipts.x402_key(fields["nonce"])
        now = int(time.time())
        try:
            secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(site["id"]))
        except ValueError as exc:
            return _balance_error(exc)
        iat, exp = now, now + receipt_mod.receipt_lifetime(
            route.get("access_seconds"),
            default_seconds=config.RECEIPT_SECONDS,
            cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
        )
        pending = {
            "rid": receipt_mod.new_receipt_id(),
            "payment_hash": payment_key,
            "site_id": int(site["id"]),
            "client_id": client.id,
            "path": route["path"],
            "rail": "x402",
            "amount_sats": None,
            "amount_usd_atomic": int(offer["amount_usd_atomic"]),
            "network": fields["network"],
            "uses": 1 if route.get("max_uses") is None else int(route["max_uses"]),
            "iat": iat,
            "exp": exp,
            "kid": receipt_mod.kid_for(secret),
            "charged": 0 if test_mode else 1,
            "signature_sha256": db_receipts.signature_sha256(body.payment_signature),
        }

        def _insert(conn) -> None:
            pending["settled_at"] = int(time.time())
            db_receipts.insert_receipt(conn, pending)

        try:
            x402_service.verify_payment(
                client_id=client.id,
                slug=slug,
                path=path,
                resource=resource,
                encoded=body.payment_signature,
                require_credit=not test_mode,
            )
        except x402.X402Error as exc:
            if exc.code != "x402_replay":
                raise
        settled = x402_service.settle_payment(
            client_id=client.id,
            slug=slug,
            path=path,
            resource=resource,
            encoded=body.payment_signature,
            require_credit=not test_mode,
            cost=0 if test_mode else None,
            before_commit=_insert,
        )
        stored = db_receipts.get_receipt(config.DB_PATH, payment_key)
        if stored is None:
            raise ReceiptIssueError("paywall_unavailable", 502)
        if now >= int(stored["exp"]):
            raise ReceiptIssueError("token_expired", 401, payment_hash=db_receipts.public_ph(payment_key))
        secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(site["id"]))
        issued = public_body(stored, secret=secret, aud=slug)
        response_header = settled.get("payment_response") if isinstance(settled, dict) else None
        if isinstance(response_header, str) and response_header:
            issued["payment_response"] = response_header
    except x402.X402Error as exc:
        content = {"ok": False, "error": exc.code}
        if exc.reason:
            content["reason"] = exc.reason
        return JSONResponse(status_code=exc.status, content=content, headers=_NO_STORE)
    except ReceiptIssueError as exc:
        return JSONResponse(
            status_code=exc.status,
            content={"ok": False, "error": exc.code, **exc.extra},
            headers=_NO_STORE,
        )
    except ValueError as exc:
        return _balance_error(exc)
    return _json_with_payment_response(issued)
