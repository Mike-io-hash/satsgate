"""Calls the core internal gate API. The buyer never sees core error bodies."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from dataclasses import dataclass

import httpx

from satsgate_gate.cache import CachedSite, GateRoute
from satsgate_gate.config import Settings

log = logging.getLogger("satsgate_gate")

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_PUBLIC_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
_ATOMIC = re.compile(r"^[1-9][0-9]{0,17}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Base Sepolia USDC. This is the asset contract, not a payTo. The gate does
# not receive, forward, or refund buyer funds.
_X402_NETWORK = "eip155:84532"
_X402_ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
_X402_HEADER_MAX = 8192

# Kept in step with satsgate-proxy. A test asserts the two sets match.
FRESH_REASONS = frozenset(
    {
        "token_used_up",
        "token_expired",
        "resource mismatch",
        "client mismatch",
        "invalid macaroon",
        "invalid signature",
        "preimage does not match payment_hash",
        "payment_hash mismatch",
        "amount mismatch",
        "invoice mismatch",
        "payee mismatch",
        "token expired",
        "invoice expired",
        "malformed Authorization header",
        "malformed L402 token",
        "preimage is not hex",
        "missing credentials",
        "scheme is not L402",
        "unsupported version",
        "purpose mismatch",
        "invalid payment_hash",
        "not_found",
        "preimage_required",
    }
)

MERCHANT_ERRORS = frozenset(
    {
        "api_key_revoked",
        "invalid_api_key",
        "insufficient_scope",
        "resource_not_allowed",
        "client_payee_not_set",
        "access_seconds_too_long",
        "invalid_buyer_ip",
        "payee_fetch_failed",
        "invoice_rejected",
        "db_error",
        "insufficient balance",
    }
)

SPENT_NOTE = (
    "The payment was accepted before the origin was called. This use is spent. Credits are not refunded."
)


@dataclass(frozen=True)
class Challenge:
    """One 402. Lightning, x402, or both. Empty strings mean that rail is absent."""

    resource: str
    max_uses: int | None
    access_seconds: int | None
    macaroon: str = ""
    invoice: str = ""
    payment_hash: str = ""
    invoice_expires_at: int = 0
    amount_sats: int = 0
    www_authenticate: str = ""
    payment_required: str = ""
    x402: dict | None = None

    @property
    def offers_lightning(self) -> bool:
        return bool(self.invoice)

    @property
    def offers_x402(self) -> bool:
        return bool(self.payment_required)


@dataclass(frozen=True)
class CoreResult:
    action: str
    error: str = ""
    retry_after: int | None = None
    payment_hash: str = ""
    amount_sats: int | None = None
    challenge: Challenge | None = None
    reason: str = ""
    payment_response: str = ""
    amount_usd_atomic: int | None = None
    http_status: int = 0


def _json_body(response: httpx.Response) -> dict:
    try:
        data = response.json()
    except Exception:
        log.warning("core returned a non-JSON body http %s", response.status_code)
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _error_code(body: dict) -> str:
    error = body.get("error")
    return error if isinstance(error, str) else ""


def _retry_after(response: httpx.Response, body: dict, default: int) -> int:
    raw = response.headers.get("retry-after", "")
    if raw.isdigit():
        return max(1, int(raw))
    value = body.get("retry_after_seconds")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return default


def _public_code(error: str, fallback: str) -> str:
    if _PUBLIC_CODE.fullmatch(error):
        return error
    return fallback


def _headers(settings: Settings, buyer_ip: str | None, authorization: str | None = None) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if settings.gate_token:
        headers["X-Satsgate-Gate-Token"] = settings.gate_token
    if buyer_ip:
        headers["X-Satsgate-Buyer-Ip"] = buyer_ip
    if authorization:
        headers["Authorization"] = authorization
    return headers


def _www_authenticate(macaroon: str, invoice: str, supplied: object) -> str:
    if isinstance(supplied, str) and supplied.startswith('L402 macaroon="') and "invoice=" in supplied:
        mac_at = supplied.find("macaroon=")
        inv_at = supplied.find("invoice=")
        if mac_at != -1 and inv_at != -1 and mac_at < inv_at and "\n" not in supplied and "\r" not in supplied:
            return supplied
    if any(char in macaroon or char in invoice for char in '"\r\n'):
        raise ValueError("invalid challenge")
    return f'L402 macaroon="{macaroon}", invoice="{invoice}"'


def classify_unlock(status: int, body: dict) -> str:
    error = _error_code(body)
    if status == 404:
        return "missing"
    if status == 200 and body.get("settled") is True and body.get("status") != "pending":
        return "forward"
    if status == 200 and (body.get("status") == "pending" or body.get("settled") is False):
        return "pending"
    if error == "payment_pending" or (status == 402 and body.get("status") == "pending"):
        return "pending"
    if status == 429:
        return "limited"
    if error in MERCHANT_ERRORS or status in {500, 502, 503}:
        return "unavailable"
    if status == 402:
        return "unavailable"
    if status in {400, 401, 403}:
        return "fresh"
    return "unavailable"


def _unlock_result(response: httpx.Response, *, default_retry: int) -> CoreResult:
    body = _json_body(response)
    error = _error_code(body)
    action = classify_unlock(response.status_code, body)
    if action == "forward":
        payment_hash = body.get("payment_hash")
        amount = body.get("amount_sats")
        return CoreResult(
            action="forward",
            payment_hash=payment_hash if isinstance(payment_hash, str) else "",
            amount_sats=amount if isinstance(amount, int) and not isinstance(amount, bool) else None,
        )
    if action == "pending":
        payment_hash = body.get("payment_hash")
        return CoreResult(
            action="pending",
            error="payment_pending",
            retry_after=_retry_after(response, body, default_retry),
            payment_hash=payment_hash if isinstance(payment_hash, str) else "",
        )
    if action == "limited":
        log.warning("core rate limited http %s error %s", response.status_code, error or "rate_limited")
        return CoreResult(
            action="limited",
            error=_public_code(error, "rate_limited"),
            retry_after=_retry_after(response, body, default_retry),
        )
    if action == "missing":
        return CoreResult(action="missing", error="not_found")
    if action == "fresh":
        log.info("core rejected token http %s error %s", response.status_code, error or "rejected")
        reason = error if error in FRESH_REASONS else ""
        return CoreResult(action="fresh", error=reason)
    log.warning("core unlock unavailable http %s error %s", response.status_code, error or "unavailable")
    return CoreResult(action="unavailable", error="paywall_unavailable")


async def _send(client: httpx.AsyncClient, request: httpx.Request, timeout: float) -> httpx.Response:
    request.extensions["timeout"] = httpx.Timeout(timeout).as_dict()
    return await client.send(request, follow_redirects=False)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("invalid policy")
    return value


async def fetch_status(client: httpx.AsyncClient, settings: Settings, slug: str) -> str:
    """``approved``, ``missing``, or ``unavailable``. Not cached by the caller."""
    request = client.build_request(
        "GET",
        f"{settings.core_base_url}/internal/gate/sites/{slug}/status",
        headers=_headers(settings, None),
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core status timed out")
        return "unavailable"
    except httpx.HTTPError:
        log.warning("core status failed")
        return "unavailable"
    if response.status_code == 404:
        return "missing"
    body = _json_body(response)
    if response.status_code == 200 and body.get("status") == "approved":
        return "approved"
    log.warning("core site status http %s", response.status_code)
    return "unavailable"


async def fetch_site(client: httpx.AsyncClient, settings: Settings, slug: str) -> CachedSite | None | str:
    """Approved site, ``None`` when core says it is gone, or ``unavailable``."""
    request = client.build_request(
        "GET",
        f"{settings.core_base_url}/internal/gate/sites/{slug}",
        headers=_headers(settings, None),
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core site config timed out")
        return "unavailable"
    except httpx.HTTPError:
        log.warning("core site config failed")
        return "unavailable"
    if response.status_code == 404:
        return None
    body = _json_body(response)
    if response.status_code != 200:
        log.warning("core site config http %s", response.status_code)
        return "unavailable"
    try:
        return _parse_site(slug, body)
    except ValueError:
        log.warning("core site config was rejected")
        return "unavailable"


def _parse_site(slug: str, body: dict) -> CachedSite:
    if body.get("slug") != slug:
        raise ValueError("slug")
    origin = body.get("origin_url")
    secret = body.get("origin_secret")
    client_id = body.get("client_id")
    routes = body.get("routes")
    if not isinstance(origin, str) or not isinstance(secret, str) or not secret:
        raise ValueError("origin")
    if isinstance(client_id, bool) or not isinstance(client_id, int):
        raise ValueError("client")
    if not isinstance(routes, list):
        raise ValueError("routes")
    parsed: list[GateRoute] = []
    for item in routes:
        if not isinstance(item, dict):
            raise ValueError("route")
        parsed.append(_parse_route(item))
    payee = body.get("payee_lightning_address")
    if payee is not None and not isinstance(payee, str):
        raise ValueError("payee")
    return CachedSite(
        slug=slug,
        client_id=client_id,
        origin_url=origin,
        origin_secret=secret,
        payee=payee,
        routes=tuple(parsed),
        rail_lightning=_flag(body, "rail_lightning", default=True),
        rail_x402=_flag(body, "rail_x402", default=False),
    )


def _flag(body: dict, name: str, *, default: bool) -> bool:
    if name not in body:
        return default
    value = body[name]
    if isinstance(value, bool):
        return value
    if value in {0, 1}:
        return bool(value)
    raise ValueError(name)


def _parse_route(item: dict) -> GateRoute:
    """Accept the 0.11.0 sats payload and the 0.13.0 currency payload.

    A missing currency with an integer ``price_sats`` is Lightning, so an old
    core still loads. The derived quote is not on this object.
    """
    path = item.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("path")
    currency = item.get("price_currency", "sats")
    price_sats = item.get("price_sats")
    price_usd = item.get("price_usd_atomic")
    if currency == "sats":
        if isinstance(price_sats, bool) or not isinstance(price_sats, int) or price_sats < 1:
            raise ValueError("price")
        if price_usd not in {None, 0}:
            raise ValueError("price")
        price_usd = None
    elif currency == "usd":
        if isinstance(price_usd, bool) or not isinstance(price_usd, int) or price_usd < 1:
            raise ValueError("price")
        if price_sats not in {None, 0}:
            raise ValueError("price")
        price_sats = None
    else:
        raise ValueError("price")
    return GateRoute(
        path=path,
        price_sats=price_sats,
        max_uses=_optional_int(item.get("max_uses")),
        access_seconds=_optional_int(item.get("access_seconds")),
        price_currency=currency,
        price_usd_atomic=price_usd,
    )


async def create_challenge(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    buyer_ip: str | None,
) -> CoreResult:
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}/internal/gate/challenge",
        headers=_headers(settings, buyer_ip),
        json={"slug": site.slug, "path": route.path},
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core challenge timed out")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core challenge failed")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if response.status_code == 404:
        return CoreResult(action="missing", error="not_found")
    body = _json_body(response)
    error = _error_code(body)
    if response.status_code == 429:
        log.warning("core challenge limited error %s", error or "rate_limited")
        return CoreResult(
            action="limited",
            error=_public_code(error, "rate_limited"),
            retry_after=_retry_after(response, body, settings.pending_retry_after),
        )
    if response.status_code != 200:
        log.warning("core challenge rejected http %s error %s", response.status_code, error or "unavailable")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if body.get("resource") != site.resource(route.path):
        log.warning("core challenge did not match the route")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    try:
        policy = _policy(body, route)
        lightning = _lightning_offer(body, site, route)
        x402_offer = _x402_offer(body, response, route)
    except ValueError:
        log.warning("core challenge was rejected")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if lightning is None and x402_offer is None:
        log.warning("core challenge offered no rail")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    return CoreResult(
        action="challenge",
        challenge=Challenge(
            resource=site.resource(route.path),
            max_uses=policy[0],
            access_seconds=policy[1],
            **(lightning or {}),
            **(x402_offer or {}),
        ),
    )


def _policy(body: dict, route: GateRoute) -> tuple[int | None, int | None]:
    max_uses = route.max_uses if "max_uses" not in body else _optional_int(body.get("max_uses"))
    access = route.access_seconds if "access_seconds" not in body else _optional_int(body.get("access_seconds"))
    if max_uses != route.max_uses or access != route.access_seconds:
        raise ValueError("policy")
    return max_uses, access


def _lightning_offer(body: dict, site: CachedSite, route: GateRoute) -> dict | None:
    macaroon = body.get("macaroon")
    invoice = body.get("invoice")
    payment_hash = body.get("payment_hash")
    if macaroon is None and invoice is None and payment_hash is None:
        return None
    expires = body.get("invoice_expires_at")
    amount = body.get("amount_sats")
    if not isinstance(macaroon, str) or not isinstance(invoice, str) or not isinstance(payment_hash, str):
        raise ValueError("lightning")
    if not _HEX64.fullmatch(payment_hash) or isinstance(expires, bool) or not isinstance(expires, int):
        raise ValueError("lightning")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
        raise ValueError("lightning")
    if route.price_currency == "sats" and amount != route.price_sats:
        raise ValueError("lightning")
    header = _www_authenticate(macaroon, invoice, body.get("www_authenticate"))
    if body.get("resource") != site.resource(route.path):
        raise ValueError("lightning")
    return {
        "macaroon": macaroon,
        "invoice": invoice,
        "payment_hash": payment_hash.lower(),
        "invoice_expires_at": expires,
        "amount_sats": amount,
        "www_authenticate": header,
    }


def _x402_offer(body: dict, response: httpx.Response, route: GateRoute) -> dict | None:
    header = response.headers.get("payment-required")
    mirrored = body.get("payment_required")
    encoded = header if isinstance(header, str) and header.strip() else None
    if encoded is None and isinstance(mirrored, str) and mirrored.strip():
        encoded = mirrored.strip()
    if encoded is None:
        if body.get("x402") is not None or mirrored not in {None, ""}:
            raise ValueError("x402")
        return None
    encoded = encoded.strip()
    if isinstance(header, str) and isinstance(mirrored, str) and header.strip() != mirrored.strip():
        log.warning("PAYMENT-REQUIRED header and body differ; header wins")
        encoded = header.strip()
    if len(encoded.encode("utf-8")) > _X402_HEADER_MAX or any(char in encoded for char in "\r\n"):
        raise ValueError("x402")
    mirror = body.get("x402")
    if not isinstance(mirror, dict):
        raise ValueError("x402")
    cleaned = _x402_requirements(encoded, mirror)
    amount = cleaned["amount"]
    if route.price_currency == "usd" and amount != str(route.price_usd_atomic):
        raise ValueError("x402")
    expires = mirror.get("expires_at")
    if isinstance(expires, bool) or not isinstance(expires, int) or expires < 1:
        raise ValueError("x402")
    cleaned["expires_at"] = expires
    return {"payment_required": encoded, "x402": cleaned}


def _x402_requirements(encoded: str, mirror: dict) -> dict:
    """The header is canonical. The JSON mirror is what a client displays."""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("x402") from exc
    if len(raw) > _X402_HEADER_MAX:
        raise ValueError("x402")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("x402") from exc
    if not isinstance(document, dict) or document.get("x402Version") != 2:
        raise ValueError("x402")
    accepts = document.get("accepts")
    if not isinstance(accepts, list) or len(accepts) != 1 or not isinstance(accepts[0], dict):
        raise ValueError("x402")
    accept = accepts[0]
    if accept.get("scheme") != "exact" or accept.get("network") != _X402_NETWORK:
        raise ValueError("x402")
    asset = accept.get("asset")
    pay_to = accept.get("payTo")
    amount = accept.get("amount")
    if not isinstance(asset, str) or asset.lower() != _X402_ASSET.lower():
        raise ValueError("x402")
    if not isinstance(pay_to, str) or not _ADDRESS.fullmatch(pay_to):
        raise ValueError("x402")
    if not isinstance(amount, str) or not _ATOMIC.fullmatch(amount):
        raise ValueError("x402")
    extra = accept.get("extra")
    if not isinstance(extra, dict) or "paymentFlow" in extra:
        raise ValueError("x402")
    for key, expected in (("scheme", "exact"), ("network", _X402_NETWORK), ("amount", amount)):
        if mirror.get(key) not in {None, expected}:
            log.warning("x402 body field %s disagreed with the header", key)
    mirror_pay = mirror.get("payTo")
    if isinstance(mirror_pay, str) and mirror_pay.lower() != pay_to.lower():
        log.warning("x402 payTo disagreed with the header")
    return {
        "scheme": "exact",
        "network": _X402_NETWORK,
        "asset": _X402_ASSET,
        "amount": amount,
        "payTo": pay_to,
    }


async def unlock_with_preimage(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    authorization: str,
) -> CoreResult:
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}/internal/gate/verify",
        headers=_headers(settings, None, authorization),
        json={"slug": site.slug, "path": route.path, "consume": False, "charge": False},
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core verify timed out")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core verify failed")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    return _unlock_result(response, default_retry=settings.pending_retry_after)


async def unlock_without_preimage(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    *,
    authorization: str,
    payment_hash: str,
) -> CoreResult:
    request = client.build_request(
        "GET",
        f"{settings.core_base_url}/internal/gate/status/{payment_hash}",
        headers=_headers(settings, None, authorization),
        params={"slug": site.slug, "path": route.path, "consume": "false", "charge": "false"},
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core poll timed out")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core poll failed")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    return _unlock_result(response, default_retry=settings.pending_retry_after)


def _nonce_hex(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("nonce")
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not _HEX64.fullmatch(text):
        raise ValueError("nonce")
    return text


def _x402_outcome(response: httpx.Response, *, settle: bool) -> CoreResult:
    body = _json_body(response)
    error = _error_code(body)
    status = response.status_code
    if status == 404:
        return CoreResult(action="missing", error="not_found")
    if status == 200 and not settle and body.get("serve") is True:
        try:
            amount = body.get("amount_usd_atomic")
            if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
                raise ValueError("amount")
            nonce = _nonce_hex(body.get("nonce"))
        except ValueError:
            log.warning("x402 verify response was missing the locked amount or nonce")
            return CoreResult(action="unavailable", error="paywall_unavailable")
        return CoreResult(
            action="serve",
            payment_hash=nonce,
            amount_usd_atomic=amount,
        )
    if status == 200 and settle:
        header = response.headers.get("payment-response")
        encoded = header.strip() if isinstance(header, str) and header.strip() else body.get("payment_response")
        if not isinstance(encoded, str) or not encoded.strip() or any(char in encoded for char in "\r\n"):
            log.warning("x402 settle response had no PAYMENT-RESPONSE")
            return CoreResult(action="unavailable", error="paywall_unavailable")
        return CoreResult(action="settled", payment_response=encoded.strip())
    reason = body.get("reason")
    if not isinstance(reason, str) or not _PUBLIC_CODE.fullmatch(reason):
        reason = ""
    if status in {400, 402, 409} and _PUBLIC_CODE.fullmatch(error):
        log.info("x402 core rejected http %s error %s", status, error)
        return CoreResult(action="rejected", error=error, reason=reason, http_status=status)
    log.warning("x402 core unavailable http %s error %s", status, error or "unavailable")
    return CoreResult(action="unavailable", error="paywall_unavailable")


async def _x402_post(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    payment_signature: str,
    *,
    settle: bool,
) -> CoreResult:
    path = "/internal/gate/x402/settle" if settle else "/internal/gate/x402/verify"
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}{path}",
        headers=_headers(settings, None),
        json={"slug": site.slug, "path": route.path, "payment_signature": payment_signature},
    )
    label = "settle" if settle else "verify"
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core x402 %s timed out", label)
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core x402 %s failed", label)
        return CoreResult(action="unavailable", error="paywall_unavailable")
    return _x402_outcome(response, settle=settle)


async def charge_lightning(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    *,
    authorization: str,
    payment_hash: str,
) -> CoreResult:
    """Take the credit only after the origin returned 2xx."""
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}/internal/gate/charge",
        headers=_headers(settings, None, authorization),
        json={"slug": site.slug, "path": route.path, "payment_hash": payment_hash},
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core charge timed out")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core charge failed")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    body = _json_body(response)
    error = _error_code(body)
    if response.status_code == 200 and body.get("settled") is True:
        return CoreResult(action="charged", payment_hash=payment_hash)
    if response.status_code == 401 and error in FRESH_REASONS:
        return CoreResult(action="fresh", error=error)
    log.warning("core charge unavailable http %s error %s", response.status_code, error or "unavailable")
    return CoreResult(action="unavailable", error="paywall_unavailable")


async def verify_x402(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    payment_signature: str,
) -> CoreResult:
    return await _x402_post(client, settings, site, route, payment_signature, settle=False)


async def settle_x402(
    client: httpx.AsyncClient,
    settings: Settings,
    site: CachedSite,
    route: GateRoute,
    payment_signature: str,
) -> CoreResult:
    return await _x402_post(client, settings, site, route, payment_signature, settle=True)
