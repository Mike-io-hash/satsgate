"""Calls the core internal gate API. The buyer never sees core error bodies."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from satsgate_gate.cache import CachedSite, GateRoute
from satsgate_gate.config import Settings

log = logging.getLogger("satsgate_gate")

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_PUBLIC_CODE = re.compile(r"^[a-z0-9_]{1,64}$")

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
    macaroon: str
    invoice: str
    payment_hash: str
    invoice_expires_at: int
    amount_sats: int
    www_authenticate: str
    resource: str
    max_uses: int | None
    access_seconds: int | None


@dataclass(frozen=True)
class CoreResult:
    action: str
    error: str = ""
    retry_after: int | None = None
    payment_hash: str = ""
    amount_sats: int | None = None
    challenge: Challenge | None = None


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
        path = item.get("path")
        price = item.get("price_sats")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("path")
        if isinstance(price, bool) or not isinstance(price, int) or price < 1:
            raise ValueError("price")
        parsed.append(
            GateRoute(
                path=path,
                price_sats=price,
                max_uses=_optional_int(item.get("max_uses")),
                access_seconds=_optional_int(item.get("access_seconds")),
            )
        )
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
    macaroon = body.get("macaroon")
    invoice = body.get("invoice")
    payment_hash = body.get("payment_hash")
    expires = body.get("invoice_expires_at")
    if not isinstance(macaroon, str) or not isinstance(invoice, str) or not isinstance(payment_hash, str):
        log.warning("core challenge missing macaroon, invoice, or payment_hash")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    amount = body.get("amount_sats")
    if not _HEX64.fullmatch(payment_hash) or isinstance(expires, bool) or not isinstance(expires, int):
        log.warning("core challenge has a bad payment_hash or expiry")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if amount != route.price_sats or body.get("resource") != site.resource(route.path):
        log.warning("core challenge did not match the route")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    try:
        header = _www_authenticate(macaroon, invoice, body.get("www_authenticate"))
        max_uses = _optional_int(body.get("max_uses"))
        access_seconds = _optional_int(body.get("access_seconds"))
    except ValueError:
        log.warning("core challenge header was rejected")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if max_uses != route.max_uses or access_seconds != route.access_seconds:
        log.warning("core challenge policy did not match the route")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    return CoreResult(
        action="challenge",
        challenge=Challenge(
            macaroon=macaroon,
            invoice=invoice,
            payment_hash=payment_hash.lower(),
            invoice_expires_at=expires,
            amount_sats=route.price_sats,
            www_authenticate=header,
            resource=site.resource(route.path),
            max_uses=max_uses,
            access_seconds=access_seconds,
        ),
    )


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
        json={"slug": site.slug, "path": route.path, "consume": True},
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
        params={"slug": site.slug, "path": route.path, "consume": "true"},
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
