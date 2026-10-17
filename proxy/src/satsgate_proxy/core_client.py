"""Calls the hosted (or self-hosted) satsgate core. The buyer never sees core error bodies."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from satsgate_proxy.config import Route, Settings

log = logging.getLogger("satsgate_proxy")

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_PUBLIC_CODE = re.compile(r"^[a-z0-9_]{1,64}$")

# A presented token cannot be used for this request. Mint a new challenge so
# standard clients, which retry on 402, can recover. These are not 401s.
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

# Merchant configuration. The buyer gets a generic failure, not a new invoice.
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


def _auth_headers(settings: Settings, buyer_ip: str | None, authorization: str | None = None) -> dict[str, str]:
    headers = {"X-Api-Key": settings.api_key, "Accept": "application/json"}
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
    if status in {400, 401, 403, 404}:
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
    if action == "fresh":
        log.info("core rejected token http %s error %s", response.status_code, error or "rejected")
        reason = error if error in FRESH_REASONS else ""
        return CoreResult(action="fresh", error=reason)
    log.warning("core unlock unavailable http %s error %s", response.status_code, error or "unavailable")
    return CoreResult(action="unavailable", error="paywall_unavailable")


async def _send(client: httpx.AsyncClient, request: httpx.Request, timeout: float) -> httpx.Response:
    # httpx 0.28 takes the per-request timeout from the request, not send().
    request.extensions["timeout"] = httpx.Timeout(timeout).as_dict()
    return await client.send(request, follow_redirects=False)


async def create_challenge(
    client: httpx.AsyncClient,
    settings: Settings,
    route: Route,
    buyer_ip: str | None,
) -> CoreResult:
    max_uses, access_seconds = route.access.policy()
    payload: dict[str, object] = {
        "resource": route.resource,
        "amount_sats": route.price_sats,
    }
    if route.description:
        payload["memo"] = route.description
    if max_uses is not None:
        payload["max_uses"] = max_uses
    if access_seconds is not None:
        payload["access_seconds"] = access_seconds
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}/v1/paywall/challenge",
        headers=_auth_headers(settings, buyer_ip),
        json=payload,
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core challenge timed out")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core challenge failed")
        return CoreResult(action="unavailable", error="paywall_unavailable")

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
    if amount != route.price_sats:
        log.warning("core challenge amount did not match the route")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    try:
        header = _www_authenticate(macaroon, invoice, body.get("www_authenticate"))
    except ValueError:
        log.warning("core challenge header was rejected")
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
            resource=route.resource,
        ),
    )


async def unlock_with_preimage(
    client: httpx.AsyncClient,
    settings: Settings,
    route: Route,
    authorization: str,
) -> CoreResult:
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}/v1/paywall/verify",
        headers=_auth_headers(settings, None, authorization),
        json={"expected_resource": route.resource, "cost_credits": 1, "consume": True},
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
    route: Route,
    *,
    authorization: str,
    payment_hash: str,
) -> CoreResult:
    request = client.build_request(
        "GET",
        f"{settings.core_base_url}/v1/paywall/status/{payment_hash}",
        headers=_auth_headers(settings, None, authorization),
        params={"expected_resource": route.resource, "cost_credits": 1, "consume": "true"},
    )
    try:
        response = await _send(client, request, settings.core_timeout)
    except httpx.TimeoutException:
        log.warning("core status timed out")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    except httpx.HTTPError:
        log.warning("core status failed")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    return _unlock_result(response, default_retry=settings.pending_retry_after)
