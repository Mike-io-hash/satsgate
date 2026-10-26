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
    payment_required: str = ""
    x402: dict | None = None

    @property
    def offers_x402(self) -> bool:
        return bool(self.payment_required and self.x402)


@dataclass(frozen=True)
class CoreResult:
    action: str
    error: str = ""
    retry_after: int | None = None
    payment_hash: str = ""
    amount_sats: int | None = None
    amount_usd_atomic: int | None = None
    challenge: Challenge | None = None
    payment_response: str = ""
    reason: str = ""
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


def _resource_url(settings: Settings, path: str) -> str:
    base = settings.public_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


async def create_challenge(
    client: httpx.AsyncClient,
    settings: Settings,
    route: Route,
    buyer_ip: str | None,
    *,
    request_path: str,
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
    if route.x402:
        payload["x402"] = True
        payload["x402_mode"] = route.x402_mode or "test"
        payload["resource_url"] = _resource_url(settings, request_path)
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
    offers_x402 = bool(body.get("payment_required")) and isinstance(body.get("x402"), dict)
    if not offers_x402 and (
        not isinstance(macaroon, str) or not isinstance(invoice, str) or not isinstance(payment_hash, str)
    ):
        log.warning("core challenge missing macaroon, invoice, or payment_hash")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if offers_x402 and not isinstance(macaroon, str):
        macaroon = ""
        invoice = ""
        payment_hash = ""
    amount = body.get("amount_sats")
    if (
        not isinstance(payment_hash, str)
        or not _HEX64.fullmatch(payment_hash)
        or isinstance(expires, bool)
        or not isinstance(expires, int)
    ):
        log.warning("core challenge has a bad payment_hash or expiry")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if isinstance(amount, int) and not isinstance(amount, bool) and amount != route.price_sats:
        log.warning("core challenge amount did not match the route")
        return CoreResult(action="unavailable", error="paywall_unavailable")
    header = ""
    if isinstance(macaroon, str) and macaroon and isinstance(invoice, str) and invoice:
        try:
            header = _www_authenticate(macaroon, invoice, body.get("www_authenticate"))
        except ValueError:
            log.warning("core challenge header was rejected")
            return CoreResult(action="unavailable", error="paywall_unavailable")
    payment_required = ""
    x402_body = None
    if offers_x402:
        encoded = body.get("payment_required")
        quoted = body.get("x402")
        if not isinstance(encoded, str) or not encoded or any(char in encoded for char in "\r\n"):
            log.warning("core challenge x402 header was rejected")
            return CoreResult(action="unavailable", error="paywall_unavailable")
        if not isinstance(quoted, dict):
            return CoreResult(action="unavailable", error="paywall_unavailable")
        payment_required = encoded
        x402_body = quoted
    if not header and not payment_required:
        return CoreResult(action="unavailable", error="paywall_unavailable")
    if not isinstance(payment_hash, str):
        payment_hash = ""
    if not isinstance(expires, int) or isinstance(expires, bool):
        expires = 0
    return CoreResult(
        action="challenge",
        challenge=Challenge(
            macaroon=macaroon if isinstance(macaroon, str) else "",
            invoice=invoice if isinstance(invoice, str) else "",
            payment_hash=payment_hash.lower(),
            invoice_expires_at=expires,
            amount_sats=route.price_sats,
            www_authenticate=header,
            resource=route.resource,
            payment_required=payment_required,
            x402=x402_body,
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
        json={"expected_resource": route.resource, "cost_credits": 1, "consume": True, "charge": False},
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
        params={"expected_resource": route.resource, "cost_credits": 1, "consume": "true", "charge": "false"},
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


def _nonce_hex(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("nonce")
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not _HEX64.fullmatch(text):
        raise ValueError("nonce")
    return text


async def charge_lightning(
    client: httpx.AsyncClient,
    settings: Settings,
    route: Route,
    *,
    authorization: str,
    payment_hash: str,
) -> CoreResult:
    """Take the credit only after the origin returned 2xx."""
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}/v1/paywall/charge",
        headers=_auth_headers(settings, None, authorization),
        json={"expected_resource": route.resource, "payment_hash": payment_hash, "cost_credits": 1},
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


def _x402_outcome(response: httpx.Response, *, settle: bool) -> CoreResult:
    body = _json_body(response)
    error = _error_code(body)
    status = response.status_code
    if status == 200 and not settle and body.get("serve") is True:
        try:
            amount = body.get("amount_usd_atomic")
            if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
                raise ValueError("amount")
            nonce = _nonce_hex(body.get("nonce"))
        except ValueError:
            log.warning("x402 verify response was missing the locked amount or nonce")
            return CoreResult(action="unavailable", error="paywall_unavailable")
        return CoreResult(action="serve", payment_hash=nonce, amount_usd_atomic=amount)
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
    route: Route,
    payment_signature: str,
    *,
    request_path: str,
    settle: bool,
) -> CoreResult:
    path = "/v1/paywall/x402/settle" if settle else "/v1/paywall/x402/verify"
    request = client.build_request(
        "POST",
        f"{settings.core_base_url}{path}",
        headers=_auth_headers(settings, None),
        json={
            "resource": route.resource,
            "resource_url": _resource_url(settings, request_path),
            "payment_signature": payment_signature,
        },
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


async def verify_x402(
    client: httpx.AsyncClient,
    settings: Settings,
    route: Route,
    payment_signature: str,
    *,
    request_path: str,
) -> CoreResult:
    return await _x402_post(client, settings, route, payment_signature, request_path=request_path, settle=False)


async def settle_x402(
    client: httpx.AsyncClient,
    settings: Settings,
    route: Route,
    payment_signature: str,
    *,
    request_path: str,
) -> CoreResult:
    return await _x402_post(client, settings, route, payment_signature, request_path=request_path, settle=True)
