"""HTTP calls to a third-party x402 facilitator.

Sepolia uses the public facilitator URL. Base mainnet uses the Coinbase CDP
facilitator and a JWT bearer. Core does not sign the settlement and does not
follow redirects. Tests replace ``poster`` so this never has to reach the network.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable

from . import cdp_auth, config, x402
from .ssrf import SSRFError, safe_post_json

log = logging.getLogger("satsgate.x402")

poster: Callable[..., dict] | None = None


class FacilitatorError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reason_for_status(status: int) -> str:
    if status in {401, 403}:
        return "auth"
    return "http"


def _invoke_poster(url: str, body: dict, headers: dict) -> dict:
    assert poster is not None
    try:
        signature = inspect.signature(poster)
    except (TypeError, ValueError):
        signature = None
    if signature is None:
        result = poster(url, body)
    else:
        positional = [
            param
            for param in signature.parameters.values()
            if param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD)
        ]
        varargs = any(param.kind == param.VAR_POSITIONAL for param in signature.parameters.values())
        if varargs or len(positional) >= 3:
            result = poster(url, body, headers)
        else:
            result = poster(url, body)
    if not isinstance(result, dict):
        raise FacilitatorError("invalid_response")
    return result


def _post(path: str, body: dict, *, network: str) -> dict:
    headers: dict[str, str] = {}
    if network == x402.NETWORK_BASE:
        if not config.X402_MAINNET_ENABLED:
            log.warning("x402 facilitator status=0 reason=disabled")
            raise FacilitatorError("paywall_unavailable")
        base = config.X402_CDP_FACILITATOR_URL
        try:
            headers["Authorization"] = cdp_auth.authorization_header("POST", f"{base}{path}")
        except cdp_auth.CredentialError:
            log.warning("x402 facilitator status=0 reason=credential_invalid")
            raise FacilitatorError("paywall_unavailable") from None
    else:
        base = config.X402_FACILITATOR_URL
    url = f"{base}{path}"
    if poster is not None:
        return _invoke_poster(url, body, headers)
    try:
        status, payload = safe_post_json(
            url,
            body,
            headers=headers,
            timeout=config.X402_FACILITATOR_TIMEOUT_SECONDS,
        )
    except SSRFError:
        log.warning("x402 facilitator status=0 reason=unreachable")
        raise FacilitatorError("paywall_unavailable") from None
    if payload is None:
        log.warning("x402 facilitator status=%s reason=non_json", status)
        raise FacilitatorError("paywall_unavailable")
    if status != 200:
        log.warning("x402 facilitator status=%s reason=%s", status, _reason_for_status(status))
        raise FacilitatorError("paywall_unavailable")
    return payload


def _network_of(requirements: dict) -> str:
    network = requirements.get("network") if isinstance(requirements, dict) else None
    if network == x402.NETWORK_BASE:
        return x402.NETWORK_BASE
    return x402.NETWORK_SEPOLIA


def verify(payment_payload: dict, requirements: dict) -> dict:
    return _post(
        "/verify",
        {"x402Version": 2, "paymentPayload": payment_payload, "paymentRequirements": requirements},
        network=_network_of(requirements),
    )


def settle(payment_payload: dict, requirements: dict) -> dict:
    return _post(
        "/settle",
        {"x402Version": 2, "paymentPayload": payment_payload, "paymentRequirements": requirements},
        network=_network_of(requirements),
    )
