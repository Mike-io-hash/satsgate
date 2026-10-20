"""HTTP calls to a third-party x402 facilitator.

The URL is configuration. Core does not sign the settlement and does not
follow redirects. Tests replace ``poster`` so this never has to reach the network.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from . import config
from .ssrf import SSRFError, safe_post_json

log = logging.getLogger("satsgate.x402")

poster: Callable[[str, dict], dict] | None = None


class FacilitatorError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _post(path: str, body: dict) -> dict:
    url = f"{config.X402_FACILITATOR_URL}{path}"
    if poster is not None:
        result = poster(url, body)
        if not isinstance(result, dict):
            raise FacilitatorError("invalid_response")
        return result
    try:
        status, payload = safe_post_json(url, body, timeout=config.X402_FACILITATOR_TIMEOUT_SECONDS)
    except SSRFError as exc:
        log.warning("x402 facilitator unreachable status=%s", exc.code)
        raise FacilitatorError("paywall_unavailable") from exc
    if payload is None:
        log.warning("x402 facilitator non-json status=%s", status)
        raise FacilitatorError("paywall_unavailable")
    if status != 200:
        log.warning("x402 facilitator http status=%s", status)
        raise FacilitatorError("paywall_unavailable")
    return payload


def verify(payment_payload: dict, requirements: dict) -> dict:
    return _post("/verify", {"x402Version": 2, "paymentPayload": payment_payload, "paymentRequirements": requirements})


def settle(payment_payload: dict, requirements: dict) -> dict:
    return _post("/settle", {"x402Version": 2, "paymentPayload": payment_payload, "paymentRequirements": requirements})
