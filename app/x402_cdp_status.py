"""Cached CDP ``GET /supported`` check for an external watchdog.

The response is a fixed set of keys. It never includes the key id, the secret,
or a facilitator body. Tests replace ``probe`` so this never calls CDP.
"""

from __future__ import annotations

import json
import threading
import time

from . import cdp_auth, config, x402
from .ssrf import SSRFError, safe_get_response

_CACHE_SECONDS = 60.0
_lock = threading.Lock()
_cache: dict | None = None
_cached_at = 0.0

# Tests set this to a callable that returns (http_status, dict | None).
probe = None


def clear_cache() -> None:
    global _cache, _cached_at
    with _lock:
        _cache = None
        _cached_at = 0.0


def _cdp(*, supported_ok, checked_at, http_status, reason: str, cached: bool) -> dict:
    return {
        "supported_ok": supported_ok,
        "checked_at": checked_at,
        "http_status": http_status,
        "reason": reason,
        "cached": cached,
    }


def _has_exact_base(payload: dict) -> bool:
    supported = payload.get("supported")
    if isinstance(supported, dict):
        entry = supported.get(x402.NETWORK_BASE)
        if entry == "exact":
            return True
        if isinstance(entry, (list, tuple)) and "exact" in entry:
            return True
    for key in ("kinds", "supported", "payments"):
        items = payload.get(key)
        if isinstance(items, list) and _list_has_exact(items):
            return True
    return False


def _list_has_exact(items: list) -> bool:
    for item in items:
        if not isinstance(item, dict):
            continue
        scheme = item.get("scheme")
        network = item.get("network")
        if scheme == "exact" and network == x402.NETWORK_BASE:
            return True
        nested = item.get("scheme")
        if isinstance(item.get("networks"), list):
            for net in item["networks"]:
                if net == x402.NETWORK_BASE and (scheme == "exact" or nested == "exact"):
                    return True
    return False


def _interpret(status: int, payload: object) -> dict:
    checked = int(time.time())
    if status in {401, 403}:
        return _cdp(supported_ok=False, checked_at=checked, http_status=status, reason="auth", cached=False)
    if status != 200:
        return _cdp(supported_ok=False, checked_at=checked, http_status=status, reason="http", cached=False)
    if not isinstance(payload, dict):
        return _cdp(supported_ok=False, checked_at=checked, http_status=status, reason="non_json", cached=False)
    if _has_exact_base(payload):
        return _cdp(supported_ok=True, checked_at=checked, http_status=status, reason="ok", cached=False)
    return _cdp(supported_ok=False, checked_at=checked, http_status=status, reason="unsupported", cached=False)


def _fetch() -> dict:
    if probe is not None:
        try:
            status, payload = probe()
        except Exception:  # noqa: BLE001
            return _cdp(
                supported_ok=False,
                checked_at=int(time.time()),
                http_status=None,
                reason="unreachable",
                cached=False,
            )
        return _interpret(int(status), payload)
    url = f"{config.X402_CDP_FACILITATOR_URL}/supported"
    try:
        header = cdp_auth.authorization_header("GET", url)
        status, raw = safe_get_response(
            url,
            headers={"Authorization": header},
            timeout=config.X402_FACILITATOR_TIMEOUT_SECONDS,
        )
    except cdp_auth.CredentialError:
        return _cdp(
            supported_ok=False,
            checked_at=int(time.time()),
            http_status=None,
            reason="credential_invalid",
            cached=False,
        )
    except SSRFError:
        return _cdp(
            supported_ok=False,
            checked_at=int(time.time()),
            http_status=None,
            reason="unreachable",
            cached=False,
        )
    if not raw:
        return _interpret(status, None)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = None
    return _interpret(status, payload)


def _cached_probe() -> dict:
    global _cache, _cached_at
    now = time.monotonic()
    with _lock:
        if _cache is not None and now - _cached_at < _CACHE_SECONDS:
            served = dict(_cache)
            served["cached"] = True
            return served
        result = _fetch()
        _cache = dict(result)
        _cached_at = time.monotonic()
        return dict(result)


def snapshot() -> dict:
    """Whitelist. Callers must not add facilitator bodies or credentials."""
    if not config.X402_CDP_REQUESTED:
        cdp = _cdp(supported_ok=None, checked_at=None, http_status=None, reason="disabled", cached=False)
    elif not config.X402_MAINNET_ENABLED:
        cdp = _cdp(supported_ok=None, checked_at=None, http_status=None, reason="credentials", cached=False)
    else:
        cdp = _cached_probe()
    return {
        "ok": True,
        "mainnet_enabled": bool(config.X402_MAINNET_ENABLED),
        "test_network": x402.NETWORK_SEPOLIA,
        "live_network": x402.NETWORK_BASE,
        "topup_network": x402.topup_network(),
        "cdp": {
            "supported_ok": cdp["supported_ok"],
            "checked_at": cdp["checked_at"],
            "http_status": cdp["http_status"],
            "reason": cdp["reason"],
            "cached": cdp["cached"],
        },
    }
