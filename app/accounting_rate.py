"""Role B: the BTC price Satsgate uses to convert its own USDC amounts.

CoinGecko is primary. The D-23 median is the backup when it is still younger
than an hour. Buyer-facing 402 quotes do not read this module.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

from . import config, rates, ssrf

log = logging.getLogger("satsgate.accounting_rate")

_URL = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
fetcher: Callable[[str], dict | None] | None = None
_lock = threading.Lock()


@dataclass(frozen=True)
class AccountingRate:
    rate_num: int
    rate_den: int
    fetched_at: int
    source: str  # coingecko | d23_median
    value: str


_cache: AccountingRate | None = None
_calls = 0


def reset_for_tests() -> None:
    global _cache, _calls
    with _lock:
        _cache = None
        _calls = 0


def call_count() -> int:
    return _calls


def _parse_usd(payload: dict) -> str | None:
    bitcoin = payload.get("bitcoin") if isinstance(payload, dict) else None
    if not isinstance(bitcoin, dict):
        return None
    usd = bitcoin.get("usd")
    if isinstance(usd, bool) or usd is None:
        return None
    text = str(usd).strip()
    return text or None


def _fetch_coingecko(now: int) -> AccountingRate | None:
    global _calls
    _calls += 1
    payload = None
    if fetcher is not None:
        payload = fetcher(_URL)
    else:
        params = None
        if config.COINGECKO_API_KEY:
            # Query form of the optional demo key. The value is not logged.
            params = {"x_cg_demo_api_key": config.COINGECKO_API_KEY}
        try:
            payload = ssrf.safe_get_json(
                _URL,
                params=params,
                timeout=float(config.ACCOUNTING_RATE_TIMEOUT_S),
            )
        except Exception:
            log.info("accounting rate coingecko unavailable")
            return None
    text = _parse_usd(payload or {})
    if text is None:
        return None
    scaled = rates._scaled(text)
    if scaled is None:
        return None
    return AccountingRate(
        rate_num=int(scaled),
        rate_den=rates.RATE_DEN,
        fetched_at=int(now),
        source="coingecko",
        value=text,
    )


def _median_backup(now: int) -> AccountingRate | None:
    view = rates.snapshot(now)
    fetched = view.get("fetched_at")
    if not isinstance(fetched, int):
        return None
    if int(now) - fetched > int(config.ACCOUNTING_RATE_STALE_S):
        return None
    if not view.get("rate_num") or not view.get("rate_den"):
        return None
    return AccountingRate(
        rate_num=int(view["rate_num"]),
        rate_den=int(view["rate_den"]),
        fetched_at=int(fetched),
        source="d23_median",
        value=str(view.get("value") or ""),
    )


def accounting_rate(now: int | None = None) -> AccountingRate | None:
    """A rate young enough to price a USDC top-up or a USDC Satsgate fee."""
    global _cache
    now = int(time.time()) if now is None else int(now)
    with _lock:
        cached = _cache
    if cached is not None and now - int(cached.fetched_at) < int(config.ACCOUNTING_RATE_CACHE_S):
        if now - int(cached.fetched_at) <= int(config.ACCOUNTING_RATE_STALE_S):
            return cached
    fresh = _fetch_coingecko(now)
    if fresh is not None:
        with _lock:
            _cache = fresh
        log.info("accounting rate source=coingecko as_of=%s", fresh.fetched_at)
        return fresh
    if cached is not None and now - int(cached.fetched_at) <= int(config.ACCOUNTING_RATE_STALE_S):
        return cached
    backup = _median_backup(now)
    if backup is not None:
        log.info("accounting rate source=d23_median as_of=%s", backup.fetched_at)
        return backup
    return None
