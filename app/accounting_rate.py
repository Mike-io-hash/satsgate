"""The BTC price used for Satsgate's own USDC math and for buyer quotes.

One effective rate: the on-chain read when it is usable, otherwise the internal
median when that median is still fresh. Neither name is a public source label.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from . import chainlink, config, rates

log = logging.getLogger("satsgate.rates")

_lock = threading.Lock()


@dataclass(frozen=True)
class AccountingRate:
    rate_num: int
    rate_den: int
    fetched_at: int
    source: str  # oracle | fallback
    value: str
    cached_at: int


_cache: AccountingRate | None = None
_calls = 0


def reset_for_tests() -> None:
    global _cache, _calls
    with _lock:
        _cache = None
        _calls = 0


def call_count() -> int:
    return _calls


def accounting_rate(now: int | None = None) -> AccountingRate | None:
    """Drop-in name for callers. This is the effective rate, not a second feed."""
    return effective_rate(now)


def effective_rate(now: int | None = None) -> AccountingRate | None:
    """The spot to use right now, or None when neither feed is usable."""
    now = int(time.time()) if now is None else int(now)
    with _lock:
        cached = _cache
    if cached is not None and now - int(cached.cached_at) < int(config.ACCOUNTING_RATE_CACHE_S):
        if _still_fresh(cached, now):
            return cached
    return _fetch(now)


def refresh_effective(now: int | None = None) -> AccountingRate | None:
    """Background refresh. Bypasses the cache so the loop actually reads again."""
    now = int(time.time()) if now is None else int(now)
    return _fetch(now)


def _fetch(now: int) -> AccountingRate | None:
    global _calls
    _calls += 1
    median = rates.quote_rate(now)
    median_num = None if median is None else int(median.rate_num)
    median_den = None if median is None else int(median.rate_den)
    quote = chainlink.read_btc_usd(now, median_rate_num=median_num, median_rate_den=median_den)
    if quote is not None:
        rate = AccountingRate(
            rate_num=int(quote.rate_num),
            rate_den=int(quote.rate_den),
            fetched_at=int(quote.fetched_at),
            source="oracle",
            value=str(quote.value),
            cached_at=int(now),
        )
        _store(rate)
        log.info("btc/usd rate primary as_of=%s", rate.fetched_at)
        return rate
    if median is None:
        return None
    rate = AccountingRate(
        rate_num=int(median.rate_num),
        rate_den=int(median.rate_den),
        fetched_at=int(median.fetched_at),
        source="fallback",
        value=str(median.value),
        cached_at=int(now),
    )
    _store(rate)
    log.info("btc/usd rate fallback as_of=%s", rate.fetched_at)
    return rate


def _store(rate: AccountingRate) -> None:
    global _cache
    with _lock:
        _cache = rate


def _still_fresh(rate: AccountingRate, now: int) -> bool:
    if rate.source == "oracle":
        if int(rate.fetched_at) > int(now) + chainlink.FUTURE_GRACE_S:
            return False
        return int(now) - int(rate.fetched_at) <= int(config.ACCOUNTING_RATE_STALE_S)
    return int(now) - int(rate.fetched_at) <= int(config.RATES_STALE_SECONDS)
