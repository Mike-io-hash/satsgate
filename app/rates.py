"""BTC/USD median used only to quote the other rail.

The number is a quote. Satsgate does not convert, hold, or forward funds.
A Lightning payment is sats to the merchant's Lightning address. A USDC
payment is USDC to the merchant's verified address. The amount locked on
the offer is what the buyer pays.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Callable

from . import config, ssrf

log = logging.getLogger("satsgate.rates")

RATE_DEN = 100_000_000
_MIN_DERIVED_USD_ATOMIC = 1000
_MAX_SATS = 10_000_000
_MIN_SPOT_USD = Decimal(1000)
_MAX_SPOT_USD = Decimal(10_000_000)

fetcher: Callable[[str], dict | None] | None = None
_lock = threading.Lock()


@dataclass(frozen=True)
class Rate:
    rate_num: int
    rate_den: int
    fetched_at: int
    sources: tuple[str, ...]
    value: str


_state: Rate | None = None


@dataclass(frozen=True)
class _Source:
    name: str
    url: str
    params: dict | None
    parse: Callable[[dict, int], str | None]


def _text(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_coinbase(payload: dict, _now: int) -> str | None:
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    return _text(data.get("amount"))


def _parse_kraken(payload: dict, _now: int) -> str | None:
    result = payload.get("result")
    if not isinstance(result, dict):
        return None
    for value in result.values():
        if not isinstance(value, dict):
            continue
        last = value.get("c")
        if isinstance(last, list) and last:
            return _text(last[0])
    return None


def _parse_bitstamp(payload: dict, now: int) -> str | None:
    stamp = _text(payload.get("timestamp"))
    if stamp is not None:
        try:
            seen = int(stamp)
        except ValueError:
            return None
        if int(now) - seen > int(config.RATES_STALE_SECONDS):
            return None
    return _text(payload.get("last"))


_SOURCES = (
    _Source("bitstamp", "https://www.bitstamp.net/api/v2/ticker/btcusd/", None, _parse_bitstamp),
    _Source("coinbase", "https://api.coinbase.com/v2/prices/BTC-USD/spot", None, _parse_coinbase),
    _Source("kraken", "https://api.kraken.com/0/public/Ticker", {"pair": "XBTUSD"}, _parse_kraken),
)


def format_usd(rate_num: int, rate_den: int) -> str:
    whole = int(rate_num) // int(rate_den)
    frac = int(rate_num) % int(rate_den)
    digits = f"{frac:0{len(str(int(rate_den) - 1))}d}".rstrip("0")
    if not digits:
        return str(whole)
    return f"{whole}.{digits}"


def _scaled(amount: str) -> int | None:
    try:
        price = Decimal(amount)
    except InvalidOperation:
        return None
    if not price.is_finite() or price < _MIN_SPOT_USD or price > _MAX_SPOT_USD:
        return None
    scaled = (price * Decimal(RATE_DEN)).to_integral_value(rounding=ROUND_HALF_UP)
    if scaled <= 0:
        return None
    return int(scaled)


def _median(values: list[int]) -> int:
    ordered = sorted(int(value) for value in values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid] + 1) // 2


def _drop_outliers(values: list[int]) -> list[int]:
    if len(values) < 2:
        return []
    med = _median(values)
    if med <= 0:
        return []
    bps = int(config.RATES_OUTLIER_BPS)
    kept = [value for value in values if abs(value - med) * 10000 <= med * bps]
    if len(kept) < 2:
        return []
    return kept


def _read_source(source: _Source, now: int) -> int | None:
    try:
        if fetcher is not None:
            payload = fetcher(source.name)
        else:
            payload = ssrf.safe_get_json(
                source.url,
                params=source.params,
                timeout=config.RATES_SOURCE_TIMEOUT_SECONDS,
            )
    except Exception:
        log.warning("btc/usd source %s failed", source.name)
        return None
    if not isinstance(payload, dict):
        return None
    try:
        text = source.parse(payload, now)
    except Exception:
        log.warning("btc/usd source %s was unreadable", source.name)
        return None
    if text is None:
        return None
    return _scaled(text)


def snapshot(now: int | None = None) -> dict:
    """Public view. status is ok, stale, or unavailable. A stale value is not a quote."""
    now = int(time.time()) if now is None else int(now)
    with _lock:
        state = _state
    if state is None:
        return {
            "status": "unavailable",
            "value": None,
            "sources": [],
            "fetched_at": None,
            "rate_num": None,
            "rate_den": None,
        }
    status = "ok" if now - int(state.fetched_at) <= int(config.RATES_STALE_SECONDS) else "stale"
    return {
        "status": status,
        "value": state.value,
        "sources": list(state.sources),
        "fetched_at": int(state.fetched_at),
        "rate_num": int(state.rate_num),
        "rate_den": int(state.rate_den),
    }


def quote_rate(now: int | None = None) -> Rate | None:
    """The median to lock onto an offer, or None when it must not be used."""
    now = int(time.time()) if now is None else int(now)
    view = snapshot(now)
    if view["status"] != "ok":
        return None
    with _lock:
        return _state


def refresh(now: int | None = None) -> dict:
    """Fetch the sources. A failed refresh keeps the last good median until it is stale."""
    now = int(time.time()) if now is None else int(now)
    samples: list[tuple[str, int]] = []
    for source in _SOURCES:
        scaled = _read_source(source, now)
        if scaled is not None:
            samples.append((source.name, scaled))
    kept_values = _drop_outliers([value for _name, value in samples])
    kept: list[tuple[str, int]] = []
    remaining = list(kept_values)
    for name, value in samples:
        if value in remaining:
            remaining.remove(value)
            kept.append((name, value))
    if len(kept) >= 2:
        med = _median([value for _name, value in kept])
        state = Rate(
            rate_num=med,
            rate_den=RATE_DEN,
            fetched_at=now,
            sources=tuple(sorted(name for name, _value in kept)),
            value=format_usd(med, RATE_DEN),
        )
        with _lock:
            global _state
            _state = state
        log.info("btc/usd status=ok sources=%s", ",".join(state.sources))
    else:
        log.info("btc/usd status=unavailable sources=%s", len(samples))
    return snapshot(now)


def usd_atomic_from_sats(sats: int, rate: Rate) -> int | None:
    """Round up to the next USDC atomic unit. Below $0.001 is not offered."""
    sats = int(sats)
    if sats < 1:
        return None
    numerator = sats * int(rate.rate_num) * 1_000_000
    denominator = int(rate.rate_den) * 100_000_000
    if numerator <= 0 or denominator <= 0:
        return None
    atomic = (numerator + denominator - 1) // denominator
    if atomic < _MIN_DERIVED_USD_ATOMIC or atomic > int(config.X402_MAX_USD_ATOMIC):
        return None
    return int(atomic)


def sats_from_usd_atomic(usd_atomic: int, rate: Rate) -> int | None:
    """Round up to the next sat. Zero is not offered."""
    usd_atomic = int(usd_atomic)
    if usd_atomic < 1 or int(rate.rate_num) <= 0:
        return None
    numerator = usd_atomic * int(rate.rate_den) * 100_000_000
    denominator = int(rate.rate_num) * 1_000_000
    if numerator <= 0 or denominator <= 0:
        return None
    sats = (numerator + denominator - 1) // denominator
    if sats < 1 or sats > _MAX_SATS:
        return None
    return int(sats)


def describe_derived(
    *,
    price_currency: str,
    price_sats: int | None,
    price_usd_atomic: int | None,
    now: int | None = None,
) -> dict:
    """A live quote for the merchant view. It is not the locked challenge price."""
    view = snapshot(now)
    if view["status"] != "ok":
        return {"status": view["status"]}
    rate = quote_rate(now)
    if rate is None:
        return {"status": "unavailable"}
    if price_currency == "sats" and price_sats:
        atomic = usd_atomic_from_sats(int(price_sats), rate)
        if atomic is None:
            return {"status": "below_minimum", "price_currency": "usd"}
        return {
            "status": "ok",
            "price_currency": "usd",
            "price_usd_atomic": atomic,
            "fetched_at": rate.fetched_at,
        }
    if price_currency == "usd" and price_usd_atomic:
        sats = sats_from_usd_atomic(int(price_usd_atomic), rate)
        if sats is None:
            return {"status": "below_minimum", "price_currency": "sats"}
        return {
            "status": "ok",
            "price_currency": "sats",
            "price_sats": sats,
            "fetched_at": rate.fetched_at,
        }
    return {"status": "unavailable"}
