"""BTC/USD from the standard Base price feed. No new dependencies.

The contract address is fixed. There is no environment override. A failed
read returns None. It does not raise and it does not guess a price.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from . import config, evm_rpc, rates
from .ssrf import SSRFError, safe_post_json

log = logging.getLogger("satsgate.rates")

# Official standard BTC/USD proxy on Base. Not an SVR proxy.
STANDARD_PROXY = "0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F"
DECIMALS_SELECTOR = "0x313ce567"
LATEST_ROUND_SELECTOR = "0xfeaf968c"
DESCRIPTION_SELECTOR = "0x7284e416"
FEED_DECIMALS = 8
RATE_DEN = 10**FEED_DECIMALS
FUTURE_GRACE_S = 60
# P-A4, originally proposed by Mike, approved by Ia on 2026-11-13.
MEDIAN_BAND_PERCENT = 5
DESCRIPTION_TEXT = "BTC / USD"
_WORD = 32
_ROUND_WORDS = 5

# Tests replace this. Production posts through the SSRF guard.
poster: Callable[..., tuple] | None = None

_RPC_FAIL = object()


@dataclass(frozen=True)
class ChainlinkQuote:
    rate_num: int
    rate_den: int
    fetched_at: int
    value: str


def read_btc_usd(
    now: int,
    *,
    median_rate_num: int | None = None,
    median_rate_den: int | None = None,
) -> ChainlinkQuote | None:
    """One usable quote, or None. Never raises."""
    try:
        return _read(int(now), median_rate_num, median_rate_den)
    except Exception:
        log.info("btc/usd rpc primary failed")
        return None


def _urls() -> list[str]:
    urls = [config.BASE_RPC_URL]
    extra = (config.BASE_RPC_FALLBACK_URL or "").strip()
    if extra and extra not in urls:
        urls.append(extra)
    return urls


def _read(
    now: int,
    median_rate_num: int | None,
    median_rate_den: int | None,
) -> ChainlinkQuote | None:
    urls = _urls()
    for index, url in enumerate(urls):
        try:
            outcome = _read_url(url, now, median_rate_num, median_rate_den)
        except Exception:
            log.info("btc/usd rpc %s failed", "primary" if index == 0 else "secondary")
            continue
        if outcome is _RPC_FAIL:
            log.info("btc/usd rpc %s failed", "primary" if index == 0 else "secondary")
            continue
        return outcome
    return None


def _read_url(
    url: str,
    now: int,
    median_rate_num: int | None,
    median_rate_den: int | None,
) -> ChainlinkQuote | None | object:
    chain = _rpc(url, "eth_chainId", [])
    if chain is _RPC_FAIL:
        return _RPC_FAIL
    if _bad_chain(chain):
        return None
    decimals_hex = _eth_call(url, DECIMALS_SELECTOR)
    if decimals_hex is _RPC_FAIL:
        return _RPC_FAIL
    decimals = _uint_word(decimals_hex)
    if decimals is None:
        return _RPC_FAIL
    if _bad_decimals(decimals):
        return None
    latest = _eth_call(url, LATEST_ROUND_SELECTOR)
    if latest is _RPC_FAIL:
        return _RPC_FAIL
    parsed = _parse_round(latest)
    if parsed is None:
        return None
    round_id, answer, updated_at, answered = parsed
    if _rejected(now, answer, updated_at, round_id, answered, median_rate_num, median_rate_den):
        return None
    if _wrong_description(url):
        return None
    return ChainlinkQuote(
        rate_num=int(answer),
        rate_den=RATE_DEN,
        fetched_at=int(updated_at),
        value=rates.format_usd(int(answer), RATE_DEN),
    )


def _rejected(
    now: int,
    answer: int,
    updated_at: int,
    round_id: int,
    answered: int,
    median_rate_num: int | None,
    median_rate_den: int | None,
) -> bool:
    if answer <= 0:
        return True
    if updated_at > now + FUTURE_GRACE_S:
        return True
    if answered < round_id:
        return True
    if now - updated_at > int(config.ACCOUNTING_RATE_STALE_S):
        return True
    minimum = int(rates._MIN_SPOT_USD) * RATE_DEN
    maximum = int(rates._MAX_SPOT_USD) * RATE_DEN
    if answer < minimum or answer > maximum:
        return True
    if _outside_median_band(answer, median_rate_num, median_rate_den):
        return True
    return False


def _outside_median_band(answer: int, median_rate_num: int | None, median_rate_den: int | None) -> bool:
    if median_rate_num is None or median_rate_den is None:
        return False
    if median_rate_num <= 0 or median_rate_den <= 0:
        return False
    # |answer/1e8 - median_num/median_den| * 100 > MEDIAN_BAND_PERCENT * median
    left = abs(answer * int(median_rate_den) - int(median_rate_num) * RATE_DEN) * 100
    right = MEDIAN_BAND_PERCENT * int(median_rate_num) * RATE_DEN
    return left > right


def _bad_chain(result: object) -> bool:
    if not isinstance(result, str) or not result.startswith("0x"):
        return True
    try:
        chain_id = int(result, 16)
    except ValueError:
        return True
    return chain_id != evm_rpc.BASE_CHAIN_ID


def _bad_decimals(decimals: int) -> bool:
    return int(decimals) != FEED_DECIMALS


def _wrong_description(url: str) -> bool:
    """A revert, an empty string, or an unreadable blob does not fail the read."""
    result = _eth_call(url, DESCRIPTION_SELECTOR)
    if result is _RPC_FAIL or not isinstance(result, str):
        return False
    raw = _hex_bytes(result)
    if raw is None:
        return False
    text = _abi_string(raw)
    if text is None or text == "":
        return False
    return text != DESCRIPTION_TEXT


def _eth_call(url: str, selector: str) -> object:
    return _rpc(url, "eth_call", [{"to": STANDARD_PROXY, "data": selector}, "latest"])


def _rpc(url: str, method: str, params: list) -> object:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    status, body = _post(url, payload)
    if status != 200 or not isinstance(body, dict):
        return _RPC_FAIL
    if body.get("error"):
        return _RPC_FAIL
    result = body.get("result")
    if not isinstance(result, str):
        return _RPC_FAIL
    return result


def _post(url: str, payload: dict) -> tuple[int, dict | None]:
    timeout = float(config.ACCOUNTING_RATE_TIMEOUT_S)
    fn = poster
    try:
        if fn is not None:
            result = fn(url, payload, {}, timeout)
        else:
            result = safe_post_json(url, payload, timeout=timeout)
    except SSRFError:
        raise
    except Exception as exc:
        raise SSRFError("fetch_failed") from exc
    if not isinstance(result, tuple) or len(result) != 2:
        return 0, None
    status, body = result
    if body is not None and not isinstance(body, dict):
        return int(status), None
    return int(status), body


def _parse_round(result: object) -> tuple[int, int, int, int] | None:
    raw = _hex_bytes(result)
    if raw is None or len(raw) < _WORD * _ROUND_WORDS:
        return None
    words = [raw[index : index + _WORD] for index in range(0, _WORD * _ROUND_WORDS, _WORD)]
    round_id = int.from_bytes(words[0], "big")
    answer = int.from_bytes(words[1], "big", signed=True)
    updated_at = int.from_bytes(words[3], "big")
    answered = int.from_bytes(words[4], "big")
    return round_id, answer, updated_at, answered


def _uint_word(result: object) -> int | None:
    raw = _hex_bytes(result)
    if raw is None or len(raw) < _WORD:
        return None
    return int.from_bytes(raw[:_WORD], "big")


def _hex_bytes(result: object) -> bytes | None:
    if not isinstance(result, str) or not result.startswith("0x"):
        return None
    body = result[2:]
    if body == "" or len(body) % 2 != 0:
        return None
    try:
        return bytes.fromhex(body)
    except ValueError:
        return None


def _abi_string(data: bytes) -> str | None:
    if len(data) < _WORD * 2:
        return None
    offset = int.from_bytes(data[:_WORD], "big")
    if offset < 0 or offset + _WORD > len(data):
        return None
    length = int.from_bytes(data[offset : offset + _WORD], "big")
    if length > 256:
        return None
    start = offset + _WORD
    end = start + length
    if end > len(data):
        return None
    try:
        return data[start:end].decode("utf-8")
    except UnicodeDecodeError:
        return None
