"""Chainlink BTC/USD reader. No network except the optional live read, which skips."""

from __future__ import annotations

import os
import time

os.environ.setdefault("SATSGATE_ENV", "development")
os.environ.setdefault("SATSGATE_MACAROON_SECRET", "test-secret")
os.environ.setdefault("SATSGATE_DEV_MODE", "0")
os.environ.setdefault("SATSGATE_WALLET_MODE", "lnurl")

import pytest

from app import chainlink, config
from app.ssrf import SSRFError

_ANSWER = 68_938_64914794
_SVR = (
    "0xC01502b887D09B0f329981764268fC32a94cB453",
    "0x32F587986D3fb47601157c19615d568BeD0BCabc",
    "0x8D9e0911A532e2a3C005667B475E6F9742355f2b",
)


def _word(value: int) -> str:
    if value < 0:
        value = (1 << 256) + value
    return f"{value:064x}"


def _round_hex(round_id: int, answer: int, started: int, updated: int, answered: int) -> str:
    return "0x" + "".join(_word(part) for part in (round_id, answer, started, updated, answered))


def _string_hex(text: str) -> str:
    raw = text.encode("utf-8")
    pad = (32 - (len(raw) % 32)) % 32
    body = raw + b"\x00" * pad
    return "0x" + _word(32) + _word(len(raw)) + body.hex()


def _install(monkeypatch, poster):
    monkeypatch.setattr(chainlink, "poster", poster)
    monkeypatch.setattr(config, "BASE_RPC_FALLBACK_URL", "")


def _rpc(
    *,
    chain_id: str = "0x2105",
    decimals: int = 8,
    answer: int = _ANSWER,
    updated_at: int,
    round_id: int = 7,
    answered: int | None = None,
    latest: str | None = None,
    status: int = 200,
    error: dict | None = None,
    body: object | None = None,
    non_dict: bool = False,
    description: str | None = None,
    raise_error: bool = False,
):
    answered_round = round_id if answered is None else answered
    latest_hex = latest
    if latest_hex is None:
        latest_hex = _round_hex(round_id, answer, updated_at, updated_at, answered_round)

    def poster(url, payload, _headers, timeout):
        if raise_error:
            raise SSRFError("fetch_failed")
        assert timeout == float(config.ACCOUNTING_RATE_TIMEOUT_S)
        if non_dict:
            return status, ["not", "a", "dict"]
        if body is not None:
            return status, body
        method = payload["method"]
        if method == "eth_chainId":
            result = {"jsonrpc": "2.0", "id": 1, "result": chain_id}
        else:
            data = payload["params"][0]["data"]
            to = payload["params"][0]["to"]
            assert to.lower() == chainlink.STANDARD_PROXY.lower()
            if data == chainlink.DECIMALS_SELECTOR:
                result = {"jsonrpc": "2.0", "id": 1, "result": "0x" + _word(decimals)}
            elif data == chainlink.LATEST_ROUND_SELECTOR:
                result = {"jsonrpc": "2.0", "id": 1, "result": latest_hex}
            elif data == chainlink.DESCRIPTION_SELECTOR:
                if description is None:
                    result = {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
                else:
                    result = {"jsonrpc": "2.0", "id": 1, "result": _string_hex(description)}
            else:
                result = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "method"}}
        if error is not None and method == "eth_call" and payload["params"][0]["data"] == chainlink.LATEST_ROUND_SELECTOR:
            result = {"jsonrpc": "2.0", "id": 1, "error": error}
        if status != 200:
            return status, result
        return 200, result

    return poster


def oracle_poster(usd: int, *, updated_at: int | None = None):
    """Poster for a fresh 8-decimal quote. Tests pass this to ``chainlink.poster``."""
    stamp = int(time.time()) if updated_at is None else int(updated_at)
    return _rpc(updated_at=stamp, answer=int(usd) * 10**8)


def test_t_5_1_1_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 120
    _install(monkeypatch, _rpc(updated_at=updated, description="BTC / USD"))
    quote = chainlink.read_btc_usd(now)
    assert quote is not None
    assert quote.rate_num == _ANSWER
    assert quote.rate_den == 10**8
    assert quote.fetched_at == updated
    assert quote.value == "68938.64914794"


def test_t_5_1_2_malformed_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 30
    cases: list[tuple[str, dict]] = [
        ("empty", {"latest": ""}),
        ("bare-prefix", {"latest": "0x"}),
        ("odd-length", {"latest": "0xabc"}),
        ("non-hex", {"latest": "0x" + ("zz" * 160)}),
        ("four-words", {"latest": "0x" + (_word(7) + _word(_ANSWER) + _word(updated) + _word(updated))}),
        ("missing-prefix", {"latest": _round_hex(7, _ANSWER, updated, updated, 7)[2:]}),
        ("rpc-error", {"error": {"code": -32000, "message": "header not found"}}),
        ("http", {"status": 503}),
        ("non-dict", {"non_dict": True}),
    ]
    for name, kwargs in cases:
        _install(monkeypatch, _rpc(updated_at=updated, **kwargs))
        assert chainlink.read_btc_usd(now) is None, name


def test_t_5_1_3_stale_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    monkeypatch.setattr(config, "ACCOUNTING_RATE_STALE_S", 3600)
    _install(monkeypatch, _rpc(updated_at=now - 3601))
    assert chainlink.read_btc_usd(now) is None
    _install(monkeypatch, _rpc(updated_at=now - 3600))
    assert chainlink.read_btc_usd(now) is not None


def test_t_5_1_4_negative_and_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    for answer in (0, -1):
        _install(monkeypatch, _rpc(updated_at=now - 10, answer=answer))
        assert chainlink.read_btc_usd(now) is None


def test_t_5_1_5_future_updated_at(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    _install(monkeypatch, _rpc(updated_at=now + 61))
    assert chainlink.read_btc_usd(now) is None
    _install(monkeypatch, _rpc(updated_at=now + 60))
    assert chainlink.read_btc_usd(now) is not None
    _install(monkeypatch, _rpc(updated_at=now + 30))
    assert chainlink.read_btc_usd(now) is not None


def test_t_5_1_6_incomplete_round(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 10
    _install(monkeypatch, _rpc(updated_at=updated, round_id=9, answered=8))
    assert chainlink.read_btc_usd(now) is None
    _install(monkeypatch, _rpc(updated_at=updated, round_id=9, answered=9))
    assert chainlink.read_btc_usd(now) is not None
    _install(monkeypatch, _rpc(updated_at=updated, round_id=9, answered=10))
    assert chainlink.read_btc_usd(now) is not None


def test_t_5_1_7_wrong_decimals(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    for decimals in (18, 0, 6):
        _install(monkeypatch, _rpc(updated_at=now - 10, decimals=decimals))
        assert chainlink.read_btc_usd(now) is None, decimals


def test_t_5_1_8_wrong_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    for chain_id in ("0x1", hex(84532)):
        _install(monkeypatch, _rpc(updated_at=now - 10, chain_id=chain_id))
        assert chainlink.read_btc_usd(now) is None, chain_id


def test_t_5_1_9_rpc_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    _install(monkeypatch, _rpc(updated_at=now, raise_error=True))
    quote = chainlink.read_btc_usd(now)
    assert quote is None


def test_t_5_1_10_absolute_band(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 10
    for usd, ok in ((999, False), (10_000_001, False), (1_000, True), (10_000_000, True)):
        _install(monkeypatch, _rpc(updated_at=updated, answer=usd * 10**8))
        quote = chainlink.read_btc_usd(now)
        assert (quote is not None) is ok, usd


def test_t_5_1_11_median_band(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 10
    den = 10**8
    median = 70_000 * den
    inside = (70_000 * den) + (5 * median) // 100
    outside = 73_570 * den
    _install(monkeypatch, _rpc(updated_at=updated, answer=inside))
    assert chainlink.read_btc_usd(now, median_rate_num=median, median_rate_den=den) is not None
    low = median - (5 * median) // 100
    _install(monkeypatch, _rpc(updated_at=updated, answer=low))
    assert chainlink.read_btc_usd(now, median_rate_num=median, median_rate_den=den) is not None
    _install(monkeypatch, _rpc(updated_at=updated, answer=outside))
    assert chainlink.read_btc_usd(now, median_rate_num=median, median_rate_den=den) is None
    _install(monkeypatch, _rpc(updated_at=updated, answer=84_000 * den))
    assert chainlink.read_btc_usd(now) is not None


def test_t_5_1_12_standard_proxy_not_svr() -> None:
    assert chainlink.STANDARD_PROXY.lower() == "0x64c911996d3c6ac71f9b455b1e8e7266bcbd848f"
    for svr in _SVR:
        assert chainlink.STANDARD_PROXY.lower() != svr.lower()


def test_pa3_second_rpc_is_used_once_when_the_primary_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 15
    calls: list[str] = []
    good = _rpc(updated_at=updated)

    def poster(url, payload, headers, timeout):
        calls.append(url)
        if url == "https://primary.example":
            raise SSRFError("fetch_failed")
        return good(url, payload, headers, timeout)

    monkeypatch.setattr(chainlink, "poster", poster)
    monkeypatch.setattr(config, "BASE_RPC_URL", "https://primary.example")
    monkeypatch.setattr(config, "BASE_RPC_FALLBACK_URL", "https://secondary.example")
    quote = chainlink.read_btc_usd(now)
    assert quote is not None
    assert calls[0] == "https://primary.example"
    assert "https://secondary.example" in calls
    assert calls.count("https://primary.example") == 1


def test_description_revert_is_optional_and_a_wrong_name_is_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_700_000_000
    updated = now - 10
    _install(monkeypatch, _rpc(updated_at=updated, description=None))
    assert chainlink.read_btc_usd(now) is not None
    _install(monkeypatch, _rpc(updated_at=updated, description="ETH / USD"))
    assert chainlink.read_btc_usd(now) is None


def test_t_5_1_13_live_base_rpc_skips_when_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chainlink, "poster", None)
    monkeypatch.setattr(config, "BASE_RPC_FALLBACK_URL", "")
    try:
        quote = chainlink.read_btc_usd(int(time.time()))
    except Exception as exc:
        pytest.skip(f"rpc unavailable: {type(exc).__name__}")
    if quote is None:
        pytest.skip("rpc unavailable")
    assert quote.rate_den == 10**8
    assert quote.rate_num > 0
    age = int(time.time()) - int(quote.fetched_at)
    assert 0 <= age < 3600
