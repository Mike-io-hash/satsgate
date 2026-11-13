"""One effective BTC/USD rate for accounting and for the buyer quote."""

from __future__ import annotations

import os
import time
from types import SimpleNamespace

os.environ.setdefault("SATSGATE_ENV", "development")
os.environ.setdefault("SATSGATE_MACAROON_SECRET", "test-secret")
os.environ.setdefault("SATSGATE_DEV_MODE", "0")
os.environ.setdefault("SATSGATE_WALLET_MODE", "lnurl")

from eth_account import Account
from fastapi.testclient import TestClient

from app.pricing import floor_msat_at_rate
from app.rates import Rate
from test_chainlink import oracle_poster
from test_rates import _use
from test_x402 import _buy, _gate, _load_app, _patch_dns, _site, _verify_payee
from test_x402_topup import _app, _quote


def _median(module, usd: int, *, fetched_at: int | None = None) -> None:
    _quote(module, str(usd))
    if fetched_at is not None:
        with module.rates._lock:
            module.rates._state = module.rates.Rate(
                rate_num=module.rates._state.rate_num,
                rate_den=module.rates._state.rate_den,
                fetched_at=fetched_at,
                sources=module.rates._state.sources,
                value=module.rates._state.value,
            )


def _down(module) -> None:
    module.chainlink.poster = lambda *_args, **_kwargs: (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "down"}},
    )
    module.accounting_rate.reset_for_tests()


def test_t_5_2_1_chainlink_wins_over_a_close_or_stale_median(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    now = int(time.time())
    module.chainlink.poster = oracle_poster(80_070, updated_at=now - 30)
    module.accounting_rate.reset_for_tests()
    _median(module, 83_200)
    fresh = module.accounting_rate.effective_rate(now=now)
    assert fresh is not None and fresh.source == "oracle"
    assert fresh.rate_num == 80_070 * 10**8
    module.accounting_rate.reset_for_tests()
    _median(module, 96_084, fetched_at=now - 181)
    stale_gap = module.accounting_rate.effective_rate(now=now)
    assert stale_gap is not None and stale_gap.source == "oracle"
    assert stale_gap.rate_num == 80_070 * 10**8


def test_t_5_2_1_http_topup_and_buyer_quote_follow_the_oracle(tmp_path, monkeypatch) -> None:
    treasury = Account.create()
    owner = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _patch_dns(monkeypatch, module)
    now = int(time.time())
    module.chainlink.poster = oracle_poster(80_070, updated_at=now - 20)
    module.accounting_rate.reset_for_tests()
    _median(module, 83_200)
    with TestClient(module.app) as http:
        key = _buy(http)
        offered = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert offered.status_code == 402, offered.text
        assert offered.json()["msat_credit"] == 1_249_000
        assert offered.json()["rate"]["source"] == "oracle"
        _verify_payee(http, key, owner)
        _site(http, key, path="/blog/post", body={"price_sats": 21, "max_uses": 1})
        http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        issued = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            json={"slug": "my-shop", "path": "/blog/post"},
        )
        assert issued.status_code == 200, issued.text
        assert issued.json()["x402"]["amount"] == "16815"


def test_t_5_2_2_stale_oracle_uses_the_median(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    now = int(time.time())
    module.chainlink.poster = oracle_poster(80_070, updated_at=now - 3_601)
    module.accounting_rate.reset_for_tests()
    _median(module, 65_000)
    rate = module.accounting_rate.effective_rate(now=now)
    assert rate is not None and rate.source == "fallback"
    assert rate.rate_num == 65_000 * module.rates.RATE_DEN
    assert "bitstamp" not in rate.source
    import app.x402_service as x402_service

    plan = x402_service.quote_plan(
        {"rail_lightning": 1, "rail_x402": 1, "x402_mode": "test"},
        {"price_currency": "sats", "price_sats": 21},
    )
    assert plan["rate"] is not None
    assert plan["rate"].rate_num == rate.rate_num


def test_t_5_2_3_sanity_failure_uses_the_median(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    now = int(time.time())
    _median(module, 65_000)
    for poster in (
        oracle_poster(0, updated_at=now - 10),
        oracle_poster(-1, updated_at=now - 10),
    ):
        module.chainlink.poster = poster
        module.accounting_rate.reset_for_tests()
        rate = module.accounting_rate.effective_rate(now=now)
        assert rate is not None and rate.source == "fallback"
        assert rate.rate_num == 65_000 * module.rates.RATE_DEN


def test_t_5_2_3_http_timeout_still_quotes_from_the_median(tmp_path, monkeypatch) -> None:
    from app.ssrf import SSRFError

    treasury = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _patch_dns(monkeypatch, module)

    def boom(*_args, **_kwargs):
        raise SSRFError("fetch_failed")

    module.chainlink.poster = boom
    module.accounting_rate.reset_for_tests()
    _median(module, 65_000)
    with TestClient(module.app) as http:
        key = _buy(http)
        offered = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert offered.status_code == 402, offered.text
        assert offered.json()["rate"]["source"] == "fallback"
        body = offered.json()["rate"]
        assert "bitstamp" not in str(body).lower()
        assert "coinbase" not in str(body).lower()
        assert "kraken" not in str(body).lower()


def test_t_5_2_4_both_fail_refuses_usdc_and_leaves_lightning(tmp_path, monkeypatch) -> None:
    treasury = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _patch_dns(monkeypatch, module)
    _down(module)
    module.rates._state = None
    with TestClient(module.app) as http:
        key = _buy(http)
        refused = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert refused.status_code == 503, refused.text
        assert refused.json() == {"ok": False, "error": "rate_unavailable"}
        assert "PAYMENT-REQUIRED" not in refused.headers
        lightning = http.post("/v1/topup/lightning", json={"sats": 1000}, headers={"X-Api-Key": key})
        assert lightning.status_code == 402
        assert "invoice" in lightning.json()


def test_t_5_2_9_floor_follows_the_rate_integers() -> None:
    den = 10**8
    assert floor_msat_at_rate(80_070 * den, den) == 1_248
    assert floor_msat_at_rate(100_000 * den, den) == 1_000


def test_t_5_2_10_advice_and_derived_quote_share_the_oracle(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    now = int(time.time())
    module.chainlink.poster = oracle_poster(20_000, updated_at=now - 15)
    module.accounting_rate.reset_for_tests()
    _median(module, 21_000)
    derived = module.rates.describe_derived(price_currency="sats", price_sats=21, price_usd_atomic=None, now=now)
    assert derived["status"] == "ok"
    assert derived["price_usd_atomic"] == 4_200
    client = SimpleNamespace(payee_lightning_address=None)
    site = {"routes": [{"price_currency": "sats", "price_sats": 21}]}
    tip = module._site_lightning_advice(client, site)
    assert tip is not None
    other = module.rates.usd_atomic_from_sats(21, Rate(21_000 * module.rates.RATE_DEN, module.rates.RATE_DEN, now, (), "21000"))
    assert other == 4_410
    assert derived["price_usd_atomic"] != other


def test_t_5_2_11_refresh_survives_a_primary_exception(tmp_path, monkeypatch) -> None:
    from app.ssrf import SSRFError

    module = _load_app(tmp_path)

    def boom(*_args, **_kwargs):
        raise SSRFError("fetch_failed")

    module.chainlink.poster = boom
    module.accounting_rate.reset_for_tests()
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    module.rates._state = None
    module.refresh_rates(int(time.time()))
    view = module.rates.snapshot()
    assert view["status"] == "ok"
    assert view["value"] == "65000"
