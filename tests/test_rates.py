"""BTC/USD median and the locked quote on a challenge. The facilitator is a test double."""

from __future__ import annotations

import dataclasses
import time

from eth_account import Account
from fastapi.testclient import TestClient

from test_x402 import (
    _buy,
    _credits,
    _enable_x402,
    _gate,
    _install_poster,
    _load_app,
    _patch_dns,
    _payload,
    _poster,
    _site,
    _verify_payee,
)

_BUYER = "203.0.113.10"


def _prices(values: dict[str, str | None], *, bitstamp_ts: int | None = None):
    def fetch(name: str):
        if name not in values or values[name] is None:
            return None
        price = values[name]
        if name == "coinbase":
            return {"data": {"amount": price, "currency": "USD"}}
        if name == "kraken":
            return {"result": {"XXBTZUSD": {"c": [price, "1"]}}}
        if name == "bitstamp":
            body = {"last": price}
            if bitstamp_ts is not None:
                body["timestamp"] = str(bitstamp_ts)
            return body
        return None

    return fetch


def _use(module, prices: dict[str, str | None], **kwargs):
    rates = module.rates
    rates.fetcher = _prices(prices, **kwargs)
    return rates.refresh()


def test_median_one_source_all_down_outlier_and_stale(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    rates = module.rates
    now = int(time.time())

    view = _use(module, {"coinbase": "64000", "kraken": "65000", "bitstamp": "66000"})
    assert view["status"] == "ok"
    assert view["value"] == "65000"
    assert view["sources"] == ["bitstamp", "coinbase", "kraken"]
    assert view["fetched_at"] == now or view["fetched_at"] >= now

    one_down = _use(module, {"coinbase": "64000", "kraken": None, "bitstamp": "66000"})
    assert one_down["status"] == "ok"
    assert one_down["value"] == "65000"
    assert one_down["sources"] == ["bitstamp", "coinbase"]

    kept = _use(module, {"coinbase": "65000", "kraken": "65100", "bitstamp": "90000"})
    assert kept["status"] == "ok"
    assert kept["sources"] == ["coinbase", "kraken"]
    assert kept["value"] == "65050"

    stale_source = _use(
        module,
        {"coinbase": "65000", "kraken": "65100", "bitstamp": "1000"},
        bitstamp_ts=now - 1000,
    )
    assert stale_source["sources"] == ["coinbase", "kraken"]
    assert "bitstamp" not in stale_source["sources"]

    fresh_value = rates._state.value
    rates.fetcher = lambda _name: None
    again = rates.refresh()
    assert again["status"] == "ok"
    assert again["value"] == fresh_value

    with rates._lock:
        rates._state = dataclasses.replace(rates._state, fetched_at=now - 181)
    stale = rates.snapshot()
    assert stale["status"] == "stale"
    assert stale["value"] == fresh_value
    assert rates.quote_rate() is None

    rates.fetcher = lambda _name: None
    with rates._lock:
        rates._state = None
    empty = rates.refresh()
    assert empty["status"] == "unavailable"
    assert empty["value"] is None
    assert empty["sources"] == []

    with TestClient(module.app) as http:
        public = http.get("/v1/rates")
        assert public.status_code == 200
        assert public.json()["status"] == "unavailable"
        assert public.json()["pair"] == "BTC-USD"


def test_rounding_rounds_up_and_drops_a_sub_cent_usdc_quote():
    from app.rates import Rate, sats_from_usd_atomic, usd_atomic_from_sats

    fine = Rate(rate_num=6_500_001_000_000, rate_den=100_000_000, fetched_at=1, sources=("coinbase",), value="65000.01")
    assert usd_atomic_from_sats(2, fine) == 1301
    assert sats_from_usd_atomic(10_000, fine) == 16
    coarse = Rate(rate_num=6_500_000_000_000, rate_den=100_000_000, fetched_at=1, sources=("coinbase",), value="65000")
    assert usd_atomic_from_sats(1, coarse) is None
    assert usd_atomic_from_sats(2, coarse) == 1300
    assert sats_from_usd_atomic(1_000_000, coarse) == 1539


def test_derived_rail_locks_and_a_stale_rate_keeps_the_main_price(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        _site(http, key, path="/blog/post", body={"price_sats": 21, "max_uses": 1})
        http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})

        issued = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            json={"slug": "my-shop", "path": "/blog/post"},
            headers={"X-Satsgate-Buyer-Ip": _BUYER},
        )
        assert issued.status_code == 200, issued.text
        body = issued.json()
        assert body["amount_sats"] == 21
        assert "invoice" in body and "macaroon" in body
        assert body["x402"]["amount"] == "13650"
        assert body["x402"]["payTo"] == owner.address
        assert "paymentFlow" not in issued.headers.get("PAYMENT-REQUIRED", "")
        assert body["rate"]["rate_num"] == 6_500_000_000_000

        _use(module, {"coinbase": "70000", "kraken": "70000", "bitstamp": "70000"})
        again = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            json={"slug": "my-shop", "path": "/blog/post"},
            headers={"X-Satsgate-Buyer-Ip": _BUYER},
        )
        assert again.status_code == 200, again.text
        assert again.json()["reused"] is True
        assert again.json()["x402"]["amount"] == "13650"
        assert again.json()["payment_hash"] == body["payment_hash"]

        calls, post = _poster(buyer)
        _install_poster(post)
        encoded = _payload(body["payment_required"], buyer, int(body["x402"]["expires_at"]))
        before = _credits(http, key)
        verified = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/blog/post", "payment_signature": encoded},
        )
        assert verified.status_code == 200, verified.text
        assert calls[0][1]["paymentRequirements"]["amount"] == "13650"
        assert _credits(http, key) == before

        with module.rates._lock:
            module.rates._state = dataclasses.replace(module.rates._state, fetched_at=int(time.time()) - 181)
        http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/other", "price_sats": 21},
        )
        stale = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            json={"slug": "my-shop", "path": "/other"},
            headers={"X-Satsgate-Buyer-Ip": "203.0.113.11"},
        )
        assert stale.status_code == 200, stale.text
        assert stale.json()["amount_sats"] == 21
        assert "invoice" in stale.json()
        assert "payment_required" not in stale.json()
        assert "PAYMENT-REQUIRED" not in stale.headers


def test_usd_route_derives_sats_and_mine_shows_the_quote(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 1_000_000})
        conflict = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/bad", "price_currency": "usd", "price_sats": 21, "price_usd_atomic": 1000},
        )
        assert conflict.status_code == 400
        assert conflict.json()["error"] == "price_conflict"
        tiny = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/zero", "price_currency": "usd", "price_usd_atomic": 0},
        )
        assert tiny.status_code == 422
        http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})

        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert issued.status_code == 200, issued.text
        body = issued.json()
        assert body["amount_sats"] == 1539
        assert "invoice" in body
        assert body["x402"]["amount"] == "1000000"
        assert body["rate"]["fetched_at"]

        mine = http.get("/v1/sites/mine", headers={"X-Api-Key": key}).json()["sites"][0]
        quoted = mine["routes"][0]["derived"]
        assert quoted["status"] == "ok"
        assert quoted["price_currency"] == "sats"
        assert quoted["price_sats"] == 1539
        assert "payTo" not in mine

        public = http.get("/v1/sites").json()["sites"][0]
        row = public["routes"][0]
        assert row["price_currency"] == "usd"
        assert row["price_usd_atomic"] == 1_000_000
        assert "price_sats" not in row
        assert "derived" not in row
        assert "payTo" not in public
        assert owner.address not in http.get("/v1/sites").text

        _enable_x402(http, key)
        only = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert only.status_code == 200, only.text
        assert only.json()["rail"] == "x402"
        assert "invoice" not in only.json()
        assert only.json()["x402"]["amount"] == "1000000"
