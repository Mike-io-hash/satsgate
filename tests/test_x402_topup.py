"""USDC credit packs. The facilitator is a test double. Lightning top-up is unchanged."""

from __future__ import annotations

import sqlite3
import threading

from eth_account import Account
from fastapi.testclient import TestClient

from test_x402 import (
    _TX,
    _auth,
    _buy,
    _credits,
    _install_poster,
    _load_app,
    _patch_dns,
    _payload,
    _poster,
)

_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


def _prices(values: dict[str, str | None]):
    def fetch(name: str):
        price = values.get(name)
        if price is None:
            return None
        if name == "coinbase":
            return {"data": {"amount": price, "currency": "USD"}}
        if name == "kraken":
            return {"result": {"XXBTZUSD": {"c": [price, "1"]}}}
        if name == "bitstamp":
            return {"last": price}
        return None

    return fetch


def _quote(module, price: str = "65000"):
    module.rates.fetcher = _prices({"coinbase": price, "kraken": price, "bitstamp": price})
    view = module.rates.refresh()
    assert view["status"] == "ok"
    return view


def _app(tmp_path, monkeypatch, treasury: str | None):
    if treasury is None:
        monkeypatch.delenv("SATSGATE_TREASURY_EVM_ADDRESS", raising=False)
        module = _load_app(tmp_path)
    else:
        monkeypatch.setenv("SATSGATE_TREASURY_EVM_ADDRESS", treasury)
        module = _load_app(tmp_path, SATSGATE_TREASURY_EVM_ADDRESS=treasury)
    _patch_dns(monkeypatch, module)
    return module


def _header(response, name: str) -> str:
    return response.headers[name]


def test_usdc_topup_disabled_leaves_lightning_alone(tmp_path, monkeypatch):
    module = _app(tmp_path, monkeypatch, None)
    assert module.config.TREASURY_EVM_ADDRESS is None
    with TestClient(module.app) as http:
        blocked = http.get("/v1/topup/trial/x402")
        assert blocked.status_code == 410
        assert blocked.json()["error"] == "packs_retired"
        assert "PAYMENT-REQUIRED" not in blocked.headers
        started = http.post("/v1/topup/lightning", json={"sats": 1000})
        assert started.status_code == 402, started.text
        body = started.json()
        assert body["invoice"] and body["macaroon"] and body["payment_hash"]
        assert "payment_required" not in body
        assert "PAYMENT-REQUIRED" not in started.headers
        preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
        settled = http.post("/v1/topup/lightning", json={"sats": 1000}, headers={"Authorization": _auth(body["macaroon"], preimage)})
        assert settled.status_code == 200, settled.text
        assert settled.json()["msat_added"] == 1_000_000
        assert "credits_added" not in settled.json()


def test_invalid_treasury_disables_the_rail(tmp_path, monkeypatch):
    for bad in ("not-an-address", "0x" + "00" * 40, "0x1234"):
        module = _app(tmp_path, monkeypatch, bad)
        assert module.config.TREASURY_EVM_ADDRESS is None
        with TestClient(module.app) as http:
            blocked = http.get("/v1/topup/starter/x402")
            assert blocked.status_code == 410
            assert blocked.json()["error"] == "packs_retired"
            lightning = http.post("/v1/topup/lightning", json={"sats": 1000})
            assert lightning.status_code == 402
            assert "invoice" in lightning.json()


def test_usdc_pack_verifies_settles_once_and_rejects_replays(tmp_path, monkeypatch):
    treasury = Account.create()
    payer = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _quote(module)
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        minted = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": key},
            json={"label": "proxy", "scope": "paywall"},
        )
        assert minted.status_code == 200, minted.text
        denied = http.post(
            "/v1/topup/lightning",
            json={"sats": 1000},
            headers={"X-Api-Key": minted.json()["api_key"]},
        )
        assert denied.status_code == 403
        assert denied.json()["error"] == "insufficient_scope"
        anonymous = http.get("/v1/topup/trial/x402")
        assert anonymous.status_code == 410
        assert anonymous.json()["error"] == "packs_retired"

        module.rates._state = None
        module.accounting_rate.fetcher = lambda _url: None
        module.accounting_rate.reset_for_tests()
        stale = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert stale.status_code == 503, stale.text
        assert stale.json()["error"] == "rate_unavailable"
        assert "PAYMENT-REQUIRED" not in stale.headers
        lightning = http.post("/v1/topup/lightning", json={"sats": 1000}, headers={"X-Api-Key": key})
        assert lightning.status_code == 402 and "invoice" in lightning.json()
        module.accounting_rate.fetcher = lambda _url: {"bitcoin": {"usd": 80070}}
        module.accounting_rate.reset_for_tests()
        offered = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert offered.status_code == 402, offered.text
        body = offered.json()
        assert body["bonus_bps"] == 0
        assert body["msat_credit"] > 0
        assert body["x402"]["payTo"] == treasury.address
        assert body["x402"]["amount"] == "1000000"
        required = _header(offered, "PAYMENT-REQUIRED")
        calls, post = _poster(payer)
        _install_poster(post)
        encoded = _payload(required, payer, body["expires_at"])
        saved = http.post(
            "/v1/topup/usdc",
            headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": encoded},
            json={"usd": "1.00"},
        )
        assert saved.status_code == 200, saved.text
        paid = saved.json()
        assert paid["msat_added"] == body["msat_credit"]
        assert paid["balance_msat"] == before + body["msat_credit"]
        assert paid["tx"] == _TX
        replay = http.post(
            "/v1/topup/usdc",
            headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": encoded},
            json={"usd": "1.00"},
        )
        assert replay.status_code == 409
        assert replay.json()["error"] == "x402_replay"
        assert _credits(http, key) == before + body["msat_credit"]
        assert calls



def test_concurrent_duplicate_grants_once(tmp_path, monkeypatch):
    treasury = Account.create()
    payer = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _quote(module)
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        offered = http.get("/v1/topup/starter/x402", headers={"X-Api-Key": key})
        assert offered.status_code == 410, offered.text
        assert offered.json()["error"] == "packs_retired"
        fresh = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert fresh.status_code == 402, fresh.text
        encoded = _payload(fresh.headers["PAYMENT-REQUIRED"], payer, fresh.json()["expires_at"])
        expected = int(fresh.json()["msat_credit"])
        _install_poster(_poster(payer)[1])
        results: list = []

        def once() -> None:
            results.append(
                http.post(
                    "/v1/topup/usdc",
                    headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": encoded},
                    json={"usd": "1.00"},
                )
            )

        threads = [threading.Thread(target=once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(results) == 2
        statuses = sorted(response.status_code for response in results)
        assert statuses == [200, 409], [response.status_code for response in results]
        added = [response.json().get("msat_added", 0) for response in results if response.status_code == 200]
        assert added == [expected]
        rejected = next(response.json()["error"] for response in results if response.status_code == 409)
        assert rejected in {"x402_replay", "x402_in_progress"}
        assert _credits(http, key) == before + expected
        with sqlite3.connect(module.config.DB_PATH) as conn:
            grants = conn.execute("SELECT COUNT(*) FROM ledger WHERE reason = 'topup_x402'").fetchone()[0]
        assert grants == 1
