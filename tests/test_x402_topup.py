"""USDC credit packs. The facilitator is a test double. Lightning top-up is unchanged."""

from __future__ import annotations

import base64
import json
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
        assert blocked.status_code == 400
        assert blocked.json()["error"] == "x402_topup_disabled"
        assert "PAYMENT-REQUIRED" not in blocked.headers
        started = http.get("/v1/topup/trial")
        assert started.status_code == 402, started.text
        body = started.json()
        assert body["invoice"] and body["macaroon"] and body["payment_hash"]
        assert "payment_required" not in body
        assert "PAYMENT-REQUIRED" not in started.headers
        preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
        settled = http.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
        assert settled.status_code == 200, settled.text
        assert settled.json()["credits_added"] == 200


def test_invalid_treasury_disables_the_rail(tmp_path, monkeypatch):
    for bad in ("not-an-address", "0x" + "00" * 40, "0x1234"):
        module = _app(tmp_path, monkeypatch, bad)
        assert module.config.TREASURY_EVM_ADDRESS is None
        with TestClient(module.app) as http:
            blocked = http.get("/v1/topup/starter/x402")
            assert blocked.status_code == 400
            assert blocked.json()["error"] == "x402_topup_disabled"
            lightning = http.get("/v1/topup/starter")
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
        denied = http.get("/v1/topup/trial/x402", headers={"X-Api-Key": minted.json()["api_key"]})
        assert denied.status_code == 403
        assert denied.json()["error"] == "insufficient_scope"
        anonymous = http.get("/v1/topup/trial/x402")
        assert anonymous.status_code == 401

        module.rates._state = None
        stale = http.get("/v1/topup/trial/x402", headers={"X-Api-Key": key})
        assert stale.status_code == 503
        assert stale.json()["error"] == "rate_unavailable"
        lightning = http.get("/v1/topup/trial")
        assert lightning.status_code == 402 and "invoice" in lightning.json()
        _quote(module, "65000")

        offered = http.get("/v1/topup/trial/x402", headers={"X-Api-Key": key})
        assert offered.status_code == 402, offered.text
        body = offered.json()
        required = _header(offered, "PAYMENT-REQUIRED")
        assert required == body["payment_required"]
        document = json.loads(base64.standard_b64decode(required))
        accept = document["accepts"][0]
        expected = module.rates.usd_atomic_for_pack(1000, module.rates.quote_rate())
        assert expected == 650_000
        assert document["x402Version"] == 2
        assert accept["scheme"] == "exact"
        assert accept["network"] == "eip155:84532"
        assert accept["asset"] == _USDC
        assert accept["payTo"] == treasury.address
        assert accept["amount"] == "650000"
        assert 60 <= int(accept["maxTimeoutSeconds"]) <= 300
        assert "paymentFlow" not in accept["extra"]
        assert body["x402"]["amount"] == "650000"
        assert body["x402"]["payTo"] == treasury.address
        assert body["x402"]["network"] == "eip155:84532"
        assert body["credits"] == 200
        assert body["plan"]["id"] == "trial"
        scale = http.get("/v1/topup/scale/x402", headers={"X-Api-Key": key})
        assert scale.status_code == 402, scale.text
        scale_amount = json.loads(base64.standard_b64decode(_header(scale, "PAYMENT-REQUIRED")))["accepts"][0]["amount"]
        assert scale_amount == "325000000"
        assert module.rates.usd_atomic_from_sats(500_000, module.rates.quote_rate()) is None

        calls, post = _poster(payer)
        _install_poster(post)
        expires = body["expires_at"]

        def pay(changes=None, signature=None):
            encoded = _payload(required, payer, expires, **(changes or {}))
            if signature is not None:
                encoded = signature
            return http.get(
                "/v1/topup/trial/x402",
                headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": encoded},
            )

        wrong_payto = pay({"accepted": {"payTo": payer.address}, "authorization": {"to": payer.address}})
        assert wrong_payto.status_code == 402
        assert wrong_payto.json()["error"] == "payto_mismatch"
        wrong_amount = pay({"accepted": {"amount": "1"}, "authorization": {"value": "1"}})
        assert wrong_amount.status_code == 402
        assert wrong_amount.json()["error"] == "amount_mismatch"
        wrong_network = pay({"accepted": {"network": "eip155:8453"}})
        assert wrong_network.status_code == 402
        assert wrong_network.json()["error"] == "network_mismatch"
        assert calls == []
        assert _credits(http, key) == before

        failed_calls, failed_post = _poster(payer, settle={"success": False, "errorReason": "insufficient_funds"})
        _install_poster(failed_post)
        failed = pay()
        assert failed.status_code == 402, failed.text
        assert failed.json()["error"] == "x402_rejected"
        assert _credits(http, key) == before
        assert any(url.endswith("/settle") for url, _body in failed_calls)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            granted = conn.execute("SELECT COUNT(*) FROM ledger WHERE reason = 'topup_x402'").fetchone()[0]
        assert granted == 0

        calls, post = _poster(payer)
        _install_poster(post)
        saved = pay()
        assert saved.status_code == 200, saved.text
        paid = saved.json()
        assert paid["credits_added"] == 200
        assert paid["credits"] == before + 200
        assert paid["tx"] == _TX
        assert paid["transaction"] == _TX
        assert paid["network"] == "eip155:84532"
        assert paid["amount_usd_atomic"] == 650_000
        response = json.loads(base64.standard_b64decode(_header(saved, "PAYMENT-RESPONSE")))
        assert response["success"] is True
        assert response["transaction"] == _TX
        assert response["tx"] == _TX
        assert response["payer"]
        assert response["network"] == "eip155:84532"
        assert _credits(http, key) == before + 200
        verify_body = next(body for url, body in failed_calls if url.endswith("/verify"))
        settle_body = next(body for url, body in calls if url.endswith("/settle"))
        for posted in (verify_body, settle_body):
            requirements = posted["paymentRequirements"]
            assert requirements["payTo"] == treasury.address
            assert requirements["amount"] == "650000"
            assert requirements["network"] == "eip155:84532"
            assert requirements["asset"] == _USDC
            assert requirements["scheme"] == "exact"
            assert posted["paymentPayload"]["accepted"]["amount"] == "650000"

        replay = pay()
        assert replay.status_code == 409
        assert replay.json()["error"] == "x402_replay"
        assert _credits(http, key) == before + 200
        assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1

        ledger = http.get("/v1/ledger", headers={"X-Api-Key": key}).json()["entries"]
        entry = next(row for row in ledger if row["reason"] == "topup_x402")
        assert entry["delta_credits"] == 200
        assert entry["ref"] == _TX
        assert entry["network"] == "eip155:84532"
        assert entry["amount_usd_atomic"] == 650_000
        with sqlite3.connect(module.config.DB_PATH) as conn:
            topup = conn.execute(
                "SELECT rail, tx_hash, amount_usd_atomic, network, credits, status FROM topups WHERE tx_hash = ?",
                (_TX,),
            ).fetchone()
        assert tuple(topup) == ("x402", _TX, 650_000, "eip155:84532", 200, "settled")

        fresh = http.get("/v1/topup/trial/x402", headers={"X-Api-Key": key})
        assert fresh.status_code == 402
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1 WHERE id = ?", (fresh.json()["offer_id"],))
        expired_sig = _payload(_header(fresh, "PAYMENT-REQUIRED"), payer, fresh.json()["expires_at"])
        expired = http.get(
            "/v1/topup/trial/x402",
            headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": expired_sig},
        )
        assert expired.status_code == 402
        assert expired.json()["error"] == "expired"
        assert _credits(http, key) == before + 200


def test_concurrent_duplicate_grants_once(tmp_path, monkeypatch):
    treasury = Account.create()
    payer = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _quote(module)
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        offered = http.get("/v1/topup/starter/x402", headers={"X-Api-Key": key})
        assert offered.status_code == 402, offered.text
        encoded = _payload(offered.headers["PAYMENT-REQUIRED"], payer, offered.json()["expires_at"])
        _install_poster(_poster(payer)[1])
        results: list = []

        def once() -> None:
            results.append(
                http.get(
                    "/v1/topup/starter/x402",
                    headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": encoded},
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
        added = [response.json().get("credits_added", 0) for response in results if response.status_code == 200]
        assert added == [2500]
        rejected = next(response.json()["error"] for response in results if response.status_code == 409)
        assert rejected in {"x402_replay", "x402_in_progress"}
        assert _credits(http, key) == before + 2500
        with sqlite3.connect(module.config.DB_PATH) as conn:
            grants = conn.execute("SELECT COUNT(*) FROM ledger WHERE reason = 'topup_x402'").fetchone()[0]
        assert grants == 1
