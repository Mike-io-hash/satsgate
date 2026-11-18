"""Self-hosted and gate USDC funding under model B (T-C.6)."""

from __future__ import annotations

import base64
import json
import os
import sqlite3

import httpx
from eth_account import Account
from fastapi.testclient import TestClient

from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from test_proxy_parity import SECRET, CoreBridge, _restricted, _settings
from test_rates import _use
from test_satsgate_gate import Origin, _close, _load_app, _open_gate, _patch_dns, _prepare, _settings as gate_settings
from test_x402 import _install_poster, _payload, _poster, _verify_payee
from test_x402_cdp import _cdp_env, _material


def _free(http: TestClient, key: str) -> tuple[int, int]:
    body = http.get("/v1/balance", headers={"X-Api-Key": key}).json()
    return int(body["balance_msat"]), int(body["free_unlocks_remaining"])


def _ledger_count() -> int:
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        row = conn.execute("SELECT COUNT(*) FROM ledger WHERE reason = 'paywall_verify'").fetchone()
    return int(row[0])


def test_t_c_6_1_self_hosted_test_settle_does_not_spend(tmp_path, monkeypatch) -> None:
    """Dropping cost=0 on a Base Sepolia offer spends a slot or a balance and fails this."""
    from test_proxy_parity import test_proxy_x402_charges_once_and_records_the_ledger

    test_proxy_x402_charges_once_and_records_the_ledger(tmp_path, monkeypatch)


def test_t_c_6_2_live_offer_uses_one_free_slot(tmp_path, monkeypatch) -> None:
    """Always passing cost=0 would leave the free quota unchanged."""
    key_id, secret, _key = _material()
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500", **_cdp_env(key_id, secret))
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer = Account.create()
    calls, post = _poster(buyer)
    _install_poster(post)
    origin = Origin()
    with TestClient(module.app) as core:
        account = core.post("/v1/accounts", json={}).json()["api_key"]
        core.post(
            "/v1/client/payee",
            headers={"X-Api-Key": account},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        _verify_payee(core, account, owner)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
        text = (
            "core:\n  base_url: http://core.test\n  api_key_env: SATSGATE_API_KEY\n"
            "upstream:\n  base_url: http://upstream.test\n"
            "origin:\n  secret_env: SATSGATE_ORIGIN_SECRET\n"
            "server:\n  public_base: http://proxy.test\n"
            "routes:\n  - name: article\n    methods: [GET]\n    path: /blog/**\n"
            "    price_sats: 100\n    access: per_request\n    scope: route\n"
            "    x402: true\n    x402_mode: live\n"
        )
        path = tmp_path / "live.yaml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
        settings = load_settings(path)
        before_balance, before_free = _free(core, account)
        with TestClient(build_app(settings, transport=CoreBridge(module.app, origin))) as proxy:
            challenge = proxy.get("/blog/a")
            assert challenge.status_code == 402, challenge.text
            document = json.loads(base64.b64decode(challenge.headers["payment-required"]))
            assert document["accepts"][0]["network"] == "eip155:8453"
            signature = _payload(challenge.headers["payment-required"], buyer, challenge.json()["x402"]["expires_at"])
            origin.responder = lambda request: httpx.Response(200, content=b"ok")
            served = proxy.get("/blog/a", headers={"PAYMENT-SIGNATURE": signature})
            assert served.status_code == 200, served.text
            balance, free = _free(core, account)
            assert balance == before_balance
            assert free == before_free - 1
            from app.db import hash_api_key

            with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                key_id = conn.execute(
                    "SELECT id FROM api_keys WHERE key_hash = ?",
                    (hash_api_key(os.environ["SATSGATE_API_KEY"]),),
                ).fetchone()[0]
                conn.execute("UPDATE quota_buckets SET used_unlocks = 500")
                conn.execute("UPDATE client_quota SET used_unlocks = 500")
                conn.execute("UPDATE clients SET balance_msat = 100000000")
            paid_challenge = proxy.get("/blog/a")
            assert paid_challenge.status_code == 402, paid_challenge.text
            paid_body = paid_challenge.json()
            paid_signature = _payload(
                paid_challenge.headers["payment-required"],
                buyer,
                paid_body["x402"]["expires_at"],
                authorization={"nonce": "0x" + "cd" * 32},
            )
            origin.responder = lambda request: httpx.Response(200, content=b"paid")
            paid = proxy.get("/blog/a", headers={"PAYMENT-SIGNATURE": paid_signature})
            assert paid.status_code == 200, paid.text
            with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                row = conn.execute(
                    """
                    SELECT api_key_id, network, amount_usd_atomic
                    FROM ledger WHERE reason = 'paywall_verify'
                    """
                ).fetchone()
            assert row[0] == key_id
            assert row[1] == document["accepts"][0]["network"]
            assert row[2] == int(paid_body["x402"]["amount"])
    assert sum(1 for url, _body in calls if url.endswith("/settle")) == 2


def test_t_c_6_3_replaying_a_test_signature_does_not_record_twice(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500")
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer = Account.create()
    calls, post = _poster(buyer)
    _install_poster(post)
    origin = Origin()
    origin.responder = lambda request: httpx.Response(200, content=b"ok")
    with TestClient(module.app) as core:
        account = core.post("/v1/topup/lightning", json={"sats": 1000})
        assert account.status_code == 402
        # Use the parity buyer only as the USDC signer. The merchant is a fresh topped-up account.
        from test_satsgate_gate import _buy

        merchant = _buy(core)
        _verify_payee(core, merchant, owner)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, merchant))
        settings = _settings(tmp_path, monkeypatch, x402=True)
        with TestClient(build_app(settings, transport=CoreBridge(module.app, origin))) as proxy:
            challenge = proxy.get("/blog/a")
            signature = _payload(challenge.headers["payment-required"], buyer, challenge.json()["x402"]["expires_at"])
            headers = {"PAYMENT-SIGNATURE": signature}
            first = proxy.get("/blog/a", headers=headers)
            assert first.status_code == 200, first.text
            before = _free(core, merchant)
            rows = _ledger_count()
            second = proxy.get("/blog/a", headers=headers)
            assert second.status_code == 402, second.text
            assert second.json()["error"] == "x402_replay"
        assert _free(core, merchant) == before
        assert _ledger_count() == rows
    assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1


def test_t_c_6_4_fresh_account_live_proxy_uses_a_free_unlock(tmp_path, monkeypatch) -> None:
    """Reading clients.credits again returns 502 insufficient balance for this account."""
    key_id, secret, _key = _material()
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500", **_cdp_env(key_id, secret))
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer = Account.create()
    _buyer_calls, post = _poster(buyer)
    _install_poster(post)
    origin = Origin()
    origin.responder = lambda request: httpx.Response(200, content=b"ok")
    with TestClient(module.app) as core:
        opened = core.post("/v1/accounts", json={})
        assert opened.status_code == 201, opened.text
        account = opened.json()["api_key"]
        assert opened.json()["balance_msat"] == 0
        core.post(
            "/v1/client/payee",
            headers={"X-Api-Key": account},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        _verify_payee(core, account, owner)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
        path = tmp_path / "live.yaml"
        path.write_text(
            "core:\n  base_url: http://core.test\n  api_key_env: SATSGATE_API_KEY\n"
            "upstream:\n  base_url: http://upstream.test\n"
            "origin:\n  secret_env: SATSGATE_ORIGIN_SECRET\n"
            "server:\n  public_base: http://proxy.test\n"
            "routes:\n  - name: article\n    methods: [GET]\n    path: /blog/**\n"
            "    price_sats: 100\n    access: per_request\n    scope: route\n"
            "    x402: true\n    x402_mode: live\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
        settings = load_settings(path)
        before_balance, before_free = _free(core, account)
        assert before_free == 500
        with TestClient(build_app(settings, transport=CoreBridge(module.app, origin))) as proxy:
            challenge = proxy.get("/blog/a")
            assert challenge.status_code == 402, challenge.text
            signature = _payload(challenge.headers["payment-required"], buyer, challenge.json()["x402"]["expires_at"])
            served = proxy.get("/blog/a", headers={"PAYMENT-SIGNATURE": signature})
            assert served.status_code == 200, served.text
        balance, free = _free(core, account)
    assert balance == before_balance == 0
    assert free == before_free - 1


def test_t_c_6_5_model_b_ignores_the_legacy_credits_column(tmp_path, monkeypatch) -> None:
    """A check against clients.credits refuses the funded account below."""
    key_id, secret, _key = _material()
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500", **_cdp_env(key_id, secret))
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer = Account.create()
    _calls, post = _poster(buyer)
    _install_poster(post)
    origin = Origin()
    with TestClient(module.app) as core:
        account = core.post("/v1/accounts", json={}).json()["api_key"]
        core.post(
            "/v1/client/payee",
            headers={"X-Api-Key": account},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        _verify_payee(core, account, owner)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
        path = tmp_path / "live.yaml"
        path.write_text(
            "core:\n  base_url: http://core.test\n  api_key_env: SATSGATE_API_KEY\n"
            "upstream:\n  base_url: http://upstream.test\n"
            "origin:\n  secret_env: SATSGATE_ORIGIN_SECRET\n"
            "server:\n  public_base: http://proxy.test\n"
            "routes:\n  - name: article\n    methods: [GET]\n    path: /blog/**\n"
            "    price_sats: 100\n    access: per_request\n    scope: route\n"
            "    x402: true\n    x402_mode: live\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
        settings = load_settings(path)
        with TestClient(build_app(settings, transport=CoreBridge(module.app, origin))) as proxy:
            challenge = proxy.get("/blog/a")
            assert challenge.status_code == 402, challenge.text
            body = challenge.json()
            signature = _payload(challenge.headers["payment-required"], buyer, body["x402"]["expires_at"])
            module.config.FREE_QUOTA = 0
            with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                conn.execute("UPDATE clients SET balance_msat = 0, credits = 0")
            refused = core.post(
                "/v1/paywall/x402/verify",
                headers={"X-Api-Key": account},
                json={
                    "resource": "route:article",
                    "resource_url": "http://proxy.test/blog/a",
                    "payment_signature": signature,
                },
            )
            assert refused.status_code == 402, refused.text
            assert refused.json()["error"] == "insufficient balance"
            with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                conn.execute("UPDATE clients SET balance_msat = 100000, credits = 0")
            origin.responder = lambda request: httpx.Response(200, content=b"ok")
            served = proxy.get("/blog/a", headers={"PAYMENT-SIGNATURE": signature})
            assert served.status_code == 200, served.text
            balance, _free_left = _free(core, account)
    assert balance < 100000


def test_t_c_6_6_gate_live_receipt_uses_a_free_unlock(tmp_path, monkeypatch) -> None:
    key_id, secret, _key = _material()
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500", **_cdp_env(key_id, secret))
    _patch_dns(monkeypatch, module)
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer = Account.create()
    calls, post = _poster(buyer)
    _install_poster(post)
    with TestClient(module.app) as core:
        key, _origin_secret = _prepare(core, credits=False)
        _verify_payee(core, key, owner)
        added = core.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert added.status_code == 200, added.text
        live = core.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert live.status_code == 200, live.text
        before_balance, before_free = _free(core, key)
        gate, core_client, _origin = _open_gate(module.app, gate_settings())
        try:
            with gate as http:
                challenge = http.get("/my-shop/paid")
                assert challenge.status_code == 402, challenge.text
                signature = _payload(challenge.headers["payment-required"], buyer, challenge.json()["x402"]["expires_at"])
                paid = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert paid.status_code == 200, paid.text
                assert paid.json()["receipt"]
        finally:
            _close(core_client)
        balance, free = _free(core, key)
        assert balance == before_balance
        assert free == before_free - 1
        tested = core.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"x402_mode": "test"})
        assert tested.status_code == 200, tested.text
        _install_poster(post)
        gate, core_client, _origin = _open_gate(module.app, gate_settings())
        try:
            with gate as http:
                challenge = http.get("/my-shop/paid")
                assert challenge.status_code == 402, challenge.text
                assert challenge.json()["x402_mode"] == "test"
                signature = _payload(challenge.headers["payment-required"], buyer, challenge.json()["x402"]["expires_at"])
                held = _free(core, key)
                paid = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert paid.status_code == 200, paid.text
                assert _free(core, key) == held
        finally:
            _close(core_client)
    assert sum(1 for url, _body in calls if url.endswith("/settle")) >= 1
