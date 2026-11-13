"""Signup caps, advice, refunds, forecast, the buyer 502, and the USDC fee refuse."""

from __future__ import annotations

import logging
import sqlite3

from fastapi.testclient import TestClient

from test_satsgate_gate import _close, _open_gate, _patch_dns, _prepare, _settings
from test_x402 import _buy, _gate, _load_app
from test_x402_topup import _quote


def test_signup_caps_and_the_lightning_mint_share_them(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    monkeypatch.setattr(module.config, "SIGNUP_MAX_PER_IP_PER_DAY", 3)
    monkeypatch.setattr(module.config, "SIGNUP_MAX_GLOBAL_PER_DAY", 100)
    with TestClient(module.app) as http:
        first = http.post("/v1/accounts", json={})
        assert first.status_code == 201, first.text
        key = first.json()["api_key"]
        assert key.startswith("sg_")
        assert "credits" not in first.json()
        assert first.json()["balance_msat"] == 0
        monkeypatch.setattr(module.config, "FREE_QUOTA", 500)
        quoted = http.post("/v1/accounts", json={})
        assert quoted.status_code == 201, quoted.text
        assert quoted.json()["estimated_unlocks_remaining"] == 500
        assert quoted.json()["paid_unlocks_estimate"] == 0
        monkeypatch.setattr(module.config, "FREE_QUOTA", 0)
        again = http.post("/v1/accounts", headers={"X-Api-Key": key}, json={})
        assert again.status_code == 409
        assert again.json()["error"] == "account_exists"
        assert "api_key" not in again.json()
        personal = http.post("/v1/accounts", json={"email": "a@example.com"})
        assert personal.status_code == 422
        for _ in range(1):
            assert http.post("/v1/accounts", json={}).status_code == 201
        fourth = http.post("/v1/accounts")
        assert fourth.status_code == 429, fourth.text
        assert fourth.json()["error"] == "signup_ip_limit"
        assert int(fourth.headers["retry-after"]) >= 1
        lightning = http.post("/v1/topup/lightning", json={"sats": 1000})
        assert lightning.status_code == 429
        assert lightning.json()["error"] == "signup_ip_limit"
        owned = http.post("/v1/topup/lightning", json={"sats": 1000}, headers={"X-Api-Key": key})
        assert owned.status_code == 402, owned.text
        monkeypatch.setattr(module.config, "SIGNUP_MAX_GLOBAL_PER_DAY", 3)
        # The three accounts above already filled a global cap of 3. A new IP still shares it.
        blocked = http.post(
            "/v1/accounts",
            json={},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "signup_global_limit"


def test_restricted_key_reads_balance_and_cannot_move_money(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        minted = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": key},
            json={"label": "read", "scope": "paywall"},
        )
        assert minted.status_code == 200, minted.text
        restricted = minted.json()["api_key"]
        assert restricted.startswith("sgr_")
        balance = http.get("/v1/balance", headers={"X-Api-Key": restricted})
        assert balance.status_code == 200, balance.text
        assert "balance_msat" in balance.json()
        assert "credits" not in balance.json()
        forecast = http.get("/v1/usage/forecast", headers={"X-Api-Key": restricted})
        assert forecast.status_code == 200, forecast.text
        assert forecast.json()["forecast"]["status"] == "insufficient_data"
        assert forecast.json()["forecast"]["estimated_depletion_iso"] is None
        assert forecast.json()["recommendation"] is None
        for path, payload in (
            ("/v1/accounts", {}),
            ("/v1/topup/lightning", {"sats": 1000}),
            ("/v1/topup/usdc", {"usd": "1.00"}),
            ("/v1/client/payee", {"payee_lightning_address": "a@pay.example"}),
        ):
            denied = http.post(path, headers={"X-Api-Key": restricted}, json=payload)
            assert denied.status_code == 403, denied.text
            assert denied.json()["error"] == "insufficient_scope"


def test_forecast_never_names_a_pack(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        view = http.get("/v1/usage/forecast", headers={"X-Api-Key": key})
        assert view.status_code == 200
        text = view.text
        assert view.json()["forecast"]["status"] == "insufficient_data"
        for pack in ("trial", "starter", "growth", "scale", "hyper", "mega", "recommended_purchase"):
            assert pack not in text


def test_add_lightning_and_balance_advice_stay_off_the_buyer_402(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "shop", "display_name": "Shop", "origin_url": "https://origin.example"},
        )
        assert created.status_code == 200, created.text
        cheap = http.post(
            "/v1/sites/shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/tiny", "price_currency": "usd", "price_usd_atomic": 9900},
        )
        assert cheap.status_code == 200, cheap.text
        seen = http.get("/v1/sites/shop", headers={"X-Api-Key": key})
        assert seen.json()["advice"]["code"] == "add_lightning"
        _quote(module)
        under = http.post(
            "/v1/sites/shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/one", "price_sats": 1},
        )
        over = http.post(
            "/v1/sites/shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/twenty", "price_sats": 21},
        )
        assert under.status_code == 200 and over.status_code == 200
        # The cheap USDC route still wins. Drop it and the 1-sat route is under a cent.
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("DELETE FROM site_routes WHERE path_pattern = '/tiny'")
        sats_advice = http.get("/v1/sites/shop", headers={"X-Api-Key": key})
        assert sats_advice.json()["advice"]["code"] == "add_lightning"
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("DELETE FROM site_routes WHERE path_pattern = '/one'")
        above = http.get("/v1/sites/shop", headers={"X-Api-Key": key})
        assert above.json().get("advice", {}).get("code") != "add_lightning"
        assert seen.json()["advice"]["actions"][0]["url"] == "/v1/client/payee"
        cent = http.post(
            "/v1/sites/shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/cent", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert cent.status_code == 200, cent.text
        http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "seller@pay.example"},
        )
        funded = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/item", "amount_sats": 21},
        )
        assert funded.status_code == 200, funded.text
        assert "add_lightning" not in funded.text
        assert "advice" not in funded.json()
        quiet = http.get("/v1/sites/shop", headers={"X-Api-Key": key})
        assert "advice" not in quiet.json() or quiet.json().get("advice", {}).get("code") != "add_lightning"
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 1000")
        low = http.get("/v1/balance", headers={"X-Api-Key": key})
        assert low.json()["advice"]["code"] == "balance_low"
        assert "estimate" in low.json()["advice"]["message"]
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 0")
        zero = http.get("/v1/balance", headers={"X-Api-Key": key})
        assert zero.json()["advice"]["code"] == "balance_zero"
        challenge = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/item", "amount_sats": 21},
        )
        # No prepaid balance and no free quota: the seller hears it, the buyer must not.
        assert challenge.status_code == 409
        assert challenge.json()["error"] == "insufficient_balance"
        buyer = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/item", "amount_sats": 21},
        )
        assert "add_lightning" not in buyer.text


def test_gate_buyer_sees_paywall_unavailable(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 0, credits = 0")
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:
                denied = http.get("/my-shop/blog/post")
                assert denied.status_code == 502, denied.text
                assert denied.json()["error"] == "paywall_unavailable"
                assert "insufficient_balance" not in denied.text
                assert "insufficient balance" not in denied.text.lower()
        finally:
            _close(core_client)
        seller = core.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/item", "amount_sats": 21},
        )
        assert seller.status_code == 409
        assert seller.json()["error"] == "insufficient_balance"


def test_usdc_fee_is_refused_on_the_challenge_when_the_rate_is_missing(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    _quote(module)
    module.accounting_rate.fetcher = lambda _url: None
    module.accounting_rate.reset_for_tests()
    module.rates._state = None
    with TestClient(module.app) as http:
        key = _buy(http)
        http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "seller@pay.example"},
        )
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 0")
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "usd-shop", "display_name": "USD", "origin_url": "https://origin.example"},
        )
        assert created.status_code == 200, created.text
        route = http.post(
            "/v1/sites/usd-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert route.status_code == 200, route.text
        approved = http.post("/v1/admin/sites/usd-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert approved.status_code == 200, approved.text
        refused = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "usd-shop", "path": "/paid"})
        assert refused.status_code == 503, refused.text
        assert refused.json()["error"] == "rate_unavailable"
        assert refused.status_code != 402
        lightning = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "still/lightning", "amount_sats": 21},
        )
        # The seller is out of funds, so this is the balance refusal, not a rate error.
        assert lightning.status_code == 409
        assert lightning.json()["error"] == "insufficient_balance"
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 10000000")
        still = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "still/lightning", "amount_sats": 21},
        )
        assert still.status_code == 200, still.text
        module.accounting_rate.fetcher = lambda _url: {"bitcoin": {"usd": 80070}}
        module.accounting_rate.reset_for_tests()
        _quote(module)
        priced = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "usd-shop", "path": "/paid"})
        assert priced.status_code == 200, priced.text


def test_admin_refund_credits_the_ledger_and_hides_the_token(tmp_path, monkeypatch, caplog):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    caplog.set_level(logging.INFO)
    with TestClient(module.app) as http:
        key = _buy(http)
        client_id = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["client_id"]
        missing = http.post("/v1/refund", json={"msat": 1000, "reason": "no"})
        assert missing.status_code == 404
        secret = "test-admin-token"
        refunded = http.post(
            f"/v1/admin/clients/{client_id}/refund",
            headers={"X-Admin-Token": secret},
            json={"msat": 5000, "reason": "goodwill", "ref": "case-1"},
        )
        assert refunded.status_code == 200, refunded.text
        assert refunded.json()["balance_msat"] >= 5000
        assert secret not in caplog.text
        huge = http.post(
            f"/v1/admin/clients/{client_id}/refund",
            headers={"X-Admin-Token": secret},
            json={"msat": module.config.ADMIN_REFUND_MAX_MSAT + 1, "reason": "too much"},
        )
        assert huge.status_code == 400
        assert huge.json()["error"] == "refund_too_large"
        http.post(
            f"/v1/admin/clients/{client_id}/suspend",
            headers={"X-Admin-Token": secret},
            json={"reason": "review"},
        )
        suspended = http.post(
            f"/v1/admin/clients/{client_id}/refund",
            headers={"X-Admin-Token": secret},
            json={"msat": 1, "reason": "no"},
        )
        assert suspended.status_code == 403
        assert suspended.json()["error"] == "account_suspended"
        with sqlite3.connect(module.config.DB_PATH) as conn:
            row = conn.execute(
                "SELECT reason FROM ledger WHERE reason = 'refund_manual'"
            ).fetchone()
        assert row is not None


def test_automatic_refund_is_idempotent(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        client_id = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["client_id"]
        before = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["balance_msat"]
        from app.refunds import repair_anomalies

        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = balance_msat - 4000 WHERE id = ?", (client_id,))
            conn.execute(
                """
                INSERT INTO ledger(client_id, delta_credits, delta_msat, reason, ref, created_at)
                VALUES(?, -1, -2000, 'paywall_verify', 'pay-1', 1)
                """,
                (client_id,),
            )
            conn.execute(
                """
                INSERT INTO ledger(client_id, delta_credits, delta_msat, reason, ref, created_at)
                VALUES(?, -1, -2000, 'paywall_verify', 'pay-1', 2)
                """,
                (client_id,),
            )
            conn.execute(
                "INSERT INTO verifications(payment_hash, client_id, resource, created_at) VALUES('pay-1', ?, 'r', 1)",
                (client_id,),
            )
            conn.commit()
            conn.row_factory = sqlite3.Row
            assert repair_anomalies(conn, now=10) == 1
            assert repair_anomalies(conn, now=11) == 0
            conn.commit()
        after = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["balance_msat"]
        assert after == before - 2000
        wrong = http.post(
            f"/v1/admin/clients/{client_id}/refund",
            headers={"X-Admin-Token": "not-the-token"},
            json={"msat": 1, "reason": "no"},
        )
        assert wrong.status_code == 401
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = balance_msat - 1500 WHERE id = ?", (client_id,))
            conn.execute(
                """
                INSERT INTO ledger(client_id, delta_credits, delta_msat, reason, ref, created_at)
                VALUES(?, 0, -1500, 'paywall_verify', 'orphan-1', 3)
                """,
                (client_id,),
            )
            conn.commit()
            conn.row_factory = sqlite3.Row
            from app.refunds import repair_anomalies

            assert repair_anomalies(conn, now=12) == 1
            conn.commit()
        restored = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["balance_msat"]
        assert restored == after


def test_signup_day_boundary_and_concurrent_cap(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    monkeypatch.setattr(module.config, "SIGNUP_MAX_PER_IP_PER_DAY", 3)
    monkeypatch.setattr(module.config, "SIGNUP_MAX_GLOBAL_PER_DAY", 100)
    late = 1_762_991_999  # 2026-11-12 23:59:59 UTC
    nxt = late + 1
    import app.signup as signup_mod

    monkeypatch.setattr(signup_mod, "current_time", lambda: late)
    with TestClient(module.app) as http:
        for _ in range(3):
            assert http.post("/v1/accounts", json={}).status_code == 201
        blocked = http.post("/v1/accounts", json={})
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "signup_ip_limit"
        monkeypatch.setattr(signup_mod, "current_time", lambda: nxt)
        opened = http.post("/v1/accounts", json={})
        assert opened.status_code == 201, opened.text
    import threading

    from app.signup import SignupLimited, create_account

    monkeypatch.setattr(module.config, "SIGNUP_MAX_PER_IP_PER_DAY", 3)
    results: list[str] = []

    def once() -> None:
        try:
            create_account(module.config.DB_PATH, ip="203.0.113.77", now=nxt + 10)
            results.append("ok")
        except SignupLimited:
            results.append("limited")

    threads = [threading.Thread(target=once) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert results.count("ok") == 3
    assert results.count("limited") == 2


def test_low_balance_webhook_fires_once(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        client_id = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["client_id"]
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO client_webhooks(
                  client_id, url, secret_enc, secret_prefix, enabled, generation, created_at, updated_at
                ) VALUES(?, 'https://hooks.example/s', 'enc', 'whsec_test', 1, 1, 1, 1)
                """,
                (client_id,),
            )
            conn.execute("UPDATE clients SET balance_msat = 250000 WHERE id = ?", (client_id,))
            conn.commit()
        from app.ledger import apply

        apply(
            module.config.DB_PATH,
            client_id=client_id,
            delta_msat=-50_000,
            reason="paywall_verify",
            ref="edge-1",
            now=20,
        )
        apply(
            module.config.DB_PATH,
            client_id=client_id,
            delta_msat=-1_000,
            reason="paywall_verify",
            ref="edge-2",
            now=21,
        )
        with sqlite3.connect(module.config.DB_PATH) as conn:
            kinds = [row[0] for row in conn.execute("SELECT kind FROM webhook_outbox ORDER BY id")]
            emails = conn.execute("SELECT COUNT(*) FROM email_outbox").fetchone()[0]
            body = conn.execute("SELECT body_json FROM webhook_outbox").fetchone()[0]
        assert kinds == ["balance.low"]
        assert emails == 0
        for secret in ("sg_", "sgr_", "whsec_"):
            assert secret not in body
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE clients SET alert_email = ?, balance_msat = 250000, low_rearm = 1 WHERE id = ?",
                ("seller@example.com", client_id),
            )
            conn.commit()
        apply(
            module.config.DB_PATH,
            client_id=client_id,
            delta_msat=-50_000,
            reason="paywall_verify",
            ref="edge-3",
            now=22,
        )
        apply(
            module.config.DB_PATH,
            client_id=client_id,
            delta_msat=-1_000,
            reason="paywall_verify",
            ref="edge-4",
            now=23,
        )
        with sqlite3.connect(module.config.DB_PATH) as conn:
            lows = conn.execute(
                "SELECT COUNT(*) FROM webhook_outbox WHERE kind = 'balance.low'"
            ).fetchone()[0]
            mailed = conn.execute(
                "SELECT COUNT(*) FROM email_outbox WHERE kind = 'balance.low'"
            ).fetchone()[0]
        assert lows == 2
        assert mailed == 0
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                """
                UPDATE clients
                SET alert_email_confirmed_at = 1, balance_msat = 250000, low_rearm = 1
                WHERE id = ?
                """,
                (client_id,),
            )
            conn.commit()
        apply(
            module.config.DB_PATH,
            client_id=client_id,
            delta_msat=-50_000,
            reason="paywall_verify",
            ref="edge-5",
            now=24,
        )
        with sqlite3.connect(module.config.DB_PATH) as conn:
            mailed = conn.execute(
                "SELECT COUNT(*) FROM email_outbox WHERE kind = 'balance.low'"
            ).fetchone()[0]
        assert mailed == 1


def test_remainder_below_the_fee_is_refused_and_free_quota_still_issues(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 500")
        short = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/short", "amount_sats": 21},
        )
        assert short.status_code == 409
        assert short.json()["error"] == "insufficient_balance"
        assert short.json()["advice"]["code"] == "balance_low"
        still = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["balance_msat"]
        assert still == 500
        monkeypatch.setattr(module.config, "FREE_QUOTA", 2)
        issued = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/free", "amount_sats": 21},
        )
        assert issued.status_code == 200, issued.text
        assert "invoice" in issued.json()


def test_test_mode_issues_with_no_balance_and_no_quota(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "seller@pay.example"},
        )
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "trial-shop", "display_name": "Trial", "origin_url": "https://origin.example"},
        )
        assert created.status_code == 200, created.text
        route = http.post(
            "/v1/sites/trial-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/post", "price_sats": 21},
        )
        assert route.status_code == 200, route.text
        approved = http.post(
            "/v1/admin/sites/trial-shop/approve",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert approved.status_code == 200, approved.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 0")
            conn.execute("UPDATE sites SET x402_mode = 'test' WHERE slug = 'trial-shop'")
        before = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["balance_msat"]
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "trial-shop", "path": "/post"})
        assert issued.status_code == 200, issued.text
        assert issued.json().get("invoice") or issued.json().get("macaroon")
        after = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["balance_msat"]
        assert after == before == 0
        with sqlite3.connect(module.config.DB_PATH) as conn:
            held = conn.execute("SELECT COUNT(*) FROM quota_reservations").fetchone()[0]
            used = conn.execute("SELECT COALESCE(SUM(used_unlocks), 0) FROM quota_buckets").fetchone()[0]
        assert held == 0
        assert used == 0
