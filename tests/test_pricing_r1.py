"""Review R1 contracts. Each test fails if its guard is removed."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from test_x402 import _auth, _buy, _gate, _load_app, _patch_dns


def _caps(monkeypatch, module, ip: int = 3, global_n: int = 100) -> None:
    monkeypatch.setattr(module.config, "SIGNUP_MAX_PER_IP_PER_DAY", ip)
    monkeypatch.setattr(module.config, "SIGNUP_MAX_GLOBAL_PER_DAY", global_n)


def _pay(http: TestClient, body: dict) -> dict:
    preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = http.post(
        "/v1/topup/lightning",
        json={"sats": body["sats"]},
        headers={"Authorization": _auth(body["macaroon"], preimage)},
    )
    assert settled.status_code == 200, settled.text
    return settled.json()


def test_t_5_4_9_fourth_unauthenticated_invoice_is_refused_before_mint(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    _caps(monkeypatch, module)
    with TestClient(module.app) as http:
        issued = []
        for _ in range(4):
            response = http.post("/v1/topup/lightning", json={"sats": 1000})
            issued.append(response)
        assert [item.status_code for item in issued] == [402, 402, 402, 429]
        refused = issued[3].json()
        assert refused["error"] == "signup_ip_limit"
        assert "invoice" not in refused
        assert "payment_hash" not in refused
        paid = [_pay(http, item.json()) for item in issued[:3]]
        assert len({item["api_key"] for item in paid}) == 3
        assert all(item["msat_added"] == 1_000_000 for item in paid)
        assert "credits_added" not in paid[0]
        with sqlite3.connect(module.config.DB_PATH) as conn:
            accounts = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
            unsettled = conn.execute(
                "SELECT COUNT(*) FROM topups WHERE status != 'settled'"
            ).fetchone()[0]
            total = conn.execute("SELECT COALESCE(SUM(balance_msat), 0) FROM clients").fetchone()[0]
            ledger = conn.execute("SELECT COALESCE(SUM(delta_msat), 0) FROM ledger").fetchone()[0]
        assert accounts == 3
        assert unsettled == 0
        assert total == ledger == 3_000_000
        key = paid[0]["api_key"]
        again = http.post("/v1/topup/lightning", json={"sats": 1000}, headers={"X-Api-Key": key})
        assert again.status_code == 402, again.text
        assert again.json()["invoice"]


def test_t_5_4_9_parallel_mints_stop_at_three_invoices(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    _caps(monkeypatch, module)
    with TestClient(module.app) as http:
        results: list = []

        def once() -> None:
            results.append(http.post("/v1/topup/lightning", json={"sats": 1000}))

        threads = [threading.Thread(target=once) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        invoices = [item for item in results if item.status_code == 402 and item.json().get("invoice")]
        refused = [item for item in results if item.status_code == 429]
        assert len(invoices) == 3
        assert len(refused) == 2
        assert all(item.json()["error"] == "signup_ip_limit" for item in refused)
        assert all("invoice" not in item.json() for item in refused)


def test_forwarded_for_does_not_mint_extra_accounts_without_a_trusted_proxy(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="")
    _patch_dns(monkeypatch, module)
    _caps(monkeypatch, module)
    with TestClient(module.app) as http:
        for index in range(3):
            ok = http.post(
                "/v1/accounts",
                json={},
                headers={"X-Forwarded-For": f"203.0.113.{index}"},
            )
            assert ok.status_code == 201, ok.text
        blocked = http.post(
            "/v1/accounts",
            json={},
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "signup_ip_limit"


def test_t_5_8_edges_and_zero(tmp_path, monkeypatch):
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
                ) VALUES(?, 'https://hooks.example/s', 'enc', 'whsec_hidden', 1, 1, 1, 1)
                """,
                (client_id,),
            )
            conn.execute(
                "UPDATE clients SET balance_msat = 200001, alert_email = ? WHERE id = ?",
                ("pending@example.com", client_id),
            )
            conn.commit()
        from app.ledger import apply

        apply(module.config.DB_PATH, client_id=client_id, delta_msat=-1, reason="paywall_verify", ref="e-none", now=1)
        apply(module.config.DB_PATH, client_id=client_id, delta_msat=-1, reason="paywall_verify", ref="e-low", now=2)
        apply(module.config.DB_PATH, client_id=client_id, delta_msat=-1, reason="paywall_verify", ref="e-second", now=3)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            lows = conn.execute("SELECT COUNT(*) FROM webhook_outbox WHERE kind = 'balance.low'").fetchone()[0]
            emails = conn.execute("SELECT COUNT(*) FROM email_outbox").fetchone()[0]
        assert lows == 1
        assert emails == 0
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE clients SET balance_msat = 1500, zero_rearm = 1, low_rearm = 1 WHERE id = ?",
                (client_id,),
            )
            conn.commit()
        apply(module.config.DB_PATH, client_id=client_id, delta_msat=-1500, reason="paywall_verify", ref="z1", now=4)
        try:
            apply(module.config.DB_PATH, client_id=client_id, delta_msat=-1, reason="paywall_verify", ref="z2", now=5)
        except ValueError:
            pass
        apply(module.config.DB_PATH, client_id=client_id, delta_msat=5000, reason="topup_settled", ref="z3", now=6)
        apply(module.config.DB_PATH, client_id=client_id, delta_msat=-5000, reason="paywall_verify", ref="z4", now=7)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            zeros = conn.execute(
                "SELECT body_json FROM webhook_outbox WHERE kind = 'balance.zero' ORDER BY id"
            ).fetchall()
        assert len(zeros) == 2
        for (body,) in zeros:
            for secret in ("sg_", "sgr_", "whsec_"):
                assert secret not in body


def test_t_5_8_4_forecast_uses_msat_on_both_sides(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        client_id = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["client_id"]
        now = int(datetime.now(timezone.utc).timestamp())
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 20000 WHERE id = ?", (client_id,))
            for index in range(10):
                conn.execute(
                    """
                    INSERT INTO ledger(client_id, delta_credits, delta_msat, reason, ref, created_at)
                    VALUES(?, -1, -2000, 'paywall_verify', ?, ?)
                    """,
                    (client_id, f"h{index}", now - 60),
                )
            conn.commit()
        view = http.get("/v1/usage/forecast", headers={"X-Api-Key": key})
        assert view.status_code == 200, view.text
        forecast = view.json()["forecast"]
        assert 20 <= forecast["estimated_hours_remaining"] <= 28
        assert forecast["current_balance_msat"] == 20000
        assert forecast["verify_msat_out"] == 20000
        assert "current_balance_credits" not in forecast
        assert "credits" not in view.text
        for pack in ("trial", "starter", "growth", "scale", "hyper", "mega"):
            assert pack not in view.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 150000 WHERE id = ?", (client_id,))
        low = http.get("/v1/balance", headers={"X-Api-Key": key})
        advice = low.json()["advice"]
        assert advice["code"] == "balance_low"
        assert "75" in advice["message"]
        assert "estimate" in advice["message"]
        assert advice["forecast"]["status"] != "insufficient_data"
        assert advice["estimated_unlocks_remaining"] == 75


def test_t_5_3_5_reservations_do_not_stick(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    monkeypatch.setattr(module.config, "FREE_QUOTA", 1)
    with TestClient(module.app) as http:
        key = _buy(http)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 0")

        def challenge(resource: str):
            return http.post(
                "/v1/paywall/challenge",
                headers={"X-Api-Key": key},
                json={"resource": resource, "amount_sats": 21},
            )

        first = challenge("hold/open")
        assert first.status_code == 200, first.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE paywall_challenges SET expires_at = 1 WHERE payment_hash = ?",
                (first.json()["payment_hash"],),
            )
        nxt = challenge("hold/after-expiry")
        assert nxt.status_code == 200, nxt.text
        preimage = http.get(f"/dev/mock/pay/{nxt.json()['payment_hash']}").json()["preimage"]
        confirmed = http.get(
            f"/v1/paywall/status/{nxt.json()['payment_hash']}",
            headers={"X-Api-Key": key, "Authorization": _auth(nxt.json()["macaroon"], preimage)},
            params={"expected_resource": "hold/after-expiry", "charge": "false"},
        )
        assert confirmed.status_code == 200, confirmed.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            held = conn.execute("SELECT COUNT(*) FROM quota_reservations").fetchone()[0]
            used = conn.execute("SELECT COALESCE(SUM(used_unlocks), 0) FROM quota_buckets").fetchone()[0]
        assert held == 0
        assert used == 0
        monkeypatch.setattr(module.config, "FREE_QUOTA", 2)
        paid = challenge("hold/replay")
        assert paid.status_code == 200, paid.text
        preimage = http.get(f"/dev/mock/pay/{paid.json()['payment_hash']}").json()["preimage"]
        auth = _auth(paid.json()["macaroon"], preimage)
        once = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": key, "Authorization": auth},
            json={"expected_resource": "hold/replay"},
        )
        twice = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": key, "Authorization": auth},
            json={"expected_resource": "hold/replay"},
        )
        assert once.status_code == 200 and twice.status_code == 200
        assert twice.json()["charged_credits"] == 0
        with sqlite3.connect(module.config.DB_PATH) as conn:
            used = conn.execute("SELECT COALESCE(SUM(used_unlocks), 0) FROM quota_buckets").fetchone()[0]
            held = conn.execute("SELECT COUNT(*) FROM quota_reservations").fetchone()[0]
        assert used == 1
        assert held == 0
        mode = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "missing", "path": "/"})
        assert mode.status_code in {404, 400}


def test_t_5_10a_estimate_and_buyer_body(tmp_path, monkeypatch):
    from app.pricing import estimate_unlocks

    assert estimate_unlocks(0, 0)["estimated_unlocks_remaining"] == 0
    assert estimate_unlocks(-5, -2)["estimated_unlocks_remaining"] == 0
    assert estimate_unlocks(1_152_000, 500)["estimated_unlocks_remaining"] == 1_076
    assert estimate_unlocks(4_000, 0, fee_msat=4_000)["paid_unlocks_estimate"] == 1
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    monkeypatch.setattr(module.config, "FREE_QUOTA", 500)
    with TestClient(module.app) as http:
        created = http.post("/v1/accounts", json={})
        key = created.json()["api_key"]
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET balance_msat = 1152000")
        body = http.get("/v1/balance", headers={"X-Api-Key": key}).json()
        assert body["estimated_unlocks_remaining"] == 1_076
        minted = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": key},
            json={"label": "read", "scope": "paywall"},
        )
        restricted = minted.json()["api_key"]
        same = http.get("/v1/balance", headers={"X-Api-Key": restricted}).json()
        assert same["estimated_unlocks_remaining"] == 1_076
        assert same["paid_unlocks_estimate"] == 576
        denied = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": restricted})
        assert denied.status_code == 403
        refund = http.post(
            "/v1/admin/clients/1/refund",
            headers={"X-Api-Key": restricted},
            json={"msat": 1, "reason": "no"},
        )
        assert refund.status_code in {401, 404}
        challenge = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/item", "amount_sats": 21},
        )
        assert challenge.status_code == 200, challenge.text
        assert "estimated_unlocks_remaining" not in challenge.text
        zero = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/zero", "amount_sats": 0},
        )
        assert zero.status_code == 422
    late = int(datetime(2026, 10, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    early = late + 1
    from app.quota import period_utc

    assert period_utc(late) == "2026-10"
    assert period_utc(early) == "2026-11"


def test_t_5_8_9_and_10_receipt_and_reactivation(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        challenge = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/keep", "amount_sats": 21},
        )
        assert challenge.status_code == 200, challenge.text
        body = challenge.json()
        preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
        auth = _auth(body["macaroon"], preimage)
        first = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": key, "Authorization": auth},
            json={"expected_resource": "shop/keep"},
        )
        assert first.status_code == 200, first.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            used_before = conn.execute("SELECT COALESCE(SUM(used_unlocks), 0) FROM quota_buckets").fetchone()[0]
            conn.execute("UPDATE clients SET balance_msat = 0")
        again = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": key, "Authorization": auth},
            json={"expected_resource": "shop/keep"},
        )
        assert again.status_code == 200, again.text
        assert again.json()["charged_credits"] == 0
        with sqlite3.connect(module.config.DB_PATH) as conn:
            used_after = conn.execute("SELECT COALESCE(SUM(used_unlocks), 0) FROM quota_buckets").fetchone()[0]
        assert used_after == used_before
        blocked = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/new", "amount_sats": 21},
        )
        assert blocked.status_code == 409
        topped = http.post("/v1/topup/lightning", json={"sats": 1000}, headers={"X-Api-Key": key})
        assert topped.status_code == 402, topped.text
        _pay(http, topped.json())
        opened = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "shop/new", "amount_sats": 21},
        )
        assert opened.status_code == 200, opened.text


def test_boot_has_no_new_mandatory_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("SATSGATE_TERMS_VERSION", raising=False)
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="0")
    assert not module.config.TERMS_VERSION
    with TestClient(module.app) as http:
        health = http.get("/health")
        assert health.status_code == 200
        assert health.json()["ok"] is True


def test_t_5_2_11_locked_fee_ignores_a_later_accounting_rate(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    module.accounting_rate.fetcher = lambda _url: {"bitcoin": {"usd": 80070}}
    module.accounting_rate.reset_for_tests()
    with TestClient(module.app) as http:
        key = _buy(http)
        client_id = http.get("/v1/client", headers={"X-Api-Key": key}).json()["client_id"]
    plan = {
        "price_currency": "usd",
        "main_sats": None,
        "main_usd": 10_000,
        "lightning_sats": None,
        "x402_atomic": 10_000,
        "x402_network": "eip155:84532",
        "rate": None,
    }
    import app.x402_service as x402_service

    offer = x402_service.issue_offer(
        client_id=client_id,
        slug="shop",
        path="/paid",
        resource="gate:shop:/paid",
        pay_to="0x1111111111111111111111111111111111111111",
        plan=plan,
        max_uses=None,
        access_seconds=None,
        buyer_ip_hash=None,
    )
    with sqlite3.connect(module.config.DB_PATH) as conn:
        locked = conn.execute(
            "SELECT satsgate_fee_msat FROM payment_offers WHERE id = ?",
            (offer["offer_id"],),
        ).fetchone()[0]
    assert locked and locked > 0
    module.accounting_rate.fetcher = lambda _url: {"bitcoin": {"usd": 96084}}
    module.accounting_rate.reset_for_tests()
    from app.charging import fee_from_offer

    with sqlite3.connect(module.config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM payment_offers WHERE id = ?", (offer["offer_id"],)).fetchone()
        fee, _test = fee_from_offer(row)
    assert fee == locked
