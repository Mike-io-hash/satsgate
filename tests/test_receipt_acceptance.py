"""Offline acceptance checks for the charge-only receipt gate.

Self-hosted /v1/paywall/* behaviour is not changed here.
"""

from __future__ import annotations

import base64
import importlib
import importlib.util
import json
import os
import sqlite3
import textwrap
import threading
import time
from pathlib import Path

import httpx
import pytest
from eth_account import Account
from fastapi.testclient import TestClient
from starlette.testclient import TestClient as StarletteClient

from satsgate_gate.app import create_app
from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from satsgate_sdk.receipts import (
    MemoryReceiptStore,
    ReceiptError,
    SatsgateReceiptMiddleware,
    SqliteReceiptStore,
    origin_check_response,
    verify_receipt,
)
from test_satsgate_gate import _settings
from test_x402 import _buy, _credits, _gate, _load_app, _patch_dns, _payload, _site, _verify_payee
from test_x402_cdp import _cdp_env, _material

ROOT = Path(__file__).resolve().parents[1]


def _mod(name: str):
    return importlib.import_module(name)


def _rows(db_path: str) -> int:
    with sqlite3.connect(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM gate_receipts").fetchone()[0])


def _client_id(http: TestClient, key: str) -> int:
    body = http.get("/v1/client", headers={"X-Api-Key": key})
    assert body.status_code == 200, body.text
    return int(body.json()["client_id"])


def _issue_lightning(http: TestClient, *, path: str = "/blog/post", max_uses: int | None = 1, access_seconds: int | None = None):
    key = _buy(http)
    http.post(
        "/v1/client/payee",
        headers={"X-Api-Key": key},
        json={"payee_lightning_address": "merchant@pay.example"},
    )
    created = http.post(
        "/v1/sites",
        headers={"X-Api-Key": key},
        json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example", "listed": False},
    )
    assert created.status_code == 200, created.text
    route_body = {"path": path, "price_sats": 21, "max_uses": max_uses, "access_seconds": access_seconds}
    route = http.post("/v1/sites/my-shop/routes", headers={"X-Api-Key": key}, json=route_body)
    assert route.status_code == 200, route.text
    approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
    assert approved.status_code == 200, approved.text
    challenge = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": path})
    assert challenge.status_code == 200, challenge.text
    offered = challenge.json()
    preimage = http.get(f"/dev/mock/pay/{offered['payment_hash']}").json()["preimage"]
    return key, created.json()["origin_secret"], offered, preimage


def test_concurrent_issuance_writes_one_row_and_one_debit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, _secret, offered, preimage = _issue_lightning(http)
        before = _credits(http, key)
        owner = module.db.get_client_by_api_key(module.config.DB_PATH, key)
        site = module.db_sites.get_site_for_client(module.config.DB_PATH, client_id=owner.id, slug="my-shop")
        route = site["routes"][0]
        barrier = threading.Barrier(2)
        results: list[object] = []
        errors: list[BaseException] = []

        def once() -> None:
            try:
                barrier.wait(timeout=5)
                results.append(
                    module._unlock_paywall(
                        authorization=f"L402 {offered['macaroon']}:{preimage}",
                        expected_resource="gate:my-shop:/blog/post",
                        cost_credits=1,
                        client=owner,
                        poll=False,
                        consume=False,
                        mode="receipt",
                        receipt_site=site,
                        receipt_route=route,
                    )
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert errors == []
        assert len(results) == 2
        tokens = [item["receipt"] for item in results]
        assert tokens[0] == tokens[1]
        assert _rows(module.config.DB_PATH) == 1
        assert _credits(http, key) == before - 1


def test_replay_after_expiry_is_token_expired(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, _secret, offered, preimage = _issue_lightning(http, access_seconds=60)
        before = _credits(http, key)
        paid = _gate(
            http,
            "POST",
            "/internal/gate/receipt",
            json={
                "slug": "my-shop",
                "path": "/blog/post",
                "authorization": f"L402 {offered['macaroon']}:{preimage}",
            },
        )
        assert paid.status_code == 200, paid.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE gate_receipts SET exp = 1")
        expired = _gate(
            http,
            "POST",
            "/internal/gate/receipt",
            json={
                "slug": "my-shop",
                "path": "/blog/post",
                "authorization": f"L402 {offered['macaroon']}:{preimage}",
            },
        )
        assert expired.status_code == 401, expired.text
        assert expired.json()["error"] == "token_expired"
        assert _credits(http, key) == before - 1
        assert _rows(module.config.DB_PATH) == 1


def test_rotation_re_signs_the_same_claims(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, old_secret, offered, preimage = _issue_lightning(http, max_uses=3, access_seconds=120)
        paid = _gate(
            http,
            "POST",
            "/internal/gate/receipt",
            json={
                "slug": "my-shop",
                "path": "/blog/post",
                "authorization": f"L402 {offered['macaroon']}:{preimage}",
            },
        )
        assert paid.status_code == 200, paid.text
        first = verify_receipt(paid.json()["receipt"], secret=old_secret, site="my-shop", path="/blog/post")
        assert first.uses == 3
        assert first.exp - first.iat == 120
        assert first.header["kid"] == _mod("app.receipts").kid_for(old_secret)
        assert first.claims["aud"] == "my-shop"
        assert first.claims["uses"] == 3
        rotated = http.post("/v1/sites/my-shop/rotate-secret", headers={"X-Api-Key": key})
        assert rotated.status_code == 200, rotated.text
        new_secret = rotated.json()["origin_secret"]
        assert rotated.json()["site"]["origin_verified_at"] is None
        again = _gate(
            http,
            "POST",
            "/internal/gate/receipt",
            json={
                "slug": "my-shop",
                "path": "/blog/post",
                "authorization": f"L402 {offered['macaroon']}:{preimage}",
            },
        )
        assert again.status_code == 200, again.text
        second = verify_receipt(again.json()["receipt"], secret=new_secret, site="my-shop", path="/blog/post")
        assert second.jti == first.jti
        assert second.claims["ph"] == first.claims["ph"]
        assert second.header["kid"] == _mod("app.receipts").kid_for(new_secret)
        with pytest.raises(ReceiptError) as bad:
            verify_receipt(again.json()["receipt"], secret=old_secret, site="my-shop", path="/blog/post")
        assert bad.value.code == "receipt_invalid"


def test_receipt_lifetime_clamps():
    from app.receipts import receipt_lifetime

    assert receipt_lifetime(None, default_seconds=86400, cap_seconds=604800) == 86400
    assert receipt_lifetime(30, default_seconds=86400, cap_seconds=604800) == 60
    assert receipt_lifetime(90_000, default_seconds=86400, cap_seconds=604800) == 86400
    assert receipt_lifetime(500, default_seconds=86400, cap_seconds=120) == 120
    assert receipt_lifetime(None, default_seconds=86400, cap_seconds=120) == 120


def test_live_x402_receipt_debits_once_and_settles_once(tmp_path, monkeypatch):
    key_id, secret, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    calls: list[str] = []

    def _post(url, body, headers):
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ab" * 32, "payer": buyer.address}

    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 10_000})
        live = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert live.status_code == 200, live.text
        importlib = __import__("importlib")
        importlib.import_module("app.x402_facilitator").poster = _post
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert issued.status_code == 200, issued.text
        encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
        before = _credits(http, key)
        paid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert paid.status_code == 200, paid.text
        assert paid.json()["receipt"]
        assert _credits(http, key) == before - 1
        assert sum(1 for url in calls if url.endswith("/settle")) == 1
        replay = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["receipt"] == paid.json()["receipt"]
        assert sum(1 for url in calls if url.endswith("/settle")) == 1
        assert _credits(http, key) == before - 1


def _ledger_count(db_path: str, client_id: int) -> int:
    with sqlite3.connect(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM ledger WHERE client_id = ?", (client_id,)).fetchone()[0])


def _settle_count(calls: list[str]) -> int:
    return sum(1 for url in calls if url.endswith("/settle"))


def _verify_count(calls: list[str]) -> int:
    return sum(1 for url in calls if url.endswith("/verify"))


def test_x402_receipt_survives_an_expired_offer(tmp_path, monkeypatch):
    """R-6: the same signature returns the stored receipt after the offer window."""
    key_id, secret_key, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret_key))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    calls: list[str] = []

    def _post(url, body, headers):
        del body, headers
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ab" * 32, "payer": buyer.address}

    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "my-shop",
                "display_name": "My Shop",
                "origin_url": "https://origin.example",
                "listed": True,
            },
        )
        assert created.status_code == 200, created.text
        origin_secret = created.json()["origin_secret"]
        route = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert route.status_code == 200, route.text
        approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert approved.status_code == 200, approved.text
        live = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert live.status_code == 200, live.text
        importlib.import_module("app.x402_facilitator").poster = _post
        client_id = _client_id(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert issued.status_code == 200, issued.text
        encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
        before = _credits(http, key)
        paid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert paid.status_code == 200, paid.text
        paid_body = paid.json()
        first = verify_receipt(paid_body["receipt"], secret=origin_secret, site="my-shop", path="/paid")
        credits_after = _credits(http, key)
        assert credits_after == before - 1
        settles = _settle_count(calls)
        verifies = _verify_count(calls)
        ledger = _ledger_count(module.config.DB_PATH, client_id)
        receipts = _rows(module.config.DB_PATH)
        assert settles == 1
        assert verifies == 1
        assert receipts == 1

        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1")
        replay = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert replay.status_code == 200
        assert replay.json()["payment_hash"] == paid_body["payment_hash"]
        assert _digest(replay.json()["receipt"]) == _digest(paid_body["receipt"])
        assert _settlement_view(paid) == _settlement_view(replay)
        assert _settlement_view(replay)["transaction"] == _settlement_view(replay)["tx"]
        again = verify_receipt(replay.json()["receipt"], secret=origin_secret, site="my-shop", path="/paid")
        assert again.claims == first.claims
        assert _settle_count(calls) == settles
        assert _verify_count(calls) == verifies
        assert _credits(http, key) == credits_after
        assert _ledger_count(module.config.DB_PATH, client_id) == ledger
        assert _rows(module.config.DB_PATH) == receipts

        window = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/window", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert window.status_code == 200, window.text
        short = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/window"})
        assert short.status_code == 200, short.text
        offer_exp = int(short.json()["expires_at"])
        valid_before = offer_exp - 25
        short_sig = _payload(
            short.headers["payment-required"],
            buyer,
            offer_exp,
            authorization={"validBefore": str(valid_before), "nonce": "0x" + "cd" * 32},
        )
        window_paid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/window", "payment_signature": short_sig},
        )
        assert window_paid.status_code == 200, window_paid.text
        credits_window = _credits(http, key)
        settles = _settle_count(calls)
        verifies = _verify_count(calls)
        ledger = _ledger_count(module.config.DB_PATH, client_id)
        receipts = _rows(module.config.DB_PATH)
        x402_mod = importlib.import_module("app.x402")
        monkeypatch.setattr(x402_mod.time, "time", lambda: float(offer_exp - 5))
        window_replay = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/window", "payment_signature": short_sig},
        )
        monkeypatch.setattr(x402_mod.time, "time", time.time)
        assert window_replay.status_code == 200
        assert window_replay.json()["payment_hash"] == window_paid.json()["payment_hash"]
        assert _digest(window_replay.json()["receipt"]) == _digest(window_paid.json()["receipt"])
        assert _settlement_view(window_paid) == _settlement_view(window_replay)
        left = verify_receipt(window_paid.json()["receipt"], secret=origin_secret, site="my-shop", path="/window")
        right = verify_receipt(window_replay.json()["receipt"], secret=origin_secret, site="my-shop", path="/window")
        assert right.claims == left.claims
        assert _settle_count(calls) == settles
        assert _verify_count(calls) == verifies
        assert _credits(http, key) == credits_window
        assert _ledger_count(module.config.DB_PATH, client_id) == ledger
        assert _rows(module.config.DB_PATH) == receipts

        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE gate_receipts SET exp = 1 WHERE payment_hash = ?",
                (f"x402:{paid_body['payment_hash']}",),
            )
        stale = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert stale.status_code == 401
        assert stale.json()["error"] == "token_expired"
        assert "payment-response" not in stale.headers
        assert "payment_response" not in stale.json()
        assert "receipt" not in stale.json()
        assert _credits(http, key) == credits_window
        assert _settle_count(calls) == settles
        assert _ledger_count(module.config.DB_PATH, client_id) == ledger

        fresh_nonce = _payload(
            issued.headers["payment-required"],
            buyer,
            1,
            authorization={"nonce": "0x" + "ef" * 32, "validBefore": "1"},
        )
        unpaid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": fresh_nonce},
        )
        assert unpaid.status_code == 402, unpaid.text
        assert unpaid.json()["error"] == "expired"
        assert "receipt" not in unpaid.json()
        assert _rows(module.config.DB_PATH) == receipts
        assert _settle_count(calls) == settles
        assert _credits(http, key) == credits_window
        assert _ledger_count(module.config.DB_PATH, client_id) == ledger

        other_route = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/other", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert other_route.status_code == 200, other_route.text
        other_offer = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/other"})
        assert other_offer.status_code == 200, other_offer.text
        other_site = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "other-shop",
                "display_name": "Other Shop",
                "origin_url": "https://other.example",
                "listed": False,
            },
        )
        assert other_site.status_code == 200, other_site.text
        other_path = http.post(
            "/v1/sites/other-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert other_path.status_code == 200, other_path.text
        other_ok = http.post("/v1/admin/sites/other-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert other_ok.status_code == 200, other_ok.text
        other_live = http.patch(
            "/v1/sites/other-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert other_live.status_code == 200, other_live.text
        other_issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "other-shop", "path": "/paid"})
        assert other_issued.status_code == 200, other_issued.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1")
        wrong_path = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/other", "payment_signature": encoded},
        )
        assert wrong_path.status_code == 402, wrong_path.text
        assert wrong_path.json()["error"] == "expired"
        assert "receipt" not in wrong_path.json()
        wrong_site = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "other-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert wrong_site.status_code == 402, wrong_site.text
        assert wrong_site.json()["error"] == "expired"
        assert "receipt" not in wrong_site.json()
        assert _settle_count(calls) == settles
        assert _verify_count(calls) == verifies
        assert _credits(http, key) == credits_window
        assert _ledger_count(module.config.DB_PATH, client_id) == ledger
        assert _rows(module.config.DB_PATH) == receipts


def _rewrite_signature(encoded: str, mutate) -> str:
    payload = json.loads(base64.standard_b64decode(encoded))
    mutate(payload)
    return base64.standard_b64encode(json.dumps(payload).encode()).decode()


def _assert_expired(response) -> None:
    assert response.status_code == 402
    body = response.json()
    assert body.get("error") == "expired"
    assert "receipt" not in body
    assert "payment_response" not in body
    assert "payment-response" not in response.headers


def _settlement_view(response) -> dict:
    """Fields of PAYMENT-RESPONSE. The receipt token is not included."""
    header = response.headers.get("payment-response", "")
    body = response.json()
    encoded = header or body.get("payment_response") or ""
    data = json.loads(base64.standard_b64decode(encoded))
    return {
        "success": data.get("success") is True,
        "transaction": data.get("transaction"),
        "tx": data.get("tx"),
        "network": data.get("network"),
        "payer": data.get("payer"),
        "header": bool(header),
        "body_matches_header": body.get("payment_response") == header,
    }


def _digest(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_expired_offer_recovery_rejects_a_forged_nonce(tmp_path, monkeypatch):
    """A public nonce is not a PAYMENT-SIGNATURE. Only the settled header bytes recover."""
    key_id, secret_key, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret_key))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    stranger = Account.create()
    calls: list[str] = []

    def _post(url, body, headers):
        del body, headers
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ab" * 32, "payer": buyer.address}

    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "my-shop",
                "display_name": "My Shop",
                "origin_url": "https://origin.example",
                "listed": True,
            },
        )
        assert created.status_code == 200, created.text
        route = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert route.status_code == 200, route.text
        approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert approved.status_code == 200, approved.text
        live = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert live.status_code == 200, live.text
        importlib.import_module("app.x402_facilitator").poster = _post
        client_id = _client_id(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert issued.status_code == 200, issued.text
        encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
        paid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert paid.status_code == 200, paid.text
        paid_body = paid.json()
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1")
            stored = conn.execute("SELECT signature_sha256, settled_at FROM gate_receipts").fetchone()
        assert stored[0] == _mod("app.db_receipts").signature_sha256(encoded)
        assert stored[1] is not None
        credits = _credits(http, key)
        settles = _settle_count(calls)
        verifies = _verify_count(calls)
        ledger = _ledger_count(module.config.DB_PATH, client_id)

        def recover(signature: str, *, slug: str = "my-shop", path: str = "/paid"):
            return _gate(
                http,
                "POST",
                "/internal/gate/x402/receipt",
                json={"slug": slug, "path": path, "payment_signature": signature},
            )

        exact = recover(encoded)
        assert exact.status_code == 200
        assert _digest(exact.json()["receipt"]) == _digest(paid_body["receipt"])
        assert exact.json()["payment_hash"] == paid_body["payment_hash"]
        assert _settlement_view(paid) == _settlement_view(exact)
        assert _settlement_view(exact)["payer"] == buyer.address

        barrier = threading.Barrier(2)
        raced: list[object] = []

        def once() -> None:
            barrier.wait(timeout=5)
            raced.append(recover(encoded))

        threads = [threading.Thread(target=once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert len(raced) == 2
        assert [item.status_code for item in raced] == [200, 200]
        assert all(_digest(item.json()["receipt"]) == _digest(paid_body["receipt"]) for item in raced)
        assert all(_settlement_view(item) == _settlement_view(paid) for item in raced)

        nonce = json.loads(base64.b64decode(encoded))["payload"]["authorization"]["nonce"]
        forged = base64.b64encode(json.dumps({"payload": {"authorization": {"nonce": nonce}}}).encode()).decode()
        _assert_expired(recover(forged))

        def signature(payload):
            payload["payload"]["signature"] = "0x" + "22" * 65

        def amount(payload):
            payload["accepted"]["amount"] = "10001"
            payload["payload"]["authorization"]["value"] = "10001"

        def payer(payload):
            payload["payload"]["authorization"]["from"] = stranger.address

        def resource(payload):
            payload["resource"] = {"url": "https://gate.satsgate.org/my-shop/other"}

        def network(payload):
            payload["accepted"]["network"] = "eip155:1"

        def valid_before(payload):
            payload["payload"]["authorization"]["validBefore"] = "1"

        for mutate in (signature, amount, payer, resource, network, valid_before):
            _assert_expired(recover(_rewrite_signature(encoded, mutate)))

        other_route = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/other", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert other_route.status_code == 200, other_route.text
        other_offer = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/other"})
        assert other_offer.status_code == 200, other_offer.text
        other_key = _buy(http)
        _verify_payee(http, other_key, Account.create())
        other_site = http.post(
            "/v1/sites",
            headers={"X-Api-Key": other_key},
            json={
                "slug": "other-shop",
                "display_name": "Other Shop",
                "origin_url": "https://other.example",
                "listed": False,
            },
        )
        assert other_site.status_code == 200, other_site.text
        other_path = http.post(
            "/v1/sites/other-shop/routes",
            headers={"X-Api-Key": other_key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert other_path.status_code == 200, other_path.text
        other_ok = http.post("/v1/admin/sites/other-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert other_ok.status_code == 200, other_ok.text
        other_live = http.patch(
            "/v1/sites/other-shop",
            headers={"X-Api-Key": other_key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert other_live.status_code == 200, other_live.text
        other_issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "other-shop", "path": "/paid"})
        assert other_issued.status_code == 200, other_issued.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1")
        _assert_expired(recover(encoded, path="/other"))
        _assert_expired(recover(encoded, slug="other-shop"))

        stale = int(time.time()) - int(module.config.X402_RECEIPT_RECOVERY_SECONDS) - 5
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE gate_receipts SET settled_at = ? WHERE payment_hash = ?",
                (stale, f"x402:{paid_body['payment_hash']}"),
            )
        _assert_expired(recover(encoded))
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE gate_receipts SET signature_sha256 = NULL, settled_at = ? WHERE payment_hash = ?",
                (int(time.time()), f"x402:{paid_body['payment_hash']}"),
            )
        _assert_expired(recover(encoded))
        assert _settle_count(calls) == settles
        assert _verify_count(calls) == verifies
        assert _credits(http, key) == credits
        assert _ledger_count(module.config.DB_PATH, client_id) == ledger


def _counts(module, http, key, client_id, calls) -> tuple:
    return (
        _credits(http, key),
        _ledger_count(module.config.DB_PATH, client_id),
        _rows(module.config.DB_PATH),
        _settle_count(calls),
        _verify_count(calls),
    )


def test_recovery_window_zero_disables_the_fallback(tmp_path, monkeypatch):
    key_id, secret_key, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret_key), SATSGATE_X402_RECEIPT_RECOVERY_SECONDS="0")
    _patch_dns(monkeypatch, module)
    assert module.config.X402_RECEIPT_RECOVERY_SECONDS == 0
    owner = Account.create()
    buyer = Account.create()
    calls: list[str] = []

    def _post(url, body, headers):
        del body, headers
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ab" * 32, "payer": buyer.address}

    try:
        with TestClient(module.app) as http:
            key = _buy(http)
            _verify_payee(http, key, owner)
            created = http.post(
                "/v1/sites",
                headers={"X-Api-Key": key},
                json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example", "listed": True},
            )
            assert created.status_code == 200
            http.post(
                "/v1/sites/my-shop/routes",
                headers={"X-Api-Key": key},
                json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
            )
            http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
            http.patch(
                "/v1/sites/my-shop",
                headers={"X-Api-Key": key},
                json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
            )
            importlib.import_module("app.x402_facilitator").poster = _post
            client_id = _client_id(http, key)
            issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
            assert issued.status_code == 200
            encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
            paid = _gate(
                http,
                "POST",
                "/internal/gate/x402/receipt",
                json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
            )
            assert paid.status_code == 200
            inside = _gate(
                http,
                "POST",
                "/internal/gate/x402/receipt",
                json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
            )
            assert inside.status_code == 200
            assert _settle_count(calls) == 1
            with sqlite3.connect(module.config.DB_PATH) as conn:
                settled_at = int(
                    conn.execute("SELECT settled_at FROM gate_receipts").fetchone()[0]
                )
                conn.execute("UPDATE payment_offers SET expires_at = 1")
                conn.execute("UPDATE gate_receipts SET exp = ?", (settled_at + 10_000,))
            baseline = _counts(module, http, key, client_id, calls)
            gate_mod = importlib.import_module("app.internal_gate")
            for offset in (0, 1):
                monkeypatch.setattr(gate_mod.time, "time", lambda settled_at=settled_at, offset=offset: settled_at + offset)
                denied = _gate(
                    http,
                    "POST",
                    "/internal/gate/x402/receipt",
                    json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
                )
                _assert_expired(denied)
                assert _counts(module, http, key, client_id, calls) == baseline
            with sqlite3.connect(module.config.DB_PATH) as conn:
                conn.execute("UPDATE gate_receipts SET exp = ?", (settled_at,))
            monkeypatch.setattr(gate_mod.time, "time", lambda settled_at=settled_at: settled_at + 5)
            expired_receipt = _gate(
                http,
                "POST",
                "/internal/gate/x402/receipt",
                json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
            )
            _assert_expired(expired_receipt)
            assert expired_receipt.status_code != 401
    finally:
        os.environ.pop("SATSGATE_X402_RECEIPT_RECOVERY_SECONDS", None)


def test_recovery_window_edges_and_config(tmp_path, monkeypatch):
    from app.config import _optional_int

    name = "SATSGATE_X402_RECEIPT_RECOVERY_SECONDS"
    monkeypatch.delenv(name, raising=False)
    assert _optional_int(name, 600, minimum=0, maximum=86400) == 600
    monkeypatch.setenv(name, "  ")
    assert _optional_int(name, 600, minimum=0, maximum=86400) == 600
    for raw in ("0", "86400"):
        monkeypatch.setenv(name, raw)
        assert _optional_int(name, 600, minimum=0, maximum=86400) == int(raw)
    for raw in ("-1", "86401", "nope"):
        monkeypatch.setenv(name, raw)
        with pytest.raises(RuntimeError) as caught:
            _optional_int(name, 600, minimum=0, maximum=86400)
        assert raw.strip() not in str(caught.value)
    monkeypatch.delenv(name, raising=False)

    key_id, secret_key, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret_key))
    _patch_dns(monkeypatch, module)
    assert module.config.X402_RECEIPT_RECOVERY_SECONDS == 600
    owner = Account.create()
    buyer = Account.create()
    calls: list[str] = []

    def _post(url, body, headers):
        del body, headers
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "cd" * 32, "payer": buyer.address}

    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example", "listed": True},
        )
        http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        importlib.import_module("app.x402_facilitator").poster = _post
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
        paid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert paid.status_code == 200
        with sqlite3.connect(module.config.DB_PATH) as conn:
            settled_at = int(conn.execute("SELECT settled_at FROM gate_receipts").fetchone()[0])
            conn.execute("UPDATE payment_offers SET expires_at = 1")
            conn.execute("UPDATE gate_receipts SET exp = ?", (settled_at + 10_000,))
        gate_mod = importlib.import_module("app.internal_gate")
        for offset, status in ((599, 200), (600, 200), (601, 402)):
            monkeypatch.setattr(
                gate_mod.time,
                "time",
                lambda settled_at=settled_at, offset=offset: settled_at + offset,
            )
            replay = _gate(
                http,
                "POST",
                "/internal/gate/x402/receipt",
                json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
            )
            assert replay.status_code == status
            if status == 200:
                assert _settlement_view(replay) == _settlement_view(paid)
            else:
                _assert_expired(replay)
        monkeypatch.setattr(gate_mod.time, "time", lambda settled_at=settled_at: settled_at + 50)
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE gate_receipts SET exp = ?", (settled_at + 50,))
        stale = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert stale.status_code == 401
        assert stale.json()["error"] == "token_expired"
        assert "payment-response" not in stale.headers
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute(
                "UPDATE gate_receipts SET signature_sha256 = NULL, settled_at = NULL, exp = ? ",
                (settled_at + 10_000,),
            )
        missing = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        _assert_expired(missing)
        assert _settle_count(calls) == 1
        assert _verify_count(calls) == 1


def test_incoherent_settlement_is_unavailable_without_another_payment(tmp_path, monkeypatch):
    key_id, secret_key, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret_key))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    stranger = Account.create()
    calls: list[str] = []
    other_tx = "0x" + "11" * 32

    def _post(url, body, headers):
        del body, headers
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ab" * 32, "payer": buyer.address}

    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example", "listed": True},
        )
        http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        importlib.import_module("app.x402_facilitator").poster = _post
        client_id = _client_id(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
        paid = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert paid.status_code == 200
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1")
            auth = conn.execute(
                "SELECT network, asset, payer, nonce FROM x402_authorizations"
            ).fetchone()
        network, asset, payer, nonce = auth
        del asset, payer, nonce

        def recover():
            return _gate(
                http,
                "POST",
                "/internal/gate/x402/receipt",
                json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
            )

        def snapshot():
            with sqlite3.connect(module.config.DB_PATH) as conn:
                auths = conn.execute(
                    "SELECT state, tx_hash, credit_charged, updated_at FROM x402_authorizations ORDER BY id"
                ).fetchall()
                offers = conn.execute(
                    "SELECT client_id, resource FROM payment_offers ORDER BY created_at"
                ).fetchall()
            return (
                _counts(module, http, key, client_id, calls),
                tuple(tuple(row) for row in auths),
                tuple(tuple(row) for row in offers),
            )

        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            saved = conn.execute("SELECT * FROM x402_authorizations").fetchone()
            columns = list(saved.keys())

        def restore(conn) -> None:
            conn.execute("DELETE FROM x402_authorizations")
            conn.execute(
                f"INSERT INTO x402_authorizations ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                tuple(saved[name] for name in columns),
            )
            conn.execute(
                "UPDATE x402_authorizations SET state = 'settled', tx_hash = ?, credit_charged = 0",
                ("0x" + "ab" * 32,),
            )
            conn.execute(
                "UPDATE payment_offers SET client_id = ?, resource = ?",
                (client_id, "gate:my-shop:/paid"),
            )
            conn.execute("UPDATE gate_receipts SET network = ?", (network,))

        def clone_offer(conn, new_id: str, **changes) -> None:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM payment_offers ORDER BY created_at LIMIT 1").fetchone()
            names = list(row.keys())
            values = []
            for column in names:
                if column == "id":
                    values.append(new_id)
                elif column == "payment_hash":
                    values.append(None)
                elif column in changes:
                    values.append(changes[column])
                else:
                    values.append(row[column])
            conn.execute(
                f"INSERT INTO payment_offers ({', '.join(names)}) VALUES ({', '.join('?' for _ in names)})",
                values,
            )
            conn.execute("UPDATE x402_authorizations SET offer_id = ?", (new_id,))

        steps = (
            ("sql", "DELETE FROM x402_authorizations"),
            ("sql", "UPDATE x402_authorizations SET tx_hash = NULL"),
            ("sql", "UPDATE x402_authorizations SET state = 'verified'"),
            ("sql", "UPDATE x402_authorizations SET tx_hash = 'not-a-tx'"),
            ("sql", "UPDATE gate_receipts SET network = 'eip155:1'"),
            ("clone", ("offer-other-client", {"client_id": client_id + 1})),
            ("clone", ("offer-other-resource", {"resource": "gate:my-shop:/other"})),
        )
        for kind, payload in steps:
            with sqlite3.connect(module.config.DB_PATH) as conn:
                restore(conn)
                if kind == "sql":
                    conn.execute(payload)
                else:
                    new_id, changes = payload
                    clone_offer(conn, new_id, **changes)
            before = snapshot()
            denied = recover()
            assert denied.status_code == 502
            body = denied.json()
            assert body.get("error") == "paywall_unavailable"
            assert "receipt" not in body
            assert "payment_response" not in body
            assert "payment-response" not in denied.headers
            assert other_tx.encode() not in denied.content
            assert snapshot() == before

        with sqlite3.connect(module.config.DB_PATH) as conn:
            restore(conn)
            conn.execute("UPDATE x402_authorizations SET tx_hash = NULL")
            conn.execute(
                """
                INSERT INTO x402_authorizations(
                  network, asset, payer, nonce, offer_id, value_atomic, pay_to, state,
                  tx_hash, credit_charged, uses_consumed, updated_at
                )
                SELECT network, asset, ?, nonce, offer_id, value_atomic, pay_to, 'settled',
                       ?, 0, 0, updated_at
                FROM x402_authorizations
                """,
                (stranger.address, other_tx),
            )
        denied = recover()
        assert denied.status_code == 502
        assert other_tx.encode() not in denied.content
        assert _settle_count(calls) == 1
        assert _verify_count(calls) == 1


def test_public_gate_recovered_header_matches_the_settlement(tmp_path, monkeypatch):
    from test_satsgate_gate import _close, _open_gate
    from test_x402 import _enable_x402

    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    calls: list[str] = []

    def _post(url, body, headers):
        del body, headers
        calls.append(url)
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ef" * 32, "payer": buyer.address}

    with TestClient(module.app) as core:
        key = _buy(core)
        _verify_payee(core, key, owner)
        core.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example", "listed": False},
        )
        core.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        core.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        _enable_x402(core, key)
        importlib.import_module("app.x402_facilitator").poster = _post
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:
                challenge = http.get("/my-shop/paid")
                assert challenge.status_code == 402
                signature = _payload(
                    challenge.headers["payment-required"],
                    buyer,
                    challenge.json()["x402"]["expires_at"],
                )
                paid = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert paid.status_code == 200
                first = _settlement_view(paid)
                assert first["success"] is True
                assert first["transaction"] == "0x" + "ef" * 32
                assert first["network"]
                with sqlite3.connect(module.config.DB_PATH) as conn:
                    conn.execute("UPDATE payment_offers SET expires_at = 1")
                    conn.execute("UPDATE gate_receipts SET charged = 0")
                settles = _settle_count(calls)
                recovered = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert recovered.status_code == 200
                assert _settlement_view(recovered) == first
                assert _digest(recovered.json()["receipt"]) == _digest(paid.json()["receipt"])
                head = http.head("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert head.status_code == 200
                assert head.content == b""
                assert head.headers.get("payment-response") == recovered.headers.get("payment-response")
                assert _settle_count(calls) == settles
                assert _verify_count(calls) == settles
        finally:
            _close(core_client)


class _Sites(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        slug = parts[3] if len(parts) > 3 else ""
        mode = "test" if slug == "shop-test" else ""
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json={"status": "approved"})
        return httpx.Response(
            200,
            json={
                "slug": slug,
                "client_id": 1,
                "origin_url": "https://origin.example",
                "payee_lightning_address": "merchant@pay.example",
                "rail_lightning": True,
                "rail_x402": mode == "test",
                "x402_mode": mode,
                "routes": [{"path": "/blog/post", "price_currency": "sats", "price_sats": 21}],
            },
        )


def test_test_mode_rate_limits_do_not_apply_to_other_sites():
    settings = _settings(
        rl_per_site=0,
        rl_per_buyer=0,
        rl_test_per_site=60,
        rl_test_per_buyer=10,
        trusted_proxies="testclient",
    )
    core = httpx.AsyncClient(transport=_Sites(), base_url=settings.core_base_url, timeout=5)
    gate = create_app(settings)
    gate.state.core_client = core
    try:
        with TestClient(gate) as http:
            for _ in range(15):
                live = http.get("/shop-live/blog/post", headers={"X-Forwarded-For": "203.0.113.9"})
                assert live.status_code != 429, live.text
            for index in range(10):
                ok = http.get("/shop-test/blog/post", headers={"X-Forwarded-For": "203.0.113.1"})
                assert ok.status_code != 429, ok.text
            buyer = http.get("/shop-test/blog/post", headers={"X-Forwarded-For": "203.0.113.1"})
            assert buyer.status_code == 429, buyer.text
            assert buyer.json()["error"] == "rate_limited"
            for index in range(49):
                ok = http.get("/shop-test/blog/post", headers={"X-Forwarded-For": f"203.0.113.{20 + index}"})
                assert ok.status_code != 429, ok.text
            site = http.get("/shop-test/blog/post", headers={"X-Forwarded-For": "203.0.113.250"})
            assert site.status_code == 429, site.text
            still = http.get("/shop-live/blog/post", headers={"X-Forwarded-For": "203.0.113.1"})
            assert still.status_code != 429, still.text
    finally:
        import asyncio

        asyncio.run(core.aclose())


def _proof_body(module, secret: str):
    del module

    def respond(url, headers=None, resolver=None, timeout=5.0, max_bytes=4096):
        del url, resolver, timeout, max_bytes
        token = (headers or {})["Satsgate-Check"]
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        proof = _mod("app.receipts").check_proof(secret, payload["jti"])
        return 200, json.dumps({"ok": True, "proof": proof}).encode()

    return respond


def test_auto_approve_matrix(tmp_path, monkeypatch):
    (tmp_path / "off").mkdir()
    off = _load_app(tmp_path / "off", SATSGATE_SITES_AUTO_APPROVE="0", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, off)
    with TestClient(off.app) as http:
        key = _buy(http)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "my-shop",
                "display_name": "My Shop",
                "origin_url": "https://origin.example",
                "listed": False,
                "accept_terms": "v1",
            },
        )
        assert created.status_code == 200, created.text
        secret = created.json()["origin_secret"]
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _proof_body(off, secret))
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.status_code == 200, checked.text
        assert checked.json()["status"] == "pending"

    (tmp_path / "origin").mkdir()
    pending = _load_app(tmp_path / "origin", SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, pending)
    with TestClient(pending.app) as http:
        key = _buy(http)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "my-shop",
                "display_name": "My Shop",
                "origin_url": "https://origin.example",
                "listed": False,
                "accept_terms": "v1",
            },
        )
        assert created.json()["site"]["status"] == "pending"

    (tmp_path / "terms").mkdir()
    stale = _load_app(tmp_path / "terms", SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, stale)
    with TestClient(stale.app) as http:
        key = _buy(http)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "my-shop",
                "display_name": "My Shop",
                "origin_url": "https://origin.example",
                "listed": False,
                "accept_terms": "v1",
            },
        )
        secret = created.json()["origin_secret"]
        stale.config.TERMS_VERSION = "v2"
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _proof_body(stale, secret))
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.status_code == 200, checked.text
        assert checked.json()["status"] == "pending"

    (tmp_path / "hold").mkdir()
    suspended = _load_app(tmp_path / "hold", SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, suspended)
    with TestClient(suspended.app) as http:
        key = _buy(http)
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={
                "slug": "my-shop",
                "display_name": "My Shop",
                "origin_url": "https://origin.example",
                "listed": False,
                "accept_terms": "v1",
            },
        )
        secret = created.json()["origin_secret"]
        client_id = _client_id(http, key)
        with sqlite3.connect(suspended.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET suspended_at = 1 WHERE id = ?", (client_id,))
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _proof_body(suspended, secret))
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.status_code == 200, checked.text
        assert checked.json()["status"] == "pending"
        with sqlite3.connect(suspended.config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET suspended_at = NULL WHERE id = ?", (client_id,))
        renamed = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"display_name": "My Shop 2"},
        )
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["site"]["status"] == "approved"


def _jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    pad = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + pad))


def test_origin_check_token_carries_uses(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, secret, _offered, _preimage = _issue_lightning(http)
        captured: dict[str, str] = {}

        def respond(url, headers=None, resolver=None, timeout=5.0, max_bytes=4096):
            del url, resolver, timeout, max_bytes
            token = (headers or {})["Satsgate-Check"]
            captured["token"] = token
            payload = _jwt_claims(token)
            proof = _mod("app.receipts").check_proof(secret, payload["jti"])
            return 200, json.dumps({"ok": True, "proof": proof}).encode()

        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", respond)
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.status_code == 200, checked.text
        token = captured["token"]
        claims = _jwt_claims(token)
        assert claims["uses"] == 1
        assert claims["sub"] == "/.well-known/satsgate-check"
        status, body = origin_check_response(token, secret=secret, site="my-shop")
        assert status == 200
        assert body["ok"] is True
        assert body["proof"]


def test_verify_origin_success_disabled_and_failures(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, secret, _offered, _preimage = _issue_lightning(http)
        calls = {"n": 0}

        def respond(url, headers=None, resolver=None, timeout=5.0, max_bytes=4096):
            calls["n"] += 1
            token = (headers or {})["Satsgate-Check"]
            payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
            proof = _mod("app.receipts").check_proof(secret, payload["jti"])
            return 200, json.dumps({"ok": True, "proof": proof}).encode()

        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", respond)
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.status_code == 200, checked.text
        assert checked.json()["origin_verified_at"]
        assert checked.json()["status"] == "approved"
        disabled = http.post("/v1/admin/sites/my-shop/disable", headers={"X-Admin-Token": "test-admin-token"})
        assert disabled.status_code == 200, disabled.text
        again = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert again.status_code == 200, again.text
        assert again.json()["status"] == "disabled"

        def private(host, port, family=0, socktype=0, proto=0, flags=0):
            import socket

            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))]

        monkeypatch.setattr(_mod("app.ssrf").socket, "getaddrinfo", private)
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _mod("app.ssrf").safe_get_response)
        blocked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert blocked.status_code == 400, blocked.text
        assert blocked.json()["error"] == "origin_rejected"


def test_verify_origin_attempt_limit_and_clears_on_change(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, secret, _offered, _preimage = _issue_lightning(http)

        def wrong(url, headers=None, resolver=None, timeout=5.0, max_bytes=4096):
            del url, headers, resolver, timeout, max_bytes
            return 200, b'{"ok":true,"proof":"00"}'

        def timed_out(url, headers=None, resolver=None, timeout=5.0, max_bytes=4096):
            del url, headers, resolver, timeout, max_bytes
            raise _mod("app.ssrf").SSRFError("fetch_failed")

        def redirected(url, headers=None, resolver=None, timeout=5.0, max_bytes=4096):
            del url, headers, resolver, timeout, max_bytes
            raise _mod("app.ssrf").SSRFError("redirects_not_allowed")

        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", wrong)
        bad = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert bad.json()["error"] == "origin_check_failed"
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", timed_out)
        down = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert down.json()["error"] == "origin_unreachable"
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", redirected)
        hop = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert hop.json()["error"] == "origin_rejected"
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", wrong)
        for _ in range(2):
            failed = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
            assert failed.status_code == 400, failed.text
        limited = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert limited.status_code == 429, limited.text
        assert limited.json()["error"] == "rate_limited"

    (tmp_path / "clear").mkdir()
    fresh = _load_app(tmp_path / "clear")
    _patch_dns(monkeypatch, fresh)
    with TestClient(fresh.app) as http:
        key, secret, _offered, _preimage = _issue_lightning(http)
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _proof_body(fresh, secret))
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.json()["origin_verified_at"]
        moved = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"origin_url": "https://other.example"},
        )
        assert moved.status_code == 200, moved.text
        assert moved.json()["site"]["origin_verified_at"] is None
        monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _proof_body(fresh, secret))
        checked = http.post("/v1/sites/my-shop/verify-origin", headers={"X-Api-Key": key})
        assert checked.json()["origin_verified_at"]
        rotated = http.post("/v1/sites/my-shop/rotate-secret", headers={"X-Api-Key": key})
        assert rotated.json()["site"]["origin_verified_at"] is None


def test_suspension_disables_sites_and_blocks_new_work(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, _secret, offered, preimage = _issue_lightning(http)
        client_id = _client_id(http, key)
        suspended = http.post(
            f"/v1/admin/clients/{client_id}/suspend",
            headers={"X-Admin-Token": "test-admin-token"},
            json={"reason": "abuse report"},
        )
        assert suspended.status_code == 200, suspended.text
        mine = http.get("/v1/sites/mine", headers={"X-Api-Key": key})
        assert mine.json()["sites"][0]["status"] == "disabled"
        viewer = http.get("/v1/client", headers={"X-Api-Key": key})
        assert viewer.json()["suspended"] is True
        assert "reason" not in viewer.json()
        assert "suspend_reason" not in viewer.json()
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "other-shop", "display_name": "Other", "origin_url": "https://other.example"},
        )
        assert created.status_code == 403, created.text
        assert created.json()["error"] == "account_suspended"
        topup = http.get("/v1/topup/trial", headers={"X-Api-Key": key})
        assert topup.status_code == 403, topup.text
        link = http.post("/v1/client/payee/evm/connect", headers={"X-Api-Key": key})
        assert link.status_code == 403, link.text
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE sites SET status = 'approved' WHERE slug = 'my-shop'")
        receipt = _gate(
            http,
            "POST",
            "/internal/gate/receipt",
            json={
                "slug": "my-shop",
                "path": "/blog/post",
                "authorization": f"L402 {offered['macaroon']}:{preimage}",
            },
        )
        assert receipt.status_code == 403, receipt.text
        assert receipt.json()["error"] == "account_suspended"
        assert _rows(module.config.DB_PATH) == 0
        with sqlite3.connect(module.config.DB_PATH) as conn:
            conn.execute("UPDATE sites SET status = 'disabled' WHERE slug = 'my-shop'")
        lifted = http.post(
            f"/v1/admin/clients/{client_id}/unsuspend",
            headers={"X-Admin-Token": "test-admin-token"},
        )
        assert lifted.status_code == 200, lifted.text
        mine = http.get("/v1/sites/mine", headers={"X-Api-Key": key})
        assert mine.json()["sites"][0]["status"] == "disabled"
        assert http.get("/v1/client", headers={"X-Api-Key": key}).json()["suspended"] is False


def test_geoblock_and_ofac_screens(tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir()
    _load_app(tmp_path / "empty", SATSGATE_GEOBLOCK_COUNTRIES="", SATSGATE_GEOIP_DB=str(tmp_path / "missing.mmdb"))

    def explode(path):
        raise AssertionError("empty country list must not open the database")

    geo = _mod("app.geoblock")
    monkeypatch.setattr(geo, "_open", explode)
    assert geo.country_for_ip("203.0.113.10") is None
    assert geo.blocked_country("203.0.113.10") is None

    (tmp_path / "geo").mkdir()
    db_path = tmp_path / "geo.mmdb"
    blocked = _load_app(
        tmp_path / "geo",
        SATSGATE_GEOBLOCK_COUNTRIES="CU,IR,KP",
        SATSGATE_GEOIP_DB=str(db_path),
        SATSGATE_OFAC_EVM_FILE=str(tmp_path / "missing-ofac.txt"),
    )
    _patch_dns(monkeypatch, blocked)
    codes = {"203.0.113.10": "US", "203.0.113.20": "CU"}

    class _Reader:
        def __init__(self, mapping):
            self.mapping = dict(mapping)

        def get(self, ip):
            code = self.mapping.get(ip)
            if not code:
                return None
            return {"country": {"iso_code": code}}

        def close(self):
            return None

    with TestClient(blocked.app) as http:
        missing = http.get("/v1/topup/trial", headers={"X-Forwarded-For": "203.0.113.10"})
    assert missing.status_code == 503, missing.text
    assert missing.json()["error"] == "geoblock_unavailable"
    db_path.write_text("open", encoding="utf-8")
    os.utime(db_path, (time.time() + 5, time.time() + 5))
    monkeypatch.setattr(_mod("app.geoblock"), "_open", lambda path: _Reader(codes))
    with TestClient(blocked.app) as http:
        unknown = http.get("/v1/topup/trial", headers={"X-Forwarded-For": "198.51.100.8"})
        assert unknown.status_code == 402, unknown.text
        allowed = http.get("/v1/topup/trial", headers={"X-Forwarded-For": "203.0.113.10"})
        assert allowed.status_code == 402, allowed.text
        for code, ip in (("CU", "203.0.113.20"), ("IR", "203.0.113.21"), ("KP", "203.0.113.22")):
            codes[ip] = code
        os.utime(db_path, (time.time() + 10, time.time() + 10))
        for ip in ("203.0.113.20", "203.0.113.21", "203.0.113.22"):
            refused = http.get("/v1/topup/trial", headers={"X-Forwarded-For": ip})
            assert refused.status_code == 451, refused.text
            assert refused.json()["error"] == "region_unavailable"

    assert _mod("app.ofac").listed("0x" + "ab" * 20) is False
    assert _mod("app.ofac").status()["ofac_list"] == "missing"
    owner = Account.create()
    ofac_file = tmp_path / "ofac.txt"
    ofac_file.write_text("# empty\n", encoding="utf-8")
    (tmp_path / "ofac").mkdir()
    flagged = _load_app(tmp_path / "ofac", SATSGATE_OFAC_EVM_FILE=str(ofac_file), SATSGATE_GEOBLOCK_COUNTRIES="")
    _patch_dns(monkeypatch, flagged)
    with TestClient(flagged.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_sats": 21})
        turned = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        assert turned.status_code == 200, turned.text
        ofac_file.write_text(owner.address.lower() + "\n", encoding="utf-8")
        os.utime(ofac_file, (time.time() + 5, time.time() + 5))
        _mod("app.ofac").refresh()
        refused = _gate(
            http,
            "POST",
            "/internal/gate/x402/receipt",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": "not-a-signature"},
        )
        assert refused.status_code == 403, refused.text
        assert refused.json()["error"] == "payee_not_allowed"


def test_ofac_update_rejects_non_xml_and_tiny_files(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("ofac_evm_update", ROOT / "scripts" / "ofac_evm_update.py")
    script = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(script)
    bad = tmp_path / "not-xml.xml"
    bad.write_bytes(b"this is not xml")
    with pytest.raises(RuntimeError, match="did not parse"):
        script.extract_evm(bad)
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("keep\n", encoding="utf-8")

    class _Response:
        status = 200
        headers = {"Content-Type": "text/html"}

        def geturl(self):
            return script.PRIMARY

        def read(self, amt=-1):
            if amt is None or int(amt) < 0:
                raise AssertionError("unlimited read")
            return b"<html>no</html>"

        def close(self):
            return None

    class _Opener:
        def open(self, request, timeout=60):
            del request, timeout
            return _Response()

    monkeypatch.setattr(script, "build_opener", lambda *args, **kwargs: _Opener())
    with pytest.raises(RuntimeError, match="content type"):
        script._fetch(script.PRIMARY)

    tiny = tmp_path / "tiny.xml"
    raw = b"<Sanctions></Sanctions>"
    tiny.write_bytes(raw)
    monkeypatch.setattr(script, "_fetch", lambda url: (tiny, len(raw)))
    monkeypatch.setattr(script.sys, "argv", ["ofac_evm_update.py", str(dest)])
    assert script.main() == 1
    assert dest.read_text(encoding="utf-8") == "keep\n"


def _sign_receipt(secret: str, *, aud: str, uses: int = 1) -> str:
    import hashlib
    import hmac

    now = int(time.time())
    claims = {
        "amt": {"sats": 21},
        "aud": aud,
        "exp": now + 3600,
        "iat": now - 5,
        "iss": "https://gate.satsgate.org",
        "jti": "rcp_" + aud.replace("-", "")[:22].ljust(22, "a"),
        "ph": "ab" * 32,
        "rail": "lightning",
        "res": f"gate:{aud}:/report",
        "sub": "/report",
        "uses": uses,
    }
    header = {
        "alg": "HS256",
        "kid": hashlib.sha256(secret.encode()).hexdigest()[:16],
        "typ": "satsgate-receipt+jwt",
    }

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    head = b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    body = b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    digest = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(digest)}"


def _asgi(app, path: str, token: str):
    status = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            status["code"] = message["status"]
        elif message["type"] == "http.response.body":
            status["body"] = message.get("body") or b""

    import asyncio

    asyncio.run(
        app(
            {
                "type": "http",
                "method": "GET",
                "path": path,
                "headers": [(b"satsgate-receipt", token.encode())],
                "query_string": b"",
            },
            receive,
            send,
        )
    )
    return status["code"], json.loads(status["body"])


def test_sdk_store_commits_on_2xx_and_sqlite_is_shared():
    secret = "ab" * 32
    token = _sign_receipt(secret, aud="my-shop", uses=1)

    async def ok(scope, receive, send):
        del scope, receive
        body = b'{"ok":true}'
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    async def fail(scope, receive, send):
        del scope, receive
        await send({"type": "http.response.start", "status": 500, "headers": []})
        await send({"type": "http.response.body", "body": b'{"ok":false}'})

    async def boom(scope, receive, send):
        del scope, receive, send
        raise RuntimeError("origin failed")

    memory = MemoryReceiptStore()
    middleware = SatsgateReceiptMiddleware(fail, site="my-shop", secret=secret, store=memory, protected={"/report"})
    code, body = _asgi(middleware, "/report", token)
    assert code == 500
    middleware = SatsgateReceiptMiddleware(boom, site="my-shop", secret=secret, store=memory, protected={"/report"})
    with pytest.raises(RuntimeError):
        _asgi(middleware, "/report", token)
    middleware = SatsgateReceiptMiddleware(ok, site="my-shop", secret=secret, store=memory, protected={"/report"})
    code, body = _asgi(middleware, "/report", token)
    assert code == 200, body
    code, body = _asgi(middleware, "/report", token)
    assert code == 401
    assert body["error"] == "receipt_used_up"

    path = Path(os.environ.get("TMPDIR", "/tmp")) / f"receipt-uses-{time.time_ns()}.sqlite3"
    first = SqliteReceiptStore(str(path))
    second = SqliteReceiptStore(str(path))
    shared = SatsgateReceiptMiddleware(fail, site="my-shop", secret=secret, store=first, protected={"/report"})
    assert _asgi(shared, "/report", token)[0] == 500
    other = SatsgateReceiptMiddleware(ok, site="my-shop", secret=secret, store=second, protected={"/report"})
    assert _asgi(other, "/report", token)[0] == 200
    third = SqliteReceiptStore(str(path))
    done = SatsgateReceiptMiddleware(ok, site="my-shop", secret=secret, store=third, protected={"/report"})
    code, body = _asgi(done, "/report", token)
    assert code == 401
    assert body["error"] == "receipt_used_up"


class _Upstream(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.status = 500
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.status == 0:
            raise httpx.ConnectError("down")
        return httpx.Response(self.status, json={"ok": self.status == 200})


def test_proxy_receipt_mode_reserves_across_connections(tmp_path, monkeypatch):
    secret = "cd" * 32
    store = tmp_path / "uses.sqlite3"
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", secret)
    monkeypatch.setenv("SATSGATE_API_KEY", "sgr_unused")
    text = textwrap.dedent(
        f"""
        mode: receipt
        core:
          base_url: http://core.test
        upstream:
          base_url: http://upstream.test
        origin:
          secret_env: SATSGATE_ORIGIN_SECRET
        receipt:
          site: my-shop
          store: {store}
        routes:
          - name: report
            methods: [GET]
            path: /report
            price_sats: 21
            access: per_request
            scope: route
        """
    )
    path = tmp_path / "proxy.yaml"
    path.write_text(text, encoding="utf-8")
    settings = load_settings(path)
    upstream = _Upstream()
    app = build_app(settings, transport=upstream)
    token = _sign_receipt(secret, aud="my-shop")
    with StarletteClient(app) as http:
        failed = http.get("/report", headers={"Satsgate-Receipt": token})
        assert failed.status_code == 500, failed.text
        upstream.status = 0
        down = http.get("/report", headers={"Satsgate-Receipt": token})
        assert down.status_code == 502, down.text
        upstream.status = 200
        paid = http.get("/report", headers={"Satsgate-Receipt": token})
        assert paid.status_code == 200, paid.text
        used = http.get("/report", headers={"Satsgate-Receipt": token})
        assert used.status_code == 401, used.text
        assert used.json()["error"] == "receipt_used_up"
    again = SqliteReceiptStore(str(store))
    with pytest.raises(ReceiptError) as exc:
        again.reserve("rcp_" + "myshop".ljust(22, "a"), 1, int(time.time()) + 3600)
    assert exc.value.code == "receipt_used_up"
