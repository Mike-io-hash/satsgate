"""Hosted gate 402 offers Lightning, x402, or both. The facilitator is a test double.

The gate calls core. Core calls the facilitator. These tests never open a socket
to x402.org and never sign a transaction.
"""

from __future__ import annotations

import base64
import json

from eth_account import Account
from fastapi.testclient import TestClient

from satsgate_gate.core_client import _parse_site
from satsgate_gate.headers import filter_request_headers
from satsgate_proxy.origin import verify_origin_signature
from test_rates import _use
from test_satsgate_gate import (
    Origin,
    _GATE_TOKEN,
    _close,
    _load_app,
    _open_gate,
    _patch_dns,
    _prepare,
    _settings,
)
from test_x402 import _credits, _enable_x402, _install_poster, _payload, _poster, _verify_payee

_LIGHTNING_KEYS = {
    "ok",
    "error",
    "amount_sats",
    "payment_hash",
    "invoice",
    "invoice_expires_at",
    "macaroon",
    "resource",
    "max_uses",
    "access_seconds",
    "hint",
}
_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


def test_old_site_config_stays_lightning_and_payment_headers_are_stripped():
    site = _parse_site(
        "my-shop",
        {
            "slug": "my-shop",
            "client_id": 1,
            "origin_url": "https://origin.example",
            "origin_secret": "ab",
            "routes": [{"path": "/blog/post", "price_sats": 21, "max_uses": 1, "access_seconds": None}],
        },
    )
    assert site.rail_lightning is True
    assert site.rail_x402 is False
    assert site.routes[0].price_currency == "sats"
    assert site.routes[0].price_sats == 21
    assert site.routes[0].price_usd_atomic is None
    raw = [
        (b"payment-signature", b"abc"),
        (b"payment-response", b"nope"),
        (b"authorization", b"L402 mac:pre"),
        (b"authorization", b"Bearer keep"),
        (b"x-satsgate-paid-sats", b"1"),
    ]
    kept = filter_request_headers(raw)
    names = [name.lower() for name, _value in kept]
    assert "payment-signature" not in names
    assert "payment-response" not in names
    assert "x-satsgate-paid-sats" not in names
    assert [value for name, value in kept if name.lower() == "authorization"] == ["Bearer keep"]


def test_lightning_only_402_has_no_payment_required(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()
    with TestClient(module.app) as core:
        _prepare(core)
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                response = http.get("/my-shop/blog/post")
                assert response.status_code == 402, response.text
                body = response.json()
                assert set(body) == _LIGHTNING_KEYS
                assert body["amount_sats"] == 21
                assert body["error"] == "payment_required"
                assert "x402" not in body
                assert response.headers["www-authenticate"].startswith('L402 macaroon="')
                assert "payment-required" not in response.headers
                assert origin.requests == []
        finally:
            _close(core_client, origin_client)


def test_usd_lightning_only_locks_the_sats_quote(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    origin = Origin()
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        added = core.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/usd", "price_currency": "usd", "price_usd_atomic": 1_000_000},
        )
        assert added.status_code == 200, added.text
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                response = http.get("/my-shop/usd")
                assert response.status_code == 402, response.text
                body = response.json()
                assert body["amount_sats"] == 1539
                assert "invoice" in body
                assert "x402" not in body
                assert "payment-required" not in response.headers
                assert response.headers["www-authenticate"].startswith("L402 ")
        finally:
            _close(core_client, origin_client)


def test_x402_only_verifies_serves_and_settles(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    origin = Origin()
    origin.responder = lambda request: httpx_response(200, b"origin-ok")
    with TestClient(module.app) as core:
        key, secret = _prepare(core)
        before = _credits(core, key)
        _verify_payee(core, key, owner)
        added = core.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert added.status_code == 200, added.text
        _enable_x402(core, key)
        calls, post = _poster(buyer)
        _install_poster(post)
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                challenge = http.get("/my-shop/paid", headers={"Authorization": "Bearer buyer"})
                assert challenge.status_code == 402, challenge.text
                body = challenge.json()
                assert "invoice" not in body
                assert "macaroon" not in body
                assert "www-authenticate" not in challenge.headers
                assert body["x402"]["scheme"] == "exact"
                assert body["x402"]["network"] == "eip155:84532"
                assert body["x402"]["asset"] == _USDC
                assert body["x402"]["payTo"] == owner.address
                assert body["x402"]["amount"] == "10000"
                encoded = challenge.headers["payment-required"]
                document = json.loads(base64.b64decode(encoded))
                assert document["x402Version"] == 2
                assert document["accepts"][0]["scheme"] == "exact"
                assert "paymentFlow" not in document["accepts"][0]["extra"]
                assert owner.address != "0x0000000000000000000000000000000000000000"
                signature = _payload(encoded, buyer, body["x402"]["expires_at"])
                paid = http.get(
                    "/my-shop/paid",
                    headers={"PAYMENT-SIGNATURE": signature, "Authorization": "Bearer buyer"},
                )
                assert paid.status_code == 200, paid.text
                assert paid.content == b"origin-ok"
                assert paid.headers["payment-response"]
                settled = json.loads(base64.b64decode(paid.headers["payment-response"]))
                assert settled["success"] is True
                assert settled["network"] == "eip155:84532"
                assert settled["payer"] == buyer.address
                assert _credits(core, key) == before - 1
                assert len(origin.requests) == 1
                forwarded = origin.requests[0]
                names = {name.lower() for name in forwarded.headers}
                assert "payment-signature" not in names
                assert "authorization" in names
                assert forwarded.headers["authorization"] == "Bearer buyer"
                assert "x-satsgate-paid-sats" not in names
                assert forwarded.headers["x-satsgate-paid-usd-atomic"] == "10000"
                assert forwarded.headers["x-satsgate-payment-hash"] == "ab" * 32
                assert verify_origin_signature(
                    secret=secret,
                    header=forwarded.headers["x-satsgate-signature"],
                    method="GET",
                    target="/paid",
                    payment_hash="ab" * 32,
                    now=int(forwarded.headers["x-satsgate-signature"].split(",", 1)[0][2:]),
                    max_skew_seconds=30,
                )
                assert calls[0][0].endswith("/verify")
                assert calls[0][1]["paymentRequirements"]["payTo"] == owner.address
                assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1
        finally:
            _close(core_client, origin_client)


def test_both_rails_follow_the_live_quote_and_not_a_cached_one(tmp_path, monkeypatch):
    monkeypatch.setenv("SATSGATE_CHALLENGE_REUSE_SECONDS", "0")
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    origin = Origin()
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        _verify_payee(core, key, owner)
        enabled = core.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["site"]["rail_lightning"] is True
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                first = http.get("/my-shop/blog/post")
                assert first.status_code == 402, first.text
                body = first.json()
                assert set(_LIGHTNING_KEYS).issubset(body)
                assert body["amount_sats"] == 21
                assert body["x402"]["amount"] == "13650"
                assert body["x402"]["payTo"] == owner.address
                assert first.headers["www-authenticate"].startswith("L402 ")
                assert first.headers["payment-required"]
                _use(module, {"coinbase": "70000", "kraken": "70000", "bitstamp": "70000"})
                second = http.get("/my-shop/blog/post")
                assert second.status_code == 402, second.text
                assert second.json()["amount_sats"] == 21
                assert second.json()["x402"]["amount"] == "14700"
                assert origin.requests == []
        finally:
            _close(core_client, origin_client)


def test_verify_failure_does_not_call_the_origin_or_spend_a_credit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    origin = Origin()
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        before = _credits(core, key)
        signature = _arm_x402(core, key, owner, buyer)
        calls, post = _poster(buyer, verify={"isValid": False, "invalidReason": "invalid_signature"})
        _install_poster(post)
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                rejected = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert rejected.status_code == 402, rejected.text
                assert rejected.json()["error"] == "x402_rejected"
                assert rejected.json()["reason"] == "invalid_signature"
                assert "payment-response" not in rejected.headers
                assert origin.requests == []
                assert _credits(core, key) == before
                assert calls and calls[0][0].endswith("/verify")
                assert not any(url.endswith("/settle") for url, _body in calls)
        finally:
            _close(core_client, origin_client)


def test_origin_failure_does_not_settle_and_a_retry_does(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    origin = Origin()
    origin.responder = lambda request: httpx_response(500, b"origin-down")
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        before = _credits(core, key)
        signature = _arm_x402(core, key, owner, buyer)
        calls, post = _poster(buyer)
        _install_poster(post)
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                failed = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert failed.status_code == 500, failed.text
                assert failed.content == b"origin-down"
                assert "payment-response" not in failed.headers
                assert "use_spent" not in failed.text
                assert _credits(core, key) == before
                assert not any(url.endswith("/settle") for url, _body in calls)
                origin.responder = lambda request: httpx_response(200, b"origin-ok")
                retried = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert retried.status_code == 200, retried.text
                assert retried.content == b"origin-ok"
                assert retried.headers["payment-response"]
                assert _credits(core, key) == before - 1
                assert sum(1 for url, _body in calls if url.endswith("/verify")) == 1
                assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1
                assert len(origin.requests) == 2
        finally:
            _close(core_client, origin_client)


def test_settle_failure_hides_the_body_and_a_retry_settles_once(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    origin = Origin()
    origin.responder = lambda request: httpx_response(200, b"PAID-BODY-SECRET")
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        before = _credits(core, key)
        signature = _arm_x402(core, key, owner, buyer)
        calls, post = _poster(buyer, settle={"success": False, "errorReason": "insufficient_funds"})
        _install_poster(post)
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                failed = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert failed.status_code == 402, failed.text
                assert failed.json()["error"] == "x402_rejected"
                assert failed.json()["reason"] == "insufficient_funds"
                assert b"PAID-BODY-SECRET" not in failed.content
                assert "payment-response" not in failed.headers
                assert _credits(core, key) == before
                assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1
                _install_poster(_poster(buyer)[1])
                retried = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert retried.status_code == 200, retried.text
                assert retried.content == b"PAID-BODY-SECRET"
                assert retried.headers["payment-response"]
                assert _credits(core, key) == before - 1
                assert len(origin.requests) == 2
        finally:
            _close(core_client, origin_client)


def test_both_payment_headers_and_an_oversized_signature_settle_nothing(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    origin = Origin()
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        before = _credits(core, key)
        signature = _arm_x402(core, key, owner, buyer)
        calls, post = _poster(buyer)
        _install_poster(post)
        gate, core_client, origin_client = _open_gate(module.app, _settings(), origin)
        try:
            with gate as http:
                both = http.get(
                    "/my-shop/paid",
                    headers={"Authorization": "L402 macaroon", "PAYMENT-SIGNATURE": signature},
                )
                assert both.status_code == 400, both.text
                assert both.json()["error"] == "one_rail_only"
                huge = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": "a" * 8193})
                assert huge.status_code == 400, huge.text
                assert huge.json()["error"] == "bad_signature"
                assert origin.requests == []
                assert calls == []
                assert _credits(core, key) == before
        finally:
            _close(core_client, origin_client)


def _arm_x402(core: TestClient, key: str, owner, buyer) -> str:
    _verify_payee(core, key, owner)
    added = core.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": key},
        json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
    )
    assert added.status_code == 200, added.text
    _enable_x402(core, key)
    challenge = core.post(
        "/internal/gate/challenge",
        headers={"X-Satsgate-Gate-Token": _GATE_TOKEN},
        json={"slug": "my-shop", "path": "/paid"},
    )
    assert challenge.status_code == 200, challenge.text
    return _payload(challenge.json()["payment_required"], buyer, challenge.json()["expires_at"])


def httpx_response(status: int, content: bytes):
    import httpx

    return httpx.Response(status, content=content)
