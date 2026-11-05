"""Hosted gate x402 returns a receipt. The facilitator is a test double."""

from __future__ import annotations

import base64
import json

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from satsgate_gate.core_client import _parse_site
from test_satsgate_gate import _close, _load_app, _open_gate, _patch_dns, _prepare, _settings
from test_x402 import _credits, _enable_x402, _install_poster, _payload, _poster, _verify_payee

_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


def test_site_config_has_no_origin_secret():
    site = _parse_site(
        "my-shop",
        {
            "slug": "my-shop",
            "client_id": 1,
            "origin_url": "https://origin.example",
            "x402_mode": "test",
            "routes": [{"path": "/blog/post", "price_sats": 21, "max_uses": 1, "access_seconds": None}],
        },
    )
    assert site.x402_mode == "test"
    assert not hasattr(site, "origin_secret")
    with pytest.raises(ValueError):
        _parse_site(
            "my-shop",
            {
                "slug": "my-shop",
                "client_id": 1,
                "origin_url": "https://origin.example",
                "origin_secret": "secret",
                "routes": [],
            },
        )


def test_x402_test_mode_receipt_does_not_debit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    with TestClient(module.app) as core:
        key, _secret = _prepare(core, credits=False)
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
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:
                challenge = http.get("/my-shop/paid")
                assert challenge.status_code == 402, challenge.text
                body = challenge.json()
                assert body["delivery"] == "receipt"
                assert body["x402_mode"] == "test"
                document = json.loads(base64.b64decode(challenge.headers["payment-required"]))
                assert "Satsgate receipt for" in document["resource"]["description"]
                assert document["resource"]["description"].startswith("Test payment on Base Sepolia")
                signature = _payload(challenge.headers["payment-required"], buyer, body["x402"]["expires_at"])
                before = _credits(core, key)
                paid = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert paid.status_code == 200, paid.text
                assert paid.json()["receipt"]
                assert paid.headers["payment-response"]
                again = http.get("/my-shop/paid", headers={"PAYMENT-SIGNATURE": signature})
                assert again.status_code == 200, again.text
                assert again.json()["receipt"] == paid.json()["receipt"]
                assert _credits(core, key) == before
                assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1
        finally:
            _close(core_client)
