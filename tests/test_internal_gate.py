"""Internal gate API on core. Hidden unless SATSGATE_GATE_TOKEN is set."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
_SECRET_KEY = "ab" * 32
_GATE_TOKEN = "test-gate-token"


def _load_app(tmp_path: Path, **env: str):
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    base = {
        "SATSGATE_ENV": "development",
        "SATSGATE_WALLET_MODE": "mock",
        "SATSGATE_DEV_MODE": "1",
        "SATSGATE_RL_ENABLED": "0",
        "SATSGATE_MACAROON_SECRET": "test-secret",
        "SATSGATE_MACAROON_KEY_ID": "1",
        "SATSGATE_MACAROON_PREVIOUS_KEYS": "",
        "SATSGATE_DB_PATH": str(tmp_path / "satsgate_test.sqlite3"),
        "SATSGATE_ADMIN_TOKEN": "test-admin-token",
        "SATSGATE_TRUSTED_PROXIES": "testclient",
        "SATSGATE_LN_NETWORK": "mainnet",
        "SATSGATE_SITE_SECRET_KEY": _SECRET_KEY,
        "SATSGATE_SITES_AUTO_APPROVE": "0",
        "SATSGATE_SITES_MAX_PER_ACCOUNT": "3",
        "SATSGATE_SITES_MAX_ROUTES": "20",
        "SATSGATE_GATE_PUBLIC_BASE": "https://gate.satsgate.org",
        "SATSGATE_GATE_TOKEN": _GATE_TOKEN,
        "SATSGATE_GATE_PEERS": "",
    }
    base.update(env)
    for key, value in base.items():
        os.environ[key] = value
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("app.main")


def _patch_dns(monkeypatch, module):
    import ipaddress
    import socket

    def fake(host, port, family=0, socktype=0, proto=0, flags=0):
        name = str(host).lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            chosen = name
        except ValueError:
            chosen = "1.1.1.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (chosen, port))]

    monkeypatch.setattr(module.ssrf.socket, "getaddrinfo", fake)


def _auth(macaroon: str, preimage_hex: str) -> str:
    return f"L402 {macaroon}:{preimage_hex}"


def _buy(http: TestClient) -> str:
    started = http.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = http.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert settled.status_code == 200, settled.text
    return settled.json()["api_key"]


def _ready_site(http: TestClient, *, credits: bool = True, price: int = 21, max_uses: int | None = 1):
    if credits:
        key = _buy(http)
    else:
        module = importlib.import_module("app.main")
        key, _client = module.db.create_client(module.config.DB_PATH)
    payee = http.post(
        "/v1/client/payee",
        headers={"X-Api-Key": key},
        json={"payee_lightning_address": "merchant@pay.example"},
    )
    assert payee.status_code == 200, payee.text
    created = http.post(
        "/v1/sites",
        headers={"X-Api-Key": key},
        json={
            "slug": "my-shop",
            "display_name": "My Shop",
            "origin_url": "https://origin.example",
            "listed": False,
        },
    )
    assert created.status_code == 200, created.text
    secret = created.json()["origin_secret"]
    route = http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": key},
        json={"path": "/blog/post", "price_sats": price, "max_uses": max_uses},
    )
    assert route.status_code == 200, route.text
    approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
    assert approved.status_code == 200, approved.text
    return key, secret


def _gate(http: TestClient, method: str, path: str, **kwargs):
    headers = {"X-Satsgate-Gate-Token": _GATE_TOKEN}
    headers.update(kwargs.pop("headers", {}))
    return http.request(method, path, headers=headers, **kwargs)


def test_internal_routes_are_hidden_without_a_token(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_GATE_TOKEN="")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        assert http.get("/health").json()["version"] == "0.14.3"
        hidden = http.get("/internal/gate/sites/my-shop/status", headers={"X-Satsgate-Gate-Token": _GATE_TOKEN})
        assert hidden.status_code == 404
        assert hidden.json()["error"] == "not_found"
        spec = http.get("/openapi.json")
        assert spec.status_code == 200
        assert "/internal/gate/sites/{slug}" not in spec.json()["paths"]
        key = _buy(http)
        challenge = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "notes/1", "amount_sats": 21},
        )
        assert challenge.status_code == 200, challenge.text
        assert challenge.json()["resource"] == "notes/1"


def test_gate_token_and_peer_pin(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_GATE_PEERS="203.0.113.9")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        missing = http.get("/internal/gate/sites/my-shop/status")
        assert missing.status_code == 404
        wrong = _gate(http, "GET", "/internal/gate/sites/my-shop/status", headers={"X-Satsgate-Gate-Token": "nope"})
        assert wrong.status_code == 404
        pinned = _gate(http, "GET", "/internal/gate/sites/my-shop/status")
        assert pinned.status_code == 404
        assert pinned.json()["error"] == "not_found"
        allowed = _load_app(tmp_path, SATSGATE_GATE_PEERS="testclient")
        _patch_dns(monkeypatch, allowed)
        with TestClient(allowed.app) as http2:
            _ready_site(http2)
            ok = _gate(http2, "GET", "/internal/gate/sites/my-shop/status")
            assert ok.status_code == 200
            assert ok.json() == {"ok": True, "status": "approved"}
            pending = _gate(http2, "GET", "/internal/gate/sites/no-such/status")
            assert pending.status_code == 404
            assert "origin" not in pending.text


def test_config_returns_one_secret_and_challenge_uses_the_owner(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        _key, secret = _ready_site(http, price=42, max_uses=3)
        config = _gate(http, "GET", "/internal/gate/sites/my-shop")
        assert config.status_code == 200, config.text
        body = config.json()
        assert body["origin_secret"] == secret
        assert body["origin_url"] == "https://origin.example"
        assert body["payee_lightning_address"] == "merchant@pay.example"
        assert body["rail_lightning"] is True
        assert body["rail_x402"] is False
        assert body["routes"] == [
            {
                "path": "/blog/post",
                "price_currency": "sats",
                "price_sats": 42,
                "price_usd_atomic": None,
                "max_uses": 3,
                "access_seconds": None,
            }
        ]
        assert config.headers["cache-control"] == "no-store"
        owner = http.get("/v1/sites/my-shop", headers={"X-Api-Key": _key})
        assert "origin_secret" not in owner.text

        challenge = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            headers={"X-Satsgate-Buyer-Ip": "203.0.113.10"},
            json={"slug": "my-shop", "path": "/blog/post", "payee_lightning_address": "thief@evil.example"},
        )
        assert challenge.status_code == 200, challenge.text
        issued = challenge.json()
        assert issued["resource"] == "gate:my-shop:/blog/post"
        assert issued["amount_sats"] == 42
        assert issued["max_uses"] == 3
        assert issued["payee_lightning_address"] == "merchant@pay.example"
        assert issued["buyer_ip_accepted"] is True
        assert issued["www_authenticate"].startswith('L402 macaroon="')

        ignored = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            headers={"X-Satsgate-Buyer-Ip": "203.0.113.10"},
            json={"slug": "my-shop", "path": "/missing"},
        )
        assert ignored.status_code == 404

        sneaky = http.post(
            "/v1/admin/sites/my-shop/disable",
            headers={"X-Satsgate-Gate-Token": _GATE_TOKEN},
        )
        assert sneaky.status_code == 401
        still = _gate(http, "GET", "/internal/gate/sites/my-shop/status")
        assert still.status_code == 200


def test_disabled_and_pending_look_the_same(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key, _secret = _ready_site(http)
        http.post("/v1/admin/sites/my-shop/disable", headers={"X-Admin-Token": "test-admin-token"})
        disabled = _gate(http, "GET", "/internal/gate/sites/my-shop/status")
        assert disabled.status_code == 404
        assert disabled.json() == {"ok": False, "error": "not_found"}
        assert _gate(http, "GET", "/internal/gate/sites/my-shop").status_code == 404
        created = http.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "other-shop", "display_name": "Other", "origin_url": "https://origin.example"},
        )
        assert created.status_code == 200, created.text
        pending = _gate(http, "GET", "/internal/gate/sites/other-shop/status")
        assert pending.status_code == 404
        assert pending.json() == disabled.json()


def test_buyer_ip_is_ignored_from_an_untrusted_peer(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        _ready_site(http)
        challenge = _gate(
            http,
            "POST",
            "/internal/gate/challenge",
            headers={"X-Satsgate-Buyer-Ip": "203.0.113.10"},
            json={"slug": "my-shop", "path": "/blog/post"},
        )
        assert challenge.status_code == 200, challenge.text
        assert challenge.json()["buyer_ip_accepted"] is False
