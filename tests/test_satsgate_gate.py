"""Hosted gate sells a receipt. It does not call the seller."""

from __future__ import annotations

import asyncio
import importlib
import os
import socket
import sys
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from satsgate_gate.app import create_app, parse_public_path
from satsgate_gate.config import Settings, load_settings
from satsgate_gate.core_client import FRESH_REASONS, MERCHANT_ERRORS
from satsgate_proxy.core_client import FRESH_REASONS as PROXY_FRESH
from satsgate_proxy.core_client import MERCHANT_ERRORS as PROXY_MERCHANT

REPO_ROOT = Path(__file__).resolve().parents[1]
_SECRET_KEY = "cd" * 32
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
        "SATSGATE_TRUSTED_PROXIES": "127.0.0.1",
        "SATSGATE_LN_NETWORK": "mainnet",
        "SATSGATE_SITE_SECRET_KEY": _SECRET_KEY,
        "SATSGATE_SITES_AUTO_APPROVE": "0",
        "SATSGATE_SITES_MAX_PER_ACCOUNT": "3",
        "SATSGATE_SITES_MAX_ROUTES": "20",
        "SATSGATE_GATE_PUBLIC_BASE": "https://gate.satsgate.org",
        "SATSGATE_GATE_TOKEN": _GATE_TOKEN,
        "SATSGATE_GATE_PEERS": "",
        "SATSGATE_X402_CDP": "0",
        "SATSGATE_X402_CDP_KEY_ID": "",
        "SATSGATE_X402_CDP_KEY_SECRET": "",
        "SATSGATE_BUYER_CHALLENGE_MAX": "100",
        "SATSGATE_BUYER_MAX_OPEN_CHALLENGES": "100",
        "SATSGATE_GEOBLOCK_COUNTRIES": "",
        "SATSGATE_OFAC_EVM_FILE": str(tmp_path / "missing-ofac.txt"),
    }
    base.update(env)
    for key, value in base.items():
        os.environ[key] = value
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("app.main")


def _patch_dns(monkeypatch, module):
    def fake(host, port, family=0, socktype=0, proto=0, flags=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))]

    monkeypatch.setattr(module.ssrf.socket, "getaddrinfo", fake)


def _settings(**overrides) -> Settings:
    values = dict(
        core_base_url="http://core.test",
        gate_token=_GATE_TOKEN,
        trusted_proxies="testclient",
        cache_seconds=30,
        core_timeout=5,
        rl_window_seconds=60,
        rl_per_site=0,
        rl_per_buyer=0,
        rl_test_per_site=0,
        rl_test_per_buyer=0,
        pending_retry_after=2,
        abuse_contact="abuse@example.com",
        terms_url="",
    )
    values.update(overrides)
    return Settings(**values)


def _auth(macaroon: str, preimage: str | None = None) -> dict[str, str]:
    token = macaroon if preimage is None else f"{macaroon}:{preimage}"
    return {"Authorization": f"L402 {token}"}


def _buy(http: TestClient) -> str:
    started = http.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = http.get("/v1/topup/trial", headers=_auth(body["macaroon"], preimage))
    assert settled.status_code == 200, settled.text
    return settled.json()["api_key"]


def _pay(http: TestClient, payment_hash: str) -> str:
    paid = http.get(f"/dev/mock/pay/{payment_hash}")
    assert paid.status_code == 200, paid.text
    return paid.json()["preimage"]


class Origin:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responder = lambda request: httpx.Response(200, content=b"origin-ok")

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responder(request)


def _prepare(http: TestClient, *, credits: bool = True, max_uses: int | None = 1, access_seconds: int | None = None):
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
        json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example/api", "listed": False},
    )
    assert created.status_code == 200, created.text
    route = http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": key},
        json={"path": "/blog/post", "price_sats": 21, "max_uses": max_uses, "access_seconds": access_seconds},
    )
    assert route.status_code == 200, route.text
    approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
    assert approved.status_code == 200, approved.text
    return key, created.json()["origin_secret"]


class _CoreOnly(httpx.AsyncBaseTransport):
    def __init__(self, app) -> None:
        self.inner = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != "core.test":
            raise AssertionError(f"gate called {request.url}")
        return await self.inner.handle_async_request(request)


def _open_gate(core_app, settings: Settings, origin=None):
    del origin
    core_client = httpx.AsyncClient(transport=_CoreOnly(core_app), base_url=settings.core_base_url, timeout=5)
    gate = create_app(settings)
    gate.state.core_client = core_client
    return TestClient(gate), core_client, None


def _close(*clients) -> None:
    async def _aclose():
        for client in clients:
            if client is not None:
                await client.aclose()

    asyncio.run(_aclose())


def test_public_paths_and_reason_sets_match_the_proxy():
    assert FRESH_REASONS == PROXY_FRESH
    assert MERCHANT_ERRORS == PROXY_MERCHANT
    assert parse_public_path("/my-shop") == ("my-shop", "/")
    assert parse_public_path("/my-shop/blog/post") == ("my-shop", "/blog/post")
    assert parse_public_path("/my-shop/../secret") is None


def test_removed_gate_env_is_ignored(monkeypatch):
    monkeypatch.setenv("SATSGATE_GATE_UPSTREAM_TIMEOUT", "15")
    monkeypatch.setenv("SATSGATE_GATE_MAX_REQUEST_BYTES", "10")
    monkeypatch.setenv("SATSGATE_GATE_MAX_RESPONSE_BYTES", "10")
    monkeypatch.setenv("SATSGATE_GATE_CORE_URL", "http://core.test")
    loaded = load_settings()
    assert loaded.core_base_url == "http://core.test"
    assert not hasattr(loaded, "upstream_timeout")


def test_root_names_receipt_delivery(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    gate, core_client, _origin = _open_gate(module.app, _settings(terms_url="https://satsgate.org/terms"))
    try:
        with gate as http:
            root = http.get("/")
            assert root.status_code == 200, root.text
            body = root.json()
            assert body["version"] == "0.15.0"
            assert body["delivery"] == "receipt"
            assert body["abuse_contact"] == "abuse@example.com"
            assert body["terms_url"] == "https://satsgate.org/terms"
            assert root.headers["cache-control"] == "no-store"
    finally:
        _close(core_client)


def test_unpaid_402_names_the_seller_and_does_not_read_the_body(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as core:
        _prepare(core)
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:

                def raising_body():
                    raise AssertionError("body was read")
                    yield b""

                response = http.post("/my-shop/blog/post", content=raising_body(), headers={"content-type": "text/plain"})
                assert response.status_code == 402, response.text
                body = response.json()
                assert body["delivery"] == "receipt"
                assert body["redeem_url"] == "https://origin.example/api/blog/post"
                assert body["seller_host"] == "origin.example"
                assert body["receipt_header"] == "Satsgate-Receipt"
                assert 'rel="satsgate-redeem"' in response.headers["link"]
        finally:
            _close(core_client)


def test_lightning_receipt_is_idempotent_and_debits_once(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as core:
        key, secret = _prepare(core)
        before = core.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"]
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:
                challenge = http.get("/my-shop/blog/post")
                assert challenge.status_code == 402, challenge.text
                offered = challenge.json()
                preimage = core.get(f"/dev/mock/pay/{offered['payment_hash']}").json()["preimage"]
                paid = http.get("/my-shop/blog/post", headers=_auth(offered["macaroon"], preimage))
                assert paid.status_code == 200, paid.text
                body = paid.json()
                assert body["paid"] is True
                assert body["rail"] == "lightning"
                assert body["receipt"]
                assert body["expires_at_iso"].endswith("Z")
                assert paid.headers["satsgate-receipt"] == body["receipt"]
                assert "valid until" in body["note"]
                again = http.get("/my-shop/blog/post", headers=_auth(offered["macaroon"], preimage))
                assert again.status_code == 200, again.text
                assert again.json()["receipt"] == body["receipt"]
                after = core.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"]
                assert after == before - 1
                from satsgate_sdk.receipts import verify_receipt

                verified = verify_receipt(body["receipt"], secret=secret, site="my-shop", path="/blog/post")
                assert verified.uses == 1
        finally:
            _close(core_client)


def test_pending_invoice_sets_retry_after(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as core:
        _prepare(core)
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:
                challenge = http.get("/my-shop/blog/post")
                offered = challenge.json()
                pending = http.get("/my-shop/blog/post", headers=_auth(offered["macaroon"]))
                assert pending.status_code == 401, pending.text
                assert pending.json()["error"] == "preimage_required"
        finally:
            _close(core_client)


def test_one_rail_only(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as core:
        _prepare(core)
        gate, core_client, _origin = _open_gate(module.app, _settings())
        try:
            with gate as http:
                response = http.get(
                    "/my-shop/blog/post",
                    headers={"Authorization": "L402 abc", "PAYMENT-SIGNATURE": "def"},
                )
                assert response.status_code == 400
                assert response.json()["error"] == "one_rail_only"
        finally:
            _close(core_client)


def test_gate_package_does_not_import_an_http_client_except_for_core():
    root = REPO_ROOT / "gate" / "src" / "satsgate_gate"
    for path in root.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if path.name == "core_client.py":
            assert "import httpx" in text
            continue
        assert "import httpx" not in text
        assert "urllib.request" not in text
        assert "import requests" not in text
