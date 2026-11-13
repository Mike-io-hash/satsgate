"""Hosted gate sells a receipt. It does not call the seller."""

from __future__ import annotations

import asyncio
import importlib
import json
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
    started = http.post("/v1/topup/lightning", json={"sats": 1000})
    assert started.status_code == 402, started.text
    body = started.json()
    preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = http.post("/v1/topup/lightning", json={"sats": 1000}, headers=_auth(body["macaroon"], preimage))
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
            assert body["version"] == "0.15.2"
            assert body["delivery"] == "receipt"
            assert body["abuse_contact"] == "abuse@example.com"
            assert body["terms_url"] == "https://satsgate.org/terms"
            assert root.headers["cache-control"] == "no-store"
    finally:
        _close(core_client)


def _header_view(headers) -> dict[str, str | None]:
    keys = ("cache-control", "www-authenticate", "payment-required", "link", "retry-after")
    return {key: headers.get(key) for key in keys}


def _without_contact(body: dict) -> dict:
    data = dict(body)
    data.pop("abuse_contact", None)
    return data


def test_abuse_contact_is_on_every_402_and_absent_when_empty():
    from satsgate_gate.app import _challenge_response, _failure
    from satsgate_gate.cache import CachedSite, GateRoute
    from satsgate_gate.core_client import Challenge, CoreResult

    site = CachedSite(
        slug="my-shop",
        client_id=1,
        origin_url="https://origin.example/api",
        payee="merchant@pay.example",
        routes=(GateRoute(path="/blog/post", price_sats=21, max_uses=1, access_seconds=None),),
    )
    lightning = Challenge(
        resource="gate:my-shop:/blog/post",
        max_uses=1,
        access_seconds=None,
        macaroon="mac",
        invoice="lnbc1ptest",
        payment_hash="ab" * 32,
        invoice_expires_at=1,
        amount_sats=21,
        www_authenticate='L402 macaroon="mac", invoice="lnbc1ptest"',
    )
    x402_only = Challenge(
        resource="gate:my-shop:/blog/post",
        max_uses=1,
        access_seconds=None,
        payment_required="e30",
        x402={"testing": True, "x402_mode": "test"},
    )
    dual = Challenge(
        resource="gate:my-shop:/blog/post",
        max_uses=1,
        access_seconds=None,
        macaroon="mac",
        invoice="lnbc1ptest",
        payment_hash="ab" * 32,
        invoice_expires_at=1,
        amount_sats=21,
        www_authenticate='L402 macaroon="mac", invoice="lnbc1ptest"',
        payment_required="e30",
        x402={"testing": True, "x402_mode": "test"},
    )
    challenges = {"lightning": lightning, "x402": x402_only, "dual": dual}
    failures = {
        "pending": CoreResult(
            action="pending",
            error="payment_pending",
            payment_hash="ab" * 32,
            retry_after=3,
        ),
        "expired": CoreResult(action="rejected", error="expired", http_status=402),
        "rejected": CoreResult(
            action="rejected",
            error="x402_rejected",
            http_status=402,
            reason="payer_mismatch",
        ),
    }
    for contact in ("abuse@example.com", ""):
        settings = _settings(abuse_contact=contact)
        for label, challenge in challenges.items():
            response = _challenge_response(
                CoreResult(action="challenge", challenge=challenge),
                None,
                site,
                "/blog/post",
                settings,
            )
            body = json.loads(response.body)
            assert response.status_code == 402, label
            assert body["error"] == "payment_required", label
            assert "receipt" not in body, label
            if contact:
                assert body["abuse_contact"] == contact, label
            else:
                assert "abuse_contact" not in body, label
            empty = _challenge_response(
                CoreResult(action="challenge", challenge=challenge),
                None,
                site,
                "/blog/post",
                _settings(abuse_contact=""),
            )
            assert _without_contact(body) == json.loads(empty.body), label
            assert _header_view(response.headers) == _header_view(empty.headers), label
        for label, result in failures.items():
            response = _failure(result, settings)
            body = json.loads(response.body)
            assert response.status_code == 402, label
            assert body["error"] == result.error, label
            assert "invoice" not in body and "receipt" not in body, label
            if result.reason:
                assert body["reason"] == result.reason, label
            if label == "pending":
                assert response.headers["retry-after"] == "3", label
                assert body["retry_after_seconds"] == 3, label
            if contact:
                assert body["abuse_contact"] == contact, label
            else:
                assert "abuse_contact" not in body, label
            bare = _failure(result, _settings(abuse_contact=""))
            assert _without_contact(body) == json.loads(bare.body), label
            assert _header_view(response.headers) == _header_view(bare.headers), label
    configured = _settings()
    negatives = (
        CoreResult(action="rejected", error="bad_signature", http_status=400),
        CoreResult(action="rejected", error="token_expired", http_status=401, reason="token_expired"),
        CoreResult(action="rejected", error="account_suspended", http_status=403),
        CoreResult(action="rejected", error="x402_in_progress", http_status=409),
        CoreResult(action="limited", error="rate_limited", retry_after=4),
        CoreResult(action="unavailable", error="paywall_unavailable"),
    )
    for result in negatives:
        response = _failure(result, configured)
        assert response.status_code != 402
        assert "abuse_contact" not in json.loads(response.body)


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
                assert body["abuse_contact"] == "abuse@example.com"
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
                assert pending.status_code == 401, pending.status_code
                assert pending.json()["error"] == "preimage_required"
                assert "abuse_contact" not in pending.json()
        finally:
            _close(core_client)

    calls: list[str] = []

    class _PendingCore(_CoreOnly):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.host != "core.test":
                raise AssertionError("gate called a non-core host")
            calls.append(request.url.path)
            if request.url.path.endswith("/receipt") and "x402" not in request.url.path:
                return httpx.Response(
                    402,
                    json={
                        "ok": False,
                        "error": "payment_pending",
                        "payment_hash": "ab" * 32,
                        "retry_after_seconds": 3,
                    },
                    headers={"Retry-After": "3"},
                )
            return await super().handle_async_request(request)

    gate_app = create_app(_settings())
    client = httpx.AsyncClient(transport=_PendingCore(module.app), base_url="http://core.test", timeout=5)
    gate_app.state.core_client = client
    try:
        with TestClient(gate_app) as http:
            challenge = http.get("/my-shop/blog/post")
            offered = challenge.json()
            waiting = http.get("/my-shop/blog/post", headers=_auth(offered["macaroon"], "00" * 32))
            assert waiting.status_code == 402
            body = waiting.json()
            assert body["error"] == "payment_pending"
            assert body["abuse_contact"] == "abuse@example.com"
            assert body["retry_after_seconds"] == 3
            assert waiting.headers["retry-after"] == "3"
            assert "invoice" not in body and "receipt" not in body
    finally:
        _close(client)


def _challenge_rows(db_path: str) -> tuple[str, ...]:
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        return tuple(
            row[0]
            for row in conn.execute("SELECT payment_hash FROM paywall_challenges ORDER BY payment_hash")
        )


def test_gate_402_contact_reaches_buyers_and_head_stays_empty(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="testclient,127.0.0.1")
    _patch_dns(monkeypatch, module)
    script = {"mode": "expired"}

    class _ScriptCore(_CoreOnly):
        def __init__(self, app) -> None:
            super().__init__(app)
            self.hosts: list[str] = []
            self.paths: list[str] = []

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.hosts.append(request.url.host)
            self.paths.append(f"{request.method} {request.url.path}")
            if request.url.host != "core.test":
                raise AssertionError("gate called a non-core host")
            path = request.url.path
            mode = script["mode"]
            if path.endswith("/x402/receipt") and mode == "expired":
                return httpx.Response(402, json={"ok": False, "error": "expired"})
            if path.endswith("/x402/receipt") and mode == "rejected":
                return httpx.Response(
                    402,
                    json={"ok": False, "error": "x402_rejected", "reason": "payer_mismatch"},
                )
            if path.endswith("/x402/receipt") and mode == "other":
                status = int(script["status"])
                return httpx.Response(status, json={"ok": False, "error": script["error"]})
            return await super().handle_async_request(request)

    with TestClient(module.app) as core:
        _prepare(core)
        transport = _ScriptCore(module.app)
        client = httpx.AsyncClient(transport=transport, base_url="http://core.test", timeout=5)
        gate = create_app(_settings())
        gate.state.core_client = client
        empty_gate = create_app(_settings(abuse_contact=""))
        empty_client = httpx.AsyncClient(transport=transport, base_url="http://core.test", timeout=5)
        empty_gate.state.core_client = empty_client
        try:
            with TestClient(gate) as http:
                buyer = {"X-Forwarded-For": "203.0.113.9"}
                challenge = http.get("/my-shop/blog/post", headers=buyer)
                assert challenge.status_code == 402
                assert challenge.json()["error"] == "payment_required"
                assert challenge.json()["abuse_contact"] == "abuse@example.com"
                offers = _challenge_rows(os.environ["SATSGATE_DB_PATH"])
                head = http.head("/my-shop/blog/post", headers=buyer)
                assert head.status_code == 402
                assert head.content == b""
                same_offer = _challenge_rows(os.environ["SATSGATE_DB_PATH"]) == offers
                assert same_offer
                assert head.headers.get("cache-control") == challenge.headers.get("cache-control")
                assert head.headers.get("link") == challenge.headers.get("link")
                assert head.headers.get("www-authenticate")
                assert challenge.headers.get("www-authenticate")
                expired = http.get("/my-shop/blog/post", headers={"PAYMENT-SIGNATURE": "c2ln"})
                assert expired.status_code == 402
                assert expired.json()["error"] == "expired"
                assert expired.json()["abuse_contact"] == "abuse@example.com"
                assert "receipt" not in expired.json()
                script["mode"] = "rejected"
                rejected = http.post("/my-shop/blog/post", headers={"PAYMENT-SIGNATURE": "c2ln"})
                assert rejected.status_code == 402
                assert rejected.json()["error"] == "x402_rejected"
                assert rejected.json()["reason"] == "payer_mismatch"
                assert rejected.json()["abuse_contact"] == "abuse@example.com"
                for status, error in (
                    (400, "bad_signature"),
                    (401, "token_expired"),
                    (403, "account_suspended"),
                    (409, "x402_in_progress"),
                    (429, "rate_limited"),
                    (502, "paywall_unavailable"),
                ):
                    script["mode"] = "other"
                    script["status"] = status
                    script["error"] = error
                    response = http.get("/my-shop/blog/post", headers={"PAYMENT-SIGNATURE": "c2ln"})
                    assert response.status_code == status
                    assert "abuse_contact" not in response.json()
            with TestClient(empty_gate) as http:
                script["mode"] = "expired"
                quiet = http.get("/my-shop/blog/post", headers={"PAYMENT-SIGNATURE": "c2ln"})
                assert quiet.status_code == 402
                assert "abuse_contact" not in quiet.json()
            assert set(transport.hosts) == {"core.test"}
        finally:
            _close(client, empty_client)


def test_challenge_http_402_stays_a_public_502(tmp_path, monkeypatch):
    """A non-200 challenge from core is not a public 402.

    ``create_challenge`` turns every non-200, including 402, into
    ``unavailable``. The public body is ``502 paywall_unavailable`` and does
    not gain ``abuse_contact``.
    """
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)

    class _Challenge402(_CoreOnly):
        def __init__(self, app) -> None:
            super().__init__(app)
            self.challenge_calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.host != "core.test":
                raise AssertionError("gate called a non-core host")
            if request.method == "POST" and request.url.path.endswith("/challenge"):
                self.challenge_calls += 1
                return httpx.Response(
                    402,
                    json={"ok": False, "error": "payment_required"},
                    headers={"Cache-Control": "no-store"},
                )
            return await super().handle_async_request(request)

    with TestClient(module.app) as core:
        _prepare(core)
        transport = _Challenge402(module.app)
        client = httpx.AsyncClient(transport=transport, base_url="http://core.test", timeout=5)
        gate = create_app(_settings())
        gate.state.core_client = client
        empty = create_app(_settings(abuse_contact=""))
        empty_client = httpx.AsyncClient(transport=transport, base_url="http://core.test", timeout=5)
        empty.state.core_client = empty_client
        try:
            with TestClient(gate) as http:
                response = http.get("/my-shop/blog/post")
                assert response.status_code == 502
                body = response.json()
                assert body["error"] == "paywall_unavailable"
                assert body["ok"] is False
                assert "abuse_contact" not in body
                assert "invoice" not in body and "receipt" not in body
                assert response.headers["cache-control"] == "no-store"
                head = http.head("/my-shop/blog/post")
                assert head.status_code == 502
                assert head.content == b""
                assert head.headers["cache-control"] == "no-store"
            with TestClient(empty) as http:
                quiet = http.get("/my-shop/blog/post")
                assert quiet.status_code == 502
                assert quiet.json()["error"] == "paywall_unavailable"
                assert "abuse_contact" not in quiet.json()
                assert quiet.headers["cache-control"] == response.headers["cache-control"]
            assert transport.challenge_calls >= 1
        finally:
            _close(client, empty_client)


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
