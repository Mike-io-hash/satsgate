"""Hosted gate: charge the site owner, sign the origin, and refuse private targets."""

from __future__ import annotations

import asyncio
import importlib
import ipaddress
import os
import socket
import sqlite3
import sys
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from satsgate_gate.app import create_app, parse_public_path
from satsgate_gate.config import Settings
from satsgate_gate.core_client import FRESH_REASONS, MERCHANT_ERRORS
from satsgate_gate.origin import sign_origin
from satsgate_gate.ssrf import SSRFError, guard_url, is_public_ip, pinned_host, pinned_ip
from satsgate_proxy.core_client import FRESH_REASONS as PROXY_FRESH
from satsgate_proxy.core_client import MERCHANT_ERRORS as PROXY_MERCHANT
from satsgate_proxy.origin import sign_origin as proxy_sign
from satsgate_proxy.origin import verify_origin_signature

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
        "SATSGATE_BUYER_CHALLENGE_MAX": "100",
        "SATSGATE_BUYER_MAX_OPEN_CHALLENGES": "100",
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
        name = str(host).lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            chosen = name
        except ValueError:
            chosen = "1.1.1.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (chosen, port))]

    monkeypatch.setattr(module.ssrf.socket, "getaddrinfo", fake)


class Resolver:
    def __init__(self) -> None:
        self.answers: dict[str, str | list[str] | None] = {"*": "1.1.1.1"}

    def __call__(self, host, port, family=0, socktype=0, proto=0, flags=0):
        name = str(host).lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            chosen = name
        except ValueError:
            chosen = self.answers.get(name, self.answers["*"])
        if chosen is None:
            raise socket.gaierror(8, "no address")
        if isinstance(chosen, list):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in chosen]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (chosen, port))]


def _settings(**overrides) -> Settings:
    values = dict(
        core_base_url="http://core.test",
        gate_token=_GATE_TOKEN,
        trusted_proxies="testclient",
        cache_seconds=30,
        core_timeout=5,
        upstream_timeout=2,
        max_request_bytes=1024,
        max_response_bytes=128,
        rl_window_seconds=60,
        rl_per_site=0,
        rl_per_buyer=0,
        pending_retry_after=2,
        resolver=Resolver(),
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


def _account(http: TestClient, *, credits: bool) -> str:
    if credits:
        return _buy(http)
    module = importlib.import_module("app.main")
    key, _client = module.db.create_client(module.config.DB_PATH)
    return key


def _prepare(http: TestClient, *, credits: bool = True, max_uses: int | None = 1, access_seconds: int | None = None):
    key = _account(http, credits=credits)
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
    route_body = {"path": "/blog/post", "price_sats": 21, "max_uses": max_uses, "access_seconds": access_seconds}
    route = http.post("/v1/sites/my-shop/routes", headers={"X-Api-Key": key}, json=route_body)
    assert route.status_code == 200, route.text
    root = http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": key},
        json={"path": "/", "price_sats": 5, "max_uses": 1},
    )
    assert root.status_code == 200, root.text
    approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
    assert approved.status_code == 200, approved.text
    return key, created.json()["origin_secret"]


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


def _open_gate(core_app, settings: Settings, origin: Origin):
    core_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=core_app),
        base_url=settings.core_base_url,
        timeout=httpx.Timeout(5),
    )
    origin_client = httpx.AsyncClient(transport=httpx.MockTransport(origin), timeout=httpx.Timeout(5))
    gate = create_app(settings)
    gate.state.core_client = core_client
    gate.state.origin_client = origin_client
    return TestClient(gate), core_client, origin_client


def _close(*clients) -> None:
    async def _aclose():
        for client in clients:
            await client.aclose()

    asyncio.run(_aclose())


def test_signature_matches_the_proxy_and_public_paths():
    assert FRESH_REASONS == PROXY_FRESH
    assert MERCHANT_ERRORS == PROXY_MERCHANT
    secret = "ab" * 32
    kwargs = dict(secret=secret, timestamp=1_700_000_000, method="get", target="/blog/post?x=1", payment_hash="AB" * 32)
    assert sign_origin(**kwargs) == proxy_sign(**kwargs)
    assert verify_origin_signature(
        secret=secret,
        header=sign_origin(**kwargs),
        method="GET",
        target="/blog/post?x=1",
        payment_hash="ab" * 32,
        now=1_700_000_000,
        max_skew_seconds=30,
    )
    assert parse_public_path("/my-shop") == ("my-shop", "/")
    assert parse_public_path("/my-shop/") == ("my-shop", "/")
    assert parse_public_path("/my-shop/blog/post") == ("my-shop", "/blog/post")
    assert parse_public_path("/my-shop/../secret") is None


def test_ssrf_rejects_private_targets_and_pins_the_resolved_ip():
    from app.ssrf import is_public_ip as core_public

    samples = [
        "1.1.1.1",
        "8.8.8.8",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.255",
        "::1",
        "fc00::1",
        "fe80::1",
        "0.0.0.0",
        "255.255.255.255",
        "203.0.113.1",
        "224.0.0.1",
        "2001:db8::1",
    ]
    for sample in samples:
        assert is_public_ip(sample) is core_public(sample)

    resolver = Resolver()
    assert guard_url("https://origin.example/blog", resolver=resolver).ip == "1.1.1.1"
    resolver.answers["mixed.example"] = ["1.1.1.1", "10.0.0.8"]
    rejected = [
        "http://origin.example/a",
        "https://user:pass@origin.example/a",
        "https://127.0.0.1/",
        "https://10.0.0.1/",
        "https://192.168.1.1/",
        "https://169.254.169.254/",
        "https://100.64.0.1/",
        "https://[::1]/",
        "https://[fc00::1]/",
        "https://localhost/",
        "https://metadata.google.internal/",
        "https://mixed.example/",
        "https://2130706433/",
        "https://0177.0.0.1/",
        "https://0x7f000001/",
    ]
    for url in rejected:
        with pytest.raises(SSRFError):
            guard_url(url, resolver=resolver)

    seen: list[str] = []

    class Inner:
        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            seen.append(host)
            return object()

        async def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise AssertionError("unix")

        async def sleep(self, seconds: float) -> None:
            return None

    from satsgate_gate.ssrf import PinnedAsyncBackend

    backend = PinnedAsyncBackend(inner=Inner())

    async def _run():
        ip = pinned_ip.set("1.1.1.1")
        host = pinned_host.set("origin.example")
        try:
            await backend.connect_tcp("origin.example", 443)
            with pytest.raises(SSRFError):
                await backend.connect_tcp("rebind.example", 443)
            pinned_ip.set("10.0.0.1")
            with pytest.raises(SSRFError):
                await backend.connect_tcp("origin.example", 443)
        finally:
            pinned_ip.reset(ip)
            pinned_host.reset(host)

    asyncio.run(_run())
    assert seen == ["1.1.1.1"]


def test_unknown_pending_and_disabled_are_404(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()
    settings = _settings()
    with TestClient(module.app) as core:
        key, _secret = _prepare(core)
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                assert http.get("/healthz").json() == {"ok": True, "component": "satsgate-gate", "version": "0.11.0"}
                missing = http.get("/no-such/blog")
                assert missing.status_code == 404
                assert missing.json()["error"] == "not_found"
                core.post("/v1/admin/sites/my-shop/disable", headers={"X-Admin-Token": "test-admin-token"})
                disabled = http.get("/my-shop/blog/post")
                assert disabled.status_code == 404
                created = core.post(
                    "/v1/sites",
                    headers={"X-Api-Key": key},
                    json={"slug": "other-shop", "display_name": "Other", "origin_url": "https://origin.example"},
                )
                assert created.status_code == 200, created.text
                pending = http.get("/other-shop/blog/post")
                assert pending.status_code == 404
                assert pending.json() == disabled.json()
                assert origin.requests == []
        finally:
            _close(core_client, origin_client)


def test_paid_request_is_signed_and_strips_buyer_credentials(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()
    origin.responder = lambda request: httpx.Response(
        200,
        content=b"paid-body",
        headers={"cache-control": "public, max-age=60", "location": "https://evil.example", "x-powered-by": "secret"},
    )
    settings = _settings()
    with TestClient(module.app) as core:
        _key, secret = _prepare(core, max_uses=1)
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                first = http.get(
                    "/my-shop/blog/post?x=1",
                    headers={
                        "X-Satsgate-Buyer-Ip": "198.51.100.8",
                        "X-Satsgate-Signature": "t=1, v1=" + "ab" * 32,
                        "X-Forwarded-For": "203.0.113.50",
                        "Connection": "x-evil",
                        "X-Evil": "1",
                        "Authorization": "Bearer buyer-token",
                    },
                )
                assert first.status_code == 402, first.text
                body = first.json()
                assert body["amount_sats"] == 21
                assert body["max_uses"] == 1
                assert body["resource"] == "gate:my-shop:/blog/post"
                assert first.headers["www-authenticate"].startswith('L402 macaroon="')
                assert "invoice=" in first.headers["www-authenticate"]
                preimage = _pay(core, body["payment_hash"])
                paid = http.get(
                    "/my-shop/blog/post?x=1",
                    headers={
                        **_auth(body["macaroon"], preimage),
                        "X-Satsgate-Buyer-Ip": "198.51.100.8",
                        "X-Satsgate-Signature": "t=1, v1=" + "ab" * 32,
                        "X-Forwarded-For": "203.0.113.50",
                        "Connection": "x-evil",
                        "X-Evil": "1",
                    },
                )
                assert paid.status_code == 200, paid.text
                assert paid.content == b"paid-body"
                assert paid.headers["cache-control"] == "no-store"
                assert "location" not in paid.headers
                assert "x-powered-by" not in paid.headers
                assert len(origin.requests) == 1
                forwarded = origin.requests[0]
                assert forwarded.url.path == "/blog/post"
                assert forwarded.url.query == b"x=1"
                names = {key.lower() for key in forwarded.headers}
                assert "authorization" not in names
                assert "x-satsgate-buyer-ip" not in names
                assert "x-evil" not in names
                assert forwarded.headers["x-satsgate-payment-hash"] == body["payment_hash"]
                assert forwarded.headers["x-satsgate-resource"] == "gate:my-shop:/blog/post"
                assert forwarded.headers["x-satsgate-paid-sats"] == "21"
                assert verify_origin_signature(
                    secret=secret,
                    header=forwarded.headers["x-satsgate-signature"],
                    method="GET",
                    target="/blog/post?x=1",
                    payment_hash=body["payment_hash"],
                    now=int(forwarded.headers["x-satsgate-signature"].split(",", 1)[0][2:]),
                    max_skew_seconds=30,
                )
                again = http.get("/my-shop/blog/post?x=1", headers=_auth(body["macaroon"], preimage))
                assert again.status_code == 402, again.text
                assert again.json()["reason"] == "token_used_up"
                assert again.json()["payment_hash"] != body["payment_hash"]
                assert len(origin.requests) == 1
        finally:
            _close(core_client, origin_client)


def test_macaroon_only_poll_then_forwards(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    from app.invoices import InvoiceValidationError

    state = {"settled": False}

    def confirm_lud21(**_kwargs):
        if not state["settled"]:
            raise InvoiceValidationError("lud21_not_settled")

    monkeypatch.setattr(module.wallet_lnaddr, "confirm_lud21", confirm_lud21)
    origin = Origin()
    settings = _settings()
    with TestClient(module.app) as core:
        _prepare(core, max_uses=1)
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                challenge = http.get("/my-shop/blog/post")
                assert challenge.status_code == 402, challenge.text
                body = challenge.json()
                with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                    conn.execute(
                        "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
                        ("https://verify.example/v", body["payment_hash"]),
                    )
                pending = http.get("/my-shop/blog/post", headers=_auth(body["macaroon"]))
                assert pending.status_code == 402, pending.text
                assert pending.json()["error"] == "payment_pending"
                assert pending.json()["payment_hash"] == body["payment_hash"]
                assert "invoice" not in pending.json()
                assert origin.requests == []
                state["settled"] = True
                done = http.get("/my-shop/blog/post", headers=_auth(body["macaroon"]))
                assert done.status_code == 200, done.text
                assert done.content == b"origin-ok"
                assert len(origin.requests) == 1
        finally:
            _close(core_client, origin_client)


def test_owner_without_credits_does_not_call_the_origin(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()
    settings = _settings()
    with TestClient(module.app) as core:
        _prepare(core, credits=False, max_uses=1)
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                challenge = http.get("/my-shop/blog/post")
                assert challenge.status_code == 402, challenge.text
                body = challenge.json()
                preimage = _pay(core, body["payment_hash"])
                blocked = http.get("/my-shop/blog/post", headers=_auth(body["macaroon"], preimage))
                assert blocked.status_code == 502, blocked.text
                assert blocked.json()["error"] == "paywall_unavailable"
                assert origin.requests == []
        finally:
            _close(core_client, origin_client)


def test_disable_drops_a_warm_cache(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()
    seen: list[str] = []

    async def hook(request: httpx.Request) -> None:
        seen.append(request.url.path)

    settings = _settings(cache_seconds=30)
    with TestClient(module.app) as core:
        _prepare(core)
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        core_client.event_hooks["request"].append(hook)
        try:
            with gate as http:
                warm = http.get("/my-shop/blog/post")
                assert warm.status_code == 402, warm.text
                assert seen.count("/internal/gate/sites/my-shop") == 1
                core.post("/v1/admin/sites/my-shop/disable", headers={"X-Admin-Token": "test-admin-token"})
                blocked = http.get("/my-shop/blog/post")
                assert blocked.status_code == 404
                assert seen.count("/internal/gate/sites/my-shop") == 1
                assert origin.requests == []
        finally:
            _close(core_client, origin_client)


def test_buyer_rate_limit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()
    settings = _settings(rl_per_buyer=2)
    with TestClient(module.app) as core:
        _prepare(core)
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                limited = [http.get("/my-shop/blog/post", headers={"X-Forwarded-For": "203.0.113.7"}) for _ in range(3)]
                assert [item.status_code for item in limited] == [402, 402, 429]
                assert limited[2].headers["retry-after"]
                assert origin.requests == []
        finally:
            _close(core_client, origin_client)

    site_settings = _settings(rl_per_site=2)
    origin = Origin()
    gate, core_client, origin_client = _open_gate(module.app, site_settings, origin)
    try:
        with gate as http:
            # Distinct buyer addresses, one site budget.
            statuses = []
            for last in (1, 2, 3):
                response = http.get("/my-shop/blog/post", headers={"X-Forwarded-For": f"203.0.113.{last}"})
                statuses.append(response.status_code)
            assert statuses == [402, 402, 429]
    finally:
        _close(core_client, origin_client)


def test_limits_redirect_timeout_and_rebinding(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    origin = Origin()

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/redirect"):
            return httpx.Response(302, headers={"location": "https://evil.example/steal"})
        if request.url.path.endswith("/slow"):
            raise httpx.ReadTimeout("slow")
        if request.url.path.endswith("/big"):
            return httpx.Response(200, content=b"x" * 200)
        return httpx.Response(200, content=b"ok")

    origin.responder = respond
    settings = _settings(max_response_bytes=64)
    with TestClient(module.app) as core:
        key = _account(core, credits=True)
        core.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        created = core.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example"},
        )
        assert created.status_code == 200, created.text
        secret = created.json()["origin_secret"]
        for path in ("/redirect", "/slow", "/big", "/ok"):
            added = core.post(
                "/v1/sites/my-shop/routes",
                headers={"X-Api-Key": key},
                json={"path": path, "price_sats": 21, "max_uses": 1},
            )
            assert added.status_code == 200, added.text
        assert core.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"}).status_code == 200
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                def paid_get(path: str):
                    challenge = http.get(path, headers={"X-Forwarded-For": "203.0.113.8"})
                    assert challenge.status_code == 402, challenge.text
                    preimage = _pay(core, challenge.json()["payment_hash"])
                    return http.get(path, headers={**_auth(challenge.json()["macaroon"], preimage), "X-Forwarded-For": "203.0.113.8"})

                redirected = paid_get("/my-shop/redirect")
                assert redirected.status_code == 502
                assert redirected.json()["error"] == "upstream_redirect"
                assert redirected.json()["use_spent"] is True
                assert "location" not in redirected.headers

                slow = paid_get("/my-shop/slow")
                assert slow.status_code == 504
                assert slow.json()["error"] == "upstream_timeout"
                assert slow.json()["use_spent"] is True

                big = paid_get("/my-shop/big")
                assert big.status_code == 502
                assert big.json()["error"] == "upstream_response_too_large"
                assert big.content != b"x" * 200

                calls = len(origin.requests)
                settings.resolver.answers["origin.example"] = "10.1.2.3"
                rebound = paid_get("/my-shop/ok")
                assert rebound.status_code == 502, rebound.text
                assert rebound.json()["error"] == "upstream_unavailable"
                assert rebound.json()["use_spent"] is True
                assert len(origin.requests) == calls
                assert secret
        finally:
            _close(core_client, origin_client)


def test_open_grant_is_not_cached(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    bodies = iter([b"one", b"two"])
    origin = Origin()
    origin.responder = lambda request: httpx.Response(
        200,
        content=next(bodies),
        headers={"cache-control": "public, max-age=999"},
    )
    settings = _settings()
    with TestClient(module.app) as core:
        key = _account(core, credits=True)
        assert core.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        ).status_code == 200
        created = core.post(
            "/v1/sites",
            headers={"X-Api-Key": key},
            json={"slug": "my-shop", "display_name": "My Shop", "origin_url": "https://origin.example"},
        )
        assert created.status_code == 200, created.text
        added = core.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/open", "price_sats": 21},
        )
        assert added.status_code == 200, added.text
        assert core.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"}).status_code == 200
        gate, core_client, origin_client = _open_gate(module.app, settings, origin)
        try:
            with gate as http:
                challenge = http.get("/my-shop/open")
                assert challenge.status_code == 402, challenge.text
                body = challenge.json()
                assert body["max_uses"] is None
                assert body["access_seconds"] is None
                preimage = _pay(core, body["payment_hash"])
                headers = _auth(body["macaroon"], preimage)
                first = http.get("/my-shop/open", headers=headers)
                second = http.get("/my-shop/open", headers=headers)
                assert first.status_code == 200, first.text
                assert second.status_code == 200, second.text
                assert first.content == b"one"
                assert second.content == b"two"
                assert first.headers["cache-control"] == "no-store"
                assert second.headers["cache-control"] == "no-store"
                assert len(origin.requests) == 2
        finally:
            _close(core_client, origin_client)


def test_compose_passes_site_env_and_keeps_the_gate_private():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    core_env = compose["services"]["satsgate"]["environment"]
    for name in (
        "SATSGATE_SITE_SECRET_KEY",
        "SATSGATE_SITES_AUTO_APPROVE",
        "SATSGATE_SITES_MAX_PER_ACCOUNT",
        "SATSGATE_SITES_MAX_ROUTES",
        "SATSGATE_GATE_PUBLIC_BASE",
        "SATSGATE_GATE_TOKEN",
        "SATSGATE_GATE_PEERS",
    ):
        assert name in core_env
    assert "172.28.0.4" in core_env["SATSGATE_TRUSTED_PROXIES"]
    assert core_env["SATSGATE_FORWARDED_ALLOW_IPS"] == "${SATSGATE_FORWARDED_ALLOW_IPS:-172.28.0.2}"
    gate = compose["services"]["gate"]
    assert "ports" not in gate
    assert gate["networks"]["internal"]["ipv4_address"] == "172.28.0.4"
    assert gate["environment"]["SATSGATE_GATE_CORE_URL"] == "http://satsgate:8000"
    assert "SATSGATE_GATE_TOKEN" in gate["environment"]
    caddy = (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert "handle /internal/*" in caddy
    live = [line for line in caddy.splitlines() if "header_up -X-Satsgate-Buyer-Ip" in line and not line.strip().startswith("#")]
    commented = [line for line in caddy.splitlines() if "header_up -X-Satsgate-Buyer-Ip" in line and line.strip().startswith("#")]
    assert len(live) == 1
    assert len(commented) == 1
    assert not any(line.strip().startswith("gate.satsgate.org") for line in caddy.splitlines())
    assert "# gate.satsgate.org {" in caddy
