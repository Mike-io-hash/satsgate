"""satsgate-proxy: config, origin HMAC, and an end-to-end fake core plus origin."""

from __future__ import annotations

import importlib.util
import json
import logging
import textwrap
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from starlette.testclient import TestClient

from app.client_ip import resolve_client_ip as core_resolve_client_ip
from app.l402 import make_macaroon
from satsgate_proxy import __version__
from satsgate_proxy.app import build_app
from satsgate_proxy.client_ip import buyer_ip_for_core
from satsgate_proxy.client_ip import resolve_client_ip as proxy_resolve_client_ip
from satsgate_proxy.config import ConfigError, key_fingerprint, load_settings
from satsgate_proxy.match import compile_glob
from satsgate_proxy.origin import origin_message, request_target, sign_origin, verify_origin_signature

ROOT = Path(__file__).resolve().parents[1]
SECRET = "origin-secret-that-is-long-enough-ok"
KEY = "sgr_testkeyvalue"
PREIMAGE = "cd" * 32
PAYMENT = "ab" * 32

YAML = textwrap.dedent(
    """\
    core:
      base_url: http://core.test
      api_key_env: SATSGATE_API_KEY
      timeout_seconds: 5
    upstream:
      base_url: http://upstream.test
      timeout_seconds: 5
    origin:
      secret_env: SATSGATE_ORIGIN_SECRET
      max_skew_seconds: 300
    pricing:
      sats_per_credit: 5
    server:
      host: 127.0.0.1
      port: 8080
      pending_retry_after_seconds: 2
    limits:
      max_request_bytes: 1024
      max_response_bytes: 128
    free_paths:
      - /health
    routes:
      - name: article
        methods: [GET, POST]
        path: /blog/**
        price_sats: 100
        access: per_request
        scope: route
        description: Read an article
    """
)


def _snippet(name: str):
    path = ROOT / "proxy" / "snippets" / name
    spec = importlib.util.spec_from_file_location(name.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "proxy.yaml"
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")
    return path


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str = YAML, **env: str):
    monkeypatch.setenv("SATSGATE_API_KEY", env.get("api_key", KEY))
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", env.get("secret", SECRET))
    if "upstream_authorization" in env:
        monkeypatch.setenv("UPSTREAM_AUTHORIZATION", env["upstream_authorization"])
    return load_settings(_write(tmp_path, text))


class World(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.unlock = "settled"
        self.upstream = "ok"
        self.challenge = "ok"
        self.omit_www = False
        self.core_calls: list[dict] = []
        self.up_calls: list[dict] = []
        self.challenge_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "core.test":
            return self._core(request)
        return self._upstream(request)

    def _snap(self, request: httpx.Request) -> dict:
        body = request.content
        parsed = None
        if body:
            try:
                parsed = json.loads(body.decode())
            except json.JSONDecodeError:
                parsed = body
        return {
            "method": request.method,
            "path": request.url.path,
            "raw_path": request.url.raw_path.decode(),
            "query": request.url.query.decode(),
            "headers": {key.lower(): value for key, value in request.headers.items()},
            "body": parsed,
        }

    def _core(self, request: httpx.Request) -> httpx.Response:
        snap = self._snap(request)
        self.core_calls.append(snap)
        if request.url.path.endswith("/challenge"):
            return self._challenge(snap)
        if request.url.path.endswith("/charge"):
            return self._unlock(snap)
        if request.url.path.endswith("/verify") or "/status/" in request.url.path:
            return self._unlock(snap)
        return httpx.Response(500, json={"ok": False, "error": "unexpected"})

    def _challenge(self, snap: dict) -> httpx.Response:
        if self.challenge == "limited":
            return httpx.Response(
                429,
                json={"ok": False, "error": "buyer_rate_limited", "retry_after_seconds": 12},
                headers={"retry-after": "12"},
            )
        if self.challenge == "revoked":
            return httpx.Response(401, json={"ok": False, "error": "api_key_revoked"})
        self.challenge_count += 1
        payment_hash = f"{self.challenge_count:064x}"
        macaroon = "bWFjYXJvb24"
        invoice = "lnbc1testinvoice"
        payload = {
            "ok": True,
            "macaroon": macaroon,
            "invoice": invoice,
            "payment_hash": payment_hash,
            "invoice_expires_at": 1893456000,
            "amount_sats": snap["body"]["amount_sats"],
            "resource": snap["body"]["resource"],
        }
        if not self.omit_www:
            payload["www_authenticate"] = f'L402 macaroon="{macaroon}", invoice="{invoice}"'
        body = snap["body"] if isinstance(snap["body"], dict) else {}
        if body.get("x402"):
            mode = body.get("x402_mode") or "test"
            network = "eip155:8453" if mode == "live" else "eip155:84532"
            asset = (
                "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
                if mode == "live"
                else "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            )
            payload["payment_required"] = "dGVzdA"
            payload["x402"] = {
                "scheme": "exact",
                "network": network,
                "asset": asset,
                "amount": "10000",
                "payTo": "0x1111111111111111111111111111111111111111",
                "testing": mode == "test",
                "x402_mode": mode,
            }
        return httpx.Response(200, json=payload)

    def _unlock(self, snap: dict) -> httpx.Response:
        if self.unlock == "pending":
            return httpx.Response(
                402,
                json={"ok": False, "error": "payment_pending", "status": "pending", "payment_hash": PAYMENT},
                headers={"retry-after": "7"},
            )
        if self.unlock == "status_pending":
            return httpx.Response(
                200,
                json={"ok": True, "status": "pending", "settled": False, "payment_hash": PAYMENT},
            )
        if self.unlock == "used_up":
            return httpx.Response(401, json={"ok": False, "error": "token_used_up"})
        if self.unlock == "expired":
            return httpx.Response(401, json={"ok": False, "error": "token_expired"})
        if self.unlock == "mismatch":
            return httpx.Response(401, json={"ok": False, "error": "resource mismatch"})
        if self.unlock == "revoked":
            return httpx.Response(401, json={"ok": False, "error": "api_key_revoked"})
        return httpx.Response(
            200,
            json={
                "ok": True,
                "status": "settled",
                "settled": True,
                "payment_hash": PAYMENT,
                "amount_sats": 100,
            },
        )

    def _upstream(self, request: httpx.Request) -> httpx.Response:
        self.up_calls.append(self._snap(request))
        if self.upstream == "timeout":
            raise httpx.ReadTimeout("GET http://secret-upstream.internal/blog")
        if self.upstream == "down":
            raise httpx.ConnectError("secret-upstream.internal")
        if self.upstream == "redirect":
            return httpx.Response(302, headers={"location": "http://secret-upstream.internal/hidden"})
        if self.upstream == "huge":
            return httpx.Response(200, content=b"Z" * 400, headers={"content-type": "text/plain"})
        if self.upstream == "error":
            return httpx.Response(
                500,
                content=b"nope",
                headers={"server": "secret-upstream", "content-type": "text/plain", "x-powered-by": "secret"},
            )
        return httpx.Response(
            200,
            content=b"origin-ok",
            headers={"content-type": "text/plain", "server": "secret-upstream", "x-powered-by": "secret"},
        )


def _client(settings, world: World, peer: tuple[str, int] = ("testclient", 50000)) -> TestClient:
    return TestClient(build_app(settings, transport=world), client=peer)


def _macaroon(resource: str, payment_hash: str = PAYMENT) -> str:
    return make_macaroon(
        secret="test-secret",
        kid="k1",
        purpose="paywall",
        payment_hash=payment_hash,
        resource=resource,
        amount_sats=100,
        invoice="lnbc1test",
        ttl_seconds=3600,
        client_id=1,
        payee="payee@example.com",
    )


def test_example_config_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = (ROOT / "proxy" / "satsgate-proxy.example.yaml").read_text(encoding="utf-8")
    settings = _load(tmp_path, monkeypatch, text)
    assert settings.core_base_url == "https://api.satsgate.org"
    assert settings.upstream_base_url == "http://api:8080"
    assert settings.host == "0.0.0.0"
    assert [route.resource for route in settings.routes] == ["route:article", "route:search", "route:hour"]
    assert settings.warnings == ()


def test_versions() -> None:
    assert __version__ == "0.13.0"
    assert 'APP_VERSION = "0.16.0"' in (ROOT / "app" / "config.py").read_text(encoding="utf-8")
    compose = (ROOT / "proxy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert f"image: satsgate-proxy:{__version__}" in compose
    assert "satsgate-proxy:0.8.0" not in compose


def test_startup_fingerprint_is_not_any_part_of_the_api_key() -> None:
    key = "sgr_SUPERSECRETvalue_not_a_hex_prefix"
    fingerprint = key_fingerprint(key)
    assert fingerprint == key_fingerprint(key)
    assert fingerprint != key_fingerprint(key + "x")
    assert len(fingerprint) == 12
    assert set(fingerprint) <= set("0123456789abcdef")
    assert key not in fingerprint
    assert key[:8] not in fingerprint
    assert "SUPERSECRET" not in fingerprint
    assert "sgr_" not in fingerprint


def test_globs() -> None:
    blog = compile_glob("/blog/**")
    assert blog.fullmatch("/blog")
    assert blog.fullmatch("/blog/")
    assert blog.fullmatch("/blog/a/b")
    assert not blog.fullmatch("/blogger")
    one = compile_glob("/files/*")
    assert one.fullmatch("/files/a")
    assert not one.fullmatch("/files")
    assert not one.fullmatch("/files/a/b")
    assert compile_glob("/**").fullmatch("/a/b")
    assert compile_glob("/exact").fullmatch("/exact")
    with pytest.raises(Exception):
        compile_glob("relative")
    with pytest.raises(Exception):
        compile_glob("/a/**/b")


def test_origin_vector_matches_snippets() -> None:
    snippet = _snippet("fastapi_verify.py")
    target = "/blog/post?file=a%20b"
    header = sign_origin(
        secret=SECRET,
        timestamp=1_700_000_000,
        method="get",
        target=target,
        payment_hash="AB" * 32,
    )
    kwargs = {
        "secret": SECRET,
        "header": header,
        "method": "GET",
        "target": target,
        "payment_hash": PAYMENT.upper(),
        "now": 1_700_000_000,
        "max_skew_seconds": 300,
    }
    assert verify_origin_signature(**kwargs)
    assert snippet.verify_origin_signature(**kwargs)
    assert not verify_origin_signature(**{**kwargs, "target": "/blog/other"})
    assert not verify_origin_signature(**{**kwargs, "now": 1_700_000_000 + 301})
    message = origin_message(timestamp=1_700_000_000, method="GET", target=target, payment_hash=PAYMENT)
    assert snippet.origin_message(timestamp=1_700_000_000, method="GET", target=target, payment_hash=PAYMENT) == message
    scope = {"raw_path": b"/blog/post", "query_string": b"file=a%20b"}
    assert request_target(scope) == snippet.signed_target(scope) == target

    node = __import__("shutil").which("node")
    assert node
    script = """
const express = require(%r);
const nginx = require(%r);
const header = process.argv[1];
const opts = {secret: process.argv[2], header, method: "GET", target: process.argv[3], paymentHash: process.argv[4], now: 1700000000, maxSkewSeconds: 300};
if (!express.verifyOriginSignature(opts) || !nginx.verifyOriginSignature(opts)) process.exit(2);
if (express.originMessage(1700000000, "GET", process.argv[3], process.argv[4]) !== process.argv[5]) process.exit(3);
""" % (
        str(ROOT / "proxy" / "snippets" / "express_verify.js"),
        str(ROOT / "proxy" / "snippets" / "nginx_verify.js"),
    )
    import subprocess

    completed = subprocess.run(
        [node, "-e", script, header, SECRET, target, PAYMENT, message],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_buyer_ip_matches_core() -> None:
    cases = [
        ("203.0.113.10", None, ""),
        ("203.0.113.10", "198.51.100.4", ""),
        ("10.0.0.1", "198.51.100.4", "10.0.0.1"),
        ("10.0.0.1", "10.0.0.1, 198.51.100.4", "10.0.0.0/8"),
        ("testclient", "198.51.100.4", "testclient"),
        ("testclient", None, ""),
    ]
    for peer, forwarded, trusted in cases:
        assert core_resolve_client_ip(peer=peer, forwarded_for=forwarded, trusted_proxies=trusted) == proxy_resolve_client_ip(
            peer=peer, forwarded_for=forwarded, trusted_proxies=trusted
        )
    assert buyer_ip_for_core(peer="testclient", forwarded_for=None, trusted_proxies="") is None
    assert buyer_ip_for_core(peer="203.0.113.10", forwarded_for="198.51.100.4", trusted_proxies="") == "203.0.113.10"


def test_cheap_per_request_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    text = YAML.replace("price_sats: 100", "price_sats: 21")
    caplog.set_level(logging.WARNING, logger="satsgate_proxy")
    settings = _load(tmp_path, monkeypatch, text)
    assert any("Cheap calls should use" in item for item in settings.warnings)
    assert "Cheap calls should use" in caplog.text
    assert SECRET not in caplog.text
    assert KEY not in caplog.text


def test_bundle_does_not_warn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    text = YAML.replace("price_sats: 100", "price_sats: 21").replace("access: per_request", "access: uses:20")
    caplog.set_level(logging.WARNING, logger="satsgate_proxy")
    settings = _load(tmp_path, monkeypatch, text)
    assert settings.warnings == ()
    assert "Cheap calls" not in caplog.text


def test_config_rejects_secrets_and_typos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
    path = _write(tmp_path, YAML)
    monkeypatch.setenv("SATSGATE_API_KEY", "sg_supersecretvalue")
    with pytest.raises(ConfigError) as exc:
        load_settings(path)
    assert "supersecret" not in str(exc.value)

    monkeypatch.setenv("SATSGATE_API_KEY", KEY)
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", "short-secret")
    with pytest.raises(ConfigError) as exc:
        load_settings(path)
    assert "short-secret" not in str(exc.value)

    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
    bad = YAML + "\nroutess: []\n"
    with pytest.raises(ConfigError, match="unknown"):
        load_settings(_write(tmp_path, bad))
    userinfo = YAML.replace("http://upstream.test", "http://user:pass@upstream.test")
    with pytest.raises(ConfigError, match="userinfo"):
        load_settings(_write(tmp_path, userinfo))
    both = YAML.replace("path: /blog/**", "path: /blog/**\n    path_regex: '^/x$'")
    with pytest.raises(ConfigError, match="exactly one"):
        load_settings(_write(tmp_path, both))
    site = YAML + (
        "  - name: other\n"
        "    methods: [GET]\n"
        "    path: /other\n"
        "    price_sats: 80\n"
        "    access: per_request\n"
        "    scope: site\n"
        "  - name: more\n"
        "    methods: [GET]\n"
        "    path: /more\n"
        "    price_sats: 90\n"
        "    access: per_request\n"
        "    scope: site\n"
    )
    with pytest.raises(ConfigError, match="site-scoped"):
        load_settings(_write(tmp_path, site))
    monkeypatch.delenv("SATSGATE_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="SATSGATE_API_KEY"):
        load_settings(path)


def test_settings_repr_hides_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = YAML.replace(
        "upstream:\n  base_url: http://upstream.test\n  timeout_seconds: 5",
        "upstream:\n  base_url: http://upstream.test\n  timeout_seconds: 5\n"
        "  inject_headers:\n    - name: Authorization\n      value_env: UPSTREAM_AUTHORIZATION",
    )
    settings = _load(tmp_path, monkeypatch, text, upstream_authorization="upstream-credential-should-not-leak")
    rendered = repr(settings)
    assert "upstream-credential-should-not-leak" not in rendered
    assert KEY not in rendered
    assert SECRET not in rendered


def test_health_and_free_and_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {"ok": True, "component": "satsgate-proxy", "version": "0.13.0"}
        assert client.head("/healthz").status_code == 200
        free = client.get("/health", headers={"Authorization": "Bearer keep-me", "X-Satsgate-Payment-Hash": "forged"})
        missing = client.get("/nope")
        wrong = client.put("/blog/post")
    assert health.status_code == 200
    assert world.core_calls == []
    assert free.status_code == 200
    assert free.text == "origin-ok"
    assert world.up_calls[0]["headers"]["authorization"] == "Bearer keep-me"
    assert "x-satsgate-payment-hash" not in world.up_calls[0]["headers"]
    assert "server" not in {key.lower() for key in free.headers}
    assert missing.status_code == 404
    assert missing.json()["error"] == "not_found"
    assert wrong.status_code == 405
    assert wrong.headers["allow"] == "GET, POST"


def test_unpaid_402_and_buyer_ip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world, peer=("203.0.113.10", 50000)) as client:
        response = client.get(
            "/blog/post?file=a%20b",
            headers={"X-Satsgate-Buyer-Ip": "198.51.100.9", "X-Forwarded-For": "198.51.100.8"},
        )
    assert response.status_code == 402
    header = response.headers["www-authenticate"]
    assert header.startswith('L402 macaroon="')
    assert header.index("macaroon=") < header.index("invoice=")
    body = response.json()
    assert body["amount_sats"] == 100
    assert body["max_uses"] == 1
    assert body["access_seconds"] is None
    assert body["payment_hash"]
    assert body["invoice_expires_at"] == 1893456000
    assert "preimage" in body["hint"]
    assert "no preimage" in body["hint"] or "does not return a preimage" in body["hint"]
    assert world.up_calls == []
    challenge = world.core_calls[0]
    assert challenge["body"]["resource"] == "route:article"
    assert challenge["body"]["max_uses"] == 1
    assert challenge["body"]["memo"] == "Read an article"
    assert "access_seconds" not in challenge["body"]
    assert challenge["headers"]["x-satsgate-buyer-ip"] == "203.0.113.10"
    assert challenge["headers"]["x-api-key"] == KEY


def test_trusted_proxy_uses_forwarded_for(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = YAML.replace("port: 8080", "port: 8080\n  trusted_proxies: [testclient]")
    world = World()
    settings = _load(tmp_path, monkeypatch, text)
    with _client(settings, world) as client:
        response = client.get("/blog/a", headers={"X-Forwarded-For": "198.51.100.20"})
    assert response.status_code == 402
    assert world.core_calls[0]["headers"]["x-satsgate-buyer-ip"] == "198.51.100.20"


def test_untrusted_testclient_omits_buyer_ip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world) as client:
        client.get("/blog/a", headers={"X-Forwarded-For": "198.51.100.20", "X-Satsgate-Buyer-Ip": "198.51.100.9"})
    assert "x-satsgate-buyer-ip" not in world.core_calls[0]["headers"]


def test_paid_preimage_forwards_and_signs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    text = YAML.replace(
        "upstream:\n  base_url: http://upstream.test\n  timeout_seconds: 5",
        "upstream:\n  base_url: http://upstream.test\n  timeout_seconds: 5\n"
        "  inject_headers:\n    - name: Authorization\n      value_env: UPSTREAM_AUTHORIZATION",
    )
    credential = "upstream-credential-should-not-leak"
    world = World()
    settings = _load(tmp_path, monkeypatch, text, upstream_authorization=credential)
    caplog.set_level(logging.DEBUG, logger="satsgate_proxy")
    mac = _macaroon("route:article")
    with _client(settings, world) as client:
        response = client.post(
            "/blog/post?file=a%20b",
            content=b'{"q":1}',
            headers={
                "Authorization": f"L402 {mac}:{PREIMAGE}",
                "X-Satsgate-Signature": "t=1, v1=" + "ab" * 32,
                "X-Satsgate-Payment-Hash": "ff" * 32,
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 200
    assert response.text == "origin-ok"
    assert "secret-upstream" not in response.text
    assert "server" not in response.headers
    assert "x-powered-by" not in response.headers
    verify = world.core_calls[0]
    assert verify["path"].endswith("/verify")
    assert verify["body"]["consume"] is True
    assert verify["body"]["charge"] is False
    assert verify["body"]["expected_resource"] == "route:article"
    assert world.core_calls[1]["path"].endswith("/charge")
    assert verify["headers"]["authorization"] == f"L402 {mac}:{PREIMAGE}"
    upstream = world.up_calls[0]
    assert upstream["raw_path"] == "/blog/post?file=a%20b"
    assert upstream["body"] == {"q": 1}
    assert upstream["headers"]["authorization"] == credential
    assert upstream["headers"]["x-satsgate-payment-hash"] == PAYMENT
    assert upstream["headers"]["x-satsgate-resource"] == "route:article"
    assert upstream["headers"]["x-satsgate-paid-sats"] == "100"
    assert upstream["headers"]["accept-encoding"] == "identity"
    assert credential not in caplog.text
    snippet = _snippet("fastapi_verify.py")
    assert snippet.verify_origin_signature(
        secret=SECRET,
        header=upstream["headers"]["x-satsgate-signature"],
        method="POST",
        target="/blog/post?file=a%20b",
        payment_hash=PAYMENT,
        now=int(upstream["headers"]["x-satsgate-signature"].split(",", 1)[0].split("=", 1)[1]),
        max_skew_seconds=300,
    )


def test_lsat_and_mac_only_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    settings = _load(tmp_path, monkeypatch)
    mac = _macaroon("route:article")
    with _client(settings, world) as client:
        lsat = client.get("/blog/a", headers={"Authorization": f"LSAT {mac}:{PREIMAGE}"})
        world.unlock = "status_pending"
        pending = client.get("/blog/a", headers={"Authorization": f"L402 {mac}"})
        world.unlock = "settled"
        paid = client.get("/blog/a", headers={"Authorization": f"L402 {mac}"})
    assert lsat.status_code == 200
    assert world.core_calls[0]["headers"]["authorization"].startswith("LSAT ")
    assert pending.status_code == 402
    assert pending.json()["error"] == "payment_pending"
    assert "www-authenticate" not in pending.headers
    assert pending.headers["retry-after"] == "2"
    assert pending.json()["hint"]
    status_call = next(call for call in world.core_calls if "/status/" in call["path"])
    assert ":" not in status_call["headers"]["authorization"].split(" ", 1)[1]
    query = parse_qs(status_call["query"])
    assert query["consume"] == ["true"]
    assert query["charge"] == ["false"]
    assert query["expected_resource"] == ["route:article"]
    assert paid.status_code == 200
    assert len(world.up_calls) == 2


def test_used_up_and_wrong_route_are_fresh_402(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    world.unlock = "used_up"
    settings = _load(tmp_path, monkeypatch)
    mac = _macaroon("route:article")
    other = _macaroon("route:other")
    with _client(settings, world) as client:
        used = client.get("/blog/a", headers={"Authorization": f"L402 {mac}:{PREIMAGE}"})
        calls_after_used = len(world.core_calls)
        wrong = client.get("/blog/a", headers={"Authorization": f"L402 {other}:{PREIMAGE}"})
    assert used.status_code == 402
    assert used.json()["error"] == "payment_required"
    assert used.json()["reason"] == "token_used_up"
    assert used.json()["payment_hash"] != PAYMENT
    assert "www-authenticate" in used.headers
    assert calls_after_used == 2
    assert world.core_calls[0]["path"].endswith("/verify")
    assert world.core_calls[1]["path"].endswith("/challenge")
    assert wrong.status_code == 402
    assert wrong.json()["reason"] == "resource mismatch"
    assert all(not call["path"].endswith("/verify") for call in world.core_calls[calls_after_used:])
    assert world.up_calls == []


def test_pending_does_not_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    world.unlock = "pending"
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world) as client:
        response = client.get("/blog/a", headers={"Authorization": f"L402 not-a-real-macaroon:{PREIMAGE}"})
    assert response.status_code == 402
    assert response.json()["error"] == "payment_pending"
    assert response.json()["payment_hash"] == PAYMENT
    assert response.headers["retry-after"] == "7"
    assert "www-authenticate" not in response.headers
    assert len(world.core_calls) == 1
    assert world.up_calls == []


def test_oversize_request_does_not_call_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world) as client:
        response = client.post("/blog/a", content=b"x" * 2000)
    assert response.status_code == 413
    assert response.json()["error"] == "request_too_large"
    assert world.core_calls == []
    assert world.up_calls == []


def test_upstream_failures_spend_the_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _load(tmp_path, monkeypatch)
    mac = _macaroon("route:article")
    header = {"Authorization": f"L402 {mac}:{PREIMAGE}"}
    world = World()
    world.upstream = "timeout"
    with _client(settings, world) as client:
        timeout = client.get("/blog/a", headers=header)
    assert timeout.status_code == 504
    assert timeout.json()["error"] == "upstream_timeout"
    assert timeout.json()["use_spent"] is False
    assert "note" not in timeout.json()
    assert "secret-upstream" not in timeout.text
    assert len(world.core_calls) == 1

    world = World()
    world.upstream = "down"
    with _client(settings, world) as client:
        down = client.get("/blog/a", headers=header)
    assert down.status_code == 502
    assert down.json()["error"] == "upstream_unavailable"
    assert down.json()["use_spent"] is False
    assert "secret-upstream" not in down.text

    world = World()
    world.upstream = "redirect"
    with _client(settings, world) as client:
        redirect = client.get("/blog/a", headers=header)
    assert redirect.status_code == 502
    assert redirect.json()["error"] == "upstream_redirect"
    assert "location" not in redirect.headers
    assert "secret-upstream" not in redirect.text
    assert redirect.json()["use_spent"] is False

    world = World()
    world.upstream = "huge"
    with _client(settings, world) as client:
        huge = client.get("/blog/a", headers=header)
    assert huge.status_code == 502
    assert huge.json()["error"] == "upstream_response_too_large"
    assert "Z" * 20 not in huge.text
    assert huge.json()["use_spent"] is False

    world = World()
    world.upstream = "error"
    with _client(settings, world) as client:
        error = client.get("/blog/a", headers=header)
    assert error.status_code == 500
    assert error.text == "nope"
    assert "server" not in error.headers
    assert "x-powered-by" not in error.headers
    assert len(world.core_calls) == 1


def test_core_limit_and_merchant_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    world.challenge = "limited"
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world) as client:
        limited = client.get("/blog/a")
    assert limited.status_code == 429
    assert limited.json()["error"] == "buyer_rate_limited"
    assert limited.headers["retry-after"] == "12"
    assert "www-authenticate" not in limited.headers

    world = World()
    world.challenge = "revoked"
    with _client(settings, world) as client:
        revoked = client.get("/blog/a")
    assert revoked.status_code == 502
    assert revoked.json() == {"ok": False, "error": "paywall_unavailable"}
    assert "api_key_revoked" not in revoked.text


def test_access_modes_and_regex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = YAML + (
        "  - name: search\n"
        "    methods: [GET]\n"
        "    path: /search\n"
        "    price_sats: 21\n"
        "    access: uses:20\n"
        "    scope: route\n"
        "  - name: hour\n"
        "    methods: [POST]\n"
        "    path_regex: \"^/v1/[0-9]+$\"\n"
        "    price_sats: 50\n"
        "    access: pass:3600\n"
        "    scope: site\n"
        "  - name: siteb\n"
        "    methods: [GET]\n"
        "    path: /site\n"
        "    price_sats: 50\n"
        "    access: pass:3600\n"
        "    scope: site\n"
    )
    world = World()
    settings = _load(tmp_path, monkeypatch, text)
    with _client(settings, world) as client:
        client.get("/search")
        client.post("/v1/9")
        client.get("/site")
    bodies = [call["body"] for call in world.core_calls]
    assert bodies[0]["max_uses"] == 20
    assert "access_seconds" not in bodies[0]
    assert bodies[1]["access_seconds"] == 3600
    assert bodies[1]["resource"] == "site"
    assert "max_uses" not in bodies[1]
    assert bodies[2]["resource"] == "site"


def test_built_www_authenticate_when_core_omits_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World()
    world.omit_www = True
    settings = _load(tmp_path, monkeypatch)
    with _client(settings, world) as client:
        response = client.get("/blog/a")
    header = response.headers["www-authenticate"]
    assert header == 'L402 macaroon="bWFjYXJvb24", invoice="lnbc1testinvoice"'


def test_x402_mode_is_exclusive_and_defaults_to_test(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = YAML.replace(
        "    description: Read an article\n",
        "    description: Read an article\n    x402_mode: test\n",
    )
    with pytest.raises(ConfigError, match="x402_mode requires x402: true"):
        _load(tmp_path, monkeypatch, missing)
    bad = YAML.replace(
        "    description: Read an article\n",
        "    description: Read an article\n    x402: true\n    x402_mode: both\n",
    ).replace("port: 8080\n", "port: 8080\n  public_base: https://api.example.com\n")
    with pytest.raises(ConfigError, match="x402_mode must be test or live"):
        _load(tmp_path, monkeypatch, bad)

    implied = YAML.replace(
        "    description: Read an article\n",
        "    description: Read an article\n    x402: true\n",
    ).replace("port: 8080\n", "port: 8080\n  public_base: https://api.example.com\n")
    settings = _load(tmp_path, monkeypatch, implied)
    assert settings.routes[0].x402 is True
    assert settings.routes[0].x402_mode == "test"

    live = implied.replace("x402: true\n", "x402: true\n    x402_mode: live\n")
    settings = _load(tmp_path, monkeypatch, live)
    assert settings.routes[0].x402_mode == "live"
    world = World()
    with _client(settings, world) as client:
        response = client.get("/blog/a")
    assert response.status_code == 402
    body = response.json()
    assert body["x402"]["network"] == "eip155:8453"
    assert body["testing"] is False
    assert body["x402_mode"] == "live"
    sent = world.core_calls[0]["body"]
    assert sent["x402"] is True
    assert sent["x402_mode"] == "live"
    assert sent["resource_url"] == "https://api.example.com/blog/a"
