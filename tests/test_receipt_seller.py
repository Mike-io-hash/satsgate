"""Demo seller keeps a spent receipt spent after the process is rebuilt."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))
sys.path.insert(0, str(ROOT / "sdk" / "python" / "examples"))

from satsgate_sdk.receipts import verify_receipt  # noqa: E402


def _sign(secret: str, *, aud: str) -> str:
    import base64
    import hashlib
    import hmac

    now = int(time.time())
    claims = {
        "amt": {"sats": 21},
        "aud": aud,
        "exp": now + 3600,
        "iat": now - 5,
        "iss": "https://gate.satsgate.org",
        "jti": "rcp_" + ("live" if aud == "x402-test" else "test") + "a" * 18,
        "ph": "ab" * 32,
        "rail": "lightning",
        "res": f"gate:{aud}:/report",
        "sub": "/report",
        "uses": 1,
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


def _call(app, path: str, token: str) -> tuple[int, dict]:
    status: dict = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            status["code"] = message["status"]
        elif message["type"] == "http.response.body":
            status["body"] = message.get("body") or b""

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


def test_demo_seller_use_survives_a_new_process(tmp_path, monkeypatch):
    live = "ab" * 32
    test = "cd" * 32
    monkeypatch.setenv("SATSGATE_DEMO_SITES", "/live=x402-test,/test=demo-test")
    monkeypatch.setenv("SATSGATE_DEMO_ROUTES", "/report")
    monkeypatch.setenv("SATSGATE_SITE_SECRET_X402_TEST", live)
    monkeypatch.setenv("SATSGATE_SITE_SECRET_DEMO_TEST", test)
    monkeypatch.setenv("SATSGATE_RECEIPT_STORE", str(tmp_path / "receipts.sqlite3"))
    monkeypatch.setenv("SATSGATE_GATE_PUBLIC_BASE", "https://gate.satsgate.org")
    spec = importlib.util.spec_from_file_location(
        "receipt_seller_under_test",
        ROOT / "sdk" / "python" / "examples" / "receipt_seller.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    token = _sign(live, aud="x402-test")
    other = _sign(test, aud="demo-test")
    app = module.build_app()
    code, body = _call(app, "/live/report", token)
    assert code == 200, body
    code, body = _call(app, "/test/report", token)
    assert code == 401, body
    assert body["error"] == "receipt_wrong_site"
    code, body = _call(app, "/live/report", other)
    assert code == 401, body
    assert body["error"] == "receipt_wrong_site"
    rebuilt = module.build_app()
    code, body = _call(rebuilt, "/live/report", token)
    assert code == 401, body
    assert body["error"] == "receipt_used_up"
    checked = verify_receipt(token, secret=live, site="x402-test", path="/report")
    assert checked.uses == 1
