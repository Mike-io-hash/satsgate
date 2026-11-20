"""Local origin and core helpers for MCP route tests.

The origin listens on 127.0.0.1 only. Nothing here calls a public server.
"""

from __future__ import annotations

import importlib.util
import socket
import sqlite3
import threading
import time
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
SECRET = "origin-secret-that-is-long-enough-ok"


def load_verify():
    path = ROOT / "proxy" / "snippets" / "fastapi_verify.py"
    spec = importlib.util.spec_from_file_location("fastapi_verify_snippet", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RequireSignature:
    """Reject a request whose origin signature is missing or wrong."""

    def __init__(self, app, secret: str) -> None:
        self.app = app
        self.secret = secret
        self.verify = load_verify()

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        ok = self.verify.verify_origin_signature(
            secret=self.secret,
            header=headers.get("x-satsgate-signature", ""),
            method=scope.get("method", ""),
            target=self.verify.signed_target(scope),
            payment_hash=headers.get("x-satsgate-payment-hash", ""),
            now=int(time.time()),
            max_skew_seconds=300,
        )
        if ok:
            await self.app(scope, receive, send)
            return
        body = b'{"ok":false,"error":"bad_signature"}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class HybridCore(httpx.AsyncBaseTransport):
    """Send core calls to the in-process app and origin calls to localhost."""

    def __init__(self, core_app) -> None:
        self._core = httpx.ASGITransport(app=core_app)
        self._http = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "core.test":
            return await self._core.handle_async_request(request)
        return await self._http.handle_async_request(request)

    async def aclose(self) -> None:
        await self._core.aclose()
        await self._http.aclose()


class LocalServer:
    def __init__(self, app, port: int | None = None) -> None:
        self.port = _free_port() if port is None else port
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("local server did not start")
            time.sleep(0.05)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def challenge_count() -> int:
    with sqlite3.connect(os_db()) as conn:
        row = conn.execute("SELECT COUNT(*) FROM paywall_challenges").fetchone()
    return int(row[0])


def uses_consumed(payment_hash: str) -> int:
    with sqlite3.connect(os_db()) as conn:
        row = conn.execute(
            "SELECT uses_consumed FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()
    assert row is not None
    return int(row[0])


def os_db() -> str:
    import os

    return os.environ["SATSGATE_DB_PATH"]
