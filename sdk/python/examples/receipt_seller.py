"""Demo seller. Two sites can share one process on separate path prefixes.

SATSGATE_DEMO_SITES=/live=x402-test,/test=demo-test
SATSGATE_SITE_SECRET_X402_TEST and SATSGATE_SITE_SECRET_DEMO_TEST
SATSGATE_DEMO_ROUTES=/report

A single site at the root still uses SATSGATE_SITE and SATSGATE_SITE_SECRET.
Secrets come from the environment and are not logged.
"""

from __future__ import annotations

import json
import os

from satsgate_sdk.receipts import MemoryReceiptStore, SatsgateReceiptMiddleware, SqliteReceiptStore


def _routes() -> tuple[str, ...]:
    raw = os.environ.get("SATSGATE_DEMO_ROUTES", "/report")
    paths = tuple(part.strip() for part in raw.split(",") if part.strip())
    return paths or ("/report",)


def _sites() -> list[tuple[str, str, str]]:
    raw = os.environ.get("SATSGATE_DEMO_SITES", "").strip()
    if not raw:
        site = os.environ.get("SATSGATE_SITE", "").strip()
        secret = os.environ.get("SATSGATE_SITE_SECRET", "")
        if not site or not secret:
            raise RuntimeError("Set SATSGATE_DEMO_SITES or SATSGATE_SITE and SATSGATE_SITE_SECRET")
        return [("", site, secret)]
    found: list[tuple[str, str, str]] = []
    for part in raw.split(","):
        prefix, _, site = part.strip().partition("=")
        if not prefix.startswith("/") or not site:
            raise RuntimeError("SATSGATE_DEMO_SITES entries look like /live=x402-test")
        env = "SATSGATE_SITE_SECRET_" + site.upper().replace("-", "_")
        secret = os.environ.get(env, "")
        if not secret:
            raise RuntimeError(f"{env} is unset")
        found.append((prefix, site, secret))
    return found


def _inner(routes: tuple[str, ...]):
    async def app(scope, receive, send):
        del receive
        if scope.get("type") != "http":
            return
        path = scope.get("satsgate_route") or scope.get("path") or "/"
        state = scope.get("state") or {}
        receipt = state.get("satsgate_receipt") if isinstance(state, dict) else getattr(state, "satsgate_receipt", None)
        if path not in routes:
            body = b'{"ok":false,"error":"not_found"}'
            status = 404
        else:
            body = json.dumps({"ok": True, "path": path, "site": None if receipt is None else receipt.site}).encode()
            status = 200
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app


def build_app():
    routes = _routes()
    sites = _sites()
    store_path = os.environ.get("SATSGATE_RECEIPT_STORE", "")
    store = SqliteReceiptStore(store_path) if store_path else MemoryReceiptStore()
    gate_base = os.environ.get("SATSGATE_GATE_PUBLIC_BASE", "https://gate.satsgate.org")
    inner = _inner(routes)
    wrapped = [
        SatsgateReceiptMiddleware(
            inner,
            site=site,
            secret=secret,
            store=store,
            protected=routes,
            gate_base=gate_base,
            mount_prefix=prefix,
        )
        for prefix, site, secret in sites
    ]

    async def app(scope, receive, send):
        path = scope.get("path") or "/"
        for middleware in wrapped:
            prefix = middleware.mount_prefix
            if not prefix or path == prefix or path.startswith(prefix + "/"):
                await middleware(scope, receive, send)
                return
        body = b'{"ok":false,"error":"not_found"}'
        await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    return app


def _placeholder():
    async def app(scope, receive, send):
        del scope, receive
        body = b'{"ok":false,"error":"not_configured"}'
        await send({"type": "http.response.start", "status": 503, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    return app


app = build_app() if os.environ.get("SATSGATE_DEMO_SITES") or os.environ.get("SATSGATE_SITE") else _placeholder()
