"""Remote MCP client against the real core, the real proxy, and local origins."""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3

import httpx
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from proxy_mcp_harness import SECRET, HybridCore, LocalServer, challenge_count, os_db, uses_consumed
from satsgate_mcp.buyer import Buyer
from satsgate_mcp.config import Settings
from satsgate_mcp.store import Store
from proxy_mcp_harness import _free_port
from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from test_proxy_mcp_in_band_origins import _payment_object, _rates
from test_proxy_mcp_origins import _restricted, _server
from test_satsgate_gate import _buy, _load_app, _pay
from test_satsgate_mcp import NWC
from test_x402 import _install_poster, _poster, _verify_payee

_SHAPES = ("stateless", "stateful", "legacy_stateless", "legacy_stateful")
_SIGNALS = ("in_band", "http_402")


class _DiscoverGate:
    """Answer server/discover the way a 1.x origin does, and count sessions."""

    def __init__(self, app, *, stateful: bool) -> None:
        self.app = app
        self.stateful = stateful
        self.created: set[str] = set()
        self.deletes = 0

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "DELETE":
            self.deletes += 1
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        if headers.get("mcp-method") == "server/discover":
            if self.stateful:
                message = "Bad Request: Missing session ID"
                extra = [(b"mcp-session-id", b"ignore-me")]
            else:
                message = "Bad Request: Unsupported protocol version"
                extra = []
            body = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": message}}
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        *extra,
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        async def wrapped(message):
            if message["type"] == "http.response.start":
                for key, value in message.get("headers", []):
                    if key.decode("latin-1").lower() == "mcp-session-id":
                        self.created.add(value.decode("latin-1"))
            await send(message)

        await self.app(scope, receive, wrapped)


class _Bodies:
    def __init__(self, app) -> None:
        self.app = app
        self.raw: list[bytes] = []

    async def __call__(self, scope, receive, send) -> None:
        chunks: list[bytes] = []

        async def wrapped():
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body") or b"")
            return message

        await self.app(scope, wrapped, send)
        if chunks:
            self.raw.append(b"".join(chunks))


def _origin(shape: str):
    state = {"fail": False}
    if shape == "stateless":
        return _server(state, stateless=True, json_response=True), None
    if shape == "stateful":
        return _server(state, stateless=False, json_response=False), None
    if shape == "legacy_stateless":
        gate = _DiscoverGate(_server(state, stateless=True, json_response=True), stateful=False)
        return gate, gate
    gate = _DiscoverGate(_server(state, stateless=False, json_response=False), stateful=True)
    return gate, gate


def _with_deep(shape: str):
    """Same shapes, plus a tool priced for several uses."""
    from mcp.server.mcpserver import MCPServer
    from proxy_mcp_harness import RequireSignature

    origin = MCPServer("market")

    @origin.tool()
    def echo(text: str) -> str:
        return text

    @origin.tool()
    def quote(symbol: str) -> str:
        return symbol

    @origin.tool()
    def deep(text: str) -> str:
        return text

    @origin.tool()
    def placed(region: str) -> str:
        return region

    tool = next(item for item in origin._tool_manager.list_tools() if item.name == "placed")
    tool.parameters["properties"]["region"]["x-mcp-header"] = "Region"
    stateless = shape in {"stateless", "legacy_stateless"}
    app = RequireSignature(origin.streamable_http_app(stateless_http=stateless, json_response=stateless), SECRET)
    if shape.startswith("legacy"):
        gate = _DiscoverGate(app, stateful=shape == "legacy_stateful")
        return gate, gate
    return app, None


def _route_yaml(origin_port: int, *, x402: bool, public_base: str, signal: str) -> str:
    public = f"  public_base: {public_base}\n" if public_base else ""
    x402_line = "    x402: true\n" if x402 else ""
    return (
        "core:\n"
        "  base_url: http://core.test\n"
        "  api_key_env: SATSGATE_API_KEY\n"
        "  timeout_seconds: 10\n"
        "upstream:\n"
        f"  base_url: http://127.0.0.1:{origin_port}\n"
        "  timeout_seconds: 10\n"
        "origin:\n"
        "  secret_env: SATSGATE_ORIGIN_SECRET\n"
        "server:\n"
        "  host: 127.0.0.1\n"
        "  port: 9\n"
        f"{public}"
        "routes:\n"
        "  - name: tools\n"
        "    path: /mcp\n"
        "    methods: [POST, DELETE]\n"
        "    description: Market data tools\n"
        f"{x402_line}"
        "    mcp:\n"
        f"      signal: {signal}\n"
        "      default: free\n"
        "      tools:\n"
        "        echo: free\n"
        "        placed:\n"
        "          price_sats: 5\n"
        "          access: per_request\n"
        "          description: A region lookup\n"
        "        quote:\n"
        "          price_sats: 21\n"
        "          access: per_request\n"
        "          description: One market quote\n"
        "        deep:\n"
        "          price_sats: 5\n"
        "          access: uses:10\n"
        "          description: A deeper lookup\n"
    )


class _CoreWallet:
    def __init__(self, core: TestClient) -> None:
        self.core = core
        self.invoices: list[str] = []

    async def pay_invoice(self, invoice: str) -> str:
        self.invoices.append(invoice)
        with sqlite3.connect(os_db()) as conn:
            row = conn.execute(
                "SELECT payment_hash FROM paywall_challenges WHERE invoice = ? ORDER BY rowid DESC LIMIT 1",
                (invoice,),
            ).fetchone()
        assert row is not None
        return _pay(self.core, row[0])


def _buyer(tmp_path, wallet) -> Buyer:
    return Buyer(
        Settings(
            nwc_uri=NWC,
            max_payment_sats=100,
            daily_max_sats=500,
            max_payment_usd_atomic=1_000_000,
            daily_max_usd_atomic=5_000_000,
            auto_pay=False,
            data_dir=tmp_path / "buyer",
            core_url="http://core.test",
            api_key="",
            api_key_rejected=False,
            allowlist=(),
            timeout=20.0,
            registry="",
            max_body_bytes=1_000_000,
        ),
        store=Store(tmp_path / "buyer"),
        wallet=wallet,
    )


@contextmanager
def _boot(tmp_path, monkeypatch, *, shape: str, signal: str, x402: bool = False, deep: bool = False):
    module = _load_app(tmp_path)
    app, gate = _with_deep(shape) if deep else _origin(shape)
    logged = _Bodies(app)
    origin = LocalServer(logged)
    origin.start()
    proxy = None
    calls = None
    with TestClient(module.app) as core:
        try:
            account = _buy(core)
            monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
            monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
            buyer_key = None
            public = ""
            port = None
            if x402:
                from eth_account import Account

                _rates(module)
                owner = Account.create()
                buyer_key = Account.create()
                _verify_payee(core, account, owner)
                calls, post = _poster(buyer_key)
                _install_poster(post)
                port = _free_port()
                public = f"http://127.0.0.1:{port}"
            path = tmp_path / "proxy.yaml"
            path.write_text(
                _route_yaml(origin.port, x402=x402, public_base=public, signal=signal),
                encoding="utf-8",
            )
            settings = load_settings(path)
            proxy = LocalServer(build_app(settings, transport=HybridCore(module.app)), port=port)
            proxy.start()
            yield SimpleNamespace(
                url=f"http://127.0.0.1:{proxy.port}/mcp",
                core=core,
                module=module,
                gate=gate,
                calls=calls,
                buyer_key=buyer_key,
                bodies=logged.raw,
            )
        finally:
            if proxy is not None:
                proxy.stop()
            origin.stop()


def _texts(payload: dict) -> list[str]:
    found = []
    for block in payload.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            found.append(block.get("text"))
    return found


@pytest.mark.parametrize("shape", _SHAPES)
@pytest.mark.parametrize("signal", _SIGNALS)
def test_rc_11_1_a_free_tool_pays_nothing(tmp_path, monkeypatch, shape: str, signal: str) -> None:
    with _boot(tmp_path, monkeypatch, shape=shape, signal=signal) as env:
        before = challenge_count()
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)
        result = asyncio.run(buyer.remote_call_tool(env.url, "echo", {"text": "hi"}))
        assert result.payload["ok"] is True
        assert _texts(result.payload) == ["hi"]
        assert challenge_count() == before
        assert wallet.invoices == []


@pytest.mark.parametrize("shape", _SHAPES)
@pytest.mark.parametrize("signal", _SIGNALS)
def test_rc_11_2_a_priced_tool_pays_once(tmp_path, monkeypatch, shape: str, signal: str) -> None:
    with _boot(tmp_path, monkeypatch, shape=shape, signal=signal, deep=True) as env:
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)
        result = asyncio.run(buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}, mode="nwc"))
        assert result.payload["ok"] is True
        assert _texts(result.payload) == ["acme"]
        assert wallet.invoices and len(wallet.invoices) == 1
        token = buyer.store.token_for("mcp " + json.dumps([env.url, "quote"], separators=(",", ":")))
        assert token["resource"] == "route:tools:quote"
        assert uses_consumed(token["payment_hash"]) == 1


def test_rc_11_3_human_lud21_goes_pending_then_settled(tmp_path, monkeypatch) -> None:
    state = {"value": "pending"}
    with _boot(tmp_path, monkeypatch, shape="stateless", signal="in_band", deep=True) as env:
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)
        offer = asyncio.run(buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}))
        payment_hash = offer.payload["payment_hash"]
        with sqlite3.connect(os_db()) as conn:
            conn.execute(
                "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
                ("https://verify.invalid/pay", payment_hash),
            )
            conn.commit()
        monkeypatch.setattr(env.module, "_paywall_lud21", lambda **_kw: state["value"])
        before = challenge_count()
        pending = asyncio.run(buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}))
        assert pending.payload["error"] == "payment_pending"
        state["value"] = "settled"
        done = asyncio.run(buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}))
        assert done.payload["ok"] is True
        assert _texts(done.payload) == ["acme"]
        assert challenge_count() == before
        assert uses_consumed(payment_hash) == 1
        assert wallet.invoices == []


def test_rc_11_4_human_without_lud21_needs_the_preimage(tmp_path, monkeypatch) -> None:
    with _boot(tmp_path, monkeypatch, shape="stateless", signal="in_band", deep=True) as env:
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)
        offer = asyncio.run(buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}))
        payment_hash = offer.payload["payment_hash"]
        before = challenge_count()
        _pay(env.core, payment_hash)
        result = asyncio.run(buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}))
        assert result.payload["error"] == "preimage_required"
        assert challenge_count() == before
        assert wallet.invoices == []


@pytest.mark.parametrize("signal", _SIGNALS)
def test_rc_11_5_parallel_calls_share_one_unlock(tmp_path, monkeypatch, signal: str) -> None:
    with _boot(tmp_path, monkeypatch, shape="stateless", signal=signal, deep=True) as env:
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)

        async def run():
            return await asyncio.gather(
                buyer.remote_call_tool(env.url, "deep", {"text": "a"}, mode="nwc"),
                buyer.remote_call_tool(env.url, "deep", {"text": "b"}, mode="nwc"),
                buyer.remote_call_tool(env.url, "deep", {"text": "c"}, mode="nwc"),
            )

        results = asyncio.run(run())
        assert [item.payload["ok"] for item in results] == [True, True, True]
        assert len(wallet.invoices) == 1
        payment_hash = buyer.store.token_for("mcp " + json.dumps([env.url, "deep"], separators=(",", ":")))["payment_hash"]
        assert uses_consumed(payment_hash) == 3


def test_rc_11_6_param_header_reaches_the_origin(tmp_path, monkeypatch) -> None:
    with _boot(tmp_path, monkeypatch, shape="stateless", signal="in_band", deep=True) as env:
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)
        result = asyncio.run(buyer.remote_call_tool(env.url, "placed", {"region": "west"}, mode="nwc"))
        assert result.payload["ok"] is True
        assert result.payload.get("error") != "rpc_error"
        assert "32020" not in json.dumps(result.payload)
        assert _texts(result.payload) == ["west"]
        token = buyer.store.token_for("mcp " + json.dumps([env.url, "placed"], separators=(",", ":")))
        assert uses_consumed(token["payment_hash"]) == 1


class _Capture(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.inner = httpx.AsyncHTTPTransport()
        self.bodies: list[bytes] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        body = await response.aread()
        self.bodies.append(body)
        return httpx.Response(response.status_code, headers=response.headers, content=body)


def _notice_from(bodies: list[bytes]) -> dict:
    for raw in bodies:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        result = parsed.get("result") if isinstance(parsed, dict) else None
        structured = result.get("structuredContent") if isinstance(result, dict) else None
        if isinstance(structured, dict) and structured.get("error") == "payment_required":
            return structured
    raise AssertionError("no price notice was captured")


def test_rc_11_7_x402_payment_is_inside_the_call(tmp_path, monkeypatch) -> None:
    with _boot(tmp_path, monkeypatch, shape="stateless", signal="in_band", x402=True, deep=True) as env:
        wallet = _CoreWallet(env.core)
        buyer = _buyer(tmp_path, wallet)
        capture = _Capture()
        buyer._transport = capture

        async def once():
            offer = await buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"})
            notice = _notice_from(capture.bodies)
            payment = _payment_object(notice, env.buyer_key)
            signature = base64.standard_b64encode(json.dumps(payment).encode()).decode("ascii")
            result = await buyer.remote_call_tool(env.url, "quote", {"symbol": "acme"}, payment_signature=signature)
            return offer, result

        offer, result = asyncio.run(once())
        assert offer.payload.get("x402", {}).get("payable") is True, offer.payload
        assert result.payload["ok"] is True, result.payload
        assert result.payload["payment_response"]["success"] is True
        assert buyer.store.spent_usd_since(0) > 0
        assert sum(url.endswith("/settle") for url, _body in env.calls) == 1
        assert all(b"x402/payment" not in raw for raw in env.bodies)
        assert wallet.invoices == []


def test_rc_11_8_legacy_sessions_are_closed(tmp_path, monkeypatch) -> None:
    for shape in ("legacy_stateless", "legacy_stateful"):
        with _boot(tmp_path / shape, monkeypatch, shape=shape, signal="in_band") as env:
            wallet = _CoreWallet(env.core)
            buyer = _buyer(tmp_path / shape, wallet)
            result = asyncio.run(buyer.remote_call_tool(env.url, "echo", {"text": "hi"}))
            assert result.payload["ok"] is True
            if shape == "legacy_stateful":
                assert len(env.gate.created) == env.gate.deletes
                assert env.gate.deletes >= 1
            else:
                assert env.gate.deletes == 0
                assert env.gate.created == set()
