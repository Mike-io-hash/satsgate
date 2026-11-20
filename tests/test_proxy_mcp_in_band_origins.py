"""In-band MCP notices against a real origin and the real core."""

from __future__ import annotations

import asyncio
import base64
import json
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from proxy_mcp_harness import HybridCore, LocalServer, _free_port, challenge_count, uses_consumed
from satsgate_proxy.app import build_app
from test_proxy_mcp_origins import _post, _restricted, _rpc, _server, _settings
from test_rates import _use
from test_satsgate_gate import _buy, _load_app, _pay
from test_x402 import _install_poster, _payload, _poster, _verify_payee


class _BodyLog:
    """Record each HTTP body that reaches the origin."""

    def __init__(self, app) -> None:
        self.app = app
        self.bodies: list[bytes] = []

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []

        async def wrapped():
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body") or b"")
                if not message.get("more_body"):
                    self.bodies.append(b"".join(chunks))
                    chunks.clear()
            return message

        await self.app(scope, wrapped, send)


def _quote_call(raw: bytes) -> bool:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict) or parsed.get("method") != "tools/call":
        return False
    params = parsed.get("params")
    return isinstance(params, dict) and params.get("name") == "quote"


def _tool_texts(response: httpx.Response) -> list[str]:
    media = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    messages: list[object] = []
    if media == "application/json":
        messages.append(response.json())
    else:
        text = response.text.replace("\r\n", "\n")
        for block in text.split("\n\n"):
            data = [line[5:].lstrip() for line in block.split("\n") if line.startswith("data:")]
            if data:
                messages.append(json.loads("\n".join(data)))
    found: list[str] = []
    for message in messages:
        result = message.get("result") if isinstance(message, dict) else None
        if not isinstance(result, dict):
            continue
        for block in result.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                found.append(block["text"])
    return found


def _rates(module) -> None:
    _use(module, {source.name: "65000" for source in module.rates._SOURCES})


@contextmanager
def _boot(tmp_path, monkeypatch, *, shape: str, x402: bool, signal: str):
    module = _load_app(tmp_path)
    state = {"fail": False}
    logged = _BodyLog(_server(state, stateless=shape != "stateful", json_response=shape == "stateless"))
    origin = LocalServer(logged)
    origin.start()
    proxy = None
    calls = None
    with TestClient(module.app) as core:
        try:
            account = _buy(core)
            monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
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
            settings = _settings(
                tmp_path,
                monkeypatch,
                origin.port,
                x402=x402,
                public_base=public,
                signal=signal,
            )
            proxy = LocalServer(build_app(settings, transport=HybridCore(module.app)), port=port)
            proxy.start()
            yield SimpleNamespace(
                url=f"http://127.0.0.1:{proxy.port}/mcp",
                core=core,
                account=account,
                log=logged,
                calls=calls,
                buyer_key=buyer_key,
                module=module,
            )
        finally:
            if proxy is not None:
                proxy.stop()
            origin.stop()


def _session(buyer: httpx.Client, url: str) -> dict[str, str]:
    opened = _post(
        buyer,
        url,
        _rpc(
            "initialize",
            {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}},
        ),
        {"MCP-Protocol-Version": "2025-11-25"},
    )
    assert opened.status_code == 200, opened.text
    extra = {"MCP-Protocol-Version": "2025-11-25"}
    session = opened.headers.get("mcp-session-id")
    if session:
        extra["Mcp-Session-Id"] = session
    noted = _post(buyer, url, b'{"jsonrpc":"2.0","method":"notifications/initialized"}', extra)
    assert noted.status_code in {200, 202}, noted.text
    return extra


def _modern_quote(ident: int) -> tuple[bytes, dict[str, str]]:
    body = {
        "jsonrpc": "2.0",
        "id": ident,
        "method": "tools/call",
        "params": {
            "name": "quote",
            "arguments": {"symbol": "acme"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    headers = {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "quote",
    }
    return json.dumps(body).encode("utf-8"), headers


def _payment_object(notice: dict, account) -> dict:
    document = {
        "x402Version": notice["x402Version"],
        "resource": notice["resource"],
        "accepts": notice["accepts"],
    }
    encoded = base64.standard_b64encode(
        json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")
    signature = _payload(encoded, account, notice["x402"]["expires_at"])
    return json.loads(base64.b64decode(signature))


@pytest.mark.parametrize("shape", ["stateful", "stateless"])
def test_ib_5_1_official_client_reads_the_notice(tmp_path, monkeypatch, shape: str) -> None:
    from mcp import Client

    with _boot(tmp_path, monkeypatch, shape=shape, x402=False, signal="in_band") as env:
        before = challenge_count()

        async def once():
            async with Client(env.url) as client:
                return await client.call_tool("quote", {"symbol": "acme"})

        result = asyncio.run(once())
        assert result.is_error is True
        assert result.structured_content["tool"] == "quote"
        assert result.structured_content["lightning"]["resource"] == "route:tools:quote"
        assert challenge_count() == before + 1
        assert not any(_quote_call(body) for body in env.log.bodies)


@pytest.mark.parametrize("shape", ["stateful", "stateless", "modern"])
def test_ib_5_2_lightning_payment_returns_the_tool_result(tmp_path, monkeypatch, shape: str) -> None:
    with _boot(tmp_path, monkeypatch, shape=shape, x402=False, signal="in_band") as env:
        with httpx.Client(timeout=20) as buyer:
            if shape == "modern":
                raw, extra = _modern_quote(4)
            else:
                extra = _session(buyer, env.url)
                raw = _rpc("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, ident=4)
            unpaid = _post(buyer, env.url, raw, extra)
            assert unpaid.status_code == 200, unpaid.text
            notice = unpaid.json()["result"]["structuredContent"]
            assert notice["error"] == "payment_required"
            assert notice["tool"] == "quote"
            assert unpaid.json()["result"]["isError"] is True
            preimage = _pay(env.core, notice["lightning"]["payment_hash"])
            paid = dict(extra)
            paid["Authorization"] = f"L402 {notice['lightning']['macaroon']}:{preimage}"
            served = _post(buyer, env.url, raw, paid)
        assert served.status_code == 200, served.text
        assert _tool_texts(served) == ["acme"]
        assert uses_consumed(notice["lightning"]["payment_hash"]) == 1


@pytest.mark.parametrize("shape", ["stateless", "stateful"])
def test_ib_5_3_meta_payment_settles_after_the_tool(tmp_path, monkeypatch, shape: str) -> None:
    with _boot(tmp_path, monkeypatch, shape=shape, x402=True, signal="in_band") as env:
        with httpx.Client(timeout=20) as buyer:
            extra = _session(buyer, env.url)
            raw = _rpc("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, ident=4)
            unpaid = _post(buyer, env.url, raw, extra)
            assert unpaid.status_code == 200, unpaid.text
            notice = unpaid.json()["result"]["structuredContent"]
            payment = _payment_object(notice, env.buyer_key)
            body = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "quote",
                    "arguments": {"symbol": "acme"},
                    "_meta": {"x402/payment": payment},
                },
            }
            served = _post(buyer, env.url, json.dumps(body).encode("utf-8"), extra)
        assert served.status_code == 200, served.text
        assert served.headers["content-type"].split(";", 1)[0] == "application/json"
        settlement = served.json()["result"]["_meta"]["x402/payment-response"]
        assert settlement["success"] is True
        assert settlement["network"] == notice["x402"]["network"]
        assert sum(url.endswith("/settle") for url, _body in env.calls) == 1
        assert sum(url.endswith("/verify") for url, _body in env.calls) == 1
        assert all(b"x402/payment" not in raw_body for raw_body in env.log.bodies)
        assert any(_quote_call(raw_body) for raw_body in env.log.bodies)


def test_ib_5_4_replay_does_not_call_the_origin(tmp_path, monkeypatch) -> None:
    with _boot(tmp_path, monkeypatch, shape="stateless", x402=True, signal="in_band") as env:
        with httpx.Client(timeout=20) as buyer:
            extra = _session(buyer, env.url)
            raw = _rpc("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, ident=4)
            unpaid = _post(buyer, env.url, raw, extra)
            notice = unpaid.json()["result"]["structuredContent"]
            payment = _payment_object(notice, env.buyer_key)
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "quote",
                        "arguments": {"symbol": "acme"},
                        "_meta": {"x402/payment": payment},
                    },
                }
            ).encode("utf-8")
            first = _post(buyer, env.url, body, extra)
            assert first.status_code == 200, first.text
            seen = len(env.log.bodies)
            replay = _post(buyer, env.url, body, extra)
        assert replay.status_code == 200, replay.text
        assert replay.json()["result"]["isError"] is True
        assert replay.json()["result"]["structuredContent"]["error"] == "x402_replay"
        assert replay.json()["result"]["structuredContent"]["tool"] == "quote"
        assert len(env.log.bodies) == seen
        assert sum(url.endswith("/settle") for url, _body in env.calls) == 1


def test_ib_5_5_payment_for_one_tool_does_not_open_another(tmp_path, monkeypatch) -> None:
    with _boot(tmp_path, monkeypatch, shape="stateless", x402=True, signal="in_band") as env:
        with httpx.Client(timeout=20) as buyer:
            extra = {"MCP-Protocol-Version": "2025-11-25"}
            unpaid = _post(
                buyer,
                env.url,
                _rpc("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, ident=4),
                extra,
            )
            notice = unpaid.json()["result"]["structuredContent"]
            payment = _payment_object(notice, env.buyer_key)
            seen = len(env.log.bodies)
            wrong = _post(
                buyer,
                env.url,
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {"name": "fail", "arguments": {"text": "x"}, "_meta": {"x402/payment": payment}},
                    }
                ).encode("utf-8"),
                extra,
            )
        assert wrong.status_code == 200, wrong.text
        structured = wrong.json()["result"]["structuredContent"]
        assert wrong.json()["result"]["isError"] is True
        assert structured["tool"] == "fail"
        assert structured["error"] == "paywall_unavailable"
        assert "lightning" not in structured
        assert len(env.log.bodies) == seen
        assert sum(url.endswith("/settle") for url, _body in env.calls) == 0


def test_ib_5_6_http_402_route_raises_for_the_official_client(tmp_path, monkeypatch) -> None:
    from mcp import Client
    from mcp.shared.exceptions import MCPError

    with _boot(tmp_path, monkeypatch, shape="stateless", x402=False, signal="http_402") as env:

        async def once():
            async with Client(env.url) as client:
                await client.call_tool("quote", {"symbol": "acme"})

        with pytest.raises(ExceptionGroup) as caught:
            asyncio.run(once())
        errors = []

        def walk(exc: BaseException) -> None:
            if isinstance(exc, BaseExceptionGroup):
                for item in exc.exceptions:
                    walk(item)
                return
            errors.append(exc)

        walk(caught.value)
        assert len(errors) == 1
        assert type(errors[0]) is MCPError
