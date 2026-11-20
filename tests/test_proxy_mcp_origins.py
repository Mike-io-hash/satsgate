"""MCP routes in front of a real origin and the real core."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from proxy_mcp_harness import SECRET, HybridCore, LocalServer, RequireSignature, challenge_count, uses_consumed
from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from test_rates import _use
from test_satsgate_gate import _buy, _load_app, _pay
from test_x402 import _install_poster, _payload, _poster, _verify_payee

_ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _server(state: dict, *, stateless: bool, json_response: bool):
    global Context
    from mcp.server.mcpserver import Context, MCPServer

    origin = MCPServer("market")

    @origin.tool()
    def echo(text: str) -> str:
        return text

    @origin.tool()
    async def quote(symbol: str, ctx: Context) -> str:
        await ctx.info("working")
        return symbol

    @origin.tool()
    def fail(text: str) -> str:
        if state["fail"]:
            raise RuntimeError("tool failed")
        return text

    app = origin.streamable_http_app(stateless_http=stateless, json_response=json_response)
    return RequireSignature(app, SECRET)


def _yaml(origin_port: int, *, x402: bool, public_base: str) -> str:
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
        "      default: free\n"
        "      tools:\n"
        "        echo: free\n"
        "        quote:\n"
        "          price_sats: 21\n"
        "          access: per_request\n"
        "          description: One market quote\n"
        "        fail:\n"
        "          price_sats: 21\n"
        "          access: per_request\n"
        "          description: A tool that can fail\n"
    )


def _settings(tmp_path: Path, monkeypatch, origin_port: int, *, x402: bool, public_base: str):
    path = tmp_path / ("x402.yaml" if x402 else "proxy.yaml")
    path.write_text(_yaml(origin_port, x402=x402, public_base=public_base), encoding="utf-8")
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
    return load_settings(path)


def _restricted(core: TestClient, account: str) -> str:
    minted = core.post(
        "/v1/api-keys",
        headers={"X-Api-Key": account},
        json={"label": "proxy", "resource_prefix": "route:"},
    )
    assert minted.status_code == 200, minted.text
    return minted.json()["api_key"]


def _balance(core: TestClient, account: str) -> dict:
    response = core.get("/v1/balance", headers={"X-Api-Key": account})
    assert response.status_code == 200, response.text
    return response.json()


def _rpc(method: str, params: dict | None = None, *, ident: int = 1) -> bytes:
    body: dict = {"jsonrpc": "2.0", "id": ident, "method": method}
    if params is not None:
        body["params"] = params
    return json.dumps(body).encode("utf-8")


def _post(buyer: httpx.Client, url: str, body: bytes, headers: dict | None = None) -> httpx.Response:
    merged = dict(_ACCEPT)
    if headers:
        merged.update(headers)
    return buyer.post(url, content=body, headers=merged)


def _result_flag(response: httpx.Response) -> bool:
    media = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media == "application/json":
        payload = response.json()
    else:
        text = response.text.replace("\r\n", "\n")
        data = ""
        for block in text.split("\n\n"):
            lines = [line[5:].lstrip() if line.startswith("data:") else "" for line in block.split("\n") if line.startswith("data:")]
            if lines:
                data = "\n".join(lines)
        payload = json.loads(data) if data else {}
    result = payload.get("result") if isinstance(payload, dict) else None
    return bool(isinstance(result, dict) and result.get("isError") is True)


def _official_round_trip(url: str) -> None:
    from mcp import Client

    async def once() -> None:
        async with Client(url) as client:
            listed = await client.list_tools()
            tools = listed.tools if hasattr(listed, "tools") else listed
            names = {tool.name for tool in tools}
            assert {"echo", "quote", "fail"} <= names
            echoed = await client.call_tool("echo", {"text": "hi"})
            assert echoed.is_error is False

    asyncio.run(once())


def _lightning(buyer: httpx.Client, core: TestClient, url: str, account: str, state: dict, *, delete: bool) -> None:
    assert challenge_count() == 0
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
    session = opened.headers.get("mcp-session-id")
    extra = {"MCP-Protocol-Version": "2025-11-25"}
    if session:
        extra["Mcp-Session-Id"] = session
    noted = _post(buyer, url, b'{"jsonrpc":"2.0","method":"notifications/initialized"}', extra)
    assert noted.status_code in {200, 202}, noted.text
    listed = _post(buyer, url, _rpc("tools/list", ident=2), extra)
    assert listed.status_code == 200, listed.text
    echoed = _post(buyer, url, _rpc("tools/call", {"name": "echo", "arguments": {"text": "hi"}}, ident=3), extra)
    assert echoed.status_code == 200, echoed.text
    assert challenge_count() == 0

    unpaid = _post(buyer, url, _rpc("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, ident=4), extra)
    assert unpaid.status_code == 402, unpaid.text
    assert unpaid.json()["resource"] == "route:tools:quote"
    before = _balance(core, account)
    preimage = _pay(core, unpaid.json()["payment_hash"])
    paid_headers = dict(extra)
    paid_headers["Authorization"] = f"L402 {unpaid.json()['macaroon']}:{preimage}"
    served = _post(buyer, url, _rpc("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, ident=4), paid_headers)
    assert served.status_code == 200, served.text
    assert _result_flag(served) is False
    after = _balance(core, account)
    assert uses_consumed(unpaid.json()["payment_hash"]) == 1
    spent_free = after["free_unlocks_remaining"] == before["free_unlocks_remaining"] - 1
    spent_balance = after["balance_msat"] < before["balance_msat"]
    assert spent_free or spent_balance

    mismatched = _post(buyer, url, _rpc("tools/call", {"name": "fail", "arguments": {"text": "x"}}, ident=5), paid_headers)
    assert mismatched.status_code == 402, mismatched.text
    assert mismatched.json()["reason"] == "resource mismatch"

    fresh = _post(buyer, url, _rpc("tools/call", {"name": "fail", "arguments": {"text": "x"}}, ident=6), extra)
    assert fresh.status_code == 402, fresh.text
    mid = _balance(core, account)
    fail_hash = fresh.json()["payment_hash"]
    fail_headers = dict(extra)
    fail_headers["Authorization"] = f"L402 {fresh.json()['macaroon']}:{_pay(core, fail_hash)}"
    state["fail"] = True
    failed = _post(buyer, url, _rpc("tools/call", {"name": "fail", "arguments": {"text": "x"}}, ident=6), fail_headers)
    assert failed.status_code == 200, failed.text
    assert _result_flag(failed) is True
    assert uses_consumed(fail_hash) == 0
    held = _balance(core, account)
    assert held["free_unlocks_remaining"] == mid["free_unlocks_remaining"]
    assert held["balance_msat"] == mid["balance_msat"]
    state["fail"] = False
    recovered = _post(buyer, url, _rpc("tools/call", {"name": "fail", "arguments": {"text": "x"}}, ident=6), fail_headers)
    assert recovered.status_code == 200, recovered.text
    assert _result_flag(recovered) is False
    assert uses_consumed(fail_hash) == 1

    denied = buyer.get(url, headers={"Accept": "application/json, text/event-stream"})
    assert denied.status_code == 405
    assert denied.headers["allow"] == "DELETE, POST"
    if delete:
        removed = buyer.request("DELETE", url, headers=extra)
        assert removed.status_code == 200, removed.text


def _modern(buyer: httpx.Client, core: TestClient, url: str, account: str, state: dict) -> None:
    def meta(method: str, params: dict, ident: int) -> bytes:
        body = {
            "jsonrpc": "2.0",
            "id": ident,
            "method": method,
            "params": {
                **params,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }
        return json.dumps(body).encode("utf-8")

    def headers(method: str, name: str | None = None) -> dict[str, str]:
        sent = {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
        if name is not None:
            sent["Mcp-Name"] = name
        return sent

    assert challenge_count() == 0
    listed = _post(buyer, url, meta("tools/list", {}, 1), headers("tools/list"))
    assert listed.status_code == 200, listed.text
    echoed = _post(buyer, url, meta("tools/call", {"name": "echo", "arguments": {"text": "hi"}}, 2), headers("tools/call", "echo"))
    assert echoed.status_code == 200, echoed.text
    assert challenge_count() == 0
    _lightning_paid(buyer, core, url, account, state, headers, meta)


def _lightning_paid(buyer, core, url, account, state, headers, meta) -> None:
    unpaid = _post(buyer, url, meta("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, 4), headers("tools/call", "quote"))
    assert unpaid.status_code == 402, unpaid.text
    before = _balance(core, account)
    paid = dict(headers("tools/call", "quote"))
    paid["Authorization"] = f"L402 {unpaid.json()['macaroon']}:{_pay(core, unpaid.json()['payment_hash'])}"
    served = _post(buyer, url, meta("tools/call", {"name": "quote", "arguments": {"symbol": "acme"}}, 4), paid)
    assert served.status_code == 200, served.text
    assert uses_consumed(unpaid.json()["payment_hash"]) == 1
    after = _balance(core, account)
    assert after["free_unlocks_remaining"] == before["free_unlocks_remaining"] - 1 or after["balance_msat"] < before["balance_msat"]
    quote_only = dict(headers("tools/call", "fail"))
    quote_only["Authorization"] = paid["Authorization"]
    mismatched = _post(buyer, url, meta("tools/call", {"name": "fail", "arguments": {"text": "x"}}, 5), quote_only)
    assert mismatched.status_code == 402, mismatched.text
    assert mismatched.json()["reason"] == "resource mismatch"
    fresh = _post(buyer, url, meta("tools/call", {"name": "fail", "arguments": {"text": "x"}}, 6), headers("tools/call", "fail"))
    assert fresh.status_code == 402, fresh.text
    mid = _balance(core, account)
    fail_hash = fresh.json()["payment_hash"]
    fail_headers = dict(headers("tools/call", "fail"))
    fail_headers["Authorization"] = f"L402 {fresh.json()['macaroon']}:{_pay(core, fail_hash)}"
    state["fail"] = True
    failed = _post(buyer, url, meta("tools/call", {"name": "fail", "arguments": {"text": "x"}}, 6), fail_headers)
    assert failed.status_code == 200, failed.text
    assert _result_flag(failed) is True
    assert uses_consumed(fail_hash) == 0
    held = _balance(core, account)
    assert held["balance_msat"] == mid["balance_msat"]
    assert held["free_unlocks_remaining"] == mid["free_unlocks_remaining"]
    state["fail"] = False
    recovered = _post(buyer, url, meta("tools/call", {"name": "fail", "arguments": {"text": "x"}}, 6), fail_headers)
    assert recovered.status_code == 200, recovered.text
    assert uses_consumed(fail_hash) == 1
    denied = buyer.get(url, headers={"Accept": "application/json, text/event-stream"})
    assert denied.status_code == 405


@pytest.mark.parametrize("shape", ["stateful", "stateless", "modern"])
def test_pm_7_real_origin_and_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
    module = _load_app(tmp_path)
    state = {"fail": True}
    stateless = shape != "stateful"
    origin = LocalServer(_server(state, stateless=stateless, json_response=shape == "stateless"))
    origin.start()
    proxy = None
    try:
        with TestClient(module.app) as core:
            account = _buy(core)
            monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
            settings = _settings(tmp_path, monkeypatch, origin.port, x402=False, public_base="")
            proxy = LocalServer(build_app(settings, transport=HybridCore(module.app)))
            proxy.start()
            url = f"http://127.0.0.1:{proxy.port}/mcp"
            with httpx.Client(timeout=20) as buyer:
                if shape == "stateless":
                    assert challenge_count() == 0
                    _official_round_trip(url)
                    assert challenge_count() == 0
                if shape == "modern":
                    _modern(buyer, core, url, account, state)
                else:
                    _lightning(buyer, core, url, account, state, delete=shape == "stateful")
            if shape == "stateless":
                _x402(tmp_path, monkeypatch, module, core, account, origin.port, state)
    finally:
        if proxy is not None:
            proxy.stop()
        origin.stop()


def _x402(tmp_path, monkeypatch, module, core, account, origin_port: int, state: dict) -> None:
    from eth_account import Account

    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer_key = Account.create()
    _verify_payee(core, account, owner)
    calls, post = _poster(buyer_key)
    _install_poster(post)
    from proxy_mcp_harness import _free_port

    port = _free_port()
    public = f"http://127.0.0.1:{port}"
    settings = _settings(tmp_path, monkeypatch, origin_port, x402=True, public_base=public)
    proxy = LocalServer(build_app(settings, transport=HybridCore(module.app)), port=port)
    proxy.start()
    try:
        url = f"http://127.0.0.1:{port}/mcp"
        with httpx.Client(timeout=20) as buyer:
            state["fail"] = True
            body = _rpc("tools/call", {"name": "fail", "arguments": {"text": "x"}}, ident=8)
            unpaid = _post(buyer, url, body, {"MCP-Protocol-Version": "2025-11-25"})
            assert unpaid.status_code == 402, unpaid.text
            signature = _payload(unpaid.headers["payment-required"], buyer_key, unpaid.json()["x402"]["expires_at"])
            before = _balance(core, account)
            failed = _post(
                buyer,
                url,
                body,
                {"MCP-Protocol-Version": "2025-11-25", "PAYMENT-SIGNATURE": signature},
            )
            assert failed.status_code == 200, failed.text
            assert _result_flag(failed) is True
            assert "payment-response" not in failed.headers
            assert not any(item[0].endswith("/settle") for item in calls)
            assert _balance(core, account)["balance_msat"] == before["balance_msat"]
            state["fail"] = False
            served = _post(
                buyer,
                url,
                body,
                {"MCP-Protocol-Version": "2025-11-25", "PAYMENT-SIGNATURE": signature},
            )
            assert served.status_code == 200, served.text
            assert served.headers.get("payment-response")
            assert sum(1 for url_item, _body in calls if url_item.endswith("/settle")) == 1
    finally:
        proxy.stop()
