"""Remote MCP client: inputs, handshake, listing, and paid-request headers."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path

import httpx
import pytest

from satsgate_mcp import __version__
from satsgate_mcp.buyer import BuyerError, _X402_ERRORS, _X402_RETRY_NEW
from satsgate_mcp.manual import _run
from satsgate_mcp.nwc import NwcError
from satsgate_mcp.server import _INSTRUCTIONS, _PAY, _READ, build_server
from test_satsgate_mcp import INVOICE, MAC, NOW, NWC, PAYMENT, PREIMAGE, Clock, _buyer, _challenge, _paid
from test_satsgate_mcp_x402 import (
    RESOURCE,
    SIGNATURE,
    _accept,
    _settings_usd,
    _x402_response,
)

URL = "https://shop.example/mcp"
_HANDSHAKE_NOT_FREE = (
    "The server asked for payment during {step}. This client does not pay for the handshake. Nothing was paid."
)
_LIST_DETAIL = "Listing tools is free. A price, when there is one, is shown when the tool is called."
_UNKNOWN = "The server does not list a tool with that name. Nothing was sent or paid."
_UNKNOWN_CUT = _UNKNOWN + " The listing stopped after 10 pages."
_INVALID_RESPONSE = "The server did not return a JSON-RPC response for this request. Nothing was paid."
_SESSION_INVALID = "The server sent an invalid Mcp-Session-Id. Nothing was paid."
_REDIRECT = "The server redirected. This client does not follow redirects."


def _rpc(request_id: int, result: dict | None = None, *, error: dict | None = None, status: int = 200, headers: dict | None = None) -> httpx.Response:
    body: dict = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        body["error"] = error
    else:
        body["result"] = {} if result is None else result
    return httpx.Response(status, json=body, headers=headers)


def _body(request: httpx.Request) -> dict:
    if request.method == "DELETE" or not request.content:
        return {}
    return json.loads(request.content)


def _rpc_method(request: httpx.Request) -> str:
    if request.method == "DELETE":
        return "DELETE"
    return str(_body(request).get("method") or "")


def _limit_body(tool: str, arguments: dict) -> bytes:
    """Bytes the pre-request size check measures: tools/call, id 1, modern envelope."""
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "satsgate-mcp", "version": __version__},
    }
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments, "_meta": meta},
    }
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _echo_tool(name: str = "echo", schema: dict | None = None, description: str | None = "Echo") -> dict:
    tool: dict = {"name": name, "inputSchema": schema if schema is not None else {"type": "object"}}
    if description is not None:
        tool["description"] = description
    return tool


def _origin(
    *,
    tools: list | None = None,
    on_discover=None,
    on_initialize=None,
    on_list=None,
    on_call=None,
    on_delete=None,
    protocol: str = "2025-11-25",
    session: str | None = "sess-1",
    modern: bool = True,
):
    catalog = tools if tools is not None else [_echo_tool()]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            if on_delete is not None:
                return on_delete(request)
            return httpx.Response(200)
        body = _body(request)
        method = body.get("method")
        if method == "server/discover":
            if on_discover is not None:
                return on_discover(request, body)
            if modern:
                return _rpc(body["id"], {"supportedVersions": ["2026-07-28"]})
            return httpx.Response(
                400,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32600, "message": "Bad Request: Missing session ID"},
                },
                headers={"mcp-session-id": "ignore-me"},
            )
        if method == "initialize":
            if on_initialize is not None:
                return on_initialize(request, body)
            headers = {"mcp-session-id": session} if session else None
            return _rpc(
                body["id"],
                {"protocolVersion": protocol, "capabilities": {}, "serverInfo": {"name": "origin", "version": "0"}},
                headers=headers,
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            if on_list is not None:
                return on_list(request, body)
            return _rpc(body["id"], {"tools": catalog})
        if method == "tools/call":
            if on_call is not None:
                return on_call(request, body)
            return _rpc(body["id"], {"content": [{"type": "text", "text": "ok"}], "isError": False})
        return httpx.Response(500, json={"error": "unexpected"})

    return handler


def _save_token(buyer, tool: str = "echo", *, url: str = URL, preimage: str | None = PREIMAGE, uses: int = 5) -> str:
    key = "mcp " + json.dumps([url, tool], separators=(",", ":"), ensure_ascii=False)
    buyer.store.save_token(
        {
            "cache_key": key,
            "method": "POST",
            "url": url,
            "macaroon": MAC,
            "preimage": preimage,
            "payment_hash": PAYMENT,
            "resource": "route:tools:" + tool,
            "amount_sats": 21,
            "max_uses": uses,
            "access_seconds": None,
            "uses_remaining": uses,
            "access_until": None,
            "invoice_expires_at": None,
            "updated_at": 1_700_000_000,
        }
    )
    return key


@pytest.mark.parametrize("value", [1, ["https://shop.example/mcp"], {"url": "https://shop.example/mcp"}, None, True])
def test_rc_1_1_url_must_be_a_string(tmp_path: Path, value: object) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin())
    with pytest.raises(BuyerError) as listed:
        asyncio.run(buyer.remote_list_tools(value))
    with pytest.raises(BuyerError) as called:
        asyncio.run(buyer.remote_call_tool(value, "echo"))
    assert listed.value.code == "invalid_url"
    assert called.value.code == "invalid_url"
    assert listed.value.message == "url must be a string."
    assert called.value.message == "url must be a string."
    assert http.calls == []
    assert wallet.invoices == []


def test_rc_1_2_url_outside_the_allowlist_is_rejected(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin(), allowlist=("other.example",))
    server = build_server(buyer)
    detail = "shop.example is not in SATSGATE_MCP_URL_ALLOWLIST."
    for name in ("remote_list_tools", "remote_call_tool"):
        tool = next(item for item in server._tool_manager.list_tools() if item.name == name)
        if name == "remote_list_tools":
            result = asyncio.run(tool.fn(url=URL))
        else:
            result = asyncio.run(tool.fn(url=URL, tool="echo"))
        assert result == [{"ok": False, "error": "invalid_url", "detail": detail}]
    assert http.calls == []
    assert wallet.invoices == []


def test_rc_1_3_tool_name_is_a_short_string_without_controls(tmp_path: Path) -> None:
    message = "tool must be a non-empty string of at most 128 characters without control characters."
    for index, tool_name in enumerate((1, "", "a" * 129, "echo\n", "echo\x7f", True, None)):
        buyer, http, wallet = _buyer(tmp_path / f"bad-{index}", _origin())
        with pytest.raises(BuyerError) as caught:
            asyncio.run(buyer.remote_call_tool(URL, tool_name, {"also": []}))
        assert caught.value.code == "invalid_tool_name"
        assert caught.value.message == message
        assert http.calls == []
        assert wallet.invoices == []
    name = "b" * 128
    buyer, http, wallet = _buyer(tmp_path / "fit", _origin(tools=[_echo_tool(name)]))
    asyncio.run(buyer.remote_call_tool(URL, name))
    assert any(_rpc_method(call) == "tools/call" for call in http.calls)
    assert wallet.invoices == []


@pytest.mark.parametrize("arguments", [[], "text", 4])
def test_rc_1_4_arguments_must_be_an_object(tmp_path: Path, arguments: object) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin())
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", arguments, mode="nope"))
    assert caught.value.code == "invalid_arguments"
    assert caught.value.message == "arguments must be a JSON object with string keys."
    assert http.calls == []
    assert wallet.invoices == []


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({1: "a"}, "arguments must be a JSON object with string keys."),
        ({"a": {1, 2}}, "arguments must be JSON-serializable."),
        ({"a": float("nan")}, "arguments must be JSON-serializable."),
    ],
)
def test_rc_1_5_arguments_must_be_json_with_string_keys(tmp_path: Path, arguments: dict, message: str) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin())
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", arguments))
    assert caught.value.code == "invalid_arguments"
    assert caught.value.message == message
    assert http.calls == []


def test_rc_1_6_arguments_are_rejected_one_byte_over_the_body_cap(tmp_path: Path) -> None:
    arguments = {"note": "x" * 40}
    encoded = _limit_body("echo", arguments)
    over, over_http, _over_wallet = _buyer(tmp_path / "over", _origin(), max_body_bytes=len(encoded) - 1)
    with pytest.raises(BuyerError) as caught:
        asyncio.run(over.remote_call_tool(URL, "echo", arguments))
    assert caught.value.code == "invalid_arguments"
    assert caught.value.message == "arguments are above SATSGATE_MCP_MAX_BODY_BYTES."
    assert over_http.calls == []

    fit, fit_http, fit_wallet = _buyer(tmp_path / "fit", _origin(), max_body_bytes=len(encoded))
    asyncio.run(fit.remote_call_tool(URL, "echo", arguments))
    assert any(_rpc_method(call) == "tools/call" for call in fit_http.calls)
    assert fit_wallet.invoices == []


@pytest.mark.parametrize("mode", ["auto", None, ["human"]])
def test_rc_1_7_mode_must_be_human_or_nwc(tmp_path: Path, mode: object) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin())
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", None, mode, 1))
    assert caught.value.code == "invalid_mode"
    assert caught.value.message == "mode must be human or nwc."
    assert http.calls == []
    assert wallet.invoices == []


@pytest.mark.parametrize(
    ("signature", "message"),
    [
        (1, "payment_signature must be a string. It was not sent."),
        (["sig"], "payment_signature must be a string. It was not sent."),
        (True, "payment_signature must be a string. It was not sent."),
        ("ab cd", "PAYMENT-SIGNATURE must be a single line without spaces. It was not sent."),
        ("a" * 8193, "PAYMENT-SIGNATURE is longer than 8192 bytes. It was not sent."),
        ("%%%%", "PAYMENT-SIGNATURE must be base64 of a JSON object. It was not sent."),
        (
            base64.standard_b64encode(b"[1,2]").decode("ascii"),
            "PAYMENT-SIGNATURE must be base64 of a JSON object. It was not sent.",
        ),
    ],
)
def test_rc_1_8_payment_signature_is_rejected_before_a_request(tmp_path: Path, signature: object, message: str) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin())
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", None, "human", signature))
    assert caught.value.code == "invalid_payment_signature"
    assert caught.value.message == message
    assert http.calls == []
    assert wallet.invoices == []


def test_rc_1_9_empty_payment_signature_stays_on_the_lightning_path(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin())
    asyncio.run(buyer.remote_call_tool(URL, "echo", {"k": "v"}, "human", ""))
    call = next(item for item in http.calls if _rpc_method(item) == "tools/call")
    meta = _body(call)["params"]["_meta"]
    assert "x402/payment" not in meta
    assert "payment-signature" not in call.headers
    assert wallet.invoices == []


def test_rc_1_10_server_registers_the_remote_tools(tmp_path: Path) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin())
    server = build_server(buyer)
    tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
    assert "remote_list_tools" in tools
    assert "remote_call_tool" in tools
    listed = tools["remote_list_tools"]
    called = tools["remote_call_tool"]
    assert listed.description == (
        "List the tools of a remote MCP server at url. Free: it never calls a tool and never pays."
    )
    assert called.description == (
        "Call one tool on a remote MCP server at url with arguments. If the tool is priced, mode human "
        "returns a Lightning invoice and a QR: pay it, then call remote_call_tool again with the same url "
        "and tool. mode nwc pays from the environment wallet inside the caps. payment_signature sends an "
        "x402 PAYMENT-SIGNATURE from an external wallet. A stored token is reused for later calls to the same tool."
    )
    assert listed.annotations.read_only_hint is _READ.read_only_hint
    assert listed.annotations.destructive_hint is _READ.destructive_hint
    assert listed.annotations.open_world_hint is _READ.open_world_hint
    assert called.annotations.read_only_hint is _PAY.read_only_hint
    assert called.annotations.destructive_hint is _PAY.destructive_hint
    assert called.annotations.open_world_hint is _PAY.open_world_hint
    sentence = (
        "remote_list_tools and remote_call_tool call tools on a remote MCP server. "
        "Listing and the handshake are never paid. After paying a remote tool's invoice, "
        "call remote_call_tool again with the same url and tool, not check_payment. "
    )
    assert sentence in _INSTRUCTIONS
    assert _INSTRUCTIONS.index(sentence) < _INSTRUCTIONS.index("Do not ask the user to paste")
    assert http.calls == []


def test_rc_1_11_server_maps_a_buyer_error(tmp_path: Path) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin())

    async def boom(*_args, **_kwargs):
        raise BuyerError("remote_tool_payment", "Stopped before a request.")

    buyer.remote_call_tool = boom
    server = build_server(buyer)
    tool = next(item for item in server._tool_manager.list_tools() if item.name == "remote_call_tool")
    result = asyncio.run(tool.fn(url=URL, tool="echo"))
    assert result == [{"ok": False, "error": "remote_tool_payment", "detail": "Stopped before a request."}]
    assert http.calls == []


def test_rc_2_1_modern_discover_sets_call_headers_and_skips_initialize(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin())
    asyncio.run(buyer.remote_call_tool(URL, "echo", {"text": "hi"}))
    methods = [_rpc_method(call) for call in http.calls]
    assert methods[0] == "server/discover"
    assert "initialize" not in methods
    call = next(item for item in http.calls if _rpc_method(item) == "tools/call")
    assert call.headers["mcp-protocol-version"] == "2026-07-28"
    assert call.headers["mcp-method"] == "tools/call"
    assert call.headers["mcp-name"] == "echo"
    assert "mcp-session-id" not in call.headers
    assert call.headers["accept"] == "application/json, text/event-stream"
    assert call.headers["content-type"] == "application/json"
    body = _body(call)
    assert list(body["params"]) == ["name", "arguments", "_meta"]
    meta = body["params"]["_meta"]
    assert list(meta) == [
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
        "io.modelcontextprotocol/clientInfo",
    ]
    assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
    assert meta["io.modelcontextprotocol/clientInfo"] == {"name": "satsgate-mcp", "version": __version__}
    assert body["params"]["arguments"] == {"text": "hi"}
    assert wallet.invoices == []


def test_rc_2_2_stateful_discover_session_header_is_ignored(tmp_path: Path) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin(modern=False))
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert "initialize" in [_rpc_method(call) for call in http.calls]
    assert all(call.headers.get("mcp-session-id") != "ignore-me" for call in http.calls)
    assert any(call.headers.get("mcp-session-id") == "sess-1" for call in http.calls)


def test_rc_2_3_stateless_legacy_sends_no_session_and_no_delete(tmp_path: Path) -> None:
    def discover(_request, body):
        return httpx.Response(
            400,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32600, "message": "Bad Request: Unsupported protocol version"},
            },
        )

    buyer, http, wallet = _buyer(tmp_path, _origin(on_discover=discover, session=None, modern=False))
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    methods = [_rpc_method(call) for call in http.calls]
    assert "initialize" in methods
    assert "DELETE" not in methods
    assert all("mcp-session-id" not in call.headers for call in http.calls)
    assert wallet.invoices == []


@pytest.mark.parametrize(
    "kind",
    [
        "method_not_found",
        "http_404",
        "http_405",
        "http_406",
        "plain_200",
        "missing_versions",
        "legacy_version",
        "supported_legacy",
    ],
)
def test_rc_2_4_discover_falls_back_to_initialize(tmp_path: Path, kind: str) -> None:
    def discover(_request, body):
        if kind == "method_not_found":
            return _rpc(body["id"], error={"code": -32601, "message": "Method not found"})
        if kind == "http_404":
            return httpx.Response(404)
        if kind == "http_405":
            return httpx.Response(405)
        if kind == "http_406":
            return httpx.Response(406)
        if kind == "plain_200":
            return httpx.Response(200, content=b"not-json", headers={"content-type": "text/plain"})
        if kind == "missing_versions":
            return _rpc(body["id"], {"protocolVersion": "2026-07-28"})
        if kind == "legacy_version":
            return _rpc(body["id"], {"supportedVersions": ["2025-11-25"]})
        return _rpc(
            body["id"],
            error={"code": -32022, "message": "Unsupported protocol version", "data": {"supported": ["2025-11-25"]}},
        )

    buyer, http, _wallet = _buyer(tmp_path, _origin(on_discover=discover, modern=False))
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    methods = [_rpc_method(call) for call in http.calls]
    assert methods[0] == "server/discover"
    assert "initialize" in methods


def test_rc_2_5_disjoint_protocol_list_does_not_initialize(tmp_path: Path) -> None:
    def discover(_request, body):
        return httpx.Response(
            400,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {
                    "code": -32022,
                    "message": "Unsupported protocol version",
                    "data": {"supported": ["2027-01-01"]},
                },
            },
        )

    buyer, http, wallet = _buyer(tmp_path, _origin(on_discover=discover))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert caught.value.code == "incompatible_protocol"
    assert caught.value.message == "This server does not support a protocol version this client can use. Nothing was paid."
    assert "initialize" not in [_rpc_method(call) for call in http.calls]
    assert wallet.invoices == []


def test_rc_2_6_discover_402_is_not_paid(tmp_path: Path) -> None:
    def discover(_request, body):
        return httpx.Response(402, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "pay"}})

    buyer, http, wallet = _buyer(tmp_path, _origin(on_discover=discover), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert caught.value.code == "handshake_not_free"
    assert caught.value.message == _HANDSHAKE_NOT_FREE.format(step="server/discover")
    assert len(http.calls) == 1
    assert wallet.invoices == []


def test_rc_2_7_initialize_402_is_not_paid(tmp_path: Path) -> None:
    def initialize(_request, _body):
        return httpx.Response(402, json={"error": "payment_required"})

    buyer, http, wallet = _buyer(
        tmp_path,
        _origin(on_initialize=initialize, modern=False),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_list_tools(URL))
    assert caught.value.code == "handshake_not_free"
    assert caught.value.message == _HANDSHAKE_NOT_FREE.format(step="initialize")
    assert wallet.invoices == []
    assert "tools/list" not in [_rpc_method(call) for call in http.calls]


def test_rc_2_8_initialized_notification_402_is_not_paid(tmp_path: Path) -> None:
    seen = {"note": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            return httpx.Response(200)
        body = _body(request)
        method = body.get("method")
        if method == "server/discover":
            return httpx.Response(400, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "no"}})
        if method == "initialize":
            return _rpc(body["id"], {"protocolVersion": "2025-11-25"}, headers={"mcp-session-id": "sess-1"})
        if method == "notifications/initialized":
            seen["note"] += 1
            return httpx.Response(402, json={"error": "payment_required"})
        return httpx.Response(500)

    buyer, http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert caught.value.code == "handshake_not_free"
    assert caught.value.message == _HANDSHAKE_NOT_FREE.format(step="notifications/initialized")
    assert seen["note"] == 1
    assert wallet.invoices == []
    assert "tools/list" not in [_rpc_method(call) for call in http.calls]


def test_rc_2_9_unknown_negotiated_version_deletes_the_session(tmp_path: Path) -> None:
    def initialize(_request, body):
        return _rpc(body["id"], {"protocolVersion": "2099-01-01"}, headers={"mcp-session-id": "sess-bad-ver"})

    buyer, http, wallet = _buyer(tmp_path, _origin(on_initialize=initialize, modern=False))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert caught.value.code == "incompatible_protocol"
    deletes = [call for call in http.calls if call.method == "DELETE"]
    assert len(deletes) == 1
    assert deletes[0].headers["mcp-session-id"] == "sess-bad-ver"
    assert wallet.invoices == []


def test_rc_2_10_legacy_headers_start_after_initialize(tmp_path: Path) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin(modern=False, protocol="2025-06-18", session="sess-1"))
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    initialize = next(call for call in http.calls if _rpc_method(call) == "initialize")
    assert "mcp-protocol-version" not in initialize.headers
    assert "mcp-session-id" not in initialize.headers
    later = [
        call
        for call in http.calls
        if _rpc_method(call) in {"notifications/initialized", "tools/list", "tools/call", "DELETE"}
    ]
    assert [ _rpc_method(call) for call in later ] == [
        "notifications/initialized",
        "tools/list",
        "tools/call",
        "DELETE",
    ]
    for call in later:
        assert call.headers["mcp-protocol-version"] == "2025-06-18"
        assert call.headers["mcp-session-id"] == "sess-1"
        assert "mcp-method" not in call.headers
        assert "mcp-name" not in call.headers


def test_rc_2_11_delete_runs_once_and_its_failure_does_not_change_the_payload(tmp_path: Path) -> None:
    def run(delete_fails: bool) -> dict:
        def on_delete(_request):
            if delete_fails:
                raise httpx.ConnectError("down")
            return httpx.Response(200)

        def on_call(_request, body):
            return _rpc(body["id"], {"isError": True, "content": [{"type": "text", "text": "nope"}]})

        buyer, http, _wallet = _buyer(tmp_path / str(delete_fails), _origin(modern=False, on_delete=on_delete, on_call=on_call))
        result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
        assert [call.method for call in http.calls].count("DELETE") == 1
        return result.payload

    assert run(False) == run(True)

    def on_call(_request, _body):
        raise httpx.ReadTimeout("slow")

    buyer, http, wallet = _buyer(tmp_path / "timeout", _origin(modern=False, on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "timeout"
    assert [call.method for call in http.calls].count("DELETE") == 1
    assert wallet.invoices == []


@pytest.mark.parametrize("session", ["bad id", "", "x" * 1025])
def test_rc_2_12_invalid_session_id_fails_the_handshake(tmp_path: Path, session: str) -> None:
    def initialize(_request, body):
        return _rpc(body["id"], {"protocolVersion": "2025-11-25"}, headers={"mcp-session-id": session})

    buyer, http, wallet = _buyer(tmp_path, _origin(on_initialize=initialize, modern=False))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert caught.value.code == "connect_failed"
    assert caught.value.message == _SESSION_INVALID
    assert "tools/call" not in [_rpc_method(call) for call in http.calls]
    assert wallet.invoices == []


def test_rc_2_13_discover_redirect_is_not_followed(tmp_path: Path) -> None:
    def discover(_request, _body):
        return httpx.Response(302, headers={"location": "https://elsewhere.example/mcp"})

    buyer, http, wallet = _buyer(tmp_path, _origin(on_discover=discover))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_list_tools(URL))
    assert caught.value.code == "redirect_not_followed"
    assert caught.value.message == _REDIRECT
    assert len(http.calls) == 1
    assert wallet.invoices == []


def test_rc_2_14_session_404_renews_once_and_a_second_404_expires(tmp_path: Path) -> None:
    state = {"calls": 0}

    def on_call(request, body):
        state["calls"] += 1
        if state["calls"] == 1:
            return httpx.Response(404, content=b"missing")
        return _rpc(body["id"], {"content": [{"type": "text", "text": "renewed"}], "isError": False})

    buyer, http, wallet = _buyer(tmp_path / "once", _origin(modern=False, on_call=on_call))
    _save_token(buyer)
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    calls = [call for call in http.calls if _rpc_method(call) == "tools/call"]
    assert len(calls) == 2
    assert _body(calls[0])["id"] != _body(calls[1])["id"]
    assert calls[0].headers["authorization"] == f"L402 {MAC}:{PREIMAGE}"
    assert calls[1].headers["authorization"] == calls[0].headers["authorization"]
    assert [_rpc_method(call) for call in http.calls].count("initialize") == 2
    assert result.payload["content"] == [{"type": "text", "text": "renewed"}]
    assert wallet.invoices == []

    buyer, http, _wallet = _buyer(tmp_path / "twice", _origin(modern=False, on_call=lambda _request, _body: httpx.Response(404)))
    _save_token(buyer)
    expired = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert expired.payload["error"] == "session_expired"
    assert expired.payload["token_kept"] is True
    assert [_rpc_method(call) for call in http.calls].count("initialize") == 2
    assert [_rpc_method(call) for call in http.calls].count("tools/call") == 2


def test_rc_2_15_discover_timeout_does_not_fall_back(tmp_path: Path) -> None:
    def discover(_request, _body):
        raise httpx.ReadTimeout("slow")

    buyer, http, wallet = _buyer(tmp_path, _origin(on_discover=discover), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert caught.value.code == "timeout"
    assert caught.value.message == "The request timed out."
    assert [_rpc_method(call) for call in http.calls] == ["server/discover"]
    assert wallet.invoices == []


def test_rc_2_16_paid_retry_uses_a_new_jsonrpc_id(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            return _rpc(body["id"], {"content": [{"type": "text", "text": "paid"}], "isError": False})
        return _challenge()

    buyer, http, wallet = _buyer(
        tmp_path,
        _origin(on_call=on_call),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    calls = [call for call in http.calls if _rpc_method(call) == "tools/call"]
    assert len(calls) == 2
    assert isinstance(_body(calls[0])["id"], int)
    assert isinstance(_body(calls[1])["id"], int)
    assert _body(calls[0])["id"] != _body(calls[1])["id"]
    assert "authorization" not in calls[0].headers
    assert calls[1].headers["authorization"] == f"L402 {MAC}:{PREIMAGE.lower()}"
    assert wallet.invoices == [INVOICE]
    assert result.payload["content"] == [{"type": "text", "text": "paid"}]


def test_rc_3_1_list_tools_returns_the_catalog_and_does_not_call(tmp_path: Path) -> None:
    tools = [
        {"name": "echo", "description": "Echoes", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
        {"name": "bare"},
        {"description": "nameless"},
        {"name": "", "description": "empty"},
        {"name": 3, "description": "number"},
        {"name": "nulls", "description": None, "inputSchema": None},
    ]
    buyer, http, wallet = _buyer(tmp_path, _origin(tools=tools))
    result = asyncio.run(buyer.remote_list_tools(URL))
    payload = result.payload
    assert list(payload) == ["ok", "url", "protocol_version", "tools", "truncated", "detail"]
    assert payload["ok"] is True
    assert payload["url"] == URL
    assert payload["protocol_version"] == "2026-07-28"
    assert payload["truncated"] is False
    assert payload["detail"] == _LIST_DETAIL
    assert payload["tools"] == [
        {
            "name": "echo",
            "description": "Echoes",
            "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
        },
        {"name": "bare", "description": None, "input_schema": None},
        {"name": "nulls", "description": None, "input_schema": None},
    ]
    assert list(payload["tools"][0]) == ["name", "description", "input_schema"]
    assert "tools/call" not in [_rpc_method(call) for call in http.calls]
    assert wallet.invoices == []
    assert buyer.store.spent_since(0) == 0
    assert buyer.store.quote_for("mcp " + json.dumps([URL, "echo"], separators=(",", ":"))) is None
    assert buyer.store.token_for("mcp " + json.dumps([URL, "echo"], separators=(",", ":"))) is None


def test_rc_3_2_listing_stops_after_ten_pages(tmp_path: Path) -> None:
    seen: list = []

    def on_list(_request, body):
        seen.append(body["params"].get("cursor"))
        page = len(seen)
        return _rpc(body["id"], {"tools": [{"name": f"t{page}"}], "nextCursor": f"p{page + 1}"})

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_list=on_list))
    result = asyncio.run(buyer.remote_list_tools(URL))
    assert seen == [None, "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
    assert result.payload["truncated"] is True
    assert [item["name"] for item in result.payload["tools"]] == [f"t{page}" for page in range(1, 11)]
    assert wallet.invoices == []


@pytest.mark.parametrize("kind", ["http_402", "in_band"])
@pytest.mark.parametrize("entry", ["list", "call"])
def test_rc_3_3_a_priced_list_is_refused(tmp_path: Path, kind: str, entry: str) -> None:
    def on_list(_request, body):
        if kind == "http_402":
            return httpx.Response(402, json={"error": "payment_required", "invoice": INVOICE})
        return _rpc(
            body["id"],
            {
                "isError": True,
                "structuredContent": {"error": "payment_required", "tool": "echo"},
            },
        )

    buyer, http, wallet = _buyer(tmp_path, _origin(on_list=on_list), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    method = buyer.remote_list_tools if entry == "list" else buyer.remote_call_tool
    args = (URL,) if entry == "list" else (URL, "echo")
    with pytest.raises(BuyerError) as caught:
        asyncio.run(method(*args, mode="nwc") if entry == "call" else method(*args))
    assert caught.value.code == "listing_not_free"
    assert caught.value.message == (
        "The server asked for payment to list tools. This client does not pay for tools/list. Nothing was paid."
    )
    assert "tools/call" not in [_rpc_method(call) for call in http.calls]
    assert wallet.invoices == []


def test_rc_3_4_unknown_tool_is_not_called(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin(tools=[_echo_tool("other")]))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert caught.value.code == "unknown_tool"
    assert caught.value.message == _UNKNOWN
    assert "tools/call" not in [_rpc_method(call) for call in http.calls]
    assert wallet.invoices == []

    def on_list(_request, body):
        page = 1 if body["params"].get("cursor") is None else int(str(body["params"]["cursor"]))
        if page < 10:
            return _rpc(body["id"], {"tools": [{"name": f"other{page}"}], "nextCursor": str(page + 1)})
        return _rpc(body["id"], {"tools": [{"name": "other10"}], "nextCursor": "11"})

    buyer, http, wallet = _buyer(tmp_path / "cut", _origin(on_list=on_list))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert caught.value.code == "unknown_tool"
    assert caught.value.message == _UNKNOWN_CUT
    assert "tools/call" not in [_rpc_method(call) for call in http.calls]
    assert [_rpc_method(call) for call in http.calls].count("tools/list") == 10


def test_rc_3_5_invalid_header_schema_is_not_called(tmp_path: Path) -> None:
    schema = {"type": "object", "properties": {"n": {"type": "number", "x-mcp-header": "Count"}}}
    buyer, http, wallet = _buyer(tmp_path, _origin(tools=[_echo_tool(schema=schema)]))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", {"n": 1}))
    assert caught.value.code == "invalid_tool_schema"
    assert caught.value.message == (
        "The tool's inputSchema has an invalid x-mcp-header annotation. Nothing was sent or paid."
    )
    assert "tools/call" not in [_rpc_method(call) for call in http.calls]
    assert wallet.invoices == []


def test_rc_3_6_modern_param_headers_follow_the_schema_and_legacy_sends_none(tmp_path: Path) -> None:
    from mcp.shared.inbound import encode_header_value

    schema = {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "label": {"type": "string", "x-mcp-header": "Label"},
            "count": {"type": "integer", "x-mcp-header": "Count"},
            "flag": {"type": "boolean", "x-mcp-header": "Flag"},
            "note": {"type": "string", "x-mcp-header": "Note"},
        },
    }
    arguments = {"region": "us", "label": "caf\u00e9", "count": 4, "flag": False}
    buyer, http, _wallet = _buyer(tmp_path / "modern", _origin(tools=[_echo_tool(schema=schema)]))
    asyncio.run(buyer.remote_call_tool(URL, "echo", arguments))
    call = next(item for item in http.calls if _rpc_method(item) == "tools/call")
    assert call.headers["mcp-param-region"] == "us"
    assert call.headers["mcp-param-label"] == encode_header_value("caf\u00e9")
    assert call.headers["mcp-param-label"].startswith("=?base64?")
    assert call.headers["mcp-param-count"] == "4"
    assert call.headers["mcp-param-flag"] == "false"
    assert "mcp-param-note" not in call.headers

    buyer, http, _wallet = _buyer(tmp_path / "legacy", _origin(modern=False, tools=[_echo_tool(schema=schema)]))
    asyncio.run(buyer.remote_call_tool(URL, "echo", arguments))
    call = next(item for item in http.calls if _rpc_method(item) == "tools/call")
    assert all(not key.startswith("mcp-param-") for key in call.headers)


def test_rc_3_7_non_ascii_tool_name_is_encoded(tmp_path: Path) -> None:
    from mcp.shared.inbound import encode_header_value

    name = "caf\u00e9"
    buyer, http, _wallet = _buyer(tmp_path, _origin(tools=[_echo_tool(name)]))
    asyncio.run(buyer.remote_call_tool(URL, name))
    call = next(item for item in http.calls if _rpc_method(item) == "tools/call")
    assert call.headers["mcp-name"] == encode_header_value(name)
    assert call.headers["mcp-name"].startswith("=?base64?")


def test_rc_3_8_response_matching_is_strict(tmp_path: Path) -> None:
    def on_call(_request, body):
        request_id = body["id"]
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {}})
        sampling = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage", "params": {}})
        found = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": "picked"}], "isError": False},
            }
        )
        raw = f"event: message\ndata: {note}\n\ndata: {sampling}\n\ndata: {found}\n\n"
        return httpx.Response(200, content=raw.encode(), headers={"content-type": "text/event-stream"})

    buyer, _http, _wallet = _buyer(tmp_path / "sse", _origin(on_call=on_call))
    sse = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert sse.payload["content"] == [{"type": "text", "text": "picked"}]

    def on_list_body(_request, body):
        return httpx.Response(
            200,
            json=[
                {"jsonrpc": "2.0", "method": "notifications/message"},
                {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": "from-list"}], "isError": False}},
            ],
        )

    buyer, _http, _wallet = _buyer(tmp_path / "array", _origin(on_call=on_list_body))
    listed = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert listed.payload["content"] == [{"type": "text", "text": "from-list"}]

    def on_string_id(_request, body):
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": str(body["id"]), "result": {"content": [{"type": "text", "text": "wrong"}]}},
        )

    buyer, _http, _wallet = _buyer(tmp_path / "string-id", _origin(on_call=on_string_id))
    mismatched = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert mismatched.payload["error"] == "invalid_response"
    assert mismatched.payload["detail"] == _INVALID_RESPONSE


def test_rc_3_9_a_200_without_a_matching_response_is_invalid(tmp_path: Path) -> None:
    def on_call(_request, _body):
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "method": "notifications/message", "params": {}},
        )

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "invalid_response"
    assert result.payload["detail"] == _INVALID_RESPONSE
    assert wallet.invoices == []


@pytest.mark.parametrize("path", ["nwc", "cached", "check", "signature"])
def test_rc_10_1_paid_retries_keep_the_accept_header(tmp_path: Path, path: str) -> None:
    if path == "signature":

        def signed(request: httpx.Request) -> httpx.Response:
            if request.headers.get("payment-signature"):
                return _paid("ok")
            return _x402_response()

        buyer, http, _wallet = _settings_usd(tmp_path, handler=signed, max_payment_sats=100, daily_max_sats=500)
        asyncio.run(buyer.pay_and_fetch("https://shop.example/a", payment_signature=SIGNATURE))
        paid = [call for call in http.calls if call.headers.get("payment-signature")]
        assert len(paid) == 1
        assert paid[0].headers["accept"] == "application/json, */*"
        return

    def lightning(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization"):
            return _paid("ok")
        return _challenge()

    buyer, http, _wallet = _buyer(tmp_path, lightning, nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    if path == "nwc":
        asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
        paid = [call for call in http.calls if call.headers.get("authorization")]
        assert len(paid) == 1
        assert paid[0].headers["accept"] == "application/json, */*"
        return
    if path == "cached":
        asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
        asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
        assert len(http.calls) == 3
        assert http.calls[2].headers["authorization"].startswith("L402 ")
        assert http.calls[2].headers["accept"] == "application/json, */*"
        return
    asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "human"))
    asyncio.run(buyer.check_payment(PAYMENT))
    assert len(http.calls) == 2
    assert http.calls[1].headers["authorization"] == f"L402 {MAC}"
    assert http.calls[1].headers["accept"] == "application/json, */*"


_D_FREE = "The tool returned a result. Nothing was paid."
_D_PAID = (
    "The tool returned a result after one Lightning payment. "
    "The token is stored for later calls to this tool while it has uses or time."
)
_D_REUSED = "The tool returned a result with a stored token. Nothing new was paid."
_D_SETTLED = (
    "The invoice is settled and the tool returned a result. "
    "The token is stored for later calls to this tool while it has uses or time."
)
_D_X402 = (
    "The tool returned a result. payment_response, when present, is the settlement report "
    "(success, transaction, network, payer). This server did not sign the payment and did not log it."
)
_REMOTE_HUMAN = (
    "Pay this invoice from any Lightning wallet, then call remote_call_tool again with the same url and tool. "
    "Do not send a preimage. The same invoice is used until it expires. Do not call check_payment for a remote tool."
)
_REMOTE_PAY_DETAIL = (
    "This MCP server does not hold a buyer private key, does not sign, and does not submit this payment. "
    "Satsgate does not custody, forward, or refund it. "
    "Pay the exact atomic amount from an external wallet, on the network and asset in this offer, to pay_to, "
    "for resource_url. Then call remote_call_tool again with the same url and tool and payment_signature set to "
    "that PAYMENT-SIGNATURE. It is sent inside the tool call, never together with an L402 Authorization. "
    "The proxy verifies, calls the tool, and settles only after the tool succeeds. If the tool fails, nothing is settled. "
    "Retry the same PAYMENT-SIGNATURE."
)
_PENDING_DETAIL = (
    "The invoice is not settled yet. Pay it if you have not, then call remote_call_tool again with the same url and tool. "
    "Do not pay a second invoice."
)
_PREIMAGE_DETAIL = (
    "The payee wallet did not advertise LUD-21 verify, so a retry without the preimage cannot finish. "
    "Call remote_call_tool with mode nwc, which pays with the preimage, or use a wallet that can show the preimage."
)
_SUCCESS_KEYS = [
    "ok",
    "url",
    "tool",
    "protocol_version",
    "is_error",
    "content",
    "structured_content",
    "paid",
    "paid_with",
    "paid_sats",
    "reused_token",
    "payment_hash",
    "uses_remaining",
    "access_until",
    "detail",
]


def _key(tool: str = "echo", url: str = URL) -> str:
    return "mcp " + json.dumps([url, tool], separators=(",", ":"), ensure_ascii=False)


def _lightning(tool: str = "echo", **extra) -> dict:
    lightning = {
        "amount_sats": 21,
        "invoice": INVOICE,
        "invoice_expires_at": NOW + 3600,
        "macaroon": MAC,
        "payment_hash": PAYMENT,
        "resource": "route:tools:echo",
        "max_uses": 5,
    }
    fields = {"error": "payment_required", "tool": tool, "lightning": lightning}
    fields.update(extra)
    return fields


def _priced(body_id: int, structured: dict, *, headers: dict | None = None) -> httpx.Response:
    return _rpc(body_id, {"isError": True, "content": [], "structuredContent": structured}, headers=headers)


def _tool_ok(body_id: int, text: str = "hello", *, meta: dict | None = None, headers: dict | None = None) -> httpx.Response:
    result: dict = {"isError": False, "content": [{"type": "text", "text": text}]}
    if meta is not None:
        result["_meta"] = meta
    return _rpc(body_id, result, headers=headers)


def _calls(http, method: str) -> list:
    return [call for call in http.calls if _rpc_method(call) == method]


def test_rc_4_1_free_tool_success_payload(tmp_path: Path) -> None:
    def on_call(_request, body):
        return _tool_ok(body["id"], "hello")

    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert list(result.payload) == _SUCCESS_KEYS
    assert result.payload == {
        "ok": True,
        "url": URL,
        "tool": "echo",
        "protocol_version": "2026-07-28",
        "is_error": False,
        "content": [{"type": "text", "text": "hello"}],
        "structured_content": None,
        "paid": False,
        "paid_with": None,
        "paid_sats": None,
        "reused_token": False,
        "payment_hash": None,
        "uses_remaining": None,
        "access_until": None,
        "detail": _D_FREE,
    }
    assert wallet.invoices == []
    assert len(_calls(http, "tools/call")) == 1


def test_rc_4_2_tool_error_keeps_no_token(tmp_path: Path) -> None:
    def on_call(_request, body):
        return _rpc(body["id"], {"isError": True, "content": [{"type": "text", "text": "nope"}]})

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["ok"] is False
    assert result.payload["error"] == "tool_error"
    assert result.payload["is_error"] is True
    assert result.payload["token_kept"] is False
    assert result.payload["paid"] is False
    assert result.payload["detail"] == "The tool returned an error result. Nothing was paid."
    assert wallet.invoices == []


def test_rc_4_3_jsonrpc_error_is_scrubbed_and_cut(tmp_path: Path) -> None:
    noisy = MAC + ("x" * 600)

    def on_call(_request, body):
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": noisy}},
        )

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    buyer._now = Clock()
    _save_token(buyer)
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "rpc_error"
    assert result.payload["rpc_code"] == -32000
    assert len(result.payload["rpc_message"]) == 500
    assert MAC not in result.payload["rpc_message"]
    assert result.payload["rpc_message"].startswith("[redacted]")
    assert result.payload["detail"].startswith("The server answered with a JSON-RPC error.")
    assert wallet.invoices == []


@pytest.mark.parametrize("message", ["accept_json_and_sse_required", "header_mismatch"])
def test_rc_4_4_proxy_precheck_is_an_rpc_error(tmp_path: Path, message: str) -> None:
    def on_call(_request, body):
        return httpx.Response(
            400,
            json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": message}},
        )

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "rpc_error"
    assert result.payload["http_status"] == 400
    assert result.payload["rpc_message"] == message
    assert wallet.invoices == []


@pytest.mark.parametrize("status", [404, 406, 500])
def test_rc_4_5_http_error_without_an_offer_is_not_paid(tmp_path: Path, status: int) -> None:
    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=lambda _request, _body: httpx.Response(status)))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "request_failed"
    assert result.payload["http_status"] == status
    assert result.payload["paid"] is False
    assert wallet.invoices == []


def test_rc_4_6_input_required_is_not_supported(tmp_path: Path) -> None:
    def on_call(_request, body):
        return _rpc(body["id"], {"resultType": "input_required", "isError": False, "content": []})

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "input_required_not_supported"
    assert result.payload["detail"].startswith("The tool asked for more input. This client does not support that.")
    assert wallet.invoices == []


def test_rc_4_7_oversized_call_response_is_returned(tmp_path: Path) -> None:
    sample = _tool_ok(1, "z" * 2000)
    limit = len(sample.content) - 1

    def on_call(_request, body):
        return _tool_ok(body["id"], "z" * 2000)

    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=on_call), max_body_bytes=limit)
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "response_too_large"
    assert len(_calls(http, "tools/call")) == 1
    assert wallet.invoices == []


def test_rc_4_8_in_band_paywall_errors_pass_the_hint(tmp_path: Path) -> None:
    cases = [
        ("rate_limited", {"retry-after": "7"}, 7),
        ("paywall_unavailable", None, None),
        ("one_rail_only", None, None),
    ]
    for code, headers, retry in cases:
        structured = {"error": code, "tool": "echo", "hint": "Wait and retry the same call."}
        if retry is not None:
            structured["retry_after_seconds"] = retry
        buyer, _http, wallet = _buyer(tmp_path / code, _origin(on_call=lambda _request, body, structured=structured, headers=headers: _priced(body["id"], structured, headers=headers)))
        result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
        assert result.payload["error"] == code
        assert result.payload["paywall"] is True
        assert result.payload["hint"] == "Wait and retry the same call."
        assert result.payload["paid"] is False
        if retry is None:
            assert "retry_after_seconds" not in result.payload
        else:
            assert result.payload["retry_after_seconds"] == 7
        assert wallet.invoices == []


def test_rc_4_9_a_notice_for_another_tool_is_not_paid(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(
        tmp_path,
        _origin(on_call=lambda _request, body: _priced(body["id"], _lightning("other"))),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert result.payload["error"] == "offer_mismatch"
    assert result.payload["detail"] == "The price notice names another tool. It was not paid."
    assert wallet.invoices == []
    assert len(_calls(http, "tools/call")) == 1


def test_rc_4_10_amount_mismatch_is_not_paid(tmp_path: Path) -> None:
    from test_satsgate_mcp import SPEC_INVOICE

    structured = _lightning()
    structured["lightning"] = dict(structured["lightning"])
    structured["lightning"]["invoice"] = SPEC_INVOICE
    structured["lightning"]["amount_sats"] = 21
    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=lambda _request, body: _priced(body["id"], structured)))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "amount_mismatch"
    assert "21" in result.payload["detail"]
    assert wallet.invoices == []


def test_rc_4_11_extra_paywall_key_stays_a_tool_error(tmp_path: Path) -> None:
    structured = {"error": "rate_limited", "tool": "echo", "extra": "no"}

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=lambda _request, body: _priced(body["id"], structured)))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "tool_error"
    assert result.payload.get("paywall") is not True
    assert wallet.invoices == []


def test_rc_4_12_classic_402_and_in_band_offers_match(tmp_path: Path) -> None:
    def classic(_request, _body):
        return _challenge(amount=21, max_uses=5, payment=PAYMENT, invoice=INVOICE, macaroon=MAC, expires=NOW + 3600)

    def notice(_request, body):
        structured = _lightning()
        structured["lightning"] = dict(structured["lightning"], resource="route:article")
        return _priced(body["id"], structured)

    buyer, _http, first_wallet = _buyer(tmp_path / "classic", _origin(on_call=classic))
    buyer._now = Clock()
    first = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    buyer, _http, second_wallet = _buyer(tmp_path / "notice", _origin(on_call=notice))
    buyer._now = Clock()
    second = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert list(first.payload) == list(second.payload)
    assert first.payload == second.payload
    assert first_wallet.invoices == []
    assert second_wallet.invoices == []


def _header_view(call: httpx.Request) -> dict:
    return {key: value for key, value in call.headers.items() if key not in {"content-length", "host", "authorization"}}


def test_rc_5_1_nwc_pays_once_and_retries_the_same_call(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            return _tool_ok(body["id"], "paid")
        return _priced(body["id"], _lightning())

    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=on_call), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    buyer._now = Clock()
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", {"q": "one"}, mode="nwc"))
    calls = _calls(http, "tools/call")
    assert len(calls) == 2
    assert _header_view(calls[0]) == _header_view(calls[1])
    unpaid = _body(calls[0])
    paid = _body(calls[1])
    assert unpaid["id"] != paid["id"]
    unpaid.pop("id")
    paid.pop("id")
    assert unpaid == paid
    assert "authorization" not in calls[0].headers
    assert calls[1].headers["authorization"] == f"L402 {MAC}:{PREIMAGE.lower()}"
    assert wallet.invoices == [INVOICE]
    assert buyer.store.spent_since(0) == 21
    token = buyer.store.token_for(_key())
    assert token["uses_remaining"] == 4
    assert buyer.store.quote_for(_key()) is None
    assert result.payload["paid"] is True
    assert result.payload["paid_with"] == "lightning"
    assert result.payload["paid_sats"] == 21
    assert result.payload["detail"] == _D_PAID
    assert result.payload["content"] == [{"type": "text", "text": "paid"}]


def test_rc_5_2_caps_refuse_before_the_wallet(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(
        tmp_path,
        _origin(on_call=lambda _request, body: _priced(body["id"], _lightning())),
        nwc_uri=NWC,
        max_payment_sats=1,
        daily_max_sats=500,
    )
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert result.payload["error"] == "over_budget"
    assert result.payload["tool"] == "echo"
    assert wallet.invoices == []
    assert buyer.store.quote_for(_key())["payment_hash"] == PAYMENT
    assert len(_calls(http, "tools/call")) == 1


def test_rc_5_3_missing_nwc_uri_is_not_paid(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=lambda _request, body: _priced(body["id"], _lightning())))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert caught.value.code == "nwc_not_configured"
    assert wallet.invoices == []
    assert len(_calls(http, "tools/call")) == 1


def test_rc_5_4_human_offer_uses_the_remote_wording(tmp_path: Path) -> None:
    buyer, _http, wallet = _buyer(tmp_path / "bolt", _origin(on_call=lambda _request, body: _priced(body["id"], _lightning())))
    buyer._now = Clock()
    offer = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert offer.payload["detail"] == _REMOTE_HUMAN
    assert offer.payload["summary"].startswith("Tool echo: ")
    assert offer.payload["qr_text"]
    assert offer.qr_png is not None and offer.qr_png.startswith(b"\x89PNG")
    assert buyer.store.quote_for(_key())["cache_key"] == _key()
    assert wallet.invoices == []

    structured = _lightning()
    structured["x402Version"] = 2
    structured["resource"] = {"url": RESOURCE, "description": "", "mimeType": "application/json"}
    structured["accepts"] = [_accept()]
    structured["x402"] = {
        "scheme": "exact",
        "network": "eip155:84532",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "amount": "10000",
        "payTo": "0x862E9Fd82d2AC9D3938051C29e65Eb9C71923010",
        "expires_at": NOW + 60,
    }
    buyer, _http, _wallet = _buyer(
        tmp_path / "dual",
        _origin(on_call=lambda _request, body: _priced(body["id"], structured)),
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=5_000_000,
    )
    buyer._now = Clock()
    dual = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert dual.payload["x402"]["payment"]["detail"] == _REMOTE_PAY_DETAIL
    assert dual.payload["detail"].startswith(_REMOTE_HUMAN)
    assert "This price notice also offers USDC." in dual.payload["detail"]


def test_rc_5_5_human_reuses_the_quote_after_two_minutes(tmp_path: Path) -> None:
    state = {"n": 0}

    def on_call(request, body):
        state["n"] += 1
        if request.headers.get("authorization"):
            return _priced(
                body["id"],
                {"error": "payment_pending", "tool": "echo", "payment_hash": PAYMENT, "retry_after_seconds": 2, "hint": "wait"},
                headers={"retry-after": "2"},
            )
        return _priced(body["id"], _lightning())

    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    clock = Clock()
    buyer._now = clock
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    clock.now += 120
    pending = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    unpaid = [call for call in _calls(http, "tools/call") if "authorization" not in call.headers]
    assert len(unpaid) == 1
    assert pending.payload["error"] == "payment_pending"
    assert pending.payload["payment_hash"] == PAYMENT
    assert pending.payload["retry_after_seconds"] == 2
    assert pending.payload["detail"] == _PENDING_DETAIL
    assert buyer.store.quote_for(_key())["payment_hash"] == PAYMENT
    assert wallet.invoices == []


def test_rc_5_6_human_settlement_stores_a_token_without_a_preimage(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            assert request.headers["authorization"] == f"L402 {MAC}"
            return _tool_ok(body["id"], "settled")
        return _priced(body["id"], _lightning())

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    done = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    token = buyer.store.token_for(_key())
    assert done.payload["detail"] == _D_SETTLED
    assert done.payload["paid"] is False
    assert done.payload["paid_with"] == "lightning"
    assert token["preimage"] is None
    assert token["uses_remaining"] == 4
    assert buyer.store.quote_for(_key()) is None
    assert wallet.invoices == []


def test_rc_5_7_same_hash_preimage_notice_keeps_the_macaroon(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            fresh = _lightning()
            fresh["reason"] = "preimage_required"
            fresh["lightning"] = dict(fresh["lightning"], macaroon="bmV3LW1hY2Fyb29u")
            return _priced(body["id"], fresh)
        return _priced(body["id"], _lightning())

    buyer, _http, _wallet = _buyer(tmp_path, _origin(on_call=on_call))
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    stored = buyer.store.quote_for(_key())["macaroon"]
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert result.payload["error"] == "preimage_required"
    assert result.payload["detail"] == _PREIMAGE_DETAIL
    assert buyer.store.quote_for(_key())["macaroon"] == stored == MAC


def test_rc_5_8_human_with_an_api_key_asks_core_before_the_call(tmp_path: Path) -> None:
    phase = {"value": "pending"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "core.test":
            assert "consume=false" in str(request.url)
            if phase["value"] == "pending":
                return httpx.Response(200, json={"ok": True, "status": "pending", "settled": False, "payment_hash": PAYMENT})
            return httpx.Response(200, json={"ok": True, "status": "settled", "settled": True, "payment_hash": PAYMENT})
        body = _body(request)
        if body.get("method") == "tools/call":
            if request.headers.get("authorization"):
                return _tool_ok(body["id"], "after-core")
            return _priced(body["id"], _lightning())
        return _origin()(request)

    buyer, http, _wallet = _buyer(tmp_path / "pending", handler, api_key="sgr_testkeyvalue")
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    waiting = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert waiting.payload["error"] == "payment_pending"
    assert len(_calls(http, "tools/call")) == 1

    phase["value"] = "settled"
    buyer, http, _wallet = _buyer(tmp_path / "settled", handler, api_key="sgr_testkeyvalue")
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    done = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    calls = _calls(http, "tools/call")
    assert len(calls) == 2
    assert calls[1].headers["authorization"] == f"L402 {MAC}"
    assert done.payload["content"] == [{"type": "text", "text": "after-core"}]


def test_rc_5_9_an_expired_quote_sends_an_unpaid_call(tmp_path: Path) -> None:
    seen = {"unpaid": 0}

    def on_call(request, body):
        if not request.headers.get("authorization"):
            seen["unpaid"] += 1
        return _priced(body["id"], _lightning())

    buyer, _http, _wallet = _buyer(tmp_path, _origin(on_call=on_call))
    clock = Clock()
    buyer._now = clock
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    row = buyer.store.quote_for(_key())
    buyer.store._conn.execute("UPDATE quotes SET invoice_expires_at = ? WHERE payment_hash = ?", (clock.now - 1, row["payment_hash"]))
    buyer.store._conn.commit()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert seen["unpaid"] == 2


def test_rc_5_10_nwc_pays_a_stored_quote_without_an_unpaid_call(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            return _tool_ok(body["id"], "from-quote")
        return _priced(body["id"], _lightning())

    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=on_call), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    before = len(http.calls)
    asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    fresh = http.calls[before:]
    assert all(_rpc_method(call) != "tools/call" or "authorization" in call.headers for call in fresh)
    assert wallet.invoices == [INVOICE]
    assert len([call for call in fresh if _rpc_method(call) == "tools/call"]) == 1


def test_rc_5_11_a_fresh_notice_on_the_retry_is_not_paid_again(tmp_path: Path) -> None:
    other = "cd" * 32

    def on_call(request, body):
        if request.headers.get("authorization"):
            return _priced(body["id"], _lightning())
        structured = _lightning()
        structured["lightning"] = dict(structured["lightning"], payment_hash=other, invoice="lnbc1psecond")
        return _priced(body["id"], structured)

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    buyer._now = Clock()
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert len(wallet.invoices) == 1
    assert result.payload["action"] == "requote"
    assert result.payload.get("auto_paid") is False
    assert result.qr_png is not None


def test_rc_5_12_a_paid_failure_keeps_the_full_token(tmp_path: Path) -> None:
    failures = [
        lambda body: _rpc(body["id"], {"isError": True, "content": [{"type": "text", "text": "nope"}]}),
        lambda body: httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "down"}}),
        lambda _body: httpx.Response(500, content=b"down"),
    ]
    for index, failure in enumerate(failures):
        state = {"auth": 0}

        def on_call(request, body, failure=failure, state=state):
            if request.headers.get("authorization"):
                state["auth"] += 1
                if state["auth"] == 1:
                    return failure(body)
                return _tool_ok(body["id"], "kept")
            return _priced(body["id"], _lightning())

        buyer, http, wallet = _buyer(
            tmp_path / str(index),
            _origin(on_call=on_call),
            nwc_uri=NWC,
            max_payment_sats=100,
            daily_max_sats=500,
        )
        buyer._now = Clock()
        failed = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
        assert failed.payload["paid"] is True
        assert failed.payload["token_kept"] is True
        assert buyer.store.token_for(_key())["uses_remaining"] == 5
        again = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
        assert again.payload["reused_token"] is True
        assert wallet.invoices == [INVOICE]
        assert len([call for call in http.calls if call.headers.get("authorization")]) >= 2


class _BrokenWallet:
    def __init__(self) -> None:
        self.invoices: list[str] = []

    async def pay_invoice(self, invoice: str) -> str:
        self.invoices.append(invoice)
        raise NwcError("wallet down")


def test_rc_5_13_wallet_failure_sends_no_retry_and_records_no_spend(tmp_path: Path) -> None:
    wallet = _BrokenWallet()
    buyer, http, _wallet = _buyer(
        tmp_path,
        _origin(on_call=lambda _request, body: _priced(body["id"], _lightning())),
        wallet=wallet,
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert caught.value.code == "nwc_failed"
    assert len(_calls(http, "tools/call")) == 1
    assert buyer.store.spent_since(0) == 0


def test_rc_5_14_payloads_and_logs_hide_the_macaroon_and_preimage(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            return _tool_ok(body["id"], "hidden")
        return _priced(body["id"], _lightning())

    buyer, _http, _wallet = _buyer(tmp_path, _origin(on_call=on_call), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    buyer._now = Clock()
    with caplog.at_level(logging.DEBUG, logger="satsgate_mcp"):
        offer = asyncio.run(buyer.remote_call_tool(URL, "echo"))
        paid = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    offer_text = json.dumps(offer.payload)
    paid_text = json.dumps(paid.payload)
    assert INVOICE in offer_text
    assert MAC not in offer_text
    assert PREIMAGE not in offer_text
    assert INVOICE not in paid_text
    assert MAC not in paid_text
    assert PREIMAGE not in paid_text
    assert MAC not in caplog.text
    assert PREIMAGE not in caplog.text
    assert INVOICE not in caplog.text


def test_rc_5_15_a_timeout_on_the_paid_retry_keeps_the_token(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            raise httpx.ReadTimeout("slow")
        return _priced(body["id"], _lightning())

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call), nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    buyer._now = Clock()
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert result.payload["error"] == "timeout"
    assert result.payload["paid"] is True
    assert result.payload["token_kept"] is True
    assert buyer.store.spent_since(0) == 21
    assert wallet.invoices == [INVOICE]


def test_rc_6_1_a_usable_token_is_sent_before_an_unpaid_call(tmp_path: Path) -> None:
    def on_call(request, body):
        assert request.headers["authorization"] == f"L402 {MAC}:{PREIMAGE}"
        return _tool_ok(body["id"], "reused")

    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    buyer._now = Clock()
    _save_token(buyer, uses=5)
    result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert len(_calls(http, "tools/call")) == 1
    assert result.payload["detail"] == _D_REUSED
    assert result.payload["reused_token"] is True
    assert result.payload["paid"] is False
    assert buyer.store.token_for(_key())["uses_remaining"] == 4
    assert wallet.invoices == []


def test_rc_6_2_a_pass_expires_one_second_after_access_until(tmp_path: Path) -> None:
    buyer, http, wallet = _buyer(tmp_path, _origin(on_call=lambda request, body: _tool_ok(body["id"], "pass")))
    clock = Clock()
    buyer._now = clock
    _save_token(buyer, preimage=None, uses=5)
    buyer.store._conn.execute(
        "UPDATE tokens SET max_uses = NULL, uses_remaining = NULL, access_seconds = 30, access_until = ? WHERE cache_key = ?",
        (clock.now + 30, _key()),
    )
    buyer.store._conn.commit()
    first = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert first.payload["reused_token"] is True
    assert len(_calls(http, "tools/call")) == 1
    clock.now += 31
    http.calls.clear()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert "authorization" not in _calls(http, "tools/call")[0].headers
    assert wallet.invoices == []


def test_rc_6_3_a_rejected_token_is_requoted_without_payment(tmp_path: Path) -> None:
    def on_call(_request, body):
        return _priced(body["id"], _lightning(reason="token_used_up"))

    for mode, auto in (("human", False), ("nwc", False)):
        buyer, _http, wallet = _buyer(
            tmp_path / mode,
            _origin(on_call=on_call),
            nwc_uri=NWC,
            max_payment_sats=100,
            daily_max_sats=500,
            auto_pay=auto,
        )
        buyer._now = Clock()
        _save_token(buyer)
        result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode=mode))
        assert buyer.store.token_for(_key()) is None
        assert result.payload["action"] == "requote"
        assert result.payload["auto_paid"] is False
        assert result.payload["detail"] == (
            "The server rejected the token (token_used_up). Here is a new quote. "
            "It was not paid. Call remote_call_tool again if you want to pay it."
        )
        assert wallet.invoices == []


def test_rc_6_4_auto_pay_pays_a_requote_once(tmp_path: Path) -> None:
    state = {"n": 0}

    def on_call(request, body):
        state["n"] += 1
        if state["n"] > 1 and request.headers.get("authorization"):
            return _tool_ok(body["id"], "auto")
        return _priced(body["id"], _lightning(reason="token_used_up"))

    buyer, _http, wallet = _buyer(
        tmp_path,
        _origin(on_call=on_call),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
        auto_pay=True,
    )
    buyer._now = Clock()
    _save_token(buyer)
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert wallet.invoices == [INVOICE]
    assert result.payload["paid"] is True
    assert result.payload["detail"] == _D_PAID


def test_rc_6_5_tokens_do_not_cross_tools_or_urls(tmp_path: Path) -> None:
    other = "https://other.example/mcp"

    def on_call(request, body):
        assert "authorization" not in request.headers
        return _tool_ok(body["id"], "fresh")

    buyer, _http, _wallet = _buyer(tmp_path, _origin(tools=[_echo_tool("echo"), _echo_tool("other")], on_call=on_call))
    _save_token(buyer, tool="echo")
    asyncio.run(buyer.remote_call_tool(URL, "other"))
    asyncio.run(buyer.remote_call_tool(other, "echo"))
    assert _key("echo") != f"POST {URL}"
    assert buyer.store.token_for(_key("echo"))["uses_remaining"] == 5


def test_rc_6_6_the_cache_key_keeps_a_non_ascii_tool_name(tmp_path: Path) -> None:
    name = "caf\u00e9"
    buyer, _http, _wallet = _buyer(tmp_path, _origin(tools=[_echo_tool(name)], on_call=lambda _request, body: _tool_ok(body["id"])))
    buyer._now = Clock()
    _save_token(buyer, tool=name)
    asyncio.run(buyer.remote_call_tool(URL, name))
    expected = 'mcp ["https://shop.example/mcp","caf\u00e9"]'
    assert _key(name) == expected
    assert buyer.store.token_for(expected)["uses_remaining"] == 4


def _signature_object() -> tuple[dict, str]:
    document = {"accepted": "yes", "nonce": "nonce-remote-tool"}
    encoded = base64.standard_b64encode(json.dumps(document, separators=(",", ":")).encode()).decode("ascii")
    return document, encoded


def _x402_notice(tool: str = "echo", *, expires: int = NOW + 3600) -> dict:
    return {
        "error": "payment_required",
        "tool": tool,
        "x402Version": 2,
        "resource": {"url": RESOURCE, "description": "", "mimeType": "application/json"},
        "accepts": [_accept()],
        "x402": {
            "scheme": "exact",
            "network": "eip155:84532",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "amount": "10000",
            "payTo": "0x862E9Fd82d2AC9D3938051C29e65Eb9C71923010",
            "expires_at": expires,
        },
    }


def _usd_buyer(tmp_path: Path, handler, **overrides):
    buyer, http, wallet = _buyer(
        tmp_path,
        handler,
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=5_000_000,
        **overrides,
    )
    buyer._now = Clock()
    return buyer, http, wallet


def test_rc_7_1_x402_only_notice_asks_an_external_wallet(tmp_path: Path) -> None:
    buyer, _http, wallet = _usd_buyer(tmp_path / "human", _origin(on_call=lambda _request, body: _priced(body["id"], _x402_notice())))
    human = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert human.payload["action"] == "pay_x402_external"
    assert human.payload["x402"]["payment"]["detail"] == _REMOTE_PAY_DETAIL
    assert buyer.store.quote_for(_key()) is not None
    assert wallet.invoices == []
    buyer, _http, _wallet = _usd_buyer(
        tmp_path / "nwc",
        _origin(on_call=lambda _request, body: _priced(body["id"], _x402_notice())),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    priced = asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert priced.payload["detail"].startswith("NWC pays a Lightning invoice. This price notice has no invoice. ")


def test_rc_7_2_signature_is_sent_only_inside_meta(tmp_path: Path) -> None:
    document, encoded = _signature_object()

    def on_call(_request, body):
        if "x402/payment" in (body.get("params") or {}).get("_meta", {}):
            return _tool_ok(body["id"], "signed")
        return _priced(body["id"], _x402_notice())

    buyer, http, _wallet = _usd_buyer(tmp_path / "modern", _origin(on_call=on_call))
    asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    signed = [call for call in _calls(http, "tools/call") if "x402/payment" in _body(call)["params"].get("_meta", {})]
    assert len(signed) == 1
    meta = _body(signed[0])["params"]["_meta"]
    assert meta["x402/payment"] == document
    assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert "payment-signature" not in signed[0].headers
    assert "authorization" not in signed[0].headers

    buyer, http, _wallet = _usd_buyer(tmp_path / "legacy", _origin(modern=False, on_call=on_call))
    asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    signed = [call for call in _calls(http, "tools/call") if "x402/payment" in _body(call)["params"].get("_meta", {})]
    assert len(signed) == 1
    assert _body(signed[0])["params"]["_meta"] == {"x402/payment": document}
    assert "payment-signature" not in signed[0].headers
    assert "authorization" not in signed[0].headers


def test_rc_7_3_object_settlement_records_usd_spend(tmp_path: Path) -> None:
    document, encoded = _signature_object()
    settlement = {"success": True, "transaction": "0x" + "ab" * 32, "tx": "0x" + "ab" * 32, "network": "eip155:84532", "payer": "0x" + "11" * 20}

    def on_call(request, body):
        if "x402/payment" in (body.get("params") or {}).get("_meta", {}):
            return _tool_ok(body["id"], "settled", meta={"x402/payment-response": settlement})
        return _priced(body["id"], _x402_notice())

    buyer, _http, _wallet = _usd_buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert result.payload["payment_response"] == settlement
    assert result.payload["signature_sent"] is True
    assert result.payload["retry_same_payment_signature"] is False
    assert result.payload["amount_atomic"] == "10000"
    assert result.payload["amount_display"] == "0.01 USDC"
    assert result.payload["detail"] == _D_X402
    assert buyer.store.spent_usd_since(0) == 10000
    assert document["nonce"] not in json.dumps(result.payload)


def test_rc_7_4_header_settlement_is_read(tmp_path: Path) -> None:
    _document, encoded = _signature_object()
    settlement = {"success": True, "transaction": "0x" + "cd" * 32, "network": "eip155:84532", "payer": "0x" + "22" * 20}
    header = base64.standard_b64encode(json.dumps(settlement).encode()).decode("ascii")

    def on_call(_request, body):
        if "x402/payment" in (body.get("params") or {}).get("_meta", {}):
            return _tool_ok(body["id"], "header", headers={"payment-response": header})
        return _priced(body["id"], _x402_notice())

    buyer, _http, _wallet = _usd_buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert result.payload["payment_response"]["success"] is True
    assert result.payload["payment_response"]["transaction"] == "0x" + "cd" * 32
    assert "tx" not in result.payload["payment_response"]


def test_rc_7_5_tool_error_after_a_signature_spends_nothing(tmp_path: Path) -> None:
    _document, encoded = _signature_object()

    def on_call(_request, body):
        if "x402/payment" in (body.get("params") or {}).get("_meta", {}):
            return _rpc(body["id"], {"isError": True, "content": [{"type": "text", "text": "nope"}]})
        return _priced(body["id"], _x402_notice())

    buyer, _http, _wallet = _usd_buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert result.payload["error"] == "tool_error"
    assert result.payload["retry_same_payment_signature"] is True
    assert buyer.store.spent_usd_since(0) == 0


@pytest.mark.parametrize("code", ["x402_rejected", "x402_replay", "expired", "bad_signature"])
def test_rc_7_6_x402_error_codes_set_the_retry_flag(tmp_path: Path, code: str) -> None:
    _document, encoded = _signature_object()

    def on_call(_request, body):
        if "x402/payment" in (body.get("params") or {}).get("_meta", {}):
            return _priced(body["id"], {"error": code, "tool": "echo", "hint": "see detail"})
        return _priced(body["id"], _x402_notice())

    buyer, _http, _wallet = _usd_buyer(tmp_path, _origin(on_call=on_call))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert result.payload["error"] == code
    assert result.payload["detail"] == _X402_ERRORS[code]
    assert result.payload["retry_same_payment_signature"] is (code not in _X402_RETRY_NEW)
    assert buyer.store.spent_usd_since(0) == 0


def test_rc_7_7_over_the_usd_cap_does_not_send_the_signature(tmp_path: Path) -> None:
    _document, encoded = _signature_object()
    buyer, http, _wallet = _buyer(
        tmp_path,
        _origin(on_call=lambda _request, body: _priced(body["id"], _x402_notice())),
        max_payment_usd_atomic=1,
        daily_max_usd_atomic=1,
    )
    buyer._now = Clock()
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert result.payload["signature_sent"] is False
    assert result.payload["ok"] is False
    for call in http.calls:
        if call.content:
            assert "x402/payment" not in call.content.decode("utf-8", errors="replace")


def test_rc_7_8_a_lightning_only_notice_does_not_send_the_signature(tmp_path: Path) -> None:
    _document, encoded = _signature_object()
    buyer, http, _wallet = _usd_buyer(tmp_path, _origin(on_call=lambda _request, body: _priced(body["id"], _lightning())))
    result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert result.payload["error"] == "x402_not_offered"
    assert result.payload["signature_sent"] is False
    assert "x402/payment" not in http.calls[-1].content.decode()


def test_rc_7_9_a_fresh_x402_quote_skips_the_unpaid_call(tmp_path: Path) -> None:
    document, encoded = _signature_object()

    def on_call(_request, body):
        meta = (body.get("params") or {}).get("_meta") or {}
        if "x402/payment" in meta:
            return _tool_ok(body["id"], "quoted")
        return _priced(body["id"], _x402_notice())

    buyer, http, _wallet = _usd_buyer(tmp_path / "fresh", _origin(on_call=on_call))
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    before = len(_calls(http, "tools/call"))
    asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    fresh = _calls(http, "tools/call")[before:]
    assert len(fresh) == 1
    assert _body(fresh[0])["params"]["_meta"]["x402/payment"] == document

    buyer, http, _wallet = _usd_buyer(tmp_path / "stale", _origin(on_call=on_call))
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    stored = json.loads(buyer.store.quote_for(_key())["x402_json"])
    stored["expires_at"] = buyer._now() - 5
    buyer.store._conn.execute(
        "UPDATE quotes SET invoice_expires_at = ?, x402_json = ? WHERE cache_key = ?",
        (buyer._now() - 5, json.dumps(stored), _key()),
    )
    buyer.store._conn.commit()
    before = len(_calls(http, "tools/call"))
    asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    stale = _calls(http, "tools/call")[before:]
    assert len(stale) == 2
    assert "x402/payment" not in _body(stale[0])["params"].get("_meta", {})
    assert "x402/payment" in _body(stale[1])["params"]["_meta"]


def test_rc_7_10_a_signature_does_not_send_the_lightning_token(tmp_path: Path) -> None:
    document, encoded = _signature_object()

    def on_call(_request, body):
        meta = (body.get("params") or {}).get("_meta") or {}
        if "x402/payment" in meta:
            return _tool_ok(body["id"], "meta-only")
        return _priced(body["id"], _x402_notice())

    buyer, http, _wallet = _usd_buyer(tmp_path, _origin(on_call=on_call))
    _save_token(buyer)
    asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    signed = [call for call in _calls(http, "tools/call") if "x402/payment" in _body(call)["params"].get("_meta", {})]
    assert len(signed) == 1
    assert "authorization" not in signed[0].headers
    assert _body(signed[0])["params"]["_meta"]["x402/payment"] == document
    assert buyer.store.token_for(_key())["uses_remaining"] == 5
    assert buyer.store.token_for(_key())["macaroon"] == MAC


def test_rc_7_11_the_signature_is_not_stored_logged_or_returned(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    document, encoded = _signature_object()

    def on_call(_request, body):
        meta = (body.get("params") or {}).get("_meta") or {}
        if "x402/payment" in meta:
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "echo " + encoded}},
            )
        return _priced(body["id"], _x402_notice())

    buyer, _http, _wallet = _usd_buyer(tmp_path, _origin(on_call=on_call))
    with caplog.at_level(logging.DEBUG, logger="satsgate_mcp"):
        result = asyncio.run(buyer.remote_call_tool(URL, "echo", payment_signature=encoded))
    assert encoded not in result.payload["rpc_message"]
    assert encoded not in caplog.text
    assert document["nonce"] not in caplog.text
    blob = (tmp_path / "satsgate-mcp.sqlite").read_bytes()
    assert encoded.encode() not in blob
    assert document["nonce"].encode() not in blob


def test_rc_7_12_a_generic_x402_notice_is_payable(tmp_path: Path) -> None:
    document = {
        "x402Version": 2,
        "resource": {"url": RESOURCE, "description": "", "mimeType": "application/json"},
        "accepts": [_accept()],
    }

    def structured(_request, body):
        return _rpc(body["id"], {"isError": True, "structuredContent": document})

    def textual(_request, body):
        return _rpc(body["id"], {"isError": True, "content": [{"type": "text", "text": json.dumps(document)}]})

    for name, handler in (("structured", structured), ("text", textual)):
        buyer, _http, wallet = _usd_buyer(tmp_path / name, _origin(on_call=handler))
        result = asyncio.run(buyer.remote_call_tool(URL, "echo"))
        assert result.payload["action"] == "pay_x402_external"
        assert result.payload["x402"]["payable"] is True
        assert wallet.invoices == []


def _quote_row(cache_key: str) -> dict:
    return {
        "payment_hash": PAYMENT,
        "cache_key": cache_key,
        "method": "POST",
        "url": URL,
        "macaroon": MAC,
        "invoice": INVOICE,
        "resource": "route:tools:echo",
        "amount_sats": 21,
        "max_uses": 5,
        "access_seconds": None,
        "invoice_expires_at": NOW + 3600,
        "reason": None,
        "request_body": None,
        "created_at": NOW,
        "x402_json": None,
    }


def test_rc_9_1_check_payment_refuses_a_remote_quote(tmp_path: Path) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin())
    buyer.store.save_quote(_quote_row(_key()))
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.check_payment(PAYMENT))
    assert caught.value.code == "remote_tool_payment"
    assert caught.value.message == (
        "This payment_hash belongs to a remote MCP tool call. "
        "Call remote_call_tool again with the same url and tool. Nothing was sent."
    )
    assert http.calls == []


def test_rc_9_2_check_payment_refuses_a_remote_token(tmp_path: Path) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin())
    _save_token(buyer)
    with pytest.raises(BuyerError) as caught:
        asyncio.run(buyer.check_payment(PAYMENT))
    assert caught.value.code == "remote_tool_payment"
    assert caught.value.message == (
        "This payment_hash belongs to a remote MCP tool call. "
        "Call remote_call_tool again with the same url and tool. Nothing was sent."
    )
    assert http.calls == []


def test_rc_9_3_resume_refuses_a_remote_quote_without_a_request(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    buyer, http, _wallet = _buyer(tmp_path, _origin())
    buyer.store.save_quote(_quote_row(_key()))
    code = asyncio.run(_run(["--resume", PAYMENT], buyer=buyer, now=Clock(), sleep=lambda _seconds: asyncio.sleep(0)))
    captured = capsys.readouterr()
    assert code == 1
    assert "Call remote_call_tool again with the same url and tool. Nothing was sent." in captured.err
    assert http.calls == []


def test_rc_9_4_challenge_status_still_reads_a_remote_payment_hash(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.host == "core.test"
        assert "consume=false" in str(request.url)
        assert request.headers["x-api-key"] == "sgr_testkeyvalue"
        return httpx.Response(200, json={"ok": True, "status": "pending", "settled": False, "payment_hash": PAYMENT})

    buyer, http, _wallet = _buyer(tmp_path, handler, api_key="sgr_testkeyvalue")
    buyer.store.save_quote(_quote_row(_key()))
    result = asyncio.run(buyer.challenge_status(PAYMENT))
    assert result["payment_hash"] == PAYMENT
    assert result["consume"] is False
    assert len(http.calls) == 1
    assert http.calls[0].url.path == f"/v1/paywall/status/{PAYMENT}"


def test_rc_9_5_pay_and_fetch_and_check_payment_keep_their_request_shape(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"] == "application/json, */*"
        if request.headers.get("authorization"):
            return _paid("article")
        return _challenge()

    buyer, http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC, max_payment_sats=100, daily_max_sats=500)
    paid = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert len(http.calls) == 2
    assert http.calls[0].method == "GET"
    assert http.calls[0].url == "https://shop.example/a"
    assert "authorization" not in http.calls[0].headers
    assert http.calls[1].headers["authorization"] == f"L402 {MAC}:{PREIMAGE.lower()}"
    assert paid.payload["body"] == "article"
    assert wallet.invoices == [INVOICE]
    again = asyncio.run(buyer.check_payment(PAYMENT))
    assert len(http.calls) == 3
    assert http.calls[2].method == "GET"
    assert http.calls[2].url == "https://shop.example/a"
    assert http.calls[2].headers["authorization"] == f"L402 {MAC}:{PREIMAGE.lower()}"
    assert again.payload["body"] == "article"


class _GateWallet:
    def __init__(self) -> None:
        self.invoices: list[str] = []
        self.active = 0
        self.max_active = 0
        self.arrived = 0
        self.release = asyncio.Event()
        self.delay = 0.05
        self.barrier = 0

    async def pay_invoice(self, invoice: str) -> str:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.arrived += 1
        if self.barrier and self.arrived >= self.barrier:
            self.release.set()
        if self.barrier:
            await asyncio.wait_for(self.release.wait(), timeout=1)
        else:
            await asyncio.sleep(self.delay)
        self.active -= 1
        self.invoices.append(invoice)
        return PREIMAGE


def _parallel_notice(max_uses: int):
    def on_call(request, body):
        name = body["params"]["name"]
        if request.headers.get("authorization"):
            return _tool_ok(body["id"], "done")
        structured = _lightning(name)
        payment = PAYMENT if name == "echo" else "11" * 32
        structured["lightning"] = dict(structured["lightning"], max_uses=max_uses, payment_hash=payment)
        return _priced(body["id"], structured)

    return on_call


def test_rc_8_1_parallel_calls_share_one_payment(tmp_path: Path) -> None:
    wallet = _GateWallet()
    buyer, _http, _default = _buyer(
        tmp_path,
        _origin(on_call=_parallel_notice(10)),
        wallet=wallet,
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    buyer._now = Clock()

    async def run():
        return await asyncio.gather(
            buyer.remote_call_tool(URL, "echo", mode="nwc"),
            buyer.remote_call_tool(URL, "echo", mode="nwc"),
            buyer.remote_call_tool(URL, "echo", mode="nwc"),
        )

    results = asyncio.run(run())
    assert wallet.invoices == [INVOICE]
    assert wallet.max_active == 1
    assert [item.payload["ok"] for item in results] == [True, True, True]
    assert buyer.store.token_for(_key())["uses_remaining"] == 7


def test_rc_8_2_parallel_per_request_calls_pay_one_at_a_time(tmp_path: Path) -> None:
    wallet = _GateWallet()
    buyer, _http, _default = _buyer(
        tmp_path,
        _origin(on_call=_parallel_notice(1)),
        wallet=wallet,
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    buyer._now = Clock()

    async def run():
        return await asyncio.gather(
            buyer.remote_call_tool(URL, "echo", mode="nwc"),
            buyer.remote_call_tool(URL, "echo", mode="nwc"),
        )

    results = asyncio.run(run())
    assert wallet.invoices == [INVOICE, INVOICE]
    assert wallet.max_active == 1
    assert [item.payload["ok"] for item in results] == [True, True]


def test_rc_8_3_different_tools_pay_at_the_same_time(tmp_path: Path) -> None:
    wallet = _GateWallet()
    wallet.barrier = 2
    buyer, _http, _default = _buyer(
        tmp_path,
        _origin(tools=[_echo_tool("echo"), _echo_tool("other")], on_call=_parallel_notice(1)),
        wallet=wallet,
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    buyer._now = Clock()

    async def run():
        return await asyncio.gather(
            buyer.remote_call_tool(URL, "echo", mode="nwc"),
            buyer.remote_call_tool(URL, "other", mode="nwc"),
        )

    results = asyncio.run(run())
    assert wallet.max_active == 2
    assert len(wallet.invoices) == 2
    assert [item.payload["ok"] for item in results] == [True, True]


def test_rc_8_4_an_exception_releases_the_lock(tmp_path: Path) -> None:
    state = {"boom": True}

    def on_call(request, body):
        if state["boom"]:
            state["boom"] = False
            raise RuntimeError("boom")
        if request.headers.get("authorization"):
            return _tool_ok(body["id"], "after")
        return _priced(body["id"], _lightning())

    buyer, _http, wallet = _buyer(
        tmp_path,
        _origin(on_call=on_call),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    buyer._now = Clock()
    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    done = asyncio.run(asyncio.wait_for(buyer.remote_call_tool(URL, "echo", mode="nwc"), timeout=2))
    assert done.payload["ok"] is True
    assert wallet.invoices == [INVOICE]


def test_rc_8_5_idle_locks_are_removed(tmp_path: Path) -> None:
    buyer, _http, wallet = _buyer(
        tmp_path,
        _origin(on_call=_parallel_notice(1)),
        nwc_uri=NWC,
        max_payment_sats=100,
        daily_max_sats=500,
    )
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo", mode="nwc"))
    assert buyer._remote_locks == {}
    assert wallet.invoices == [INVOICE]
