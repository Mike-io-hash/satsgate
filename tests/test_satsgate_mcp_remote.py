"""Remote MCP client: inputs, handshake, listing, and paid-request headers."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import httpx
import pytest

from satsgate_mcp import __version__
from satsgate_mcp.buyer import BuyerError
from satsgate_mcp.server import _INSTRUCTIONS, _PAY, _READ, build_server
from test_satsgate_mcp import INVOICE, MAC, NWC, PAYMENT, PREIMAGE, _buyer, _challenge, _paid
from test_satsgate_mcp_x402 import SIGNATURE, _settings_usd, _x402_response

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
