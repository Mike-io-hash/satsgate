"""MCP route config and request checks on the proxy."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import httpx
import pytest

from satsgate_proxy.config import ConfigError, derived_route
from satsgate_proxy.mcp_http import PROTOCOL_VERSIONS, mcp_tool_succeeded
from test_satsgate_proxy import KEY, PAYMENT, SECRET, World, _client, _load, _macaroon, _snippet

ROOT = Path(__file__).resolve().parents[1]

_HEAD = textwrap.dedent(
    """\
    core:
      base_url: http://core.test
      api_key_env: SATSGATE_API_KEY
    upstream:
      base_url: http://upstream.test
    origin:
      secret_env: SATSGATE_ORIGIN_SECRET
    server:
      public_base: https://pay.example
    """
)

_TOOLS = textwrap.dedent(
    """\
    - name: tools
      path: /mcp
      methods: [POST, DELETE]
      description: Market data tools
      x402: true
      mcp:
        signal: http_402
        default: free
        tools:
          quote:
            price_sats: 21
            access: per_request
            description: One market quote
          deep_search:
            price_sats: 100
            access: uses:10
          echo: free
    """
)


def _indent(text: str, spaces: int = 2) -> str:
    pad = " " * spaces
    return "".join(pad + line if line.strip() else line for line in text.splitlines(True))


def _config(routes: str, *, prelude: str = "") -> str:
    return _HEAD + prelude + "routes:\n" + _indent(textwrap.dedent(routes).strip() + "\n")


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, routes: str, *, prelude: str = ""):
    return _load(tmp_path, monkeypatch, _config(routes, prelude=prelude))


def test_pm_1_1_missing_default_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = _TOOLS.replace("    default: free\n", "")
    blank = _TOOLS.replace("    default: free\n", "    default:\n")
    for routes in (missing, blank):
        with pytest.raises(ConfigError, match="default is required"):
            _settings(tmp_path, monkeypatch, routes)


def test_pm_1_2_unknown_mcp_keys_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extra = _TOOLS.replace("  mcp:\n", "  mcp:\n    extra: 1\n")
    memo = _TOOLS.replace(
        "        access: per_request\n",
        "        access: per_request\n        memo: nope\n",
        1,
    )
    for routes in (extra, memo):
        with pytest.raises(ConfigError, match="unknown mcp key"):
            _settings(tmp_path, monkeypatch, routes)


def test_pm_1_3_signal_must_be_http_402(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError, match="signal must be http_402"):
        _settings(tmp_path, monkeypatch, _TOOLS.replace("signal: http_402", "signal: in_band"))
    with pytest.raises(ConfigError, match="signal must be http_402"):
        _settings(tmp_path, monkeypatch, _TOOLS.replace("    signal: http_402\n", "    signal:\n"))
    loaded = _settings(tmp_path, monkeypatch, _TOOLS)
    assert loaded.routes[0].mcp is not None
    assert loaded.routes[0].mcp.signal == "http_402"
    omitted = _settings(tmp_path, monkeypatch, _TOOLS.replace("    signal: http_402\n", ""))
    assert omitted.routes[0].mcp is not None
    assert omitted.routes[0].mcp.signal == ""


def test_pm_1_4_tool_name_and_resource_length_are_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spaced = _TOOLS.replace("      quote:\n", "      bad tool:\n", 1)
    slash = _TOOLS.replace("      quote:\n", "      quote/name:\n", 1)
    too_long = _TOOLS.replace("      echo: free\n", f"      {'e' * 129}: free\n")
    for routes in (spaced, slash, too_long):
        with pytest.raises(ConfigError, match="tool name is invalid"):
            _settings(tmp_path, monkeypatch, routes)

    numeric = _TOOLS.replace("      echo: free\n", "      123: free\n      echo: free\n")
    boolean = _TOOLS.replace("      echo: free\n", "      true: free\n      echo: free\n")
    for routes in (numeric, boolean):
        with pytest.raises(ConfigError, match="tool name must be a string"):
            _settings(tmp_path, monkeypatch, routes)

    route_name = "a" * 64
    tool_name = "b" * 128
    boundary = _TOOLS.replace("name: tools", f"name: {route_name}", 1).replace(
        "      echo: free\n",
        f"      {tool_name}: free\n",
    )
    boundary_settings = _settings(tmp_path, monkeypatch, boundary)
    assert boundary_settings.routes[0].mcp is not None
    assert boundary_settings.routes[0].mcp.tool(tool_name) is not None

    monkeypatch.setattr(
        "satsgate_proxy.config._ROUTE_NAME",
        re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,179}$"),
    )
    wide = "c" * 80
    over = _TOOLS.replace("name: tools", f"name: {wide}", 1).replace(
        "      quote:\n",
        f"      {tool_name}:\n",
        1,
    )
    with pytest.raises(ConfigError, match="resource too long"):
        _settings(tmp_path, monkeypatch, over)


def test_pm_1_5_mcp_route_shape_is_restricted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cases = [
        (_TOOLS.replace("  x402: true\n", "  x402: true\n  price_sats: 9\n"), "price_sats"),
        (_TOOLS.replace("  x402: true\n", "  x402: true\n  access: per_request\n"), "access"),
        (_TOOLS.replace("  x402: true\n", "  x402: true\n  scope: site\n"), "scope must be route"),
        (_TOOLS.replace("  path: /mcp\n", "  path: /mcp\n  path_regex: '^/mcp$'\n"), "path_regex"),
        (_TOOLS.replace("  path: /mcp\n", "  path: /mcp/*\n"), "cannot contain"),
        (_TOOLS.replace("methods: [POST, DELETE]", "methods: [GET, POST, DELETE]"), "POST and DELETE"),
        (_TOOLS.replace("methods: [POST, DELETE]", "methods: [DELETE]"), "POST and DELETE"),
        (_TOOLS.replace("methods: [POST, DELETE]", "methods: [POST, PUT]"), "POST and DELETE"),
    ]
    for routes, message in cases:
        with pytest.raises(ConfigError, match=message):
            _settings(tmp_path, monkeypatch, routes)


def test_pm_1_6_shadowed_mcp_path_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    early = textwrap.dedent(
        """\
        - name: early
          methods: [GET]
          path: /mcp
          price_sats: 5
          access: per_request
          scope: route
        """
    )
    with pytest.raises(ConfigError, match="shadowed by route early"):
        _settings(tmp_path, monkeypatch, early + _TOOLS)
    with pytest.raises(ConfigError, match="shadowed by a free path"):
        _settings(tmp_path, monkeypatch, _TOOLS, prelude="free_paths:\n  - /mcp\n")
    with pytest.raises(ConfigError, match="shadowed by a free path"):
        _settings(tmp_path, monkeypatch, _TOOLS, prelude="free_paths:\n  - /mcp/**\n")

    later = textwrap.dedent(
        """\
        - name: later
          methods: [GET]
          path: /mcp
          price_sats: 5
          access: per_request
          scope: route
        """
    )
    loaded = _settings(tmp_path, monkeypatch, _TOOLS + later)
    assert [route.name for route in loaded.routes] == ["tools", "later"]
    assert loaded.routes[0].mcp is not None
    assert loaded.routes[1].mcp is None


def test_pm_1_7_receipt_mode_rejects_mcp_routes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prelude = "mode: receipt\nreceipt:\n  site: shop\n"
    with pytest.raises(ConfigError, match="mcp routes need mode: paywall"):
        _settings(tmp_path, monkeypatch, _TOOLS, prelude=prelude)


def test_pm_1_8_derived_routes_carry_the_tool_price(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path, monkeypatch, _TOOLS)
    route = settings.routes[0]
    assert route.mcp is not None
    quote = route.mcp.paid_route("quote")
    assert quote is not None
    assert quote is derived_route(route, "quote")
    assert quote.name == "tools"
    assert quote.resource == "route:tools:quote"
    assert quote.price_sats == 21
    assert quote.access.label() == "per_request"
    assert quote.scope == "route"
    assert quote.description == "One market quote"
    assert quote.x402 is True
    assert quote.x402_mode == "test"
    assert quote.methods == frozenset({"POST", "DELETE"})
    assert quote.pattern.fullmatch("/mcp")
    assert quote.mcp is None

    deep = route.mcp.paid_route("deep_search")
    assert deep is not None
    assert deep.resource == "route:tools:deep_search"
    assert deep.price_sats == 100
    assert deep.access.label() == "uses:10"
    assert deep.access.policy() == (10, None)
    assert deep.description == "Market data tools"
    assert deep.x402 is True
    assert deep.x402_mode == "test"

    echo = route.mcp.tool("echo")
    assert echo is not None and echo.free
    assert route.mcp.paid_route("echo") is None

    paid_default = _TOOLS.replace(
        "    default: free\n",
        "    default:\n      price_sats: 7\n      access: per_request\n",
    )
    parent = _settings(tmp_path, monkeypatch, paid_default).routes[0]
    assert parent.mcp is not None
    assert parent.mcp.paid_route("fresh_tool") is None
    first = derived_route(parent, "fresh_tool")
    second = derived_route(parent, "fresh_tool")
    assert first == second
    assert first is not second
    assert first.resource == "route:tools:fresh_tool"
    assert first.price_sats == 7
    assert first.access.label() == "per_request"
    assert first.description == "Market data tools"
    assert first.x402 is True
    assert first.x402_mode == "test"

    bare = _TOOLS.replace("  description: Market data tools\n", "").replace(
        "        description: One market quote\n",
        "",
    )
    bare_route = _settings(tmp_path, monkeypatch, bare).routes[0]
    assert bare_route.mcp is not None
    unnamed = bare_route.mcp.paid_route("quote")
    assert unnamed is not None
    assert unnamed.description is None


def test_pm_1_9_readme_example_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    readme = (ROOT / "proxy" / "README.md").read_text(encoding="utf-8")
    marker = "## MCP servers"
    assert marker in readme
    section = []
    for line in readme.split(marker, 1)[1].splitlines():
        if line.startswith("## "):
            break
        section.append(line)
    match = re.search(r"```yaml\n(.*?)```", "\n".join(section), re.DOTALL)
    assert match, "mcp example block is missing"
    wrapped = _HEAD + match.group(1).strip() + "\n"
    settings = _load(tmp_path, monkeypatch, wrapped)
    route = settings.routes[0]
    assert route.mcp is not None
    assert route.name == "tools"
    assert route.mcp.signal == "http_402"
    assert route.mcp.default.free
    assert route.mcp.tool("echo") is not None and route.mcp.tool("echo").free
    quote = route.mcp.paid_route("quote")
    assert quote is not None
    assert quote.resource == "route:tools:quote"
    assert quote.price_sats == 21
    assert quote.description == "One market quote"
    deep = route.mcp.paid_route("deep_search")
    assert deep is not None
    assert deep.price_sats == 100
    assert deep.description == "Market data tools"


def test_pm_1_10_missing_default_exits_with_code_2(tmp_path: Path) -> None:
    path = tmp_path / "proxy.yaml"
    path.write_text(_config(_TOOLS.replace("    default: free\n", "")), encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "proxy" / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["SATSGATE_API_KEY"] = KEY
    env["SATSGATE_ORIGIN_SECRET"] = SECRET
    completed = subprocess.run(
        [sys.executable, "-m", "satsgate_proxy", "--config", str(path)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert completed.returncode == 2
    assert completed.stderr.startswith("satsgate-proxy:")
    assert "default is required" in completed.stderr
    assert "tools" in completed.stderr


_ACCEPT = "application/json, text/event-stream"


class McpWorld(World):
    def __init__(self) -> None:
        super().__init__()
        self.queue: list[httpx.Response] = []

    def _unlock(self, snap: dict) -> httpx.Response:
        response = super()._unlock(snap)
        if response.status_code != 200:
            return response
        body = response.json()
        body.pop("amount_sats", None)
        return httpx.Response(200, json=body)

    def _core(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/x402/verify") or path.endswith("/x402/settle"):
            snap = self._snap(request)
            self.core_calls.append(snap)
            if path.endswith("/x402/verify"):
                return httpx.Response(
                    200,
                    json={"ok": True, "serve": True, "amount_usd_atomic": 10000, "nonce": "ab" * 32},
                )
            return httpx.Response(
                200,
                json={"ok": True, "payment_response": "c2V0dGxlZA"},
                headers={"payment-response": "c2V0dGxlZA"},
            )
        return super()._core(request)

    def _upstream(self, request: httpx.Request) -> httpx.Response:
        if self.queue:
            raw = bytes(request.content)
            snap = self._snap(request)
            snap["raw"] = raw
            self.up_calls.append(snap)
            return self.queue.pop(0)
        raw = bytes(request.content)
        snap = self._snap(request)
        snap["raw"] = raw
        self.up_calls.append(snap)
        if request.method == "DELETE":
            return httpx.Response(200, content=b"deleted", headers={"content-type": "text/plain"})
        payload = None
        if raw:
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = None
        if isinstance(payload, dict) and ("method" not in payload or "id" not in payload):
            return httpx.Response(202, content=b"")
        return httpx.Response(
            200,
            content=b'{"jsonrpc":"2.0","id":1,"result":{}}',
            headers={"content-type": "application/json"},
        )


def _mcp_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, routes: str | None = None, *, prelude: str = ""):
    chosen = _TOOLS if routes is None else routes
    if routes is None:
        chosen = _TOOLS.replace("  x402: true\n", "")
    return _load(tmp_path, monkeypatch, _config(chosen, prelude=prelude))


def _post(client, content: bytes | str, headers: dict | list | None = None, path: str = "/mcp"):
    base: list[tuple[str, str]] = [
        ("accept", _ACCEPT),
        ("content-type", "application/json"),
    ]
    if isinstance(headers, dict):
        base.extend((key, value) for key, value in headers.items())
    elif isinstance(headers, list):
        base.extend(headers)
    raw = content.encode("utf-8") if isinstance(content, str) else content
    return client.post(path, content=raw, headers=base)


def _word(response) -> str:
    return response.json()["error"]["data"]["error"]


def _assert_rejected(response, word: str, world: McpWorld) -> dict:
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["data"]["error"] == word
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("application/json")
    assert world.core_calls == []
    assert world.up_calls == []
    return body


def _rpc(method: str, params: dict | None = None, *, ident: object = 1, notify: bool = False) -> bytes:
    body: dict[str, object] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if not notify:
        body["id"] = ident
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _verify_free_signatures(calls: list[dict]) -> None:
    snippet = _snippet("fastapi_verify.py")
    node = shutil.which("node")
    assert node
    script = """
const express = require(process.argv[1]);
const nginx = require(process.argv[2]);
const checks = JSON.parse(process.argv[3]);
for (const item of checks) {
  const opts = {secret: item.secret, header: item.header, method: item.method, target: item.target, paymentHash: item.paymentHash, now: item.now, maxSkewSeconds: 300};
  if (!express.verifyOriginSignature(opts) || !nginx.verifyOriginSignature(opts)) process.exit(2);
}
"""
    payload = []
    for call in calls:
        headers = call["headers"]
        signature = headers["x-satsgate-signature"]
        now = int(signature.split(",", 1)[0].split("=", 1)[1])
        assert headers["x-satsgate-payment-hash"] == "0" * 64
        assert headers["x-satsgate-resource"] == "free"
        assert headers["x-satsgate-paid-sats"] == "0"
        assert "x-satsgate-paid-usd-atomic" not in headers
        assert "payment-signature" not in headers
        authorization = headers.get("authorization", "")
        assert not authorization.lower().startswith("l402")
        assert not authorization.lower().startswith("lsat")
        target = call["raw_path"]
        assert snippet.verify_origin_signature(
            secret=SECRET,
            header=signature,
            method=call["method"],
            target=target,
            payment_hash="0" * 64,
            now=now,
            max_skew_seconds=300,
        )
        payload.append(
            {
                "secret": SECRET,
                "header": signature,
                "method": call["method"],
                "target": target,
                "paymentHash": "0" * 64,
                "now": now,
            }
        )
    completed = subprocess.run(
        [
            node,
            "-e",
            script,
            str(ROOT / "proxy" / "snippets" / "express_verify.js"),
            str(ROOT / "proxy" / "snippets" / "nginx_verify.js"),
            json.dumps(payload),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _b64_name(name: str) -> str:
    return "=?base64?" + base64.b64encode(name.encode("utf-8")).decode("ascii") + "?="


def _year_headers(method: str, name: str | None = None) -> dict[str, str]:
    headers = {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


def _year_params(extra: dict | None = None) -> dict:
    params = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }
    if extra:
        params.update(extra)
    return params


def test_pm_2_1_free_messages_never_call_the_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    mac = _macaroon("route:tools:quote")
    passes = (
        {"Authorization": f"L402 {mac}:{'cd' * 32}"},
        {"PAYMENT-SIGNATURE": "sig-test"},
    )
    messages = [
        ("POST", _rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}), "/mcp"),
        ("POST", _rpc("notifications/initialized", notify=True), "/mcp"),
        ("POST", _rpc("tools/list"), "/mcp"),
        ("POST", _rpc("ping"), "/mcp"),
        ("POST", _rpc("resources/list"), "/mcp"),
        ("POST", _rpc("resources/read", {"uri": "file://note.txt"}), "/mcp"),
        ("POST", _rpc("prompts/get", {"name": "hello"}), "/mcp"),
        ("POST", _rpc("completion/complete", {"ref": {"type": "ref/prompt", "name": "hello"}, "argument": {"name": "q", "value": "a"}}), "/mcp"),
        ("POST", _rpc("tools/call", {"name": "echo", "arguments": {"text": "hi"}}, ident=7), "/mcp"),
        ("POST", b'{"jsonrpc":"2.0","id":3,"result":{"ok":true}}', "/mcp"),
        ("DELETE", b"", "/mcp"),
    ]
    world = McpWorld()
    with _client(settings, world) as client:
        for extra in passes:
            for method, content, path in messages:
                if method == "DELETE":
                    response = client.delete(path, headers=extra)
                else:
                    response = _post(client, content, extra, path)
                if method == "DELETE":
                    assert response.status_code == 200
                elif b'"method":"notifications/initialized"' in content or content == b'{"jsonrpc":"2.0","id":3,"result":{"ok":true}}':
                    assert response.status_code == 202
                    assert response.content == b""
                else:
                    assert response.status_code == 200
    assert world.core_calls == []
    assert len(world.up_calls) == len(messages) * len(passes)
    for index, call in enumerate(world.up_calls):
        sent = messages[index % len(messages)][1]
        assert call["raw"] == sent
    echo_calls = [call for call in world.up_calls if call["raw"] and b'"name":"echo"' in call["raw"]]
    assert echo_calls
    assert all(call["headers"].get("x-satsgate-mcp-tool") == "echo" for call in echo_calls)
    other = [call for call in world.up_calls if call not in echo_calls]
    assert all("x-satsgate-mcp-tool" not in call["headers"] for call in other)
    _verify_free_signatures(world.up_calls)


def test_pm_2_2_free_2026_messages_are_signed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    calls = [
        ("server/discover", _year_params(), None),
        ("tools/list", _year_params(), None),
        ("tools/call", _year_params({"name": "echo", "arguments": {"text": "hi"}}), "echo"),
    ]
    with _client(settings, world) as client:
        for method, params, name in calls:
            response = _post(client, _rpc(method, params), _year_headers(method, name))
            assert response.status_code == 200, response.text
    assert world.core_calls == []
    assert world.up_calls[-1]["headers"]["x-satsgate-mcp-tool"] == "echo"
    assert "x-satsgate-mcp-tool" not in world.up_calls[0]["headers"]
    _verify_free_signatures(world.up_calls)


def test_pm_2_3_unlisted_tool_uses_free_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    raw = _rpc("tools/call", {"name": "other_tool", "arguments": {}})
    with _client(settings, world) as client:
        response = _post(client, raw)
    assert response.status_code == 200
    assert world.core_calls == []
    assert world.up_calls[0]["raw"] == raw
    assert world.up_calls[0]["headers"]["x-satsgate-mcp-tool"] == "other_tool"
    _verify_free_signatures(world.up_calls)


def test_pm_3_paid_tool_cannot_be_reached_for_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    quote = _rpc("tools/call", {"name": "quote"})
    echo = _rpc("tools/call", {"name": "echo"})

    world = McpWorld()
    with _client(settings, world) as client:
        mismatch = _post(client, quote, {"Mcp-Method": "tools/list"})
    body = _assert_rejected(mismatch, "header_mismatch", world)
    assert body["id"] == 1

    world = McpWorld()
    with _client(settings, world) as client:
        named = _post(client, quote, {"Mcp-Name": "echo"})
        bad_b64 = _post(client, quote, {"Mcp-Name": "=?base64?***?="})
        good_b64 = _post(client, quote, {"Mcp-Name": _b64_name("quote")})
    _assert_rejected(named, "header_mismatch", McpWorld())
    assert named.status_code == 400 and _word(named) == "header_mismatch"
    assert bad_b64.status_code == 400 and _word(bad_b64) == "header_mismatch"
    assert good_b64.status_code == 402
    assert good_b64.json()["resource"] == "route:tools:quote"
    assert world.up_calls == []
    assert all(call["path"].endswith("/challenge") for call in world.core_calls)

    world = McpWorld()
    batch_paid = b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"quote"}}]'
    batch_free = b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}]'
    with _client(settings, world) as client:
        paid_batch = _post(client, batch_paid)
        free_batch = _post(client, batch_free)
    assert paid_batch.status_code == 400 and _word(paid_batch) == "batch_with_paid_tool"
    assert paid_batch.json()["id"] is None
    assert free_batch.status_code == 200
    assert world.core_calls == []
    assert world.up_calls[0]["raw"] == batch_free
    assert "x-satsgate-mcp-tool" not in world.up_calls[0]["headers"]

    world = McpWorld()
    disguised = [
        _rpc("Tools/Call", {"name": "quote"}),
        _rpc(" tools/call", {"name": "quote"}),
        _rpc("tools/call ", {"name": "quote"}),
        _rpc("tools\uff0fcall", {"name": "quote"}),
    ]
    with _client(settings, world) as client:
        for raw in disguised:
            response = _post(client, raw)
            assert response.status_code == 400 and _word(response) == "invalid_method"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        glued = _post(client, b'{"jsonrpc":"2.0","id":1,"method":"ping"}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"quote"}}')
    _assert_rejected(glued, "invalid_json", world)

    world = McpWorld()
    duplicates = [
        b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"quote"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping","params":{"name":"quote"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","name":"quote"}}',
    ]
    with _client(settings, world) as client:
        for raw in duplicates:
            response = _post(client, raw)
            assert response.status_code == 400 and _word(response) == "invalid_json"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        note = _post(client, b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"quote"}}')
    _assert_rejected(note, "invalid_message", world)

    world = McpWorld()
    null_ids = [
        b'{"jsonrpc":"2.0","id":null,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":true,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}',
    ]
    kept_ids = [
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}',
    ]
    with _client(settings, world) as client:
        for raw in null_ids:
            response = _post(client, raw)
            assert response.status_code == 400 and _word(response) == "invalid_message"
            assert response.json()["id"] is None
        for raw in kept_ids:
            response = _post(client, raw)
            assert response.status_code == 400 and _word(response) == "invalid_message"
            assert response.json()["id"] == 1
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    escaped = b'{"jsonrpc":"2.0","id":1,"method":"tools\\/call","params":{"name":"quot\\u0065"}}'
    with _client(settings, world) as client:
        paid = _post(client, escaped)
    assert paid.status_code == 402
    assert paid.json()["resource"] == "route:tools:quote"
    assert world.core_calls[0]["body"]["resource"] == "route:tools:quote"
    assert world.up_calls == []

    world = McpWorld()
    aliases = ["Quote", "quote ", "\uff51uote"]
    with _client(settings, world) as client:
        for name in aliases:
            response = _post(client, _rpc("tools/call", {"name": name}))
            assert response.status_code == 400 and _word(response) == "invalid_tool_name"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        bom = _post(client, b"\xef\xbb\xbf" + quote)
        plain = client.post(
            "/mcp",
            content=quote,
            headers={"accept": _ACCEPT, "content-type": "text/plain"},
        )
    assert bom.status_code == 400 and _word(bom) == "invalid_json"
    assert plain.status_code == 400 and _word(plain) == "unsupported_content_type"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    forged = {
        "X-Satsgate-Resource": "free",
        "X-Satsgate-Mcp-Tool": "echo",
        "X-Satsgate-Payment-Hash": "ab" * 32,
    }
    with _client(settings, world) as client:
        still_paid = _post(client, quote, forged)
        still_free = _post(client, echo, forged)
    assert still_paid.status_code == 402
    assert still_paid.json()["resource"] == "route:tools:quote"
    assert still_free.status_code == 200
    free_headers = world.up_calls[0]["headers"]
    assert free_headers["x-satsgate-resource"] == "free"
    assert free_headers["x-satsgate-payment-hash"] == "0" * 64
    assert free_headers["x-satsgate-mcp-tool"] == "echo"
    assert free_headers["x-satsgate-paid-sats"] == "0"

    world = McpWorld()
    with _client(settings, world) as client:
        queried = _post(client, quote, path="/mcp?tool=echo")
    assert queried.status_code == 402
    assert queried.json()["resource"] == "route:tools:quote"
    assert world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        deleted = client.request("DELETE", "/mcp", content=quote, headers={"content-type": "application/json"})
    _assert_rejected(deleted, "delete_body_not_allowed", world)

    world = McpWorld()
    caplog.set_level("INFO", logger="satsgate_proxy")
    with _client(settings, world) as client:
        free_task = _post(client, _rpc("tools/call", {"name": "echo", "task": {"id": "argument-marker"}}))
        paid_task = _post(client, _rpc("tools/call", {"name": "quote", "task": "argument-marker"}))
    assert free_task.status_code == 400 and _word(free_task) == "tasks_not_supported"
    assert paid_task.status_code == 400 and _word(paid_task) == "tasks_not_supported"
    assert world.core_calls == [] and world.up_calls == []
    assert "argument-marker" not in caplog.text
    assert "mcp rejected tasks_not_supported" in caplog.text


def test_pm_4_checks_run_before_an_invoice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    ping = _rpc("ping", ident="abc")
    world = McpWorld()
    with _client(settings, world) as client:
        only_json = client.post("/mcp", content=ping, headers={"accept": "application/json", "content-type": "application/json"})
        wildcard = client.post("/mcp", content=ping, headers={"accept": "*/*", "content-type": "application/json"})
        missing = client.post("/mcp", content=ping, headers={"content-type": "application/json"})
    for response in (only_json, wildcard, missing):
        assert response.status_code == 400 and _word(response) == "accept_json_and_sse_required"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        unknown = _post(client, _rpc("ping", ident=5), {"MCP-Protocol-Version": "2099-01-01"})
        for version in PROTOCOL_VERSIONS:
            if version == "2026-07-28":
                response = _post(client, _rpc("tools/list", _year_params()), _year_headers("tools/list"))
            else:
                response = _post(client, _rpc("ping"), {"MCP-Protocol-Version": version})
            assert response.status_code == 200, version
        opened = _post(client, _rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}))
        later = _post(client, _rpc("ping"))
    assert unknown.status_code == 400
    unknown_body = unknown.json()
    assert unknown_body["error"]["code"] == -32022
    assert unknown_body["error"]["data"]["error"] == "unsupported_protocol_version"
    assert unknown_body["error"]["data"]["requested"] == "2099-01-01"
    assert unknown_body["error"]["data"]["supported"] == list(PROTOCOL_VERSIONS)
    assert unknown_body["id"] == 5
    assert opened.status_code == 200 and later.status_code == 200
    assert all(not call["path"].endswith("/challenge") for call in world.core_calls)
    assert world.core_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        repeated = _post(
            client,
            ping,
            [("mcp-method", "ping"), ("mcp-method", "tools/call")],
        )
    _assert_rejected(repeated, "duplicate_routing_header", world)

    world = McpWorld()
    with _client(settings, world) as client:
        no_method = _post(client, _rpc("tools/list", _year_params()), {"MCP-Protocol-Version": "2026-07-28"})
        no_name = _post(
            client,
            _rpc("tools/call", _year_params({"name": "echo"})),
            {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call"},
        )
        no_meta = _post(client, _rpc("tools/list", {}), _year_headers("tools/list"))
        bad_meta = _post(
            client,
            _rpc(
                "tools/list",
                {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            ),
            _year_headers("tools/list"),
        )
        batch = _post(
            client,
            b'[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{}}},{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{}}}]',
            {"MCP-Protocol-Version": "2026-07-28"},
        )
    assert _word(no_method) == "header_mismatch"
    assert _word(no_name) == "header_mismatch"
    assert no_meta.status_code == 400 and no_meta.json()["error"]["code"] == -32602
    assert _word(no_meta) == "missing_request_envelope"
    assert _word(bad_meta) == "header_mismatch"
    assert batch.status_code == 400 and _word(batch) == "invalid_message"
    assert world.core_calls == [] and world.up_calls == []

    limited = _mcp_settings(tmp_path, monkeypatch, prelude="limits:\n  max_request_bytes: 1024\n")
    world = McpWorld()
    with _client(limited, world) as client:
        huge = client.post("/mcp", content=b"x" * 2000)
    assert huge.status_code == 413
    assert huge.json()["error"] == "request_too_large"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        string_id = _post(client, _rpc("Tools/Call", {"name": "quote"}, ident="abc"))
        int_id = _post(client, _rpc("Tools/Call", {"name": "quote"}, ident=7))
        broken = _post(client, b"{")
        batch_id = _post(
            client,
            b'[{"jsonrpc":"2.0","id":"keep","method":"tools/call","params":{"name":"quote"}}]',
        )
    assert string_id.json()["id"] == "abc"
    assert int_id.json()["id"] == 7
    assert broken.json()["id"] is None
    assert batch_id.json()["id"] is None
    for response in (string_id, int_id, broken, batch_id):
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["jsonrpc"] == "2.0"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    with _client(settings, world) as client:
        fetched = client.get("/mcp")
        options = client.options("/mcp")
    assert fetched.status_code == 405
    assert options.status_code == 405
    assert fetched.headers["allow"] == "DELETE, POST"
    assert options.headers["allow"] == "DELETE, POST"
    assert world.core_calls == [] and world.up_calls == []

    world = McpWorld()
    methods = ["subscriptions/listen", "tasks/get", "tasks/result", "tasks/list", "tasks/cancel"]
    with _client(settings, world) as client:
        for method in methods:
            response = _post(client, _rpc(method, ident=4))
            assert response.status_code == 200, method
            assert response.headers["content-type"].startswith("application/json")
            payload = response.json()
            assert payload["id"] == 4
            assert payload["error"]["code"] == -32601
            assert payload["error"]["message"] == "Method not supported by this gateway"
            assert payload["error"]["data"]["error"] == "unsupported_method"
            notice = _post(client, _rpc(method, notify=True))
            assert notice.status_code == 202
            assert notice.content == b""
        mixed = _post(
            client,
            b'[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tasks/get"}]',
        )
    assert mixed.status_code == 400 and _word(mixed) == "invalid_message"
    assert world.core_calls == [] and world.up_calls == []


def _result(result: dict, *, ident: object = 1) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": ident, "result": result}).encode("utf-8")


def _rpc_error_body(error: dict, *, ident: object = 1) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": ident, "error": error}).encode("utf-8")


def _reply(status: int, body: bytes, content_type: str) -> httpx.Response:
    headers = {"content-type": content_type} if content_type else {}
    return httpx.Response(status, content=body, headers=headers)


def _paths(world: McpWorld) -> list[str]:
    return [call["path"] for call in world.core_calls]


def _auth(resource: str) -> dict[str, str]:
    return {"Authorization": f"L402 {_macaroon(resource)}:{'cd' * 32}"}


def _signed(headers: dict, *, payment_hash: str) -> None:
    signature = headers["x-satsgate-signature"]
    now = int(signature.split(",", 1)[0].split("=", 1)[1])
    assert _snippet("fastapi_verify.py").verify_origin_signature(
        secret=SECRET,
        header=signature,
        method="POST",
        target="/mcp",
        payment_hash=payment_hash,
        now=now,
        max_skew_seconds=300,
    )


def _failure_replies() -> list[tuple[str, httpx.Response]]:
    success = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode("utf-8")
    doubled = b"data: " + success + b"\n\ndata: " + success + b"\n\n"
    return [
        ("is_error", _reply(200, _result({"isError": True}), "application/json")),
        ("rpc_error", _reply(200, _rpc_error_body({"code": -32000, "message": "failed"}), "application/json")),
        ("result_type", _reply(200, _result({"resultType": "input_required"}), "application/json")),
        ("task", _reply(200, _result({"task": {"id": "job"}}), "application/json")),
        ("text_flag", _reply(200, _result({"isError": "true"}), "application/json")),
        ("wrong_id", _reply(200, _result({"ok": True}, ident=9), "application/json")),
        ("two_matches", _reply(200, doubled, "text/event-stream")),
        ("accepted", _reply(202, b"", "")),
        ("html", _reply(200, b"<p>no</p>", "text/html")),
        ("not_json", _reply(200, b"not-json", "application/json")),
    ]


def test_pm_5_1_unpaid_quote_is_a_classic_402(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    with _client(settings, world) as client:
        response = _post(client, _rpc("tools/call", {"name": "quote"}))
    assert response.status_code == 402
    assert response.headers["www-authenticate"].startswith('L402 macaroon="')
    body = response.json()
    assert body["error"] == "payment_required"
    assert body["amount_sats"] == 21
    assert body["resource"] == "route:tools:quote"
    assert body["max_uses"] == 1
    assert body["access_seconds"] is None
    assert body["invoice"] and body["macaroon"] and body["payment_hash"]
    sent = world.core_calls[0]["body"]
    assert sent["resource"] == "route:tools:quote"
    assert sent["amount_sats"] == 21
    assert sent["max_uses"] == 1
    assert sent["memo"] == "One market quote"
    assert "x402" not in sent
    assert world.up_calls == []

    x402_settings = _mcp_settings(tmp_path, monkeypatch, _TOOLS)
    x402_world = McpWorld()
    with _client(x402_settings, x402_world) as client:
        priced = _post(client, _rpc("tools/call", {"name": "quote"}))
    assert priced.status_code == 402
    assert "payment-required" in priced.headers
    assert priced.json()["x402"]["testing"] is True
    challenge = x402_world.core_calls[0]["body"]
    assert challenge["x402"] is True
    assert challenge["resource"] == "route:tools:quote"
    assert challenge["resource_url"] == "https://pay.example/mcp"


def test_pm_5_2_each_tool_has_its_own_price(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    with _client(settings, world) as client:
        deep = _post(client, _rpc("tools/call", {"name": "deep_search"}))
    assert deep.status_code == 402
    assert deep.json()["resource"] == "route:tools:deep_search"
    assert deep.json()["amount_sats"] == 100
    assert deep.json()["max_uses"] == 10
    assert world.core_calls[0]["body"]["resource"] == "route:tools:deep_search"
    assert world.core_calls[0]["body"]["amount_sats"] == 100
    assert world.core_calls[0]["body"]["max_uses"] == 10

    paid_default = _TOOLS.replace("  x402: true\n", "").replace(
        "    default: free\n",
        "    default:\n      price_sats: 9\n      access: per_request\n",
    )
    fresh = McpWorld()
    with _client(_mcp_settings(tmp_path, monkeypatch, paid_default), fresh) as client:
        other = _post(client, _rpc("tools/call", {"name": "fresh_tool"}))
    assert other.status_code == 402
    assert other.json()["resource"] == "route:tools:fresh_tool"
    assert other.json()["amount_sats"] == 9
    assert fresh.core_calls[0]["body"]["memo"] == "Market data tools"


def test_pm_5_3_token_for_one_tool_does_not_open_another(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    with _client(settings, world) as client:
        response = _post(client, _rpc("tools/call", {"name": "deep_search"}), _auth("route:tools:quote"))
    assert response.status_code == 402
    assert response.json()["reason"] == "resource mismatch"
    assert response.json()["resource"] == "route:tools:deep_search"
    assert world.up_calls == []
    assert not any(path.endswith("/charge") for path in _paths(world))
    assert not any(path.endswith("/verify") and "/x402/" not in path for path in _paths(world))


def test_pm_5_4_paid_success_charges_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    body = _result({"content": [{"type": "text", "text": "ok"}]})
    world.queue.append(_reply(200, body, "application/json"))
    with _client(settings, world) as client:
        response = _post(client, _rpc("tools/call", {"name": "quote"}), _auth("route:tools:quote"))
    assert response.status_code == 200
    assert response.content == body
    headers = world.up_calls[0]["headers"]
    assert headers["x-satsgate-resource"] == "route:tools:quote"
    assert headers["x-satsgate-paid-sats"] == "21"
    assert headers["x-satsgate-mcp-tool"] == "quote"
    assert headers["x-satsgate-payment-hash"] == PAYMENT
    _signed(headers, payment_hash=PAYMENT)
    assert _paths(world) == [
        "/v1/paywall/verify",
        "/v1/paywall/charge",
    ]


def test_pm_5_5_failed_tool_takes_no_fee(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    world = McpWorld()
    header = _auth("route:tools:quote")
    raw = _rpc("tools/call", {"name": "quote"})
    with _client(settings, world) as client:
        for _name, reply in _failure_replies():
            world.queue.append(reply)
            response = _post(client, raw, header)
            assert response.status_code == reply.status_code
            assert response.content == reply.content
            assert not any(path.endswith("/charge") for path in _paths(world))
        world.queue.append(_reply(200, _result({"ok": True}), "application/json"))
        done = _post(client, raw, header)
    assert done.status_code == 200
    assert sum(path.endswith("/charge") for path in _paths(world)) == 1


def test_pm_5_6_failed_x402_tool_does_not_settle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch, _TOOLS)
    world = McpWorld()
    header = {"PAYMENT-SIGNATURE": "sig-test"}
    raw = _rpc("tools/call", {"name": "quote"})
    with _client(settings, world) as client:
        for _name, reply in _failure_replies():
            world.queue.append(reply)
            response = _post(client, raw, header)
            assert response.status_code == reply.status_code
            assert response.content == reply.content
            assert "payment-response" not in response.headers
            assert not any(path.endswith("/x402/settle") for path in _paths(world))
        world.queue.append(_reply(200, _result({"ok": True}), "application/json"))
        done = _post(client, raw, header)
    assert done.status_code == 200
    assert done.headers["payment-response"] == "c2V0dGxlZA"
    assert sum(path.endswith("/x402/settle") for path in _paths(world)) == 1
    assert sum(path.endswith("/x402/verify") for path in _paths(world)) == len(_failure_replies()) + 1


def test_pm_5_7_sse_result_decides_the_fee(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch)
    header = _auth("route:tools:quote")
    raw = _rpc("tools/call", {"name": "quote"})
    progress = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}})
    final = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    crlf = (
        b":\r\n\r\n"
        + f"event: message\r\ndata: {progress}\r\n\r\n".encode()
        + f"data: {final}\r\n\r\n".encode()
    )
    failed = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"isError": True}})
    lf = f"data: {failed}\n\n".encode()
    errored = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "failed"}})
    after_note = f"data: {progress}\n\ndata: {errored}\n\n".encode()
    broken = b"data: {not-json}\n\n"
    later = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"isError": True}})
    success_then_other = f"data: {final}\n\ndata: {later}\n\n".encode()
    cases = [
        (crlf, True),
        (lf, False),
        (after_note, False),
        (broken, False),
        (success_then_other, True),
    ]
    for body, charged in cases:
        world = McpWorld()
        world.queue.append(_reply(200, body, "text/event-stream"))
        with _client(settings, world) as client:
            response = _post(client, raw, header)
        assert response.status_code == 200
        assert response.content == body
        assert any(path.endswith("/charge") for path in _paths(world)) is charged


def test_pm_5_8_explicit_signal_matches_the_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = _mcp_settings(tmp_path, monkeypatch)
    omitted = _mcp_settings(
        tmp_path,
        monkeypatch,
        _TOOLS.replace("  x402: true\n", "").replace("    signal: http_402\n", ""),
    )
    left = McpWorld()
    right = McpWorld()
    with _client(explicit, left) as client:
        first = _post(client, _rpc("tools/call", {"name": "quote"}))
    with _client(omitted, right) as client:
        second = _post(client, _rpc("tools/call", {"name": "quote"}))
    assert first.status_code == second.status_code == 402
    assert first.json() == second.json()
    assert first.headers["www-authenticate"] == second.headers["www-authenticate"]


def test_pm_5_9_tool_success_predicate_covers_each_branch() -> None:
    def judge(body: bytes, request_id: object = 1, content_type: str = "application/json", status: int = 200) -> bool:
        return mcp_tool_succeeded(status, {"content-type": content_type}, body, request_id)

    ok = _result({"content": [{"type": "text", "text": "ok"}]})
    assert judge(ok) is True
    assert judge(_result({"isError": False, "content": []})) is True
    assert judge(_result({"resultType": "complete"})) is True
    assert judge(_result({"isError": True})) is False
    assert judge(_result({"isError": "true"})) is False
    assert judge(_result({"isError": None})) is False
    assert judge(_result({"isError": 1})) is False
    assert judge(_rpc_error_body({"code": -32000, "message": "failed"})) is False
    assert judge(_result({"resultType": "input_required"})) is False
    assert judge(_result({"task": None})) is False
    assert judge(_result({"ok": True}, ident="1"), 1) is False
    assert judge(json.dumps({"jsonrpc": "2.0", "id": True, "result": {"ok": True}}).encode(), 1) is False
    assert judge(_result({"ok": True}, ident=2), 1) is False
    assert judge(b'[{"jsonrpc":"2.0","id":1,"result":{"ok":true}},{"jsonrpc":"2.0","id":1,"result":{"ok":true}}]') is False
    assert judge(b"", content_type="") is False
    assert judge(b"<p>no</p>", content_type="text/html") is False
    assert judge(b"not-json") is False
    assert judge(ok, status=202) is True
    note = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    final = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    stream = f":\r\n\r\ndata: {note}\r\n\r\ndata: {final}\r\n\r\n".encode()
    assert judge(stream, content_type="text/event-stream") is True
    cr_only = f"data: {final}\rdata: \r\r".encode()
    assert judge(cr_only, content_type="text/event-stream") is True
    flagged = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"isError": True}})
    assert judge(f"data: {flagged}\n\n".encode(), content_type="text/event-stream") is False
    doubled = f"data: {final}\n\ndata: {final}\n\n".encode()
    assert judge(doubled, content_type="text/event-stream") is False
    assert judge(b"data: {not-json}\n\n", content_type="text/event-stream") is False
