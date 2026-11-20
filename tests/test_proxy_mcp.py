"""MCP route config on the proxy."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from satsgate_proxy.config import ConfigError, derived_route
from test_satsgate_proxy import KEY, SECRET, _load

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
