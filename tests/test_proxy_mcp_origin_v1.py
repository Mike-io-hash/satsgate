"""MCP SDK 1.x origin. The default test job does not install that SDK."""

from __future__ import annotations

import os
from importlib.metadata import version

import pytest

_MAJOR = int(version("mcp").split(".", 1)[0])
_JOB = os.environ.get("SATSGATE_MCP_V1_JOB")
if _JOB == "1" and _MAJOR != 1:
    pytest.fail("MCP SDK 1.x is required")
if _MAJOR != 1 and not _JOB:
    pytest.skip("needs the MCP SDK 1.x job", allow_module_level=True)


@pytest.mark.parametrize("shape", ["stateful", "stateless"])
def test_pm_8_real_v1_origin(tmp_path, monkeypatch, shape: str) -> None:
    import httpx
    from fastapi.testclient import TestClient

    from mcp.server.fastmcp import FastMCP
    from proxy_mcp_harness import SECRET, HybridCore, LocalServer, RequireSignature
    from satsgate_proxy.app import build_app
    from test_proxy_mcp_origins import _lightning, _restricted, _settings
    from test_satsgate_gate import _buy, _load_app

    def build(state: dict) -> RequireSignature:
        origin = FastMCP("market", stateless_http=shape == "stateless", json_response=shape == "stateless")

        @origin.tool()
        def echo(text: str) -> str:
            return text

        @origin.tool()
        def quote(symbol: str) -> str:
            return symbol

        @origin.tool()
        def fail(text: str) -> str:
            if state["fail"]:
                raise RuntimeError("tool failed")
            return text

        return RequireSignature(origin.streamable_http_app(), SECRET)

    module = _load_app(tmp_path)
    state = {"fail": True}
    origin = LocalServer(build(state))
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
                _lightning(buyer, core, url, account, state, delete=shape == "stateful")
    finally:
        if proxy is not None:
            proxy.stop()
        origin.stop()
