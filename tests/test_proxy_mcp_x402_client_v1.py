"""Official x402 MCP client through the proxy. The main test job does not install it."""

from __future__ import annotations

import asyncio
import os
from importlib.metadata import PackageNotFoundError, version

import pytest

_JOB = os.environ.get("SATSGATE_MCP_V1_JOB")
try:
    _MCP_MAJOR = int(version("mcp").split(".", 1)[0])
except PackageNotFoundError:
    _MCP_MAJOR = 0
try:
    version("x402")
    _HAVE_X402 = True
except PackageNotFoundError:
    _HAVE_X402 = False
if _JOB == "1" and (_MCP_MAJOR != 1 or not _HAVE_X402):
    pytest.fail("MCP SDK 1.x and the x402 client are required")
if _MCP_MAJOR != 1 or not _HAVE_X402:
    pytest.skip("needs the MCP SDK 1.x job", allow_module_level=True)

from eth_account import Account  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402
from mcp.server.fastmcp import Context, FastMCP  # noqa: E402
from x402 import x402Client  # noqa: E402
from x402.mcp.client import x402MCPSession  # noqa: E402
from x402.mechanisms.evm.exact import ExactEvmClientScheme  # noqa: E402
from x402.mechanisms.evm.signers import EthAccountSigner  # noqa: E402

from proxy_mcp_harness import SECRET, HybridCore, LocalServer, RequireSignature, _free_port  # noqa: E402
from satsgate_proxy.app import build_app  # noqa: E402
from test_proxy_mcp_origins import _restricted, _settings  # noqa: E402
from test_rates import _use  # noqa: E402
from test_satsgate_gate import _buy, _load_app  # noqa: E402
from test_x402 import _install_poster, _poster, _verify_payee  # noqa: E402

_TEST_NETWORK = "eip155:84532"


class _CoreLog(HybridCore):
    """Record each path the proxy sends to the core."""

    def __init__(self, core_app) -> None:
        super().__init__(core_app)
        self.paths: list[str] = []

    async def handle_async_request(self, request):
        if request.url.host == "core.test":
            self.paths.append(request.url.path)
        return await super().handle_async_request(request)


class _BodyLog:
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


def _origin(state: dict, *, stateless: bool):
    server = FastMCP("market", stateless_http=stateless, json_response=stateless)

    @server.tool()
    def echo(text: str) -> str:
        return text

    @server.tool()
    async def quote(symbol: str, ctx: Context) -> str:
        await ctx.info("working")
        return symbol

    @server.tool()
    def fail(text: str) -> str:
        if state["fail"]:
            raise RuntimeError("tool failed")
        return text

    return _BodyLog(RequireSignature(server.streamable_http_app(), SECRET))


def _rates(module) -> None:
    _use(module, {source.name: "65000" for source in module.rates._SOURCES})


def _boot(tmp_path, monkeypatch, *, stateless: bool, x402: bool):
    module = _load_app(tmp_path)
    logged = _origin({"fail": False}, stateless=stateless)
    origin = LocalServer(logged)
    origin.start()
    proxy = None
    calls = []
    core_log = _CoreLog(module.app)
    core_cm = TestClient(module.app)
    core = core_cm.__enter__()
    try:
        account = _buy(core)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
        port = None
        public = ""
        buyer = Account.create()
        if x402:
            _rates(module)
            owner = Account.create()
            _verify_payee(core, account, owner)
            calls, post = _poster(buyer)
            _install_poster(post)
            port = _free_port()
            public = f"http://127.0.0.1:{port}"
        settings = _settings(
            tmp_path,
            monkeypatch,
            origin.port,
            x402=x402,
            public_base=public,
            signal="in_band",
        )
        proxy = LocalServer(build_app(settings, transport=core_log), port=port)
        proxy.start()
        return core_cm, origin, proxy, logged, calls, core_log.paths, buyer, f"http://127.0.0.1:{proxy.port}/mcp"
    except Exception:
        if proxy is not None:
            proxy.stop()
        origin.stop()
        core_cm.__exit__(None, None, None)
        raise


def _close(core_cm, origin, proxy) -> None:
    if proxy is not None:
        proxy.stop()
    origin.stop()
    core_cm.__exit__(None, None, None)


async def _paid_call(url: str, network: str, account):
    payer = x402Client()
    payer.register(network, ExactEvmClientScheme(EthAccountSigner(account)))
    async with streamablehttp_client(url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            wrapped = x402MCPSession(session, payer)
            await wrapped.initialize()
            return await wrapped.call_tool("quote", {"symbol": "acme"})


def _settle_count(calls) -> int:
    return sum(url.endswith("/settle") for url, _body in calls)


def _verify_count(calls) -> int:
    return sum(url.endswith("/verify") for url, _body in calls)


def test_ib_6_1_official_client_pays_a_stateless_origin(tmp_path, monkeypatch) -> None:
    core_cm, origin, proxy, logged, calls, paths, buyer, url = _boot(tmp_path, monkeypatch, stateless=True, x402=True)
    try:
        result = asyncio.run(_paid_call(url, _TEST_NETWORK, buyer))
    finally:
        _close(core_cm, origin, proxy)
    assert result.payment_made is True
    assert result.is_error is False
    assert result.content[0].text == "acme"
    assert result.payment_response.success is True
    assert _verify_count(calls) == 1
    assert _settle_count(calls) == 1
    assert sum(path.endswith("/x402/verify") for path in paths) == 1
    assert sum(path.endswith("/x402/settle") for path in paths) == 1
    assert all(b"x402/payment" not in body for body in logged.bodies)


def test_ib_6_2_official_client_pays_a_stateful_origin(tmp_path, monkeypatch) -> None:
    core_cm, origin, proxy, logged, calls, paths, buyer, url = _boot(tmp_path, monkeypatch, stateless=False, x402=True)
    try:
        result = asyncio.run(_paid_call(url, _TEST_NETWORK, buyer))
    finally:
        _close(core_cm, origin, proxy)
    assert result.payment_made is True
    assert result.is_error is False
    assert result.content[0].text == "acme"
    assert result.payment_response.success is True
    assert _verify_count(calls) == 1
    assert _settle_count(calls) == 1
    assert sum(path.endswith("/x402/verify") for path in paths) == 1
    assert sum(path.endswith("/x402/settle") for path in paths) == 1
    assert all(b"x402/payment" not in body for body in logged.bodies)


def test_ib_6_3_lightning_only_route_is_not_paid(tmp_path, monkeypatch) -> None:
    core_cm, origin, proxy, _logged, _calls, paths, buyer, url = _boot(tmp_path, monkeypatch, stateless=True, x402=False)
    try:
        result = asyncio.run(_paid_call(url, _TEST_NETWORK, buyer))
    finally:
        _close(core_cm, origin, proxy)
    assert result.payment_made is False
    assert result.is_error is True
    assert sum(path.endswith("/v1/paywall/challenge") for path in paths) == 1
    assert sum(path.endswith("/x402/verify") for path in paths) == 0
    assert sum(path.endswith("/x402/settle") for path in paths) == 0
