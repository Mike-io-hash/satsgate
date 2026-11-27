"""T-PF: paid fields after a human payment, the server/discover fallback log, and the proxy health body."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest

import satsgate_mcp.__main__ as mcp_main
from test_satsgate_mcp_remote import (
    PAYMENT,
    URL,
    Clock,
    _buyer,
    _key,
    _lightning,
    _origin,
    _priced,
    _rpc,
    _tool_ok,
)

ROOT = Path(__file__).resolve().parents[1]
_D_SETTLED = (
    "The invoice is settled and the tool returned a result. "
    "The token is stored for later calls to this tool while it has uses or time."
)
_D_REUSED = "The tool returned a result with a stored token. Nothing new was paid."
_SUFFIX_TOKEN = " The stored token was kept. Call remote_call_tool again to retry with it. Do not pay again."
_FALLBACK = (
    "server/discover at shop.example/mcp answered HTTP 400. Using initialize instead. "
    "Servers on an earlier MCP version answer this way. It is not an error."
)


def test_pf_1_1_human_settlement_reports_the_payment(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            return _tool_ok(body["id"], "settled")
        return _priced(body["id"], _lightning())

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    done = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert done.payload["paid"] is True
    assert done.payload["paid_with"] == "lightning"
    assert done.payload["paid_sats"] == 21
    assert done.payload["reused_token"] is False
    assert done.payload["payment_hash"] == PAYMENT
    assert done.payload["detail"] == _D_SETTLED
    again = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert again.payload["paid"] is False
    assert again.payload["paid_with"] is None
    assert again.payload["paid_sats"] is None
    assert again.payload["reused_token"] is True
    assert again.payload["detail"] == _D_REUSED
    assert wallet.invoices == []


def test_pf_1_2_human_settlement_then_tool_error_reports_the_payment(tmp_path: Path) -> None:
    def on_call(request, body):
        if request.headers.get("authorization"):
            return _rpc(body["id"], {"isError": True, "content": [{"type": "text", "text": "nope"}]})
        return _priced(body["id"], _lightning())

    buyer, _http, wallet = _buyer(tmp_path, _origin(on_call=on_call))
    buyer._now = Clock()
    asyncio.run(buyer.remote_call_tool(URL, "echo"))
    failed = asyncio.run(buyer.remote_call_tool(URL, "echo"))
    assert failed.payload["error"] == "tool_error"
    assert failed.payload["paid"] is True
    assert failed.payload["paid_with"] == "lightning"
    assert failed.payload["paid_sats"] == 21
    assert failed.payload["token_kept"] is True
    assert failed.payload["detail"] == "The tool returned an error result." + _SUFFIX_TOKEN
    assert buyer.store.token_for(_key())["uses_remaining"] == 5
    assert wallet.invoices == []


_LOGGERS = ("", "satsgate_mcp", "httpx", "httpcore", "httpx2", "httpcore2")


@pytest.fixture
def logger_state():
    """Save and restore the loggers these tests touch. Another test may have changed them."""
    saved = []
    for name in _LOGGERS:
        item = logging.getLogger(name)
        saved.append((item, item.level, list(item.handlers), list(item.filters), item.propagate))
    yield
    for item, level, handlers, filters, propagate in saved:
        item.handlers[:] = handlers
        item.filters[:] = filters
        item.propagate = propagate
        item.setLevel(level)


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _listen() -> _Records:
    named = logging.getLogger("satsgate_mcp")
    sink = _Records()
    named.addHandler(sink)
    named.setLevel(logging.INFO)
    return sink


def test_pf_2_1_discover_fallback_is_one_info_line(tmp_path: Path, logger_state) -> None:
    sink = _listen()
    buyer, _http, _wallet = _buyer(tmp_path, _origin(modern=False))
    listed = asyncio.run(buyer.remote_list_tools(URL))
    assert listed.payload["ok"] is True
    assert listed.payload["protocol_version"] == "2025-11-25"
    lines = [record for record in sink.records if "server/discover" in record.getMessage()]
    assert [record.getMessage() for record in lines] == [_FALLBACK]
    assert [record.levelno for record in lines] == [logging.INFO]
    assert [record for record in sink.records if record.levelno >= logging.WARNING] == []


def test_pf_2_2_modern_server_logs_no_fallback(tmp_path: Path, logger_state) -> None:
    sink = _listen()
    buyer, _http, _wallet = _buyer(tmp_path, _origin(modern=True))
    asyncio.run(buyer.remote_list_tools(URL))
    assert [record for record in sink.records if "server/discover" in record.getMessage()] == []


def test_pf_2_3_http_client_loggers_log_only_warnings(logger_state) -> None:
    names = ("httpx", "httpcore", "httpx2", "httpcore2")
    for name in names:
        logging.getLogger(name).setLevel(logging.NOTSET)
    mcp_main.configure_logging()
    for name in names:
        assert logging.getLogger(name).level == logging.WARNING
    assert logging.getLogger("satsgate_mcp").getEffectiveLevel() == logging.INFO


def test_pf_3_1_proxy_health_body_is_compact_and_documented(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from satsgate_proxy import __version__
    from test_satsgate_proxy import World, _client, _load

    settings = _load(tmp_path, monkeypatch)
    with _client(settings, World()) as client:
        body = client.get("/healthz").content
    expected = '{"ok":true,"component":"satsgate-proxy","version":"%s"}' % __version__
    assert body == expected.encode("utf-8")
    readme = (ROOT / "proxy" / "README.md").read_text(encoding="utf-8")
    assert "(`" + expected + "`)" in readme
