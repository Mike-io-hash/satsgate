"""Buyer MCP: challenge parsing, budgets, token reuse, and the human poll."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import httpx
import pytest

from app.l402 import make_macaroon, www_authenticate_header
from satsgate_mcp import __version__
from satsgate_mcp.bolt11 import amount_sats, expires_at
from satsgate_mcp.buyer import Buyer, BuyerError
from satsgate_mcp.clients import parse_fetch402, parse_lnget
from satsgate_mcp.config import ConfigError, Settings, load_settings
from satsgate_mcp.nwc import NwcError
from satsgate_mcp.server import build_server
from satsgate_mcp.store import Store

PAYMENT = "ab" * 32
OTHER = "11" * 32
PREIMAGE = "cd" * 32
MAC = "bWFjYXJvb24"
INVOICE = "lnbc1pinvoice"
NOW = 1_700_000_000
# BOLT11 spec example: 2500 uBTC, timestamp 1496314658, expiry 60.
SPEC_INVOICE = (
    "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5"
    "qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4js"
    "xqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s"
    "06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
)
NWC = (
    "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4"
    "?relay=wss://relay.example.com&secret=1111111111111111111111111111111111111111111111111111111111111111"
)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> int:
        return self.now


class Wallet:
    def __init__(self) -> None:
        self.invoices: list[str] = []
        self.error: Exception | None = None

    async def pay_invoice(self, invoice: str) -> str:
        if self.error is not None:
            raise self.error
        self.invoices.append(invoice)
        return PREIMAGE


class Http(httpx.AsyncBaseTransport):
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        return self.handler(request)


def _settings(tmp_path: Path, **overrides) -> Settings:
    values = dict(
        nwc_uri="",
        max_payment_sats=100,
        daily_max_sats=500,
        auto_pay=False,
        data_dir=tmp_path,
        core_url="http://core.test",
        api_key="",
        api_key_rejected=False,
        allowlist=(),
        timeout=5.0,
        registry="",
        max_body_bytes=100_000,
    )
    values.update(overrides)
    return Settings(**values)


def _buyer(tmp_path: Path, handler, wallet: Wallet | None = None, **overrides) -> tuple[Buyer, Http, Wallet]:
    http = Http(handler)
    paying = wallet or Wallet()
    clock = Clock()
    buyer = Buyer(
        _settings(tmp_path, **overrides),
        store=Store(tmp_path),
        wallet=paying,
        transport=http,
        now=clock,
    )
    return buyer, http, paying


def _challenge(
    *,
    amount: int = 21,
    max_uses: int | None = 5,
    access_seconds: int | None = None,
    payment: str = PAYMENT,
    invoice: str = INVOICE,
    reason: str | None = None,
    macaroon: str = MAC,
) -> httpx.Response:
    body: dict[str, object] = {
        "ok": False,
        "error": "payment_required",
        "amount_sats": amount,
        "payment_hash": payment,
        "invoice": invoice,
        "invoice_expires_at": NOW + 3600,
        "macaroon": macaroon,
        "resource": "route:article",
        "max_uses": max_uses,
        "access_seconds": access_seconds,
    }
    if reason:
        body["reason"] = reason
    header = f'L402 macaroon="{macaroon}", invoice="{invoice}"'
    return httpx.Response(402, json=body, headers={"www-authenticate": header})


def _paid(text: str = "hello") -> httpx.Response:
    return httpx.Response(200, content=text.encode(), headers={"content-type": "text/plain"})


def _auth(request: httpx.Request) -> str:
    return request.headers.get("authorization", "")


def test_version_and_bolt11_amount() -> None:
    assert __version__ == "0.9.0"
    assert amount_sats(SPEC_INVOICE) == 250_000
    assert expires_at(SPEC_INVOICE) == 1_496_314_718
    assert amount_sats("lnbc200n1ignored") == 20


def test_discover_reads_policy_and_hides_the_macaroon(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "timeout" in request.extensions
        return _challenge(max_uses=10, access_seconds=3600)

    buyer, http, wallet = _buyer(tmp_path, handler)
    found = asyncio.run(buyer.discover("https://shop.example/blog/post"))
    quoted = asyncio.run(buyer.quote("https://shop.example/blog/post"))
    assert found["amount_sats"] == 21
    assert found["max_uses"] == 10
    assert found["access_seconds"] == 3600
    assert found["invoice_expires_at"] == NOW + 3600
    assert found["resource"] == "route:article"
    assert "costs 21 sats" in found["summary"]
    assert MAC not in json.dumps(found)
    assert "10 uses" in quoted["summary"]
    assert wallet.invoices == []
    assert len(http.calls) == 2
    header = http.calls[0].headers
    assert "authorization" not in header


def test_header_only_challenge_uses_the_macaroon_and_invoice_amount(tmp_path: Path) -> None:
    macaroon = make_macaroon(
        secret="test-secret",
        kid="k1",
        purpose="paywall",
        payment_hash=PAYMENT,
        resource="route:article",
        amount_sats=20,
        invoice="lnbc200n1ignored",
        ttl_seconds=3600,
        client_id=1,
        payee="payee@example.com",
    )
    invoice = "lnbc200n1ignored"
    header = www_authenticate_header(macaroon=macaroon, invoice=invoice)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, content=b"", headers={"www-authenticate": header})

    buyer, _http, _wallet = _buyer(tmp_path, handler)
    found = asyncio.run(buyer.discover("https://shop.example/file"))
    assert found["amount_sats"] == 20
    assert found["payment_hash"] == PAYMENT
    assert found["resource"] == "route:article"
    assert macaroon not in json.dumps(found)
    assert parse_lnget(header) == (macaroon, invoice)
    assert parse_fetch402(header) == (macaroon, invoice)


def test_amount_mismatch_and_bad_urls(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _challenge(amount=21, invoice=SPEC_INVOICE)

    buyer, http, _wallet = _buyer(tmp_path, handler, allowlist=("shop.example",))
    with pytest.raises(Exception) as mismatch:
        asyncio.run(buyer.discover("https://shop.example/x"))
    assert "amount_mismatch" in str(mismatch.value) or getattr(mismatch.value, "code", "") == "amount_mismatch"
    with pytest.raises(Exception):
        asyncio.run(buyer.discover("file:///etc/passwd"))
    with pytest.raises(Exception):
        asyncio.run(buyer.discover("https://user:pass@shop.example/x"))
    with pytest.raises(Exception):
        asyncio.run(buyer.discover("https://evil.example/x"))
    assert len(http.calls) == 1


def test_budget_blocks_before_the_wallet_and_rolls_the_day(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _auth(request):
            return _paid()
        return _challenge(amount=30)

    buyer, _http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC, max_payment_sats=20, daily_max_sats=40)
    blocked = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert blocked.payload["error"] == "over_budget"
    assert "per-payment cap of 20" in blocked.payload["detail"]
    assert wallet.invoices == []

    object.__setattr__(buyer, "settings", _settings(tmp_path, nwc_uri=NWC, max_payment_sats=30, daily_max_sats=40))
    first = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert first.payload["body"] == "hello"
    assert wallet.invoices == [INVOICE]
    second = asyncio.run(buyer.pay_and_fetch("https://shop.example/b", "nwc"))
    assert second.payload["error"] == "over_budget"
    assert "last 24 hours" in second.payload["detail"]
    assert wallet.invoices == [INVOICE]


def test_token_reuse_does_not_pay_again(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _auth(request):
            return _paid()
        return _challenge(max_uses=5)

    buyer, http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC)
    first = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    second = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert first.payload["uses_remaining"] == 4
    assert second.payload["uses_remaining"] == 3
    assert wallet.invoices == [INVOICE]
    assert _auth(http.calls[1]).endswith(":" + PREIMAGE)
    assert _auth(http.calls[2]).endswith(":" + PREIMAGE)


def test_used_up_requotes_and_pays_only_when_asked_again(tmp_path: Path) -> None:
    state = {"authed": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if not _auth(request):
            return _challenge(max_uses=None)
        state["authed"] += 1
        if state["authed"] == 1:
            return _paid()
        if state["authed"] == 2:
            return _challenge(max_uses=1, payment=OTHER, invoice="lnbc1psecond", reason="token_used_up")
        return _paid("again")

    buyer, _http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC)
    assert asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc")).payload["body"] == "hello"
    again = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert again.payload["action"] == "requote"
    assert again.payload["auto_paid"] is False
    assert again.payload["reason"] == "token_used_up"
    assert again.payload["payment_hash"] == OTHER
    assert wallet.invoices == [INVOICE]
    paid = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert paid.payload["body"] == "again"
    assert wallet.invoices == [INVOICE, "lnbc1psecond"]


def test_auto_pay_pays_a_used_up_token_only_inside_budget(tmp_path: Path) -> None:
    state = {"authed": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if not _auth(request):
            return _challenge(max_uses=None, amount=21)
        state["authed"] += 1
        if state["authed"] == 1:
            return _paid()
        if state["authed"] == 2:
            return _challenge(max_uses=1, amount=80, payment=OTHER, invoice="lnbc1ptoobig", reason="token_used_up")
        return _paid("again")

    buyer, _http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC, auto_pay=True, max_payment_sats=50, daily_max_sats=500)
    asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    blocked = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert blocked.payload["error"] == "over_budget"
    assert blocked.payload["auto_paid"] is False
    assert wallet.invoices == [INVOICE]
    assert state["authed"] == 2

    allowed = _buyer(tmp_path / "pay", handler, nwc_uri=NWC, auto_pay=True, max_payment_sats=100, daily_max_sats=500)
    state["authed"] = 0
    asyncio.run(allowed[0].pay_and_fetch("https://shop.example/a", "nwc"))
    paid = asyncio.run(allowed[0].pay_and_fetch("https://shop.example/a", "nwc"))
    assert paid.payload["body"] == "again"
    assert paid.payload["auto_paid"] is True
    assert allowed[2].invoices == [INVOICE, "lnbc1ptoobig"]


def test_human_pay_qr_and_poll(tmp_path: Path) -> None:
    pending = {"value": True}

    def handler(request: httpx.Request) -> httpx.Response:
        auth = _auth(request)
        if not auth:
            return _challenge(max_uses=1)
        assert ":" not in auth.split(" ", 1)[1]
        assert "x-api-key" not in request.headers
        if pending["value"]:
            return httpx.Response(
                402,
                json={"ok": False, "error": "payment_pending", "payment_hash": PAYMENT, "retry_after_seconds": 3},
                headers={"retry-after": "3"},
            )
        return _paid("article")

    buyer, _http, wallet = _buyer(tmp_path, handler)
    offer = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "human"))
    assert wallet.invoices == []
    assert offer.payload["invoice"] == INVOICE
    assert offer.payload["action"] == "pay_invoice"
    assert offer.qr_png is not None and offer.qr_png.startswith(b"\x89PNG")
    assert offer.payload["qr_text"]
    assert MAC not in json.dumps(offer.payload)
    waiting = asyncio.run(buyer.check_payment(PAYMENT))
    assert waiting.payload["error"] == "payment_pending"
    assert waiting.payload["retry_after_seconds"] == 3
    pending["value"] = False
    fetched = asyncio.run(buyer.check_payment(PAYMENT))
    assert fetched.payload["body"] == "article"
    assert fetched.payload["uses_remaining"] == 0


def test_check_payment_polls_core_before_the_resource(tmp_path: Path) -> None:
    phase = {"core": "pending"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "core.test":
            assert request.method == "GET"
            assert "consume=false" in request.url.query.decode()
            assert request.headers["x-api-key"] == "sgr_testkeyvalue"
            assert ":" not in request.headers["authorization"].split(" ", 1)[1]
            if phase["core"] == "pending":
                return httpx.Response(200, json={"ok": True, "status": "pending", "settled": False, "payment_hash": PAYMENT})
            return httpx.Response(200, json={"ok": True, "status": "settled", "settled": True, "payment_hash": PAYMENT})
        if not _auth(request):
            return _challenge()
        return _paid("from-origin")

    buyer, http, wallet = _buyer(tmp_path, handler, api_key="sgr_testkeyvalue")
    asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "human"))
    shop_calls = len(http.calls)
    waiting = asyncio.run(buyer.check_payment(PAYMENT))
    assert waiting.payload["error"] == "payment_pending"
    assert http.calls[-1].url.host == "core.test"
    assert len(http.calls) == shop_calls + 1
    phase["core"] = "settled"
    fetched = asyncio.run(buyer.check_payment(PAYMENT))
    assert fetched.payload["body"] == "from-origin"
    assert wallet.invoices == []
    assert [call.url.host for call in http.calls[-2:]] == ["core.test", "shop.example"]


def test_secrets_stay_out_of_errors_logs_and_repr(tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _auth(request):
            return _paid()
        return _challenge()

    wallet = Wallet()
    wallet.error = NwcError(f"relay rejected {NWC}")
    buyer, _http, _wallet = _buyer(tmp_path, handler, wallet=wallet, nwc_uri=NWC, api_key="sgr_testkeyvalue")
    caplog.set_level(logging.INFO, logger="satsgate_mcp")
    with pytest.raises(BuyerError) as failed:
        asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert failed.value.code == "nwc_failed"
    blob = failed.value.message + caplog.text + repr(buyer.settings)
    assert NWC not in blob
    assert "1111111111111111111111111111111111111111111111111111111111111111" not in blob
    assert "sgr_testkeyvalue" not in blob
    monkeypatch.setenv("SATSGATE_MCP_NWC_URI", "https://not-a-wallet.example/secret-value-here")
    with pytest.raises(ConfigError) as exc:
        load_settings()
    assert "secret-value-here" not in str(exc.value)
    monkeypatch.delenv("SATSGATE_MCP_NWC_URI")
    monkeypatch.setenv("SATSGATE_MCP_API_KEY", "sg_accountkeyvalue")
    loaded = load_settings()
    assert loaded.api_key == ""
    assert loaded.api_key_rejected is True
    assert "sg_accountkeyvalue" not in repr(loaded)


def test_redirect_is_not_followed(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://secret-upstream.internal/hidden"})

    buyer, http, _wallet = _buyer(tmp_path, handler)
    with pytest.raises(Exception) as exc:
        asyncio.run(buyer.discover("https://shop.example/a"))
    assert getattr(exc.value, "code", "") == "redirect_not_followed"
    assert len(http.calls) == 1
    assert "secret-upstream" not in str(exc.value)


def test_registry_balance_and_status_are_read_only(tmp_path: Path) -> None:
    registry = tmp_path / "sites.json"
    registry.write_text(
        json.dumps(
            {
                "sites": [
                    {"name": "shop", "url": "https://shop.example/a", "description": "A file"},
                    {"name": "bad", "url": "file:///tmp/x"},
                ]
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        if request.url.path == "/v1/balance":
            return httpx.Response(403, json={"ok": False, "error": "insufficient_scope"})
        if "/v1/paywall/status/" in request.url.path:
            assert "consume=false" in request.url.query.decode()
            return httpx.Response(
                200,
                json={"ok": True, "status": "pending", "settled": False, "payment_hash": PAYMENT, "uses_remaining": 5},
            )
        return _challenge()

    buyer, http, _wallet = _buyer(tmp_path, handler, api_key="sgr_testkeyvalue", registry=str(registry))
    sites = asyncio.run(buyer.list_sites())
    assert sites["hosted_registry"] is False
    assert sites["sites"] == [{"name": "shop", "url": "https://shop.example/a", "description": "A file"}]
    assert sites["skipped"] == 1
    balance = asyncio.run(buyer.credits_balance())
    assert balance["error"] == "insufficient_scope"
    assert "No write was attempted" in balance["detail"]
    asyncio.run(buyer.discover("https://shop.example/a"))
    status = asyncio.run(buyer.challenge_status(PAYMENT))
    assert status["consume"] is False
    assert status["settled"] is False
    assert all(call.method == "GET" for call in http.calls)

    bare, _http2, _wallet2 = _buyer(tmp_path / "other", handler)
    missing = asyncio.run(bare.list_sites())
    assert missing["error"] == "registry_not_configured"
    assert missing["hosted_registry"] is False


def test_discover_then_human_pay_reuses_the_quote(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _auth(request):
            return _paid()
        return _challenge()

    buyer, http, _wallet = _buyer(tmp_path, handler)
    asyncio.run(buyer.discover("https://shop.example/a"))
    asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "human"))
    assert len(http.calls) == 1


def test_server_registers_tools_and_returns_a_qr_image(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _auth(request):
            return _paid()
        return _challenge()

    buyer, _http, wallet = _buyer(tmp_path, handler)
    server = build_server(buyer)
    names = sorted(tool.name for tool in server._tool_manager.list_tools())
    assert names == [
        "challenge_status",
        "check_payment",
        "credits_balance",
        "discover",
        "list_sites",
        "pay_and_fetch",
        "quote",
    ]
    pay = next(tool for tool in server._tool_manager.list_tools() if tool.name == "pay_and_fetch")
    result = asyncio.run(pay.fn(url="https://shop.example/a", mode="human"))
    assert result[0]["invoice"] == INVOICE
    assert result[1].to_image_content().mime_type == "image/png"
    assert wallet.invoices == []
