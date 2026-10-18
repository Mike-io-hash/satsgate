"""Buyer MCP: challenge parsing, budgets, token reuse, and the human poll."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path

import httpx
import pytest

from app.l402 import make_macaroon, www_authenticate_header
from satsgate_mcp import __version__
from satsgate_mcp.bolt11 import amount_sats, expires_at
from satsgate_mcp.buyer import Buyer, BuyerError
from satsgate_mcp.clients import parse_fetch402, parse_lnget
from satsgate_mcp.config import ConfigError, Settings, load_settings
from satsgate_mcp.manual import (
    configure_manual_logging,
    format_log_line,
    poll_until,
    poll_wait_seconds,
    resume_command,
    _run,
)
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
    expires: int = NOW + 3600,
) -> httpx.Response:
    body: dict[str, object] = {
        "ok": False,
        "error": "payment_required",
        "amount_sats": amount,
        "payment_hash": payment,
        "invoice": invoice,
        "invoice_expires_at": expires,
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


def _signed_invoice(amount_msat: int | None) -> str:
    """A real BOLT11 invoice. Amount digits that contain 1 sit before the separator."""
    from bolt11 import Bolt11, MilliSatoshi, Tags, encode
    from bolt11.models.tags import TagChar

    tags = Tags()
    tags.add(TagChar.payment_hash, PAYMENT)
    tags.add(TagChar.payment_secret, PREIMAGE)
    tags.add(TagChar.description, "satsgate")
    tags.add(TagChar.expire_time, 3600)
    invoice = Bolt11(
        currency="bc",
        amount_msat=None if amount_msat is None else MilliSatoshi(amount_msat),
        date=NOW,
        tags=tags,
    )
    return encode(invoice, private_key="11" * 32)


def _hrp(invoice: str) -> str:
    return invoice.lower()[: invoice.lower().rfind("1")]


def test_version_and_bolt11_amount() -> None:
    assert __version__ == "0.10.0"
    assert amount_sats(SPEC_INVOICE) == 250_000
    assert expires_at(SPEC_INVOICE) == 1_496_314_718
    assert amount_sats("lnbc200n1ignored") == 20


def test_bolt11_amounts_whose_digits_contain_one() -> None:
    expected = {
        1: "lnbc10n",
        10: "lnbc100n",
        21: "lnbc210n",
        100: "lnbc1u",
        1000: "lnbc10u",
        10000: "lnbc100u",
    }
    for sats, hrp in expected.items():
        invoice = _signed_invoice(sats * 1000)
        assert _hrp(invoice) == hrp
        assert "1" in hrp
        assert amount_sats(invoice) == sats
    # 1 millisatoshi is 10 pico-btc. The p suffix is sub-sat and rounds up to 1 sat.
    millis = _signed_invoice(1)
    assert _hrp(millis) == "lnbc10p"
    assert amount_sats(millis) == 1
    bare = _signed_invoice(None)
    assert _hrp(bare) == "lnbc"
    assert amount_sats(bare) is None


def test_twenty_one_sat_invoice_passes_the_budget_check(tmp_path: Path) -> None:
    invoice = _signed_invoice(21 * 1000)
    assert amount_sats(invoice) == 21

    def handler(request: httpx.Request) -> httpx.Response:
        if _auth(request):
            return _paid()
        return _challenge(amount=21, invoice=invoice)

    buyer, _http, wallet = _buyer(tmp_path, handler, nwc_uri=NWC, max_payment_sats=50, daily_max_sats=50)
    paid = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "nwc"))
    assert paid.payload["body"] == "hello"
    assert paid.payload["paid_sats"] == 21
    assert wallet.invoices == [invoice]


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

    bare, bare_http, _wallet2 = _buyer(tmp_path / "other", handler)
    missing = asyncio.run(bare.list_sites())
    assert missing["ok"] is False
    assert missing["error"] == "registry_unavailable"
    assert missing["sites"] == []
    assert bare_http.calls[0].url.path == "/v1/sites"
    assert not any(call.url.path == "/v1/sites" for call in http.calls)


def test_list_sites_reads_the_core_directory(tmp_path: Path) -> None:
    pages = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "directory.example":
            return _challenge()
        assert request.method == "GET"
        pages["n"] += 1
        if pages["n"] == 1:
            assert "cursor" not in request.url.query.decode()
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "hosted_registry": True,
                    "next_cursor": "shop",
                    "sites": [
                        {
                            "name": "Shop",
                            "slug": "shop",
                            "url": "https://gate.satsgate.org/shop/",
                            "description": "A stand",
                            "routes": [{"path": "/post", "price_sats": 21, "max_uses": 1, "access_seconds": None}],
                            "client_id": 9,
                            "origin_url": "https://origin.example",
                        }
                    ],
                },
            )
        assert request.url.params["cursor"] == "shop"
        return httpx.Response(
            200,
            json={
                "ok": True,
                "hosted_registry": True,
                "next_cursor": None,
                "sites": [{"name": "Press", "slug": "press", "url": "https://gate.satsgate.org/press/"}],
            },
        )

    buyer, _http, _wallet = _buyer(tmp_path, handler, registry="https://directory.example/v1/sites")
    sites = asyncio.run(buyer.list_sites())
    assert sites["hosted_registry"] is True
    assert [item["slug"] for item in sites["sites"]] == ["shop", "press"]
    assert sites["sites"][0]["routes"] == [
        {"path": "/post", "price_sats": 21, "max_uses": 1, "access_seconds": None}
    ]
    assert "client_id" not in sites["sites"][0]
    assert "origin_url" not in sites["sites"][0]
    assert pages["n"] == 2


def test_list_sites_defaults_to_the_public_directory(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/sites"
        timeout = request.extensions.get("timeout")
        assert isinstance(timeout, dict)
        assert max(timeout[key] for key in ("connect", "read", "write", "pool")) <= 5
        return httpx.Response(
            200,
            json={
                "ok": True,
                "hosted_registry": True,
                "sites": [
                    {
                        "name": "Shop",
                        "slug": "shop",
                        "url": "https://gate.satsgate.org/shop/",
                        "description": "A stand",
                        "routes": [
                            {"path": "/hello", "price_sats": 21, "max_uses": 1, "access_seconds": None},
                            {"path": "/hour", "price_sats": 50, "max_uses": None, "access_seconds": 3600},
                        ],
                    },
                    {
                        "name": "Pending",
                        "slug": "pending-shop",
                        "url": "https://gate.satsgate.org/pending-shop/",
                        "status": "pending",
                        "listed": False,
                    },
                    {
                        "name": "Disabled",
                        "slug": "disabled-shop",
                        "url": "https://gate.satsgate.org/disabled-shop/",
                        "status": "disabled",
                        "listed": True,
                    },
                    {
                        "name": "Quiet",
                        "slug": "quiet-shop",
                        "url": "https://gate.satsgate.org/quiet-shop/",
                        "status": "approved",
                        "listed": False,
                    },
                ],
            },
        )

    buyer, http, _wallet = _buyer(tmp_path, handler)
    sites = asyncio.run(buyer.list_sites())
    assert sites["ok"] is True
    assert sites["hosted_registry"] is True
    assert sites["skipped"] == 3
    assert sites["sites"] == [
        {
            "name": "Shop",
            "slug": "shop",
            "url": "https://gate.satsgate.org/shop/",
            "description": "A stand",
            "routes": [
                {"path": "/hello", "price_sats": 21, "max_uses": 1, "access_seconds": None},
                {"path": "/hour", "price_sats": 50, "max_uses": None, "access_seconds": 3600},
            ],
        }
    ]
    assert http.calls[0].url == "http://core.test/v1/sites"
    assert "unapproved" in sites["detail"]


@pytest.mark.parametrize(
    ("mode", "error"),
    [
        ("timeout", "registry_unavailable"),
        ("connect", "registry_unavailable"),
        ("http", "registry_unavailable"),
        ("json", "invalid_registry"),
    ],
)
def test_list_sites_registry_errors_do_not_raise(tmp_path: Path, mode: str, error: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "timeout":
            raise httpx.ReadTimeout("slow")
        if mode == "connect":
            raise httpx.ConnectError("down")
        if mode == "http":
            return httpx.Response(503, text="upstream")
        return httpx.Response(200, content=b"not-json")

    buyer, _http, _wallet = _buyer(tmp_path, handler)
    sites = asyncio.run(buyer.list_sites())
    assert sites["ok"] is False
    assert sites["error"] == error
    assert sites["sites"] == []
    assert sites["detail"]
    assert "Traceback" not in sites["detail"]
    assert "upstream" not in sites["detail"]


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


_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ")


def test_poll_wait_grows_from_two_seconds_toward_fifteen() -> None:
    waits = [poll_wait_seconds(attempt, 2) for attempt in range(20)]
    assert waits[:4] == [2, 3, 4, 5]
    assert waits[-1] == 15
    assert all(item <= 15 for item in waits)
    assert poll_wait_seconds(0, 30) == 15
    assert poll_wait_seconds(0, 1) == 2


def test_poll_until_invoice_expiry_is_not_capped_at_forty_rounds() -> None:
    clock = Clock()
    expires = NOW + 3600
    waits: list[int] = []

    async def sleep(seconds: int) -> None:
        waits.append(seconds)
        clock.now += seconds

    async def check() -> dict:
        if clock.now >= expires:
            return {"ok": True, "payment_required": False, "status": 200, "body": "late"}
        return {"ok": False, "error": "payment_pending", "retry_after_seconds": 2}

    result = asyncio.run(
        poll_until(
            check,
            expires_at=expires,
            polls=None,
            timeout=None,
            now=clock,
            sleep=sleep,
            log=lambda _message: None,
        )
    )
    assert result.status == "paid"
    assert result.reason == "paid"
    assert result.checks > 40
    assert waits[:13] == list(range(2, 15))
    assert waits[13] == 15
    assert all(item == 15 for item in waits[13:-1])
    assert waits[-1] <= 15
    assert clock.now >= expires


def test_poll_until_stops_at_expiry_when_still_unpaid() -> None:
    clock = Clock()
    expires = NOW + 30
    seen: list[int] = []

    async def sleep(seconds: int) -> None:
        clock.now += seconds

    async def check() -> dict:
        seen.append(clock.now)
        return {"ok": False, "error": "payment_pending", "retry_after_seconds": 2}

    result = asyncio.run(
        poll_until(
            check,
            expires_at=expires,
            polls=None,
            timeout=None,
            now=clock,
            sleep=sleep,
            log=lambda _message: None,
        )
    )
    assert result.reason == "expired"
    assert result.checks == len(seen)
    assert result.checks < 40
    assert seen[-1] >= expires
    assert seen[0] == NOW


def test_polls_and_timeout_still_cap_the_loop() -> None:
    clock = Clock()

    async def sleep(seconds: int) -> None:
        clock.now += seconds

    async def check() -> dict:
        return {"ok": False, "error": "payment_pending", "retry_after_seconds": 2}

    capped = asyncio.run(
        poll_until(
            check,
            expires_at=NOW + 3600,
            polls=3,
            timeout=None,
            now=clock,
            sleep=sleep,
            log=lambda _message: None,
        )
    )
    assert capped.reason == "polls"
    assert capped.checks == 3
    assert capped.waits == (2, 3)

    clock.now = NOW
    timed = asyncio.run(
        poll_until(
            check,
            expires_at=NOW + 3600,
            polls=None,
            timeout=5,
            now=clock,
            sleep=sleep,
            log=lambda _message: None,
        )
    )
    assert timed.reason == "timeout"
    assert timed.checks < 40
    assert clock.now >= NOW + 5
    assert sum(timed.waits) == 5


def test_manual_resume_from_a_stored_quote(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clock = Clock()
    paid = {"value": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if not _auth(request):
            return _challenge(expires=NOW + 3600)
        assert ":" not in _auth(request).split(" ", 1)[1]
        if paid["value"]:
            return _paid("article")
        return httpx.Response(402, json={"ok": False, "error": "payment_pending", "payment_hash": PAYMENT})

    buyer, _http, wallet = _buyer(tmp_path, handler)
    buyer._now = clock
    offer = asyncio.run(buyer.pay_and_fetch("https://shop.example/a", "human"))
    assert offer.payload["payment_hash"] == PAYMENT
    assert wallet.invoices == []

    async def sleep(seconds: int) -> None:
        clock.now += seconds

    missing = asyncio.run(_run(["--resume", "ff" * 32], buyer=buyer, now=clock, sleep=sleep))
    assert missing == 1
    missed = capsys.readouterr()
    assert "No stored invoice" in missed.err
    assert "SATSGATE_MCP_DATA_DIR" in missed.err
    assert MAC not in missed.err + missed.out

    paid["value"] = True
    code = asyncio.run(_run(["--resume", PAYMENT], buyer=buyer, now=clock, sleep=sleep))
    assert code == 0
    captured = capsys.readouterr()
    assert "article" in captured.out
    assert MAC not in captured.out + captured.err
    assert _STAMP.match(captured.out.splitlines()[0])
    assert wallet.invoices == []


def test_manual_give_up_prints_the_resume_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        if not _auth(request):
            return _challenge(expires=NOW + 10)
        return httpx.Response(
            402,
            json={"ok": False, "error": "payment_pending", "payment_hash": PAYMENT, "retry_after_seconds": 2},
        )

    buyer, _http, _wallet = _buyer(tmp_path, handler)
    buyer._now = clock

    async def sleep(seconds: int) -> None:
        clock.now += seconds

    code = asyncio.run(_run(["https://shop.example/a"], buyer=buyer, now=clock, sleep=sleep))
    assert code == 1
    captured = capsys.readouterr()
    command = resume_command(tmp_path, PAYMENT)
    assert command in captured.err
    assert "Stopped (expired)." in captured.err
    assert MAC not in captured.out + captured.err
    pending = [line for line in captured.out.splitlines() if "pending, retrying in " in line]
    assert pending
    assert len(pending) < 40
    assert all(_STAMP.match(line) for line in pending)
    assert "retrying in 2s" in pending[0]
    assert "retrying in 3s" in pending[1]
    assert format_log_line("pending, retrying in 2s", now=lambda: NOW).startswith("2023-11-14T22:13:20Z ")


def test_manual_polls_timeout_and_resume_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert asyncio.run(_run(["--polls", "0", "https://shop.example/a"])) == 2
    assert asyncio.run(_run(["--timeout", "0", "https://shop.example/a"])) == 2
    assert asyncio.run(_run(["--nwc", "--resume", PAYMENT])) == 2
    assert asyncio.run(_run(["--resume", PAYMENT, "https://shop.example/a"])) == 2
    assert asyncio.run(_run([])) == 2
    capsys.readouterr()

    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        if not _auth(request):
            return _challenge()
        return httpx.Response(402, json={"ok": False, "error": "payment_pending", "payment_hash": PAYMENT})

    buyer, _http, _wallet = _buyer(tmp_path, handler)
    buyer._now = clock

    async def sleep(seconds: int) -> None:
        clock.now += seconds

    code = asyncio.run(
        _run(["--polls", "2", "--timeout", "100", "https://shop.example/a"], buyer=buyer, now=clock, sleep=sleep)
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "Stopped (polls)." in captured.err
    assert captured.out.count("pending, retrying in ") == 1

    configure_manual_logging()
    logger = logging.getLogger("satsgate_mcp")
    record = logger.makeRecord(logger.name, logging.INFO, __file__, 1, "pending", (), None)
    formatted = next(handler.format(record) for handler in logger.handlers if handler.formatter is not None)
    assert _STAMP.match(formatted)
    assert formatted.endswith("INFO pending")
