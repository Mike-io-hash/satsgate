"""satsgate-mcp reads x402 requirements and does not sign them."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import sqlite3
from pathlib import Path

import httpx
import pytest

from satsgate_mcp.config import ConfigError, load_settings
from satsgate_mcp.store import Store
from satsgate_mcp.x402 import for_agent, format_usdc, parse_offered
from test_satsgate_mcp import INVOICE, MAC, NOW, _buyer, _challenge, _paid

USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PAYTO = "0x4A9E2CA774BB87110ffF3CB8a250e935cFE52Ce3"
OTHER = "0x0000000000000000000000000000000000000001"
SIGNATURE = "ZmFrZS14NDAyLXNpZ25hdHVyZQ"
URL = "https://shop.example/a"
RESOURCE = "https://shop.example/a"


def _accept(
    *,
    amount: str = "10000",
    network: str = "eip155:84532",
    asset: str = USDC,
    scheme: str = "exact",
    pay_to: str = PAYTO,
) -> dict:
    return {
        "scheme": scheme,
        "network": network,
        "amount": amount,
        "asset": asset,
        "payTo": pay_to,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }


def _encoded(accepts: list[dict], *, version: int = 2, resource: str = RESOURCE) -> str:
    document = {
        "x402Version": version,
        "resource": {"url": resource, "description": "", "mimeType": "application/json"},
        "accepts": accepts,
    }
    return base64.standard_b64encode(json.dumps(document).encode("utf-8")).decode("ascii")


def _body(
    *,
    amount: str = "10000",
    network: str = "eip155:84532",
    asset: str = USDC,
    scheme: str = "exact",
    lightning: bool = False,
    expires: int = NOW + 60,
) -> dict:
    payload: dict = {
        "ok": False,
        "error": "payment_required",
        "resource": "route:article",
        "max_uses": 1,
        "access_seconds": None,
        "x402": {
            "scheme": scheme,
            "network": network,
            "asset": asset,
            "amount": amount,
            "payTo": PAYTO,
            "expires_at": expires,
        },
    }
    if lightning:
        payload.update(
            {
                "amount_sats": 21,
                "payment_hash": "ab" * 32,
                "invoice": INVOICE,
                "invoice_expires_at": NOW + 3600,
                "macaroon": MAC,
            }
        )
    return payload


def _x402_response(
    *,
    amount: str = "10000",
    network: str = "eip155:84532",
    asset: str = USDC,
    lightning: bool = False,
    header: str | None = None,
    accepts: list[dict] | None = None,
    status: int = 402,
) -> httpx.Response:
    body = _body(amount=amount, network=network, asset=asset, lightning=lightning)
    encoded = header if header is not None else _encoded(accepts or [_accept(amount=amount, network=network, asset=asset)])
    headers = {"payment-required": encoded}
    if lightning:
        headers["www-authenticate"] = f'L402 macaroon="{MAC}", invoice="{INVOICE}"'
    return httpx.Response(status, json=body, headers=headers)


def _settings_usd(tmp_path: Path, **overrides):
    values = dict(max_payment_usd_atomic=1_000_000, daily_max_usd_atomic=5_000_000)
    values.update(overrides)
    return _buyer(tmp_path, values.pop("handler"), **values)


def test_format_usdc_uses_six_decimals() -> None:
    assert format_usdc(10_000) == "0.01 USDC"
    assert format_usdc(1) == "0.000001 USDC"
    assert format_usdc(1_000_000) == "1 USDC"
    assert format_usdc(1_500_000) == "1.5 USDC"


def test_parse_valid_requirement_shows_human_usdc_and_the_atomic_amount() -> None:
    header = _encoded([_accept()])
    parsed = parse_offered(header, _body())
    assert parsed is not None and not parsed.malformed
    assert parsed.canonical is True
    assert parsed.resource_url == RESOURCE
    assert parsed.expires_at == NOW + 60
    assert parsed.mirror_disagreed is False
    accept = parsed.accepts[0]
    assert accept.scheme == "exact"
    assert accept.network == "eip155:84532"
    assert accept.asset == USDC
    assert accept.amount_atomic == "10000"
    assert accept.amount_display() == "0.01 USDC"
    assert accept.pay_to == PAYTO
    assert accept.supported is True
    assert accept.max_timeout_seconds == 60


def test_parse_malformed_header_does_not_raise() -> None:
    junk = parse_offered("%%%", _body())
    assert junk is not None and junk.malformed is True
    assert "base64" in (junk.detail or "")
    raw = base64.standard_b64encode(b"[]").decode("ascii")
    not_object = parse_offered(raw, {})
    assert not_object is not None and not_object.malformed is True
    missing = parse_offered(_encoded([]), {})
    assert missing is not None and missing.malformed is True
    bad_amount = parse_offered(_encoded([_accept(amount="0.01")]), _body(amount="0.01"))
    assert bad_amount is not None and not bad_amount.malformed
    assert bad_amount.accepts[0].supported is False
    assert bad_amount.accepts[0].unsupported_reason == "malformed_x402"
    assert bad_amount.accepts[0].amount_display() is None


def test_parse_multiple_accepts_reports_each_one() -> None:
    second = _accept(amount="5000", network="eip155:1", asset=OTHER)
    parsed = parse_offered(_encoded([_accept(), second]), _body())
    assert parsed is not None
    assert len(parsed.accepts) == 2
    assert parsed.accepts[0].supported is True
    assert parsed.accepts[0].amount_display() == "0.01 USDC"
    assert parsed.accepts[1].supported is False
    assert parsed.accepts[1].unsupported_reason == "unsupported_network"
    assert parsed.accepts[1].network == "eip155:1"
    assert parsed.accepts[1].amount_atomic == "5000"


def test_parse_unknown_network_and_asset_are_reported() -> None:
    unknown_net = parse_offered(_encoded([_accept(network="eip155:1", asset=OTHER)]), _body(network="eip155:1", asset=OTHER))
    assert unknown_net is not None
    assert unknown_net.accepts[0].unsupported_reason == "unsupported_network"
    assert unknown_net.accepts[0].amount_display() is None
    unknown_asset = parse_offered(_encoded([_accept(asset=OTHER)]), _body(asset=OTHER))
    assert unknown_asset is not None
    assert unknown_asset.accepts[0].unsupported_reason == "unsupported_asset"
    assert unknown_asset.accepts[0].asset == OTHER
    assert unknown_asset.accepts[0].amount_atomic == "10000"
    mainnet = parse_offered(
        _encoded([_accept(network="eip155:8453", asset=MAINNET_USDC, amount="1")]),
        _body(network="eip155:8453", asset=MAINNET_USDC, amount="1"),
    )
    assert mainnet is not None and mainnet.accepts[0].supported is True
    assert mainnet.accepts[0].amount_display() == "0.000001 USDC"


def test_header_amount_wins_when_the_body_disagrees() -> None:
    body = _body(amount="999")
    parsed = parse_offered(_encoded([_accept(amount="10000")]), body)
    assert parsed is not None
    assert parsed.mirror_disagreed is True
    assert parsed.accepts[0].amount_atomic == "10000"
    assert parsed.accepts[0].amount_display() == "0.01 USDC"


def test_discover_x402_only_and_both_rails(tmp_path: Path) -> None:
    def only(request: httpx.Request) -> httpx.Response:
        return _x402_response()

    buyer, _http, wallet = _settings_usd(tmp_path, handler=only)
    found = asyncio.run(buyer.discover(URL))
    assert found["ok"] is True
    assert found["rails"] == ["x402"]
    assert "invoice" not in found
    assert found["x402"]["payable"] is True
    shown = found["x402"]["accepts"][0]
    assert shown["amount_atomic"] == "10000"
    assert shown["amount_usdc"] == "0.01"
    assert shown["amount_display"] == "0.01 USDC"
    assert shown["pay_to"] == PAYTO
    assert shown["network"] == "eip155:84532"
    assert shown["scheme"] == "exact"
    assert shown["resource_url"] == RESOURCE
    assert shown["expires_at"] == NOW + 60
    assert "does not hold a buyer private key" in found["x402"]["payment"]["detail"]
    assert "same PAYMENT-SIGNATURE" in found["x402"]["payment"]["detail"]
    assert wallet.invoices == []

    def both(request: httpx.Request) -> httpx.Response:
        return _x402_response(lightning=True)

    buyer, _http, wallet = _settings_usd(tmp_path / "both", handler=both)
    found = asyncio.run(buyer.discover(URL))
    assert found["rails"] == ["lightning", "x402"]
    assert found["amount_sats"] == 21
    assert found["invoice"] == INVOICE
    assert "costs 21 sats" in found["summary"]
    assert "0.01 USDC" in found["summary"]
    assert found["x402"]["payable"] is True
    offered = asyncio.run(buyer.pay_and_fetch(URL, "human"))
    assert offered.payload["invoice"] == INVOICE
    assert offered.qr_png
    assert offered.payload["x402"]["payable"] is True
    assert wallet.invoices == []


def test_usd_cap_is_independent_of_the_sats_cap(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "payment-signature" not in request.headers
        return _x402_response(amount="2000000")

    buyer, http, wallet = _settings_usd(
        tmp_path,
        handler=handler,
        max_payment_sats=0,
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=5_000_000,
    )
    found = asyncio.run(buyer.discover(URL))
    assert found["x402"]["payable"] is False
    assert found["x402"]["error"] == "over_budget"
    assert "2 USDC" in found["x402"]["cap_detail"]
    assert "SATSGATE_MCP_MAX_PAYMENT_USD" in found["x402"]["cap_detail"]
    assert "payment" not in found["x402"]
    refused = asyncio.run(buyer.pay_and_fetch(URL, "human", payment_signature=SIGNATURE))
    assert refused.payload["ok"] is False
    assert refused.payload["signature_sent"] is False
    assert refused.payload["error"] == "over_budget"
    assert all("payment-signature" not in call.headers for call in http.calls)
    assert wallet.invoices == []

    def cheap(request: httpx.Request) -> httpx.Response:
        return _x402_response()

    allowed, _http, _wallet = _settings_usd(tmp_path / "cheap", handler=cheap, max_payment_sats=0)
    priced = asyncio.run(allowed.discover("https://shop.example/cheap"))
    assert priced["x402"]["payable"] is True


def test_unset_usd_cap_does_not_proceed(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _x402_response()

    buyer, http, _wallet = _buyer(tmp_path, handler)
    found = asyncio.run(buyer.discover(URL))
    assert found["x402"]["accepts"][0]["amount_display"] == "0.01 USDC"
    assert found["x402"]["payable"] is False
    assert found["x402"]["error"] == "cap_not_configured"
    refused = asyncio.run(buyer.pay_and_fetch(URL, payment_signature=SIGNATURE))
    assert refused.payload["signature_sent"] is False
    assert "SATSGATE_MCP_MAX_PAYMENT_USD" in refused.payload["detail"]
    assert all("payment-signature" not in call.headers for call in http.calls)


def test_pass_through_reports_origin_failure_then_success(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    state = {"signed": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        signature = request.headers.get("payment-signature")
        if not signature:
            return _x402_response()
        assert signature == SIGNATURE
        assert "authorization" not in request.headers
        state["signed"] += 1
        if state["signed"] == 1:
            return httpx.Response(500, content=b"origin-down", headers={"content-type": "text/plain"})
        response_doc = {
            "success": True,
            "transaction": "0x" + "ab" * 32,
            "tx": "0x" + "ab" * 32,
            "network": "eip155:84532",
            "payer": PAYTO,
        }
        encoded = base64.standard_b64encode(json.dumps(response_doc).encode("utf-8")).decode("ascii")
        return httpx.Response(
            200,
            content=b"origin-ok",
            headers={"content-type": "text/plain", "payment-response": encoded},
        )

    buyer, http, wallet = _settings_usd(tmp_path, handler=handler)
    with caplog.at_level(logging.DEBUG, logger="satsgate_mcp"):
        failed = asyncio.run(buyer.pay_and_fetch(URL, payment_signature=SIGNATURE))
    assert failed.payload["ok"] is False
    assert failed.payload["http_status"] == 500
    assert failed.payload["signature_sent"] is True
    assert failed.payload["retry_same_payment_signature"] is True
    assert "not settled" in failed.payload["detail"]
    assert "same PAYMENT-SIGNATURE" in failed.payload["detail"]
    assert failed.payload["body"] == "origin-down"
    assert buyer.store.spent_usd_since(0) == 0
    with caplog.at_level(logging.DEBUG, logger="satsgate_mcp"):
        paid = asyncio.run(buyer.pay_and_fetch(URL, payment_signature=SIGNATURE))
    assert paid.payload["ok"] is True
    assert paid.payload["body"] == "origin-ok"
    assert paid.payload["paid_with"] == "x402"
    assert paid.payload["amount_display"] == "0.01 USDC"
    assert paid.payload["amount_atomic"] == "10000"
    assert paid.payload["payment_response"]["success"] is True
    assert paid.payload["payment_response"]["transaction"] == "0x" + "ab" * 32
    assert SIGNATURE not in json.dumps(paid.payload)
    assert SIGNATURE not in caplog.text
    assert buyer.store.spent_usd_since(0) == 10_000
    signed = [call for call in http.calls if call.headers.get("payment-signature")]
    assert len(signed) == 2
    assert signed[0].headers["payment-signature"] == SIGNATURE
    assert wallet.invoices == []


def test_daily_usd_cap_blocks_the_next_signature(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("payment-signature"):
            return _paid("ok")
        return _x402_response()

    buyer, http, _wallet = _settings_usd(
        tmp_path,
        handler=handler,
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=10_000,
    )
    first = asyncio.run(buyer.pay_and_fetch(URL, payment_signature=SIGNATURE))
    assert first.payload["ok"] is True
    second = asyncio.run(buyer.pay_and_fetch(URL, payment_signature=SIGNATURE))
    assert second.payload["ok"] is False
    assert second.payload["error"] == "over_budget"
    assert second.payload["signature_sent"] is False
    assert "SATSGATE_MCP_DAILY_MAX_USD" in second.payload["detail"]
    assert sum(1 for call in http.calls if call.headers.get("payment-signature")) == 1


def test_malformed_x402_keeps_the_lightning_invoice(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _challenge()
        response.headers["payment-required"] = "not-base64"
        return response

    buyer, _http, wallet = _settings_usd(tmp_path, handler=handler)
    found = asyncio.run(buyer.discover(URL))
    assert found["invoice"] == INVOICE
    assert found["amount_sats"] == 21
    assert found["x402"]["ok"] is False
    assert found["x402"]["error"] == "malformed_x402"
    assert wallet.invoices == []


def test_lightning_only_discover_has_no_x402(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _challenge()

    buyer, _http, _wallet = _buyer(tmp_path, handler)
    found = asyncio.run(buyer.discover(URL))
    assert found["rails"] == ["lightning"]
    assert "x402" not in found
    assert "costs 21 sats" in found["summary"]


def test_list_sites_passes_usd_routes(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "hosted_registry": True,
                "sites": [
                    {
                        "name": "Shop",
                        "slug": "shop",
                        "url": "https://gate.satsgate.org/shop/",
                        "routes": [
                            {"path": "/post", "price_sats": 21, "price_currency": "sats", "max_uses": 1, "access_seconds": None},
                            {
                                "path": "/usdc",
                                "price_currency": "usd",
                                "price_usd_atomic": 10000,
                                "max_uses": 1,
                                "access_seconds": 60,
                            },
                        ],
                    }
                ],
            },
        )

    buyer, _http, _wallet = _buyer(tmp_path, handler, registry="https://directory.example/v1/sites")
    sites = asyncio.run(buyer.list_sites())
    routes = sites["sites"][0]["routes"]
    assert routes[0]["price_sats"] == 21
    assert routes[0]["price_currency"] == "sats"
    assert routes[1]["price_currency"] == "usd"
    assert routes[1]["price_usd_atomic"] == 10000
    assert "price_sats" not in routes[1]


def test_usd_env_parses_atomic_units(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SATSGATE_MCP_MAX_PAYMENT_USD", "0.01")
    monkeypatch.setenv("SATSGATE_MCP_DAILY_MAX_USD", "1")
    loaded = load_settings()
    assert loaded.max_payment_usd_atomic == 10_000
    assert loaded.daily_max_usd_atomic == 1_000_000
    monkeypatch.setenv("SATSGATE_MCP_MAX_PAYMENT_USD", "0.0000001")
    with pytest.raises(ConfigError):
        load_settings()


def test_quote_migration_keeps_existing_rows(tmp_path: Path) -> None:
    path = tmp_path / "satsgate-mcp.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE quotes (
            payment_hash TEXT PRIMARY KEY,
            cache_key TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            macaroon TEXT NOT NULL,
            invoice TEXT NOT NULL,
            resource TEXT,
            amount_sats INTEGER NOT NULL,
            max_uses INTEGER,
            access_seconds INTEGER,
            invoice_expires_at INTEGER,
            reason TEXT,
            request_body BLOB,
            created_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO quotes (
            payment_hash, cache_key, method, url, macaroon, invoice, resource,
            amount_sats, max_uses, access_seconds, invoice_expires_at, reason,
            request_body, created_at
        ) VALUES (?, ?, 'GET', ?, ?, ?, 'route:article', 21, 1, NULL, NULL, NULL, NULL, ?)
        """,
        ("ab" * 32, "GET https://shop.example/a", URL, MAC, INVOICE, NOW),
    )
    conn.commit()
    conn.close()
    store = Store(tmp_path)
    row = store.quote_by_hash("ab" * 32)
    assert row is not None
    assert row["amount_sats"] == 21
    assert row["x402_json"] is None
    assert store.spent_usd_since(0) == 0
    store.close()


def test_multiple_accepts_are_not_payable_until_every_one_is_supported() -> None:
    parsed = parse_offered(_encoded([_accept(), _accept(network="eip155:1", asset=OTHER)]), _body())
    assert parsed is not None

    class _Caps:
        max_payment_usd_atomic = 1_000_000
        daily_max_usd_atomic = 5_000_000

    view = for_agent(parsed, _Caps(), 0)  # type: ignore[arg-type]
    assert view["payable"] is False
    assert len(view["accepts"]) == 2
    assert view["accepts"][0]["supported"] is True
    assert view["accepts"][1]["unsupported_reason"] == "unsupported_network"
