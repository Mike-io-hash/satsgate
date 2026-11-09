"""MCP 0.12.0 follows a hosted-gate receipt to the seller. Offline only."""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest

from satsgate_mcp.buyer import BuyerError
from satsgate_mcp.config import _gate_hosts
from test_satsgate_mcp import INVOICE, MAC, NWC, NOW, PAYMENT, PREIMAGE, _buyer

GATE = "https://gate.satsgate.org/my-shop/blog/post"
SELLER = "https://origin.example/report"
RECEIPT = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJteS1zaG9wIn0.c2ln"
BODY = b'{"item":1}'
SIGNATURE = "c2lnbmF0dXJlLW5vdC1hLXByZWltYWdl"
ALLOW = ("gate.satsgate.org", "origin.example")
_SECRET_MARKS = (PREIMAGE, MAC, NWC, SIGNATURE, "1111111111111111111111111111111111111111111111111111111111111111")


def _payment_required() -> str:
    document = {
        "x402Version": 2,
        "resource": {"url": GATE},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:84532",
                "amount": "10000",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": "0x1111111111111111111111111111111111111111",
                "maxTimeoutSeconds": 60,
            }
        ],
    }
    return base64.b64encode(json.dumps(document).encode()).decode()


def _challenge_body(*, x402: bool, redeem: str = SELLER) -> dict:
    body: dict = {
        "ok": False,
        "error": "payment_required",
        "delivery": "receipt",
        "redeem_url": redeem,
        "seller_host": "origin.example",
        "resource": "gate:my-shop:/blog/post",
        "max_uses": 3,
        "access_seconds": 3600,
    }
    if x402:
        return body
    body.update(
        {
            "amount_sats": 21,
            "payment_hash": PAYMENT,
            "invoice": INVOICE,
            "invoice_expires_at": NOW + 3600,
            "macaroon": MAC,
        }
    )
    return body


def _receipt(*, uses: int = 3, redeem: str = SELLER) -> dict:
    return {
        "ok": True,
        "paid": True,
        "receipt": RECEIPT,
        "redeem_url": redeem,
        "uses": uses,
        "expires_at": NOW + 5000,
        "payment_hash": PAYMENT,
    }


def _forbidden(request: httpx.Request) -> None:
    blob = " ".join(f"{key}:{value}" for key, value in request.headers.items())
    lowered = {key.lower() for key in request.headers}
    assert "authorization" not in lowered
    assert "payment-signature" not in lowered
    assert "x-api-key" not in lowered
    for secret in _SECRET_MARKS:
        assert secret not in blob
        assert secret.encode() not in request.content


def _seller_ok(request: httpx.Request) -> None:
    assert request.method == "POST"
    assert request.url.host == "origin.example"
    assert request.content == BODY
    assert request.headers["satsgate-receipt"] == RECEIPT
    _forbidden(request)


class _World:
    def __init__(
        self,
        *,
        x402: bool = False,
        redeem: str = SELLER,
        gate_host: str = "gate.satsgate.org",
        require_empty_gate_body: bool = True,
        seller_redirect: str | None = None,
        seller_exc: Exception | None = None,
    ) -> None:
        self.x402 = x402
        self.redeem = redeem
        self.gate_host = gate_host
        self.require_empty_gate_body = require_empty_gate_body
        self.seller_redirect = seller_redirect
        self.seller_exc = seller_exc
        self.seller_status = 200
        self.seller_fails_left = 0
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.host == "origin.example":
            if self.seller_exc is not None:
                raise self.seller_exc
            _seller_ok(request)
            if self.seller_redirect is not None:
                return httpx.Response(302, headers={"location": self.seller_redirect})
            if self.seller_fails_left > 0:
                self.seller_fails_left -= 1
                return httpx.Response(503, json={"ok": False, "error": "down"})
            return httpx.Response(self.seller_status, content=b"article", headers={"content-type": "text/plain"})
        assert request.url.host == self.gate_host
        if self.require_empty_gate_body:
            assert request.content == b""
        presented = request.headers.get("authorization", "") or request.headers.get("payment-signature", "")
        paid = bool(presented)
        if not paid and not self.x402:
            header = f'L402 macaroon="{MAC}", invoice="{INVOICE}"'
            return httpx.Response(402, json=_challenge_body(x402=False, redeem=self.redeem), headers={"www-authenticate": header})
        if not paid and self.x402:
            return httpx.Response(
                402,
                json=_challenge_body(x402=True, redeem=self.redeem),
                headers={"payment-required": _payment_required()},
            )
        if self.x402:
            assert request.headers["payment-signature"] == SIGNATURE
            assert "authorization" not in request.headers
        elif ":" in request.headers.get("authorization", ""):
            assert PREIMAGE in request.headers["authorization"]
            assert "payment-signature" not in request.headers
        else:
            assert request.headers["authorization"].startswith("L402 ")
            assert PREIMAGE not in request.headers["authorization"]
        return httpx.Response(200, json=_receipt(redeem=self.redeem))


def _paid_gate_calls(world: _World) -> list[httpx.Request]:
    return [
        call
        for call in world.calls
        if call.url.host == "gate.satsgate.org"
        and ("payment-signature" in call.headers or ":" in call.headers.get("authorization", ""))
    ]


def test_lightning_pay_and_fetch_follows_the_receipt(tmp_path) -> None:
    world = _World()
    buyer, _http, wallet = _buyer(tmp_path, world, nwc_uri=NWC, allowlist=ALLOW)
    paid = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert paid.payload["body"] == "article"
    assert paid.payload["paid_with"] == "lightning"
    assert paid.payload["receipt"] == RECEIPT
    assert paid.payload["redeem_url"] == SELLER
    assert wallet.invoices == [INVOICE]
    sellers = [call for call in world.calls if call.url.host == "origin.example"]
    assert len(sellers) == 1
    assert len(_paid_gate_calls(world)) == 1
    assert paid.payload["uses_remaining"] == 2


def test_x402_pay_and_fetch_follows_the_receipt(tmp_path) -> None:
    world = _World(x402=True)
    buyer, _http, wallet = _buyer(
        tmp_path,
        world,
        allowlist=ALLOW,
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=1_000_000,
    )
    offered = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert offered.payload["action"] == "pay_x402_external"
    assert wallet.invoices == []
    assert not any(call.url.host == "origin.example" for call in world.calls)
    paid = asyncio.run(
        buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode(), payment_signature=SIGNATURE)
    )
    assert paid.payload["body"] == "article"
    assert paid.payload["paid_with"] == "x402"
    assert paid.payload["receipt"] == RECEIPT
    sellers = [call for call in world.calls if call.url.host == "origin.example"]
    assert len(sellers) == 1
    assert _seller_ok(sellers[0]) is None
    assert len(_paid_gate_calls(world)) == 1


def test_disallowed_or_invalid_seller_is_rejected_before_payment(tmp_path) -> None:
    blocked = _World()
    buyer, _http, wallet = _buyer(tmp_path / "blocked", blocked, nwc_uri=NWC, allowlist=("gate.satsgate.org",))
    with pytest.raises(BuyerError) as denied:
        asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert denied.value.code == "redeem_host_not_allowed"
    assert wallet.invoices == []
    assert _paid_gate_calls(blocked) == []
    assert not any(call.url.host == "origin.example" for call in blocked.calls)

    invalid = _World(redeem="https://user:pass@origin.example/report")
    buyer, _http, wallet = _buyer(tmp_path / "invalid", invalid, nwc_uri=NWC, allowlist=ALLOW)
    with pytest.raises(BuyerError) as bad:
        asyncio.run(buyer.pay_and_fetch(GATE, "human"))
    assert bad.value.code == "redeem_host_not_allowed"
    assert wallet.invoices == []
    assert _paid_gate_calls(invalid) == []


def test_seller_outage_retries_the_same_receipt_without_a_second_payment(tmp_path) -> None:
    world = _World()
    world.seller_fails_left = 3
    buyer, _http, wallet = _buyer(tmp_path, world, nwc_uri=NWC, allowlist=ALLOW)
    failed = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert failed.payload["error"] == "seller_unavailable"
    assert failed.payload["receipt"] == RECEIPT
    assert wallet.invoices == [INVOICE]
    assert len(_paid_gate_calls(world)) == 1
    assert sum(1 for call in world.calls if call.url.host == "origin.example") == 3
    again = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert again.payload["body"] == "article"
    assert wallet.invoices == [INVOICE]
    assert len(_paid_gate_calls(world)) == 1
    sellers = [call for call in world.calls if call.url.host == "origin.example"]
    assert len(sellers) == 4
    assert all(call.headers["satsgate-receipt"] == RECEIPT for call in sellers)


def test_receipt_is_reused_until_it_expires(tmp_path) -> None:
    world = _World()
    buyer, _http, wallet = _buyer(tmp_path, world, nwc_uri=NWC, allowlist=ALLOW)
    first = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert first.payload["uses_remaining"] == 2
    second = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert second.payload["body"] == "article"
    assert second.payload["uses_remaining"] == 1
    assert wallet.invoices == [INVOICE]
    assert len(_paid_gate_calls(world)) == 1
    assert sum(1 for call in world.calls if call.url.host == "origin.example") == 2
    buyer._now.now = NOW + 5001
    third = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert third.payload["body"] == "article"
    assert wallet.invoices == [INVOICE, INVOICE]
    assert len(_paid_gate_calls(world)) == 2


def test_human_qr_flow_follows_the_receipt_on_check_payment(tmp_path) -> None:
    world = _World()
    buyer, _http, wallet = _buyer(tmp_path, world, allowlist=ALLOW)
    offer = asyncio.run(buyer.pay_and_fetch(GATE, "human", method="POST", body=BODY.decode()))
    assert offer.payload["action"] == "pay_invoice"
    assert offer.payload["delivery"] == "receipt"
    assert offer.payload["redeem_url"] == SELLER
    assert offer.qr_png is not None and offer.qr_png.startswith(b"\x89PNG")
    assert offer.payload["qr_text"]
    assert MAC not in json.dumps(offer.payload)
    assert wallet.invoices == []
    assert not any(call.url.host == "origin.example" for call in world.calls)
    fetched = asyncio.run(buyer.check_payment(PAYMENT))
    assert fetched.payload["body"] == "article"
    assert fetched.payload["receipt"] == RECEIPT
    sellers = [call for call in world.calls if call.url.host == "origin.example"]
    assert len(sellers) == 1
    assert sellers[0].method == "POST"
    assert sellers[0].content == BODY
    _forbidden(sellers[0])
    gate_polls = [
        call
        for call in world.calls
        if call.url.host == "gate.satsgate.org" and call.headers.get("authorization", "").startswith("L402 ")
    ]
    assert len(gate_polls) == 1
    assert ":" not in gate_polls[0].headers["authorization"].split(" ", 1)[1]


def test_gate_hosts_honors_only_the_configured_hosts(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SATSGATE_MCP_GATE_HOSTS", raising=False)
    assert _gate_hosts() == ("gate.satsgate.org",)
    monkeypatch.setenv("SATSGATE_MCP_GATE_HOSTS", "pay.example, Gate.Example")
    assert _gate_hosts() == ("pay.example", "gate.example")
    monkeypatch.setenv("SATSGATE_MCP_GATE_HOSTS", " , ")
    assert _gate_hosts() == ("gate.satsgate.org",)

    default = _World(x402=True)
    buyer, _http, _wallet = _buyer(
        tmp_path / "default",
        default,
        allowlist=ALLOW,
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=1_000_000,
    )
    paid = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode(), payment_signature=SIGNATURE))
    assert paid.payload["body"] == "article"
    assert paid.payload["paid_with"] == "x402"
    assert any(call.url.host == "origin.example" for call in default.calls)
    assert len(_paid_gate_calls(default)) == 1

    foreign = _World(x402=True, require_empty_gate_body=False)
    buyer, _http, _wallet = _buyer(
        tmp_path / "foreign",
        foreign,
        allowlist=ALLOW,
        gate_hosts=("pay.example",),
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=1_000_000,
    )
    ignored = asyncio.run(
        buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode(), payment_signature=SIGNATURE)
    )
    assert ignored.payload.get("paid_with") == "x402"
    assert ignored.payload.get("receipt") != RECEIPT
    assert not any(call.url.host == "origin.example" for call in foreign.calls)
    assert len(_paid_gate_calls(foreign)) == 1

    custom_url = "https://pay.example/my-shop/blog/post"
    custom = _World(x402=True, gate_host="pay.example")
    buyer, _http, _wallet = _buyer(
        tmp_path / "custom",
        custom,
        allowlist=("pay.example", "origin.example"),
        gate_hosts=("pay.example",),
        max_payment_usd_atomic=1_000_000,
        daily_max_usd_atomic=1_000_000,
    )
    honored = asyncio.run(
        buyer.pay_and_fetch(custom_url, "nwc", method="POST", body=BODY.decode(), payment_signature=SIGNATURE)
    )
    assert honored.payload["body"] == "article"
    assert honored.payload["receipt"] == RECEIPT
    assert honored.payload["redeem_url"] == SELLER
    sellers = [call for call in custom.calls if call.url.host == "origin.example"]
    assert len(sellers) == 1
    assert len([call for call in custom.calls if call.url.host == "pay.example" and "payment-signature" in call.headers]) == 1


def test_seller_redirect_on_redeem_is_not_followed(tmp_path) -> None:
    world = _World(seller_redirect="https://evil.example/taken")
    buyer, _http, wallet = _buyer(tmp_path, world, nwc_uri=NWC, allowlist=ALLOW)
    failed = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert failed.payload["error"] == "redirect_not_followed"
    assert failed.payload["receipt"] == RECEIPT
    assert failed.payload["redeem_url"] == SELLER
    assert wallet.invoices == [INVOICE]
    assert len(_paid_gate_calls(world)) == 1
    sellers = [call for call in world.calls if call.url.host == "origin.example"]
    assert len(sellers) == 1
    assert not any(call.url.host == "evil.example" for call in world.calls)
    again = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert again.payload["error"] == "redirect_not_followed"
    assert again.payload["receipt"] == RECEIPT
    assert wallet.invoices == [INVOICE]
    assert len(_paid_gate_calls(world)) == 1
    assert not any(call.url.host == "evil.example" for call in world.calls)


def test_seller_connect_error_keeps_the_receipt(tmp_path) -> None:
    world = _World(seller_exc=httpx.ConnectError("connection refused"))
    buyer, _http, wallet = _buyer(tmp_path, world, nwc_uri=NWC, allowlist=ALLOW)
    failed = asyncio.run(buyer.pay_and_fetch(GATE, "nwc", method="POST", body=BODY.decode()))
    assert failed.payload["error"] == "seller_unavailable"
    assert "connection_failed" in failed.payload["detail"]
    assert failed.payload["receipt"] == RECEIPT
    assert failed.payload["redeem_url"] == SELLER
    assert wallet.invoices == [INVOICE]
    assert len(_paid_gate_calls(world)) == 1
    assert sum(1 for call in world.calls if call.url.host == "origin.example") == 3
