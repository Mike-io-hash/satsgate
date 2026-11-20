"""In-band price notices for MCP routes."""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from satsgate_proxy.config import ConfigError
from test_proxy_mcp import (
    _TOOLS,
    _auth,
    _client,
    _config,
    _mcp_settings,
    _post,
    _reply,
    _result,
    _rpc,
    _rpc_error_body,
    _settings,
    McpWorld,
)
from test_satsgate_proxy import KEY, PAYMENT, SECRET

ROOT = Path(__file__).resolve().parents[1]

_LIGHTNING_HINT = (
    "Pay the Lightning invoice, then repeat this tools/call with the HTTP header "
    "Authorization: L402 <macaroon>:<preimage>. If the wallet does not return a preimage, "
    "send Authorization: L402 <macaroon> and this proxy will poll until the invoice settles."
)
_X402_HINT = (
    'To pay with x402, repeat this tools/call with the payment payload in params._meta["x402/payment"] '
    "or in the PAYMENT-SIGNATURE header."
)
_PENDING_HINT = "The invoice is not settled yet. Retry the same Authorization header. Do not pay a new invoice."
_SIGNAL_ERROR = "route tools mcp signal must be in_band or http_402"
_ORIGIN_OK = b'{"jsonrpc":"2.0","id":1,"result":{}}'
_MARKER = "marker-origin-output"

_DOCUMENT = {
    "x402Version": 2,
    "resource": {
        "url": "https://pay.example/mcp",
        "description": "Priced tool access",
        "mimeType": "application/json",
    },
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x0000000000000000000000000000000000000001",
            "payTo": "0x0000000000000000000000000000000000000002",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }
    ],
}
_SUMMARY = {
    "scheme": "exact",
    "network": "eip155:84532",
    "asset": "0x0000000000000000000000000000000000000001",
    "amount": "10000",
    "payTo": "0x0000000000000000000000000000000000000002",
    "testing": True,
    "x402_mode": "test",
}
_REQUIRED = base64.standard_b64encode(
    json.dumps(_DOCUMENT, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
).decode("ascii")
_SETTLEMENT = {
    "success": True,
    "transaction": "0xabc",
    "tx": "0xabc",
    "network": "eip155:84532",
    "payer": "0x0000000000000000000000000000000000000002",
}
_SETTLEMENT_B64 = base64.standard_b64encode(
    json.dumps(_SETTLEMENT, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
).decode("ascii")
_UNREADABLE_SETTLEMENT = "c2V0dGxlZA"
_IN_BAND = _TOOLS.replace("    signal: http_402\n", "")
_LIGHTNING = _IN_BAND.replace("  x402: true\n", "")
_REPORT = (
    "- name: report\n"
    "  path: /api/report\n"
    "  methods: [GET]\n"
    "  price_sats: 21\n"
    "  access: per_request\n"
    "  scope: route\n"
)


class OfferWorld(McpWorld):
    """Stub core with a real base64 PaymentRequired document."""

    def __init__(self) -> None:
        super().__init__()
        self.payment_required = _REQUIRED
        self.summary = dict(_SUMMARY)
        self.unreadable = False
        self.blank_lightning = False
        self.challenge_status: int | None = None
        self.verify_status: int | None = None
        self.settle_status: int | None = None
        self.charge_status: int | None = None
        self.settlement: str | None = None
        self.order: list[str] = []

    def _challenge(self, snap: dict) -> httpx.Response:
        if self.challenge_status == 429:
            return httpx.Response(
                429,
                json={"ok": False, "error": "buyer_rate_limited", "retry_after_seconds": 5},
                headers={"retry-after": "5"},
            )
        if self.challenge_status == 500:
            return httpx.Response(500, json={"ok": False, "error": "db_error"})
        response = super()._challenge(snap)
        if response.status_code != 200:
            return response
        payload = response.json()
        if "x402" in payload:
            payload["payment_required"] = "dGVzdA" if self.unreadable else self.payment_required
            payload["x402"] = dict(self.summary)
        if self.blank_lightning:
            payload["macaroon"] = ""
            payload["invoice"] = ""
            payload.pop("www_authenticate", None)
        return httpx.Response(response.status_code, json=payload)

    def _unlock(self, snap: dict) -> httpx.Response:
        if self.unlock == "limited":
            return httpx.Response(
                429,
                json={"ok": False, "error": "buyer_rate_limited", "retry_after_seconds": 5},
                headers={"retry-after": "5"},
            )
        if self.unlock == "pending":
            return httpx.Response(
                402,
                json={
                    "ok": False,
                    "error": "payment_pending",
                    "status": "pending",
                    "payment_hash": PAYMENT,
                    "retry_after_seconds": 3,
                },
                headers={"retry-after": "3"},
            )
        return super()._unlock(snap)

    def _core(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/x402/verify"):
            self.order.append("verify")
        elif path.endswith("/x402/settle"):
            self.order.append("settle")
        elif path.endswith("/challenge"):
            self.order.append("challenge")
        elif path.endswith("/charge"):
            self.order.append("charge")
        elif path.endswith("/verify"):
            self.order.append("unlock")
        if path.endswith("/charge") and self.charge_status is not None:
            self.core_calls.append(self._snap(request))
            return httpx.Response(self.charge_status, json={"ok": False, "error": "db_error"})
        if path.endswith("/x402/verify") and self.verify_status is not None:
            self.core_calls.append(self._snap(request))
            return httpx.Response(
                self.verify_status,
                json={"ok": False, "error": "payment_rejected", "reason": "expired"},
            )
        if path.endswith("/x402/settle") and self.settle_status is not None:
            self.core_calls.append(self._snap(request))
            return httpx.Response(
                self.settle_status,
                json={"ok": False, "error": "already_settled", "reason": "duplicate"},
            )
        if path.endswith("/x402/settle") and self.settlement is not None:
            self.core_calls.append(self._snap(request))
            return httpx.Response(
                200,
                json={"ok": True, "payment_response": self.settlement},
                headers={"payment-response": self.settlement},
            )
        return super()._core(request)

    def _upstream(self, request: httpx.Request) -> httpx.Response:
        self.order.append("origin")
        if self.upstream == "timeout":
            self.up_calls.append(self._snap(request))
            raise httpx.ReadTimeout("timed out")
        return super()._upstream(request)


def _tools_call(name: str = "quote", ident: object = 7) -> bytes:
    return _rpc("tools/call", {"name": name}, ident=ident)


def _challenges(world: OfferWorld) -> list[dict]:
    return [call for call in world.core_calls if call["path"].endswith("/challenge")]


def _assert_one_challenge(world: OfferWorld, tool: str) -> None:
    found = _challenges(world)
    assert len(found) == 1
    assert found[0]["body"]["resource"] == f"route:tools:{tool}"
    assert world.up_calls == []


def _structured(response, ident: object, *, retry_after: str | None = None) -> dict:
    assert response.status_code == 200
    assert response.headers["content-type"].split(";", 1)[0] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    assert "www-authenticate" not in response.headers
    assert "payment-required" not in response.headers
    if retry_after is None:
        assert "retry-after" not in response.headers
    else:
        assert response.headers["retry-after"] == retry_after
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == ident
    assert type(body["id"]) is type(ident)
    result = body["result"]
    assert list(result) == ["content", "structuredContent", "isError", "resultType"]
    assert result["isError"] is True
    assert result["resultType"] == "complete"
    content = result["content"]
    assert content == [
        {
            "type": "text",
            "text": json.dumps(result["structuredContent"], separators=(",", ":"), ensure_ascii=False),
        }
    ]
    assert json.loads(content[0]["text"]) == result["structuredContent"]
    return result["structuredContent"]


def _quote_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, world: OfferWorld, routes: str, ident: object = 7):
    settings = _mcp_settings(tmp_path, monkeypatch, routes)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(ident=ident))
    return response


def test_ib_1_1_omitted_signal_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = _settings(tmp_path, monkeypatch, _IN_BAND)
    assert loaded.routes[0].mcp is not None
    assert loaded.routes[0].mcp.signal == "in_band"


def test_ib_1_2_explicit_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    routes = _TOOLS.replace("signal: http_402", "signal: in_band")
    loaded = _settings(tmp_path, monkeypatch, routes)
    assert loaded.routes[0].mcp is not None
    assert loaded.routes[0].mcp.signal == "in_band"


def test_ib_1_3_explicit_http_402(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = _settings(tmp_path, monkeypatch, _TOOLS)
    assert loaded.routes[0].mcp is not None
    assert loaded.routes[0].mcp.signal == "http_402"


@pytest.mark.parametrize(
    "signal_yaml",
    [
        "    signal:\n",
        "    signal: IN_BAND\n",
        "    signal: Http_402\n",
        "    signal: inband\n",
        "    signal: 402\n",
        "    signal: true\n",
    ],
)
def test_ib_1_4_invalid_signal_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signal_yaml: str) -> None:
    routes = _TOOLS.replace("    signal: http_402\n", signal_yaml)
    with pytest.raises(ConfigError) as caught:
        _settings(tmp_path, monkeypatch, routes)
    assert str(caught.value) == _SIGNAL_ERROR


def test_ib_1_5_bad_signal_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "proxy.yaml"
    path.write_text(_config(_TOOLS.replace("signal: http_402", "signal: inband")), encoding="utf-8")
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
    assert completed.stderr.strip() == f"satsgate-proxy: {_SIGNAL_ERROR}"


def test_ib_2_1_unpaid_quote_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND, 7)
    structured = _structured(response, 7)
    assert structured["error"] == "payment_required"
    assert structured["tool"] == "quote"
    _assert_one_challenge(world, "quote")


def test_ib_2_2_string_request_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND, "call-1")
    structured = _structured(response, "call-1")
    assert structured["error"] == "payment_required"
    assert structured["tool"] == "quote"
    _assert_one_challenge(world, "quote")


def test_ib_2_3_text_matches_structured_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    content = response.json()["result"]["content"]
    assert len(content) == 1
    assert content[0]["type"] == "text"
    assert json.loads(content[0]["text"]) == structured
    _assert_one_challenge(world, "quote")


def test_ib_2_4_x402_document_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    decoded = json.loads(base64.b64decode(world.payment_required, validate=True))
    assert structured["x402Version"] == decoded["x402Version"]
    assert structured["resource"] == decoded["resource"]
    assert structured["accepts"] == decoded["accepts"]
    assert structured["error"] == "payment_required"
    assert structured["tool"] == "quote"
    _assert_one_challenge(world, "quote")


def test_ib_2_5_lightning_block_is_nested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    lightning = structured["lightning"]
    assert list(lightning) == [
        "amount_sats",
        "invoice",
        "invoice_expires_at",
        "macaroon",
        "payment_hash",
        "resource",
        "max_uses",
        "access_seconds",
    ]
    assert lightning["amount_sats"] == 21
    assert lightning["invoice"] == "lnbc1testinvoice"
    assert lightning["invoice_expires_at"] == 1893456000
    assert lightning["macaroon"] == "bWFjYXJvb24"
    assert lightning["payment_hash"] == f"{1:064x}"
    assert lightning["resource"] == "route:tools:quote"
    assert lightning["max_uses"] == 1
    assert lightning["access_seconds"] is None
    assert "invoice" not in structured
    assert "macaroon" not in structured
    assert "payment_hash" not in structured
    assert "amount_sats" not in structured
    _assert_one_challenge(world, "quote")


def test_ib_2_6_x402_summary_and_labels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    assert structured["x402"] == world.summary
    assert structured["testing"] == world.summary["testing"]
    assert structured["x402_mode"] == world.summary["x402_mode"]
    _assert_one_challenge(world, "quote")


def test_ib_2_7_hint_joins_both_offers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    assert structured["hint"] == f"{_LIGHTNING_HINT} {_X402_HINT}"
    _assert_one_challenge(world, "quote")


def test_ib_2_8_lightning_only_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    response = _quote_notice(tmp_path, monkeypatch, world, _LIGHTNING)
    structured = _structured(response, 7)
    assert list(structured) == ["error", "tool", "lightning", "hint"]
    assert structured["error"] == "payment_required"
    assert structured["tool"] == "quote"
    assert structured["hint"] == _LIGHTNING_HINT
    assert structured["lightning"]["resource"] == "route:tools:quote"
    _assert_one_challenge(world, "quote")


def test_ib_2_9_unreadable_document_drops_x402(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    world = OfferWorld()
    world.unreadable = True
    caplog.set_level(logging.WARNING, logger="satsgate_proxy")
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    assert "x402Version" not in structured
    assert "accepts" not in structured
    assert "x402" not in structured
    assert "testing" not in structured
    assert "x402_mode" not in structured
    assert structured["hint"] == _LIGHTNING_HINT
    assert structured["error"] == "payment_required"
    assert structured["tool"] == "quote"
    assert [record.getMessage() for record in caplog.records if record.name == "satsgate_proxy"] == [
        "core challenge x402 document was not readable"
    ]
    _assert_one_challenge(world, "quote")


def test_ib_2_10_unreadable_document_without_lightning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    world = OfferWorld()
    world.unreadable = True
    world.blank_lightning = True
    caplog.set_level(logging.WARNING, logger="satsgate_proxy")
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    assert structured == {"error": "paywall_unavailable", "tool": "quote"}
    assert [record.getMessage() for record in caplog.records if record.name == "satsgate_proxy"] == [
        "core challenge x402 document was not readable"
    ]
    _assert_one_challenge(world, "quote")


def test_ib_2_11_fresh_notice_keeps_the_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.unlock = "used_up"
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), _auth("route:tools:quote"))
    structured = _structured(response, 7)
    assert structured["reason"] == "token_used_up"
    assert structured["error"] == "payment_required"
    assert structured["tool"] == "quote"
    assert [call["path"] for call in world.core_calls] == ["/v1/paywall/verify", "/v1/paywall/challenge"]
    assert len(_challenges(world)) == 1
    assert _challenges(world)[0]["body"]["resource"] == "route:tools:quote"
    assert world.up_calls == []


def test_ib_2_12_each_tool_has_its_own_resource(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call("deep_search"))
    structured = _structured(response, 7)
    assert structured["tool"] == "deep_search"
    assert structured["lightning"]["resource"] == "route:tools:deep_search"
    assert structured["lightning"]["max_uses"] == 10
    assert structured["lightning"]["amount_sats"] == 100
    _assert_one_challenge(world, "deep_search")


def test_ib_2_13_each_notice_mints_one_challenge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        first = _post(client, _tools_call(ident=7))
        second = _post(client, _tools_call(ident=8))
    assert first.status_code == 200
    assert first.json()["result"]["isError"] is True
    assert second.status_code == 200
    assert second.json()["result"]["isError"] is True
    assert len(_challenges(world)) == 2
    assert [call["body"]["resource"] for call in _challenges(world)] == ["route:tools:quote", "route:tools:quote"]
    assert world.up_calls == []


def test_ib_2_14_free_messages_keep_the_origin_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    bodies = [
        _rpc("initialize", ident=1),
        _rpc("tools/list", ident=1),
        _rpc("tools/call", {"name": "echo", "arguments": {"text": "hi"}}, ident=1),
        _rpc("tools/call", {"name": "other_tool", "arguments": {}}, ident=1),
    ]
    with _client(settings, world) as client:
        responses = [_post(client, body) for body in bodies]
    assert world.core_calls == []
    assert len(world.up_calls) == 4
    for body, response, call in zip(bodies, responses, world.up_calls, strict=True):
        assert call["raw"] == body
        assert response.status_code == 200
        assert response.content == _ORIGIN_OK


def test_ib_2_15_validation_errors_stay_http_400(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        mismatch = _post(client, _tools_call(), {"Mcp-Name": "echo"})
        lookalike = _post(client, _rpc("tools/call", {"name": "Quote"}, ident=7))
    assert mismatch.status_code == 400
    assert mismatch.json()["jsonrpc"] == "2.0"
    assert mismatch.json()["error"]["data"]["error"] == "header_mismatch"
    assert lookalike.status_code == 400
    assert lookalike.json()["jsonrpc"] == "2.0"
    assert lookalike.json()["error"]["data"]["error"] == "invalid_tool_name"
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_2_16_oversize_body_stays_413(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND, prelude="limits:\n  max_request_bytes: 1024\n")
    world = OfferWorld()
    with _client(settings, world) as client:
        huge = client.post("/mcp", content=b"x" * 2000)
    assert huge.status_code == 413
    assert huge.json() == {"ok": False, "error": "request_too_large"}
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_2_17_classic_route_stays_http_402(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _REPORT + _IN_BAND)
    with _client(settings, world) as client:
        response = client.get("/api/report")
    assert response.status_code == 402
    assert response.headers["www-authenticate"].startswith('L402 macaroon="')
    body = response.json()
    assert body["ok"] is False
    assert body["error"] == "payment_required"
    assert world.up_calls == []


def test_ib_2_18_http_402_route_keeps_the_classic_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _TOOLS)
    with _client(settings, world) as client:
        response = _post(client, _tools_call())
    assert response.status_code == 402
    assert response.headers["www-authenticate"].startswith('L402 macaroon="')
    assert response.headers["payment-required"] == world.payment_required
    body = response.json()
    assert body["ok"] is False
    assert body["error"] == "payment_required"
    assert body["macaroon"] == "bWFjYXJvb24"
    assert body["invoice"] == "lnbc1testinvoice"
    assert body["x402"] == world.summary
    assert world.up_calls == []


def test_ib_3_1_pending_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.unlock = "pending"
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), _auth("route:tools:quote"))
    structured = _structured(response, 7, retry_after="3")
    assert structured == {
        "error": "payment_pending",
        "tool": "quote",
        "retry_after_seconds": 3,
        "hint": _PENDING_HINT,
        "payment_hash": PAYMENT,
    }
    assert world.up_calls == []


def test_ib_3_2_challenge_rate_limit_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.challenge_status = 429
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7, retry_after="5")
    assert structured == {"error": "buyer_rate_limited", "tool": "quote", "retry_after_seconds": 5}
    assert world.up_calls == []


def test_ib_3_3_unlock_rate_limit_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.unlock = "limited"
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), _auth("route:tools:quote"))
    structured = _structured(response, 7, retry_after="5")
    assert structured == {"error": "buyer_rate_limited", "tool": "quote", "retry_after_seconds": 5}
    assert world.up_calls == []


def test_ib_3_4_rail_conflict_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    headers = dict(_auth("route:tools:quote"))
    headers["PAYMENT-SIGNATURE"] = "sig-test"
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), headers)
    structured = _structured(response, 7)
    assert structured == {"error": "one_rail_only", "tool": "quote"}
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_3_5_bad_header_signature_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), {"PAYMENT-SIGNATURE": "a" * 8193})
    structured = _structured(response, 7)
    assert structured == {"error": "bad_signature", "tool": "quote"}
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_3_6_verify_rejection_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.verify_status = 402
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), {"PAYMENT-SIGNATURE": "sig-test"})
    structured = _structured(response, 7)
    assert structured == {"error": "payment_rejected", "tool": "quote", "reason": "expired"}
    assert world.up_calls == []
    assert sum(call["path"].endswith("/x402/settle") for call in world.core_calls) == 0
    assert sum(call["path"].endswith("/x402/verify") for call in world.core_calls) == 1


def test_ib_3_7_settle_rejection_hides_the_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.settle_status = 409
    payload = _result({"content": [{"type": "text", "text": _MARKER}]}, ident=7)
    world.queue.append(_reply(200, payload, "application/json"))
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), {"PAYMENT-SIGNATURE": "sig-test"})
    structured = _structured(response, 7)
    assert structured == {"error": "already_settled", "tool": "quote", "reason": "duplicate"}
    assert len(world.up_calls) == 1
    assert _MARKER.encode() not in response.content


def test_ib_3_8_challenge_unavailable_is_in_band(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.challenge_status = 500
    response = _quote_notice(tmp_path, monkeypatch, world, _IN_BAND)
    structured = _structured(response, 7)
    assert structured == {"error": "paywall_unavailable", "tool": "quote"}
    assert world.up_calls == []


def test_ib_3_9_charge_unavailable_hides_the_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    world.charge_status = 500
    payload = _result({"content": [{"type": "text", "text": _MARKER}]}, ident=7)
    world.queue.append(_reply(200, payload, "application/json"))
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), _auth("route:tools:quote"))
    structured = _structured(response, 7)
    assert structured == {"error": "paywall_unavailable", "tool": "quote"}
    assert len(world.up_calls) == 1
    assert _MARKER.encode() not in response.content


@pytest.mark.parametrize("shape", ["tool_error", "rpc_error", "origin_500", "timeout"])
def test_ib_3_10_origin_answers_stay_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    raw = _tools_call()
    header = _auth("route:tools:quote")
    if shape == "timeout":
        world.upstream = "timeout"
        with _client(settings, world) as client:
            response = _post(client, raw, header)
        assert response.status_code == 504
        assert response.json() == {"ok": False, "error": "upstream_timeout", "use_spent": False}
    elif shape == "origin_500":
        world.queue.append(_reply(500, b"origin-down", "text/plain"))
        with _client(settings, world) as client:
            response = _post(client, raw, header)
        assert response.status_code == 500
        assert response.content == b"origin-down"
    elif shape == "tool_error":
        payload = _result({"isError": True, "content": [{"type": "text", "text": "no"}]}, ident=7)
        world.queue.append(_reply(200, payload, "application/json"))
        with _client(settings, world) as client:
            response = _post(client, raw, header)
        assert response.status_code == 200
        assert response.content == payload
    else:
        payload = _rpc_error_body({"code": -32000, "message": "failed"}, ident=7)
        world.queue.append(_reply(200, payload, "application/json"))
        with _client(settings, world) as client:
            response = _post(client, raw, header)
        assert response.status_code == 200
        assert response.content == payload
    assert sum(call["path"].endswith("/charge") for call in world.core_calls) == 0
    assert sum(call["path"].endswith("/x402/settle") for call in world.core_calls) == 0


def test_ib_3_11_lightning_success_returns_origin_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    payload = _result({"content": [{"type": "text", "text": "priced"}]}, ident=7)
    world.queue.append(_reply(200, payload, "application/json"))
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), _auth("route:tools:quote"))
    assert response.status_code == 200
    assert response.content == payload
    assert sum(call["path"].endswith("/charge") for call in world.core_calls) == 1


def test_ib_3_12_header_x402_success_returns_origin_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    payload = _result({"content": [{"type": "text", "text": "priced"}]}, ident=7)
    world.queue.append(_reply(200, payload, "application/json"))
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), {"PAYMENT-SIGNATURE": "sig-test"})
    assert response.status_code == 200
    assert response.content == payload
    assert "x402/payment-response" not in response.text
    assert response.headers["payment-response"] == "c2V0dGxlZA"
    assert sum(call["path"].endswith("/x402/settle") for call in world.core_calls) == 1


@pytest.mark.parametrize(
    "situation",
    [
        "pending",
        "challenge_limit",
        "unlock_limit",
        "conflict",
        "bad_signature",
        "verify",
        "settle",
        "challenge_down",
        "charge_down",
    ],
)
def test_ib_3_13_http_402_route_keeps_classic_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, situation: str
) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _TOOLS)
    headers: dict[str, str] | None = None
    retry_after: str | None = None
    if situation == "pending":
        world.unlock = "pending"
        headers = _auth("route:tools:quote")
        status = 402
        expected = {
            "ok": False,
            "error": "payment_pending",
            "retry_after_seconds": 3,
            "hint": _PENDING_HINT,
            "payment_hash": PAYMENT,
        }
        retry_after = "3"
    elif situation == "challenge_limit":
        world.challenge_status = 429
        status = 429
        expected = {"ok": False, "error": "buyer_rate_limited", "retry_after_seconds": 5}
        retry_after = "5"
    elif situation == "unlock_limit":
        world.unlock = "limited"
        headers = _auth("route:tools:quote")
        status = 429
        expected = {"ok": False, "error": "buyer_rate_limited", "retry_after_seconds": 5}
        retry_after = "5"
    elif situation == "conflict":
        headers = dict(_auth("route:tools:quote"))
        headers["PAYMENT-SIGNATURE"] = "sig-test"
        status = 400
        expected = {"ok": False, "error": "one_rail_only"}
    elif situation == "bad_signature":
        headers = {"PAYMENT-SIGNATURE": "a" * 8193}
        status = 400
        expected = {"ok": False, "error": "bad_signature"}
    elif situation == "verify":
        world.verify_status = 402
        headers = {"PAYMENT-SIGNATURE": "sig-test"}
        status = 402
        expected = {"ok": False, "error": "payment_rejected", "reason": "expired"}
    elif situation == "settle":
        world.settle_status = 409
        served = _result({"content": [{"type": "text", "text": "ok"}]}, ident=7)
        world.queue.append(_reply(200, served, "application/json"))
        headers = {"PAYMENT-SIGNATURE": "sig-test"}
        status = 409
        expected = {"ok": False, "error": "already_settled", "reason": "duplicate"}
    elif situation == "challenge_down":
        world.challenge_status = 500
        status = 502
        expected = {"ok": False, "error": "paywall_unavailable"}
    else:
        world.charge_status = 500
        served = _result({"content": [{"type": "text", "text": _MARKER}]}, ident=7)
        world.queue.append(_reply(200, served, "application/json"))
        headers = _auth("route:tools:quote")
        status = 502
        expected = {"ok": False, "error": "paywall_unavailable"}
    with _client(settings, world) as client:
        response = _post(client, _tools_call(), headers)
    assert response.status_code == status
    assert response.json() == expected
    if retry_after is None:
        assert "retry-after" not in response.headers
    else:
        assert response.headers["retry-after"] == retry_after


def _signature(payment: dict) -> str:
    raw = json.dumps(payment, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.standard_b64encode(raw).decode("ascii")


def _call_with_meta(
    payment: object,
    *,
    name: str = "quote",
    ident: object = 7,
    arguments: dict | None = None,
    meta_before: dict | None = None,
) -> bytes:
    meta: dict[str, object] = {}
    if meta_before:
        meta.update(meta_before)
    meta["x402/payment"] = payment
    params: dict[str, object] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    params["_meta"] = meta
    return _rpc("tools/call", params, ident=ident)


def _deliver(world: OfferWorld, result: dict | None = None, *, ident: object = 7, content_type: str = "application/json", body: bytes | None = None) -> bytes:
    if body is None:
        payload = {"content": [{"type": "text", "text": "ok"}]}
        if result:
            payload.update(result)
        body = _result(payload, ident=ident)
    world.queue.append(_reply(200, body, content_type))
    return body


def _meta_world() -> OfferWorld:
    world = OfferWorld()
    world.settlement = _SETTLEMENT_B64
    return world


def _payment_of_length(target: int) -> dict:
    for pad in range(6000, 6200):
        payment = {"note": "a" * pad}
        if len(_signature(payment)) == target:
            return payment
    raise AssertionError(f"no payload encodes to {target}")


def test_ib_4_1_meta_payment_uses_compact_encoding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payment = {"scheme": "exact", "note": "\u00a5"}
    encoded = _signature(payment)
    world = _meta_world()
    _deliver(world)
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        _post(client, _call_with_meta(payment))
    verify = [call for call in world.core_calls if call["path"].endswith("/x402/verify")]
    settle = [call for call in world.core_calls if call["path"].endswith("/x402/settle")]
    assert len(verify) == 1
    assert len(settle) == 1
    assert verify[0]["body"]["payment_signature"] == encoded
    assert settle[0]["body"]["payment_signature"] == encoded


def test_ib_4_2_meta_rail_matches_the_header_rail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payment = {"scheme": "exact", "note": "\u00a5"}
    encoded = _signature(payment)
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    meta = _meta_world()
    header = _meta_world()
    _deliver(meta)
    _deliver(header)
    with _client(settings, meta) as client:
        _post(client, _call_with_meta(payment))
    with _client(settings, header) as client:
        _post(client, _tools_call(), {"PAYMENT-SIGNATURE": encoded})
    meta_calls = [(call["path"], call["body"]) for call in meta.core_calls]
    header_calls = [(call["path"], call["body"]) for call in header.core_calls]
    assert meta_calls == header_calls
    assert len(meta_calls) == 2


def test_ib_4_3_meta_success_injects_the_settlement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    origin = _deliver(world)
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.status_code == 200
    assert response.headers["content-type"].split(";", 1)[0] == "application/json"
    assert response.headers["payment-response"] == world.settlement
    body = response.json()
    assert body["result"]["_meta"]["x402/payment-response"] == _SETTLEMENT
    rest = {key: value for key, value in body["result"].items() if key != "_meta"}
    assert rest == json.loads(origin)["result"]


def test_ib_4_4_origin_body_drops_only_the_payment_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payment = {"scheme": "exact", "note": "keep-me"}
    raw = _call_with_meta(payment, arguments={"symbol": "acme"}, meta_before={"progressToken": "tok", "custom": "keep"})
    world = _meta_world()
    _deliver(world)
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        _post(client, raw)
    expected = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "quote",
            "arguments": {"symbol": "acme"},
            "_meta": {"progressToken": "tok", "custom": "keep"},
        },
        "id": 7,
    }
    assert world.up_calls[0]["raw"] == json.dumps(expected, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_ib_4_5_empty_meta_stays_in_the_origin_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    _deliver(world)
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        _post(client, _call_with_meta({"scheme": "exact"}))
    sent = json.loads(world.up_calls[0]["raw"])
    assert sent["params"]["_meta"] == {}


def test_ib_4_6_sse_origin_becomes_one_json_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    note = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}})
    final = json.dumps({"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "ok"}]}})
    streamed = f"data: {note}\n\ndata: {final}\n\n".encode()
    world = _meta_world()
    world.queue.append(_reply(200, streamed, "text/event-stream"))
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.status_code == 200
    assert response.headers["content-type"].split(";", 1)[0] == "application/json"
    assert response.headers["payment-response"] == world.settlement
    assert "notifications/progress" not in response.text
    body = response.json()
    assert body["id"] == 7
    assert body["result"]["content"] == [{"type": "text", "text": "ok"}]
    assert body["result"]["_meta"]["x402/payment-response"] == _SETTLEMENT


def test_ib_4_7_origin_meta_keys_are_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    _deliver(world, {"_meta": {"progressToken": "tok"}})
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.json()["result"]["_meta"] == {"progressToken": "tok", "x402/payment-response": _SETTLEMENT}


def test_ib_4_8_proxy_settlement_overwrites_the_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    _deliver(world, {"_meta": {"x402/payment-response": {"success": False, "forged": True}, "other": "kept"}})
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    meta = response.json()["result"]["_meta"]
    assert meta["x402/payment-response"] == _SETTLEMENT
    assert meta["other"] == "kept"


def test_ib_4_9_non_object_result_meta_is_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    world = _meta_world()
    _deliver(world, {"_meta": "not-an-object"})
    caplog.set_level(logging.WARNING, logger="satsgate_proxy")
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.json()["result"]["_meta"] == {"x402/payment-response": _SETTLEMENT}
    assert sum(call["path"].endswith("/x402/settle") for call in world.core_calls) == 1
    assert [record.getMessage() for record in caplog.records if record.name == "satsgate_proxy"] == [
        "tool result _meta was not an object"
    ]


def test_ib_4_10_unreadable_settlement_returns_the_tool_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    world = _meta_world()
    world.settlement = _UNREADABLE_SETTLEMENT
    origin = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "ok"}]}}
    world.queue.append(_reply(200, json.dumps(origin).encode(), "application/json"))
    caplog.set_level(logging.WARNING, logger="satsgate_proxy")
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.status_code == 200
    assert response.json() == origin
    assert "x402/payment-response" not in response.text
    assert response.headers["payment-response"] == _UNREADABLE_SETTLEMENT
    assert [record.getMessage() for record in caplog.records if record.name == "satsgate_proxy"] == [
        "x402 settlement was not readable"
    ]


def test_ib_4_11_tool_failure_can_be_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    failed = _result({"isError": True, "content": [{"type": "text", "text": "no"}]}, ident=7)
    world.queue.append(_reply(200, failed, "application/json"))
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    raw = _call_with_meta({"scheme": "exact"})
    with _client(settings, world) as client:
        first = _post(client, raw)
        assert first.status_code == 200
        assert first.content == failed
        assert sum(call["path"].endswith("/x402/settle") for call in world.core_calls) == 0
        _deliver(world)
        second = _post(client, raw)
    assert second.status_code == 200
    assert second.headers["payment-response"] == world.settlement
    assert sum(call["path"].endswith("/x402/settle") for call in world.core_calls) == 1


def test_ib_4_12_meta_and_header_conflict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}), {"PAYMENT-SIGNATURE": "sig-test"})
    assert _structured(response, 7) == {"error": "one_rail_only", "tool": "quote"}
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_4_13_meta_and_lightning_conflict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}), _auth("route:tools:quote"))
    assert _structured(response, 7) == {"error": "one_rail_only", "tool": "quote"}
    assert world.core_calls == []
    assert world.up_calls == []


@pytest.mark.parametrize("value", ["abc", [1], 1, True, None])
def test_ib_4_14_payment_must_be_an_object(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta(value))
    assert _structured(response, 7) == {"error": "bad_signature", "tool": "quote"}
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_4_15_encoded_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    under = _payment_of_length(8192)
    over = _payment_of_length(8196)
    assert len(_signature(under)) == 8192
    assert len(_signature(over)) == 8196
    accepted = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, accepted) as client:
        _post(client, _call_with_meta(under))
    assert sum(call["path"].endswith("/x402/verify") for call in accepted.core_calls) == 1
    rejected = OfferWorld()
    with _client(settings, rejected) as client:
        response = _post(client, _call_with_meta(over))
    assert _structured(response, 7) == {"error": "bad_signature", "tool": "quote"}
    assert rejected.core_calls == []
    assert rejected.up_calls == []


def test_ib_4_16_http_402_route_accepts_the_meta_rail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    origin = _deliver(world)
    settings = _mcp_settings(tmp_path, monkeypatch, _TOOLS)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.status_code == 200
    assert response.headers["content-type"].split(";", 1)[0] == "application/json"
    assert response.headers["payment-response"] == world.settlement
    body = response.json()
    assert body["result"]["_meta"]["x402/payment-response"] == _SETTLEMENT
    rest = {key: value for key, value in body["result"].items() if key != "_meta"}
    assert rest == json.loads(origin)["result"]


def test_ib_4_17_http_402_route_keeps_the_classic_conflict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _TOOLS)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}), {"PAYMENT-SIGNATURE": "sig-test"})
    assert response.status_code == 400
    assert response.json() == {"ok": False, "error": "one_rail_only"}
    assert world.core_calls == []
    assert world.up_calls == []


def test_ib_4_18_free_tool_with_a_payment_key_stays_free(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _call_with_meta({"scheme": "exact"}, name="echo", ident=4, arguments={"text": "hi"})
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, raw)
    assert world.core_calls == []
    assert response.status_code == 200
    assert response.content == _ORIGIN_OK
    sent = json.loads(world.up_calls[0]["raw"])
    assert "x402/payment" not in sent["params"]["_meta"]
    assert sent["params"]["name"] == "echo"
    assert sent["params"]["arguments"] == {"text": "hi"}


def test_ib_4_19_other_messages_drop_the_payment_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _rpc("tools/list", {"_meta": {"x402/payment": {"a": 1}, "progressToken": "tok"}}, ident=3)
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, raw)
    assert world.core_calls == []
    assert response.content == _ORIGIN_OK
    sent = json.loads(world.up_calls[0]["raw"])
    assert sent["params"]["_meta"] == {"progressToken": "tok"}


def test_ib_4_20_free_batch_drops_the_payment_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {"x402/payment": {"a": 1}}}}
    second = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping",
        "params": {"_meta": {"keep": "yes", "x402/payment": {"a": 2}}},
    }
    raw = json.dumps([first, second], separators=(",", ":")).encode()
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        _post(client, raw)
    assert world.core_calls == []
    expected = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"_meta": {"keep": "yes"}}},
    ]
    assert world.up_calls[0]["raw"] == json.dumps(expected, separators=(",", ":"), ensure_ascii=False).encode()


def test_ib_4_21_bodies_without_the_key_are_not_rewritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    free = b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "caf\\u00e9"}}}'
    paid = b'{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "quote", "arguments": {"text": "caf\\u00e9"}}}'
    world = OfferWorld()
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        _post(client, free)
        _post(client, paid, {"PAYMENT-SIGNATURE": "sig-test"})
    assert world.up_calls[0]["raw"] == free
    assert world.up_calls[1]["raw"] == paid


def test_ib_4_22_resource_follows_the_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    quote = OfferWorld()
    deep = OfferWorld()
    with _client(settings, quote) as client:
        _post(client, _call_with_meta({"scheme": "exact"}, name="quote"))
    with _client(settings, deep) as client:
        _post(client, _call_with_meta({"scheme": "exact"}, name="deep_search"))
    quote_verify = [call for call in quote.core_calls if call["path"].endswith("/x402/verify")]
    deep_verify = [call for call in deep.core_calls if call["path"].endswith("/x402/verify")]
    assert len(quote_verify) == 1
    assert len(deep_verify) == 1
    assert quote_verify[0]["body"]["resource"] == "route:tools:quote"
    assert deep_verify[0]["body"]["resource"] == "route:tools:deep_search"


def test_ib_4_23_settle_follows_a_successful_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    world = _meta_world()
    _deliver(world)
    settings = _mcp_settings(tmp_path, monkeypatch, _IN_BAND)
    with _client(settings, world) as client:
        response = _post(client, _call_with_meta({"scheme": "exact"}))
    assert response.status_code == 200
    assert world.order == ["verify", "origin", "settle"]
