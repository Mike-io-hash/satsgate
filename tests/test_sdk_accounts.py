"""SDK account open and free-amount top-up against an in-process core (T-B.3)."""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from satsgate_sdk import SatsgateClient, SatsgateError, create_account
from satsgate_sdk.client import httpx as sdk_httpx
from test_x402 import _load_app

ROOT = Path(__file__).resolve().parents[1]
_TREASURY = "0x1111111111111111111111111111111111111111"
_BASE = "http://testserver"


class _CoreTransport(httpx.BaseTransport):
    """Send the real SDK's httpx calls to the in-process FastAPI app."""

    def __init__(self, app_client: TestClient) -> None:
        self._app = app_client
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.satsgate.org":
            raise AssertionError("SDK test called api.satsgate.org")
        self.requests.append(request)
        url = request.url.path
        if request.url.query:
            url = f"{url}?{request.url.query.decode()}"
        headers = {key: value for key, value in request.headers.items() if key.lower() != "host"}
        response = self._app.request(request.method, url, headers=headers, content=request.content)
        return httpx.Response(status_code=response.status_code, headers=dict(response.headers), content=response.content)


def _bind(monkeypatch: pytest.MonkeyPatch, transport: _CoreTransport) -> None:
    real = sdk_httpx.Client

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    monkeypatch.setattr(sdk_httpx, "Client", factory)


def test_t_b_3_0_sdk_tests_stay_on_the_in_process_core() -> None:
    """Other SDK tests must not name the public API. This file's transport rejects that host."""
    public = "https://api." + "satsgate.org"
    for path in (ROOT / "tests").glob("test_*.py"):
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8")
        if "satsgate_sdk" not in text:
            continue
        assert public not in text, path
        assert public.replace("https://", "http://") not in text, path


def test_t_b_3_1_create_account_against_the_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        opened = create_account(base_url=_BASE)
        assert opened["api_key"].startswith("sg_")
        assert isinstance(opened["client_id"], int)
        assert opened["balance_msat"] == 0
        assert "balance_sats" in opened
        assert "estimated_unlocks_remaining" in opened
        assert "free_unlocks_remaining" in opened
        assert "paid_unlocks_estimate" in opened
        sent = transport.requests[-1]
        assert sent.method == "POST"
        assert sent.url.path == "/v1/accounts"
        assert "x-api-key" not in {key.lower() for key in sent.headers}
        assert sent.content in {b"{}", b""}
        personal = http.post("/v1/accounts", json={"email": "person@example.com"})
        assert personal.status_code == 422


def test_t_b_3_2_signup_limit_is_raised_and_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_app(
        tmp_path,
        SATSGATE_SIGNUP_MAX_PER_IP_PER_DAY="3",
        SATSGATE_SIGNUP_MAX_GLOBAL_PER_DAY="100",
    )
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        for _ in range(3):
            opened = create_account(base_url=_BASE)
            assert opened["api_key"].startswith("sg_")
        before = len(transport.requests)
        with pytest.raises(SatsgateError) as raised:
            create_account(base_url=_BASE)
        assert raised.value.status_code == 429
        assert raised.value.data is not None
        assert raised.value.data["error"] == "signup_ip_limit"
        assert "retry_after_seconds" in raised.value.data
        assert len(transport.requests) == before + 1


def test_t_b_3_3_lightning_topup_returns_402_and_paywall_402_still_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        opened = create_account(base_url=_BASE)
        client = SatsgateClient(base_url=_BASE, api_key=opened["api_key"])
        try:
            issued = client.topup_lightning(sats=1000)
            assert issued["error"] == "payment_required"
            assert issued["sats"] == 1000
            assert issued["msat_credit"] == 1_000_000
            assert isinstance(issued.get("invoice"), str) and issued["invoice"]
            assert isinstance(issued.get("macaroon"), str) and issued["macaroon"]
            assert isinstance(issued.get("payment_hash"), str) and issued["payment_hash"]
            with pytest.raises(SatsgateError) as small:
                client.topup_lightning(sats=999)
            assert small.value.status_code == 400
            assert small.value.data is not None
            assert small.value.data["error"] == "amount_too_small"

            funded = http.post(
                "/v1/topup/lightning",
                json={"sats": 1000},
                headers={"X-Api-Key": opened["api_key"]},
            )
            assert funded.status_code == 402
            funded_body = funded.json()
            paid_topup = http.get(f"/dev/mock/pay/{funded_body['payment_hash']}")
            assert paid_topup.status_code == 200
            settled = http.post(
                "/v1/topup/lightning",
                json={"sats": 1000},
                headers={
                    "X-Api-Key": opened["api_key"],
                    "Authorization": f"L402 {funded_body['macaroon']}:{paid_topup.json()['preimage']}",
                },
            )
            assert settled.status_code == 200
            challenge = client.paywall_challenge(resource="sdk/broke", amount_sats=1)
            from app import config, db

            with db._connect(config.DB_PATH) as conn:
                conn.execute("UPDATE clients SET credits = 0, balance_msat = 0")
            paid = http.get(f"/dev/mock/pay/{challenge.payment_hash}")
            assert paid.status_code == 200
            with pytest.raises(SatsgateError) as pending:
                client.paywall_verify(
                    authorization_header=f"L402 {challenge.macaroon}:{paid.json()['preimage']}",
                    expected_resource="sdk/broke",
                )
            assert pending.value.status_code == 402
            assert pending.value.data is not None
            assert pending.value.data["error"] == "insufficient balance"
        finally:
            client.close()


def test_t_b_3_4_usdc_topup_returns_402_and_rate_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_app(tmp_path, SATSGATE_TREASURY_EVM_ADDRESS=_TREASURY)
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        opened = create_account(base_url=_BASE)
        client = SatsgateClient(base_url=_BASE, api_key=opened["api_key"])
        try:
            issued = client.topup_usdc(usd="1.00")
            assert issued["error"] == "payment_required"
            assert isinstance(issued.get("PAYMENT-REQUIRED"), str) and issued["PAYMENT-REQUIRED"]
            assert issued["PAYMENT-REQUIRED"] == issued["payment_required"]
            before = len(transport.requests)
            with pytest.raises(SatsgateError):
                client.topup_usdc(usd="1.00", payment_signature="not-a-real-signature")
            sent = transport.requests[-1]
            assert len(transport.requests) == before + 1
            assert sent.headers.get("payment-signature") == "not-a-real-signature"
            module.rates._state = None
            module.chainlink.poster = lambda *_args, **_kwargs: (
                200,
                {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "down"}},
            )
            module.accounting_rate.reset_for_tests()
            with pytest.raises(SatsgateError) as unavailable:
                client.topup_usdc(usd="1.00")
            assert unavailable.value.status_code == 503
            assert unavailable.value.data is not None
            assert unavailable.value.data["error"] == "rate_unavailable"
        finally:
            client.close()


def test_t_b_3_5_restricted_key_can_read_balance_and_cannot_top_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_app(tmp_path, SATSGATE_TREASURY_EVM_ADDRESS=_TREASURY)
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        opened = create_account(base_url=_BASE)
        account = SatsgateClient(base_url=_BASE, api_key=opened["api_key"])
        try:
            minted = account.create_api_key(label="reader")
            restricted = SatsgateClient(base_url=_BASE, api_key=minted["api_key"])
            try:
                balance = restricted.balance()
                assert "balance_msat" in balance
                assert "estimated_unlocks_remaining" in balance
                with pytest.raises(SatsgateError) as lightning:
                    restricted.topup_lightning(sats=1000)
                assert lightning.value.status_code == 403
                assert lightning.value.data is not None
                assert lightning.value.data["error"] == "insufficient_scope"
                with pytest.raises(SatsgateError) as usdc:
                    restricted.topup_usdc(usd="1.00")
                assert usdc.value.status_code == 403
                assert usdc.value.data is not None
                assert usdc.value.data["error"] == "insufficient_scope"
            finally:
                restricted.close()
        finally:
            account.close()


def test_t_b_3_6_sdk_does_not_document_packs_or_cost_credits() -> None:
    readme = (ROOT / "sdk" / "python" / "README.md").read_text(encoding="utf-8")
    assert "GET /v1/topup/{plan_id}" not in readme
    assert "/v1/topup/{plan_id}" not in readme
    assert "cost_credits" not in readme
    for path in (ROOT / "sdk" / "python" / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "GET /v1/topup/{plan_id}" not in text
        assert "/v1/topup/{plan_id}" not in text


def test_t_b_3_7_create_account_does_not_log_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        transport = _CoreTransport(http)
        _bind(monkeypatch, transport)
        caplog.set_level(logging.DEBUG)
        opened = create_account(base_url=_BASE)
        key = opened["api_key"]
        captured = capsys.readouterr()
        assert key not in captured.out
        assert key not in captured.err
        assert key not in caplog.text
