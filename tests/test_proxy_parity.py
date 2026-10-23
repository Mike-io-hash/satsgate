"""Proxy 0.12.0 charges both rails only after the origin returns 2xx."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import textwrap
from pathlib import Path

import httpx
from eth_account import Account
from fastapi.testclient import TestClient

from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from test_rates import _use
from test_satsgate_gate import Origin, _buy, _load_app, _pay
from test_x402 import _install_poster, _payload, _poster, _verify_payee

SECRET = "origin-secret-that-is-long-enough-ok"

_YAML = """\
core:
  base_url: http://core.test
  api_key_env: SATSGATE_API_KEY
  timeout_seconds: 5
upstream:
  base_url: http://upstream.test
  timeout_seconds: 5
origin:
  secret_env: SATSGATE_ORIGIN_SECRET
server:
  public_base: http://proxy.test
routes:
  - name: article
    methods: [GET]
    path: /blog/**
    price_sats: 100
    access: per_request
    scope: route
    x402: {x402}
"""


class CoreBridge(httpx.AsyncBaseTransport):
    def __init__(self, app, origin: Origin) -> None:
        self._core = httpx.ASGITransport(app=app)
        self._origin = origin

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "core.test":
            return await self._core.handle_async_request(request)
        return self._origin(request)


def _settings(tmp_path: Path, monkeypatch, *, x402: bool):
    text = textwrap.dedent(_YAML).format(x402="true" if x402 else "false")
    path = tmp_path / "proxy.yaml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", SECRET)
    return load_settings(path)


def _restricted(core: TestClient, account: str) -> str:
    minted = core.post(
        "/v1/api-keys",
        headers={"X-Api-Key": account},
        json={"label": "proxy", "resource_prefix": "route:"},
    )
    assert minted.status_code == 200, minted.text
    return minted.json()["api_key"]


def _debits() -> tuple:
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        return conn.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(delta_credits), 0)
            FROM ledger WHERE reason = 'paywall_verify'
            """
        ).fetchone()


def test_proxy_lightning_charges_once_after_a_successful_origin(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    state = {"status": 500, "body": b"origin-down"}
    origin = Origin()
    origin.responder = lambda request: httpx.Response(state["status"], content=state["body"])
    with TestClient(module.app) as core:
        account = _buy(core)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
        settings = _settings(tmp_path, monkeypatch, x402=False)
        before = core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"]
        with TestClient(build_app(settings, transport=CoreBridge(module.app, origin))) as proxy:
            challenge = proxy.get("/blog/a")
            assert challenge.status_code == 402, challenge.text
            body = challenge.json()
            assert "payment-required" not in challenge.headers
            assert challenge.headers["www-authenticate"].startswith("L402 ")
            headers = {"Authorization": f"L402 {body['macaroon']}:{_pay(core, body['payment_hash'])}"}
            failed = proxy.get("/blog/a", headers=headers)
            assert failed.status_code == 500, failed.text
            assert failed.content == b"origin-down"
            assert "use_spent" not in failed.json() if failed.headers.get("content-type", "").startswith("application/json") else True
            assert core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"] == before
            state["status"] = 404
            state["body"] = b"missing"
            missing = proxy.get("/blog/a", headers=headers)
            assert missing.status_code == 404
            assert missing.content == b"missing"
            assert _debits() == (0, 0)
            state["status"] = 200
            state["body"] = b"origin-ok"
            served = proxy.get("/blog/a", headers=headers)
            assert served.status_code == 200, served.text
            assert served.content == b"origin-ok"
            assert core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"] == before - 1
            assert _debits() == (1, -1)
            again = proxy.get("/blog/a", headers=headers)
            assert again.status_code == 402, again.text
            assert again.json()["reason"] == "token_used_up"
            assert core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"] == before - 1
            assert len(origin.requests) == 3
            assert origin.requests[0].headers["x-satsgate-paid-sats"] == "100"


def test_proxy_x402_charges_once_and_records_the_ledger(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _use(module, {"coinbase": "65000", "kraken": "65000", "bitstamp": "65000"})
    owner = Account.create()
    buyer = Account.create()
    state = {"status": 500, "body": b"origin-down"}
    origin = Origin()
    origin.responder = lambda request: httpx.Response(state["status"], content=state["body"])
    calls, post = _poster(buyer)
    _install_poster(post)
    with TestClient(module.app) as core:
        account = _buy(core)
        _verify_payee(core, account, owner)
        monkeypatch.setenv("SATSGATE_API_KEY", _restricted(core, account))
        settings = _settings(tmp_path, monkeypatch, x402=True)
        before = core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"]
        with TestClient(build_app(settings, transport=CoreBridge(module.app, origin))) as proxy:
            challenge = proxy.get("/blog/a", headers={"Authorization": "Bearer buyer"})
            assert challenge.status_code == 402, challenge.text
            body = challenge.json()
            assert body["amount_sats"] == 100
            assert challenge.headers["www-authenticate"].startswith("L402 ")
            encoded = challenge.headers["payment-required"]
            document = json.loads(base64.b64decode(encoded))
            assert document["x402Version"] == 2
            assert document["resource"]["url"] == "http://proxy.test/blog/a"
            assert document["accepts"][0]["payTo"] == owner.address
            assert document["accepts"][0]["scheme"] == "exact"
            signature = _payload(encoded, buyer, body["x402"]["expires_at"])
            both = proxy.get(
                "/blog/a",
                headers={"Authorization": "L402 macaroon", "PAYMENT-SIGNATURE": signature},
            )
            assert both.status_code == 400
            assert both.json()["error"] == "one_rail_only"
            assert origin.requests == []
            oversized = proxy.get("/blog/a", headers={"PAYMENT-SIGNATURE": "x" * 8193})
            assert oversized.status_code == 400
            assert oversized.json()["error"] == "bad_signature"
            failed = proxy.get(
                "/blog/a",
                headers={"PAYMENT-SIGNATURE": signature, "Authorization": "Bearer buyer"},
            )
            assert failed.status_code == 500, failed.text
            assert failed.content == b"origin-down"
            assert "payment-response" not in failed.headers
            assert core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"] == before
            assert not any(url.endswith("/settle") for url, _body in calls)
            names = {name.lower() for name in origin.requests[0].headers}
            assert "payment-signature" not in names
            assert "x-satsgate-paid-sats" not in names
            assert origin.requests[0].headers["x-satsgate-paid-usd-atomic"] == body["x402"]["amount"]
            assert origin.requests[0].headers["authorization"] == "Bearer buyer"
            state["status"] = 200
            state["body"] = b"origin-ok"
            served = proxy.get(
                "/blog/a",
                headers={"PAYMENT-SIGNATURE": signature, "Authorization": "Bearer buyer"},
            )
            assert served.status_code == 200, served.text
            assert served.content == b"origin-ok"
            settled = json.loads(base64.b64decode(served.headers["payment-response"]))
            assert settled["success"] is True
            assert settled["transaction"].startswith("0x")
            assert settled["tx"] == settled["transaction"]
            assert settled["network"] == "eip155:84532"
            assert settled["payer"] == buyer.address
            assert core.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"] == before - 1
            with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                ledger = conn.execute(
                    """
                    SELECT network, amount_usd_atomic, COUNT(*)
                    FROM ledger WHERE reason = 'paywall_verify'
                    """
                ).fetchone()
            assert ledger[0] == "eip155:84532"
            assert ledger[1] == int(body["x402"]["amount"])
            assert ledger[2] == 1
            assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1
            assert sum(1 for url, _body in calls if url.endswith("/verify")) == 1
