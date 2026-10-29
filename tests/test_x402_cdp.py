"""Base mainnet USDC through the CDP facilitator. HTTP is a test double.

Nothing in this file calls Coinbase or spends USDC.
"""

from __future__ import annotations

import base64
import importlib
import json
import logging

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from eth_account import Account
from fastapi.testclient import TestClient

from satsgate_gate.core_client import _x402_requirements
from test_x402 import _buy, _enable_x402, _gate, _load_app, _patch_dns, _site, _verify_payee
from test_x402_topup import _quote

_BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
_TREASURY = "0x1111111111111111111111111111111111111111"


def _material() -> tuple[str, str, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    secret = base64.b64encode(seed + public).decode("ascii")
    return "organizations/org-1/apiKeys/key-1", secret, key


def _cdp_env(key_id: str, secret: str) -> dict[str, str]:
    return {
        "SATSGATE_X402_CDP": "1",
        "SATSGATE_X402_CDP_KEY_ID": key_id,
        "SATSGATE_X402_CDP_KEY_SECRET": secret,
    }


def _document(accepts: list[dict]) -> str:
    raw = json.dumps({"x402Version": 2, "resource": {"url": "https://gate.example/paid"}, "accepts": accepts})
    return base64.standard_b64encode(raw.encode()).decode()


def _accept(network: str, asset: str) -> dict:
    name = "USD Coin" if network == "eip155:8453" else "USDC"
    return {
        "scheme": "exact",
        "network": network,
        "amount": "10000",
        "asset": asset,
        "payTo": _TREASURY,
        "extra": {"name": name, "version": "2", "assetTransferMethod": "eip3009"},
    }


def test_cdp_jwt_matches_the_documented_claims(caplog: pytest.LogCaptureFixture) -> None:
    from app import cdp_auth

    key_id, secret, key = _material()
    derived = Ed25519PrivateKey.from_private_bytes(base64.b64decode(secret)[:32])
    assert derived.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == base64.b64decode(secret)[32:]
    monkey_env = {
        "SATSGATE_X402_CDP_KEY_ID": key_id,
        "SATSGATE_X402_CDP_KEY_SECRET": secret,
    }
    import os

    saved = {name: os.environ.get(name) for name in monkey_env}
    os.environ.update(monkey_env)
    try:
        header = cdp_auth.authorization_header(
            "POST", "https://api.cdp.coinbase.com/platform/v2/x402/verify"
        )
        token = header.removeprefix("Bearer ")
        decoded = jwt.get_unverified_header(token)
        claims = jwt.decode(
            token,
            key.public_key(),
            algorithms=["EdDSA"],
            audience="cdp_service",
            leeway=5,
        )
        assert decoded["alg"] == "EdDSA"
        assert decoded["typ"] == "JWT"
        assert decoded["kid"] == key_id
        assert len(decoded["nonce"]) == 32
        assert claims["sub"] == key_id
        assert claims["iss"] == "cdp"
        assert claims["aud"] == ["cdp_service"]
        assert claims["uri"] == "POST api.cdp.coinbase.com/platform/v2/x402/verify"
        assert secret not in token
        assert secret not in header
        cdp_auth.install_redactor()
        caplog.set_level(logging.WARNING, logger="satsgate.x402")
        logging.getLogger("satsgate.x402").warning("seen %s %s", secret, key_id)
        assert secret not in caplog.text
        assert key_id not in caplog.text
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_unusable_secret_keeps_mainnet_off_and_does_not_log_the_value(tmp_path, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="satsgate.x402")
    secret = "not-a-cdp-secret"
    module = _load_app(
        tmp_path,
        SATSGATE_X402_CDP="1",
        SATSGATE_X402_CDP_KEY_ID="organizations/org-1/apiKeys/key-1",
        SATSGATE_X402_CDP_KEY_SECRET=secret,
    )
    assert module.config.X402_MAINNET_ENABLED is False
    assert module.config.APP_VERSION == "0.16.0"
    assert secret not in caplog.text
    assert "USDC mainnet disabled" in caplog.text
    with TestClient(module.app) as http:
        assert http.get("/health").json()["version"] == "0.16.0"
        status = http.get("/v1/admin/x402", headers={"X-Admin-Token": "test-admin-token"}).json()
        assert status["mainnet_enabled"] is False
        assert status["cdp"]["reason"] == "credentials"
        assert status["cdp"]["supported_ok"] is None
        assert secret not in json.dumps(status)


def test_new_site_defaults_to_test_and_live_is_rejected_while_the_switch_is_off(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 10_000})
        site = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert site["rail_x402"] is False
        assert site["x402_mode"] is None
        assert site["x402_testing"] is False
        assert "x402_network" not in site
        _verify_payee(http, key, owner)
        denied = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"x402_mode": "live"})
        assert denied.status_code == 400
        assert denied.json()["error"] == "x402_mainnet_disabled"
        invalid = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"x402_mode": "both"})
        assert invalid.status_code == 400
        assert invalid.json()["error"] == "x402_mode_invalid"
        writer = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": key},
            json={"label": "sites", "scope": "sites:write"},
        ).json()["api_key"]
        scoped = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": writer}, json={"x402_mode": "test"})
        assert scoped.status_code == 403
        _enable_x402(http, key)
        enabled = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert enabled["x402_mode"] == "test"
        assert enabled["x402_testing"] is True
        assert enabled["x402_network"] == "eip155:84532"
        listed = http.get("/v1/sites").json()["sites"][0]
        assert listed["x402_mode"] == "test"
        assert listed["x402_testing"] is True
        assert "payTo" not in listed
        assert "origin_url" not in listed
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        body = issued.json()
        document = json.loads(base64.b64decode(issued.headers["payment-required"]))
        assert document["accepts"][0]["network"] == "eip155:84532"
        assert len(document["accepts"]) == 1
        assert document["accepts"][0]["extra"] == {
            "name": "USDC",
            "version": "2",
            "assetTransferMethod": "eip3009",
        }
        assert body["testing"] is True
        assert body["x402_mode"] == "test"
        assert "testing" not in document["accepts"][0]["extra"]


def test_live_offer_uses_cdp_and_test_mode_stays_on_x402_org(tmp_path, monkeypatch, caplog) -> None:
    key_id, secret, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret))
    _patch_dns(monkeypatch, module)
    assert module.config.X402_MAINNET_ENABLED is True
    owner = Account.create()
    buyer = Account.create()
    calls = []

    def _post(url, body, headers):
        calls.append((url, dict(headers)))
        if url.endswith("/verify"):
            return {"isValid": True, "payer": buyer.address}
        return {"success": True, "transaction": "0x" + "ab" * 32, "payer": buyer.address}

    caplog.set_level(logging.WARNING, logger="satsgate.x402")
    with TestClient(module.app) as http:
        key = _buy(http)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 10_000})
        _verify_payee(http, key, owner)
        live = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert live.status_code == 200, live.text
        assert live.json()["site"]["x402_testing"] is False
        assert live.json()["site"]["x402_network"] == "eip155:8453"
        importlib.import_module("app.x402_facilitator").poster = _post
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        document = json.loads(base64.b64decode(issued.headers["payment-required"]))
        assert [item["network"] for item in document["accepts"]] == ["eip155:8453"]
        assert document["accepts"][0]["asset"] == _BASE_USDC
        assert document["accepts"][0]["extra"] == {
            "name": "USD Coin",
            "version": "2",
            "assetTransferMethod": "eip3009",
        }
        assert document["resource"]["description"] == ""
        assert issued.json()["testing"] is False
        assert issued.json()["x402_mode"] == "live"
        from test_x402 import _payload

        encoded = _payload(issued.headers["payment-required"], buyer, issued.json()["expires_at"])
        verified = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert verified.status_code == 200, verified.text
        assert calls[0][0] == "https://api.cdp.coinbase.com/platform/v2/x402/verify"
        assert calls[0][1]["Authorization"].startswith("Bearer ")
        assert secret not in calls[0][1]["Authorization"]
        assert secret not in caplog.text
        assert key_id not in caplog.text

        back = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"x402_mode": "test"})
        assert back.status_code == 200, back.text
        calls.clear()
        again = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        test_doc = json.loads(base64.b64decode(again.headers["payment-required"]))
        assert test_doc["accepts"][0]["network"] == "eip155:84532"
        assert test_doc["accepts"][0]["asset"] == _SEPOLIA_USDC
        assert test_doc["accepts"][0]["extra"]["name"] == "USDC"
        assert test_doc["resource"]["description"] == "Test payment on Base Sepolia. Not Base mainnet."
        assert again.json()["testing"] is True
        encoded = _payload(again.headers["payment-required"], buyer, again.json()["expires_at"])
        tested = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert tested.status_code == 200, tested.text
        assert calls[0][0] == "https://x402.org/facilitator/verify"
        assert "Authorization" not in calls[0][1]


def test_mainnet_offer_rejects_the_sepolia_eip712_name(tmp_path, monkeypatch) -> None:
    key_id, secret, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    calls = []

    def _post(url, body, headers):
        calls.append(url)
        return {"isValid": True}

    with TestClient(module.app) as http:
        key = _buy(http)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 10_000})
        _verify_payee(http, key, owner)
        live = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "rail_lightning": False, "x402_mode": "live"},
        )
        assert live.status_code == 200, live.text
        importlib.import_module("app.x402_facilitator").poster = _post
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        document = json.loads(base64.b64decode(issued.headers["payment-required"]))
        assert document["accepts"][0]["extra"]["name"] == "USD Coin"
        from test_x402 import _payload

        encoded = _payload(
            issued.headers["payment-required"],
            buyer,
            issued.json()["expires_at"],
            accepted={"extra": {"name": "USDC", "version": "2", "assetTransferMethod": "eip3009"}},
        )
        rejected = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert rejected.status_code == 402, rejected.text
        assert rejected.json()["error"] == "bad_signature"
        assert calls == []


def test_display_name_patch_does_not_fail_when_stored_live_and_cdp_is_later_off(tmp_path, monkeypatch) -> None:
    key_id, secret, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        _site(http, key, path="/paid", body={"price_sats": 21})
        _verify_payee(http, key, owner)
        turned = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True, "x402_mode": "live"},
        )
        assert turned.status_code == 200, turned.text
    module = _load_app(tmp_path, SATSGATE_X402_CDP="0")
    _patch_dns(monkeypatch, module)
    assert module.config.X402_MAINNET_ENABLED is False
    with TestClient(module.app) as http:
        renamed = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"display_name": "Still Live"},
        )
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["site"]["x402_mode"] == "live"
        assert renamed.json()["site"]["display_name"] == "Still Live"
        blocked = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": False},
        )
        assert blocked.status_code == 200, blocked.text
        again = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_x402": True},
        )
        assert again.status_code == 400
        assert again.json()["error"] == "x402_mainnet_disabled"


def test_topup_is_mainnet_only_while_the_switch_is_on(tmp_path, monkeypatch) -> None:
    key_id, secret, _key = _material()
    module = _load_app(tmp_path, SATSGATE_TREASURY_EVM_ADDRESS=_TREASURY, **_cdp_env(key_id, secret))
    _patch_dns(monkeypatch, module)
    _quote(module)
    buyer = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        quoted = http.get("/v1/topup/trial/x402", headers={"X-Api-Key": key})
        assert quoted.status_code == 402, quoted.text
        document = json.loads(base64.b64decode(quoted.headers["payment-required"]))
        assert [item["network"] for item in document["accepts"]] == ["eip155:8453"]
        assert document["accepts"][0]["asset"] == _BASE_USDC
        assert document["accepts"][0]["extra"]["name"] == "USD Coin"
        assert document["accepts"][0]["extra"]["version"] == "2"
        assert quoted.json()["testing"] is False
        assert quoted.json()["x402_mode"] == "live"
        from test_x402 import _payload

        signature = _payload(quoted.headers["payment-required"], buyer, quoted.json()["expires_at"])
    module = _load_app(tmp_path, SATSGATE_TREASURY_EVM_ADDRESS=_TREASURY, SATSGATE_X402_CDP="0")
    _patch_dns(monkeypatch, module)
    _quote(module)
    with TestClient(module.app) as http:
        paid = http.get(
            "/v1/topup/trial/x402",
            headers={"X-Api-Key": key, "PAYMENT-SIGNATURE": signature},
        )
        assert paid.status_code == 402
        assert paid.json()["error"] == "network_mismatch"
        fresh = http.get("/v1/topup/trial/x402", headers={"X-Api-Key": key})
        assert fresh.status_code == 402, fresh.text
        fresh_doc = json.loads(base64.b64decode(fresh.headers["payment-required"]))
        assert fresh_doc["accepts"][0]["network"] == "eip155:84532"
        assert fresh_doc["accepts"][0]["extra"]["name"] == "USDC"
        assert fresh.json()["testing"] is True
        assert fresh.json()["x402_mode"] == "test"
        started = http.get("/v1/topup/trial", headers={"X-Api-Key": key})
        assert started.status_code == 402
        assert started.json()["invoice"]


def test_admin_x402_status_is_cached_and_has_no_secrets(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        assert http.get("/v1/admin/x402").status_code == 401
        assert http.get("/v1/admin/x402", headers={"X-Admin-Token": "nope"}).status_code == 401
        body = http.get("/v1/admin/x402", headers={"X-Admin-Token": "test-admin-token"}).json()
    assert body["mainnet_enabled"] is False
    assert body["cdp"]["reason"] == "disabled"
    assert body["cdp"]["supported_ok"] is None
    assert body["topup_network"] == "eip155:84532"
    assert set(body) == {"ok", "mainnet_enabled", "test_network", "live_network", "topup_network", "cdp"}
    assert set(body["cdp"]) == {"supported_ok", "checked_at", "http_status", "reason", "cached"}

    key_id, secret, _key = _material()
    module = _load_app(tmp_path, **_cdp_env(key_id, secret))
    calls = {"n": 0}

    def _probe():
        calls["n"] += 1
        return 200, {"kinds": [{"scheme": "exact", "network": "eip155:8453"}]}

    status_mod = importlib.import_module("app.x402_cdp_status")
    status_mod.probe = _probe
    status_mod.clear_cache()
    with TestClient(module.app) as http:
        first = http.get("/v1/admin/x402", headers={"X-Admin-Token": "test-admin-token"}).json()
        second = http.get("/v1/admin/x402", headers={"X-Admin-Token": "test-admin-token"}).json()
    assert calls["n"] == 1
    assert first["mainnet_enabled"] is True
    assert first["cdp"]["supported_ok"] is True
    assert first["cdp"]["reason"] == "ok"
    assert first["cdp"]["cached"] is False
    assert first["topup_network"] == "eip155:8453"
    assert second["cdp"]["cached"] is True
    assert secret not in json.dumps(first)
    assert key_id not in json.dumps(first)


def test_facilitator_log_is_status_and_reason_only(tmp_path, monkeypatch, caplog) -> None:
    key_id, secret, _key = _material()
    _load_app(tmp_path, **_cdp_env(key_id, secret))
    seen = {}

    def _post(url, payload, headers=None, timeout=None):
        seen["url"] = url
        seen["headers"] = dict(headers or {})
        return 401, {"error": secret, "kid": key_id}

    facilitator = importlib.import_module("app.x402_facilitator")
    monkeypatch.setattr(facilitator, "safe_post_json", _post)
    facilitator.poster = None
    caplog.set_level(logging.WARNING, logger="satsgate.x402")
    with pytest.raises(facilitator.FacilitatorError):
        facilitator.verify(
            {"x402Version": 2},
            {"scheme": "exact", "network": "eip155:8453"},
        )
    assert seen["url"] == "https://api.cdp.coinbase.com/platform/v2/x402/verify"
    assert secret not in seen["headers"]["Authorization"]
    assert "status=401" in caplog.text
    assert "reason=auth" in caplog.text
    assert secret not in caplog.text
    assert key_id not in caplog.text


def test_gate_accepts_one_network_and_labels_test_mode() -> None:
    sepolia = _x402_requirements(_document([_accept("eip155:84532", _SEPOLIA_USDC)]), {})
    assert sepolia["testing"] is True
    assert sepolia["x402_mode"] == "test"
    assert sepolia["asset"] == _SEPOLIA_USDC
    live = _x402_requirements(_document([_accept("eip155:8453", _BASE_USDC)]), {})
    assert live["testing"] is False
    assert live["x402_mode"] == "live"
    assert live["network"] == "eip155:8453"
    with pytest.raises(ValueError):
        _x402_requirements(
            _document([_accept("eip155:84532", _SEPOLIA_USDC), _accept("eip155:8453", _BASE_USDC)]),
            {},
        )
    with pytest.raises(ValueError):
        _x402_requirements(_document([_accept("eip155:8453", _SEPOLIA_USDC)]), {})
