"""Core x402 on Base Sepolia. The facilitator is a test double. Lightning is unchanged."""

from __future__ import annotations

import base64
import importlib
import json
import os
import sqlite3
import sys
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
_SECRET_KEY = "ab" * 32
_GATE_TOKEN = "test-gate-token"
_TX = "0x" + "cd" * 32


def _load_app(tmp_path: Path, **env: str):
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    base = {
        "SATSGATE_ENV": "development",
        "SATSGATE_WALLET_MODE": "mock",
        "SATSGATE_DEV_MODE": "1",
        "SATSGATE_RL_ENABLED": "0",
        "SATSGATE_MACAROON_SECRET": "test-secret",
        "SATSGATE_MACAROON_KEY_ID": "1",
        "SATSGATE_MACAROON_PREVIOUS_KEYS": "",
        "SATSGATE_DB_PATH": str(tmp_path / "satsgate_test.sqlite3"),
        "SATSGATE_ADMIN_TOKEN": "test-admin-token",
        "SATSGATE_TRUSTED_PROXIES": "testclient",
        "SATSGATE_LN_NETWORK": "mainnet",
        "SATSGATE_SITE_SECRET_KEY": _SECRET_KEY,
        "SATSGATE_SITES_AUTO_APPROVE": "0",
        "SATSGATE_SITES_MAX_PER_ACCOUNT": "3",
        "SATSGATE_SITES_MAX_ROUTES": "20",
        "SATSGATE_GATE_PUBLIC_BASE": "https://gate.satsgate.org",
        "SATSGATE_GATE_TOKEN": _GATE_TOKEN,
        "SATSGATE_GATE_PEERS": "",
        "SATSGATE_X402_NETWORK": "eip155:84532",
        "SATSGATE_X402_FACILITATOR_URL": "https://x402.org/facilitator",
        "SATSGATE_TREASURY_EVM_ADDRESS": "",
    }
    base.update(env)
    for key, value in base.items():
        os.environ[key] = value
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("app.main")


def _patch_dns(monkeypatch, module):
    import ipaddress
    import socket

    def fake(host, port, family=0, socktype=0, proto=0, flags=0):
        name = str(host).lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            chosen = name
        except ValueError:
            chosen = "1.1.1.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (chosen, port))]

    monkeypatch.setattr(module.ssrf.socket, "getaddrinfo", fake)


def _auth(macaroon: str, preimage_hex: str) -> str:
    return f"L402 {macaroon}:{preimage_hex}"


def _buy(http: TestClient) -> str:
    started = http.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    preimage = http.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = http.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert settled.status_code == 200, settled.text
    return settled.json()["api_key"]


def _gate(http: TestClient, method: str, path: str, **kwargs):
    headers = {"X-Satsgate-Gate-Token": _GATE_TOKEN}
    headers.update(kwargs.pop("headers", {}))
    return http.request(method, path, headers=headers, **kwargs)


def _site(http: TestClient, key: str, *, path: str, body: dict):
    created = http.post(
        "/v1/sites",
        headers={"X-Api-Key": key},
        json={
            "slug": "my-shop",
            "display_name": "My Shop",
            "origin_url": "https://origin.example",
            "listed": True,
        },
    )
    assert created.status_code == 200, created.text
    route = http.post("/v1/sites/my-shop/routes", headers={"X-Api-Key": key}, json={"path": path, **body})
    assert route.status_code == 200, route.text
    approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
    assert approved.status_code == 200, approved.text
    return route.json()["route"]


def _sign(account, message: str) -> str:
    signed = account.sign_message(encode_defunct(text=message))
    hexed = signed.signature.hex()
    return hexed if hexed.startswith("0x") else "0x" + hexed


def _verify_payee(http: TestClient, key: str, account) -> str:
    challenge = http.post(
        "/v1/client/payee/evm/challenge",
        headers={"X-Api-Key": key},
        json={"address": account.address},
    )
    assert challenge.status_code == 200, challenge.text
    saved = http.post(
        "/v1/client/payee/evm",
        headers={"X-Api-Key": key},
        json={"address": account.address, "signature": _sign(account, challenge.json()["message"])},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["payee_evm_address"] == account.address
    assert "signature" not in saved.json()
    return account.address


def _enable_x402(http: TestClient, key: str):
    updated = http.patch(
        "/v1/sites/my-shop",
        headers={"X-Api-Key": key},
        json={"rail_x402": True, "rail_lightning": False},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["site"]["rail_x402"] is True


def _payload(required_b64: str, account, expires: int, **changes) -> str:
    document = json.loads(base64.standard_b64decode(required_b64))
    accepted = dict(document["accepts"][0])
    accepted.update(changes.get("accepted") or {})
    authorization = {
        "from": account.address,
        "to": accepted["payTo"],
        "value": accepted["amount"],
        "validAfter": "0",
        "validBefore": str(expires),
        "nonce": "0x" + "ab" * 32,
    }
    authorization.update(changes.get("authorization") or {})
    signature = changes.get("signature") or ("0x" + "11" * 65)
    payload = {
        "x402Version": 2,
        "resource": document["resource"],
        "accepted": accepted,
        "payload": {"signature": signature, "authorization": authorization},
    }
    return base64.standard_b64encode(json.dumps(payload).encode()).decode()


def _poster(account, *, settle=None, verify=None):
    calls = []

    def _post(url, body):
        calls.append((url, body))
        if url.endswith("/verify"):
            if verify is not None:
                return verify
            return {"isValid": True, "payer": account.address}
        if settle is not None:
            return settle
        return {"success": True, "transaction": _TX, "payer": account.address, "network": "eip155:84532"}

    return calls, _post


def _install_poster(post) -> None:
    facilitator = importlib.import_module("app.x402_facilitator")
    facilitator.poster = post


def _credits(http: TestClient, key: str) -> int:
    return http.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"]


def test_x402_is_off_by_default_and_lightning_is_unchanged(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        _site(http, key, path="/blog/post", body={"price_sats": 21, "max_uses": 1})
        minted = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": key},
            json={"label": "sites", "scope": "sites:write"},
        )
        assert minted.status_code == 200, minted.text
        writer = minted.json()["api_key"]
        denied = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": writer}, json={"rail_x402": True})
        assert denied.status_code == 403
        blocked = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        assert blocked.status_code == 400
        assert blocked.json()["error"] == "payee_evm_not_verified"
        challenge = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/blog/post"})
        assert challenge.status_code == 200, challenge.text
        body = challenge.json()
        assert "invoice" in body and "macaroon" in body
        assert "payment_required" not in body
        assert "PAYMENT-REQUIRED" not in challenge.headers
        both = http.patch(
            "/v1/sites/my-shop",
            headers={"X-Api-Key": key},
            json={"rail_lightning": False, "rail_x402": False},
        )
        assert both.status_code == 400
        assert both.json()["error"] == "rails_required"


def test_payee_signature_and_usd_route_offer_only_when_priced(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    other = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        challenge = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": owner.address},
        )
        assert challenge.status_code == 200, challenge.text
        message = challenge.json()["message"]
        wrong = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": owner.address, "signature": _sign(other, message)},
        )
        assert wrong.status_code == 400
        assert wrong.json()["error"] == "bad_signature"
        info = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        assert info["payee_evm_verified"] is False
        assert info["payee_evm_address"] is None
        saved = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": owner.address, "signature": _sign(owner, message)},
        )
        assert saved.status_code == 200, saved.text
        _site(http, key, path="/blog/post", body={"price_sats": 21})
        http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        sats_only = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/blog/post"})
        assert sats_only.status_code == 200, sats_only.text
        assert "invoice" in sats_only.json()
        assert "payment_required" not in sats_only.json()
        usd = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/paid", "price_currency": "usd", "price_usd_atomic": 10_000},
        )
        assert usd.status_code == 200, usd.text
        assert usd.json()["route"]["price_sats"] is None
        assert usd.json()["route"]["price_usd_atomic"] == 10_000
        offered = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert offered.status_code == 200, offered.text
        body = offered.json()
        assert body["rail"] == "x402"
        assert body["x402"]["network"] == "eip155:84532"
        assert body["x402"]["payTo"] == owner.address
        assert body["x402"]["amount"] == "10000"
        assert "invoice" not in body
        decoded = json.loads(base64.standard_b64decode(body["payment_required"]))
        assert decoded["x402Version"] == 2
        assert decoded["accepts"][0]["scheme"] == "exact"
        assert "paymentFlow" not in decoded["accepts"][0].get("extra", {})
        public = http.get("/v1/sites").json()["sites"][0]
        usd_row = next(route for route in public["routes"] if route["path"] == "/paid")
        assert usd_row["price_currency"] == "usd"
        assert usd_row["price_usd_atomic"] == 10_000
        assert "price_sats" not in usd_row
        assert "payTo" not in public and owner.address not in http.get("/v1/sites").text


def _swap_line(message: str, prefix: str, value: str) -> str:
    lines = []
    for line in message.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        if body.startswith(prefix):
            lines.append(prefix + value + ending)
        else:
            lines.append(line)
    return "".join(lines)


def test_payee_signature_accepts_trimmed_text_and_rejects_any_other_change(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    other = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)

        def issue() -> str:
            response = http.post(
                "/v1/client/payee/evm/challenge",
                headers={"X-Api-Key": key},
                json={"address": owner.address},
            )
            assert response.status_code == 200, response.text
            text = response.json()["message"]
            assert text.endswith("\n")
            assert "\r" not in text
            return text

        def submit(message: str, signer=owner, address: str | None = None):
            return http.post(
                "/v1/client/payee/evm",
                headers={"X-Api-Key": key},
                json={"address": address or owner.address, "signature": _sign(signer, message)},
            )

        def unchanged() -> None:
            info = http.get("/v1/client", headers={"X-Api-Key": key}).json()
            assert info["payee_evm_address"] == owner.address
            assert info["payee_evm_verified"] is True

        message = issue()
        exact = submit(message)
        assert exact.status_code == 200, exact.text
        assert exact.json()["payee_evm_address"] == owner.address
        replay = submit(message)
        assert replay.status_code == 400
        assert replay.json()["error"] == "stale_challenge"
        unchanged()
        fresh = issue()
        again = submit(message)
        assert again.status_code == 400
        assert again.json()["error"] == "bad_signature"
        unchanged()
        assert fresh != message

        trimmed = issue()
        saved = submit(trimmed.rstrip(), address=owner.address.lower())
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_address"] == owner.address

        crlf = issue()
        saved = submit(crlf.replace("\n", "\r\n"))
        assert saved.status_code == 200, saved.text

        def rejected(edited: str, signer=owner) -> None:
            response = submit(edited, signer=signer)
            assert response.status_code == 400, response.text
            assert response.json()["error"] == "bad_signature"
            unchanged()

        nonce = issue()
        current = nonce.split("Nonce: ", 1)[1].split("\n", 1)[0]
        rejected(_swap_line(nonce, "Nonce: ", "0x" + "11" * 16))
        assert current not in ("0x" + "11" * 16)
        rejected(_swap_line(issue(), "Address: ", other.address))
        rejected(_swap_line(issue(), "Expires: ", "1"))
        rejected(_swap_line(issue(), "Domain: ", "not-satsgate"))
        rejected(" " + issue())
        rejected(issue(), signer=other)

        expired_message = issue()
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE clients SET payee_evm_pending_expires = 1")
        expired = submit(expired_message)
        assert expired.status_code == 400
        assert expired.json()["error"] == "stale_challenge"
        unchanged()


def test_verify_settle_replay_and_failures(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 25_000})
        _enable_x402(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        assert issued.status_code == 200, issued.text
        expires = issued.json()["expires_at"]
        required = issued.json()["payment_required"]
        encoded = _payload(required, buyer, expires)
        calls, post = _poster(buyer)
        _install_poster(post)

        verified = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["serve"] is True
        assert _credits(http, key) == before
        assert calls[0][0].endswith("/verify")
        assert calls[0][1]["paymentRequirements"]["amount"] == "25000"
        assert calls[0][1]["paymentRequirements"]["payTo"] == owner.address

        settled = _gate(
            http,
            "POST",
            "/internal/gate/x402/settle",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert settled.status_code == 200, settled.text
        assert settled.json()["charged"] == 1
        assert settled.json()["credits"] == before - 1
        decoded = json.loads(base64.b64decode(settled.headers["payment-response"]))
        assert decoded["success"] is True
        assert decoded["transaction"] == _TX
        assert decoded["tx"] == _TX
        assert decoded["network"] == "eip155:84532"
        assert decoded["payer"]
        assert _credits(http, key) == before - 1
        assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1

        replay = _gate(
            http,
            "POST",
            "/internal/gate/x402/settle",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["charged"] == 0
        assert replay.json()["replay"] is True
        assert _credits(http, key) == before - 1
        assert sum(1 for url, _body in calls if url.endswith("/settle")) == 1


def test_local_rejections_do_not_call_the_facilitator_or_debit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 25_000})
        _enable_x402(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        expires = issued.json()["expires_at"]
        required = issued.json()["payment_required"]
        calls, post = _poster(buyer)
        _install_poster(post)

        cases = [
            ("bad_signature", {"signature": "0x1234"}),
            ("amount_mismatch", {"accepted": {"amount": "1"}, "authorization": {"value": "1"}}),
            ("payto_mismatch", {"accepted": {"payTo": buyer.address}, "authorization": {"to": buyer.address}}),
            ("network_mismatch", {"accepted": {"network": "eip155:8453"}}),
            ("expired", {"authorization": {"validBefore": "1"}}),
        ]
        for code, change in cases:
            encoded = _payload(required, buyer, expires, **change)
            response = _gate(
                http,
                "POST",
                "/internal/gate/x402/verify",
                json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
            )
            assert response.status_code == 402, response.text
            assert response.json()["error"] == code
        assert calls == []
        assert _credits(http, key) == before

        stale = _payload(required, buyer, expires)
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE payment_offers SET expires_at = 1")
        expired = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": stale},
        )
        assert expired.status_code == 402
        assert expired.json()["error"] == "expired"
        assert calls == []


def test_settle_failure_does_not_consume_a_credit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 25_000})
        _enable_x402(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        encoded = _payload(issued.json()["payment_required"], buyer, issued.json()["expires_at"])
        calls, post = _poster(buyer, settle={"success": False, "errorReason": "insufficient_funds"})
        _install_poster(post)
        verified = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert verified.status_code == 200, verified.text
        failed = _gate(
            http,
            "POST",
            "/internal/gate/x402/settle",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert failed.status_code == 402, failed.text
        assert failed.json()["error"] == "x402_rejected"
        assert failed.json()["reason"] == "insufficient_funds"
        assert "payment-response" not in failed.headers
        assert _credits(http, key) == before
        assert any(url.endswith("/settle") for url, _body in calls)


def test_facilitator_rejects_a_signature_without_a_debit(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    buyer = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        before = _credits(http, key)
        _verify_payee(http, key, owner)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 25_000})
        _enable_x402(http, key)
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/paid"})
        encoded = _payload(issued.json()["payment_required"], buyer, issued.json()["expires_at"])
        _calls, post = _poster(buyer, verify={"isValid": False, "invalidReason": "invalid_signature"})
        _install_poster(post)
        rejected = _gate(
            http,
            "POST",
            "/internal/gate/x402/verify",
            json={"slug": "my-shop", "path": "/paid", "payment_signature": encoded},
        )
        assert rejected.status_code == 402
        assert rejected.json()["error"] == "x402_rejected"
        assert rejected.json()["reason"] == "invalid_signature"
        assert _credits(http, key) == before


def test_mainnet_network_env_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("SATSGATE_X402_NETWORK", "eip155:84532")
    try:
        _load_app(tmp_path, SATSGATE_X402_NETWORK="eip155:8453")
    except RuntimeError as exc:
        assert "eip155:84532" in str(exc)
    else:
        raise AssertionError("mainnet network was accepted")


def test_old_site_routes_keep_their_sats_price(tmp_path):
    db_path = tmp_path / "satsgate_test.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE site_routes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              site_id INTEGER NOT NULL,
              path_pattern TEXT NOT NULL,
              price_sats INTEGER NOT NULL,
              max_uses INTEGER,
              access_seconds INTEGER,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(site_id, path_pattern)
            )
            """
        )
        conn.execute(
            "INSERT INTO site_routes(site_id, path_pattern, price_sats, max_uses, access_seconds, created_at, updated_at) VALUES(1, '/blog/post', 21, 1, NULL, 10, 10)"
        )
    module = _load_app(tmp_path)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT price_sats, price_currency, price_usd_atomic FROM site_routes").fetchone()
        notnull = conn.execute("PRAGMA table_info(site_routes)").fetchall()
    assert row == (21, "sats", None)
    price = next(column for column in notnull if column[1] == "price_sats")
    assert price[3] == 0
    assert module.config.APP_VERSION == "0.14.1"


def test_address_change_clears_the_x402_rail(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    first = Account.create()
    second = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, first)
        _site(http, key, path="/paid", body={"price_currency": "usd", "price_usd_atomic": 1000})
        _enable_x402(http, key)
        challenge = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": second.address},
        )
        saved = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": second.address, "signature": _sign(second, challenge.json()["message"])},
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["rails_cleared"] is True
        site = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert site["rail_x402"] is False
