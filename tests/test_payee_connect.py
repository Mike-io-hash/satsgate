"""One-time EVM connect link. The account key never reaches the browser page."""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import os
import socket
import sqlite3
import sys
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
_SECRET_KEY = "ab" * 32
_FROZEN = 1_700_000_000
_CONNECT_ENV = (
    "SATSGATE_X402_PAYEE_CHALLENGE_SECONDS",
    "SATSGATE_PAYEE_CONNECT_SECONDS",
    "SATSGATE_CONNECT_PUBLIC_BASE",
)


@pytest.fixture(autouse=True)
def _drop_connect_env():
    yield
    for name in _CONNECT_ENV:
        os.environ.pop(name, None)


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
        "SATSGATE_GATE_TOKEN": "",
        "SATSGATE_GATE_PEERS": "",
        "SATSGATE_X402_NETWORK": "eip155:84532",
        "SATSGATE_X402_FACILITATOR_URL": "https://x402.org/facilitator",
        "SATSGATE_X402_CDP": "0",
        "SATSGATE_X402_CDP_KEY_ID": "",
        "SATSGATE_X402_CDP_KEY_SECRET": "",
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


def _sign(account, message: str, *, low_v: bool = False) -> str:
    signed = account.sign_message(encode_defunct(text=message))
    raw = bytearray(signed.signature)
    if low_v and raw[-1] >= 27:
        raw[-1] = raw[-1] - 27
    if not low_v and raw[-1] < 27:
        raw[-1] = raw[-1] + 27
    return "0x" + bytes(raw).hex()


def _token_from(url: str) -> str:
    base, fragment = url.split("#", 1)
    assert fragment.startswith("t=")
    token = fragment.removeprefix("t=")
    assert token.startswith("sgc_")
    assert token not in base
    return token


def _mint_link(http: TestClient, key: str) -> tuple[str, dict]:
    created = http.post("/v1/client/payee/evm/connect", headers={"X-Api-Key": key})
    assert created.status_code == 200, created.text
    body = created.json()
    return _token_from(body["connect_url"]), body


def _headers(token: str) -> dict[str, str]:
    return {"X-Connect-Token": token}


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


def _client_row():
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        return conn.execute(
            """
            SELECT payee_evm_address, payee_evm_verified_at, payee_evm_message, payee_evm_signature,
                   payee_evm_pending_message, payee_evm_pending_expires,
                   payee_evm_connect_hash, payee_evm_connect_expires
            FROM clients
            """
        ).fetchone()


def test_connect_link_requires_the_account_key(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        missing = http.post("/v1/client/payee/evm/connect")
        assert missing.status_code == 401
        key = _buy(http)
        minted = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": key},
            json={"label": "paywall"},
        )
        assert minted.status_code == 200, minted.text
        restricted = http.post(
            "/v1/client/payee/evm/connect",
            headers={"X-Api-Key": minted.json()["api_key"]},
        )
        assert restricted.status_code == 403
        assert restricted.json()["error"] == "insufficient_scope"
        created = http.post("/v1/client/payee/evm/connect", headers={"X-Api-Key": key})
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["ok"] is True
        assert body["connect_url"].startswith("https://satsgate.org/connect#t=sgc_")
        assert "expires_at" in body
        token = _token_from(body["connect_url"])
        assert token not in body["note"]


def test_token_is_hashed_and_absent_from_later_responses(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        key = _buy(http)
        token, body = _mint_link(http, key)
        assert set(body) == {"ok", "connect_url", "expires_at", "note"}
        db_path = Path(os.environ["SATSGATE_DB_PATH"])
        assert token.encode() not in db_path.read_bytes()
        with sqlite3.connect(db_path) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(clients)")}
            stored = conn.execute(
                "SELECT payee_evm_connect_hash FROM clients"
            ).fetchone()[0]
        assert "payee_evm_connect_hash" in cols
        assert "payee_evm_connect_expires" in cols
        assert stored == hashlib.sha256(token.encode()).hexdigest()
        assert token not in stored
        info = http.get("/v1/connect/evm", headers=_headers(token))
        assert info.status_code == 200, info.text
        assert token not in info.text
        client = http.get("/v1/client", headers={"X-Api-Key": key})
        assert token not in client.text
        listed = http.get("/v1/api-keys", headers={"X-Api-Key": key})
        assert token not in listed.text


def test_connect_happy_path_verifies_the_payee(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        info = http.get("/v1/connect/evm", headers=_headers(token))
        assert info.status_code == 200, info.text
        assert info.json()["current_payee_evm_address"] is None
        assert info.json()["current_payee_evm_verified"] is False
        assert info.json()["challenge_seconds"] == 1800
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": owner.address},
        )
        assert challenge.status_code == 200, challenge.text
        message = challenge.json()["message"]
        assert message.endswith("\n")
        assert message.splitlines()[0] == "Satsgate x402 payee"
        saved = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": _sign(owner, message)},
        )
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_address"] == owner.address
        assert saved.json()["payee_evm_verified"] is True
        assert saved.json()["rails_cleared"] is False
        assert "signature" not in saved.json()
        client = http.get("/v1/client", headers={"X-Api-Key": key})
        assert client.json()["payee_evm_verified"] is True
        assert client.json()["payee_evm_address"] == owner.address


def test_successful_verify_makes_the_token_single_use(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": owner.address},
        )
        saved = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": _sign(owner, challenge.json()["message"])},
        )
        assert saved.status_code == 200, saved.text
        for method, path, payload in (
            ("get", "/v1/connect/evm", None),
            ("post", "/v1/connect/evm/challenge", {"address": owner.address}),
            ("post", "/v1/connect/evm/verify", {"address": owner.address, "signature": "0x" + "11" * 65}),
        ):
            kwargs = {"headers": _headers(token)}
            if payload is not None:
                kwargs["json"] = payload
            again = getattr(http, method)(path, **kwargs)
            assert again.status_code == 401, again.text
            assert again.json()["error"] == "connect_link_invalid"
            assert token not in again.text


def test_expired_token_is_rejected(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE clients SET payee_evm_connect_expires = 1")
        info = http.get("/v1/connect/evm", headers=_headers(token))
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": owner.address},
        )
        verify = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": "0x" + "22" * 65},
        )
        for response in (info, challenge, verify):
            assert response.status_code == 401, response.text
            assert response.json()["error"] == "connect_link_invalid"


def test_a_new_link_invalidates_the_previous_one(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        key = _buy(http)
        first, _body = _mint_link(http, key)
        second, _body = _mint_link(http, key)
        assert first != second
        stale = http.get("/v1/connect/evm", headers=_headers(first))
        assert stale.status_code == 401
        assert stale.json()["error"] == "connect_link_invalid"
        fresh = http.get("/v1/connect/evm", headers=_headers(second))
        assert fresh.status_code == 200, fresh.text


def test_tokens_and_api_keys_are_not_interchangeable(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        as_api_key = http.get("/v1/balance", headers={"X-Api-Key": token})
        assert as_api_key.status_code == 401
        assert token not in as_api_key.text
        as_connect = http.get("/v1/connect/evm", headers={"X-Connect-Token": key})
        assert as_connect.status_code == 401
        assert as_connect.json()["error"] == "connect_link_invalid"
        api_key_only = http.get("/v1/connect/evm", headers={"X-Api-Key": key})
        assert api_key_only.status_code == 401
        assert api_key_only.json()["error"] == "connect_link_invalid"
        query = http.get(f"/v1/connect/evm?t={token}")
        assert query.status_code == 401
        assert query.json()["error"] == "connect_link_invalid"


def test_challenge_window_defaults_to_1800_and_clamps(tmp_path, monkeypatch):
    def window(**env: str) -> int:
        module = _load_app(tmp_path, **env)
        monkeypatch.setattr(module.db_x402.time, "time", lambda: _FROZEN)
        owner = Account.create()
        with TestClient(module.app) as http:
            key = _buy(http)
            response = http.post(
                "/v1/client/payee/evm/challenge",
                headers={"X-Api-Key": key},
                json={"address": owner.address},
            )
            assert response.status_code == 200, response.text
            return response.json()["expires_at"] - _FROZEN

    assert window() == 1800
    assert window(SATSGATE_X402_PAYEE_CHALLENGE_SECONDS="900") == 900
    assert window(SATSGATE_X402_PAYEE_CHALLENGE_SECONDS="299") == 300
    assert window(SATSGATE_X402_PAYEE_CHALLENGE_SECONDS="4000") == 3600


def test_connect_ttl_defaults_to_3600_and_clamps(tmp_path, monkeypatch):
    def ttl(**env: str) -> int:
        module = _load_app(tmp_path, **env)
        monkeypatch.setattr(module.db_x402.time, "time", lambda: _FROZEN)
        with TestClient(module.app) as http:
            key = _buy(http)
            _token, body = _mint_link(http, key)
            return body["expires_at"] - _FROZEN

    assert ttl() == 3600
    assert ttl(SATSGATE_PAYEE_CONNECT_SECONDS="1200") == 1200
    assert ttl(SATSGATE_PAYEE_CONNECT_SECONDS="599") == 600
    assert ttl(SATSGATE_PAYEE_CONNECT_SECONDS="90000") == 86400


def test_non_integer_windows_refuse_to_boot(tmp_path):
    with pytest.raises(RuntimeError, match="SATSGATE_X402_PAYEE_CHALLENGE_SECONDS"):
        _load_app(tmp_path, SATSGATE_X402_PAYEE_CHALLENGE_SECONDS="soon")
    os.environ.pop("SATSGATE_X402_PAYEE_CHALLENGE_SECONDS", None)
    with pytest.raises(RuntimeError, match="SATSGATE_PAYEE_CONNECT_SECONDS"):
        _load_app(tmp_path, SATSGATE_PAYEE_CONNECT_SECONDS="soon")


def test_connect_public_base_requires_an_https_path(tmp_path):
    with pytest.raises(RuntimeError, match="SATSGATE_CONNECT_PUBLIC_BASE"):
        _load_app(tmp_path, SATSGATE_CONNECT_PUBLIC_BASE="https://satsgate.org")
    module = _load_app(tmp_path, SATSGATE_CONNECT_PUBLIC_BASE="https://pay.example/connect/")
    assert module.config.CONNECT_PUBLIC_BASE == "https://pay.example/connect"


def test_connect_route_keeps_the_trimmed_signature_rule(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    other = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)

        def issue() -> str:
            response = http.post(
                "/v1/connect/evm/challenge",
                headers=_headers(token),
                json={"address": owner.address},
            )
            assert response.status_code == 200, response.text
            return response.json()["message"]

        def submit(message: str, *, address: str | None = None, signer=owner):
            return http.post(
                "/v1/connect/evm/verify",
                headers=_headers(token),
                json={"address": address or owner.address, "signature": _sign(signer, message)},
            )

        message = issue()
        for edited in (
            _swap_line(message, "Nonce: ", "0x" + "11" * 16),
            _swap_line(message, "Address: ", other.address),
            _swap_line(message, "Expires: ", "1"),
        ):
            rejected = submit(edited)
            assert rejected.status_code == 400, rejected.text
            assert rejected.json()["error"] == "bad_signature"
            still = http.get("/v1/connect/evm", headers=_headers(token))
            assert still.status_code == 200
        saved = submit(message.rstrip(), address=owner.address.lower())
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_address"] == owner.address
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            stored = conn.execute("SELECT payee_evm_message FROM clients").fetchone()[0]
        assert stored == message
        assert stored.endswith("\n")


def test_v_zero_and_twentyseven_both_verify(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        for low_v in (True, False):
            token, _body = _mint_link(http, key)
            challenge = http.post(
                "/v1/connect/evm/challenge",
                headers=_headers(token),
                json={"address": owner.address},
            )
            message = challenge.json()["message"]
            signature = _sign(owner, message, low_v=low_v)
            last = int(signature[-2:], 16)
            if low_v:
                assert last in (0, 1)
            else:
                assert last in (27, 28)
            saved = http.post(
                "/v1/connect/evm/verify",
                headers=_headers(token),
                json={"address": owner.address, "signature": signature},
            )
            assert saved.status_code == 200, saved.text
            with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
                stored = conn.execute("SELECT payee_evm_signature FROM clients").fetchone()[0]
            assert stored == signature


def test_long_signature_is_a_smart_wallet_and_changes_nothing(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": owner.address},
        )
        assert challenge.status_code == 200, challenge.text
        before = _client_row()
        rejected = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": "0x" + "ab" * 66},
        )
        assert rejected.status_code == 400, rejected.text
        assert rejected.json() == {"ok": False, "error": "smart_wallet_not_supported"}
        assert _client_row() == before
        account_route = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": owner.address, "signature": "0x" + "ab" * 66},
        )
        assert account_route.status_code == 422
        assert _client_row() == before


def test_a_failed_verify_keeps_the_token(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    stranger = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": owner.address},
        )
        message = challenge.json()["message"]
        bad = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": _sign(stranger, message)},
        )
        assert bad.status_code == 400
        assert bad.json()["error"] == "bad_signature"
        still = http.get("/v1/connect/evm", headers=_headers(token))
        assert still.status_code == 200
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE clients SET payee_evm_pending_expires = 1")
        stale = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": _sign(owner, message)},
        )
        assert stale.status_code == 400
        assert stale.json()["error"] == "stale_challenge"
        assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200


def test_address_change_clears_rails_and_the_same_address_does_not(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    other = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _body = _mint_link(http, key)
        challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": owner.address},
        )
        first = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": owner.address, "signature": _sign(owner, challenge.json()["message"])},
        )
        assert first.json()["rails_cleared"] is False
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
        approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert approved.status_code == 200, approved.text
        enabled = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True})
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["site"]["rail_x402"] is True

        same_token, _body = _mint_link(http, key)
        same_challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(same_token),
            json={"address": owner.address},
        )
        same = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(same_token),
            json={"address": owner.address, "signature": _sign(owner, same_challenge.json()["message"])},
        )
        assert same.status_code == 200, same.text
        assert same.json()["rails_cleared"] is False
        assert http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]["rail_x402"] is True

        next_token, _body = _mint_link(http, key)
        next_challenge = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(next_token),
            json={"address": other.address},
        )
        changed = http.post(
            "/v1/connect/evm/verify",
            headers=_headers(next_token),
            json={"address": other.address, "signature": _sign(other, next_challenge.json()["message"])},
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["rails_cleared"] is True
        site = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert site["rail_x402"] is False
        public = http.get("/v1/sites")
        assert public.status_code == 200
        assert "payTo" not in public.text
        assert owner.address not in public.text
        assert other.address not in public.text


def test_manifest_lists_the_connect_routes(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        endpoints = http.get("/.well-known/satsgate.json").json()["api"]["endpoints"]
    assert endpoints["evm_payee_connect"]["path"] == "/v1/client/payee/evm/connect"
    assert endpoints["connect_evm"]["path"] == "/v1/connect/evm"
    assert endpoints["connect_evm_challenge"]["path"] == "/v1/connect/evm/challenge"
    assert endpoints["connect_evm_verify"]["path"] == "/v1/connect/evm/verify"


def test_connect_routes_use_the_anonymous_rate_limit(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_RL_ENABLED="1",
        SATSGATE_RL_MAX_ANON="2",
        SATSGATE_RL_MAX_AUTH="50",
        SATSGATE_TRUSTED_PROXIES="",
    )
    with TestClient(module.app) as http:
        statuses = [
            http.get("/v1/connect/evm", headers={"X-Connect-Token": f"sgc_{'a' * 20}{i}"}).status_code
            for i in range(3)
        ]
    assert statuses == [401, 401, 429]
