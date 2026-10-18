"""Restricted API keys: permissions, resource prefix, revocation, and migration."""

from __future__ import annotations

import hashlib
import importlib
import os
import sqlite3
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]

_OLD_SCHEMA = """
CREATE TABLE clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_hash TEXT NOT NULL UNIQUE,
  credits INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  payee_lightning_address TEXT
);
CREATE TABLE ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  delta_credits INTEGER NOT NULL,
  reason TEXT NOT NULL,
  ref TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE topups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_hash TEXT NOT NULL UNIQUE,
  invoice TEXT NOT NULL,
  sats INTEGER NOT NULL,
  credits INTEGER NOT NULL,
  status TEXT NOT NULL,
  client_id INTEGER,
  created_at INTEGER NOT NULL,
  settled_at INTEGER,
  verify_url TEXT,
  requester_ip TEXT,
  expires_at INTEGER,
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  payment_hash TEXT NOT NULL,
  resource TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(client_id, payment_hash),
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE paywall_challenges (
  payment_hash TEXT PRIMARY KEY,
  client_id INTEGER NOT NULL,
  invoice TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  payee TEXT,
  resource TEXT NOT NULL,
  verify_url TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE ticket_challenges (
  payment_hash TEXT PRIMARY KEY,
  invoice TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  payee TEXT,
  resource TEXT NOT NULL,
  verify_url TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  settled_at INTEGER
);
"""

_ACCOUNT_ONLY = [
    ("get", "/v1/balance", None),
    ("get", "/v1/client", None),
    ("get", "/v1/ledger", None),
    ("get", "/v1/usage/summary", None),
    ("get", "/v1/usage/daily", None),
    ("get", "/v1/usage/forecast", None),
    ("get", "/v1/api-keys", None),
    ("get", "/v1/topup/trial", None),
    ("post", "/v1/client/payee", {"payee_lightning_address": "other@pay.example"}),
    ("post", "/v1/api-keys", {"label": "nope"}),
    ("post", "/v1/api-keys/1/revoke", None),
    ("post", "/v1/spend", None),
]


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
        "SATSGATE_TRUSTED_PROXIES": "",
        "SATSGATE_LN_NETWORK": "mainnet",
    }
    base.update(env)
    for key, value in base.items():
        os.environ[key] = value

    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)

    return importlib.import_module("app.main")


def _auth(macaroon: str, preimage_hex: str) -> str:
    return f"L402 {macaroon}:{preimage_hex}"


def _buy_client(client: TestClient) -> str:
    started = client.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = client.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert settled.status_code == 200, settled.text
    return settled.json()["api_key"]


def _challenge(client: TestClient, api_key: str, *, resource: str, amount_sats: int = 1, **extra) -> dict:
    response = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": resource, "amount_sats": amount_sats, **extra},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _pay(client: TestClient, challenge: dict) -> str:
    paid = client.get(f"/dev/mock/pay/{challenge['payment_hash']}")
    assert paid.status_code == 200, paid.text
    return _auth(challenge["macaroon"], paid.json()["preimage"])


def _mint(client: TestClient, account_key: str, **body) -> dict:
    payload = {"label": "proxy", **body}
    response = client.post("/v1/api-keys", headers={"X-Api-Key": account_key}, json=payload)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture()
def client(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        yield http


def test_create_list_shows_secret_once_and_stores_a_hash(client):
    account = _buy_client(client)
    assert account.startswith("sg_")
    assert not account.startswith("sgr_")

    created = _mint(client, account, label="  blog proxy  ", resource_prefix=" blog/ ")
    secret = created["api_key"]
    meta = created["key"]
    assert secret.startswith("sgr_")
    assert not secret.startswith("sg_")
    assert secret not in created["note"]
    assert meta["label"] == "blog proxy"
    assert meta["prefix"] == secret[:8]
    assert meta["scope"] == "paywall"
    assert meta["resource_prefix"] == "blog/"
    assert meta["last_used_at"] is None
    assert meta["revoked_at"] is None
    assert "key_hash" not in meta
    assert secret not in str(meta)

    listed = client.get("/v1/api-keys", headers={"X-Api-Key": account})
    assert listed.status_code == 200
    body = listed.json()
    assert secret not in listed.text
    assert body["keys"][0]["id"] == meta["id"]
    assert "api_key" not in body["keys"][0]

    db_path = os.environ["SATSGATE_DB_PATH"]
    raw = Path(db_path).read_bytes()
    assert secret.encode() not in raw
    assert account.encode() not in raw
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT key_hash, key_prefix FROM api_keys WHERE id = ?", (meta["id"],)).fetchone()
    assert row[0] == hashlib.sha256(secret.encode()).hexdigest()
    assert row[1] == secret[:8]
    assert account not in row[0]


def test_restricted_key_can_challenge_verify_and_status_and_debits_name_the_key(client):
    account = _buy_client(client)
    created = _mint(client, account, label="edge")
    restricted = created["api_key"]
    key_id = created["key"]["id"]

    challenge = _challenge(client, restricted, resource="api/premium", amount_sats=5)
    verified = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": restricted, "Authorization": _pay(client, challenge)},
        json={"expected_resource": "api/premium", "cost_credits": 1},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["charged_credits"] == 1

    other = _challenge(client, account, resource="api/other")
    status = client.get(
        f"/v1/paywall/status/{other['payment_hash']}",
        headers={"X-Api-Key": restricted, "Authorization": _pay(client, other)},
        params={"expected_resource": "api/other"},
    )
    assert status.status_code == 200, status.text
    assert status.json()["charged_credits"] == 1

    account_challenge = _challenge(client, account, resource="api/account")
    account_verify = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": account, "Authorization": _pay(client, account_challenge)},
        json={"expected_resource": "api/account"},
    )
    assert account_verify.status_code == 200, account_verify.text

    ledger = client.get("/v1/ledger", headers={"X-Api-Key": account})
    assert ledger.status_code == 200
    debits = [entry for entry in ledger.json()["entries"] if entry["reason"] == "paywall_verify"]
    by_resource = {entry["resource"]: entry for entry in debits}
    assert by_resource["api/premium"]["api_key_id"] == key_id
    assert by_resource["api/premium"]["api_key_label"] == "edge"
    assert by_resource["api/premium"]["api_key_prefix"] == restricted[:8]
    assert by_resource["api/other"]["api_key_id"] == key_id
    assert by_resource["api/account"]["api_key_id"] is None
    assert by_resource["api/account"]["api_key_label"] is None
    assert by_resource["api/account"]["resource"] == "api/account"

    summary = client.get("/v1/usage/summary", headers={"X-Api-Key": account})
    assert summary.status_code == 200
    buckets = {row["api_key_id"]: row for row in summary.json()["summary"]["by_api_key"]}
    assert buckets[key_id]["label"] == "edge"
    assert buckets[key_id]["verify_events"] == 2
    assert buckets[key_id]["credits_out"] == 2
    assert buckets[None]["verify_events"] == 1
    assert buckets[None]["label"] is None

    listed = client.get("/v1/api-keys", headers={"X-Api-Key": account}).json()["keys"]
    assert isinstance(listed[0]["last_used_at"], int)

    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        stored = conn.execute(
            "SELECT api_key_id FROM paywall_challenges WHERE payment_hash = ?",
            (challenge["payment_hash"],),
        ).fetchone()
    assert stored[0] == key_id


@pytest.mark.parametrize(("method", "path", "payload"), _ACCOUNT_ONLY)
def test_restricted_key_cannot_touch_account_routes(client, method, path, payload):
    account = _buy_client(client)
    restricted = _mint(client, account)["api_key"]
    before = client.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"]
    kwargs = {"headers": {"X-Api-Key": restricted}}
    if payload is not None:
        kwargs["json"] = payload
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"] == "insufficient_scope"
    assert body["scope"] == "paywall"
    assert client.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"] == before


def test_restricted_key_cannot_save_or_change_the_payee(client):
    account = _buy_client(client)
    restricted = _mint(client, account)["api_key"]

    attempted = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": restricted},
        json={
            "resource": "api/premium",
            "amount_sats": 1,
            "payee_lightning_address": "first@pay.example",
        },
    )
    assert attempted.status_code == 403
    assert attempted.json()["error"] == "insufficient_scope"
    assert client.get("/v1/client", headers={"X-Api-Key": account}).json()["payee_lightning_address"] is None

    saved = client.post(
        "/v1/client/payee",
        headers={"X-Api-Key": account},
        json={"payee_lightning_address": "merchant@pay.example"},
    )
    assert saved.status_code == 200, saved.text

    mismatch = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": restricted},
        json={
            "resource": "api/premium",
            "amount_sats": 1,
            "payee_lightning_address": "other@pay.example",
        },
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["error"] == "payee_mismatch"
    assert client.get("/v1/client", headers={"X-Api-Key": account}).json()["payee_lightning_address"] == "merchant@pay.example"

    allowed = _challenge(
        client,
        restricted,
        resource="api/premium",
        payee_lightning_address="merchant@pay.example",
    )
    assert allowed["payee_saved"] is False
    assert allowed["payee_lightning_address"] == "merchant@pay.example"


def test_resource_prefix_limits_challenge_verify_and_status(client):
    account = _buy_client(client)
    restricted = _mint(client, account, label="blog", resource_prefix="blog/")["api_key"]

    allowed = _challenge(client, restricted, resource="blog/post")
    assert allowed["resource"] == "blog/post"

    blocked = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": restricted},
        json={"resource": "blogger", "amount_sats": 1},
    )
    assert blocked.status_code == 403
    assert blocked.json()["error"] == "resource_not_allowed"
    assert blocked.json()["resource_prefix"] == "blog/"

    wrong_case = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": restricted},
        json={"resource": "Blog/post", "amount_sats": 1},
    )
    assert wrong_case.status_code == 403
    assert wrong_case.json()["error"] == "resource_not_allowed"

    foreign = _challenge(client, account, resource="shop/item")
    foreign_auth = _pay(client, foreign)
    rejected = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": restricted, "Authorization": foreign_auth},
        json={"expected_resource": "shop/item"},
    )
    assert rejected.status_code == 403
    assert rejected.json()["error"] == "resource_not_allowed"
    rejected_status = client.get(
        f"/v1/paywall/status/{foreign['payment_hash']}",
        headers={"X-Api-Key": restricted, "Authorization": foreign_auth},
        params={"expected_resource": "shop/item"},
    )
    assert rejected_status.status_code == 403
    assert rejected_status.json()["error"] == "resource_not_allowed"

    unlocked = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": restricted, "Authorization": _pay(client, allowed)},
        json={"expected_resource": "blog/post"},
    )
    assert unlocked.status_code == 200, unlocked.text
    assert unlocked.json()["charged_credits"] == 1

    # The same payment is still this client's. The account key can see the debit.
    balance = client.get("/v1/balance", headers={"X-Api-Key": account}).json()["credits"]
    assert balance == 200 - 1


def test_revoke_is_idempotent_and_stops_the_key(client):
    account = _buy_client(client)
    other = _buy_client(client)
    created = _mint(client, account, label="temp")
    secret = created["api_key"]
    key_id = created["key"]["id"]

    # Use it once so last_used_at is set, then revoke.
    _challenge(client, secret, resource="api/premium")

    first = client.post(f"/v1/api-keys/{key_id}/revoke", headers={"X-Api-Key": account})
    assert first.status_code == 200, first.text
    revoked_at = first.json()["key"]["revoked_at"]
    assert isinstance(revoked_at, int)

    again = client.post(f"/v1/api-keys/{key_id}/revoke", headers={"X-Api-Key": account})
    assert again.status_code == 200
    assert again.json()["key"]["revoked_at"] == revoked_at

    hidden = client.get("/v1/api-keys", headers={"X-Api-Key": account}).json()["keys"]
    assert hidden == []
    shown = client.get("/v1/api-keys", headers={"X-Api-Key": account}, params={"include_revoked": True}).json()["keys"]
    assert shown[0]["id"] == key_id
    assert shown[0]["revoked_at"] == revoked_at
    assert secret not in str(shown)

    blocked = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": secret},
        json={"resource": "api/premium", "amount_sats": 1},
    )
    assert blocked.status_code == 401
    assert blocked.json()["error"] == "api_key_revoked"

    stolen = client.post(f"/v1/api-keys/{key_id}/revoke", headers={"X-Api-Key": other})
    assert stolen.status_code == 404
    assert stolen.json()["error"] == "api_key_not_found"

    missing = client.post("/v1/api-keys/999999/revoke", headers={"X-Api-Key": account})
    assert missing.status_code == 404


def test_unknown_restricted_prefix_is_not_an_anonymous_topup(client):
    before = client.get("/v1/admin/overview", headers={"X-Admin-Token": "test-admin-token"}).json()
    response = client.get("/v1/topup/trial", headers={"X-Api-Key": "sgr_this-key-does-not-exist"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_api_key"
    # An unknown account-key-shaped header still starts an anonymous top-up.
    legacy = client.get("/v1/topup/trial", headers={"X-Api-Key": "sg_not-a-real-key"})
    assert legacy.status_code == 402
    assert before["ok"] is True


def test_active_key_cap(client):
    account = _buy_client(client)
    import app.db_keys as db_keys

    previous_cap = db_keys.MAX_ACTIVE_RESTRICTED_KEYS
    db_keys.MAX_ACTIVE_RESTRICTED_KEYS = 1
    try:
        first = _mint(client, account, label="one")
        second = client.post("/v1/api-keys", headers={"X-Api-Key": account}, json={"label": "two"})
        assert second.status_code == 409
        assert second.json()["error"] == "too_many_api_keys"
        client.post(f"/v1/api-keys/{first['key']['id']}/revoke", headers={"X-Api-Key": account})
        third = _mint(client, account, label="three")
        assert third["key"]["label"] == "three"
    finally:
        db_keys.MAX_ACTIVE_RESTRICTED_KEYS = previous_cap


def test_manifest_lists_key_routes(client):
    manifest = client.get("/.well-known/satsgate.json")
    assert manifest.status_code == 200
    endpoints = manifest.json()["api"]["endpoints"]
    assert endpoints["api_keys_create"]["path"] == "/v1/api-keys"
    assert endpoints["api_keys_revoke"]["path"] == "/v1/api-keys/{key_id}/revoke"


def test_migration_on_an_existing_database(tmp_path):
    """A pre-0.5.0 SQLite file gains columns and keeps its account key and rows."""
    db_path = tmp_path / "satsgate_test.sqlite3"
    legacy_key = "sg_legacy-account-key-value"
    legacy_hash = hashlib.sha256(legacy_key.encode()).hexdigest()
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_OLD_SCHEMA)
        conn.execute(
            "INSERT INTO clients(api_key_hash, credits, created_at, payee_lightning_address) VALUES(?, ?, ?, ?)",
            (legacy_hash, 42, now, "kept@pay.example"),
        )
        client_id = int(conn.execute("SELECT id FROM clients").fetchone()[0])
        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (client_id, 42, "topup_settled", "old-payment", now),
        )
        conn.execute(
            """
            INSERT INTO paywall_challenges(
              payment_hash, client_id, invoice, amount_sats, payee, resource, verify_url, created_at, expires_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("ab" * 32, client_id, "lnbc1old", 5, "kept@pay.example", "old/resource", None, now, now + 600),
        )
        conn.commit()
        before_tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "api_keys" not in before_tables
        ledger_cols = {row[1] for row in conn.execute("PRAGMA table_info(ledger)")}
        assert "api_key_id" not in ledger_cols

    module = _load_app(tmp_path)
    from app import db

    db.init_db(str(db_path))

    with sqlite3.connect(db_path) as conn:
        ledger_cols = {row[1] for row in conn.execute("PRAGMA table_info(ledger)")}
        challenge_cols = {row[1] for row in conn.execute("PRAGMA table_info(paywall_challenges)")}
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        stored_hash, credits, payee = conn.execute(
            "SELECT api_key_hash, credits, payee_lightning_address FROM clients"
        ).fetchone()
        old_ledger = conn.execute(
            "SELECT delta_credits, reason, ref, api_key_id, resource FROM ledger"
        ).fetchone()
        old_challenge = conn.execute(
            "SELECT resource, api_key_id FROM paywall_challenges WHERE payment_hash = ?",
            ("ab" * 32,),
        ).fetchone()
    assert "api_keys" in tables
    assert {"api_key_id", "resource"} <= ledger_cols
    assert "api_key_id" in challenge_cols
    assert stored_hash == legacy_hash
    assert credits == 42
    assert payee == "kept@pay.example"
    assert old_ledger == (42, "topup_settled", "old-payment", None, None)
    assert old_challenge == ("old/resource", None)

    with TestClient(module.app) as http:
        assert http.get("/health").json()["version"] == "0.10.0"
        balance = http.get("/v1/balance", headers={"X-Api-Key": legacy_key})
        assert balance.status_code == 200
        assert balance.json()["credits"] == 42
        info = http.get("/v1/client", headers={"X-Api-Key": legacy_key})
        assert info.json()["payee_lightning_address"] == "kept@pay.example"
        created = _mint(http, legacy_key, label="after-upgrade", resource_prefix="old/")
        assert created["api_key"].startswith("sgr_")
        ledger = http.get("/v1/ledger", headers={"X-Api-Key": legacy_key})
        assert ledger.status_code == 200
        old = [entry for entry in ledger.json()["entries"] if entry["ref"] == "old-payment"]
        assert old[0]["api_key_id"] is None
        assert old[0]["resource"] is None
        assert old[0]["delta_credits"] == 42


class _TestClientTransport(httpx.BaseTransport):
    """Drive the synchronous SDK through the FastAPI test client."""

    def __init__(self, app_client: TestClient) -> None:
        self._app = app_client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url.path
        if request.url.query:
            url = f"{url}?{request.url.query.decode()}"
        headers = {key: value for key, value in request.headers.items() if key.lower() != "host"}
        response = self._app.request(request.method, url, headers=headers, content=request.content)
        return httpx.Response(status_code=response.status_code, headers=dict(response.headers), content=response.content)


def test_sdk_creates_lists_and_revokes(tmp_path):
    module = _load_app(tmp_path)
    sdk_root = REPO_ROOT / "sdk" / "python" / "src"
    if str(sdk_root) not in sys.path:
        sys.path.insert(0, str(sdk_root))
    from satsgate_sdk import SatsgateClient, SatsgateError, __version__

    assert __version__ == "0.6.0"
    with TestClient(module.app) as http:
        account = _buy_client(http)
        sg = SatsgateClient(base_url="http://testserver", api_key=account)
        sg._http.close()
        sg._http = httpx.Client(transport=_TestClientTransport(http), base_url="http://testserver")
        try:
            created = sg.create_api_key(label="sdk-proxy", resource_prefix="sdk/")
            assert created["api_key"].startswith("sgr_")
            assert created["key"]["resource_prefix"] == "sdk/"
            listed = sg.list_api_keys()
            assert [row["id"] for row in listed["keys"]] == [created["key"]["id"]]
            blocked = SatsgateClient(base_url="http://testserver", api_key=created["api_key"])
            blocked._http.close()
            blocked._http = httpx.Client(transport=_TestClientTransport(http), base_url="http://testserver")
            try:
                with pytest.raises(SatsgateError) as raised:
                    blocked.balance()
                assert raised.value.status_code == 403
                assert raised.value.data["error"] == "insufficient_scope"
            finally:
                blocked.close()
            revoked = sg.revoke_api_key(created["key"]["id"])
            assert revoked["key"]["revoked_at"] is not None
            assert sg.list_api_keys()["keys"] == []
            assert sg.list_api_keys(include_revoked=True)["keys"][0]["id"] == created["key"]["id"]
        finally:
            sg.close()
