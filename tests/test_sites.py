"""Hosted-proxy sites registry: migration, SSRF checks, scopes, and the public list."""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
_SECRET_KEY = "ab" * 32

_REALISTIC_SCHEMA = """
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
  api_key_id INTEGER,
  resource TEXT,
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
  api_key_id INTEGER,
  max_uses INTEGER,
  access_seconds INTEGER,
  uses_consumed INTEGER NOT NULL DEFAULT 0,
  settled_at INTEGER,
  access_until INTEGER,
  buyer_ip_hash TEXT,
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  label TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource_prefix TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
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

_OLD_TABLES = (
    "clients",
    "ledger",
    "topups",
    "verifications",
    "paywall_challenges",
    "api_keys",
    "ticket_challenges",
)


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
        "SATSGATE_SITE_SECRET_KEY": _SECRET_KEY,
        "SATSGATE_SITES_AUTO_APPROVE": "0",
        "SATSGATE_SITES_MAX_PER_ACCOUNT": "3",
        "SATSGATE_SITES_MAX_ROUTES": "20",
        "SATSGATE_GATE_PUBLIC_BASE": "https://gate.satsgate.org",
        "SATSGATE_GATE_TOKEN": "",
        "SATSGATE_GATE_PEERS": "",
    }
    base.update(env)
    for key, value in base.items():
        os.environ[key] = value
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("app.main")


def _patch_dns(monkeypatch, module):
    answers = {"*": "1.1.1.1"}

    def fake(host, port, family=0, socktype=0, proto=0, flags=0):
        name = str(host).lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            chosen = name
        except ValueError:
            chosen = answers.get(name, answers["*"])
        if chosen is None:
            raise socket.gaierror(8, "no address")
        if isinstance(chosen, list):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in chosen]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (chosen, port))]

    monkeypatch.setattr(module.ssrf.socket, "getaddrinfo", fake)
    return answers


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


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]


def _create(http: TestClient, key: str, **extra) -> dict:
    payload = {
        "slug": "my-shop",
        "display_name": "My Shop",
        "description": "A stand",
        "origin_url": "https://origin.example/blog",
        "listed": True,
    }
    payload.update(extra)
    response = http.post("/v1/sites", headers={"X-Api-Key": key}, json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_migration_adds_tables_and_leaves_a_realistic_database(tmp_path, monkeypatch):
    db_path = tmp_path / "satsgate_test.sqlite3"
    legacy_key = "sg_legacy-account-key-value"
    legacy_hash = hashlib.sha256(legacy_key.encode()).hexdigest()
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_REALISTIC_SCHEMA)
        conn.execute(
            "INSERT INTO clients(api_key_hash, credits, created_at, payee_lightning_address) VALUES(?, ?, ?, ?)",
            (legacy_hash, 42, now, "kept@pay.example"),
        )
        client_id = int(conn.execute("SELECT id FROM clients").fetchone()[0])
        conn.execute(
            """
            INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at, api_key_id, resource)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (client_id, 42, "topup_settled", "old-payment", now, None, None),
        )
        conn.execute(
            """
            INSERT INTO paywall_challenges(
              payment_hash, client_id, invoice, amount_sats, payee, resource, verify_url,
              created_at, expires_at, api_key_id, max_uses, access_seconds, uses_consumed,
              settled_at, access_until, buyer_ip_hash
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("ab" * 32, client_id, "lnbc1old", 21, "kept@pay.example", "blog/post", None, now, now + 600, None, 1, None, 0, None, None, "digest"),
        )
        conn.execute(
            """
            INSERT INTO api_keys(
              client_id, key_hash, key_prefix, label, scope, resource_prefix, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (client_id, "hash", "sgr_abcd", "proxy", "paywall", "blog/", now),
        )
        before = {table: _columns(conn, table) for table in _OLD_TABLES}
        tables_before = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "sites" not in tables_before
        assert "site_routes" not in tables_before
        conn.commit()

    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    from app import db

    db.init_db(str(db_path))
    with sqlite3.connect(db_path) as conn:
        after = {table: _columns(conn, table) for table in _OLD_TABLES}
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        credits, payee = conn.execute("SELECT credits, payee_lightning_address FROM clients").fetchone()
        challenge = conn.execute(
            "SELECT resource, max_uses, uses_consumed, buyer_ip_hash FROM paywall_challenges"
        ).fetchone()
        key_row = conn.execute("SELECT label, scope, resource_prefix FROM api_keys").fetchone()
        site_count = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    assert after == before
    assert {"sites", "site_routes"} <= tables
    assert credits == 42
    assert payee == "kept@pay.example"
    assert challenge == ("blog/post", 1, 0, "digest")
    assert key_row == ("proxy", "paywall", "blog/")
    assert site_count == 0

    with TestClient(module.app) as http:
        assert http.get("/health").json() == {"ok": True, "version": "0.11.0"}
        balance = http.get("/v1/balance", headers={"X-Api-Key": legacy_key})
        assert balance.status_code == 200
        assert balance.json()["credits"] == 42


def test_origin_urls_reject_private_and_trick_targets(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    answers = _patch_dns(monkeypatch, module)
    from app.db_sites import OriginError, validate_origin_url

    assert validate_origin_url("https://origin.example/blog") == "https://origin.example/blog"
    assert validate_origin_url("https://origin.example:8443/a") == "https://origin.example:8443/a"

    answers["evil.example"] = "10.1.2.3"
    answers["mixed.example"] = ["1.1.1.1", "10.0.0.8"]
    answers["cgnat.example"] = "100.100.100.200"
    answers["meta.example"] = "169.254.169.254"
    answers["loop.example"] = "::1"

    rejected = [
        "http://origin.example",
        "https://user:pass@origin.example/a",
        "https://origin.example/a?x=1",
        "https://origin.example/a#frag",
        "https://origin.example/../../etc",
        "https://127.0.0.1/",
        "https://10.0.0.1/",
        "https://192.168.1.1/",
        "https://169.254.169.254/",
        "https://100.64.0.1/",
        "https://[::1]/",
        "https://[fc00::1]/",
        "https://localhost/",
        "https://metadata.google.internal/",
        "https://evil.example/",
        "https://mixed.example/",
        "https://cgnat.example/",
        "https://meta.example/",
        "https://2130706433/",
        "https://0177.0.0.1/",
        "https://0x7f000001/",
    ]
    for url in rejected:
        with pytest.raises(OriginError) as exc:
            validate_origin_url(url)
        assert exc.value.code in {"invalid_origin", "origin_rejected"}
        assert "10.1.2.3" not in exc.value.code


@pytest.fixture()
def http(tmp_path, monkeypatch):
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as client:
        yield client


def test_owner_crud_secret_once_and_routes(http: TestClient):
    account = _buy(http)
    created = _create(http, account)
    secret = created["origin_secret"]
    site = created["site"]
    assert secret not in created["note"]
    assert "origin_secret" not in site
    assert site["status"] == "pending"
    assert site["gate_url"] == "https://gate.satsgate.org/my-shop/"
    assert site["origin_url"] == "https://origin.example/blog"
    assert len(secret) == 64
    assert site["secret_fingerprint"]

    db_path = os.environ["SATSGATE_DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        blob = conn.execute("SELECT origin_secret_ciphertext FROM sites").fetchone()[0]
    assert secret not in blob

    from app.db_sites import load_origin_secret

    site_id = site["id"]
    assert load_origin_secret(db_path, site_id=site_id) == secret

    listed = http.get("/v1/sites/mine", headers={"X-Api-Key": account})
    assert listed.status_code == 200
    assert secret not in listed.text
    assert listed.json()["sites"][0]["slug"] == "my-shop"

    fetched = http.get("/v1/sites/my-shop", headers={"X-Api-Key": account})
    assert secret not in fetched.text

    route = http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": account},
        json={"path": "/blog/post", "price_sats": 21, "max_uses": 1, "access_seconds": 3600},
    )
    assert route.status_code == 200, route.text
    assert route.json()["route"]["max_uses"] == 1
    assert route.json()["route"]["access_seconds"] == 3600
    route_id = route.json()["route"]["id"]

    changed = http.patch(
        f"/v1/sites/my-shop/routes/{route_id}",
        headers={"X-Api-Key": account},
        json={"price_sats": 42, "max_uses": None},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["route"]["price_sats"] == 42
    assert changed.json()["route"]["max_uses"] is None
    assert changed.json()["route"]["access_seconds"] == 3600

    rotated = http.post("/v1/sites/my-shop/rotate-secret", headers={"X-Api-Key": account})
    assert rotated.status_code == 200, rotated.text
    new_secret = rotated.json()["origin_secret"]
    assert new_secret != secret
    assert rotated.json()["site"]["secret_fingerprint"] != site["secret_fingerprint"]
    again = http.get("/v1/sites/my-shop", headers={"X-Api-Key": account})
    assert new_secret not in again.text
    assert secret not in again.text
    assert load_origin_secret(db_path, site_id=site_id) == new_secret

    removed = http.delete(f"/v1/sites/my-shop/routes/{route_id}", headers={"X-Api-Key": account})
    assert removed.status_code == 200
    deleted = http.delete("/v1/sites/my-shop", headers={"X-Api-Key": account})
    assert deleted.status_code == 200
    missing = http.get("/v1/sites/my-shop", headers={"X-Api-Key": account})
    assert missing.status_code == 404
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM site_routes").fetchone()[0] == 0


def test_scopes_limits_and_other_owners(http: TestClient, monkeypatch):
    account = _buy(http)
    other = _buy(http)
    paywall = http.post("/v1/api-keys", headers={"X-Api-Key": account}, json={"label": "proxy"}).json()["api_key"]
    reader = http.post(
        "/v1/api-keys",
        headers={"X-Api-Key": account},
        json={"label": "read", "scope": "sites:read"},
    ).json()["api_key"]
    writer = http.post(
        "/v1/api-keys",
        headers={"X-Api-Key": account},
        json={"label": "write", "scope": "sites:write", "resource_prefix": "blog/"},
    )
    assert writer.status_code == 400
    assert writer.json()["error"] == "resource_prefix_not_allowed"
    writer_key = http.post(
        "/v1/api-keys",
        headers={"X-Api-Key": account},
        json={"label": "write", "scope": "sites:write"},
    ).json()["api_key"]

    denied = http.post(
        "/v1/sites",
        headers={"X-Api-Key": paywall},
        json={"slug": "my-shop", "display_name": "Shop", "origin_url": "https://origin.example"},
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "insufficient_scope"

    read_denied = http.post(
        "/v1/sites",
        headers={"X-Api-Key": reader},
        json={"slug": "my-shop", "display_name": "Shop", "origin_url": "https://origin.example"},
    )
    assert read_denied.status_code == 403

    created = _create(http, writer_key, slug="my-shop")
    assert created["site"]["status"] == "pending"
    assert http.get("/v1/sites/mine", headers={"X-Api-Key": reader}).status_code == 200
    assert http.get("/v1/sites/my-shop", headers={"X-Api-Key": other}).status_code == 404
    challenge = http.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": writer_key},
        json={"resource": "blog/post", "amount_sats": 1},
    )
    assert challenge.status_code == 403
    assert challenge.json()["error"] == "insufficient_scope"
    balance = http.get("/v1/balance", headers={"X-Api-Key": writer_key})
    assert balance.status_code == 403

    still = http.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": account},
        json={"resource": "blog/post", "amount_sats": 1, "payee_lightning_address": "kept@pay.example"},
    )
    assert still.status_code == 200, still.text

    from app import config

    monkeypatch.setattr(config, "SITES_MAX_PER_ACCOUNT", 1)
    capped = http.post(
        "/v1/sites",
        headers={"X-Api-Key": account},
        json={"slug": "second-shop", "display_name": "Two", "origin_url": "https://origin.example"},
    )
    assert capped.status_code == 409
    assert capped.json()["error"] == "site_limit"
    monkeypatch.setattr(config, "SITES_MAX_ROUTES", 1)
    first = http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": writer_key},
        json={"path": "/one", "price_sats": 21},
    )
    assert first.status_code == 200, first.text
    second = http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": writer_key},
        json={"path": "/two", "price_sats": 21},
    )
    assert second.status_code == 409
    assert second.json()["error"] == "route_limit"

    bad = http.post(
        "/v1/sites",
        headers={"X-Api-Key": account},
        json={"slug": "admin", "display_name": "Nope", "origin_url": "https://origin.example"},
    )
    assert bad.status_code == 400
    assert bad.json()["error"] == "slug_reserved"
    private = http.post(
        "/v1/sites",
        headers={"X-Api-Key": account},
        json={"slug": "other-shop", "display_name": "Nope", "origin_url": "https://127.0.0.1"},
    )
    assert private.status_code == 400
    assert private.json()["error"] == "origin_rejected"
    assert "127.0.0.1" not in private.text


def test_public_list_requires_approval_and_opt_in(http: TestClient):
    account = _buy(http)
    _create(http, account, listed=True)
    http.post(
        "/v1/sites/my-shop/routes",
        headers={"X-Api-Key": account},
        json={"path": "/post", "price_sats": 21, "max_uses": 1},
    )
    hidden = http.get("/v1/sites")
    assert hidden.status_code == 200
    assert hidden.json()["sites"] == []
    assert hidden.json()["hosted_registry"] is True

    no_token = http.post("/v1/admin/sites/my-shop/approve")
    assert no_token.status_code == 401
    bad = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "nope"})
    assert bad.status_code == 401
    approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
    assert approved.status_code == 200, approved.text
    assert "origin_secret" not in approved.json()["site"]
    assert approved.json()["site"]["client_id"]
    secret_blob = sqlite3.connect(os.environ["SATSGATE_DB_PATH"]).execute(
        "SELECT origin_secret_ciphertext FROM sites"
    ).fetchone()[0]
    assert secret_blob not in approved.text

    public = http.get("/v1/sites")
    body = public.json()
    assert body["hosted_registry"] is True
    assert body["sites"][0]["name"] == "My Shop"
    assert body["sites"][0]["url"] == "https://gate.satsgate.org/my-shop/"
    assert body["sites"][0]["slug"] == "my-shop"
    assert body["sites"][0]["routes"][0]["price_sats"] == 21
    assert "origin_url" not in body["sites"][0]
    assert "client_id" not in body["sites"][0]
    assert "secret" not in public.text

    unlisted = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": account}, json={"listed": False})
    assert unlisted.status_code == 200
    assert http.get("/v1/sites").json()["sites"] == []
    http.patch("/v1/sites/my-shop", headers={"X-Api-Key": account}, json={"listed": True})
    assert len(http.get("/v1/sites").json()["sites"]) == 1
    disabled = http.post("/v1/admin/sites/my-shop/disable", headers={"X-Admin-Token": "test-admin-token"})
    assert disabled.status_code == 200
    assert http.get("/v1/sites").json()["sites"] == []
    pending = http.get("/v1/admin/sites", headers={"X-Admin-Token": "test-admin-token"}, params={"status": "disabled"})
    assert pending.status_code == 200
    assert pending.json()["sites"][0]["slug"] == "my-shop"
    assert "origin_secret" not in pending.text


def test_auto_approve_is_opt_in(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="1")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        account = _buy(http)
        created = _create(http, account, listed=True)
        assert created["site"]["status"] == "approved"
        assert http.get("/v1/sites").json()["sites"][0]["slug"] == "my-shop"


def test_admin_routes_hide_when_the_token_is_unset(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_ADMIN_TOKEN="")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        assert http.post("/v1/admin/sites/my-shop/approve").status_code == 404
        assert http.get("/v1/admin/sites").status_code == 404
        assert http.get("/health").json()["version"] == "0.11.0"


def test_missing_site_secret_key_refuses_create_and_boots(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITE_SECRET_KEY="")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        assert http.get("/health").json()["version"] == "0.11.0"
        account = _buy(http)
        response = http.post(
            "/v1/sites",
            headers={"X-Api-Key": account},
            json={"slug": "my-shop", "display_name": "Shop", "origin_url": "https://origin.example"},
        )
        assert response.status_code == 503
        assert response.json()["error"] == "site_secret_key_unconfigured"
