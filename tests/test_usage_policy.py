"""Per-challenge usage policy: bundles, time passes, and a race-safe consume."""

from __future__ import annotations

import hashlib
import importlib
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]

_V05_SCHEMA = """
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


def _verify(client: TestClient, api_key: str, authorization: str, resource: str, **extra) -> httpx.Response:
    return client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": authorization},
        json={"expected_resource": resource, **extra},
    )


def _status(client: TestClient, api_key: str, challenge: dict, authorization: str, resource: str, **params) -> httpx.Response:
    return client.get(
        f"/v1/paywall/status/{challenge['payment_hash']}",
        headers={"X-Api-Key": api_key, "Authorization": authorization},
        params={"expected_resource": resource, **params},
    )


def _balance(client: TestClient, api_key: str) -> int:
    response = client.get("/v1/balance", headers={"X-Api-Key": api_key})
    assert response.status_code == 200, response.text
    return int(response.json()["credits"])


def _uses(payment_hash: str) -> int:
    from app import config, db

    row = db.get_paywall_challenge(config.DB_PATH, payment_hash)
    assert row is not None
    return int(row["uses_consumed"] or 0)


@pytest.fixture()
def client(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        yield http


def test_no_policy_still_replays_for_free_and_consume_does_not_count(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/plain")
    assert challenge["max_uses"] is None
    assert challenge["access_seconds"] is None
    assert challenge["uses_consumed"] == 0
    assert challenge["uses_remaining"] is None
    assert challenge["access_until"] is None
    assert challenge["settled_at"] is None
    assert "token_used_up" not in challenge["note"]
    assert "cache_until" in challenge["note"]

    authorization = _pay(client, challenge)
    first = _verify(client, api_key, authorization, "api/plain")
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["charged_credits"] == 1
    assert body["uses_remaining"] is None
    assert body["uses_consumed"] == 0
    assert body["access_until"] is None
    assert body["consumed"] is False
    assert body["settled_at"] is not None
    assert "cache_until" in body["note"]
    assert "token_used_up" not in body["note"]

    again = _verify(client, api_key, authorization, "api/plain")
    assert again.status_code == 200, again.text
    assert again.json()["charged_credits"] == 0
    assert again.json()["uses_consumed"] == 0

    consumed = _verify(client, api_key, authorization, "api/plain", consume=True)
    assert consumed.status_code == 200, consumed.text
    assert consumed.json()["consumed"] is True
    assert consumed.json()["charged_credits"] == 0
    assert consumed.json()["uses_consumed"] == 0
    assert _balance(client, api_key) == 199


def test_max_uses_one_then_token_used_up_and_a_check_still_works(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/once", max_uses=1)
    assert challenge["uses_remaining"] == 1
    assert "token_used_up" in challenge["note"]
    authorization = _pay(client, challenge)

    first = _verify(client, api_key, authorization, "api/once", consume=True)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["charged_credits"] == 1
    assert body["consumed"] is True
    assert body["uses_consumed"] == 1
    assert body["uses_remaining"] == 0
    assert body["max_uses"] == 1
    assert body["access_seconds"] is None
    from app import config

    assert abs(body["access_until"] - (body["settled_at"] + config.PAYWALL_ACCESS_CAP_SECONDS)) <= 2

    denied = _verify(client, api_key, authorization, "api/once", consume=True)
    assert denied.status_code == 401
    error = denied.json()
    assert error["error"] == "token_used_up"
    assert error["ok"] is False
    assert error["settled"] is True
    assert error["charged_credits"] == 0
    assert error["uses_remaining"] == 0
    assert error["consumed"] is False
    assert "new challenge" in error["detail"]

    checked = _status(client, api_key, challenge, authorization, "api/once", consume=False)
    assert checked.status_code == 200, checked.text
    assert checked.json()["uses_remaining"] == 0
    assert checked.json()["consumed"] is False
    assert checked.json()["charged_credits"] == 0
    assert _balance(client, api_key) == 199
    assert _uses(challenge["payment_hash"]) == 1


def test_bundle_charges_once_across_verify_and_status(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/bundle", max_uses=3, access_seconds=3600)
    authorization = _pay(client, challenge)

    peeked = _verify(client, api_key, authorization, "api/bundle", consume=False)
    assert peeked.status_code == 200, peeked.text
    assert peeked.json()["charged_credits"] == 1
    assert peeked.json()["uses_consumed"] == 0
    assert peeked.json()["uses_remaining"] == 3
    assert peeked.json()["consumed"] is False
    assert abs(peeked.json()["access_until"] - (peeked.json()["settled_at"] + 3600)) <= 2

    for remaining in (2, 1, 0):
        taken = _status(client, api_key, challenge, authorization, "api/bundle", consume=True)
        assert taken.status_code == 200, taken.text
        assert taken.json()["consumed"] is True
        assert taken.json()["uses_remaining"] == remaining
        assert taken.json()["charged_credits"] == 0

    denied = _verify(client, api_key, authorization, "api/bundle", consume=True)
    assert denied.status_code == 401
    assert denied.json()["error"] == "token_used_up"
    assert denied.json()["charged_credits"] == 0
    assert _balance(client, api_key) == 199


def test_access_seconds_expires_and_expiry_wins_when_uses_are_also_gone(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/hour", access_seconds=120, max_uses=1)
    authorization = _pay(client, challenge)
    opened = _verify(client, api_key, authorization, "api/hour", consume=False)
    assert opened.status_code == 200, opened.text
    assert abs(opened.json()["access_until"] - (opened.json()["settled_at"] + 120)) <= 2
    assert opened.json()["uses_remaining"] == 1

    from app import config, db

    frozen = int(time.time()) + 50
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET access_until = ? WHERE payment_hash = ?",
            (frozen, challenge["payment_hash"]),
        )

    original = time.time
    time.time = lambda: frozen
    try:
        at_deadline = _verify(client, api_key, authorization, "api/hour", consume=True)
    finally:
        time.time = original
    assert at_deadline.status_code == 200, at_deadline.text
    assert at_deadline.json()["consumed"] is True
    assert at_deadline.json()["uses_remaining"] == 0
    assert at_deadline.json()["charged_credits"] == 0

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET access_until = ? WHERE payment_hash = ?",
            (frozen - 1, challenge["payment_hash"]),
        )
    time.time = lambda: frozen
    try:
        expired = _verify(client, api_key, authorization, "api/hour", consume=True)
        still_visible = _status(client, api_key, challenge, authorization, "api/hour")
    finally:
        time.time = original

    assert expired.status_code == 401
    assert expired.json()["error"] == "token_expired"
    assert expired.json()["charged_credits"] == 0
    assert expired.json()["uses_remaining"] == 0
    assert "new challenge" in expired.json()["detail"]
    assert still_visible.status_code == 200, still_visible.text
    assert still_visible.json()["uses_remaining"] == 0
    assert still_visible.json()["access_until"] == frozen - 1
    assert _balance(client, api_key) == 199


def test_time_pass_without_a_use_cap_expires(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/pass", access_seconds=60)
    authorization = _pay(client, challenge)
    opened = _verify(client, api_key, authorization, "api/pass", consume=True)
    assert opened.status_code == 200, opened.text
    assert opened.json()["uses_remaining"] is None
    assert opened.json()["uses_consumed"] == 1
    assert opened.json()["max_uses"] is None

    from app import config, db

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET access_until = ? WHERE payment_hash = ?",
            (int(time.time()) - 5, challenge["payment_hash"]),
        )
    denied = _verify(client, api_key, authorization, "api/pass", consume=True)
    assert denied.status_code == 401
    assert denied.json()["error"] == "token_expired"
    assert denied.json()["uses_remaining"] is None
    checked = _verify(client, api_key, authorization, "api/pass", consume=False)
    assert checked.status_code == 200
    assert checked.json()["consumed"] is False


def test_consume_before_payment_does_not_take_a_use(client):
    from app import config, db
    from app.invoices import InvoiceValidationError
    from app import wallet_lnaddr

    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/wait", max_uses=1)
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + challenge["payment_hash"], challenge["payment_hash"]),
        )

    def _not_settled(**kwargs):
        assert kwargs["preimage_hex"] is None
        raise InvoiceValidationError("lud21_not_settled")

    original = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _not_settled
    try:
        pending = _verify(client, api_key, f"L402 {challenge['macaroon']}", "api/wait", consume=True)
    finally:
        wallet_lnaddr.confirm_lud21 = original

    assert pending.status_code == 402
    assert pending.json()["error"] == "payment_pending"
    assert _uses(challenge["payment_hash"]) == 0
    assert _balance(client, api_key) == 200


def test_insufficient_balance_takes_no_use(client):
    from app import config, db

    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/broke", max_uses=2)
    authorization = _pay(client, challenge)
    with db._connect(config.DB_PATH) as conn:
        conn.execute("UPDATE clients SET credits = 0")
    denied = _verify(client, api_key, authorization, "api/broke", consume=True)
    assert denied.status_code == 402
    assert denied.json()["error"] == "insufficient balance"
    assert _uses(challenge["payment_hash"]) == 0

    with db._connect(config.DB_PATH) as conn:
        conn.execute("UPDATE clients SET credits = 3")
    opened = _verify(client, api_key, authorization, "api/broke", consume=True)
    assert opened.status_code == 200, opened.text
    assert opened.json()["charged_credits"] == 1
    assert opened.json()["uses_remaining"] == 1


def test_access_seconds_over_the_configured_cap_is_rejected(client):
    from app import config

    api_key = _buy_client(client)
    previous = config.PAYWALL_ACCESS_CAP_SECONDS
    config.PAYWALL_ACCESS_CAP_SECONDS = 120
    try:
        too_long = client.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": api_key},
            json={"resource": "api/long", "amount_sats": 1, "access_seconds": 121},
        )
        assert too_long.status_code == 400
        assert too_long.json()["error"] == "access_seconds_too_long"
        assert too_long.json()["max_access_seconds"] == 120
        accepted = _challenge(client, api_key, resource="api/long", access_seconds=120)
        assert accepted["access_seconds"] == 120
    finally:
        config.PAYWALL_ACCESS_CAP_SECONDS = previous

    zero = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "api/long", "amount_sats": 1, "max_uses": 0},
    )
    assert zero.status_code == 422
    huge = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "api/long", "amount_sats": 1, "access_seconds": 604801},
    )
    assert huge.status_code == 422


def test_restricted_key_can_set_a_policy_inside_its_prefix(client):
    account = _buy_client(client)
    minted = client.post(
        "/v1/api-keys",
        headers={"X-Api-Key": account},
        json={"label": "blog", "resource_prefix": "blog/"},
    )
    assert minted.status_code == 200, minted.text
    restricted = minted.json()["api_key"]
    key_id = minted.json()["key"]["id"]

    blocked = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": restricted},
        json={"resource": "other/post", "amount_sats": 1, "max_uses": 1},
    )
    assert blocked.status_code == 403
    assert blocked.json()["error"] == "resource_not_allowed"

    challenge = _challenge(client, restricted, resource="blog/post", max_uses=1)
    authorization = _pay(client, challenge)
    opened = _verify(client, restricted, authorization, "blog/post", consume=True)
    assert opened.status_code == 200, opened.text
    assert opened.json()["uses_remaining"] == 0
    denied = _status(client, restricted, challenge, authorization, "blog/post", consume=True)
    assert denied.status_code == 401
    assert denied.json()["error"] == "token_used_up"

    ledger = client.get("/v1/ledger", headers={"X-Api-Key": account}).json()["entries"]
    debits = [entry for entry in ledger if entry["reason"] == "paywall_verify"]
    assert len(debits) == 1
    assert debits[0]["api_key_id"] == key_id
    assert debits[0]["resource"] == "blog/post"
    assert debits[0]["delta_credits"] == -1
    assert _balance(client, account) == 199


def test_settled_policy_rows_outlive_invoice_cleanup(client):
    api_key = _buy_client(client)
    kept = _challenge(client, api_key, resource="api/keep", max_uses=2, access_seconds=3600)
    kept_auth = _pay(client, kept)
    opened = _verify(client, api_key, kept_auth, "api/keep", consume=True)
    assert opened.status_code == 200, opened.text

    plain = _challenge(client, api_key, resource="api/drop")
    plain_auth = _pay(client, plain)
    assert _verify(client, api_key, plain_auth, "api/drop").status_code == 200

    from app import config, db

    ancient = int(time.time()) - 10 * 24 * 60 * 60
    future = int(time.time()) + 3600
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET created_at = ?, expires_at = ?, access_until = ? WHERE payment_hash = ?",
            (ancient, ancient, future, kept["payment_hash"]),
        )
        conn.execute(
            "UPDATE paywall_challenges SET created_at = ?, expires_at = ? WHERE payment_hash = ?",
            (ancient, ancient, plain["payment_hash"]),
        )

    _challenge(client, api_key, resource="api/trigger-cleanup")
    assert db.get_paywall_challenge(config.DB_PATH, kept["payment_hash"]) is not None
    assert db.get_paywall_challenge(config.DB_PATH, plain["payment_hash"]) is None

    still = _verify(client, api_key, kept_auth, "api/keep", consume=True)
    assert still.status_code == 200, still.text
    assert still.json()["uses_remaining"] == 0
    assert still.json()["charged_credits"] == 0

    gone = _verify(client, api_key, plain_auth, "api/drop", consume=True)
    assert gone.status_code == 401
    assert gone.json()["error"] == "client mismatch"

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET access_until = ? WHERE payment_hash = ?",
            (int(time.time()) - 2 * 24 * 60 * 60, kept["payment_hash"]),
        )
    _challenge(client, api_key, resource="api/trigger-cleanup-2")
    assert db.get_paywall_challenge(config.DB_PATH, kept["payment_hash"]) is None


def _race(db_path: str, *, client_id: int, payment_hash: str, resource: str, n: int) -> list:
    from app import config, db_verify

    barrier = threading.Barrier(n)
    results: list = [None] * n

    def worker(index: int) -> None:
        barrier.wait()
        try:
            spent = db_verify.settle_and_consume(
                db_path,
                client_id=client_id,
                payment_hash=payment_hash,
                cost=1,
                resource=resource,
                api_key_id=None,
                consume=True,
                access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
            )
            results[index] = ("ok", spent)
        except db_verify.UsageDenied as exc:
            results[index] = ("deny", exc)
        except Exception as exc:  # noqa: BLE001
            results[index] = ("err", exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def test_concurrent_consumes_cannot_share_the_last_use(client):
    from app import config, db, db_verify

    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/race", max_uses=1)
    _pay(client, challenge)
    row = db.get_paywall_challenge(config.DB_PATH, challenge["payment_hash"])
    results = _race(
        config.DB_PATH,
        client_id=int(row["client_id"]),
        payment_hash=challenge["payment_hash"],
        resource="api/race",
        n=8,
    )
    assert all(item is not None and item[0] != "err" for item in results), results
    wins = [item[1] for item in results if item[0] == "ok"]
    losses = [item[1] for item in results if item[0] == "deny"]
    assert len(wins) == 1
    assert len(losses) == 7
    assert wins[0]["charged"] == 1
    assert wins[0]["uses_remaining"] == 0
    assert all(loss.code == "token_used_up" and loss.charged == 0 for loss in losses)
    assert sum(item[1]["charged"] if item[0] == "ok" else item[1].charged for item in results) == 1
    assert _balance(client, api_key) == 199
    assert _uses(challenge["payment_hash"]) == 1

    bundle = _challenge(client, api_key, resource="api/race-bundle", max_uses=4)
    _pay(client, bundle)
    bundle_row = db.get_paywall_challenge(config.DB_PATH, bundle["payment_hash"])
    bundle_results = _race(
        config.DB_PATH,
        client_id=int(bundle_row["client_id"]),
        payment_hash=bundle["payment_hash"],
        resource="api/race-bundle",
        n=10,
    )
    assert all(item[0] != "err" for item in bundle_results), bundle_results
    assert sum(1 for item in bundle_results if item[0] == "ok") == 4
    assert sum(1 for item in bundle_results if item[0] == "deny") == 6
    assert sum(item[1]["charged"] if item[0] == "ok" else item[1].charged for item in bundle_results) == 1
    assert all(item[1].code == "token_used_up" for item in bundle_results if item[0] == "deny")
    assert _uses(bundle["payment_hash"]) == 4
    assert _balance(client, api_key) == 198
    # The helper stays the public race primitive. A direct call agrees with the HTTP counter.
    with pytest.raises(db_verify.UsageDenied) as raised:
        db_verify.settle_and_consume(
            config.DB_PATH,
            client_id=int(bundle_row["client_id"]),
            payment_hash=bundle["payment_hash"],
            cost=1,
            resource="api/race-bundle",
            api_key_id=None,
            consume=True,
            access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
        )
    assert raised.value.code == "token_used_up"
    assert raised.value.charged == 0


def test_migration_from_a_v05_database_keeps_unlimited_grants(tmp_path):
    db_path = tmp_path / "satsgate_test.sqlite3"
    legacy_key = "sg_legacy-account-key-value"
    legacy_hash = hashlib.sha256(legacy_key.encode()).hexdigest()
    now = int(time.time())
    paid = "ab" * 32
    unpaid = "cd" * 32
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_V05_SCHEMA)
        challenge_cols = {row[1] for row in conn.execute("PRAGMA table_info(paywall_challenges)")}
        assert "max_uses" not in challenge_cols
        assert "uses_consumed" not in challenge_cols
        conn.execute(
            "INSERT INTO clients(api_key_hash, credits, created_at) VALUES(?, ?, ?)",
            (legacy_hash, 10, now),
        )
        client_id = int(conn.execute("SELECT id FROM clients").fetchone()[0])
        for payment_hash, resource in ((paid, "old/paid"), (unpaid, "old/open")):
            conn.execute(
                """
                INSERT INTO paywall_challenges(
                  payment_hash, client_id, invoice, amount_sats, payee, resource, verify_url, created_at, expires_at, api_key_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (payment_hash, client_id, "lnbc1old", 5, None, resource, None, now, now + 3600, None),
            )
        conn.execute(
            "INSERT INTO verifications(client_id, payment_hash, resource, created_at) VALUES(?, ?, ?, ?)",
            (client_id, paid, "old/paid", now),
        )
        conn.commit()

    module = _load_app(tmp_path)
    from app import config, db_verify

    with sqlite3.connect(db_path) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(paywall_challenges)")}
        stored = conn.execute(
            "SELECT resource, api_key_id, max_uses, access_seconds, uses_consumed, settled_at, access_until FROM paywall_challenges WHERE payment_hash = ?",
            (paid,),
        ).fetchone()
    assert {"max_uses", "access_seconds", "uses_consumed", "settled_at", "access_until"} <= cols
    assert stored == ("old/paid", None, None, None, 0, None, None)

    already = db_verify.settle_and_consume(
        str(db_path),
        client_id=client_id,
        payment_hash=paid,
        cost=1,
        resource="old/paid",
        api_key_id=None,
        consume=True,
        access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
    )
    assert already["charged"] == 0
    assert already["consumed"] is True
    assert already["uses_consumed"] == 0
    assert already["uses_remaining"] is None
    assert already["max_uses"] is None
    assert already["settled_at"] is not None

    first = db_verify.settle_and_consume(
        str(db_path),
        client_id=client_id,
        payment_hash=unpaid,
        cost=1,
        resource="old/open",
        api_key_id=None,
        consume=True,
        access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
    )
    second = db_verify.settle_and_consume(
        str(db_path),
        client_id=client_id,
        payment_hash=unpaid,
        cost=1,
        resource="old/open",
        api_key_id=None,
        consume=True,
        access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
    )
    assert first["charged"] == 1
    assert second["charged"] == 0
    assert second["uses_consumed"] == 0
    with sqlite3.connect(db_path) as conn:
        credits = conn.execute("SELECT credits FROM clients").fetchone()[0]
        debits = conn.execute("SELECT COUNT(*) FROM ledger WHERE reason = 'paywall_verify'").fetchone()[0]
    assert credits == 9
    assert debits == 1

    with TestClient(module.app) as http:
        assert http.get("/health").json()["version"] == "0.15.1"
        assert _balance(http, legacy_key) == 9
        fresh = _challenge(http, legacy_key, resource="old/new")
        assert fresh["max_uses"] is None
        paid_auth = _pay(http, fresh)
        unlocked = _verify(http, legacy_key, paid_auth, "old/new")
        replay = _verify(http, legacy_key, paid_auth, "old/new", consume=True)
        assert unlocked.json()["charged_credits"] == 1
        assert replay.json()["charged_credits"] == 0
        assert replay.json()["consumed"] is True
        assert _balance(http, legacy_key) == 8


class _TestClientTransport(httpx.BaseTransport):
    def __init__(self, app_client: TestClient) -> None:
        self._app = app_client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url.path
        if request.url.query:
            url = f"{url}?{request.url.query.decode()}"
        headers = {key: value for key, value in request.headers.items() if key.lower() != "host"}
        response = self._app.request(request.method, url, headers=headers, content=request.content)
        return httpx.Response(status_code=response.status_code, headers=dict(response.headers), content=response.content)


def test_sdk_sends_policy_and_does_not_cache_a_consume(tmp_path):
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
            challenge = sg.paywall_challenge(resource="sdk/item", amount_sats=1, max_uses=2, access_seconds=600)
            assert challenge.max_uses == 2
            assert challenge.access_seconds == 600
            assert challenge.uses_remaining == 2
            assert challenge.access_until is None
            authorization = _pay(http, {"macaroon": challenge.macaroon, "payment_hash": challenge.payment_hash})
            first = sg.paywall_verify(
                authorization_header=authorization,
                expected_resource="sdk/item",
                consume=True,
            )
            assert first.charged_credits == 1
            assert first.consumed is True
            assert first.uses_remaining == 1
            assert first.access_until == first.settled_at + 600
            second = sg.paywall_verify(
                authorization_header=authorization,
                expected_resource="sdk/item",
                consume=True,
            )
            assert second.charged_credits == 0
            assert second.uses_remaining == 0
            assert second.client_id != -1
            with pytest.raises(SatsgateError) as raised:
                sg.paywall_verify(
                    authorization_header=authorization,
                    expected_resource="sdk/item",
                    consume=True,
                )
            assert raised.value.status_code == 401
            assert raised.value.data["error"] == "token_used_up"
            assert raised.value.data["charged_credits"] == 0
            assert challenge.payment_hash not in sg._verified
        finally:
            sg.close()
