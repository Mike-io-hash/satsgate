"""Per-buyer challenge limits: trusted proxy header, caps, reuse, migration."""

from __future__ import annotations

import hashlib
import importlib
import os
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]

_V06_SCHEMA = """
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
  FOREIGN KEY(client_id) REFERENCES clients(id)
);
CREATE TABLE verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  payment_hash TEXT NOT NULL,
  resource TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(client_id, payment_hash)
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
  access_until INTEGER
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
  revoked_at INTEGER
);
CREATE TABLE ticket_challenges (
  payment_hash TEXT PRIMARY KEY,
  invoice TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  payee TEXT,
  resource TEXT NOT NULL,
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
        "SATSGATE_BUYER_CHALLENGE_MAX": "10",
        "SATSGATE_BUYER_MAX_OPEN_CHALLENGES": "5",
        "SATSGATE_CHALLENGE_REUSE_SECONDS": "30",
        "SATSGATE_BUYER_LIMIT_SCOPE": "client",
        "SATSGATE_RL_WINDOW_SECONDS": "60",
        "SATSGATE_MAX_OPEN_CHALLENGES_PER_CLIENT": "100",
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


def _challenge(client: TestClient, api_key: str, *, resource: str, buyer_ip: str | None = None, **extra) -> httpx.Response:
    headers = {"X-Api-Key": api_key}
    if buyer_ip is not None:
        headers["X-Satsgate-Buyer-Ip"] = buyer_ip
    return client.post(
        "/v1/paywall/challenge",
        headers=headers,
        json={"resource": resource, "amount_sats": 1, **extra},
    )


def _pay(client: TestClient, challenge: dict) -> str:
    paid = client.get(f"/dev/mock/pay/{challenge['payment_hash']}")
    assert paid.status_code == 200, paid.text
    return _auth(challenge["macaroon"], paid.json()["preimage"])


def _hash_column(payment_hash: str) -> str | None:
    from app import config, db

    row = db.get_paywall_challenge(config.DB_PATH, payment_hash)
    assert row is not None
    return row["buyer_ip_hash"]


def test_truncate_and_hash_share_a_privacy_boundary():
    from app.client_ip import hash_buyer_ip, peer_is_trusted, truncate_buyer_ip

    assert truncate_buyer_ip("1.2.3.4") == "1.2.3.0"
    assert truncate_buyer_ip("1.2.3.255") == "1.2.3.0"
    assert truncate_buyer_ip("::ffff:1.2.3.4") == "1.2.3.0"
    assert truncate_buyer_ip("2001:db8:1:2::1") == truncate_buyer_ip("2001:db8:1:2::abcd")
    assert truncate_buyer_ip("2001:db8:1:2::1") != truncate_buyer_ip("2001:db8:1:3::1")
    assert hash_buyer_ip("1.2.3.4", secret="test-secret") == hash_buyer_ip("1.2.3.9", secret="test-secret")
    assert hash_buyer_ip("1.2.3.4", secret="test-secret") != hash_buyer_ip("1.2.4.4", secret="test-secret")
    assert hash_buyer_ip("1.2.3.4", secret="test-secret") != hash_buyer_ip("1.2.3.4", secret="other-secret")
    assert peer_is_trusted("10.1.2.3", "10.0.0.0/8")
    assert not peer_is_trusted("11.0.0.1", "10.0.0.0/8")
    assert peer_is_trusted("testclient", "testclient")
    assert not peer_is_trusted("testclient", "")


def test_header_is_ignored_unless_the_peer_is_trusted(tmp_path):
    module = _load_app(tmp_path, SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1", SATSGATE_CHALLENGE_REUSE_SECONDS="0")
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        first = _challenge(http, api_key, resource="api/a", buyer_ip="203.0.113.10")
        second = _challenge(http, api_key, resource="api/b", buyer_ip="203.0.113.10")
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["buyer_ip_accepted"] is False
        assert second.json()["reused"] is False
        assert _hash_column(first.json()["payment_hash"]) is None
        raw = Path(os.environ["SATSGATE_DB_PATH"]).read_bytes()
        assert b"203.0.113.10" not in raw


def test_untrusted_garbage_header_is_ignored(tmp_path):
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        response = _challenge(http, api_key, resource="api/a", buyer_ip="not-an-ip")
        assert response.status_code == 200, response.text
        assert response.json()["buyer_ip_accepted"] is False


def test_trusted_buyer_open_cap_rate_and_a_different_buyer(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_CHALLENGE_MAX="2",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="2",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        one = _challenge(http, api_key, resource="api/one", buyer_ip="203.0.113.10")
        two = _challenge(http, api_key, resource="api/two", buyer_ip="203.0.113.10")
        assert one.status_code == 200, one.text
        assert two.status_code == 200, two.text
        assert one.json()["buyer_ip_accepted"] is True
        assert one.json()["reused"] is False
        stored = _hash_column(one.json()["payment_hash"])
        from app.client_ip import hash_buyer_ip

        assert stored == hash_buyer_ip("203.0.113.10", secret="test-secret")
        assert b"203.0.113.10" not in Path(os.environ["SATSGATE_DB_PATH"]).read_bytes()

        blocked = _challenge(http, api_key, resource="api/three", buyer_ip="203.0.113.11")
        # 203.0.113.11 is the same /24, so it shares the bucket and hits the rate (2).
        assert blocked.status_code == 429
        body = blocked.json()
        assert body["error"] == "buyer_rate_limited"
        assert body["retry_after_seconds"] >= 1
        assert blocked.headers["retry-after"] == str(body["retry_after_seconds"])
        assert "Retry-After" in body["detail"] or "window" in body["detail"]

        other = _challenge(http, api_key, resource="api/other", buyer_ip="198.51.100.4")
        assert other.status_code == 200, other.text
        assert _hash_column(other.json()["payment_hash"]) != stored


def test_same_slash_24_shares_a_bucket_and_a_neighbor_does_not(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_CHALLENGE_MAX="10",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        first = _challenge(http, api_key, resource="api/a", buyer_ip="10.1.2.3")
        assert first.status_code == 200, first.text
        shared = _challenge(http, api_key, resource="api/b", buyer_ip="10.1.2.200")
        assert shared.status_code == 429
        assert shared.json()["error"] == "too_many_open_challenges_for_buyer"
        assert int(shared.headers["retry-after"]) >= 1
        neighbor = _challenge(http, api_key, resource="api/c", buyer_ip="10.1.3.3")
        assert neighbor.status_code == 200, neighbor.text


def test_ipv6_prefix_and_mapped_ipv4(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        first = _challenge(http, api_key, resource="api/v6", buyer_ip="2001:db8:1:2::1")
        assert first.status_code == 200, first.text
        again = _challenge(http, api_key, resource="api/v6b", buyer_ip="2001:db8:1:2::abcd")
        assert again.status_code == 429
        assert again.json()["error"] == "too_many_open_challenges_for_buyer"
        other = _challenge(http, api_key, resource="api/v6c", buyer_ip="2001:db8:1:3::1")
        assert other.status_code == 200, other.text

        mapped = _challenge(http, api_key, resource="api/v4", buyer_ip="192.0.2.8")
        assert mapped.status_code == 200, mapped.text
        folded = _challenge(http, api_key, resource="api/v4b", buyer_ip="::ffff:192.0.2.9")
        assert folded.status_code == 429
        assert folded.json()["error"] == "too_many_open_challenges_for_buyer"


def test_paying_frees_the_unpaid_slot_but_not_the_rate(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_CHALLENGE_MAX="2",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        first = _challenge(http, api_key, resource="api/pay", buyer_ip="203.0.113.8")
        assert first.status_code == 200, first.text
        held = _challenge(http, api_key, resource="api/next", buyer_ip="203.0.113.8")
        assert held.status_code == 429
        assert held.json()["error"] == "too_many_open_challenges_for_buyer"

        paid = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": _pay(http, first.json())},
            json={"expected_resource": "api/pay"},
        )
        assert paid.status_code == 200, paid.text
        nxt = _challenge(http, api_key, resource="api/next", buyer_ip="203.0.113.8")
        assert nxt.status_code == 200, nxt.text

        third = _challenge(http, api_key, resource="api/third", buyer_ip="203.0.113.8")
        assert third.status_code == 429
        assert third.json()["error"] == "buyer_rate_limited"


def test_reuse_returns_the_same_invoice_until_the_window_passes(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_CHALLENGE_REUSE_SECONDS="60",
        SATSGATE_BUYER_CHALLENGE_MAX="2",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        first = _challenge(http, api_key, resource="api/item", buyer_ip="203.0.113.20", max_uses=1)
        assert first.status_code == 200, first.text
        again = _challenge(http, api_key, resource="api/item", buyer_ip="203.0.113.21", max_uses=1)
        assert again.status_code == 200, again.text
        assert again.json()["reused"] is True
        assert again.json()["payment_hash"] == first.json()["payment_hash"]
        assert again.json()["invoice"] == first.json()["invoice"]
        assert again.json()["macaroon"] != first.json()["macaroon"]
        assert "does not mint" in again.json()["note"]
        # The re-signed macaroon is bound to the same invoice and still unlocks.
        unlocked = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": _pay(http, again.json())},
            json={"expected_resource": "api/item", "consume": True},
        )
        assert unlocked.status_code == 200, unlocked.text
        assert unlocked.json()["payment_hash"] == first.json()["payment_hash"]

        other_amount = _challenge(http, api_key, resource="api/item", buyer_ip="203.0.113.20", amount_sats=2, max_uses=1)
        assert other_amount.status_code == 200, other_amount.text
        assert other_amount.json()["reused"] is False
        assert other_amount.json()["payment_hash"] != first.json()["payment_hash"]

        # Rate is 2 new invoices. The reuse did not count. A third new one is limited.
        other_policy = _challenge(http, api_key, resource="api/item", buyer_ip="203.0.113.20")
        assert other_policy.status_code == 429
        assert other_policy.json()["error"] == "buyer_rate_limited"

        from app import config, db

        old = int(time.time()) - 120
        with db._connect(config.DB_PATH) as conn:
            conn.execute(
                "UPDATE paywall_challenges SET created_at = ? WHERE payment_hash = ?",
                (old, first.json()["payment_hash"]),
            )
        # The amount=2 row is still inside the rate window, so lower the rate count by aging it too.
        with db._connect(config.DB_PATH) as conn:
            conn.execute("UPDATE paywall_challenges SET created_at = ?", (old,))
        fresh = _challenge(http, api_key, resource="api/item", buyer_ip="203.0.113.20", max_uses=1)
        assert fresh.status_code == 200, fresh.text
        assert fresh.json()["reused"] is False
        assert fresh.json()["payment_hash"] != first.json()["payment_hash"]


def test_settled_and_other_keys_are_not_reused(tmp_path):
    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="testclient", SATSGATE_CHALLENGE_REUSE_SECONDS="60")
    with TestClient(module.app) as http:
        account = _buy_client(http)
        minted = http.post(
            "/v1/api-keys",
            headers={"X-Api-Key": account},
            json={"label": "proxy", "resource_prefix": "blog/"},
        )
        assert minted.status_code == 200, minted.text
        restricted = minted.json()["api_key"]

        first = _challenge(http, account, resource="blog/post", buyer_ip="203.0.113.30")
        assert first.status_code == 200, first.text
        other_key = _challenge(http, restricted, resource="blog/post", buyer_ip="203.0.113.30")
        assert other_key.status_code == 200, other_key.text
        assert other_key.json()["reused"] is False
        assert other_key.json()["payment_hash"] != first.json()["payment_hash"]

        blocked = _challenge(http, restricted, resource="other/post", buyer_ip="203.0.113.30")
        assert blocked.status_code == 403
        assert blocked.json()["error"] == "resource_not_allowed"

        paid = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": account, "Authorization": _pay(http, first.json())},
            json={"expected_resource": "blog/post"},
        )
        assert paid.status_code == 200, paid.text
        after_pay = _challenge(http, account, resource="blog/post", buyer_ip="203.0.113.30")
        assert after_pay.status_code == 200, after_pay.text
        assert after_pay.json()["reused"] is False
        assert after_pay.json()["payment_hash"] != first.json()["payment_hash"]


def test_trusted_peer_rejects_a_bad_buyer_header(tmp_path):
    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="testclient")
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        for value in ("not-an-ip", "203.0.113.10, 198.51.100.2", "http://203.0.113.10"):
            response = _challenge(http, api_key, resource="api/bad", buyer_ip=value)
            assert response.status_code == 400, response.text
            assert response.json()["error"] == "invalid_buyer_ip"
        ok = _challenge(http, api_key, resource="api/bad", buyer_ip="203.0.113.10")
        assert ok.status_code == 200, ok.text


def test_forwarded_for_is_not_the_buyer(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        headers = {"X-Api-Key": api_key, "X-Forwarded-For": "8.8.8.8"}
        first = http.post("/v1/paywall/challenge", headers=headers, json={"resource": "api/a", "amount_sats": 1})
        second = http.post("/v1/paywall/challenge", headers=headers, json={"resource": "api/b", "amount_sats": 1})
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["buyer_ip_accepted"] is False
        assert _hash_column(first.json()["payment_hash"]) is None


def test_account_cap_still_applies_and_sends_retry_after(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_MAX_OPEN_CHALLENGES_PER_CLIENT="2",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="10",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        assert _challenge(http, api_key, resource="api/1", buyer_ip="203.0.113.1").status_code == 200
        assert _challenge(http, api_key, resource="api/2", buyer_ip="203.0.113.1").status_code == 200
        blocked = _challenge(http, api_key, resource="api/3", buyer_ip="198.51.100.8")
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "too_many_open_challenges"
        assert blocked.headers["retry-after"] == str(blocked.json()["retry_after_seconds"])


def test_per_client_challenge_rate_still_covers_every_buyer(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_RL_ENABLED="1",
        SATSGATE_RL_MAX_CHALLENGE="2",
        SATSGATE_RL_MAX_AUTH="50",
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_CHALLENGE_MAX="50",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        assert _challenge(http, api_key, resource="api/1", buyer_ip="203.0.113.1").status_code == 200
        assert _challenge(http, api_key, resource="api/2", buyer_ip="198.51.100.2").status_code == 200
        blocked = _challenge(http, api_key, resource="api/3", buyer_ip="192.0.2.3")
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "rate_limited"
        assert blocked.headers["retry-after"]


def test_scope_key_separates_restricted_keys(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_LIMIT_SCOPE="key",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        account = _buy_client(http)
        first_key = http.post("/v1/api-keys", headers={"X-Api-Key": account}, json={"label": "a"}).json()["api_key"]
        second_key = http.post("/v1/api-keys", headers={"X-Api-Key": account}, json={"label": "b"}).json()["api_key"]
        assert _challenge(http, first_key, resource="api/a", buyer_ip="203.0.113.40").status_code == 200
        assert _challenge(http, second_key, resource="api/b", buyer_ip="203.0.113.40").status_code == 200
        blocked = _challenge(http, first_key, resource="api/c", buyer_ip="203.0.113.41")
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "too_many_open_challenges_for_buyer"


def test_scope_client_shares_the_buyer_across_keys(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_LIMIT_SCOPE="client",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    with TestClient(module.app) as http:
        account = _buy_client(http)
        restricted = http.post("/v1/api-keys", headers={"X-Api-Key": account}, json={"label": "a"}).json()["api_key"]
        assert _challenge(http, account, resource="api/a", buyer_ip="203.0.113.50").status_code == 200
        blocked = _challenge(http, restricted, resource="api/b", buyer_ip="203.0.113.50")
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "too_many_open_challenges_for_buyer"


def test_invalid_scope_refuses_to_boot(tmp_path):
    try:
        with pytest.raises(RuntimeError, match="SATSGATE_BUYER_LIMIT_SCOPE"):
            _load_app(tmp_path, SATSGATE_BUYER_LIMIT_SCOPE="both")
    finally:
        os.environ["SATSGATE_BUYER_LIMIT_SCOPE"] = "client"


def test_concurrent_inserts_cannot_share_the_last_unpaid_slot(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_BUYER_CHALLENGE_MAX="100",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    from app import config, db

    with TestClient(module.app) as http:
        _buy_client(http)
        client_id = int(sqlite3.connect(config.DB_PATH).execute("SELECT id FROM clients").fetchone()[0])

    barrier = threading.Barrier(8)
    results: list = [None] * 8

    def worker(index: int) -> None:
        barrier.wait()
        try:
            db.add_paywall_challenge(
                config.DB_PATH,
                payment_hash=secrets.token_hex(32),
                client_id=client_id,
                invoice="lnmock",
                amount_sats=1,
                payee=None,
                resource=f"api/race-{index}",
                verify_url=None,
                expires_at=int(time.time()) + 600,
                buyer_ip_hash="buyer-hash",
                max_open_per_client=100,
                buyer_rate_max=100,
                buyer_rate_window_seconds=60,
                buyer_max_open=1,
                buyer_limit_scope="client",
                claim_grace_seconds=config.PAYWALL_CLAIM_GRACE_SECONDS,
                claim_cap_seconds=config.PAYWALL_TOKEN_TTL_CAP_SECONDS,
            )
            results[index] = "ok"
        except db.ChallengeLimit as exc:
            results[index] = exc.code
        except Exception as exc:  # noqa: BLE001
            results[index] = f"err:{exc}"

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("ok") == 1, results
    assert results.count("too_many_open_challenges_for_buyer") == 7, results


def test_expired_offers_do_not_count_and_retry_after_is_the_soonest_expiry(tmp_path):
    module = _load_app(
        tmp_path,
        SATSGATE_TRUSTED_PROXIES="testclient",
        SATSGATE_BUYER_CHALLENGE_MAX="100",
        SATSGATE_BUYER_MAX_OPEN_CHALLENGES="1",
        SATSGATE_CHALLENGE_REUSE_SECONDS="0",
    )
    from app.client_ip import hash_buyer_ip

    with TestClient(module.app) as http:
        api_key = _buy_client(http)
        buyer = hash_buyer_ip("203.0.113.70", secret="test-secret")
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            client_id = int(conn.execute("SELECT id FROM clients").fetchone()[0])
        now = int(time.time())
        for index in range(5):
            module.db_x402.create_offer(
                module.config.DB_PATH,
                client_id=client_id,
                resource=f"api/expired-{index}",
                resource_url="https://gate.satsgate.org/shop/expired",
                price_currency="usd",
                amount_sats=None,
                amount_usd_atomic=1000,
                pay_to="0x1111111111111111111111111111111111111111",
                requirements=None,
                buyer_ip_hash=buyer,
                max_uses=None,
                access_seconds=None,
                expires_at=now - 30,
                enforce=False,
                now=now - 90,
            )
        first = _challenge(http, api_key, resource="api/live", buyer_ip="203.0.113.70")
        assert first.status_code == 200, first.text
        soon = now + 40
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute(
                "UPDATE paywall_challenges SET expires_at = ? WHERE payment_hash = ?",
                (soon, first.json()["payment_hash"]),
            )
        blocked = _challenge(http, api_key, resource="api/next", buyer_ip="203.0.113.70")
        assert blocked.status_code == 429, blocked.text
        assert blocked.json()["error"] == "too_many_open_challenges_for_buyer"
        retry_after = int(blocked.headers["retry-after"])
        assert blocked.json()["retry_after_seconds"] == retry_after
        assert 1 <= retry_after <= 45

        # The full Lightning slot does not block an x402 offer. A charged offer does not count.
        offered = module.db_x402.create_offer(
            module.config.DB_PATH,
            client_id=client_id,
            resource="api/x402",
            resource_url="https://gate.satsgate.org/shop/x402",
            price_currency="usd",
            amount_sats=None,
            amount_usd_atomic=1000,
            pay_to="0x1111111111111111111111111111111111111111",
            requirements=None,
            buyer_ip_hash=buyer,
            max_uses=None,
            access_seconds=None,
            expires_at=now + 25,
            enforce=True,
            now=now,
        )
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute(
                """
                INSERT INTO x402_authorizations(
                  network, asset, payer, nonce, offer_id, value_atomic, pay_to, state,
                  credit_charged, uses_consumed, updated_at
                ) VALUES('eip155:84532', 'usdc', '0xabc', ?, ?, '1000', '0xabc', 'settled', 1, 1, ?)
                """,
                (secrets.token_hex(32), offered["id"], now),
            )
        second = module.db_x402.create_offer(
            module.config.DB_PATH,
            client_id=client_id,
            resource="api/x402-b",
            resource_url="https://gate.satsgate.org/shop/x402-b",
            price_currency="usd",
            amount_sats=None,
            amount_usd_atomic=1000,
            pay_to="0x1111111111111111111111111111111111111111",
            requirements=None,
            buyer_ip_hash=buyer,
            max_uses=None,
            access_seconds=None,
            expires_at=now + 50,
            enforce=True,
            now=now,
        )
        assert second["id"] != offered["id"]
        try:
            module.db_x402.create_offer(
                module.config.DB_PATH,
                client_id=client_id,
                resource="api/x402-c",
                resource_url="https://gate.satsgate.org/shop/x402-c",
                price_currency="usd",
                amount_sats=None,
                amount_usd_atomic=1000,
                pay_to="0x1111111111111111111111111111111111111111",
                requirements=None,
                buyer_ip_hash=buyer,
                max_uses=None,
                access_seconds=None,
                expires_at=now + 80,
                enforce=True,
                now=now,
            )
        except module.db.ChallengeLimit as exc:
            limited = exc
        else:
            raise AssertionError("a second unexpired x402 offer should hit the cap")
        assert limited.code == "too_many_open_challenges_for_buyer"
        assert 1 <= limited.retry_after <= 55


def test_migration_adds_the_hash_column_and_leaves_old_rows_unlimited(tmp_path):
    db_path = tmp_path / "satsgate_test.sqlite3"
    legacy_key = "sg_legacy-account-key-value"
    legacy_hash = hashlib.sha256(legacy_key.encode()).hexdigest()
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_V06_SCHEMA)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(paywall_challenges)")}
        assert "buyer_ip_hash" not in cols
        conn.execute(
            "INSERT INTO clients(api_key_hash, credits, created_at) VALUES(?, ?, ?)",
            (legacy_hash, 7, now),
        )
        client_id = int(conn.execute("SELECT id FROM clients").fetchone()[0])
        conn.execute(
            """
            INSERT INTO paywall_challenges(
              payment_hash, client_id, invoice, amount_sats, payee, resource, verify_url, created_at, expires_at,
              api_key_id, max_uses, access_seconds, uses_consumed
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("ab" * 32, client_id, "lnbc1old", 5, None, "old/resource", None, now, now + 600, None, None, None, 0),
        )
        conn.commit()

    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="testclient", SATSGATE_CHALLENGE_REUSE_SECONDS="0")
    with sqlite3.connect(db_path) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(paywall_challenges)")}
        stored = conn.execute(
            "SELECT resource, max_uses, buyer_ip_hash FROM paywall_challenges WHERE payment_hash = ?",
            ("ab" * 32,),
        ).fetchone()
        indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert "buyer_ip_hash" in cols
    assert stored == ("old/resource", None, None)
    assert "idx_challenges_buyer" in indexes

    with TestClient(module.app) as http:
        assert http.get("/health").json()["version"] == "0.14.1"
        balance = http.get("/v1/balance", headers={"X-Api-Key": legacy_key})
        assert balance.status_code == 200
        assert balance.json()["credits"] == 7
        first = _challenge(http, legacy_key, resource="old/new")
        second = _challenge(http, legacy_key, resource="old/new")
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["buyer_ip_accepted"] is False
        assert second.json()["payment_hash"] != first.json()["payment_hash"]
        assert _hash_column(first.json()["payment_hash"]) is None


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


def test_sdk_sends_the_buyer_header(tmp_path):
    module = _load_app(tmp_path, SATSGATE_TRUSTED_PROXIES="testclient", SATSGATE_CHALLENGE_REUSE_SECONDS="60")
    sdk_root = REPO_ROOT / "sdk" / "python" / "src"
    if str(sdk_root) not in sys.path:
        sys.path.insert(0, str(sdk_root))
    from satsgate_sdk import SatsgateClient, __version__

    assert __version__ == "0.6.0"
    with TestClient(module.app) as http:
        account = _buy_client(http)
        sg = SatsgateClient(base_url="http://testserver", api_key=account)
        sg._http.close()
        sg._http = httpx.Client(transport=_TestClientTransport(http), base_url="http://testserver")
        try:
            first = sg.paywall_challenge(resource="sdk/item", amount_sats=1, buyer_ip="203.0.113.77")
            assert first.buyer_ip_accepted is True
            assert first.reused is False
            again = sg.paywall_challenge(resource="sdk/item", amount_sats=1, buyer_ip="203.0.113.77")
            assert again.reused is True
            assert again.payment_hash == first.payment_hash
        finally:
            sg.close()
