"""Account-key rotation and the seller security webhook. No network."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import sqlite3
import threading
import time
from pathlib import Path

import httpx
import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from test_payee_connect import _buy, _load_app, _sign

ROOT = Path(__file__).resolve().parents[1]
_VECTOR = json.loads((ROOT / "tests" / "fixtures" / "webhook_signature_vector.json").read_text(encoding="utf-8"))
_HOOK = "https://hooks.example/satsgate"


def _patch_dns(monkeypatch, module, mapping: dict[str, str] | None = None):
    chosen = dict(mapping or {})

    def fake(host, port, family=0, socktype=0, proto=0, flags=0):
        name = str(host).lower().rstrip(".")
        try:
            ipaddress.ip_address(name)
            ip = name
        except ValueError:
            ip = chosen.get(name, "1.1.1.1")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(module.ssrf.socket, "getaddrinfo", fake)


def _env(**extra):
    base = {
        "SATSGATE_WEBHOOKS": "0",
        "SATSGATE_EMAIL_ENABLED": "0",
        "SATSGATE_RESEND_API_KEY": "",
        "SATSGATE_SUPPORT_EMAIL": "satsgateapp@proton.me",
    }
    base.update(extra)
    return base


def _rows(query: str, args=()):
    with sqlite3.connect(os_db()) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, args).fetchall()


def os_db() -> str:
    import os

    return os.environ["SATSGATE_DB_PATH"]


def _email():
    return _rows("SELECT * FROM email_outbox ORDER BY id")


def _hooks():
    return _rows("SELECT * FROM webhook_outbox ORDER BY id")


def _put_hook(http: TestClient, key: str, url: str = _HOOK, rotate: bool = False):
    body = {"url": url}
    if rotate:
        body["rotate_secret"] = True
    return http.put("/v1/client/webhook", headers={"X-Api-Key": key}, json=body)


def test_rotate_replaces_the_key_and_queues_only_what_exists(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_RESEND_API_KEY="re_test_key_value_not_a_secret"))
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        denied = http.post("/v1/client/api-key/rotate", headers={"X-Admin-Token": "test-admin-token"})
        assert denied.status_code == 401
        assert denied.json()["error"] == "invalid_api_key"
        connect = http.post("/v1/client/api-key/rotate", headers={"X-Connect-Token": "sgc_" + "a" * 24})
        assert connect.status_code == 401
        minted = http.post("/v1/api-keys", headers={"X-Api-Key": key}, json={"label": "paywall"})
        restricted = minted.json()["api_key"]
        blocked = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": restricted})
        assert blocked.status_code == 403
        assert blocked.json()["error"] == "insufficient_scope"
        still = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": restricted},
            json={"resource": "demo/item", "amount_sats": 1},
        )
        assert still.status_code == 200, still.text
        quiet = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": key})
        assert quiet.status_code == 200, quiet.text
        assert _email() == []
        assert _hooks() == []
        body = quiet.json()
        new_key = body["api_key"]
        assert new_key.startswith("sg_")
        assert body["prefix"] == new_key[:8]
        ledger_blob = json.dumps([tuple(row) for row in _rows("SELECT reason, ref FROM ledger")])
        assert new_key not in ledger_blob
        old = http.get("/v1/balance", headers={"X-Api-Key": key})
        assert old.status_code == 401
        assert old.json()["error"] == "invalid_api_key"
        assert http.get("/v1/balance", headers={"X-Api-Key": new_key}).status_code == 200
        ledger = [row for row in _rows("SELECT reason, ref FROM ledger") if row["reason"] == "api_key_rotated"]
        assert ledger[-1]["ref"] == new_key[:8]

        saved = http.put(
            "/v1/client/alert-email",
            headers={"X-Api-Key": new_key},
            json={"email": "seller@proton.me"},
        )
        assert saved.status_code == 200, saved.text
        token = json.loads(_email()[-1]["params_json"])["token"]
        confirmed = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
        assert confirmed.status_code == 200, confirmed.text
        created = _put_hook(http, new_key)
        assert created.status_code == 200, created.text
        secret = created.json()["secret"]
        again = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": new_key})
        assert again.status_code == 200, again.text
        mailed = [row for row in _email() if row["kind"] == "account_key_rotated"]
        hooked = [row for row in _hooks() if row["kind"] == "account_key_rotated"]
        assert len(mailed) == 1
        assert len(hooked) == 1
        params = json.loads(mailed[0]["params_json"])
        assert params["prefix"] == again.json()["prefix"]
        assert params["via"] == "api"
        assert again.json()["api_key"] not in mailed[0]["params_json"]
        assert again.json()["api_key"] not in hooked[0]["body_json"]
        assert secret not in hooked[0]["body_json"]
        event = json.loads(hooked[0]["body_json"])
        assert event["id"] == hooked[0]["event_id"]
        assert event["type"] == "account_key_rotated"
        assert event["data"] == params


def test_concurrent_rotation_commits_one_key(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
    barrier = threading.Barrier(2)
    results: list[dict] = []
    errors: list[str] = []
    lock = threading.Lock()

    def once():
        barrier.wait()
        try:
            rotated = module.db_account_key.rotate_account_key(os_db(), key)
        except module.db_keys.AuthError as exc:
            with lock:
                errors.append(exc.code)
            return
        with lock:
            results.append(rotated)

    threads = [threading.Thread(target=once) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 1
    assert errors == ["invalid_api_key"]
    winner = results[0]["api_key"]
    stored = _rows("SELECT api_key_hash FROM clients")[0]["api_key_hash"]
    assert stored == hashlib.sha256(winner.encode()).hexdigest()
    with TestClient(module.app) as http:
        assert http.get("/v1/balance", headers={"X-Api-Key": key}).status_code == 401
        assert http.get("/v1/balance", headers={"X-Api-Key": winner}).status_code == 200


def test_rotation_rolls_back_when_the_outbox_insert_fails(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_RESEND_API_KEY="re_test_key_value_not_a_secret"))
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        saved = http.put(
            "/v1/client/alert-email",
            headers={"X-Api-Key": key},
            json={"email": "seller@proton.me"},
        )
        token = json.loads(_email()[-1]["params_json"])["token"]
        assert saved.status_code == 200
        assert http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token}).status_code == 200

    def boom():
        raise RuntimeError("boom")

    module.db_alert_email.commit_guard = boom
    with pytest.raises(RuntimeError, match="boom"):
        module.db_account_key.rotate_account_key(os_db(), key)
    module.db_alert_email.commit_guard = None
    with TestClient(module.app) as http:
        assert http.get("/v1/balance", headers={"X-Api-Key": key}).status_code == 200


def test_webhook_api_secret_once_and_url_rules(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        minted = http.post("/v1/api-keys", headers={"X-Api-Key": key}, json={"label": "paywall"})
        restricted = minted.json()["api_key"]
        denied = _put_hook(http, restricted)
        assert denied.status_code == 403
        assert denied.json()["error"] == "insufficient_scope"
        for bad in (
            "http://hooks.example/satsgate",
            "https://user:pass@hooks.example/satsgate",
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://10.1.2.3/hook",
            "https://" + "a" * 290 + ".example/hook",
        ):
            rejected = _put_hook(http, key, bad)
            assert rejected.status_code == 400, bad
            assert rejected.json()["error"] == "invalid_webhook_url"
            assert "user:pass" not in rejected.text
            assert bad not in rejected.text or bad.startswith("https://10.")
        created = _put_hook(http, key)
        assert created.status_code == 200, created.text
        secret = created.json()["secret"]
        assert secret.startswith("whsec_")
        assert "secret" in created.json()
        replaced = _put_hook(http, key, "https://hooks.example/other")
        assert replaced.status_code == 200, replaced.text
        assert "secret" not in replaced.json()
        assert replaced.json()["url"] == "https://hooks.example/other"
        assert replaced.json()["enabled"] is True
        turned = _put_hook(http, key, "https://hooks.example/other", rotate=True)
        assert turned.status_code == 200, turned.text
        assert turned.json()["secret"].startswith("whsec_")
        assert turned.json()["secret"] != secret
        viewed = http.get("/v1/client/webhook", headers={"X-Api-Key": key})
        assert viewed.status_code == 200, viewed.text
        body = viewed.json()
        assert secret not in viewed.text
        assert turned.json()["secret"] not in viewed.text
        assert body["secret_prefix"] == turned.json()["secret"][:10]
        assert body["last_delivery"] is None
        assert body["url"] == "https://hooks.example/other"
        removed = http.delete("/v1/client/webhook", headers={"X-Api-Key": key})
        assert removed.status_code == 200
        empty = http.get("/v1/client/webhook", headers={"X-Api-Key": key}).json()
        assert empty["url"] is None
        assert empty["enabled"] is False
        assert _rows("SELECT client_id FROM client_webhooks") == []


def test_missing_site_secret_key_refuses_webhook_storage(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_SITE_SECRET_KEY=""))
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        rejected = _put_hook(http, key)
        assert rejected.status_code == 503
        assert rejected.json()["error"] == "webhooks_unavailable"
        assert _rows("SELECT client_id FROM client_webhooks") == []


def test_signature_vector_matches_the_documented_snippet(tmp_path):
    _load_app(tmp_path, **_env())
    body = _VECTOR["body"].encode("utf-8")
    import importlib

    signer = importlib.import_module("app.webhook_sign")
    signed = signer.signature(_VECTOR["secret"], _VECTOR["timestamp"], body)
    assert signed == _VECTOR["signature"]
    assert signer.verify(
        _VECTOR["secret"],
        _VECTOR["timestamp"],
        body,
        signed,
        now=_VECTOR["now"],
    )
    assert signer.verify(
        _VECTOR["secret"],
        _VECTOR["timestamp"],
        body,
        signed,
        now=_VECTOR["timestamp"] + 301,
    ) is False
    quickstart = (ROOT / "CUSTOMER_QUICKSTART.md").read_text(encoding="utf-8")
    assert _VECTOR["signature"] in quickstart
    assert "compare_digest" in quickstart
    assert "timingSafeEqual" in quickstart


def test_delivery_retries_disables_and_pins(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_RESEND_API_KEY="re_test_key_value_not_a_secret"))
    _patch_dns(monkeypatch, module)
    calls: list[tuple] = []

    def poster(url, body, headers, timeout):
        calls.append((url, body, dict(headers), timeout))
        if len(calls) < 5:
            return 500, b""
        return 200, b"ok"

    module.webhook_send.poster = poster
    with TestClient(module.app) as http:
        key = _buy(http)
        saved = http.put(
            "/v1/client/alert-email",
            headers={"X-Api-Key": key},
            json={"email": "seller@proton.me"},
        )
        token = json.loads(_email()[-1]["params_json"])["token"]
        assert saved.status_code == 200
        assert http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token}).status_code == 200
        created = _put_hook(http, key)
        secret = created.json()["secret"]
        tested = http.post("/v1/client/webhook/test", headers={"X-Api-Key": key})
        assert tested.status_code == 200, tested.text
    assert len(_hooks()) == 1
    stored = _hooks()[0]["body_json"].encode("utf-8")
    now = int(time.time())
    delays = []
    for _attempt in range(4):
        module.webhook_send.pump_once(now=now)
        row = _hooks()[0]
        assert row["status"] == "pending"
        delays.append(int(row["next_attempt_at"]) - now)
        now = int(row["next_attempt_at"])
    assert delays == [60, 300, 1800, 7200]
    module.webhook_send.pump_once(now=now)
    assert _hooks()[0]["status"] == "sent"
    assert _hooks()[0]["attempts"] == 5
    assert len(calls) == 5
    bodies = {item[1] for item in calls}
    assert bodies == {stored}
    first_headers = calls[0][2]
    assert first_headers["Satsgate-Webhook-Id"] == _hooks()[0]["event_id"]
    assert first_headers["User-Agent"] == f"satsgate/{module.config.APP_VERSION}"
    import importlib

    signer = importlib.import_module("app.webhook_sign")
    assert signer.verify(
        secret,
        int(first_headers["Satsgate-Webhook-Timestamp"]),
        stored,
        first_headers["Satsgate-Webhook-Signature"],
        now=int(first_headers["Satsgate-Webhook-Timestamp"]),
    )
    assert secret not in json.dumps(first_headers)
    assert calls[0][3] == 5.0

    def gone(url, body, headers, timeout):
        calls.append((url, body, headers, timeout))
        return 410, b"no"

    module.webhook_send.poster = gone
    with TestClient(module.app) as http:
        http.post("/v1/client/webhook/test", headers={"X-Api-Key": key})
    before = len(calls)
    module.webhook_send.pump_once(now=int(time.time()))
    assert len(calls) == before + 1
    assert _rows("SELECT enabled, disabled_reason FROM client_webhooks")[0]["enabled"] == 0
    assert _rows("SELECT disabled_reason FROM client_webhooks")[0]["disabled_reason"] == "http_410"
    disabled = [row for row in _email() if row["kind"] == "webhook_disabled"]
    assert len(disabled) == 1
    assert "hooks.example" not in disabled[0]["params_json"]
    assert json.loads(disabled[0]["params_json"])["status"] == 410
    module.webhook_send.pump_once(now=int(time.time()) + 10_000)
    assert len(calls) == before + 1


def test_redirect_is_not_followed_and_private_dns_is_not_sent(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    seen: list[str] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    with pytest.raises(module.ssrf.SSRFError) as caught:
        module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            headers={"User-Agent": "satsgate-test"},
            resolver=lambda host, port, *args, **kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))
            ],
            client=httpx.Client(transport=httpx.MockTransport(redirect)),
        )
    assert caught.value.code == "redirects_not_allowed"
    assert seen == [_HOOK]
    assert "127.0.0.1" not in seen[0]

    def huge(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (8 * 1024), headers={"content-length": "999999"})

    status, payload = module.ssrf.safe_post_bytes(
        _HOOK,
        b"{}",
        resolver=lambda host, port, *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))
        ],
        client=httpx.Client(transport=httpx.MockTransport(huge)),
        max_bytes=4096,
    )
    assert status == 200
    assert len(payload) == 4096

    def chunked(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, content=b"y" * 5000)

    status, payload = module.ssrf.safe_post_bytes(
        _HOOK,
        b"{}",
        resolver=lambda host, port, *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))
        ],
        client=httpx.Client(transport=httpx.MockTransport(chunked)),
    )
    assert status == 204
    assert len(payload) <= 4096
    client = module.ssrf._shared_client()
    assert client.follow_redirects is False
    assert client.trust_env is False

    with TestClient(module.app) as http:
        key = _buy(http)
        created = _put_hook(http, key)
        assert created.status_code == 200, created.text
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
    _patch_dns(monkeypatch, module, {"hooks.example": "10.2.0.8"})
    module.webhook_send.poster = None

    def explode(*args, **kwargs):
        raise AssertionError("private DNS must not connect")

    monkeypatch.setattr(module.ssrf, "_shared_client", explode)
    module.webhook_send.pump_once(now=int(time.time()))
    row = _hooks()[0]
    assert row["status"] == "failed"
    assert row["attempts"] == 1
    assert _rows("SELECT enabled FROM client_webhooks")[0]["enabled"] == 1


def test_old_generation_410_does_not_disable_the_replacement(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _put_hook(http, key)
        assert created.status_code == 200, created.text
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
        replaced = _put_hook(http, key, "https://hooks.example/next")
        assert replaced.status_code == 200, replaced.text
    assert _rows("SELECT status FROM webhook_outbox WHERE status = 'pending'") == []
    client_id = int(_rows("SELECT id FROM clients")[0]["id"])
    now = int(time.time())
    with sqlite3.connect(os_db()) as conn:
        conn.execute(
            """
            INSERT INTO webhook_outbox(
              client_id, event_id, generation, kind, body_json, status, attempts,
              next_attempt_at, created_at
            ) VALUES(?, 'evt_stale', 1, 'webhook_test', '{}', 'sending', 0, ?, ?)
            """,
            (client_id, now, now),
        )
    row = dict(_rows("SELECT * FROM webhook_outbox WHERE event_id = 'evt_stale'")[0])
    module.webhook_send._apply_disable(row, int(time.time()), 410)
    current = _rows("SELECT enabled, generation, url FROM client_webhooks")[0]
    assert current["enabled"] == 1
    assert current["generation"] == 2
    assert current["url"] == "https://hooks.example/next"


def test_payee_change_commits_when_the_webhook_later_fails(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)

    def fail(url, body, headers, timeout):
        return 500, b""

    module.webhook_send.poster = fail
    with TestClient(module.app) as http:
        key = _buy(http)
        assert _put_hook(http, key).status_code == 200
        saved = http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        assert saved.status_code == 200, saved.text
    assert _rows("SELECT payee_lightning_address FROM clients")[0][0] == "merchant@pay.example"
    module.webhook_send.pump_once(now=int(time.time()))
    assert _hooks()[0]["status"] == "pending"
    assert _rows("SELECT payee_lightning_address FROM clients")[0][0] == "merchant@pay.example"
    assert _email() == []


def test_security_events_reach_the_webhook_without_an_alert_email(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_EMAIL_ENABLED="0", SATSGATE_RESEND_API_KEY=""))
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    with TestClient(module.app) as http:
        assert "satsgate-email" not in {thread.name for thread in threading.enumerate()}
        key = _buy(http)
        assert _put_hook(http, key).status_code == 200
        moved = http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        assert moved.status_code == 200, moved.text
        challenge = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": owner.address},
        )
        verified = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": owner.address, "signature": _sign(owner, challenge.json()["message"])},
        )
        assert verified.status_code == 200, verified.text
    kinds = [row["kind"] for row in _hooks()]
    assert "payee_lightning_changed" in kinds
    assert "payee_evm_changed" in kinds
    lightning = json.loads(next(row["body_json"] for row in _hooks() if row["kind"] == "payee_lightning_changed"))
    assert "merchant@pay.example" not in json.dumps(lightning)
    assert lightning["data"]["new"] == "merc…@pay.example"
    evm = json.loads(next(row["body_json"] for row in _hooks() if row["kind"] == "payee_evm_changed"))
    assert owner.address not in json.dumps(evm)
    assert _email() == []
    import importlib

    importlib.import_module("app.ofac")._flag_matches(frozenset({owner.address.lower()}))
    ofac = [row for row in _hooks() if row["kind"] == "payee_ofac_flagged"]
    assert len(ofac) == 1
    assert owner.address not in ofac[0]["body_json"]
    assert _email() == []
    assert _rows("SELECT payee_flagged_at FROM clients")[0][0] is not None


def test_alert_email_change_and_removal_are_webhook_events(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_RESEND_API_KEY="re_test_key_value_not_a_secret"))
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        assert _put_hook(http, key).status_code == 200
        first = http.put(
            "/v1/client/alert-email",
            headers={"X-Api-Key": key},
            json={"email": "old@proton.me"},
        )
        assert first.status_code == 200, first.text
        token = json.loads(_email()[-1]["params_json"])["token"]
        assert http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token}).status_code == 200
        with sqlite3.connect(os_db()) as conn:
            conn.execute("UPDATE email_outbox SET created_at = created_at - 120")
        second = http.put(
            "/v1/client/alert-email",
            headers={"X-Api-Key": key},
            json={"email": "new@proton.me"},
        )
        assert second.status_code == 200, second.text
        fresh = [row for row in _email() if row["to_email"] == "new@proton.me" and row["kind"] == "alert_email_confirm"]
        token = json.loads(fresh[-1]["params_json"])["token"]
        assert http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token}).status_code == 200
        removed = http.delete("/v1/client/alert-email", headers={"X-Api-Key": key})
        assert removed.status_code == 200, removed.text
    kinds = [row["kind"] for row in _hooks()]
    assert "alert_email_changed" in kinds
    assert "alert_email_removed" in kinds
    assert "alert_email_confirm" not in kinds
    assert "alert_email_confirmed" not in kinds
    assert "alert_email_change_requested" not in kinds
    changed = json.loads(next(row["body_json"] for row in _hooks() if row["kind"] == "alert_email_changed"))
    assert changed["data"]["masked_new"] == "n***@proton.me"
    blob = json.dumps([json.loads(row["body_json"]) for row in _hooks()])
    assert "sge_" not in blob
    assert "new@proton.me" not in blob


def test_webhook_sender_starts_without_resend(tmp_path):
    module = _load_app(tmp_path, **_env(SATSGATE_WEBHOOKS="1", SATSGATE_EMAIL_ENABLED="0", SATSGATE_RESEND_API_KEY=""))
    module.webhook_send.poster = lambda *args: (200, b"")
    with TestClient(module.app) as http:
        names = {thread.name for thread in threading.enumerate()}
        assert "satsgate-webhook" in names
        assert "satsgate-email" not in names
        assert http.get("/health").status_code == 200


def test_manifest_and_openapi_list_the_routes(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        endpoints = http.get("/.well-known/satsgate.json").json()["api"]["endpoints"]
        spec = http.get("/openapi.json").json()
    assert endpoints["api_key_rotate"]["path"] == "/v1/client/api-key/rotate"
    assert endpoints["webhook"]["method"] == "PUT"
    assert endpoints["webhook_test"]["path"] == "/v1/client/webhook/test"
    rotate = spec["paths"]["/v1/client/api-key/rotate"]["post"]
    assert "X-Api-Key" in json.dumps(rotate)
    webhook = spec["paths"]["/v1/client/webhook"]["put"]
    assert "rotate_secret" in json.dumps(webhook)
    assert "whsec_" in (webhook.get("description") or "")


def test_migrations_are_idempotent_on_fresh_and_pre_a_databases(tmp_path):
    module = _load_app(tmp_path, **_env())
    fresh = tmp_path / "fresh.sqlite3"
    module.db.init_db(str(fresh))
    module.db.init_db(str(fresh))
    with sqlite3.connect(fresh) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        cols = {row[1] for row in conn.execute("PRAGMA table_info(gate_receipts)")}
    assert "client_webhooks" in tables
    assert "webhook_outbox" in tables
    assert {"signature_sha256", "settled_at"} <= cols

    pre = tmp_path / "pre-a.sqlite3"
    module.db.init_db(str(pre))
    with sqlite3.connect(pre) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute(
            "INSERT INTO clients(api_key_hash, credits, created_at) VALUES(?, ?, ?)",
            ("hash-kept", 7, 10),
        )
        client_id = int(conn.execute("SELECT id FROM clients").fetchone()[0])
        conn.execute(
            """
            INSERT INTO sites(
              client_id, slug, display_name, origin_url, status, listed,
              origin_secret_ciphertext, secret_fingerprint, created_at, updated_at
            ) VALUES(?, 'shop', 'Shop', 'https://origin.example', 'approved', 0, 'cipher', 'fp', 10, 10)
            """,
            (client_id,),
        )
        site_id = int(conn.execute("SELECT id FROM sites").fetchone()[0])
        conn.execute("ALTER TABLE gate_receipts RENAME TO gate_receipts_full")
        conn.execute(
            """
            CREATE TABLE gate_receipts (
              rid TEXT PRIMARY KEY,
              payment_hash TEXT NOT NULL UNIQUE,
              site_id INTEGER NOT NULL,
              client_id INTEGER NOT NULL,
              path TEXT NOT NULL,
              rail TEXT NOT NULL,
              amount_sats INTEGER,
              amount_usd_atomic INTEGER,
              network TEXT,
              uses INTEGER NOT NULL,
              iat INTEGER NOT NULL,
              exp INTEGER NOT NULL,
              kid TEXT NOT NULL,
              charged INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO gate_receipts(
              rid, payment_hash, site_id, client_id, path, rail, uses, iat, exp, kid, charged
            ) VALUES('rid-kept', 'ph-kept', ?, ?, '/paid', 'lightning', 1, 10, 20, '1', 1)
            """,
            (site_id, client_id),
        )
        conn.execute("DROP TABLE gate_receipts_full")
        conn.commit()
    module.db.init_db(str(pre))
    module.db.init_db(str(pre))
    with sqlite3.connect(pre) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(gate_receipts)")}
        receipt = conn.execute(
            "SELECT rid, signature_sha256, settled_at FROM gate_receipts"
        ).fetchone()
        credits = conn.execute("SELECT credits FROM clients WHERE api_key_hash = 'hash-kept'").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        webhooks = conn.execute("SELECT COUNT(*) FROM client_webhooks").fetchone()[0]
    assert {"signature_sha256", "settled_at"} <= cols
    assert receipt == ("rid-kept", None, None)
    assert credits == 7
    assert "client_webhooks" in tables
    assert webhooks == 0


def test_retry_exhaustion_is_five_sends(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    calls = {"n": 0}

    def poster(url, body, headers, timeout):
        calls["n"] += 1
        return 500, b""

    module.webhook_send.poster = poster
    with TestClient(module.app) as http:
        key = _buy(http)
        assert _put_hook(http, key).status_code == 200
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
    now = int(_hooks()[0]["next_attempt_at"])
    for _ in range(5):
        module.webhook_send.pump_once(now=now)
        row = _hooks()[0]
        if row["status"] == "pending":
            now = int(row["next_attempt_at"])
    assert calls["n"] == 5
    assert _hooks()[0]["status"] == "failed"
    assert _hooks()[0]["attempts"] == 5
    module.webhook_send.pump_once(now=now + 100_000)
    assert calls["n"] == 5
    assert hmac.compare_digest(_VECTOR["signature"], _VECTOR["signature"])


def _public_resolver(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))]


def _ledger_blob() -> str:
    rows = _rows("SELECT reason, IFNULL(ref, '') FROM ledger")
    return "\n".join(f"{row[0]} {row[1]}" for row in rows)


def test_response_cap_ignores_compression_and_stops_at_the_limit(tmp_path):
    import gzip

    module = _load_app(tmp_path, **_env())
    compressed = gzip.compress(b"\x00" * (8 * 1024 * 1024), compresslevel=9)
    assert 4096 < len(compressed) < 32 * 1024
    extra: list[str] = []

    class OneChunk(httpx.SyncByteStream):
        def __iter__(self):
            self.reads = 0
            return self

        def __next__(self):
            self.reads += 1
            if self.reads == 1:
                return compressed
            extra.append("again")
            raise httpx.ReadTimeout("past the cap")

        def close(self) -> None:
            return None

    seen = {}

    def compressed_handler(request: httpx.Request) -> httpx.Response:
        seen["accept"] = request.headers.get("accept-encoding")
        return httpx.Response(200, stream=OneChunk(), headers={"content-encoding": "gzip"})

    status, payload = module.ssrf.safe_post_bytes(
        _HOOK,
        b"{}",
        resolver=_public_resolver,
        client=httpx.Client(transport=httpx.MockTransport(compressed_handler)),
        max_bytes=4096,
    )
    assert status == 200
    assert payload == compressed[:4096]
    assert payload.startswith(b"\x1f\x8b")
    assert extra == []
    assert seen["accept"] == "identity"

    class ExactThenTimeout(httpx.SyncByteStream):
        def __iter__(self):
            self.reads = 0
            return self

        def __next__(self):
            self.reads += 1
            if self.reads == 1:
                return b"Z" * 4096
            extra.append("exact-extra")
            raise httpx.ReadTimeout("body already full")

        def close(self) -> None:
            return None

    status, payload = module.ssrf.safe_post_bytes(
        _HOOK,
        b"{}",
        resolver=_public_resolver,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=ExactThenTimeout()))),
        max_bytes=4096,
    )
    assert status == 200
    assert payload == b"Z" * 4096
    assert extra == []

    gate = threading.Event()

    class SlowTail(httpx.SyncByteStream):
        def __iter__(self):
            self.reads = 0
            return self

        def __next__(self):
            self.reads += 1
            if self.reads == 1:
                return b"abc"
            gate.wait(2)
            return b"late"

        def close(self) -> None:
            gate.set()

    started = time.monotonic()
    status, payload = module.ssrf.safe_post_bytes(
        _HOOK,
        b"{}",
        resolver=_public_resolver,
        timeout=5.0,
        deadline=0.25,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=SlowTail()))),
    )
    elapsed = time.monotonic() - started
    gate.set()
    assert status == 200
    assert payload == b"abc"
    assert elapsed < 1.0


def test_crash_before_result_never_sends_a_sixth_time(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)

    class _Crash(BaseException):
        pass

    calls: list[int] = []

    def explode(url, body, headers):
        calls.append(1)
        raise _Crash()

    module.webhook_send._post = explode
    with TestClient(module.app) as http:
        key = _buy(http)
        assert _put_hook(http, key).status_code == 200
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
    now = int(_hooks()[0]["next_attempt_at"])
    for _ in range(6):
        try:
            module.webhook_send.pump_once(now=now)
        except _Crash:
            pass
        now += module.webhook_send.STALE_SENDING_SECONDS + 1
    assert len(calls) == 5
    row = _hooks()[0]
    assert row["status"] == "failed"
    assert int(row["attempts"]) == 5
    module.webhook_send._reclaim_stale(now + 10_000)
    module.webhook_send._reclaim_stale(now + 20_000)
    module.webhook_send.pump_once(now=now + 30_000)
    assert len(calls) == 5
    assert _hooks()[0]["status"] == "failed"


def test_webhook_configuration_changes_are_audited(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    secret_url = "https://hooks.example/satsgate?token=super-secret-query"
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _put_hook(http, key, secret_url)
        assert created.status_code == 200, created.text
        secret = created.json()["secret"]
        replaced = _put_hook(http, key, "https://hooks.example/other")
        assert replaced.status_code == 200, replaced.text
        rotated = _put_hook(http, key, "https://hooks.example/other", rotate=True)
        assert rotated.status_code == 200, rotated.text
        with sqlite3.connect(os_db()) as conn:
            conn.execute("UPDATE client_webhooks SET enabled = 0, disabled_reason = 'http_410'")
        again = _put_hook(http, key, "https://hooks.example/other")
        assert again.status_code == 200, again.text
        assert "secret" not in again.json()
        removed = http.delete("/v1/client/webhook", headers={"X-Api-Key": key})
        assert removed.status_code == 200
    reasons = [row["reason"] for row in _rows("SELECT reason FROM ledger ORDER BY id")]
    assert "webhook_created" in reasons
    assert "webhook_url_changed" in reasons
    assert "webhook_secret_rotated" in reasons
    assert "webhook_enabled" in reasons
    assert "webhook_deleted" in reasons
    blob = _ledger_blob()
    assert secret not in blob
    assert rotated.json()["secret"] not in blob
    assert "super-secret-query" not in blob
    assert secret_url not in blob
    assert "whsec_" not in blob
    assert "Satsgate-Webhook-Signature" not in blob


def test_404_disables_and_is_audited(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env(SATSGATE_RESEND_API_KEY="re_test_key_value_not_a_secret"))
    _patch_dns(monkeypatch, module)

    def missing(url, body, headers, timeout):
        return 404, b"no"

    module.webhook_send.poster = missing
    with TestClient(module.app) as http:
        key = _buy(http)
        saved = http.put(
            "/v1/client/alert-email",
            headers={"X-Api-Key": key},
            json={"email": "seller@proton.me"},
        )
        token = json.loads(_email()[-1]["params_json"])["token"]
        assert saved.status_code == 200
        assert http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token}).status_code == 200
        assert _put_hook(http, key).status_code == 200
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
    module.webhook_send.pump_once(now=int(time.time()))
    row = _rows("SELECT enabled, disabled_reason FROM client_webhooks")[0]
    assert row["enabled"] == 0
    assert row["disabled_reason"] == "http_404"
    audited = [item for item in _rows("SELECT reason, ref FROM ledger") if item["reason"] == "webhook_disabled"]
    assert audited[-1]["ref"] == "http_404"
    assert "hooks.example" not in _ledger_blob()
    disabled = [item for item in _email() if item["kind"] == "webhook_disabled"]
    assert json.loads(disabled[0]["params_json"])["status"] == 404
    module.webhook_send.pump_once(now=int(time.time()) + 10_000)
    assert _hooks()[0]["status"] == "failed"


def test_unreadable_ciphertext_fails_once(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    calls: list[int] = []

    def poster(url, body, headers, timeout):
        calls.append(1)
        return 200, b""

    module.webhook_send.poster = poster
    with TestClient(module.app) as http:
        key = _buy(http)
        assert _put_hook(http, key).status_code == 200
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
    with sqlite3.connect(os_db()) as conn:
        conn.execute("UPDATE client_webhooks SET secret_enc = 'not-ciphertext'")
    now = int(_hooks()[0]["next_attempt_at"])
    module.webhook_send.pump_once(now=now)
    assert calls == []
    assert _hooks()[0]["status"] == "failed"
    assert int(_hooks()[0]["attempts"]) == 1
    assert _rows("SELECT enabled FROM client_webhooks")[0]["enabled"] == 1
    module.webhook_send.pump_once(now=now + 10_000)
    assert calls == []


def test_webhook_input_is_rejected_without_a_500(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    quickstart = (ROOT / "CUSTOMER_QUICKSTART.md").read_text(encoding="utf-8")
    block = quickstart.split("```python", 1)[1].split("```", 1)[0]
    namespace: dict = {}
    exec(block, namespace)
    verify = namespace["verify_satsgate_webhook"]
    body = _VECTOR["body"].encode("utf-8")
    assert verify(_VECTOR["secret"], str(_VECTOR["timestamp"]), body, _VECTOR["signature"], _VECTOR["now"]) is True
    assert verify(_VECTOR["secret"], "not-a-timestamp", body, _VECTOR["signature"], _VECTOR["now"]) is False
    assert verify(_VECTOR["secret"], str(_VECTOR["timestamp"]), body, _VECTOR["signature"], "now") is False
    with TestClient(module.app) as http:
        key = _buy(http)
        broken = http.put(
            "/v1/client/webhook",
            headers={"X-Api-Key": key},
            json={"url": "https://[::1"},
        )
        assert broken.status_code == 400
        assert broken.json()["error"] == "invalid_webhook_url"
        unknown = http.put(
            "/v1/client/webhook",
            headers={"X-Api-Key": key},
            json={"url": _HOOK, "note": "nope"},
        )
        assert unknown.status_code == 400
        assert unknown.json()["error"] == "invalid_webhook_url"
        oversized = "x" * 3000
        huge = http.put(
            "/v1/client/webhook",
            headers={"X-Api-Key": key, "Content-Type": "application/json"},
            content=json.dumps({"url": _HOOK, "pad": oversized}),
        )
        assert huge.status_code == 400
        assert huge.json()["error"] == "invalid_webhook_url"
        assert oversized not in huge.text
        assert _rows("SELECT client_id FROM client_webhooks") == []


def test_security_limit_follows_the_account_not_the_key(tmp_path, monkeypatch):
    module = _load_app(
        tmp_path,
        **_env(
            SATSGATE_RL_ENABLED="1",
            SATSGATE_RL_MAX_SECURITY="2",
            SATSGATE_RL_MAX_AUTH="100",
            SATSGATE_RL_WINDOW_SECONDS="60",
        ),
    )
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        first = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": key})
        assert first.status_code == 200, first.text
        second = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": first.json()["api_key"]})
        assert second.status_code == 200, second.text
        newest = second.json()["api_key"]
        blocked = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": newest})
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "rate_limited"
        assert blocked.headers["retry-after"]
        assert http.get("/v1/balance", headers={"X-Api-Key": newest}).status_code == 200
        assert http.get("/v1/balance", headers={"X-Api-Key": key}).status_code == 401
