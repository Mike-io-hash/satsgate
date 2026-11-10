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
    with pytest.raises(module.ssrf.SSRFError) as caught:
        module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            resolver=_public_resolver,
            timeout=5.0,
            deadline=0.25,
            client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=SlowTail()))),
        )
    elapsed = time.monotonic() - started
    gate.set()
    assert caught.value.code == "fetch_failed"
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


def test_restricted_key_does_not_spend_the_security_quota(tmp_path, monkeypatch):
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
    calls = (
        ("POST", "/v1/client/api-key/rotate", None),
        ("PUT", "/v1/client/webhook", {"url": _HOOK}),
        ("PUT", "/v1/client/webhook", {"url": _HOOK, "rotate_secret": True}),
        ("DELETE", "/v1/client/webhook", None),
        ("POST", "/v1/client/webhook/test", None),
    )
    with TestClient(module.app) as http:
        key = _buy(http)
        minted = http.post("/v1/api-keys", headers={"X-Api-Key": key}, json={"label": "paywall"})
        restricted = minted.json()["api_key"]
        for method, path, body in calls:
            for _ in range(2):
                denied = http.request(method, path, headers={"X-Api-Key": restricted}, json=body)
                assert denied.status_code == 403, (method, path, denied.text)
                assert denied.json()["error"] == "insufficient_scope"
        rotated = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": key})
        assert rotated.status_code == 200, rotated.text
        again = http.post("/v1/client/api-key/rotate", headers={"X-Api-Key": rotated.json()["api_key"]})
        assert again.status_code == 200, again.text
        blocked = http.post("/v1/client/webhook/test", headers={"X-Api-Key": again.json()["api_key"]})
        assert blocked.status_code == 429
        assert blocked.json()["error"] == "rate_limited"
        assert http.get("/v1/balance", headers={"X-Api-Key": again.json()["api_key"]}).status_code == 200


def test_delivery_deadline_covers_dns_headers_and_body(tmp_path):
    module = _load_app(tmp_path, **_env())
    budget = 0.12
    tolerance = 0.35

    def assert_timeout(call) -> None:
        started = time.monotonic()
        with pytest.raises(module.ssrf.SSRFError) as caught:
            call()
        elapsed = time.monotonic() - started
        assert caught.value.code == "fetch_failed"
        assert elapsed <= budget + tolerance

    def slow_headers(request: httpx.Request) -> httpx.Response:
        time.sleep(0.6)
        return httpx.Response(200, content=b"ok")

    assert_timeout(
        lambda: module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            resolver=_public_resolver,
            deadline=budget,
            timeout=5.0,
            client=httpx.Client(transport=httpx.MockTransport(slow_headers)),
        )
    )

    def slow_dns(host, port, *args, **kwargs):
        time.sleep(0.6)
        return _public_resolver(host, port)

    assert_timeout(
        lambda: module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            resolver=slow_dns,
            deadline=budget,
            timeout=5.0,
            client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"ok"))),
        )
    )

    class LateBody(httpx.SyncByteStream):
        def __iter__(self):
            return self

        def __next__(self):
            time.sleep(0.6)
            return b"late"

        def close(self) -> None:
            return None

    assert_timeout(
        lambda: module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            resolver=_public_resolver,
            deadline=budget,
            timeout=5.0,
            client=httpx.Client(
                transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=LateBody()))
            ),
        )
    )

    seen = {}

    def fast(request: httpx.Request) -> httpx.Response:
        seen["accept"] = request.headers.get("accept-encoding")
        return httpx.Response(200, content=b"ready")

    status, payload = module.ssrf.safe_post_bytes(
        _HOOK,
        b"{}",
        resolver=_public_resolver,
        deadline=budget,
        timeout=5.0,
        client=httpx.Client(transport=httpx.MockTransport(fast)),
    )
    assert status == 200
    assert payload == b"ready"
    assert seen["accept"] == "identity"


def _http_workers() -> list[threading.Thread]:
    return [thread for thread in threading.enumerate() if thread.name == "satsgate-webhook-http" and thread.is_alive()]


def _dns_workers() -> list[threading.Thread]:
    return [thread for thread in threading.enumerate() if thread.name == "satsgate-webhook-dns" and thread.is_alive()]


class _CloseableStream(httpx.SyncByteStream):
    """Not used. Pool tests speak HTTP on a fake network stream."""


def _pool_client(backend):
    import ssl

    import httpcore

    pool = httpcore.ConnectionPool(
        ssl_context=ssl.create_default_context(),
        max_connections=1,
        max_keepalive_connections=1,
        retries=0,
        network_backend=backend,
    )
    transport = httpx.HTTPTransport(retries=0, trust_env=False)
    transport._pool.close()
    transport._pool = pool
    client = httpx.Client(transport=transport, follow_redirects=False, trust_env=False)
    return client, pool


class _ScriptedBackend:
    """In-memory HTTP/1.1 peer. ``close`` unblocks a stalled read."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.connects = 0
        self.streams: list[_ScriptedStream] = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connects += 1
        stream = _ScriptedStream(self.mode)
        self.streams.append(stream)
        return stream

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise OSError("no unix socket")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class _ScriptedStream:
    def __init__(self, mode: str) -> None:
        import httpcore

        self._errors = httpcore
        self.mode = mode
        self.closed = threading.Event()
        self.was_closed = False
        self._header = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
        self._index = 0
        self._body_started = False

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self.was_closed or self.closed.is_set():
            return b""
        if self.mode == "fast":
            self.was_closed = True
            return self._header + b"fastbody"
        if self.mode == "headers":
            if self.closed.wait(0.01):
                return b""
            if self._index >= len(self._header):
                if self.closed.wait(0.01):
                    return b""
                return b"x"
            self._index += 1
            return self._header[self._index - 1 : self._index]
        if not self._body_started:
            self._body_started = True
            return self._header + b"x"
        if self.closed.wait(0 if timeout == 0 else (timeout if timeout is not None else 2)):
            return b""
        raise self._errors.ReadTimeout()

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if self.was_closed:
            raise OSError("closed")

    def close(self) -> None:
        self.was_closed = True
        self.closed.set()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return self

    def get_extra_info(self, info: str):
        return None


def _pool_in_use(pool) -> int:
    used = 0
    for conn in list(pool.connections):
        try:
            if not conn.is_closed() and not conn.is_idle():
                used += 1
        except Exception:
            used += 1
    return used


def test_expired_delivery_releases_the_pool_and_the_worker(tmp_path):
    module = _load_app(tmp_path, **_env())
    budget = 0.12
    tolerance = 0.35

    def deliver(mode: str):
        backend = _ScriptedBackend(mode)
        client, pool = _pool_client(backend)
        started = time.monotonic()
        with pytest.raises(module.ssrf.SSRFError) as caught:
            module.ssrf.safe_post_bytes(
                _HOOK,
                b"{}",
                resolver=_public_resolver,
                deadline=budget,
                timeout=5.0,
                client=client,
            )
        elapsed = time.monotonic() - started
        assert caught.value.code == "fetch_failed"
        assert elapsed <= budget + tolerance
        deadline = time.monotonic() + 0.5
        while _http_workers() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _http_workers() == []
        assert _pool_in_use(pool) == 0
        assert backend.streams
        assert backend.streams[-1].was_closed
        fast = _ScriptedBackend("fast")
        # Reuse the same pool by swapping only the backend's behavior is not
        # possible; the next delivery goes through this same pool object.
        pool._network_backend = fast
        status, payload = module.ssrf.safe_post_bytes(
            _HOOK,
            b"ok",
            resolver=_public_resolver,
            deadline=1.0,
            timeout=1.0,
            client=client,
        )
        assert status == 200
        assert payload == b"fastbody"
        assert fast.connects == 1
        client.close()

    deliver("headers")
    deliver("body")
    assert _http_workers() == []

    for _ in range(4):
        backend = _ScriptedBackend("headers")
        client, _pool = _pool_client(backend)
        with pytest.raises(module.ssrf.SSRFError):
            module.ssrf.safe_post_bytes(
                _HOOK,
                b"{}",
                resolver=_public_resolver,
                deadline=budget,
                timeout=5.0,
                client=client,
            )
        client.close()
    deadline = time.monotonic() + 0.5
    while _http_workers() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(_http_workers()) <= 1


def test_resolver_threads_are_bounded_and_do_not_post(tmp_path):
    module = _load_app(tmp_path, **_env())
    release = threading.Event()
    connects = {"n": 0}

    def slow_dns(host, port, *args, **kwargs):
        release.wait(0.4)
        return _public_resolver(host, port)

    class CountingBackend(_ScriptedBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            connects["n"] += 1
            return super().connect_tcp(host, port, timeout, local_address, socket_options)

    backend = CountingBackend("fast")
    client, _pool = _pool_client(backend)
    errors: list[str] = []

    def once():
        try:
            module.ssrf.safe_post_bytes(
                _HOOK,
                b"{}",
                resolver=slow_dns,
                deadline=0.1,
                timeout=5.0,
                client=client,
            )
        except module.ssrf.SSRFError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=once) for _ in range(4)]
    for thread in threads:
        thread.start()
    found = time.monotonic() + 0.3
    while len(_dns_workers()) < 4 and time.monotonic() < found:
        time.sleep(0.01)
    assert len(_dns_workers()) <= 4
    started = time.monotonic()
    once()
    assert time.monotonic() - started < 0.08
    assert errors[-1] == "fetch_failed"
    for thread in threads:
        thread.join(1)
    assert connects["n"] == 0
    release.set()
    deadline = time.monotonic() + 1
    while _dns_workers() and time.monotonic() < deadline:
        time.sleep(0.01)
    client.close()


def test_partial_or_slow_body_is_a_retryable_failure(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)

    def attempt(mode: str) -> None:
        backend = _ScriptedBackend(mode)
        client, _pool = _pool_client(backend)

        def poster(url, body, headers, timeout):
            return module.ssrf.safe_post_bytes(
                url,
                body,
                headers=headers,
                timeout=timeout,
                deadline=0.1,
                resolver=_public_resolver,
                client=client,
            )

        module.webhook_send.poster = poster
        with TestClient(module.app) as http:
            key = _buy(http)
            assert _put_hook(http, key).status_code == 200
            assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
        now = int(_hooks()[-1]["next_attempt_at"])
        module.webhook_send.pump_once(now=now)
        row = _hooks()[-1]
        assert row["status"] == "pending"
        assert int(row["attempts"]) == 1
        assert int(row["next_attempt_at"]) - now == 60
        client.close()
        with sqlite3.connect(os_db()) as conn:
            conn.execute("DELETE FROM webhook_outbox")
            conn.execute("DELETE FROM client_webhooks")

    attempt("body")
    attempt("headers")

    for status_code, body in ((200, b"ready"), (204, b""), (404, b"no"), (410, b"gone")):
        seen = {}

        def handler(request, status_code=status_code, body=body):
            seen["accept"] = request.headers.get("accept-encoding")
            return httpx.Response(status_code, content=body)

        code, payload = module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            resolver=_public_resolver,
            deadline=1.0,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert code == status_code
        assert payload == body
        assert seen["accept"] == "identity"


def _permit_value(module) -> int:
    return int(module.ssrf._resolver_slots._value)


class _DnsCtorBoom(threading.Thread):
    def __init__(self, *args, **kwargs):
        if kwargs.get("name") == "satsgate-webhook-dns":
            raise RuntimeError("constructor failed")
        super().__init__(*args, **kwargs)


class _DnsStartBoom(threading.Thread):
    def start(self):
        if self.name == "satsgate-webhook-dns":
            raise RuntimeError("start failed")
        super().start()


def test_dns_permit_returns_when_the_worker_never_starts(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    assert _permit_value(module) == 4
    real_thread = threading.Thread
    connects = {"n": 0}

    class _Counting(_ScriptedBackend):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            connects["n"] += 1
            return super().connect_tcp(host, port, timeout, local_address, socket_options)

    for boom in (_DnsCtorBoom, _DnsStartBoom):
        monkeypatch.setattr(module.ssrf.threading, "Thread", boom)
        client, _pool = _pool_client(_Counting("fast"))
        try:
            for _ in range(5):
                with pytest.raises(module.ssrf.SSRFError) as caught:
                    module.ssrf.safe_post_bytes(
                        _HOOK,
                        b"{}",
                        resolver=_public_resolver,
                        deadline=0.2,
                        timeout=5.0,
                        client=client,
                    )
                assert caught.value.code == "fetch_failed"
            assert connects["n"] == 0
            assert _permit_value(module) == 4
            assert _dns_workers() == []
        finally:
            client.close()

    monkeypatch.setattr(module.ssrf.threading, "Thread", real_thread)
    client, _pool = _pool_client(_ScriptedBackend("fast"))
    try:
        status, payload = module.ssrf.safe_post_bytes(
            _HOOK,
            b"{}",
            resolver=_public_resolver,
            deadline=1.0,
            client=client,
        )
        assert status == 200
        assert payload == b"fastbody"
        assert _permit_value(module) == 4
    finally:
        client.close()


def test_dns_permit_is_released_once_and_held_until_lookup_ends(tmp_path):
    module = _load_app(tmp_path, **_env())
    client, _pool = _pool_client(_ScriptedBackend("fast"))
    try:
        status, _payload = module.ssrf.safe_post_bytes(
            _HOOK, b"{}", resolver=_public_resolver, deadline=1.0, client=client
        )
        assert status == 200
        assert _permit_value(module) == 4

        def gai(host, port, *args, **kwargs):
            raise socket.gaierror("lookup failed")

        with pytest.raises(module.ssrf.SSRFError) as caught:
            module.ssrf.safe_post_bytes(_HOOK, b"{}", resolver=gai, deadline=1.0, client=client)
        assert caught.value.code == "destination_rejected"
        assert _permit_value(module) == 4

        def boom(host, port, *args, **kwargs):
            raise RuntimeError("lookup exploded")

        with pytest.raises(RuntimeError):
            module.ssrf.safe_post_bytes(_HOOK, b"{}", resolver=boom, deadline=1.0, client=client)
        assert _permit_value(module) == 4

        started = threading.Event()
        release = threading.Event()

        def blocking(host, port, *args, **kwargs):
            started.set()
            release.wait(3)
            return _public_resolver(host, port)

        with pytest.raises(module.ssrf.SSRFError) as caught:
            module.ssrf.safe_post_bytes(_HOOK, b"{}", resolver=blocking, deadline=0.05, client=client)
        assert caught.value.code == "fetch_failed"
        assert started.is_set()
        assert _dns_workers()
        assert _permit_value(module) == 3
        release.set()
        deadline = time.monotonic() + 1
        while _dns_workers() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _dns_workers() == []
        assert _permit_value(module) == 4

        release_all = threading.Event()

        def hold(host, port, *args, **kwargs):
            release_all.wait(3)
            return _public_resolver(host, port)

        errors: list[str] = []

        def once():
            try:
                module.ssrf.safe_post_bytes(_HOOK, b"{}", resolver=hold, deadline=0.4, client=client)
            except module.ssrf.SSRFError as exc:
                errors.append(exc.code)

        threads = [threading.Thread(target=once) for _ in range(4)]
        for thread in threads:
            thread.start()
        found = time.monotonic() + 0.5
        while len(_dns_workers()) < 4 and time.monotonic() < found:
            time.sleep(0.01)
        assert len(_dns_workers()) == 4
        assert _permit_value(module) == 0
        started_fifth = time.monotonic()
        once()
        assert time.monotonic() - started_fifth < 0.08
        assert errors[-1] == "fetch_failed"
        release_all.set()
        for thread in threads:
            thread.join(1)
        deadline = time.monotonic() + 1
        while _dns_workers() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _permit_value(module) == 4
        status, payload = module.ssrf.safe_post_bytes(
            _HOOK, b"ok", resolver=_public_resolver, deadline=1.0, client=client
        )
        assert status == 200
        assert payload == b"fastbody"
    finally:
        client.close()
        for thread in threading.enumerate():
            if thread.name == "satsgate-webhook-dns" and thread is not threading.current_thread():
                thread.join(0.2)


def test_dns_start_failure_uses_only_the_reserved_attempt(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    monkeypatch.setattr(module.ssrf.threading, "Thread", _DnsStartBoom)
    with TestClient(module.app) as http:
        key = _buy(http)
        credits = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"]
        assert _put_hook(http, key).status_code == 200
        assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
    now = int(_hooks()[-1]["next_attempt_at"])
    module.webhook_send.pump_once(now=now)
    row = _hooks()[-1]
    assert row["status"] == "pending"
    assert int(row["attempts"]) == 1
    assert int(row["last_status"]) == 0
    assert int(row["next_attempt_at"]) - now == 60
    module.webhook_send.pump_once(now=now)
    assert int(_hooks()[-1]["attempts"]) == 1
    with TestClient(module.app) as http:
        assert http.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"] == credits
    assert _permit_value(module) == 4


class _RecordingBackend:
    def __init__(self, events, clock, deadline):
        self.events = events
        self.clock = clock
        self.deadline = deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.events.append(("connect", timeout, self.clock["t"]))
        return _RecordingStream(self)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise OSError("no unix")

    def sleep(self, seconds):
        return None


class _RecordingStream:
    def __init__(self, backend):
        self.backend = backend
        self._sent = 0

    def read(self, max_bytes, timeout=None):
        now = self.backend.clock["t"]
        self.backend.events.append(("read", timeout, now))
        if now >= self.backend.deadline:
            raise TimeoutError("read after deadline")
        self.backend.clock["t"] = now + 0.25
        self._sent += 1
        return b"H"

    def write(self, buffer, timeout=None):
        self.backend.events.append(("write", timeout, self.backend.clock["t"]))

    def close(self):
        return None

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.backend.events.append(("tls", timeout, self.backend.clock["t"]))
        return self

    def get_extra_info(self, info):
        return None


def test_socket_timeouts_stay_inside_the_delivery_deadline(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    clock = {"t": 1_000.0}
    monkeypatch.setattr(module.ssrf.time, "monotonic", lambda: clock["t"])
    events: list[tuple] = []
    deadline = clock["t"] + 0.4
    backend = _RecordingBackend(events, clock, deadline)
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client, _pool = _pool_client(backend)
    client._transport._pool._ssl_context = context
    try:
        with pytest.raises(module.ssrf.SSRFError) as caught:
            module.ssrf.safe_post_bytes(
                _HOOK,
                b"{}",
                resolver=_public_resolver,
                deadline=0.4,
                timeout=5.0,
                client=client,
            )
        assert caught.value.code == "fetch_failed"
    finally:
        client.close()
    kinds = [item[0] for item in events]
    assert "connect" in kinds and "tls" in kinds and "write" in kinds and "read" in kinds
    assert any(kind == "read" and timeout is not None and timeout < 0.4 for kind, timeout, _now in events)
    for kind, timeout, now in events:
        assert timeout is not None
        assert timeout <= (deadline - now) + 1e-6
        assert now < deadline


def _mint_cert(directory, hostname: str):
    import os
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "key.pem"
    cert_path = directory / "cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_path, 0o600)
    return cert_path, key_path


def _tls_client(module, cert_path, backend):
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(cert_path))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    client, pool = _pool_client(backend)
    pool._ssl_context = context
    return client, pool


class _LoopbackPin:
    def __init__(self, module, port: int) -> None:
        self.module = module
        self.port = port
        self.connects = 0

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        from httpcore._backends.sync import SyncStream

        pinned = getattr(self.module.ssrf._local, "pinned_ip", None)
        pinned_host = getattr(self.module.ssrf._local, "pinned_host", None)
        if not pinned or not self.module.ssrf.is_public_ip(str(pinned)):
            raise self.module.ssrf.SSRFError("destination_rejected")
        if pinned_host and str(host).lower().rstrip(".") != str(pinned_host):
            raise self.module.ssrf.SSRFError("destination_rejected")
        self.connects += 1
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        return SyncStream(sock)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise OSError("no unix")

    def sleep(self, seconds):
        time.sleep(seconds)


def _serve_tls(cert_path, key_path, mode: str, origin: dict, release: threading.Event):
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    workers: list[threading.Thread] = []

    def handle(conn):
        tls = None
        try:
            tls = context.wrap_socket(conn, server_side=True)
            tls.settimeout(1)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 8192:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                buf += chunk
            if mode == "fast":
                body = b"ready"
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n" + body
                )
                release.wait(2)
                return
            if mode == "redirect":
                tls.sendall(
                    b"HTTP/1.1 302 Found\r\nLocation: https://hooks.example/next\r\nContent-Length: 0\r\n\r\n"
                )
                release.wait(2)
                return
            while origin.get("t") is None and not release.is_set():
                time.sleep(0.01)
            if origin.get("t") is not None:
                delay = origin["t"] + 0.3 - time.monotonic()
                if delay > 0:
                    time.sleep(min(delay, 1))
            if mode == "headers":
                tls.sendall(b"H")
            elif mode == "body200":
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nx")
            elif mode == "body404":
                tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 20\r\nConnection: close\r\n\r\nx")
            elif mode == "body410":
                tls.sendall(b"HTTP/1.1 410 Gone\r\nContent-Length: 20\r\nConnection: close\r\n\r\nx")
            release.wait(2)
        except Exception:
            return
        finally:
            try:
                if tls is not None:
                    tls.close()
                else:
                    conn.close()
            except Exception:
                return

    def accept():
        while not release.is_set():
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=handle, args=(conn,), daemon=True)
            workers.append(worker)
            worker.start()
        try:
            listener.close()
        except OSError:
            return

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    return port, thread, workers, listener


def test_real_tls_stalls_fail_and_fast_responses_stay(tmp_path):
    module = _load_app(tmp_path, **_env())
    cert_dir = tmp_path / "tls"
    cert_dir.mkdir()
    listeners = []
    try:
        for mode in ("headers", "body200", "body404", "body410"):
            cert_path, key_path = _mint_cert(cert_dir, "hooks.example")
            release = threading.Event()
            origin = {"t": None}
            port, thread, workers, listener = _serve_tls(cert_path, key_path, mode, origin, release)
            listeners.append((release, thread, workers, listener, cert_path, key_path))
            backend = _LoopbackPin(module, port)
            client, pool = _tls_client(module, cert_path, backend)
            try:
                repeats = 8 if mode == "headers" else 1
                for _ in range(repeats):
                    origin["t"] = time.monotonic()
                    started = origin["t"]
                    with pytest.raises(module.ssrf.SSRFError) as caught:
                        module.ssrf.safe_post_bytes(
                            _HOOK,
                            b"{}",
                            resolver=_public_resolver,
                            deadline=0.4,
                            timeout=5.0,
                            client=client,
                        )
                    elapsed = time.monotonic() - started
                    assert caught.value.code == "fetch_failed"
                    assert elapsed <= 0.4 + 0.1 + 0.15
                    assert _http_workers() == []
                    assert _pool_in_use(pool) == 0
            finally:
                release.set()
                client.close()
                for worker in workers:
                    worker.join(1)
                thread.join(1)
        cert_path, key_path = _mint_cert(cert_dir, "hooks.example")
        release = threading.Event()
        port, thread, workers, listener = _serve_tls(cert_path, key_path, "fast", {"t": None}, release)
        listeners.append((release, thread, workers, listener, cert_path, key_path))
        backend = _LoopbackPin(module, port)
        client, _pool = _tls_client(module, cert_path, backend)
        try:
            status, payload = module.ssrf.safe_post_bytes(
                _HOOK, b"{}", resolver=_public_resolver, deadline=1.0, client=client
            )
            assert status == 200
            assert payload == b"ready"
        finally:
            release.set()
            client.close()
            thread.join(1)
        wrong_cert, wrong_key = _mint_cert(cert_dir, "other.example")
        release = threading.Event()
        port, thread, workers, listener = _serve_tls(wrong_cert, wrong_key, "fast", {"t": None}, release)
        listeners.append((release, thread, workers, listener, wrong_cert, wrong_key))
        backend = _LoopbackPin(module, port)
        client, _pool = _tls_client(module, wrong_cert, backend)
        # Trust the other name, then ask for hooks.example. Hostname verification fails.
        try:
            with pytest.raises(module.ssrf.SSRFError) as caught:
                module.ssrf.safe_post_bytes(
                    _HOOK, b"{}", resolver=_public_resolver, deadline=1.0, client=client
                )
            assert caught.value.code == "fetch_failed"
        finally:
            release.set()
            client.close()
            thread.join(1)
        backend = _LoopbackPin(module, port)
        with pytest.raises(module.ssrf.SSRFError) as caught:
            module.ssrf.safe_post_bytes(
                _HOOK,
                b"{}",
                resolver=lambda host, port, *args, **kwargs: [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.2.0.8", port))
                ],
                deadline=1.0,
                client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
            )
        assert caught.value.code == "destination_rejected"
        assert backend.connects == 0

        def slow(host, port, *args, **kwargs):
            time.sleep(0.3)
            return _public_resolver(host, port)

        connects = {"n": 0}

        class _Count(_ScriptedBackend):
            def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
                connects["n"] += 1
                return super().connect_tcp(host, port, timeout, local_address, socket_options)

        client, _pool = _pool_client(_Count("fast"))
        try:
            with pytest.raises(module.ssrf.SSRFError) as caught:
                module.ssrf.safe_post_bytes(
                    _HOOK, b"{}", resolver=slow, deadline=0.1, timeout=5.0, client=client
                )
            assert caught.value.code == "fetch_failed"
            assert connects["n"] == 0
        finally:
            client.close()
    finally:
        for release, thread, workers, listener, cert_path, key_path in listeners:
            release.set()
            try:
                listener.close()
            except OSError:
                pass
            for worker in workers:
                worker.join(0.5)
            thread.join(0.5)
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)
        assert _http_workers() == []


def test_sender_deadline_miss_retries_and_then_stops(tmp_path, monkeypatch):
    module = _load_app(tmp_path, **_env())
    _patch_dns(monkeypatch, module)
    cert_dir = tmp_path / "tls"
    cert_dir.mkdir()
    cert_path, key_path = _mint_cert(cert_dir, "hooks.example")
    release = threading.Event()
    origin = {"t": None}
    port, thread, workers, listener = _serve_tls(cert_path, key_path, "body404", origin, release)
    backend = _LoopbackPin(module, port)
    client, _pool = _tls_client(module, cert_path, backend)

    def poster(url, body, headers, timeout):
        origin["t"] = time.monotonic()
        return module.ssrf.safe_post_bytes(
            url,
            body,
            headers=headers,
            timeout=timeout,
            deadline=0.4,
            resolver=_public_resolver,
            client=client,
        )

    try:
        module.webhook_send.poster = poster
        with TestClient(module.app) as http:
            key = _buy(http)
            credits = http.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"]
            assert _put_hook(http, key).status_code == 200
            assert http.post("/v1/client/webhook/test", headers={"X-Api-Key": key}).status_code == 200
        now = int(_hooks()[-1]["next_attempt_at"])
        module.webhook_send.pump_once(now=now)
        row = _hooks()[-1]
        assert row["status"] == "pending"
        assert int(row["attempts"]) == 1
        assert int(row["last_status"]) == 0
        assert int(row["next_attempt_at"]) - now == 60
        assert int(_rows("SELECT enabled FROM client_webhooks")[0]["enabled"]) == 1
        module.webhook_send.pump_once(now=now)
        assert int(_hooks()[-1]["attempts"]) == 1
        for _ in range(4):
            now = int(_hooks()[-1]["next_attempt_at"])
            module.webhook_send.pump_once(now=now)
        assert _hooks()[-1]["status"] == "failed"
        assert int(_hooks()[-1]["attempts"]) == 5
        module.webhook_send.pump_once(now=now + 100_000)
        assert int(_hooks()[-1]["attempts"]) == 5
        with TestClient(module.app) as http:
            assert http.get("/v1/balance", headers={"X-Api-Key": key}).json()["credits"] == credits
    finally:
        release.set()
        client.close()
        for worker in workers:
            worker.join(0.5)
        thread.join(0.5)
        try:
            listener.close()
        except OSError:
            pass
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
        module.webhook_send.poster = None
