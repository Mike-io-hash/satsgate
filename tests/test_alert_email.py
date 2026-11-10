"""Optional security-alert email. The sender poster never reaches Resend."""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import sqlite3
import threading
import time

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

from test_payee_connect import _buy, _headers, _load_app, _mint_link, _sign

_KEY = "re_test_key_value_not_a_secret"
_RPC = "https://rpc.example/v1/secretkeyvalue"


def _env(**extra):
    base = {
        "SATSGATE_RESEND_API_KEY": _KEY,
        "SATSGATE_EMAIL_ENABLED": "0",
        "SATSGATE_SUPPORT_EMAIL": "satsgateapp@proton.me",
        "SATSGATE_BASE_RPC_URL": _RPC,
    }
    base.update(extra)
    return base


def _rows(query: str, args=()):
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, args).fetchall()


def _outbox():
    return _rows("SELECT * FROM email_outbox ORDER BY id")


def _client():
    return _rows("SELECT * FROM clients")[0]


def _put(http: TestClient, key: str, email: str):
    return http.put(
        "/v1/client/alert-email",
        headers={"X-Api-Key": key},
        json={"email": email},
    )


def _confirm_token(http: TestClient, key: str, email: str = "seller@proton.me") -> str:
    saved = _put(http, key, email)
    assert saved.status_code == 200, saved.text
    params = json.loads(_outbox()[-1]["params_json"])
    token = params["token"]
    confirmed = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
    assert confirmed.status_code == 200, confirmed.text
    return token


def test_set_confirm_mask_and_hash(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        saved = _put(http, key, "Seller@Proton.Me")
        assert saved.status_code == 200, saved.text
        body = saved.json()
        assert body["alert_email"] is None
        assert body["alert_email_pending"] == "S***@proton.me"
        assert body["alert_email_status"] == "pending"
        assert "Seller@" not in json.dumps(body)
        row = _client()
        assert row["alert_email"] is None
        assert row["alert_email_pending"] == "Seller@proton.me"
        queued = _outbox()
        assert [item["kind"] for item in queued] == ["alert_email_confirm"]
        assert queued[0]["to_email"] == "Seller@proton.me"
        token = json.loads(queued[0]["params_json"])["token"]
        assert token.startswith("sge_")
        assert row["alert_email_pending_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in row["alert_email_pending_hash"]
        info = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        assert info["alert_email_status"] == "pending"
        assert info["alert_email_pending"] == "S***@proton.me"
        assert info["email_alerts_available"] is True
        assert info["payee_evm_kind"] == "eoa"
        preview = http.get("/v1/connect/alert-email", headers={"X-Email-Token": token})
        assert preview.status_code == 200, preview.text
        assert preview.json()["alert_email_pending"] == "S***@proton.me"
        assert preview.json()["client_id"] == info["client_id"]
        still = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        assert still["alert_email_status"] == "pending"
        confirmed = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["alert_email"] == "S***@proton.me"
        assert confirmed.json()["alert_email_status"] == "confirmed"
        assert "Seller@" not in confirmed.text
        kinds = [item["kind"] for item in _outbox()]
        assert kinds == ["alert_email_confirm", "alert_email_confirmed"]
        assert _outbox()[-1]["to_email"] == "Seller@proton.me"
        used = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
        assert used.status_code == 401
        assert used.json()["error"] == "email_link_invalid"
        after = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        assert after["alert_email_status"] == "confirmed"
        assert after["alert_email"] == "S***@proton.me"
        assert after["alert_email_pending"] is None


def test_pending_does_not_replace_confirmed_and_old_address_is_told(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        _confirm_token(http, key, "old@proton.me")
        # The 60s confirmation limit would block a second send. Age the first row.
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE email_outbox SET created_at = created_at - 120")
        changed = _put(http, key, "new@proton.me")
        assert changed.status_code == 200, changed.text
        assert changed.json()["alert_email"] == "o***@proton.me"
        assert changed.json()["alert_email_pending"] == "n***@proton.me"
        assert changed.json()["alert_email_status"] == "pending"
        assert _client()["alert_email"] == "old@proton.me"
        fresh = [item for item in _outbox() if item["id"] > 2]
        by_dest = {item["to_email"]: item["kind"] for item in fresh}
        assert by_dest["new@proton.me"] == "alert_email_confirm"
        assert by_dest["old@proton.me"] == "alert_email_change_requested"
        assert "new@proton.me" not in json.loads(
            next(item["params_json"] for item in fresh if item["kind"] == "alert_email_change_requested")
        )["masked_new"]
        token = json.loads(next(item["params_json"] for item in fresh if item["kind"] == "alert_email_confirm"))["token"]
        done = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
        assert done.status_code == 200, done.text
        assert _client()["alert_email"] == "new@proton.me"
        told = [item for item in _outbox() if item["kind"] == "alert_email_changed"]
        assert told[0]["to_email"] == "old@proton.me"
        assert json.loads(told[0]["params_json"])["masked_new"] == "n***@proton.me"
        removed = http.delete("/v1/client/alert-email", headers={"X-Api-Key": key})
        assert removed.status_code == 200, removed.text
        assert removed.json()["alert_email_status"] == "none"
        assert _client()["alert_email"] is None
        gone = [item for item in _outbox() if item["kind"] == "alert_email_removed"]
        assert gone[0]["to_email"] == "new@proton.me"


def test_connect_route_cannot_replace_a_confirmed_address(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        _confirm_token(http, key, "kept@proton.me")
        token, _body = _mint_link(http, key)
        rejected = http.post(
            "/v1/connect/alert-email",
            headers=_headers(token),
            json={"email": "other@proton.me"},
        )
        assert rejected.status_code == 409
        assert rejected.json()["error"] == "alert_email_already_set"
        assert _client()["alert_email"] == "kept@proton.me"
        assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200
        session = http.get("/v1/connect/evm", headers=_headers(token)).json()
        assert session["alert_email_status"] == "confirmed"
        assert session["alert_email"] == "k***@proton.me"
        assert session["email_alerts_available"] is True


def test_restricted_key_and_bad_tokens(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        minted = http.post("/v1/api-keys", headers={"X-Api-Key": key}, json={"label": "paywall"})
        restricted = minted.json()["api_key"]
        denied = _put(http, restricted, "a@b.co")
        assert denied.status_code == 403
        assert denied.json()["error"] == "insufficient_scope"
        saved = _put(http, key, "a@b.co")
        token = json.loads(_outbox()[-1]["params_json"])["token"]
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE clients SET alert_email_pending_expires = 1")
        expired = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
        assert expired.status_code == 401
        assert expired.json()["error"] == "email_link_invalid"
        missing = http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": "sge_" + "a" * 20})
        assert missing.status_code == 401
        assert missing.json()["error"] == "email_link_invalid"
        assert saved.status_code == 200
        for bad in ("not-an-email", "a@b@c.co", "a b@c.co", '"q"@c.co', "a@localhost", "Ann <a@b.co>"):
            rejected = _put(http, key, bad)
            assert rejected.status_code == 400, bad
            assert rejected.json()["error"] == "invalid_email"
            assert bad not in rejected.text
        accepted = _put(http, key, "user@xn--bcher-kva.example")
        # The previous pending is less than 60s old, so this is rate limited, not invalid.
        assert accepted.status_code == 429
        assert "xn--bcher-kva.example" not in accepted.text


def test_validation_accepts_a_punycode_domain_when_the_limit_allows_it(tmp_path):
    _load_app(tmp_path, **_env())
    alerts = importlib.import_module("app.db_alert_email")
    errors = importlib.import_module("app.x402")
    assert alerts.normalize_email("user@xn--bcher-kva.example") == "user@xn--bcher-kva.example"
    assert alerts.normalize_email("  Seller@Proton.Me. ") == "Seller@proton.me"
    with pytest.raises(errors.X402Error):
        alerts.normalize_email("a" * 65 + "@proton.me")


def test_payout_alerts_include_first_set_and_skip_repeats(tmp_path):
    module = _load_app(tmp_path, **_env())
    owner = Account.create()
    other = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        saved = http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        assert saved.status_code == 200, saved.text
        assert _outbox() == []
        _confirm_token(http, key, "alerts@proton.me")
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE email_outbox SET created_at = created_at - 120")
        again = http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        assert again.status_code == 200, again.text
        assert [item["kind"] for item in _outbox() if item["kind"].startswith("payee_")] == []
        moved = http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "other@pay.example"},
        )
        assert moved.status_code == 200, moved.text
        lightning = [item for item in _outbox() if item["kind"] == "payee_lightning_changed"]
        assert len(lightning) == 1
        params = json.loads(lightning[0]["params_json"])
        assert params["new"] == "othe…@pay.example"
        assert params["previous"] == "merc…@pay.example"
        assert params["via"] == "API"
        assert "other@pay.example" not in lightning[0]["params_json"]
        assert "merchant@pay.example" not in lightning[0]["params_json"]

        challenge = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": owner.address},
        )
        first = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": owner.address, "signature": _sign(owner, challenge.json()["message"])},
        )
        assert first.status_code == 200, first.text
        assert first.json()["rails_cleared"] is False
        evm = [item for item in _outbox() if item["kind"] == "payee_evm_changed"]
        assert len(evm) == 1
        evm_params = json.loads(evm[0]["params_json"])
        assert evm_params["previous"] == "none"
        assert evm_params["via"] == "API"
        assert owner.address not in evm[0]["params_json"]
        same = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": owner.address},
        )
        repeat = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": owner.address, "signature": _sign(owner, same.json()["message"])},
        )
        assert repeat.status_code == 200, repeat.text
        assert repeat.json()["rails_cleared"] is False
        assert len([item for item in _outbox() if item["kind"] == "payee_evm_changed"]) == 1
        nxt = http.post(
            "/v1/client/payee/evm/challenge",
            headers={"X-Api-Key": key},
            json={"address": other.address},
        )
        changed = http.post(
            "/v1/client/payee/evm",
            headers={"X-Api-Key": key},
            json={"address": other.address, "signature": _sign(other, nxt.json()["message"])},
        )
        assert changed.json()["rails_cleared"] is True
        assert len([item for item in _outbox() if item["kind"] == "payee_evm_changed"]) == 2


def test_first_challenge_queues_a_lightning_alert(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        _confirm_token(http, key, "alerts@proton.me")
        issued = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "api/premium", "amount_sats": 1, "payee_lightning_address": "merchant@pay.example"},
        )
        assert issued.status_code == 200, issued.text
        assert issued.json()["payee_saved"] is True
        kinds = [item["kind"] for item in _outbox()]
        assert "payee_lightning_changed" in kinds
        again = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": key},
            json={"resource": "api/premium", "amount_sats": 1, "payee_lightning_address": "merchant@pay.example"},
        )
        assert again.status_code == 200, again.text
        assert [item["kind"] for item in _outbox()].count("payee_lightning_changed") == 1


def test_outbox_rolls_back_with_the_payee_write(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        _confirm_token(http, key, "alerts@proton.me")
    before = len(_outbox())
    address = _client()["payee_lightning_address"]

    def boom():
        raise RuntimeError("boom")

    module.db_alert_email.commit_guard = boom
    with pytest.raises(RuntimeError, match="boom"):
        module.db_clients.set_client_payee(
            os.environ["SATSGATE_DB_PATH"],
            client_id=int(_client()["id"]),
            payee_lightning_address="other@pay.example",
        )
    assert _client()["payee_lightning_address"] == address
    assert len(_outbox()) == before


def test_sender_retries_and_clears_secrets(tmp_path):
    module = _load_app(tmp_path, **_env())
    captured = []

    def poster(url, body, headers, timeout):
        captured.append((url, body, headers, timeout))
        if len(captured) <= 5:
            return 500, None
        return 200, {"id": "ok"}

    module.email_send.poster = poster
    with TestClient(module.app) as http:
        key = _buy(http)
        _put(http, key, "seller@proton.me")
    assert len(_outbox()) == 1
    row_id = int(_outbox()[0]["id"])
    now = int(time.time())
    delays = []
    for _attempt in range(5):
        module.email_send.pump_once(now=now)
        row = _outbox()[0]
        assert row["status"] == "pending"
        delays.append(int(row["next_attempt_at"]) - now)
        now = int(row["next_attempt_at"])
    assert delays == [60, 300, 1800, 7200, 21600]
    module.email_send.pump_once(now=now)
    row = _outbox()[0]
    assert row["status"] == "sent"
    assert row["to_email"] is None
    assert "token" not in json.loads(row["params_json"])
    assert row["sent_at"] == now
    url, body, headers, timeout = captured[0]
    assert url == "https://api.resend.com/emails"
    assert timeout == 5.0
    assert headers["Authorization"] == f"Bearer {_KEY}"
    assert headers["Idempotency-Key"] == f"satsgate-alert_email_confirm-{row_id}"
    assert headers["User-Agent"] == "satsgate/0.19.0"
    assert body["from"] == "Satsgate <alerts@satsgate.org>"
    assert body["to"] == ["seller@proton.me"]
    assert body["reply_to"] == "satsgateapp@proton.me"
    assert body["subject"] == "Satsgate: confirm your security alert email"
    assert "<img" not in body["html"].lower()
    assert "http://" not in body["html"]
    assert "tags" not in body
    assert body["text"].startswith("Confirm this address")
    assert "https://satsgate.org/connect/confirm-email#t=sge_" in body["text"]


def test_permanent_4xx_fails_once_and_stale_sending_is_reclaimed(tmp_path):
    module = _load_app(tmp_path, **_env())
    calls = {"n": 0}

    def poster(url, body, headers, timeout):
        calls["n"] += 1
        return 422, {"message": "no"}

    module.email_send.poster = poster
    with TestClient(module.app) as http:
        key = _buy(http)
        _put(http, key, "seller@proton.me")
    now = int(time.time())
    module.email_send.pump_once(now=now)
    row = _outbox()[0]
    assert row["status"] == "failed"
    assert row["attempts"] == 1
    assert row["to_email"] is None
    assert "token" not in json.loads(row["params_json"])
    assert row["last_status"] == 422
    module.email_send.pump_once(now=now + 10_000)
    assert calls["n"] == 1

    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        conn.execute(
            """
            INSERT INTO email_outbox(
              client_id, kind, to_email, to_hash, params_json, status, attempts,
              next_attempt_at, created_at
            ) VALUES(1, 'alert_email_confirmed', 'seller@proton.me', ?, '{}', 'sending', 0, ?, ?)
            """,
            (hashlib.sha256(b"seller@proton.me").hexdigest(), now - 121, now),
        )
    calls["n"] = 0

    def ok(url, body, headers, timeout):
        calls["n"] += 1
        return 200, {}

    module.email_send.poster = ok
    module.email_send.pump_once(now=now)
    assert calls["n"] == 1
    assert _rows("SELECT status FROM email_outbox WHERE kind = 'alert_email_confirmed'")[0]["status"] == "sent"


def test_purge_drops_rows_older_than_30_days(tmp_path):
    module = _load_app(tmp_path, **_env())
    module.email_send.poster = lambda *args: (200, {})
    now = 1_700_000_000
    with TestClient(module.app) as http:
        key = _buy(http)
        _put(http, key, "seller@proton.me")
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        conn.execute("UPDATE email_outbox SET created_at = ?", (now - 31 * 24 * 3600,))
    module.email_send.pump_once(now=now)
    assert _outbox() == []


def test_email_off_when_the_key_is_unset(tmp_path):
    module = _load_app(tmp_path, SATSGATE_RESEND_API_KEY="", SATSGATE_EMAIL_ENABLED="1")
    with TestClient(module.app) as http:
        assert "satsgate-email" not in {thread.name for thread in threading.enumerate()}
        key = _buy(http)
        info = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        assert info["email_alerts_available"] is False
        assert info["alert_email_status"] == "none"
        rejected = _put(http, key, "seller@proton.me")
        assert rejected.status_code == 503
        assert rejected.json()["error"] == "email_unavailable"
        assert _client()["alert_email_pending"] is None
        saved = http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
        assert saved.status_code == 200, saved.text
        assert _outbox() == []


def test_sender_thread_starts_only_when_email_is_enabled(tmp_path):
    module = _load_app(tmp_path, **_env(SATSGATE_EMAIL_ENABLED="1"))
    module.email_send.poster = lambda *args: (200, {})
    with TestClient(module.app) as http:
        assert any(thread.name == "satsgate-email" for thread in threading.enumerate())
        assert http.get("/health").json()["version"] == "0.19.0"


def test_confirmation_rate_limits(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        first = _put(http, key, "seller@proton.me")
        assert first.status_code == 200, first.text
        pending_hash = _client()["alert_email_pending_hash"]
        second = _put(http, key, "other@proton.me")
        assert second.status_code == 429, second.text
        assert second.json()["error"] == "alert_email_rate_limited"
        assert second.headers["retry-after"]
        assert _client()["alert_email_pending_hash"] == pending_hash
        assert _client()["alert_email_pending"] == "seller@proton.me"
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            conn.execute("UPDATE email_outbox SET created_at = ?", (int(time.time()) - 120,))
            for _index in range(4):
                conn.execute(
                    """
                    INSERT INTO email_outbox(
                      client_id, kind, to_email, to_hash, params_json, status, attempts,
                      next_attempt_at, created_at
                    ) VALUES(1, 'alert_email_confirm', 'seller@proton.me', ?, '{}', 'sent', 1, 0, ?)
                    """,
                    (
                        hashlib.sha256(b"seller@proton.me").hexdigest(),
                        int(time.time()) - 3600,
                    ),
                )
        limited = _put(http, key, "seller@proton.me")
        assert limited.status_code == 429
        assert _client()["alert_email_pending"] == "seller@proton.me"


def test_destination_limit_is_three_a_day(tmp_path):
    module = _load_app(tmp_path, **_env())
    with TestClient(module.app) as http:
        key = _buy(http)
        digest = hashlib.sha256(b"seller@proton.me").hexdigest()
        with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
            for _index in range(3):
                conn.execute(
                    """
                    INSERT INTO email_outbox(
                      client_id, kind, to_email, to_hash, params_json, status, attempts,
                      next_attempt_at, created_at
                    ) VALUES(1, 'alert_email_confirm', NULL, ?, '{}', 'sent', 1, 0, ?)
                    """,
                    (digest, int(time.time()) - 3600),
                )
        limited = _put(http, key, "Seller@Proton.me")
        assert limited.status_code == 429
        assert limited.json()["error"] == "alert_email_rate_limited"
        assert int(limited.headers["retry-after"]) >= 1
        assert _client()["alert_email_pending"] is None


def test_templates_shorten_escape_and_name_support(tmp_path):
    _load_app(tmp_path, **_env())
    templates = importlib.import_module("app.email_templates")
    address = "0x4A9E2CA774BB87110ffF3CB8a250e935cFE52Ce3"
    assert templates.shorten_evm(address) == "0x4A9E…2Ce3"
    assert templates.shorten_lightning("merchant@pay.example") == "merc…@pay.example"
    stamp = templates.format_utc(1_761_773_520)
    assert stamp.endswith(" UTC")
    assert len(stamp) == len("2026-10-29 21:42 UTC")
    params = templates.payout_params(
        rail="evm",
        new_address=address,
        previous=None,
        at=1_761_773_520,
        via="connect page",
        rails_cleared=True,
    )
    assert address not in json.dumps(params)
    subject, text, html = templates.render("payee_evm_changed", client_id=12, params=params)
    assert subject == "Satsgate: your USDC payout address changed"
    assert "Account #12" in text
    assert "0x4A9E…2Ce3" in text
    assert "none" in text
    assert "connect page" in text
    assert "USDC was turned off on your sites." in text
    assert "satsgateapp@proton.me" in text
    assert "POST /v1/client/api-key/rotate" in text
    assert text.find("POST /v1/client/api-key/rotate") < text.find("satsgateapp@proton.me")
    assert "Never send a key, seed phrase or private key." in text
    assert "If this was you, you don't need to do anything." in text
    ofac_subject, ofac_text, _ofac_html = templates.render(
        "payee_ofac_flagged",
        client_id=12,
        params={"address": "0x4A9E…2Ce3", "at": 1_761_773_520},
    )
    assert ofac_subject == "Satsgate: a payout address was blocked"
    assert "sanctions list" in ofac_text
    assert "api-key/rotate" not in ofac_text
    assert "<img" not in html.lower()
    escaped = templates.render(
        "payee_lightning_changed",
        client_id=3,
        params={
            "new": "ab<c…@evil.com",
            "previous": "none",
            "at": stamp,
            "via": "API",
            "rails_cleared": False,
        },
    )
    assert "<script>" not in escaped[2]
    assert "&lt;" in escaped[2]
    assert escaped[0] == "Satsgate: your Lightning payout address changed"

    _load_app(tmp_path, SATSGATE_RESEND_API_KEY=_KEY, SATSGATE_EMAIL_ENABLED="0", SATSGATE_SUPPORT_EMAIL="")
    _subject, text, _html = importlib.import_module("app.email_templates").render(
        "payee_lightning_changed",
        client_id=3,
        params={
            "new": "merc…@pay.example",
            "previous": "none",
            "at": stamp,
            "via": "API",
            "rails_cleared": False,
        },
    )
    assert "https://github.com/Mike-io-hash/satsgate/security/advisories" in text
    assert "satsgateapp@proton.me" not in text


def test_logs_and_paths_do_not_carry_secrets(tmp_path, caplog):
    module = _load_app(tmp_path, **_env())
    caplog.set_level(logging.DEBUG)
    with TestClient(module.app) as http:
        key = _buy(http)
        saved = _put(http, key, "seller@proton.me")
        token = json.loads(_outbox()[-1]["params_json"])["token"]
        http.post("/v1/connect/alert-email/confirm", headers={"X-Email-Token": token})
        http.post(
            "/v1/client/payee",
            headers={"X-Api-Key": key},
            json={"payee_lightning_address": "merchant@pay.example"},
        )
    module.email_send.poster = lambda *args: (500, None)
    module.email_send.pump_once(now=int(time.time()))
    blob = caplog.text
    assert "seller@proton.me" not in blob
    assert token not in blob
    assert _KEY not in blob
    assert "secretkeyvalue" not in blob
    assert "merchant@pay.example" not in blob
    for route in module.app.routes:
        path = getattr(route, "path", "")
        assert "@" not in path
        assert "sge_" not in path
        assert "sgc_" not in path
    assert saved.status_code == 200
