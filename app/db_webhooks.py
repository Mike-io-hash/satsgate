"""One security webhook per account. The signing secret is encrypted at rest.

The plaintext ``whsec_`` value is returned only when it is created. A URL
change keeps the secret. Pending deliveries from an older generation are
dropped so a stale 404 cannot disable the replacement.
"""

from __future__ import annotations

import json
import secrets
import time

from . import config
from .db import _connect
from .email_templates import format_utc
from .site_secret import SiteSecretError, encrypt_origin_secret
from .ssrf import SSRFError, guard_url
from .x402 import X402Error

WEBHOOK_URL_MAX = 300
SECRET_PREFIX_LEN = 10


def webhooks_available() -> bool:
    """False when the encryption key is unset. The sender switch is separate."""
    try:
        return config.site_secret_key() is not None
    except RuntimeError:
        return False


def _require_available() -> bytes:
    """Refuse to store a secret we cannot encrypt. Never store plaintext."""
    try:
        key = config.site_secret_key()
    except RuntimeError as exc:
        raise X402Error("webhooks_unavailable", status=503) from exc
    if key is None:
        raise X402Error("webhooks_unavailable", status=503)
    return key


def _controls(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_webhook_url(url: object, *, resolver=None) -> str:
    """https, no userinfo, public address, at most 300 characters."""
    if not isinstance(url, str) or url != url.strip():
        raise X402Error("invalid_webhook_url", status=400)
    if not url or len(url) > WEBHOOK_URL_MAX or _controls(url) or any(ch in url for ch in " \t"):
        raise X402Error("invalid_webhook_url", status=400)
    try:
        guard_url(url, resolver=resolver)
    except (SSRFError, ValueError) as exc:
        raise X402Error("invalid_webhook_url", status=400) from exc
    return url


def audit_webhook(conn, *, client_id: int, reason: str, now: int, ref: str | None = None) -> None:
    """One ledger row. The ref is a short code, never a secret, URL, or header."""
    if ref is not None and (len(ref) > 16 or any(ch in ref for ch in "/?#@&= ")):
        ref = None
    conn.execute(
        "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, 0, ?, ?, ?)",
        (int(client_id), reason, ref, int(now)),
    )


def new_webhook_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def event_body(*, event_id: str, kind: str, created_at: int, data: dict) -> str:
    """Canonical JSON. Deliveries send these exact UTF-8 bytes again on retry."""
    payload = {
        "id": event_id,
        "type": kind,
        "created_at": int(created_at),
        "data": data,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def enqueue_delivery(conn, *, client_id: int, kind: str, data: dict, now: int) -> bool:
    """Insert one outbox row for the current enabled webhook. False when there is none.

    Runs inside the caller's transaction. A database error propagates.
    ``SATSGATE_WEBHOOKS=0`` stops the sender thread and does not skip this insert,
    matching the email outbox. No enabled webhook means no row.
    """
    row = conn.execute(
        "SELECT generation, enabled FROM client_webhooks WHERE client_id = ?",
        (int(client_id),),
    ).fetchone()
    if row is None or not int(row["enabled"]):
        return False
    event_id = "evt_" + secrets.token_urlsafe(18)
    body = event_body(event_id=event_id, kind=kind, created_at=int(now), data=data)
    conn.execute(
        """
        INSERT INTO webhook_outbox(
          client_id, event_id, generation, kind, body_json, status, attempts,
          next_attempt_at, created_at
        ) VALUES(?, ?, ?, ?, ?, 'pending', 0, ?, ?)
        """,
        (int(client_id), event_id, int(row["generation"]), kind, body, int(now), int(now)),
    )
    return True


def _drop_old(conn, *, client_id: int, generation: int) -> None:
    conn.execute(
        """
        DELETE FROM webhook_outbox
        WHERE client_id = ? AND generation != ? AND status IN ('pending', 'sending')
        """,
        (int(client_id), int(generation)),
    )


def put_webhook(
    db_path: str,
    *,
    client_id: int,
    url: object,
    rotate_secret: bool,
    now: int | None = None,
    resolver=None,
) -> dict:
    """Create or replace the URL. The secret is included only when a new one is stored."""
    key = _require_available()
    clean = validate_webhook_url(url, resolver=resolver)
    now = int(time.time()) if now is None else int(now)
    revealed: str | None = None
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM client_webhooks WHERE client_id = ?", (int(client_id),)).fetchone()
        if row is None:
            secret = new_webhook_secret()
            try:
                blob = encrypt_origin_secret(secret, key)
            except SiteSecretError as exc:
                conn.execute("ROLLBACK")
                raise X402Error("webhooks_unavailable", status=503) from exc
            conn.execute(
                """
                INSERT INTO client_webhooks(
                  client_id, url, secret_enc, secret_prefix, enabled, generation, created_at, updated_at
                ) VALUES(?, ?, ?, ?, 1, 1, ?, ?)
                """,
                (int(client_id), clean, blob, secret[:SECRET_PREFIX_LEN], now, now),
            )
            audit_webhook(conn, client_id=int(client_id), reason="webhook_created", now=now)
            revealed = secret
        else:
            generation = int(row["generation"])
            secret_enc = row["secret_enc"]
            prefix = row["secret_prefix"]
            url_changed = clean != row["url"]
            was_disabled = not int(row["enabled"])
            changed = url_changed or bool(rotate_secret) or was_disabled
            if rotate_secret:
                secret = new_webhook_secret()
                try:
                    secret_enc = encrypt_origin_secret(secret, key)
                except SiteSecretError as exc:
                    conn.execute("ROLLBACK")
                    raise X402Error("webhooks_unavailable", status=503) from exc
                prefix = secret[:SECRET_PREFIX_LEN]
                revealed = secret
            if changed:
                generation += 1
                _drop_old(conn, client_id=int(client_id), generation=generation)
            conn.execute(
                """
                UPDATE client_webhooks
                SET url = ?, secret_enc = ?, secret_prefix = ?, enabled = 1, generation = ?,
                    updated_at = ?, disabled_reason = NULL
                WHERE client_id = ?
                """,
                (clean, secret_enc, prefix, generation, now, int(client_id)),
            )
            if url_changed:
                audit_webhook(conn, client_id=int(client_id), reason="webhook_url_changed", now=now)
            if rotate_secret:
                audit_webhook(conn, client_id=int(client_id), reason="webhook_secret_rotated", now=now)
            if was_disabled:
                audit_webhook(conn, client_id=int(client_id), reason="webhook_enabled", now=now)
        conn.execute("COMMIT")
    body = {"ok": True, "url": clean, "enabled": True}
    if revealed is not None:
        body["secret"] = revealed
    return body


def get_webhook(db_path: str, *, client_id: int) -> dict:
    """Public view. The signing secret is never selected."""
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT url, secret_prefix, enabled, generation
            FROM client_webhooks WHERE client_id = ?
            """,
            (int(client_id),),
        ).fetchone()
        if row is None:
            return {
                "ok": True,
                "url": None,
                "enabled": False,
                "secret_prefix": None,
                "last_delivery": None,
            }
        last = conn.execute(
            """
            SELECT status, sent_at, created_at
            FROM webhook_outbox
            WHERE client_id = ? AND generation = ? AND status != 'dropped'
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(client_id), int(row["generation"])),
        ).fetchone()
    delivery = None
    if last is not None:
        at = last["sent_at"] if last["sent_at"] is not None else last["created_at"]
        delivery = {"status": last["status"], "at": int(at)}
    return {
        "ok": True,
        "url": row["url"],
        "enabled": bool(int(row["enabled"])),
        "secret_prefix": row["secret_prefix"],
        "last_delivery": delivery,
    }


def delete_webhook(db_path: str, *, client_id: int, now: int | None = None) -> dict:
    """Remove the webhook and drop deliveries that have not been posted yet."""
    now = int(time.time()) if now is None else int(now)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        removed = conn.execute("DELETE FROM client_webhooks WHERE client_id = ?", (int(client_id),))
        conn.execute(
            """
            DELETE FROM webhook_outbox
            WHERE client_id = ? AND status IN ('pending', 'sending')
            """,
            (int(client_id),),
        )
        if removed.rowcount:
            audit_webhook(conn, client_id=int(client_id), reason="webhook_deleted", now=now)
        conn.execute("COMMIT")
    return {"ok": True}


def queue_test(db_path: str, *, client_id: int, now: int | None = None, resolver=None) -> dict:
    """Queue ``webhook_test`` for the enabled webhook. The URL is checked again."""
    _require_available()
    now = int(time.time()) if now is None else int(now)
    from . import security_events, webhook_send

    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT url, enabled FROM client_webhooks WHERE client_id = ?",
            (int(client_id),),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise X402Error("webhook_not_configured", status=404)
        if not int(row["enabled"]):
            conn.execute("ROLLBACK")
            raise X402Error("webhook_disabled", status=409)
        try:
            validate_webhook_url(row["url"], resolver=resolver)
        except X402Error:
            conn.execute("ROLLBACK")
            raise
        queued = security_events.queue(
            conn,
            int(client_id),
            "webhook_test",
            {"at": format_utc(now)},
            now,
            to_email=None,
        )
        if not queued.webhook:
            conn.execute("ROLLBACK")
            raise X402Error("webhook_not_configured", status=404)
        conn.execute("COMMIT")
    webhook_send.notify()
    return {"ok": True, "queued": True}
