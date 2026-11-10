"""Replace the account key immediately. The old key does not keep working.

Restricted keys are not touched. The plaintext is returned only to the caller
of a commit that succeeded. A lost race returns ``invalid_api_key`` and no key.
"""

from __future__ import annotations

import time

from . import db_alert_email, security_events
from .db import _connect, hash_api_key, new_api_key
from .db_keys import AuthError
from .email_templates import format_utc

_PREFIX_LEN = 8


def rotate_account_key(db_path: str, api_key: str, *, now: int | None = None) -> dict:
    """Swap ``clients.api_key_hash`` for ``api_key`` and queue the security event.

    The presented hash is checked again inside ``BEGIN IMMEDIATE``. A concurrent
    rotation that already committed does not get overwritten.
    """
    if not api_key:
        raise AuthError("invalid_api_key")
    presented = hash_api_key(api_key)
    fresh = new_api_key()
    fresh_hash = hash_api_key(fresh)
    prefix = fresh[:_PREFIX_LEN]
    now = int(time.time()) if now is None else int(now)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id, alert_email, alert_email_confirmed_at FROM clients WHERE api_key_hash = ?",
            (presented,),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise AuthError("invalid_api_key")
        client_id = int(row["id"])
        updated = conn.execute(
            "UPDATE clients SET api_key_hash = ? WHERE id = ? AND api_key_hash = ?",
            (fresh_hash, client_id, presented),
        )
        if updated.rowcount != 1:
            conn.execute("ROLLBACK")
            raise AuthError("invalid_api_key")
        # The prefix identifies the new key. The secret itself is not stored.
        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (client_id, 0, "api_key_rotated", prefix, now),
        )
        to_email = None
        if row["alert_email"] and row["alert_email_confirmed_at"]:
            to_email = row["alert_email"]
        queued = security_events.queue(
            conn,
            client_id,
            "account_key_rotated",
            {"at": format_utc(now), "prefix": prefix, "via": "api"},
            now,
            to_email=to_email,
        )
        if queued:
            db_alert_email.raise_if_guarded()
        conn.execute("COMMIT")
    _notify(queued)
    return {"api_key": fresh, "prefix": prefix}


def _notify(queued) -> None:
    """Wake senders after the key is committed. A wake failure must not hide the new key."""
    import logging

    from . import email_send, webhook_send

    try:
        if queued.email:
            email_send.notify()
        if queued.webhook:
            webhook_send.notify()
    except Exception:
        logging.getLogger("satsgate").warning("account key rotation notify failed")
