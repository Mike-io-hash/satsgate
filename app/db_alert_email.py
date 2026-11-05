"""Optional security-alert email. A pending address never replaces a confirmed one.

The confirmation token is stored as a SHA-256 hash. The raw token lives only
in the outbox until that row is sent or fails. Alerts for a payout change go
to the confirmed address, never to a pending one.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from . import config, db
from .db import _connect
from . import email_send
from .email_templates import payout_params
from .x402 import X402Error

ALERT_TOKEN_SECONDS = 24 * 60 * 60
_DAY = 24 * 60 * 60
_ACCOUNT_INTERVAL = 60
_ACCOUNT_DAILY = 5
_DEST_DAILY = 3
_EMAIL_TOKEN = re.compile(r"^sge_[A-Za-z0-9_-]{16,128}$")
_LOCAL_REJECTED = re.compile(r"[\s\x00-\x1f\x7f\"']")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

# Tests set this to raise after the outbox insert and before COMMIT.
commit_guard = None


def alerts_available() -> bool:
    return bool(config.RESEND_API_KEY)


def mask_email(address: str) -> str:
    local, domain = address.split("@", 1)
    return f"{local[:1]}***@{domain}"


def normalize_email(value: object) -> str:
    """Trim, lowercase the domain, and reject anything that is not one address."""
    if not isinstance(value, str):
        raise X402Error("invalid_email", status=400)
    text = value.strip()
    if not text or len(text) > 254 or text.count("@") != 1:
        raise X402Error("invalid_email", status=400)
    local, domain = text.split("@", 1)
    domain = domain.lower().rstrip(".")
    if not local or len(local) > 64 or _LOCAL_REJECTED.search(local):
        raise X402Error("invalid_email", status=400)
    if not _hostname(domain):
        raise X402Error("invalid_email", status=400)
    return f"{local}@{domain}"


def _hostname(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    return all(_LABEL.fullmatch(label) for label in domain.split("."))


def _hash_address(address: str) -> str:
    return hashlib.sha256(address.lower().encode("utf-8")).hexdigest()


def raise_if_guarded() -> None:
    if commit_guard is not None:
        commit_guard()


def describe(db_path: str, *, client_id: int, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else int(now)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (int(client_id),)).fetchone()
    if row is None:
        raise ValueError("client does not exist")
    return _view(row, now)


def set_pending(
    db_path: str,
    *,
    client_id: int,
    email: object,
    allow_when_confirmed: bool,
    now: int | None = None,
) -> dict:
    """Store a pending address and queue the confirmation. Nothing is confirmed here."""
    if not alerts_available():
        raise X402Error("email_unavailable", status=503)
    stored = normalize_email(email)
    now = int(time.time()) if now is None else int(now)
    token = "sge_" + secrets.token_urlsafe(32)
    expires = now + ALERT_TOKEN_SECONDS
    queued = False
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        confirmed = row["alert_email"]
        if confirmed and not allow_when_confirmed:
            conn.execute("ROLLBACK")
            raise X402Error("alert_email_already_set", status=409)
        if confirmed and confirmed == stored:
            conn.execute("ROLLBACK")
            view = _view(row, now)
            view["pending_expires_at"] = view.get("pending_expires_at")
            view["note"] = "This address is already confirmed."
            return view
        retry_after = _retry_after(conn, client_id=int(client_id), email=stored, now=now)
        if retry_after:
            conn.execute("ROLLBACK")
            raise X402Error("alert_email_rate_limited", status=429, retry_after=retry_after)
        conn.execute(
            """
            UPDATE clients
            SET alert_email_pending = ?,
                alert_email_pending_hash = ?,
                alert_email_pending_expires = ?
            WHERE id = ?
            """,
            (stored, db.hash_api_key(token), expires, int(client_id)),
        )
        _enqueue(
            conn,
            client_id=int(client_id),
            kind="alert_email_confirm",
            to_email=stored,
            params={"token": token},
            now=now,
        )
        if confirmed and confirmed != stored:
            _enqueue(
                conn,
                client_id=int(client_id),
                kind="alert_email_change_requested",
                to_email=confirmed,
                params={"masked_new": mask_email(stored)},
                now=now,
            )
        raise_if_guarded()
        conn.execute("COMMIT")
        queued = True
        view = {
            "alert_email": mask_email(confirmed) if confirmed else None,
            "alert_email_pending": mask_email(stored),
            "alert_email_status": "pending",
            "pending_expires_at": expires,
            "note": (
                "Check that inbox to confirm. Alerts still go to the current address until you confirm."
                if confirmed
                else "Check that inbox to confirm. Alerts start after you confirm."
            ),
        }
    if queued:
        email_send.notify()
    return view


def remove(db_path: str, *, client_id: int, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else int(now)
    queued = False
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        confirmed = row["alert_email"]
        if confirmed:
            _enqueue(
                conn,
                client_id=int(client_id),
                kind="alert_email_removed",
                to_email=confirmed,
                params={},
                now=now,
            )
            queued = True
        conn.execute(
            """
            UPDATE clients
            SET alert_email = NULL,
                alert_email_confirmed_at = NULL,
                alert_email_pending = NULL,
                alert_email_pending_hash = NULL,
                alert_email_pending_expires = NULL
            WHERE id = ?
            """,
            (int(client_id),),
        )
        if queued:
            raise_if_guarded()
        conn.execute("COMMIT")
    if queued:
        email_send.notify()
    return {
        "alert_email": None,
        "alert_email_pending": None,
        "alert_email_status": "none",
        "note": "Security alerts are off.",
    }


def preview(db_path: str, token: str, *, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else int(now)
    with _connect(db_path) as conn:
        row = _token_row(conn, token, now)
    if row is None:
        raise X402Error("email_link_invalid", status=401)
    return {
        "ok": True,
        "alert_email_pending": mask_email(row["alert_email_pending"]),
        "client_id": int(row["id"]),
        "expires_at": int(row["alert_email_pending_expires"]),
    }


def confirm(db_path: str, token: str, *, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else int(now)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _token_row(conn, token, now)
        if row is None:
            conn.execute("ROLLBACK")
            raise X402Error("email_link_invalid", status=401)
        old = row["alert_email"]
        new = row["alert_email_pending"]
        if old and old != new:
            _enqueue(
                conn,
                client_id=int(row["id"]),
                kind="alert_email_changed",
                to_email=old,
                params={"masked_new": mask_email(new)},
                now=now,
            )
        _enqueue(
            conn,
            client_id=int(row["id"]),
            kind="alert_email_confirmed",
            to_email=new,
            params={},
            now=now,
        )
        conn.execute(
            """
            UPDATE clients
            SET alert_email = ?,
                alert_email_confirmed_at = ?,
                alert_email_pending = NULL,
                alert_email_pending_hash = NULL,
                alert_email_pending_expires = NULL
            WHERE id = ?
            """,
            (new, now, int(row["id"])),
        )
        raise_if_guarded()
        conn.execute("COMMIT")
        client_id = int(row["id"])
    email_send.notify()
    return {
        "ok": True,
        "client_id": client_id,
        "alert_email": mask_email(new),
        "alert_email_status": "confirmed",
    }


def queue_ofac(conn, *, client_id: int, to_email: str, address: str, now: int) -> None:
    from .email_templates import shorten_evm

    _enqueue(
        conn,
        client_id=int(client_id),
        kind="payee_ofac_flagged",
        to_email=to_email,
        params={"address": shorten_evm(address), "at": int(now)},
        now=int(now),
    )


def queue_payout(
    conn,
    *,
    client_id: int,
    to_email: str | None,
    kind: str,
    new_address: str,
    previous: str | None,
    via: str,
    rails_cleared: bool,
    now: int,
) -> bool:
    """Queue a payout alert inside the caller's transaction. Returns whether a row was inserted."""
    if not to_email:
        return False
    rail = "evm" if kind == "payee_evm_changed" else "lightning"
    _enqueue(
        conn,
        client_id=int(client_id),
        kind=kind,
        to_email=to_email,
        params=payout_params(
            rail=rail,
            new_address=new_address,
            previous=previous,
            at=now,
            via=via,
            rails_cleared=rails_cleared,
        ),
        now=now,
    )
    return True


def _enqueue(conn, *, client_id: int, kind: str, to_email: str, params: dict, now: int) -> None:
    conn.execute(
        """
        INSERT INTO email_outbox(
          client_id, kind, to_email, to_hash, params_json, status, attempts,
          next_attempt_at, created_at
        ) VALUES(?, ?, ?, ?, ?, 'pending', 0, ?, ?)
        """,
        (
            int(client_id),
            kind,
            to_email,
            _hash_address(to_email),
            json.dumps(params, separators=(",", ":"), sort_keys=True),
            int(now),
            int(now),
        ),
    )


def _token_row(conn, token: str, now: int):
    if not isinstance(token, str) or not _EMAIL_TOKEN.fullmatch(token):
        return None
    row = conn.execute(
        "SELECT * FROM clients WHERE alert_email_pending_hash = ?",
        (db.hash_api_key(token),),
    ).fetchone()
    if row is None or not row["alert_email_pending"]:
        return None
    expires = row["alert_email_pending_expires"]
    if expires is None or int(expires) < int(now):
        return None
    return row


def _view(row, now: int) -> dict:
    confirmed = row["alert_email"] or None
    pending = _live_pending(row, now)
    if confirmed:
        status = "confirmed"
    elif pending:
        status = "pending"
    else:
        status = "none"
    expires = row["alert_email_pending_expires"]
    return {
        "alert_email": mask_email(confirmed) if confirmed else None,
        "alert_email_status": status,
        "alert_email_pending": mask_email(pending) if pending else None,
        "pending_expires_at": int(expires) if pending and expires is not None else None,
    }


def _live_pending(row, now: int) -> str | None:
    pending = row["alert_email_pending"]
    expires = row["alert_email_pending_expires"]
    if not pending or expires is None or int(expires) < int(now):
        return None
    return pending


def _retry_after(conn, *, client_id: int, email: str, now: int) -> int:
    since = int(now) - _DAY
    account_rows = conn.execute(
        """
        SELECT created_at FROM email_outbox
        WHERE client_id = ? AND kind = 'alert_email_confirm' AND created_at >= ?
        ORDER BY created_at ASC
        """,
        (int(client_id), since),
    ).fetchall()
    dest_rows = conn.execute(
        """
        SELECT created_at FROM email_outbox
        WHERE to_hash = ? AND kind = 'alert_email_confirm' AND created_at >= ?
        ORDER BY created_at ASC
        """,
        (_hash_address(email), since),
    ).fetchall()
    waits: list[int] = []
    if account_rows:
        latest = int(account_rows[-1]["created_at"])
        if int(now) - latest < _ACCOUNT_INTERVAL:
            waits.append(_ACCOUNT_INTERVAL - (int(now) - latest))
    if len(account_rows) >= _ACCOUNT_DAILY:
        waits.append(int(account_rows[0]["created_at"]) + _DAY - int(now))
    if len(dest_rows) >= _DEST_DAILY:
        waits.append(int(dest_rows[0]["created_at"]) + _DAY - int(now))
    if not waits:
        return 0
    return max(1, max(waits))
