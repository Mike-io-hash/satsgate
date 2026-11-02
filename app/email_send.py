"""Resend sender. One HTTPS call, an outbox, and a daemon thread.

A send never rolls back the payee or email change that queued it. The API
host is fixed. Tests replace ``poster`` and never reach the network.
"""

from __future__ import annotations

import json
import logging
import threading

from . import config, db
from .email_templates import render
from .ssrf import SSRFError, safe_post_json

log = logging.getLogger("satsgate.email")

RESEND_URL = "https://api.resend.com/emails"
# The first send is immediate. A retryable failure is tried again at each of
# these delays, measured from the previous failure. Five waits, then the next
# failure is terminal (six sends at most). Resend keeps the idempotency key
# for 24 hours, and this schedule finishes inside that window.
RETRY_DELAYS_SECONDS = (60, 5 * 60, 30 * 60, 2 * 3600, 6 * 3600)
MAX_ATTEMPTS = len(RETRY_DELAYS_SECONDS) + 1
STALE_SENDING_SECONDS = 120
POLL_SECONDS = 30

poster = None
wake = threading.Event()


def sender_should_run() -> bool:
    return bool(config.RESEND_API_KEY) and bool(config.EMAIL_ENABLED)


def notify() -> None:
    wake.set()


def loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            pump_once()
        except Exception:
            log.warning("email pump failed")
        wake.wait(POLL_SECONDS)
        wake.clear()


def pump_once(*, now: int | None = None) -> int:
    """Send every due row. Returns how many sends were attempted."""
    import time

    now = int(time.time()) if now is None else int(now)
    _reclaim_stale(now)
    _purge(now)
    attempted = 0
    while True:
        row = _claim(now)
        if row is None:
            return attempted
        _deliver(row, now)
        attempted += 1


def _connect():
    return db._connect(config.DB_PATH)


def _reclaim_stale(now: int) -> None:
    cutoff = int(now) - STALE_SENDING_SECONDS
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE email_outbox
            SET status = 'pending', next_attempt_at = ?
            WHERE status = 'sending' AND next_attempt_at <= ?
            """,
            (int(now), cutoff),
        )
        conn.execute("COMMIT")


def _purge(now: int) -> None:
    cutoff = int(now) - (30 * 24 * 3600)
    with _connect() as conn:
        conn.execute("DELETE FROM email_outbox WHERE created_at < ?", (cutoff,))


def _claim(now: int) -> dict | None:
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT * FROM email_outbox
            WHERE status = 'pending' AND next_attempt_at <= ?
            ORDER BY id
            LIMIT 1
            """,
            (int(now),),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return None
        cur = conn.execute(
            """
            UPDATE email_outbox
            SET status = 'sending', next_attempt_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (int(now), int(row["id"])),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return None
        conn.execute("COMMIT")
        return dict(row)


def _deliver(row: dict, now: int) -> None:
    kind = str(row["kind"])
    row_id = int(row["id"])
    to_email = row["to_email"]
    status_code = 0
    retryable = True
    try:
        params = json.loads(row["params_json"] or "{}")
        if not isinstance(params, dict):
            params = {}
        subject, text, html = render(kind, client_id=int(row["client_id"]), params=params)
        if not to_email:
            retryable = False
            status_code = 400
            raise RuntimeError("missing_destination")
        status_code, _body = _post_resend(
            row_id=row_id,
            kind=kind,
            to_email=str(to_email),
            subject=subject,
            text=text,
            html=html,
        )
        if 200 <= status_code < 300:
            _finish(row_id, status="sent", attempts=int(row["attempts"]) + 1, now=now, last_status=status_code)
            log.info("email_sent kind=%s id=%s", kind, row_id)
            return
        # 0 is a network failure from the poster. 429 and 5xx are retried. Any other 4xx is final.
        retryable = status_code == 0 or status_code == 429 or status_code >= 500
    except Exception:
        if status_code == 0:
            retryable = True
        elif not (status_code == 429 or status_code >= 500):
            retryable = False
    attempts = int(row["attempts"]) + 1
    if retryable and attempts < MAX_ATTEMPTS:
        delay = RETRY_DELAYS_SECONDS[attempts - 1]
        _finish(
            row_id,
            status="pending",
            attempts=attempts,
            now=now + delay,
            last_status=status_code,
            clear=False,
        )
        log.info("email_retry kind=%s id=%s status=%s", kind, row_id, status_code)
        return
    _finish(row_id, status="failed", attempts=attempts, now=now, last_status=status_code)
    log.info("email_failed kind=%s id=%s status=%s", kind, row_id, status_code)


def _post_resend(*, row_id: int, kind: str, to_email: str, subject: str, text: str, html: str) -> tuple[int, dict | None]:
    body: dict = {
        "from": config.EMAIL_FROM,
        "to": [to_email],
        "subject": subject,
        "text": text,
        "html": html,
    }
    support = (config.SUPPORT_EMAIL or "").strip()
    if support:
        body["reply_to"] = support
    headers = {
        "Authorization": f"Bearer {config.RESEND_API_KEY}",
        "Idempotency-Key": f"satsgate-{kind}-{row_id}",
        "User-Agent": f"satsgate/{config.APP_VERSION}",
    }
    fn = poster
    try:
        if fn is not None:
            result = fn(RESEND_URL, body, headers, 5.0)
        else:
            result = safe_post_json(RESEND_URL, body, headers=headers, timeout=5.0)
    except SSRFError:
        return 0, None
    except Exception:
        return 0, None
    if not isinstance(result, tuple) or len(result) != 2:
        return 0, None
    status, payload = result
    if payload is not None and not isinstance(payload, dict):
        payload = None
    return int(status), payload


def _finish(row_id: int, *, status: str, attempts: int, now: int, last_status: int, clear: bool = True) -> None:
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if status == "pending" and not clear:
            conn.execute(
                """
                UPDATE email_outbox
                SET status = 'pending', attempts = ?, next_attempt_at = ?, last_status = ?
                WHERE id = ?
                """,
                (int(attempts), int(now), int(last_status), int(row_id)),
            )
        else:
            row = conn.execute("SELECT params_json FROM email_outbox WHERE id = ?", (int(row_id),)).fetchone()
            params = {}
            if row is not None and row["params_json"]:
                try:
                    loaded = json.loads(row["params_json"])
                    if isinstance(loaded, dict):
                        params = loaded
                except json.JSONDecodeError:
                    params = {}
            params.pop("token", None)
            sent_at = int(now) if status == "sent" else None
            conn.execute(
                """
                UPDATE email_outbox
                SET status = ?, attempts = ?, next_attempt_at = ?, last_status = ?,
                    to_email = NULL, params_json = ?, sent_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    int(attempts),
                    int(now),
                    int(last_status),
                    json.dumps(params, separators=(",", ":"), sort_keys=True),
                    sent_at,
                    int(row_id),
                ),
            )
        conn.execute("COMMIT")
