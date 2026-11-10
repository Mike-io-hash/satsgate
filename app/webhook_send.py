"""Deliver signed security webhooks. The payee change is already committed.

Five sends at most: the first try and four retries. HTTP 404 and 410 disable
that webhook generation and stop the rest. A private address or a redirect is
not sent and is not retried. The thread does not depend on Resend.
"""

from __future__ import annotations

import logging
import threading

from . import config, db
from .site_secret import SiteSecretError, decrypt_origin_secret
from .ssrf import SSRFError, safe_post_bytes
from .webhook_sign import signature

log = logging.getLogger("satsgate.webhook")

# Measured from the previous failure. Four waits, then the fifth failure is terminal.
RETRY_DELAYS_SECONDS = (60, 5 * 60, 30 * 60, 2 * 3600)
MAX_ATTEMPTS = len(RETRY_DELAYS_SECONDS) + 1
STALE_SENDING_SECONDS = 120
POLL_SECONDS = 30
RESPONSE_CAP_BYTES = 4 * 1024
# One wall-clock budget for a delivery: DNS, connect, TLS, the request,
# response headers, and the body. It is not restarted when the body starts.
DELIVERY_DEADLINE_SECONDS = 5.0
_TERMINAL_SSRF = frozenset({"destination_rejected", "redirects_not_allowed"})
_DISABLE_STATUS = frozenset({404, 410})

poster = None
wake = threading.Event()


def sender_should_run() -> bool:
    """Independent of the email sender. An empty outbox makes ``pump_once`` a no-op."""
    return bool(config.WEBHOOKS_ENABLED)


def notify() -> None:
    wake.set()


def loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            pump_once()
        except Exception:
            log.warning("webhook pump failed")
        wake.wait(POLL_SECONDS)
        wake.clear()


def pump_once(*, now: int | None = None) -> int:
    """Send every due row for the current webhook generation. Returns how many were attempted."""
    import time

    now = int(time.time()) if now is None else int(now)
    _reclaim_stale(now)
    _drop_inactive()
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
    """A crashed send already consumed its attempt. Five reserved sends stay five."""
    cutoff = int(now) - STALE_SENDING_SECONDS
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE webhook_outbox
            SET status = 'failed'
            WHERE status = 'sending' AND next_attempt_at <= ? AND attempts >= ?
            """,
            (cutoff, MAX_ATTEMPTS),
        )
        conn.execute(
            """
            UPDATE webhook_outbox
            SET status = 'pending', next_attempt_at = ?
            WHERE status = 'sending' AND next_attempt_at <= ? AND attempts < ?
            """,
            (int(now), cutoff, MAX_ATTEMPTS),
        )
        conn.execute("COMMIT")


def _drop_inactive() -> None:
    """Queued rows whose webhook generation is gone or disabled are not sent."""
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE webhook_outbox
            SET status = 'dropped'
            WHERE status IN ('pending', 'sending')
              AND NOT EXISTS (
                SELECT 1 FROM client_webhooks w
                WHERE w.client_id = webhook_outbox.client_id
                  AND w.generation = webhook_outbox.generation
                  AND w.enabled = 1
              )
            """
        )
        conn.execute("COMMIT")


def _purge(now: int) -> None:
    cutoff = int(now) - (30 * 24 * 3600)
    with _connect() as conn:
        conn.execute("DELETE FROM webhook_outbox WHERE created_at < ?", (cutoff,))


def _claim(now: int) -> dict | None:
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT o.*
            FROM webhook_outbox o
            JOIN client_webhooks w
              ON w.client_id = o.client_id
             AND w.generation = o.generation
             AND w.enabled = 1
            WHERE o.status = 'pending' AND o.next_attempt_at <= ? AND o.attempts < ?
            ORDER BY o.id
            LIMIT 1
            """,
            (int(now), MAX_ATTEMPTS),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return None
        reserved = int(row["attempts"]) + 1
        cur = conn.execute(
            """
            UPDATE webhook_outbox
            SET status = 'sending', attempts = ?, next_attempt_at = ?
            WHERE id = ? AND status = 'pending' AND attempts = ? AND attempts < ?
            """,
            (reserved, int(now), int(row["id"]), int(row["attempts"]), MAX_ATTEMPTS),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return None
        conn.execute("COMMIT")
        claimed = dict(row)
        claimed["attempts"] = reserved
        claimed["status"] = "sending"
        return claimed


def _claim_matches(conn, row: dict) -> bool:
    """This result belongs to the reserved attempt, and the webhook generation is still live."""
    current = conn.execute(
        "SELECT status, generation, attempts FROM webhook_outbox WHERE id = ?",
        (int(row["id"]),),
    ).fetchone()
    webhook = conn.execute(
        "SELECT generation, enabled FROM client_webhooks WHERE client_id = ?",
        (int(row["client_id"]),),
    ).fetchone()
    if current is None or current["status"] != "sending":
        return False
    if int(current["attempts"]) != int(row["attempts"]):
        return False
    if int(current["generation"]) != int(row["generation"]):
        return False
    if webhook is None or not int(webhook["enabled"]):
        return False
    return int(webhook["generation"]) == int(row["generation"])


def _finish_attempt(
    conn,
    row: dict,
    *,
    status: str,
    now: int,
    last_status: int,
    sent: bool = False,
) -> bool:
    """Record the result for this claim only. Attempts were reserved before the POST."""
    sent_at = int(now) if sent else None
    cur = conn.execute(
        """
        UPDATE webhook_outbox
        SET status = ?, next_attempt_at = ?, last_status = ?, sent_at = ?
        WHERE id = ? AND generation = ? AND status = 'sending' AND attempts = ?
        """,
        (
            status,
            int(now),
            int(last_status),
            sent_at,
            int(row["id"]),
            int(row["generation"]),
            int(row["attempts"]),
        ),
    )
    return cur.rowcount == 1


def _load_target(row: dict, now: int) -> tuple[str, str] | None:
    """Return ``(url, secret)`` when this row's generation is still the live one."""
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not _claim_matches(conn, row):
            conn.execute(
                """
                UPDATE webhook_outbox
                SET status = 'dropped'
                WHERE id = ? AND status = 'sending' AND generation = ? AND attempts = ?
                """,
                (int(row["id"]), int(row["generation"]), int(row["attempts"])),
            )
            conn.execute("COMMIT")
            return None
        webhook = conn.execute(
            "SELECT url, secret_enc FROM client_webhooks WHERE client_id = ? AND generation = ?",
            (int(row["client_id"]), int(row["generation"])),
        ).fetchone()
        conn.execute("COMMIT")
    if webhook is None:
        return None
    try:
        key = config.site_secret_key()
        if key is None:
            raise SiteSecretError("site_secret_key_unconfigured")
        secret = decrypt_origin_secret(webhook["secret_enc"], key)
    except (SiteSecretError, RuntimeError):
        log.warning("webhook secret unreadable id=%s", int(row["id"]))
        _finish_terminal(row, last_status=0, now=now)
        return None
    return str(webhook["url"]), secret


def _finish_terminal(row: dict, *, last_status: int, now: int) -> None:
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if _claim_matches(conn, row):
            _finish_attempt(conn, row, status="failed", now=now, last_status=last_status)
        else:
            conn.execute(
                """
                UPDATE webhook_outbox
                SET status = 'dropped', last_status = ?
                WHERE id = ? AND generation = ? AND status = 'sending' AND attempts = ?
                """,
                (int(last_status), int(row["id"]), int(row["generation"]), int(row["attempts"])),
            )
        conn.execute("COMMIT")
    log.info("webhook_failed kind=%s id=%s status=%s", row["kind"], int(row["id"]), last_status)


def _deliver(row: dict, now: int) -> None:
    target = _load_target(row, now)
    if target is None:
        return
    url, secret = target
    body = str(row["body_json"]).encode("utf-8")
    import time

    timestamp = int(time.time())
    signed = signature(secret, timestamp, body)
    # The secret is only the HMAC key. It is not logged and not kept after this.
    del secret
    headers = {
        "Satsgate-Webhook-Id": str(row["event_id"]),
        "Satsgate-Webhook-Timestamp": str(timestamp),
        "Satsgate-Webhook-Signature": signed,
        "User-Agent": f"satsgate/{config.APP_VERSION}",
    }
    try:
        status_code = _post(url, body, headers)
    except SSRFError as exc:
        if exc.code in _TERMINAL_SSRF:
            _finish_terminal(row, last_status=0, now=now)
            return
        _retry_or_fail(row, now, last_status=0)
        return
    except Exception:
        log.warning("webhook delivery failed id=%s", int(row["id"]))
        _retry_or_fail(row, now, last_status=0)
        return
    if 200 <= status_code < 300:
        _apply_sent(row, now, status_code)
        return
    if status_code in _DISABLE_STATUS:
        _apply_disable(row, now, status_code)
        return
    _retry_or_fail(row, now, last_status=status_code)


def _post(url: str, body: bytes, headers: dict) -> int:
    fn = poster
    if fn is not None:
        result = fn(url, body, headers, 5.0)
    else:
        status, _payload = safe_post_bytes(
            url,
            body,
            headers=headers,
            timeout=5.0,
            deadline=DELIVERY_DEADLINE_SECONDS,
            max_bytes=RESPONSE_CAP_BYTES,
        )
        return int(status)
    if not isinstance(result, tuple) or len(result) < 1:
        return 0
    return int(result[0])


def _apply_sent(row: dict, now: int, status_code: int) -> None:
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if _claim_matches(conn, row):
            _finish_attempt(conn, row, status="sent", now=now, last_status=status_code, sent=True)
        else:
            conn.execute(
                """
                UPDATE webhook_outbox
                SET status = 'dropped', last_status = ?, sent_at = ?
                WHERE id = ? AND generation = ? AND status = 'sending' AND attempts = ?
                """,
                (int(status_code), int(now), int(row["id"]), int(row["generation"]), int(row["attempts"])),
            )
        conn.execute("COMMIT")
    log.info("webhook_sent kind=%s id=%s", row["kind"], int(row["id"]))


def _apply_disable(row: dict, now: int, status_code: int) -> None:
    """Disable this generation only. A newer webhook is left alone."""
    emailed = False
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not _claim_matches(conn, row):
            conn.execute(
                """
                UPDATE webhook_outbox
                SET status = 'dropped', last_status = ?
                WHERE id = ? AND generation = ? AND status = 'sending' AND attempts = ?
                """,
                (int(status_code), int(row["id"]), int(row["generation"]), int(row["attempts"])),
            )
            conn.execute("COMMIT")
            log.info("webhook_stale kind=%s id=%s status=%s", row["kind"], int(row["id"]), status_code)
            return
        reason = f"http_{int(status_code)}"
        disabled = conn.execute(
            """
            UPDATE client_webhooks
            SET enabled = 0, disabled_reason = ?, updated_at = ?
            WHERE client_id = ? AND generation = ? AND enabled = 1
            """,
            (reason, int(now), int(row["client_id"]), int(row["generation"])),
        )
        if disabled.rowcount != 1:
            conn.execute(
                """
                UPDATE webhook_outbox
                SET status = 'dropped', last_status = ?
                WHERE id = ? AND generation = ? AND status = 'sending' AND attempts = ?
                """,
                (int(status_code), int(row["id"]), int(row["generation"]), int(row["attempts"])),
            )
            conn.execute("COMMIT")
            return
        if not _finish_attempt(conn, row, status="failed", now=now, last_status=status_code):
            conn.execute("ROLLBACK")
            return
        from .db_webhooks import audit_webhook

        audit_webhook(
            conn,
            client_id=int(row["client_id"]),
            reason="webhook_disabled",
            now=int(now),
            ref=reason,
        )
        conn.execute(
            """
            UPDATE webhook_outbox
            SET status = 'dropped', last_status = ?
            WHERE client_id = ? AND generation = ? AND id != ? AND status IN ('pending', 'sending')
            """,
            (int(status_code), int(row["client_id"]), int(row["generation"]), int(row["id"])),
        )
        client = conn.execute(
            "SELECT alert_email, alert_email_confirmed_at FROM clients WHERE id = ?",
            (int(row["client_id"]),),
        ).fetchone()
        if client is not None and client["alert_email"] and client["alert_email_confirmed_at"]:
            from .db_alert_email import _enqueue
            from .email_templates import format_utc

            _enqueue(
                conn,
                client_id=int(row["client_id"]),
                kind="webhook_disabled",
                to_email=client["alert_email"],
                params={"status": int(status_code), "at": format_utc(now)},
                now=int(now),
            )
            emailed = True
        conn.execute("COMMIT")
    log.info("webhook_disabled kind=%s id=%s status=%s", row["kind"], int(row["id"]), status_code)
    if emailed:
        from . import email_send

        email_send.notify()


def _retry_or_fail(row: dict, now: int, *, last_status: int) -> None:
    attempts = int(row["attempts"])
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not _claim_matches(conn, row):
            conn.execute(
                """
                UPDATE webhook_outbox
                SET status = 'dropped', last_status = ?
                WHERE id = ? AND generation = ? AND status = 'sending' AND attempts = ?
                """,
                (int(last_status), int(row["id"]), int(row["generation"]), attempts),
            )
            conn.execute("COMMIT")
            return
        if attempts >= MAX_ATTEMPTS:
            _finish_attempt(conn, row, status="failed", now=now, last_status=last_status)
            conn.execute("COMMIT")
            log.info("webhook_failed kind=%s id=%s status=%s", row["kind"], int(row["id"]), last_status)
            return
        delay = RETRY_DELAYS_SECONDS[attempts - 1]
        _finish_attempt(conn, row, status="pending", now=int(now) + delay, last_status=last_status)
        conn.execute("COMMIT")
    log.info("webhook_retry kind=%s id=%s status=%s", row["kind"], int(row["id"]), last_status)
