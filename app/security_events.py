"""Fan out one security event to the alert email and the seller webhook.

The caller is already inside the transaction that made the change. An insert
failure raises, and that change rolls back with it. Nothing is sent on the
network here.
"""

from __future__ import annotations

# Kinds the alert email already covers, plus rotation and the merchant's test.
# Confirmation tokens stay on the email path only. ``webhook_disabled`` is an
# email about the webhook itself and is not delivered back to that URL.
WEBHOOK_KINDS = frozenset(
    {
        "payee_lightning_changed",
        "payee_evm_changed",
        "payee_ofac_flagged",
        "alert_email_changed",
        "alert_email_removed",
        "account_key_rotated",
        "webhook_test",
    }
)


class Fanout:
    """Which outboxes received a row. Truthy when either did."""

    __slots__ = ("email", "webhook")

    def __init__(self, *, email: bool = False, webhook: bool = False) -> None:
        self.email = bool(email)
        self.webhook = bool(webhook)

    def __bool__(self) -> bool:
        return self.email or self.webhook


def queue(conn, client_id: int, kind: str, params: dict, now: int, *, to_email: str | None = None) -> Fanout:
    """Insert email and webhook rows. ``to_email`` empty skips the email only."""
    emailed = False
    if to_email:
        from .db_alert_email import _enqueue

        _enqueue(
            conn,
            client_id=int(client_id),
            kind=kind,
            to_email=to_email,
            params=params,
            now=int(now),
        )
        emailed = True
    hooked = False
    if kind in WEBHOOK_KINDS:
        from .db_webhooks import enqueue_delivery

        hooked = enqueue_delivery(
            conn,
            client_id=int(client_id),
            kind=kind,
            data=params,
            now=int(now),
        )
    return Fanout(email=emailed, webhook=hooked)
