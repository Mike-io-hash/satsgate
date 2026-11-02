from __future__ import annotations

import time

from . import db_alert_email, email_send
from .db import _connect


def set_client_payee(db_path: str, *, client_id: int, payee_lightning_address: str | None) -> bool:
    """Save the Lightning payee. Returns whether the stored address changed.

    A change, including the first address, queues an alert when a confirmed
    email exists. The same value queues nothing. The alert row commits with
    the payee write.
    """
    now = int(time.time())
    queued = False
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        previous = row["payee_lightning_address"]
        changed = previous != payee_lightning_address
        conn.execute(
            "UPDATE clients SET payee_lightning_address = ? WHERE id = ?",
            (payee_lightning_address, int(client_id)),
        )
        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (int(client_id), 0, "payee_set", payee_lightning_address, now),
        )
        if changed and payee_lightning_address:
            queued = db_alert_email.queue_payout(
                conn,
                client_id=int(client_id),
                to_email=row["alert_email"],
                kind="payee_lightning_changed",
                new_address=payee_lightning_address,
                previous=previous,
                via="API",
                rails_cleared=False,
                now=now,
            )
            if queued:
                db_alert_email.raise_if_guarded()
        conn.execute("COMMIT")
    if queued:
        email_send.notify()
    return changed


def get_client_payee(db_path: str, *, client_id: int) -> str | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT payee_lightning_address FROM clients WHERE id = ?",
            (int(client_id),),
        ).fetchone()
        if not row:
            return None
        return row[0]
