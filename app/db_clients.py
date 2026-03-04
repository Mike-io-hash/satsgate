from __future__ import annotations

import time

from .db import _connect


def set_client_payee(db_path: str, *, client_id: int, payee_lightning_address: str | None) -> None:
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE clients SET payee_lightning_address = ? WHERE id = ?",
            (payee_lightning_address, int(client_id)),
        )
        if cur.rowcount == 0:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")

        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (int(client_id), 0, "payee_set", payee_lightning_address, now),
        )
        conn.execute("COMMIT")


def get_client_payee(db_path: str, *, client_id: int) -> str | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT payee_lightning_address FROM clients WHERE id = ?",
            (int(client_id),),
        ).fetchone()
        if not row:
            return None
        return row[0]
