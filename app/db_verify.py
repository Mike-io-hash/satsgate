from __future__ import annotations

import time

from .db import _connect


def has_verification(db_path: str, *, client_id: int, payment_hash: str) -> bool:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM verifications WHERE client_id = ? AND payment_hash = ?",
            (int(client_id), payment_hash),
        ).fetchone()
        return row is not None


def verify_once_and_spend(
    db_path: str,
    *,
    client_id: int,
    payment_hash: str,
    cost: int,
    resource: str | None = None,
    api_key_id: int | None = None,
) -> dict:
    """Mark (client_id, payment_hash) as verified and spend credits exactly once.

    - Idempotent: if it was already verified, it will not charge again.
    - Atomic: everything happens in a single transaction.
    - The debit row records `api_key_id` (NULL for the account key) and `resource`.

    Returns: {charged, new_balance}
    """

    now = int(time.time())
    cost = int(cost)

    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")

        # already verified?
        row = conn.execute(
            "SELECT 1 FROM verifications WHERE client_id = ? AND payment_hash = ?",
            (int(client_id), payment_hash),
        ).fetchone()

        if row:
            bal = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
            conn.execute("COMMIT")
            return {"charged": 0, "new_balance": int(bal[0]) if bal else 0}

        # sufficient balance
        bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if not bal_row:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")

        current = int(bal_row[0])
        if current < cost:
            conn.execute("ROLLBACK")
            raise ValueError("insufficient balance")

        # charge
        conn.execute(
            "UPDATE clients SET credits = credits - ? WHERE id = ?",
            (cost, int(client_id)),
        )
        conn.execute(
            """
            INSERT INTO ledger(
              client_id, delta_credits, reason, ref, created_at, api_key_id, resource
            )
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(client_id),
                -cost,
                "paywall_verify",
                payment_hash,
                now,
                int(api_key_id) if api_key_id is not None else None,
                resource,
            ),
        )
        conn.execute(
            "INSERT INTO verifications(client_id, payment_hash, resource, created_at) VALUES(?, ?, ?, ?)",
            (int(client_id), payment_hash, resource, now),
        )

        new_bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        new_balance = int(new_bal_row[0]) if new_bal_row else 0

        conn.execute("COMMIT")

    return {"charged": cost, "new_balance": new_balance}
