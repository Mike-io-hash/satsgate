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


class UsageDenied(Exception):
    """A consume lost the race or the grant is over. Settlement is already committed."""

    def __init__(self, code: str, *, usage: dict, charged: int, new_balance: int) -> None:
        super().__init__(code)
        self.code = code
        self.usage = usage
        self.charged = int(charged)
        self.new_balance = int(new_balance)


def usage_view(row, *, consumed: bool) -> dict:
    """Public usage fields. uses_remaining is null when the challenge has no max_uses."""
    max_uses = row["max_uses"]
    access_seconds = row["access_seconds"]
    uses_consumed = int(row["uses_consumed"] or 0)
    access_until = row["access_until"]
    settled_at = row["settled_at"]
    remaining = None if max_uses is None else max(0, int(max_uses) - uses_consumed)
    return {
        "max_uses": int(max_uses) if max_uses is not None else None,
        "access_seconds": int(access_seconds) if access_seconds is not None else None,
        "uses_consumed": uses_consumed,
        "uses_remaining": remaining,
        "access_until": int(access_until) if access_until is not None else None,
        "settled_at": int(settled_at) if settled_at is not None else None,
        "consumed": bool(consumed),
    }


def _policy_set(row) -> bool:
    return row["max_uses"] is not None or row["access_seconds"] is not None


def _grant_open(row, now: int) -> bool:
    if not _policy_set(row):
        return True
    access_until = row["access_until"]
    if access_until is not None and now > int(access_until):
        return False
    max_uses = row["max_uses"]
    if max_uses is not None and int(row["uses_consumed"] or 0) >= int(max_uses):
        return False
    return True


def settle_and_consume(
    db_path: str,
    *,
    client_id: int,
    payment_hash: str,
    cost: int,
    resource: str | None,
    api_key_id: int | None,
    consume: bool,
    access_cap_seconds: int,
    now: int | None = None,
) -> dict:
    """Charge credits once for this payment, then optionally take one use.

    `consume=False` is a check: it can settle the payment and never changes
    uses_consumed. `consume=True` on a challenge with no policy is allowed and
    does not decrement a counter (that is the pre-0.6.0 grant).

    A challenge with max_uses and/or access_seconds stores the counter and
    access_until on the challenge row. The conditional UPDATE is the only way
    a use is taken, inside the same IMMEDIATE transaction as the credit debit,
    so two callers cannot both take the last use.

    When access_seconds is omitted, a max_uses bundle still ends at
    `access_cap_seconds` after settlement. That deadline is stored in
    access_until.

    Raises UsageDenied after committing settlement. Raises ValueError for a
    missing client or an insufficient balance, with no use taken.
    Returns charged, new_balance, and the usage view.
    """

    now = int(time.time()) if now is None else int(now)
    cost = int(cost)
    denied: UsageDenied | None = None

    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        challenge = conn.execute(
            "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()
        if challenge is None or int(challenge["client_id"]) != int(client_id):
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")

        verified = conn.execute(
            "SELECT 1 FROM verifications WHERE client_id = ? AND payment_hash = ?",
            (int(client_id), payment_hash),
        ).fetchone()

        charged = 0
        if not verified:
            bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
            if not bal_row:
                conn.execute("ROLLBACK")
                raise ValueError("client does not exist")
            current = int(bal_row[0])
            if current < cost:
                conn.execute("ROLLBACK")
                raise ValueError("insufficient balance")
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
            charged = cost

            window: int | None = None
            if challenge["access_seconds"] is not None:
                window = int(challenge["access_seconds"])
            elif challenge["max_uses"] is not None:
                window = int(access_cap_seconds)
            if window is not None:
                conn.execute(
                    """
                    UPDATE paywall_challenges
                    SET settled_at = COALESCE(settled_at, ?),
                        access_until = COALESCE(access_until, ?)
                    WHERE payment_hash = ?
                    """,
                    (now, now + window, payment_hash),
                )
            else:
                conn.execute(
                    "UPDATE paywall_challenges SET settled_at = COALESCE(settled_at, ?) WHERE payment_hash = ?",
                    (now, payment_hash),
                )
        elif challenge["settled_at"] is None:
            conn.execute(
                "UPDATE paywall_challenges SET settled_at = COALESCE(settled_at, ?) WHERE payment_hash = ?",
                (now, payment_hash),
            )

        challenge = conn.execute(
            "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()
        bal = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        new_balance = int(bal[0]) if bal else 0
        consumed = False

        if consume and _policy_set(challenge):
            if not _grant_open(challenge, now):
                code = "token_expired"
                access_until = challenge["access_until"]
                if access_until is None or now <= int(access_until):
                    code = "token_used_up"
                denied = UsageDenied(
                    code,
                    usage=usage_view(challenge, consumed=False),
                    charged=charged,
                    new_balance=new_balance,
                )
            else:
                before = int(challenge["uses_consumed"] or 0)
                conn.execute(
                    """
                    UPDATE paywall_challenges
                    SET uses_consumed = uses_consumed + 1
                    WHERE payment_hash = ?
                      AND (max_uses IS NULL OR uses_consumed < max_uses)
                      AND (access_until IS NULL OR access_until >= ?)
                    """,
                    (payment_hash, now),
                )
                challenge = conn.execute(
                    "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
                    (payment_hash,),
                ).fetchone()
                if int(challenge["uses_consumed"] or 0) != before + 1:
                    code = "token_expired"
                    access_until = challenge["access_until"]
                    if access_until is None or now <= int(access_until):
                        code = "token_used_up"
                    denied = UsageDenied(
                        code,
                        usage=usage_view(challenge, consumed=False),
                        charged=charged,
                        new_balance=new_balance,
                    )
                else:
                    consumed = True
        elif consume:
            consumed = True

        usage = usage_view(challenge, consumed=consumed and denied is None)
        conn.execute("COMMIT")

    if denied is not None:
        raise denied
    return {"charged": charged, "new_balance": new_balance, **usage}


def _closed_code(challenge, now: int) -> str:
    access_until = challenge["access_until"]
    if access_until is None or now <= int(access_until):
        return "token_used_up"
    return "token_expired"


def _stamp_confirmed(conn, challenge, payment_hash: str, now: int, access_cap_seconds: int) -> None:
    """Start the access window when the Lightning payment is confirmed. Do not debit."""
    window: int | None = None
    if challenge["access_seconds"] is not None:
        window = int(challenge["access_seconds"])
    elif challenge["max_uses"] is not None:
        window = int(access_cap_seconds)
    if window is not None:
        conn.execute(
            """
            UPDATE paywall_challenges
            SET settled_at = COALESCE(settled_at, ?),
                access_until = COALESCE(access_until, ?)
            WHERE payment_hash = ?
            """,
            (now, now + window, payment_hash),
        )
    else:
        conn.execute(
            "UPDATE paywall_challenges SET settled_at = COALESCE(settled_at, ?) WHERE payment_hash = ?",
            (now, payment_hash),
        )


def _deny_closed(conn, challenge, *, now: int, new_balance: int) -> None:
    usage = usage_view(challenge, consumed=False)
    conn.execute("ROLLBACK")
    raise UsageDenied(_closed_code(challenge, now), usage=usage, charged=0, new_balance=new_balance)


def confirm_payment(
    db_path: str,
    *,
    client_id: int,
    payment_hash: str,
    cost: int,
    access_cap_seconds: int,
    now: int | None = None,
) -> dict:
    """Record that the buyer paid. Do not debit a credit and do not take a use.

    The hosted gate calls this before the origin. ``settled_at`` frees the
    unpaid-challenge slot. A later 2xx calls ``charge_after_delivery``. A
    grant that is already used up is denied here, so the origin is not called.
    """
    now = int(time.time()) if now is None else int(now)
    cost = int(cost)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        challenge = conn.execute(
            "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()
        if challenge is None or int(challenge["client_id"]) != int(client_id):
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if not bal_row:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        new_balance = int(bal_row[0])
        if _policy_set(challenge) and not _grant_open(challenge, now):
            _deny_closed(conn, challenge, now=now, new_balance=new_balance)
        verified = conn.execute(
            "SELECT 1 FROM verifications WHERE client_id = ? AND payment_hash = ?",
            (int(client_id), payment_hash),
        ).fetchone()
        if not verified and new_balance < cost:
            conn.execute("ROLLBACK")
            raise ValueError("insufficient balance")
        _stamp_confirmed(conn, challenge, payment_hash, now, access_cap_seconds)
        challenge = conn.execute(
            "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()
        usage = usage_view(challenge, consumed=False)
        conn.execute("COMMIT")
    return {"charged": 0, "new_balance": new_balance, **usage}


def charge_after_delivery(
    db_path: str,
    *,
    client_id: int,
    payment_hash: str,
    cost: int,
    resource: str | None,
    api_key_id: int | None,
    now: int | None = None,
) -> dict:
    """Take one use and, on the first success, one credit. One IMMEDIATE transaction.

    The use update runs first. If it loses, this rolls back and raises
    UsageDenied with no debit. An insufficient balance rolls the use back too,
    so the token stays usable. A challenge with no policy debits once and does
    not increment a counter. ``UNIQUE(client_id, payment_hash)`` keeps a second
    caller from debiting again.
    """
    now = int(time.time()) if now is None else int(now)
    cost = int(cost)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        challenge = conn.execute(
            "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()
        if challenge is None or int(challenge["client_id"]) != int(client_id):
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        if challenge["settled_at"] is None:
            conn.execute("ROLLBACK")
            raise ValueError("payment not confirmed")
        bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if not bal_row:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        new_balance = int(bal_row[0])
        if _policy_set(challenge) and not _grant_open(challenge, now):
            _deny_closed(conn, challenge, now=now, new_balance=new_balance)
        took_use = False
        if _policy_set(challenge):
            before = int(challenge["uses_consumed"] or 0)
            conn.execute(
                """
                UPDATE paywall_challenges
                SET uses_consumed = uses_consumed + 1
                WHERE payment_hash = ?
                  AND (max_uses IS NULL OR uses_consumed < max_uses)
                  AND (access_until IS NULL OR access_until >= ?)
                """,
                (payment_hash, now),
            )
            challenge = conn.execute(
                "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
                (payment_hash,),
            ).fetchone()
            if int(challenge["uses_consumed"] or 0) != before + 1:
                _deny_closed(conn, challenge, now=now, new_balance=new_balance)
            took_use = True
        inserted = conn.execute(
            "INSERT OR IGNORE INTO verifications(client_id, payment_hash, resource, created_at) VALUES(?, ?, ?, ?)",
            (int(client_id), payment_hash, resource, now),
        )
        wrote = inserted.rowcount
        if wrote < 0:
            wrote = int(conn.execute("SELECT changes()").fetchone()[0])
        charged = 0
        if wrote == 1:
            if new_balance < cost:
                conn.execute("ROLLBACK")
                raise ValueError("insufficient balance")
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
            charged = cost
            new_balance -= cost
        consumed = took_use or not _policy_set(challenge)
        usage = usage_view(challenge, consumed=consumed)
        conn.execute("COMMIT")
    return {"charged": charged, "new_balance": new_balance, **usage}
