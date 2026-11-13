"""The only prepaid write path. Balance and the ledger move together.

``clients.balance_msat = SUM(ledger.delta_msat)`` after every committed write.
Amounts are Python ints of millisatoshis. A float is refused.
"""

from __future__ import annotations

import sqlite3
import time

from . import config
from .pricing import require_int
from .quota import commit_slot


def sum_delta(conn: sqlite3.Connection, client_id: int) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(delta_msat), 0) FROM ledger WHERE client_id = ?",
        (int(client_id),),
    ).fetchone()
    return int(row[0]) if row else 0


def _notify(conn: sqlite3.Connection, *, client_id: int, kind: str, balance_msat: int, now: int) -> None:
    """Edge email and webhook. No confirmed address skips email and does not fail the debit."""
    from . import quota
    from .security_events import queue

    row = conn.execute(
        "SELECT alert_email, alert_email_confirmed_at FROM clients WHERE id = ?",
        (int(client_id),),
    ).fetchone()
    email = None
    if row is not None and row["alert_email"] and row["alert_email_confirmed_at"]:
        email = str(row["alert_email"])
    remaining = quota.free_remaining(conn, client_id, now)
    data = {
        "client_id": int(client_id),
        "balance_msat": int(balance_msat),
        "quota_remaining": int(remaining),
        "hint": "Top up with POST /v1/topup/lightning or POST /v1/topup/usdc.",
    }
    if kind == "balance.low":
        data["threshold_msat"] = int(config.LOW_BALANCE_MSAT)
    queue(conn, int(client_id), kind, data, int(now), to_email=email)


def _crossings(conn: sqlite3.Connection, *, client_id: int, previous: int, new: int, now: int) -> None:
    threshold = int(config.LOW_BALANCE_MSAT)
    flags = conn.execute(
        "SELECT low_rearm, zero_rearm FROM clients WHERE id = ?",
        (int(client_id),),
    ).fetchone()
    if flags is None:
        return
    low_rearm = int(flags["low_rearm"] if flags["low_rearm"] is not None else 1)
    zero_rearm = int(flags["zero_rearm"] if flags["zero_rearm"] is not None else 1)
    if previous > threshold >= new and new > 0 and low_rearm:
        _notify(conn, client_id=client_id, kind="balance.low", balance_msat=new, now=now)
        conn.execute(
            "UPDATE clients SET low_rearm = 0, low_notified_at = ? WHERE id = ?",
            (int(now), int(client_id)),
        )
    if new == 0 and previous > 0 and zero_rearm:
        if previous > threshold and low_rearm:
            _notify(conn, client_id=client_id, kind="balance.low", balance_msat=new, now=now)
            conn.execute(
                "UPDATE clients SET low_rearm = 0, low_notified_at = ? WHERE id = ?",
                (int(now), int(client_id)),
            )
        _notify(conn, client_id=client_id, kind="balance.zero", balance_msat=new, now=now)
        conn.execute(
            "UPDATE clients SET zero_rearm = 0, zero_notified_at = ? WHERE id = ?",
            (int(now), int(client_id)),
        )
    if new > threshold:
        conn.execute("UPDATE clients SET low_rearm = 1 WHERE id = ?", (int(client_id),))
    if new > 0:
        conn.execute("UPDATE clients SET zero_rearm = 1 WHERE id = ?", (int(client_id),))


def apply(db_path: str, **kwargs) -> int:
    """Open a write transaction, apply one delta, and commit. Returns the new balance."""
    from .db import _connect

    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        return apply_delta(conn, **kwargs)


def apply_delta(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    delta_msat: int,
    reason: str,
    ref: str | None,
    now: int | None = None,
    api_key_id: int | None = None,
    resource: str | None = None,
    network: str | None = None,
    amount_usd_atomic: int | None = None,
    notify: bool = True,
    legacy_delta_credits: int = 0,
) -> int:
    """Add ``delta_msat`` inside the caller's transaction. Returns the new balance.

    A result below zero raises ``ValueError('insufficient balance')`` before the
    write. The column CHECK is the second rejection.
    """
    delta_msat = require_int(delta_msat, "delta_msat")
    now = int(time.time()) if now is None else int(now)
    row = conn.execute(
        "SELECT balance_msat FROM clients WHERE id = ?",
        (int(client_id),),
    ).fetchone()
    if row is None:
        raise ValueError("client does not exist")
    current = int(row["balance_msat"])
    new_balance = current + delta_msat
    if new_balance < 0:
        raise ValueError("insufficient balance")
    updated = conn.execute(
        "UPDATE clients SET balance_msat = ? WHERE id = ? AND balance_msat = ?",
        (new_balance, int(client_id), current),
    )
    if updated.rowcount != 1:
        raise ValueError("insufficient balance")
    legacy_delta_credits = require_int(legacy_delta_credits, "legacy_delta_credits")
    conn.execute(
        """
        INSERT INTO ledger(
          client_id, delta_credits, delta_msat, reason, ref, created_at,
          api_key_id, resource, network, amount_usd_atomic
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(client_id),
            legacy_delta_credits,
            delta_msat,
            reason,
            ref,
            now,
            int(api_key_id) if api_key_id is not None else None,
            resource,
            network,
            int(amount_usd_atomic) if amount_usd_atomic is not None else None,
        ),
    )
    if legacy_delta_credits:
        conn.execute(
            "UPDATE clients SET credits = credits + ? WHERE id = ?",
            (legacy_delta_credits, int(client_id)),
        )
    if notify and delta_msat != 0:
        _crossings(conn, client_id=int(client_id), previous=current, new=new_balance, now=now)
    return new_balance


def take_live_fee(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    payment_hash: str,
    fee_msat: int,
    reason: str,
    resource: str | None,
    api_key_id: int | None,
    now: int,
    test_mode: bool = False,
    network: str | None = None,
    amount_usd_atomic: int | None = None,
) -> dict:
    """Commit one successful live unlock: free slot first, otherwise the locked fee.

    Test mode debits nothing and does not consume quota. A second call is the
    caller's job to skip (the verification row). This function always counts
    a live, non-test unlock.
    """
    fee_msat = require_int(fee_msat, "fee_msat")
    if fee_msat < 0:
        raise ValueError("invalid price")
    if test_mode:
        row = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        balance = 0 if row is None else int(row["balance_msat"])
        return {"charged_msat": 0, "balance_msat": balance, "free": False, "test_mode": True}
    free = commit_slot(conn, client_id=int(client_id), payment_hash=payment_hash, now=int(now))
    if free:
        row = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        balance = 0 if row is None else int(row["balance_msat"])
        return {"charged_msat": 0, "balance_msat": balance, "free": True, "test_mode": False}
    balance = apply_delta(
        conn,
        client_id=int(client_id),
        delta_msat=-fee_msat,
        reason=reason,
        ref=payment_hash,
        now=int(now),
        api_key_id=api_key_id,
        resource=resource,
        network=network,
        amount_usd_atomic=amount_usd_atomic,
        # The credits column still drops by one paid unlock so current API
        # clients keep seeing a debit until balance_msat replaces it.
        legacy_delta_credits=-1 if fee_msat else 0,
    )
    return {"charged_msat": fee_msat, "balance_msat": balance, "free": False, "test_mode": False}
