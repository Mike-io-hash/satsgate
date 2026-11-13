"""Refunds credit the prepaid balance. They never send Lightning or USDC."""

from __future__ import annotations

import logging
import sqlite3

from .ledger import apply_delta

log = logging.getLogger("satsgate.refunds")


def _already(conn: sqlite3.Connection, ref: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM ledger WHERE reason IN ('refund_automatic', 'refund_manual') AND ref = ?",
        (ref,),
    ).fetchone()
    return row is not None


def repair_anomalies(conn: sqlite3.Connection, *, now: int) -> int:
    """Credit back a second debit for one payment, or a debit with no settlement.

    Idempotent: a refund row's ref is ``auto:<ledger id>``. A second pass credits nothing.
    Returns how many refunds were written. Caller holds the transaction.
    """
    written = 0
    groups = conn.execute(
        """
        SELECT ref FROM ledger
        WHERE reason = 'paywall_verify' AND delta_msat < 0 AND ref IS NOT NULL
        GROUP BY ref HAVING COUNT(*) > 1
        """
    ).fetchall()
    for group in groups:
        rows = conn.execute(
            """
            SELECT id, client_id, delta_msat FROM ledger
            WHERE reason = 'paywall_verify' AND ref = ? AND delta_msat < 0
            ORDER BY id
            """,
            (group["ref"],),
        ).fetchall()
        for extra in rows[1:]:
            ref = f"auto:{int(extra['id'])}"
            if _already(conn, ref):
                continue
            apply_delta(
                conn,
                client_id=int(extra["client_id"]),
                delta_msat=-int(extra["delta_msat"]),
                reason="refund_automatic",
                ref=ref,
                now=now,
                notify=False,
            )
            written += 1
    orphans = conn.execute(
        """
        SELECT l.id, l.client_id, l.delta_msat, l.ref FROM ledger l
        WHERE l.reason = 'paywall_verify' AND l.delta_msat < 0 AND l.ref IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM verifications v WHERE v.payment_hash = l.ref)
          AND NOT EXISTS (SELECT 1 FROM gate_receipts g WHERE g.payment_hash = l.ref)
          AND NOT EXISTS (
            SELECT 1 FROM x402_authorizations a
            WHERE a.tx_hash = l.ref AND COALESCE(a.credit_charged, 0) = 1
          )
        """
    ).fetchall()
    for row in orphans:
        # A duplicate was already handled above. An orphan is a debit with no settlement.
        ref = f"orphan:{int(row['id'])}"
        if _already(conn, ref) or _already(conn, f"auto:{int(row['id'])}"):
            continue
        siblings = conn.execute(
            "SELECT COUNT(*) FROM ledger WHERE reason = 'paywall_verify' AND ref = ? AND delta_msat < 0",
            (row["ref"],),
        ).fetchone()
        if siblings and int(siblings[0]) > 1:
            continue
        apply_delta(
            conn,
            client_id=int(row["client_id"]),
            delta_msat=-int(row["delta_msat"]),
            reason="refund_automatic",
            ref=ref,
            now=now,
            notify=False,
        )
        written += 1
    return written


def credit_manual(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    msat: int,
    reason: str,
    ref: str | None,
    now: int,
) -> int:
    """Operator credit. Logs the audit line without any admin token."""
    balance = apply_delta(
        conn,
        client_id=int(client_id),
        delta_msat=int(msat),
        reason="refund_manual",
        ref=ref or "admin",
        now=int(now),
        notify=False,
    )
    log.info(
        "admin refund client_id=%s msat=%s reason=%s ref=%s balance_msat=%s",
        int(client_id),
        int(msat),
        (reason or "")[:200],
        (ref or "")[:120],
        balance,
    )
    return balance
