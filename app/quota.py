"""Monthly free quota. Remaining is ``max(0, quota - used)`` for the UTC month.

Used counts live on the bucket, not as a decremented remainder. A payee change
moves this account's own used count from the old bucket to the new one (sum,
not max). The slot is committed only when a live unlock succeeds.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from . import config


class FundsRefused(Exception):
    """A new live challenge cannot be funded. Not a buyer payment error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class IssueDecision:
    ok: bool
    reserved: bool
    fee_msat: int
    code: str = ""


def period_utc(now: int) -> str:
    moment = datetime.fromtimestamp(int(now), tz=timezone.utc)
    return f"{moment.year:04d}-{moment.month:02d}"


def bucket_id_for(conn: sqlite3.Connection, client_id: int) -> str:
    """One bucket. Verified EVM payee, else Lightning Address, else the client id.

    An account with both payees shares the EVM bucket. That is the verified
    payout. Lightning-only accounts that use the same address share a different
    bucket. Documented in the pricing notes.
    """
    row = conn.execute(
        """
        SELECT payee_lightning_address, payee_evm_address, payee_evm_verified_at
        FROM clients WHERE id = ?
        """,
        (int(client_id),),
    ).fetchone()
    if row is None:
        raise ValueError("client does not exist")
    evm = row["payee_evm_address"]
    verified = row["payee_evm_verified_at"]
    if evm and verified is not None:
        return "evm:" + str(evm).strip().lower()
    lightning = row["payee_lightning_address"]
    if lightning and str(lightning).strip():
        return "ln:" + str(lightning).strip().lower()
    return f"client:{int(client_id)}"


def _bucket_used(conn: sqlite3.Connection, bucket_id: str, period: str) -> int:
    row = conn.execute(
        "SELECT used_unlocks FROM quota_buckets WHERE bucket_id = ? AND period_utc = ?",
        (bucket_id, period),
    ).fetchone()
    return 0 if row is None else int(row["used_unlocks"])


def _reserved_count(conn: sqlite3.Connection, bucket_id: str, period: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM quota_reservations WHERE bucket_id = ? AND period_utc = ?",
        (bucket_id, period),
    ).fetchone()
    return int(row[0]) if row else 0


def sync_membership(conn: sqlite3.Connection, client_id: int, now: int) -> str:
    """Move this account's used count when its bucket changed. Sum, not max."""
    period = period_utc(now)
    desired = bucket_id_for(conn, client_id)
    row = conn.execute(
        "SELECT bucket_id, used_unlocks FROM client_quota WHERE client_id = ? AND period_utc = ?",
        (int(client_id), period),
    ).fetchone()
    if row is None:
        conn.execute(
            """
            INSERT INTO client_quota(client_id, period_utc, bucket_id, used_unlocks)
            VALUES(?, ?, ?, 0)
            """,
            (int(client_id), period, desired),
        )
        conn.execute(
            """
            INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks)
            VALUES(?, ?, 0)
            ON CONFLICT(bucket_id, period_utc) DO NOTHING
            """,
            (desired, period),
        )
        return desired
    current = str(row["bucket_id"])
    used = int(row["used_unlocks"])
    if current == desired:
        return desired
    if used:
        conn.execute(
            """
            UPDATE quota_buckets
            SET used_unlocks = CASE WHEN used_unlocks > ? THEN used_unlocks - ? ELSE 0 END
            WHERE bucket_id = ? AND period_utc = ?
            """,
            (used, used, current, period),
        )
        conn.execute(
            """
            INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks)
            VALUES(?, ?, ?)
            ON CONFLICT(bucket_id, period_utc) DO UPDATE SET
              used_unlocks = used_unlocks + excluded.used_unlocks
            """,
            (desired, period, used),
        )
    else:
        conn.execute(
            """
            INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks)
            VALUES(?, ?, 0)
            ON CONFLICT(bucket_id, period_utc) DO NOTHING
            """,
            (desired, period),
        )
    conn.execute(
        "UPDATE client_quota SET bucket_id = ? WHERE client_id = ? AND period_utc = ?",
        (desired, int(client_id), period),
    )
    return desired


def free_remaining(conn: sqlite3.Connection, client_id: int, now: int, *, quota: int | None = None) -> int:
    """Shared remainder for this account's bucket. Does not reserve a slot."""
    bucket = sync_membership(conn, client_id, now)
    limit = int(config.FREE_QUOTA) if quota is None else int(quota)
    used = _bucket_used(conn, bucket, period_utc(now))
    return max(0, limit - used)


def authorize_issue(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    fee_msat: int,
    now: int,
    test_mode: bool,
    quota: int | None = None,
) -> IssueDecision:
    """Reserve a free slot, or require the locked fee. Caller holds the write lock."""
    fee_msat = int(fee_msat)
    if test_mode:
        return IssueDecision(ok=True, reserved=False, fee_msat=0)
    bucket = sync_membership(conn, client_id, now)
    period = period_utc(now)
    limit = int(config.FREE_QUOTA) if quota is None else int(quota)
    used = _bucket_used(conn, bucket, period)
    reserved = _reserved_count(conn, bucket, period)
    if used + reserved < limit:
        return IssueDecision(ok=True, reserved=True, fee_msat=fee_msat)
    row = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (int(client_id),)).fetchone()
    balance = 0 if row is None else int(row["balance_msat"])
    if fee_msat >= 0 and balance >= fee_msat:
        return IssueDecision(ok=True, reserved=False, fee_msat=fee_msat)
    return IssueDecision(ok=False, reserved=False, fee_msat=fee_msat, code="insufficient_balance")


def hold_reservation(
    conn: sqlite3.Connection,
    *,
    payment_hash: str,
    client_id: int,
    now: int,
) -> None:
    bucket = bucket_id_for(conn, client_id)
    conn.execute(
        """
        INSERT INTO quota_reservations(payment_hash, client_id, bucket_id, period_utc, created_at)
        VALUES(?, ?, ?, ?, ?)
        """,
        (payment_hash, int(client_id), bucket, period_utc(now), int(now)),
    )


def release_reservation(conn: sqlite3.Connection, payment_hash: str) -> None:
    conn.execute("DELETE FROM quota_reservations WHERE payment_hash = ?", (payment_hash,))


def commit_slot(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    payment_hash: str,
    now: int,
    quota: int | None = None,
) -> bool:
    """Count one successful live unlock. Returns whether it was free.

    The caller holds ``BEGIN IMMEDIATE``. A reservation is released here.
    Two callers at ``used == quota - 1`` cannot both be free.
    """
    bucket = sync_membership(conn, client_id, now)
    period = period_utc(now)
    limit = int(config.FREE_QUOTA) if quota is None else int(quota)
    used = _bucket_used(conn, bucket, period)
    free = used < limit
    conn.execute(
        """
        INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks)
        VALUES(?, ?, 1)
        ON CONFLICT(bucket_id, period_utc) DO UPDATE SET used_unlocks = used_unlocks + 1
        """,
        (bucket, period),
    )
    conn.execute(
        """
        UPDATE client_quota SET used_unlocks = used_unlocks + 1
        WHERE client_id = ? AND period_utc = ?
        """,
        (int(client_id), period),
    )
    release_reservation(conn, payment_hash)
    return free
