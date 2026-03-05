from __future__ import annotations

from datetime import datetime, timezone

from .db import _connect


def _iso(ts: int | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()


def operator_overview(db_path: str, *, since_ts: int) -> dict:
    """Operator-level overview across all customers.

    This is meant for the hosted service operator (you), not for customers.
    """

    since_ts = int(since_ts)

    with _connect(db_path) as conn:
        clients_total = int(conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0])
        credits_outstanding = int(conn.execute("SELECT COALESCE(SUM(credits),0) FROM clients").fetchone()[0])

        clients_new = int(
            conn.execute("SELECT COUNT(*) FROM clients WHERE created_at >= ?", (since_ts,)).fetchone()[0]
        )

        topups_pending = int(conn.execute("SELECT COUNT(*) FROM topups WHERE status='pending'").fetchone()[0])

        topups_settled_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM topups WHERE status='settled' AND settled_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        topups_sats_sum = int(
            conn.execute(
                "SELECT COALESCE(SUM(sats),0) FROM topups WHERE status='settled' AND settled_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        topups_credits_sum = int(
            conn.execute(
                "SELECT COALESCE(SUM(credits),0) FROM topups WHERE status='settled' AND settled_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        verify_events = int(
            conn.execute(
                "SELECT COALESCE(SUM(CASE WHEN reason='paywall_verify' THEN 1 ELSE 0 END),0) FROM ledger WHERE created_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        verify_credits_spent = int(
            conn.execute(
                "SELECT COALESCE(SUM(CASE WHEN reason='paywall_verify' AND delta_credits < 0 THEN -delta_credits ELSE 0 END),0) FROM ledger WHERE created_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        credits_in = int(
            conn.execute(
                "SELECT COALESCE(SUM(CASE WHEN delta_credits > 0 THEN delta_credits ELSE 0 END),0) FROM ledger WHERE created_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        credits_out = int(
            conn.execute(
                "SELECT COALESCE(SUM(CASE WHEN delta_credits < 0 THEN -delta_credits ELSE 0 END),0) FROM ledger WHERE created_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        net_credits = int(
            conn.execute(
                "SELECT COALESCE(SUM(delta_credits),0) FROM ledger WHERE created_at >= ?",
                (since_ts,),
            ).fetchone()[0]
        )

        last_topup_settled = conn.execute(
            "SELECT MAX(settled_at) FROM topups WHERE status='settled'",
        ).fetchone()[0]

        last_verify = conn.execute(
            "SELECT MAX(created_at) FROM ledger WHERE reason='paywall_verify'",
        ).fetchone()[0]

    return {
        "since_ts": since_ts,
        "since_iso": _iso(since_ts),
        "totals": {
            "clients_total": clients_total,
            "credits_outstanding": credits_outstanding,
            "topups_pending": topups_pending,
        },
        "window": {
            "clients_new": clients_new,
            "topups_settled_count": topups_settled_count,
            "topups_sats_sum": topups_sats_sum,
            "topups_credits_sum": topups_credits_sum,
            "verify_events": verify_events,
            "verify_credits_spent": verify_credits_spent,
            "credits_in": credits_in,
            "credits_out": credits_out,
            "net_credits": net_credits,
        },
        "last_seen": {
            "topup_settled_ts": int(last_topup_settled) if last_topup_settled is not None else None,
            "topup_settled_iso": _iso(last_topup_settled),
            "verify_ts": int(last_verify) if last_verify is not None else None,
            "verify_iso": _iso(last_verify),
        },
        "note": "Operator overview. Values are derived from the database and are best-effort.",
    }
