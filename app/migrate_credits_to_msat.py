"""Convert prepaid credits to milisatoshis. 1 credit = 2,000 msat.

Run this only against a path you pass in. It never opens ``SATSGATE_DB_PATH``
and it never opens a production file on its own. Production apply is manual,
after a backup and a dry-run on a copy, and only with a separate OK.

    python -m app.migrate_credits_to_msat --db PATH --dry-run
    python -m app.migrate_credits_to_msat --db PATH --apply
    python -m app.migrate_credits_to_msat --db PATH --reverse

A second apply after a successful conversion is a no-op (``already_migrated``).
Reverse divides by 2,000 only while every milisat value is still a multiple of
2,000. After any other movement, restore the backup instead.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time

FACTOR = 2000


class MigrationError(Exception):
    """The conversion did not write. The database is unchanged."""


def _connect(path: str, *, readonly: bool) -> sqlite3.Connection:
    if readonly:
        uri = "file:" + path.replace("?", "%3F") + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    else:
        conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _require_legacy(conn: sqlite3.Connection) -> None:
    if "credits" not in _columns(conn, "clients"):
        raise MigrationError("schema is missing clients.credits")
    if "delta_credits" not in _columns(conn, "ledger"):
        raise MigrationError("schema is missing ledger.delta_credits")


def _completed(conn: sqlite3.Connection) -> bool:
    if "credit_migration" not in {
        row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }:
        return False
    row = conn.execute("SELECT completed FROM credit_migration WHERE id = 1").fetchone()
    return row is not None and int(row["completed"]) == 1


def _clients(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT id, credits FROM clients ORDER BY id"))


def _ledger_sum(conn: sqlite3.Connection, client_id: int) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(delta_credits), 0) FROM ledger WHERE client_id = ?",
        (int(client_id),),
    ).fetchone()
    return int(row[0])


def _plan(conn: sqlite3.Connection) -> dict:
    """Compute the conversion. Raises when a client's credits do not match the ledger."""
    rows = []
    anomalies = []
    for client in _clients(conn):
        old = int(client["credits"])
        total = _ledger_sum(conn, int(client["id"]))
        if old < 0:
            anomalies.append(f"client {int(client['id'])} has negative credits ({old})")
        if old != total:
            anomalies.append(
                f"client {int(client['id'])} credits {old} != SUM(ledger.delta_credits) {total}"
            )
        rows.append({"client_id": int(client["id"]), "old_credits": old, "new_msat": old * FACTOR})
    if anomalies:
        raise MigrationError("conversion stopped: " + "; ".join(anomalies))
    old_sum = sum(item["old_credits"] for item in rows)
    new_sum = sum(item["new_msat"] for item in rows)
    if old_sum * FACTOR != new_sum:
        raise MigrationError("SUM(old credits) * 2000 != SUM(new msat)")
    payload = "\n".join(f"{item['client_id']},{item['old_credits']},{item['new_msat']}" for item in rows)
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "clients": len(rows),
        "rows": rows,
        "old_credits_sum": old_sum,
        "new_msat_sum": new_sum,
        "checksum": checksum,
        "factor": FACTOR,
        "balanced": True,
    }


def _ensure_columns(conn: sqlite3.Connection) -> None:
    clients = _columns(conn, "clients")
    if "balance_msat" not in clients:
        conn.execute(
            "ALTER TABLE clients ADD COLUMN balance_msat INTEGER NOT NULL DEFAULT 0 CHECK (balance_msat >= 0)"
        )
    ledger = _columns(conn, "ledger")
    if "delta_msat" not in ledger:
        conn.execute("ALTER TABLE ledger ADD COLUMN delta_msat INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS credit_migration (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          factor INTEGER NOT NULL,
          ran_at INTEGER,
          checksum TEXT,
          completed INTEGER NOT NULL DEFAULT 0
        )
        """
    )


def _diverged(conn: sqlite3.Connection) -> str | None:
    """Refuse to overwrite a database that already moved milisatoshis on its own."""
    if "balance_msat" not in _columns(conn, "clients"):
        return None
    for client in conn.execute("SELECT id, credits, balance_msat FROM clients"):
        credits = int(client["credits"])
        balance = int(client["balance_msat"])
        if balance not in {0, credits * FACTOR}:
            return f"client {int(client['id'])} balance_msat {balance} is not credits*2000"
    if "delta_msat" not in _columns(conn, "ledger"):
        return None
    for row in conn.execute("SELECT id, delta_credits, delta_msat FROM ledger"):
        delta = int(row["delta_credits"])
        msat = int(row["delta_msat"])
        if msat not in {0, delta * FACTOR}:
            return f"ledger {int(row['id'])} delta_msat {msat} is not delta_credits*2000"
    return None


def _aligned(conn: sqlite3.Connection) -> str | None:
    for client in conn.execute("SELECT id, balance_msat FROM clients"):
        balance = int(client["balance_msat"])
        if balance % FACTOR != 0:
            return f"client {int(client['id'])} balance_msat {balance} is not a multiple of {FACTOR}"
    for row in conn.execute("SELECT id, delta_msat FROM ledger"):
        delta = int(row["delta_msat"])
        if delta % FACTOR != 0:
            return f"ledger {int(row['id'])} delta_msat {delta} is not a multiple of {FACTOR}"
    return None


def dry_run(path: str) -> dict:
    """Report the conversion and do not write. The file bytes stay as they were."""
    conn = _connect(path, readonly=True)
    try:
        _require_legacy(conn)
        if _completed(conn):
            return {"status": "already_migrated", "factor": FACTOR}
        report = _plan(conn)
        report["status"] = "dry_run"
        return report
    finally:
        conn.close()


def apply(path: str, *, now: int | None = None) -> dict:
    """Convert every credit. A second successful call does not multiply again."""
    now = int(time.time()) if now is None else int(now)
    conn = _connect(path, readonly=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _require_legacy(conn)
        if _completed(conn):
            conn.execute("COMMIT")
            return {"status": "already_migrated", "factor": FACTOR}
        report = _plan(conn)
        problem = _diverged(conn)
        if problem:
            conn.execute("ROLLBACK")
            raise MigrationError("refusing to overwrite milisat balances: " + problem)
        _ensure_columns(conn)
        for item in report["rows"]:
            conn.execute(
                "UPDATE clients SET balance_msat = ? WHERE id = ?",
                (int(item["new_msat"]), int(item["client_id"])),
            )
        conn.execute("UPDATE ledger SET delta_msat = delta_credits * ?", (FACTOR,))
        conn.execute(
            """
            INSERT INTO credit_migration(id, factor, ran_at, checksum, completed)
            VALUES(1, ?, ?, ?, 1)
            ON CONFLICT(id) DO UPDATE SET
              factor = excluded.factor,
              ran_at = excluded.ran_at,
              checksum = excluded.checksum,
              completed = 1
            """,
            (FACTOR, now, report["checksum"]),
        )
        for client in conn.execute("SELECT id, balance_msat FROM clients"):
            total = conn.execute(
                "SELECT COALESCE(SUM(delta_msat), 0) FROM ledger WHERE client_id = ?",
                (int(client["id"]),),
            ).fetchone()
            if int(client["balance_msat"]) != int(total[0]):
                conn.execute("ROLLBACK")
                raise MigrationError(f"invariant failed for client {int(client['id'])} before commit")
        conn.execute("COMMIT")
        report["status"] = "applied"
        return report
    except MigrationError:
        raise
    except sqlite3.OperationalError as exc:
        raise MigrationError(f"could not lock the database: {exc}") from exc
    finally:
        conn.close()


def reverse(path: str) -> dict:
    """Divide by 2,000. Refuses after any value that is not a multiple of 2,000."""
    conn = _connect(path, readonly=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _require_legacy(conn)
        if "balance_msat" not in _columns(conn, "clients") or not _completed(conn):
            conn.execute("ROLLBACK")
            raise MigrationError("nothing to reverse: the conversion has not been applied")
        problem = _aligned(conn)
        if problem:
            conn.execute("ROLLBACK")
            raise MigrationError(
                "reverse refused: " + problem + ". Restore the backup; do not divide."
            )
        before = [
            (int(row["id"]), int(row["balance_msat"]))
            for row in conn.execute("SELECT id, balance_msat FROM clients ORDER BY id")
        ]
        conn.execute("UPDATE clients SET credits = balance_msat / ?, balance_msat = 0", (FACTOR,))
        conn.execute("UPDATE ledger SET delta_credits = delta_msat / ?, delta_msat = 0", (FACTOR,))
        conn.execute("UPDATE credit_migration SET completed = 0 WHERE id = 1")
        conn.execute("COMMIT")
        return {"status": "reversed", "clients": [{"id": item[0], "msat_before": item[1]} for item in before]}
    except MigrationError:
        raise
    except sqlite3.OperationalError as exc:
        raise MigrationError(f"could not lock the database: {exc}") from exc
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert satsgate credits to milisatoshis (1 credit = 2000 msat).")
    parser.add_argument("--db", required=True, help="SQLite file to read or convert. There is no default path.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--reverse", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.dry_run:
            report = dry_run(args.db)
        elif args.apply:
            report = apply(args.db)
        else:
            report = reverse(args.db)
    except MigrationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, **_public(report)}, sort_keys=True))
    return 0


def _public(report: dict) -> dict:
    """Drop nothing secret. Client ids and balances are the operator's own report."""
    return report


if __name__ == "__main__":
    raise SystemExit(main())
