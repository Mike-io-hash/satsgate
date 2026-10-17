"""Local sqlite for the spend ledger, unpaid quotes, and paid token cache."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS spend (
    id INTEGER PRIMARY KEY,
    created_at INTEGER NOT NULL,
    amount_sats INTEGER NOT NULL,
    payment_hash TEXT NOT NULL,
    host TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quotes (
    payment_hash TEXT PRIMARY KEY,
    cache_key TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    macaroon TEXT NOT NULL,
    invoice TEXT NOT NULL,
    resource TEXT,
    amount_sats INTEGER NOT NULL,
    max_uses INTEGER,
    access_seconds INTEGER,
    invoice_expires_at INTEGER,
    reason TEXT,
    request_body BLOB,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    cache_key TEXT PRIMARY KEY,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    macaroon TEXT NOT NULL,
    preimage TEXT,
    payment_hash TEXT NOT NULL,
    resource TEXT,
    amount_sats INTEGER NOT NULL,
    max_uses INTEGER,
    access_seconds INTEGER,
    uses_remaining INTEGER,
    access_until INTEGER,
    invoice_expires_at INTEGER,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS quotes_by_key ON quotes (cache_key, created_at);
"""


class Store:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        try:
            os.chmod(data_dir, 0o700)
        except OSError:
            pass
        path = data_dir / "satsgate-mcp.sqlite"
        self._conn = sqlite3.connect(path, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        self._conn.close()

    def spent_since(self, since: int) -> int:
        row = self._conn.execute("SELECT COALESCE(SUM(amount_sats), 0) AS total FROM spend WHERE created_at >= ?", (since,))
        return int(row.fetchone()["total"])

    def record_spend(self, *, created_at: int, amount_sats: int, payment_hash: str, host: str) -> None:
        self._conn.execute(
            "INSERT INTO spend (created_at, amount_sats, payment_hash, host) VALUES (?, ?, ?, ?)",
            (created_at, amount_sats, payment_hash, host),
        )
        self._conn.commit()

    def save_quote(self, row: dict) -> None:
        self._conn.execute("DELETE FROM quotes WHERE cache_key = ?", (row["cache_key"],))
        self._conn.execute(
            """
            INSERT INTO quotes (
                payment_hash, cache_key, method, url, macaroon, invoice, resource,
                amount_sats, max_uses, access_seconds, invoice_expires_at, reason,
                request_body, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["payment_hash"],
                row["cache_key"],
                row["method"],
                row["url"],
                row["macaroon"],
                row["invoice"],
                row.get("resource"),
                row["amount_sats"],
                row.get("max_uses"),
                row.get("access_seconds"),
                row.get("invoice_expires_at"),
                row.get("reason"),
                row.get("request_body"),
                row["created_at"],
            ),
        )
        self._conn.commit()

    def quote_for(self, cache_key: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM quotes WHERE cache_key = ? ORDER BY created_at DESC LIMIT 1",
            (cache_key,),
        ).fetchone()

    def quote_by_hash(self, payment_hash: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM quotes WHERE payment_hash = ?", (payment_hash,)).fetchone()

    def delete_quote(self, payment_hash: str) -> None:
        self._conn.execute("DELETE FROM quotes WHERE payment_hash = ?", (payment_hash,))
        self._conn.commit()

    def save_token(self, row: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO tokens (
                cache_key, method, url, macaroon, preimage, payment_hash, resource,
                amount_sats, max_uses, access_seconds, uses_remaining, access_until,
                invoice_expires_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                method = excluded.method,
                url = excluded.url,
                macaroon = excluded.macaroon,
                preimage = excluded.preimage,
                payment_hash = excluded.payment_hash,
                resource = excluded.resource,
                amount_sats = excluded.amount_sats,
                max_uses = excluded.max_uses,
                access_seconds = excluded.access_seconds,
                uses_remaining = excluded.uses_remaining,
                access_until = excluded.access_until,
                invoice_expires_at = excluded.invoice_expires_at,
                updated_at = excluded.updated_at
            """,
            (
                row["cache_key"],
                row["method"],
                row["url"],
                row["macaroon"],
                row.get("preimage"),
                row["payment_hash"],
                row.get("resource"),
                row["amount_sats"],
                row.get("max_uses"),
                row.get("access_seconds"),
                row.get("uses_remaining"),
                row.get("access_until"),
                row.get("invoice_expires_at"),
                row["updated_at"],
            ),
        )
        self._conn.commit()

    def token_for(self, cache_key: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM tokens WHERE cache_key = ?", (cache_key,)).fetchone()

    def token_by_hash(self, payment_hash: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM tokens WHERE payment_hash = ? ORDER BY updated_at DESC LIMIT 1",
            (payment_hash,),
        ).fetchone()

    def delete_token(self, cache_key: str) -> None:
        self._conn.execute("DELETE FROM tokens WHERE cache_key = ?", (cache_key,))
        self._conn.commit()
