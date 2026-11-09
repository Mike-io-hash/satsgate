"""Stored receipt claims. The JWT itself is not stored.

``payment_hash`` is the Lightning payment hash, or ``x402:`` plus the EIP-3009
nonce. ``charged`` is 0 for an x402 test-mode receipt that did not debit.
"""

from __future__ import annotations

import hashlib
import sqlite3

from .db import _connect


def signature_sha256(encoded: str) -> str:
    """SHA-256 hex of the exact PAYMENT-SIGNATURE string, UTF-8, nothing stripped.

    Recovery compares this to the header that settled. Re-encoding the JSON
    does not match. The raw signature is not stored.
    """
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def x402_key(nonce: str) -> str:
    text = nonce.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return f"x402:{text}"


def public_ph(payment_hash: str) -> str:
    if payment_hash.startswith("x402:"):
        return payment_hash.removeprefix("x402:")
    return payment_hash


def _view(row) -> dict:
    return {
        "rid": row["rid"],
        "payment_hash": row["payment_hash"],
        "site_id": int(row["site_id"]),
        "client_id": int(row["client_id"]),
        "path": row["path"],
        "rail": row["rail"],
        "amount_sats": None if row["amount_sats"] is None else int(row["amount_sats"]),
        "amount_usd_atomic": None if row["amount_usd_atomic"] is None else int(row["amount_usd_atomic"]),
        "network": row["network"],
        "uses": int(row["uses"]),
        "iat": int(row["iat"]),
        "exp": int(row["exp"]),
        "kid": row["kid"],
        "charged": int(row["charged"]),
        "signature_sha256": row["signature_sha256"],
        "settled_at": None if row["settled_at"] is None else int(row["settled_at"]),
    }


def get_receipt(db_path: str, payment_hash: str) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM gate_receipts WHERE payment_hash = ?", (payment_hash,)).fetchone()
    return None if row is None else _view(row)


def insert_receipt(conn: sqlite3.Connection, row: dict) -> bool:
    """Insert on the caller's transaction. False when that payment already has a row."""
    try:
        conn.execute(
            """
            INSERT INTO gate_receipts(
              rid, payment_hash, site_id, client_id, path, rail,
              amount_sats, amount_usd_atomic, network, uses, iat, exp, kid, charged,
              signature_sha256, settled_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["rid"],
                row["payment_hash"],
                int(row["site_id"]),
                int(row["client_id"]),
                row["path"],
                row["rail"],
                row.get("amount_sats"),
                row.get("amount_usd_atomic"),
                row.get("network"),
                int(row["uses"]),
                int(row["iat"]),
                int(row["exp"]),
                row["kid"],
                int(row["charged"]),
                row.get("signature_sha256"),
                row.get("settled_at"),
            ),
        )
    except sqlite3.IntegrityError:
        return False
    return True
