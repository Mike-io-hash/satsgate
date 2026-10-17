from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Client:
    id: int
    credits: int
    payee_lightning_address: str | None = None


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys in SQLite
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str) -> None:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              api_key_hash TEXT NOT NULL UNIQUE,
              credits INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL
            );
            """
        )

        # Migration (idempotent): add payee_lightning_address
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(clients)").fetchall()]
        if "payee_lightning_address" not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN payee_lightning_address TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              client_id INTEGER NOT NULL,
              delta_credits INTEGER NOT NULL,
              reason TEXT NOT NULL,
              ref TEXT,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS topups (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              payment_hash TEXT NOT NULL UNIQUE,
              invoice TEXT NOT NULL,
              sats INTEGER NOT NULL,
              credits INTEGER NOT NULL,
              status TEXT NOT NULL,
              client_id INTEGER,
              created_at INTEGER NOT NULL,
              settled_at INTEGER,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verifications (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              client_id INTEGER NOT NULL,
              payment_hash TEXT NOT NULL,
              resource TEXT,
              created_at INTEGER NOT NULL,
              UNIQUE(client_id, payment_hash),
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )

        topup_cols = [r["name"] for r in conn.execute("PRAGMA table_info(topups)").fetchall()]
        if "verify_url" not in topup_cols:
            conn.execute("ALTER TABLE topups ADD COLUMN verify_url TEXT")
        if "requester_ip" not in topup_cols:
            conn.execute("ALTER TABLE topups ADD COLUMN requester_ip TEXT")
        if "expires_at" not in topup_cols:
            conn.execute("ALTER TABLE topups ADD COLUMN expires_at INTEGER")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS paywall_challenges (
              payment_hash TEXT PRIMARY KEY,
              client_id INTEGER NOT NULL,
              invoice TEXT NOT NULL,
              amount_sats INTEGER NOT NULL,
              payee TEXT,
              resource TEXT NOT NULL,
              verify_url TEXT,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )

        # Indexes (improve dashboard/reporting performance)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_client_id ON ledger(client_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_client_created ON ledger(client_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_topups_client_created ON topups(client_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_topups_pending_ip ON topups(requester_ip, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_verifications_client_created ON verifications(client_id, created_at)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_challenges_client_expires ON paywall_challenges(client_id, expires_at)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ticket_challenges (
              payment_hash TEXT PRIMARY KEY,
              invoice TEXT NOT NULL,
              amount_sats INTEGER NOT NULL,
              payee TEXT,
              resource TEXT NOT NULL,
              verify_url TEXT,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              settled_at INTEGER
            );
            """
        )


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def new_api_key() -> str:
    # Prefix for identification only (not secret)
    return "sg_" + secrets.token_urlsafe(32)


def create_client(db_path: str) -> tuple[str, Client]:
    api_key = new_api_key()
    api_key_hash = hash_api_key(api_key)
    now = int(time.time())

    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO clients(api_key_hash, credits, created_at) VALUES(?, 0, ?)",
            (api_key_hash, now),
        )
        client_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (client_id, 0, "client_created", None, now),
        )

    return api_key, Client(id=client_id, credits=0, payee_lightning_address=None)


def get_client_by_api_key(db_path: str, api_key: str) -> Client | None:
    if not api_key:
        return None
    h = hash_api_key(api_key)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, credits, payee_lightning_address FROM clients WHERE api_key_hash = ?",
            (h,),
        ).fetchone()
        if not row:
            return None
        return Client(
            id=int(row["id"]),
            credits=int(row["credits"]),
            payee_lightning_address=row["payee_lightning_address"],
        )


def add_topup(
    db_path: str,
    *,
    payment_hash: str,
    invoice: str,
    sats: int,
    credits: int,
    client_id: int | None,
    requester_ip: str | None = None,
    verify_url: str | None = None,
    expires_at: int | None = None,
    max_pending_per_ip: int = 20,
    now: int | None = None,
    claim_grace_seconds: int = 0,
    claim_cap_seconds: int = 86_400,
) -> None:
    """Insert a pending top-up. Rows past the claim window are removed first.

    A pending row with `expires_at` stays until that expiry plus
    `claim_grace_seconds`, and never longer than `claim_cap_seconds` after
    `created_at`. Rows with no expiry still age out after a day.

    Raises ValueError('too_many_pending_topups') when this IP already has too
    many unpaid top-ups. That caps anonymous invoice spam.
    """
    now = int(time.time()) if now is None else int(now)
    invoice_cutoff = now - int(claim_grace_seconds)
    cap_cutoff = now - int(claim_cap_seconds)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            DELETE FROM topups
            WHERE status = 'pending'
              AND (
                (
                  expires_at IS NOT NULL
                  AND (expires_at < ? OR created_at < ?)
                )
                OR (expires_at IS NULL AND created_at < ?)
              )
            """,
            (invoice_cutoff, cap_cutoff, now - 86_400),
        )
        if requester_ip:
            pending = conn.execute(
                "SELECT COUNT(*) FROM topups WHERE status = 'pending' AND requester_ip = ?",
                (requester_ip,),
            ).fetchone()
            if pending and int(pending[0]) >= int(max_pending_per_ip):
                conn.execute("ROLLBACK")
                raise ValueError("too_many_pending_topups")
        conn.execute(
            """
            INSERT INTO topups(
              payment_hash, invoice, sats, credits, status, client_id, created_at, verify_url, requester_ip, expires_at
            )
            VALUES(?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                payment_hash,
                invoice,
                int(sats),
                int(credits),
                client_id,
                now,
                verify_url,
                requester_ip,
                expires_at,
            ),
        )
        conn.execute("COMMIT")


def get_topup(db_path: str, payment_hash: str) -> sqlite3.Row | None:
    with _connect(db_path) as conn:
        return conn.execute("SELECT * FROM topups WHERE payment_hash = ?", (payment_hash,)).fetchone()


def _insert_client(conn: sqlite3.Connection, now: int) -> tuple[str, int]:
    api_key = new_api_key()
    cur = conn.execute(
        "INSERT INTO clients(api_key_hash, credits, created_at) VALUES(?, 0, ?)",
        (hash_api_key(api_key), now),
    )
    client_id = int(cur.lastrowid)
    conn.execute(
        "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
        (client_id, 0, "client_created", None, now),
    )
    return api_key, client_id


def settle_topup_and_credit(
    db_path: str,
    *,
    payment_hash: str,
    client_id: int | None,
) -> dict:
    """Mark a topup as settled and add credits atomically.

    `client_id=None` creates the account inside this transaction, and the
    plaintext API key is returned only from that call. A replay returns
    `api_key=None` and `credits_added=0`.

    Returns: {credits_added, new_balance, client_id, api_key}
    """
    now = int(time.time())

    with _connect(db_path) as conn:
        # IMMEDIATE: take a write lock early (reduces double-credit races)
        conn.execute("BEGIN IMMEDIATE")

        topup = conn.execute(
            "SELECT * FROM topups WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()

        if not topup:
            conn.execute("ROLLBACK")
            raise ValueError("topup not found")

        if topup["status"] == "settled":
            # Idempotent: do not credit twice and do not reveal the API key again.
            stored_id = topup["client_id"]
            if stored_id is None:
                conn.execute("ROLLBACK")
                raise ValueError("topup not found")
            bal = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(stored_id),)).fetchone()
            conn.execute("COMMIT")
            return {
                "credits_added": 0,
                "new_balance": int(bal[0]) if bal else 0,
                "client_id": int(stored_id),
                "api_key": None,
            }

        credits_added = int(topup["credits"])
        existing_client_id = topup["client_id"]
        api_key: str | None = None
        if existing_client_id is not None:
            if client_id is not None and int(existing_client_id) != int(client_id):
                conn.execute("ROLLBACK")
                raise ValueError("this topup belongs to a different client")
            target_id = int(existing_client_id)
        elif client_id is not None:
            target_id = int(client_id)
        else:
            api_key, target_id = _insert_client(conn, now)

        conn.execute(
            "UPDATE topups SET status='settled', client_id = ?, settled_at = ? WHERE payment_hash = ?",
            (target_id, now, payment_hash),
        )

        conn.execute(
            "UPDATE clients SET credits = credits + ? WHERE id = ?",
            (credits_added, target_id),
        )

        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (target_id, credits_added, "topup_settled", payment_hash, now),
        )

        bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (target_id,)).fetchone()
        new_balance = int(bal_row[0]) if bal_row else 0

        conn.execute("COMMIT")

    return {
        "credits_added": credits_added,
        "new_balance": new_balance,
        "client_id": target_id,
        "api_key": api_key,
    }


def spend_credits(db_path: str, *, client_id: int, cost: int, reason: str, ref: str | None = None) -> int:
    """Spend credits if there is sufficient balance. Returns new balance."""
    now = int(time.time())
    cost = int(cost)
    if cost <= 0:
        return get_balance(db_path, client_id=client_id)

    with _connect(db_path) as conn:
        # IMMEDIATE: lock early so two requests can't spend the same balance concurrently
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if not row:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")

        current = int(row[0])
        if current < cost:
            conn.execute("ROLLBACK")
            raise ValueError("insufficient balance")

        conn.execute(
            "UPDATE clients SET credits = credits - ? WHERE id = ?",
            (cost, int(client_id)),
        )
        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, ?, ?, ?)",
            (int(client_id), -cost, reason, ref, now),
        )
        new_balance_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        new_balance = int(new_balance_row[0]) if new_balance_row else 0
        conn.execute("COMMIT")
        return new_balance


def get_balance(db_path: str, *, client_id: int) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        return int(row[0]) if row else 0


def add_paywall_challenge(
    db_path: str,
    *,
    payment_hash: str,
    client_id: int,
    invoice: str,
    amount_sats: int,
    payee: str | None,
    resource: str,
    verify_url: str | None,
    expires_at: int,
    max_open_per_client: int = 100,
    now: int | None = None,
    claim_grace_seconds: int = 0,
    claim_cap_seconds: int = 86_400,
) -> None:
    """Remember a challenge so verify can bind the token to the invoice we issued.

    `expires_at` is the invoice expiry, not the macaroon caveat. A row stays
    until that expiry plus `claim_grace_seconds`, and never longer than
    `claim_cap_seconds` after `created_at`.
    """
    now = int(time.time()) if now is None else int(now)
    invoice_cutoff = now - int(claim_grace_seconds)
    cap_cutoff = now - int(claim_cap_seconds)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM paywall_challenges WHERE expires_at < ? OR created_at < ?",
            (invoice_cutoff, cap_cutoff),
        )
        open_rows = conn.execute(
            """
            SELECT COUNT(*) FROM paywall_challenges
            WHERE client_id = ? AND expires_at >= ? AND created_at >= ?
            """,
            (int(client_id), invoice_cutoff, cap_cutoff),
        ).fetchone()
        if open_rows and int(open_rows[0]) >= int(max_open_per_client):
            conn.execute("ROLLBACK")
            raise ValueError("too_many_open_challenges")
        conn.execute(
            """
            INSERT INTO paywall_challenges(
              payment_hash, client_id, invoice, amount_sats, payee, resource, verify_url, created_at, expires_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payment_hash,
                int(client_id),
                invoice,
                int(amount_sats),
                payee,
                resource,
                verify_url,
                now,
                int(expires_at),
            ),
        )
        conn.execute("COMMIT")


def get_paywall_challenge(db_path: str, payment_hash: str) -> sqlite3.Row | None:
    with _connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()


def add_ticket_challenge(
    db_path: str,
    *,
    payment_hash: str,
    invoice: str,
    amount_sats: int,
    payee: str | None,
    resource: str,
    verify_url: str | None,
    expires_at: int,
    max_open: int = 100,
) -> None:
    """Remember a dev-only ticket challenge so a later claim can use its verify URL."""
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM ticket_challenges WHERE expires_at < ?", (now,))
        open_rows = conn.execute(
            "SELECT COUNT(*) FROM ticket_challenges WHERE settled_at IS NULL AND expires_at >= ?",
            (now,),
        ).fetchone()
        if open_rows and int(open_rows[0]) >= int(max_open):
            conn.execute("ROLLBACK")
            raise ValueError("too_many_open_challenges")
        conn.execute(
            """
            INSERT INTO ticket_challenges(
              payment_hash, invoice, amount_sats, payee, resource, verify_url, created_at, expires_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payment_hash,
                invoice,
                int(amount_sats),
                payee,
                resource,
                verify_url,
                now,
                int(expires_at),
            ),
        )
        conn.execute("COMMIT")


def get_ticket_challenge(db_path: str, payment_hash: str) -> sqlite3.Row | None:
    with _connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM ticket_challenges WHERE payment_hash = ?",
            (payment_hash,),
        ).fetchone()


def mark_ticket_settled(db_path: str, *, payment_hash: str) -> None:
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE ticket_challenges SET settled_at = ? WHERE payment_hash = ? AND settled_at IS NULL",
            (now, payment_hash),
        )
