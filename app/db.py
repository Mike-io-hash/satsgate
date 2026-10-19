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
    # timeout: concurrent paywall consumes from more than one process wait for the writer.
    conn = sqlite3.connect(db_path, timeout=30.0)
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

        # Additive only. Existing rows keep NULL api_key_id / resource.
        ledger_cols = [r["name"] for r in conn.execute("PRAGMA table_info(ledger)").fetchall()]
        if "api_key_id" not in ledger_cols:
            conn.execute("ALTER TABLE ledger ADD COLUMN api_key_id INTEGER")
        if "resource" not in ledger_cols:
            conn.execute("ALTER TABLE ledger ADD COLUMN resource TEXT")

        challenge_cols = [r["name"] for r in conn.execute("PRAGMA table_info(paywall_challenges)").fetchall()]
        if "api_key_id" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN api_key_id INTEGER")
        # Usage policy. NULL max_uses and access_seconds means the pre-0.6.0 grant:
        # re-verify does not consume a unit. uses_consumed stays 0 until a policy exists.
        if "max_uses" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN max_uses INTEGER")
        if "access_seconds" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN access_seconds INTEGER")
        if "uses_consumed" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN uses_consumed INTEGER NOT NULL DEFAULT 0")
        if "settled_at" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN settled_at INTEGER")
        if "access_until" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN access_until INTEGER")
        # Truncated-IP HMAC. NULL means the caller did not pass a trusted buyer address.
        # The raw IP is never stored. The row's existing cleanup deletes the digest with it.
        if "buyer_ip_hash" not in challenge_cols:
            conn.execute("ALTER TABLE paywall_challenges ADD COLUMN buyer_ip_hash TEXT")

        # Restricted keys. The account key stays on clients.api_key_hash.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              client_id INTEGER NOT NULL,
              key_hash TEXT NOT NULL UNIQUE,
              key_prefix TEXT NOT NULL,
              label TEXT NOT NULL,
              scope TEXT NOT NULL,
              resource_prefix TEXT,
              created_at INTEGER NOT NULL,
              last_used_at INTEGER,
              revoked_at INTEGER,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )

        # Indexes (improve dashboard/reporting performance)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_client_id ON ledger(client_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_client_created ON ledger(client_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_api_key ON ledger(client_id, api_key_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_topups_client_created ON topups(client_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_topups_pending_ip ON topups(requester_ip, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_verifications_client_created ON verifications(client_id, created_at)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_challenges_client_expires ON paywall_challenges(client_id, expires_at)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_challenges_api_key ON paywall_challenges(api_key_id)")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_challenges_buyer
            ON paywall_challenges(client_id, buyer_ip_hash, created_at)
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_client ON api_keys(client_id, revoked_at)")

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

        # Hosted-proxy registry. New tables only. Existing tables are not altered here.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sites (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              client_id INTEGER NOT NULL,
              slug TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              description TEXT,
              origin_url TEXT NOT NULL,
              status TEXT NOT NULL,
              listed INTEGER NOT NULL DEFAULT 0,
              origin_secret_ciphertext TEXT NOT NULL,
              secret_fingerprint TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              approved_at INTEGER,
              FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS site_routes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              site_id INTEGER NOT NULL,
              path_pattern TEXT NOT NULL,
              price_sats INTEGER,
              price_currency TEXT NOT NULL DEFAULT 'sats',
              price_usd_atomic INTEGER,
              max_uses INTEGER,
              access_seconds INTEGER,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(site_id, path_pattern),
              FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sites_client ON sites(client_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sites_public ON sites(status, listed, slug)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_site_routes_site ON site_routes(site_id, id)")
        _migrate_x402(conn)


def _migrate_x402(conn: sqlite3.Connection) -> None:
    """Payee, rails, USD route prices, and x402 replay rows.

    Existing Lightning rows stay valid. price_sats cannot lose NOT NULL with
    ALTER TABLE, so an old site_routes table is copied and renamed.
    """
    client_cols = [r["name"] for r in conn.execute("PRAGMA table_info(clients)").fetchall()]
    for name, ddl in (
        ("payee_evm_address", "ALTER TABLE clients ADD COLUMN payee_evm_address TEXT"),
        ("payee_evm_verified_at", "ALTER TABLE clients ADD COLUMN payee_evm_verified_at INTEGER"),
        ("payee_evm_message", "ALTER TABLE clients ADD COLUMN payee_evm_message TEXT"),
        ("payee_evm_signature", "ALTER TABLE clients ADD COLUMN payee_evm_signature TEXT"),
        ("payee_evm_pending_message", "ALTER TABLE clients ADD COLUMN payee_evm_pending_message TEXT"),
        ("payee_evm_pending_expires", "ALTER TABLE clients ADD COLUMN payee_evm_pending_expires INTEGER"),
    ):
        if name not in client_cols:
            conn.execute(ddl)
    site_cols = [r["name"] for r in conn.execute("PRAGMA table_info(sites)").fetchall()]
    if "rail_lightning" not in site_cols:
        conn.execute("ALTER TABLE sites ADD COLUMN rail_lightning INTEGER NOT NULL DEFAULT 1")
    if "rail_x402" not in site_cols:
        conn.execute("ALTER TABLE sites ADD COLUMN rail_x402 INTEGER NOT NULL DEFAULT 0")

    info = conn.execute("PRAGMA table_info(site_routes)").fetchall()
    by_name = {row["name"]: row for row in info}
    needs_rebuild = "price_currency" not in by_name or int(by_name["price_sats"]["notnull"]) == 1
    if needs_rebuild:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN")
        conn.execute("DROP TABLE IF EXISTS site_routes_v2")
        conn.execute(
            """
            CREATE TABLE site_routes_v2 (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              site_id INTEGER NOT NULL,
              path_pattern TEXT NOT NULL,
              price_sats INTEGER,
              price_currency TEXT NOT NULL DEFAULT 'sats',
              price_usd_atomic INTEGER,
              max_uses INTEGER,
              access_seconds INTEGER,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(site_id, path_pattern),
              FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            INSERT INTO site_routes_v2(
              id, site_id, path_pattern, price_sats, price_currency, price_usd_atomic,
              max_uses, access_seconds, created_at, updated_at
            )
            SELECT id, site_id, path_pattern, price_sats, 'sats', NULL,
                   max_uses, access_seconds, created_at, updated_at
            FROM site_routes
            """
        )
        conn.execute("DROP TABLE site_routes")
        conn.execute("ALTER TABLE site_routes_v2 RENAME TO site_routes")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_site_routes_site ON site_routes(site_id, id)")
        conn.execute("COMMIT")
        conn.execute("PRAGMA foreign_keys=ON")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_offers (
          id TEXT PRIMARY KEY,
          client_id INTEGER NOT NULL,
          resource TEXT NOT NULL,
          api_key_id INTEGER,
          price_currency TEXT NOT NULL,
          amount_sats INTEGER,
          amount_usd_atomic INTEGER,
          rate_num INTEGER,
          rate_den INTEGER,
          rate_fetched_at INTEGER,
          expires_at INTEGER NOT NULL,
          max_uses INTEGER,
          access_seconds INTEGER,
          payment_hash TEXT UNIQUE,
          scheme TEXT,
          network TEXT,
          asset TEXT,
          pay_to TEXT,
          requirements_json TEXT,
          buyer_ip_hash TEXT,
          created_at INTEGER NOT NULL,
          FOREIGN KEY(client_id) REFERENCES clients(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS x402_authorizations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          network TEXT NOT NULL,
          asset TEXT NOT NULL,
          payer TEXT NOT NULL,
          nonce TEXT NOT NULL,
          offer_id TEXT NOT NULL,
          value_atomic TEXT NOT NULL,
          pay_to TEXT NOT NULL,
          state TEXT NOT NULL,
          tx_hash TEXT,
          settled_at INTEGER,
          credit_charged INTEGER NOT NULL DEFAULT 0,
          uses_consumed INTEGER NOT NULL DEFAULT 0,
          access_until INTEGER,
          updated_at INTEGER NOT NULL,
          UNIQUE(network, asset, payer, nonce)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_offers_client ON payment_offers(client_id, created_at)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_offers_buyer ON payment_offers(client_id, buyer_ip_hash, created_at)"
    )


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def new_api_key() -> str:
    # Prefix for identification only (not secret). Restricted keys use sgr_ (see db_keys).
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


def get_client_by_id(db_path: str, client_id: int) -> Client | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, credits, payee_lightning_address FROM clients WHERE id = ?",
            (int(client_id),),
        ).fetchone()
        if not row:
            return None
        return Client(
            id=int(row["id"]),
            credits=int(row["credits"]),
            payee_lightning_address=row["payee_lightning_address"],
        )


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


class ChallengeLimit(Exception):
    """A new challenge would exceed an open-row or per-buyer cap."""

    def __init__(self, code: str, retry_after: int) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after = max(1, int(retry_after))


def _retry_after(deadline: int | None, now: int) -> int:
    if deadline is None:
        return 1
    return max(1, int(deadline) - int(now))


def _buyer_rate_row(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    buyer_ip_hash: str,
    since: int,
    scope: str,
    api_key_id: int | None,
):
    if scope == "key" and api_key_id is None:
        return conn.execute(
            """
            SELECT COUNT(*), MIN(created_at)
            FROM paywall_challenges
            WHERE client_id = ? AND buyer_ip_hash = ? AND created_at >= ? AND api_key_id IS NULL
            """,
            (client_id, buyer_ip_hash, since),
        ).fetchone()
    if scope == "key":
        return conn.execute(
            """
            SELECT COUNT(*), MIN(created_at)
            FROM paywall_challenges
            WHERE client_id = ? AND buyer_ip_hash = ? AND created_at >= ? AND api_key_id = ?
            """,
            (client_id, buyer_ip_hash, since, int(api_key_id)),
        ).fetchone()
    return conn.execute(
        """
        SELECT COUNT(*), MIN(created_at)
        FROM paywall_challenges
        WHERE client_id = ? AND buyer_ip_hash = ? AND created_at >= ?
        """,
        (client_id, buyer_ip_hash, since),
    ).fetchone()


def _offer_rate_row(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    buyer_ip_hash: str,
    since: int,
    scope: str,
    api_key_id: int | None,
):
    if scope == "key" and api_key_id is None:
        return conn.execute(
            """
            SELECT COUNT(*), MIN(created_at)
            FROM payment_offers
            WHERE client_id = ? AND buyer_ip_hash = ? AND created_at >= ? AND api_key_id IS NULL
            """,
            (client_id, buyer_ip_hash, since),
        ).fetchone()
    if scope == "key":
        return conn.execute(
            """
            SELECT COUNT(*), MIN(created_at)
            FROM payment_offers
            WHERE client_id = ? AND buyer_ip_hash = ? AND created_at >= ? AND api_key_id = ?
            """,
            (client_id, buyer_ip_hash, since, int(api_key_id)),
        ).fetchone()
    return conn.execute(
        """
        SELECT COUNT(*), MIN(created_at)
        FROM payment_offers
        WHERE client_id = ? AND buyer_ip_hash = ? AND created_at >= ?
        """,
        (client_id, buyer_ip_hash, since),
    ).fetchone()


def _offer_open_row(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    buyer_ip_hash: str,
    grace: int,
    cap: int,
    invoice_cutoff: int,
    cap_cutoff: int,
    scope: str,
    api_key_id: int | None,
):
    if scope == "key" and api_key_id is None:
        return conn.execute(
            """
            SELECT COUNT(*), MIN(min(expires_at + ?, created_at + ?))
            FROM payment_offers
            WHERE client_id = ? AND buyer_ip_hash = ? AND expires_at >= ? AND created_at >= ?
              AND api_key_id IS NULL
            """,
            (grace, cap, client_id, buyer_ip_hash, invoice_cutoff, cap_cutoff),
        ).fetchone()
    if scope == "key":
        return conn.execute(
            """
            SELECT COUNT(*), MIN(min(expires_at + ?, created_at + ?))
            FROM payment_offers
            WHERE client_id = ? AND buyer_ip_hash = ? AND expires_at >= ? AND created_at >= ?
              AND api_key_id = ?
            """,
            (grace, cap, client_id, buyer_ip_hash, invoice_cutoff, cap_cutoff, int(api_key_id)),
        ).fetchone()
    return conn.execute(
        """
        SELECT COUNT(*), MIN(min(expires_at + ?, created_at + ?))
        FROM payment_offers
        WHERE client_id = ? AND buyer_ip_hash = ? AND expires_at >= ? AND created_at >= ?
        """,
        (grace, cap, client_id, buyer_ip_hash, invoice_cutoff, cap_cutoff),
    ).fetchone()


def _sum_counts(left, right) -> tuple[int, int | None]:
    count = int(left[0] or 0) + int(right[0] or 0)
    stamps = [stamp for stamp in (left[1], right[1]) if stamp is not None]
    return count, (min(int(stamp) for stamp in stamps) if stamps else None)


def _buyer_open_row(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    buyer_ip_hash: str,
    grace: int,
    cap: int,
    invoice_cutoff: int,
    cap_cutoff: int,
    scope: str,
    api_key_id: int | None,
):
    if scope == "key" and api_key_id is None:
        return conn.execute(
            """
            SELECT COUNT(*), MIN(min(expires_at + ?, created_at + ?))
            FROM paywall_challenges
            WHERE client_id = ? AND buyer_ip_hash = ? AND settled_at IS NULL
              AND expires_at >= ? AND created_at >= ? AND api_key_id IS NULL
            """,
            (grace, cap, client_id, buyer_ip_hash, invoice_cutoff, cap_cutoff),
        ).fetchone()
    if scope == "key":
        return conn.execute(
            """
            SELECT COUNT(*), MIN(min(expires_at + ?, created_at + ?))
            FROM paywall_challenges
            WHERE client_id = ? AND buyer_ip_hash = ? AND settled_at IS NULL
              AND expires_at >= ? AND created_at >= ? AND api_key_id = ?
            """,
            (grace, cap, client_id, buyer_ip_hash, invoice_cutoff, cap_cutoff, int(api_key_id)),
        ).fetchone()
    return conn.execute(
        """
        SELECT COUNT(*), MIN(min(expires_at + ?, created_at + ?))
        FROM paywall_challenges
        WHERE client_id = ? AND buyer_ip_hash = ? AND settled_at IS NULL
          AND expires_at >= ? AND created_at >= ?
        """,
        (grace, cap, client_id, buyer_ip_hash, invoice_cutoff, cap_cutoff),
    ).fetchone()


def enforce_challenge_capacity(
    conn: sqlite3.Connection,
    *,
    client_id: int,
    now: int,
    invoice_cutoff: int,
    cap_cutoff: int,
    claim_grace_seconds: int,
    claim_cap_seconds: int,
    max_open_per_client: int,
    buyer_ip_hash: str | None,
    buyer_rate_max: int,
    buyer_rate_window_seconds: int,
    buyer_max_open: int,
    buyer_limit_scope: str,
    api_key_id: int | None,
) -> None:
    """Raise ChallengeLimit when this insert would pass a cap. Caller holds the write lock."""
    if buyer_ip_hash and int(buyer_rate_max) > 0:
        window = max(1, int(buyer_rate_window_seconds))
        rate = _buyer_rate_row(
            conn,
            client_id=int(client_id),
            buyer_ip_hash=buyer_ip_hash,
            since=int(now) - window,
            scope=buyer_limit_scope,
            api_key_id=api_key_id,
        )
        offers = _offer_rate_row(
            conn,
            client_id=int(client_id),
            buyer_ip_hash=buyer_ip_hash,
            since=int(now) - window,
            scope=buyer_limit_scope,
            api_key_id=api_key_id,
        )
        total, earliest = _sum_counts(rate or (0, None), offers or (0, None))
        if total >= int(buyer_rate_max):
            raise ChallengeLimit("buyer_rate_limited", _retry_after((earliest or now) + window, now))

    if buyer_ip_hash and int(buyer_max_open) > 0:
        # Unpaid only. A settled challenge no longer occupies the buyer's slot.
        # "Unexpired" matches the cleanup window: invoice expiry plus grace, and
        # not older than the claim cap.
        open_buyer = _buyer_open_row(
            conn,
            client_id=int(client_id),
            buyer_ip_hash=buyer_ip_hash,
            grace=int(claim_grace_seconds),
            cap=int(claim_cap_seconds),
            invoice_cutoff=int(invoice_cutoff),
            cap_cutoff=int(cap_cutoff),
            scope=buyer_limit_scope,
            api_key_id=api_key_id,
        )
        open_offers = _offer_open_row(
            conn,
            client_id=int(client_id),
            buyer_ip_hash=buyer_ip_hash,
            grace=int(claim_grace_seconds),
            cap=int(claim_cap_seconds),
            invoice_cutoff=int(invoice_cutoff),
            cap_cutoff=int(cap_cutoff),
            scope=buyer_limit_scope,
            api_key_id=api_key_id,
        )
        open_total, open_deadline = _sum_counts(open_buyer or (0, None), open_offers or (0, None))
        if open_total >= int(buyer_max_open):
            raise ChallengeLimit("too_many_open_challenges_for_buyer", _retry_after(open_deadline, now))

    open_rows = conn.execute(
        """
        SELECT COUNT(*),
               MIN(min(expires_at + ?, created_at + ?))
        FROM paywall_challenges
        WHERE client_id = ? AND expires_at >= ? AND created_at >= ?
        """,
        (
            int(claim_grace_seconds),
            int(claim_cap_seconds),
            int(client_id),
            int(invoice_cutoff),
            int(cap_cutoff),
        ),
    ).fetchone()
    offer_rows = conn.execute(
        """
        SELECT COUNT(*),
               MIN(min(expires_at + ?, created_at + ?))
        FROM payment_offers
        WHERE client_id = ? AND expires_at >= ? AND created_at >= ?
        """,
        (
            int(claim_grace_seconds),
            int(claim_cap_seconds),
            int(client_id),
            int(invoice_cutoff),
            int(cap_cutoff),
        ),
    ).fetchone()
    open_total, open_deadline = _sum_counts(open_rows or (0, None), offer_rows or (0, None))
    if open_total >= int(max_open_per_client):
        raise ChallengeLimit("too_many_open_challenges", _retry_after(open_deadline, now))


def preview_challenge_capacity(
    db_path: str,
    *,
    client_id: int,
    now: int,
    claim_grace_seconds: int,
    claim_cap_seconds: int,
    max_open_per_client: int,
    buyer_ip_hash: str | None,
    buyer_rate_max: int,
    buyer_rate_window_seconds: int,
    buyer_max_open: int,
    buyer_limit_scope: str,
    api_key_id: int | None,
) -> None:
    """Check caps before calling the LNURL provider. The insert checks again."""
    now = int(now)
    grace = int(claim_grace_seconds)
    cap = int(claim_cap_seconds)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        enforce_challenge_capacity(
            conn,
            client_id=int(client_id),
            now=now,
            invoice_cutoff=now - grace,
            cap_cutoff=now - cap,
            claim_grace_seconds=grace,
            claim_cap_seconds=cap,
            max_open_per_client=int(max_open_per_client),
            buyer_ip_hash=buyer_ip_hash,
            buyer_rate_max=int(buyer_rate_max),
            buyer_rate_window_seconds=int(buyer_rate_window_seconds),
            buyer_max_open=int(buyer_max_open),
            buyer_limit_scope=buyer_limit_scope,
            api_key_id=api_key_id,
        )
        conn.execute("COMMIT")


def find_reusable_paywall_challenge(
    db_path: str,
    *,
    client_id: int,
    buyer_ip_hash: str | None,
    resource: str,
    amount_sats: int,
    payee: str | None,
    max_uses: int | None,
    access_seconds: int | None,
    api_key_id: int | None,
    reuse_seconds: int,
    now: int,
) -> sqlite3.Row | None:
    """Pending challenge this buyer already holds for the same purchase.

    Identity is buyer, resource, amount, usage policy, payee, and key.
    Memo and ttl are not part of it. Reuse is off without a buyer hash or
    when reuse_seconds is 0, so two callers who share an API key do not
    receive each other's invoice.
    """
    if not buyer_ip_hash or int(reuse_seconds) <= 0:
        return None
    with _connect(db_path) as conn:
        return conn.execute(
            """
            SELECT * FROM paywall_challenges
            WHERE client_id = ?
              AND buyer_ip_hash = ?
              AND resource = ?
              AND amount_sats = ?
              AND payee IS ?
              AND max_uses IS ?
              AND access_seconds IS ?
              AND api_key_id IS ?
              AND settled_at IS NULL
              AND created_at >= ?
              AND expires_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (
                int(client_id),
                buyer_ip_hash,
                resource,
                int(amount_sats),
                payee,
                int(max_uses) if max_uses is not None else None,
                int(access_seconds) if access_seconds is not None else None,
                int(api_key_id) if api_key_id is not None else None,
                int(now) - int(reuse_seconds),
                int(now),
            ),
        ).fetchone()


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
    api_key_id: int | None = None,
    max_uses: int | None = None,
    access_seconds: int | None = None,
    buyer_ip_hash: str | None = None,
    max_open_per_client: int = 100,
    buyer_rate_max: int = 0,
    buyer_rate_window_seconds: int = 60,
    buyer_max_open: int = 0,
    buyer_limit_scope: str = "client",
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
        # Keep a settled usage grant until a day after access_until so a late
        # consume still returns token_used_up / token_expired. Grants with no
        # policy follow the invoice claim cleanup, as before.
        retain_after = now - 86_400
        conn.execute(
            """
            DELETE FROM paywall_challenges
            WHERE (expires_at < ? OR created_at < ?)
              AND NOT (
                settled_at IS NOT NULL
                AND (max_uses IS NOT NULL OR access_seconds IS NOT NULL)
                AND access_until IS NOT NULL
                AND access_until >= ?
              )
            """,
            (invoice_cutoff, cap_cutoff, retain_after),
        )
        try:
            enforce_challenge_capacity(
                conn,
                client_id=int(client_id),
                now=now,
                invoice_cutoff=invoice_cutoff,
                cap_cutoff=cap_cutoff,
                claim_grace_seconds=int(claim_grace_seconds),
                claim_cap_seconds=int(claim_cap_seconds),
                max_open_per_client=int(max_open_per_client),
                buyer_ip_hash=buyer_ip_hash,
                buyer_rate_max=int(buyer_rate_max),
                buyer_rate_window_seconds=int(buyer_rate_window_seconds),
                buyer_max_open=int(buyer_max_open),
                buyer_limit_scope=buyer_limit_scope,
                api_key_id=api_key_id,
            )
        except ChallengeLimit:
            conn.execute("ROLLBACK")
            raise
        conn.execute(
            """
            INSERT INTO paywall_challenges(
              payment_hash, client_id, invoice, amount_sats, payee, resource, verify_url, created_at, expires_at,
              api_key_id, max_uses, access_seconds, uses_consumed, buyer_ip_hash
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
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
                int(api_key_id) if api_key_id is not None else None,
                int(max_uses) if max_uses is not None else None,
                int(access_seconds) if access_seconds is not None else None,
                buyer_ip_hash,
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
