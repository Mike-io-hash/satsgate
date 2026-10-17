"""Restricted API keys (prefix ``sgr_``).

The account key stays on ``clients.api_key_hash`` (prefix ``sg_``) and is the
only credential that can manage the account. A restricted key can create a
paywall challenge, check its status, and verify it. It cannot top up, change
the payee, manage keys, or read the ledger and other account data.

``resource_prefix``, when set, limits those three calls to resources that
start with the prefix. The comparison is the same case-sensitive
``startswith`` check the paywall uses for resource names.

Per-challenge usage policies (max uses, access window, consume) and per-buyer
IP limits are not stored on the key. They belong on the challenge. ``api_key_id``
on ``paywall_challenges`` and on ledger debits is the attribution those
features can use later.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from .db import Client, _connect, hash_api_key

# Account keys are "sg_" + token. Restricted keys are "sgr_" + token.
# "sgr_" does not start with "sg_", so the two prefixes do not overlap.
ACCOUNT_KEY_PREFIX = "sg_"
RESTRICTED_KEY_PREFIX = "sgr_"
SCOPE_ACCOUNT = "account"
SCOPE_PAYWALL = "paywall"
MAX_ACTIVE_RESTRICTED_KEYS = 50
_LABEL_MAX = 64
_PREFIX_MAX = 200
# last_used_at is stamped at most this often. Revocation is still checked on every request.
_LAST_USED_INTERVAL_SECONDS = 60
_DISPLAY_PREFIX_LEN = 8


class AuthError(Exception):
    """The presented API key is missing, unknown, or revoked."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Principal:
    """Caller identity. ``api_key_id`` is None for the account key."""

    client: Client
    api_key_id: int | None
    scope: str
    resource_prefix: str | None
    label: str | None


def key_kind(api_key: str) -> str | None:
    """Return ``account``, ``restricted``, or None when the prefix is neither."""
    if api_key.startswith(RESTRICTED_KEY_PREFIX):
        return "restricted"
    if api_key.startswith(ACCOUNT_KEY_PREFIX):
        return "account"
    return None


def _reject_controls(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def clean_label(label: str) -> str:
    text = label.strip()
    if not text or len(text) > _LABEL_MAX or _reject_controls(text):
        raise ValueError("invalid_label")
    return text


def clean_resource_prefix(prefix: str | None) -> str | None:
    if prefix is None:
        return None
    text = prefix.strip()
    if not text:
        return None
    if len(text) > _PREFIX_MAX or _reject_controls(text):
        raise ValueError("invalid_resource_prefix")
    return text


def new_restricted_api_key() -> str:
    return RESTRICTED_KEY_PREFIX + secrets.token_urlsafe(32)


def _public_key(row) -> dict:
    last_used = row["last_used_at"]
    revoked = row["revoked_at"]
    return {
        "id": int(row["id"]),
        "label": row["label"],
        "prefix": row["key_prefix"],
        "scope": row["scope"],
        "resource_prefix": row["resource_prefix"],
        "created_at": int(row["created_at"]),
        "last_used_at": int(last_used) if last_used is not None else None,
        "revoked_at": int(revoked) if revoked is not None else None,
    }


def _principal_from_restricted(row) -> Principal:
    return Principal(
        client=Client(
            id=int(row["client_id"]),
            credits=int(row["credits"]),
            payee_lightning_address=row["payee_lightning_address"],
        ),
        api_key_id=int(row["id"]),
        scope=SCOPE_PAYWALL,
        resource_prefix=row["resource_prefix"],
        label=row["label"],
    )


def _lookup_restricted(conn, key_hash: str):
    return conn.execute(
        """
        SELECT
          k.id, k.client_id, k.label, k.resource_prefix, k.revoked_at, k.last_used_at,
          c.credits, c.payee_lightning_address
        FROM api_keys k
        JOIN clients c ON c.id = k.client_id
        WHERE k.key_hash = ?
        """,
        (key_hash,),
    ).fetchone()


def _touch_last_used(conn, row, now: int) -> None:
    previous = row["last_used_at"]
    if previous is not None and int(previous) >= now - _LAST_USED_INTERVAL_SECONDS:
        return
    conn.execute(
        "UPDATE api_keys SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL",
        (now, int(row["id"])),
    )


def client_for_rate_limit(db_path: str, api_key: str) -> Client | None:
    """Active account or restricted key, for rate-limit buckets. Does not record use."""
    if not api_key:
        return None
    kind = key_kind(api_key)
    key_hash = hash_api_key(api_key)
    with _connect(db_path) as conn:
        if kind == "account":
            row = conn.execute(
                "SELECT id, credits, payee_lightning_address FROM clients WHERE api_key_hash = ?",
                (key_hash,),
            ).fetchone()
            if not row:
                return None
            return Client(
                id=int(row["id"]),
                credits=int(row["credits"]),
                payee_lightning_address=row["payee_lightning_address"],
            )
        if kind == "restricted":
            row = _lookup_restricted(conn, key_hash)
            if not row or row["revoked_at"] is not None:
                return None
            return _principal_from_restricted(row).client
    return None


def authenticate(db_path: str, api_key: str) -> Principal:
    """Resolve a presented key. Raises AuthError(invalid_api_key | api_key_revoked)."""
    if not api_key:
        raise AuthError("invalid_api_key")
    kind = key_kind(api_key)
    key_hash = hash_api_key(api_key)
    now = int(time.time())
    with _connect(db_path) as conn:
        if kind == "account":
            row = conn.execute(
                "SELECT id, credits, payee_lightning_address FROM clients WHERE api_key_hash = ?",
                (key_hash,),
            ).fetchone()
            if not row:
                raise AuthError("invalid_api_key")
            return Principal(
                client=Client(
                    id=int(row["id"]),
                    credits=int(row["credits"]),
                    payee_lightning_address=row["payee_lightning_address"],
                ),
                api_key_id=None,
                scope=SCOPE_ACCOUNT,
                resource_prefix=None,
                label=None,
            )
        if kind != "restricted":
            raise AuthError("invalid_api_key")
        row = _lookup_restricted(conn, key_hash)
        if not row:
            raise AuthError("invalid_api_key")
        if row["revoked_at"] is not None:
            raise AuthError("api_key_revoked")
        _touch_last_used(conn, row, now)
        return _principal_from_restricted(row)


def create_restricted_key(
    db_path: str,
    *,
    client_id: int,
    label: str,
    resource_prefix: str | None,
) -> dict:
    """Insert a restricted key. The plaintext ``api_key`` is returned only from here."""
    label = clean_label(label)
    resource_prefix = clean_resource_prefix(resource_prefix)
    api_key = new_restricted_api_key()
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        owner = conn.execute("SELECT id FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if not owner:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        active = conn.execute(
            "SELECT COUNT(*) FROM api_keys WHERE client_id = ? AND revoked_at IS NULL",
            (int(client_id),),
        ).fetchone()
        if active and int(active[0]) >= MAX_ACTIVE_RESTRICTED_KEYS:
            conn.execute("ROLLBACK")
            raise ValueError("too_many_api_keys")
        cur = conn.execute(
            """
            INSERT INTO api_keys(
              client_id, key_hash, key_prefix, label, scope, resource_prefix, created_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(client_id),
                hash_api_key(api_key),
                api_key[:_DISPLAY_PREFIX_LEN],
                label,
                SCOPE_PAYWALL,
                resource_prefix,
                now,
            ),
        )
        key_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        public = _public_key(row)
        conn.execute("COMMIT")
    public["api_key"] = api_key
    return public


def list_restricted_keys(db_path: str, *, client_id: int, include_revoked: bool) -> list[dict]:
    sql = "SELECT * FROM api_keys WHERE client_id = ?"
    params: list = [int(client_id)]
    if not include_revoked:
        sql += " AND revoked_at IS NULL"
    sql += " ORDER BY id DESC"
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_public_key(row) for row in rows]


def revoke_restricted_key(db_path: str, *, client_id: int, key_id: int) -> dict | None:
    """Revoke one of this client's keys. None when the id is not theirs. Idempotent."""
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM api_keys WHERE id = ? AND client_id = ?",
            (int(key_id), int(client_id)),
        ).fetchone()
        if not row:
            conn.execute("ROLLBACK")
            return None
        if row["revoked_at"] is None:
            conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (now, int(key_id)),
            )
            row = conn.execute(
                "SELECT * FROM api_keys WHERE id = ? AND client_id = ?",
                (int(key_id), int(client_id)),
            ).fetchone()
        public = _public_key(row)
        conn.execute("COMMIT")
    return public
