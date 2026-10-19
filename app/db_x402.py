"""Stored x402 offers, nonce replay rows, and the merchant EVM payee."""

from __future__ import annotations

import json
import secrets
import time

from . import config, db, x402
from .db import ChallengeLimit, _connect, enforce_challenge_capacity


def get_evm_payee(db_path: str, *, client_id: int) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT payee_evm_address, payee_evm_verified_at
            FROM clients WHERE id = ?
            """,
            (int(client_id),),
        ).fetchone()
    if row is None:
        return None
    return {
        "address": row["payee_evm_address"],
        "verified_at": None if row["payee_evm_verified_at"] is None else int(row["payee_evm_verified_at"]),
    }


def begin_payee_challenge(db_path: str, *, client_id: int, address: str, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else int(now)
    checksum = x402.checksum_address(address)
    nonce = "0x" + secrets.token_hex(16)
    expires = now + int(config.X402_PAYEE_CHALLENGE_SECONDS)
    message = x402.payee_message(client_id=client_id, address=checksum, nonce=nonce, expires=expires)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            """
            UPDATE clients
            SET payee_evm_pending_message = ?, payee_evm_pending_expires = ?
            WHERE id = ?
            """,
            (message, expires, int(client_id)),
        )
        if cur.rowcount == 0:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        conn.execute("COMMIT")
    return {"address": checksum, "message": message, "expires_at": expires}


def verify_payee_signature(db_path: str, *, client_id: int, address: str, signature: str, now: int | None = None) -> dict:
    """Recover the signer of the stored challenge. A bad signature changes nothing."""
    now = int(time.time()) if now is None else int(now)
    checksum = x402.checksum_address(address)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        message = row["payee_evm_pending_message"]
        expires = row["payee_evm_pending_expires"]
        if not message or expires is None or int(expires) < now:
            conn.execute("ROLLBACK")
            raise x402.X402Error("stale_challenge", status=400)
        expected = x402.checksum_address(_address_in_message(message))
        if checksum != expected:
            conn.execute("ROLLBACK")
            raise x402.X402Error("bad_signature", status=400)
        try:
            recovered = x402.recover_personal_signer(message, signature)
        except x402.X402Error:
            conn.execute("ROLLBACK")
            raise
        if recovered != checksum:
            conn.execute("ROLLBACK")
            raise x402.X402Error("bad_signature", status=400)
        previous = row["payee_evm_address"]
        changed = previous is not None and x402.checksum_address(previous) != checksum
        conn.execute(
            """
            UPDATE clients
            SET payee_evm_address = ?,
                payee_evm_verified_at = ?,
                payee_evm_message = ?,
                payee_evm_signature = ?,
                payee_evm_pending_message = NULL,
                payee_evm_pending_expires = NULL
            WHERE id = ?
            """,
            (checksum, now, message, signature, int(client_id)),
        )
        if changed:
            conn.execute(
                "UPDATE sites SET rail_x402 = 0, updated_at = ? WHERE client_id = ?",
                (now, int(client_id)),
            )
        conn.execute("COMMIT")
    return {"address": checksum, "verified_at": now, "rails_cleared": changed}


def _address_in_message(message: str) -> str:
    for line in message.splitlines():
        if line.startswith("Address: "):
            return line.removeprefix("Address: ").strip()
    raise x402.X402Error("stale_challenge", status=400)


def payee_verified(db_path: str, *, client_id: int) -> str | None:
    info = get_evm_payee(db_path, client_id=client_id)
    if info is None or not info["address"] or info["verified_at"] is None:
        return None
    return x402.checksum_address(info["address"])


def _limits(
    *,
    client_id: int,
    api_key_id: int | None,
    buyer_ip_hash: str | None,
    now: int,
) -> dict:
    return {
        "client_id": int(client_id),
        "now": int(now),
        "claim_grace_seconds": config.PAYWALL_CLAIM_GRACE_SECONDS,
        "claim_cap_seconds": config.PAYWALL_TOKEN_TTL_CAP_SECONDS,
        "max_open_per_client": config.MAX_OPEN_CHALLENGES_PER_CLIENT,
        "buyer_ip_hash": buyer_ip_hash,
        "buyer_rate_max": config.BUYER_CHALLENGE_MAX,
        "buyer_rate_window_seconds": config.RL_WINDOW_SECONDS,
        "buyer_max_open": config.BUYER_MAX_OPEN_CHALLENGES,
        "buyer_limit_scope": config.BUYER_LIMIT_SCOPE,
        "api_key_id": api_key_id,
    }


def find_reusable_offer(
    db_path: str,
    *,
    client_id: int,
    resource: str,
    amount: int,
    pay_to: str,
    buyer_ip_hash: str | None,
    max_uses: int | None,
    access_seconds: int | None,
    now: int,
) -> dict | None:
    if not buyer_ip_hash or config.CHALLENGE_REUSE_SECONDS <= 0:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE client_id = ?
              AND resource = ?
              AND amount_usd_atomic = ?
              AND pay_to = ?
              AND buyer_ip_hash = ?
              AND max_uses IS ?
              AND access_seconds IS ?
              AND expires_at > ?
              AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (
                int(client_id),
                resource,
                int(amount),
                pay_to,
                buyer_ip_hash,
                int(max_uses) if max_uses is not None else None,
                int(access_seconds) if access_seconds is not None else None,
                int(now),
                int(now) - int(config.CHALLENGE_REUSE_SECONDS),
            ),
        ).fetchone()
    return None if row is None else _offer_dict(row)


def create_offer(
    db_path: str,
    *,
    client_id: int,
    resource: str,
    resource_url: str,
    amount: int,
    pay_to: str,
    requirements: dict,
    buyer_ip_hash: str | None,
    max_uses: int | None,
    access_seconds: int | None,
    now: int | None = None,
) -> dict:
    now = int(time.time()) if now is None else int(now)
    expires = now + int(config.X402_OFFER_SECONDS)
    offer_id = secrets.token_hex(16)
    requirements = dict(requirements)
    requirements["maxTimeoutSeconds"] = int(config.X402_OFFER_SECONDS)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            limits = _limits(
                client_id=client_id,
                api_key_id=None,
                buyer_ip_hash=buyer_ip_hash,
                now=now,
            )
            enforce_challenge_capacity(
                conn,
                invoice_cutoff=now - int(limits["claim_grace_seconds"]),
                cap_cutoff=now - int(limits["claim_cap_seconds"]),
                **limits,
            )
        except ChallengeLimit:
            conn.execute("ROLLBACK")
            raise
        conn.execute(
            """
            INSERT INTO payment_offers(
              id, client_id, resource, api_key_id, price_currency, amount_sats, amount_usd_atomic,
              rate_num, rate_den, rate_fetched_at, expires_at, max_uses, access_seconds, payment_hash,
              scheme, network, asset, pay_to, requirements_json, buyer_ip_hash, created_at
            ) VALUES(?, ?, ?, NULL, 'usd', NULL, ?, NULL, NULL, NULL, ?, ?, ?, NULL, 'exact', ?, ?, ?, ?, ?, ?)
            """,
            (
                offer_id,
                int(client_id),
                resource,
                int(amount),
                expires,
                int(max_uses) if max_uses is not None else None,
                int(access_seconds) if access_seconds is not None else None,
                config.X402_NETWORK,
                x402.checksum_address(config.X402_USDC),
                pay_to,
                json.dumps(requirements, separators=(",", ":"), sort_keys=True),
                buyer_ip_hash,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM payment_offers WHERE id = ?", (offer_id,)).fetchone()
        conn.execute("COMMIT")
    offer = _offer_dict(row)
    offer["resource_url"] = resource_url
    return offer


def get_offer(db_path: str, offer_id: str) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM payment_offers WHERE id = ?", (offer_id,)).fetchone()
    return None if row is None else _offer_dict(row)


def latest_offer(db_path: str, *, client_id: int, resource: str) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE client_id = ? AND resource = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (int(client_id), resource),
        ).fetchone()
    return None if row is None else _offer_dict(row)


def find_offer_for_payment(db_path: str, *, client_id: int, resource: str, amount: int, pay_to: str, now: int) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE client_id = ? AND resource = ? AND amount_usd_atomic = ? AND pay_to = ? AND expires_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (int(client_id), resource, int(amount), pay_to, int(now)),
        ).fetchone()
    return None if row is None else _offer_dict(row)


def _offer_dict(row) -> dict:
    requirements = json.loads(row["requirements_json"]) if row["requirements_json"] else None
    return {
        "id": row["id"],
        "client_id": int(row["client_id"]),
        "resource": row["resource"],
        "price_currency": row["price_currency"],
        "amount_usd_atomic": None if row["amount_usd_atomic"] is None else int(row["amount_usd_atomic"]),
        "expires_at": int(row["expires_at"]),
        "max_uses": None if row["max_uses"] is None else int(row["max_uses"]),
        "access_seconds": None if row["access_seconds"] is None else int(row["access_seconds"]),
        "scheme": row["scheme"],
        "network": row["network"],
        "asset": row["asset"],
        "pay_to": row["pay_to"],
        "requirements": requirements,
        "created_at": int(row["created_at"]),
    }


def authorization_row(db_path: str, *, network: str, asset: str, payer: str, nonce: str):
    with _connect(db_path) as conn:
        return conn.execute(
            """
            SELECT * FROM x402_authorizations
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
            """,
            (network, asset, payer, nonce),
        ).fetchone()


def insert_pending(
    db_path: str,
    *,
    network: str,
    asset: str,
    payer: str,
    nonce: str,
    offer_id: str,
    value: str,
    pay_to: str,
    now: int,
) -> str:
    """Insert a pending nonce. Returns the resulting state if the row already exists."""
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """
            SELECT state FROM x402_authorizations
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
            """,
            (network, asset, payer, nonce),
        ).fetchone()
        if existing is not None:
            conn.execute("ROLLBACK")
            return str(existing["state"])
        conn.execute(
            """
            INSERT INTO x402_authorizations(
              network, asset, payer, nonce, offer_id, value_atomic, pay_to, state,
              credit_charged, uses_consumed, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, 'pending', 0, 0, ?)
            """,
            (network, asset, payer, nonce, offer_id, value, pay_to, int(now)),
        )
        conn.execute("COMMIT")
    return "inserted"


def set_authorization_state(
    db_path: str,
    *,
    network: str,
    asset: str,
    payer: str,
    nonce: str,
    state: str,
    now: int,
    expect: tuple[str, ...] | None = None,
) -> bool:
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = _update_state(
            conn,
            state=state,
            now=now,
            network=network,
            asset=asset,
            payer=payer,
            nonce=nonce,
            expect=expect,
        )
        changed = cur.rowcount == 1
        conn.execute("COMMIT")
    return changed


def _update_state(conn, *, state: str, now: int, network: str, asset: str, payer: str, nonce: str, expect: tuple[str, ...] | None):
    if expect is None:
        return conn.execute(
            """
            UPDATE x402_authorizations
            SET state = ?, updated_at = ?
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
            """,
            (state, int(now), network, asset, payer, nonce),
        )
    if expect == ("verified",):
        return conn.execute(
            """
            UPDATE x402_authorizations
            SET state = ?, updated_at = ?
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ? AND state = 'verified'
            """,
            (state, int(now), network, asset, payer, nonce),
        )
    if expect == ("settling",):
        return conn.execute(
            """
            UPDATE x402_authorizations
            SET state = ?, updated_at = ?
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ? AND state = 'settling'
            """,
            (state, int(now), network, asset, payer, nonce),
        )
    raise ValueError("invalid_state")


def mark_settled_and_charge(
    db_path: str,
    *,
    network: str,
    asset: str,
    payer: str,
    nonce: str,
    tx_hash: str,
    client_id: int,
    resource: str,
    access_seconds: int | None,
    max_uses: int | None,
    cost: int,
    now: int,
) -> dict:
    """Store the tx and debit one credit. A second call does not debit again."""
    now = int(now)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT * FROM x402_authorizations
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
            """,
            (network, asset, payer, nonce),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise x402.X402Error("bad_signature")
        if int(row["credit_charged"] or 0) == 1:
            balance = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
            conn.execute("COMMIT")
            return {
                "charged": 0,
                "credits": int(balance[0]) if balance else 0,
                "tx_hash": row["tx_hash"],
            }
        bal_row = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if bal_row is None:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        current = int(bal_row[0])
        if current < int(cost):
            conn.execute(
                """
                UPDATE x402_authorizations
                SET state = 'settled', tx_hash = ?, settled_at = COALESCE(settled_at, ?), updated_at = ?
                WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
                """,
                (tx_hash, now, now, network, asset, payer, nonce),
            )
            conn.execute("COMMIT")
            raise ValueError("insufficient balance")
        window = None
        if access_seconds is not None:
            window = int(access_seconds)
        elif max_uses is not None:
            window = int(config.PAYWALL_ACCESS_CAP_SECONDS)
        access_until = None if window is None else now + window
        conn.execute(
            "UPDATE clients SET credits = credits - ? WHERE id = ?",
            (int(cost), int(client_id)),
        )
        conn.execute(
            """
            INSERT INTO ledger(
              client_id, delta_credits, reason, ref, created_at, api_key_id, resource
            ) VALUES(?, ?, 'paywall_verify', ?, ?, NULL, ?)
            """,
            (int(client_id), -int(cost), tx_hash, now, resource),
        )
        conn.execute(
            """
            UPDATE x402_authorizations
            SET state = 'settled', tx_hash = ?, settled_at = ?, credit_charged = 1,
                uses_consumed = 1, access_until = ?, updated_at = ?
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
            """,
            (tx_hash, now, access_until, now, network, asset, payer, nonce),
        )
        new_balance = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        conn.execute("COMMIT")
    return {"charged": int(cost), "credits": int(new_balance[0]), "tx_hash": tx_hash}


def client_credits(db_path: str, client_id: int) -> int:
    client = db.get_client_by_id(db_path, client_id)
    if client is None:
        raise ValueError("client does not exist")
    return int(client.credits)
