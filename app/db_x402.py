"""Stored x402 offers, nonce replay rows, and the merchant EVM payee."""

from __future__ import annotations

import json
import re
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


_CONNECT_TOKEN = re.compile(r"^sgc_[A-Za-z0-9_-]{16,128}$")


def create_connect_link(db_path: str, *, client_id: int, now: int | None = None) -> dict:
    """Store a hashed one-time connect token. The raw token is only in the returned URL."""
    now = int(time.time()) if now is None else int(now)
    token = "sgc_" + secrets.token_urlsafe(32)
    expires = now + int(config.PAYEE_CONNECT_SECONDS)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            """
            UPDATE clients
            SET payee_evm_connect_hash = ?, payee_evm_connect_expires = ?
            WHERE id = ?
            """,
            (db.hash_api_key(token), expires, int(client_id)),
        )
        if cur.rowcount == 0:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        conn.execute("COMMIT")
    return {
        "connect_url": f"{config.CONNECT_PUBLIC_BASE}#t={token}",
        "expires_at": expires,
    }


def connect_session(db_path: str, token: str, *, now: int | None = None) -> dict:
    """Resolve a connect token. Missing, expired, and unknown tokens share one error."""
    now = int(time.time()) if now is None else int(now)
    if not isinstance(token, str) or not _CONNECT_TOKEN.fullmatch(token):
        raise x402.X402Error("connect_link_invalid", status=401)
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, payee_evm_address, payee_evm_verified_at, payee_evm_connect_expires
            FROM clients
            WHERE payee_evm_connect_hash = ?
            """,
            (db.hash_api_key(token),),
        ).fetchone()
    if row is None or row["payee_evm_connect_expires"] is None or int(row["payee_evm_connect_expires"]) < now:
        raise x402.X402Error("connect_link_invalid", status=401)
    address = row["payee_evm_address"]
    if not address:
        shown = None
        verified = False
    else:
        shown = x402.checksum_address(address)
        verified = row["payee_evm_verified_at"] is not None
    return {
        "client_id": int(row["id"]),
        "address": shown,
        "verified": verified,
        "expires_at": int(row["payee_evm_connect_expires"]),
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


def verify_payee_signature(
    db_path: str,
    *,
    client_id: int,
    address: str,
    signature: str,
    now: int | None = None,
    consume_connect: bool = False,
) -> dict:
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
            x402.recover_payee_signer(message, signature, address=checksum)
        except x402.X402Error:
            conn.execute("ROLLBACK")
            raise
        previous = row["payee_evm_address"]
        changed = previous is not None and x402.checksum_address(previous) != checksum
        if consume_connect:
            conn.execute(
                """
                UPDATE clients
                SET payee_evm_address = ?,
                    payee_evm_verified_at = ?,
                    payee_evm_message = ?,
                    payee_evm_signature = ?,
                    payee_evm_pending_message = NULL,
                    payee_evm_pending_expires = NULL,
                    payee_evm_connect_hash = NULL,
                    payee_evm_connect_expires = NULL
                WHERE id = ?
                """,
                (checksum, now, message, signature, int(client_id)),
            )
        else:
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
        "rail": "x402",
    }


def find_reusable_offer(
    db_path: str,
    *,
    client_id: int,
    resource: str,
    price_currency: str,
    main_sats: int | None,
    main_usd: int | None,
    pay_to: str | None,
    buyer_ip_hash: str | None,
    max_uses: int | None,
    access_seconds: int | None,
    now: int,
    network: str | None = None,
) -> dict | None:
    """Reuse the locked quote. The derived amount is not part of the match."""
    if not buyer_ip_hash or config.CHALLENGE_REUSE_SECONDS <= 0:
        return None
    if price_currency == "sats":
        if main_sats is None:
            return None
        amount_column = "amount_sats"
        amount = int(main_sats)
    else:
        if main_usd is None:
            return None
        amount_column = "amount_usd_atomic"
        amount = int(main_usd)
    params: tuple = (
        int(client_id),
        resource,
        price_currency,
        amount,
        pay_to,
        buyer_ip_hash,
        int(max_uses) if max_uses is not None else None,
        int(access_seconds) if access_seconds is not None else None,
        int(now),
        int(now) - int(config.CHALLENGE_REUSE_SECONDS),
    )
    sats_sql = """
        SELECT * FROM payment_offers
        WHERE client_id = ?
          AND resource = ?
          AND price_currency = ?
          AND amount_sats = ?
          AND pay_to IS ?
          AND buyer_ip_hash = ?
          AND max_uses IS ?
          AND access_seconds IS ?
          AND (? IS NULL OR network = ?)
          AND expires_at > ?
          AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 1
    """
    usd_sql = """
        SELECT * FROM payment_offers
        WHERE client_id = ?
          AND resource = ?
          AND price_currency = ?
          AND amount_usd_atomic = ?
          AND pay_to IS ?
          AND buyer_ip_hash = ?
          AND max_uses IS ?
          AND access_seconds IS ?
          AND (? IS NULL OR network = ?)
          AND expires_at > ?
          AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 1
    """
    params = params[:8] + (network, network) + params[8:]
    with _connect(db_path) as conn:
        row = conn.execute(sats_sql if amount_column == "amount_sats" else usd_sql, params).fetchone()
    return None if row is None else _offer_dict(row)


def create_offer(
    db_path: str,
    *,
    client_id: int,
    resource: str,
    resource_url: str,
    price_currency: str,
    amount_sats: int | None,
    amount_usd_atomic: int | None,
    pay_to: str | None,
    requirements: dict | None,
    buyer_ip_hash: str | None,
    max_uses: int | None,
    access_seconds: int | None,
    rate_num: int | None = None,
    rate_den: int | None = None,
    rate_fetched_at: int | None = None,
    payment_hash: str | None = None,
    expires_at: int | None = None,
    enforce: bool = True,
    grant_credits: int | None = None,
    now: int | None = None,
) -> dict:
    now = int(time.time()) if now is None else int(now)
    expires = int(expires_at) if expires_at is not None else now + int(config.X402_OFFER_SECONDS)
    offer_id = secrets.token_hex(16)
    stored = None
    scheme = None
    network = None
    asset = None
    if requirements is not None:
        stored = dict(requirements)
        stored["maxTimeoutSeconds"] = max(1, expires - now)
        scheme = "exact"
        network = stored.get("network")
        if network not in {x402.NETWORK_SEPOLIA, x402.NETWORK_BASE}:
            raise x402.X402Error("network_mismatch")
        asset = x402.usdc_for_network(network)
        stored["network"] = network
        stored["asset"] = asset
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if enforce:
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
              scheme, network, asset, pay_to, requirements_json, buyer_ip_hash, created_at,
              resource_url, grant_credits
            ) VALUES(?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                offer_id,
                int(client_id),
                resource,
                price_currency,
                None if amount_sats is None else int(amount_sats),
                None if amount_usd_atomic is None else int(amount_usd_atomic),
                None if rate_num is None else int(rate_num),
                None if rate_den is None else int(rate_den),
                None if rate_fetched_at is None else int(rate_fetched_at),
                expires,
                int(max_uses) if max_uses is not None else None,
                int(access_seconds) if access_seconds is not None else None,
                payment_hash,
                scheme,
                network,
                asset,
                pay_to,
                None if stored is None else json.dumps(stored, separators=(",", ":"), sort_keys=True),
                buyer_ip_hash,
                now,
                resource_url,
                int(grant_credits) if grant_credits is not None else None,
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


def offer_by_payment_hash(db_path: str, payment_hash: str) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE payment_hash = ?
            ORDER BY expires_at DESC, created_at DESC
            LIMIT 1
            """,
            (payment_hash,),
        ).fetchone()
    return None if row is None else _offer_dict(row)


def replace_x402_quote(
    db_path: str,
    *,
    payment_hash: str,
    expires_at: int,
    requirements: dict,
    amount_usd_atomic: int | None,
    pay_to: str | None,
    rate_num: int | None,
    rate_den: int | None,
    rate_fetched_at: int | None,
    now: int,
) -> dict | None:
    """Point the Lightning payment's x402 half at a new short quote.

    ``payment_hash`` is unique on this table, so a reused invoice cannot insert
    a second row. The Lightning expiry stays on the challenge, not here.
    """
    stored = dict(requirements)
    stored["maxTimeoutSeconds"] = max(1, int(expires_at) - int(now))
    network = stored.get("network")
    if network not in {x402.NETWORK_SEPOLIA, x402.NETWORK_BASE}:
        raise x402.X402Error("network_mismatch")
    asset = x402.usdc_for_network(network)
    stored["network"] = network
    stored["asset"] = asset
    payload = json.dumps(stored, separators=(",", ":"), sort_keys=True)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE payment_offers
            SET expires_at = ?, requirements_json = ?, amount_usd_atomic = ?, pay_to = ?,
                scheme = 'exact', network = ?, asset = ?,
                rate_num = ?, rate_den = ?, rate_fetched_at = ?
            WHERE payment_hash = ?
            """,
            (
                int(expires_at),
                payload,
                None if amount_usd_atomic is None else int(amount_usd_atomic),
                pay_to,
                network,
                asset,
                None if rate_num is None else int(rate_num),
                None if rate_den is None else int(rate_den),
                None if rate_fetched_at is None else int(rate_fetched_at),
                payment_hash,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE payment_hash = ?
            ORDER BY expires_at DESC, created_at DESC
            LIMIT 1
            """,
            (payment_hash,),
        ).fetchone()
        conn.execute("COMMIT")
    return None if row is None else _offer_dict(row)


def recent_offers(db_path: str, *, client_id: int, resource: str, limit: int = 20) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE client_id = ? AND resource = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (int(client_id), resource, int(limit)),
        ).fetchall()
    return [_offer_dict(row) for row in rows]


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
        "amount_sats": None if row["amount_sats"] is None else int(row["amount_sats"]),
        "amount_usd_atomic": None if row["amount_usd_atomic"] is None else int(row["amount_usd_atomic"]),
        "rate_num": None if row["rate_num"] is None else int(row["rate_num"]),
        "rate_den": None if row["rate_den"] is None else int(row["rate_den"]),
        "rate_fetched_at": None if row["rate_fetched_at"] is None else int(row["rate_fetched_at"]),
        "payment_hash": row["payment_hash"],
        "expires_at": int(row["expires_at"]),
        "max_uses": None if row["max_uses"] is None else int(row["max_uses"]),
        "access_seconds": None if row["access_seconds"] is None else int(row["access_seconds"]),
        "scheme": row["scheme"],
        "network": row["network"],
        "asset": row["asset"],
        "pay_to": row["pay_to"],
        "requirements": requirements,
        "resource_url": row["resource_url"],
        "grant_credits": None if row["grant_credits"] is None else int(row["grant_credits"]),
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
    amount_usd_atomic: int,
    api_key_id: int | None = None,
) -> dict:
    """Store the tx and debit one credit. A second call does not debit again.

    ``api_key_id`` is the restricted key that settled the request, when the
    caller authenticated with one. The account key and the hosted gate leave
    it null. Existing ledger rows are not rewritten.
    """
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
              client_id, delta_credits, reason, ref, created_at, api_key_id, resource,
              network, amount_usd_atomic
            ) VALUES(?, ?, 'paywall_verify', ?, ?, ?, ?, ?, ?)
            """,
            (
                int(client_id),
                -int(cost),
                tx_hash,
                now,
                int(api_key_id) if api_key_id is not None else None,
                resource,
                network,
                int(amount_usd_atomic),
            ),
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


def find_topup_offer(
    db_path: str,
    *,
    client_id: int,
    resource: str,
    pay_to: str,
    amount_usd_atomic: int,
    grant_credits: int,
    network: str,
    now: int,
) -> dict | None:
    """An unexpired pack quote with the same locked amount and network.

    A new median is a new row. So is a switch from testnet USDC to mainnet.
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM payment_offers
            WHERE client_id = ? AND resource = ? AND pay_to = ? AND amount_usd_atomic = ?
              AND grant_credits = ? AND network = ? AND expires_at > ? AND resource_url IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (
                int(client_id),
                resource,
                pay_to,
                int(amount_usd_atomic),
                int(grant_credits),
                network,
                int(now),
            ),
        ).fetchone()
    return None if row is None else _offer_dict(row)


def grant_topup_credits(
    db_path: str,
    *,
    network: str,
    asset: str,
    payer: str,
    nonce: str,
    tx_hash: str,
    client_id: int,
    offer_id: str,
    plan_id: str,
    credits: int,
    sats: int,
    amount_usd_atomic: int,
    pay_to: str,
    expires_at: int,
    now: int,
) -> dict:
    """Add the pack once. A second caller sees credit_charged and adds nothing.

    The ledger row, the top-up row, and credit_charged commit together.
    """
    now = int(now)
    payment_hash = str(nonce).removeprefix("0x").lower()
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT * FROM x402_authorizations
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ?
            """,
            (network, asset, payer, nonce),
        ).fetchone()
        if row is None or row["offer_id"] != offer_id:
            conn.execute("ROLLBACK")
            raise x402.X402Error("bad_signature")
        if str(row["value_atomic"]) != str(int(amount_usd_atomic)) or row["pay_to"] != pay_to:
            conn.execute("ROLLBACK")
            raise x402.X402Error("amount_mismatch")
        if int(row["credit_charged"] or 0) == 1:
            conn.execute("ROLLBACK")
            raise x402.X402Error("x402_replay", status=409)
        bal = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        if bal is None:
            conn.execute("ROLLBACK")
            raise ValueError("client does not exist")
        conn.execute(
            "UPDATE clients SET credits = credits + ? WHERE id = ?",
            (int(credits), int(client_id)),
        )
        conn.execute(
            """
            INSERT INTO ledger(
              client_id, delta_credits, reason, ref, created_at, resource, network, amount_usd_atomic
            ) VALUES(?, ?, 'topup_x402', ?, ?, ?, ?, ?)
            """,
            (
                int(client_id),
                int(credits),
                tx_hash,
                now,
                f"v1/topup/{plan_id}",
                network,
                int(amount_usd_atomic),
            ),
        )
        conn.execute(
            """
            INSERT INTO topups(
              payment_hash, invoice, sats, credits, status, client_id, created_at, settled_at,
              expires_at, rail, tx_hash, amount_usd_atomic, network
            ) VALUES(?, 'x402', ?, ?, 'settled', ?, ?, ?, ?, 'x402', ?, ?, ?)
            """,
            (
                payment_hash,
                int(sats),
                int(credits),
                int(client_id),
                now,
                now,
                int(expires_at),
                tx_hash,
                int(amount_usd_atomic),
                network,
            ),
        )
        cur = conn.execute(
            """
            UPDATE x402_authorizations
            SET state = 'settled', tx_hash = ?, settled_at = ?, credit_charged = 1, updated_at = ?
            WHERE network = ? AND asset = ? AND payer = ? AND nonce = ? AND credit_charged = 0
            """,
            (tx_hash, now, now, network, asset, payer, nonce),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            raise x402.X402Error("x402_replay", status=409)
        new_balance = conn.execute("SELECT credits FROM clients WHERE id = ?", (int(client_id),)).fetchone()
        conn.execute("COMMIT")
    return {
        "credits_added": int(credits),
        "credits": int(new_balance[0]),
        "tx_hash": tx_hash,
    }


def client_credits(db_path: str, client_id: int) -> int:
    client = db.get_client_by_id(db_path, client_id)
    if client is None:
        raise ValueError("client does not exist")
    return int(client.credits)
