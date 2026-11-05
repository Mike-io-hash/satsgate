"""Mint one hosted-gate receipt when a payment is proved.

Lightning debits through settle_and_consume with consume left false: the
seller counts uses. x402 debits through settle_payment. Test mode passes
cost 0. The receipt row is inserted in that same transaction.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import config, db, db_receipts, db_sites, receipts, x402, x402_service


class ReceiptIssueError(Exception):
    def __init__(self, code: str, status: int, **extra: object) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.extra = extra


def resource_description(origin_url: str, path: str, *, network: str | None) -> str:
    host = urlsplit(origin_url).hostname or ""
    text = f"Satsgate receipt for {host}{path}"
    if network == x402.NETWORK_SEPOLIA:
        return f"{x402.TEST_DESCRIPTION} {text}"
    return text


def _uses(route: dict) -> int:
    raw = route.get("max_uses")
    return 1 if raw is None else int(raw)


def _window(route: dict, now: int) -> tuple[int, int]:
    seconds = receipts.receipt_lifetime(
        route.get("access_seconds"),
        default_seconds=config.RECEIPT_SECONDS,
        cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
    )
    return now, now + seconds


def _suspended(client_id: int) -> None:
    if db.client_is_suspended(config.DB_PATH, client_id=client_id):
        raise ReceiptIssueError("account_suspended", 403)


def public_body(row: dict, *, secret: str, aud: str) -> dict:
    claims = receipts.claims_from_row(row, iss=config.GATE_PUBLIC_BASE, aud=aud)
    token = receipts.encode_token(claims, secret=secret, typ=receipts.TYP_RECEIPT)
    exp = int(row["exp"])
    iso = receipts.expires_at_iso(exp)
    ph = db_receipts.public_ph(row["payment_hash"])
    return {
        "ok": True,
        "paid": True,
        "rail": row["rail"],
        "payment_hash": ph,
        "receipt": token,
        "receipt_header": "Satsgate-Receipt",
        "uses": int(row["uses"]),
        "expires_at": exp,
        "expires_at_iso": iso,
        "note": (
            "Repeat your request at redeem_url with the Satsgate-Receipt header. "
            f"Satsgate does not serve this content. The receipt is valid until {iso} UTC."
        ),
    }


def existing_body(payment_hash: str, *, secret: str, aud: str, now: int) -> dict | None:
    row = db_receipts.get_receipt(config.DB_PATH, payment_hash)
    if row is None:
        return None
    if now >= int(row["exp"]):
        raise ReceiptIssueError(
            "token_expired",
            401,
            status="settled",
            settled=True,
            payment_hash=db_receipts.public_ph(payment_hash),
        )
    return public_body(row, secret=secret, aud=aud)


def mint_lightning(
    *,
    client_id: int,
    site: dict,
    route: dict,
    payment_hash: str,
    amount_sats: int,
    now: int,
) -> dict:
    _suspended(client_id)
    secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(site["id"]))
    found = existing_body(payment_hash, secret=secret, aud=site["slug"], now=now)
    if found is not None:
        return found
    iat, exp = _window(route, now)
    pending = {
        "rid": receipts.new_receipt_id(),
        "payment_hash": payment_hash,
        "site_id": int(site["id"]),
        "client_id": int(client_id),
        "path": route["path"],
        "rail": "lightning",
        "amount_sats": int(amount_sats),
        "amount_usd_atomic": None,
        "network": None,
        "uses": _uses(route),
        "iat": iat,
        "exp": exp,
        "kid": receipts.kid_for(secret),
        "charged": 1,
    }

    def _insert(conn) -> None:
        db_receipts.insert_receipt(conn, pending)

    from . import db_verify

    db_verify.settle_and_consume(
        config.DB_PATH,
        client_id=int(client_id),
        payment_hash=payment_hash,
        cost=x402_service._COST,
        resource=f"gate:{site['slug']}:{route['path']}",
        api_key_id=None,
        consume=False,
        access_cap_seconds=config.PAYWALL_ACCESS_CAP_SECONDS,
        now=now,
        before_commit=_insert,
    )
    row = db_receipts.get_receipt(config.DB_PATH, payment_hash)
    if row is None:
        raise ReceiptIssueError("paywall_unavailable", 502)
    secret = db_sites.load_origin_secret(config.DB_PATH, site_id=int(site["id"]))
    return public_body(row, secret=secret, aud=site["slug"])
