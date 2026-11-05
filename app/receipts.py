"""HS256 access receipts signed with the site origin secret.

Claims are stored. The token is rebuilt with the current secret, so a rotation
does not strand a buyer who still holds the paid macaroon or x402 signature.
The token is not logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

TYP_RECEIPT = "satsgate-receipt+jwt"
TYP_CHECK = "satsgate-check+jwt"


def kid_for(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def new_receipt_id() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return "rcp_" + "".join(secrets.choice(alphabet) for _ in range(22))


def new_check_id() -> str:
    return "chk_" + secrets.token_hex(8)


def receipt_lifetime(access_seconds: int | None, *, default_seconds: int, cap_seconds: int) -> int:
    """Seconds until exp. A route access window wins; otherwise the receipt default.

    Clamped into 60..86400 and to the paywall access cap.
    """
    raw = int(default_seconds) if access_seconds is None else int(access_seconds)
    return max(60, min(86400, int(cap_seconds), raw))


def expires_at_iso(exp: int) -> str:
    return datetime.fromtimestamp(int(exp), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_token(claims: dict, *, secret: str, typ: str) -> str:
    header = {"alg": "HS256", "kid": kid_for(secret), "typ": typ}
    head = _b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing = f"{head}.{body}".encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), signing, hashlib.sha256).digest()
    token = f"{head}.{body}.{_b64(digest)}"
    if typ == TYP_RECEIPT and len(token.encode("ascii")) > 1024:
        raise RuntimeError("receipt exceeds 1KB")
    return token


def check_proof(secret: str, jti: str) -> str:
    return hmac.new(secret.encode("utf-8"), f"satsgate-check|{jti}".encode("utf-8"), hashlib.sha256).hexdigest()


def proof_matches(secret: str, jti: str, presented: object) -> bool:
    if not isinstance(presented, str) or not presented:
        return False
    expected = check_proof(secret, jti)
    if len(presented) != len(expected):
        return False
    return hmac.compare_digest(presented.lower(), expected)


def claims_from_row(row: dict, *, iss: str, aud: str) -> dict:
    if row["rail"] == "lightning":
        amount: dict = {"sats": int(row["amount_sats"])}
    else:
        amount = {"network": row["network"], "usd_atomic": int(row["amount_usd_atomic"])}
    ph = row["payment_hash"]
    if isinstance(ph, str) and ph.startswith("x402:"):
        ph = ph.removeprefix("x402:")
    return {
        "amt": amount,
        "aud": aud,
        "exp": int(row["exp"]),
        "iat": int(row["iat"]),
        "iss": iss,
        "jti": row["rid"],
        "ph": ph,
        "rail": row["rail"],
        "res": f"gate:{aud}:{row['path']}",
        "sub": row["path"],
        "uses": int(row["uses"]),
    }
