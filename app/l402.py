from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass

TOKEN_VERSION = 2
PURPOSE_PAYWALL = "paywall"
PURPOSE_TOPUP = "topup"
PURPOSE_TICKET = "ticket"


@dataclass(frozen=True)
class L402Challenge:
    macaroon: str  # base64
    invoice: str  # bolt11 (or mock)
    payment_hash: str  # hex


class L402Error(Exception):
    pass


def _b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _json_dumps(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def payee_binding(payee: str | None) -> str:
    """Stable hash of the Lightning Address this challenge pays."""
    normalized = (payee or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def invoice_binding(invoice: str) -> str:
    return hashlib.sha256(invoice.encode("utf-8")).hexdigest()


def make_macaroon(
    *,
    secret: str,
    kid: str,
    purpose: str,
    payment_hash: str,
    resource: str,
    amount_sats: int,
    invoice: str,
    ttl_seconds: int,
    client_id: int | None,
    payee: str | None,
) -> str:
    """Sign a v2 token bound to client, amount, payee, and invoice.

    v1 tokens ({v, ph, res, exp, nonce} with a global secret) are not issued.
    """
    if purpose not in {PURPOSE_PAYWALL, PURPOSE_TOPUP, PURPOSE_TICKET}:
        raise L402Error("invalid purpose")
    if not isinstance(payment_hash, str) or len(payment_hash) != 64:
        raise L402Error("invalid payment_hash")
    if purpose == PURPOSE_PAYWALL and client_id is None:
        raise L402Error("paywall token requires client_id")

    payload = {
        "v": TOKEN_VERSION,
        "kid": kid,
        "purpose": purpose,
        "cid": None if client_id is None else int(client_id),
        "ph": payment_hash,
        "res": resource,
        "amt": int(amount_sats),
        "payee_h": payee_binding(payee),
        "inv_h": invoice_binding(invoice),
        "exp": int(time.time()) + int(ttl_seconds),
        "nonce": secrets.token_hex(8),
    }

    payload_bytes = _json_dumps(payload)
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    token = payload_bytes + b"." + sig.encode("ascii")
    return _b64encode(token)


def _require_hex64(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise L402Error(f"invalid {label}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise L402Error(f"invalid {label}") from exc
    if len(raw) != 32:
        raise L402Error(f"invalid {label}")
    return value.lower()


def _require_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise L402Error(f"invalid {label}")
    return value


def parse_and_verify_macaroon(
    *,
    keys: Mapping[str, str],
    macaroon_b64: str,
    purpose: str,
    resource: str,
    client_id: int | None = None,
) -> dict:
    """Verify a v2 token. Resource is required. Paywall checks also pass client_id.

    `client_id` when provided must equal the signed `cid`. A token minted for one
    client never verifies for another.
    """
    if not resource:
        raise L402Error("resource mismatch")

    try:
        token = _b64decode(macaroon_b64)
        payload_bytes, sig_bytes = token.rsplit(b".", 1)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise L402Error("invalid macaroon") from exc

    if not isinstance(payload, dict):
        raise L402Error("invalid macaroon")

    def _sig_ok(secret: str) -> bool:
        expected_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest().encode("ascii")
        if len(sig_bytes) != len(expected_sig):
            return False
        return hmac.compare_digest(expected_sig, sig_bytes)

    kid = payload.get("kid")
    if isinstance(kid, str) and kid in keys:
        signed = _sig_ok(keys[kid])
    else:
        # No usable kid (v1 tokens omit it). A MAC under a configured key still
        # counts so the version check below can reject it as unsupported.
        signed = any(_sig_ok(secret) for secret in keys.values())
    if not signed:
        raise L402Error("invalid signature")

    if payload.get("v") != TOKEN_VERSION:
        raise L402Error("unsupported version")

    if payload.get("purpose") != purpose:
        raise L402Error("purpose mismatch")

    if payload.get("res") != resource:
        raise L402Error("resource mismatch")

    try:
        exp = _require_int(payload.get("exp"), "exp")
    except L402Error:
        raise
    if int(time.time()) > exp:
        raise L402Error("token expired")

    _require_hex64(payload.get("ph"), "payment_hash")
    _require_hex64(payload.get("payee_h"), "payee")
    _require_hex64(payload.get("inv_h"), "invoice")
    _require_int(payload.get("amt"), "amount")

    cid = payload.get("cid")
    if purpose == PURPOSE_PAYWALL:
        if client_id is None:
            raise L402Error("client mismatch")
        if isinstance(cid, bool) or not isinstance(cid, int) or int(cid) != int(client_id):
            raise L402Error("client mismatch")
    elif cid is not None:
        if isinstance(cid, bool) or not isinstance(cid, int):
            raise L402Error("client mismatch")
        if client_id is not None and int(cid) != int(client_id):
            raise L402Error("client mismatch")

    payload["ph"] = str(payload["ph"]).lower()
    payload["payee_h"] = str(payload["payee_h"]).lower()
    payload["inv_h"] = str(payload["inv_h"]).lower()
    return payload


def parse_authorization_header(auth: str | None) -> tuple[str, str]:
    """Returns (macaroon_b64, preimage_hex)."""
    if not auth:
        raise L402Error("missing credentials")

    try:
        scheme, token = auth.split(" ", 1)
    except ValueError as exc:
        raise L402Error("malformed Authorization header") from exc

    if scheme.lower() != "l402":
        raise L402Error("scheme is not L402")

    try:
        macaroon_b64, preimage_hex = token.split(":", 1)
    except ValueError as exc:
        raise L402Error("malformed L402 token") from exc

    try:
        raw = bytes.fromhex(preimage_hex)
    except ValueError as exc:
        raise L402Error("preimage is not hex") from exc
    if len(raw) != 32:
        raise L402Error("preimage is not hex")

    return macaroon_b64, preimage_hex.lower()


def verify_preimage_matches_payment_hash(*, preimage_hex: str, payment_hash: str) -> None:
    preimage = bytes.fromhex(preimage_hex)
    got = hashlib.sha256(preimage).hexdigest()
    if got != payment_hash.lower():
        raise L402Error("preimage does not match payment_hash")
