from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


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
    # re-add padding
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _json_dumps(obj: dict) -> bytes:
    # deterministic
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def make_macaroon(*, secret: str, payment_hash: str, resource: str, ttl_seconds: int) -> str:
    exp = int(time.time()) + int(ttl_seconds)
    payload = {
        "v": 1,
        "ph": payment_hash,
        "res": resource,
        "exp": exp,
        "nonce": secrets.token_hex(8),
    }

    payload_bytes = _json_dumps(payload)
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    token = payload_bytes + b"." + sig.encode("ascii")
    return _b64encode(token)


def parse_and_verify_macaroon(*, secret: str, macaroon_b64: str, resource: str | None = None) -> dict:
    try:
        token = _b64decode(macaroon_b64)
        payload_bytes, sig_bytes = token.rsplit(b".", 1)
    except Exception as e:  # noqa: BLE001
        raise L402Error("invalid macaroon") from e

    expected_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest().encode("ascii")
    if not hmac.compare_digest(expected_sig, sig_bytes):
        raise L402Error("invalid signature")

    payload = json.loads(payload_bytes.decode("utf-8"))

    if payload.get("v") != 1:
        raise L402Error("unsupported version")

    if resource is not None and payload.get("res") != resource:
        raise L402Error("resource mismatch")

    exp = int(payload.get("exp", 0))
    if int(time.time()) > exp:
        raise L402Error("token expired")

    ph = payload.get("ph")
    if not isinstance(ph, str) or len(ph) != 64:
        raise L402Error("invalid payment_hash")

    return payload


def parse_authorization_header(auth: str | None) -> tuple[str, str]:
    """Returns (macaroon_b64, preimage_hex)."""
    if not auth:
        raise L402Error("missing credentials")

    try:
        scheme, token = auth.split(" ", 1)
    except ValueError as e:
        raise L402Error("malformed Authorization header") from e

    if scheme.lower() != "l402":
        raise L402Error("scheme is not L402")

    try:
        macaroon_b64, preimage_hex = token.split(":", 1)
    except ValueError as e:
        raise L402Error("malformed L402 token") from e

    # validate hex
    try:
        bytes.fromhex(preimage_hex)
    except ValueError as e:
        raise L402Error("preimage is not hex") from e

    return macaroon_b64, preimage_hex


def verify_preimage_matches_payment_hash(*, preimage_hex: str, payment_hash: str) -> None:
    preimage = bytes.fromhex(preimage_hex)
    got = hashlib.sha256(preimage).hexdigest()
    if got != payment_hash:
        raise L402Error("preimage does not match payment_hash")
