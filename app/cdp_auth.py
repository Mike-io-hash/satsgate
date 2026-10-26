"""Coinbase CDP JWT for the x402 facilitator.

The secret is a CDP Secret API key: standard base64 of 64 bytes (32-byte
Ed25519 seed, then 32-byte public key). Core uses it only to authenticate
HTTP calls. It never signs or submits a transaction.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import time
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_REDACTED = "[redacted]"


class CredentialError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("credential_invalid")


def secret_is_usable(secret: str) -> bool:
    """True when the value is standard base64 of a 64-byte CDP Ed25519 secret."""
    if not isinstance(secret, str) or not secret or any(ch.isspace() for ch in secret):
        return False
    try:
        raw = base64.b64decode(secret, validate=True)
    except Exception:  # noqa: BLE001
        return False
    if len(raw) != 64:
        return False
    try:
        key = Ed25519PrivateKey.from_private_bytes(raw[:32])
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception:  # noqa: BLE001
        return False
    return public == raw[32:]


def _private_key(secret: str) -> Ed25519PrivateKey:
    if not secret_is_usable(secret):
        raise CredentialError from None
    raw = base64.b64decode(secret, validate=True)
    return Ed25519PrivateKey.from_private_bytes(raw[:32])


def _key_id() -> str:
    raw = os.environ.get("SATSGATE_X402_CDP_KEY_ID", "")
    if raw != raw.strip() or not raw or any(ch.isspace() for ch in raw) or len(raw) > 256:
        raise CredentialError from None
    return raw


def authorization_header(method: str, url: str) -> str:
    """Bearer JWT. The URI claim is ``METHOD host/path`` with no scheme."""
    key_id = _key_id()
    secret = os.environ.get("SATSGATE_X402_CDP_KEY_SECRET", "").strip()
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.scheme != "https":
        raise CredentialError from None
    path = parsed.path or "/"
    uri = f"{method.upper()} {parsed.hostname}{path}"
    # One second of slack so a facilitator clock that is slightly behind
    # still accepts the token. The documented lifetime is two minutes.
    now = int(time.time()) - 1
    try:
        key = _private_key(secret)
        token = jwt.encode(
            {
                "sub": key_id,
                "iss": "cdp",
                "aud": ["cdp_service"],
                "nbf": now,
                "exp": now + 120,
                "uri": uri,
            },
            key,
            algorithm="EdDSA",
            headers={"typ": "JWT", "kid": key_id, "nonce": secrets.token_hex(16)},
        )
    except CredentialError:
        raise
    except Exception:  # noqa: BLE001
        raise CredentialError from None
    if not isinstance(token, str) or (secret and secret in token):
        raise CredentialError from None
    return f"Bearer {token}"


class _Redactor(logging.Filter):
    """Drop the live CDP secret and key id from log records.

    Reads the environment on each record so a reload cannot keep a stale copy
    inside this filter, and so a secret that arrives after import is still covered.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        secret = os.environ.get("SATSGATE_X402_CDP_KEY_SECRET", "")
        key_id = os.environ.get("SATSGATE_X402_CDP_KEY_ID", "")
        needles = [item.strip() for item in (secret, key_id) if isinstance(item, str) and len(item.strip()) >= 8]
        if not needles:
            return True
        record.msg = _scrub(record.msg, needles)
        record.args = _scrub(record.args, needles)
        if record.exc_text:
            record.exc_text = _scrub(record.exc_text, needles)
        return True


def _scrub(value, needles: list[str]):
    if isinstance(value, str):
        for needle in needles:
            value = value.replace(needle, _REDACTED)
        return value
    if isinstance(value, tuple):
        return tuple(_scrub(item, needles) for item in value)
    if isinstance(value, dict):
        return {key: _scrub(item, needles) for key, item in value.items()}
    return value


def install_redactor() -> None:
    filt = _Redactor()
    for name in ("satsgate.x402", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        if any(isinstance(item, _Redactor) for item in logger.filters):
            continue
        logger.addFilter(filt)
