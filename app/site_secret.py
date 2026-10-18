"""Encrypt a site origin HMAC secret at rest.

The hosted proxy has to sign ``X-Satsgate-Signature`` with the raw secret, so a
one-way hash is not enough. The sqlite file stores ciphertext. The key is
``SATSGATE_SITE_SECRET_KEY`` (32 bytes, hex), which never goes in the database.

Format (version 1): ``base64(nonce[16] || mac[32] || ciphertext)``.

``mac`` is HMAC-SHA256 over ``satsgate-site-mac-v1 || nonce || ciphertext``.
The ciphertext is the secret XORed with a HMAC-SHA256 keystream keyed by the
same secret and a different domain string. Losing the env key makes old
ciphertext unreadable. Rotating a site secret does not need the old plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_NONCE_LEN = 16
_MAC_LEN = 32
_MAC_PREFIX = b"satsgate-site-mac-v1"
_STREAM_PREFIX = b"satsgate-site-stream-v1"


class SiteSecretError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _keystream(key: bytes, nonce: bytes, size: int) -> bytes:
    blocks: list[bytes] = []
    counter = 0
    produced = 0
    while produced < size:
        block = hmac.new(
            key,
            _STREAM_PREFIX + nonce + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        blocks.append(block)
        produced += len(block)
        counter += 1
    return b"".join(blocks)[:size]


def encrypt_origin_secret(secret: str, key: bytes) -> str:
    if not isinstance(secret, str) or not secret:
        raise SiteSecretError("invalid_origin_secret")
    if not isinstance(key, bytes) or len(key) != 32:
        raise SiteSecretError("site_secret_key_unconfigured")
    nonce = secrets.token_bytes(_NONCE_LEN)
    plain = secret.encode("utf-8")
    stream = _keystream(key, nonce, len(plain))
    ciphertext = bytes(left ^ right for left, right in zip(plain, stream, strict=True))
    mac = hmac.new(key, _MAC_PREFIX + nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(nonce + mac + ciphertext).decode("ascii")


def decrypt_origin_secret(blob: str, key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        raise SiteSecretError("site_secret_key_unconfigured")
    try:
        raw = base64.b64decode(blob.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SiteSecretError("origin_secret_unreadable") from exc
    if len(raw) <= _NONCE_LEN + _MAC_LEN:
        raise SiteSecretError("origin_secret_unreadable")
    nonce = raw[:_NONCE_LEN]
    mac = raw[_NONCE_LEN : _NONCE_LEN + _MAC_LEN]
    ciphertext = raw[_NONCE_LEN + _MAC_LEN :]
    expected = hmac.new(key, _MAC_PREFIX + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise SiteSecretError("origin_secret_unreadable")
    stream = _keystream(key, nonce, len(ciphertext))
    plain = bytes(left ^ right for left, right in zip(ciphertext, stream, strict=True))
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SiteSecretError("origin_secret_unreadable") from exc


def fingerprint_origin_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
