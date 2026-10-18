"""HMAC the origin checks before it trusts a forwarded request.

Message: ``{unix}|{METHOD}|{target}|{payment_hash}``

``target`` is the raw request target the origin receives: the path, then ``?``
and the raw query string when a query is present. Percent-encoding is kept.
The method is uppercased. ``payment_hash`` is lowercase hex.

Header: ``t=<unix>, v1=<hex hmac-sha256 of the message>``

This is the same scheme as satsgate-proxy 0.8.0.
"""

from __future__ import annotations

import hashlib
import hmac


def origin_message(*, timestamp: int, method: str, target: str, payment_hash: str) -> str:
    return f"{int(timestamp)}|{method.upper()}|{target}|{payment_hash.lower()}"


def sign_origin(
    *,
    secret: str,
    timestamp: int,
    method: str,
    target: str,
    payment_hash: str,
) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        origin_message(
            timestamp=timestamp,
            method=method,
            target=target,
            payment_hash=payment_hash,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"t={int(timestamp)}, v1={digest}"
