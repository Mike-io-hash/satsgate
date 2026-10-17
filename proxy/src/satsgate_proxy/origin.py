"""HMAC the origin checks before it trusts a forwarded request.

Message: ``{unix}|{METHOD}|{target}|{payment_hash}``

``target`` is the raw request target the origin receives: the path, then ``?``
and the raw query string when a query is present. Percent-encoding is kept.
The method is uppercased. ``payment_hash`` is lowercase hex.

Header: ``t=<unix>, v1=<hex hmac-sha256 of the message>``
"""

from __future__ import annotations

import hashlib
import hmac
import re

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def _parse_signature(header: str) -> tuple[int, str] | None:
    timestamp: int | None = None
    digest: str | None = None
    for part in (header or "").split(","):
        item = part.strip()
        if item.startswith("t="):
            raw = item[2:].strip()
            if raw.isdigit():
                timestamp = int(raw)
        elif item.startswith("v1="):
            digest = item[3:].strip().lower()
    if timestamp is None or digest is None or not _HEX64.fullmatch(digest):
        return None
    return timestamp, digest


def verify_origin_signature(
    *,
    secret: str,
    header: str,
    method: str,
    target: str,
    payment_hash: str,
    now: int,
    max_skew_seconds: int,
) -> bool:
    parsed = _parse_signature(header)
    if parsed is None or not secret:
        return False
    timestamp, digest = parsed
    if abs(int(now) - timestamp) > int(max_skew_seconds):
        return False
    expected = sign_origin(
        secret=secret,
        timestamp=timestamp,
        method=method,
        target=target,
        payment_hash=payment_hash,
    )
    expected_digest = expected.split("v1=", 1)[1]
    return hmac.compare_digest(expected_digest, digest)


def request_target(scope: dict) -> str:
    """Raw path plus raw query, the string both sides sign."""
    raw_path = scope.get("raw_path") or scope.get("path") or "/"
    if isinstance(raw_path, bytes):
        path = raw_path.decode("latin-1")
    else:
        path = str(raw_path)
    if "?" in path:
        path = path.split("?", 1)[0]
    query = scope.get("query_string") or b""
    if isinstance(query, bytes):
        query_text = query.decode("latin-1")
    else:
        query_text = str(query)
    if query_text:
        return f"{path}?{query_text}"
    return path
