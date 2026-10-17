"""Verify X-Satsgate-Signature on a request satsgate-proxy forwarded.

Copy this into the origin. Set SATSGATE_ORIGIN_SECRET to the proxy's secret.

The signed message is ``{unix}|{METHOD}|{target}|{payment_hash}``.
``target`` is the raw path, plus ``?`` and the raw query when there is one.
Percent-encoding is not decoded. The method is uppercased. The payment hash
is lowercase hex. The header is ``t=<unix>, v1=<hex hmac-sha256>``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time

from fastapi import HTTPException, Request

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def origin_message(*, timestamp: int, method: str, target: str, payment_hash: str) -> str:
    return f"{int(timestamp)}|{method.upper()}|{target}|{payment_hash.lower()}"


def signed_target(scope: dict) -> str:
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
    max_skew_seconds: int = 300,
) -> bool:
    parsed = _parse_signature(header)
    if parsed is None or not secret:
        return False
    timestamp, digest = parsed
    if abs(int(now) - timestamp) > int(max_skew_seconds):
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        origin_message(
            timestamp=timestamp,
            method=method,
            target=target,
            payment_hash=payment_hash,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, digest)


def require_origin(request: Request) -> str:
    """FastAPI dependency. Rejects a missing or bad origin signature."""
    secret = os.environ.get("SATSGATE_ORIGIN_SECRET", "")
    header = request.headers.get("x-satsgate-signature", "")
    payment_hash = request.headers.get("x-satsgate-payment-hash", "")
    try:
        max_skew = int(os.environ.get("SATSGATE_ORIGIN_MAX_SKEW_SECONDS", "300"))
    except ValueError:
        max_skew = 300
    ok = verify_origin_signature(
        secret=secret,
        header=header,
        method=request.method,
        target=signed_target(request.scope),
        payment_hash=payment_hash,
        now=int(time.time()),
        max_skew_seconds=max_skew,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="invalid origin signature")
    return payment_hash
