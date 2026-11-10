"""HMAC for seller security webhooks.

The key is the UTF-8 bytes of the entire ``whsec_`` string returned once at
create or secret rotation. The signed message is ``{unix_timestamp}.{raw_body}``.
Receivers must verify the raw HTTP body before they parse JSON, and they
should reject a timestamp more than 300 seconds from their clock.
"""

from __future__ import annotations

import hashlib
import hmac

TOLERANCE_SECONDS = 300


def signature(secret: str, timestamp: int, body: bytes) -> str:
    message = f"{int(timestamp)}.".encode("ascii") + body
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return "v1=" + digest


def verify(
    secret: str,
    timestamp: int,
    body: bytes,
    header: str,
    *,
    now: int,
    tolerance: int = TOLERANCE_SECONDS,
) -> bool:
    """Constant-time check of ``Satsgate-Webhook-Signature`` plus the skew window."""
    if not isinstance(header, str) or not isinstance(body, (bytes, bytearray)):
        return False
    try:
        stamp = int(timestamp)
        current = int(now)
    except (TypeError, ValueError):
        return False
    if abs(current - stamp) > int(tolerance):
        return False
    expected = signature(secret, stamp, bytes(body))
    return hmac.compare_digest(expected, header)
