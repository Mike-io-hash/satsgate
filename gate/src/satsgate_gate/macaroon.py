"""Read the payment hash and resource out of a satsgate macaroon.

This does not verify the signature. Core does that on verify and status.
"""

from __future__ import annotations

import logging
import re

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
log = logging.getLogger("satsgate_gate")


def macaroon_fields(token: str) -> dict[str, str] | None:
    compact = "".join(str(token).split())
    if not compact:
        return None
    try:
        from pymacaroons import Macaroon

        mac = Macaroon.deserialize(compact)
        fields: dict[str, str] = {}
        for caveat in mac.caveats:
            raw = caveat.caveat_id
            text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
            if "=" not in text:
                continue
            key, value = text.split("=", 1)
            fields[key] = value
    except Exception:
        log.debug("macaroon could not be decoded")
        return None
    payment_hash = fields.get("ph", "")
    if not _HEX64.fullmatch(payment_hash):
        return None
    fields["ph"] = payment_hash.lower()
    return fields
