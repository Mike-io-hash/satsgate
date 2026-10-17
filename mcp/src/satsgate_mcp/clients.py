"""Parsers that mirror lnget and Alby fetch402, so a proxy 402 can be checked in CI."""

from __future__ import annotations

import re

# lnget requires the macaroon (or token) parameter before invoice, and Aperture's
# credential grammar is standard base64.
LNGET_CHALLENGE = re.compile(
    r'(?i)(?:L402|LSAT) (?:macaroon|token)="([A-Za-z0-9+/=]+)", invoice="([^"]+)"'
)


def parse_lnget(header: str) -> tuple[str, str] | None:
    match = LNGET_CHALLENGE.search(header.strip())
    if match is None:
        return None
    macaroon, invoice = match.group(1), match.group(2)
    if header.find(match.group(0)) == -1:
        return None
    mac_at = header.lower().find("macaroon=")
    if mac_at == -1:
        mac_at = header.lower().find("token=")
    inv_at = header.lower().find("invoice=")
    if mac_at == -1 or inv_at == -1 or mac_at > inv_at:
        return None
    return macaroon, invoice


def parse_fetch402(header: str) -> tuple[str, str] | None:
    """Alby fetch402 drops one leading L402 or LSAT scheme, then reads the quotes.

    A global strip of those words would also delete them from inside the macaroon.
    Satsgate re-rolls a macaroon whose base64 contains either word so that strip is safe.
    """
    text = header.strip()
    text = re.sub(r"^(?:L402|LSAT)\s+", "", text, count=1, flags=re.IGNORECASE)
    macaroon_match = re.search(r'(?:macaroon|token)="([^"]+)"', text, flags=re.IGNORECASE)
    invoice_match = re.search(r'invoice="([^"]+)"', text, flags=re.IGNORECASE)
    if macaroon_match is None or invoice_match is None:
        return None
    if macaroon_match.start() > invoice_match.start():
        return None
    return macaroon_match.group(1), invoice_match.group(1)


def fetch402_global_strip_keeps_macaroon(header: str, macaroon: str) -> bool:
    """True when deleting every L402 and LSAT substring still leaves the macaroon."""
    stripped = header.replace("L402", "").replace("LSAT", "").replace("l402", "").replace("lsat", "")
    return macaroon in stripped
