"""Read the amount and expiry from a BOLT11 invoice. The signature is not checked."""

from __future__ import annotations

import re

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_HRP = re.compile(r"^ln(?:bc|tb|tbs|bcrt)(\d*)([munp]?)$", re.IGNORECASE)
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
# millisatoshis per unit of the BOLT11 amount
_MILLIS = {"": 100_000_000_000, "m": 100_000_000, "u": 100_000, "n": 100, "p": 0}


def _polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(_GENERATOR):
            if (top >> index) & 1:
                chk ^= generator
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _bech32_payload(invoice: str) -> tuple[str, list[int]] | None:
    compact = invoice.strip()
    if compact.lower() != compact and compact.upper() != compact:
        return None
    compact = compact.lower()
    split_at = compact.rfind("1")
    if split_at < 1 or split_at + 7 > len(compact):
        return None
    hrp = compact[:split_at]
    data: list[int] = []
    for char in compact[split_at + 1 :]:
        index = _CHARSET.find(char)
        if index == -1:
            return None
        data.append(index)
    if _polymod(_hrp_expand(hrp) + data) != 1:
        return None
    return hrp, data[:-6]


def amount_sats(invoice: str) -> int | None:
    """Whole sats, rounded up when the invoice is a fraction of a sat."""
    hrp = invoice.strip().lower().split("1", 1)[0]
    match = _HRP.fullmatch(hrp)
    if match is None or not match.group(1):
        return None
    number = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "p":
        millis = (number + 9) // 10
    else:
        millis = number * _MILLIS[unit]
    if millis <= 0:
        return None
    return (millis + 999) // 1000


def _int_from_groups(groups: list[int]) -> int:
    value = 0
    for group in groups:
        value = (value << 5) | group
    return value


def expires_at(invoice: str) -> int | None:
    """Unix time when the invoice expires. Missing expiry tag means 3600 seconds."""
    decoded = _bech32_payload(invoice)
    if decoded is None:
        return None
    _hrp, data = decoded
    if len(data) < 7:
        return None
    # The last 104 five-bit groups are the 65-byte signature, not a tagged field.
    if len(data) < 7 + 104:
        return None
    timestamp = _int_from_groups(data[:7])
    expiry = 3600
    index = 7
    tagged_end = len(data) - 104
    while index + 3 <= tagged_end:
        field_type = data[index]
        length = (data[index + 1] << 5) | data[index + 2]
        index += 3
        if index + length > tagged_end:
            return None
        field = data[index : index + length]
        index += length
        if field_type == 6:
            expiry = _int_from_groups(field)
    if timestamp <= 0 or expiry < 0:
        return None
    return timestamp + expiry
