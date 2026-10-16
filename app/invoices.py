"""BOLT11 checks for invoices returned by an LNURL-pay callback.

The preimage proves someone paid *an* invoice with that payment hash. These
checks pin that invoice to the amount, network, metadata, and lifetime we asked
for before a challenge is issued. LUD-21 `verify` is optional: Wallet of Satoshi
does not advertise it, and a missing `verify` field stays a preimage-only proof.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import bolt11

_NETWORK_CURRENCY = {
    "mainnet": "bc",
    "testnet": "tb",
    "signet": "tbs",
    "regtest": "bcrt",
}
_CLOCK_SKEW_SECONDS = 30
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class InvoiceValidationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ValidatedInvoice:
    invoice: str
    payment_hash: str
    amount_sats: int
    expires_at: int
    description_hash: str
    network: str


def expected_description_hash(metadata: str) -> str:
    return hashlib.sha256(metadata.encode("utf-8")).hexdigest()


def validate_bolt11(
    pr: str,
    *,
    amount_sats: int,
    metadata: str,
    network: str,
    min_expiry_seconds: int,
    now: int | None = None,
) -> ValidatedInvoice:
    currency = _NETWORK_CURRENCY.get(network)
    if currency is None:
        raise InvoiceValidationError("network_mismatch")
    if not isinstance(metadata, str) or not metadata:
        raise InvoiceValidationError("description_hash_mismatch")

    try:
        decoded = bolt11.decode(pr)
    except Exception as exc:  # noqa: BLE001
        raise InvoiceValidationError("invalid_bolt11") from exc

    if decoded.currency != currency:
        raise InvoiceValidationError("network_mismatch")

    if decoded.amount_msat is None or int(decoded.amount_msat) != int(amount_sats) * 1000:
        raise InvoiceValidationError("amount_mismatch")

    expected = expected_description_hash(metadata)
    got = (decoded.description_hash or "").lower()
    if got != expected:
        raise InvoiceValidationError("description_hash_mismatch")

    payment_hash = (decoded.payment_hash or "").lower()
    if not _HEX64.fullmatch(payment_hash):
        raise InvoiceValidationError("payment_hash_invalid")

    current = int(time.time()) if now is None else int(now)
    expires_at = int(decoded.expiry_time)
    if expires_at <= current:
        raise InvoiceValidationError("invoice_expired")
    if expires_at + _CLOCK_SKEW_SECONDS < current + int(min_expiry_seconds):
        raise InvoiceValidationError("invoice_expires_too_soon")

    return ValidatedInvoice(
        invoice=pr,
        payment_hash=payment_hash,
        amount_sats=int(amount_sats),
        expires_at=expires_at,
        description_hash=got,
        network=network,
    )


def assert_verify_url_consistent(verify_url: str, payment_hash: str) -> None:
    """If the LUD-21 URL embeds a payment hash, it must be this invoice's hash."""
    segment = urlsplit(verify_url).path.rstrip("/").split("/")[-1]
    if _HEX64.fullmatch(segment) and segment.lower() != payment_hash.lower():
        raise InvoiceValidationError("verify_url_mismatch")


def assert_lud21_settled(data: dict, *, payment_hash: str, preimage_hex: str) -> None:
    """Additional settlement check. Caller already proved sha256(preimage)=payment_hash."""
    if str(data.get("status", "")).upper() != "OK":
        raise InvoiceValidationError("lud21_unavailable")
    if data.get("settled") is not True:
        raise InvoiceValidationError("lud21_not_settled")

    remote_preimage = data.get("preimage")
    if remote_preimage is not None:
        if not isinstance(remote_preimage, str) or not _HEX64.fullmatch(remote_preimage):
            raise InvoiceValidationError("lud21_mismatch")
        digest = hashlib.sha256(bytes.fromhex(remote_preimage)).hexdigest()
        if digest != payment_hash.lower() or remote_preimage.lower() != preimage_hex.lower():
            raise InvoiceValidationError("lud21_mismatch")

    remote_invoice = data.get("pr")
    if isinstance(remote_invoice, str) and remote_invoice:
        try:
            decoded = bolt11.decode(remote_invoice)
        except Exception as exc:  # noqa: BLE001
            raise InvoiceValidationError("lud21_mismatch") from exc
        if (decoded.payment_hash or "").lower() != payment_hash.lower():
            raise InvoiceValidationError("lud21_mismatch")
