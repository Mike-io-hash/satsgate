from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Invoice:
    invoice: str
    payment_hash: str  # hex
    amount_sats: int
    expires_at: int  # unix seconds


class MockWallet:
    """Fake wallet for development.

    - Generates a fake "invoice" string
    - Generates a secret preimage (hex)
    - Computes payment_hash = sha256(preimage)

    In real Lightning:
    - the payer pays the invoice
    - the payer gets the preimage as proof
    """

    def __init__(self) -> None:
        self._preimages: dict[str, str] = {}  # payment_hash -> preimage_hex
        self._expires: dict[str, int] = {}  # payment_hash -> expires_at

    def create_invoice(self, *, amount_sats: int, memo: str = "", expiry_seconds: int = 600) -> Invoice:
        preimage = secrets.token_bytes(32)
        preimage_hex = preimage.hex()
        payment_hash = hashlib.sha256(preimage).hexdigest()

        expires_at = int(time.time()) + int(expiry_seconds)
        self._preimages[payment_hash] = preimage_hex
        self._expires[payment_hash] = expires_at

        # Fake invoice (MVP only). In prod this is a real BOLT11 invoice.
        invoice = f"lnmock{amount_sats}sats:{payment_hash}"

        return Invoice(
            invoice=invoice,
            payment_hash=payment_hash,
            amount_sats=amount_sats,
            expires_at=expires_at,
        )

    def dev_get_preimage(self, payment_hash: str) -> str | None:
        """DEV ONLY: simulates a paid invoice and returns the preimage."""
        exp = self._expires.get(payment_hash)
        if exp is None:
            return None
        if int(time.time()) > exp:
            return None
        return self._preimages.get(payment_hash)
