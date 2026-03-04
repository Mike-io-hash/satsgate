from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

try:
    import bolt11
except Exception as e:  # noqa: BLE001
    raise RuntimeError(
        "Missing dependency 'bolt11'. Install requirements.txt (pip install -r requirements.txt)."
    ) from e


@dataclass(frozen=True)
class Invoice:
    invoice: str  # BOLT11
    payment_hash: str  # hex
    amount_sats: int
    expires_at: int | None  # unix seconds (if derivable)


class LightningAddressWallet:
    """Generate invoices using a Lightning Address (LNURL-pay).

    No API keys required: it uses the provider's public LNURL-pay endpoints.

    Important:
    - This is for *receiving* payments.
    - The payer gets the preimage when the invoice is settled.
    """

    def __init__(self, lightning_address: str, *, cache_ttl_seconds: int = 300) -> None:
        if "@" not in lightning_address:
            raise ValueError("Invalid Lightning Address (expected user@domain)")
        self.lightning_address = lightning_address
        self.user, self.domain = lightning_address.split("@", 1)
        self._cache_ttl_seconds = int(cache_ttl_seconds)
        self._cached_payreq: dict | None = None
        self._cached_payreq_until: float = 0.0

    def _get_payreq(self) -> dict:
        now = time.time()
        if self._cached_payreq is not None and now < self._cached_payreq_until:
            return self._cached_payreq

        url = f"https://{self.domain}/.well-known/lnurlp/{self.user}"
        r = httpx.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()

        if data.get("tag") != "payRequest":
            raise RuntimeError("LNURL-pay: unexpected response (tag != payRequest)")
        if "callback" not in data:
            raise RuntimeError("LNURL-pay: missing callback")

        self._cached_payreq = data
        self._cached_payreq_until = now + self._cache_ttl_seconds
        return data

    def create_invoice(self, *, amount_sats: int, memo: str = "") -> Invoice:
        payreq = self._get_payreq()
        callback = payreq["callback"]

        amount_msat = int(amount_sats) * 1000
        min_sendable = int(payreq.get("minSendable", 0))
        max_sendable = int(payreq.get("maxSendable", 0))
        if amount_msat < min_sendable or amount_msat > max_sendable:
            raise ValueError(
                f"Amount out of range for this Lightning Address: {amount_msat} msat (min={min_sendable}, max={max_sendable})"
            )

        params: dict[str, str | int] = {"amount": amount_msat}
        comment_allowed = int(payreq.get("commentAllowed", 0) or 0)
        if memo and comment_allowed > 0:
            params["comment"] = memo[:comment_allowed]

        r = httpx.get(callback, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()

        pr = data.get("pr")
        if not isinstance(pr, str) or not pr:
            raise RuntimeError("LNURL-pay: missing 'pr' (invoice)")

        # Decode BOLT11 to extract payment_hash (needed for L402)
        inv = bolt11.decode(pr)
        payment_hash = getattr(inv, "payment_hash", None)
        if not isinstance(payment_hash, str) or len(payment_hash) != 64:
            # Some decoders return dict
            if isinstance(inv, dict) and isinstance(inv.get("payment_hash"), str):
                payment_hash = inv["payment_hash"]
            else:
                raise RuntimeError("Could not extract payment_hash from BOLT11")

        expires_at: int | None = None
        try:
            # bolt11 lib uses `date` (unix seconds) instead of `timestamp`
            if hasattr(inv, "date"):
                ts = int(getattr(inv, "date"))
            elif hasattr(inv, "timestamp"):
                ts = int(getattr(inv, "timestamp"))
            else:
                ts = int(inv.get("date") or inv.get("timestamp"))

            exp = int(getattr(inv, "expiry")) if hasattr(inv, "expiry") else int(inv.get("expiry"))
            expires_at = ts + exp
        except Exception:
            expires_at = None

        return Invoice(
            invoice=pr,
            payment_hash=payment_hash,
            amount_sats=int(amount_sats),
            expires_at=expires_at,
        )
