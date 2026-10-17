from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

from . import invoices, ssrf

try:
    import bolt11  # noqa: F401
except Exception as exc:  # noqa: BLE001
    raise RuntimeError(
        "Missing dependency 'bolt11'. Install requirements.txt (pip install -r requirements.txt)."
    ) from exc


class LnurlError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Invoice:
    invoice: str  # BOLT11
    payment_hash: str  # hex
    amount_sats: int
    expires_at: int | None  # unix seconds
    verify_url: str | None = None  # LUD-21, when the provider advertises it


class LightningAddressWallet:
    """Generate invoices using a Lightning Address (LNURL-pay).

    No API keys: this uses the provider's public LNURL-pay endpoints.
    Outbound fetches go through the SSRF guard. The BOLT11 invoice is checked
    before it is returned. LUD-21 `verify` is stored when present and is not
    required (Wallet of Satoshi does not advertise it).

    A LUD-12 ``comment`` is not sent unless ``send_comment`` is set and the
    provider advertises ``commentAllowed`` > 0. Some hosts (Alby) otherwise
    put the comment in the invoice description and omit
    ``description_hash = SHA256(metadata)``.
    """

    def __init__(
        self,
        lightning_address: str,
        *,
        cache_ttl_seconds: int = 300,
        fetch_json: Callable | None = None,
        resolver: Callable | None = None,
        network: str = "mainnet",
        send_comment: bool = False,
    ) -> None:
        if "@" not in lightning_address:
            raise ValueError("Invalid Lightning Address (expected user@domain)")
        user, domain = lightning_address.split("@", 1)
        if not user or not domain or "/" in user or "/" in domain or "\\" in domain:
            raise ValueError("Invalid Lightning Address (expected user@domain)")
        self.lightning_address = lightning_address
        self.user = user
        self.domain = domain
        self._cache_ttl_seconds = int(cache_ttl_seconds)
        self._fetch_json = fetch_json
        self._resolver = resolver
        self._network = network
        self._send_comment = bool(send_comment)
        self._cached_payreq: dict | None = None
        self._cached_payreq_until: float = 0.0

    def _get_json(self, url: str, params: dict | None = None) -> dict:
        # Guard even when a test double performs the fetch, so a private callback
        # is rejected before any request is made.
        ssrf.guard_url(url, resolver=self._resolver)
        if self._fetch_json is not None:
            data = self._fetch_json(url, params)
            if not isinstance(data, dict):
                raise LnurlError("lnurl_invalid_response")
            return data
        return ssrf.safe_get_json(url, params=params, resolver=self._resolver)

    def _get_payreq(self) -> dict:
        now = time.time()
        if self._cached_payreq is not None and now < self._cached_payreq_until:
            return self._cached_payreq

        url = f"https://{self.domain}/.well-known/lnurlp/{quote(self.user, safe='')}"
        data = self._get_json(url)

        if data.get("status") == "ERROR":
            raise LnurlError("lnurl_provider_error")
        if data.get("tag") != "payRequest":
            raise LnurlError("lnurl_unexpected_response")
        callback = data.get("callback")
        if not isinstance(callback, str) or not callback:
            raise LnurlError("lnurl_missing_callback")
        metadata = data.get("metadata")
        if not isinstance(metadata, str) or not metadata:
            raise LnurlError("lnurl_missing_metadata")
        # Reject a private or non-https callback before it is cached.
        ssrf.guard_url(callback, resolver=self._resolver)

        self._cached_payreq = data
        self._cached_payreq_until = now + self._cache_ttl_seconds
        return data

    def create_invoice(
        self,
        *,
        amount_sats: int,
        memo: str = "",
        min_expiry_seconds: int = 60,
        expiry_seconds: int | None = None,
    ) -> Invoice:
        del expiry_seconds  # LNURL providers choose the BOLT11 expiry; we only enforce a minimum.
        payreq = self._get_payreq()
        callback = payreq["callback"]
        metadata = payreq["metadata"]

        amount_msat = int(amount_sats) * 1000
        min_sendable = int(payreq.get("minSendable", 0) or 0)
        max_sendable = int(payreq.get("maxSendable", 0) or 0)
        if amount_msat < min_sendable or amount_msat > max_sendable:
            raise ValueError(
                f"Amount out of range for this Lightning Address: {amount_msat} msat "
                f"(min={min_sendable}, max={max_sendable})"
            )

        params: dict[str, str | int] = {"amount": amount_msat}
        comment = self._lud12_comment(payreq, memo)
        if comment:
            params["comment"] = comment

        data = self._get_json(callback, params=params)
        if data.get("status") == "ERROR":
            raise LnurlError("lnurl_provider_error")

        pr = data.get("pr")
        if not isinstance(pr, str) or not pr:
            raise LnurlError("lnurl_missing_invoice")

        validated = invoices.validate_bolt11(
            pr,
            amount_sats=int(amount_sats),
            metadata=metadata,
            network=self._network,
            min_expiry_seconds=int(min_expiry_seconds),
        )

        verify_url = data.get("verify")
        if verify_url is not None:
            if not isinstance(verify_url, str) or not verify_url:
                raise LnurlError("lnurl_invalid_verify_url")
            ssrf.guard_url(verify_url, resolver=self._resolver)
            invoices.assert_verify_url_consistent(verify_url, validated.payment_hash)

        return Invoice(
            invoice=validated.invoice,
            payment_hash=validated.payment_hash,
            amount_sats=validated.amount_sats,
            expires_at=validated.expires_at,
            verify_url=verify_url if isinstance(verify_url, str) else None,
        )

    def _lud12_comment(self, payreq: dict, memo: str) -> str:
        """Return a callback comment only when explicitly enabled and allowed.

        The description_hash check stays strict either way. A comment that a
        provider copies into the BOLT11 description will still be rejected.
        """
        if not self._send_comment or not memo:
            return ""
        comment_allowed = int(payreq.get("commentAllowed", 0) or 0)
        if comment_allowed <= 0:
            return ""
        return memo[:comment_allowed]

    def is_settled(self, *, verify_url: str, payment_hash: str, preimage_hex: str) -> bool:
        """LUD-21 settlement probe. Raises if the provider does not confirm payment."""
        confirm_lud21(
            verify_url=verify_url,
            payment_hash=payment_hash,
            preimage_hex=preimage_hex,
            fetch_json=self._fetch_json,
            resolver=self._resolver,
        )
        return True


def confirm_lud21(
    *,
    verify_url: str,
    payment_hash: str,
    preimage_hex: str,
    fetch_json: Callable | None = None,
    resolver: Callable | None = None,
) -> None:
    """Optional LUD-21 check. No-op is the caller's job when the provider omitted `verify`."""
    ssrf.guard_url(verify_url, resolver=resolver)
    if fetch_json is not None:
        data = fetch_json(verify_url, None)
        if not isinstance(data, dict):
            raise LnurlError("lnurl_invalid_response")
    else:
        data = ssrf.safe_get_json(verify_url, resolver=resolver)
    invoices.assert_lud21_settled(data, payment_hash=payment_hash, preimage_hex=preimage_hex)
