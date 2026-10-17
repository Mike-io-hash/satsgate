"""Pay a BOLT11 invoice with Nostr Wallet Connect. The URI comes from the environment."""

from __future__ import annotations

import asyncio

from satsgate_mcp.redact import scrub


class NwcError(RuntimeError):
    pass


class NwcWallet:
    def __init__(self, uri: str, *, timeout: float) -> None:
        self._uri = uri
        self._timeout = timeout

    async def pay_invoice(self, invoice: str) -> str:
        if not self._uri:
            raise NwcError("SATSGATE_MCP_NWC_URI is not set. Human pay does not need it.")
        try:
            from nostr_sdk import NostrWalletConnect, NostrWalletConnectUri, PayInvoiceRequest
        except ModuleNotFoundError as exc:
            raise NwcError("nostr-sdk is not installed, so NWC payments cannot run.") from exc
        try:
            parsed = NostrWalletConnectUri.parse(self._uri)
            nwc = NostrWalletConnect(parsed)
            result = await asyncio.wait_for(
                nwc.pay_invoice(PayInvoiceRequest(id=None, invoice=invoice, amount=None)),
                timeout=self._timeout,
            )
        except NwcError:
            raise
        except Exception as exc:
            message = scrub(str(exc), (self._uri, invoice))
            raise NwcError(f"NWC payment failed: {message[:300]}") from None
        preimage = getattr(result, "preimage", None)
        if not isinstance(preimage, str):
            raise NwcError("NWC wallet returned no preimage.")
        return preimage
