"""MCP tools. Wallet URIs and API keys are read from the environment, never from arguments."""

from __future__ import annotations

from mcp.server.mcpserver import Image, MCPServer
from mcp.types import ToolAnnotations

from satsgate_mcp import __version__
from satsgate_mcp.buyer import Buyer, BuyerError, Presentation
from satsgate_mcp.config import ConfigError, Settings, load_settings
from satsgate_mcp.store import Store
from satsgate_mcp.urls import UrlError

_INSTRUCTIONS = (
    "Satsgate buyer tools. discover and quote read a 402 and do not pay. "
    "pay_and_fetch with mode human returns a BOLT11 invoice and a QR; then call check_payment "
    "with the payment_hash until the content arrives. No preimage is required. "
    "mode nwc pays from the wallet configured in the server environment, never from a tool argument. "
    "A used-up token is quoted again and is not paid inside the same call unless auto-pay is enabled "
    "and the invoice is inside the configured budget. "
    "Do not ask the user to paste a wallet connection string or an API key into the chat."
)

_READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)
_PAY = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)


def _error(exc: Exception) -> dict:
    if isinstance(exc, BuyerError):
        return {"ok": False, "error": exc.code, "detail": exc.message}
    if isinstance(exc, UrlError):
        return {"ok": False, "error": "invalid_url", "detail": str(exc)}
    if isinstance(exc, ConfigError):
        return {"ok": False, "error": "config", "detail": str(exc)}
    return {"ok": False, "error": "internal", "detail": "The tool failed before a payment was made."}


def _present(result: Presentation) -> list:
    if result.qr_png:
        return [result.payload, Image(data=result.qr_png, format="png")]
    return [result.payload]


def build_server(buyer: Buyer | None = None, settings: Settings | None = None) -> MCPServer:
    if buyer is None:
        loaded = settings or load_settings()
        buyer = Buyer(loaded, store=Store(loaded.data_dir))
    mcp = MCPServer(
        "satsgate",
        instructions=_INSTRUCTIONS,
        version=__version__,
    )

    @mcp.tool(annotations=_READ, structured_output=False)
    async def discover(url: str, method: str = "GET") -> dict:
        """Request a URL with no payment and read a 402 L402 challenge.

        Returns the price in sats, max_uses, access_seconds, and invoice expiry when the
        server sends them. Does not pay and does not reuse a token.
        """
        try:
            return await buyer.discover(url, method)
        except (BuyerError, UrlError, ConfigError) as exc:
            return _error(exc)

    @mcp.tool(annotations=_READ, structured_output=False)
    async def quote(url: str, method: str = "GET") -> dict:
        """Same lookup as discover, with a short summary a person can read. Does not pay."""
        try:
            return await buyer.quote(url, method)
        except (BuyerError, UrlError, ConfigError) as exc:
            return _error(exc)

    @mcp.tool(annotations=_PAY, structured_output=False)
    async def pay_and_fetch(url: str, mode: str = "human", method: str = "GET", body: str | None = None) -> list:
        """Fetch a paywalled URL.

        mode human returns the invoice, a text QR, and a PNG. Then call check_payment.
        mode nwc pays with the NWC URI from the environment, inside the sats budget.
        A token that still has uses or time left is reused and is not paid again.
        A fresh 402 token_used_up is returned as a new quote unless SATSGATE_MCP_AUTO_PAY is on
        and the new invoice is inside the budget.
        """
        try:
            return _present(await buyer.pay_and_fetch(url, mode, method, body))
        except (BuyerError, UrlError, ConfigError) as exc:
            return [_error(exc)]

    @mcp.tool(annotations=_READ, structured_output=False)
    async def check_payment(payment_hash: str) -> list:
        """Poll a human payment and, once it has settled, fetch the URL.

        One call does one poll. payment_pending means call again after retry_after_seconds.
        When a restricted key and resource are known, this first calls the core
        no-preimage status route with consume=false, then retries the URL with the macaroon.
        Without a key, the URL itself is the poll: the proxy asks core. No preimage is sent.
        """
        try:
            return _present(await buyer.check_payment(payment_hash))
        except (BuyerError, UrlError, ConfigError) as exc:
            return [_error(exc)]

    @mcp.tool(annotations=_READ, structured_output=False)
    async def credits_balance() -> dict:
        """Read GET /v1/balance with the optional restricted key. A restricted key is refused by core.

        This tool does not top up, change the payee, or create keys.
        """
        try:
            return await buyer.credits_balance()
        except (BuyerError, UrlError, ConfigError) as exc:
            return _error(exc)

    @mcp.tool(annotations=_READ, structured_output=False)
    async def challenge_status(payment_hash: str, expected_resource: str | None = None) -> dict:
        """Read GET /v1/paywall/status with consume=false. Does not take a use and does not pay.

        The macaroon is the one stored by discover or pay_and_fetch. It is not a tool argument.
        """
        try:
            return await buyer.challenge_status(payment_hash, expected_resource)
        except (BuyerError, UrlError, ConfigError) as exc:
            return _error(exc)

    @mcp.tool(annotations=_READ, structured_output=False)
    async def list_sites() -> dict:
        """Read the optional JSON registry from SATSGATE_MCP_REGISTRY.

        This is a local file or URL. A hosted Satsgate registry is not available yet.
        """
        try:
            return await buyer.list_sites()
        except (BuyerError, UrlError, ConfigError) as exc:
            return _error(exc)

    return mcp
