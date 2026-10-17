"""Per-payment and rolling 24-hour spend caps for the NWC wallet."""

from __future__ import annotations

from satsgate_mcp.config import Settings
from satsgate_mcp.store import Store

_DAY = 24 * 60 * 60


def refusal(settings: Settings, store: Store, amount_sats: int, now: int) -> str | None:
    """A message when this payment must not be sent. None means the caps allow it."""
    if amount_sats < 1:
        return "The invoice amount is not a positive number of sats."
    if settings.max_payment_sats is None:
        return (
            "NWC payments are refused until SATSGATE_MCP_MAX_PAYMENT_SATS is set "
            "to the most sats one invoice may cost."
        )
    if amount_sats > settings.max_payment_sats:
        return (
            f"Invoice is {amount_sats} sats, above the per-payment cap of {settings.max_payment_sats} sats "
            "(SATSGATE_MCP_MAX_PAYMENT_SATS)."
        )
    if settings.daily_max_sats is None:
        return (
            "NWC payments are refused until SATSGATE_MCP_DAILY_MAX_SATS is set "
            "to the most sats the wallet may spend in any 24 hours."
        )
    spent = store.spent_since(now - _DAY)
    if spent + amount_sats > settings.daily_max_sats:
        return (
            f"This payment would spend {spent + amount_sats} sats in the last 24 hours, "
            f"above the daily cap of {settings.daily_max_sats} sats (SATSGATE_MCP_DAILY_MAX_SATS). "
            f"{spent} sats are already recorded."
        )
    return None
