"""Spend caps. Lightning sats and x402 USDC are separate ledgers.

The sats checks below apply only to NWC invoice payments. They are not reused
for USDC. A USDC requirement is compared with SATSGATE_MCP_MAX_PAYMENT_USD
and SATSGATE_MCP_DAILY_MAX_USD, in atomic units (6 decimals).
"""

from __future__ import annotations

from satsgate_mcp.config import Settings
from satsgate_mcp.store import Store

_DAY = 24 * 60 * 60
_USDC_SCALE = 1_000_000


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


def _usdc(atomic: int) -> str:
    whole, frac = divmod(int(atomic), _USDC_SCALE)
    if frac == 0:
        return f"{whole} USDC"
    text = f"{frac:06d}".rstrip("0")
    return f"{whole}.{text} USDC"


def usd_refusal(settings: Settings, amount_atomic: int, spent_atomic: int) -> str | None:
    """A message when this USDC requirement must not be paid. None means the caps allow it.

    ``spent_atomic`` is USDC already recorded in the rolling 24 hours. This does
    not look at the sats ledger.
    """
    if amount_atomic < 1:
        return "The USDC amount is not a positive number of atomic units."
    shown = _usdc(amount_atomic)
    if settings.max_payment_usd_atomic is None:
        return (
            "x402 payments are refused until SATSGATE_MCP_MAX_PAYMENT_USD is set "
            "to the most USDC one requirement may cost. "
            f"This requirement is {shown} ({amount_atomic} atomic units). Nothing was paid."
        )
    if amount_atomic > settings.max_payment_usd_atomic:
        return (
            f"This requirement is {shown} ({amount_atomic} atomic units), above the per-payment cap of "
            f"{_usdc(settings.max_payment_usd_atomic)} ({settings.max_payment_usd_atomic} atomic units) "
            "(SATSGATE_MCP_MAX_PAYMENT_USD). Nothing was paid."
        )
    if settings.daily_max_usd_atomic is None:
        return (
            "x402 payments are refused until SATSGATE_MCP_DAILY_MAX_USD is set "
            "to the most USDC the agent may approve in any 24 hours. "
            f"This requirement is {shown} ({amount_atomic} atomic units). Nothing was paid."
        )
    if spent_atomic + amount_atomic > settings.daily_max_usd_atomic:
        return (
            f"This payment would approve {_usdc(spent_atomic + amount_atomic)} in the last 24 hours, "
            f"above the daily cap of {_usdc(settings.daily_max_usd_atomic)} "
            f"({settings.daily_max_usd_atomic} atomic units, SATSGATE_MCP_DAILY_MAX_USD). "
            f"{_usdc(spent_atomic)} ({spent_atomic} atomic units) are already recorded. Nothing was paid."
        )
    return None
