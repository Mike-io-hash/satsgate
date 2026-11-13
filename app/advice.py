"""Seller-facing advice. Never attached to a buyer's 402."""

from __future__ import annotations

from . import config
from .pricing import balance_sats_text, estimate_unlocks

_ADD_LIGHTNING = {
    "code": "add_lightning",
    "message": (
        "This item is under US$0.01, the card-network minimum. "
        "Add a Lightning Address so agents can pay it. "
        "USDC stays available at US$0.01 and above."
    ),
    "actions": [
        {
            "action": "add_lightning",
            "method": "POST",
            "url": "/v1/client/payee",
            "docs": "docs/hosted-gate-terms.md",
        }
    ],
}

_USD_CENT = 10_000  # 6-decimal USDC atoms


def add_lightning_for_price(
    *,
    price_currency: str | None,
    price_usd_atomic: int | None,
    price_sats: int | None,
    has_lightning: bool,
    buyer_usd_atomic: int | None,
    rate_known: bool,
) -> dict | None:
    """Return add_lightning, or None. A stale sats conversion never guesses."""
    if has_lightning:
        return None
    if price_currency == "usd" and price_usd_atomic is not None:
        if int(price_usd_atomic) < _USD_CENT:
            return dict(_ADD_LIGHTNING)
        return None
    if price_currency == "sats" and price_sats is not None:
        if not rate_known or buyer_usd_atomic is None:
            return None
        if int(buyer_usd_atomic) < _USD_CENT:
            return dict(_ADD_LIGHTNING)
    return None


def balance_advice(
    *,
    balance_msat: int,
    free_remaining: int,
    resets_at: str,
    resets_local: str,
    cannot_cover_fee: bool = False,
) -> dict | None:
    """Low or zero status. Repeats on responses; it is not the edge event."""
    balance_msat = int(balance_msat)
    free_remaining = max(0, int(free_remaining))
    estimate = estimate_unlocks(balance_msat, free_remaining)
    threshold = int(config.LOW_BALANCE_MSAT)
    if balance_msat == 0 and free_remaining == 0:
        code = "balance_zero"
        message = (
            "Your prepaid balance is zero. About 0 unlocks remaining at the standard 2-sat rate "
            "(0 free this month). This is an estimate at the standard 2-sat rate. "
            "Actual remaining unlocks vary with the 10% cap and the USDC floor."
        )
    elif cannot_cover_fee and 0 < balance_msat:
        code = "balance_low"
        message = (
            f"Your prepaid balance cannot cover this item ({balance_msat} msat left). "
            f"About {estimate['estimated_unlocks_remaining']} unlocks remaining at the standard 2-sat rate "
            f"({free_remaining} free this month). This is an estimate at the standard 2-sat rate."
        )
    elif 0 < balance_msat <= threshold:
        code = "balance_low"
        message = (
            f"Your prepaid balance is low. About {estimate['estimated_unlocks_remaining']} unlocks remaining "
            f"at the standard 2-sat rate ({free_remaining} free this month). "
            "This is an estimate at the standard 2-sat rate. "
            "Actual remaining unlocks vary with the 10% cap and the USDC floor."
        )
    else:
        return None
    return {
        "code": code,
        "message": message,
        "balance_msat": balance_msat,
        "balance_sats": balance_sats_text(balance_msat),
        "threshold_msat": threshold,
        "quota_remaining": free_remaining,
        "quota_resets_at": resets_at,
        "quota_resets_at_local": resets_local,
        **estimate,
        "forecast": {"status": "insufficient_data"},
        "actions": [
            {"action": "topup_lightning", "url": "/v1/topup/lightning"},
            {"action": "topup_usdc", "url": "/v1/topup/usdc"},
        ],
    }
