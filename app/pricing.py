"""Model B prices. Integer milisatoshis only. One formula for every live debit.

Fees round down. Top-up credits, including the bonus, round up. Both favour
the seller. Buyer-facing USD quotes stay in ``app.rates`` and are not computed
here.
"""

from __future__ import annotations

from . import config

CONVERSION_MSAT = 2000
RETIRED_PLAN_IDS = ("trial", "starter", "growth", "scale", "hyper", "mega")
PACKS_RETIRED_HINT = (
    "Credit packs are retired. Top up any amount with POST /v1/topup/lightning "
    "or POST /v1/topup/usdc."
)


def require_int(value: object, name: str) -> int:
    """Reject bools and floats. A money amount is a Python int."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int")
    return value


def round_down_msat(numerator: int, denominator: int) -> int:
    """Integer floor. ``12489 / 10`` is the 1,248.9 msat fee stored as 1,248."""
    numerator = require_int(numerator, "numerator")
    denominator = require_int(denominator, "denominator")
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    if numerator < 0:
        raise ValueError("money numerator must be non-negative")
    return numerator // denominator


def round_up_msat(numerator: int, denominator: int) -> int:
    """Integer ceil. ``10001 / 10`` is the 1,000.1 msat credit stored as 1,001."""
    numerator = require_int(numerator, "numerator")
    denominator = require_int(denominator, "denominator")
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    if numerator < 0:
        raise ValueError("money numerator must be non-negative")
    return (numerator + denominator - 1) // denominator


def balance_sats_text(balance_msat: int) -> str:
    """Three decimal places. Derived for display. Never stored."""
    balance_msat = require_int(balance_msat, "balance_msat")
    sign = "-" if balance_msat < 0 else ""
    whole, frac = divmod(abs(balance_msat), 1000)
    return f"{sign}{whole}.{frac:03d}"


def ten_percent_msat(item_msat: int) -> int:
    item_msat = require_int(item_msat, "item_msat")
    return (item_msat * int(config.FEE_CAP_BPS)) // 10_000


def base_fee_msat(item_msat: int) -> int:
    """``min(standard fee, 10% of the item)``. The cap wins under 20 sats."""
    item_msat = require_int(item_msat, "item_msat")
    if item_msat <= 0:
        raise ValueError("invalid price")
    return min(int(config.FEE_MSAT), ten_percent_msat(item_msat))


def lightning_fee_msat(item_msat: int) -> int:
    """Lightning: the cap wins. The USDC floor is not applied."""
    return base_fee_msat(item_msat)


def usdc_fee_msat(item_msat: int, floor_msat: int) -> int:
    """USDC: ``max(base, floor)``. The floor is CDP's cost, with no margin."""
    floor_msat = require_int(floor_msat, "floor_msat")
    if floor_msat < 0:
        raise ValueError("invalid floor")
    return max(base_fee_msat(item_msat), floor_msat)


def item_msat_from_usd(usd_atomic: int, rate_num: int, rate_den: int) -> int:
    """Floor of a USDC item in msat at a locked accounting rate.

    ``rate_num / rate_den`` is USD per BTC, the same scaling as ``app.rates.Rate``.
    """
    usd_atomic = require_int(usd_atomic, "usd_atomic")
    rate_num = require_int(rate_num, "rate_num")
    rate_den = require_int(rate_den, "rate_den")
    if usd_atomic <= 0 or rate_num <= 0 or rate_den <= 0:
        raise ValueError("invalid price")
    return (usd_atomic * rate_den * 100_000) // rate_num


def floor_msat_at_rate(rate_num: int, rate_den: int, usd_atomic: int | None = None) -> int:
    """US$0.001 (or the configured floor) converted down to msat."""
    atomic = int(config.USDC_FEE_FLOOR_USD_ATOMIC) if usd_atomic is None else require_int(usd_atomic, "usd_atomic")
    if atomic <= 0:
        return 0
    return item_msat_from_usd(atomic, rate_num, rate_den)


def sats_ceil_from_usd(usd_atomic: int, rate_num: int, rate_den: int) -> int:
    """Ceil of a USDC top-up into sats, before the bonus. Favours the seller."""
    usd_atomic = require_int(usd_atomic, "usd_atomic")
    rate_num = require_int(rate_num, "rate_num")
    rate_den = require_int(rate_den, "rate_den")
    if usd_atomic <= 0 or rate_num <= 0 or rate_den <= 0:
        raise ValueError("invalid amount")
    return round_up_msat(usd_atomic * rate_den * 100, rate_num)


def bonus_bps(principal_sats: int) -> int:
    """Per top-up, not lifetime, not stacked. 0 / 1000 / 2000 basis points."""
    principal_sats = require_int(principal_sats, "principal_sats")
    if principal_sats >= 1_000_000:
        return 2000
    if principal_sats >= 100_000:
        return 1000
    return 0


def credit_msat_for_principal(principal_sats: int) -> int:
    """``ceil(principal_sats * (1 + bonus) * 1000)`` in integers."""
    principal_sats = require_int(principal_sats, "principal_sats")
    if principal_sats < 0:
        raise ValueError("invalid amount")
    bps = bonus_bps(principal_sats)
    # principal * (10000 + bps) / 10000 * 1000
    return round_up_msat(principal_sats * (10_000 + bps) * 1000, 10_000)


def estimate_unlocks(balance_msat: int, free_remaining: int, *, fee_msat: int | None = None) -> dict:
    """Headline count at the standard 2-sat rate. Never negative. Not a reservation."""
    balance_msat = require_int(balance_msat, "balance_msat")
    free_remaining = require_int(free_remaining, "free_remaining")
    fee = int(config.FEE_MSAT) if fee_msat is None else require_int(fee_msat, "fee_msat")
    if fee < 1:
        raise ValueError("standard fee must be positive")
    if balance_msat < 0:
        balance_msat = 0
    free = max(0, free_remaining)
    paid = balance_msat // fee
    rate_words = "2-sat (2,000 msat)" if fee == 2000 else f"{fee} msat"
    return {
        "estimated_unlocks_remaining": free + paid,
        "free_unlocks_remaining": free,
        "paid_unlocks_estimate": paid,
        "unlocks_estimate_basis": {
            "kind": "standard_fee_msat",
            "standard_fee_msat": fee,
            "note": (
                f"Estimate at the standard {rate_words} rate. Actual remaining unlocks may be "
                "higher when the 10% cap makes the fee smaller, or lower when the USDC floor "
                "makes the fee larger than 2 sats (if BTC is cheap). The free part is this "
                "account's shared bucket, and the paid part is this account's balance only, so "
                "the sum is what this account could still do if it were the only one drawing on "
                "the bucket. Not a reservation, and not a guarantee."
            ),
        },
    }


def plans_document() -> dict:
    """Machine-readable model B. Not a Trial–Mega catalogue."""
    return {
        "ok": True,
        "model": "B",
        "unit": "msat",
        "quota": int(config.FREE_QUOTA),
        "quota_period": "utc_month",
        "quota_resets": "day 1 00:00:00 UTC",
        "quota_accumulates": False,
        "quota_shared_by": "same verified EVM payee or same Lightning Address",
        "fee_msat": int(config.FEE_MSAT),
        "fee_sats": int(config.FEE_MSAT) // 1000,
        "fee_cap_bps": int(config.FEE_CAP_BPS),
        "fee_cap": "10%",
        "usdc_floor_usd_atomic": int(config.USDC_FEE_FLOOR_USD_ATOMIC),
        "usdc_floor_usd": "0.001",
        "usdc_floor_applies_until": "batch settlement exists; no date is promised",
        "lightning_floor": False,
        "topup_min_sats": int(config.TOPUP_MIN_SATS),
        "topup_min_usd_atomic": int(config.TOPUP_MIN_USD_ATOMIC),
        "bonus_tiers": [
            {"min_principal_sats": 0, "max_principal_sats": 99_999, "bonus_bps": 0},
            {"min_principal_sats": 100_000, "max_principal_sats": 999_999, "bonus_bps": 1000},
            {"min_principal_sats": 1_000_000, "max_principal_sats": None, "bonus_bps": 2000},
        ],
        "bonus_scope": "per top-up, not lifetime, not stacked",
        "prepaid_expires": False,
        "signup": "POST /v1/accounts",
        "topup_lightning": "/v1/topup/lightning",
        "topup_usdc": "/v1/topup/usdc",
    }


def packs_retired_body() -> dict:
    return {
        "ok": False,
        "error": "packs_retired",
        "hint": PACKS_RETIRED_HINT,
        "topup_lightning": "/v1/topup/lightning",
        "topup_usdc": "/v1/topup/usdc",
    }
