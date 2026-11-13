"""Lock a Satsgate fee, then debit that exact amount.

``cost_credits`` is not a fee. A zero cost is the existing test-mode signal:
no debit and no free-quota slot. Every other live debit uses the formula, or
the milisat amount stored on the challenge when it was issued.
"""

from __future__ import annotations

import sqlite3

from . import config
from .pricing import item_msat_from_usd, lightning_fee_msat, usdc_fee_msat
from .quota import free_remaining


def lightning_item_fee(amount_sats: int) -> int:
    if int(amount_sats) <= 0:
        raise ValueError("invalid price")
    return lightning_fee_msat(int(amount_sats) * 1000)


def usdc_item_fee(item_msat: int, *, rate_num: int, rate_den: int) -> int:
    from .pricing import floor_msat_at_rate

    return usdc_fee_msat(int(item_msat), floor_msat_at_rate(int(rate_num), int(rate_den)))


def resolve_fee(conn: sqlite3.Connection, payment_hash: str, cost: int) -> tuple[int, bool]:
    """Return ``(fee_msat, test_mode)``. ``cost == 0`` is test mode and ignores the formula."""
    if int(cost) == 0:
        return 0, True
    row = conn.execute(
        "SELECT * FROM paywall_challenges WHERE payment_hash = ?",
        (payment_hash,),
    ).fetchone()
    if row is not None and int(row["test_mode"] or 0) == 1:
        return 0, True
    if row is not None and row["satsgate_fee_msat"] is not None:
        return int(row["satsgate_fee_msat"]), False
    if row is not None and row["amount_sats"] is not None:
        return lightning_item_fee(int(row["amount_sats"])), False
    offer = conn.execute(
        "SELECT * FROM payment_offers WHERE payment_hash = ?",
        (payment_hash,),
    ).fetchone()
    if offer is not None and offer["satsgate_fee_msat"] is not None:
        return int(offer["satsgate_fee_msat"]), False
    if offer is not None and offer["amount_sats"]:
        return lightning_item_fee(int(offer["amount_sats"])), False
    if offer is not None and offer["amount_usd_atomic"] and offer["rate_num"] and offer["rate_den"]:
        item = item_msat_from_usd(int(offer["amount_usd_atomic"]), int(offer["rate_num"]), int(offer["rate_den"]))
        return usdc_item_fee(item, rate_num=int(offer["rate_num"]), rate_den=int(offer["rate_den"])), False
    raise ValueError("invalid price")


def can_fund(conn: sqlite3.Connection, *, client_id: int, fee_msat: int, now: int, test_mode: bool) -> bool:
    if test_mode:
        return True
    if free_remaining(conn, int(client_id), int(now)) > 0:
        return True
    row = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (int(client_id),)).fetchone()
    balance = 0 if row is None else int(row["balance_msat"])
    return balance >= int(fee_msat)


def seller_shortfall(conn: sqlite3.Connection, *, client_id: int, fee_msat: int, now: int) -> bool:
    """True when this live item cannot be covered by a free slot or prepaid balance."""
    return not can_fund(conn, client_id=client_id, fee_msat=fee_msat, now=now, test_mode=False)


def fee_from_offer(offer) -> tuple[int, bool]:
    """Formula fee for an x402 offer that was not given an explicit test-mode zero."""
    if offer is None:
        raise ValueError("invalid price")
    if offer["satsgate_fee_msat"] is not None:
        return int(offer["satsgate_fee_msat"]), False
    if offer["amount_sats"]:
        return lightning_item_fee(int(offer["amount_sats"])), False
    if offer["amount_usd_atomic"] and offer["rate_num"] and offer["rate_den"]:
        item = item_msat_from_usd(int(offer["amount_usd_atomic"]), int(offer["rate_num"]), int(offer["rate_den"]))
        return usdc_item_fee(item, rate_num=int(offer["rate_num"]), rate_den=int(offer["rate_den"])), False
    # A live offer issued before a fee was locked, with no rate to convert a
    # USDC price. Debit the standard 2-sat term rather than failing the buyer.
    return int(config.FEE_MSAT), False


def standard_fee() -> int:
    return int(config.FEE_MSAT)
